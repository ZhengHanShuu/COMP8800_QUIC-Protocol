import argparse
import asyncio
import json
import os
import time
from typing import Set

from aioquic.asyncio import QuicConnectionProtocol, serve
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.logger import QuicLogger

from cid_lifecycle import CidLifecycleManager, RotationPolicy


class EchoServerProtocol(QuicConnectionProtocol):
    def __init__(
        self,
        *args,
        clm: CidLifecycleManager = None,
        registry: Set["EchoServerProtocol"] = None,
        **kwargs,
    ):
        super().__init__(*args, **kwargs)
        self._clm = clm
        self._registry = registry
        if self._registry is not None:
            self._registry.add(self)

        # periodic timer to trigger rotation attempts
        self._ticker_task = asyncio.create_task(self._ticker())

    async def _ticker(self):
        try:
            while True:
                await asyncio.sleep(0.2)
                if self._clm is not None:
                    self._clm.maybe_rotate(self._quic, reason="timer")
        except asyncio.CancelledError:
            return

    def quic_event_received(self, event):
        # Simple stream echo
        from aioquic.quic.events import StreamDataReceived

        if isinstance(event, StreamDataReceived):
            stream_id = event.stream_id
            data = event.data
            if data:
                self._quic.send_stream_data(
                    stream_id, data, end_stream=event.end_stream
                )
                self.transmit()

    def connection_lost(self, exc):
        if hasattr(self, "_ticker_task"):
            self._ticker_task.cancel()
        if self._registry is not None and self in self._registry:
            self._registry.remove(self)
        return super().connection_lost(exc)


def ensure_cert(cert_path: str, key_path: str):
    """
    You need a TLS cert for QUIC. If you already have one, skip.
    If you don't, generate quickly:
      openssl req -x509 -newkey rsa:2048 -keyout server.key -out server.crt -days 365 -nodes -subj "/CN=localhost"
    """
    if not (os.path.exists(cert_path) and os.path.exists(key_path)):
        raise RuntimeError(
            f"Missing cert/key. Generate with:\n"
            f'  openssl req -x509 -newkey rsa:2048 -keyout {key_path} -out {cert_path} '
            f'-days 365 -nodes -subj "/CN=localhost"'
        )


def write_qlog(quic_logger: QuicLogger, path: str) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        # support different aioquic versions
        if hasattr(quic_logger, "to_json"):
            f.write(quic_logger.to_json())
        elif hasattr(quic_logger, "to_dict"):
            f.write(json.dumps(quic_logger.to_dict(), indent=2))
        elif hasattr(quic_logger, "traces"):
            f.write(json.dumps({"traces": quic_logger.traces}, indent=2))
        else:
            f.write(json.dumps({"error": "Unsupported QuicLogger API"}, indent=2))


def force_rotate_all(
    protocols: Set[EchoServerProtocol], clm: CidLifecycleManager
) -> None:
    # Best-effort manual rotation on all active connections
    count = 0
    for p in list(protocols):
        try:
            # call the CLM best-effort rotate immediately
            ok, detail = clm._try_rotate_local_cid(p._quic)  # intentional (best-effort)
            clm.log.log(
                {
                    "event": "rotate_ok" if ok else "rotate_failed",
                    "role": "server",
                    "reason": "manual",
                    "detail": detail,
                }
            )
            count += 1
        except Exception as e:
            clm.log.log(
                {
                    "event": "rotate_failed",
                    "role": "server",
                    "reason": "manual",
                    "detail": {"note": f"{type(e).__name__}: {e}"},
                }
            )
    print(f"[server] manual rotate requested for {count} connection(s)", flush=True)


async def cli_loop(protocols: Set[EchoServerProtocol], clm: CidLifecycleManager):
    help_text = (
        "\n[server cli] commands:\n"
        "  help            Show commands\n"
        "  status          Show status\n"
        "  connections     Show number of active connections\n"
        "  rotate          Force a rotate attempt on active connections\n"
        "  quit / exit     Stop server\n"
    )
    print(help_text, flush=True)

    while True:
        # Run blocking stdin read in a thread so it doesn't break QUIC
        cmd = (await asyncio.to_thread(input, "[server cli] > ")).strip().lower()

        if cmd in ("help", "?"):
            print(help_text, flush=True)
        elif cmd in ("status",):
            print(
                f"[server] active connections: {len(protocols)} | "
                f"policy: interval={clm.policy.rotate_interval_s}s jitter={clm.policy.jitter_s}s min_gap={clm.policy.min_gap_s}s",
                flush=True,
            )
        elif cmd in ("connections", "conn"):
            print(f"[server] active connections: {len(protocols)}", flush=True)
        elif cmd in ("rotate", "r"):
            force_rotate_all(protocols, clm)
        elif cmd in ("quit", "exit", "q"):
            print("[server] shutting down...", flush=True)
            return
        elif cmd == "":
            continue
        else:
            print("[server cli] unknown command. type 'help'.", flush=True)


async def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=4433)
    ap.add_argument("--cert", default="server.crt")
    ap.add_argument("--key", default="server.key")
    ap.add_argument("--qlog-dir", default="qlog")
    ap.add_argument("--secrets-log", default="runs/server/secrets.log")
    ap.add_argument("--rotation-log", default="runs/server/rotation.jsonl")
    ap.add_argument("--rotate-interval", type=float, default=15.0)
    ap.add_argument("--jitter", type=float, default=2.0)
    ap.add_argument("--alpn", default="hq-29", help="ALPN protocol (e.g., hq-29, h3, h3-29)")
    args = ap.parse_args()

    ensure_cert(args.cert, args.key)
    os.makedirs(args.qlog_dir, exist_ok=True)
    os.makedirs(os.path.dirname(args.secrets_log), exist_ok=True)
    os.makedirs(os.path.dirname(args.rotation_log), exist_ok=True)

    quic_logger = QuicLogger()
    config = QuicConfiguration(
        is_client=False,
        alpn_protocols=[args.alpn],
        quic_logger=quic_logger,
    )
    config.load_cert_chain(args.cert, args.key)
    config.secrets_log_file = open(args.secrets_log, "a", encoding="utf-8")

    policy = RotationPolicy(
        rotate_interval_s=args.rotate_interval,
        jitter_s=args.jitter,
        min_gap_s=max(5.0, args.rotate_interval * 0.5),
    )
    clm = CidLifecycleManager(policy, log_path=args.rotation_log, role="server")

    active_protocols: Set[EchoServerProtocol] = set()

    server = await serve(
        args.host,
        args.port,
        configuration=config,
        create_protocol=lambda *p, **kw: EchoServerProtocol(
            *p, clm=clm, registry=active_protocols, **kw
        ),
    )

    print(f"[server] listening on {args.host}:{args.port}", flush=True)
    print(f"[server] qlog dir: {args.qlog_dir} (written on exit)", flush=True)
    print(f"[server] secrets log: {args.secrets_log}", flush=True)
    print(f"[server] rotation log: {args.rotation_log}", flush=True)

    try:
        # run CLI until user quits
        await cli_loop(active_protocols, clm)
    finally:
        server.close()
        if hasattr(server, "wait_closed"): await server.wait_closed()

        # close secrets log
        try:
            if config.secrets_log_file:
                config.secrets_log_file.close()
        except Exception:
            pass

        # write qlog at shutdown
        qlog_path = os.path.join(args.qlog_dir, f"server_{int(time.time())}.qlog.json")
        write_qlog(quic_logger, qlog_path)
        print(f"[server] wrote qlog: {qlog_path}", flush=True)
        print("[server] bye", flush=True)


if __name__ == "__main__":
    asyncio.run(main())
