import argparse
import asyncio
import json
import os
import time
from dataclasses import dataclass
from datetime import datetime
from typing import Dict, Optional, Set

from aioquic.asyncio import QuicConnectionProtocol, serve
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.logger import QuicLogger

from cid_lifecycle import CidLifecycleManager, RotationPolicy


RESET = "\033[0m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
RED = "\033[91m"
MAGENTA = "\033[95m"

EVENT_COLORS = {
    "START": CYAN,
    "CONNECT": CYAN,
    "HANDSHAKE": GREEN,
    "STREAM": RESET,
    "CID": MAGENTA,
    "PATH": YELLOW,
    "ERROR": RED,
    "CLOSE": GREEN,
    "FILE": CYAN,
    "CLI": YELLOW,
}


def short_cid(cid) -> str:
    if cid is None:
        return "None"
    if isinstance(cid, (bytes, bytearray)):
        cid = cid.hex()
    cid = str(cid)
    return cid if len(cid) <= 16 else cid[:8] + "..." + cid[-4:]


def log(role: str, event: str, message: str, *, use_color: bool = True) -> None:
    now = datetime.now().strftime("%H:%M:%S")
    color = EVENT_COLORS.get(event, RESET) if use_color else ""
    reset = RESET if use_color else ""
    print(f"{color}[{now}] [{role}] [{event}] {message}{reset}", flush=True)


def banner(title: str, *, use_color: bool = True) -> None:
    line = "=" * 72
    if use_color:
        print(f"{CYAN}\n{line}\n{title}\n{line}{RESET}", flush=True)
    else:
        print(f"\n{line}\n{title}\n{line}", flush=True)


def write_qlog(quic_logger: QuicLogger, path: str) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        if hasattr(quic_logger, "to_json"):
            f.write(quic_logger.to_json())
        elif hasattr(quic_logger, "to_dict"):
            f.write(json.dumps(quic_logger.to_dict(), indent=2))
        elif hasattr(quic_logger, "traces"):
            f.write(json.dumps({"traces": quic_logger.traces}, indent=2))
        else:
            f.write(json.dumps({"error": "Unsupported QuicLogger API"}, indent=2))


def ensure_cert(cert_path: str, key_path: str):
    if not (os.path.exists(cert_path) and os.path.exists(key_path)):
        raise RuntimeError(
            f"Missing cert/key. Generate with:\n"
            f'  openssl req -x509 -newkey rsa:2048 -keyout {key_path} -out {cert_path} '
            f'-days 365 -nodes -subj "/CN=localhost"'
        )


def make_clm_console_logger(role: str, *, use_color: bool = True):
    def _console(event: dict) -> None:
        event_name = event.get("event", "unknown")
        detail = event.get("detail", {}) or {}
        reason = event.get("reason")

        if event_name == "clm_initialized":
            log(
                role,
                "CID",
                (
                    "CLM ready: "
                    f"policy={event.get('policy')} "
                    f"current_cid={short_cid(detail.get('current_cid_hex'))}"
                ),
                use_color=use_color,
            )
        elif event_name == "rotate_ok":
            trigger = reason or "unknown"
            old_cid = short_cid(detail.get("old_cid_hex"))
            new_cid = short_cid(detail.get("new_cid_hex"))
            strategy = detail.get("strategy", "unknown")
            log(role, "CID", f"Rotating CID (trigger={trigger}, strategy={strategy})", use_color=use_color)
            log(role, "CID", f"old={old_cid} new={new_cid}", use_color=use_color)
            retire_at = detail.get("retire_at")
            if retire_at is not None:
                seconds_left = max(0.0, retire_at - time.time())
                log(role, "CID", f"Old CID enters grace period (~{seconds_left:.1f}s)", use_color=use_color)
        elif event_name == "rotate_failed":
            log(
                role,
                "ERROR",
                f"CID rotation failed (trigger={reason or 'unknown'}): {detail.get('note', 'unknown error')}",
                use_color=use_color,
            )
        elif event_name == "rotate_skipped":
            log(
                role,
                "CID",
                f"CID rotation skipped (trigger={reason or 'unknown'}): {detail.get('note', 'guard active')}",
                use_color=use_color,
            )
        elif event_name == "retire_connection_id_emitted":
            log(
                role,
                "CID",
                f"Retired old CID: {short_cid(detail.get('cid_hex'))}",
                use_color=use_color,
            )
        elif event_name == "retire_connection_id_failed":
            log(
                role,
                "ERROR",
                f"Failed to retire old CID {short_cid(detail.get('cid_hex'))}: {detail.get('note', 'unknown error')}",
                use_color=use_color,
            )
    return _console


@dataclass
class ServerRuntime:
    policy: RotationPolicy
    rotation_log: str
    use_color: bool


class EchoServerProtocol(QuicConnectionProtocol):
    def __init__(
        self,
        *args,
        runtime: ServerRuntime,
        registry: Set["EchoServerProtocol"],
        **kwargs,
    ):
        super().__init__(*args, **kwargs)
        self._runtime = runtime
        self._registry = registry
        self._use_color = runtime.use_color
        self._handshake_logged = False
        self._protocol_logged = False
        self._registry.add(self)

        # IMPORTANT: one CLM per connection / protocol
        self._clm = CidLifecycleManager(
            runtime.policy,
            log_path=runtime.rotation_log,
            role="server",
            console_callback=make_clm_console_logger("SERVER", use_color=self._use_color),
        )

        self._ticker_task = asyncio.create_task(self._ticker())

    async def _ticker(self):
        try:
            while True:
                await asyncio.sleep(0.2)
                self._clm.tick(self)
        except asyncio.CancelledError:
            return

    def quic_event_received(self, event):
        name = event.__class__.__name__

        if name == "ProtocolNegotiated" and not self._protocol_logged:
            alpn = getattr(event, "alpn_protocol", None)
            if alpn is not None:
                log("SERVER", "HANDSHAKE", f"ALPN negotiated: {alpn}", use_color=self._use_color)
            self._protocol_logged = True

        elif name == "HandshakeCompleted" and not self._handshake_logged:
            resumed = getattr(event, "session_resumed", False)
            early_data = getattr(event, "early_data_accepted", False)
            log(
                "SERVER",
                "HANDSHAKE",
                f"Handshake completed (resumed={resumed}, early_data={early_data})",
                use_color=self._use_color,
            )
            self._handshake_logged = True

        elif name == "StreamDataReceived":
            if event.data:
                preview = event.data.decode("utf-8", errors="replace").strip()
                if len(preview) > 80:
                    preview = preview[:77] + "..."
                log(
                    "SERVER",
                    "STREAM",
                    f"Received on stream {event.stream_id}: {preview}",
                    use_color=self._use_color,
                )
                self._quic.send_stream_data(
                    event.stream_id, event.data, end_stream=event.end_stream
                )
                self.transmit()
                log(
                    "SERVER",
                    "STREAM",
                    f"Echoed back on stream {event.stream_id}",
                    use_color=self._use_color,
                )

        elif name == "ConnectionTerminated":
            error_code = getattr(event, "error_code", None)
            frame_type = getattr(event, "frame_type", None)
            reason = getattr(event, "reason_phrase", "")
            log(
                "SERVER",
                "CLOSE",
                f"Connection terminated (error_code={error_code}, frame_type={frame_type}, reason={reason!r})",
                use_color=self._use_color,
            )

    def connection_lost(self, exc):
        if hasattr(self, "_ticker_task"):
            self._ticker_task.cancel()
        self._registry.discard(self)
        if exc is None:
            log("SERVER", "CLOSE", "Connection closed", use_color=self._use_color)
        else:
            log("SERVER", "ERROR", f"Connection lost: {exc}", use_color=self._use_color)
        return super().connection_lost(exc)


def force_rotate_all(protocols: Set[EchoServerProtocol], *, use_color: bool = True) -> None:
    count = 0
    for p in list(protocols):
        try:
            p._clm.force_rotate(p, reason="manual")
            count += 1
        except Exception as e:
            log("SERVER", "ERROR", f"Manual rotate failed: {type(e).__name__}: {e}", use_color=use_color)
    log("SERVER", "CLI", f"Manual rotate requested for {count} connection(s)", use_color=use_color)


def simulate_path_change_all(protocols: Set[EchoServerProtocol], *, use_color: bool = True) -> None:
    count = 0
    tag = f"simulated-path-{int(time.time())}"
    for p in list(protocols):
        try:
            p._clm.on_path_validated(p, path_id=tag, old_path_id="manual-trigger")
            count += 1
        except Exception as e:
            log("SERVER", "ERROR", f"Path-change rotate failed: {type(e).__name__}: {e}", use_color=use_color)
    log("SERVER", "PATH", f"Simulated validated path change requested for {count} connection(s)", use_color=use_color)


async def cli_loop(protocols: Set[EchoServerProtocol], runtime: ServerRuntime):
    use_color = runtime.use_color
    help_text = (
        "\n[server cli] commands:\n"
        "  help              Show commands\n"
        "  status            Show status\n"
        "  connections       Show number of active connections\n"
        "  rotate            Force a rotate attempt on active connections\n"
        "  path-change       Simulate a validated path change on active connections\n"
        "  quit / exit       Stop server\n"
    )
    print(help_text, flush=True)

    while True:
        cmd = (await asyncio.to_thread(input, "[server cli] > ")).strip().lower()

        if cmd in ("help", "?"):
            print(help_text, flush=True)
        elif cmd == "status":
            p = runtime.policy
            log(
                "SERVER",
                "CLI",
                (
                    f"active_connections={len(protocols)} "
                    f"policy={p.cid_policy} "
                    f"time_interval={p.cid_time_interval_s}s "
                    f"jitter_fraction={p.cid_jitter_fraction} "
                    f"byte_threshold={p.cid_byte_threshold} "
                    f"grace_period={p.cid_grace_period_s}s "
                    f"min_gap={p.min_gap_s}s"
                ),
                use_color=use_color,
            )
        elif cmd in ("connections", "conn"):
            log("SERVER", "CLI", f"Active connections: {len(protocols)}", use_color=use_color)
        elif cmd in ("rotate", "r"):
            force_rotate_all(protocols, use_color=use_color)
        elif cmd in ("path-change", "path", "p"):
            simulate_path_change_all(protocols, use_color=use_color)
        elif cmd in ("quit", "exit", "q"):
            log("SERVER", "CLOSE", "Shutting down server...", use_color=use_color)
            return
        elif cmd == "":
            continue
        else:
            log("SERVER", "ERROR", "Unknown command. Type 'help'.", use_color=use_color)


async def main():
    ap = argparse.ArgumentParser()

    ap.add_argument("--host", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=4433)
    ap.add_argument("--cert", default="server.crt")
    ap.add_argument("--key", default="server.key")
    ap.add_argument("--qlog-dir", default="qlog")
    ap.add_argument("--secrets-log", default="runs/server/secrets.log")
    ap.add_argument("--rotation-log", default="runs/server/rotation.jsonl")
    ap.add_argument("--alpn", default="hq-29", help="ALPN protocol (e.g., hq-29, h3, h3-29)")
    ap.add_argument("--demo", action="store_true", help="Enable presentation-friendly banners and logs")
    ap.add_argument("--no-color", action="store_true", help="Disable ANSI colors in terminal output")

    ap.add_argument("--cid-policy", choices=["baseline", "clm"], default="clm")
    ap.add_argument("--cid-time-interval", type=float, default=15.0)
    ap.add_argument("--cid-jitter", type=float, default=0.10, help="Jitter fraction J, e.g. 0.10 for ±10%")
    ap.add_argument("--cid-byte-threshold", type=int, default=0)
    ap.add_argument("--cid-grace-period", type=float, default=3.0)
    ap.add_argument("--cid-min-gap", type=float, default=1.0)
    ap.add_argument("--cid-random-seed", type=int, default=None)

    args = ap.parse_args()
    use_color = not args.no_color

    ensure_cert(args.cert, args.key)
    os.makedirs(args.qlog_dir, exist_ok=True)
    os.makedirs(os.path.dirname(args.secrets_log), exist_ok=True)
    os.makedirs(os.path.dirname(args.rotation_log), exist_ok=True)

    if args.demo:
        banner("QUIC SERVER DEMO", use_color=use_color)

    quic_logger = QuicLogger()
    config = QuicConfiguration(
        is_client=False,
        alpn_protocols=[args.alpn],
        quic_logger=quic_logger,
    )
    config.load_cert_chain(args.cert, args.key)
    config.secrets_log_file = open(args.secrets_log, "a", encoding="utf-8")

    runtime = ServerRuntime(
        policy=RotationPolicy(
            cid_policy=args.cid_policy,
            cid_time_interval_s=args.cid_time_interval,
            cid_jitter_fraction=args.cid_jitter,
            cid_byte_threshold=args.cid_byte_threshold,
            cid_grace_period_s=args.cid_grace_period,
            min_gap_s=args.cid_min_gap,
            random_seed=args.cid_random_seed,
        ),
        rotation_log=args.rotation_log,
        use_color=use_color,
    )

    active_protocols: Set[EchoServerProtocol] = set()

    server = await serve(
        args.host,
        args.port,
        configuration=config,
        create_protocol=lambda *p, **kw: EchoServerProtocol(
            *p, runtime=runtime, registry=active_protocols, **kw
        ),
    )

    log("SERVER", "START", f"Listening on {args.host}:{args.port}", use_color=use_color)
    log("SERVER", "FILE", f"qlog dir: {args.qlog_dir} (written on exit)", use_color=use_color)
    log("SERVER", "FILE", f"secrets log: {args.secrets_log}", use_color=use_color)
    log("SERVER", "FILE", f"rotation log: {args.rotation_log}", use_color=use_color)

    try:
        await cli_loop(active_protocols, runtime)
    finally:
        server.close()
        if hasattr(server, "wait_closed"):
            await server.wait_closed()

        try:
            if config.secrets_log_file:
                config.secrets_log_file.close()
        except Exception:
            pass

        qlog_path = os.path.join(args.qlog_dir, f"server_{int(time.time())}.qlog.json")
        write_qlog(quic_logger, qlog_path)
        log("SERVER", "FILE", f"wrote qlog: {qlog_path}", use_color=use_color)
        log("SERVER", "CLOSE", "Bye", use_color=use_color)


if __name__ == "__main__":
    asyncio.run(main())
