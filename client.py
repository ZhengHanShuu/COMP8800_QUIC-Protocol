import argparse
import asyncio
import json
import os
import ssl
import time
from datetime import datetime
from typing import Optional

from aioquic.asyncio import QuicConnectionProtocol, connect
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


def write_qlog(quic_logger: Optional[QuicLogger], path: str) -> None:
    if quic_logger is None:
        return
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


class ClientProtocol(QuicConnectionProtocol):
    def __init__(self, *args, clm: CidLifecycleManager = None, use_color: bool = True, **kwargs):
        super().__init__(*args, **kwargs)
        self._clm = clm
        self._use_color = use_color
        self._recv_q: asyncio.Queue[tuple[int, bytes, bool]] = asyncio.Queue()
        self._ticker_task = asyncio.create_task(self._ticker())
        self._handshake_logged = False
        self._protocol_logged = False

    async def _ticker(self):
        try:
            while True:
                await asyncio.sleep(0.2)
                if self._clm is not None:
                    self._clm.tick(self)
        except asyncio.CancelledError:
            return

    def connection_lost(self, exc):
        if self._ticker_task:
            self._ticker_task.cancel()
        if exc is None:
            log("CLIENT", "CLOSE", "Connection closed", use_color=self._use_color)
        else:
            log("CLIENT", "ERROR", f"Connection lost: {exc}", use_color=self._use_color)
        return super().connection_lost(exc)

    def quic_event_received(self, event):
        name = event.__class__.__name__

        if name == "ProtocolNegotiated" and not self._protocol_logged:
            alpn = getattr(event, "alpn_protocol", None)
            if alpn is not None:
                log("CLIENT", "HANDSHAKE", f"ALPN negotiated: {alpn}", use_color=self._use_color)
            self._protocol_logged = True

        elif name == "HandshakeCompleted" and not self._handshake_logged:
            resumed = getattr(event, "session_resumed", False)
            early_data = getattr(event, "early_data_accepted", False)
            log(
                "CLIENT",
                "HANDSHAKE",
                f"Handshake completed (resumed={resumed}, early_data={early_data})",
                use_color=self._use_color,
            )
            self._handshake_logged = True

        elif name == "StreamDataReceived":
            if getattr(event, "data", b""):
                preview = event.data.decode("utf-8", errors="replace").strip()
                if len(preview) > 80:
                    preview = preview[:77] + "..."
                log(
                    "CLIENT",
                    "STREAM",
                    f"Received echo on stream {event.stream_id}: {preview}",
                    use_color=self._use_color,
                )
            self._recv_q.put_nowait((event.stream_id, event.data, event.end_stream))

        elif name == "ConnectionTerminated":
            error_code = getattr(event, "error_code", None)
            frame_type = getattr(event, "frame_type", None)
            reason = getattr(event, "reason_phrase", "")
            log(
                "CLIENT",
                "CLOSE",
                f"Connection terminated (error_code={error_code}, frame_type={frame_type}, reason={reason!r})",
                use_color=self._use_color,
            )


async def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=4433)
    parser.add_argument("--duration", type=float, default=20.0)
    parser.add_argument("--send-interval", type=float, default=1.0)
    parser.add_argument("--payload-size", type=int, default=0, help="Pad payload to this size in bytes; 0 disables padding")

    parser.add_argument("--qlog-dir", default="qlog")
    parser.add_argument("--runs-dir", default="runs/client")
    parser.add_argument("--secrets-log", default="runs/client/secrets.log")
    parser.add_argument("--alpn", default="hq-29", help="ALPN protocol (e.g., hq-29, h3, h3-29)")
    parser.add_argument("--demo", action="store_true", help="Enable presentation-friendly banners and logs")
    parser.add_argument("--no-color", action="store_true", help="Disable ANSI colors in terminal output")

    parser.add_argument("--cid-policy", choices=["baseline", "clm"], default="clm")
    parser.add_argument("--cid-time-interval", type=float, default=15.0)
    parser.add_argument("--cid-jitter", type=float, default=0.10, help="Jitter fraction J, e.g. 0.10 for ±10%")
    parser.add_argument("--cid-byte-threshold", type=int, default=0)
    parser.add_argument("--cid-grace-period", type=float, default=3.0)
    parser.add_argument("--cid-min-gap", type=float, default=1.0)
    parser.add_argument("--cid-random-seed", type=int, default=None)

    parser.add_argument(
        "--simulate-path-change-after",
        type=float,
        default=0.0,
        help="Trigger a simulated validated path-change after N seconds; 0 disables",
    )

    args = parser.parse_args()
    use_color = not args.no_color

    os.makedirs(args.runs_dir, exist_ok=True)
    os.makedirs(args.qlog_dir, exist_ok=True)
    os.makedirs(os.path.dirname(args.secrets_log), exist_ok=True)

    if args.demo:
        banner("QUIC CLIENT DEMO", use_color=use_color)

    configuration = QuicConfiguration(is_client=True, alpn_protocols=[args.alpn])
    configuration.verify_mode = ssl.CERT_NONE
    configuration.secrets_log_file = open(args.secrets_log, "a", encoding="utf-8")

    quic_logger = QuicLogger()
    configuration.quic_logger = quic_logger

    policy = RotationPolicy(
        cid_policy=args.cid_policy,
        cid_time_interval_s=args.cid_time_interval,
        cid_jitter_fraction=args.cid_jitter,
        cid_byte_threshold=args.cid_byte_threshold,
        cid_grace_period_s=args.cid_grace_period,
        min_gap_s=args.cid_min_gap,
        random_seed=args.cid_random_seed,
    )
    rotation_log_path = os.path.join(args.runs_dir, "rotation_client.jsonl")
    clm = CidLifecycleManager(
        policy=policy,
        log_path=rotation_log_path,
        role="client",
        console_callback=make_clm_console_logger("CLIENT", use_color=use_color),
    )

    start_ts = int(time.time())
    qlog_path = os.path.join(args.qlog_dir, f"client_{start_ts}.qlog.json")

    log("CLIENT", "CONNECT", f"Connecting to {args.host}:{args.port}", use_color=use_color)

    async with connect(
        args.host,
        args.port,
        configuration=configuration,
        create_protocol=lambda *a, **kw: ClientProtocol(*a, clm=clm, use_color=use_color, **kw),
    ) as protocol:
        assert isinstance(protocol, ClientProtocol)
        log("CLIENT", "CONNECT", f"Connected to {args.host}:{args.port}", use_color=use_color)

        stream_id = protocol._quic.get_next_available_stream_id(is_unidirectional=False)
        log("CLIENT", "STREAM", f"Opened bidirectional stream {stream_id}", use_color=use_color)

        deadline = time.time() + args.duration
        started_at = time.time()
        path_change_sent = False
        counter = 0

        while time.time() < deadline:
            now = time.time()
            payload = f"ping {counter} @ {now:.3f}\n".encode("utf-8")

            if args.payload_size > 0 and len(payload) < args.payload_size:
                payload += b"x" * (args.payload_size - len(payload))

            preview = payload[:80].decode("utf-8", errors="replace").strip()
            log("CLIENT", "STREAM", f"Sent on stream {stream_id}: {preview}", use_color=use_color)

            protocol._quic.send_stream_data(stream_id, payload, end_stream=False)
            protocol.transmit()

            try:
                await asyncio.wait_for(protocol._recv_q.get(), timeout=1.0)
            except asyncio.TimeoutError:
                log("CLIENT", "ERROR", "Timed out waiting for echo", use_color=use_color)

            if (
                args.simulate_path_change_after > 0
                and not path_change_sent
                and (time.time() - started_at) >= args.simulate_path_change_after
            ):
                path_change_sent = True
                simulated_path = f"simulated-client-path-{int(time.time())}"
                log(
                    "CLIENT",
                    "PATH",
                    f"Simulating validated path change -> {simulated_path}",
                    use_color=use_color,
                )
                clm.on_path_validated(
                    protocol,
                    path_id=simulated_path,
                    old_path_id="simulated-old-path",
                )

            counter += 1
            await asyncio.sleep(args.send_interval)

        log("CLIENT", "CLOSE", "Closing stream and connection cleanly", use_color=use_color)
        protocol._quic.send_stream_data(stream_id, b"", end_stream=True)
        protocol.transmit()

        protocol.close()
        if hasattr(protocol, "wait_closed"):
            await protocol.wait_closed()

    try:
        if configuration.secrets_log_file:
            configuration.secrets_log_file.close()
    except Exception:
        pass

    write_qlog(quic_logger, qlog_path)
    log("CLIENT", "FILE", f"qlog saved: {qlog_path}", use_color=use_color)
    log("CLIENT", "FILE", f"rotation log: {rotation_log_path}", use_color=use_color)
    log("CLIENT", "FILE", f"secrets log: {args.secrets_log}", use_color=use_color)


if __name__ == "__main__":
    asyncio.run(main())
