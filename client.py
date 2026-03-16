import argparse
import asyncio
import json
import os
import ssl
import time
from typing import Optional

from aioquic.asyncio import QuicConnectionProtocol, connect
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.logger import QuicLogger

from cid_lifecycle import CidLifecycleManager, RotationPolicy


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


class ClientProtocol(QuicConnectionProtocol):
    def __init__(self, *args, clm: CidLifecycleManager = None, **kwargs):
        super().__init__(*args, **kwargs)
        self._clm = clm
        self._recv_q: asyncio.Queue[tuple[int, bytes, bool]] = asyncio.Queue()
        self._ticker_task = asyncio.create_task(self._ticker())

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
        return super().connection_lost(exc)

    def quic_event_received(self, event):
        from aioquic.quic.events import StreamDataReceived

        if isinstance(event, StreamDataReceived):
            self._recv_q.put_nowait((event.stream_id, event.data, event.end_stream))


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

    # Milestone 4 flags
    parser.add_argument("--cid-policy", choices=["baseline", "clm"], default="clm")
    parser.add_argument("--cid-time-interval", type=float, default=15.0)
    parser.add_argument("--cid-jitter", type=float, default=0.10, help="Jitter fraction J, e.g. 0.10 for ±10%")
    parser.add_argument("--cid-byte-threshold", type=int, default=0)
    parser.add_argument("--cid-grace-period", type=float, default=3.0)
    parser.add_argument("--cid-min-gap", type=float, default=1.0)
    parser.add_argument("--cid-random-seed", type=int, default=None)

    # Optional experiment helper
    parser.add_argument(
        "--simulate-path-change-after",
        type=float,
        default=0.0,
        help="Trigger a simulated validated path-change after N seconds; 0 disables",
    )

    args = parser.parse_args()

    os.makedirs(args.runs_dir, exist_ok=True)
    os.makedirs(args.qlog_dir, exist_ok=True)
    os.makedirs(os.path.dirname(args.secrets_log), exist_ok=True)

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
    clm = CidLifecycleManager(
        policy=policy,
        log_path=os.path.join(args.runs_dir, "rotation_client.jsonl"),
        role="client",
    )

    start_ts = int(time.time())
    qlog_path = os.path.join(args.qlog_dir, f"client_{start_ts}.qlog.json")

    async with connect(
        args.host,
        args.port,
        configuration=configuration,
        create_protocol=lambda *a, **kw: ClientProtocol(*a, clm=clm, **kw),
    ) as protocol:
        assert isinstance(protocol, ClientProtocol)
        print(f"[client] connected to {args.host}:{args.port}")

        stream_id = protocol._quic.get_next_available_stream_id(is_unidirectional=False)

        deadline = time.time() + args.duration
        path_change_sent = False
        counter = 0

        while time.time() < deadline:
            now = time.time()
            payload = f"ping {counter} @ {now:.3f}\n".encode("utf-8")

            if args.payload_size > 0 and len(payload) < args.payload_size:
                payload += b"x" * (args.payload_size - len(payload))

            protocol._quic.send_stream_data(stream_id, payload, end_stream=False)
            protocol.transmit()

            try:
                await asyncio.wait_for(protocol._recv_q.get(), timeout=1.0)
            except asyncio.TimeoutError:
                pass

            if (
                args.simulate_path_change_after > 0
                and not path_change_sent
                and (time.time() >= (deadline - args.duration + args.simulate_path_change_after))
            ):
                path_change_sent = True
                clm.on_path_validated(
                    protocol,
                    path_id=f"simulated-client-path-{int(time.time())}",
                    old_path_id="simulated-old-path",
                )

            counter += 1
            await asyncio.sleep(args.send_interval)

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
    print(f"[client] qlog saved: {qlog_path}")
    print(f"[client] rotation log: {os.path.join(args.runs_dir, 'rotation_client.jsonl')}")
    print(f"[client] secrets log: {args.secrets_log}")


if __name__ == "__main__":
    asyncio.run(main())