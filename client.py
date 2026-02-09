import argparse
import asyncio
import json
import os
import ssl
import time
from typing import Optional

from aioquic.asyncio import connect, QuicConnectionProtocol
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
                    self._clm.maybe_rotate(self._quic, reason="timer")
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

    parser.add_argument("--rotate-interval", type=float, default=0.0)
    parser.add_argument("--jitter", type=float, default=0.0)
    parser.add_argument("--min-gap", type=float, default=10.0)

    parser.add_argument("--qlog-dir", default="qlog")
    parser.add_argument("--runs-dir", default="runs")
    parser.add_argument("--secrets-log", default="runs/client/secrets.log")
    parser.add_argument("--alpn", default="hq-29", help="ALPN protocol (e.g., hq-29, h3, h3-29)")
    args = parser.parse_args()

    configuration = QuicConfiguration(is_client=True, alpn_protocols=[args.alpn])
    configuration.verify_mode = ssl.CERT_NONE
    configuration.secrets_log_file = open(args.secrets_log, "a", encoding="utf-8")

    quic_logger = QuicLogger()
    configuration.quic_logger = quic_logger

    os.makedirs(args.runs_dir, exist_ok=True)
    policy = RotationPolicy(
        rotate_interval_s=args.rotate_interval,
        jitter_s=args.jitter,
        min_gap_s=args.min_gap,
    )
    clm = CidLifecycleManager(policy, os.path.join(args.runs_dir, "rotation_client.log"), role="client")

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

        # Create a single bidirectional stream id
        stream_id = protocol._quic.get_next_available_stream_id(is_unidirectional=False)

        deadline = time.time() + args.duration
        counter = 0

        while time.time() < deadline:
            payload = f"ping {counter} @ {time.time():.3f}\n".encode("utf-8")
            protocol._quic.send_stream_data(stream_id, payload, end_stream=False)
            protocol.transmit()

            # wait a bit for echo (optional)
            try:
                sid, data, end_stream = await asyncio.wait_for(protocol._recv_q.get(), timeout=1.0)
                if data:
                    # keep output short
                    pass
            except asyncio.TimeoutError:
                pass

            counter += 1
            await asyncio.sleep(1.0)

        # End the stream ONCE (send FIN once)
        protocol._quic.send_stream_data(stream_id, b"", end_stream=True)
        protocol.transmit()

        # Close connection cleanly
        protocol.close()
        if hasattr(protocol, "wait_closed"):
            await protocol.wait_closed()

    write_qlog(quic_logger, qlog_path)
    print(f"[client] qlog saved: {qlog_path}")
    print(f"[client] rotation log: {os.path.join(args.runs_dir, 'rotation_client.log')}")
    print(f"[client] secrets log: {args.secrets_log}")


if __name__ == "__main__":
    asyncio.run(main())
