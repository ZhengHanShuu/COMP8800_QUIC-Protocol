#!/usr/bin/env python3
import argparse, asyncio, logging, ssl
from pathlib import Path
from aioquic.asyncio import connect, QuicConnectionProtocol
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import StreamDataReceived, ConnectionTerminated

ALPN = ["hq-interop"]

class EchoClient(QuicConnectionProtocol):
    def __init__(self, *args, message: bytes, **kwargs):
        super().__init__(*args, **kwargs)
        loop = asyncio.get_event_loop()
        self._done = loop.create_future()
        self._message = message
        self._stream_id = None
        self._buffer = bytearray()

    async def run(self):
        # open a bidirectional stream and send a message
        self._stream_id = self._quic.get_next_available_stream_id(is_unidirectional=False)
        self._quic.send_stream_data(self._stream_id, self._message + b"\n", end_stream=True)
        self.transmit()  # <-- was _transmit()

        # wait for echo
        await self._done

        # explicit CONNECTION_CLOSE
        self._quic.close(error_code=0x0, reason_phrase="done")
        self.transmit()  # <-- was _transmit()

    def quic_event_received(self, event):
        if isinstance(event, StreamDataReceived) and event.stream_id == self._stream_id:
            self._buffer.extend(event.data)
            if event.end_stream and not self._done.done():
                print(self._buffer.decode(errors="replace").rstrip("\n"))
                self._done.set_result(True)
        elif isinstance(event, ConnectionTerminated):
            if not self._done.done():
                self._done.set_result(True)

async def main():
    ap = argparse.ArgumentParser(description="QUIC Echo Client (aioquic)")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8443)
    ap.add_argument("--in", dest="msg", default="hello quic")
    ap.add_argument("--qlog-dir", default=None)
    ap.add_argument("--local-port", type=int, default=0)
    args = ap.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

    cfg = QuicConfiguration(is_client=True, alpn_protocols=ALPN)
    cfg.verify_mode = ssl.CERT_NONE  # demo: accept self-signed
    cfg.server_name = "localhost"

    if args.qlog_dir:
        qdir = Path(args.qlog_dir); qdir.mkdir(parents=True, exist_ok=True)
        cfg.secrets_log_file = open(qdir / "secrets.log", "a")

    async with connect(
        args.host, args.port, configuration=cfg,
        create_protocol=lambda *a, **kw: EchoClient(*a, message=args.msg.encode(), **kw),
        local_port=args.local_port
    ) as proto:
        await proto.run()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
