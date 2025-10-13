#!/usr/bin/env python3
import argparse, asyncio, logging
from pathlib import Path
from aioquic.asyncio import QuicConnectionProtocol, serve
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import ProtocolNegotiated, StreamDataReceived
from aioquic.quic.logger import QuicFileLogger

ALPN = ["hq-interop"]

class EchoServerProtocol(QuicConnectionProtocol):
    def quic_event_received(self, event):
        if isinstance(event, ProtocolNegotiated):
            # Just log negotiated ALPN (avoid accessing fields that may not exist across versions)
            logging.info("[server] ALPN negotiated protocol %s", event.alpn_protocol)

        if isinstance(event, StreamDataReceived):
            # Echo the payload and mirror FIN
            self._quic.send_stream_data(event.stream_id, event.data, end_stream=event.end_stream)
            self.transmit()  # flush the echo immediately

            # If the client ended the stream, close the whole connection gracefully
            if event.end_stream:
                self._quic.close(error_code=0x0, reason_phrase="server done")
                self.transmit()

async def main():
    ap = argparse.ArgumentParser(description="QUIC Echo Server (aioquic)")
    ap.add_argument("--addr", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=8443)
    ap.add_argument("--cert", default=str(Path(__file__).with_name("server.crt")))
    ap.add_argument("--key",  default=str(Path(__file__).with_name("server.key")))
    ap.add_argument("--qlog-dir", default=str(Path(__file__).with_name("qlog")))
    args = ap.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

    cfg = QuicConfiguration(is_client=False, alpn_protocols=ALPN)
    cfg.load_cert_chain(args.cert, args.key)

    # Wireshark secrets + qlog (optional but handy)
    qdir = Path(args.qlog_dir); qdir.mkdir(parents=True, exist_ok=True)
    cfg.secrets_log_file = open(qdir / "secrets.log", "w")
    cfg.quic_logger = QuicFileLogger(str(qdir))

    server = await serve(
        args.addr, args.port,
        configuration=cfg,
        create_protocol=EchoServerProtocol,
        retry=False,
    )
    logging.info("[server] listening on %s:%d (udp)", args.addr, args.port)
    try:
        await asyncio.Future()  # keep running until Ctrl+C
    finally:
        server.close()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
