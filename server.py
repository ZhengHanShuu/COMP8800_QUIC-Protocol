#!/usr/bin/env python3
import argparse, asyncio, logging
from pathlib import Path

from aioquic.asyncio import QuicConnectionProtocol, serve
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import (
    ProtocolNegotiated,
    StreamDataReceived,
    ConnectionTerminated,
)
from aioquic.quic.logger import QuicFileLogger

ALPN = ["hq-interop"]


class RotatingCIDMixin:
    """
    Periodically switches to a fresh outbound Connection ID and logs the active CID hex.
    Shuts down cleanly on connection close.
    """
    def __init__(self, *args, cid_interval: float = 8.0, **kwargs):
        super().__init__(*args, **kwargs)
        self._cid_interval = cid_interval
        self._cid_task = None
        self._cid_stop = asyncio.Event()

    # ---------- helpers ----------

    @staticmethod
    def _to_bytes(x):
        if x is None:
            return None
        if isinstance(x, (bytes, bytearray)):
            return bytes(x)
        try:
            return bytes(x)  # memoryview or buffer-protocol
        except Exception:
            return None

    def _current_outbound_cid_hex(self):
        """
        For this aioquic build: use the QuicConnectionId with the largest sequence_number.
        """
        qc = self._quic
        host_cids = getattr(qc, "_host_cids", None)
        if not host_cids:
            return None

        # QuicConnectionId objects with attributes: cid (bytes/memoryview), sequence_number (int),
        # stateless_reset_token, was_sent (bool). Pick the highest sequence_number.
        try:
            best = max(host_cids, key=lambda x: getattr(x, "sequence_number", -1))
            cid = getattr(best, "cid", None)
            if cid is None:
                return None
            # cid might be bytes, bytearray, or memoryview
            if not isinstance(cid, (bytes, bytearray)):
                cid = bytes(cid)
            return cid.hex()
        except Exception:
            return None

    # ---------- lifecycle ----------

    def connection_made(self, transport):
        super().connection_made(transport)
        self._cid_task = asyncio.create_task(self._cid_rotator())

    def connection_lost(self, exc):
        if self._cid_task:
            self._cid_stop.set()
            self._cid_task.cancel()
        return super().connection_lost(exc)

    async def _cid_rotator(self):
        try:
            await asyncio.sleep(0.8)  # give handshake a moment
            while not self._cid_stop.is_set():
                if getattr(self._quic, "is_closing", False) or getattr(self._quic, "_close_pending", False):
                    break
                try:
                    self._quic.change_connection_id()
                    self.transmit()
                    cid_hex = self._current_outbound_cid_hex()
                    logging.info("[%s] rotated CID -> %s", self.__class__.__name__, cid_hex or "<unknown>")
                    #logging.info("DEBUG host_cids=%r idx=%r pm=%r",
                                 #getattr(self._quic, "_host_cids", None),
                                 #getattr(self._quic, "_host_cid_in_use", None) or getattr(self._quic, "_connection_id_in_use", None),
                                 #type(getattr(self._quic, "_path_manager", None)).__name__ if getattr(self._quic, "_path_manager", None) else None)

                except AttributeError:
                    logging.warning("change_connection_id() not available in this aioquic version")
                    break
                await asyncio.sleep(self._cid_interval)
        except asyncio.CancelledError:
            pass


class EchoServerProtocol(RotatingCIDMixin, QuicConnectionProtocol):
    def __init__(self, *args, cid_interval=10.0, auto_close=False, close_delay=0.0, **kwargs):
        super().__init__(*args, cid_interval=cid_interval, **kwargs)
        self._auto_close = auto_close
        self._close_delay = close_delay

    def quic_event_received(self, event):
        if isinstance(event, ProtocolNegotiated):
            logging.info("[server] ALPN: %s", event.alpn_protocol)

        if isinstance(event, StreamDataReceived):
            self._quic.send_stream_data(event.stream_id, event.data, end_stream=event.end_stream)
            self.transmit()
            if self._auto_close and event.end_stream:
                async def _delayed_close():
                    if self._close_delay > 0:
                        await asyncio.sleep(self._close_delay)
                    self._quic.close(error_code=0x0, reason_phrase="server done")
                    self.transmit()
                asyncio.create_task(_delayed_close())

        if isinstance(event, ConnectionTerminated):
            logging.info("[server] connection terminated: %s", event.reason_phrase or "")
            if self._cid_task:
                self._cid_stop.set()
                self._cid_task.cancel()


async def main():
    ap = argparse.ArgumentParser(description="QUIC Echo Server with CID rotation (aioquic)")
    ap.add_argument("--addr", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=8443)
    ap.add_argument("--cert", default=str(Path(__file__).with_name("server.crt")))
    ap.add_argument("--key",  default=str(Path(__file__).with_name("server.key")))
    ap.add_argument("--qlog-dir", default=str(Path(__file__).with_name("qlog")))
    ap.add_argument("--cid-interval", type=float, default=10.0)
    ap.add_argument("--auto-close", action="store_true")
    ap.add_argument("--close-delay", type=float, default=0.0)
    args = ap.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

    cfg = QuicConfiguration(is_client=False, alpn_protocols=ALPN)
    cfg.connection_id_length = 8
    cfg.load_cert_chain(args.cert, args.key)

    qdir = Path(args.qlog_dir); qdir.mkdir(parents=True, exist_ok=True)
    cfg.secrets_log_file = open(qdir / "secrets.log", "w")
    cfg.quic_logger = QuicFileLogger(str(qdir))

    server = await serve(
        args.addr, args.port,
        configuration=cfg,
        create_protocol=lambda *a, **kw: EchoServerProtocol(
            *a,
            cid_interval=args.cid_interval,
            auto_close=args.auto_close,
            close_delay=args.close_delay,
            **kw
        ),
        retry=False,
    )
    logging.info("[server] listening on %s:%d (udp)", args.addr, args.port)
    try:
        await asyncio.Future()
    finally:
        server.close()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
