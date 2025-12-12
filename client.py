import argparse, asyncio, logging, ssl
from pathlib import Path

from aioquic.asyncio import connect, QuicConnectionProtocol
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import (
    ProtocolNegotiated,
    StreamDataReceived,
    ConnectionTerminated,
)

ALPN = ["hq-interop"]


class RotatingCIDMixin:
    """
    Periodically switches to a fresh outbound Connection ID and logs the active CID hex.
    Shuts down cleanly on connection close.
    """
    def __init__(self, *args, cid_interval: float = 5.0, **kwargs):
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
            return bytes(x)
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
            await asyncio.sleep(0.8)
            while not self._cid_stop.is_set():
                if getattr(self._quic, "is_closing", False) or getattr(self._quic, "_close_pending", False):
                    break
                try:
                    self._quic.change_connection_id()
                    self.transmit()
                    cid_hex = self._current_outbound_cid_hex()
                    logging.info("[%s] rotated CID -> %s", self.__class__.__name__, cid_hex or "<unknown>")
                except AttributeError:
                    logging.warning("change_connection_id() not available in this aioquic version")
                    break
                await asyncio.sleep(self._cid_interval)
        except asyncio.CancelledError:
            pass


class EchoClient(RotatingCIDMixin, QuicConnectionProtocol):
    def __init__(self, *args, message: bytes, hold_secs: float, cid_interval: float, **kwargs):
        super().__init__(*args, cid_interval=cid_interval, **kwargs)
        self._message = message
        self._hold_secs = hold_secs
        self._stream_id = None
        loop = asyncio.get_event_loop()
        self._done = loop.create_future()
        self._buffer = bytearray()

    async def run(self):
        self._stream_id = self._quic.get_next_available_stream_id(is_unidirectional=False)
        self._quic.send_stream_data(self._stream_id, self._message + b"\n", end_stream=True)
        self.transmit()

        await self._done

        if self._hold_secs > 0:
            await asyncio.sleep(self._hold_secs)

        self._quic.close(error_code=0x0, reason_phrase="done")
        self.transmit()

    def quic_event_received(self, event):
        if isinstance(event, ProtocolNegotiated):
            logging.info("[client] ALPN: %s", event.alpn_protocol)
            try:
                self._quic.change_connection_id()
                self.transmit()
                cid_hex = self._current_outbound_cid_hex()
                logging.info("[EchoClient] rotated CID (post-handshake) -> %s", cid_hex or "<unknown>")
                #logging.info("DEBUG host_cids=%r idx=%r pm=%r",
                             #getattr(self._quic, "_host_cids", None),
                             #getattr(self._quic, "_host_cid_in_use", None) or getattr(self._quic, "_connection_id_in_use", None),
                             #type(getattr(self._quic, "_path_manager", None)).__name__ if getattr(self._quic, "_path_manager", None) else None)

            except AttributeError:
                logging.warning("change_connection_id() not available in this aioquic version")

        if isinstance(event, StreamDataReceived) and event.stream_id == self._stream_id:
            self._buffer.extend(event.data)
            if event.end_stream and not self._done.done():
                print(self._buffer.decode(errors="replace").rstrip("\n"))
                self._done.set_result(True)
        elif isinstance(event, ConnectionTerminated):
            if not self._done.done():
                logging.info("[client] connection terminated: %s", event.reason_phrase or "")
                self._done.set_result(True)
            if self._cid_task:
                self._cid_stop.set()
                self._cid_task.cancel()


async def main():
    ap = argparse.ArgumentParser(description="QUIC Echo Client with CID rotation (aioquic)")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8443)
    ap.add_argument("--in", dest="msg", default="hello quic")
    ap.add_argument("--qlog-dir", default=None)
    ap.add_argument("--local-port", type=int, default=0)
    ap.add_argument("--hold", type=float, default=15.0, help="seconds to keep connection open after echo")
    ap.add_argument("--cid-interval", type=float, default=5.0, help="seconds between rotations")
    args = ap.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

    cfg = QuicConfiguration(is_client=True, alpn_protocols=ALPN)
    cfg.connection_id_length = 8
    cfg.verify_mode = ssl.CERT_NONE
    cfg.server_name = "localhost"

    if args.qlog_dir:
        qdir = Path(args.qlog_dir); qdir.mkdir(parents=True, exist_ok=True)
        cfg.secrets_log_file = open(qdir / "secrets.log", "a")

    async with connect(
        args.host, args.port, configuration=cfg,
        create_protocol=lambda *a, **kw: EchoClient(
            *a,
            message=args.msg.encode(),
            hold_secs=args.hold,
            cid_interval=args.cid_interval,
            **kw
        ),
        local_port=args.local_port
    ) as proto:
        await proto.run()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
