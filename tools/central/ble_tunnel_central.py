#!/usr/bin/env python3
"""
Reference central relay for the TLS over BLE tunnel (test / verification tool).

Connects to the device, sends HELLO (+ optional device authentication + TIME),
and relays each OPEN_REQ to a TCP connection. TLS stays end-to-end between the
ESP32 and the server; this tool only sees encrypted bytes.

    pip install -r ../requirements.txt
    python ble_tunnel_central.py --name "TLS over BLE" --allow example.com:443

Pair the device with the OS first (it is also a BLE keyboard). If the OS keeps
it connected and it stops advertising, pass --address (on macOS: the
CoreBluetooth identifier shown by a previous scan).
"""
import argparse
import asyncio
import logging
import os
import socket
import struct
import sys
import time
from datetime import datetime, timezone

from bleak import BleakClient, BleakScanner
from bleak.backends.device import BLEDevice
from bleak.exc import BleakGATTProtocolError

# UUIDs: defaults of the component's Kconfig (CONFIG_TLS_OVER_BLE_*_UUID)
SVC_UUID = "6e7a0001-7c3b-4f5e-9a1d-3b2f0c8e5a10"
RX_UUID = "6e7a0002-7c3b-4f5e-9a1d-3b2f0c8e5a10"
TX_UUID = "6e7a0003-7c3b-4f5e-9a1d-3b2f0c8e5a10"
CTRL_UUID = "6e7a0004-7c3b-4f5e-9a1d-3b2f0c8e5a10"

PROTO_MAJOR, PROTO_MINOR = 1, 0

OP_HELLO, OP_AUTH_CHALLENGE, OP_AUTH_RESPONSE, OP_TIME = 0x01, 0x02, 0x03, 0x04
OP_OPEN_REQ, OP_OPEN_RSP, OP_CREDIT, OP_CLOSE, OP_REMOTE_CLOSED = 0x10, 0x11, 0x12, 0x13, 0x14

TLV_PROTO_VERSION, TLV_APP_VERSION, TLV_RX_BUFFER_SIZE = 0x01, 0x02, 0x03
TLV_DEVICE_CERT, TLV_INTERMEDIATE_CERT, TLV_NONCE_D, TLV_SIGNATURE = 0x10, 0x11, 0x12, 0x13
TLV_HOST, TLV_PORT = 0x20, 0x21

OPEN_OK, OPEN_NOT_AUTH, OPEN_NOT_ALLOWED, OPEN_DNS, OPEN_REFUSED, OPEN_TIMEOUT, OPEN_BUSY = range(7)
CLOSE_NORMAL, CLOSE_VERSION = 0x00, 0x04
FLAG_MORE = 0x01
AUTH_CONTEXT = b"TLS-over-BLE-device-auth-v1"

log = logging.getLogger("central")


def tlv(t: int, v: bytes) -> bytes:
    return struct.pack("<BH", t, len(v)) + v


def parse_tlv(b: bytes) -> dict:
    out, off = {}, 0
    while off + 3 <= len(b):
        t, n = struct.unpack_from("<BH", b, off)
        if off + 3 + n > len(b):
            break
        out[t] = b[off + 3: off + 3 + n]
        off += 3 + n
    return out


class Session:
    def __init__(self, sid: int):
        self.sid = sid
        self.credits = 0
        self.credit_event = asyncio.Event()
        self.writer = None
        self.pump = None
        self.closed = False


class Relay:
    def __init__(self, client: BleakClient, allow: set, auth_root: str | None):
        self.client = client
        self.allow = allow
        self.auth_root = auth_root
        self.authenticated = auth_root is None   # device auth disabled -> allowlist only
        self.max_write = 20
        self.queue: asyncio.Queue = asyncio.Queue()
        self.waiters: dict[int, asyncio.Future] = {}
        self.rx_op = None
        self.rx_buf = bytearray()
        self.session: Session | None = None

    # ---------------------------------------------------------- BLE I/O

    async def write_ctrl(self, op: int, sid: int, payload: bytes = b"") -> None:
        chunk_max = self.max_write - 5
        off = 0
        while True:
            chunk = payload[off: off + chunk_max]
            more = off + len(chunk) < len(payload)
            frame = struct.pack("<BBBH", op, FLAG_MORE if more else 0, sid, len(chunk)) + chunk
            await self.client.write_gatt_char(CTRL_UUID, frame, response=True)
            off += len(chunk)
            if not more:
                return

    def on_ctrl(self, _char, data: bytearray) -> None:
        if len(data) < 5:
            return
        op, flags, sid, n = struct.unpack_from("<BBBH", data, 0)
        if n != len(data) - 5:
            log.warning("control length mismatch")
            return
        if self.rx_op != op:
            self.rx_op, self.rx_buf = op, bytearray()
        self.rx_buf += data[5:]
        if flags & FLAG_MORE:
            return
        self.queue.put_nowait((op, sid, bytes(self.rx_buf)))
        self.rx_op, self.rx_buf = None, bytearray()

    def on_tx(self, _char, data: bytearray) -> None:
        s = self.session
        if s and not s.closed and s.writer and len(data) >= 1 and data[0] == s.sid:
            s.writer.write(bytes(data[1:]))

    def expect(self, op: int) -> asyncio.Future:
        fut = asyncio.get_running_loop().create_future()
        self.waiters[op] = fut
        return fut

    # ---------------------------------------------------------- protocol

    async def handshake(self) -> None:
        fut = self.expect(OP_HELLO)
        await self.write_ctrl(OP_HELLO, 0, tlv(TLV_PROTO_VERSION, bytes([PROTO_MAJOR, PROTO_MINOR])))
        t = parse_tlv(await asyncio.wait_for(fut, 10))
        ver = t.get(TLV_PROTO_VERSION, b"\0\0")
        log.info("device HELLO: protocol %d.%d, app %s, rx buffer %s", ver[0], ver[1],
                 t.get(TLV_APP_VERSION, b"?").decode(errors="replace"),
                 struct.unpack("<I", t[TLV_RX_BUFFER_SIZE])[0] if TLV_RX_BUFFER_SIZE in t else "?")
        if ver[0] != PROTO_MAJOR:
            await self.write_ctrl(OP_CLOSE, 0, bytes([CLOSE_VERSION]))
            raise RuntimeError("protocol major version mismatch")
        if self.auth_root:
            await self.authenticate()
        await self.write_ctrl(OP_TIME, 0, struct.pack("<Q", int(time.time())))

    async def authenticate(self) -> None:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec

        nonce_c = os.urandom(32)
        fut = self.expect(OP_AUTH_RESPONSE)
        await self.write_ctrl(OP_AUTH_CHALLENGE, 0, nonce_c)
        t = parse_tlv(await asyncio.wait_for(fut, 15))
        need = (TLV_DEVICE_CERT, TLV_NONCE_D, TLV_SIGNATURE)
        if not t.get(TLV_DEVICE_CERT) or not all(k in t for k in need):
            log.error("device did not provide an identity; OPEN requests will be refused")
            return
        with open(self.auth_root, "rb") as f:
            root = x509.load_pem_x509_certificate(f.read())
        try:
            dev = x509.load_der_x509_certificate(t[TLV_DEVICE_CERT])
            chain = [dev]
            if t.get(TLV_INTERMEDIATE_CERT):
                # production: root (Ed25519) -> intermediate (ECDSA) -> device
                inter = x509.load_der_x509_certificate(t[TLV_INTERMEDIATE_CERT])
                inter.verify_directly_issued_by(root)
                bc = inter.extensions.get_extension_for_class(x509.BasicConstraints).value
                if not bc.ca:
                    raise ValueError("intermediate is not a CA")
                dev.verify_directly_issued_by(inter)
                chain.append(inter)
            else:
                # empty intermediate: device certificate issued directly by the root
                # (e.g. the test CA of tools/ota_server)
                dev.verify_directly_issued_by(root)
            try:
                if dev.extensions.get_extension_for_class(x509.BasicConstraints).value.ca:
                    raise ValueError("device certificate is a CA certificate")
            except x509.ExtensionNotFound:
                pass
            now = datetime.now(timezone.utc)
            for c in chain:
                if not (c.not_valid_before_utc <= now <= c.not_valid_after_utc):
                    raise ValueError(f"certificate not valid now: {c.subject.rfc4514_string()}")
            msg = AUTH_CONTEXT + nonce_c + t[TLV_NONCE_D]
            dev.public_key().verify(t[TLV_SIGNATURE], msg, ec.ECDSA(hashes.SHA256()))
        except Exception as e:  # noqa: BLE001 - report any verification failure
            log.error("device authentication failed: %s", str(e) or type(e).__name__)
            return
        self.authenticated = True
        log.info("device authenticated: %s", dev.subject.rfc4514_string())

    async def dispatch(self) -> None:
        while self.client.is_connected:
            op, sid, p = await self.queue.get()
            fut = self.waiters.pop(op, None)
            if fut and not fut.done():
                fut.set_result(p)
                continue
            if op == OP_OPEN_REQ:
                asyncio.create_task(self.open_session(sid, p))
            elif op == OP_CREDIT and self.session and sid == self.session.sid and len(p) == 4:
                self.session.credits += struct.unpack("<I", p)[0]
                self.session.credit_event.set()
            elif op == OP_CLOSE:
                if sid == 0:
                    log.warning("device closed the tunnel (reason 0x%02x)", p[0] if p else 0)
                elif self.session and sid == self.session.sid:
                    log.info("session %d closed by device (reason 0x%02x)", sid, p[0] if p else 0)
                    await self.end_session()
            elif op == OP_HELLO:
                log.info("device sent HELLO again")
            else:
                log.debug("ignored op 0x%02x", op)

    async def open_session(self, sid: int, p: bytes) -> None:
        t = parse_tlv(p)
        host = t.get(TLV_HOST, b"").decode(errors="replace")
        port = struct.unpack("<H", t[TLV_PORT])[0] if len(t.get(TLV_PORT, b"")) == 2 else 0
        log.info("OPEN_REQ session %d -> %s:%d", sid, host, port)

        code = OPEN_OK
        if self.session and not self.session.closed:
            code = OPEN_BUSY
        elif not self.authenticated:
            code = OPEN_NOT_AUTH
        elif (host, port) not in self.allow:
            code = OPEN_NOT_ALLOWED
        reader = writer = None
        if code == OPEN_OK:
            try:
                reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), 10)
            except socket.gaierror:
                code = OPEN_DNS
            except asyncio.TimeoutError:
                code = OPEN_TIMEOUT
            except OSError:
                code = OPEN_REFUSED
        if code != OPEN_OK:
            log.warning("OPEN refused: code %d", code)
            await self.write_ctrl(OP_OPEN_RSP, sid, bytes([code]))
            return

        s = Session(sid)
        s.writer = writer
        self.session = s
        await self.write_ctrl(OP_OPEN_RSP, sid, bytes([OPEN_OK]))
        s.pump = asyncio.create_task(self.pump_tcp_to_ble(s, reader))

    async def pump_tcp_to_ble(self, s: Session, reader: asyncio.StreamReader) -> None:
        reason = 0x00   # FIN
        total = 0
        try:
            while True:
                data = await reader.read(4096)
                if not data:
                    break
                off = 0
                while off < len(data):
                    while s.credits <= 0 and not s.closed:
                        s.credit_event.clear()
                        await s.credit_event.wait()
                    if s.closed:
                        return
                    n = min(self.max_write - 1, len(data) - off, s.credits)
                    await self.client.write_gatt_char(RX_UUID, bytes([s.sid]) + data[off: off + n],
                                                      response=False)
                    s.credits -= n
                    off += n
                    total += n
        except (ConnectionError, OSError):
            reason = 0x01   # RST / error
        if not s.closed:
            log.info("server closed (%s) after %d bytes", "FIN" if reason == 0 else "error", total)
            # all data above was written first, so the device sees it before this
            await self.write_ctrl(OP_REMOTE_CLOSED, s.sid, bytes([reason]))

    async def end_session(self) -> None:
        s, self.session = self.session, None
        if not s:
            return
        s.closed = True
        s.credit_event.set()
        if s.pump:
            s.pump.cancel()
        if s.writer:
            s.writer.close()

    async def run(self) -> None:
        await asyncio.sleep(1.0)   # let the MTU exchange finish
        rx = self.client.services.get_characteristic(RX_UUID)
        if rx is None:
            raise RuntimeError("tunnel service not found (check the UUIDs)")
        self.max_write = max(20, rx.max_write_without_response_size)
        log.info("max write %d bytes", self.max_write)
        await self.client.start_notify(CTRL_UUID, self.on_ctrl)
        await self.client.start_notify(TX_UUID, self.on_tx)
        dispatcher = asyncio.create_task(self.dispatch())
        try:
            await self.handshake()
        except BleakGATTProtocolError as e:
            # 0x05: the device has no bond with us / 0x0F: link not encrypted yet
            if e.args[0] not in (0x05, 0x0F) or sys.platform == "darwin":
                raise   # macOS pairs by itself on the first encrypted access
            log.info("link is not encrypted (ATT error 0x%02x); pairing with the device...",
                     e.args[0])
            await self.client.pair()
            log.info("paired")
            await self.handshake()
        log.info("relay ready; waiting for OPEN requests (Ctrl+C to quit)")
        while self.client.is_connected:
            await asyncio.sleep(0.5)
        dispatcher.cancel()
        await self.end_session()


async def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--name", default="TLS over BLE", help="device name to scan for")
    ap.add_argument("--address", help="connect to this address without scanning "
                    "(Windows; the device must be paired with Windows)")
    ap.add_argument("--allow", action="append", default=[],
                    help="allowed destination host:port (repeatable; default example.com:443)")
    ap.add_argument("--auth-root", help="PEM of the root CA; enables device authentication "
                    "(OPEN requests are refused unless the device proves its identity; "
                    "for the OTA demo: tools/certs/ca.pem)")
    ap.add_argument("--scan-timeout", type=float, default=15.0)
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args()
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format="%(asctime)s %(levelname)s %(message)s")

    if args.auth_root and not os.path.isfile(args.auth_root):
        raise SystemExit(f"--auth-root: {args.auth_root} not found "
                         "(the test CA is tools/certs/ca.pem, created by ota_server.py init)")

    allow = set()
    for a in args.allow or ["example.com:443"]:
        host, _, port = a.rpartition(":")
        allow.add((host, int(port)))

    target = args.address
    if target and sys.platform == "win32":
        # A BLEDevice makes bleak open the device directly by address instead of
        # scanning first; needed when Windows keeps the keyboard connected and it
        # no longer advertises.
        target = BLEDevice(target, None, None)
    if not target:
        log.info("scanning for %r or the tunnel service...", args.name)
        dev = await BleakScanner.find_device_by_filter(
            lambda d, ad: (ad.local_name or d.name) == args.name
            or SVC_UUID in [u.lower() for u in ad.service_uuids],
            timeout=args.scan_timeout)
        if dev is None:
            raise SystemExit("device not found (if the OS is connected to it, use --address)")
        target = dev
    async with BleakClient(target) as client:
        log.info("connected to %s", client.address)
        await Relay(client, allow, args.auth_root).run()
    log.info("disconnected")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
