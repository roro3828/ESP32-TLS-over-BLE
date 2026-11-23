#!/usr/bin/env python3
"""
Test HTTPS update server for the OTA demo (TLS 1.3 only, runs on the master PC).

The ESP32 reaches it through the BLE tunnel: the central relay opens a TCP
connection to localhost:8443 on the same PC, so no network setup is needed.

  1. Create a test CA and a server certificate (once):
         python ota_server.py init
     This also writes the CA certificate to main/ota_ca.pem, which the firmware
     embeds. Build and flash the firmware after this step.

  2. Issue the device identity (key + certificate signed by the test CA):
         python ota_server.py device
     The device uses it as its TLS client certificate (mTLS to this server) and
     to answer the central's device authentication. It goes into the "fctry"
     NVS partition, not into the app image, so served images carry no key.
     "idf.py build flash" builds and flashes that partition too.

  3. Build a newer firmware (e.g. change version.txt to 1.0.1, then idf.py build;
     do not flash it), and serve it:
         python ota_server.py serve
     It serves build/TLS_over_BLE.bin at https://localhost:8443/firmware.bin
     and only to clients with a certificate from the test CA (mTLS).

  4. Run the central relay with the server allowed and device authentication on:
         python ../central/ble_tunnel_central.py --address XX:XX:XX:XX:XX:XX \
             --allow example.com:443 --allow localhost:8443 --auth-root ../certs/ca.pem

Re-running "init" creates a new CA; devices that embed the old CA can then no
longer update over the air, so it refuses to overwrite unless --force is given.

tools/certs/ and main/ota_ca.pem are not in the repository (.gitignore): every
user creates their own test CA and keys with "init" and "device". Do not commit
or share them: whoever holds ca.key can update devices that embed this CA.
They are for testing only; never use them in a product.
"""
import argparse
import datetime
import http.server
import ipaddress
import os
import ssl
import struct
import sys
import time

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

HERE = os.path.dirname(os.path.abspath(__file__))
PROJECT = os.path.normpath(os.path.join(HERE, "..", ".."))
CERT_DIR = os.path.normpath(os.path.join(HERE, "..", "certs"))   # tools/certs, shared with the central
CA_CERT = os.path.join(CERT_DIR, "ca.pem")
CA_KEY = os.path.join(CERT_DIR, "ca.key")
SRV_CERT = os.path.join(CERT_DIR, "server.pem")
SRV_KEY = os.path.join(CERT_DIR, "server.key")
DEV_CERT = os.path.join(CERT_DIR, "device.pem")
DEV_KEY = os.path.join(CERT_DIR, "device.key")
# The device reads DER from NVS; main/CMakeLists.txt builds the fctry partition from these.
DEV_CERT_DER = os.path.join(CERT_DIR, "device.crt.der")
DEV_KEY_DER = os.path.join(CERT_DIR, "device.key.der")
FW_CA = os.path.join(PROJECT, "main", "ota_ca.pem")
DEFAULT_IMAGE = os.path.join(PROJECT, "build", "TLS_over_BLE.bin")
URL_PATH = "/firmware.bin"

APP_DESC_MAGIC = 0xABCD5432


# ------------------------------------------------------------------ init

def write_pem(path: str, data: bytes) -> None:
    with open(path, "wb") as f:
        f.write(data)


def cmd_init(args) -> None:
    if os.path.exists(CA_CERT) and not args.force:
        sys.exit(f"{CA_CERT} exists. Use --force to create a new CA "
                 "(devices with the old CA can then no longer update over the air).")
    os.makedirs(CERT_DIR, exist_ok=True)
    now = datetime.datetime.now(datetime.timezone.utc)

    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "TLS over BLE OTA test CA")])
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_name).issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(x509.KeyUsage(digital_signature=False, content_commitment=False,
                                     key_encipherment=False, data_encipherment=False,
                                     key_agreement=False, key_cert_sign=True, crl_sign=True,
                                     encipher_only=False, decipher_only=False), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()),
                       critical=False)
        .sign(ca_key, hashes.SHA256())
    )

    srv_key = ec.generate_private_key(ec.SECP256R1())
    srv_cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")]))
        .issuer_name(ca_name)
        .public_key(srv_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=825))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.SubjectAlternativeName([
            x509.DNSName("localhost"),
            x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
        ]), critical=False)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
                       critical=False)
        .sign(ca_key, hashes.SHA256())
    )

    nokey = serialization.NoEncryption()
    write_pem(CA_KEY, ca_key.private_bytes(serialization.Encoding.PEM,
                                           serialization.PrivateFormat.PKCS8, nokey))
    write_pem(SRV_KEY, srv_key.private_bytes(serialization.Encoding.PEM,
                                             serialization.PrivateFormat.PKCS8, nokey))
    ca_pem = ca_cert.public_bytes(serialization.Encoding.PEM)
    write_pem(CA_CERT, ca_pem)
    write_pem(SRV_CERT, srv_cert.public_bytes(serialization.Encoding.PEM))
    write_pem(FW_CA, ca_pem)
    print(f"created {CERT_DIR}")
    print(f"wrote the CA certificate for the firmware to {FW_CA}")
    print("next: python ota_server.py device, then build and flash the firmware")


# ---------------------------------------------------------------- device

def load_ca():
    for p in (CA_CERT, CA_KEY):
        if not os.path.exists(p):
            sys.exit(f"{p} not found; run 'python ota_server.py init' first")
    with open(CA_CERT, "rb") as f:
        ca_cert = x509.load_pem_x509_certificate(f.read())
    with open(CA_KEY, "rb") as f:
        ca_key = serialization.load_pem_private_key(f.read(), password=None)
    return ca_cert, ca_key


def cmd_device(args) -> None:
    ca_cert, ca_key = load_ca()
    cn = args.cn or f"tls-over-ble-dev-{os.urandom(4).hex()}"
    now = datetime.datetime.now(datetime.timezone.utc)

    key = ec.generate_private_key(ec.SECP256R1())
    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)]))
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False,
                                     key_encipherment=False, data_encipherment=False,
                                     key_agreement=False, key_cert_sign=False, crl_sign=False,
                                     encipher_only=False, decipher_only=False), critical=True)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
                       critical=False)
        .sign(ca_key, hashes.SHA256())
    )

    os.makedirs(CERT_DIR, exist_ok=True)
    write_pem(DEV_KEY, key.private_bytes(serialization.Encoding.PEM,
                                         serialization.PrivateFormat.PKCS8,
                                         serialization.NoEncryption()))
    write_pem(DEV_KEY_DER, key.private_bytes(serialization.Encoding.DER,
                                             serialization.PrivateFormat.PKCS8,
                                             serialization.NoEncryption()))
    write_pem(DEV_CERT, cert.public_bytes(serialization.Encoding.PEM))
    write_pem(DEV_CERT_DER, cert.public_bytes(serialization.Encoding.DER))
    print(f"issued device certificate CN={cn} (signed by {ca_cert.subject.rfc4514_string()})")
    print(f"wrote {DEV_CERT}, {DEV_KEY} and the DER copies for the fctry partition")
    print("next: idf.py build flash  (writes the fctry partition with this identity)")


# ----------------------------------------------------------------- serve

def image_version(path: str) -> str:
    """Reads esp_app_desc_t.version from an ESP-IDF app image."""
    with open(path, "rb") as f:
        head = f.read(32 + 48)
    # 24-byte image header + 8-byte segment header, then esp_app_desc_t:
    # magic(4) secure_version(4) reserv1[2](8) version[32]
    if len(head) < 80 or struct.unpack_from("<I", head, 32)[0] != APP_DESC_MAGIC:
        return "?"
    return head[48:80].split(b"\0", 1)[0].decode(errors="replace")


class Handler(http.server.BaseHTTPRequestHandler):
    image = DEFAULT_IMAGE
    server_version = "tls-over-ble-ota-test"

    def _head(self) -> int | None:
        if self.path.split("?", 1)[0] != URL_PATH:
            self.send_error(404)
            return None
        try:
            size = os.path.getsize(self.image)
        except OSError:
            self.send_error(404, "image not built")
            return None
        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(size))
        self.end_headers()
        return size

    def do_HEAD(self) -> None:
        self._head()

    def client_name(self) -> str:
        cert = self.connection.getpeercert()   # verified client certificate (mTLS)
        if not cert:
            return "no client certificate"
        attrs = dict(a for rdn in cert.get("subject", ()) for a in rdn)
        return f"client CN={attrs.get('commonName', '?')}"

    def do_GET(self) -> None:
        size = self._head()
        if size is None:
            return
        print(f"sending {os.path.basename(self.image)} (version {image_version(self.image)}, "
              f"{size} bytes) to {self.client_name()}")
        sent, next_report, t0 = 0, 0, time.monotonic()
        try:
            with open(self.image, "rb") as f:
                while chunk := f.read(4096):
                    self.wfile.write(chunk)
                    sent += len(chunk)
                    if sent * 10 // size >= next_report:
                        dt = max(time.monotonic() - t0, 1e-6)
                        print(f"  {sent * 100 // size:3d}%  {sent:8d} bytes  "
                              f"{sent / 1024 / dt:6.1f} KB/s")
                        next_report = sent * 10 // size + 1
        except (ConnectionError, ssl.SSLError) as e:
            print(f"  aborted by the client after {sent} bytes ({e.__class__.__name__})")
            return
        print(f"  done in {time.monotonic() - t0:.1f} s")

    def log_message(self, fmt: str, *a) -> None:
        print(f"{self.client_address[0]} - {fmt % a}")


class Server(http.server.ThreadingHTTPServer):
    def get_request(self):
        # The TLS handshake (incl. the client certificate check) runs in accept();
        # socketserver drops its errors silently, so report them here.
        try:
            return super().get_request()
        except ssl.SSLError as e:
            print(f"TLS handshake failed: {e.reason or e}")
            raise


def cmd_serve(args) -> None:
    for p in (SRV_CERT, SRV_KEY, CA_CERT):
        if not os.path.exists(p):
            sys.exit(f"{p} not found; run 'python ota_server.py init' first")
    if not os.path.exists(args.image):
        sys.exit(f"{args.image} not found; build the firmware first")
    Handler.image = args.image

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.load_cert_chain(SRV_CERT, SRV_KEY)
    if not args.no_client_auth:
        # mTLS: only clients with a certificate issued by the test CA
        ctx.verify_mode = ssl.CERT_REQUIRED
        ctx.load_verify_locations(CA_CERT)

    httpd = Server((args.bind, args.port), Handler)
    httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
    print(f"serving {args.image} (version {image_version(args.image)}) "
          f"at https://localhost:{args.port}{URL_PATH}  (Ctrl+C to stop)")
    print("client certificate: " + ("not requested" if args.no_client_auth
                                    else f"required (issued by {CA_CERT})"))
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass


def main() -> None:
    sys.stdout.reconfigure(line_buffering=True)   # progress shows up even when piped
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("init", help="create the test CA and server certificate")
    p.add_argument("--force", action="store_true", help="overwrite an existing CA")
    p.set_defaults(func=cmd_init)
    p = sub.add_parser("device", help="issue the device key and client certificate")
    p.add_argument("--cn", help="certificate subject CN (default: tls-over-ble-dev-<random>)")
    p.set_defaults(func=cmd_device)
    p = sub.add_parser("serve", help="serve the firmware image")
    p.add_argument("--image", default=DEFAULT_IMAGE, help="app image to serve")
    p.add_argument("--port", type=int, default=8443)
    p.add_argument("--bind", default="127.0.0.1",
                   help="listen address (default: this PC only)")
    p.add_argument("--no-client-auth", action="store_true",
                   help="do not require a client certificate (no mTLS)")
    p.set_defaults(func=cmd_serve)
    args = ap.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
