# Builds an HTTP/3 capture with aioquic 1.2.0: a client and a server exchange datagrams in memory (no network), each
# datagram written to http3.pcap as Ethernet/IPv4/UDP between 10.0.0.1:50000 and 10.0.0.2:443. The client's TLS secrets
# go to http3.keys (NSS key log) and both endpoints' events to client.qlog and server.qlog (qlog 0.3 JSON).
# Requests: GET /index.html, GET /data.bin (60,000 bytes), a key update, POST /upload (2,000 bytes), GET /notes.txt
# (gzip), and GET /missing (404). Headers repeat across requests so QPACK inserts and references dynamic table entries.
# With "v2-chacha" as the second argument, QUIC version 2 and ChaCha20-Poly1305 are negotiated and only
# http3-v2-chacha.pcap and http3-v2-chacha.keys are written.
# Usage: python3 build.py [folder] [v2-chacha] (needs aioquic; writes to the folder given, or this one).
import datetime
import gzip
import json
import os
import struct
import sys

from aioquic.buffer import Buffer
from aioquic.h3.connection import H3_ALPN, H3Connection
from aioquic.h3.events import DataReceived, HeadersReceived
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection
from aioquic.quic.logger import QuicLogger
from aioquic.quic.packet import QuicProtocolVersion, pull_quic_header
from aioquic.tls import CipherSuite
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

out = sys.argv[1] if len(sys.argv) > 1 else os.path.dirname(os.path.abspath(__file__))
variant = sys.argv[2] if len(sys.argv) > 2 else ""
stem = "http3-" + variant if variant else "http3"
HOST = "h3.example.test"
CLIENT, SERVER = ("10.0.0.1", 50000), ("10.0.0.2", 443)

key = ec.generate_private_key(ec.SECP256R1())
name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, HOST)])
now_dt = datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc)
cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key()).serial_number(1)
        .not_valid_before(now_dt).not_valid_after(now_dt + datetime.timedelta(days=3650))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(HOST)]), False).sign(key, hashes.SHA256()))

keys = open(os.path.join(out, stem + ".keys"), "w")
client_log, server_log = QuicLogger(), QuicLogger()
ccfg = QuicConfiguration(is_client=True, alpn_protocols=H3_ALPN, server_name=HOST, secrets_log_file=keys, quic_logger=client_log)
ccfg.verify_mode = 0
scfg = QuicConfiguration(is_client=False, alpn_protocols=H3_ALPN, quic_logger=server_log)
scfg.certificate, scfg.private_key = cert, key
if variant == "v2-chacha":
    for cfg in (ccfg, scfg):
        cfg.supported_versions = [QuicProtocolVersion.VERSION_2]
        cfg.cipher_suites = [CipherSuite.CHACHA20_POLY1305_SHA256]

BODIES = {
    "/index.html": (b"text/html", None, b"<html><body>index</body></html>\n"),
    "/data.bin": (b"application/octet-stream", None, bytes((i * 7) % 256 for i in range(60000))),
    "/notes.txt": (b"text/plain", b"gzip", gzip.compress(b"notes line\n" * 400, mtime=0)),
}

frames = []
clock = [1767225600.0]
client = QuicConnection(configuration=ccfg)
client.connect(SERVER, now=clock[0])
server = None
ch3 = sh3 = None


def record(data, src, dst):
    frames.append((clock[0], src, dst, data))


def pump():
    global server, sh3
    moved, quiet = True, 0
    while moved:
        moved = False
        clock[0] += 0.001
        for data, _ in client.datagrams_to_send(now=clock[0]):
            record(data, CLIENT, SERVER)
            if server is None:
                header = pull_quic_header(Buffer(data=data), host_cid_length=8)
                server = QuicConnection(configuration=scfg, original_destination_connection_id=header.destination_cid)
                sh3 = H3Connection(server)
            server.receive_datagram(data, CLIENT, now=clock[0])
            moved = True
        if server is not None:
            for data, _ in server.datagrams_to_send(now=clock[0]):
                record(data, SERVER, CLIENT)
                client.receive_datagram(data, SERVER, now=clock[0])
                moved = True
            moved |= events(server, sh3, serve)
        moved |= events(client, ch3, collect)
        if moved:
            quiet = 0
        elif quiet < 2000:
            # Pacing holds datagrams without a timer, and acknowledgement delays wait on one: step the clock 1 ms at a
            # time, handling timers that fall due, for up to 2 s of quiet.
            quiet += 1
            for c in (client, server):
                if c is not None and (t := c.get_timer()) is not None and t <= clock[0]:
                    c.handle_timer(now=clock[0])
            moved = True


def events(conn, h3, handle):
    seen = False
    while (e := conn.next_event()) is not None:
        seen = True
        if h3 is not None:
            for he in h3.handle_event(e):
                handle(he)
    return seen


uploads = {}


def serve(e):
    if isinstance(e, HeadersReceived):
        h = dict(e.headers)
        uploads[e.stream_id] = [h[b":method"], h[b":path"].decode(), b""]
        if e.stream_ended:
            answer(e.stream_id)
    elif isinstance(e, DataReceived):
        uploads[e.stream_id][2] += e.data
        if e.stream_ended:
            answer(e.stream_id)


def answer(stream_id):
    method, path, body = uploads[stream_id]
    if method == b"POST":
        mime, enc, data, status = b"text/plain", None, b"received %d bytes\n" % len(body), b"201"
    elif path in BODIES:
        mime, enc, data = BODIES[path]
        status = b"200"
    else:
        mime, enc, data, status = b"text/plain", None, b"not found\n", b"404"
    headers = [(b":status", status), (b"server", b"fixture"), (b"content-type", mime), (b"content-length", str(len(data)).encode())]
    if enc:
        headers.append((b"content-encoding", enc))
    sh3.send_headers(stream_id, headers)
    sh3.send_data(stream_id, data, end_stream=True)


def collect(e):
    pass


def request(path, method=b"GET", body=b""):
    sid = client.get_next_available_stream_id()
    headers = [(b":method", method), (b":scheme", b"https"), (b":authority", HOST.encode()), (b":path", path.encode()),
               (b"user-agent", b"fixture-client/1.0"), (b"accept", b"*/*")]
    if body:
        headers += [(b"content-type", b"application/octet-stream"), (b"content-length", str(len(body)).encode())]
    ch3.send_headers(sid, headers, end_stream=not body)
    if body:
        ch3.send_data(sid, body, end_stream=True)
    pump()


pump()
ch3 = H3Connection(client)
pump()
request("/index.html")
request("/data.bin")
client.request_key_update()
request("/upload", b"POST", bytes(range(250)) * 8)
request("/notes.txt")
request("/missing")
client.close(error_code=0x100)
pump()
keys.close()

with open(os.path.join(out, stem + ".pcap"), "wb") as f:
    f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
    for i, (t, (sip, sport), (dip, dport), data) in enumerate(frames):
        udp = struct.pack(">HHHH", sport, dport, 8 + len(data), 0) + data
        ip = struct.pack(">BBHHHBBH4s4s", 0x45, 0, 20 + len(udp), i & 0xFFFF, 0x4000, 64, 17, 0,
                         bytes(map(int, sip.split("."))), bytes(map(int, dip.split("."))))
        s = sum(struct.unpack(">10H", ip))
        s = (s & 0xFFFF) + (s >> 16)
        ip = ip[:10] + struct.pack(">H", ~((s & 0xFFFF) + (s >> 16)) & 0xFFFF) + ip[12:]
        eth = bytes.fromhex("020000000002020000000001") + b"\x08\x00"
        pkt = eth + ip + udp
        f.write(struct.pack("<IIII", int(t), int(round((t - int(t)) * 1e6)), len(pkt), len(pkt)) + pkt)

for log, file in () if variant else ((client_log, "client.qlog"), (server_log, "server.qlog")):
    with open(os.path.join(out, file), "w") as f:
        json.dump(log.to_dict(), f, separators=(",", ":"))

print(f"{len(frames)} datagrams; {len(uploads)} requests answered")
