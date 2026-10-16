# Writes TLS sessions (OpenSSL through Python's ssl, memory BIOs) with their key log, as base64 lines:
# "# <comment>", "session <name>", "key <keylog line>", "c <client bytes>", "s <server bytes>".
import base64, datetime, gzip, os, ssl, sys, tempfile
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

out_path = sys.argv[1]
work = tempfile.mkdtemp()
key = ec.generate_private_key(ec.SECP256R1())
name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "tls.example.com")])
now = datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc)
cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key()).serial_number(1)
        .not_valid_before(now).not_valid_after(now + datetime.timedelta(days=3650))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("tls.example.com")]), False).sign(key, hashes.SHA256()))
cert_file, key_file = os.path.join(work, "c.pem"), os.path.join(work, "k.pem")
open(cert_file, "wb").write(cert.public_bytes(serialization.Encoding.PEM))
open(key_file, "wb").write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))

def session(label, version, cipher, request, response, alpn=None):
    log = os.path.join(work, label + ".keys")
    sctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    sctx.load_cert_chain(cert_file, key_file)
    cctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    cctx.check_hostname = False
    cctx.verify_mode = ssl.CERT_NONE
    cctx.keylog_filename = log
    for ctx in (sctx, cctx):
        ctx.minimum_version = ctx.maximum_version = version
        if cipher and version != ssl.TLSVersion.TLSv1_3:
            ctx.set_ciphers(cipher)
        if alpn:
            ctx.set_alpn_protocols(alpn)
    cin, cout, sin, sout = ssl.MemoryBIO(), ssl.MemoryBIO(), ssl.MemoryBIO(), ssl.MemoryBIO()
    c = cctx.wrap_bio(cin, cout, server_hostname="tls.example.com")
    s = sctx.wrap_bio(sin, sout, server_side=True)
    lines = []

    def pump():
        moved = True
        while moved:
            moved = False
            data = cout.read()
            if data:
                lines.append("c " + base64.b64encode(data).decode()); sin.write(data); moved = True
            data = sout.read()
            if data:
                lines.append("s " + base64.b64encode(data).decode()); cin.write(data); moved = True

    done = [False, False]
    while not all(done):
        for i, side in enumerate((c, s)):
            if done[i]:
                continue
            try:
                side.do_handshake(); done[i] = True
            except ssl.SSLWantReadError:
                pass
        pump()
    c.write(request); pump()
    got = b""
    while len(got) < len(request):
        got += s.read(); pump()
    s.write(response); pump()
    got = b""
    while len(got) < len(response):
        try:
            got += c.read()
        except ssl.SSLWantReadError:
            pump()
    c.unwrap() if False else None
    keys = [l.strip() for l in open(log) if l.strip() and not l.startswith("#")]
    return [f"session {label} {c.version()} {c.cipher()[0]}"] + ["key " + k for k in keys] + lines

body = gzip.compress(b'{"user":{"id":7,"name":"Ada"}}', mtime=0)
request = b"GET /api/me?token=t HTTP/1.1\r\nHost: tls.example.com\r\nAccept-Encoding: gzip\r\n\r\n"
response = (b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Encoding: gzip\r\nContent-Length: " + str(len(body)).encode()
            + b"\r\n\r\n" + body)
chunked = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n"
out = ["# TLS sessions made by OpenSSL " + ssl.OPENSSL_VERSION.split()[1] + " through Python's ssl module and memory BIOs (TlsSessions.py): each session's",
       "# key log lines, then the bytes each side wrote, in order (c: client, s: server), base64."]
out += session("tls13", ssl.TLSVersion.TLSv1_3, None, request, response)
out += session("tls12-aes128gcm", ssl.TLSVersion.TLSv1_2, "ECDHE-ECDSA-AES128-GCM-SHA256", request.replace(b"/api/me", b"/api/v12"), chunked)
out += session("tls12-chacha", ssl.TLSVersion.TLSv1_2, "ECDHE-ECDSA-CHACHA20-POLY1305", request.replace(b"/api/me", b"/api/chacha"), response)
out += session("tls12-aes256gcm", ssl.TLSVersion.TLSv1_2, "ECDHE-ECDSA-AES256-GCM-SHA384", request.replace(b"/api/me", b"/api/sha384"), response)
open(out_path, "w", newline="\n").write("\n".join(out) + "\n")
