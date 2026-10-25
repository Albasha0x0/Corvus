# Writes a type 2 AppImage: a 64-bit ELF header with "AI" 2 at ident offset 8, an update information section,
# an empty signature section and a section name table, then the squashfs image right after the section headers,
# where the AppImage runtime looks for it.
# Usage: python3 stub.py <squashfs> <output>
import struct
import sys

update = b"gh-releases-zsync|example|ledger|latest|Ledger-*x86_64.AppImage.zsync".ljust(1024, b"\0")
signature = bytes(1024)
names = b"\0.upd_info\0.sha256_sig\0.shstrtab\0"
data_at = 64
sections = [(0, 0, 0, 0)]
offset = data_at
for name, body in ((b".upd_info", update), (b".sha256_sig", signature), (b".shstrtab", names)):
    sections.append((names.index(name + b"\0"), 3 if name == b".shstrtab" else 1, offset, len(body)))
    offset += len(body)
shoff = offset
ident = b"\x7fELF" + bytes([2, 1, 1, 0]) + b"AI\x02" + bytes(5)
header = ident + struct.pack("<HHIQQQIHHHHHH", 2, 0x3E, 1, 0, 0, shoff, 0, 64, 0, 0, 64, len(sections), len(sections) - 1)
table = b"".join(struct.pack("<IIQQQQIIQQ", n, t, 0, 0, off, size, 0, 0, 1, 0) for n, t, off, size in sections)
with open(sys.argv[1], "rb") as f:
    image = f.read()
with open(sys.argv[2], "wb") as f:
    f.write(header + update + signature + names + table + image)
