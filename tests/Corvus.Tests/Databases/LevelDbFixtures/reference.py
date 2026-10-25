# Prints what libleveldb reads from a database folder, one tab-separated record per line (keys in hex):
#   L <key> <SHA-256 of the value>                      a live record, from plyvel iterating a copy of the folder
#   R <file> <key> <sequence> <put|del> <SHA-256>       a record of a table or log file, from leveldbutil dump
# Usage: python3 reference.py <folder> <leveldbutil>
import hashlib
import os
import re
import shutil
import subprocess
import sys
import tempfile

import plyvel

folder, dump = sys.argv[1], sys.argv[2]


def sha(b):
    return hashlib.sha256(b).hexdigest()


def unescape(s):
    # leveldbutil writes bytes outside ' '..'~' as \xNN but a backslash as itself, so a key or value holding a
    # backslash before "x" and two hex digits reads back wrong: compared databases hold no backslash bytes.
    out = bytearray()
    i = 0
    while i < len(s):
        if s.startswith("\\x", i):
            out.append(int(s[i + 2:i + 4], 16))
            i += 4
        else:
            out.append(ord(s[i]))
            i += 1
    return bytes(out)


# Opening replays the logs into new files, so plyvel reads a copy.
work = tempfile.mkdtemp()
try:
    copy = os.path.join(work, "db")
    shutil.copytree(folder, copy)
    db = plyvel.DB(copy)
    for k, v in db:
        print(f"L\t{k.hex()}\t{sha(v)}")
    db.close()
finally:
    shutil.rmtree(work)

table = re.compile(r"^'(.*?)' @ (\d+) : (val|del) => '(.*)'$")
put = re.compile(r"^  put '(.*?)' '(.*)'$")
delete = re.compile(r"^  del '(.*)'$")
for name in sorted(os.listdir(folder)):
    if not name.endswith((".ldb", ".sst", ".log")):
        continue
    text = subprocess.run([dump, "dump", os.path.join(folder, name)], capture_output=True, check=True).stdout.decode("latin-1")
    seq = 0
    for line in text.splitlines():
        if m := table.match(line):
            print(f"R\t{name}\t{unescape(m[1]).hex()}\t{m[2]}\t{'put' if m[3] == 'val' else 'del'}\t{sha(unescape(m[4])) if m[3] == 'val' else ''}")
        elif line.startswith("--- offset ") and "; sequence " in line:
            seq = int(line.rsplit(" ", 1)[1])
        elif m := put.match(line):
            print(f"R\t{name}\t{unescape(m[1]).hex()}\t{seq}\tput\t{sha(unescape(m[2]))}")
            seq += 1
        elif m := delete.match(line):
            print(f"R\t{name}\t{unescape(m[1]).hex()}\t{seq}\tdel\t")
            seq += 1
