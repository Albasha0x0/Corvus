# Builds the LevelDB fixtures with plyvel (libleveldb 1.23), one database per block compression:
#   ledger-snappy/, ledger-none/  200 account records compacted into a table; 20 overwritten, 5 deleted and 1,000
#                                 journal records flushed to a level-0 table; 10 more deleted and two keys added
#                                 (binary bytes, a Local Storage style key) left in the write-ahead log
# Usage, from this folder: python3 build.py
import os
import shutil
import tempfile
import time

import plyvel

for compression in ("snappy", None):
    name = f"ledger-{compression or 'none'}"
    work = tempfile.mkdtemp()
    db = plyvel.DB(work, create_if_missing=True, compression=compression, block_size=512, write_buffer_size=65536)
    for i in range(1, 201):
        db.put(f"account/{i:04}".encode(), f"owner=holder{i}; balance={i * 37 % 1000}.{i % 100:02}".encode())
    db.compact_range()
    # Over the 64 KiB minimum write buffer: the next write flushes this batch to a level-0 table above the compacted one.
    with db.write_batch() as batch:
        for i in range(1, 21):
            batch.put(f"account/{i:04}".encode(), f"owner=holder{i}; balance=0.00; closed".encode())
        for i in range(181, 186):
            batch.delete(f"account/{i:04}".encode())
        for i in range(1, 1001):
            batch.put(f"journal/{i:04}".encode(), f"entry {i}: transfer {i * 13 % 500}.00 from holder{i % 200 + 1}".encode())
    with db.write_batch() as batch:
        for i in range(191, 201):
            batch.delete(f"account/{i:04}".encode())
    # This write starts the flush in the background; closing first would cut it off.
    time.sleep(1)
    db.put(b"meta/\x00\x01\xff", bytes(range(16)))
    db.put(b"_https://ledger.test\x00\x01title", b"\x01Ledger")
    db.close()
    out = os.path.join(os.getcwd(), name)
    shutil.rmtree(out, ignore_errors=True)
    os.mkdir(out)
    # The info log (LOG) and the lock file carry nothing the reader needs.
    for f in sorted(os.listdir(work)):
        if f not in ("LOCK", "LOG", "LOG.old"):
            shutil.copy(os.path.join(work, f), out)
    shutil.rmtree(work)
    print(name, sorted(os.listdir(out)))
