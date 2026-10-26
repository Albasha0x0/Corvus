# Builds the Berkeley DB fixtures with the berkeleydb module on libdb 5.3.28:
#   ledger.db      little-endian, 4 KiB pages, one database per access method in one file:
#                    accounts  btree, 200 records and a 10,000-byte statement (overflow pages); 20 overwritten, 10 deleted
#                    tags      btree with sorted duplicates: "small" on the leaf page, "large" (400 values) in an
#                              off-page duplicate tree
#                    journal   recno, 300 records; 5 deleted
#                    index     hash, 300 records; 10 deleted
#   queue.db       queue, 100 fixed-length 32-byte records; 5 consumed
#   ledger-be.db   big-endian, 512-byte pages, btree only: 300 records over a three-level tree
# Usage, from this folder: python3 build.py
import os

from berkeleydb import db

here = os.getcwd()
for name in ("ledger.db", "queue.db", "ledger-be.db"):
    if os.path.exists(os.path.join(here, name)):
        os.remove(os.path.join(here, name))


def open_db(name, sub, kind, pagesize=4096, lorder=1234, flags=0):
    d = db.DB()
    d.set_pagesize(pagesize)
    d.set_lorder(lorder)
    if flags:
        d.set_flags(flags)
    d.open(os.path.join(here, name), sub, kind, db.DB_CREATE)
    return d


accounts = open_db("ledger.db", "accounts", db.DB_BTREE)
for i in range(1, 201):
    accounts.put(f"account/{i:04}".encode(), f"owner=holder{i}; balance={i * 37 % 1000}.{i % 100:02}".encode())
accounts.put(b"statement/2026", b"".join(f"line {i:05}: settled\n".encode() for i in range(500))[:10000])
for i in range(1, 21):
    accounts.put(f"account/{i:04}".encode(), f"owner=holder{i}; balance=0.00; closed".encode())
for i in range(191, 201):
    accounts.delete(f"account/{i:04}".encode())
accounts.close()

tags = open_db("ledger.db", "tags", db.DB_BTREE, flags=db.DB_DUPSORT)
for v in (b"red", b"green", b"blue"):
    tags.put(b"small", v)
for i in range(400):
    tags.put(b"large", f"value-{i:04}".encode())
tags.close()

journal = open_db("ledger.db", "journal", db.DB_RECNO)
for i in range(1, 301):
    journal.append(f"transfer {i * 13 % 500}.00 from holder{i % 200 + 1}".encode())
for i in range(296, 301):
    journal.delete(i)
journal.close()

index = open_db("ledger.db", "index", db.DB_HASH)
for i in range(1, 301):
    index.put(f"holder{i}".encode(), f"account/{i % 200 + 1:04}".encode())
for i in range(291, 301):
    index.delete(f"holder{i}".encode())
index.close()

queue = db.DB()
queue.set_re_len(32)
queue.set_re_pad(0x20)
queue.set_pagesize(4096)
queue.open(os.path.join(here, "queue.db"), None, db.DB_QUEUE, db.DB_CREATE)
for i in range(1, 101):
    queue.append(f"job {i:03}: export ledger".encode())
for _ in range(5):
    queue.consume()
queue.close()

big = open_db("ledger-be.db", None, db.DB_BTREE, pagesize=512, lorder=4321)
for i in range(1, 301):
    big.put(f"entry/{i:04}".encode(), f"transfer {i * 13 % 500}.00 from holder{i % 200 + 1}".encode())
big.close()

for name in ("ledger.db", "queue.db", "ledger-be.db"):
    print(f"{name}: {os.path.getsize(os.path.join(here, name)):,} bytes")
