# Builds ledger.mdb with python3-lmdb (liblmdb 0.9.24, 4 KiB pages), one file without a lock file (subdir=False):
#   main      200 account records and a 10,000-byte statement (overflow pages)
#   journal   300 records
#   tags      duplicate values: "small" in a sub-page, "large" (400 values) in a sub-database
#   fixed     duplicate 8-byte values (DUPFIXED) under one key
# A transaction then overwrites 20 accounts and deletes 10, and a last one adds a journal record: the freed pages keep
# the old account data.
# Usage, from this folder: python3 build.py
import os

import lmdb

path = os.path.join(os.getcwd(), "ledger.mdb")
for f in (path, path + "-lock"):
    if os.path.exists(f):
        os.remove(f)
env = lmdb.open(path, subdir=False, map_size=4 << 20, max_dbs=4, lock=False)
journal = env.open_db(b"journal")
tags = env.open_db(b"tags", dupsort=True)
fixed = env.open_db(b"fixed", dupsort=True, dupfixed=True)
with env.begin(write=True) as txn:
    for i in range(1, 201):
        txn.put(f"account/{i:04}".encode(), f"owner=holder{i}; balance={i * 37 % 1000}.{i % 100:02}".encode())
    txn.put(b"statement/2026", b"".join(f"line {i:05}: settled\n".encode() for i in range(500))[:10000])
    for i in range(1, 301):
        txn.put(f"entry/{i:04}".encode(), f"transfer {i * 13 % 500}.00 from holder{i % 200 + 1}".encode(), db=journal)
    for v in (b"red", b"green", b"blue"):
        txn.put(b"small", v, db=tags)
    for i in range(400):
        txn.put(b"large", f"value-{i:04}".encode(), db=tags)
    for i in range(50):
        txn.put(b"ids", i.to_bytes(8, "big"), db=fixed)
with env.begin(write=True) as txn:
    for i in range(1, 21):
        txn.put(f"account/{i:04}".encode(), f"owner=holder{i}; balance=0.00; closed".encode())
    for i in range(191, 201):
        txn.delete(f"account/{i:04}".encode())
# A journal-only transaction: the account pages the previous one freed are no longer reached from either meta page.
with env.begin(write=True) as txn:
    txn.put(b"entry/0301", b"transfer 13.00 from holder2", db=journal)
env.close()
