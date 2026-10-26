# Prints what libdb reads from a Berkeley DB file, one tab-separated line per database and record:
#   D <database> <kind>             kind: btree, hash, recno or queue; the database of a single-database file is ""
#   R <database> <key> <value>      key and value in hex; a recno or queue record's key is #<number>
# Duplicates are one line each, in cursor order.
# Usage: python3 reference.py <file> (needs the berkeleydb module).
import sys

from berkeleydb import db

KINDS = {db.DB_BTREE: "btree", db.DB_HASH: "hash", db.DB_RECNO: "recno", db.DB_QUEUE: "queue"}


def records(path, name):
    d = db.DB()
    d.open(path, name, db.DB_UNKNOWN, db.DB_RDONLY)
    kind = KINDS.get(d.get_type(), "other")
    print(f"D\t{name or ''}\t{kind}")
    c = d.cursor()
    item = c.first()
    while item:
        key, value = item
        print(f"R\t{name or ''}\t{'#%d' % key if isinstance(key, int) else key.hex()}\t{value.hex()}")
        item = c.next()
    c.close()
    d.close()


path = sys.argv[1]
master = db.DB()
master.open(path, None, db.DB_UNKNOWN, db.DB_RDONLY)
# A file of named databases lists them in its master btree; a key that opens as no database means a single database.
names = [k for k in master.keys()] if master.get_type() == db.DB_BTREE else []
master.close()
try:
    for n in names:
        sub = db.DB()
        sub.open(path, n.decode(), db.DB_UNKNOWN, db.DB_RDONLY)
        sub.close()
except (db.DBError, UnicodeDecodeError):
    names = []
if names:
    for n in names:
        records(path, n.decode())
else:
    records(path, None)
