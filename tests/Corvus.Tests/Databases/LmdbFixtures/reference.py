# Prints what liblmdb reads from an environment file, one tab-separated record per line (key and value in hex):
#   D <database>                     a named database
#   R <database> <key> <value>       a record of the main database ("") or a named one, duplicates one line each
# Usage: python3 reference.py <file> (needs mdb_dump from lmdb-utils).
import subprocess
import sys


def dump(args):
    text = subprocess.run(["mdb_dump", "-n", *args, sys.argv[1]], capture_output=True, check=True, text=True).stdout
    db, pending = "", None
    for line in text.splitlines():
        if line.startswith("database="):
            db = line[len("database="):]
        elif line.startswith(" "):
            if pending is None:
                pending = line[1:]
            else:
                yield db, pending, line[1:]
                pending = None


named = set()
for db, key, value in dump(["-a"]):
    named.add(db)
    print(f"R\t{db}\t{key}\t{value}")
for db in sorted(named):
    print(f"D\t{db}")
# The main database lists each named database under its name.
for _, key, value in dump([]):
    if bytes.fromhex(key).decode("utf-8", "replace") not in named:
        print(f"R\t\t{key}\t{value}")
