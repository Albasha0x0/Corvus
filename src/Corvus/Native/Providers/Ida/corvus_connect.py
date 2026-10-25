# Serves the database open in IDA to Corvus: run it with File > Script file once the database is open.
# Corvus (CORVUS_IDA_CONNECT=1) connects when the image it reads is this database's input, by SHA-256.
# "idat -A -S"corvus_connect.py once" db" serves one client after the analysis, then closes IDA.
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import ida_worker  # noqa: E402
import idc  # noqa: E402

once = "once" in idc.ARGV[1:]
if once:
    import ida_auto
    ida_auto.auto_wait()
path = ida_worker.serve_connected(once=once)
if once:
    import ida_pro
    ida_pro.qexit(0)
print("Corvus: serving this database; connection file %s" % path)
