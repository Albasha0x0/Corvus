# Writes constructs-<version>.pyc and its dis.dis output (.dis) with the running Python (2.7 or 3.x). The .pyc header has
# a zero timestamp and size; code objects print without their address, as Corvus prints them. 3.0 to 3.7 compile
# constructs-3.0.py, the same program without the syntax of later releases.
import dis, io, marshal, os, re, sys

here = os.path.dirname(os.path.abspath(__file__))
version = "%d.%d" % sys.version_info[:2]
source = "constructs-2.7.py" if sys.version_info[0] == 2 else "constructs-3.0.py" if sys.version_info < (3, 8) else "constructs.py"
with open(os.path.join(here, source), "rb") as f:
    # 3.0 and 3.1 do not compile source bytes with CRLF line ends.
    code = compile(f.read().replace(b"\r\n", b"\n"), "constructs.py", "exec", dont_inherit=True)
if sys.version_info >= (3, 4):
    import importlib.util
    magic = importlib.util.MAGIC_NUMBER
else:
    import imp
    magic = imp.get_magic()
header = 16 if sys.version_info >= (3, 7) else 12 if sys.version_info >= (3, 3) else 8
with open(os.path.join(here, "constructs-%s.pyc" % version), "wb") as f:
    f.write(magic + b"\0" * (header - 4) + marshal.dumps(code))

out = io.StringIO() if sys.version_info[0] == 3 else io.BytesIO()
saved = sys.stdout
sys.stdout = out
try:
    def walk(c):
        # Dis before 3.7 does not descend into nested code objects: printed here as
        # 3.7 does.
        dis.dis(c)
        if sys.version_info < (3, 7):
            for x in c.co_consts:
                if hasattr(x, "co_code"):
                    print("")
                    print("Disassembly of %r:" % (x,))
                    walk(x)
    walk(code)
finally:
    sys.stdout = saved
text = out.getvalue()
if sys.version_info[0] == 2:
    text = text.decode("latin-1")
text = re.sub(r"<code object (\S+) at (0x)?[0-9a-fA-F]+, ", r"<code object \1, ", text)
with io.open(os.path.join(here, "constructs-%s.dis" % version), "w", encoding="utf-8", newline="\n") as f:
    f.write(text)
print(version)
