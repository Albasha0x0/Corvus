# Prints the records AutoIt-Ripper extracts from a compiled script as JSON: [name, SHA-256, text of script.au3].
# Usage: python -I reference.py <AutoIt-Ripper source folder> <file>
import hashlib
import json
import sys

sys.path.insert(0, sys.argv[1])
from autoit_ripper.autoit_unpack import AutoItVersion, extract  # noqa: E402

data = open(sys.argv[2], 'rb').read()
items = extract(data, AutoItVersion.EA05) or extract(data, AutoItVersion.EA06) or []
out = [[name, hashlib.sha256(content).hexdigest(), content.decode('utf-8') if name == 'script.au3' else None]
       for name, content in items]
sys.stdout.write(json.dumps(out))
