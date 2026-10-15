# Showcase: where SQLite makes its random numbers

The question: where does a native SQLite build generate random numbers, and what reaches that code? The binary is
`e_sqlite3.dll` for Windows x64 from the public NuGet package
[SQLitePCLRaw.lib.e_sqlite3](https://www.nuget.org/packages/SQLitePCLRaw.lib.e_sqlite3/2.1.11), read from the NuGet
packages folder after a restore. Only the built-in analysis is used (`engine=ours`); no decompiler is needed.

Survey the crypto rules, follow the constant they find to its code, list that function's callers, then record the
three findings as an evidence bundle and check it:

<!-- check: batch show=1,2,3,4,6 -->
```json
{"tool": "load_assembly", "args": {"path": "~/.nuget/packages/sqlitepclraw.lib.e_sqlite3/2.1.11/runtimes/win-x64/native/e_sqlite3.dll"}}
{"tool": "survey_features", "args": {"image": "e_sqlite3.dll", "category": "crypto"}}
{"tool": "find_xrefs", "args": {"image": "e_sqlite3.dll", "address": "0x18016CD88", "engine": "ours"}}
{"tool": "native_call_tree", "args": {"image": "e_sqlite3.dll", "function": "sqlite3_randomness", "direction": "callers", "depth": 1, "engine": "ours"}}
{"tool": "read_result", "args": {"id": "last:3", "format": "evidence", "outputPath": "samples/bin/sqlite-random.json", "overwrite": true}}
{"tool": "read_result", "args": {"id": "samples/bin/sqlite-random.json", "format": "verify"}}
```

<!-- check: output -->
```text
=== [1/6] load_assembly
Loaded native image e_sqlite3.dll: AMD64 DLL, WINDOWS_CUI
  ~/.nuget/packages/sqlitepclraw.lib.e_sqlite3/2.1.11/runtimes/win-x64/native/e_sqlite3.dll
  7 sections, 124 imports, 301 exports, 5093 unwind entries
=== [2/6] survey_features
e_sqlite3.dll: 1 feature(s) in crypto, 2,941 methods or functions scanned.
crypto
  block cipher or stream cipher constants, 1 match
    const:chacha x1
      ChaCha20 / Salsa20 constant @0x18016CD88 in .rdata
Note: native image: rules over static and late-bound imports, call arguments, strings, sections and RTTI class names
=== [3/6] find_xrefs
References to 0x18016CD88 ("expand 32-byte klead"):
Engine: ours (engine=ours: the built-in index; no engine consulted)
2 references (showing 1-2):
  0x180015443  Read       sqlite3_randomness+0x83
  0x1800154B9  Read       sqlite3_randomness+0xF9
[End: 2 references]
=== [4/6] native_call_tree
Engine: ours (engine=ours: the built-in index; no engine consulted)
14 nodes (showing 1-14):
  sqlite3_randomness  0x1800153C0
    sub_1A330  0x18001A330
    sub_1A3F0  0x18001A3F0
    sqlite3_test_control  0x180024710
    sub_76630  0x180076630  (more not shown)
    sub_BE1F0  0x1800BE1F0  (more not shown)
    sub_C53F0  0x1800C53F0  (more not shown)
    sub_103F20  0x180103F20  (more not shown)
    sub_112F40  0x180112F40  (more not shown)
    sub_134E90  0x180134E90  (more not shown)
    sub_13A780  0x18013A780  (more not shown)
    sub_13B3F0  0x18013B3F0  (more not shown)
    sub_144AD0  0x180144AD0  (more not shown)
    sub_149810  0x180149810  (more not shown)
[End: 14 nodes]
=== [6/6] read_result
samples/bin/sqlite-random.json: 3 record(s), 3 verified, 0 differ
  ok  c-2 survey_features: same content
  ok  c-3 find_xrefs: same content
  ok  c-4 native_call_tree: same content
```

- **Survey:** one crypto feature, the ChaCha20 constant `expand 32-byte k` in `.rdata`.
- **Code:** its only readers are two instructions in the exported `sqlite3_randomness`, so the pseudo-random
  generator is built on ChaCha20.
- **Callers:** the call tree lists the 13 functions that call it directly; each is a place where SQLite draws random
  bytes (`sqlite3_test_control` among them).
- **Evidence:** step 5 writes the three calls to a bundle (not shown: its size and hash change with the build); it
  holds each call's arguments, the SHA-256 of the image it ran on and the SHA-256 of its result. `format=verify`
  re-runs every call and names any record whose input or result differs.

The `investigate_feature` prompt walks the same steps for a behaviour of your own.
