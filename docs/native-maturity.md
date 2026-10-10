# Native track: tool-level reliability

What was run against the native tools (`get_pe_info`, `list_imports`, `list_exports`, `resolve_address`,
`search_bytes`, `read_bytes`, `list_resources` / `get_resource`, `list_functions`, `disassemble`, `get_cfg`,
`find_xrefs`, `native_call_tree`, `search_native_strings`, `list_cpp_classes`, `decompile_native`, and
`load_assembly` / `reload_assembly` / `unload_assembly` on native images), what it found, and what is still open.
Numbers are from one Windows 11 machine (20 logical processors), 2026-10-10; other test runs shared the machine
part of the time, so times are upper bounds.

## Tests

All are `[Trait("Speed", "Slow")]` unless marked quick; run with `-p:NDM_ALL_TESTS=1 --filter ...`.

| Test | What it does |
|---|---|
| `NativeToolSweepTests` | Loads each image through `load_assembly`, calls every tool with arguments taken from the image (entry point, an export, an import, the first / largest / most-called / middle function, a string, every section start, the last byte, each resource type), then reloads and unloads it. Fails on an unexpected exception, an unclassified error, a typed error where the arguments came from the image, a call over its time limit, a result over the response budget (page size + 16,000 characters), a large image whose GC heap passes 16 bytes per file byte + 1 GB, or more than 400 MB left after everything is unloaded. Images of 64 MB and more run one at a time with memory sampled every 100 ms. `NDM_NATIVE_TOOL_SWEEP_LIMIT` (per directory, 0 = all), `NDM_NATIVE_TOOL_SWEEP_PF_LIMIT`, `NDM_NATIVE_TOOL_SWEEP_IDA`. |
| `NativeStdioSweepTests` | The same tools through the real server over stdio on a sample plus the largest installed `msedge.dll` / `chrome.dll`: only typed errors, no protocol error, and the longest gap between indexing progress notifications under 15 s. |
| `NativeToolFuzzTests` | Seeded mutation of 8 seeds (the two synthetic kitchen-sink images, `null.sys`, `notepad.exe`, SysWOW64 `cmd.exe`, `user32.dll.mui`, and a small C++ DLL with RTTI from System32 and from SysWOW64): headers, section table, every directory, import/export tables, entry and function code, code sections, `.pdata`, resource data and RTTI type descriptors. Each mutant is written to disk, loaded with `load_assembly` and given to every tool (30 s per call). Typed errors are fine. `NDM_NATIVE_TOOL_FUZZ_ITERATIONS` (default 2,500, about a minute), `NDM_NATIVE_TOOL_FUZZ_SEED`, `NDM_NATIVE_TOOL_FUZZ_DUMP`. |
| `NativeConcurrencyTests` | 24 tasks calling tools on 7 images (two of them `windows.storage.dll`, large enough that unloads land during their index builds) while 4 tasks load, unload and reload them; then everything is unloaded and every index build seen must end within 30 s. A second test unloads an image during its IDA auto-analysis. `NDM_NATIVE_STRESS_SECONDS`. |
| `NativeAdapterConsistencyTests` | `NativeCodeIndex` and `MsvcRtti` on `PeFile` and on the test-only adapters (`CodeTestImage`, `MsvcTestImage`): same image fields, function starts, xref / string / instruction counts and RTTI classes. `NDM_NATIVE_ADAPTER_SAMPLE`. |
| `NativeToolBoundsTests` (quick) | Zero fill and raw sizes past the end of the file are not scanned; `search_bytes` pages and counts what a naive scan counts; index requests on an unloaded image, a build cancelled under a waiting call and concurrent reloads give conflict errors. |

## Results

| Run | Images | Tool calls | Failures | Time |
|---|---|---|---|---|
| System32 (all native PEs, top level) | 4,526 | 374,902 | 0 | 133 s |
| SysWOW64 (all) | 2,920 | 224,128 | 0 | 114 s |
| System32\drivers (all) | 498 | 47,769 | 0 | 9 s |
| Program Files + Program Files (x86), 1,500 sampled per root (of 52,490 .dll/.exe files) | 3,000 | 189,058 | 0 tool failures (1 memory-sample artifact, fixed in the test) | 18 min |
| Largest: three largest files + two with the most code among the fifteen largest | 5 | 479 | 0 | 228 s |
| Fuzz (final code, seed 20261010) | 25,000 mutants | 1,906,957 | 0; slowest mutant 5 s | 349 s |
| Fuzz (final code, seed 7) | 100,000 mutants | 7,622,219 (572,859 typed errors, 1,646 mutants rejected at load) | 0; slowest mutant 16 s | 21 min |
| Concurrency stress, 120 s | 7 | 26,034 (19,694 ok, 6,340 conflict / not found / not loaded) | 0; 1,199 index builds (526 cancelled), all ended | 124 s |
| stdio | 81 (incl. msedge.dll 333 MB) | 1,562 | 0; longest progress gap 8.0 s | 148 s |
| Adapter cross-check | 800 (400 per directory) | – | 0 differences (1,250,926 functions, 9,418 RTTI classes) | 3 min |

Before the fixes below, the first 25,000-iteration fuzz run failed on 87 mutants (code index runs of 20 s to minutes
on small files, `get_cfg` internal errors), the second on 2 (`search_bytes` and `list_cpp_classes` over 30 s / 120 s);
the first full System32 / SysWOW64 sweep passed apart from `search_bytes` results over the response budget, and the
first stdio run found the 56 s progress gap.

Typed errors seen in the sweeps were `get_cfg` `not_found` on section starts that are no function (`.reloc`,
`.rdata`, ...) and, for ARM64 images under Program Files, `disassemble` / `get_cfg` `unsupported`.
The existing native sweeps still pass after the fixes: `NativeCodeSweepTests` (System32 x64 682,528 functions,
0 of 485,461 `.pdata` starts missing; SysWOW64 729,708 functions), `MsvcRttiTests.SweepSystemImages` (7,368 images,
125,426 classes), `NativePeSweepTests`, `NativePeFuzzTests` (20,000 iterations).

### Large images

| Image | Size | Index wait | All tools | Peak GC heap (incl. garbage) | Peak private bytes |
|---|---|---|---|---|---|
| chrome.dll | 314 MB | 104 s | 118 s | 3.3 GB | 3.7 GB |
| codex.exe (Electron) | 317 MB | 57 s | 71 s | 4.1 GB | 4.2 GB |
| msedge.dll (Program Files run) | 333 MB | 113-129 s | 131-149 s | 3.3-5.0 GB | 3.7-5.4 GB |
| libcef.dll | 183 MB | 86 s | 100 s | 1.6 GB | 3.0 GB |
| cublasLt64_12.dll | 507 MB | 8 s | 21 s | 1.3 GB | 1.8 GB |
| cudnn_engines_precompiled64_9.dll | 424 MB | 0.1 s | 12 s | 2.3 GB | 2.4 GB |
| MRT.exe | 220 MB | 0 s | 4 s | 0.75 GB | 1.1 GB |

Live memory measured step by step on codex.exe (317 MB): 369 MB after loading, 1.15 GB with its index (peak 2.1 GB
while building), 33 MB after unloading. msedge.dll: 988,220 functions, 69 M instructions, 17.5 M references, index
retained 883 MB. A build cancelled by an unload stops within about 5 s on these images.

## Bugs found and fixed

| Tool / area | Input | Symptom | Root cause | Fix |
|---|---|---|---|---|
| code index (`list_functions` and every code tool) | mutated section table: raw size far past the end of the file, section past SizeOfImage | 20 s-minutes on a 20 KB file, up to 1 GB allocated | code regions were the section's raw size, zero fill included | regions are the file-backed part inside SizeOfImage (`FileBackedLength`) |
| `list_cpp_classes` | mutated headers (huge virtual sizes, SizeOfImage 0xFFFFFFFF) | over 120 s, a buffer of up to 512 MB per section | RTTI loaded each section's mapped size | only file-backed bytes, 2x the section limit in total |
| `search_bytes` | the same | 30 s+ scanning gigabytes of zero fill | scanned the mapped size | scans file-backed bytes; matches of all-zero patterns in zero fill are counted |
| `search_bytes` | any image, `limit` 10,000 | up to 350,000 characters (over the response budget); one allocation of the section's whole virtual size (up to 512 MB) | rows not paged; one buffer per section | 1 MB chunks, rows stop at the page size, `offset` parameter |
| `search_bytes` | 500 MB images | 15 s text search | byte-by-byte comparison | vectorized search for the pattern's fixed prefix (2-3 s) |
| `get_cfg` | ARM64 / unknown-machine image | `Error (internal)`: NotSupportedException | no architecture check (`disassemble` had one) | `unsupported` error |
| code tools | unload or reload while a call waits for the index | OperationCanceledException (not a tool error) | the build's cancellation reached the caller | `conflict` error (`LoadedNative.Gone`) |
| workspace | a call that resolved the image before an unload | a new index build nothing cancels | analysis created after the unload | unload / reload mark the image released; later disposable analysis is disposed and the call gets `conflict` |
| workspace | two concurrent reloads of one image | two entries with the same id, one never released | the stale entry was not checked | stale unload / reload is a `conflict` (as main also does) |
| workspace | `Dispose` | index builds and IDA sessions kept running | natives not released | released on dispose |
| `decompile_native` | unload during IDA auto-analysis | the worker kept analyzing (minutes) | open not tied to the image's lifetime | open ends with the image; the waiting call gets `conflict` (57 ms) |
| code index progress | msedge.dll over stdio | no progress for 56 s | progress was the phase's count, which restarts each phase and progress going backwards is dropped | progress is seconds waited; phase and counts in the message |
| code index progress | msedge.dll | 26 s without a report in discovery | candidate verification and gap scans did not report | report at least every 0.5 s |
| function discovery | image reaching the function limit (4 M) | gap scan loops forever | candidate accepted although nothing was added | rejected at the limit |
| `read_bytes`, `native_call_tree` | 64 KB dump, large tree | output cut at 60,000 characters with a footer asking for an `offset` the tools did not take | missing parameters | `offset` / `maxChars` |

## Adapters

`CodeTestImage` and `MsvcTestImage` agree with `PeFile` on every image compared (image fields, imports, exports,
`.pdata`, relocations, TLS callbacks, function starts, reference / string / instruction counts, RTTI classes).
Tests on real files now use `PeFile`; the adapters remain for synthetic images built from code bytes
(`CodeTestImage.Synthetic`) and for reading an image without its relocations (`MsvcTestImage`).

## Limits and known gaps

- Index time on 300 MB browser DLLs is one to two minutes, with a transient GC heap of 3-5 GB (6-15 bytes per file
  byte, garbage included). No bound beyond the 16x heuristic is enforced; a machine with less memory than that cannot
  index such an image.
- A cancelled index build stops at its next cancellation check: up to about 5 s on the largest images.
- `load_assembly` on a native file first tries it as .NET (the whole file is read and parsed by dnlib, then
  discarded) before parsing it as PE: one extra read of the file and garbage of its size.
- Instructions are decoded for x86 and x64 only; ARM64 images get declared functions (`.pdata`, exports) and
  `unsupported` from `disassemble` / `get_cfg`.
- `list_resources` and several .NET tools page with a footer that names an `offset` the tool does not take; for native
  images only `list_resources` is affected (an image with thousands of resources).
- IDA was exercised on a small sample only (`DecompilesThroughIdaAndRecoversCppClasses`, the unload test, and up to
  three sweep images); IDA on the largest images was not measured.
- Program Files was sampled (3,000 of 52,490 files); the adapter cross-check covered 800 of the 7,446 System32 / SysWOW64 images.
- Not covered here: dumpbin agreement for imports / exports (maturity gate item), x86 function recall against IDA.
