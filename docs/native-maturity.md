# Native tools: reliability and accuracy

The tests run against the native tools (`get_pe_info`, `list_imports`, `list_exports`, `resolve_address`,
`search_bytes`, `read_bytes`, `list_resources` / `get_resource`, `list_functions`, `disassemble`, `get_cfg`,
`find_xrefs`, `native_call_tree`, `search_native_strings`, `list_cpp_classes`, `decompile_native`, and
`load_assembly` / `reload_assembly` / `unload_assembly` on native images), their results, and what is open.
One Windows 11 machine (20 logical processors), 2026-10-10; other runs shared it at times, so times are upper bounds.

## Tests

All are `[Trait("Speed", "Slow")]` unless marked quick; run with `-p:CORVUS_ALL_TESTS=1 --filter ...`.

| Test | What it does |
|---|---|
| `NativeToolSweepTests` | Loads each image through `load_assembly`, calls every tool with arguments taken from the image (entry point, an export, an import, the first / largest / most-called / middle function, a string, every section start, the last byte, each resource type), then reloads and unloads it. Fails on an unexpected exception, an unclassified error, a typed error where the arguments came from the image, a call over its time limit, a result over the response budget (page size + 16,000 characters), a large image whose GC heap passes 16 bytes per file byte + 1 GB, or more than 400 MB left after everything is unloaded. Images of 64 MB and more run one at a time with memory sampled every 100 ms. `CORVUS_NATIVE_TOOL_SWEEP_LIMIT` (per directory, 0 = all), `CORVUS_NATIVE_TOOL_SWEEP_PF_LIMIT`, `CORVUS_NATIVE_TOOL_SWEEP_IDA`. |
| `NativeStdioSweepTests` | The same tools through the real server over stdio on a sample plus the largest installed `msedge.dll` / `chrome.dll`: only typed errors, no protocol error, and the longest gap between indexing progress notifications under 15 s. |
| `NativeToolFuzzTests` | Seeded mutation of 8 seeds (the two synthetic test images, `null.sys`, `notepad.exe`, SysWOW64 `cmd.exe`, `user32.dll.mui`, and a small C++ DLL with RTTI from System32 and from SysWOW64): headers, section table, every directory, import/export tables, entry and function code, code sections, `.pdata`, resource data and RTTI type descriptors. Each mutant is written to disk, loaded with `load_assembly` and given to every tool (30 s per call). Typed errors are fine. `CORVUS_NATIVE_TOOL_FUZZ_ITERATIONS` (default 2,500, about a minute), `CORVUS_NATIVE_TOOL_FUZZ_SEED`, `CORVUS_NATIVE_TOOL_FUZZ_DUMP`. |
| `NativeConcurrencyTests` | 24 tasks calling tools on 7 images (two of them `windows.storage.dll`, large enough that unloads land during their index builds) while 4 tasks load, unload and reload them; then everything is unloaded and every index build seen must end within 30 s. A second test unloads an image during its IDA auto-analysis. `CORVUS_NATIVE_STRESS_SECONDS`. |
| `NativeAdapterConsistencyTests` | `NativeCodeIndex` and `MsvcRtti` on `PeFile` and on the test-only adapters (`CodeTestImage`, `MsvcTestImage`): same image fields, function starts, xref / string / instruction counts and RTTI classes. `CORVUS_NATIVE_ADAPTER_SAMPLE`. |
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

Before the fixes: the first 25,000-iteration fuzz run failed on 87 mutants (code index runs of 20 s to minutes on
small files, `get_cfg` internal errors), the second on 2 (`search_bytes` / `list_cpp_classes` over 30 s / 120 s); the
first System32 / SysWOW64 sweep failed only on `search_bytes` results over the response budget; the first stdio run
found a 56 s progress gap.

Typed errors in the sweeps: `get_cfg` `not_found` on section starts that are no function (`.reloc`, `.rdata`, ...)
and, in that run, `disassemble` / `get_cfg` `unsupported` on ARM64 images under Program Files (ARM64 is decoded
since). The existing native sweeps still pass after the fixes: `NativeCodeSweepTests` (System32 x64 682,528 functions,
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

Live memory on codex.exe (317 MB): 369 MB loaded, 1.15 GB with its index (peak 2.1 GB while building), 33 MB after
unloading. msedge.dll: 988,220 functions, 69 M instructions, 17.5 M references, index
retained 883 MB. A build cancelled by an unload stops within about 5 s on these images.

## Tested engine versions

The full suite before each release runs against these (pinned in `tests/Corvus.Tests/Support/remote-tools-assets.json`);
older versions inside the supported range are not tested.

| Engine | Supported | Tested |
|---|---|---|
| IDA Pro (idalib) | 9.0 or newer (older is refused) | 9.3, with Python 3.12 |
| Ghidra | 12.0 or newer | 12.1.4 (and 12.0.4), with JDK 24.0.1+9; on 12.0 `emulate_native` reads unmapped memory as zero instead of stopping (12.1's emulator says why it reads) |
| JADX headless server (`decompile_java`) | jadx-headless-mcp fat jar | 0.7.1, with JDK 24.0.1+9 |

## Limits and known gaps

- Indexing a 300 MB browser DLL takes one to two minutes with a transient GC heap of 3-5 GB (6-15 bytes per file
  byte, garbage included). No bound beyond the 16x heuristic is enforced; a machine with less memory cannot index it.
- A cancelled index build stops at its next cancellation check: up to about 5 s on the largest images.
- `load_assembly` on a native file first tries it as .NET (dnlib reads and parses the whole file, then discards it):
  one extra read and garbage of the file's size.
- The built-in analysis decodes x86, x64, ARM64 and 32-bit ARM (A32 and Thumb-2; ARMv8 AES / SHA / VMULL.P64
  included, other rare SIMD encodings decode as `simd` without operands). WebAssembly has its own bytecode reader.
  Other instruction sets (MIPS, PPC, RISC-V, ...) get only the function starts the image declares; disassembly and
  decompilation of them need IDA or Ghidra.
- A function's ARM / Thumb state comes from symbols, mapping symbols, BL / BLX and code pointers, else from decoding
  its first words in both states and their prologues; when both read plausibly the image's prevailing state is taken
  and `list_functions` tags the function "state guessed" (stripped libSkiaSharp armv7: 18,219 of 18,219 functions
  right, IDA 15,781 of 15,781; static busybox armhf: 99.82% agreement with IDA).
- `list_resources` and several .NET tools page with a footer naming an `offset` the tool does not take; among native
  tools only `list_resources` is affected (images with thousands of resources).
- IDA was exercised on a small sample only (`DecompilesThroughIdaAndRecoversCppClasses`, the unload test, and up to
  three sweep images); IDA on the largest images was not measured.
- Program Files was sampled (3,000 of 52,490 files); the adapter cross-check covered 800 of 7,446 System32 /
  SysWOW64 images.

## Agreement with other tools

Measured by the component test suites (all `Speed=Slow`), not by the tool sweeps above.

| Component | Reference | Sample | Result |
|---|---|---|---|
| PE parser (`NativePeSweepTests`) | dumpbin (imports, delay / bound imports, exports, load config, SEH and CFG tables), `System.Reflection.PortableExecutable` (headers, sections), AsmResolver (imports, exports, relocations, TLS, `.pdata`, CodeView, resources), ImageHlp `CheckSumMappedFile`, `FileVersionInfo` | 15,031 System32 / SysWOW64 files (15,025 PE) | 0 disagreements; 2 documented oracle differences (AsmResolver lists ABSOLUTE relocation padding; `.pdata` entries whose end is not after their start are dropped with an issue) |
| Function discovery (`NativeCodeOracleTests`) | IDA 9.3 through idalib, PDB loading off | version, cabinet, msvcp_win, wininet; x64 from System32, x86 from SysWOW64 | function starts: recall **99.96%** (x64), **99.03%** (x86); precision 99.83% (x64), 95.06% (x86) after exception funclets and handlers connect to their parent; direct call edges: recall 100% (x64), 100% (x86). The x86 extras are delay-load thunks and frame setups inside functions IDA starts earlier; all extra starts are code in IDA too. Floors asserted: precision 0.99 (x64), 0.93 (x86) |
| MSVC demangler (`MsvcDemangleCorpusTests`) | DbgHelp `UnDecorateSymbolName` | 99,568 decorated names from System32 / SysWOW64 exports and SDK import libraries | 99.81% identical (whitespace-normalized); every remaining difference is a DbgHelp error, malformed output or rejection |
| RTTI (`MsvcRttiTests`) | linker map of an MSVC-built sample | x86 and x64 builds | exact: type descriptors, hierarchy and base descriptors, locators, vftables, slot targets |
| Exception metadata (`MsvcEhTests`) | linker map of an MSVC-built sample | x86 and x64 | exact catch types, funclet and handler addresses, chunk owners |
| PDB reader (`PdbOracleTests`) | linker map; exports | compiled sample (x64, x86); 216 cached system PDBs (743 MB, 2.3 M symbols) | every map symbol matched (address, kind, name); 0 read issues |
| Assembler (`NativeEditTests.RoundTrip_System32Functions`) | Iced decoder (same mnemonic, operand / address size, operands, immediates, prefixes) | 131,831 instructions from System32 / SysWOW64 functions | 100% equivalent (required), 97.5% byte-identical |
| Cross-build matching (`NativeDiffRealTests`) | PDB / export names present in both builds | 13 real x64 pairs, matching with names off | precision 99.77-100% per pair; recall 76.7-99.8% (ambiguous functions reported, not guessed) |
| Other instruction sets (`IsaEngineTests`) | the source of fixtures built from one Rust file (`tests/.../Engines/IsaFixtures`) | MIPS BE / LE, PPC32, PPC64 ELFv2, RISC-V 32 / 64, ARM big-endian ELF; Cortex-M flash image, 6502 raw; in IDA 9.3 and Ghidra 12.1 | every function found, a decompile (IDA has no 6502 decompiler), call edges equal to the source's, a switch case's call included. MIPS16 not covered: LLVM emits no MIPS16 objects |
| DOS table dispatch (`Dos_table_dispatched_handlers_in_Ghidra`) | the fixture's table | MZ executable calling 540 prologue-free handlers through `call [bx+table]` | 540 of 540 found with the Corvus table scan as Ghidra seeds; Ghidra alone finds none |
| ReadyToRun (`ReadyToRunTests`) | framework assemblies' metadata | ~61,000 methods in 6 framework assemblies | every method decodes, every name resolves, ranges inside executable code, reverse lookups consistent |

- Not measured: IDA function recall on images larger than these four; the oracle samples are small system DLLs.
