# Native tools: reliability and accuracy

How the native tools are tested, the results, and what is open.

- Tools covered: `get_pe_info`, `list_imports`, `list_exports`, `resolve_address`, `search_bytes`, `read_bytes`,
  `list_resources`, `get_resource`, `list_functions`, `disassemble`, `get_cfg`, `find_xrefs`, `native_call_tree`,
  `search_native_strings`, `list_cpp_classes`, `decompile_native`, and `load_assembly`, `reload_assembly`,
  `unload_assembly` on native images.
- One Windows 11 machine (20 logical processors), 2026-10-10; other runs shared it at times, so times are upper bounds.

## Tests

All are `[Trait("Speed", "Slow")]` unless marked quick; run with `-p:CORVUS_ALL_TESTS=1 --filter ...`.

| Test | What it does |
|---|---|
| `NativeToolSweepTests` | loads each image, calls every tool with arguments from the image, reloads and unloads it |
| `NativeStdioSweepTests` | the same tools through the server over stdio, on a sample and the largest browser DLL |
| `NativeToolFuzzTests` | seeded mutation of 8 images, each mutant given to every tool (30 s per call) |
| `NativeConcurrencyTests` | 24 tasks calling tools on 7 images while 4 tasks load, unload and reload them |
| `NativeAdapterConsistencyTests` | the code index and RTTI reader on `PeFile` and the test adapters agree |
| `NativeToolBoundsTests` (quick) | padding past the file is not scanned; paging and conflict errors hold |

- The sweep fails on an unexpected exception, an unclassified error, a typed error on image-derived arguments, a call
  over its time limit, or a result over the response budget (page size + 16,000 characters).
- Memory checks: a large image's GC heap under 16 bytes per file byte + 1 GB; under 400 MB left after unloading.
  Images of 64 MB and more run one at a time, memory sampled every 100 ms.
- Sweep arguments: entry point, an export, an import, the first, largest, most-called and middle function, a string,
  every section start, the last byte, each resource type.
- Sweep variables: `CORVUS_NATIVE_TOOL_SWEEP_LIMIT` (per directory, 0 = all), `CORVUS_NATIVE_TOOL_SWEEP_PF_LIMIT`,
  `CORVUS_NATIVE_TOOL_SWEEP_IDA`.
- The stdio run requires only typed errors, no protocol error, and indexing progress gaps under 15 s.
- Fuzz seeds: two synthetic images, `null.sys`, `notepad.exe`, SysWOW64 `cmd.exe`, `user32.dll.mui`, and a small C++
  DLL with RTTI (System32 and SysWOW64). Mutations cover headers, sections, directories, import and export tables,
  code, `.pdata`, resources and RTTI descriptors.
- Fuzz variables: `CORVUS_NATIVE_TOOL_FUZZ_ITERATIONS` (default 2,500, about a minute), `CORVUS_NATIVE_TOOL_FUZZ_SEED`,
  `CORVUS_NATIVE_TOOL_FUZZ_DUMP`.
- Concurrency: two images are `windows.storage.dll`, so unloads land during index builds; every build must end within
  30 s. A second test unloads an image during IDA auto-analysis. `CORVUS_NATIVE_STRESS_SECONDS`.
- Adapter check: same image fields, function starts, reference, string and instruction counts, RTTI classes.
  `CORVUS_NATIVE_ADAPTER_SAMPLE`.

## Results

| Run | Images | Tool calls | Failures | Time |
|---|---|---|---|---|
| System32 (all native PEs, top level) | 4,526 | 374,902 | 0 | 133 s |
| SysWOW64 (all) | 2,920 | 224,128 | 0 | 114 s |
| System32\drivers (all) | 498 | 47,769 | 0 | 9 s |
| Program Files, both roots, 1,500 sampled each (of 52,490) | 3,000 | 189,058 | 0 | 18 min |
| Largest: three largest files + two with the most code | 5 | 479 | 0 | 228 s |
| Fuzz, seed 20261010 | 25,000 mutants | 1,906,957 | 0; slowest mutant 5 s | 349 s |
| Fuzz, seed 7 | 100,000 mutants | 7,622,219 | 0; slowest mutant 16 s | 21 min |
| Concurrency stress, 120 s | 7 | 26,034 | 0; 1,199 index builds, all ended | 124 s |
| stdio | 81 (incl. msedge.dll 333 MB) | 1,562 | 0; longest progress gap 8.0 s | 148 s |
| Adapter cross-check | 800 (400 per directory) | – | 0 differences | 3 min |

- Seed 7: 572,859 typed errors, 1,646 mutants rejected at load.
- Concurrency: 19,694 calls ok, 6,340 conflict, not found or not loaded; 526 builds cancelled.
- Adapter check: 1,250,926 functions, 9,418 RTTI classes.
- Typed errors in the sweeps: `get_cfg` `not_found` on section starts that are not functions (`.reloc`, `.rdata`).
- The earlier native sweeps still pass: System32 x64 682,528 functions with 0 of 485,461 `.pdata` starts missing;
  SysWOW64 729,708 functions; RTTI on 7,368 images (125,426 classes); PE sweep; PE fuzz (20,000 iterations).

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

- codex.exe (317 MB) live memory: 369 MB loaded, 1.15 GB with its index (peak 2.1 GB while building), 33 MB after
  unloading.
- msedge.dll: 988,220 functions, 69 M instructions, 17.5 M references; index retained 883 MB.
- A build cancelled by an unload stops within about 5 s on these images.

## Tested engine versions

Pinned in `tests/Corvus.Tests/Support/remote-tools-assets.json`; older versions in the supported range are not tested.

| Engine | Supported | Tested |
|---|---|---|
| IDA Pro (idalib) | 9.0 or newer (older is refused) | 9.3, with Python 3.12 |
| Ghidra | 12.0 or newer | 12.1.4 and 12.0.4, with JDK 24.0.1+9 |
| JADX headless server (`decompile_java`) | jadx-headless-mcp fat jar | 0.7.1, with JDK 24.0.1+9 |

- On Ghidra 12.0, `emulate_native` reads unmapped memory as zero instead of stopping; 12.1 reports the read.

## Limits and known gaps

- Indexing a 300 MB browser DLL takes one to two minutes with a transient GC heap of 3-5 GB (6-15 bytes per file byte).
  No bound beyond the 16x heuristic is enforced; a machine with less memory cannot index it.
- A cancelled index build stops at its next check: up to about 5 s on the largest images.
- `load_assembly` on a native file first tries it as .NET: one extra read and garbage of the file's size.
- Built-in decoding: x86, x64, ARM64 and 32-bit ARM (A32, Thumb-2, ARMv8 AES, SHA and VMULL.P64). Other rare SIMD
  encodings decode as `simd` without operands. WebAssembly has its own reader.
- Other instruction sets (MIPS, PPC, RISC-V, ...) get only declared function starts; IDA or Ghidra reads their code.
- ARM or Thumb state comes from symbols, mapping symbols, BL / BLX and code pointers, else from decoding both states.
  When both read plausibly, the prevailing state is taken and `list_functions` tags "state guessed".
- State accuracy: stripped libSkiaSharp armv7 18,219 of 18,219 right (IDA 15,781 of 15,781); static busybox armhf
  99.82% agreement with IDA.
- `list_resources` and several .NET tools page with a footer naming an `offset` the tool does not take.
- IDA was exercised on a small sample only; IDA on the largest images was not measured.
- Program Files was sampled (3,000 of 52,490 files); the adapter check covered 800 of 7,446 system images.

## Agreement with other tools

Measured by the component suites (all `Speed=Slow`), not by the sweeps above.

| Component | Reference | Sample | Result |
|---|---|---|---|
| PE parser | dumpbin, `System.Reflection.PortableExecutable`, AsmResolver, ImageHlp, `FileVersionInfo` | 15,031 system files (15,025 PE) | 0 disagreements |
| Function discovery | IDA 9.3 (idalib), PDB off | 4 system DLLs, x64 and x86 | recall 99.96% (x64), 99.03% (x86) |
| MSVC demangler | DbgHelp `UnDecorateSymbolName` | 99,568 decorated names | 99.81% identical |
| RTTI | linker map of an MSVC sample | x86 and x64 builds | exact |
| Exception metadata | linker map of an MSVC sample | x86 and x64 | exact |
| PDB reader | linker map; exports | compiled sample; 216 system PDBs (2.3 M symbols) | every map symbol matched; 0 read issues |
| Assembler | Iced decoder | 131,831 system instructions | 100% equivalent, 97.5% byte-identical |
| Cross-build matching | names present in both builds | 13 x64 pairs, names off | precision 99.77-100%; recall 76.7-99.8% |
| Other instruction sets | the fixture source (one Rust file) | MIPS, PPC, RISC-V, ARM BE, Cortex-M, 6502 | every function found, call edges equal |
| DOS table dispatch | the fixture's table | MZ program, 540 handlers via `call [bx+table]` | 540 of 540 as Ghidra seeds; Ghidra alone 0 |
| ReadyToRun | framework metadata | ~61,000 methods in 6 assemblies | every method decodes and resolves |

- PE parser references cover imports, delay and bound imports, exports, load config, SEH and CFG tables, headers,
  sections, relocations, TLS, `.pdata`, CodeView, resources and checksums. Two documented oracle differences:
  AsmResolver lists ABSOLUTE relocation padding; `.pdata` entries ending before their start are dropped with an issue.
- Function discovery precision: 99.83% (x64), 95.06% (x86); floors asserted 0.99 and 0.93. Direct call edge recall
  100% on both. The x86 extras are delay-load thunks and frame setups inside functions IDA starts earlier; every extra start is code in IDA too.
- Demangler: every remaining difference is a DbgHelp error, malformed output or rejection.
- RTTI exact: type descriptors, hierarchy, base descriptors, locators, vftables, slot targets. Exception metadata exact:
  catch types, funclet and handler addresses, chunk owners.
- Cross-build matching reports ambiguous functions instead of guessing.
- Other instruction sets: MIPS BE / LE, PPC32, PPC64 ELFv2, RISC-V 32 / 64, ARM big-endian ELF, a Cortex-M flash image,
  6502 raw; in IDA 9.3 and Ghidra 12.1. Each gets a decompile (IDA has no 6502 decompiler). MIPS16 is not covered: LLVM emits no MIPS16 objects.
- Not measured: IDA function recall on images larger than the four sampled.
