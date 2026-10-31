# Features

What each of the 165 tools and 15 prompts reads or shows. Parameters: [tools.md](tools.md).

## Built on

- Decompiler: ILSpy (`ICSharpCode.Decompiler`).
- Metadata and patching: [dnlib](https://github.com/0xd4d/dnlib) and a `System.Reflection.Metadata` IL scanner.
- C# patching: Roslyn.
- .NET crash dumps: [ClrMD](https://github.com/microsoft/clrmd), with the dumped runtime's DAC, signature-checked first.
- Archives: [SharpCompress](https://github.com/adamhathcock/sharpcompress) (tar, 7z, RAR, gzip, bzip2, xz).
- Archive and disk image entries with `..`, rooted, drive or stream names, a trailing blank or dot, a file and folder of one name, or the hidden attribute are named in the notes; RAR 5 stream records are listed.
- JavaScript: [Acornima](https://github.com/adams85/acornima); source maps decoded by built-in code.
- Mail: [MimeKit](https://github.com/jstedfast/MimeKit) (`.eml`, `.mht`); `.msg` and `.ics` read by built-in code.
- Transport: stdio, through the [MCP C# SDK](https://github.com/modelcontextprotocol/csharp-sdk).
- Native code: built-in engine (x86, x64, ARM32, ARM64); IDA or Ghidra optional.

## MCP features

- Tools, prompts, resources, resource templates, argument completion, progress, cancellation.
- Annotations: title, read-only, destructive, idempotent and open-world hints on every tool.
- Resource updates: `resources/subscribe`, or `subscriptions/listen` on protocol version 2026-07-28.
- Structured output for list, search and info tools.
- Errors: `Error (<code>) in <tool>: ...` with a `Next:` step and a JSON copy ([errors.md](errors.md)).
- Strict arguments: an undeclared parameter or unlisted value is `invalid_argument`, naming the closest match.
- Stale server check: `server_status expectedCatalogDigest=...` or `corvus doctor`.
- Size guard: each tool declares `anthropic/maxResultSizeChars`; larger results are kept for `read_result`.
- Server instructions: under 2,048 characters; details in the `guide` prompt.

## Tools

| Area | Tools |
|---|---|
| Workspace | `load_assembly`: load a file or folder: .NET, PE, ELF, Mach-O, metadata builds |
| | `list_assemblies`: loaded ids, versions and flags; with a path, the assemblies inside a container |
| | `unload_assembly`: remove an assembly or close a dump |
| | `reload_assembly`: re-read an assembly from disk |
| | `add_search_directory`: add a folder for resolving references |
| | `get_assembly_info`: identity, references, metadata tables, bad rows, transformation layers |
| | `save_session`: write files, edits, patches, names and notes to one JSON file |
| | `load_session`: restore by SHA-256, here or on another build (`targetBuild=other`); `dryRun` by default |
| Browse | `list_namespaces`: namespaces with type counts |
| | `list_types`: types by namespace, name and kind |
| | `get_type_info`: outline of a type without decompiling; FieldRVA data decoded |
| | `get_type_hierarchy`: bases, interfaces and derived types |
| | `get_attributes`: custom attributes with decoded arguments |
| | `resolve_symbol`: every match of a symbol string or token |
| Decompile | `decompile_member`: C# of a type or member; state machines and lambdas folded back |
| | `get_il`: IL with tokens, offsets, normalized IL hash ([il-hash.md](il-hash.md)) and source lines |
| | `export_project`: an assembly as a buildable C# project; a package as a Gradle project |
| | `decompile_native`: pseudocode of a native function through IDA or Ghidra |
| | `search_decompiled`: regex over the pseudocode of every function |
| Search | `search_symbols`: types and members by substring, wildcard or regex |
| | `search_strings`: string literals with the method and IL offset using each |
| | `search_constants`: numbers in IL, constants, attributes and static arrays |
| | `search_il`: IL instruction-sequence patterns with wildcards |
| Cross-references | `find_references`: every use of a method, field, property, event or type |
| | `find_callees`: what a method calls, reads, writes and creates |
| Call graph | `get_call_tree`: callers or callees several levels deep |
| | `find_call_paths`: shortest call chains to a method, into native code too |
| Compare builds | `compare_assemblies`: renamed, moved, added, removed and changed members of two builds |
| | `find_counterpart`: where a type or member went in the new build |
| | `compare_folders`: two folders, packages or files, entry by entry; links not followed |
| Resources | `list_resources`: managed and Win32 resources with SHA-256 and offsets |
| | `get_resource`: read or extract a resource; BAML as XAML |
| Containers | `unpack_container`: extract and load what a container holds ([containers](#containers)) |
| | `search_container`: search a container's assemblies or files without extracting |
| JavaScript | `analyze_js`: bundle modules, endpoints, data flow, source maps, Hermes and Ark bytecode |
| File inspection | `summarize_file`: one report on any file: hashes, identity, signature, contents ([views](#summarize_file-views)) |
| | `survey_features`: capabilities from APIs, imports, strings and constants, with evidence |
| | `extract_strings`: typed values: URLs, IPs, paths, registry keys, keys |
| | `extract_embedded`: embedded content decoded until a known format appears |
| Builds | `summarize_build`: a build folder's version, scripting backend, metadata state and next calls |
| Android packages | `get_android_manifest`: the decoded manifest with effective component exposure |
| | `list_android_resources`: every resource and configuration |
| | `get_android_resource`: one entry, binary XML decoded |
| Android DEX | `list_dex_classes`: classes of every DEX file |
| | `get_dex_class`: one class with fields, methods and Kotlin metadata |
| | `disassemble_dex`: smali of a method or class; decoded strings with `format=simplified` |
| Android Java | `decompile_java`: Java source through JADX or Vineflower; smali where JADX fails; cached on disk |
| | `search_dex`: strings, types, members, constants and opcodes in DEX code |
| | `find_dex_references`: cross-references in DEX code |
| Android bindings | `map_java_dotnet`: Java wrappers to .NET types and back |
| | `list_jni_bindings`: Java native methods paired with their native code |
| Android devices | `list_android_devices`: devices and emulators adb sees |
| | `get_android_device_info`: properties, processes, screen, window, bugreport; read only |
| | `list_android_packages`: installed packages |
| | `get_android_package_info`: one package with permissions and grant state |
| | `pull_android_package`: copy an installed package's APKs |
| | `pull_android_file`: copy one device file |
| | `read_android_log`: logcat by process, tag, priority and time |
| | `install_android_package`: install an APK or split set (`--allow-device-changes`) |
| | `uninstall_android_package`: remove an app (`--allow-device-changes`) |
| Compiled metadata | `get_method_addresses`: addresses, vtable slots and field offsets of methods ([metadata](#compiled-metadata)) |
| | `find_method_by_address`: the method or metadata slot at a native address |
| | `export_method_symbols`: IDA and Ghidra scripts, a C header and JSON |
| | `apply_metadata_names`: name a native binary's functions from its metadata |
| | `generate_cpp_binding`: C++ binding code for a managed type |
| .NET edits | `rename_symbol`: rename a type or member |
| | `rename_namespace`: move a namespace's types |
| | `stub_method`: replace a body with a constant return |
| | `patch_method_csharp`: replace a body with C# ([patching](#patching)) |
| | `add_members_csharp`: add C# members to a type |
| | `add_types_csharp`: add C# types to an assembly |
| | `patch_method_il`: rewrite a body from IL text |
| | `simplify_methods`: fold string decoders in a sandboxed IL interpreter, clean control flow ([simplify.md](simplify.md)) |
| | `save_assembly`: write a patched copy, verified against the original ([saving.md](saving.md)) |
| Edit history | `list_edits`: unsaved edits in order |
| | `diff_edits`: before and after C# of edited members |
| | `undo_edit`: undo one edit |
| | `revert_edits`: discard every edit |
| | `export_edits`: an edit script bound to its build |
| | `apply_edits`: replay an edit script, on a new build too |
| Notes | `record_note`: a finding, question, hypothesis or todo kept per binary |
| | `update_note`: change a note; verify its evidence |
| | `list_notes`: notes by status, kind, anchor, tag and text |
| Native overview | `get_pe_info`: headers, sections, mitigations, signature, anomalies of PE, ELF and Mach-O |
| | `list_imports`: imports per library, bound to their exports |
| | `list_exports`: exports with ordinals, forwarders and demangled names |
| | `resolve_address`: what an address is: section, symbol, function, data, method |
| | `get_engine_status`: IDA and Ghidra sessions of an image; never starts an engine |
| Native code | `list_functions`: functions with names, sizes and flags |
| | `list_globals`: named data outside code |
| | `disassemble`: MASM disassembly of a function |
| | `inspect_instruction`: operands, registers, flags, memory and flow per instruction |
| | `search_instructions`: instructions by mnemonic, operand or value |
| | `get_cfg`: basic blocks, edges and switch tables |
| | `get_exception_info`: exception handling of a function |
| Native references | `find_xrefs`: code and data references to an address |
| | `native_call_tree`: callers or callees through thunks and imports |
| | `get_call_arguments`: argument values at call sites |
| | `trace_native_values`: a value traced to its sources or uses across functions |
| | `resolve_call_targets`: targets of indirect calls with basis and confidence |
| | `find_virtual_calls`: virtual calls resolved through RTTI or MethodTables |
| Native functions | `analyze_native_function`: everything known about one function, in bounded sections |
| | `trace_native_feature`: from a text or name to the code behind a behaviour |
| | `find_similar_functions`: functions like a given one, ranked with evidence |
| Native data | `search_native_strings`: strings referenced by code or data |
| | `search_bytes`: byte patterns with wildcards and masks |
| | `read_bytes`: bytes or typed values at an address |
| | `convert_number`: a number in every base, width and byte order |
| Symbols and types | `load_pdb`: PDB or DWARF names, types and source lines |
| | `search_pdb_symbols`: symbols of the loaded debug information |
| | `list_cpp_classes`: C++, Delphi and Free Pascal classes from RTTI and VMTs |
| | `get_native_type`: layout of a native type, with field values |
| | `get_nativeaot_info`: what NativeAOT metadata recovers (.NET 7-10) |
| Emulate and script | `emulate_native`: emulate code, nothing run natively ([emulation](#emulation-emulate_native)) |
| | `ida_python`: IDAPython in the image's IDA worker (`--ida-scripting`) |
| | `ghidra_script`: a Ghidra script in the image's Ghidra worker (`--ghidra-scripting`) |
| | `export_engine_database`: the engine database for the engine's GUI |
| Engine types | `set_native_type`: set a function prototype or global type |
| | `set_native_local`: rename or retype a pseudocode local |
| | `get_native_frame`: stack frame and decompiler locals |
| | `set_native_stack_var`: rename, retype, create or delete a stack variable |
| | `declare_native_types`: declare or edit C types in the engine |
| | `list_native_types`: browse the engine's types |
| | `define_native`: make code, a function, data or undefined bytes |
| | `reanalyze_native`: re-run the engine's auto-analysis |
| | `set_native_operand`: set how an operand displays |
| Native edits | `rename_native`: name an address |
| | `comment_native`: comment an address |
| | `export_native_annotations`: names and comments as IDA or Ghidra scripts, JSON or a header |
| | `patch_bytes`: replace bytes in memory |
| | `patch_asm`: assemble x86 or x64 code; unsafe sites refused with a reason; others use `patch_bytes` |
| | `list_native_edits`: patches, names, comments and type edits |
| | `undo_native_edit`: undo native edits |
| | `export_native_patches`: patches as IDAPython, .dif, IPS or JSON |
| | `save_native`: write a patched copy ([native-editing.md](native-editing.md)) |
| New builds | `update_to_new_build`: carry names, types, patches and notes to a new build |
| | `migrate_native_patches`: reapply patches where the original bytes match |
| | `compare_native_images`: match functions of two native builds |
| | `diff_function`: one function's changes between builds |
| | `map_address_between_builds`: where an old address is in the new build |
| | `migrate_native_names`: copy names to a new build, or from a static library |
| | `make_code_pattern`: a rebuild-stable byte pattern for an address |
| | `search_code_pattern`: find a byte pattern in loaded images |
| .NET and native | `verify_native_imports`: check P/Invoke imports against library exports |
| | `get_r2r_code`: ReadyToRun precompiled code of a method |
| | `find_r2r_method`: the managed method at a ReadyToRun address |
| Crash dumps | `open_minidump`: open a minidump, core dump or region set; DAC fetched only with `downloadDac=true` |
| | `dump_stack`: a thread's call stack, managed frames named |
| | `dump_heap`: .NET heap of a dump or session |
| | `dump_object`: one .NET object with its fields |
| | `read_dump_memory`: dump memory at an address |
| | `symbolize_stack_text`: resolve crash text against the loaded build |
| | `bucket_minidumps`: group dumps by crash signature |
| Running programs | `inspect_process`: read-only view of a running Windows process; nothing written or suspended; `view=windows` needs `--allow-window-capture` |
| | `live_session`: attach (`--allow-live-attach`) or start (`--allow-live-spawn` with `--live-allow`); `--live-allow` limits targets |
| | `live_break`: stop points with named stacks; managed DAC fetched only with `downloadDac=true` |
| | `live_watch`: record calls with arguments and results |
| | `live_read`: registers and memory of a held thread; YARA scan of memory (Windows, Linux) |
| | `live_events`: page a session's events |
| | `live_coverage`: code coverage of a run; compare two runs |
| | `live_timeline`: files, registry keys, endpoints and processes a program opens (Windows) |
| | `live_console`: scripted console run (Windows; `--allow-live-spawn`) |
| | `live_script`: your own Frida script in the program (`--live-scripting`) |
| Session | `server_status`: version, catalog digest, limits, engines, unusable tools |
| | `read_result`: page, search or save a kept result; kept on disk 7 days |

**Resources:** `corvus://assemblies`, `corvus://assembly/{assembly}/info`, `corvus://assembly/{assembly}/type/{type}`,
`corvus://assembly/{assembly}/il/{symbol}`, `corvus://native/{image}/segments`, `corvus://native/{image}/entrypoints`,
`corvus://native/{image}/type/{name}`, `corvus://guide/{topic}`.

**Prompts:** `analyze_assembly`, `find_feature`, `explain_type`, `plan_patch`, `map_native_address`, `analyze_native`,
`trace_native_feature`, `find_api_usage`, `patch_native`, `compare_builds`, `triage_crash`, `investigate_feature`,
`check_reimplementation`, `guide` (topics: dotnet, native, aot, containers, edits, builds, idapython, dumps, errors),
`getting_started`.

**Completion:** assembly, image and dump ids, type names, file paths and guide topics.

**Edits:** kept in memory until saved; .NET edit tools and native patches take `dryRun`. `save_assembly` replaces
an existing file only with `overwrite=true`. Both save tools replace the loaded file only with `replaceOriginal=true`,
behind `--allow-replace-original`, keeping a `.bak`.

**Running programs:** the session tools refuse every call until a `--allow-live*` switch is on, and need a Python with
Frida's bindings ([live-inspection.md](live-inspection.md)).

## Native images

- PE, ELF and Mach-O (one slice of a universal file) load with `load_assembly`, or with any native tool given a path.
- x86, x64, ARM64 and ARM32 / Thumb-2 decode in the built-in engine. Other instruction sets use IDA, else Ghidra, marked "(via IDA)" or "(via Ghidra)".
- Headerless code: `load_assembly format=raw arch=x86|x64|arm|thumb|arm64 base=… entry=…`. `summarize_file view=raw` suggests the instruction set and load base.
- `load_assembly` overrides: `processor=`, `language=`, `compilerSpec=`, `seeds=`, `disableAnalyzers=`. Each set gets its own engine database.
- Ghidra `.gzf` archives (checked against their recorded SHA-256) and `.gpr` projects open without analysis. Projects are left unchanged.
- An image open in IDA: run `corvus_connect.py` (from `corvus ida-script`) in IDA 9+, and start Corvus with `CORVUS_IDA_CONNECT=1`. No local IDA install is needed.
  - The script serves 127.0.0.1 behind a token, in a file only its user can read.
  - Corvus never rebases, saves, closes or deletes that database. A different base is refused. A closed session only
    detaches.
- IDA (idalib) or Ghidra is required for `decompile_native`, `search_decompiled`, `ida_python`, `ghidra_script`, `list_functions view=candidates`, the default `emulate_native` engine, and every `engine=ida|ghidra` mode.
- `engine=auto|ours|ida|ghidra` (server default `--engine` / `CORVUS_ENGINE`). `auto` uses the first engine that analyzed the image (IDA, then Ghidra), else Corvus's index. Corvus's names win over the engine's. Every result names its engine.
- Node-API add-ons, Dart AOT snapshots (Dart 3.0-3.13) and NativeAOT images get names from their own metadata.
- More: [native-editing.md](native-editing.md), [engine-databases.md](engine-databases.md).

### Debug information (`load_pdb`)

- PE: the matching PDB beside the file, the CodeView path, the symbol path or caches. `download=true` uses a symbol server.
- ELF and Mach-O: DWARF 2-5 from the image; a `.debug` file by build id (`CORVUS_DEBUG_DIRS`) or `.gnu_debuglink`; a dSYM; `.dwo` / `.dwp`; the object files of a Mach-O debug map. `download=true` uses debuginfod.
- Gives names, types, prototypes, source lines, inlined calls, and the locals in scope at an address.
- Runs on any host.
- Names are saved per file hash and reapplied on later loads. `clear=true` removes them.

### Emulation (`emulate_native`)

- Default engine: Ghidra's p-code emulator, from a function or address, in a private scratch area. Nothing runs natively.
  - Stops on return, a stop address, or an instruction or time budget.
  - Calls step into the image or return `stubs=` values. An unmodelled call stops the run and names the address.
  - Reports the return value, changed registers, written memory with decoded strings, and a trace.
- `engine=ours`: built in, no engine needed; x86, x64 and ARM64 integer code. `auto` picks it without Ghidra.
  - Floating point, vector arithmetic, system calls and segment bases stop the run and name the instruction.
- `engine=speakeasy`: a whole PE, or raw x86 / x64 code, in speakeasy 2.0.0b9 (`CORVUS_EMULATOR`), in the worker host. Windows APIs are modelled. Nothing runs natively.
  - An unmodelled API stops the run by name, keeping the calls before it.
  - Reports API calls, written files and memory as a region set that `open_minidump` reads.

### Other dump files

- Linux and Android ELF cores: threads, registers, signal, modules matched by build id, CFI unwinding.
  - .NET cores use Microsoft's signature-checked DAC for Linux targets. It loads only on Windows, checked against the
    runtime file version in `imageDirectories`.
- macOS Mach-O cores: ARM64 and x86_64 threads; images matched by UUID.
- Region sets: memory region files listed in a `"format": 1` JSON manifest open as a dump. Threads read as unknown.
  - Overlapping regions are refused. A missing region file reads as unknown for its range.

### WebAssembly

- A `.wasm` module loads as a native image. A component opens as its largest core module.
- Webcil is not read as a module; `unpack_container` converts it.
- Names from the name section, exports, imports and an Emscripten symbol map; no size limit below 4 GiB.
- `disassemble`: WAT output matches `wasm2wat`.
- `decompile_native`: a structured view without an engine. `engine=ghidra` answers unsupported unless `CORVUS_GHIDRA_EXTENSIONS` names a WebAssembly extension.
- `list_functions`, `find_xrefs`, `native_call_tree`, `get_cfg`, `inspect_instruction`, `search_native_strings`: the module's own index, `call_indirect` edges included.
- `compare_native_images`: imports, exports and functions paired by name, then by body hash.

## Compiled metadata

Managed code compiled ahead of time to native code: a build folder, `global-metadata.dat` with `GameAssembly.dll`,
`libil2cpp.so`, `GameAssembly.so`, `GameAssembly.dylib` or `UnityFramework`.

- `load_assembly` reads metadata versions 24-39 with the built-in reader. No external tool is needed.
- Packages: `.apk`, `.xapk`, `.apks`, `.aab` (`slice=` picks the ABI), `.ipa`, `.app`.
- Unreadable metadata is an error with a reason: `encrypted_or_transformed`, `unsupported_version`, `binary_mismatch_or_transformed`, ...
- 32-bit ARM builds without a found code registration report `registration_not_found_armv7` or `armv7_unreadable`. Load the arm64-v8a build.
- Encrypted metadata is not decrypted. `summarize_build` reports it. Load a copy dumped from memory instead.
- FairPlay-encrypted iOS binaries fail with `encrypted_fairplay`.
- Metadata alone (no binary): types, methods, fields and string literals. No addresses or field offsets.
- Folders of dummy assemblies with `[Address]` attributes load too.
- With `script.json` beside them: every function start, generic instantiation and metadata slot is named.
- With `stringliteral.json` or `script.json`: `search_strings` searches the build's literals. With an x64 `GameAssembly.dll`, each literal names the functions that load it.
- `find_method_by_address` takes an RVA, VA or file offset (`kind=auto` guesses).
- Reads are cached per user (`CORVUS_AOT_CACHE`).

## Containers

- `unpack_container` writes out a container's files (table below) and loads its assemblies. `extractOnly=true` only extracts.
- Reads bytes only; never runs the file.
- Nested containers open, up to 4 levels deep.
- `password=` opens an encrypted zip (ZipCrypto, AES), 7z or RAR; only that password is tried and a wrong one names each entry as not read.
- `list_assemblies path=` lists a container's assemblies and writes nothing.
- `search_container` finds types and members by name across a container's assemblies: default 100 matches, up to 5,000.

| Container | What comes out |
|---|---|
| .NET single-file bundle | every manifest entry, compressed bundles inflated |
| Costura.Fody | each embedded assembly |
| NuGet (`.nupkg`), zip, `.vsix`, `.xap` | every file; assemblies, deps files and nested packages opened |
| `.apk` / `.aab` | every file; XALZ and store members as their decoded assemblies |
| Java runtime image (`lib/modules`) | every resource, as `jimage extract` writes it |
| Electron `.asar` | every file, integrity checked against the app's declared hash |
| WebGL `.data` (UnityWebData) | every file with its role |
| Godot `.pck` | every file, Godot 3 and 4 |
| Qt resources (`.rcc` or compiled in) | every file, Qt 5 and 6 |
| Flash SWF | tags, ActionScript blocks, images, sounds |
| Unreal pak and IoStore | every file or chunk, decompressed; encrypted indexes named |
| GameMaker data file | chunks, code entries, strings, textures, audio |
| Lua 5.1-5.4 and LuaJIT 2.0/2.1 bytecode | functions with listings and strings |
| Compiled AutoIt script | the script source, rebuilt for EA06 |
| Frozen Python (PyInstaller, py2exe, cx_Freeze, Nuitka onefile) | modules as `.pyc`, the entry script, the Python version |
| HAR, mitmproxy flows | one file per response body |
| squashfs, cramfs, ext2/3/4, FAT, JFFS2, UBI, UBIFS | every file and link |
| uImage, FIT, Android boot, TRX | kernels, ramdisks, device trees |
| `.deb`, `.a`, `.rpm`, AppImage, snap, apk v3, Flatpak | package facts and every file |
| Office OLE documents | streams, VBA source, Excel 4.0 macros, OLE packages |
| PDF | embedded files, JavaScript, XFA forms; streams with `allFiles` |
| `.lnk` | appended data |
| Mail (`.eml`, `.mht`, `.ics`, `.msg`) | bodies, attachments, embedded messages, files an HTML body builds in a Blob; `.msg` streams |
| OneNote `.one` | embedded files under their stored names; scripts flagged |
| ISO / UDF, VHD / VHDX (NTFS, FAT, ext) | every file of each partition |
| Apple `.dmg`, HFS+, APFS | every file; encrypted APFS volumes named |
| `Assets.car` | renditions; bitmaps as PNG with `allFiles` |
| `.cab`, `.msi` / `.msp` / `.mst` | files, custom action binaries and scripts |
| Squirrel, WiX Burn, NSIS, Inno Setup, ClickOnce | installed files under their install paths |
| Firmware image | each embedded filesystem, boot image and archive |
| ESP32 flash image | bootloader, partition table, every partition |
| iNES ROM | PRG and CHR banks, with the `format=raw` load call |
| JavaScript bundle and source map | one file per module; the original source tree |
| pcap / pcapng | HTTP objects and TCP streams ([captures](#captures)) |
| anything else | .NET images carved from the raw bytes |

Untrusted input:

- Output stays inside the output directory. `..`, rooted and drive parts are dropped; device names get a `_` prefix.
- Runnable extensions (`.exe`, `.bat`, `.ps1`, `.lnk`, ...) get a `.bin` suffix. `.dll` is kept.
- Shell-parsed files (`.url`, `.library-ms`, `desktop.ini`, `.inf`, ...) get a `.bin` suffix.
- On Windows, extracted files carry a `Zone.Identifier` stream with `ZoneId=3`.
- A corrupt entry is skipped with a note. A corrupt container fails with an error.
- Limits: 512 MB per item; 4 GB and 20,000 files per extraction.
- Expansion limit: past 256 MiB extracted, one call's output stops at 2,000 times its input (`CORVUS_MAX_EXPANSION`).
- Default output: a folder under the temp directory, named by the file and its SHA-256. A given directory must be new, empty, or an earlier extract of the same file.

Labels:

- `readyToRun`: precompiled native code beside the IL. The IL still decompiles.
- `merged`: traces of ILRepack or ILMerge, with the original module count where known. Inputs are not split back.

### Searching files (`search_container kind=`)

| Kind | Finds |
|---|---|
| `electron` | windows, preloads, bridge methods, IPC channels paired across processes, sinks, native add-on calls |
| `feature` | from a UI or error text to its handler, IPC hops and sinks |
| `endpoint` | endpoints the code names (Retrofit, OkHttp, Refit, HttpClient, gRPC, ...), or request templates of a capture |
| `request` | every request of a HAR, mitmproxy or `.saz` capture; values only with `values=true` |
| `packet` | pcap frames matching a Wireshark display filter |
| `dart` | strings and identifiers of a Dart AOT snapshot |
| `hermes` | strings and function names of a Hermes bundle |
| `yara` | YARA rule matches ([YARA rules](#yara-rules)) |

- `capture=` joins code rows to captured requests. Two captures compare template by template.
- `compare_folders` compares two `.asar` archives without extracting.

### Captures

- `kind=packet` takes a Wireshark display filter and lists matching frames with the fields it names.
- Decoded in process: frame, IP, TCP, UDP, DNS, HTTP, TLS (SNI, ALPN, JA3, JA4), cleartext HTTP/2, QUIC Initials, SMB2, NTLMSSP, Kerberos.
- Other fields run through TShark when `CORVUS_TSHARK`, `PATH` or the Wireshark folder finds it.
- Captures are streamed; size is not limited.
- `unpack_container` on a capture reassembles TCP and writes:
  - HTTP/1.x and HTTP/2 bodies, decoded by Content-Encoding;
  - TLS 1.2 and 1.3 streams, decrypted with `keyLog` or the pcapng's own secrets;
  - HTTP/3 over QUIC v1 and v2;
  - other streams under `streams/`;
  - `tls.json`: version, suite, ALPN, JA3, JA4, JA4S and decryption state per connection.

### Lockfiles

- `summarize_file view=lockfile` reads `package-lock.json`, `npm-shrinkwrap.json`, `pnpm-lock.yaml`, `yarn.lock` (v1 and berry), `poetry.lock`, `uv.lock` and hashed `requirements*.txt`.
- Each resolved package shows its source: registry, git, url or path. A git or URL source is review; plain HTTP is noteworthy.
- `compare_folders` on two lockfiles, or two folders with lockfiles at one path, lists packages added, removed or changed.
- A git or URL source taken on, or an integrity changed for one version, is noteworthy; a newly flagged install script is listed.
- `compare_folders` on two package versions lists malcontent behaviours added or removed in each changed code file, and build or install steps a `.nupkg` gains.
- `search_container kind=dependency query=name@version` on a folder names each lockfile that resolves it; `node_modules` and `.git` are skipped.
- `search_container kind=incident query=<list file or pack:name>` lists lockfile packages, files and archive members that an incident list names (`name@version` or SHA-256 per line); a listing is not a verdict.

### Workflows

- `summarize_file` on a folder with `.github/workflows` lists each job with its trigger and what it runs; `compare_folders` on two package folders lists added workflow jobs.
- Noteworthy: `pull_request_target` or `workflow_run` checking out the change, `toJSON(secrets)`, and an author-controlled event field in a `run:` command.

### MCP servers

- `summarize_file` on a folder, `.mcp.json`, an MCPB `manifest.json`, a registry `server.json` or a saved `tools/list` response reviews MCP servers: unpinned launchers, plain-HTTP or raw-address remotes and credential-named `env` keys (names only) are review; a tool description with a comment or hidden characters is noteworthy.
- `compare_folders` on two source trees lists MCP server and hook entries that were added, removed or whose command changed.

### Provenance

- `compare_folders` on two attested packages reports a "provenance dropped" row when the new version has no verified provenance.
- `summarize_file` on an npm package with provenance beside it flags a signed source repository other than the declared one.

### Names

- A zip member or mail attachment name with a bidirectional control, a runnable extension after a document extension or long padding is named.
- A package name close to a popular npm, PyPI, NuGet or RubyGems name, or one with filler words or look-alike letters added, is review.

### Model files

- A model file in a package (pickle, PyTorch, `.npy`, `.npz`, joblib, `.keras`, GGUF, ONNX) is read without loading it.
  - A pickle importing `os`, `subprocess`, `runpy`, `importlib` or `builtins.exec` is noteworthy; other globals outside the weights-only allowlist are review.
  - joblib is read through zlib, gzip, xz, lz4 and bzip2; HDF5 is named as not read.
  - A Keras `Lambda` layer, a GGUF `chat_template` walking `__class__` or `__globals__`, and an ONNX data path with `..` or an absolute path are noteworthy.

### Package code

- A dev-time config (`*.config.js`, `.eslintrc.js`) is read as entry code.
- Code that evals text fetched from a JSON storage or chain RPC host is noteworthy.
- A token read, a workflow or repository write on the GitHub API and a registry publish: three steps, or two at install, are noteworthy.
- Variation-selector and private-use runs are decoded to bytes; terminal escapes and Markdown hidden from rendering in an instruction file are reported.
- Agent settings (`.claude/settings.json`): `env` endpoint, proxy and loader overrides are noteworthy; helper commands, permission widening, plugins and marketplaces are reviewed.
- Codex settings (`.codex/config.toml`): `approval_policy = "never"` and a loader or endpoint variable in `shell_environment_policy.set` are noteworthy; `danger-full-access`, `model_providers` and `profiles` (read from a user-level file only) and `mcp_servers` are review.
- Plugin manifests and hooks, command, agent, skill and prompt files, MCP files of other agents and `chat.tools.autoApprove` are read; `.codex` and `.gemini` folders count as agent files.
- A program that runs `claude`, `codex`, `gemini` or `copilot` with confirmation off is noteworthy.

### YARA rules

- `search_container kind=yara`. The query is a rule file, a folder, rule text, or `pack:<name>` from `corvus rules fetch` ([cli.md](cli.md)). Corvus ships no rules.
- Runs YARA-X 1.22.1 in a worker process. Unavailable with `CORVUS_WORKER_HOST=0`.
- Scans the file, then each container member. Minidumps and cores are scanned by their captured memory.
- Modules: `pe`, `elf`, `macho`, `dotnet`, `dex`, `hash`, `math`, `time`, `lnk`.
- Shipped for win-x64, win-arm64, linux-x64, linux-arm64 (glibc 2.34+), osx-x64 and osx-arm64. Elsewhere, set `CORVUS_YARA_LIBRARY`.
- The shipped library loads only when its SHA-256 matches the release's; a `CORVUS_YARA_LIBRARY` build loads unchecked.

## File inspection

| Tool | Output |
|---|---|
| `summarize_file` | hashes, identity, signature, protection product, containers, highlights, entry points |
| `survey_features` | capabilities by category with evidence; MASVS findings for Android and Apple apps |
| `survey_features category=capa` | capa labels of PE, ELF and .NET files (`CORVUS_CAPA`) |
| `extract_strings` | URLs, domains, IPs, paths, registry keys, mutexes, keys; serialized asset fields |
| `extract_embedded` | embedded items with their decoding chain (`base64 > xor key 5a > gzip`) |

- `summarize_file` reads up to 25 assemblies inside a container.
- `summarize_file` counts a script's modules and map sources in their first 8 MB; a script over 64 MB is not named as a container.
- `stixPath=` writes a STIX 2.1 bundle of the file, its members and the indicators of every view.
- `view=indicators` lists URLs, domains, addresses, TLS fingerprints, strings of native images and certificate names and revocation URLs from every view, one row per value with its sources.
- `batch --file --report` names each rule the YARA step matched.
- `summarize_file` reports the import hash of a PE image beside its file hashes.
- Features describe API use, not whether the code runs.
- `extract_embedded xorText=true` recovers repeating XOR keys of 1-16 bytes over text. Off by default.
- Authenticode digest and signature checks are exact. Chain trust uses the machine's root store. Revocation is not checked.

### `summarize_file` views

Pass the name as `view=`.

| View | Reads |
|---|---|
| `managed` | each assembly's details |
| `dependencies` | shipped components with evidence ([below](#dependencies-view)) |
| `native` | ELF / Mach-O facts, packers, NativeAOT counts, triage of a loaded image |
| `android` | manifest, runtimes, ABIs, DEX, signature; `view=layers` graphs the code layers |
| `apple` | `.ipa` / `.app`: Info.plist, Mach-O signatures, entitlements, profile |
| `electron` | versions, fuses, archive integrity, `webPreferences` |
| `go` | toolchain, modules, build settings |
| `rust` | crates from cargo-auditable or panic paths |
| `flutter` | Dart snapshot version, packages, string pool |
| `sqlite` | schema and rows, WAL applied, no SQL engine |
| `sqlite-recover` | deleted rows carved from free space and WAL |
| `leveldb`, `lmdb`, `ese`, `berkeleydb`, `realm` | records, and records the live state no longer shows |
| `registry` | a hive's keys and values, deleted ones recovered |
| `evtx` | event log records, free-space records recovered |
| `procmon` | Process Monitor events |
| `pcap` | flows, DNS, TLS fingerprints, HTTP templates, beaconing hints |
| `qlog` | QUIC and HTTP/3 event logs |
| `certificate` | certificates, chains, SPKI pins, trust verdict |
| `nib`, `xbf`, `pri`, `plist` | compiled UI and resource files decoded |
| `esp32` | ESP32 images, partitions, NVS values |
| `model` | safetensors, GGUF, ONNX, PyTorch, pickle, joblib, `.npy`, `.npz`, `.keras`; code a file runs when loaded; nothing unpickled |
| `installer` | MSI custom actions, services, autostart entries |
| `lnk` | a shortcut's target, arguments and noteworthy traits |
| `installer`, `lnk`, `script`, `procmon` | command lines that download, decode or hide through a system tool: one `launcher/command-line` finding |
| `mail` | headers, received chain, recorded authentication results, From, Reply-To and Return-Path side by side, links, parts, attachments |
| `office` | VBA with folded strings, Excel 4.0 macros, OLE packages and classes, RTF objects and templates, findings by line |
| `pdf` | keywords, actions, scripts, embedded files |
| `firmware` | formats found at offsets in an opaque image |
| `raw` | likely instruction sets and load bases of headerless code |
| `wasm` | imports, exports, validation verdict, a component's WIT world |
| `harmony`, `hermes` | HarmonyOS modules and Hermes bundles |
| `protobuf` | `.proto` definitions recovered from embedded descriptors |
| `page` | a saved web page's scripts, integrity hashes and CSP |
| `script` | PowerShell, batch, VBScript, JavaScript, HTML and SVG scripts deobfuscated, Script Encoder text decoded, nothing run; a file a standalone page builds in a Blob is carved as a member |
| `package` | npm, PyPI, RubyGems, NuGet, Composer, VS Code and browser packages before install; source folders |
| `python` | frozen Python programs; `.pyc` disassembly |
| `assets` | serialized asset files and bundles: each asset's fields |
| `flight` | React Server Components payloads |

### Dependencies view

- .NET: packages from deps.json with SHA-512. Without one, assemblies by name, versions unknown.
- Also: Go modules, Rust crates, frozen Python distributions, Android Maven and native libraries.
- `sbomPath=` writes a CycloneDX 1.6 SBOM. An existing file needs `overwrite=true`.
- Advisories: matched offline by osv-scanner (`CORVUS_OSV_SCANNER`). Without it, reported as not checked.

### Large files

- Files over 64 MiB are streamed: hashes, captures, SQLite, zip, HAR, packages, plists, WebAssembly, native images, tar / 7z / gzip.
- A native image's own sections and a module's code are still read whole.

## JavaScript (`analyze_js`)

- Bundles: webpack, esbuild, Browserify, Parcel, AMD, SystemJS, Metro, Rollup / Vite chunks; module table, requires.
- webpack runtime: chunks, public path, async loads.
- Endpoints and routes: fetch, axios, XMLHttpRequest, WebSocket, GraphQL; React Router, Vue Router, Angular, Next.js.
- Secrets: key-like literals by provider pattern, masked.
- Two builds compared module by module.
- Data flow: `view=flow` forward, `view=origins` back to sinks. Unfollowable steps end as unknown.
- `view=beautify`: one statement per line. `query` renames bindings by scope.
- `view=react` and `view=jsx`: components, hooks and JSX of a compiled bundle.
- Hermes bytecode versions 59-96 and Ark bytecode: disassembly, decompiled view, users of a function or string.
- Source maps: inline, by `sourceMappingURL`, or a sibling `.map`.

## Android

- `mapping=` (R8 / ProGuard `mapping.txt`) on the DEX tools puts original names beside ids.
- `disassemble_dex format=simplified` runs string decoders in a bounded Dalvik interpreter: 100,000 instructions per call, call depth 8, 10 s per package-wide pass.
  - A call not folded names its reason (`not-constant`, `mutable-static`, `instruction-budget`, ...).
- `summarize_file` on a package names its runtimes, ABIs, DEX files and signature verdict.
- Device tools find adb through `CORVUS_ADB`, `PATH` or the SDK. Installs and uninstalls need `--allow-device-changes`.

## Reliability

| Concern | Handling |
|---|---|
| Locked files | assemblies are read into memory; files are never locked |
| Concurrency | reads share a lock, edits take it exclusively |
| Broken bodies | decompiled member by member, IL for the broken part |
| Lenient metadata | decompiled from a normalized copy with the same tokens |
| Invisible names | zero-width, bidi and control characters shown as `\uXXXX` |
| Large output | paged by tokens; overflow kept for `read_result` |
| Files changing on disk | clean assemblies reload; edited ones stay and the agent is told |
| Long calls | `--timeout` per decompilation (default 180 s); `timeout` error at twice that |
| Crashing inputs | file reads run in a worker process; the server keeps answering |
| Invalid patches | IL is stack-validated, C# compiled; nothing changes on failure |

- `read_result format=evidence` writes a findings bundle. `format=verify` re-runs its calls and names what changed.
- `compare_assemblies`, `compare_native_images` and `compare_folders` take `oldResult` / `newResult` to compare kept results.

## Symbol syntax

```
Ns.Type          Ns.Outer+Inner   Ns.Outer/Inner   Ns.Outer.Inner   Type (short name)
List`1           List<T>
Ns.Type::Method  Ns.Type.Method   Ns.Type::Method(int, string)      Ns.Type::.ctor
0x06000123       (metadata token; pass `assembly` when several assemblies are loaded)
```

## Patching

C#: pass only the new body.

```
patch_method_csharp  method="App.Account::Withdraw(int)"
                     code="if (amount <= 0) return; _balance -= amount;"
```

- The body compiles against the real assembly with access checks off. Lambdas, async, `yield` and LINQ work.

New members and types:

```
add_members_csharp  type="App.Shop"  code="private int _bonus; public int Bonus(int x) => x + _bonus;"
add_types_csharp    assembly="App"   code="namespace Extensions { public static class Diagnostics { public static void Trace() { } } }"
```

IL: edit the `get_il` lines and pass them back. `/* token */` comments resolve operands.

```
ldarg.0
call System.String::IsNullOrEmpty(string)
brtrue.s fail
ldc.i4.1
ret
fail:
ldc.i4.0
ret
```

- `mode=prepend` inserts code before the original body. `.local <type>` declares a local.
- `export_edits` binds a script to its build (SHA-256, MVID). `apply_edits` refuses another build unless `targetBuild=other`.

## Exported projects

- `export_project` writes a project meant to build.
- References: the project's own framework (its reference pack when not installed), NuGet cache, Windows SDK metadata.
- Costura-wrapped dependencies go to `lib\` and are referenced.
- Build-convention files (`Directory.Build.*`, `*.props`, `*.targets`, `NuGet.config`, `global.json`, `gradle/wrapper/*`, `init.gradle`) and shell-parsed files get a `.bin` suffix. `renamedFiles` lists them.
- Missing dependencies are rebuilt as stand-ins from how the code uses them. The project still builds.
- Known decompiler output errors are rewritten. A method that cannot be decompiled throws `NotSupportedException`.
