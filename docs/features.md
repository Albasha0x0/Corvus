# Features in detail

Everything Corvus does, tool by tool. The generated per-tool reference with every parameter is [tools.md](tools.md).

## Built on

Corvus is a reverse-engineering server for AI agents over the [Model Context Protocol](https://modelcontextprotocol.io).
It decompiles, searches, cross-references and patches .NET assemblies (including Unity Mono, Il2Cpp games, ReadyToRun
and NativeAOT), and analyzes, diffs and patches native PE, ELF and Mach-O binaries with its own engine (x86, x64, ARM32,
ARM64), with IDA or Ghidra as optional decompilers. No GUI, no admin rights and no network port.

- **Decompiler:** the ILSpy engine (`ICSharpCode.Decompiler`), the same engine dnSpy uses.
- **Metadata and patching:** [dnlib](https://github.com/0xd4d/dnlib), plus a fast `System.Reflection.Metadata` IL scanner.
- **C# method patching:** Roslyn.
- **.NET crash dumps:** [ClrMD](https://github.com/microsoft/clrmd) with the dumped runtime's own data access library (DAC), signature-checked before it loads.
- **Archives:** [SharpCompress](https://github.com/adamhathcock/sharpcompress) reads tar, 7z, RAR, gzip, bzip2 and xz.
- **JavaScript:** [Acornima](https://github.com/adams85/acornima) parses bundles for their module tables; source maps are decoded by our own code.
- **Transport:** stdio, using the official [MCP C# SDK](https://github.com/modelcontextprotocol/csharp-sdk).

## What it covers

**MCP features:** 156 tools (each with a title and read-only / destructive / idempotent / open-world annotations from one audited table, `src/Corvus/Mcp/Contract`),
resources and resource templates (subscribers get an update notice after each workspace change, through `resources/subscribe` or, on 2026-07-28, the `resourceSubscriptions` of a `subscriptions/listen` stream), 15 prompts, argument completion, progress notifications, structured output for the list,
search and info tools, typed errors (`Error (<code>) in <tool>: ...` with a `Next:` step and a JSON copy; codes and format in [docs/errors.md](errors.md)), strict arguments
(an undeclared parameter is `invalid_argument` naming the closest declared ones; closed value sets such as `engine`, `kind`
and `format` are advertised as `enum` and an unlisted value is `invalid_argument` with the closest one), a stale-server check
(`server_status expectedCatalogDigest=...`, `corvus doctor`), a response-size guard (`read_result`; every tool declares `anthropic/maxResultSizeChars` so Claude Code keeps a default page in context instead of saving it to a file), cancellation,
server instructions (a core under 2,048 characters; the details in the `guide` prompt), and workspace notices (files reloaded from disk) at the top of the next tool result.

| Area | Tools |
|---|---|
| Workspace | `save_session` / `load_session` (the session's files by path and SHA-256 with their unsaved .NET edits, native patches, user names and comments, notes, Il2Cpp games (package or metadata and binary) and open minidumps in one JSON file; restored by SHA-256 with a per-item outcome and reason, here, on another machine, or carried to another build with `targetBuild=other`; `dryRun` by default) · `load_assembly` (a file or a whole folder, with progress; native PE, ELF and Mach-O files load as native images, `slice` picks a universal Mach-O's architecture; an Il2Cpp game folder or `global-metadata.dat` goes through the built-in metadata reader: see [Il2Cpp navigation](#il2cpp-navigation)) · `list_assemblies` (ids, versions, ReadyToRun / merged labels, unsaved edits; with `path`, the assemblies inside a container file) · `unload_assembly` · `reload_assembly` · `add_search_directory` · `get_assembly_info` (identity with MVID and file SHA-256, TFM, counts; `view=references`: references and how each resolves; `view=metadata`: PE headers, metadata streams, table row counts and heap sizes, every row with a bad table, coded or heap index (reason and file offset), Il2Cpp detection, method bodies that are not valid IL and exception clauses off instruction boundaries or out of range) |
| Browse | `list_namespaces` · `list_types` · `get_type_info` (outline with tokens, constants, hex enum values, IL sizes, Il2Cpp RVAs and offsets; `section=methods` and the other sections page one kind; on a FieldRVA field, its data: RVA, file offset checked against the bytes, SHA-256, the methods reading it, the elements decoded with the type they are read as, hex rows: [showcase](showcase/fieldrva-table.md)) · `get_type_hierarchy` · `get_attributes` (type, member, parameter, return value, assembly or module; arguments decoded with enums and `[Flags]` combinations by member name, also as typed `{type, value, name}` records; `format=csharp` decompiles the assembly attributes: [showcase](showcase/attribute-arguments.md)) · `resolve_symbol`. Lists page by rows (`offset`, `limit`, `maxTokens`), with `nextOffset` in the text and the record |
| Decompile | `decompile_member` (a type whole, or a member with its overloads, async, iterators and lambdas folded back; `simplified=true` shows the code after `simplify_methods` without editing; `provenance=true` heads it with token, IL hashes, file SHA-256 and MVID) · `get_il` (tokens, offsets, structured EH, a normalized IL hash and the raw IL SHA-256 per method: [docs/il-hash.md](il-hash.md); `source=true`: the source lines of the build's Portable PDB, embedded or beside it with a matching id, at their IL offsets, with local names and SourceLink URLs: [showcase](showcase/source-lines.md)) · `export_project` (whole assembly → .csproj that builds: see [Exported projects](#exported-projects); written whole or not at all, `overwrite=true` replaces a previous export; reports progress and failed types; an `.apk` / `.aab` path gives a Gradle project: manifest and resources decoded at their canonical paths, the resource table as values XML, assets, `jniLibs`, Java through JADX when configured, else smali) |
| Search | `search_symbols` (substring, wildcard or regex) · `search_strings` (paged; for Il2Cpp dummy DLLs, whose bodies are empty, the literals of the dump: see [Il2Cpp string literals](#il2cpp-string-literals)) · `search_constants` (IL literals, const and enum values, attribute arguments, and static array data such as S-boxes, CRC and crypto tables, read element by element as the array's own type) · `search_il` (instruction-sequence patterns with wildcards and gaps) |
| Cross-references | `find_references` (methods, including calls through base / interface methods and static delegate fields; fields by read / write / address; properties; events; types in every position; `kind=overrides`: overrides and implementations; rows reached through a base declaration have `basis=derived`) · `find_callees`. These and the call-graph tools also take framework symbols the loaded code uses (`System.IDisposable::Dispose`) |
| Call graph | `get_call_tree` (callers or callees N levels deep, one row per node in tree order; repeats, recursion and virtual dispatch marked) · `find_call_paths` (shortest call chains from a method or from entry points to a target; direct calls preferred, virtual-dispatch hops marked, `directOnly=true` for direct calls only; to native code too: chains through native callers across loaded images, imports, RTTI virtual calls and resolved function pointers, from native roots or managed methods through P/Invoke, each step with its call site and edge kind) |
| Compare builds | `compare_assemblies` (added, removed and renamed types, members and events; every change of a matched member: rename, signature, body by normalized IL hash, flags and attributes, field-offset and RVA; members matched in tiers, unique-only, ambiguous ones listed with candidates; methods moved to another type paired by identical body; members whose counterpart cannot be judged (bodies not valid IL, unreadable signatures) marked unknown instead of removed or added; IL fingerprints, string literals and constants line up rebuilds whose every name changed; structured result, and `tokenMap=true` keeps the full old → new token map as a result that `read_result outputPath=` writes as JSON) · `find_counterpart` (where a type or member went in the new build, with the tier and confidence; `diff=true` / `il=true` add a unified diff of the pair's decompiled C# / normalized IL, with the new build's renames applied first so a pure rename is no change; for a type, each changed, added or removed member) · `compare_folders` (two folders, zip-family packages or files entry by entry: modified, added, removed, moved by content with ambiguous moves listed, case-only renames, links reported and not followed, locked files unreadable; archives compared by central-directory CRC-32 and size without reading entries; an incomplete side is never reported unchanged; changed binaries with MVID, assembly and file version, machine and timestamp and a ready-to-run next call; inline diffs of small text files; inventories cached so paging does not re-hash) |
| Resources | `list_resources` (with SHA-256 and file offsets; Win32 rows with file ranges, icon groups paired with their RT_ICON entries, icon and bitmap headers decoded) · `get_resource` (text, hex, `.resources` entries, WPF `.baml` entries as XAML; `outputPath` extracts to disk) |
| Containers | `unpack_container` (single-file bundles, Costura, NuGet, Xamarin / MAUI APKs, embedded images; extracts and loads the assemblies, each labelled ReadyToRun / merged; Electron `.asar` with integrity checks, Unity WebGL `.data`, HAR and mitmproxy captures give every file; tar, `.tar.gz` / `.tgz`, `.tar.bz2`, `.tar.xz`, 7z, RAR, xar (macOS `.pkg`) and cpio (`.pkg` Payloads, initramfs) and single gzip / bzip2 / xz files list every entry and extract binaries and nested packages, or every file with `allFiles`) · `search_container` (types and members by name across every assembly in a container, without extracting; capped, with a truncation flag). See [Unpacking containers](#unpacking-containers) |
| JavaScript | `analyze_js` (bundler signatures of a `.js` file: webpack, esbuild, Vite, Parcel, Metro...; its module table (webpack, esbuild, Browserify, Parcel, AMD, SystemJS, Metro and Rollup / Vite ES-module chunks: ids, original paths where the bundle keeps them, requires) and one module's code; search over strings and names with the original position; which modules require one; Hermes bytecode identified; its source map, inline, by `sourceMappingURL` or a sibling `.map`; a minified line:column mapped to the original source and name; the original sources listed and paged from `sourcesContent`) |
| File inspection | `summarize_file` (one report: hashes, identity, strong name and Authenticode with digest check, toolchain markers, container wrapping, features, typed strings, entry points; opens containers; an Electron executable or `.asar` adds Electron / Chromium / Node versions, fuses, archive integrity, the `package.json` main entry and `webPreferences` values with file:line; a loaded native image adds triage: top functions by references with a thunk / wrapper / leaf / dispatcher / complex role, top strings, import groups, entry points at their addresses, roots and leaves) · `survey_features` (capa-style rules over APIs, P/Invoke imports and strings, with ATT&CK techniques and evidence) · `extract_strings` (URLs, domains, IPs, paths, registry keys, mutexes, user agents, crypto keys; JSON / CSV export) · `extract_embedded` (resources, static arrays and strings decoded through base64 / hex / gzip / deflate / XOR). See [File inspection](#file-inspection) |
| Unity titles | `unity_overview` (one call, structured; reads a title folder, an .apk / .ipa or a zipped title in place, and WebGL builds through their .data and .wasm: engine version per source, scripting backend (`il2cpp` / `mono`) with evidence and metadata state (`readable`, `encrypted`, `header_tampered`, ...), toolchain and middleware markers (optional Detect It Easy: `detectItEasy=true`), platform and architecture, and the next tool calls with their arguments) |
| Android packages (`.apk`, `.aab`, `.apks` / `.xapk` / `.apkm`; read natively, any host) | `get_android_manifest` (package, versions and SDKs; permissions incl. `-sdk-23` and `maxSdkVersion`, declared permissions with protection levels; application flags with the network security config file; every component with explicit and effective exported state and the reason, permissions, intent filters, launcher, deep links, meta-data; queries; highlights) · `list_android_resources` (every resource and configuration: id, type, name, qualifiers, typed value; styles, arrays and plurals) · `get_android_resource` (an entry with binary XML decoded and references named, or `@type/name` values per configuration; `savePath` writes it) · `list_dex_classes` (every class of every `classes*.dex`, inner classes included) · `get_dex_class` (fields with static values, methods with exact ids `Lpkg/C;->m(I)V` so overloads never collide, Java signatures, annotations, Kotlin `@Metadata`, inner classes, parameter names) · `disassemble_dex` (smali of one method, never all overloads at once, or of a class, in baksmali's layout with resolved operands, line numbers, try / catch and payloads; `format=annotated` adds offsets and code units) · `decompile_java` (Java / Kotlin source of a class or one exact overload through the JADX headless server, one session per package kept loaded; smali where JADX fails) · `search_dex` (strings loaded by code with each use, types, members with use counts, constants, opcodes) · `find_dex_references` (callers, field readers and writers, class and string uses, or what a method calls and touches, each with method and code offset) · `map_java_dotnet` (Xamarin / .NET for Android: a Java wrapper class or method to its .NET type or method and back, with crc64 wrapper names computed as the build does and methods through `[Register]` or the registered method they override; `get_android_manifest` names each component's .NET type; Unity Mono: the C# that reaches a Java class or member through `AndroidJavaClass` / `AndroidJavaObject` calls, `AndroidJavaProxy` or `AndroidJNI`, matched to exact DEX ids with a confidence) · `list_jni_bindings` (Java native methods paired with their code in `lib/<abi>/*.so`: `Java_` exports by JNI name mangling, overloads included, and `RegisterNatives` tables found in the libraries' data with their class from the `FindClass` string; unbound methods and stray exports listed). `summarize_file` on a package adds its runtimes with evidence (.NET for Android, Unity Il2Cpp / Mono, Flutter, React Native / Hermes, Kotlin / Java), ABIs, DEX files and the APK signature verdict |
| Android devices (adb from `CORVUS_ADB`, `PATH` or the SDK) | `list_android_devices` · `get_android_device_info` (properties with an SDK / ABI / fingerprint summary and emulator evidence; `view=` processes, features, services, settings or the files of a directory) · `list_android_packages` · `get_android_package_info` (versions, paths, ABI, flags, every permission with its install or runtime grant state) · `pull_android_package` (base and split APKs into a new or empty directory with SHA-256, then read like `summarize_file`) · `pull_android_file` · `read_android_log` (logcat by process, tag, priority and time, cut at a byte budget with `truncated=true`) · `install_android_package` (APK, split set or directory) · `uninstall_android_package`; the last two change the device and are off unless the server runs with `--allow-device-changes` |
| Il2Cpp | `get_il2cpp_info` (RVA, VA, file offset, slots, field offsets, tokens; for a method its function bounds, shared code, generic instantiations and string literals; for a type its metadata slots and vtable) · `find_method_by_address` (the methods at or containing an IDA / Ghidra address) — see [Il2Cpp navigation](#il2cpp-navigation) · `export_il2cpp_symbols` (IDA / Ghidra scripts with names and prototypes, a C header with struct layouts, JSON) |
| Native bindings | `generate_cpp_binding` (C++ binding for a type in a Mono or Il2Cpp application: class lookup, field offsets, exact-overload method lookups, typed accessors and invoke wrappers; generic definitions as C++ templates. Styles: `mono` (Mono embedding API), `il2cpp` (Il2Cpp runtime exports, with each method's code pointer), `hostapi` (a host function table found in `projectDir`); without `style` it is picked from the project, and the header's first line says which and why) |
| Patch (in memory, `dryRun` on all) | `rename_symbol` · `rename_namespace` · `stub_method` · `patch_method_csharp` (new body in C#: lambdas, async, `yield`, LINQ, private members accessible) · `add_members_csharp` · `add_types_csharp` · `patch_method_il` (IL assembler that accepts edited `get_il` output; replace or prepend) · `simplify_methods` (for transformed code: string-decoder calls run in a sandboxed IL interpreter and become literals; constant branches, dead code and flattened control flow cleaned up; forwarders and delegate-field call proxies call their real target; every result stack-verified, everything left alone reported with a reason code: [docs/simplify.md](simplify.md)) · `save_assembly` (atomic write with `.bak`, never overwrites without `overwrite=true`; bodies and signatures no edit touched are kept byte-for-byte and the written image is checked against the original: [docs/saving.md](saving.md)) |
| Edit history | `list_edits` · `diff_edits` (before/after decompiled C# of pending edits) · `undo_edit` · `revert_edits` · `export_edits` / `apply_edits` (replayable JSON edit scripts: re-apply a patch set to a new build; a dry run applies and compiles every edit, then rolls back). Unsaved .NET edits and native patches are journaled per user after every change; loading a file whose last session ended without saving names the journal to replay (`apply_edits`, or `migrate_native_patches` with the same image twice) |
| Notes | `record_note` (a finding, question, hypothesis or todo anchored to a native address, a .NET member, a file or a dump; kept per user by file SHA-256 / module MVID across sessions and server processes; native notes show in IDA as marked positions and in Ghidra as bookmarks of category Corvus; evidence entries name a tool call with the SHA-256 of its result, so a check can re-run it) · `update_note` (partial update guarded by the note's revision; a conflict returns the current note) · `list_notes` (by status, kind, anchor, tag and text; an address lists its function's notes) |

**Resources:** `corvus://assemblies`, `corvus://assembly/{assembly}/info`, `corvus://assembly/{assembly}/type/{type}`
(decompiled C#), `corvus://assembly/{assembly}/il/{symbol}`, `corvus://native/{image}/segments` (sections with exclusive
ends and r/w/x), `corvus://native/{image}/entrypoints` (entry point, TLS callbacks, exports with ordinals),
`corvus://native/{image}/type/{name}` (as `get_native_type`), `corvus://guide/{topic}` (the guide topics).

**Prompts:** `analyze_assembly`, `find_feature`, `explain_type`, `plan_patch`, `map_native_address`, `analyze_native`,
`trace_native_feature`, `find_api_usage`, `patch_native`, `compare_builds`, `triage_crash`, `investigate_feature` (a described behaviour traced to its code, with an evidence bundle and the unknowns), `check_reimplementation` (a native function emulated on chosen inputs against expected outputs), `guide` (one topic of the full guidance: `dotnet`, `native`, `il2cpp`, `containers`, `edits`, `builds`, `dumps`, `errors`), `getting_started`.

**Completion:** assembly, native image and open dump ids, type names (full or short), file paths (binaries, dumps, or build folders and packages, by argument) and guide topics for prompt and resource-template arguments.

### Native images

Native `.exe` / `.dll` / `.sys` files, ELF (`.so`, executables) and Mach-O (`.dylib`, executables, one slice of a universal file) images (x86, x64, ARM64 and 32-bit ARM / Thumb-2 decoded by our own engine; other instruction sets go through IDA, else Ghidra, when one is installed, marked "(via IDA)" or "(via Ghidra)") load with
`load_assembly` by path, or are loaded by any native tool given a path. Headerless code (shellcode, firmware, a memory
region) loads with `load_assembly format=raw arch=x86|x64|arm|thumb|arm64 base=… entry=…`: one entry per layout
(`fw.bin[thumb@0x8000000]`), analyzed from its entry by our engine, and by IDA or Ghidra at the same base with the same
processor (each layout keeps its own engine database). Import overrides on `load_assembly` set how both engines import any
native image before their first analysis: `processor=` (IDA's `-p`, checked against its processor modules), `language=` and
`compilerSpec=` (Ghidra's, checked against its `.ldefs`; the compiler spec also sets IDA's compiler), `seeds=` (functions,
code and labels, named or not) and `disableAnalyzers=`; each set is its own engine database beside the default one, and
`get_engine_status` and the provenance name it. A Ghidra archive (`.gzf`, from Ghidra or from
`export_engine_database`) loads the file it was made from, checked against its recorded SHA-256, and Ghidra opens the
archive as the database without analyzing. Everything below is our own analysis
(PE parser, Iced disassembler, function discovery, MSVC RTTI / exception data / name demangling, PDB reader);
only `decompile_native` needs an external engine (IDA through idalib, or Ghidra through a Java worker built on first use). Reliability runs and their numbers:
[docs/native-maturity.md](native-maturity.md); editing contract: [docs/native-editing.md](native-editing.md).

| Area | Tools |
|---|---|
| Overview | `get_pe_info` (headers, mitigations (ELF also CET IBT / shadow stack and BTI / PAC from the GNU property note), sections with entropy, PDB match, version resource, rich header, Authenticode, overlay, anything malformed; ELF program headers, soname, NDK note, build id, relocations; Mach-O slices, segments, libraries, fixups, code signature and entitlements, FairPlay encryption; capability groups from static imports; the same answer whether or not the code index is built) · `list_imports` (per DLL or library; `bind=true` resolves each to its export, `includeDynamic=true` adds GetProcAddress imports) · `list_exports` (ordinals, forwarders and re-exports, MSVC and Itanium names demangled) · `list_resources` / `get_resource` (Win32 resources decoded) · `resolve_address` (RVA / VA / file offset to section, symbol, function and offset, instruction boundary or data item, references by kind, import target, Il2Cpp method, the field of a PDB global) · `get_engine_status` (each IDA or Ghidra session of an image: opening with its stage and elapsed time, or the engine's own view: version, language, compiler, format, analysis complete or partial, warnings, function counts, entry points, input hashes, memory blocks, database, worker pid, unsaved edits; never starts an engine) |
| Code | `list_functions` (names from user / PDB / NativeAOT metadata / Il2Cpp / IDA library recognition / exports / discovery, with size and flags; `view=candidates` lists the code IDA or Ghidra decoded outside any function, most referenced first, for `define_native kind=function`) · `list_globals` (named data outside code from every name source, with PDB and user types and sizes; `engine=ida\|ghidra` adds the engine's defined data with type and value; paged) · `disassemble` (MASM with named calls, data and call arguments; NativeAOT string literals and vtable calls; warns at mid-instruction, data and bss addresses, renders strings, pointers and switch tables as data and resynchronizes, names the gaps between a function's blocks) · `inspect_instruction` (what an address is: instruction start, mid-instruction with the covering instruction, data item, bss; operands with base / index / scale / displacement and access, registers and flags read and written, flow with fallthrough, references, call arguments; ARM64 with pre / post-index writeback, extends and ADRP pairs; ARM32 through IDA or Ghidra) · `search_instructions` (mnemonic, operand and line regexes and an operand value over every function, one function or a range; paged within a scan budget; also over IDA's or Ghidra's listing) · `get_cfg` (blocks, edges, switch cases: values per target, default and bias, also through IDA; unresolved jumps with the reason) · `get_exception_info` (MSVC try blocks, unwind maps, SEH scopes, funclets; ELF / Mach-O LSDA call sites, landing pads and caught types) · `find_xrefs` (code and data references, also across loaded images and through import slots, thunks and virtual calls; struct members `Type::member` through IDA or Ghidra) · `native_call_tree` (callers / callees across loaded images, P/Invoke and C++/CLI seams, RTTI virtual calls; `calls=all\|direct\|virtual`; `direction=both`: one level of callers and callees by call site with call / jump, direct / indirect, external and virtual flags) · `get_call_arguments` (recovered argument values per call site, each with its derivation) · `trace_native_values` (a value traced backward to its sources or forward to its uses across functions: merges, loops, callers' arguments, callee returns, writers and readers of globals, API constants decoded; budgets with follow-up calls for what they leave out; `engine=ida` or `ghidra` takes each function's slice from Hex-Rays microcode or Ghidra p-code, falling back per function) · `resolve_call_targets` (targets of call sites with basis and confidence: imports, thunks, constant and GetProcAddress pointers, RTTI virtual calls, NativeAOT interface calls through their dispatch cells, writers of global function pointers, pointer tables, `deep=true` through callers; `scope=image` lists every unresolved indirect site with its reason; `engine=ida` or `ghidra` merges that engine's view) · `analyze_native_function` (one function, or up to 16, in bounded sections: identity with xref counts, signature evidence, frame, callers with reachability, callees with targets and arguments, data, flow with loops, switches and cyclomatic complexity, annotations; optional constants, parameter values from callers and pseudocode; `component=true` over several functions: internal calls, shared globals and strings, interface or internal; a failing section keeps the others) · `trace_native_feature` (from a text to the code behind a behaviour: matching strings, names, imports, exports and RTTI classes, their references through string interiors, pointer tables and import calls with arguments, functions ranked by evidence, hubs that reach several; failures per seed) · `find_similar_functions` (functions like a given one, ranked by a score with the evidence: instruction-shape similarity with registers, addresses and constants ignored, containment for inlined copies, CFG shape, shared strings, constants, imports and callees; identical and same-shape copies first; across every loaded image of the architecture with `scope=all`; `view=duplicates` groups same-shape bodies, `view=clusters` links near-duplicates image-wide through MinHash bands; sketches built once per code index) · `search_native_strings` (also Il2Cpp and NativeAOT string literals; `engine=ida\|ghidra` adds the strings the engine defined that nothing references, in its string types) · `search_bytes` (hex with `??` and nibble wildcards (`4?`), per-bit masks (`40&F8`, `mask=`), or text; up to 50 patterns a call without an engine; `memory=engine\|ida\|ghidra` searches the engine's loaded bytes and marks hits the loader fixed up) · `read_bytes` (hex dump, or `type=` values: integers in either byte order, floats, pointers with their target's name, string runs; uninitialized bytes as `??`) · `convert_number` (decimal, signed, hex, binary, octal, LE / BE bytes, ASCII and float views of a number at a width) |
| Engine preference | `engine=auto\|ours\|ida\|ghidra` on `list_functions`, `disassemble`, `search_instructions`, `get_cfg`, `find_xrefs`, `native_call_tree`, `resolve_call_targets` and `trace_native_values` (server default `--engine` / `CORVUS_ENGINE`). `auto`: the first engine (IDA, then Ghidra) that has analyzed the image's bytes, open in this process or saved in the analysis cache, else ours; the choice never depends on earlier calls; `ours`: the built-in index only; `ida` / `ghidra`: that engine's analysis, started or waited for (one image can have both). Our names win over the engine's and RTTI virtual-call edges it lacks are added. `inspect_instruction` takes `auto\|ours\|ida\|ghidra`; its `auto` is the built-in decoder for x86 / x64 / ARM64 and IDA (else Ghidra) for ARM32. Every result names its engine. |
| Symbols and classes | `load_pdb` (the matching PDB from beside the file, the CodeView path, symbol path or caches; `download=true` from a symbol server; names saved per file hash and reapplied on later loads; `clear=true` removes them) · `search_pdb_symbols` · `list_cpp_classes` (RTTI classes, bases, vftables: MSVC on PE, Itanium typeinfo and vtables on ELF / Mach-O; `engine=ghidra` lists Ghidra's class namespaces, also PDB classes, with function counts and vftables, `namespaces=true` adds the other namespaces and libraries; `engine=ida` lists IDA's C++ structs with bases, vftable slots and Class:: function counts) · `get_native_type` (a type's layout by name, id or typed address from the PDB, RTTI, Il2Cpp and the engine's types (IDA or Ghidra): fields with offsets, sizes and bit fields, padding, bases, vftable slots named, enums by value, function types; ambiguous names list their ids; `at=0x48` names the field at an offset, also through unions, arrays and pointers; an address in a PDB global gives its field path; `read=true` adds each field's value from the image's bytes, at a typed address or with a name at any address) · `find_virtual_calls` (virtual call sites resolved through RTTI; `crossCheck=true` compares with IDA, else Ghidra) · `apply_il2cpp_names` (Il2Cpp method names, string literals and metadata slots onto GameAssembly.dll, also pushed into IDA; saved and reapplied like PDB names) · `get_nativeaot_info` (a NativeAOT image's runtime version, sections, recovery stages, MethodTables, named method bodies, frozen strings, statics with their types and interface dispatch cells, .NET 7-10 in PE, ELF and Mach-O, 64- and 32-bit; its method, vtable, MethodTable and string names apply on load as the nativeaot layer, below PDB names, go into IDA and Ghidra and into export_native_annotations). Node-API add-ons (`.node`) name their callbacks after the JavaScript names they register (`js_<name>`, `js_get_` / `js_set_`, `js_Class_member`) from the constant arguments of their N-API registration calls (napi_create_function, napi_define_properties, napi_define_class, napi_module_register), as the napi layer |
| Decompile | `decompile_native` (Hex-Rays pseudocode through IDA's idalib worker, or Ghidra's decompiler through a Java worker (`CORVUS_GHIDRA_DIR`, a JDK); analysis cached per file hash, an IDA `.i64` left beside the input and made from the same bytes used as a starting copy; our names, patches, Il2Cpp prototypes, RTTI class structs and the PDB's types pushed in, so pseudocode shows real struct and member names; `functions=[...]` decompiles several in one request with a per-function deadline, deduplicated, keeping partial results, and `callersOf=` the callers of a function by the engine's references; `--prewarm ida\|ghidra\|auto` analyzes images in the background as they load) · `search_decompiled` (a regex over the pseudocode of every function or a filtered set, in batches sized to the decompiler pool and reused from earlier calls; stops at a function count, time budget or hit limit with a cursor to continue) · `emulate_native` (static p-code emulation in Ghidra's emulator from a function or address, nothing run natively: arguments by the calling convention, registers, memory writes, strings and buffers in a private scratch area; calls step into the image or return `stubs=` values (`*=0` answers every call); stops on return, a stop address or an instruction or time budget; an unmodelled call or unmapped read is an error naming the address; reports the return value, changed registers, written memory with decoded strings, reads and a trace) · `ida_python` (IDAPython in the image's IDA worker, code or a script file, `persist=true` saves the database; off unless the server runs with `--ida-scripting` / `CORVUS_IDA_SCRIPTING=1`) · `ghidra_script` (a Java GhidraScript in the image's Ghidra worker, one transaction rolled back on failure and saved after; off unless `--ghidra-scripting` / `CORVUS_GHIDRA_SCRIPTING=1`) · `export_engine_database` (the image's engine database with everything pushed into it, for the engine's GUI: a compressed `.i64` copy for IDA, a packed `.gzf` archive for Ghidra; Ghidra's own types alone as a `.h` header or `.gdt` archive) |
| Engine types (IDA or Ghidra; edits saved per file hash, re-applied to a new database, exported and carried to new builds) | `set_native_type` (function prototypes and global types; user types win over the recovered ones; `items` applies many in one request) · `set_native_local` (rename / retype a pseudocode local or argument, by name or stack offset) · `get_native_frame` (stack frame members and decompiler locals) · `set_native_stack_var` (rename / retype / create / delete a stack frame member) · `declare_native_types` (C structs, unions, enums and typedefs; they win over recovered types of the same name; `typeName` with `members` adds, changes or removes enum members, with `fields` struct or union members (by name or offset); `delete` and `rename` edit a named type, and a rename follows into the other edits) · `list_native_types` (browse the database's types, one in full with member offsets; `related=true` names the types each refers to) · `define_native` (make code, a function (with its end), data (byte / word / dword / qword / float / double / string / string16 / a C type, with `[count]`) or undefined bytes at an address; replayed in order on a new database) · `reanalyze_native` (the engine's auto-analysis run again over the image or a range within a time budget, with analyzer options for that run; `analyzers=true` lists them with their values; also completes a Ghidra analysis the open cut short) · `set_native_operand` (an operand as hex / dec / oct / bin / char, offset, stack variable, enum member or struct offset, or back to the default; Ghidra uses equates and references) |
| Edit (in memory, `dryRun` on patches) | `rename_native` · `comment_native` (kept per file hash across restarts) · `export_native_annotations` (IDA / Ghidra scripts, JSON, C header; the user's names over the NativeAOT and Il2Cpp layers) · `patch_bytes` · `patch_asm` (x86 / x64 MASM assembled at the address, relocation-correct under ASLR; `extend=true` moves code too large for its site into a relocation stub in a code cave or a new section; unsafe sites are refused with a reason code) · `list_native_edits` (patches and name layers; `search=` finds names and comments by text) · `undo_native_edit` · `export_native_patches` (IDAPython, IDA `.dif`, IPS / IPS32 or JSON, each reproducing `save_native`'s bytes) · `save_native` (patched copy, checksum recomputed, relocations re-checked, `.bak`, verified after writing). Contract: [docs/native-editing.md](native-editing.md) |
| New builds | `update_to_new_build` (one call carries names, comments, PDB / Il2Cpp layers, byte patches, code patterns, notes and the Il2Cpp method mapping to a new build, with a reason code for everything that did not carry; for two .NET assemblies, notes on members follow `find_counterpart`; `dryRun` by default) · `migrate_native_patches` (byte patches reapplied only where the new build's original bytes match) · `compare_native_images` (function matches in tiers, unique-only) · `diff_function` (one matched function's aligned instruction diff with build-independent operands: calls by matched name, branch targets as aligned labels, strings by text, data by mapped address; or a unified diff of both builds' IDA pseudocode) · `map_address_between_builds` · `migrate_native_names` · `make_code_pattern` (rebuild-stable IDA-style pattern, on ARM64 with branch, ADRP and low-12 fields masked; `anchor=xrefs` makes one at every reference, IDA's included) · `search_code_pattern` |
| .NET and native together | `verify_native_imports` (each `[DllImport]` checked against the real DLL's exports; Linux / macOS / Android / iOS targets on any host: `.so` / `.dylib` probed as .NET does along the RID chain, ELF / Mach-O exports, C++ mangled names, `__Internal` in an Il2Cpp game binary, wrong_platform and arch_mismatch; verified / contradicted / unresolved / dynamic_only / not_checked with a reason code, plus run-time loading sites in the IL) · `get_r2r_code` / `find_r2r_method` (a method's ReadyToRun precompiled code, and the method at a native address) · the .NET call tools take native exports as symbols (`kernel32.dll!CreateFileW`) and follow P/Invokes into native code; mixed-mode C++/CLI assemblies also load as native images |
| Crash dumps | `open_minidump` (Windows user-mode minidump: the exception, faulting thread, instruction and registers, modules, threads; module files found by path, by name in `imageDirectories`, then by timestamp and size (renamed copies, loaded images, local symbol stores); for .NET (CoreCLR and .NET Framework, 64- and 32-bit) the managed exception with its inner chain, threads and heap state through the runtime's signature-checked DAC, found locally or downloaded only with `downloadDac=true`; a 32-bit dump is decoded by the bundled 32-bit decoder process, which checks the DAC's hash before loading it) · `dump_stack` (x64 unwind through `.pdata`, x86 frame pointers; frames named from loaded images, PDBs and exports; .NET frames from the runtime's own walk with token, IL offset, the loaded assembly of that build and the C# statement at that IL offset; Mono JIT code named from the Mono runtime's report beside a Unity dump, whose managed exception `open_minidump` shows) · `dump_heap` (.NET heap statistics by type, or matching objects, bounded) · `dump_object` (a .NET object's fields, string or array elements, references expanded) · `read_dump_memory` · `symbolize_stack_text` (crash text without a dump: Unity Player.log / error.log backtraces, Mono and Il2Cpp managed lines, .NET exception text, WER Report.wer, Event Log 1000/1026, debugger stacks, Android tombstones; each frame resolved against the loaded build with a build check by time stamp, MVID, BuildId or name, and the C# statement at a frame's IL offset) · `bucket_minidumps` (a folder of dumps grouped by crash signature: exception code, faulting function and top frames, managed for .NET; offsets and versions per bucket, a representative dump each, incremental) Linux and Android ELF core dumps open through the same tools: threads and registers (x64, x86, ARM64, ARM; ppc64, s390x and riscv64 registers only), the signal, mapped modules matched to local files by GNU build id, process and auxv facts, `.eh_frame` CFI stack unwinding with a frame-pointer fallback, and memory reads. |
| Live processes | `inspect_process` (read-only view of a running local Windows process: modules, memory regions, threads and call stacks with named addresses; query and read handles only, nothing written or suspended: [docs/live-inspection.md](live-inspection.md)) |
| Session | `server_status` (version and commit, program path with an `expectedExecutable` check, install kind, start time, negotiated protocol and client, tool catalog digest and `expectedCatalogDigest` check, limits, toolsets, the tools or modes that cannot work here with the reason and fix, long-running tools, which engines are available and how to fix a missing one, IDA background-analysis state, open and total notes; sections for the budget, kept results, caches, leftover calls and lock holders, worker processes and the run id) · `read_result` (a kept result by its content id `r-<12 hex>`, kept on disk 7 days across restarts: pages by `maxTokens`, `query` searches its lines, `format=json|jsonl` gives the structured record, `outputPath` writes it whole and returns its SHA-256) |

## Reliability

| Concern | How it is handled |
|---|---|
| Locked files | Assemblies are read into memory; files on disk are never locked. |
| Concurrency | Reads share a lock; edits take it exclusively, and a call cancelled while it waits for the lock returns at once. Stress-tested with interleaved readers and writers, and with 40 parallel MCP calls. |
| Corrupt or transformed bodies | The IL scanner stops at invalid opcodes instead of throwing; `decompile_member` on a type falls back to member-by-member output with IL for the broken part. |
| Post-processed metadata | Out-of-range names and coded indexes that some third-party toolchains leave behind are read leniently by dnlib but not by the decompiler; such assemblies are decompiled from a copy normalized by dnlib, with the same tokens, and the output says so. |
| Invisible names | Names made of zero-width and bidi characters (U+202E reverses the rest of a line) are shown as `\uXXXX`, as the decompiler does; symbols are accepted back in that form. |
| Huge output | Paged by estimated tokens per part (`offset` / `maxTokens`, `nextOffset` in both parts); pages come from a cache. A result with no natural order sends its head and is kept (on disk, `CORVUS_RESULT_CACHE`) for `read_result`, which pages, searches or exports it. `read_result format=evidence` writes a findings bundle: kept results or the session's latest calls (`last:N`) with tool, arguments, input SHA-256s, text and record; `format=verify` re-runs every call through the same pipeline and names each record whose input or content differs. |
| Files changing on disk | Watched: clean assemblies reload automatically; ones with unsaved edits are left alone and the agent is told. |
| Slow first queries | Method bodies are indexed and the call graph is built in the background after loading, in small chunks that never block edits. |
| Runaway work | Each decompilation stops after `--timeout` (default 180 s; `export_project` 10×). A call to a tool not marked long-running ends with a retryable `timeout` error after twice `--timeout` (its partial result when the tool kept one). MCP cancellation stops a call in flight or waiting for the workspace lock. |
| Vague names | A symbol resolver accepts many spellings and tokens; ambiguity and misses return candidates. |
| Unexpected exceptions | Returned as tool errors; the server keeps running. |
| Invalid patches | IL is stack-validated, C# is compiled (errors point at your line), and nothing changes on failure. Patched assemblies are executed in the tests to prove the IL is valid at runtime. |

Measured on a real Unity application (36 assemblies, 40,895 types, ~300k methods):

- Load all assemblies: 94 ms.
- Decompile every one of its 23,327 application types concurrently: 40 s, with 0 failures.
- First full string search: 2.7 s; repeat searches: 0.3 s.
- Type cross-references across everything: 1.9 s.
- Compare two builds of the main assembly (11k types): about 5 s.
- Export IDA/Ghidra scripts and a C header for a whole Il2Cpp dump (93k functions, 9k structs): 3.6 s; the header compiles with clang.
- Il2Cpp string literals of a game (41k literals, 254 MB script.json, 216 MB GameAssembly.dll): indexed and every code
  reference found in 1.5 s on first use (42 MB kept, with the script.json index below); 98.7% of the literals are loaded by code, 97.3% by a dummy-DLL method.
- Il2Cpp navigation index of the same dump (288k function starts, 573k script.json methods, 38k metadata and 91k
  MethodInfo slots): 0.9-1.4 s on first use, 27 MB kept (823k methods: 1.2-1.7 s, 34 MB); then about 1 ms per address
  lookup. On 200 sampled addresses per kind every function start, interior address, generic instantiation, literal,
  metadata and MethodInfo slot is named correctly.

## Il2Cpp navigation

No external dumper is needed: `load_assembly` on an Il2Cpp game folder or its `global-metadata.dat` (with
`GameAssembly.dll` beside it) reads the metadata directly through LibCpp2IL (versions 24-39; on a title with v31 metadata read from a memory dump,
methods, RVAs, vtable slots, fields, field offsets and every `script.json` method agree 100% with Il2CppDumper's output; first read
15 s, reloads from the per-user cache `CORVUS_IL2CPP_CACHE` in 0.1 s). Unreadable metadata is an error with a reason
(`encrypted_or_obfuscated`, `unsupported_version`, `binary_mismatch_or_protected`, ...); single items that cannot be read
are listed by reason in the load report. Mobile and Unix builds read the same way: an `.apk` / `.xapk` / `.apks` / `.aab`
(`libil2cpp.so` of one ABI, `slice=` picks it; only the binary, the metadata and the version files are extracted to the
cache), an extracted Android package, an `.ipa` or iOS `.app` (`UnityFramework`; FairPlay-encrypted binaries fail with
`encrypted_fairplay`), a macOS `.app` (`GameAssembly.dylib`) or a Linux build (`GameAssembly.so`). When LibCpp2IL
does not find the code registration, it is found from the module list (Unity 6 armeabi-v7a), or built from the module array when
the game fills it at run time (Unity 2021.3 armeabi-v7a, 2023.2 Linux; no generic method bodies then); 32-bit ARM builds that still
fail report `registration_not_found_armv7` / `armv7_unreadable` and point to the arm64-v8a build.

`global-metadata.dat` loaded with no binary beside it (a file pulled from a device or a memory dump of the metadata alone)
still gives the inventory, in the same dummy-assembly form the other tools read: images, types with flags, nesting (from the
metadata's nested-type table), value type or enum, generic parameters; methods with flags and parameter names; fields,
properties, events and metadata tokens; and every string literal for `search_strings`. Each Unity sub-version layout of the
header version is tried and the first whose names and ranges read back consistently is kept. Types a signature names live
in the binary, so they show as `TypeInBinary`, and there are no addresses or field offsets. On a v31 title (159 images,
31,540 types, 230,177 methods) the read takes 6 s and gives the same images, types, methods, fields and literals as the read
with the binary.
Il2CppDumper / Cpp2IL output folders keep working as below.

With only the dummy DLLs, the known function starts are the dummy methods' `[Address]` RVAs; `find_method_by_address`
then reports the preceding method as "probably inside", because generic instantiations (a third to a half of a game's
functions) have no dummy method and can sit in between. When the dump's `script.json` is in the DummyDll folder or its
parent, its `Addresses` and `ScriptMethod` entries give every function start, so a function ends where the next one
starts (or at the end of its section, when `GameAssembly.dll` is there too), and the address is named by:

- the dummy-DLL methods starting there and the `script.json` names of the instantiations sharing the code (shared
  generic bodies and identical code folding put over 30k methods on one function: a total, then `offset` / `limit`);
- a string literal slot, a `ScriptMetadata` slot (`Ns.Type_TypeInfo` class pointer, `_var` type, `Field$` data) with
  the dummy type it describes, or a `ScriptMetadataMethod` slot (`Method$Ns.Type.M()`) with the function it describes;
- nothing, when the address is more than 0x40000 bytes past the last function start before it, or outside the
  executable sections.

`kind=auto` reads an address at or above the image base (the dumper's, from the `VA` values, or the binary's) as a VA,
any other as an RVA, and as a file offset only when the RVA finds nothing; `kind` forces one reading.

The other way, `get_il2cpp_info` gives a method's function bounds, how many methods share its code, its MethodInfo
slot and, for a generic method or a method of a generic type, the `script.json` instantiations with their RVAs; a
type's metadata slots (for a generic type, those of its instantiations); and with `slot=N` the method implementing
vtable slot N (searching base types; `slot=all` lists the vtable). Names only `script.json` has are accepted as the
symbol: `List`1<int>::Add`, `System.Collections.Generic.List<int>$$Add`, `List<System.Int32>.Add` (generic arguments
also match by simple name), a type alone for all its instantiated methods, `Ns.Type_TypeInfo`,
`Method$Ns.Type.M()`. A literal's slot comes from `search_strings`.

`script.json` names drop arity, so one name can stand for several dummy methods (`Action<int>$$.ctor`: the `.ctor`
of every `Action` arity; `List<int>$$IndexOf`: three overloads). An instantiation is matched to its method by the
generic argument counts of the name, then the parameter count of its C prototype, then its C types (`int32_t`, `X_o`
by value, `X_o*`, `X_array*`, `Il2CppObject*`, enums as their underlying type) compared with each candidate's types as
declared and with the arguments substituted; a unique best match wins. When candidates are left with the same C
signature (two enums of one width, `T` and `in T`, the same method in two assemblies), the instantiation is reported as
ambiguous with the candidates listed, both on the instantiation and on each candidate's list. On two games, 95% and
92% of the instantiations of such names resolve to one method, the rest are ambiguous; every resolved one that the
dumper's `dump.cs` lists is the overload it lists it under, and every ambiguous one has that overload among its candidates.

The index keeps sorted arrays and the names as pooled UTF-8 (type and method parts separately); signatures and
metadata names are read back from `script.json` by file offset when shown.

## Il2Cpp string literals

Il2CppDumper's dummy DLLs have empty method bodies, so the game's string literals are not in them. When the dump's
`stringliteral.json` (or `script.json`) is in the DummyDll folder or its parent, `search_strings` searches those
literals too and prints each with the RVA of its slot (the global the code loads the string object from). When
`GameAssembly.dll` (x64) is in that folder or its parent as well, the executable sections are scanned once for
RIP-relative `mov` / `lea` of the slots; each load is attributed to the function containing it (function starts from
`script.json`'s `Addresses`) and named by the dummy-DLL method whose `[Address]` RVA starts there, or by the
`script.json` name (generic instantiations have no dummy method of their own). `get_il2cpp_info` on a method lists
the literals its native code loads, and `find_method_by_address` names a literal slot.

The files are read on first use, streamed (`script.json` is hundreds of MB), and kept until they change or the
dummy DLLs are unloaded. With an assembly filter, only literals used by that assembly's methods are listed. Literals
a game stores encrypted are shown as stored. 32-bit and non-PE binaries (`libil2cpp.so`) are not scanned.

## Unpacking containers

`unpack_container` takes a file, extracts the .NET code inside it, and loads the assemblies it finds (`extractOnly=true`
to only extract). It reads bytes only and never runs the file. When an extracted file is itself a container
(for example a Costura-wrapped app inside a single-file bundle, or a `.nupkg` inside a zip), it is opened too,
up to 4 levels deep, into a `<name>_unpacked` folder next to it.

| Container | How it is recognized | What comes out |
|---|---|---|
| .NET single-file bundle (`PublishSingleFile`) | The bundle signature in an apphost: Windows PE, Linux ELF or macOS Mach-O | Every manifest entry under its bundle path: assemblies, native libraries, `.deps.json`, `.runtimeconfig.json`, symbols. Compressed bundles (`EnableCompressionInSingleFile`) are inflated, and every entry is checked against its declared size. |
| Costura.Fody | A .NET assembly with `costura.*` / `costura32.*` / `costura64.*` manifest resources | Each embedded assembly under its original name, inflated when the resource ends in `.compressed`. |
| NuGet package (`.nupkg`) | A zip with a `.nuspec` | `lib/`, `runtimes/` and `tools/` assemblies (one per target framework), and nested packages. |
| Xamarin / MAUI `.apk` / `.aab` | A zip with `AndroidManifest.xml` | Assemblies, with `XALZ` (LZ4) and `XAZS` (Zstandard) ones decompressed. Assembly stores are parsed, so entries keep their names and ABI (`assemblies/<abi>/Name.dll`, with `.pdb` / `.config` data when present): v1 `assemblies[.<abi>].blob` (names from `assemblies.manifest`, else from the metadata), v2 / v3 raw or inside `libassemblies.<abi>.blob.so` (`payload` section) and `libassembly-store.so` (`_assembly_store` symbol). A store that does not parse is scanned for PE images and `XALZ` chunks instead, with a note. An assembly repeated in several per-ABI stores is written once. |
| Other zips (`.zip`, `.vsix`, `.xap`) | Zip signature | `.dll` / `.exe` / `.winmd`, `.deps.json` / `.runtimeconfig.json`, and nested packages. Everything else (images, Android resources, Java code) is skipped. |
| Standalone `XALZ` / `XAZS` file | `XALZ` / `XAZS` magic | The decompressed assembly. |
| Electron `.asar` | The pickle header with a JSON file tree | Every file, `.asar.unpacked` ones included and links written as copies of their targets. Each file's SHA-256 and 4 MiB block hashes are checked (`ok`, `hash_mismatch`, `block_mismatch` with the first bad block, `no_integrity`, `unpacked_missing`; an unpacked add-on Authenticode-signed after packing is `ok_signed_after_packing`), and the header hash against the one the app declares (the executable's `INTEGRITY/ELECTRONASAR` resource, or `ElectronAsarIntegrity` in `Info.plist`): good, bad or absent. Names with a separator, `..`, `:` or a control character are listed, never written. |
| Unity WebGL `.data` (also `.gz`, `.br`, `.unityweb`) | `UnityWebData1.0` | Every file, each with its role (Il2Cpp metadata and its version, serialized files, bundles), the Unity version, and the `.wasm` / `.framework.js` / `.loader.js` beside it named. |
| HAR, mitmproxy flow files | A JSON `log.entries` array; tnetstrings | One file per response body, named `host/path` (the query folded into a short hash, the extension from the MIME type), decoded from base64 and its `Content-Encoding` (gzip, deflate, br, zstd). Nothing is fetched or replayed. |
| Anything else | No known format | .NET images and `XALZ` chunks carved out of the raw bytes (installers, memory dumps), validated by their PE headers. |

A plain .NET assembly is reported as containing nothing, and an apphost without a bundle as a launcher for the
.dll beside it. NativeAOT executables are identified, with a note that they have no IL to decompile.

The tool returns structured output: the detected container, the output directory, one entry per file (`path`,
`kind`, `size`, `sha256`, `origin` (where in the container it came from and how it was decoded), `loadedAs` (the
workspace id, if loaded), and for .NET assemblies `readyToRun` and `merged`), and notes about anything skipped.

To see what is inside without writing or loading anything, call `list_assemblies` with `path`. It walks the
container the same way (same parser, same limits, nested containers included) and returns a `container` section:
each managed assembly's path inside the container, full name, version, size, SHA-256, origin, `readyToRun` and
`merged`. A plain assembly lists itself. A zip cut off or missing its central directory (a broken download) still
lists its entries, read from their local headers (sizes from the header, zip64 field, or the data descriptor of a
streamed zip, checked by CRC), with a note; encrypted or damaged entries are skipped by name. A container with nothing
readable returns a tool error that says what is wrong. For an archive (`.asar`, Unity WebGL `.data`, HAR, flows) the
section also lists every entry with its size and flags (integrity verdict, unpacked, link target; role; method, status
and URL), paged by `offset` / `limit` and filtered by path. Without
`path`, `list_assemblies` lists the workspace as before.

`search_container` searches the metadata of every managed assembly in a container (or a plain assembly) by name,
also without writing or loading anything. Matching is the same as `search_symbols`: a case-insensitive substring,
`*` / `?` wildcards, and full-name matching when the query contains `.` or `:`. `kind` narrows it to `type`,
`method`, `field` or `property`. Each match gives the assembly's path inside the container, the assembly name, the
full member name and the kind, best matches first (exact, then prefix, then substring). At most `limit` matches are
returned (default 200, up to 5000); `total` counts every match and `truncated` says whether some were left out.

Other kinds search files rather than metadata. `kind=electron` lists where an Electron app's own scripts cross a
boundary, each with `file:line:column`: preload scripts, `contextBridge` keys, IPC channels handled in main and used
from renderers, `child_process` and `shell` sinks, and native add-ons loaded, each add-on found under
`app.asar.unpacked` and named with its N-API registrations (the query matches the channel or the row kind, e.g. `ipc-main`). `kind=endpoint` on a HAR or mitmproxy capture lists each request template once (numeric and id
path segments folded, query values never shown) with its request count and statuses. `compare_folders` compares two
`.asar` archives entry by entry without unpacking (the app's declared SHA-256 per file, or the hashed data).

**ReadyToRun** (`readyToRun`): the image carries precompiled native code next to its IL (crossgen2,
`PublishReadyToRun`, and the shared framework itself). The IL is still there and decompiles normally.

**Merged assemblies** (`merged`, omitted when there is no sign of merging):

| Tool | Trace | Original module count |
|---|---|---|
| ILRepack | An `ILRepack.List` resource listing every merged assembly (unless run with `/noRepackRes`) | Exact, with the names |
| ILMerge | No marker of its own, but a later input's non-public type that clashes is renamed to `Input.Name` (compiler-generated types) or `Input<key>.Name`, next to the first input's `Name`. C# cannot declare a dotted type name, so the pair is reliable | At least (renamed inputs + 1), with the renamed inputs' names. Inputs with no clashing types leave no trace |
| Either, pre-Roslyn inputs | Several `<PrivateImplementationDetails>{MVID}` helper classes, one per original module | At least that many |

This is detection and labelling only: merged assemblies are not split back into their inputs.

Malformed and untrusted input is expected:

- **Output stays inside the output directory.** Entry names are split on both `/` and `\`, and `.`, `..`,
  rooted and drive parts are dropped. Every final path is checked against the output root before writing.
  Reserved device names (`CON`, `NUL`, ...) get a `_` prefix.
- **Nothing extracted can be double-clicked.** Runnable extensions (`.exe`, `.bat`, `.ps1`, `.lnk`, ...) get a `.bin`
  suffix. `.dll` is kept so extracted assemblies still resolve by name.
- **Corrupt or truncated data.** Every offset and length is bounds-checked and overflow-safe. A corrupt container
  fails with a clear error; a corrupt *entry* is skipped with a note and the rest still comes out.
- **Decompression bombs.** Each item is limited to 512 MB, a whole unpack to 4 GB and 20,000 files. An `XALZ` header
  that claims more than LZ4 could produce from its data is rejected before anything is allocated.
- **Output directory.** By default a folder under the temp directory named after the file and its SHA-256. A
  directory you pass must be new, empty, or an earlier unpack of the same file (a marker file records which). An
  unrelated directory is never written into.

## File inspection

Four tools that read an assembly's metadata, IL, resources and signature without executing it. Each takes a loaded
`assembly` or a `path`; `summarize_file` also accepts containers (bundles, packages, APKs, zips) and summarizes up to
25 assemblies inside.

| Tool | Output |
|---|---|
| `summarize_file` | File hashes, type and entropy; per assembly: identity (name, version, MVID, target framework, GUI / console / library, architecture, ReadyToRun, merged), strong name and Authenticode signature, toolchain markers and heuristics, container wrapping (embedded assemblies, decoded embedded content, high-entropy sections), features, a summary of typed strings, and entry points (Main, module initializers, native exports, installer / service / AppDomainManager / COM hooks). For a NativeAOT executable: runtime version, module sections and counts of the method names, MethodTables and frozen strings its metadata recovers. `highlights` lists the notable findings. A file over 64 MiB is read as a stream: hashes, captures, zip (SAZ, NuGet), HAR and tar / 7z / gzip archives never hold it whole (a 2 GB capture adds about 10 MB to the working set); formats that need the whole image (PE, ELF, Mach-O, wasm, APK and IPA signatures) still read it. The default `view=overview` keeps to identity, hashes, signature, the assemblies, highlights, entry points and value counts; `view=managed`, `native`, `android`, `electron`, `go`, `sqlite` (a SQLite 3 database read by its own B-tree reader, no SQL and no native library: page size, encoding, journal mode, the schema as stored, row counts and the first rows of each table; a -wal file is not read), `flutter` (Dart AOT snapshots of a Flutter app, libapp.so or App.framework/App, with their version hash and features, or the Dart VM version and build id of a Flutter engine), `rust` (the crate list cargo-auditable embeds in .dep-v0: root crate, every crate with version, source and kind, and the dependency edges), `pcap` (a pcap / pcapng capture in one streaming pass, no TShark needed: Ethernet, VLAN, SLL / SLL2, raw IP and loopback; the largest TCP/UDP flows, DNS names with A / AAAA / CNAME answers, TLS ClientHello server names with ALPN, HTTP/1.x request templates; `search_container kind=endpoint` lists the same requests and names, and also reads HAR, mitmproxy and Fiddler `.saz` captures), `nib` (a compiled nib, NIBArchive or keyed archive: classes, outlets and actions, each action resolved to its implementation in the enclosing app's executable through the Objective-C metadata), `plist` (binary or XML property lists as JSON; NSKeyedArchiver archives decoded into their object graph), `apple` (an `.ipa` or `.app` folder: Info.plist facts, every Mach-O with its role and a signature verdict per slice from its page hashes, the main executable's entitlements, the provisioning profile's kind), `firmware` (formats found at offsets inside an opaque image: U-Boot, squashfs, cramfs, device trees, TRX, UBI, Android boot, gzip, xz, LZMA, zip, ELF and PE, each sized by its own header), `wasm` (a WebAssembly module's imports by module, exports, memories, function counts, toolchain from the producers section or its import shapes, name-section names) or `all` gives the details (the record's `views` names those that apply). |
| `survey_features` | Rules over the APIs the code calls, the native functions it imports, its string literals and (native) crypto and hash constants (AES, SHA-256/512, MD5, SHA-1, CRC-32, Blowfish, ChaCha, TEA, FNV, MurmurHash3 tables and immediates), in categories: network, execution, registry, persistence, collection, credential access, anti-analysis, defense evasion, code loading, injection, discovery, crypto. Each matched feature has its evidence (pattern, count, up to 5 locations) and an ATT&CK technique where the operation is the technique itself. The default page lists each feature with its match count; `category` (a category, a technique prefix, or `all`) adds the evidence, marked `basis=derived` when it is a string or argument constant. |
| `extract_strings` | URLs, domains, IPv4 / IPv6, email addresses, file paths, named pipes, registry keys, mutex names, user agents and crypto keys from string literals, constants, resource text and decoded embedded text, with the APIs each value is passed to. Rows are paged (offset / limit); every value is kept as a result that `read_result` with `outputPath` writes as CSV (`format=text`) or JSON. |
| `extract_embedded` | Embedded resources, `.resources` entries, static byte arrays and string literals of 64+ characters, decoded through hex, base64, gzip / zlib / deflate and XOR until a recognized kind appears (PE / .NET images, archives, ELF / Mach-O, text), plus high-entropy blobs. Each item shows its source and encoding chain, e.g. `base64 > xor key 5a > gzip`. `save=true` writes them with defanged names; `load=true` also loads the .NET ones; `xorText=true` adds a single-byte XOR search over text (see below); images (png, jpeg, gif, ico) are only counted unless `includeMedia=true`. A container path (`.apk`, `.nupkg`, zip, bundle) searches every assembly inside; rows are paged by `offset` / `limit`. |

Limits:

- **Features describe API use.** A rule matches when the code calls, imports or contains what the rule lists (an
  HTTP client call matches "send HTTP requests"); it does not tell whether or when the code runs.
- **XOR keys are recovered from known file headers** (PE, ZIP, gzip), so XOR is undone when it covers a binary or
  compressed item, with keys up to the header's length (up to 3 bytes for gzip, 4 for ZIP, 16 for PE). XOR straight
  over plain text has no known plaintext to recover a key from, so by default it is not decoded.
- **`xorText=true`** (`extract_embedded`, off by default) recovers repeating XOR keys of 1-16 bytes over text in
  resources and arrays that are not readable as they are: UTF-8 text in any script (English, Arabic, Cyrillic, CJK...)
  and UTF-16 text, including structured configuration (JSON, XML, URL lists, key=value / INI). Key lengths come from
  the index of coincidence (flat, encrypted-looking data is skipped at once); each key byte is chosen for the bytes it
  covers, then refined by how likely the decoded character pairs are, with known starts of configuration (`{"`,
  `https://`, `<?xml`, `[`) tried as plaintext for the first key bytes; text in other scripts is refined as UTF-8. A
  decode is kept only when it is natural text (valid in its encoding, no control or stray characters, words of real
  length with vowels in Latin script, likely letter pairs, natural repetition in CJK) or parses as JSON / XML / config
  lines. Such items show `xor key 1337c0de (brute-forced)` (`, UTF-16 text` for UTF-16, returned as UTF-8) in their
  chain. Measured on 30 real assemblies (libraries with codec and opcode tables, PowerShell, WPF and Unity applications): no false
  decodes, 32 seconds for all of them.
- **Authenticode:** the digest check (was the file changed after signing?) and the signature check are exact. Whether the
  chain is trusted depends on the machine's root store; revocation is not checked (offline and deterministic).
- **Lookalikes are excluded:** XML / schema namespace URLs, version numbers that look like IP addresses, and file
  names or namespaces that look like domain names are not reported as values.
- Corrupt or truncated assemblies give a tool error saying what is unreadable; inside a container, one unreadable
  assembly is noted and the others are still summarized.

## Symbol syntax

```
Ns.Type          Ns.Outer+Inner   Ns.Outer/Inner   Ns.Outer.Inner   Type (short name)
List`1           List<T>
Ns.Type::Method  Ns.Type.Method   Ns.Type::Method(int, string)      Ns.Type::.ctor
0x06000123       (metadata token; pass `assembly` when several assemblies are loaded)
```

## Patching

**C#:** pass only the new body.

```
patch_method_csharp  method="App.Account::Withdraw(int)"
                     code="if (amount <= 0) return; _balance -= amount;"
```

The body is compiled as a static helper against the real assembly (with accessibility checks off), `this` and implicit
members rewritten to the instance. The new IL is then transplanted, with references mapped back to the original
definitions and reference scopes. Lambdas, closures, async, `yield`, LINQ and local functions work: the compiler-generated
closure and state-machine types are copied into the target. Members that would be inaccessible at runtime are relaxed,
or an `IgnoresAccessChecksTo` attribute is added for other assemblies.

**New members and types:**

```
add_members_csharp  type="App.Shop"  code="private int _bonus; public int Bonus(int x) => x + _bonus;"
add_types_csharp    assembly="App"   code="namespace Extensions { public static class Diagnostics { public static void Trace() { } } }"
```

**History:** every edit is recorded. `diff_edits` shows the decompiled C# before and after, `undo_edit` removes one edit
(the rest are replayed), `export_edits` writes a JSON script tied to its build (the file's SHA-256, the MVID and the
assembly identity), and `apply_edits` replays it, by token on the same build and by name on a new one; another build is
refused with a conflict error naming expected vs actual unless `targetBuild=other` (try `dryRun=true` first), and the
report says what was remapped. Scripts from before this check apply with a warning. When a target was renamed in the new build, load the build the script was made from as well:
`apply_edits` then follows the target through the same content match as `compare_assemblies` and reports the new name.

**IL:** call `get_il` on the method, edit the instruction lines, and pass them back. The `/* token */` comments resolve
operands exactly. Hand-written IL works too:

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

`mode=prepend` inserts code before the original body and can branch into it by its offsets (`bge IL_0000`).
`.local <type>` declares a local variable.

## Exported projects

`export_project` writes a project meant to build, not just to read. On a survey of 30 real assemblies (NuGet libraries
such as Newtonsoft.Json, System.Text.Json, NLog, SharpCompress, AsmResolver and BouncyCastle; PowerShell 7's
System.Management.Automation; a transformed, Costura-wrapped WPF app; Windows Store installers; Unity assemblies),
every one whose dependencies exist on disk builds with no errors, and a rebuilt BouncyCastle computes the same results
as the original. What makes that work:

- **References for the target framework:** framework assemblies of the project's own .NET version (its reference pack
  when that runtime is not installed), the .NET Standard reference assembly for netstandard libraries, .NET Framework
  reference assemblies for .NET Framework apps (and a path for the ones outside them), dependencies from the NuGet
  cache built for that framework, Windows Runtime metadata from the Windows SDK (one union `Windows.winmd`) and from
  installed app packages.
- **Wrapped dependencies:** assemblies inside the exported one (Costura) are written to `lib\` and referenced.
- **Project settings the build needs:** `StartupObject` from the entry point, public signing with the original public
  key (friend assemblies that grant internals by key keep doing so), preserialized resources for a .NET Framework
  project whose `.resx` holds images or other non-string data (`dotnet build` requires them; 4.6.2 or later).
- **Output the decompiler engine gets wrong, rewritten** (also in `decompile_member`): span-slicing
  `ref` temporaries, `scoped` locals, initialized `stackalloc`, base constructor calls in bodies, constructor
  parameters in field initializers, nested locals of one name, struct enumerators disposed by pattern, trimmed
  getters, bools used as integers, negative constants cast to unsigned types, null-conditional extension calls,
  framework type names that clash across imported namespaces, compiler-reserved and source-generator attributes, and
  transformation leftovers (renamed `value` parameters, unspeakable parameter names, dropped `new()` constraints, a
  renamed `Main`). LINQ comes out as method calls in exports.
- A method the engine cannot decompile at all keeps the engine's explanation and throws `NotSupportedException`.

**Dependencies that are not on the machine** (an assembly missing from a partial dump) do not stop decompilation: a
stand-in is rebuilt from how the loaded code uses it: every type it references or forwards to it with its kind (struct, enum,
interface, delegate, exception, attribute), every member with its exact signature, properties and events, the virtual
members the code overrides, and what generic constraints require. The decompiler then reads the rest against real
types (no "unknown result type" guesses, properties instead of accessor calls), `get_assembly_info` lists the reference
as `not found; stub built from what the loaded code uses (N types, M members)`, and an exported project references the
stand-in from `lib\` (with a note saying so) and builds. Enum member names of a missing enum are compiled away, so
its values show as numbers (`(Mode)2`).

Also recovered: local functions the engine drops (compiled into a closure because lambdas capture their variables),
and a constructor's work the engine shows as field initializers or a primary constructor: `decompile_member` on such
a constructor shows it inside its type, trimmed to what runs as part of it.

On 30 real assemblies, including an application with three dependencies missing, every exported project builds with 0
errors.
