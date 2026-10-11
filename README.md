# NetDecompilerMcp

Ask your coding agent how a compiled program works: it reads the code of .NET assemblies and native PE, ELF and Mach-O
binaries, follows calls, compares builds, and can patch and save a copy. Nothing is executed and nothing is uploaded.

## Get started

**Windows** (PowerShell):

```powershell
irm https://raw.githubusercontent.com/Albasha0x0/NetDecompilerMcp/main/install.ps1 | iex
```

**Linux / macOS:**

```sh
curl -fsSL https://raw.githubusercontent.com/Albasha0x0/NetDecompilerMcp/main/install.sh | sh
```

While the repository is private, set `GITHUB_TOKEN` to a token with read access first (for example
`GITHUB_TOKEN=$(gh auth token)`).

The installer checks the download against the release's `SHA256SUMS`, shows which MCP clients it will register with,
and asks once. **Restart your client**, then paste this prompt:

> Use net-decompiler to load the NetDecompilerMcp.dll of its own installation (`%LOCALAPPDATA%\NetDecompilerMcp\current`
> on Windows, `~/.local/share/net-decompiler-mcp/current` elsewhere) and explain how its `install` command decides
> which MCP clients to register. Cite the methods you read.

Expected result: the agent calls `load_assembly`, finds the setup code with `search_symbols`, reads it with
`decompile_member`, and answers with the plan rules (existing registrations are refreshed, detected new clients wait
for confirmation, named clients are added), citing `SetupPlan.Build` and `SetupCli.Install`.

From a terminal, without an agent ([docs/cli.md](docs/cli.md)):

```sh
NetDecompilerMcp tools
NetDecompilerMcp decompile_member --load app.dll member=Ns.Type::Method
NetDecompilerMcp batch steps.jsonl
```

Questions: [docs/faq.md](docs/faq.md). Something not working: `NetDecompilerMcp status`, then
[docs/troubleshooting.md](docs/troubleshooting.md).

**Documentation:** [installation](docs/installation.md) (clients, options, skill, update, uninstall) ·
[command line](docs/cli.md) · [tool reference](docs/tools.md) · [errors](docs/errors.md) ·
[troubleshooting](docs/troubleshooting.md) · [FAQ](docs/faq.md) · [testing](docs/testing.md) ·
[release notes](docs/release-notes.md)

**Lawful use.** Analyze software you own or are permitted to analyze. Decompiling, patching or redistributing
third-party code can be restricted by its license and by law where you live; you are responsible for complying.

## About

A headless .NET decompiler and native analyzer for AI agents, served over the [Model Context Protocol](https://modelcontextprotocol.io).
It decompiles, searches, cross-references and patches .NET assemblies, including Unity Mono builds and
Il2CppDumper / Cpp2IL dummy DLLs, and analyzes, diffs and patches native PE, ELF and Mach-O files (x86 / x64 / ARM64), with IDA as the
optional decompiler for native code. No GUI, no dnSpy instance, no admin rights and no network port.

- **Decompiler:** the ILSpy engine (`ICSharpCode.Decompiler`), the same engine dnSpy uses.
- **Metadata and patching:** [dnlib](https://github.com/0xd4d/dnlib), plus a fast `System.Reflection.Metadata` IL scanner.
- **C# method patching:** Roslyn.
- **.NET crash dumps:** [ClrMD](https://github.com/microsoft/clrmd) with the dumped runtime's own data access library (DAC), signature-checked before it loads.
- **Transport:** stdio, using the official [MCP C# SDK](https://github.com/modelcontextprotocol/csharp-sdk).

## Install details

One command installs everything and registers the server with every MCP client on the machine. Nothing to
configure, no admin rights, no .NET needed (the download is self-contained).

**Windows** (PowerShell):

```powershell
irm https://raw.githubusercontent.com/Albasha0x0/NetDecompilerMcp/main/install.ps1 | iex
```

**Linux / macOS:**

```sh
curl -fsSL https://raw.githubusercontent.com/Albasha0x0/NetDecompilerMcp/main/install.sh | sh
```

Options: `--version X` (a release to pin or roll back to), `--dry-run` (show the release, the checksum source, the
install folder and every client file it would change; change nothing), `--yes` (register new clients without
asking) and `--client a,b` (only those clients). On Windows they are `-Version`, `-DryRun`, `-Yes` and `-Client`:
`& ([scriptblock]::Create((irm <url>))) -DryRun`; with sh: `curl -fsSL <url> | sh -s -- --dry-run`.
`NDM_VERSION` and `NDM_YES=1` do the same from the environment. Piped into `sh`, the confirmation is read from the
terminal.

Then restart your MCP client. What the installer does:

1. Downloads the latest release for your system (Windows, Linux glibc / musl, macOS; x64 and arm64) into a per-user
   folder (`%LOCALAPPDATA%\NetDecompilerMcp`, `~/.local/share/net-decompiler-mcp`) and puts `NetDecompilerMcp` on PATH.
   The download is checked against the release's `SHA256SUMS` (as is every `update`); a missing manifest or a
   mismatch stops the install. A local archive given in `NDM_ARCHIVE` is checked only when `NDM_SHA256SUMS` names a manifest.
2. Starts the server once and checks it answers (MCP handshake and tool list).
3. Registers it as `net-decompiler` with the installed clients it finds, keeping their other settings (each changed
   file is backed up once as `<file>.netdecompiler.bak`; a file it cannot parse is left untouched and reported). An
   existing `net-decompiler` entry keeps your arguments (e.g. `--load`), env and other keys; only its command is updated.
   Only the entry's text changes, so comments and formatting elsewhere in the file are kept.
   Clients without an entry are listed first, with each file it would change, and registered after one keypress
   (Enter = yes). Without a terminal they are registered only with `--yes` (or `NDM_YES=1`) or `--all-detected`.

Supported clients: Claude Code, Claude Desktop, Cursor, Windsurf, VS Code, VS Code Insiders, VSCodium, Cline, Roo Code,
Kilo Code, Visual Studio, Codex, Gemini CLI, Qwen Code, GitHub Copilot CLI, OpenCode, Crush, Zed, LM Studio,
Amazon Q, Kiro, Antigravity, Devin, Command Code, Grok Build, OMP and Pi. Any other client: add the output of
`NetDecompilerMcp config`. Client folders moved with `CLAUDE_CONFIG_DIR`, `CODEX_HOME`, `GEMINI_CLI_HOME`,
`QWEN_HOME`, `COPILOT_HOME`, `OPENCODE_CONFIG`, `OPENCODE_CONFIG_DIR`, `GROK_HOME`, `PI_CONFIG_DIR`, `OMP_PROFILE`,
`PI_CODING_AGENT_DIR` or `XDG_CONFIG_HOME` are followed. An entry the client has turned off (`disabled`,
`enabled: false`, a disable list) is reported and kept off.

| Command | What it does |
|---|---|
| `NetDecompilerMcp status` | Read-only check (alias `doctor`): which clients have it registered and with which copy, each registration started with its own args and env, the tool catalog against this build, and the engines (IDA, Python, Ghidra). `--client X`, `--engine ida\|python\|ghidra\|all` (`--deep` starts IDA's worker) and `--target PATH` narrow it, and only what is in scope can fail; `--json` prints the report. Exit codes: 0 healthy, 1 a failure in scope, 2 usage error. |
| `NetDecompilerMcp install [client...]` | Register again, e.g. after installing a new client; names (or `--client a,b`) register clients not detected. `--dry-run` prints the plan and writes nothing, `--json` prints the plan and result as JSON, `--yes` / `--all-detected` add new clients without asking, `--strict` writes nothing when a client's file cannot be read, `--dev-reload DIR` registers the development relay (below). |
| `NetDecompilerMcp update` | Install the latest release and refresh existing registrations (it never adds clients); client settings point at a stable path and need no change. `--version X` installs release X, also an older one; `--dry-run` shows what it would install. |
| `NetDecompilerMcp config [client]` | Print the configuration for a client, or the generic `mcpServers` JSON. |
| `NetDecompilerMcp uninstall` | Remove it from every client and delete the program files (`--keep-files` keeps them). Your annotations, caches and symbols are kept; `--purge-data` deletes them too; `--dry-run` lists what it would remove. |

From source instead: `./publish.ps1`, then `publish/NetDecompilerMcp install`.

`install --skill` also writes an optional agent skill, generated from the server's own guidance, for clients that read
skills (Claude Code, Codex, Gemini CLI, Cursor, GitHub Copilot CLI, OpenCode, Antigravity); later installs and updates keep
it current and `uninstall` removes it ([docs/installation.md](docs/installation.md#the-agent-skill)).

### Development reload

For work on the server itself: `publish/NetDecompilerMcp install --dev-reload publish` registers a relay instead of the
server (`config --dev-reload publish` prints it). The relay runs from a staged copy under
`<LocalAppData>/NetDecompilerMcp/relay` (`NDM_RELAY_DIR`), speaks MCP to the client and runs the server published in
that folder as a child, itself from a staged copy. Each `./publish.ps1` writes `publish/.build-complete` last; once
it is stable and no call is in flight, the relay starts the new build, repeats the client's `initialize`, replays
the workspace calls that succeeded (`load_assembly`, `unload_assembly`, `add_search_directory`, `load_pdb`,
`unpack_container`, log level, resource subscriptions), switches over and sends `tools`, `prompts` and `resources`
`list_changed`, so the client sees the new build without reconnecting. A `[relay]` line on the next tool result names
the build, its catalog digest and what was replayed. In-memory edits, native engine sessions and kept results are not
carried over: with unsaved edits or patches the switch waits until they are saved or reverted, and the added tool
`relay_apply` switches at once. A build that fails to start or to replay is reported and the old server stays.
Arguments after the relay's own (`relay --target <dir> [--state <dir>] [--poll-ms <n>] [--] ...`) go to the server;
a plain `install` switches the registration back. publish.ps1 renames files of a running server aside
(`*.aside-*`) and deletes them once free.

## What it covers

**MCP features:** 155 tools (each with a title and read-only / destructive / idempotent / open-world annotations from one audited table, `src/NetDecompilerMcp/Mcp/ToolEffects.cs`),
resources and resource templates (subscribers get an update notice after each workspace change), 13 prompts, argument completion, progress notifications, structured output for the list,
search and info tools, typed errors (`Error (<code>) in <tool>: ...` with a `Next:` step and a JSON copy; codes and format in [docs/errors.md](docs/errors.md)), strict arguments
(an undeclared parameter is `invalid_argument` naming the closest declared ones; closed value sets such as `engine`, `kind`
and `format` are advertised as `enum` and an unlisted value is `invalid_argument` with the closest one), a stale-server check
(`server_status expectedCatalogDigest=...`, `NetDecompilerMcp doctor`), a response-size guard (`read_result`; every tool declares `anthropic/maxResultSizeChars` so Claude Code keeps a default page in context instead of saving it to a file), cancellation,
server instructions (a core under 2,048 characters; the details in the `guide` prompt), and workspace notices (files reloaded from disk) at the top of the next tool result.

| Area | Tools |
|---|---|
| Workspace | `save_session` / `load_session` (the session's files by path and SHA-256 with their unsaved .NET edits, native patches, user names and comments, and notes in one JSON file; restored by SHA-256 with a per-item outcome and reason, here, on another machine, or carried to another build with `targetBuild=other`; `dryRun` by default) · `load_assembly` (a file or a whole folder, with progress; native PE, ELF and Mach-O files load as native images, `slice` picks a universal Mach-O's architecture; an Il2Cpp game folder or `global-metadata.dat` goes through the built-in metadata reader: see [Il2Cpp navigation](#il2cpp-navigation)) · `list_assemblies` (ids, versions, ReadyToRun / merged labels, unsaved edits; with `path`, the assemblies inside a container file) · `unload_assembly` · `reload_assembly` · `add_search_directory` · `get_assembly_info` (identity with MVID and file SHA-256, TFM, references and how each resolves, PE headers, metadata streams, table row counts and heap sizes, every row with a bad table, coded or heap index (reason and file offset), Il2Cpp detection, method bodies that are not valid IL and exception clauses off instruction boundaries or out of range) |
| Browse | `list_namespaces` · `list_types` · `get_type_info` (outline with tokens, constants, hex enum values, IL sizes, Il2Cpp RVAs and offsets) · `get_type_hierarchy` · `get_attributes` (type, member, parameter, return value, assembly or module) · `resolve_symbol` |
| Decompile | `decompile_type` · `decompile_member` (overloads, async, iterators and lambdas folded back; `simplified=true` shows the code after `simplify_methods` without editing; `provenance=true` heads it with token, IL hashes, file SHA-256 and MVID) · `get_il` (tokens, offsets, structured EH, a normalized IL hash and the raw IL SHA-256 per method: [docs/il-hash.md](docs/il-hash.md)) · `decompile_assembly_attributes` · `export_project` (whole assembly → .csproj that builds: see [Exported projects](#exported-projects); reports progress and failed types; an `.apk` / `.aab` path gives a Gradle project: manifest and resources decoded at their canonical paths, the resource table as values XML, assets, `jniLibs`, Java through JADX when configured, else smali) |
| Search | `search_symbols` (substring, wildcard or regex) · `search_strings` (paged; for Il2Cpp dummy DLLs, whose bodies are empty, the literals of the dump: see [Il2Cpp string literals](#il2cpp-string-literals)) · `search_constants` (IL literals, const and enum values, attribute arguments, and static array data such as S-boxes, CRC and crypto tables, read element by element as the array's own type) · `search_il` (instruction-sequence patterns with wildcards and gaps) |
| Cross-references | `find_references` (methods, including calls through base / interface methods and static delegate fields; fields by read / write / address; properties; events; types in every position) · `find_callees` · `find_overrides`. These and the call-graph tools also take framework symbols the loaded code uses (`System.IDisposable::Dispose`) |
| Call graph | `get_call_tree` (callers or callees N levels deep, breadth-first so a node budget cuts the deepest level; repeats, recursion and virtual dispatch marked) · `find_call_paths` (shortest call chains from a method or from entry points to a target; direct calls preferred, virtual-dispatch hops marked, `includeVirtual=false` for direct calls only; to native code too: chains through native callers across loaded images, imports, RTTI virtual calls and resolved function pointers, from native roots or managed methods through P/Invoke, each step with its call site and edge kind) |
| Compare builds | `compare_assemblies` (added, removed and renamed types, members and events; every change of a matched member: rename, signature, body by normalized IL hash, flags and attributes, field-offset and RVA; members matched in tiers, unique-only, ambiguous ones listed with candidates; methods moved to another type paired by identical body; members whose counterpart cannot be judged (bodies not valid IL, unreadable signatures) marked unknown instead of removed or added; IL fingerprints, string literals and constants line up rebuilds whose every name changed; structured result, and `tokenMapPath` writes the full old → new token map as JSON) · `find_counterpart` (where a type or member went in the new build, with the tier and confidence; `diff=true` / `il=true` add a unified diff of the pair's decompiled C# / normalized IL, with the new build's renames applied first so a pure rename is no change; for a type, each changed, added or removed member) |
| Resources | `list_resources` · `get_resource` (text, hex, `.resources` entries, WPF `.baml` entries as XAML; extract to disk) |
| Containers | `unpack_container` (single-file bundles, Costura, NuGet, Xamarin / MAUI APKs, embedded images; extracts and loads the assemblies, each labelled ReadyToRun / merged) · `search_container` (types and members by name across every assembly in a container, without extracting; capped, with a truncation flag). See [Unpacking containers](#unpacking-containers) |
| File inspection | `summarize_file` (one report: hashes, identity, strong name and Authenticode with digest check, toolchain markers, container wrapping, features, typed strings, entry points; opens containers; a loaded native image adds triage: top functions by references with a thunk / wrapper / leaf / dispatcher / complex role, top strings, import groups, entry points at their addresses, roots and leaves) · `survey_features` (capa-style rules over APIs, P/Invoke imports and strings, with ATT&CK techniques and evidence) · `extract_strings` (URLs, domains, IPs, paths, registry keys, mutexes, user agents, crypto keys; JSON / CSV export) · `extract_embedded` (resources, static arrays and strings decoded through base64 / hex / gzip / deflate / XOR). See [File inspection](#file-inspection) |
| Unity titles | `unity_overview` (one call, structured: engine version per source, scripting backend (`il2cpp` / `mono`) with evidence and metadata state (`readable`, `encrypted`, `header_tampered`, ...), toolchain and middleware markers (optional Detect It Easy: `detectItEasy=true`), platform and architecture, and the next tool calls with their arguments) |
| Android packages (`.apk`, `.aab`, `.apks` / `.xapk` / `.apkm`; read natively, any host) | `get_android_manifest` (package, versions and SDKs; permissions incl. `-sdk-23` and `maxSdkVersion`, declared permissions with protection levels; application flags with the network security config file; every component with explicit and effective exported state and the reason, permissions, intent filters, launcher, deep links, meta-data; queries; highlights) · `list_android_resources` (every resource and configuration: id, type, name, qualifiers, typed value; styles, arrays and plurals) · `get_android_resource` (an entry with binary XML decoded and references named, or `@type/name` values per configuration; `savePath` writes it) · `list_dex_classes` (every class of every `classes*.dex`, inner classes included) · `get_dex_class` (fields with static values, methods with exact ids `Lpkg/C;->m(I)V` so overloads never collide, Java signatures, annotations, Kotlin `@Metadata`, inner classes, parameter names) · `disassemble_dex` (smali of one method, never all overloads at once, or of a class, in baksmali's layout with resolved operands, line numbers, try / catch and payloads; `format=annotated` adds offsets and code units) · `decompile_java` (Java / Kotlin source of a class or one exact overload through the JADX headless server, one session per package kept loaded; smali where JADX fails) · `search_dex` (strings loaded by code with each use, types, members with use counts, constants, opcodes) · `find_dex_references` (callers, field readers and writers, class and string uses, or what a method calls and touches, each with method and code offset) · `map_java_dotnet` (Xamarin / .NET for Android: a Java wrapper class or method to its .NET type or method and back, with crc64 wrapper names computed as the build does and methods through `[Register]` or the registered method they override; `get_android_manifest` names each component's .NET type; Unity Mono: the C# that reaches a Java class or member through `AndroidJavaClass` / `AndroidJavaObject` calls, `AndroidJavaProxy` or `AndroidJNI`, matched to exact DEX ids with a confidence) · `list_jni_bindings` (Java native methods paired with their code in `lib/<abi>/*.so`: `Java_` exports by JNI name mangling, overloads included, and `RegisterNatives` tables found in the libraries' data with their class from the `FindClass` string; unbound methods and stray exports listed). `summarize_file` on a package adds its runtimes with evidence (.NET for Android, Unity Il2Cpp / Mono, Flutter, React Native / Hermes, Kotlin / Java), ABIs, DEX files and the APK signature verdict |
| Android devices (adb from `NDM_ADB`, `PATH` or the SDK) | `list_android_devices` · `get_android_device_info` (properties with an SDK / ABI / fingerprint summary and emulator evidence) · `list_android_packages` · `get_android_package_info` (versions, paths, ABI, flags, every permission with its install or runtime grant state) · `pull_android_package` (base and split APKs into a new or empty directory with SHA-256, then read like `summarize_file`) · `pull_android_file` · `read_android_log` (logcat by process, tag, priority and time, cut at a byte budget with `truncated=true`) · `install_android_package` (APK, split set or directory) · `uninstall_android_package`; the last two change the device and are off unless the server runs with `--allow-device-changes` |
| Il2Cpp | `get_il2cpp_info` (RVA, VA, file offset, slots, field offsets, tokens; for a method its function bounds, shared code, generic instantiations and string literals; for a type its metadata slots and vtable) · `find_method_by_address` (the methods at or containing an IDA / Ghidra address) — see [Il2Cpp navigation](#il2cpp-navigation) · `export_il2cpp_symbols` (IDA / Ghidra scripts with names and prototypes, a C header with struct layouts, JSON) |
| Native bindings | `generate_cpp_binding` (C++ binding for a type in a Mono or Il2Cpp application: class lookup, field offsets, exact-overload method lookups, typed accessors and invoke wrappers; generic definitions as C++ templates. Styles: `mono` (Mono embedding API), `il2cpp` (Il2Cpp runtime exports, with each method's code pointer), `hostapi` (a host function table found in `projectDir`); without `style` it is picked from the project, and the header's first line says which and why) |
| Patch (in memory, `dryRun` on all) | `rename_symbol` · `rename_namespace` · `stub_method` · `patch_method_csharp` (new body in C#: lambdas, async, `yield`, LINQ, private members accessible) · `add_members_csharp` · `add_types_csharp` · `patch_method_il` (IL assembler that accepts edited `get_il` output; replace or prepend) · `simplify_methods` (for transformed code: string-decoder calls run in a sandboxed IL interpreter and become literals; constant branches, dead code and flattened control flow cleaned up; forwarders and delegate-field call proxies call their real target; every result stack-verified, everything left alone reported with a reason code: [docs/simplify.md](docs/simplify.md)) · `save_assembly` (atomic write with `.bak`, never overwrites without `overwrite=true`; bodies and signatures no edit touched are kept byte-for-byte and the written image is checked against the original: [docs/saving.md](docs/saving.md)) |
| Edit history | `list_edits` · `diff_edits` (before/after decompiled C# of pending edits) · `undo_edit` · `revert_edits` · `export_edits` / `apply_edits` (replayable JSON edit scripts: re-apply a patch set to a new build; a dry run applies and compiles every edit, then rolls back). Unsaved .NET edits and native patches are journaled per user after every change; loading a file whose last session ended without saving names the journal to replay (`apply_edits`, or `migrate_native_patches` with the same image twice) |
| Notes | `record_note` (a finding, question, hypothesis or todo anchored to a native address, a .NET member, a file or a dump; kept per user by file SHA-256 / module MVID across sessions and server processes; native notes show in IDA as marked positions and in Ghidra as bookmarks of category NDM) · `update_note` (partial update guarded by the note's revision; a conflict returns the current note) · `list_notes` (by status, kind, anchor, tag and text; an address lists its function's notes) |

**Resources:** `netdecomp://assemblies`, `netdecomp://assembly/{assembly}/info`, `netdecomp://assembly/{assembly}/type/{type}`
(decompiled C#), `netdecomp://assembly/{assembly}/il/{symbol}`, `netdecomp://native/{image}/segments` (sections with exclusive
ends and r/w/x), `netdecomp://native/{image}/entrypoints` (entry point, TLS callbacks, exports with ordinals),
`netdecomp://native/{image}/type/{name}` (as `get_native_type`), `netdecomp://guide/{topic}` (the guide topics).

**Prompts:** `analyze_assembly`, `find_feature`, `explain_type`, `plan_patch`, `map_native_address`, `analyze_native`,
`trace_native_feature`, `find_api_usage`, `patch_native`, `compare_builds`, `triage_crash`, `guide` (one topic of the full guidance: `dotnet`, `native`, `il2cpp`, `containers`, `edits`, `builds`, `dumps`, `errors`), `getting_started`.

**Completion:** assembly, native image and open dump ids, type names (full or short), file paths (binaries, dumps, or build folders and packages, by argument) and guide topics for prompt and resource-template arguments.

### Native images

Native `.exe` / `.dll` / `.sys` files, ELF (`.so`, executables) and Mach-O (`.dylib`, executables, one slice of a universal file) images (x86, x64, ARM64 and 32-bit ARM / Thumb-2 decoded by our own engine; other instruction sets go through IDA, else Ghidra, when one is installed, marked "(via IDA)" or "(via Ghidra)") load with
`load_assembly` by path, or are loaded by any native tool given a path. Everything below is our own analysis
(PE parser, Iced disassembler, function discovery, MSVC RTTI / exception data / name demangling, PDB reader);
only `decompile_native` needs an external engine (IDA through idalib, or Ghidra through a Java worker built on first use). Reliability runs and their numbers:
[docs/native-maturity.md](docs/native-maturity.md); editing contract: [docs/native-editing.md](docs/native-editing.md).

| Area | Tools |
|---|---|
| Overview | `get_pe_info` (headers, mitigations, sections with entropy, PDB match, version resource, rich header, Authenticode, overlay, late-bound imports, anything malformed; ELF program headers, soname, NDK note, build id, relocations; Mach-O slices, segments, libraries, fixups, code signature and entitlements, FairPlay encryption; capability groups from imports; once the code index is built, a code section: functions, coverage, switch tables, unresolved jumps, virtual calls, RTTI classes, most called and largest functions) · `list_imports` (per DLL or library; `bind=true` resolves each to its export, `includeDynamic=true` adds GetProcAddress imports) · `list_exports` (ordinals, forwarders and re-exports, MSVC and Itanium names demangled) · `list_resources` / `get_resource` (Win32 resources decoded) · `resolve_address` (RVA / VA / file offset to section, symbol, function and offset, instruction boundary or data item, references by kind, import target, Il2Cpp method, the field of a PDB global) · `get_engine_status` (each IDA or Ghidra session of an image: opening with its stage and elapsed time, or the engine's own view: version, language, compiler, format, analysis complete or partial, warnings, function counts, entry points, input hashes, memory blocks, database, worker pid, unsaved edits; never starts an engine) |
| Code | `list_functions` (names from user / PDB / NativeAOT metadata / Il2Cpp / IDA library recognition / exports / discovery, with size and flags; `view=candidates` lists the code IDA or Ghidra decoded outside any function, most referenced first, for `define_native kind=function`) · `list_globals` (named data outside code from every name source, with PDB and user types and sizes; `engine=ida\|ghidra` adds the engine's defined data with type and value; paged) · `disassemble` (MASM with named calls, data and call arguments; NativeAOT string literals and vtable calls; warns at mid-instruction, data and bss addresses, renders strings, pointers and switch tables as data and resynchronizes, names the gaps between a function's blocks) · `inspect_instruction` (what an address is: instruction start, mid-instruction with the covering instruction, data item, bss; operands with base / index / scale / displacement and access, registers and flags read and written, flow with fallthrough, references, call arguments; ARM64 with pre / post-index writeback, extends and ADRP pairs; ARM32 through IDA or Ghidra) · `search_instructions` (mnemonic, operand and line regexes and an operand value over every function, one function or a range; paged within a scan budget; also over IDA's or Ghidra's listing) · `get_cfg` (blocks, edges, switch cases: values per target, default and bias, also through IDA; unresolved jumps with the reason) · `get_exception_info` (try blocks, unwind maps, SEH scopes, funclets) · `find_xrefs` (code and data references, also across loaded images and through import slots, thunks and virtual calls; struct members `Type::member` through IDA or Ghidra) · `native_call_tree` (callers / callees across loaded images, P/Invoke and C++/CLI seams, RTTI virtual calls; `calls=all\|direct\|virtual`; `direction=both`: one level of callers and callees by call site with call / jump, direct / indirect, external and virtual flags) · `get_call_arguments` (recovered argument values per call site, each with its derivation) · `trace_native_values` (a value traced backward to its sources or forward to its uses across functions: merges, loops, callers' arguments, callee returns, writers and readers of globals, API constants decoded; budgets with follow-up calls for what they leave out; `engine=ida` or `ghidra` takes each function's slice from Hex-Rays microcode or Ghidra p-code, falling back per function) · `resolve_call_targets` (targets of call sites with basis and confidence: imports, thunks, constant and GetProcAddress pointers, RTTI virtual calls, writers of global function pointers, pointer tables, `deep=true` through callers; `scope=image` lists every unresolved indirect site with its reason; `engine=ida` or `ghidra` merges that engine's view) · `analyze_native_function` (one function, or up to 16, in bounded sections: identity with xref counts, signature evidence, frame, callers with reachability, callees with targets and arguments, data, flow with loops, switches and cyclomatic complexity, annotations; optional constants, parameter values from callers and pseudocode; `component=true` over several functions: internal calls, shared globals and strings, interface or internal; a failing section keeps the others) · `trace_native_feature` (from a text to the code behind a behaviour: matching strings, names, imports, exports and RTTI classes, their references through string interiors, pointer tables and import calls with arguments, functions ranked by evidence, hubs that reach several; failures per seed) · `search_native_strings` (also Il2Cpp and NativeAOT string literals; `engine=ida\|ghidra` adds the strings the engine defined that nothing references, in its string types) · `search_bytes` (hex with `??` wildcards, or text) · `read_bytes` (hex dump, or `type=` values: integers in either byte order, floats, pointers with their target's name, string runs; uninitialized bytes as `??`) · `convert_number` (decimal, signed, hex, binary, octal, LE / BE bytes, ASCII and float views of a number at a width) |
| Engine preference | `engine=auto\|ours\|ida\|ghidra` on `list_functions`, `disassemble`, `search_instructions`, `get_cfg`, `find_xrefs`, `native_call_tree`, `resolve_call_targets` and `trace_native_values` (server default `--engine` / `NDM_ENGINE`). `auto`: an engine's analysis once it is complete in this session (IDA's before Ghidra's), else ours, never waiting for an engine; `ours`: the built-in index only; `ida` / `ghidra`: that engine's analysis, started or waited for (one image can have both). Our names win over the engine's and RTTI virtual-call edges it lacks are added. `inspect_instruction` takes `auto\|ours\|ida\|ghidra`; its `auto` is the built-in decoder for x86 / x64 / ARM64 and IDA (else Ghidra) for ARM32. Every result names its engine. |
| Symbols and classes | `load_pdb` (the matching PDB from beside the file, the CodeView path, symbol path or caches; `download=true` from a symbol server; names saved per file hash and reapplied on later loads; `clear=true` removes them) · `search_pdb_symbols` · `list_cpp_classes` (MSVC RTTI classes, bases, vftables; `engine=ghidra` lists Ghidra's class namespaces, also PDB and Itanium classes, with function counts and vftables, `namespaces=true` adds the other namespaces and libraries) · `get_native_type` (a type's layout by name, id or typed address from the PDB, RTTI, Il2Cpp and the engine's types (IDA or Ghidra): fields with offsets, sizes and bit fields, padding, bases, vftable slots named, enums by value, function types; ambiguous names list their ids; `at=0x48` names the field at an offset, also through unions, arrays and pointers; an address in a PDB global gives its field path; `read=true` adds each field's value from the image's bytes, at a typed address or with a name at any address) · `find_virtual_calls` (virtual call sites resolved through RTTI; `crossCheck=true` compares with IDA, else Ghidra) · `apply_il2cpp_names` (Il2Cpp method names, string literals and metadata slots onto GameAssembly.dll, also pushed into IDA; saved and reapplied like PDB names) · `get_nativeaot_info` (a NativeAOT image's runtime version, sections, recovery stages, MethodTables, named method bodies, frozen strings and statics with their types, .NET 7-10 in PE, ELF and Mach-O, 64- and 32-bit; its method, vtable, MethodTable and string names apply on load as the nativeaot layer, below PDB names, and go into IDA) |
| Decompile | `decompile_native` (Hex-Rays pseudocode through IDA's idalib worker, or Ghidra's decompiler through a Java worker (`NDM_GHIDRA_DIR`, a JDK); analysis cached per file hash; our names, patches, Il2Cpp prototypes, RTTI class structs and the PDB's types pushed in, so pseudocode shows real struct and member names; `functions=[...]` decompiles several in one request with a per-function deadline, deduplicated, keeping partial results, and `callersOf=` the callers of a function by the engine's references; `--prewarm ida\|ghidra\|auto` analyzes images in the background as they load) · `search_decompiled` (a regex over the pseudocode of every function or a filtered set, in batches sized to the decompiler pool and reused from earlier calls; stops at a function count, time budget or hit limit with a cursor to continue) · `ida_python` (IDAPython in the image's IDA worker, code or a script file, `persist=true` saves the database; off unless the server runs with `--ida-scripting` / `NDM_IDA_SCRIPTING=1`) · `ghidra_script` (a Java GhidraScript in the image's Ghidra worker, one transaction rolled back on failure and saved after; off unless `--ghidra-scripting` / `NDM_GHIDRA_SCRIPTING=1`) · `export_engine_database` (the image's engine database with everything pushed into it, for the engine's GUI: a compressed `.i64` copy for IDA, a packed `.gzf` archive for Ghidra) |
| Engine types (IDA or Ghidra; edits saved per file hash, re-applied to a new database, exported and carried to new builds) | `set_native_type` (function prototypes and global types; user types win over the recovered ones; `items` applies many in one request) · `set_native_local` (rename / retype a pseudocode local or argument, by name or stack offset) · `get_native_frame` (stack frame members and decompiler locals) · `set_native_stack_var` (rename / retype / create / delete a stack frame member) · `declare_native_types` (C structs, unions, enums and typedefs; they win over recovered types of the same name; `typeName` with `members` adds, changes or removes enum members, with `fields` struct or union members (by name or offset); `delete` and `rename` edit a named type, and a rename follows into the other edits) · `list_native_types` (browse the database's types, one in full with member offsets) · `define_native` (make code, a function (with its end), data (byte / word / dword / qword / float / double / string / string16 / a C type, with `[count]`) or undefined bytes at an address; replayed in order on a new database) · `reanalyze_native` (the engine's auto-analysis run again over the image or a range within a time budget, with analyzer options for that run; `analyzers=true` lists them with their values; also completes a Ghidra analysis the open cut short) · `set_native_operand` (an operand as hex / dec / oct / bin / char, offset, stack variable, enum member or struct offset, or back to the default; Ghidra uses equates and references) |
| Edit (in memory, `dryRun` on patches) | `rename_native` · `comment_native` (kept per file hash across restarts) · `export_native_annotations` (IDA / Ghidra scripts, JSON) · `patch_bytes` · `patch_asm` (x86 / x64 MASM assembled at the address, relocation-correct under ASLR; `extend=true` moves code too large for its site into a relocation stub in a code cave or a new section; unsafe sites are refused with a reason code) · `list_native_edits` (patches and name layers; `search=` finds names and comments by text) · `undo_native_edit` · `export_native_patches` (IDAPython, IDA `.dif`, IPS / IPS32 or JSON, each reproducing `save_native`'s bytes) · `save_native` (patched copy, checksum recomputed, relocations re-checked, `.bak`, verified after writing). Contract: [docs/native-editing.md](docs/native-editing.md) |
| New builds | `update_to_new_build` (one call carries names, comments, PDB / Il2Cpp layers, byte patches, code patterns, notes and the Il2Cpp method mapping to a new build, with a reason code for everything that did not carry; `dryRun` by default) · `migrate_native_patches` (byte patches reapplied only where the new build's original bytes match) · `compare_native_images` (function matches in tiers, unique-only) · `diff_function` (one matched function's aligned instruction diff with build-independent operands: calls by matched name, branch targets as aligned labels, strings by text, data by mapped address; or a unified diff of both builds' IDA pseudocode) · `map_address_between_builds` · `migrate_native_names` · `make_code_pattern` (rebuild-stable IDA-style pattern, on ARM64 with branch, ADRP and low-12 fields masked; `anchor=xrefs` makes one at every reference, IDA's included) · `search_code_pattern` |
| .NET and native together | `verify_native_imports` (each `[DllImport]` checked against the real DLL's exports; Linux / macOS / Android / iOS targets on any host: `.so` / `.dylib` probed as .NET does along the RID chain, ELF / Mach-O exports, C++ mangled names, `__Internal` in an Il2Cpp game binary, wrong_platform and arch_mismatch; verified / contradicted / unresolved / dynamic_only / not_checked with a reason code, plus run-time loading sites in the IL) · `get_r2r_code` / `find_r2r_method` (a method's ReadyToRun precompiled code, and the method at a native address) · the .NET call tools take native exports as symbols (`kernel32.dll!CreateFileW`) and follow P/Invokes into native code; mixed-mode C++/CLI assemblies also load as native images |
| Crash dumps | `open_minidump` (Windows user-mode minidump: the exception, faulting thread, instruction and registers, modules, threads; module files found by path, by name in `imageDirectories`, then by timestamp and size (renamed copies, loaded images, local symbol stores); for .NET (CoreCLR and .NET Framework, 64- and 32-bit) the managed exception with its inner chain, threads and heap state through the runtime's signature-checked DAC, found locally or downloaded only with `downloadDac=true`; a 32-bit dump is decoded by the bundled 32-bit decoder process, which checks the DAC's hash before loading it) · `dump_stack` (x64 unwind through `.pdata`, x86 frame pointers; frames named from loaded images, PDBs and exports; .NET frames from the runtime's own walk with token, IL offset, the loaded assembly of that build and the C# statement at that IL offset; Mono JIT code named from the Mono runtime's report beside a Unity dump, whose managed exception `open_minidump` shows) · `dump_heap` (.NET heap statistics by type, or matching objects, bounded) · `dump_object` (a .NET object's fields, string or array elements, references expanded) · `read_dump_memory` · `symbolize_stack_text` (crash text without a dump: Unity Player.log / error.log backtraces, Mono and Il2Cpp managed lines, .NET exception text, WER Report.wer, Event Log 1000/1026, debugger stacks; each frame resolved against the loaded build with a build check by time stamp, MVID or name, and the C# statement at a frame's IL offset) · `bucket_minidumps` (a folder of dumps grouped by crash signature: exception code, faulting function and top frames, managed for .NET; offsets and versions per bucket, a representative dump each, incremental) |
| Live processes | `inspect_process` (read-only view of a running local Windows process: modules, memory regions, threads and call stacks with named addresses; query and read handles only, nothing written or suspended: [docs/live-inspection.md](docs/live-inspection.md)) |
| Session | `server_status` (version and commit, program path with an `expectedExecutable` check, install kind, start time, negotiated protocol and client, tool catalog digest and `expectedCatalogDigest` check, limits, toolsets, the tools or modes that cannot work here with the reason and fix, long-running tools, which engines are available and how to fix a missing one, IDA background-analysis state, saved native code indexes: directory, size, hits; open and total notes) · `read_result` (pages through a result too large to send; the `limit_exceeded` error names it) |

## Reliability

| Concern | How it is handled |
|---|---|
| Locked files | Assemblies are read into memory; files on disk are never locked. |
| Concurrency | Reads share a lock; edits take it exclusively, and a call cancelled while it waits for the lock returns at once. Stress-tested with interleaved readers and writers, and with 40 parallel MCP calls. |
| Corrupt or transformed bodies | The IL scanner stops at invalid opcodes instead of throwing; `decompile_type` falls back to member-by-member output with IL for the broken part. |
| Post-processed metadata | Out-of-range names and coded indexes that some third-party toolchains leave behind are read leniently by dnlib but not by the decompiler; such assemblies are decompiled from a copy normalized by dnlib, with the same tokens, and the output says so. |
| Invisible names | Names made of zero-width and bidi characters (U+202E reverses the rest of a line) are shown as `\uXXXX`, as the decompiler does; symbols are accepted back in that form. |
| Huge output | Paged (`offset` / `maxChars`); pages come from a cache. A result or error over the response limit is kept, and `read_result` pages through it. |
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
15 s, reloads from the per-user cache `NDM_IL2CPP_CACHE` in 0.1 s). Unreadable metadata is an error with a reason
(`encrypted_or_obfuscated`, `unsupported_version`, `binary_mismatch_or_protected`, ...); single items that cannot be read
are listed by reason in the load report. Mobile and Unix builds read the same way: an `.apk` / `.xapk` / `.apks` / `.aab`
(`libil2cpp.so` of one ABI, `slice=` picks it; only the binary, the metadata and the version files are extracted to the
cache), an extracted Android package, an `.ipa` or iOS `.app` (`UnityFramework`; FairPlay-encrypted binaries fail with
`encrypted_fairplay`), a macOS `.app` (`GameAssembly.dylib`) or a Linux build (`GameAssembly.so`). Builds LibCpp2IL
cannot read on 32-bit ARM fail with `registration_not_found_armv7` / `armv7_unreadable` and point to the arm64-v8a build.
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

`unpack_container` takes a file, extracts the .NET code inside it, and loads the assemblies it finds (`load=false`
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
readable returns a tool error that says what is wrong. Without
`path`, `list_assemblies` lists the workspace as before.

`search_container` searches the metadata of every managed assembly in a container (or a plain assembly) by name,
also without writing or loading anything. Matching is the same as `search_symbols`: a case-insensitive substring,
`*` / `?` wildcards, and full-name matching when the query contains `.` or `:`. `kind` narrows it to `type`,
`method`, `field` or `property`. Each match gives the assembly's path inside the container, the assembly name, the
full member name and the kind, best matches first (exact, then prefix, then substring). At most `limit` matches are
returned (default 200, up to 5000); `total` counts every match and `truncated` says whether some were left out.

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
| `summarize_file` | File hashes, type and entropy; per assembly: identity (name, version, MVID, target framework, GUI / console / library, architecture, ReadyToRun, merged), strong name and Authenticode signature, toolchain markers and heuristics, container wrapping (embedded assemblies, decoded embedded content, high-entropy sections), features, a summary of typed strings, and entry points (Main, module initializers, native exports, installer / service / AppDomainManager / COM hooks). For a NativeAOT executable: runtime version, module sections and counts of the method names, MethodTables and frozen strings its metadata recovers. `highlights` lists the notable findings. |
| `survey_features` | Rules over the APIs the code calls, the native functions it imports and its string literals, in categories: network, execution, registry, persistence, collection, credential access, anti-analysis, defense evasion, code loading, injection, discovery, crypto. Each matched feature has its evidence (pattern, count, up to 5 locations) and an ATT&CK technique where the operation is the technique itself. `category` filters by category or technique prefix. |
| `extract_strings` | URLs, domains, IPv4 / IPv6, email addresses, file paths, named pipes, registry keys, mutex names, user agents and crypto keys from string literals, constants, resource text and decoded embedded text, with the APIs each value is passed to. `savePath` exports JSON or CSV (it refuses to replace a file unless `overwrite=true`). |
| `extract_embedded` | Embedded resources, `.resources` entries, static byte arrays and string literals of 64+ characters, decoded through hex, base64, gzip / zlib / deflate and XOR until a recognized kind appears (PE / .NET images, archives, ELF / Mach-O, text), plus high-entropy blobs. Each item shows its source and encoding chain, e.g. `base64 > xor key 5a > gzip`. `save=true` writes them with defanged names; `load=true` also loads the .NET ones; `xorText=true` adds a single-byte XOR search over text (see below); images (png, jpeg, gif, ico) are only counted unless `includeMedia=true`. |

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
- **Output the decompiler engine gets wrong, rewritten** (also in `decompile_type` / `decompile_member`): span-slicing
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

## Build, test, publish

Requires the .NET 10 SDK.

```powershell
dotnet test                    # the quick set (about 20 s): every test except those marked [Trait("Speed", "Slow")]
                               # (real-library builds, whole-server runs, sweeps, fuzz)
$env:NDM_ALL_TESTS=1; dotnet test   # everything (about 2 min; or dotnet test -p:NDM_ALL_TESTS=1):
                               # services, IL/C# patching (with runtime execution), edit history,
                               # build comparison, call graph, IDA/Ghidra/C/C++ generation (compiled with clang),
                               # background indexing, file watching, every tool over stdio, real-assembly stress,
                               # container unpacking and listing (fixtures built at test time, incl. crossgen2 ReadyToRun
                               # output) with truncation/fuzz/path-traversal cases, merged-assembly detection,
                               # file inspection (features, typed strings, embedded-content decoding, Authenticode, fuzzed inputs),
                               # invalid-IL detection, reference binding across side-by-side builds,
                               # simplify_methods over generated IL (fuzz) and over real libraries (sweep)
./publish.ps1                  # -> publish/NetDecompilerMcp.exe (needs the .NET 10 runtime)
./publish.ps1 -SelfContained   # no runtime needed
```

Some tests run against real-world data, found through environment variables. Each is skipped when its variables
are unset:

| Variable | What it points to | Tests |
|---|---|---|
| `NDM_ASSEMBLY_DIR` | A folder of real .NET assemblies (e.g. a Unity `*_Data/Managed` folder) | decompile / search / xrefs / C# patch of the app's own code; call-path timing |
| `NDM_CALLPATH_TARGET` | Optional: a method in that folder to search call paths to (default: picked automatically) | call-path timing |
| `NDM_IL2CPP_DUMMY_DIR` | An Il2CppDumper / Cpp2IL `DummyDll` folder | address round-trips; IDA / Ghidra / C header export |
| `NDM_UNITY_TITLES` | Optional: `;`-separated Unity game folders to add to the ones found in Steam libraries | `unity_overview` on real titles: version, backend, markers, timings |
| `NDM_IL2CPP_GAME`, `NDM_IL2CPP_GAME_DUMP` | A raw Il2Cpp game (folder or `global-metadata.dat`); optionally an Il2CppDumper `DummyDll` folder of the same game | built-in metadata reader end to end; agreement rates with the dump (types, methods, RVAs, fields, offsets, literals) |
| `NDM_IL2CPP_MOBILE` | A folder of mobile Il2Cpp builds (`.apk` / `.xapk` / `.aab` / `.ipa` packages and extracted game folders) | each loaded through `load_assembly`, Android packages once per ABI; counts, timings and reason codes; apply_il2cpp_names, find_method_by_address round trips, the code index and (with IDA) IDA's functions against the Il2Cpp method starts |
| `NDM_IL2CPP_STRINGS_DIR` | An Il2CppDumper `DummyDll` folder with `stringliteral.json` / `script.json` (and optionally `GameAssembly.dll`) beside it | string-literal index and code references: counts, timings, retained memory; navigation index size and time, round trips (method → RVA → method, script.json name → RVA → name, type → TypeInfo slot → type, vtable slot → method) |
| `NDM_COMPARE_OLD_DIR`, `NDM_COMPARE_NEW_DIR` | Two builds of the same app | build comparison |
| `NDM_COMPARE_ASSEMBLY` | Optional: the assembly to compare (default: the largest application assembly in both) | build comparison |
| `NDM_COMPARE_EXPECT` | Optional: known type moves to check, `Old.Name=>New.Name;Old2=>New2` | build comparison |
| `NDM_HOSTAPI_PROJECT_DIR` | Root of a C/C++ project with a host function table | `hostapi` detection on a real project; bindings compile against its headers |
| `NDM_EXPORT_REAL=1` | Exports real NuGet libraries (downloaded on restore) and builds them: 0 errors expected (a few minutes) | exported projects build |
| `NDM_EXPORT_LIST` | A text file of assembly paths: exports and builds each, 0 errors expected; writes error counts by code next to it | exported projects build |

simplify_methods is checked two ways, both in a collection that runs alone after the parallel tests (slow: they run
with `NDM_ALL_TESTS=1`):

- **Fuzz** (`SimplifyFuzzTests`): seeded random IL methods (nested try / catch / finally / fault / filter, loops,
  switches, flattened dispatchers, many locals, struct operations). The engine must not crash, must stay within its
  time and memory limits, and must give the same image twice. Every rewrite must verify and survive save / reload.
  The originals and the simplified methods are JIT-compiled and run, and their results must match. A failure names
  its seed, also when the runtime crashes (`[fuzz] seed N` on stderr).
- **Sweep** (`SimplifySweepTests`): every method of real libraries found on the machine: .NET Framework reference and
  runtime libraries (C#, VB.NET, C++/CLI mixed mode), ReadyToRun shared frameworks of several .NET versions, F#, and
  NuGet packages. It checks for crashes and clean save / reload round trips, repeats runs for byte-identical output,
  and guards performance (whole-library time per method against a 0.6 ms baseline). Absent assemblies are skipped.
  Per-assembly statistics (methods simplified, fallback reasons, time) are printed with
  `dotnet test -p:NDM_ALL_TESTS=1 --filter SimplifySweepTests --logger "console;verbosity=detailed"`.
- **Pipeline round trip** (`PipelineRoundTripTests`, opt-in): .NET Framework programs are compiled, run through an
  external post-build pipeline under each of its options and three seeds, simplified, saved and executed; the
  original, processed and simplified builds must print the same. The programs are `PipelineSamples/*.cs`, one per
  feature area (generics, async and iterators, LINQ, delegates and events, inheritance, exceptions, strings, reflection,
  structs, collections, and a mixed workload); a new file there is a new sample, a new line in `Options` a new option.
  The options cover every option family of the tool in all of its modes, alone and combined, and its bundled profiles. What
  simplifying took back of the instructions each option added is checked against floors pinned per option and sample,
  and the report ends with an option × sample coverage table. Needs the .NET Framework 4.8 reference assemblies;
  options the tool cannot process, or whose output is not checkable IL, are listed with the reason.

| Variable | Effect |
|---|---|
| `NDM_FUZZ_COUNT` | Fuzz seeds 1..N (default 40) |
| `NDM_FUZZ_SEED` | Run one seed (`random` for a fresh one) |
| `NDM_SWEEP=full` | Add the largest libraries to the sweep (System.Private.CoreLib, mscorlib, Roslyn VB, BouncyCastle, Math.NET) |
| `NDM_PERF_FACTOR` | Allowed multiple of the per-method baseline (default 5) |
| `NDM_PIPELINE_TOOL` | The pipeline's command-line executable (enables the round trip; floors pinned from a clean full run) |
| `NDM_PIPELINE_SAMPLES` | Optional: the tool's sample folder (`BasicFlow`, `Constants`, `ExceptionFlow`, one `Program.cs` each) |
| `NDM_PIPELINE_PROFILES` | Optional: a folder of bundled project profiles (default: `Build/Profiles` next to the tool) |
| `NDM_PIPELINE_SEEDS`, `NDM_PIPELINE_ONLY`, `NDM_PIPELINE_SAMPLE` | Seeds 1..N (default 3); only options / samples whose name contains this text |
| `NDM_PIPELINE_PARALLEL` | Round trips run at once (default 1; the full matrix takes about 6 minutes at 8) |
| `NDM_PIPELINE_REPORT`, `NDM_PIPELINE_KEEP` | Write the result table and coverage table to this file; keep the work files |
| `NDM_PIPELINE_RECHECK=1` | Also run the skipped options, to see whether a new tool build changed them |

The generated C, C++ and Python are compiled or parsed with clang (`C:\Program Files\LLVM\bin`) and python when
they are installed.

CI (`.github/workflows/ci.yml`) is a smoke lane: it runs the quick set on Windows, Linux and macOS; the full suite and the real-app runner run locally before a push. The tests publish hello-world apps and
download runtime / crossgen2 packs and NuGet packages at test time; CI keeps them in one package folder, cached per OS,
SDK version and project files. Real-data tests have no data there and report as skipped. Pushing a `v*` tag runs
`release.yml`, which attaches self-contained builds for win-x64, win-arm64, linux-x64, linux-arm64, linux-musl-x64,
linux-musl-arm64, osx-x64 and osx-arm64, plus a `SHA256SUMS` manifest the installers and `update` verify, to a GitHub release.

## Server options

Options go after the command in a client's configuration (`args`), e.g. to preload a folder:
`"args": ["--load", "D:\\App\\App_Data\\Managed"]`.

| Option | Meaning |
|---|---|
| `--load <path>` | Assembly file or folder to load at startup (repeatable). The `NETDECOMP_LOAD` env var takes `;`-separated paths. |
| `--search-dir <dir>` | Extra directory for resolving references (repeatable). |
| `--max-output <chars>` | Page size for long results (default 60000). |
| `--timeout <seconds>` | Per-call decompilation timeout (default 180; `export_project` gets 10×). Calls to tools not marked long-running end after twice this. |
| `--no-index` | Don't index method bodies and build the call graph in the background after loading. |
| `--no-watch` | Don't watch loaded files or reload them when they change on disk. |
| `--allow-device-changes` | Allow `install_android_package` and `uninstall_android_package`, which change a connected Android device (`NDM_ALLOW_DEVICE_CHANGES=1`). Off by default; the other device tools only read. |
| `--ida-scripting` | Allow `ida_python` (arbitrary Python in the IDA worker, with the server's rights; `NDM_IDA_SCRIPTING=1`). Off by default. |
| `--ghidra-scripting` | Allow `ghidra_script` (arbitrary Java in the Ghidra worker, with the server's rights; `NDM_GHIDRA_SCRIPTING=1`). Off by default. |
| `--engine <auto\|ours\|ida\|ghidra>` | Default engine for the native function, cross-reference and CFG tools, and for `decompile_native` when it names one (default `auto`; `NDM_ENGINE`); see Engine preference above. |
| `--prewarm <ida\|ghidra\|auto>` | Analyze each native image in that engine in the background as it loads, one at a time (`auto`: IDA when installed, else Ghidra; `NDM_PREWARM`; `--ida-prewarm` / `NDM_IDA_PREWARM=1` mean `ida`). Off by default. |
| `--index-cache <dir\|off>` | Where native code indexes are saved (default `<LocalAppData>/NetDecompilerMcp/code-index`; `NDM_CODE_INDEX_CACHE`). Entries are keyed by the file's SHA-256 and the build options, so reopening the same bytes loads the index in seconds (msedge.dll, 334 MB: 2.6 s instead of 36 s); changed, damaged or older-format entries are rebuilt. |
| `--index-cache-mb <n>`, `--index-cache-days <n>` | Bounds of that cache (default 8192 MB and 30 days unused; least recently used entries go first; `NDM_CODE_INDEX_CACHE_MB` / `_DAYS`). |
| `--binding-style <mono\|hostapi>` | `generate_cpp_binding` style when a call gives none and no host table is detected (default `mono`). |
| `--binding-project <dir>` | Project directory `generate_cpp_binding` scans for a host table when a call gives no `projectDir`. |
| `--toolsets <list>` | Register only these tool families (`NDM_TOOLSETS`), for clients with little context; without it every tool is registered. `core` is the reduced profile: `session` (always on), `dotnet`, `containers`, `edit`, `il2cpp`, `native`, `native-edit`, `builds`; the other families are `engine` (IDA or Ghidra type, local, frame and declaration edits, `ida_python`, `ghidra_script`), `android`, `dumps` and `live`. Combine names, e.g. `core,dumps`; `all` is the default. Tools of other families are not listed, and `server_status` names the families. |
| `--tools-file <file\|readonly\|triage>` | Register only the tools a whitelist names, applied after `--toolsets`; the session tools stay (`NDM_TOOLS_FILE`). The file holds tool names separated by spaces, commas or lines, `#` starts a comment; an unknown name stops the server at startup. Built-in lists: `readonly` (every analysis tool that changes nothing and writes no file, without device and live-process tools) and `triage` (a small first-look set). |
| `--log-level <level>` | Stderr log level: `trace`, `debug`, `information` (default), `warning`, `error` or `none` (`NDM_LOG_LEVEL`). `debug` adds one line per tool call: the tool, its outcome (`ok` or the error code) and milliseconds, never the arguments. |
| `--trace <file>` | Append one JSON line per tool call to this file (`NDM_TRACE`): time, tool, arguments, milliseconds, error code (`null` when it succeeded) and result characters. Off by default; arguments can hold paths and code, so the file is only written when asked for. An engine database path is refused. |

Logs go to stderr; stdout is reserved for the protocol.

Each IDA or Ghidra worker is capped at three quarters of the memory available to the server (Windows Job Object; `NDM_ENGINE_MEMORY_MB`
sets the limit in MB, `0` removes it). A worker that reaches it fails its request with the limit named and restarts on the next one.

Each engine request may take `NDM_ENGINE_REQUEST_TIMEOUT` seconds (default 120; `decompile_native` and `resolve_call_targets`
take `timeoutSeconds` per call), and an engine's start plus auto-analysis `NDM_ENGINE_OPEN_TIMEOUT` seconds (default 1200).
A request that runs out of time or is cancelled by the client is stopped inside the worker, which keeps the database open:
scans answer with what they found, marked partial with where to continue, and only a worker that does not stop within 10 s
is killed (the next request restarts it from the saved database). `server_status` reports both limits.
For huge or hostile inputs, `NDM_ENGINE_ANALYSIS=none` opens images in IDA without auto-analysis: functions are made where a
tool asks for one, the database is kept apart from the fully analyzed one, and output headers say so.
A second server process opening an image whose IDA database another process holds gets a read-only snapshot of the last
saved database (edits are neither journaled nor saved; decompile headers and `server_status` say so), or, when none is
saved yet, a conflict naming the owning process.

Ghidra (12.0 or newer) is found through `NDM_GHIDRA_DIR` (else `GHIDRA_INSTALL_DIR`) and a JDK through `NDM_GHIDRA_JAVA` (else
`JAVA_HOME`, else `PATH`); the worker is compiled from its embedded sources on first use. `NDM_GHIDRA_ANALYSIS` picks the
analysis profile (`standard`, `full` or `minimal`), `NDM_GHIDRA_MAXMEM` the JVM heap, `NDM_GHIDRA_OPTIONS` extra analyzer
options (`Name=value;...`), and `NDM_GHIDRA_EXTENSIONS` a directory of Ghidra extension zips built for that Ghidra (a NativeAOT
analyzer, for example), installed into the workers' private settings; nothing is downloaded. Projects are kept per file hash
and configuration, so a changed profile or extension set analyzes again once. `NDM_GHIDRA_DECOMPILE_TIMEOUT` (seconds, default 60)
and `NDM_GHIDRA_DECOMPILE_PAYLOAD_MB` (default 200) bound one decompilation; a timeout or an oversized result is retried once
with four times the time and twice the payload.

Other external programs are optional and each is found through one variable (a file or its folder), then as listed;
`server_status` reports where each was found, its version, or the fix. They run in their own process tree with a minimal
environment (path, temp, home and Android / Java variables only).

| Variable | Program | Used for |
|---|---|---|
| `NDM_JAVA` | `java`, JDK 17+ (else `JAVA_HOME`, else `PATH`) | running the Java decompiler |
| `NDM_JAVA_DECOMPILER` | the [jadx-headless-mcp](https://github.com/1013503897/jadx-headless-mcp) fat jar (Apache-2.0), started with `java -jar` | Java / Kotlin source |
| `NDM_ADB` | `adb` (else `PATH`, else the Android SDK's `platform-tools`) | the Android device tools |
| `NDM_AAPT2`, `NDM_APKSIGNER`, `NDM_DEX_DISASSEMBLER` | aapt2, the apksigner jar, the baksmali jar | test oracles only |

Code that targets a .NET version not installed on the machine is read against that version's reference pack, which
is downloaded once from nuget.org into the local app data folder. Set `NDM_OFFLINE=1` to never download; such code is
then read against the nearest installed version.

## Layout

```
src/NetDecompilerMcp/
  Core/      workspace (loading, locking, reference resolution), symbol resolver, formatting, paging
  Services/  decompiler, search, references, fast IL reader, call graph, assembly comparer, Il2Cpp (+ IDA/Ghidra/C
             export, Il2CppDumper script.json / stringliteral.json reader, string literals and native code references, metadata ↔ native navigation), C++ binding generator, resources, assembly report, edits and edit history, IL assembler,
             C# patcher (module merger, access fixer), background indexing, file watching
    Analysis/  bounds-checked PE parsing, byte-level helpers (identification, bounded decompression, carving, safe
               output paths), container formats, unpacking
  Tools/     thin MCP tool classes: resolve input, call a service, format text
  Mcp/       resources, prompts, completion
tests/
  TestFixture/            sample assembly covering every feature (inheritance, async, resources, stand-in Il2Cpp attributes)
  TestFixture.Consumer/   second assembly that uses the first (cross-assembly and virtual-dispatch references)
  NetDecompilerMcp.Tests/ service, patching, concurrency, protocol and real-assembly tests
```

To add a tool, put the logic in a service, then add a `[McpServerTool]` method in `Tools/` that wraps it in
`ToolSupport.Read`, `Write` or `Edit` and returns text. Throw `ToolError` for anything the agent should read and
act on. `McpProtocolTests.ToolCases` must get an entry, or the coverage test fails.

## Contributing and security

Building, testing and adding a tool: [CONTRIBUTING.md](CONTRIBUTING.md). Security reports go through the repository's
Security tab; the security boundary is described in [SECURITY.md](SECURITY.md).

## License

MIT. See [LICENSE](LICENSE); notices for derived third-party material are in [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md).
