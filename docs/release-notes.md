# Release notes

## 1.2.0

155 tools (1.1.0 had 101) and 13 prompts (9). The project is now **Corvus**; it was NetDecompilerMcp up to 1.1.0. This
release adds a second decompiler engine (Ghidra), ELF and Mach-O images, our own ARM64 and ARM32 / Thumb-2 analysis,
NativeAOT and mobile Il2Cpp builds, Android packages and devices, deeper crash-dump decoding, and a round of reliability
work across the server and its engine workers.

### Renamed to Corvus

Upgrading needs no manual steps beyond environment variables you set yourself; details in
[docs/installation.md](installation.md#install-script) ("Upgrading from NetDecompilerMcp").

- **Program and registration.** The program is `corvus` (`corvus.exe`), installed under `Corvus`, and registers with
  clients under the MCP key `corvus`. Release archives are `corvus-<rid>` from the `Albasha0x0/Corvus` repository.
- **Environment variables** are read only under their new names: `NDM_X` becomes `CORVUS_X` and `NETDECOMP_LOAD`
  becomes `CORVUS_LOAD`. The old names are not read.
- **Resources** use the `corvus://` scheme (was `netdecomp://`).
- **Data folder.** On first start annotations, notes, caches, code indexes, engine databases, symbols and relay state move
  from the old data folder to the new one; an entry in use is copied and the original kept. Engine databases and files
  saved before the rename (sessions, edit scripts, patch sets, notes) are still read.
- **Client entries.** `corvus install` and `corvus update` rename every `net-decompiler` entry to `corvus`, keeping its
  arguments and env (`NDM_*` keys renamed); a development relay entry stays a relay for the same publish folder. Skill
  folders written by `install --skill` move to `corvus`; `status` reports old entries and `uninstall` removes both.
- **Update path from 1.1.0.** The release also ships its archives under their old names, so `NetDecompilerMcp update`
  on 1.1.0 reaches this release, which moves the install to the new folder and puts `corvus` on PATH. For a private
  repository, run it as `NDM_REPO=Albasha0x0/Corvus NetDecompilerMcp update` (1.1.0 loses the token on GitHub's redirect
  from the old name), or run the new install script with `GITHUB_TOKEN` set; it takes over the old install. Corvus's own
  `update` keeps the token across GitHub's redirects.

### Changes in behaviour

- **Exports never overwrite by default.** Files written by export and save tools are written atomically and refuse to
  replace an existing file unless `overwrite=true`; links and device names are refused as targets. `save_assembly`
  recognizes the original through links and hard links, refuses an original that changed on disk since it loaded, and
  `save_native` verifies the written file before renaming it into place.
- **`uninstall` keeps user data.** Annotations, caches and symbols stay; `--purge-data` removes them.
- **Call deadline.** A tool not marked long-running ends with a timeout error after twice `--timeout`; cancelled calls
  stop waiting for the workspace lock. New error codes `cancelled` and `changed_on_disk` ([docs/errors.md](errors.md)).
- **Closed argument values** are advertised as enums and checked before the tool runs, with aliases and a
  did-you-mean suggestion; `limit < 1` is `invalid_argument` on every paged native tool.
- **Native names.** A name on several addresses is an ambiguous error listing them; hex-shaped names (`Bach`, `...h`)
  resolve as names before MASM numbers; a name on a jump thunk and on its body resolves to the body.
- **Incomplete results say so.** Regex searches that time out report what was not evaluated; a cut-short `read_bytes`
  says so; `read_bytes` shows bytes with no file data (`.bss`, virtual size past raw size) as `??` with a gap list.
- **Member labels carry generic parameters** (`Method<T>(string)`), so generic and non-generic overloads differ in
  diffs and replays; older edit scripts resolve their bare labels as before.
- **Native patches** pad with the architecture's NOP (whole NOPs on ARM64) and are refused where none is defined.
- **IDA before 9.0 is refused** with the reason; the reported idalib version shows in `server_status`.
- **Inputs:** FIFOs, sockets, devices and directories are refused as input files.

### Second engine: Ghidra

- **`engine=ghidra` everywhere an engine is used:** `decompile_native`, the code tools (`list_functions`, `disassemble`,
  `get_cfg`, `find_xrefs`, `native_call_tree`, `resolve_call_targets`, `trace_native_values`, `inspect_instruction`),
  the type, frame and local edit tools, `crossCheck` and `find_xrefs Type::member`. A session per engine and image;
  `auto` takes a complete IDA analysis, then Ghidra's, else ours. Ghidra 12.0 or newer through `CORVUS_GHIDRA_DIR` and a
  JDK; the worker is built on first use.
- **Saved projects** per file SHA-256 and profile key, warm reopen, rebase, damaged-project rebuild, an analysis budget
  with a partial save that `reanalyze_native` completes, and a background function pass after the open.
- **Large functions decompile:** 200 MB decompiler payload, one retry with four times the time on a fresh decompiler,
  `timeoutSeconds` per call.
- **Ghidra's names** (loader and analysis names, function identification included) form a name layer below the others;
  `FUN_` / `LAB_` / `DAT_` and IDA default names resolve as addresses.
- **`ghidra_script`** runs a Java GhidraScript in the worker in one transaction, rolled back on failure (opt-in,
  `--ghidra-scripting`). `export_engine_database` writes a `.gzf` archive, or Ghidra's own types as `.h` / `.gdt`.

### IDA and engine depth

- **New edit tools:** `define_native` (code, functions, data, undefined bytes), `set_native_operand` (number base, char,
  offset, stack variable, enum member, struct offset), `reanalyze_native`; enum, struct and union member upsert,
  type delete and rename (followed into the other edits), stack member delete, `clear=true` to restore the engine's
  own local. All kept per file hash, replayed on a new database, exported and carried to new builds.
- **Comments:** kinds `eol`, `pre`, `plate` and pseudocode comments placed on the statement, with append and dedupe;
  `rename_native` and `comment_native` take batches with `dryRun`, `stopOnError` and per-item results;
  `showDecompile=after|diff` on the type and name edits.
- **Views:** `list_globals`, `search_instructions`, `convert_number`, `get_engine_status`, `search_decompiled` (regex
  over every function's pseudocode, resumable by cursor), `decompile_native functions=[...]` and `callersOf=`,
  `list_functions view=candidates`, `find_xrefs direction=from|both` and `kind=`, `list_native_types` filters,
  `related=true` and members, `list_cpp_classes engine=ida|ghidra`, typed reads (`get_native_type read=true`,
  `read_bytes type=`), `export_engine_database` (`.i64` copy), `make_code_pattern` in IDA / x64dbg / mask formats.
- **Worker control:** cancel and deadlines inside the IDA and Ghidra workers (partial results with a cursor; the worker
  is killed only past a grace period), `CORVUS_ENGINE_REQUEST_TIMEOUT` / `CORVUS_ENGINE_OPEN_TIMEOUT`,
  `CORVUS_ENGINE_ANALYSIS=none` for huge or hostile inputs, a read-only snapshot when another server holds the
  database, batch mode so no dialog waits, engine sessions and open-stage timings in `server_status`.

### Own engine: ELF, Mach-O, ARM64 and ARM32

- **ELF and Mach-O images** load beside PE (universal files by slice) through every native tool: relocations, PLT and
  GOT, symbol versions, chained fixups, exports trie, function starts, compact unwind, code signature and encryption.
  IDA and Ghidra open them too. Itanium C++ demangler, Itanium RTTI (single, multiple and virtual bases) for classes,
  type push and virtual calls, Itanium exception tables in `get_exception_info`, System V x64 calling convention.
- **ARM64** decoder, function discovery, jump tables, call arguments (integer and floating-point), value tracing and
  call targets; `inspect_instruction` on the built-in decoder; ARM64X / ARM64EC images from their CHPE metadata.
- **ARM32 / Thumb-2:** own A32 / T32 decoder (VFP and NEON included) with per-function state, cross-references through
  literal pools and MOVW / MOVT, TBB / TBH and PC-relative jump tables, IT blocks, AAPCS call arguments and value
  traces, fixed-address executables.
- **Discovery:** Go function tables (Go 1.2 to 1.24, ELF / PE / Mach-O) as a function and name source; static and
  fixed-address ELF (a static x86-64 Linux executable: 194 to 3,112 functions; its i386 build: 19 to 3,173); x64
  absolute switch tables; jump thunks named `j_<target>`. Image-scope `resolve_call_targets` on a 3.8 MB library:
  1,474 s to 12 s (ARM32), over 900 s to 7 s (ARM64).
- **Patching ELF and Mach-O:** `patch_bytes`, `patch_asm`, undo and `save_native` (universal files keep their other
  slices); bytes the loader rewrites are refused unless forced, encrypted bytes refused.
- **Packers and protectors** reported with evidence in `summarize_file` and `get_pe_info` (detection only).

### Native analysis

- **`inspect_instruction`**, **`get_native_type`** (PDB, RTTI, Il2Cpp and engine types; field paths at an offset),
  **`trace_native_values`** (interprocedural value slices across functions and loaded images, struct fields, switch
  case selection) and **`resolve_call_targets`** (targets with basis and confidence).
- **`analyze_native_function`** (a function dossier in bounded sections, up to 16 at once, `component=true`),
  **`trace_native_feature`** (from a text to the ranked functions behind it), native goals in **`find_call_paths`**,
  **`diff_function`** (aligned instruction and pseudocode diff of a matched pair), `get_cfg` switch cases,
  `native_call_tree direction=both`, `summarize_file` triage for native images.

### NativeAOT

- **`get_nativeaot_info`** and a nativeaot name layer from the image's own metadata: method bodies, MethodTables,
  vtable slots, frozen strings, statics and interface dispatch cells, ranked below PDB names, pushed to IDA and Ghidra
  and exported. .NET 7 to 11 layouts, PE, ELF and Mach-O, 64- and 32-bit.

### Il2Cpp and Unity

- **Mobile and desktop layouts:** Android, iOS, macOS and Linux games, read from `.apk` / `.xapk` / `.apks` / `.aab` /
  `.ipa`; ELF and Mach-O game binaries; metadata up to v39; builds that fill the code registration at run time.
- 32-bit games get headers and prototypes pushed to IDA and Ghidra; Il2Cpp games and minidumps are kept in sessions;
  `unity_overview` reads packages and iOS layouts.

### Android

- **Packages:** manifest and resources (binary XML, `resources.arsc`, app bundle protobuf), APK signature verification
  (v1 to v4 with rotation and several signers, content digests recomputed), .NET for Android assembly stores.
- **Code:** DEX reader and Dalvik disassembler (`list_dex_classes`, `get_dex_class`, `disassemble_dex`, `search_dex`,
  `find_dex_references`), `decompile_java` through JADX, `map_java_dotnet` (also Unity Mono C# to Java),
  `list_jni_bindings`, `export_project` to a Gradle project skeleton.
- **Devices** through adb: read-only by default; install and uninstall behind `--allow-device-changes`.

### Crash dumps

- **.NET decoding:** managed exception, mixed frames, `dump_heap` and `dump_object`; DAC lookup with signature check and
  opt-in download; .NET Framework and 32-bit dumps through a bundled 32-bit decoder (Windows); IL offsets mapped to the
  C# statement.
- **`symbolize_stack_text`** (Unity, Mono, Il2Cpp, .NET, WER, Event Log, debugger, Android tombstone and logcat stacks,
  with build checks) and **`bucket_minidumps`**; WoW64 32-bit side, frame-pointer-less x86 frames, modules found by
  timestamp and size.

### Also since 1.1.0

- **.NET builds:** `compare_assemblies` / `find_counterpart` report every change of a matched member, members moved
  between types, and optional C# or IL diffs; provenance (file SHA-256, MVID, IL hashes); metadata and exception-clause
  health in `get_assembly_info`.
- **.NET export and patching:** `export_project` builds more real projects (framework inference, package references, preserialized resources);
  Blazor WebAssembly Webcil modules load and unpack; many C# patch compile fixes; `diff_edits` first page of a
  whole-assembly simplify 27 s to 4 s.
- **Sessions and notes:** `save_session` / `load_session` (files by SHA-256, edits, patches, names, notes), an edit
  journal that offers unsaved work for replay, `record_note` / `update_note` / `list_notes`, shown in IDA and Ghidra.
- **Setup:** `corvus install` plans and edits client files in place (comments kept, `--dry-run`, `--json`), more
  clients and config homes, `corvus status` checks each registration with its own args and env; the agent skill
  (`install --skill`); `SHA256SUMS` checked by the installers and `update`.
- **CLI:** a generic tool runner (`corvus call`, `describe`), `batch`, prompts and resources, shell completions.
- **Server:** `--toolsets` and `--tools-file` to register fewer tools (`core`, `readonly`, `triage`), `--trace` JSONL
  call trace, `--log-level`, resource subscriptions, a development reload relay that also serves 2026-07-28 clients.
  Tool descriptions and schemas were trimmed from 225,472 to 165,631 bytes (-26.5%) at 155 tools.
- **Reliability:** cross-process locks and merges for annotation sidecars and notes; one ordered writer per engine
  worker; child-process output and exits read off the thread pool; a deadlock between the edit journal and saves fixed.

## 1.1.0

101 tools (1.0.1 had 54). This release adds the native PE track (analysis, IDA engine, PDB, patching, crash dumps,
build migration) and a batch of usability and analysis-depth work on top of it.

### Changes in behaviour

- **Unknown argument names are errors.** A parameter a tool does not declare is `invalid_argument` with the closest
  declared names ("unknown parameter 'max_chars'. Did you mean 'maxChars'?"; `details.suggestions`), instead of being
  ignored while the tool ran with its defaults. Clients that sent extra arguments must drop them.
- `load_pdb` is marked destructive: `clear=true` removes imported PDB names and their saved copy.
- With `engine=auto` (the default), `list_functions`, `disassemble`, `get_cfg`, `find_xrefs` and `native_call_tree`
  answer from IDA for an image once IDA has finished analyzing it in the session; pass `engine=ours` for the built-in
  index only.

### New in this batch

- **Persistent native code index.** Each image's code index is saved per user, keyed by the file's SHA-256 and the build
  options; reopening the same bytes loads it (msedge.dll, 334 MB: 2.6 s instead of 36 s; GameAssembly.dll, 206 MB:
  1.8 s instead of 54 s). Changed, damaged or older-format entries are rebuilt; bounded by size (8 GB) and age (30 days),
  least recently used first. `--index-cache <dir|off>`, `--index-cache-mb`, `--index-cache-days`; shown in `server_status`.
- **Imported names survive restarts.** Names from `load_pdb` and `apply_il2cpp_names` are saved beside user renames and
  reapplied when the same file loads again, also with the PDB moved or deleted (434,680 names on an Il2Cpp title restored in 0.8 s).
  `list_native_edits` lists each layer and whether it was restored; `clear=true` removes a layer.
- **Engine preference** `engine=auto|ours|ida` (server default `--engine` / `CORVUS_ENGINE`): see above; `auto` never starts
  IDA and costs about 0.1 µs per call. With IDA, our names still win and RTTI virtual-call edges IDA lacks are added.
  Every result names its engine.
- **PDB types in IDA.** `decompile_native` loads the PDB's structs, enums, typedefs and prototypes into the IDA database
  once per PDB, through IDA's PDB loader or the server's own PDB type reader, so pseudocode uses real struct and member
  names (`return source->flags;` instead of `return *(unsigned int *)(a1 + 712);`).
- **Virtual calls through RTTI.** `obj->vfunc()` sites are resolved from MSVC RTTI class hierarchies into
  `virtual_exact` / `virtual_possible` call-graph edges (+11,041 edges on Qt6Widgets.dll, +15,026 on Acrobat.dll).
  `find_virtual_calls` lists the sites; `crossCheck=true` compares with IDA (98-100% agreement on Qt6Widgets and
  steamclient). `native_call_tree calls=direct|virtual`.
- **Built-in Il2Cpp metadata reader.** `load_assembly` on an Il2Cpp game folder or `global-metadata.dat` reads metadata
  versions 24-31 through LibCpp2IL, also from a memory dump of GameAssembly.dll; no external dumper. On a v31 title every method,
  RVA, vtable slot, field and field offset matches Il2CppDumper's output. Unreadable metadata is an error with a reason;
  unreadable items are listed by reason.
- **`unity_overview`.** One call on a Unity title: engine version per source, Mono or Il2Cpp with evidence and metadata
  state (readable, encrypted, header tampered), toolchain and middleware markers (optional Detect
  It Easy), and the next tool calls. Under 0.2 s on the titles tested.
- **`inspect_process`.** Read-only view of a running local process (Windows): modules, memory regions, threads and
  stacks, named through PE, PDB, Il2Cpp and user names. Opens only query and read handles, writes and suspends nothing,
  closes every handle before returning (docs/live-inspection.md).
- **Patch-site extension.** `patch_asm` / `patch_bytes` `extend=true` turn a site that is too small into a jump to a
  relocation stub that runs the new code (and the displaced instructions, `stubMode=before|after`) and returns after the
  site. `placement=auto|cave|section`: a code cave when one fits, else a new executable section (undo removes it byte
  for byte). Exports describe grown files (JSON v2, IDAPython, IPS / IPS32; `.dif` refuses them with `grown_file`).
- **`update_to_new_build`.** One call carries names, comments, PDB / Il2Cpp layers, patches (stubs re-created), code
  patterns with drift and the Il2Cpp method mapping to a new build, with one report: what carried, what did not and why.

### Also since 1.0.1

- **Native PE images:** own PE parser; x86 / x64 code index (functions, xrefs, CFGs, strings); MSVC demangler, RTTI and
  exception metadata; PDB reader with opt-in symbol download; Win32 resources; ReadyToRun code; P/Invoke verification
  with verdicts; late-bound imports and call-site arguments; navigation across loaded images and between managed and
  native code; ARM / ARM64 through IDA.
- **IDA (idalib) engine:** `decompile_native`, analysis cached per file hash, names, patches and types pushed in,
  library-function names, optional background analysis (`--ida-prewarm`).
- **Native editing:** renames and comments kept per file hash, `patch_bytes` / `patch_asm` (full MASM assembler,
  relocation-correct under ASLR), undo, `save_native`, `export_native_patches`, `migrate_native_patches`.
- **Builds and dumps:** `compare_native_images`, address and name migration, rebuild-stable code patterns; minidumps
  (`open_minidump`, `dump_stack`, `read_dump_memory`).
- **Il2Cpp:** string literals, metadata <-> native navigation both ways, complete struct layouts and prototypes, C++
  bindings in Il2Cpp style with generic templates.
- **Protocol:** typed errors with a JSON copy, structured output for list / search / info tools, response-size guard with
  `read_result`, `server_status` with a tool-catalog digest, one audited annotations table.
- **.NET:** normalized IL hash, tiered unique-only member matching, many `simplify_methods` readability passes.
