# Release notes

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
  reapplied when the same file loads again, also with the PDB moved or deleted (a real game: 434,680 names restored in 0.8 s).
  `list_native_edits` lists each layer and whether it was restored; `clear=true` removes a layer.
- **Engine preference** `engine=auto|ours|ida` (server default `--engine` / `NDM_ENGINE`): see above; `auto` never starts
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
  versions 24-31 through LibCpp2IL, also from a memory dump of GameAssembly.dll; no external dumper. On a real game every method,
  RVA, vtable slot, field and field offset matches Il2CppDumper's output. Unreadable metadata is an error with a reason;
  unreadable items are listed by reason.
- **`unity_overview`.** One call on a Unity title: engine version per source, Mono or Il2Cpp with evidence and metadata
  state (readable, encrypted, header tampered), anti-cheat / obfuscator / packer / middleware markers (optional Detect
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
