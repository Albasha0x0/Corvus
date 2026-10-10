# NetDecompilerMcp

A headless .NET decompiler and native PE analyzer for AI agents, served over the [Model Context Protocol](https://modelcontextprotocol.io).
It decompiles, searches, cross-references and patches .NET assemblies, including Unity Mono builds and
Il2CppDumper / Cpp2IL dummy DLLs, and analyzes, diffs and patches native Windows PE files (x86 / x64), with IDA as the
optional decompiler for native code. No GUI, no dnSpy instance, no admin rights and no network port.

- **Decompiler:** the ILSpy engine (`ICSharpCode.Decompiler`), the same engine dnSpy uses.
- **Metadata and patching:** [dnlib](https://github.com/0xd4d/dnlib), plus a fast `System.Reflection.Metadata` IL scanner.
- **C# method patching:** Roslyn.
- **Transport:** stdio, using the official [MCP C# SDK](https://github.com/modelcontextprotocol/csharp-sdk).

## Install

One command installs everything and registers the server with every MCP client on the machine. Nothing to
configure, no admin rights, no .NET needed (the download is self-contained).

**Windows** (PowerShell):

```powershell
irm https://raw.githubusercontent.com/Albasha0x0/Corvus/main/install.ps1 | iex
```

**Linux / macOS:**

```sh
curl -fsSL https://raw.githubusercontent.com/Albasha0x0/Corvus/main/install.sh | sh
```

Then restart your MCP client. What the installer does:

1. Downloads the latest release for your system (Windows, Linux glibc / musl, macOS; x64 and arm64) into a per-user
   folder (`%LOCALAPPDATA%\NetDecompilerMcp`, `~/.local/share/net-decompiler-mcp`) and puts `NetDecompilerMcp` on PATH.
2. Starts the server once and checks it answers (MCP handshake and tool list).
3. Registers it as `net-decompiler` with every installed client it finds, keeping their other settings (each changed
   file is backed up once as `<file>.netdecompiler.bak`; a file it cannot parse is left untouched and reported).

Supported clients: Claude Code, Claude Desktop, Cursor, Windsurf, VS Code, VS Code Insiders, VSCodium, Cline, Roo Code,
Kilo Code, Visual Studio, Codex, Gemini CLI, Qwen Code, GitHub Copilot CLI, OpenCode, Crush, Zed, LM Studio,
Amazon Q, Kiro and Antigravity. Any other client: add the output of `NetDecompilerMcp config`.

| Command | What it does |
|---|---|
| `NetDecompilerMcp status` | Which clients have it registered (and with which copy), plus a live server check. |
| `NetDecompilerMcp install [client...]` | Register again, e.g. after installing a new client; names register clients not detected. |
| `NetDecompilerMcp update` | Install the latest release; client settings point at a stable path and need no change. |
| `NetDecompilerMcp config [client]` | Print the configuration for a client, or the generic `mcpServers` JSON. |
| `NetDecompilerMcp uninstall` | Remove it from every client and delete the installed files (`--keep-files` keeps them). |

From source instead: `./publish.ps1`, then `publish/NetDecompilerMcp install`.

## What it covers

**MCP features:** 92 tools (every one with a title and read-only / destructive / closed-world annotations),
resources and resource templates, 9 prompts, argument completion, progress notifications, structured output
(`list_assemblies`, `unpack_container`, `search_container`, `summarize_file`, `survey_features`, `extract_strings`, `extract_embedded`, `server_status` and the newer native tools), typed errors (`Error (<code>) in <tool>: ...` with a `Next:` step), a response-size guard (`read_result` pages through anything larger), cancellation, server instructions, and workspace notices (files reloaded from disk) at the top
of the next tool result, plus best-effort `resources/list_changed` and log notifications.

| Area | Tools |
|---|---|
| Workspace | `load_assembly` (a file or a whole folder; reports progress) · `list_assemblies` (ids, versions, ReadyToRun, merged-assembly label, unsaved edits; `filter` / `offset` / `limit` for big folders; with `path`, the managed assemblies inside a container file without extracting them) · `unload_assembly` · `reload_assembly` · `add_search_directory` · `get_assembly_info` (identity, TFM, references and whether each resolves (to the loaded build in the same folder first), PE headers and sections, metadata streams, attributes, Il2Cpp detection, method bodies that are not valid IL — encrypted or dumped before decryption, also flagged in decompiled code and comparisons) |
| Browse | `list_namespaces` · `list_types` · `get_type_info` (outline with tokens, constants, hex enum values, IL sizes, Il2Cpp RVAs and offsets) · `get_type_hierarchy` · `get_attributes` (type, member, parameter, return value, assembly or module) · `resolve_symbol` |
| Decompile | `decompile_type` · `decompile_member` (overloads, async, iterators and lambdas folded back; `simplified=true` shows the code after `simplify_methods` without editing) · `get_il` (tokens, offsets, structured EH, a normalized IL hash per method: [docs/il-hash.md](docs/il-hash.md)) · `decompile_assembly_attributes` · `export_project` (whole assembly → .csproj that builds: see [Exported projects](#exported-projects); reports progress and failed types) |
| Search | `search_symbols` (substring, wildcard or regex) · `search_strings` (paged; for Il2Cpp dummy DLLs, whose bodies are empty, the literals of the dump: see [Il2Cpp string literals](#il2cpp-string-literals)) · `search_constants` (IL literals, const and enum values, attribute arguments, and static array data such as S-boxes, CRC and crypto tables, read element by element as the array's own type) · `search_il` (instruction-sequence patterns with wildcards and gaps) |
| Cross-references | `find_references` (methods, including calls dispatched through base/interface methods and calls through static delegate fields whose target the interpreter works out, which `find_callees`, `get_call_tree` and `find_call_paths` follow too; fields with read/write/address; properties; events; types in every position: base, interface, constraint, field/param/return/local, catch, attribute, cast, newobj) · `find_callees` · `find_overrides` (paged). These, `get_type_hierarchy`, `get_call_tree` and `find_call_paths` also take framework and dependency symbols the loaded code uses (`System.IDisposable::Dispose`, `System.Diagnostics.Process::Start(string)`), matched across mscorlib / System.Private.CoreLib |
| Call graph | `get_call_tree` (callers or callees N levels deep, breadth-first so a node budget cuts the deepest level; repeats, recursion and virtual dispatch marked) · `find_call_paths` (shortest call chains from a method or from entry points to a target; direct calls preferred, virtual-dispatch hops marked, `includeVirtual=false` for direct calls only) |
| Compare builds | `compare_assemblies` (added/removed/renamed types and members, signature, body (by normalized IL hash), metadata-only (flags or attributes changed, IL identical), field-offset and RVA changes; members matched in tiers (full name and signature, matched type and name, IL hash, body shape, structure, similarity), each pairing only when unique on both sides, otherwise reported as ambiguous with the candidates; renamed types and members matched by IL fingerprints (with and without numeric constants, which control-flow code transformers change at every build), string literals and constants, so transformed rebuilds whose every name changed still line up; compiler-generated closures, state machines, backing fields and array data are hidden and counted unless `includeCompilerGenerated=true`) · `find_counterpart` (where did this type/member go in the new build, with the matching tier and confidence: exact, strong or structural) |
| Resources | `list_resources` · `get_resource` (text, hex, `.resources` entries, WPF `.baml` entries as XAML; extract to disk) |
| Containers | `unpack_container` (single-file bundles, Costura, NuGet, Xamarin / MAUI APKs, embedded images; extracts and loads the assemblies, each labelled ReadyToRun / merged) · `search_container` (types and members by name across every assembly in a container, without extracting; capped, with a truncation flag). See [Unpacking containers](#unpacking-containers) |
| File inspection | `summarize_file` (one report: hashes, identity, strong name and Authenticode with digest check, toolchain markers, container wrapping, features, typed strings, entry points; opens containers) · `survey_features` (capa-style rules over APIs, P/Invoke imports and strings, with ATT&CK techniques and evidence) · `extract_strings` (URLs, domains, IPs, paths, registry keys, mutexes, user agents, crypto keys; JSON / CSV export) · `extract_embedded` (resources, static arrays and strings decoded through base64 / hex / gzip / deflate / XOR). See [File inspection](#file-inspection) |
| Il2Cpp | `get_il2cpp_info` (RVA, VA, file offset, slot, field offsets, tokens; for a method, its function bounds, the methods sharing its code, its MethodInfo slot, its generic instantiations (overloads told apart by the dumper's C signature) and the string literals its native code loads; for a type, its metadata slots and, with `slot`, the method implementing a vtable slot or the whole vtable; also takes `script.json` names such as `List`1<int>::Add` or `Ns.Type_TypeInfo`) · `find_method_by_address` (IDA/Ghidra address formats; the function starting at or containing it, bounded by the next function start, with every method sharing its code, generic instantiations included, paged; string literal, type metadata and MethodInfo slots are named; an address outside every known function says so; invalid addresses that dumpers write for methods without native code are ignored) — see [Il2Cpp navigation](#il2cpp-navigation) · `export_il2cpp_symbols` (IDA and Ghidra scripts that name every function and apply its C prototype, a C header with struct layouts that compiles as C and C++ — generic instances laid out where the dumpers give offset 0, static fields, fixed buffers — and JSON) |
| Native bindings | `generate_cpp_binding` (C++ binding for a type in a Mono or Il2Cpp application: class lookup, field/static offsets, method lookups with exact overloads, typed accessors and invoke wrappers; base-class members named in `members` (e.g. a singleton's static `Instance` on a generic base) bound through the hierarchy. Style `mono`: a self-contained header on the standard Mono embedding API. Style `il2cpp`: a self-contained header on the Il2Cpp runtime's exports (`GameAssembly.dll`), with each method's native code pointer (to hook) and a typed direct call, overloads matched by the dumper's token. A generic definition (``List`1``) binds as a C++ template over its type parameters (the C++ type of each argument, a pointer for a reference type), resolved on an instantiation's class; style `il2cpp` adds a layout template that lays out instantiations as Il2Cpp does. Style `hostapi`: for projects whose host passes a function table; with `projectDir`, the table, its handle types, the helpers' headers and namespace are detected and `#include` paths are computed relative to `headerPath`; value types use the table's `EmbeddedStructOffset` / `GetValueTypeSize` when it has them. Without `style`: a host table in `projectDir` gives `hostapi`; a project calling Il2Cpp or Mono exports itself (`il2cpp_class_from_name`, `typedef il2cpp_*_t`, `using fn_* = ...`, `mono_class_from_name`) gives `il2cpp` or `mono`; an Il2Cpp dummy assembly gives `il2cpp`; else the server's `--binding-style`, else `mono`; the header's first line says which and why) |
| Patch (in memory, `dryRun` on all) | `rename_symbol` · `rename_namespace` · `stub_method` · `patch_method_csharp` (new body in C#: lambdas, async, `yield`, LINQ, private/internal members accessible) · `add_members_csharp` (new methods, fields, properties, nested types) · `add_types_csharp` (whole new classes) · `patch_method_il` (IL assembler that accepts edited `get_il` output; replace or prepend) · `simplify_methods` (for transformed code, on a method, a type or the whole assembly: calls that build strings from constants, such as string decoders, run in a sandboxed IL interpreter and become literals; constant branches (also conditions computed through locals, such as provably-constant conditions), unreachable blocks, branch chains, dead stores, repeats of loads kept only for their effect and empty try/finally are cleaned up; flattened control flow (a loop over a switch on a state variable, also with states computed from the previous one as ConfuserEx does, or passed on the stack as .NET Reactor does) becomes sequential code; forwarder call sites call the real target; calls through static delegate fields (call proxies, string delegates) call the delegate's target, worked out by running the field's type initializer in the interpreter, reflection-based ones included (inside that initializer itself, on the state as it stands at the call); helpers reading the assembly's own embedded resources (streams, BinaryReader, StreamReader) are evaluated too; opt-in `deterministicEnvironment=true` pins what initialization code reads of the machine (the module's own path and file, directories, special folders, environment variables) to fixed stand-ins listed in docs/simplify.md; I/O, reflection, exceptions and over-budget calls are left alone and reported with a reason code; every result is stack-verified; the evaluated IL subset, limits and reason codes are in [docs/simplify.md](docs/simplify.md)) · `save_assembly` (never overwrites without `overwrite=true`, keeps `.bak`, atomic write; without edits writes the original bytes, with edits keeps every method body and signature no edit touched byte-for-byte, checks the written image against the original and lists anything that differs or is invalid in the original with a reason code; `strict=true` refuses such a save; contract in [docs/saving.md](docs/saving.md)) |
| Edit history | `list_edits` · `diff_edits` (before/after decompiled C# of pending edits) · `undo_edit` · `revert_edits` · `export_edits` / `apply_edits` (replayable JSON edit scripts: re-apply a patch set to a new build; a dry run applies and compiles every edit, then rolls back) |

**Resources:** `netdecomp://assemblies`, `netdecomp://assembly/{assembly}/info`, `netdecomp://assembly/{assembly}/type/{type}`
(decompiled C#), `netdecomp://assembly/{assembly}/il/{symbol}`.

**Prompts:** `analyze_assembly`, `find_feature`, `explain_type`, `plan_patch`, `map_native_address`, `analyze_native`,
`trace_native_feature`, `find_api_usage`, `patch_native`.

**Completion:** assembly ids, type names (full or short), and file paths for prompt and resource-template arguments.

### Native PE images

Native `.exe` / `.dll` / `.sys` files (x86 and x64; ARM64 images are read but their code is not decoded) load with
`load_assembly` by path, or are loaded by any native tool given a path. Everything below is our own analysis
(PE parser, Iced disassembler, function discovery, MSVC RTTI / exception data / name demangling, PDB reader);
only `decompile_native` needs an external engine (IDA through idalib). Reliability runs and their numbers:
[docs/native-maturity.md](docs/native-maturity.md); editing contract: [docs/native-editing.md](docs/native-editing.md).

| Area | Tools |
|---|---|
| Overview | `get_pe_info` (machine, subsystem, image base, entry, mitigations (ASLR, DEP, CFG, SafeSEH, GS, CET...), sections with entropy, PDB path and match, version resource, manifest, rich header, checksum, overlay, Authenticode, late-bound imports, anything malformed) · `list_imports` (per DLL with IAT slots and API set targets; `bind=true` binds each import to its export, 'at VA [image]' when the provider is loaded, its path when not, or why it does not resolve; `includeDynamic=true` adds late-bound GetProcAddress imports with module, call site and confidence, marked [dynamic]) · `list_exports` (ordinals, forwarders, MSVC names demangled) · `list_resources` / `get_resource` (Win32 resources: version info and string tables decoded, manifests as text) · `resolve_address` (RVA / VA / file offset, section, symbol and its source, containing function, bound import target, Il2Cpp method) |
| Code | `list_functions` (name from user / PDB / Il2Cpp / export / discovery, size, flags, how found, reference count, funclets and exception chunks) · `disassemble` (MASM, block labels, named calls and data, string comments, call arguments) · `get_cfg` (blocks, edges, switch tables, unresolved jumps, tail calls) · `get_exception_info` (try blocks, catch types, unwind maps, SEH scopes, funclet parents) · `find_xrefs` (calls incl. through import slots, thunks and late-bound pointers, jumps, reads / writes, address-taken, switch tables, data pointers; for an export also the importing call sites in other loaded images; `module!name` for every call site of an API) · `native_call_tree` (callers / callees across loaded images: imports continue into the provider's function; managed P/Invoke and C++/CLI seams shown) · `get_call_arguments` (per call site the recovered argument values: decoded flags and constants, strings, names, results of earlier calls, each with its derivation) · `search_native_strings` · `search_bytes` (hex with `??` wildcards or text) · `read_bytes` (hex dump as mapped) |
| Symbols and classes | `load_pdb` (matching PDB next to the file, from the CodeView path, symbol path or caches; `download=true` from a symbol server, opt-in) · `search_pdb_symbols` · `list_cpp_classes` (MSVC RTTI: classes, bases with offsets, vftables and slots) · `apply_il2cpp_names` (C# method names, string literals and metadata slots from Il2Cpp dumps onto GameAssembly.dll; also pushed into IDA) |
| Decompile | `decompile_native` (Hex-Rays pseudocode through IDA's idalib worker: job-contained, analysis cached per file hash, our names pushed in; lines annotated with addresses) |
| Edit (in memory, `dryRun` on patches) | `rename_native` · `comment_native` (kept per file hash across restarts; user names win over PDB / Il2Cpp names) · `export_native_annotations` (IDA / Ghidra scripts, JSON) · `patch_bytes` · `patch_asm` (full x86 / x64 MASM as `disassemble` prints it, RIP-relative and branch targets fixed up for the address, NOP padding, refuses to split instructions unless forced; relocation-correct under ASLR: base-relocation entries the new bytes no longer use are neutralized, new absolute addresses get an entry in a free slot of the page's block, `relocations=auto|keep|neutralize`) · `list_native_edits` · `undo_native_edit` · `save_native` (patched copy, checksum recomputed, relocation table re-checked, signature reported or stripped, `.bak`, byte-compared after writing) |
| New builds | `compare_native_images` (function matches between two builds in tiers: name / identical bytes, structure, signature, call graph, fuzzy; unique-only, ambiguous ones listed with candidates) · `map_address_between_builds` · `migrate_native_names` (your names and comments into the new build, with `dryRun` and reason codes) · `make_code_pattern` (a rebuild-stable IDA-style pattern, addresses as `??`) · `search_code_pattern` (across loaded native images) |
| .NET and native together | `verify_native_imports` ([DllImport]s against the real DLL exports: search order, API sets, A/W, stdcall `@N`, ordinals, forwarders) · `get_r2r_code` / `find_r2r_method` (ReadyToRun precompiled code of a method, with managed call names, and the method at a native address) · the .NET call tools take native exports as symbols (`kernel32.dll!CreateFileW`) and follow P/Invokes into native code; mixed-mode C++/CLI assemblies also load as a native image · `survey_features` covers native images (imports, late-bound imports, call arguments, strings, sections, RTTI) |
| Session | `server_status` (version, tool catalog digest, limits, which engines are available and how to fix a missing one) · `read_result` (pages through a result too large to send; the `limit_exceeded` error names it) |

### Compared with [tuna1999/dnspy-mcp](https://github.com/tuna1999/dnspy-mcp)

| | dnspy-mcp | NetDecompilerMcp |
|---|---|---|
| Runs without dnSpy / GUI | headless mode only (36 tools) | always (92 tools) |
| Cross-references | methods and fields (`get_xrefs_to`) | methods (incl. virtual/interface dispatch), fields (read/write/address), properties, events, types in every position, overrides, hierarchy with derived types |
| Search | types, methods, strings, `grep` | symbols (wildcard/regex, all member kinds), strings, numeric constants, IL instruction patterns |
| Method patching | C# statements (`update_method_body`) | C# bodies with lambdas/async/LINQ (Roslyn, private access, ctor initializers preserved), new members and types, IL assembler (accepts edited `get_il` output, prepend hooks), constant stubs |
| Undo, diffs, edit scripts | — | undo / revert, before/after C# diffs, replayable edit scripts |
| Call trees, build comparison | — | multi-level call trees and call paths; build-to-build diff with rename matching |
| Saving patched DLLs | no (in-memory only) | yes: `.bak`, atomic write, stable tokens |
| Il2Cpp dummy DLLs | not supported | addresses, field offsets, native address ↔ method / generic instantiation / metadata slot, vtable slots, string literals and the methods using them, IDA/Ghidra scripts and C header, C++ bindings |
| Resources | list and raw bytes | text/hex view, `.resources` entries, extraction |
| Whole-project export | `decompile_assembly` (first 10 types) | full .csproj with progress |
| MCP resources / prompts / completion / progress | — | yes |
| Large output | truncation | paging with cached pages |

## Reliability

| Concern | How it is handled |
|---|---|
| Locked files | Assemblies are read into memory; files on disk are never locked. |
| Concurrency | Reads share a lock; edits take it exclusively. Stress-tested with interleaved readers and writers, and with 40 parallel MCP calls. |
| Corrupt or transformed bodies | The IL scanner stops at invalid opcodes instead of throwing; `decompile_type` falls back to member-by-member output with IL for the broken part. |
| Post-processed metadata | Out-of-range names and coded indexes that toolchains (Babel, Goliath, ConfuserEx-style) leave behind are read leniently by dnlib but not by the decompiler; such assemblies are decompiled from a copy normalized by dnlib, with the same tokens, and the output says so. |
| Invisible names | Names made of zero-width and bidi characters (U+202E reverses the rest of a line) are shown as `\uXXXX`, as the decompiler does; symbols are accepted back in that form. |
| Huge output | Paged (`offset` / `maxChars`); pages come from a cache. |
| Files changing on disk | Watched: clean assemblies reload automatically; ones with unsaved edits are left alone and the agent is told. |
| Slow first queries | Method bodies are indexed and the call graph is built in the background after loading, in small chunks that never block edits. |
| Runaway work | Per-call timeout (default 180 s) and MCP cancellation. |
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
| Xamarin / MAUI `.apk` / `.aab` | A zip with `AndroidManifest.xml` | Assemblies, with `XALZ` (LZ4) ones decompressed; `assemblies.blob` / `libassemblies.*.blob.so` stores are scanned for PE images and `XALZ` chunks. An assembly repeated in several per-ABI stores is written once. |
| Other zips (`.zip`, `.vsix`, `.xap`) | Zip signature | `.dll` / `.exe` / `.winmd`, `.deps.json` / `.runtimeconfig.json`, and nested packages. Everything else (images, Android resources, Java code) is skipped. |
| Standalone `XALZ` file | `XALZ` magic | The decompressed assembly. |
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
| `summarize_file` | File hashes, type and entropy; per assembly: identity (name, version, MVID, target framework, GUI / console / library, architecture, ReadyToRun, merged), strong name and Authenticode signature, toolchain markers and heuristics, container wrapping (embedded assemblies, decoded embedded content, high-entropy sections), features, a summary of typed strings, and entry points (Main, module initializers, native exports, installer / service / AppDomainManager / COM hooks). `highlights` lists the notable findings. |
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
(the rest are replayed), `export_edits` writes a JSON script, and `apply_edits` replays it, by token on the same build
and by name on a new one. When a target was renamed in the new build, load the build the script was made from as well:
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
  key (friend assemblies that grant internals by key keep doing so).
- **Output the decompiler engine gets wrong, rewritten** (also in `decompile_type` / `decompile_member`): span-slicing
  `ref` temporaries, `scoped` locals, initialized `stackalloc`, base constructor calls in bodies, constructor
  parameters in field initializers, nested locals of one name, struct enumerators disposed by pattern, trimmed
  getters, bools used as integers, negative constants cast to unsigned types, null-conditional extension calls,
  framework type names that clash across imported namespaces, compiler-reserved and source-generator attributes, and
  transformation leftovers (renamed `value` parameters, unspeakable parameter names, dropped `new()` constraints, a
  renamed `Main`). LINQ comes out as method calls in exports.
- A method the engine cannot decompile at all keeps the engine's explanation and throws `NotSupportedException`.

**Dependencies that are not on the machine** (an assembly missing from a partial dump) do not stop decompilation: a
stand-in is rebuilt from how the loaded code uses it: every type it references with its kind (struct, enum,
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
  The options cover every option family of the tool and its packer, alone and combined, and its bundled profiles. What
  simplifying took back of the instructions each option added is checked against floors pinned per option and sample,
  and the report ends with an option × sample coverage table. Needs the .NET Framework 4.8 reference assemblies;
  options the tool cannot process, or whose output is not checkable IL, are listed with the reason.

| Variable | Effect |
|---|---|
| `NDM_FUZZ_COUNT` | Fuzz seeds 1..N (default 40) |
| `NDM_FUZZ_SEED` | Run one seed (`random` for a fresh one) |
| `NDM_SWEEP=full` | Add the largest libraries to the sweep (System.Private.CoreLib, mscorlib, Roslyn VB, BouncyCastle, Math.NET) |
| `NDM_PERF_FACTOR` | Allowed multiple of the per-method baseline (default 5) |
| `NDM_PIPELINE_TOOL` | The pipeline's command-line executable (enables the round trip; floors pinned with neo-ConfuserEx 1.0.0-rc1) |
| `NDM_PIPELINE_SAMPLES` | Optional: the tool's sample folder (`BasicFlow`, `Constants`, `ExceptionFlow`, one `Program.cs` each) |
| `NDM_PIPELINE_PROFILES` | Optional: a folder of bundled project profiles (default: `Build/Profiles` next to the tool) |
| `NDM_PIPELINE_SEEDS`, `NDM_PIPELINE_ONLY`, `NDM_PIPELINE_SAMPLE` | Seeds 1..N (default 3); only options / samples whose name contains this text |
| `NDM_PIPELINE_PARALLEL` | Round trips run at once (default 1; the full matrix takes about 6 minutes at 8) |
| `NDM_PIPELINE_REPORT`, `NDM_PIPELINE_KEEP` | Write the result table and coverage table to this file; keep the work files |
| `NDM_PIPELINE_RECHECK=1` | Also run the skipped options, to see whether a new tool build changed them |

The generated C, C++ and Python are compiled or parsed with clang (`C:\Program Files\LLVM\bin`) and python when
they are installed.

CI (`.github/workflows/ci.yml`) runs the tests on Windows, Linux and macOS. The tests publish hello-world apps and
download runtime / crossgen2 packs and NuGet packages at test time; CI keeps them in one package folder, cached per OS,
SDK version and project files. Real-data tests have no data there and report as skipped. Pushing a `v*` tag runs
`release.yml`, which attaches self-contained single-file builds for win-x64, linux-x64 and osx-arm64 to a GitHub release.

## Server options

Options go after the command in a client's configuration (`args`), e.g. to preload a folder:
`"args": ["--load", "D:\\App\\App_Data\\Managed"]`.

| Option | Meaning |
|---|---|
| `--load <path>` | Assembly file or folder to load at startup (repeatable). The `NETDECOMP_LOAD` env var takes `;`-separated paths. |
| `--search-dir <dir>` | Extra directory for resolving references (repeatable). |
| `--max-output <chars>` | Page size for long results (default 60000). |
| `--timeout <seconds>` | Per-call decompilation timeout (default 180; `export_project` gets 10×). |
| `--no-index` | Don't index method bodies and build the call graph in the background after loading. |
| `--no-watch` | Don't watch loaded files or reload them when they change on disk. |
| `--binding-style <mono\|hostapi>` | `generate_cpp_binding` style when a call gives none and no host table is detected (default `mono`). |
| `--binding-project <dir>` | Project directory `generate_cpp_binding` scans for a host table when a call gives no `projectDir`. |

Logs go to stderr; stdout is reserved for the protocol.

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

## License

MIT. See [LICENSE](LICENSE).
