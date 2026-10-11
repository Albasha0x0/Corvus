# Tools

<!-- Generated from the tool catalog by DocsTests; run the tests with NDM_UPDATE_DOCS=1 to update. -->

131 tools in 13 toolsets. A server registers every tool unless it is started with `--toolsets` (README, "Server options"). From a terminal, `NetDecompilerMcp describe <tool>` prints the same reference and `NetDecompilerMcp <tool> name=value ...` calls a tool ([cli.md](cli.md)).

Annotations: **read-only** tools change nothing; **edit** tools change the in-memory workspace; **destructive** tools can remove or overwrite state; **long-running** tools can take more than 10 s and have no call deadline.

| Toolset | In `core` | Tools |
|---|---|---|
| [session](#session) | yes | 9: workspace and server state |
| [dotnet](#dotnet) | yes | 25: .NET browse, decompile, search, navigate, resources, ReadyToRun, project export |
| [containers](#containers) | yes | 7: file inspection, containers and wrapped apps, Unity overview |
| [edit](#edit) | yes | 15: .NET edits, edit history and saving |
| [il2cpp](#il2cpp) | yes | 5: Il2Cpp metadata, addresses, symbols and bindings |
| [native](#native) | yes | 25: native PE analysis, symbols and decompilation |
| [native-edit](#native-edit) | yes | 9: native names, comments, patches and saving |
| [builds](#builds) | yes | 10: build-to-build comparison and carrying work to a new build |
| [notes](#notes) | yes | 3: analyst notes kept per binary across sessions |
| [engine](#engine) | no | 7: edits inside the decompiler engine's database: types, locals, frames, declarations, scripting |
| [android](#android) | no | 8: Android packages: manifest, resources, DEX code, Java decompilation, Java / .NET mapping, devices |
| [dumps](#dumps) | no | 7: crash dumps and crash text |
| [live](#live) | no | 1: read-only inspection of a running process |

## session

Workspace and server state.

### load_assembly

**Load assembly** (edit, idempotent, long-running)

Load a .NET assembly (.dll/.exe) or every assembly in a directory (e.g. an application folder, a Unity *_Data/Managed folder or an Il2CppDumper DummyDll folder). A native PE (without .NET metadata), ELF or Mach-O file given by path loads as a native image for the native tools (get_pe_info, list_imports, list_exports, list_functions, disassemble); a universal Mach-O loads one slice (slice=) as name[slice]; folder loads take only .NET assemblies and list the native files they skipped. An Il2Cpp game (game folder or global-metadata.dat: Windows, Linux, macOS, extracted Android, iOS .app; an .apk/.xapk/.aab/.ipa; also a memory dump of the binary) is read by the built-in metadata reader (versions 24-39, no external dumper): dummy assemblies with method addresses, field offsets and tokens, plus string literals, generic instantiations and metadata slots for the Il2Cpp tools, cached per user (NDM_IL2CPP_CACHE); the binary is loaded as a native image too. Unreadable metadata is an error with a reason (encrypted_or_obfuscated, unsupported_version, binary_mismatch_or_protected, encrypted_fairplay); unreadable items are listed by reason. Files are read into memory and never locked. The directory joins the reference search path. Loading the same path twice is a no-op. loadProviders=true also loads the DLLs a file's imports bind to (one level, never their own dependencies; at most 16 per call), so native_call_tree, find_xrefs and the .NET call tools continue into them.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `path` | string | yes |  | Absolute path to an assembly file or a directory. |
| `recursive` | boolean |  | `false` | When path is a directory, also load assemblies in subdirectories. |
| `loadProviders` | boolean |  | `false` | For a file: also load the DLLs its imports bind to, one level deep (at most 16). |
| `slice` | string |  |  | Universal Mach-O slice (name or index; default arm64e, arm64, x86_64), or an Android Il2Cpp game's ABI (default arm64-v8a). Values: arm64e, arm64, x86_64, x86_64h, arm64_32, armv7, armv7s, armv7k, i386, arm64-v8a, armeabi-v7a, x86. |

### unload_assembly

**Unload assembly** (destructive, idempotent)

Remove an assembly from the workspace (unsaved edits are discarded).

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `assembly` | string | yes |  | Assembly id, name, file name or path (see list_assemblies). |

### reload_assembly

**Reload assembly** (destructive, idempotent)

Re-read an assembly from disk (e.g. after an update or after save_assembly overwrote it), discarding unsaved in-memory edits.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `assembly` | string | yes |  | Assembly id, name, file name or path (see list_assemblies). |

### add_search_directory

**Add reference search directory** (edit, idempotent)

Add a directory for resolving referenced assemblies that are not loaded (an application folder, a framework directory). Improves decompilation, cross-assembly navigation and C# patching.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `directory` | string | yes |  | Directory path. |

### list_assemblies

**List loaded assemblies** (read-only, idempotent)

Loaded assemblies with their ids (use the id in other tools), versions, paths, whether they are Il2Cpp dummy DLLs, ReadyToRun (precompiled native code next to the IL), merged (ILMerge / ILRepack output, with the original module count), and unsaved edits (paged: filter, offset, limit — total has the full count); plus the reference search directories. Pass path instead to list the managed assemblies inside a container file (single-file bundle, .nupkg, .apk / .aab, Costura host, zip) without extracting or loading them (only the container is listed then, not the workspace); unpack_container extracts and loads them.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `path` | string |  |  | Optional: a container file whose managed assemblies to list (a plain assembly lists itself). |
| `filter` | string |  |  | Only loaded assemblies whose id, name or path contains this text (case-insensitive). |
| `offset` | integer |  | `0` | Index of the first loaded assembly to return. |
| `limit` | integer |  | `100` | Max loaded assemblies to return (default 100; total has the full count). |

Structured output: `assemblies`, `searchDirectories`, `backgroundIndexing`, `container`, `total`, `nativeImages`.

### server_status

**Server status** (read-only, idempotent, open-world)

Which server is running (version and commit, program path, install kind, start time, protocol, client), a digest of the tool and prompt catalog, what is loaded, background indexing state, response limits, long-running tools, which capabilities are available here with the reason and the fix when one is not, the tool families registered, and the tools or modes that cannot work here. Pass expectedCatalogDigest (from an earlier server_status, or NetDecompilerMcp doctor) to detect a stale server, and expectedExecutable to check that the client started the copy it was registered with.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `expectedCatalogDigest` | string |  |  | Catalog digest to compare with this server's (e.g. t92-0123456789ab.p5-01234567). |
| `expectedExecutable` | string |  |  | Path of the server program the client is registered with, compared with the running one. |

Structured output: `version`, `informationalVersion`, `executable`, `executableMatches`, `installKind`, `startedAt`, `uptimeSeconds`, `protocolVersion`, `client`, `catalogDigest`, `catalogMatches`, `catalogDifference`, `tools`, `loadedAssemblies`, `backgroundIndexing`, `maxOutputChars`, `timeoutSeconds`, `workingSetMB`, `capabilities`, `longRunningTools`, `toolsets`, `unavailableTools`, `notes`.

### read_result

**Read a kept result** (read-only, idempotent)

Page through a result that was too large to send (a limit_exceeded error names it, e.g. r3). Results are kept while memory allows.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `id` | string | yes |  | Kept result id from the limit_exceeded error, e.g. r3. |
| `offset` | integer |  | `0` | Character offset for paging long output (use the value from the truncation footer). |
| `maxChars` | integer |  |  | Max characters in this page (default from server config, ~60000). |

### save_session

**Save the session** (destructive, idempotent)

Write the work of this session to one JSON file (net-decompiler-session/1): every loaded file by path, path relative to the session file and SHA-256; each assembly's unsaved edits (the export_edits script), each native image's patches (the export_native_patches json) and user names and comments, and the notes on these files. load_session restores it here or on another machine.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `path` | string | yes |  | Output file path (.json). |
| `overwrite` | boolean |  | `false` | Replace the file if it exists. |
| `include` | string |  |  | Parts to include, comma-separated: edits, patches, annotations, notes; all (default). Files are always listed. |

Structured output: `path`, `files`, `editedAssemblies`, `edits`, `patchedImages`, `patches`, `names`, `comments`, `notes`.

### load_session

**Load a session** (destructive, long-running)

Restore a save_session file: find each file (recorded path, path relative to the session file, else a file with the same SHA-256 under searchRoots), load it, then apply names and comments (never replacing a different user name), native patches and .NET edits, and import the notes. Files are checked by SHA-256: targetBuild=same (default) refuses a changed file; other carries the work to the build now at the recorded path (.NET edits re-resolved by name as apply_edits targetBuild=other; native names and patches through the function match, which needs the old build too, found by SHA-256 under searchRoots). dryRun (default true) reports and changes nothing. Returns one outcome per item with a reason.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `path` | string | yes |  | The session file. |
| `dryRun` | boolean |  | `true` | Report only (default true). |
| `targetBuild` | string |  |  | same (default): only the recorded builds; other: carry the work to the build now at the recorded path. Values: same, other. |
| `searchRoots` | string |  |  | ';'-separated folders searched (recursively) for files that moved, by SHA-256. |
| `include` | string |  |  | Parts to restore, comma-separated: edits, patches, annotations, notes; all (default). Files are always loaded. |
| `offset` | integer |  | `0` | Items to skip. |
| `limit` | integer |  | `200` | Items to return (default 200, max 2000). |

Structured output: `path`, `dryRun`, `targetBuild`, `outcomes`, `offset`, `total`, `truncated`, `items`, `notes`.

## dotnet

.NET browse, decompile, search, navigate, resources, ReadyToRun, project export.

### list_namespaces

**List namespaces** (read-only, idempotent)

List namespaces with their type counts (nested types counted under their outer type's namespace, as list_types lists them; the counts add up to get_assembly_info's total).

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `assembly` | string |  |  | Assembly id, name, file name or path (see list_assemblies). Optional: omit to use all loaded assemblies. |
| `filter` | string |  |  | Only namespaces containing this text (case-insensitive). |
| `offset` | integer |  | `0` | Index of the first namespace to return. |
| `limit` | integer |  | `2000` | Max namespaces (default 2000). |

Structured output: `items`, `offset`, `total`, `truncated`.

### list_types

**List types** (read-only, idempotent)

List types, optionally restricted to a namespace, a name filter and a kind. Paged by offset/limit.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `assembly` | string |  |  | Assembly id, name, file name or path (see list_assemblies). Optional: omit to use all loaded assemblies. |
| `namespace` | string |  |  | Exact namespace ('' or '<global>' for the global namespace). Omit for all. |
| `filter` | string |  |  | Name filter: substring, wildcard (*, ?) or regex if regex=true. |
| `regex` | boolean |  | `false` | Treat filter as a regular expression. |
| `kind` | string |  |  | Only this kind: class, struct, interface, enum, delegate. Values: class, struct, interface, enum, delegate. |
| `includeNested` | boolean |  | `true` | Include nested types. |
| `offset` | integer |  | `0` | Index of the first result to return. |
| `limit` | integer |  | `300` | Max results (default 300). |

Structured output: `items`, `offset`, `total`, `truncated`, `notEvaluated`.

### get_type_info

**Type outline** (read-only, idempotent)

Outline of a type without decompiling: declaration, attributes, nested types, fields (constants, enum values with hex, Il2Cpp offsets), properties, events and method signatures with tokens, IL sizes and Il2Cpp RVAs.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `type` | string | yes |  | Type name or token. Type or member. Forms: 'Ns.Type', 'Ns.Outer+Inner', short 'Type', 'Ns.Type::Method', 'Ns.Type.Method', 'Ns.Type::Method(int, string)' for one overload, 'Ns.Type::.ctor', or a metadata token like '0x06000123'. |
| `assembly` | string |  |  | Assembly id, name, file name or path (see list_assemblies). Optional: omit to use all loaded assemblies. |
| `includeCompilerGenerated` | boolean |  | `false` | Include compiler-generated members (backing fields, lambdas, state machines). |

Structured output: `type`, `fullName`, `declaration`, `declaringType`, `attributes`, `nestedTypes`, `fields`, `properties`, `events`, `methods`, `compilerGeneratedHidden`, `truncated`.

### get_assembly_info

**Assembly overview** (read-only, idempotent)

Assembly overview: identity (MVID, file SHA-256), target framework, entry point, counts, references (and whether each resolves), PE headers and sections, metadata streams, table row counts and heap sizes, metadata problems (every bad table, coded or heap index, with file offsets), assembly attributes, Il2Cpp detection, invalid IL bodies and exception clauses, unsaved edits.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `assembly` | string | yes |  | Assembly id, name, file name or path (see list_assemblies). |

Structured output: `id`, `fullName`, `file`, `sha256`, `mvid`, `runtime`, `kind`, `machine`, `targetFramework`, `entryPoint`, `types`, `nestedTypes`, `namespaces`, `methods`, `fields`, `resources`, `referenceAssembly`, `il2CppAddressedMethods`, `invalidBodies`, `invalidExceptionClauses`, `unsavedEdits`, `references`, `attributes`, `tables`, `heaps`, `metadataIssueCount`, `metadataIssues`.

### get_attributes

**Custom attributes** (read-only, idempotent)

Custom attributes with arguments on a type, method (including parameter and return attributes), field, property or event — or on the assembly/module when symbol is omitted. To find everything carrying an attribute, use find_references on the attribute type.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `symbol` | string |  |  | Symbol to inspect; omit for assembly-level attributes. Type or member. Forms: 'Ns.Type', 'Ns.Outer+Inner', short 'Type', 'Ns.Type::Method', 'Ns.Type.Method', 'Ns.Type::Method(int, string)' for one overload, 'Ns.Type::.ctor', or a metadata token like '0x06000123'. |
| `assembly` | string |  |  | Assembly id, name, file name or path (see list_assemblies). Optional: omit to use all loaded assemblies. Required when symbol is omitted. |
| `filter` | string |  |  | Only attributes whose type name contains this text. |

### get_type_hierarchy

**Type hierarchy** (read-only, idempotent)

Base-type chain, all implemented interfaces (including inherited), and the types that directly derive from it (or implement it, for an interface) across all loaded assemblies.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `type` | string | yes |  | Type name or token. Type or member. Forms: 'Ns.Type', 'Ns.Outer+Inner', short 'Type', 'Ns.Type::Method', 'Ns.Type.Method', 'Ns.Type::Method(int, string)' for one overload, 'Ns.Type::.ctor', or a metadata token like '0x06000123'. |
| `assembly` | string |  |  | Assembly id, name, file name or path (see list_assemblies). Optional: omit to use all loaded assemblies. |
| `limit` | integer |  | `200` | Max derived types to list (default 200). |

### resolve_symbol

**Resolve symbol** (read-only, idempotent)

Show what a symbol string or metadata token resolves to (every match, with kind, assembly, token and signature). Use it to disambiguate before other calls.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `symbol` | string | yes |  | Type or member. Forms: 'Ns.Type', 'Ns.Outer+Inner', short 'Type', 'Ns.Type::Method', 'Ns.Type.Method', 'Ns.Type::Method(int, string)' for one overload, 'Ns.Type::.ctor', or a metadata token like '0x06000123'. |
| `assembly` | string |  |  | Assembly id, name, file name or path (see list_assemblies). Optional: omit to use all loaded assemblies. |
| `kind` | string |  |  | Restrict to: any, type, method, field, property, event, member. Values: any, type, method, field, property, event, member. |

Structured output: `items`, `offset`, `total`, `truncated`, `notEvaluated`.

### decompile_type

**Decompile type to C#** (read-only, idempotent)

Decompile a whole type (class/struct/interface/enum/delegate, including nested types) to C#. Long output is paged: call again with the offset from the footer. If one method breaks the decompiler, the rest is still returned with IL for the broken part.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `type` | string | yes |  | Type name or token. Type or member. Forms: 'Ns.Type', 'Ns.Outer+Inner', short 'Type', 'Ns.Type::Method', 'Ns.Type.Method', 'Ns.Type::Method(int, string)' for one overload, 'Ns.Type::.ctor', or a metadata token like '0x06000123'. |
| `assembly` | string |  |  | Assembly id, name, file name or path (see list_assemblies). Optional: omit to use all loaded assemblies. |
| `simplified` | boolean |  | `false` | Show the code as simplify_methods would leave it (constant strings folded, dead branches removed, forwarders inlined), without changing the assembly. |
| `offset` | integer |  | `0` | Character offset for paging long output (use the value from the truncation footer). |
| `maxChars` | integer |  |  | Max characters in this page (default from server config, ~60000). |

### decompile_member

**Decompile member to C#** (read-only, idempotent)

Decompile a method, property, field, event or constructor to C#. When a name has several overloads all are returned, unless a parameter list narrows it ('Ns.Type::Foo(int, string)'). Async/iterator state machines and lambdas are folded back into the original method. A type name decompiles the whole type.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `member` | string | yes |  | Type or member. Forms: 'Ns.Type', 'Ns.Outer+Inner', short 'Type', 'Ns.Type::Method', 'Ns.Type.Method', 'Ns.Type::Method(int, string)' for one overload, 'Ns.Type::.ctor', or a metadata token like '0x06000123'. |
| `assembly` | string |  |  | Assembly id, name, file name or path (see list_assemblies). Optional: omit to use all loaded assemblies. |
| `kind` | string |  |  | Restrict to: method, field, property, event (default any). Values: any, method, field, property, event. |
| `simplified` | boolean |  | `false` | Show the code as simplify_methods would leave it (constant strings folded, dead branches removed, forwarders inlined), without changing the assembly. |
| `provenance` | boolean |  | `false` | Start with comment lines that pin the output to its build: file SHA-256 and MVID, each member's token, and for methods the normalized IL hash and the raw IL SHA-256 (docs/il-hash.md). |
| `offset` | integer |  | `0` | Character offset for paging long output (use the value from the truncation footer). |
| `maxChars` | integer |  |  | Max characters in this page (default from server config, ~60000). |

### decompile_assembly_attributes

**Decompile assembly attributes** (read-only, idempotent)

Decompile assembly- and module-level attributes (InternalsVisibleTo, versions, TargetFramework...) to C#.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `assembly` | string | yes |  | Assembly id, name, file name or path (see list_assemblies). |

### get_il

**IL disassembly** (read-only, idempotent)

IL disassembly (ildasm style, with /* metadata token */ comments, IL offsets and structured try/catch blocks) of a method, field, property, event, or a whole type. Each method starts with its normalized IL hash (stable across rebuilds), the SHA-256 of its raw IL bytes (exact build) and any invalid exception clause. Use it when the C# looks wrong, for transformed code, or as the starting point for patch_method_il.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `symbol` | string | yes |  | Type or member. Forms: 'Ns.Type', 'Ns.Outer+Inner', short 'Type', 'Ns.Type::Method', 'Ns.Type.Method', 'Ns.Type::Method(int, string)' for one overload, 'Ns.Type::.ctor', or a metadata token like '0x06000123'. |
| `assembly` | string |  |  | Assembly id, name, file name or path (see list_assemblies). Optional: omit to use all loaded assemblies. |
| `offset` | integer |  | `0` | Character offset for paging long output (use the value from the truncation footer). |
| `maxChars` | integer |  |  | Max characters in this page (default from server config, ~60000). |

### search_symbols

**Search symbols by name** (read-only, idempotent)

Find types and members by name across loaded assemblies. Query is a case-insensitive substring, a wildcard pattern (Get*Value?) or a regex (regex=true). Queries containing '.' or '::' also match full names. Exact matches are listed first.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `query` | string | yes |  | Name, substring, wildcard or regex. |
| `kind` | string |  |  | Restrict to: any, type, method, field, property, event, member. Values: any, type, method, field, property, event, member. |
| `assembly` | string |  |  | Assembly id, name, file name or path (see list_assemblies). Optional: omit to use all loaded assemblies. |
| `namespace` | string |  |  | Only types in namespaces starting with this. |
| `regex` | boolean |  | `false` | Treat query as a regular expression. |
| `limit` | integer |  | `100` | Max results (default 100). |
| `offset` | integer |  | `0` | Index of the first result to return. |

Structured output: `items`, `offset`, `total`, `truncated`, `notEvaluated`.

### search_strings

**Search string literals** (read-only, idempotent)

Find string literals (ldstr in method bodies, and string constants) by substring, wildcard or regex, with the method and IL offset using each. Locates code from UI text, log messages, URLs, keys. For Il2Cpp dummy DLLs (empty bodies) it searches the game's string literals instead (the dump's stringliteral.json, or the metadata read by the built-in reader): each literal with its slot RVA and, when GameAssembly.dll is next to the dump, the native functions that load it, named by their dummy-DLL method (or script.json name for generic instantiations).

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `query` | string | yes |  | Substring, wildcard or regex. |
| `assembly` | string |  |  | Assembly id, name, file name or path (see list_assemblies). Optional: omit to use all loaded assemblies. |
| `regex` | boolean |  | `false` | Treat query as a regular expression. |
| `limit` | integer |  | `200` | Max results (default 200). |
| `offset` | integer |  | `0` | Index of the first result to return. |
| `usesPerLiteral` | integer |  | `10` | Il2Cpp literals: max functions listed per literal (default 10). |

Structured output: `items`, `offset`, `total`, `truncated`, `notEvaluated`.

### search_constants

**Search numeric constants** (read-only, idempotent)

Find a numeric constant (magic number, packet/opcode id, flag, hash seed, crypto constant) wherever it appears: IL literals (ldc.*), const and enum field values, attribute arguments, and static array data (lookup tables, S-boxes, CRC and crypto tables), read element by element as the array's own type. Accepts decimal, 0x hex, negative and floating-point values.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `value` | string | yes |  | Number, e.g. 1337, 0xDEADBEEF, -1, 3.14. |
| `assembly` | string |  |  | Assembly id, name, file name or path (see list_assemblies). Optional: omit to use all loaded assemblies. |
| `limit` | integer |  | `200` | Max results (default 200). |
| `offset` | integer |  | `0` | Index of the first result to return. |

Structured output: `value`, `items`, `offset`, `total`, `truncated`.

### search_il

**Search IL instruction patterns** (read-only, idempotent)

Find methods containing an IL instruction sequence. Elements separated by ';' or newlines, each 'opcode [operand]' with * and ? wildcards; '...' skips up to 16 instructions. Operands match member labels/full names, type names, strings and numbers (decimal or 0x hex). Examples: 'ldstr *password*; ...; call *::Hash*' | 'callvirt *Socket::Send*' | 'ldc.i4 0x1F4; call *' | 'newobj *Exception::.ctor*; throw'.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `pattern` | string | yes |  | Instruction pattern. |
| `assembly` | string |  |  | Assembly id, name, file name or path (see list_assemblies). Optional: omit to use all loaded assemblies. |
| `limit` | integer |  | `100` | Max matches (default 100). |
| `offset` | integer |  | `0` | Index of the first match to return. |

Structured output: `items`, `offset`, `total`, `truncated`.

### find_references

**Find usages (xrefs to)** (read-only, idempotent)

Every usage of a symbol across all loaded assemblies ('Used By'). Method: call sites (call/callvirt/newobj/ldftn/ldtoken). Field: reads, writes, address-taken. Property/event: accessor calls. Type: base type, interface, generic constraint, field/parameter/return/local types, catch clauses, attributes, instantiations, casts, member accesses. With includeVirtualCalls (default true) a method's results also include calls made through the base/interface method it overrides or implements. A native export (kernel32.dll!CreateFileW) lists the P/Invoke declarations bound to it with their call sites, and native call sites in loaded images; a managed method called from native code (C++/CLI) also lists those native call sites.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `symbol` | string | yes |  | Type or member. Forms: 'Ns.Type', 'Ns.Outer+Inner', short 'Type', 'Ns.Type::Method', 'Ns.Type.Method', 'Ns.Type::Method(int, string)' for one overload, 'Ns.Type::.ctor', or a metadata token like '0x06000123'. Or a native export: 'kernel32.dll!CreateFileW' (module with .dll/.exe/.sys extension), or 'native:<image>!<export>' where image is a loaded image id, file name or path, or a DLL name found by the loader's search order, and export is a name, '#ordinal', or for a loaded image an address or function name ('native:KERNELBASE.dll!0x180034560'). Matches the P/Invoke declarations bound to that code and their callers. |
| `assembly` | string |  |  | Assembly that defines the symbol (only to disambiguate). References are searched in all loaded assemblies. |
| `kind` | string |  |  | Restrict symbol resolution to: type, method, field, property, event. Values: type, method, field, property, event. |
| `includeVirtualCalls` | boolean |  | `true` | For methods: include calls through base/interface declarations that dispatch here. |
| `limit` | integer |  | `300` | Max results (default 300). |
| `offset` | integer |  | `0` | Index of the first reference to return. |

Structured output: `target`, `items`, `nativeCallSites`, `offset`, `total`, `truncated`.

### find_callees

**What a method uses (xrefs from)** (read-only, idempotent)

What a method uses: methods it calls, fields it reads/writes, types it instantiates/casts, and string literals, in IL order with offsets ('Uses'). Calls to P/Invoke declarations (and native method bodies of mixed-mode assemblies) also show the native code they bind to ('native: module!export -> PROVIDER!export at VA [image]'; disassemble takes that image and VA). For a P/Invoke method itself, or a native export symbol, the native function's callees.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `method` | string | yes |  | Method. Type or member. Forms: 'Ns.Type', 'Ns.Outer+Inner', short 'Type', 'Ns.Type::Method', 'Ns.Type.Method', 'Ns.Type::Method(int, string)' for one overload, 'Ns.Type::.ctor', or a metadata token like '0x06000123'. Or a native export: 'kernel32.dll!CreateFileW' (module with .dll/.exe/.sys extension), or 'native:<image>!<export>' where image is a loaded image id, file name or path, or a DLL name found by the loader's search order, and export is a name, '#ordinal', or for a loaded image an address or function name ('native:KERNELBASE.dll!0x180034560'). Matches the P/Invoke declarations bound to that code and their callers. |
| `assembly` | string |  |  | Assembly id, name, file name or path (see list_assemblies). Optional: omit to use all loaded assemblies. |
| `distinct` | boolean |  | `false` | Collapse repeated targets into one line with a count. |
| `offset` | integer |  | `0` | Index of the first entry to return. |
| `limit` | integer |  | `2000` | Max entries (default 2000). |

Structured output: `method`, `items`, `nativeLines`, `offset`, `total`, `truncated`.

### find_overrides

**Find overrides / implementations** (read-only, idempotent)

Methods that override a virtual/abstract method or implement an interface method, across all derived types in loaded assemblies (explicit and implicit implementations).

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `method` | string | yes |  | Virtual, abstract or interface method. Type or member. Forms: 'Ns.Type', 'Ns.Outer+Inner', short 'Type', 'Ns.Type::Method', 'Ns.Type.Method', 'Ns.Type::Method(int, string)' for one overload, 'Ns.Type::.ctor', or a metadata token like '0x06000123'. |
| `assembly` | string |  |  | Assembly id, name, file name or path (see list_assemblies). Optional: omit to use all loaded assemblies. |
| `limit` | integer |  | `200` | Max results (default 200). |
| `offset` | integer |  | `0` | Index of the first result to return. |

Structured output: `method`, `items`, `offset`, `total`, `truncated`.

### get_call_tree

**Call tree (callers / callees)** (read-only, idempotent)

Multi-level call tree of a method across all loaded assemblies: direction=callers (who calls it, who calls those...) or callees (what it calls, recursively). Callers include calls through base/interface methods it overrides or implements. Repeated nodes and recursion are marked instead of expanded again. Callees continue into native code: a P/Invoke (or a native method body of a mixed-mode C++/CLI assembly) shows 'native: module!export -> PROVIDER!export at VA [image]' and, when that image is loaded, the native callees below it (disassemble works with the image and VA shown). Callers of a managed method called from native code (C++/CLI thunks) list those native callers. Given a native export, callers lists native call sites in loaded images and the P/Invoke declarations bound to it with their managed callers.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `method` | string | yes |  | Method. Type or member. Forms: 'Ns.Type', 'Ns.Outer+Inner', short 'Type', 'Ns.Type::Method', 'Ns.Type.Method', 'Ns.Type::Method(int, string)' for one overload, 'Ns.Type::.ctor', or a metadata token like '0x06000123'. Or a native export: 'kernel32.dll!CreateFileW' (module with .dll/.exe/.sys extension), or 'native:<image>!<export>' where image is a loaded image id, file name or path, or a DLL name found by the loader's search order, and export is a name, '#ordinal', or for a loaded image an address or function name ('native:KERNELBASE.dll!0x180034560'). Matches the P/Invoke declarations bound to that code and their callers. |
| `direction` | string |  | `callers` | callers or callees. Values: callers, callees. |
| `depth` | integer |  | `3` | Levels to expand (1-8, default 3). |
| `maxNodes` | integer |  | `300` | Stop after this many nodes (default 300). |
| `includeExternal` | boolean |  | `false` | For callees: also list calls into assemblies that are not loaded (framework). |
| `assembly` | string |  |  | Assembly id, name, file name or path (see list_assemblies). Optional: omit to use all loaded assemblies. |
| `offset` | integer |  | `0` | Character offset for paging long output (use the value from the truncation footer). |
| `maxChars` | integer |  |  | Max characters in this page (default from server config, ~60000). |

Structured output: `root`, `direction`, `depth`, `items`, `total`, `truncated`.

### find_call_paths

**Call paths to a method** (read-only, idempotent)

How execution reaches a method: call chains from 'from' to 'to', or — when 'from' is omitted — from entry points (methods nothing in the workspace calls: Main, Unity callbacks, event handlers). Shortest first, direct calls preferred; a hop that only happens through virtual dispatch (a call to a base/interface method this one overrides) is marked. 'to' may be a native export: paths then end at the P/Invoke declarations bound to it, followed by the native hop.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `to` | string | yes |  | Target method. Type or member. Forms: 'Ns.Type', 'Ns.Outer+Inner', short 'Type', 'Ns.Type::Method', 'Ns.Type.Method', 'Ns.Type::Method(int, string)' for one overload, 'Ns.Type::.ctor', or a metadata token like '0x06000123'. Or a native export: 'kernel32.dll!CreateFileW' (module with .dll/.exe/.sys extension), or 'native:<image>!<export>' where image is a loaded image id, file name or path, or a DLL name found by the loader's search order, and export is a name, '#ordinal', or for a loaded image an address or function name ('native:KERNELBASE.dll!0x180034560'). Matches the P/Invoke declarations bound to that code and their callers. |
| `from` | string |  |  | Start method (optional). Type or member. Forms: 'Ns.Type', 'Ns.Outer+Inner', short 'Type', 'Ns.Type::Method', 'Ns.Type.Method', 'Ns.Type::Method(int, string)' for one overload, 'Ns.Type::.ctor', or a metadata token like '0x06000123'. |
| `maxDepth` | integer |  | `8` | Maximum chain length (default 8). |
| `maxPaths` | integer |  | `10` | Maximum number of paths (default 10). |
| `includeVirtual` | boolean |  | `true` | Also follow virtual dispatch: calls to a base/interface method reaching an override (default true). False keeps only direct calls, which avoids chains through widely overridden methods (ToString, Dispose, interface callbacks). |
| `assembly` | string |  |  | Assembly id, name, file name or path (see list_assemblies). Optional: omit to use all loaded assemblies. |

Structured output: `target`, `from`, `items`, `total`, `truncated`.

### list_resources

**List manifest resources** (read-only, idempotent)

List manifest resources: embedded files, .resources containers (with entry counts), linked resources. For a native image, its Win32 resources as TYPE/NAME/LANGUAGE.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `assembly` | string | yes |  | Assembly id, name, file name or path (see list_assemblies). |

Structured output: `assembly`, `items`, `total`, `truncated`.

### get_resource

**Read / extract resource** (destructive, idempotent)

Read a resource: text as text, binary as a hex preview, .resources containers as an entry list (pass entry to read one; WPF .baml entries come back as XAML). Pass savePath to extract the raw bytes to disk (images, asset bundles, configs). For a native image, name is TYPE/NAME[/LANGUAGE] from list_resources: version info and string tables are decoded, manifests shown as text.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `assembly` | string | yes |  | Assembly id, name, file name or path (see list_assemblies). |
| `name` | string | yes |  | Resource name as shown by list_resources. |
| `entry` | string |  |  | Entry name inside a .resources container. |
| `savePath` | string |  |  | Write the raw bytes of the resource (or entry) to this file path. |
| `overwrite` | boolean |  | `false` | Replace savePath if it exists. |
| `offset` | integer |  | `0` | Character offset for paging long output (use the value from the truncation footer). |
| `maxChars` | integer |  |  | Max characters in this page (default from server config, ~60000). |

### export_project

**Export C# project** (edit, idempotent, long-running)

Decompile an entire assembly into a C# project on disk (one .cs file per type, a .csproj, and resources). Best way to grep or browse a large codebase with normal file tools. Reports progress.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `assembly` | string | yes |  | Assembly id, name, file name or path (see list_assemblies). |
| `outputDirectory` | string | yes |  | Empty or new output directory. |

### get_r2r_code

**ReadyToRun native code of a method** (read-only, idempotent)

The precompiled native code of a method in a ReadyToRun assembly (crossgen / PublishReadyToRun; the .NET shared framework's assemblies are ReadyToRun): entry address, every code range (hot body, exception funclets, cold code), the import cells its fixups resolve before it first runs, and its x86 / x64 disassembly with import cells named by what they resolve to (called methods as 'call qword ptr [Ns.Type::Method(int)]', type handles, static bases, helpers, string literals). A generic method has code only for the instantiations compiled into the image (e.g. over __Canon); each is shown. For a component of a composite image the code is read from the composite file next to it.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `method` | string | yes |  | Method. Type or member. Forms: 'Ns.Type', 'Ns.Outer+Inner', short 'Type', 'Ns.Type::Method', 'Ns.Type.Method', 'Ns.Type::Method(int, string)' for one overload, 'Ns.Type::.ctor', or a metadata token like '0x06000123'. |
| `assembly` | string |  |  | Assembly id, name, file name or path (see list_assemblies). Optional: omit to use all loaded assemblies. A full path to an assembly that is not loaded yet loads it. |
| `instantiation` | string |  |  | Only bodies whose name contains this text (case-insensitive), e.g. an instantiation argument such as 'Int32' or '__Canon'. |
| `maxBodies` | integer |  | `4` | Max method bodies disassembled (default 4); the rest are listed with their addresses. |
| `maxInstructions` | integer |  | `5000` | Max instructions per body (default 5000). |
| `offset` | integer |  | `0` | Character offset for paging long output (use the value from the truncation footer). |
| `maxChars` | integer |  |  | Max characters in this page (default from server config, ~60000). |

### find_r2r_method

**Managed method at a ReadyToRun address** (read-only, idempotent)

The managed method whose precompiled ReadyToRun code contains a native address (e.g. from a crash dump, profiler or debugger): its name and token, which range (hot body, funclet, cold code) and offset, and the instruction there. An import cell address is described by what it resolves to. Addresses are in the file holding the code (the assembly, or its composite image).

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `assembly` | string | yes |  | Assembly id, name, file name or path (see list_assemblies). A full path to an assembly that is not loaded yet loads it. |
| `address` | string | yes |  | Address in the code image: a VA (0x180012340, inside the image base range), an RVA, or rva:/va:/off: prefixed. |

## containers

File inspection, containers and wrapped apps, Unity overview.

### summarize_file

**Summarize file** (read-only, idempotent)

Summary of a file or loaded assembly, without executing it: file hashes, type and entropy; per managed assembly its identity (name, version, MVID, target framework, GUI/console/library, architecture, ReadyToRun, merged), signature (strong name, Authenticode signer with a digest check and chain), toolchain markers and heuristics, container wrapping (embedded assemblies, decoded embedded content, high-entropy sections), features with ATT&CK techniques, a summary of extracted values, and entry points (Main, module initializer, native exports, installer / service / AppDomainManager / COM hooks). Containers (single-file bundles, packages, APKs, zips, Costura hosts) are opened: the app's own assembly in full, up to 7 more in brief (framework libraries last, translations skipped); an apphost launcher's .dll next to it is summarized as the app. For a NativeAOT executable, nativeAot gives the runtime version, module sections, recovery stages and counts of named methods, MethodTables and frozen strings. ELF / Mach-O: nativeImage gives format, slices, build id, libraries, platform, code signature, entitlements and FairPlay encryption. Android packages: android gives package, versions, SDKs, runtimes with evidence (dotnet-android, unity-il2cpp, unity-mono, flutter, react-native, kotlin / java), ABIs, DEX files, exported components and the APK signature verdict. highlights lists the notable findings.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `path` | string |  |  | Any file: assembly, single-file bundle, .nupkg, .apk, zip, native executable. Pass this or assembly. |
| `assembly` | string |  |  | A loaded assembly (id, name, file name or path). Pass this or path. |

Structured output: `file`, `container`, `assemblies`, `highlights`, `notes`, `nativeAot`, `nativeImage`, `android`.

### survey_features

**Survey features** (read-only, idempotent)

Rule-based (capa-style) survey of the APIs an assembly calls, the native functions it imports (P/Invoke) and its string literals, in categories: network, execution, registry, persistence, collection (keylogging, screen, clipboard, browser credentials), anti-debug / anti-VM, defense evasion, reflective loading and run-time compilation, process injection, discovery, crypto. Each matched feature has its MITRE ATT&CK technique where the operation is the technique itself, and its evidence (pattern, count, up to 5 locations). Native images (a loaded one, or a PE / ELF / Mach-O path) get the same rules over static and late-bound (GetProcAddress) imports, call arguments (VirtualProtect with PAGE_EXECUTE_READWRITE, CreateProcess with CREATE_SUSPENDED...), strings, sections (entropy, packer names, writable code) and RTTI class names, with addresses and functions as locations.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `assembly` | string |  |  | A loaded assembly (id, name, file name or path). Pass this or path. A loaded native image works too. |
| `path` | string |  |  | A .NET assembly or native PE / ELF / Mach-O file to analyze without loading it. Pass this or assembly. |
| `category` | string |  |  | Only this category (network, execution, registry, persistence, collection, credential access, anti-analysis, defense evasion, privilege escalation, code loading, injection, discovery, crypto, impact...) or ATT&CK technique prefix (T1055). |

Structured output: `assembly`, `methodsScanned`, `features`, `notes`.

### extract_strings

**Extract typed strings** (destructive, idempotent)

Typed values from string literals, constants, resource text and base64 / hex / compressed text decoded from the assembly: URLs, domains, IPv4 / IPv6, email addresses, file paths, named pipes, registry keys, mutex names, user agents and crypto keys, each with its count, locations and the APIs it is passed to. XML namespace URLs, version numbers and file names that look like domains are excluded. Pass savePath to export JSON or CSV.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `assembly` | string |  |  | A loaded assembly (id, name, file name or path). Pass this or path. |
| `path` | string |  |  | A .NET assembly file to analyze without loading it. Pass this or assembly. |
| `types` | string |  |  | Only these types (comma-separated): url, domain, ipv4, ipv6, email, file_path, named_pipe, registry_key, mutex, user_agent, crypto_key. |
| `savePath` | string |  |  | Write the values to this file. |
| `format` | string |  |  | Export format: json (default) or csv; a .csv savePath implies csv. Values: json, csv. |
| `overwrite` | boolean |  | `false` | Replace savePath if it exists. |

Structured output: `assembly`, `total`, `values`, `savedTo`, `notes`.

### extract_embedded

**Extract embedded content** (edit, idempotent)

Embedded content of an assembly: embedded resources, .resources entries, static byte arrays (<PrivateImplementationDetails>) and string literals of 64+ characters, decoded through hex, base64, gzip / zlib / deflate and XOR (key recovered from a known PE / ZIP / gzip header; repeating-key XOR over plain text with xorText=true) until a recognized kind appears: .NET / native PE images, archives, ELF / Mach-O binaries, or text; plus high-entropy blobs (1 KB+, 7.5+ bits per byte). Each item shows its source and encoding chain. save=true writes them (defanged names) to a directory of their own; load=true also loads the .NET ones into the workspace. Nothing is executed.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `assembly` | string |  |  | A loaded assembly (id, name, file name or path). Pass this or path. |
| `path` | string |  |  | A .NET assembly file to analyze without loading it. Pass this or assembly. |
| `save` | boolean |  | `false` | Write the items to disk. |
| `outputDirectory` | string |  |  | Directory to write into (new, empty, or an earlier extraction of the same file). Default: under the temp directory. |
| `load` | boolean |  | `false` | Load the .NET assemblies found into the workspace (implies save). |
| `xorText` | boolean |  | `false` | Also recover XOR keys of 1-16 bytes over text on resources and arrays that are not readable as they are (UTF-8 in any script, or UTF-16), keeping a decode only if it is clearly natural text (words of one script, spaces, likely letter pairs) or structured configuration (JSON, XML, URL / key=value lines). Off by default: heuristic, and slower on large data. |
| `includeMedia` | boolean |  | `false` | Also list (and save) images: png, jpeg, gif, ico. By default they are only counted in notes. |

Structured output: `assembly`, `contents`, `outputDirectory`, `notes`.

### search_container

**Search inside a container** (read-only, idempotent)

Find types and members by name in every managed assembly inside a container (single-file bundle, .nupkg, .apk / .aab, Costura host, zip; nested containers too) or a plain assembly, without extracting or loading anything. Query is a case-insensitive substring ('*' / '?' wildcards; a query with '.' or ':' also matches full names). Each match gives the assembly's path inside the container, the assembly name, the full member name and its kind; best matches first. truncated=true means more than limit matched (total has the full count).

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `path` | string | yes |  | Absolute path to the container or assembly file. |
| `query` | string | yes |  | Name or part of a name. |
| `kind` | string |  |  | Restrict to: type, method, field, property. Omit for all (events included). Values: type, method, field, property. |
| `limit` | integer |  | `200` | Max matches returned (default 200, max 5000). |

Structured output: `source`, `container`, `assembliesSearched`, `matches`, `total`, `truncated`, `notes`.

### unpack_container

**Unpack container** (edit, idempotent, long-running)

Extract the .NET assemblies shipped inside a container and (by default) load them: .NET single-file bundles (apphost .exe / Linux / macOS, compressed or not), Costura.Fody embedded assemblies, NuGet packages, Xamarin / MAUI .apk / .aab (XALZ / XAZS compressed assemblies, assembly stores v1-v3 with real names, per ABI), plain zips, and .NET images embedded anywhere else. Nested containers are opened too. Nothing is executed; extracted names cannot escape the output directory and runnable extensions get a .bin suffix. Reports NativeAOT executables, which have no IL to extract.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `path` | string | yes |  | Absolute path to the container file. |
| `outputDirectory` | string |  |  | Directory to extract into: new, empty, or an earlier unpack of the same file. Default: a folder under the temp directory named after the file and its hash. |
| `load` | boolean |  | `true` | Load the extracted .NET assemblies into the workspace (their ids are in loadedAs). |

Structured output: `source`, `container`, `outputDirectory`, `files`, `notes`.

### unity_overview

**Unity title overview** (read-only, idempotent, open-world)

One-call overview of a Unity game, in seconds and without loading it: engine version from each source (UnityPlayer / executable version resources, globalgamemanagers / mainData / level0 serialized-file header, data.unity3d bundle header) with their agreement and an Il2Cpp metadata-version cross-check; scripting backend (il2cpp / mono) with its evidence, metadata version and state (readable by the built-in reader, encrypted, header_tampered, unsupported_version, missing), Mono runtime and .NET profile; toolchain and middleware markers from file, assembly, section and identifier names, each with its category (Detect It Easy detections with detectItEasy=true); platform and architecture; notable folders (Managed, il2cpp_data, StreamingAssets, aa Addressables catalogs, Plugins); and the next tool calls with their arguments (load_assembly the Managed folder or the metadata, or dump from memory with the reason). Reads directory listings, headers and version resources only. Not a Unity title: an unsupported error with reason not_a_unity_title and what was looked for.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `path` | string | yes |  | The game folder, its executable, its <Game>_Data folder, UnityPlayer.dll, GameAssembly.dll or global-metadata.dat; also an extracted Android APK folder or a macOS .app. |
| `detectItEasy` | boolean |  | `false` | Also run Detect It Easy (diec, from NDM_DIE or PATH) on the executable, GameAssembly.dll or Assembly-CSharp.dll: launches it, about a second per file. |

Structured output: `input`, `gameDirectory`, `dataDirectory`, `executable`, `company`, `product`, `platform`, `architecture`, `architectureSource`, `engine`, `backend`, `markers`, `folders`, `nextSteps`, `notes`, `elapsedSeconds`.

## edit

.NET edits, edit history and saving.

### rename_symbol

**Rename symbol** (destructive)

Rename a type, method, field, property (with its accessors) or event in memory — e.g. to give transformed names meaning. Other assemblies that reference the old name are not updated.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `symbol` | string | yes |  | Type or member. Forms: 'Ns.Type', 'Ns.Outer+Inner', short 'Type', 'Ns.Type::Method', 'Ns.Type.Method', 'Ns.Type::Method(int, string)' for one overload, 'Ns.Type::.ctor', or a metadata token like '0x06000123'. |
| `newName` | string | yes |  | New name (for a type: the simple name without namespace). |
| `assembly` | string |  |  | Assembly id, name, file name or path (see list_assemblies). Optional: omit to use all loaded assemblies. |
| `kind` | string |  |  | Restrict symbol resolution to: type, method, field, property, event. Values: type, method, field, property, event. |
| `dryRun` | boolean |  | `false` | Preview the change without applying it. |

### rename_namespace

**Rename namespace** (destructive)

Move every type in a namespace (optionally including sub-namespaces) to a new namespace, in memory.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `assembly` | string | yes |  | Assembly id, name, file name or path (see list_assemblies). |
| `oldNamespace` | string | yes |  | Existing namespace ('' for the global namespace). |
| `newNamespace` | string | yes |  | New namespace. |
| `includeSubNamespaces` | boolean |  | `false` | Also rewrite namespaces that start with oldNamespace + '.'. |
| `dryRun` | boolean |  | `false` | Preview the change without applying it. |

### stub_method

**Stub method (return constant)** (destructive)

Replace a method's body with 'return <value>;' (or 'return;' for void) in memory — force a check to return true, disable a call. value: true/false, an integer (decimal or 0x hex), a float, a "quoted string", null, or default (omit).

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `method` | string | yes |  | Method. Type or member. Forms: 'Ns.Type', 'Ns.Outer+Inner', short 'Type', 'Ns.Type::Method', 'Ns.Type.Method', 'Ns.Type::Method(int, string)' for one overload, 'Ns.Type::.ctor', or a metadata token like '0x06000123'. |
| `value` | string |  |  | Return value; omit for void methods or default(T). |
| `assembly` | string |  |  | Assembly id, name, file name or path (see list_assemblies). Optional: omit to use all loaded assemblies. |
| `dryRun` | boolean |  | `false` | Preview the change without applying it. |

### patch_method_csharp

**Replace method body with C#** (destructive)

Replace a method's body with C# statements, compiled against the assembly and its references (private/internal members are accessible, like in dnSpy's Edit Method). Pass only the body (statements), e.g. 'if (amount <= 0) return; _balance -= amount;'. Works for methods, constructors and property/indexer/event accessors. Lambdas, LINQ, local functions, async/await and yield work: the compiler-generated helpers are copied into the assembly. Compile errors are reported with line numbers relative to your code. Returns the decompiled result. Persisted only by save_assembly.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `method` | string | yes |  | Method. Type or member. Forms: 'Ns.Type', 'Ns.Outer+Inner', short 'Type', 'Ns.Type::Method', 'Ns.Type.Method', 'Ns.Type::Method(int, string)' for one overload, 'Ns.Type::.ctor', or a metadata token like '0x06000123'. |
| `code` | string | yes |  | C# statements forming the new body. |
| `assembly` | string |  |  | Assembly id, name, file name or path (see list_assemblies). Optional: omit to use all loaded assemblies. |
| `dryRun` | boolean |  | `false` | Preview the change without applying it. Compiles and shows the IL that would be written. |

### patch_method_il

**Rewrite method body in IL** (destructive)

Rewrite a method body from IL text, in memory. Easiest: get_il the method, edit the instruction lines, pass them back (header lines are ignored; the /* token */ comments resolve operands exactly). Line syntax: '[label:] opcode [operand]'. Operands: numbers, "strings", labels, switch (L1, L2), arg/local index or name, members as 'Ns.Type::Method(int, string)' (framework members included) or tokens. '.local <type>' adds a local. mode=replace swaps the whole body (no try/catch); mode=prepend inserts before the original code and can branch to its IL_xxxx labels. Stack-validated before applying.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `method` | string | yes |  | Method. Type or member. Forms: 'Ns.Type', 'Ns.Outer+Inner', short 'Type', 'Ns.Type::Method', 'Ns.Type.Method', 'Ns.Type::Method(int, string)' for one overload, 'Ns.Type::.ctor', or a metadata token like '0x06000123'. |
| `il` | string | yes |  | IL instructions, one per line. |
| `mode` | string |  | `replace` | replace (default) or prepend. Values: replace, prepend. |
| `assembly` | string |  |  | Assembly id, name, file name or path (see list_assemblies). Optional: omit to use all loaded assemblies. |
| `dryRun` | boolean |  | `false` | Preview the change without applying it. |

### add_members_csharp

**Add members to a type (C#)** (edit)

Add new members written in C# to an existing class or struct: methods (incl. overloads), fields, properties, events, constructors, nested types. Code is compiled against the assembly (private/internal members accessible; lambdas/async/LINQ fine). Example: 'public int Twice(int x) { return x * 2; }  private static int _counter;'. Field/property initializers are not supported (initialize from a method). Persisted only by save_assembly.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `type` | string | yes |  | Type to extend. Type or member. Forms: 'Ns.Type', 'Ns.Outer+Inner', short 'Type', 'Ns.Type::Method', 'Ns.Type.Method', 'Ns.Type::Method(int, string)' for one overload, 'Ns.Type::.ctor', or a metadata token like '0x06000123'. |
| `code` | string | yes |  | C# member declarations. |
| `assembly` | string |  |  | Assembly id, name, file name or path (see list_assemblies). Optional: omit to use all loaded assemblies. |
| `dryRun` | boolean |  | `false` | Preview the change without applying it. Compiles and lists what would be added. |

### add_types_csharp

**Add new types (C#)** (edit)

Add new classes, structs, interfaces, enums or delegates written in C# (with their namespace) to an assembly. They can use the assembly's own types, including private/internal ones. Combine with patch_method_csharp to call into the new code from existing methods. Persisted only by save_assembly.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `assembly` | string | yes |  | Assembly id, name, file name or path (see list_assemblies). |
| `code` | string | yes |  | C# source declaring the new types (e.g. 'namespace Extensions { public static class Helpers { ... } }'). |
| `dryRun` | boolean |  | `false` | Preview the change without applying it. Compiles and lists what would be added. |

### simplify_methods

**Simplify method bodies** (destructive, long-running)

Compiler-style cleanup of method bodies in memory, e.g. for transformed code. Passes (all by default): fold: calls that compute a string from constant inputs (string decoders and their char, array, StringBuilder, Encoding and Base64 helpers) run in a safe IL interpreter and become the string literal; calls outside the safe subset (I/O, reflection, exceptions, instance objects, native code, mutable statics) or over budget are kept and reported. cfg: branches and switches on constant conditions fold (constant propagation through locals, readonly statics and calls with constant arguments); dead stores, branch chains, empty try/finally, dead handlers and unreachable code are removed; flattened control flow (a loop over a state switch) becomes sequential code, and a dispatcher whose state differs between runs is kept (flattened-shape). inline: call sites of forwarders and of static delegate fields (call proxies) call the real target when it is always the same (else delegate-target). Scope: a method, a type (nested types included), or omit symbol for the whole assembly. Each rewritten body is stack-verified or left unchanged; every call left alone and every method left unchanged is reported with a reason code (docs/simplify.md lists the evaluated instructions, the limits and the codes; the guide's edits topic summarizes the passes). Limits: per-evaluation and per-method budgets, 16 MB of simulated memory, 5 s per method. Persisted only by save_assembly. To preview the C# without editing, use decompile_member / decompile_type with simplified=true.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `symbol` | string |  |  | Method or type. Type or member. Forms: 'Ns.Type', 'Ns.Outer+Inner', short 'Type', 'Ns.Type::Method', 'Ns.Type.Method', 'Ns.Type::Method(int, string)' for one overload, 'Ns.Type::.ctor', or a metadata token like '0x06000123'. Omit to simplify every method of the assembly. |
| `assembly` | string |  |  | Assembly id, name, file name or path (see list_assemblies). Optional: omit to use all loaded assemblies. Required when symbol is omitted. |
| `passes` | string |  |  | Comma-separated passes: fold, cfg, inline (default: all). |
| `maxDepth` | integer |  |  | Max call depth when evaluating, the evaluated call included (default 8). |
| `budget` | integer |  |  | Max IL instructions executed per evaluated call, nested calls included (default 100000). |
| `dryRun` | boolean |  | `false` | Preview the change without applying it. Reports folded constants, removed blocks and inlined forwarders. |
| `deterministicEnvironment` | boolean |  | `false` | Opt-in (default false). Pin what evaluated code reads of the machine it runs on - the module's own path, the base and current directories, special folders, a fixed set of environment variables, the machine and user names - to fixed stand-ins, and read the module's own file as the loaded image, so initialization code that depends on them evaluates the same on every run. Results then hold for that stand-in environment; docs/simplify.md lists the values. Without it such reads are reported (external-io). |

### list_edits

**List unsaved edits** (read-only, idempotent)

The unsaved in-memory edits of an assembly, numbered in the order they were applied (numbers are used by undo_edit and diff_edits).

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `assembly` | string | yes |  | Assembly id, name, file name or path (see list_assemblies). |

### diff_edits

**Diff edits (before/after C#)** (read-only, idempotent)

Unified diff of the decompiled C# before and after the edits: every member touched by every edit, or one edit by number. Review this before save_assembly.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `assembly` | string | yes |  | Assembly id, name, file name or path (see list_assemblies). |
| `number` | integer |  |  | Only this edit (1-based, from list_edits). Omit for all edits. |
| `offset` | integer |  | `0` | Character offset for paging long output (use the value from the truncation footer). |
| `maxChars` | integer |  |  | Max characters in this page (default from server config, ~60000). |

### undo_edit

**Undo an edit** (destructive)

Undo one edit — the last one by default, or any earlier one by number (from list_edits). The assembly is rebuilt from its original image and the remaining edits are re-applied; if one of them depended on the undone edit, nothing changes and the conflict is reported.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `assembly` | string | yes |  | Assembly id, name, file name or path (see list_assemblies). |
| `number` | integer |  |  | Edit number (1-based, from list_edits). Omit to undo the last edit. |

### revert_edits

**Discard all edits** (destructive, idempotent)

Discard every unsaved edit of an assembly (back to the image it was loaded from). Use export_edits first to keep them as a script.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `assembly` | string | yes |  | Assembly id, name, file name or path (see list_assemblies). |

### export_edits

**Export edits as a script** (destructive, idempotent)

Save the edits of an assembly as a JSON edit script, bound to the build they were made on (file SHA-256, MVID, assembly identity). apply_edits replays it on that build, or deliberately on another one (targetBuild=other, e.g. the next build after an update), where symbols are re-resolved by name.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `assembly` | string | yes |  | Assembly id, name, file name or path (see list_assemblies). |
| `path` | string | yes |  | Output .json path. |
| `overwrite` | boolean |  | `false` | Replace path if it exists. |

### apply_edits

**Apply an edit script** (destructive)

Replay a JSON edit script (from export_edits) onto an assembly. The script is bound to the build it was made from (SHA-256, MVID, identity): by default (targetBuild=same) another build is refused with a conflict error naming both; targetBuild=other carries the edits across deliberately: symbols are re-resolved by name (renamed targets followed when the source build is loaded too) and the report lists what was remapped. Scripts without the binding are applied with a warning. On the same build, recorded tokens are used; each edit reports ok/FAILED. dryRun applies every edit for real (C# compiled, IL stack-checked) and then rolls back, so it reports exactly what would fail, with the full compiler errors. With stopOnError (default) a failure rolls the assembly back to its state before the script.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `path` | string | yes |  | Path to the .json edit script. |
| `assembly` | string |  |  | Target assembly. Omit to use the assembly named in the script. |
| `dryRun` | boolean |  | `false` | Apply and compile every edit, report, then roll back: nothing changes. |
| `stopOnError` | boolean |  | `true` | Roll back everything on the first failure (default true). |
| `targetBuild` | string |  | `same` | same (default): only the build the script was made from; other: carry the edits to a different build, re-resolving symbols by name. Values: same, other. |

### save_assembly

**Save patched assembly** (destructive, idempotent)

Write an assembly with its in-memory edits to disk. Default output: '<name>.patched.dll' next to the original. Replacing an existing file requires overwrite=true; when that file is the original (also through a link), it is first copied to '<file>.bak', and an original changed on disk since load is refused. Writes atomically. Without edits the original bytes are written; with edits, every method body and signature no edit touched keeps its original bytes, and the written image is compared with the original. The result lists, one line per member with a reason code: 'Changed by the writer' (bytes differ from the original without an edit asking for it, e.g. a body whose header lies outside the image) and 'Kept byte-for-byte although invalid in the original' (invalid IL or signatures, saved unchanged). strict=true refuses the save when the first list is not empty, writing nothing. Reason codes: docs/saving.md.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `assembly` | string | yes |  | Assembly id, name, file name or path (see list_assemblies). |
| `outputPath` | string |  |  | Output file path. Omit for '<original>.patched.dll'. |
| `overwrite` | boolean |  | `false` | Allow replacing an existing file. |
| `strict` | boolean |  | `false` | Refuse the save (writing nothing) when any member would be written differently from the original without an edit asking for it. Default: save and list them. |

## il2cpp

Il2Cpp metadata, addresses, symbols and bindings.

### get_il2cpp_info

**Il2Cpp addresses and offsets** (read-only, idempotent)

For Il2Cpp dummy DLLs (Il2CppDumper/Cpp2IL output, or those the built-in reader makes when load_assembly is given the game folder or its global-metadata.dat): native addresses (RVA, VA, file offset, vtable slot) of a method or of every method in a type, plus field offsets and metadata tokens. Use them to jump to the function in IDA/Ghidra. With the dump's script.json next to the DummyDll folder (always, for the built-in reader), also: a method's function bounds, the methods sharing its code, its MethodInfo slot and its generic instantiations (same-named overloads told apart by the C signature, or reported as ambiguous); a type's metadata slots (Ns.Type_TypeInfo class pointer, _var); and the native code of names that only script.json has, such as generic instantiations ('List`1<int>::Add', 'System.Collections.Generic.List<int>$$Add'), metadata names ('Ns.Type_TypeInfo', 'Method$Ns.Type.M()'). For a method, also the string literals its native code loads, when stringliteral.json and GameAssembly.dll are there too (search_strings finds a literal's slot).

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `symbol` | string | yes |  | Type or method. Type or member. Forms: 'Ns.Type', 'Ns.Outer+Inner', short 'Type', 'Ns.Type::Method', 'Ns.Type.Method', 'Ns.Type::Method(int, string)' for one overload, 'Ns.Type::.ctor', or a metadata token like '0x06000123'. Or a script.json name of a generic instantiation or metadata slot. |
| `assembly` | string |  |  | Assembly id, name, file name or path (see list_assemblies). Optional: omit to use all loaded assemblies. |
| `slot` | string |  |  | With a type: the vtable slot number to resolve to the implementing method (searching base types), or 'all' for the whole vtable. |
| `offset` | integer |  | `0` | Index of the first entry of long lists (instantiations, metadata slots, vtable, script.json matches). |
| `limit` | integer |  | `20` | Max entries of each long list (default 20). |

### find_method_by_address

**Native address to method** (read-only, idempotent)

Map a native address from IDA/Ghidra/a crash log back to what is there: the method(s) whose function starts at or contains it, or the string literal, type metadata (Ns.Type_TypeInfo) or MethodInfo slot at it. With the dump's script.json next to the DummyDll folder, functions end where the next one starts and generic instantiations (which have no dummy-DLL method) are named, with the dummy method each instantiates; without it, only dummy-DLL methods are known and a containing method is a guess. Code shared by many methods (shared generics, identical code folding) is listed with a total and paged.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `address` | string | yes |  | Address in hex as IDA/Ghidra show it: '0x1A2B3C', '1A2B3C', '1A2B3Ch' or '00000001`8001A2B3'. Prefix 'd:' for decimal. |
| `kind` | string |  | `auto` | rva, va, offset (file offset), or auto: a VA when at or above the image base, else an RVA, else a file offset if the RVA finds nothing. Values: auto, rva, va, offset. |
| `assembly` | string |  |  | Assembly id, name, file name or path (see list_assemblies). Optional: omit to use all loaded assemblies. |
| `offset` | integer |  | `0` | Index of the first method to list when many share the code. |
| `limit` | integer |  | `20` | Max methods listed (default 20). |

### export_il2cpp_symbols

**Export IDA/Ghidra scripts** (destructive, idempotent, long-running)

Export Il2Cpp dummy-DLL metadata for native analysis: an IDA Python script and a Ghidra script that create every function, name it Namespace.Type$$Method and comment it with the managed signature, a C header with struct layouts at the dumped field offsets (the IDA script imports it), and an Il2CppDumper-style script.json. Addresses are RVAs added to the database's image base, so the scripts work on any load address.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `outputDirectory` | string | yes |  | Output directory. |
| `formats` | string |  | `all` | Formats, comma-separated: ida, ghidra, header, json, or all (default). |
| `baseName` | string |  | `il2cpp` | Base name for the generated files (default il2cpp). |
| `assembly` | string |  |  | Assembly id, name, file name or path (see list_assemblies). Optional: omit to use all loaded assemblies. |
| `overwrite` | boolean |  | `false` | Replace files of the same names if they exist. |

### generate_cpp_binding

**Generate C++ binding** (read-only, idempotent)

Generate C++ binding code for a managed type of a Mono or Il2Cpp application: a struct that resolves the class, field offsets, static fields and methods once, with typed field accessors, property getters and method invoke wrappers. style=mono: a self-contained header on the standard Mono embedding API (mono_class_from_name, mono_field_get_offset, mono_runtime_invoke, ...), loaded from the runtime's exports; works with any injector or host. style=il2cpp: a self-contained header on the Il2Cpp runtime's exports (il2cpp_class_from_name, il2cpp_field_get_offset, il2cpp_runtime_invoke, ...) from GameAssembly.dll, plus each method's native code pointer (to hook) and a typed direct call. style=hostapi: for projects whose host passes a function table (a struct with FindClass, GetMethod, FieldOffset, StaticFieldOffset, GetStaticFieldData and Invoke). Without style: projectDir has such a table -> hostapi with #include paths relative to headerPath; projectDir calls Il2Cpp or Mono exports itself (il2cpp_class_from_name, typedef il2cpp_*_t, using fn_* = ..., mono_class_from_name) -> il2cpp or mono; an Il2Cpp dummy assembly -> il2cpp; else the server's --binding-style, else mono. The first line of the output says which style was chosen and why. A generic definition (List`1) binds as a C++ template over its type parameters, resolved with Resolve(api, instanceClass) on an instantiation's class; style=il2cpp adds a layout template of its instances. The assembly, namespace and class strings come from the real metadata, so they are exactly what the runtime's class lookup expects.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `type` | string | yes |  | Type to bind. Type or member. Forms: 'Ns.Type', 'Ns.Outer+Inner', short 'Type', 'Ns.Type::Method', 'Ns.Type.Method', 'Ns.Type::Method(int, string)' for one overload, 'Ns.Type::.ctor', or a metadata token like '0x06000123'. |
| `assembly` | string |  |  | Assembly id, name, file name or path (see list_assemblies). Optional: omit to use all loaded assemblies. |
| `members` | string |  |  | Only these members (comma-separated field/property/method names). Default: all non-compiler-generated members. |
| `includeInherited` | boolean |  | `false` | Also bind every property getter (static and instance) inherited from base classes. Base-class members named in members are bound without it. |
| `style` | string |  |  | Output style: mono, il2cpp or hostapi. Omit to detect it (see the description). Values: mono, il2cpp, hostapi. |
| `projectDir` | string |  |  | The C/C++ project the header is for: scanned for a host function table and the helpers the hostapi code calls. |
| `headerPath` | string |  |  | Where the header will be saved (absolute, or relative to projectDir); #include paths are computed from its folder. Default: projectDir. |
| `offset` | integer |  | `0` | Character offset for paging long output (use the value from the truncation footer). |
| `maxChars` | integer |  |  | Max characters in this page (default from server config, ~60000). |

### apply_il2cpp_names

**Name a native Il2Cpp binary from its metadata** (destructive, idempotent, long-running)

Names the functions and data of a native Il2Cpp game binary (GameAssembly, libil2cpp.so) from the loaded Il2CppDumper / Cpp2IL dummy assemblies ([Address] RVAs) and the dump's script.json (every function start, generic instantiations, Ns_Type_TypeInfo metadata and MethodInfo slots) and stringliteral.json (StringLiteral_<n> slots commented with the text). Functions are named Ns_Type__Method (the Il2CppDumper name Ns.Type$$Method as a C identifier, as IDA accepts it: '$$' becomes '__', '.', '<', '>', ',' and spaces '_'; a name used twice gets _<RVA>), commented with the C# form Ns.Type::Method(args) and the other methods sharing the code. The names show in list_functions, disassemble, find_xrefs, native_call_tree, search_native_strings, resolve_address and as addresses, and decompile_native pushes them into the IDA database. They rank below user names (rename_native) and PDB names; applying again replaces them, clear=true removes them. Saved with the image's annotations (per file hash) and reapplied automatically when the same file is loaded again (list_native_edits shows the restored layers); clear=true also deletes the saved copy. Reports counts of functions named, shared code, strings, slots, collisions and misses. Explicit, not automatic: run it once both the binary and the dummy assemblies are loaded.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `image` | string | yes |  | Native image id or file name (see list_assemblies), or the path of a native PE file, which is loaded. |
| `assembly` | string |  |  | Dummy assemblies to use (id, name, file name or path); omit to use every loaded one with Il2Cpp metadata. |
| `clear` | boolean |  | `false` | Remove the il2cpp names (and their saved copy) instead of applying them. |

## native

Native PE analysis, symbols and decompilation.

### get_pe_info

**Native image overview** (read-only, idempotent)

Overview of a native image. PE: machine, kind, subsystem, image base, entry point, timestamps, linker, sections (with flags and entropy), security mitigations (ASLR, DEP, CFG, SafeSEH, GS cookie, CET...), import/export counts, TLS callbacks, debug info (PDB path and GUID), load config, version resource, manifest, rich header (toolchain), checksum, overlay, Authenticode signature, and anything malformed. ELF: program headers, soname, NDK note, build id, relocations, hardening. Mach-O: slice, segments, libraries, fixups, code signature, entitlements, FairPlay encryption.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `image` | string | yes |  | Native image id or file name (see list_assemblies), or the path of a native PE file, which is loaded. |
| `offset` | integer |  | `0` | Character offset for paging long output (use the value from the truncation footer). |
| `maxChars` | integer |  |  | Max characters in this page (default from server config, ~60000). |

Structured output: `image`, `path`, `machine`, `kind`, `format`, `subsystem`, `fileSize`, `sha256`, `imageBase`, `entryPoint`, `timestamp`, `dotNet`, `mitigationsOn`, `mitigationsOff`, `sections`, `importModules`, `importFunctions`, `delayImportModules`, `exports`, `tlsCallbacks`, `pdbPath`, `pdbGuid`, `pdbAge`, `signer`, `checksumMatches`, `overlaySize`, `issues`.

### list_imports

**List native imports** (read-only, idempotent, long-running)

Functions a native image imports, per DLL (delay-loaded marked), with the IAT slot address code calls through; ELF / Mach-O: per library (* for unversioned ELF symbols), lazy binding marked. API set names (api-ms-win-*) are shown with the DLL they resolve to on this system. With bind=true each import is bound like the loader does (DLL search order, API sets, forwarders, jump thunks in loaded providers) to its export: 'at VA [image]' when the provider is loaded (disassemble / native_call_tree work on it), its path when not (load_assembly with that path, or with this image and loadProviders=true), or the reason it does not resolve (dll_not_found, api_set_unmapped, missing_export, missing_ordinal, forwarder_broken). includeDynamic adds late-bound imports (GetProcAddress with a constant name or ordinal, the module traced from LoadLibrary / GetModuleHandle), marked [dynamic].

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `image` | string | yes |  | Native image id or file name (see list_assemblies), or the path of a native PE file, which is loaded. |
| `module` | string |  |  | Only this DLL (name with or without .dll). |
| `filter` | string |  |  | Only functions whose name contains this text (case-insensitive). |
| `bind` | boolean |  | `false` | Bind each import to the export it reaches and summarize: bound / provider not loaded / unresolved by reason. |
| `offset` | integer |  | `0` | Index of the first row. |
| `limit` | integer |  | `500` | Max rows (default 500). |
| `includeDynamic` | boolean |  | `false` | Also list late-bound imports (waits for the code index). |

Structured output: `image`, `items`, `offset`, `total`, `truncated`, `bindings`.

### list_exports

**List native exports** (read-only, idempotent)

Functions and data a native image exports: ordinal, address (VA), name (with the demangled C++ form of MSVC and Itanium names), and forwarders (Mach-O re-exports).

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `image` | string | yes |  | Native image id or file name (see list_assemblies), or the path of a native PE file, which is loaded. |
| `filter` | string |  |  | Only exports whose name contains this text (case-insensitive; matches the demangled form too). |
| `offset` | integer |  | `0` | Index of the first row. |
| `limit` | integer |  | `500` | Max rows (default 500). |

Structured output: `image`, `items`, `offset`, `total`, `truncated`.

### resolve_address

**Resolve native address** (read-only, idempotent)

What an address in a native image is: RVA, VA and file offset, the section and its permissions, the nearest export or import at or before it, and, once the code index is built, its name and the name's source (user, pdb, nativeaot, il2cpp); after apply_il2cpp_names the managed method or metadata slot; in a NativeAOT image the MethodTable, frozen object or method body there, or its module section. For an IAT slot, the export it is bound to (in a loaded image: its address and image); for an export, the loaded images importing it. With the code index built: the containing function and offset; whether the address is an instruction start, inside an instruction (with the instruction covering it) or in a data item (string, IAT slot, switch table, relocated pointer; with its extent); the comment; and the references to it by kind. In a PDB global, the field there (get_native_type has the layout).

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `image` | string | yes |  | Native image id or file name (see list_assemblies), or the path of a native PE file, which is loaded. |
| `address` | string | yes |  | Address: hex VA (0x180001000) or RVA (0x1000), rva:/va:/off: prefixed, an export name, module!import, or a function name (one on several addresses is an ambiguous error listing them). |

Structured output: `image`, `rva`, `va`, `fileOffset`, `section`, `access`, `name`, `nameSource`, `import`, `boundTo`, `export`, `lines`, `function`, `status`, `containingInstruction`, `dataItem`, `comment`, `referencesTo`.

### search_bytes

**Search native bytes** (read-only, idempotent)

Find a byte pattern in a native image's mapped sections: hex bytes with ?? wildcards ('48 8B 05 ?? ?? ?? ?? C3'), or text with text="..." (searched as ASCII and UTF-16). Reports each hit's VA, section and file offset.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `image` | string | yes |  | Native image id or file name (see list_assemblies), or the path of a native PE file, which is loaded. |
| `pattern` | string | yes |  | Hex bytes with ?? wildcards, or the text to find when text=true. |
| `text` | boolean |  | `false` | Treat pattern as text (ASCII and UTF-16LE). |
| `section` | string |  |  | Only this section (e.g. .text, .rdata). |
| `limit` | integer |  | `200` | Max hits (default 200). |
| `offset` | integer |  | `0` | Index of the first hit. |

### read_bytes

**Hex dump native bytes** (read-only, idempotent)

Hex dump (with ASCII) of a native image's mapped bytes at an address, as the loader maps them.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `image` | string | yes |  | Native image id or file name (see list_assemblies), or the path of a native PE file, which is loaded. |
| `address` | string | yes |  | Address: hex VA (0x180001000) or RVA (0x1000), rva:/va:/off: prefixed, an export name, module!import, or a function name (one on several addresses is an ambiguous error listing them). |
| `length` | integer |  | `256` | Bytes to dump (default 256, max 65536). |
| `offset` | integer |  | `0` | Character offset for paging long output (use the value from the truncation footer). |
| `maxChars` | integer |  |  | Max characters in this page (default from server config, ~60000). |

### list_functions

**List native functions** (read-only, idempotent, open-world, long-running)

Functions of a native image (x86 / x64 / ARM64): address, size, name (export name, module!import for thunks, or sub_<rva>), flags (thunk, noreturn, unresolved jumps, invalid code, funclet, funclet of its parent, exception chunks: catch blocks, unwind funclets, filters and handlers attached to their function), how it was found and how many call sites reach it. get_exception_info shows the details. Names from rename_native, PDB symbols and apply_il2cpp_names take precedence in that order. The first call on an image waits for its code index (built in the background after loading; seconds for a typical DLL, one to two minutes for a 300 MB browser DLL; progress is reported).

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `image` | string | yes |  | Native image id or file name (see list_assemblies), or the path of a native PE file, which is loaded. |
| `filter` | string |  |  | Only functions whose name contains this text (case-insensitive). |
| `sort` | string |  |  | Order: address (default), size (largest first) or callers (most called first). Values: address, size, callers. |
| `offset` | integer |  | `0` | Index of the first row. |
| `limit` | integer |  | `300` | Max rows (default 300). |
| `engine` | string |  |  | Where functions, references and control flow come from: auto (default: an engine's analysis when one of this image is complete in this session, IDA's before Ghidra's, else the built-in index; never starts an engine), ours (the built-in index only), ida or ghidra (that engine's analysis, started or waited for when needed). The server default is set with --engine or NDM_ENGINE. Values: auto, ours, ida, ghidra. |

Structured output: `image`, `functions`, `items`, `offset`, `total`, `truncated`, `coverage`, `engine`, `engineNote`.

### disassemble

**Disassemble native code** (read-only, idempotent, open-world, long-running)

MASM-syntax disassembly of the native function containing an address (with block labels), or of maxInstructions from the address when it is in no function or function=false. Calls and data references are named (module!import, exports, sub_<rva>, loc_<rva>) and string references shown as comments; calls are commented with their recovered arguments (CreateFileW(L"a.ini", GENERIC_READ, ...), see get_call_arguments). Warns when the address is inside an instruction, in data or in bss; a listing from an address renders strings, pointers, IAT slots and switch tables as data and resynchronizes when it runs into a known instruction; a function listing names the gaps between its blocks (switch table, padding, unreached bytes). Warnings are repeated in a footer. In a NativeAOT image, string literal loads show the text and virtual calls the vtable slot and, on this, the method in it. The first call on an image waits for its code index (built in the background after loading; seconds for a typical DLL, one to two minutes for a 300 MB browser DLL; progress is reported).

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `image` | string | yes |  | Native image id or file name (see list_assemblies), or the path of a native PE file, which is loaded. |
| `address` | string | yes |  | Address: hex VA (0x180001000) or RVA (0x1000), rva:/va:/off: prefixed, an export name, module!import, or a function name (one on several addresses is an ambiguous error listing them). |
| `function` | boolean |  | `true` | Disassemble the whole containing function (default true); false: maxInstructions from the address. |
| `maxInstructions` | integer |  | `2000` | Max instructions (default 2000). |
| `offset` | integer |  | `0` | Character offset for paging long output (use the value from the truncation footer). |
| `maxChars` | integer |  |  | Max characters in this page (default from server config, ~60000). |
| `engine` | string |  |  | Where functions, references and control flow come from: auto (default: an engine's analysis when one of this image is complete in this session, IDA's before Ghidra's, else the built-in index; never starts an engine), ours (the built-in index only), ida or ghidra (that engine's analysis, started or waited for when needed). The server default is set with --engine or NDM_ENGINE. With an engine, the function's bounds and instructions are the engine's. Values: auto, ours, ida, ghidra. |

### inspect_instruction

**Inspect native instructions** (read-only, idempotent, open-world, long-running)

What is at an address of a native image (x86 / x64 / ARM64), instruction by instruction: decoded (an instruction start in a known function), mid_instruction (with the covering instruction), data (string, IAT / GOT slot, switch table, relocated pointer, PE directory, ARM64 literal or data in code; with its start and end), not_in_function, unmapped (bss), outside_image or invalid. For an instruction: bytes, prefixes, encoding, CPUID / ARM64 features; each operand's kind, size and access, registers with their full register, memory as base, index, scale or extend, displacement and pre / post-index writeback, with the effective address named; registers and flags read and written, memory accesses, stack pointer change; flow with target and fallthrough; the ARM64 ADRP pair and the address it forms; references from and to; a call's arguments; a switch's table. count > 1 walks forward, skipping data items. With IDA (ARM32 and other instruction sets): IDA's items, operands, access, flow and references; fields IDA does not supply are null. The first call on an image waits for its code index (built in the background after loading; seconds for a typical DLL, one to two minutes for a 300 MB browser DLL; progress is reported).

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `image` | string | yes |  | Native image id or file name (see list_assemblies), or the path of a native PE file, which is loaded. |
| `address` | string | yes |  | Address: hex VA (0x180001000) or RVA (0x1000), rva:/va:/off: prefixed, an export name, module!import, or a function name (one on several addresses is an ambiguous error listing them). |
| `count` | integer |  | `1` | Instructions to inspect from the address (1-64, default 1). |
| `offset` | integer |  | `0` | Character offset for paging long output (use the value from the truncation footer). |
| `maxChars` | integer |  |  | Max characters in this page (default from server config, ~60000). |
| `engine` | string |  |  | Engine: auto (default: the built-in decoder for x86 / x64 / ARM64, IDA for other instruction sets when it is installed), ours or ida. Values: auto, ours, ida. |

Structured output: `image`, `engine`, `engineNote`, `items`, `notes`.

### get_cfg

**Native control-flow graph** (read-only, idempotent, open-world, long-running)

Basic blocks of the native function containing an address: each block's range, instruction count, how it ends (return, jump, switch, tail call, noreturn call...) and its successors; switch tables with values per target, default and bias; unresolved indirect jumps with the reason. The first call on an image waits for its code index (built in the background after loading; seconds for a typical DLL, one to two minutes for a 300 MB browser DLL; progress is reported).

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `image` | string | yes |  | Native image id or file name (see list_assemblies), or the path of a native PE file, which is loaded. |
| `address` | string | yes |  | Address: hex VA (0x180001000) or RVA (0x1000), rva:/va:/off: prefixed, an export name, module!import, or a function name (one on several addresses is an ambiguous error listing them). |
| `offset` | integer |  | `0` | Character offset for paging long output (use the value from the truncation footer). |
| `maxChars` | integer |  |  | Max characters in this page (default from server config, ~60000). |
| `engine` | string |  |  | Where functions, references and control flow come from: auto (default: an engine's analysis when one of this image is complete in this session, IDA's before Ghidra's, else the built-in index; never starts an engine), ours (the built-in index only), ida or ghidra (that engine's analysis, started or waited for when needed). The server default is set with --engine or NDM_ENGINE. With an engine, the blocks and edges are the engine's. Values: auto, ours, ida, ghidra. |

Structured output: `image`, `function`, `address`, `engine`, `blocks`, `switches`, `unresolvedJumps`, `tailCalls`, `truncated`.

### find_xrefs

**Native cross-references** (read-only, idempotent, open-world, long-running)

Everything in a native image that references an address: calls (direct and through import slots and thunks), jumps, data reads and writes, address-taken uses, switch tables and relocated data pointers, each with the function it is in; for a virtual method, the virtual call sites that reach it (VirtualExact: the only implementation; VirtualPossible: one of several; resolved through MSVC RTTI). For an import (module!name) lists the call sites of that API (x86 calls through a register loaded from the slot included) and what it is bound to; for an export, also the call sites in other loaded images that import it ([image] prefix). Call rows show the recovered arguments. A late-bound import (module!name resolved by GetProcAddress) lists where it is resolved and the calls through its pointer. A struct member (Type::member, Type.member or Type+0x18, from the engine's types: PDB, RTTI classes, Il2Cpp, declare_native_types) lists its uses through IDA: operands typed as the member, and reads, writes and address-of in the pseudocode of the functions whose prototype names the type (methods with a typed this). The first call on an image waits for its code index (built in the background after loading; seconds for a typical DLL, one to two minutes for a 300 MB browser DLL; progress is reported).

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `image` | string | yes |  | Native image id or file name (see list_assemblies), or the path of a native PE file, which is loaded. |
| `address` | string | yes |  | Address: hex VA (0x180001000) or RVA (0x1000), rva:/va:/off: prefixed, an export name, module!import, or a function name (one on several addresses is an ambiguous error listing them). Or a struct member: Type::member, Type.member, Type+0xOFFSET. |
| `offset` | integer |  | `0` | Index of the first row. |
| `limit` | integer |  | `500` | Max rows (default 500). |
| `engine` | string |  |  | Where functions, references and control flow come from: auto (default: an engine's analysis when one of this image is complete in this session, IDA's before Ghidra's, else the built-in index; never starts an engine), ours (the built-in index only), ida or ghidra (that engine's analysis, started or waited for when needed). The server default is set with --engine or NDM_ENGINE. With an engine, the references are the engine's, plus the RTTI-resolved virtual call sites it has none for (marked ours). Values: auto, ours, ida, ghidra. |

Structured output: `image`, `target`, `items`, `offset`, `total`, `truncated`, `boundTo`, `engine`, `engineNote`.

### native_call_tree

**Native call tree** (read-only, idempotent, open-world, long-running)

Callers or callees of a native function, several levels deep (calls through thunks and import slots included). Across images: a call through module!import continues into the provider's function when that image is loaded (shown as module!import -> PROVIDER.dll!export at VA [image], forwarders and jump thunks followed; otherwise the provider's path, or why it does not resolve), and callers include call sites in other loaded images that import the function. Callees include late-bound imports called through a GetProcAddress pointer stored once ([dynamic]) and the implementations virtual calls reach, resolved through MSVC RTTI ([virtual]: the only one; [virtual?: one of n]: one of several; find_virtual_calls lists the sites). Repeated subtrees and recursion are marked instead of expanded. The first call on an image waits for its code index (built in the background after loading; seconds for a typical DLL, one to two minutes for a 300 MB browser DLL; progress is reported).

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `image` | string | yes |  | Native image id or file name (see list_assemblies), or the path of a native PE file, which is loaded. |
| `function` | string | yes |  | Address: hex VA (0x180001000) or RVA (0x1000), rva:/va:/off: prefixed, an export name, module!import, or a function name (one on several addresses is an ambiguous error listing them). |
| `direction` | string |  | `callees` | callers or callees (default callees). Values: callers, callees. |
| `depth` | integer |  | `3` | Levels (1-8, default 3). |
| `maxNodes` | integer |  | `500` | Max nodes (default 500). |
| `offset` | integer |  | `0` | Character offset for paging long output (use the value from the truncation footer). |
| `maxChars` | integer |  |  | Max characters in this page (default from server config, ~60000). |
| `calls` | string |  |  | Call edges to follow: all (default), direct (no virtual call edges) or virtual (only virtual_exact / virtual_possible edges). Values: all, direct, virtual. |
| `engine` | string |  |  | Where functions, references and control flow come from: auto (default: an engine's analysis when one of this image is complete in this session, IDA's before Ghidra's, else the built-in index; never starts an engine), ours (the built-in index only), ida or ghidra (that engine's analysis, started or waited for when needed). The server default is set with --engine or NDM_ENGINE. With an engine, edges are its call and jump references plus the RTTI-resolved virtual calls it has none for (marked ours); calls into other loaded images are followed with the built-in index only. Values: auto, ours, ida, ghidra. |

### find_virtual_calls

**Native virtual calls** (read-only, idempotent, open-world, long-running)

Virtual call sites of an MSVC-built native image (x86 / x64), resolved through RTTI: calls through a vftable slot, also through stack spills, this adjustments and the CFG dispatch. The receiver's class comes from a vftable stored into the object (constructors, or a constructor called on it), from this of a virtual method, or from decorated names (this of member functions, class pointers passed as parameters or returned); the slot's implementations in that class and its derived classes (RTTI hierarchy) give the targets: one is exact, several are possible (pure virtual stubs left out); the rest are unresolved, with the reason. The edges are part of the call graph (native_call_tree, find_xrefs, get_call_arguments, disassemble comments). crossCheck=true compares a sample with a decompiler engine (IDA when installed, else Ghidra; its decompiler with the RTTI class types pushed, and its code references) and reports the agreement rate; the report names the engine.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `image` | string | yes |  | Native image id or file name (see list_assemblies), or the path of a native PE file, which is loaded. |
| `function` | string |  |  | Only sites in the function containing this address or named so. Address: hex VA (0x180001000) or RVA (0x1000), rva:/va:/off: prefixed, an export name, module!import, or a function name (one on several addresses is an ambiguous error listing them). |
| `status` | string |  |  | Only sites with this status: exact, possible or unresolved. Values: exact, possible, unresolved. |
| `offset` | integer |  | `0` | Index of the first site. |
| `limit` | integer |  | `100` | Max sites (default 100, max 1000). |
| `crossCheck` | boolean |  | `false` | Compare a sample of the sites with the engine's view of them (runs IDA or Ghidra; minutes on a large image the first time). |
| `sampleFunctions` | integer |  | `100` | Cross-check: functions to sample (default 100; as many again with only unresolved sites, halved). |
| `seconds` | integer |  | `300` | Cross-check: time budget in seconds (default 300). |

Structured output: `image`, `sites`, `exact`, `possible`, `unresolved`, `edges`, `directEdges`, `rttiClasses`, `total`, `offset`, `truncated`, `items`, `crossCheck`, `notes`.

### search_native_strings

**Search native strings** (read-only, idempotent, long-running)

Strings (ASCII and UTF-16) a native image's code or data references, with the address, the number of references and the first referencing function; filter by substring or regex. After apply_il2cpp_names also the Il2Cpp string literals, by the slot code loads them from; in a NativeAOT image the string literals (frozen String objects), by the object code loads. The first call on an image waits for its code index (built in the background after loading; seconds for a typical DLL, one to two minutes for a 300 MB browser DLL; progress is reported).

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `image` | string | yes |  | Native image id or file name (see list_assemblies), or the path of a native PE file, which is loaded. |
| `query` | string |  |  | Text to find (case-insensitive substring), or a regex with regex=true; omit to list all. |
| `regex` | boolean |  | `false` | Treat query as a regular expression. |
| `offset` | integer |  | `0` | Index of the first row. |
| `limit` | integer |  | `300` | Max rows (default 300). |

Structured output: `image`, `items`, `offset`, `total`, `truncated`, `notEvaluated`.

### get_call_arguments

**Native call arguments** (read-only, idempotent, long-running)

Call sites of a native image (x86 / x64 / ARM64) with their argument values, recovered by backward constant propagation in the calling function under the platform conventions (x64 rcx, rdx, r8, r9 / xmm0-3, then [rsp+20h+8*i]; x86 pushed / stored stack slots; ARM64 x0-x7): immediates, string literals, named addresses, results of earlier calls, globals; merges of different values are unknown. Known Win32 / CRT APIs give parameter names and decoded constants (GENERIC_READ, PAGE_EXECUTE_READWRITE, HKEY_LOCAL_MACHINE, printf formats). Pass address (a call instruction, or any address in a function for all its calls) and/or callee (an API or function name: all calls to it).

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `image` | string | yes |  | Native image id or file name (see list_assemblies), or the path of a native PE file, which is loaded. |
| `address` | string |  |  | A call instruction, or an address in a function (all calls in it). Address: hex VA (0x180001000) or RVA (0x1000), rva:/va:/off: prefixed, an export name, module!import, or a function name (one on several addresses is an ambiguous error listing them). |
| `callee` | string |  |  | Only calls to this callee: API name (CreateFileW), module!name, or function name; without address, every call to it in the image. |
| `offset` | integer |  | `0` | Index of the first call site. |
| `limit` | integer |  | `100` | Max call sites (default 100, max 1000). |

Structured output: `image`, `scope`, `total`, `offset`, `calls`, `notes`.

### trace_native_values

**Native value trace** (read-only, idempotent, long-running)

Traces a value through native code (x86 / x64 / ARM64) across functions. Backward (where does it come from): constants, strings, function pointers, API results, through copies, stack slots, merges (every path's value) and loops; an incoming parameter is bound to every caller's argument, a call result to the callee's return values, a writable global to its writers and initial contents. Forward (where does it go): API arguments (named, constants decoded), callees' parameters, stores to globals and their readers, returns into callers' uses, compares, switch indexes, dereferences. The seed: address plus location (a register (rdx, ecx, xmm1; ARM64 x1, w2), a stack or frame slot ([rsp+28h], [ebp-8]; ARM64 [sp+10h], [x29-8]), op1 / op2 (an operand of the instruction) or result (the value the call at address returns)), or argument (of a call, or a function's parameter at its start), or a writable global alone. Budgets cap depth, functions, nodes, callers and writers; what they leave out is listed as frontier entries with the exact follow-up call. Pages (offset / limit) reuse the built graph.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `image` | string | yes |  | Native image id or file name (see list_assemblies), or the path of a native PE file, which is loaded. |
| `address` | string | yes |  | An instruction, a call, a function start (with argument) or a writable global. Address: hex VA (0x180001000) or RVA (0x1000), rva:/va:/off: prefixed, an export name, module!import, or a function name (one on several addresses is an ambiguous error listing them). |
| `location` | string |  |  | The value at address: a register (rdx, ecx, xmm1; ARM64 x1, w2), a stack or frame slot ([rsp+28h], [ebp-8]; ARM64 [sp+10h], [x29-8]), op1 / op2 (an operand of the instruction) or result (the value the call at address returns). |
| `argument` | string |  |  | An argument of the call at address, or a parameter of the function starting at address: its 1-based position or its API parameter name (dwDesiredAccess). |
| `direction` | string |  |  | backward (default: the values that reach it), forward (its uses) or both. Values: backward, forward, both. |
| `maxDepth` | integer |  | `3` | Function boundaries to cross (default 3, 0-8). |
| `maxFunctions` | integer |  | `32` | Functions to slice (default 32, 1-256). |
| `maxNodes` | integer |  | `500` | Nodes in the graph (default 500, 1-5000). |
| `maxCallers` | integer |  | `16` | Call sites bound per parameter or return (default 16, 1-256). |
| `maxWriters` | integer |  | `16` | Writers (backward) or readers (forward) followed per global (default 16, 1-256). |
| `followGlobals` | boolean |  | `true` | Follow writable globals into their writers / readers (default true). |
| `offset` | integer |  | `0` | Index of the first node. |
| `limit` | integer |  | `200` | Max nodes per page (default 200, max 1000). |

Structured output: `image`, `engine`, `seed`, `direction`, `values`, `nodes`, `edges`, `frontier`, `totalNodes`, `totalEdges`, `functions`, `offset`, `truncated`, `notes`.

### resolve_call_targets

**Native call targets** (read-only, idempotent, open-world, long-running)

Targets of call and tail-jump sites in native code (x86 / x64 / ARM64), each with its basis and confidence: direct branches, import and GOT slots, thunks, constant pointers (also through the CFG dispatch), GetProcAddress pointers, RTTI virtual calls, the writers and initial contents of a global function pointer, relocated pointer tables (complete when an index bound is found), and with deep=true the function pointers callers pass in. Several targets are listed, never collapsed; unresolved sites carry the reason and the trace_native_values call to follow. engine=ida or ghidra merges that engine's references and decompiler targets for the sites returned (a disagreement is ambiguous).

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `image` | string | yes |  | Native image id or file name (see list_assemblies), or the path of a native PE file, which is loaded. |
| `address` | string |  |  | A call instruction, or an address in a function (its sites). Address: hex VA (0x180001000) or RVA (0x1000), rva:/va:/off: prefixed, an export name, module!import, or a function name (one on several addresses is an ambiguous error listing them). |
| `scope` | string |  |  | site, function or image (every indirect site); default: site at a call, else function, image without address. Values: site, function, image. |
| `status` | string |  |  | all (default), resolved, possible, ambiguous, unresolved or indirect (all but direct branches). Values: all, resolved, possible, ambiguous, unresolved, indirect. |
| `deep` | boolean |  | `false` | Trace pointers that arrive as parameters back into the callers (slower). |
| `engine` | string |  |  | Where functions, references and control flow come from: auto (default: an engine's analysis when one of this image is complete in this session, IDA's before Ghidra's, else the built-in index; never starts an engine), ours (the built-in index only), ida or ghidra (that engine's analysis, started or waited for when needed). The server default is set with --engine or NDM_ENGINE. Values: auto, ours, ida, ghidra. |
| `offset` | integer |  | `0` | Index of the first site. |
| `limit` | integer |  | `100` | Max sites (default 100, max 1000). |

Structured output: `image`, `scope`, `engine`, `total`, `byStatus`, `byMechanism`, `topUnresolved`, `offset`, `truncated`, `items`, `notes`.

### get_exception_info

**Native exception handling** (read-only, idempotent, long-running)

MSVC exception handling of the native function containing an address: the handler (__C_specific_handler, __CxxFrameHandler3/4, __GSHandlerCheck variants; x86 _except_handler3/4 frames and __ehhandler$ stubs), try blocks with their catch clauses and caught types, the unwind map, SEH scopes (filters, __except and __finally blocks), the IP-to-state map, and the code it reaches: catch blocks, unwind funclets, filters and handlers attached to the function as chunks, x64 C++ funclets with their parent, chained fragments. Without an address: counts for the image and the metadata that failed its checks. The first call waits for the code index.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `image` | string | yes |  | Native image id or file name (see list_assemblies), or the path of a native PE file, which is loaded. |
| `address` | string |  |  | Address: hex VA (0x180001000) or RVA (0x1000), rva:/va:/off: prefixed, an export name, module!import, or a function name (one on several addresses is an ambiguous error listing them). Omit for a summary of the image. |
| `offset` | integer |  | `0` | Character offset for paging long output (use the value from the truncation footer). |
| `maxChars` | integer |  |  | Max characters in this page (default from server config, ~60000). |

### list_cpp_classes

**C++ classes from RTTI** (read-only, idempotent)

C++ classes of an MSVC-built native image recovered from RTTI: demangled class names, base classes (with offsets, virtual and multiple inheritance), and vftables with their slot targets. Every structure is cross-checked; rejected candidates are counted with the reason.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `image` | string | yes |  | Native image id or file name (see list_assemblies), or the path of a native PE file, which is loaded. |
| `filter` | string |  |  | Only classes whose name contains this text (case-insensitive). |
| `slots` | boolean |  | `false` | Include each vftable's slot addresses. |
| `offset` | integer |  | `0` | Character offset for paging long output (use the value from the truncation footer). |
| `maxChars` | integer |  |  | Max characters in this page (default from server config, ~60000). |

### get_native_type

**Native type layout** (read-only, idempotent, open-world, long-running)

A native type's layout from the image's sources: PDB type records (structs, classes, unions, enums, typedefs, pointers, arrays, function types; fields with offset, size and bit fields, bases, padding), MSVC RTTI (bases, vftables with named slot targets; merged with the PDB's class), Il2Cpp layouts (after apply_il2cpp_names) and the engine's types (IDA or Ghidra; source=engine opens it, auto reads it when already analyzed, for names the others lack). By name (exact, case-insensitive, then substring candidates; several definitions are an ambiguous error listing ids), id (drill-down) or typed address (in a PDB global: the field path, g_Game.players[3].pos.y; also vftables and Il2Cpp metadata slots). at=0x48 names the field at an offset (all union members; 0x48.0x10 reads through a pointer); depth inlines by-value members; enums sorted by value.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `image` | string | yes |  | Native image id or file name (see list_assemblies), or the path of a native PE file, which is loaded. |
| `name` | string |  |  | Type name (Packet, ns::Widget, Ns.Type for Il2Cpp). |
| `id` | string |  |  | Type id from a result (pdb:0x1A2B, rtti:0x140012000, il2cpp:Ns.Type, ida:Name). |
| `address` | string |  |  | A typed address: Address: hex VA (0x180001000) or RVA (0x1000), rva:/va:/off: prefixed, an export name, module!import, or a function name (one on several addresses is an ambiguous error listing them). |
| `at` | string |  |  | Hex offset of a field to name: 0x48; 0x48.0x10 reads through the pointer at 0x48. |
| `depth` | integer |  | `0` | Levels of by-value members to inline (0-4, default 0). |
| `source` | string |  |  | auto (default), pdb, rtti, il2cpp or engine. Values: auto, pdb, rtti, il2cpp, engine. |
| `format` | string |  |  | table (default) or c (C declaration). Values: table, c. |
| `offset` | integer |  | `0` | Index of the first row (field, enumerator, slot, candidate). |
| `limit` | integer |  | `200` | Max rows (default 200, max 5000). |
| `engine` | string |  |  | Engine for source=engine: auto (default), ida or ghidra. Values: auto, ida, ghidra. |

Structured output: `image`, `query`, `type`, `candidates`, `totalCandidates`, `owner`, `ownerAddress`, `paths`, `offset`, `truncated`, `notes`.

### decompile_native

**Decompile native function** (read-only, idempotent, open-world, long-running)

C pseudocode of the native function containing an address, through IDA (idalib; Hex-Rays) or Ghidra (its decompiler, through a Java worker). The first call on an image runs the engine's auto-analysis (seconds for a small DLL, minutes for a large game executable; progress is reported) and keeps the database per file hash, so later calls and later sessions are fast. The header names the engine. Lines are annotated with the address they come from. Names and comments in effect (rename_native / comment_native, apply_il2cpp_names, PDB names) are pushed into the database first, once per change, and saved with it. When the image has a PDB (found next to it or in the symbol cache, or loaded with load_pdb), its structs, enums, typedefs and prototypes are loaded into the database through the engine's PDB loader (the server's own PDB type reader when that loader is not available), once per PDB; the first line says which type source applies. The user's types (declare_native_types, set_native_type, set_native_local, set_native_stack_var) are applied last and win over recovered ones.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `image` | string | yes |  | Native image id or file name (see list_assemblies), or the path of a native PE file, which is loaded. |
| `address` | string | yes |  | Address: hex VA (0x180001000) or RVA (0x1000), rva:/va:/off: prefixed, an export name, module!import, or a function name (one on several addresses is an ambiguous error listing them). |
| `engine` | string |  |  | Engine: auto (default: an engine with a session of this image open, else IDA when installed, else Ghidra; the server default --engine when it names one), ida or ghidra. Values: auto, ida, ghidra. |
| `addresses` | boolean |  | `false` | Prefix each line with the address it was generated from. |
| `offset` | integer |  | `0` | Character offset for paging long output (use the value from the truncation footer). |
| `maxChars` | integer |  |  | Max characters in this page (default from server config, ~60000). |

### verify_native_imports

**Verify P/Invoke imports** (read-only, idempotent)

Check a .NET assembly's P/Invoke declarations ([DllImport]) against the exports of the libraries they bind to, with the runtime's lookup rules: DLL search order (app folder, system folder for the assembly's bitness), API set redirection, A/W suffixes, x86 stdcall decoration (_Name@N), ordinals and forwarder chains; for Linux / macOS / Android / iOS targets (platform=, or detected from deps.json and the libraries shipped) .so / .dylib probing along the RID chain, ELF / Mach-O exports and __Internal in an Il2Cpp game binary. Verdict per declaration, with a reason: verified (exact, suffixed, decorated, forwarded, ordinal, versioned, internal), contradicted (missing_export, missing_ordinal, exact_spelling, ordinal_points_elsewhere, forwarder_broken, arch_mismatch, mangled_only), unresolved (dll_not_found with the places searched, system_dll_not_on_host, wrong_platform, malformed_metadata with its location), dynamic_only (the assembly loads the library itself: NativeLibrary.Load/GetExport, LoadLibrary/GetProcAddress, a DllImportResolver), not_checked (runtime-internal). Run-time loading found in the IL is listed; a missing static import does not rule out dynamic loading. Malformed metadata is reported with locations.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `assembly` | string | yes |  | Assembly id, name, file name or path (see list_assemblies). |
| `status` | string |  |  | Only declarations with this status (verified, contradicted, unresolved, dynamic_only, not_checked) or reason (e.g. missing_export). |
| `offset` | integer |  | `0` | Index of the first row. |
| `limit` | integer |  | `500` | Max rows (default 500, max 5000). |
| `platform` | string |  |  | Target platform (default auto). Values: auto, windows, linux, osx, android, ios. |

Structured output: `assembly`, `declarations`, `counts`, `filter`, `offset`, `total`, `truncated`, `items`, `dynamicLoads`, `dynamicLoadsTotal`, `metadataIssues`, `notes`.

### load_pdb

**Load native debug symbols** (destructive, idempotent, open-world, long-running)

Load the PDB (MSF 7.0) of a native image: function and data names with addresses (publics, global and static data, procedures of every module, thunks), checked against the image's CodeView GUID and age. Searched: the path given (file or directory), the image's directory, the path recorded in the image, _NT_SYMBOL_PATH caches and directories, the Visual Studio / WinDbg / IDA caches and C:\symbols. download=true (off by default) fetches it from a symbol server (server, else those in _NT_SYMBOL_PATH, else Microsoft's) into a per-user cache. Names show up as source 'pdb' in list_functions, disassemble and cross-references; user names (rename_native) are kept. Functions the PDB names that discovery missed become function starts (the index rebuilds in the background). A matching local PDB is also read automatically when the index is first built. The next decompile_native loads the PDB's types (structs, enums, prototypes) into the IDA database. The names of a load_pdb are saved with the image's annotations (PDB path, GUID and age, names, function starts) and reapplied automatically when the same file is loaded again, even when the PDB has moved; clear=true removes the PDB names and the saved copy.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `image` | string | yes |  | Native image id or file name (see list_assemblies), or the path of a native PE file, which is loaded. |
| `path` | string |  |  | PDB file, or a directory (or symbol store) to look in first. |
| `download` | boolean |  | `false` | Download from a symbol server when no local PDB matches (network; off by default). |
| `server` | string |  |  | Symbol server URL for download (default: _NT_SYMBOL_PATH servers, else https://msdl.microsoft.com/download/symbols). |
| `force` | boolean |  | `false` | Use the PDB at path even when its GUID or age differs from the image (names may be wrong). |
| `timeoutSeconds` | integer |  | `120` | Download time limit in seconds (default 120). |
| `maxMegabytes` | integer |  | `2048` | Download size limit in MB (default 2048). |
| `clear` | boolean |  | `false` | Remove the image's PDB names and their saved copy instead of loading (a matching local PDB is not read again in this session). |

### search_pdb_symbols

**Search native debug symbols** (read-only, idempotent)

Symbols of the PDB loaded for a native image (load_pdb, or found automatically): address, kind (function, data, public, thunk), size, name, the full signature undecorated from the public name, and the module (object file). query matches names case-insensitively; empty lists all.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `image` | string | yes |  | Native image id or file name (see list_assemblies), or the path of a native PE file, which is loaded. |
| `query` | string |  |  | Text the name (or decorated name) contains; empty for all. |
| `kind` | string |  |  | Only this kind: function, data, public, or all (default). Values: function, data, public, all. |
| `offset` | integer |  | `0` | Index of the first row. |
| `limit` | integer |  | `200` | Max rows (default 200). |

### get_nativeaot_info

**NativeAOT metadata** (read-only, idempotent, long-running)

What a NativeAOT image's own metadata recovers, read without executing it (.NET 7-10). view=summary: runtime and ReadyToRun version, dehydration, module header, each recovery stage with its status (complete / partial / absent / unsupported), counts and the share of function starts named. view=sections: the module sections. view=types: MethodTables with name, name origin (typemap / composition / vtable / element / generated), kind and base. view=type: one MethodTable by name or address with flags, base chain, interfaces and vtable slots and dispatch-map interface implementations with their code. view=methods: named method bodies (origin stacktrace / invoke). view=strings: frozen string literals with their references. query filters types / methods / strings by substring. The names also apply automatically as the nativeaot name layer.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `image` | string | yes |  | Native image id or file name (see list_assemblies), or the path of a native PE file, which is loaded. |
| `view` | string |  |  | summary (default), sections, types, type, methods or strings. Values: summary, sections, types, type, methods, strings. |
| `query` | string |  |  | view=type: a type name ('System.String', 'MT_System_String') or the MethodTable's address; other list views: substring filter. |
| `offset` | integer |  | `0` | First row for the list views; character offset for summary and type. |
| `limit` | integer |  | `200` | Max rows for the list views (default 200). |

Structured output: `image`, `view`, `summary`, `coverage`, `items`, `offset`, `total`, `truncated`.

## native-edit

Native names, comments, patches and saving.

### rename_native

**Name a native address** (destructive, idempotent, long-running)

Give a name to a native address (a function start, or any address): the name shows up in list_functions, disassemble (labels and call targets), find_xrefs and native_call_tree, and is saved to a per-user sidecar keyed by the file's SHA-256, so it survives reloads and restarts. Names are C-identifier-like (<=255 chars) and unique unless allowDuplicate=true. An empty name clears it.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `image` | string | yes |  | Native image id or file name (see list_assemblies), or the path of a native PE file, which is loaded. |
| `address` | string | yes |  | Address: hex VA (0x180001000) or RVA (0x1000), rva:/va:/off: prefixed, an export name, module!import, or a function name (one on several addresses is an ambiguous error listing them). |
| `name` | string | yes |  | The new name; empty to clear the name at this address. |
| `allowDuplicate` | boolean |  | `false` | Allow a name already used at another address. |

### comment_native

**Comment a native address** (destructive, idempotent, long-running)

Attach a comment to a native address; it shows up next to disassembly that references the address and is saved to the per-user sidecar keyed by the file's SHA-256 (so it survives reloads and restarts). An empty text clears the comment.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `image` | string | yes |  | Native image id or file name (see list_assemblies), or the path of a native PE file, which is loaded. |
| `address` | string | yes |  | Address: hex VA (0x180001000) or RVA (0x1000), rva:/va:/off: prefixed, an export name, module!import, or a function name (one on several addresses is an ambiguous error listing them). |
| `text` | string | yes |  | The comment text; empty to clear it. |

### export_native_annotations

**Export native annotations** (destructive, idempotent, long-running)

Write the image's names and comments as an IDAPython script (format=ida), a Ghidra script (format=ghidra) or JSON (format=json); the IDA script and JSON also carry the user's engine types (declarations, prototypes and global types, stack variables, locals). Scripts apply by RVA rebased to the database's own image base at run time.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `image` | string | yes |  | Native image id or file name (see list_assemblies), or the path of a native PE file, which is loaded. |
| `outputPath` | string | yes |  | Output file path. |
| `format` | string |  |  | ida, ghidra or json (default json). Values: ida, ghidra, json. |
| `overwrite` | boolean |  | `false` | Replace outputPath if it exists. |

### patch_bytes

**Patch native bytes** (destructive, long-running)

Replace bytes at a native address with a hex string, in memory. The patch is recorded as an undoable edit and every read path (disassemble, strings, search_bytes, read_bytes) then sees the patched bytes. Over code, trailing bytes of a partly overwritten instruction are padded with NOPs; the patch is refused if it would start mid-instruction, run past the function end or hit zero-fill/header bytes, unless force=true. Base relocations under the patch are planned (see relocations). dryRun shows the before/after disassembly and the relocation changes without recording it.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `image` | string | yes |  | Native image id or file name (see list_assemblies), or the path of a native PE file, which is loaded. |
| `address` | string | yes |  | Address: hex VA (0x180001000) or RVA (0x1000), rva:/va:/off: prefixed, an export name, module!import, or a function name (one on several addresses is an ambiguous error listing them). |
| `hex` | string | yes |  | Replacement bytes as hex (e.g. '90 90' or '9090' or '0x90,0x90'). |
| `force` | boolean |  | `false` | Override the safety checks (mid-instruction, past function end, header bytes, a new address with no free relocation slot). |
| `dryRun` | boolean |  | `false` | Preview only; do not record the patch. |
| `relocations` | string |  |  | Base relocations under the patch (the loader adds the load delta to each under ASLR / rebasing): auto (default) keeps an entry where the new bytes still hold an address, neutralizes the rest (type ABSOLUTE) and adds entries for new absolute addresses by reusing an ABSOLUTE slot of the page's relocation block; keep leaves every entry as it is; neutralize neutralizes every entry under the patch. The report lists kept / neutralized / added entries; undo restores them. Ignored when extend=true. Values: auto, keep, neutralize. |
| `extend` | boolean |  | `false` | When the new code is larger than a single in-place patch allows (or always, to keep the original site intact), place a relocation stub in slack space: the site becomes a near jump to the stub (a file-backed code cave, or a new executable section when none fits — see placement) holding the new code, and control returns to the instruction after the site. Refused with a reason code (branch_target_in_site, displaced_absolute_reloc, unwind_data, no_space, no_space_at_site, no_header_space, stub_needs_reloc, unreachable_section, arm64_unsupported) when unsafe. The stub is one undoable edit, exported and saved with the patch. |
| `stubMode` | string |  |  | With extend=true, how the stub runs the new code relative to the site's displaced instructions: replace (default; the new code runs instead of them), before (new code then the displaced originals), after (the displaced originals then the new code). Values: replace, before, after. |
| `placement` | string |  |  | With extend=true, where the stub goes: auto (default; a reusable code cave if one fits, else a new executable section), cave (a file-backed code cave only; no_space when none fits), section (always a new section appended to the file). A new section updates the section count, SizeOfImage, SizeOfCode and PE checksum; undo removes it and the file returns byte-for-byte to the original. Refused with no_header_space (no free section-table slot), stub_needs_reloc (an absolute in-image operand under ASLR) or unreachable_section. Values: auto, cave, section. |

### patch_asm

**Assemble and patch native code** (destructive, long-running)

Assemble x86/x64 instructions (multi-line; labels, numeric and symbol branch targets; a 'db <hex>' escape) and write them at a native address, in memory. Branch displacements and RIP-relative references are computed for the target address. Same safety rules and NOP padding as patch_bytes; the patch is recorded as an undoable edit. Absolute addresses (x86 [addr] operands, 'offset name' / symbol immediates, x64 imm64 addresses) get base relocations and overwritten ones are neutralized (see relocations). dryRun shows the before/after disassembly and the relocation changes without recording it.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `image` | string | yes |  | Native image id or file name (see list_assemblies), or the path of a native PE file, which is loaded. |
| `address` | string | yes |  | Address: hex VA (0x180001000) or RVA (0x1000), rva:/va:/off: prefixed, an export name, module!import, or a function name (one on several addresses is an ambiguous error listing them). |
| `assembly` | string | yes |  | Assembly, one instruction per line (e.g. 'jmp target' with a 'target:' label, or 'mov eax, 1\nret'). |
| `force` | boolean |  | `false` | Override the safety checks (mid-instruction, past function end, header bytes, a new address with no free relocation slot). |
| `dryRun` | boolean |  | `false` | Preview only; do not record the patch. |
| `relocations` | string |  |  | Base relocations under the patch (the loader adds the load delta to each under ASLR / rebasing): auto (default) keeps an entry where the new bytes still hold an address, neutralizes the rest (type ABSOLUTE) and adds entries for new absolute addresses by reusing an ABSOLUTE slot of the page's relocation block; keep leaves every entry as it is; neutralize neutralizes every entry under the patch. The report lists kept / neutralized / added entries; undo restores them. Ignored when extend=true. Values: auto, keep, neutralize. |
| `extend` | boolean |  | `false` | When the new code is larger than a single in-place patch allows (or always, to keep the original site intact), place a relocation stub in slack space: the site becomes a near jump to the stub (a file-backed code cave, or a new executable section when none fits — see placement) holding the new code, and control returns to the instruction after the site. Refused with a reason code (branch_target_in_site, displaced_absolute_reloc, unwind_data, no_space, no_space_at_site, no_header_space, stub_needs_reloc, unreachable_section, arm64_unsupported) when unsafe. The stub is one undoable edit, exported and saved with the patch. |
| `stubMode` | string |  |  | With extend=true, how the stub runs the new code relative to the site's displaced instructions: replace (default; the new code runs instead of them), before (new code then the displaced originals), after (the displaced originals then the new code). Values: replace, before, after. |
| `placement` | string |  |  | With extend=true, where the stub goes: auto (default; a reusable code cave if one fits, else a new executable section), cave (a file-backed code cave only; no_space when none fits), section (always a new section appended to the file). A new section updates the section count, SizeOfImage, SizeOfCode and PE checksum; undo removes it and the file returns byte-for-byte to the original. Refused with no_header_space (no free section-table slot), stub_needs_reloc (an absolute in-image operand under ASLR) or unreachable_section. Values: auto, cave, section. |

### list_native_edits

**List native byte patches** (read-only, idempotent, long-running)

The in-memory byte patches of a native image, numbered; undo_native_edit reverts by number and save_native writes them to a file. Then the names by source: the user's (rename_native / comment_native) and each imported layer (pdb, il2cpp, ida) with counts, origin, source file and identity, and whether it was saved or restored from the saved copy when the image loaded (with the import time).

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `image` | string | yes |  | Native image id or file name (see list_assemblies), or the path of a native PE file, which is loaded. |

### undo_native_edit

**Undo a native byte patch** (destructive, long-running)

Undo one in-memory byte patch of a native image — the last by default, or any earlier one by number (from list_native_edits).

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `image` | string | yes |  | Native image id or file name (see list_assemblies), or the path of a native PE file, which is loaded. |
| `number` | integer |  |  | Patch number (1-based, from list_native_edits). Omit to undo the last. |

### save_native

**Save patched native image** (destructive, idempotent, long-running)

Write the patched native image to a file. Everything not patched is byte-for-byte identical to the original; the PE checksum is recomputed when the original had one; a signed file becomes unsigned (pass stripSignature=true to remove the certificate table). Writes atomically, never overwrites without overwrite=true (the original, also through a link, is backed up to .bak; one changed on disk since load is refused), and verifies the written file before it replaces the target by re-parsing and comparing every byte outside the patched ranges (and the relocation entries the patches rewrote), then re-parses the relocation table and checks that every patched range holds exactly its kept/added entries.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `image` | string | yes |  | Native image id or file name (see list_assemblies), or the path of a native PE file, which is loaded. |
| `outputPath` | string | yes |  | Output file path. |
| `overwrite` | boolean |  | `false` | Allow replacing an existing file. |
| `stripSignature` | boolean |  | `false` | Remove the Authenticode certificate table from the output. |

### export_native_patches

**Export native patches** (destructive, idempotent)

Write the image's in-memory byte patches for other tools: format=ida an IDAPython script (applies each patch at its RVA rebased to the database's image base, only where the original bytes are found, and prints a summary), dif IDA's .dif (file offsets, 'orig new' per changed byte), ips (file offsets below 16 MB) or ips32, json the full patch set (original bytes, assembly text, relocation edits, file hash; migrate_native_patches reads it). Relocation-table entry rewrites and the recomputed PE checksum are exported too, so a .dif or IPS applied to the original file gives exactly the bytes save_native writes.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `image` | string | yes |  | Native image id or file name (see list_assemblies), or the path of a native PE file, which is loaded. |
| `outputPath` | string | yes |  | Output file path. |
| `format` | string |  |  | ida, dif, ips, ips32 or json (default json). Values: ida, dif, ips, ips32, json. |
| `overwrite` | boolean |  | `false` | Replace outputPath if it exists. |

Structured output: `image`, `outputPath`, `format`, `patches`, `relocationEdits`, `changedBytes`, `records`, `checksumUpdated`, `bytes`, `originalSha256`, `notes`.

## builds

Build-to-build comparison and carrying work to a new build.

### compare_assemblies

**Compare two builds** (destructive, idempotent, long-running)

Compare two builds of an assembly (e.g. before and after an update; load both — the second gets an id like Name#2). Reports renamed/moved types and members (matched by content, so transformed or refactored names carry forward), added and removed members, and for each matched member every way it changed: renamed, signature, body (normalized IL hash), metadata (flags, implementation flags, attributes), field type, and Il2Cpp field offset / address. Members are matched in tiers and only when the match is unique on both sides; otherwise they are listed as ambiguous with their candidates. tokenMapPath writes every old type and member with its new token, tier, confidence and whether the method body hash is equal (JSON).

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `oldAssembly` | string | yes |  | The old build (id, name or path). |
| `newAssembly` | string | yes |  | The new build (id, name or path). |
| `namespace` | string |  |  | Only types whose old or new full name starts with this. |
| `changes` | string |  |  | Member change kinds to include, comma-separated: renamed, moved (to another type), signature, body, metadata, type, offset, address, added, removed, ambiguous, unknown (no counterpart, but the evidence to pair it is missing), or all; a member is listed when any of its changes is included. Default: all except address. |
| `listAddedRemovedTypes` | boolean |  | `true` | Also list the names of added and removed types (otherwise only counts). |
| `includeCompilerGenerated` | boolean |  | `false` | Also show compiler-generated types and members (closures, iterator / async state machines, backing fields, <PrivateImplementationDetails> data): they change with every recompile, so they are hidden and counted by default. |
| `tokenMapPath` | string |  |  | Write the full token map (old token -> new token, status, tier, confidence, body hash equality) to this JSON file; covers the whole assembly whatever the filters. |
| `overwrite` | boolean |  | `false` | Replace an existing token map file. |
| `offset` | integer |  | `0` | Character offset for paging long output (use the value from the truncation footer). |
| `maxChars` | integer |  |  | Max characters in this page (default from server config, ~60000). |

Structured output: `old`, `new`, `oldTypes`, `matchedTypes`, `typeChanges`, `memberChanges`, `memberMatches`, `ambiguousMembers`, `oldSkippedBodies`, `newSkippedBodies`, `hiddenCompilerGenerated`, `items`, `total`, `truncated`, `tokenMapFile`, `tokenMapEntries`.

### find_counterpart

**Find symbol in another build** (read-only, idempotent, long-running)

Where did a type or member of the old build go in the new build? Matches by name, then by content (renamed/transformed members), taking a match only when it is unique on both sides. Shows the new name and token, the matching tier and its confidence (exact, strong, structural), whether a method body changed (normalized IL hash), and Il2Cpp offset/address changes; ambiguous matches list their candidates. Both builds are identified by file SHA-256 and MVID (tokens are only valid within their build). diff=true adds a unified diff of the pair's decompiled C# (for a type, of each changed, added or removed member), il=true one of their normalized IL; names the new build renamed are rewritten first, so a pure rename is no change, and a method with the same normalized IL is not decompiled. Use it to update FindClass names and offsets after an update.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `symbol` | string | yes |  | Symbol in the old build. Type or member. Forms: 'Ns.Type', 'Ns.Outer+Inner', short 'Type', 'Ns.Type::Method', 'Ns.Type.Method', 'Ns.Type::Method(int, string)' for one overload, 'Ns.Type::.ctor', or a metadata token like '0x06000123'. |
| `oldAssembly` | string | yes |  | The old build (id, name or path). |
| `newAssembly` | string | yes |  | The new build (id, name or path). |
| `diff` | boolean |  | `false` | Add a unified diff of the old and new decompiled C# of each matched pair (cut at 300 lines). |
| `il` | boolean |  | `false` | Add a unified diff of the matched methods' normalized IL (the canonical text of docs/il-hash.md: names instead of tokens, instruction indexes instead of offsets). |

### compare_native_images

**Compare native builds** (read-only, idempotent, long-running)

Match the functions of two builds of one native image (x86 / x64 / ARM64), e.g. before and after an application update. Tiers, each accepting a pair only when unique on both sides: 1 same name (export, PDB, Il2Cpp, user), same import thunk, or identical bytes with addresses masked; 2 same canonical control-flow graph and instruction shapes; 3 same imports, strings and constants; 4 call-graph propagation from matched pairs (callees in the same position, mutually best callers / callees, callers and callees in common, the same slot of matched function-pointer tables such as vtables) to a fixed point; 5 fuzzy similarity (instruction mix, graph, size, references, matched neighbors) above minScore with a margin over the runner-up. Returns per-tier counts and one paged list (view): pairs with tier, score and what changed; changed pairs; unmatched functions with the reason; ambiguous functions with their candidates. The first call waits for both code indexes; results are cached until names change.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `oldImage` | string | yes |  | The older build: native image id (e.g. game.dll) or path. Load both builds; the second gets an id like game.dll#2. |
| `newImage` | string | yes |  | The newer build: native image id (e.g. game.dll#2) or path. |
| `view` | string |  |  | List to return: pairs (default), changed (pairs whose code differs), unmatched, ambiguous. Values: pairs, changed, unmatched, ambiguous. |
| `tier` | integer |  | `0` | Only pairs of this tier (1-5); 0 for all. |
| `useNames` | boolean |  | `true` | Match functions by names from exports, PDB, Il2Cpp and user annotations (tier 1). false matches on code alone. |
| `minScore` | number |  | `0.7` | Least similarity for a fuzzy match (0-1, default 0.7). |
| `offset` | integer |  | `0` | Items to skip. |
| `limit` | integer |  | `100` | Items to return (default 100, max 2000). |

Structured output: `oldImage`, `newImage`, `oldFunctions`, `newFunctions`, `matched`, `identical`, `changed`, `unmatchedOld`, `unmatchedNew`, `ambiguous`, `tiers`, `view`, `offset`, `total`, `truncated`, `pairs`, `unmatched`, `ambiguousFunctions`, `notes`, `seconds`.

### diff_function

**Diff a function between builds** (read-only, idempotent, open-world, long-running)

What changed in one function between two builds. The function containing the address is paired through compare_native_images. view=asm (default): both instruction lists aligned, each row = (same), ~ (same shape, other operands), - or +; operands are build-independent: branch targets as labels of the aligned old instruction, calls to matched functions by the new build's name on both sides, strings by text, other data by the new address it maps to, so moved code and relocations do not show as changes. Only changed regions with context rows are returned. view=pseudocode: a unified diff of both functions' pseudocode (IDA) with addresses replaced the same way. An unmatched function returns the reason and candidates.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `oldImage` | string | yes |  | The older build: native image id (e.g. game.dll) or path. Load both builds; the second gets an id like game.dll#2. |
| `newImage` | string | yes |  | The newer build: native image id (e.g. game.dll#2) or path. |
| `address` | string | yes |  | An address in the function: Address: hex VA (0x180001000) or RVA (0x1000), rva:/va:/off: prefixed, an export name, module!import, or a function name (one on several addresses is an ambiguous error listing them). |
| `side` | string |  |  | Which build the address is in: old (default) or new. Values: old, new. |
| `view` | string |  |  | asm (default) or pseudocode (needs IDA). Values: asm, pseudocode. |
| `context` | integer |  | `4` | Unchanged rows (asm) or lines (pseudocode) shown around each change (default 4, 0-50). |
| `maxLines` | integer |  | `300` | Most rows or diff lines returned (default 300, max 5000). |
| `useNames` | boolean |  | `true` | Match functions by names from exports, PDB, Il2Cpp and user annotations (tier 1). false matches on code alone. |
| `engine` | string |  |  | view=pseudocode: Where functions, references and control flow come from: auto (default: an engine's analysis when one of this image is complete in this session, IDA's before Ghidra's, else the built-in index; never starts an engine), ours (the built-in index only), ida or ghidra (that engine's analysis, started or waited for when needed). The server default is set with --engine or NDM_ENGINE. Values: auto, ida, ghidra. |

Structured output: `oldImage`, `newImage`, `oldFunction`, `newFunction`, `oldAddress`, `newAddress`, `tier`, `basis`, `score`, `view`, `summary`, `same`, `changed`, `removed`, `added`, `rows`, `unified`, `candidates`, `truncated`, `notes`.

### map_address_between_builds

**Map an address to a new build** (read-only, idempotent, long-running)

Where an address of the old build is in the new build: a function start goes to the matched function (compare_native_images), an address inside a function to the corresponding instruction after aligning both instruction sequences, a string literal to the same string, other data by following the old build's references through matched instructions. Returns the new address with a confidence and the reason, or null with why (and nearby candidates).

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `oldImage` | string | yes |  | The older build: native image id (e.g. game.dll) or path. Load both builds; the second gets an id like game.dll#2. |
| `newImage` | string | yes |  | The newer build: native image id (e.g. game.dll#2) or path. |
| `address` | string | yes |  | Address in the old build: Address: hex VA (0x180001000) or RVA (0x1000), rva:/va:/off: prefixed, an export name, module!import, or a function name (one on several addresses is an ambiguous error listing them). |
| `useNames` | boolean |  | `true` | Match functions by names from exports, PDB, Il2Cpp and user annotations (tier 1). false matches on code alone. |

Structured output: `oldImage`, `newImage`, `oldAddress`, `newAddress`, `confidence`, `reason`, `detail`, `oldFunction`, `newFunction`, `tier`, `candidates`.

### make_code_pattern

**Make a code pattern** (read-only, idempotent, open-world, long-running)

A byte pattern for an address that survives rebuilds: instruction bytes with branch displacements, RIP-relative displacements and relocated or in-image addresses as ?? (IDA style '48 8B 05 ?? ?? ?? ??'), extended an instruction at a time until it occurs once in the image's executable sections. When the code at the address is not unique (anchor auto) or anchor=reference, the pattern starts at or shortly before an instruction that references the address, with the operand's offset and how to recover the address from a hit. anchor=xrefs makes a unique signature at each instruction that references the address (shortest first; the engine's references are added when the engine is IDA or Ghidra), so a new build that changed one site still has others. search_code_pattern finds it again in another build.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `image` | string | yes |  | Native image id or file name (see list_assemblies), or the path of a native PE file, which is loaded. |
| `address` | string | yes |  | Address: hex VA (0x180001000) or RVA (0x1000), rva:/va:/off: prefixed, an export name, module!import, or a function name (one on several addresses is an ambiguous error listing them). |
| `anchor` | string |  |  | auto (default): at the address, else at a reference to it; address; reference; xrefs: one at each reference. Values: auto, address, reference, xrefs. |
| `maxBytes` | integer |  | `64` | Longest pattern in bytes (default 64, 8-512). |
| `maxPatterns` | integer |  | `8` | anchor=xrefs: most signatures (default 8, 1-32). |
| `engine` | string |  |  | anchor=xrefs: Where functions, references and control flow come from: auto (default: an engine's analysis when one of this image is complete in this session, IDA's before Ghidra's, else the built-in index; never starts an engine), ours (the built-in index only), ida or ghidra (that engine's analysis, started or waited for when needed). The server default is set with --engine or NDM_ENGINE. Values: auto, ours, ida, ghidra. |

Structured output: `image`, `address`, `pattern`, `length`, `fixedBytes`, `unique`, `hits`, `anchor`, `patternAddress`, `referenceOffset`, `operandOffset`, `operandSize`, `operandKind`, `instructionEnd`, `note`, `references`, `engine`.

### search_code_pattern

**Search a code pattern** (read-only, idempotent, long-running)

Find a byte pattern with ?? wildcards (as make_code_pattern or search_bytes write it) in the executable sections of every loaded native image, or of the given images, with the function containing each hit and the offset into it.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `pattern` | string | yes |  | Hex bytes with ?? wildcards, e.g. '48 8B 05 ?? ?? ?? ?? E8'. |
| `images` | string |  |  | Comma-separated image ids or paths; omit for every loaded native image. |
| `allSections` | boolean |  | `false` | Search every section, not only executable ones. |
| `limit` | integer |  | `200` | Max hits (default 200, max 5000). |

Structured output: `pattern`, `length`, `images`, `total`, `truncated`, `hits`, `notes`.

### migrate_native_names

**Carry names to a new build** (edit, idempotent, long-running)

Copy names and comments from the old build to the new build's user annotations through the function matches of compare_native_images and map_address_between_builds: function names to the matched function, names and comments inside functions to the aligned instruction, data names to the same string or the data the matched instructions reference. Sources: the old build's user annotations (default; with its engine types: declarations as they are, prototypes and global types by mapped address, locals and stack variables by matched function), and optionally its pdb and il2cpp names (made identifiers). Never replaces a user name, comment or type of the new build; every skipped item has a reason code. dryRun shows exactly what would change.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `oldImage` | string | yes |  | The older build: native image id (e.g. game.dll) or path. Load both builds; the second gets an id like game.dll#2. |
| `newImage` | string | yes |  | The newer build: native image id (e.g. game.dll#2) or path. |
| `dryRun` | boolean |  | `false` | Preview the change without applying it. |
| `minTier` | integer |  | `5` | Weakest match tier accepted for function addresses: 1 (names and identical bytes only) to 5 (all, default). |
| `minScore` | number |  | `0` | Least mapping confidence accepted, 0-1 (default 0: any mapped address). |
| `sources` | string |  |  | Comma-separated layers of the old build to copy: user (default), pdb, il2cpp. |
| `comments` | boolean |  | `true` | Copy comments too (default true). |
| `useNames` | boolean |  | `true` | Match functions by names from exports, PDB, Il2Cpp and user annotations (tier 1). false matches on code alone. |
| `offset` | integer |  | `0` | Entries to skip in the report. |
| `limit` | integer |  | `200` | Entries to return (default 200, max 5000). |

Structured output: `oldImage`, `newImage`, `dryRun`, `considered`, `set`, `skipped`, `skippedBy`, `offset`, `total`, `truncated`, `entries`, `notes`.

### migrate_native_patches

**Migrate patches to a new build** (destructive, long-running)

Carry byte patches from an old build to a new build. Each patch's old address is found in the new build through the build matcher (compare_native_images: function match + instruction alignment). A patch is reapplied only where the new build's ORIGINAL bytes at the mapped address match what the patch expected — exact for raw patch_bytes, ignoring relocated / RIP-relative / branch-displacement bytes for patch_asm patches (whose replacement is re-assembled at the new address). Survivors go through the normal patch path (safety checks and relocations). Every patch is reported applied or refused with a reason code and evidence. Source: the old build's in-memory patches (default) or an exported json (patchSet). dryRun shows everything without changing the new build. The same image as old and new with patchSet replays a patch set on the build it was made for (an export, or the journal of a session that ended without saving).

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `oldImage` | string | yes |  | The old build: native image id or path (its in-memory patches are the source unless patchSet is given). |
| `newImage` | string | yes |  | The new build: native image id or path. Load both builds; the second gets an id like name#2. |
| `patchSet` | string |  |  | A patch set exported by export_native_patches (format=json): a file path or the JSON text. Omit to use the old build's in-memory patches. |
| `dryRun` | boolean |  | `true` | Preview the change without applying it. Default true: preview before changing the new build. |
| `useNames` | boolean |  | `true` | Match functions by names (exports, PDB, Il2Cpp, user); false matches on code alone. |
| `offset` | integer |  | `0` | Entries to skip in the report. |
| `limit` | integer |  | `200` | Entries to return (default 200, max 5000). |

Structured output: `oldImage`, `newImage`, `source`, `dryRun`, `patches`, `applied`, `wouldApply`, `refused`, `refusedBy`, `offset`, `total`, `truncated`, `entries`, `notes`.

### update_to_new_build

**Update work to a new build** (destructive, idempotent, long-running)

Carry everything done on an old build of a native image (x86 / x64 / ARM64) to its new build in one call, through one function match (compare_native_images): user names, comments and engine types (migrate_native_names rules), imported names (the PDB layer is re-imported only from the new build's own matching PDB, else not_applicable pdb_mismatch; the Il2Cpp layer is re-applied from the new build's own metadata, else the old names are mapped through the function match and saved as a layer marked carried by match), byte patches (migrate_native_patches rules; stub extensions and grown-file patches are re-created at the mapped site through the extend path after the displaced original instructions are verified), code patterns (made at every carried name and patch site on the old build, searched in the new build for drift — still_unique, now_ambiguous, not_found, points_elsewhere — and made again on the new build), and for Il2Cpp titles the method -> RVA mapping by metadata identity cross-checked with the matcher, and notes (record_note) at mapped addresses. dryRun (default true) previews everything and changes nothing; dryRun=false applies in the order names, imported layers, patches; a re-run reports already_present. Returns a summary, per-category counts with reason codes, and a paged item list (filter by category / outcome). .NET assemblies are out of scope (compare_assemblies, find_counterpart, export_edits + apply_edits).

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `oldImage` | string | yes |  | The old build: native image id or path (its names, layers and in-memory patches are the source). |
| `newImage` | string | yes |  | The new build: native image id or path. Load both builds; the second gets an id like name#2. |
| `dryRun` | boolean |  | `true` | Preview only (default true): report what would carry over without changing the new build. |
| `include` | string |  |  | Comma-separated categories: names, pdb, il2cpp (names layer and method mapping), patches, patterns, notes; all (default). |
| `patchSet` | string |  |  | Patches from a json patch set (export_native_patches format=json: a path or the JSON text) instead of the old build's in-memory patches. |
| `stubPlacement` | string |  |  | Where re-created patch stubs go: auto (a cave, else a new section; default), cave, section. Values: auto, cave, section. |
| `oldIl2Cpp` | string |  |  | The old build's Il2Cpp dummy assemblies (comma-separated ids); omit to find them (the dump made from this binary, the game's metadata beside it, or what apply_il2cpp_names used). |
| `newIl2Cpp` | string |  |  | The new build's Il2Cpp dummy assemblies (comma-separated ids); omit to find them the same way. |
| `useNames` | boolean |  | `true` | Match functions by names (exports, PDB, Il2Cpp, user); false matches on code alone. |
| `maxPatterns` | integer |  | `100` | Most items (names and patch sites) to make code patterns for (default 100, 0-1000). |
| `category` | string |  |  | Only items of this category: names, pdb, il2cpp_names, patches, patterns, il2cpp_mapping, notes. Values: names, pdb, il2cpp_names, patches, patterns, il2cpp_mapping, notes, dotnet. |
| `outcome` | string |  |  | Only items with this outcome: carried, would_carry, already_present, refused, not_applicable, ambiguous. Values: carried, would_carry, already_present, refused, not_applicable, ambiguous. |
| `offset` | integer |  | `0` | Items to skip. |
| `limit` | integer |  | `100` | Items to return (default 100, max 2000). |

Structured output: `summary`, `oldImage`, `newImage`, `dryRun`, `included`, `oldFunctions`, `newFunctions`, `functionsMatched`, `categories`, `il2CppMapping`, `category`, `outcome`, `offset`, `total`, `truncated`, `items`, `notes`, `seconds`.

## notes

Analyst notes kept per binary across sessions.

### record_note

**Record a note** (edit)

Record a finding, question, hypothesis or todo, anchored to a native address, a .NET member, a file or a dump. Notes persist per user across sessions and processes, keyed by the binary's SHA-256 (MVID for .NET members); decompile_member and decompile_native show how many open notes a target has. Returns the note with id and revision 1.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `text` | string | yes |  | The note (at most 4,000 characters). |
| `kind` | string |  |  | finding (default), question, hypothesis or todo. Values: finding, question, hypothesis, todo. |
| `status` | string |  |  | open (default), confirmed, refuted, answered or dropped. Values: open, confirmed, refuted, answered, dropped. |
| `anchor` | string |  |  | What the note is about: '<image>@<address>' (a native address), '<assembly>:<symbol or token>' (a .NET type or member), an image or assembly id (the whole file), 'dump:<id or path>', or empty (session-wide). Stored by file SHA-256 or module MVID, so it follows the binary. |
| `tags` | string |  |  | Comma-separated tags (at most 10). |
| `evidence` | string |  |  | Where it was seen, ';'-separated (at most 10): e.g. 'decompile_native image=app.dll address=0x140001000'. |

Structured output: `id`, `kind`, `status`, `text`, `tags`, `evidence`, `anchor`, `revision`, `created`, `updated`, `author`.

### update_note

**Update a note** (destructive, idempotent)

Change a note in part: status, text (replace or append), tags (add / remove), evidence (add). expectedRevision must be the revision last read; when the note changed meanwhile the call fails with a conflict that carries the current note (details.current).

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `id` | string | yes |  | The note id (from record_note or list_notes). |
| `expectedRevision` | integer | yes |  | The note's revision as last read. |
| `status` | string |  |  | New status: open, confirmed, refuted, answered or dropped. Values: open, confirmed, refuted, answered, dropped. |
| `kind` | string |  |  | New kind: finding, question, hypothesis or todo. Values: finding, question, hypothesis, todo. |
| `text` | string |  |  | Replacement text. |
| `appendText` | string |  |  | Text appended on a new line. |
| `addTags` | string |  |  | Comma-separated tags to add. |
| `removeTags` | string |  |  | Comma-separated tags to remove. |
| `addEvidence` | string |  |  | ';'-separated evidence entries to add. |

Structured output: `id`, `kind`, `status`, `text`, `tags`, `evidence`, `anchor`, `revision`, `created`, `updated`, `author`.

### list_notes

**List notes** (read-only, idempotent)

Notes, newest first, filtered by status (default open; all for every status), kind, anchor, tag and text. An anchor naming an image or assembly lists all of its notes; '<image>@<address>' lists the notes in the function containing the address; '<assembly>:<type>' includes the notes on its members.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `status` | string |  |  | open (default), confirmed, refuted, answered, dropped, or all. Values: open, confirmed, refuted, answered, dropped, all. |
| `kind` | string |  |  | finding, question, hypothesis or todo. Values: finding, question, hypothesis, todo. |
| `anchor` | string |  |  | What the note is about: '<image>@<address>' (a native address), '<assembly>:<symbol or token>' (a .NET type or member), an image or assembly id (the whole file), 'dump:<id or path>', or empty (session-wide). Stored by file SHA-256 or module MVID, so it follows the binary. |
| `tag` | string |  |  | Only notes with this tag. |
| `text` | string |  |  | Only notes whose text contains this (case-insensitive). |
| `offset` | integer |  | `0` | Notes to skip. |
| `limit` | integer |  | `50` | Notes to return (default 50, max 500). |

Structured output: `items`, `offset`, `total`, `truncated`, `notes`.

## engine

Edits inside the decompiler engine's database: types, locals, frames, declarations, scripting.

### set_native_type

**Set a native prototype or global type** (destructive, idempotent, open-world, long-running)

Set the type of a native function (its prototype, e.g. 'int __fastcall Parse(Packet *p, int len)') or of a global (e.g. 'Config', 'char[64]', 'Handler *[8]') in the decompiler engine (IDA or Ghidra). Named types must exist there (the PDB, RTTI and Il2Cpp types decompile_native pushes, or declare_native_types). User types win over recovered ones. An empty type clears it. Saved per file hash with the image's annotations: re-applied to a new database, exported by export_native_annotations and carried by migrate_native_names and update_to_new_build.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `image` | string | yes |  | Native image id or file name (see list_assemblies), or the path of a native PE file, which is loaded. |
| `address` | string | yes |  | A function start or a global: Address: hex VA (0x180001000) or RVA (0x1000), rva:/va:/off: prefixed, an export name, module!import, or a function name (one on several addresses is an ambiguous error listing them). |
| `type` | string | yes |  | C prototype for a function, C type for a global; empty to clear the user type. |
| `engine` | string |  |  | Engine: auto (default: an engine with a session of this image open, else IDA when installed, else Ghidra), ida or ghidra. Values: auto, ida, ghidra. |

### set_native_local

**Rename or retype a decompiler local** (destructive, idempotent, open-world, long-running)

Rename and/or retype a local variable or argument in the pseudocode of a native function (IDA Hex-Rays or Ghidra's decompiler): name it as decompile_native shows it (v3, a1), or by stack offset as stack:0x28. Later edits may name it by its new name; it stays one edit. The decompiler can refuse a type that does not fit the variable (reported). Saved per file hash with the image's annotations: re-applied to a new database, exported by export_native_annotations and carried by migrate_native_names and update_to_new_build.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `image` | string | yes |  | Native image id or file name (see list_assemblies), or the path of a native PE file, which is loaded. |
| `function` | string | yes |  | The function: Address: hex VA (0x180001000) or RVA (0x1000), rva:/va:/off: prefixed, an export name, module!import, or a function name (one on several addresses is an ambiguous error listing them). |
| `local` | string | yes |  | The variable: its name in the pseudocode, or stack:<offset> (hex). |
| `newName` | string |  |  | New name (a C identifier). |
| `type` | string |  |  | New C type, e.g. 'unsigned int', 'Packet *', 'char[16]'. |
| `engine` | string |  |  | Engine: auto (default: an engine with a session of this image open, else IDA when installed, else Ghidra), ida or ghidra. Values: auto, ida, ghidra. |

### set_native_stack_var

**Rename or retype a stack variable** (destructive, idempotent, open-world, long-running)

Rename and/or retype a member of a native function's stack frame in the engine, named as get_native_frame lists it (var_28) or by frame offset (0x20 or +0x20, from the frame's lowest address); a type at an offset with no member creates one. The return address and saved registers are refused. Stack variables the decompiler has not renamed take the member's name. Saved per file hash with the image's annotations: re-applied to a new database, exported by export_native_annotations and carried by migrate_native_names and update_to_new_build.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `image` | string | yes |  | Native image id or file name (see list_assemblies), or the path of a native PE file, which is loaded. |
| `function` | string | yes |  | The function: Address: hex VA (0x180001000) or RVA (0x1000), rva:/va:/off: prefixed, an export name, module!import, or a function name (one on several addresses is an ambiguous error listing them). |
| `variable` | string | yes |  | The member: its name, or its frame offset (hex). |
| `newName` | string |  |  | New name (a C identifier). |
| `type` | string |  |  | New C type, e.g. 'int', 'char[16]', 'Packet'. |
| `engine` | string |  |  | Engine: auto (default: an engine with a session of this image open, else IDA when installed, else Ghidra), ida or ghidra. Values: auto, ida, ghidra. |

### get_native_frame

**Native stack frame and locals** (read-only, idempotent, open-world, long-running)

The stack frame of a native function as the engine has it (members with offsets, names, types and sizes: locals, arguments, return address and saved registers; Ghidra counts saved registers among the locals) and its decompiler locals (name, type, register or stack offset, argument, user-named / user-typed). Offsets count from the frame's lowest address; the offset from the return address (IDA's var_/arg_ names use it) is in brackets. set_native_stack_var and set_native_local edit them.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `image` | string | yes |  | Native image id or file name (see list_assemblies), or the path of a native PE file, which is loaded. |
| `function` | string | yes |  | The function: Address: hex VA (0x180001000) or RVA (0x1000), rva:/va:/off: prefixed, an export name, module!import, or a function name (one on several addresses is an ambiguous error listing them). |
| `engine` | string |  |  | Engine: auto (default: an engine with a session of this image open, else IDA when installed, else Ghidra), ida or ghidra. Values: auto, ida, ghidra. |

### declare_native_types

**Declare C types in the engine** (destructive, idempotent, open-world, long-running)

Declare C types (structs, unions, enums, typedefs, function pointer types) in the decompiler engine (IDA or Ghidra) from C declarations, e.g. 'struct Packet { int length; char data[256]; };'. A type of the same name is replaced, and user declarations win over the recovered PDB, RTTI and Il2Cpp types of that name. Declarations with errors are reported with the engine's messages and not saved. Use the types with set_native_type, set_native_local and set_native_stack_var. Saved per file hash with the image's annotations: re-applied to a new database, exported by export_native_annotations and carried by migrate_native_names and update_to_new_build.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `image` | string | yes |  | Native image id or file name (see list_assemblies), or the path of a native PE file, which is loaded. |
| `declarations` | string | yes |  | C declarations, several allowed; types they name must exist or be declared in the same text. |
| `engine` | string |  |  | Engine: auto (default: an engine with a session of this image open, else IDA when installed, else Ghidra), ida or ghidra. Values: auto, ida, ghidra. |

### list_native_types

**Browse the engine's types** (read-only, idempotent, open-world, long-running)

The named types of the decompiler engine's database (IDA local types, Ghidra data types: from the PDB, RTTI classes, Il2Cpp, the engine's type libraries and declare_native_types), filtered by name and kind, with size and member count; name= shows one type as a C declaration with its members' offsets.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `image` | string | yes |  | Native image id or file name (see list_assemblies), or the path of a native PE file, which is loaded. |
| `filter` | string |  |  | Only types whose name contains this text (case-insensitive). |
| `kind` | string |  |  | Only this kind: struct, union, enum, typedef or func. |
| `name` | string |  |  | Show this one type in full instead of a list. |
| `offset` | integer |  | `0` | Index of the first row. |
| `limit` | integer |  | `200` | Max rows (default 200, max 5000). |
| `engine` | string |  |  | Engine: auto (default: an engine with a session of this image open, else IDA when installed, else Ghidra), ida or ghidra. Values: auto, ida, ghidra. |

### ida_python

**Run IDAPython on a native image** (destructive, open-world, long-running)

Run Python in the IDA worker that holds a native image's database (idalib): IDAPython modules are imported, base is the image base, globals persist between calls (reset=true clears them), and the value of a final expression is returned with stdout and stderr. Disabled unless the server runs with --ida-scripting or NDM_IDA_SCRIPTING=1: the code runs with the server's rights and can change or destroy the analysis database. Changes are not journaled or saved in the annotation sidecar: a worker restart loses unsaved ones (ida_loader.save_database keeps them).

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `image` | string | yes |  | Native image id or file name (see list_assemblies), or the path of a native PE file, which is loaded. |
| `code` | string | yes |  | Python source; a final expression's value is returned. |
| `reset` | boolean |  | `false` | Clear the globals earlier calls left. |
| `engine` | string |  |  | Engine: auto (default) or ida. Values: auto, ida. |

## android

Android packages: manifest, resources, DEX code, Java decompilation, Java / .NET mapping, devices.

### get_android_manifest

**Android manifest** (read-only, idempotent)

AndroidManifest.xml of an Android package, decoded natively (no Java tools): package, versions, min / target / compile SDK; permissions (also -sdk-23 and maxSdkVersion) and declared permissions with protection levels; application flags (debuggable, allowBackup, usesCleartextTraffic, networkSecurityConfig with its file, extractNativeLibs); every activity, alias, service, receiver and provider with its explicit and effective exported state and why, permissions, intent filters, launcher, deep links and meta-data; queries, features, libraries; highlights. Resource references are resolved. The XML itself: get_android_resource name=AndroidManifest.xml.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `path` | string | yes |  | An Android package: .apk, .aab (its base module), or a split set (.apks, .xapk, .apkm, read through its base APK). |

Structured output: `package`, `versionCode`, `versionName`, `minSdk`, `targetSdk`, `maxSdk`, `compileSdk`, `split`, `permissions`, `declaredPermissions`, `application`, `components`, `queries`, `features`, `libraries`, `metaData`, `highlights`, `issues`.

### list_android_resources

**List Android resources** (read-only, idempotent)

Compiled resources of an Android package (resources.arsc, or resources.pb of an app bundle): one row per resource and configuration with id (0x7f...), type, name, configuration qualifiers (pt-rBR, b+zh+Hans, night, xxhdpi, v31; '' is the default), value type and value (strings, references by name, colors, dimensions, file paths; styles, arrays and plurals as name=value lists). types gives every resource type with its count.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `path` | string | yes |  | An Android package: .apk, .aab (its base module), or a split set (.apks, .xapk, .apkm, read through its base APK). |
| `type` | string |  |  | Only this type: string, layout, xml, drawable, color, ... |
| `name` | string |  |  | Only names matching this (case-insensitive; * and ? wildcards). |
| `config` | string |  |  | Only this configuration: qualifiers as in a directory name (values-pt-rBR: pt-rBR), or default. |
| `offset` | integer |  | `0` | Rows to skip. |
| `limit` | integer |  | `500` | Most rows to return (default 500). |

Structured output: `items`, `offset`, `total`, `truncated`, `types`.

### get_android_resource

**Get Android resource** (destructive, idempotent)

One file of an Android package, or one resource: a path (res/xml/network_security_config.xml, res/layout/main.xml, assets/..., AndroidManifest.xml) is read with binary XML decoded and resource references named, text as text, other data as a hex preview; @type/name or 0x7f... gives the resource's value in every configuration, or its file. savePath writes the raw bytes.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `path` | string | yes |  | An Android package: .apk, .aab (its base module), or a split set (.apks, .xapk, .apkm, read through its base APK). |
| `name` | string | yes |  | An entry path, @type/name (@xml/network_security_config, @string/app_name) or a resource id 0x7f... |
| `savePath` | string |  |  | Write the entry's bytes to this file. |
| `overwrite` | boolean |  | `false` | Replace savePath if it exists. |
| `offset` | integer |  | `0` | Character offset for paging long output (use the value from the truncation footer). |
| `maxChars` | integer |  |  | Max characters in this page (default from server config, ~60000). |

### list_dex_classes

**List DEX classes** (read-only, idempotent)

Classes defined in the DEX code of an Android package (every classes*.dex, inner and anonymous classes included): descriptor, Java name, DEX file, access, superclass, interfaces, method and field counts, source file. Read natively, no Java tools.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `path` | string | yes |  | An Android package (.apk, .aab, .apks, .xapk, .apkm), a .dex file, or a jar / zip with classes*.dex. |
| `query` | string |  |  | Only classes whose Java name or descriptor contains this (case-insensitive), or matches it with * and ? wildcards. |
| `package` | string |  |  | Only this package and its subpackages, e.g. com.example. |
| `offset` | integer |  | `0` | Classes to skip. |
| `limit` | integer |  | `500` | Most classes to return (default 500). |

Structured output: `items`, `offset`, `total`, `truncated`, `notes`.

### get_dex_class

**DEX class** (read-only, idempotent)

One DEX class in full: access, superclass, interfaces, source file, generic signature, enclosing and inner classes, Kotlin @Metadata (kind and names), annotations; fields with type, access, static initial value and annotations; methods with their exact id (Lpkg/C;->name(params)ret, so overloads never collide), Java signature, access, code size, registers and parameter names.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `path` | string | yes |  | An Android package (.apk, .aab, .apks, .xapk, .apkm), a .dex file, or a jar / zip with classes*.dex. |
| `class` | string | yes |  | Class: Lpkg/Name;, pkg.Name, or pkg.Outer.Inner / pkg.Outer$Inner. |

Structured output: `descriptor`, `javaName`, `dexFile`, `access`, `super`, `interfaces`, `sourceFile`, `genericSignature`, `enclosingClass`, `enclosingMethod`, `innerClasses`, `kotlin`, `annotations`, `fields`, `methods`.

### disassemble_dex

**Disassemble DEX** (read-only, idempotent)

Smali of one method, or of a whole class, from the DEX code of an Android package, in baksmali's layout: registers as pN / vN, string, type, field and method operands resolved, labels by code offset, .line numbers, try / catch blocks, switch and array payloads, annotations. A method is one exact id (Lpkg/C;->m(I)V) or one overload (pkg.C::m(int)); never several at once. format=annotated adds each instruction's code offset and code units.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `path` | string | yes |  | An Android package (.apk, .aab, .apks, .xapk, .apkm), a .dex file, or a jar / zip with classes*.dex. |
| `symbol` | string | yes |  | A method (Lpkg/C;->name(params)ret, or pkg.C::name with optional (int, String)) or a class (pkg.C, Lpkg/C;). |
| `format` | string |  |  | smali (default) or annotated. Values: smali, annotated. |
| `offset` | integer |  | `0` | Character offset for paging long output (use the value from the truncation footer). |
| `maxChars` | integer |  |  | Max characters in this page (default from server config, ~60000). |

### search_dex

**Search DEX code** (read-only, idempotent, long-running)

Search the DEX code of an Android package. kind=string: string literals loaded by code, with the method and offset of each use; type: defined classes and type uses (new-instance, check-cast, const-class...); method / field: defined and referenced members with their use counts; const: numeric constants (42, 0x7f010000, 1.5); opcode: instructions by mnemonic (invoke-static, sget-object). query is a case-insensitive substring, or a pattern with * and ? wildcards.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `path` | string | yes |  | An Android package (.apk, .aab, .apks, .xapk, .apkm), a .dex file, or a jar / zip with classes*.dex. |
| `kind` | string | yes |  | string, type, method, field, const or opcode. Values: string, type, method, field, const, opcode. |
| `query` | string | yes |  | Text to find (substring or wildcard pattern); for const a number. |
| `offset` | integer |  | `0` | Hits to skip. |
| `limit` | integer |  | `200` | Most hits to return (default 200). |

Structured output: `items`, `offset`, `total`, `truncated`, `notes`.

### find_dex_references

**Find DEX references** (read-only, idempotent, long-running)

Cross-references in DEX code with the method and code offset of each instruction. direction=to: callers of a method, readers and writers of a field, uses of a class (type uses and accesses to its members) or of a string literal. direction=from: what a method (or every method of a class) calls, reads, writes and loads. Methods are matched by exact id, so one overload never stands for another.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `path` | string | yes |  | An Android package (.apk, .aab, .apks, .xapk, .apkm), a .dex file, or a jar / zip with classes*.dex. |
| `target` | string | yes |  | A class, a method (Lpkg/C;->m(I)V, or pkg.C::m with optional parameters (int, String)), a field (Lpkg/C;->f:I or pkg.C::f), or a string in double quotes. |
| `direction` | string |  |  | to (default: who refers to the target) or from (what the target refers to). Values: to, from. |
| `kind` | string |  |  | auto (default), class, method, field or string (target taken literally). Values: auto, class, method, field, string. |
| `offset` | integer |  | `0` | References to skip. |
| `limit` | integer |  | `500` | Most references to return (default 500). |

Structured output: `target`, `targetKind`, `direction`, `items`, `offset`, `total`, `truncated`, `notes`.

## dumps

Crash dumps and crash text.

### open_minidump

**Open a crash dump** (read-only, idempotent, open-world, long-running)

Summary of a Windows minidump (.dmp): OS and CPU, process (id, times, integrity, WoW64, managed runtime), the exception (code and name, e.g. EXCEPTION_ACCESS_VIOLATION writing 0x0, the faulting thread, module+offset and function, the faulting instruction disassembled from dump memory or the module image, registers, the thrown type of a C++ exception), the .NET state (managed exception with stack and inner chain, threads, heap state), modules (path, base, size, timestamp, checksum, version, PDB name/GUID/age, and whether a matching image file exists on this machine), threads (ids, names, stack ranges, where each one is), unloaded modules, captured memory, handle counts by type, and what the parser could not read. Modules and threads are paged. The dump gets an id for the other dump tools. The dumped program is not run; .NET decoding loads Microsoft's signature-checked debugging library (DAC) for that runtime build, never code from the dump.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `path` | string | yes |  | Path of the .dmp file (or the id of an open dump). |
| `imageDirectories` | string |  |  | Folders with the crashed program's binaries (';'-separated), searched by file name when a module's recorded path is not on this machine or holds another build. The dump's own folder is always searched. |
| `modulesOffset` | integer |  | `0` | Index of the first module listed. |
| `modulesLimit` | integer |  | `50` | Max modules listed (default 50). |
| `threadsOffset` | integer |  | `0` | Index of the first thread listed. |
| `threadsLimit` | integer |  | `50` | Max threads listed (default 50). |
| `dacPath` | string |  |  | The dumped runtime's DAC (mscordaccore.dll / mscordacwks.dll) or its folder, when the same runtime build is not installed here. |
| `downloadDac` | boolean |  | `false` | Download the DAC from the symbol server (_NT_SYMBOL_PATH's, else Microsoft's) when no local copy matches; refused under NDM_OFFLINE=1. |

Structured output: `id`, `path`, `fileSize`, `timeUtc`, `dumpType`, `system`, `process`, `exception`, `managed`, `moduleCount`, `modulesOffset`, `modulesTruncated`, `modules`, `threadCount`, `threadsOffset`, `threadsTruncated`, `threads`, `unloadedModuleCount`, `unloadedModules`, `memory`, `handleCount`, `handleTypes`, `streams`, `comments`, `issues`, `notes`.

### dump_stack

**Crash dump stack** (read-only, idempotent)

Call stack of a thread in a minidump. x64: virtual unwind with the modules' .pdata unwind data (from the matching image file on disk, or the image in dump memory); x86: the EBP chain. Where unwind data is missing (JIT code, no image) the stack is scanned for return addresses and those frames are marked heuristic. Frames are named from a loaded native image's code index (user, PDB, Il2Cpp, discovered names), Il2Cpp dummy DLLs for GameAssembly.dll, a matching local PDB, or exports (nearest_export is a guess). .NET frames come from the runtime's own walk (DAC), merged by stack pointer, with token, IL offset and the loaded assembly of that build (by MVID). The faulting thread uses the exception context, like .ecxr.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `dump` | string | yes |  | A minidump: the path of a .dmp file, or the id open_minidump returned (its file name). |
| `thread` | string |  |  | Thread id (decimal or 0x hex), '#index', a thread name, or 'exception'. Default: the faulting thread, else the first thread. |
| `exceptionContext` | boolean |  | `true` | For the faulting thread, start from the context at the exception (true) or from the thread's context when the dump was written (false). |
| `maxFrames` | integer |  | `256` | Max frames walked (default 256, up to 1024). |
| `offset` | integer |  | `0` | Index of the first frame returned. |
| `limit` | integer |  | `100` | Max frames returned (default 100). |
| `imageDirectories` | string |  |  | Folders with the crashed program's binaries (';'-separated), searched by file name when a module's recorded path is not on this machine or holds another build. The dump's own folder is always searched. |
| `managed` | string |  | `auto` | auto: decode .NET frames through a local DAC (or the one open_minidump loaded); off: native walk only. Values: auto, off. |

Structured output: `dump`, `threadId`, `threadName`, `context`, `architecture`, `registers`, `total`, `offset`, `truncated`, `frames`, `stop`, `heuristicFrames`, `managed`, `notes`.

### dump_heap

**Crash dump .NET heap** (read-only, idempotent, long-running)

The .NET GC heap of a minidump (through the runtime's DAC). stats: count and size per type, largest first, with the loaded assembly and type token of that build; objects: matching objects (address, type, size, a string's value). Needs heap memory in the dump (else heap_not_captured). Bounded by maxObjects.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `dump` | string | yes |  | A minidump: the path of a .dmp file, or the id open_minidump returned (its file name). |
| `mode` | string |  | `stats` | stats (per type) or objects (one row per object). Values: stats, objects. |
| `type` | string |  |  | Type full name, with '*' / '?' wildcards (System.Collections.Generic.List*); default all. |
| `minSize` | integer |  | `0` | Only objects of at least this many bytes. |
| `offset` | integer |  | `0` | Index of the first row returned. |
| `limit` | integer |  | `50` | Max rows returned (default 50, up to 1000). |
| `maxObjects` | integer |  | `5000000` | Max objects walked (default 5,000,000). |

Structured output: `dump`, `mode`, `type`, `minSize`, `walked`, `walkStopped`, `total`, `offset`, `truncated`, `matchedBytes`, `types`, `objects`, `notes`.

### dump_object

**Crash dump .NET object** (read-only, idempotent)

One .NET object of a minidump (through the runtime's DAC): type, size, fields (references expanded depth levels, structs inline), a string's or boxed value, or array elements, with the type's loaded assembly and token.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `dump` | string | yes |  | A minidump: the path of a .dmp file, or the id open_minidump returned (its file name). |
| `address` | string | yes |  | Hex address of the object. |
| `depth` | integer |  | `1` | Levels of referenced objects expanded (default 1, up to 3). |
| `maxFields` | integer |  | `100` | Max fields listed, nested ones included (default 100). |
| `maxArrayItems` | integer |  | `32` | Max array elements listed (default 32). |

Structured output: `dump`, `address`, `type`, `size`, `assembly`, `token`, `buildCheck`, `value`, `length`, `fields`, `truncated`, `notes`.

### read_dump_memory

**Read crash dump memory** (read-only, idempotent)

Hex dump of the dumped process's memory at an address: the bytes the dump captured, with what is there (module!function, captured range, page protection). Bytes the dump does not hold are read from the module image when imageFallback is true (code and read-only data match; writable data shows initial values), and the source is reported.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `dump` | string | yes |  | A minidump: the path of a .dmp file, or the id open_minidump returned (its file name). |
| `address` | string | yes |  | Address: hex (0x7FF6A1B21000), 'module+0x1234', or a module name for its base. |
| `length` | integer |  | `256` | Bytes to read (default 256, up to 65536). |
| `imageFallback` | boolean |  | `true` | Read bytes the dump does not hold from the module image. |

Structured output: `dump`, `address`, `requested`, `length`, `source`, `location`, `region`, `protection`, `hex`, `bytes`, `note`.

### symbolize_stack_text

**Symbolize crash text** (read-only, idempotent, long-running)

Resolves crash text against the loaded build: Unity Player.log / error.log backtraces (its module list gives load addresses), Mono frames (by module MVID), Il2Cpp/Unity managed lines, .NET exception text (inner chain, NativeAOT), WER Report.wer, Event Log 1000/1026 text and debugger stacks. Each frame gets our name and a buildCheck (time stamp, MVID or the text's own name); modules not loaded are listed; unrecognized lines are counted.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `text` | string |  |  | The crash text (up to 1 MiB). Pass this or path. |
| `path` | string |  |  | A log or report file (Player.log, error.log, Report.wer, saved event text); its last 8 MiB are read. |
| `format` | string |  | `auto` | auto (default), unity, dotnet, wer, eventlog or windbg. Values: auto, unity, dotnet, wer, eventlog, windbg. |
| `images` | string |  |  | Native image ids or paths to resolve against (';'-separated); default every loaded native image. |
| `moduleBases` | string |  |  | Module load addresses for absolute addresses, 'name=0xBASE;...' (the crash's module list in the text is used too). |
| `offset` | integer |  | `0` | Index of the first frame returned. |
| `limit` | integer |  | `200` | Max frames returned (default 200). |

Structured output: `format`, `exception`, `total`, `offset`, `truncated`, `frames`, `unrecognizedLines`, `unrecognizedSample`, `modulesMissing`, `notes`.

### bucket_minidumps

**Group crash dumps** (read-only, idempotent, long-running)

Groups a folder of minidumps by signature: exception code | faulting module!function | next frames (raising frames such as RaiseException and _CxxThrowException skipped); .NET: clr | exception type | top managed frames; no exception: hang | top frames. Function names, so rebases and offsets do not split a bucket; offsets and module versions are counted. Each bucket has dump ids and its newest dump as representative. Cached per file, so re-runs parse only new dumps.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `folder` | string | yes |  | Folder with the .dmp files. |
| `recursive` | boolean |  | `false` | Also search subfolders. |
| `pattern` | string |  |  | File patterns, ';'-separated (default *.dmp;*.mdmp). |
| `topFrames` | integer |  | `3` | Frames after the faulting one in the signature (default 3). |
| `skipModules` | string |  |  | More frames to skip, ';'-separated: a module (ucrtbase) or module!function, '*' wildcards. |
| `splitByVersion` | boolean |  | `false` | Put the faulting module's version in the signature. |
| `managed` | string |  | `auto` | auto: CLR exceptions get managed signatures when a local DAC is found; off: native frames only. Values: auto, off. |
| `maxDumps` | integer |  | `1000` | Most dumps bucketed, newest first (default 1000). |
| `imageDirectories` | string |  |  | Folders with the crashed program's binaries (';'-separated), for module images not at their recorded paths. |
| `offset` | integer |  | `0` | Index of the first bucket returned. |
| `limit` | integer |  | `50` | Max buckets returned (default 50). |

Structured output: `folder`, `dumps`, `total`, `offset`, `truncated`, `buckets`, `failed`, `notes`.

## live

Read-only inspection of a running process.

### inspect_process

**Inspect a running process (read-only)** (read-only, idempotent, open-world)

Read-only look at a running local process (Windows): modules (path, base, size, timestamp, PDB, whether a matching file is on disk), memory regions (VirtualQuery view: state, protection, type, owning module; paged and filtered), threads (id, name, suspend count, priority, TEB, stack range, start address, registers, where each one is) and their call stacks (x64 unwind data / x86 EBP chain, scan frames marked heuristic), every address named as dump_stack names it: a loaded image's code index (user renames, PDB, Il2Cpp, discovered names), Il2Cpp dummy DLLs, a matching local PDB, or exports. Strictly read-only: the process is opened with PROCESS_QUERY_INFORMATION | PROCESS_VM_READ only, each thread briefly with THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION; no memory write, no breakpoint, no debugger attach, no thread suspension or injection; all handles are closed before the call returns (also on error, cancellation or timeout). Threads keep running, so a running thread's registers are a snapshot.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `process` | string | yes |  | Process id (decimal or 0x hex) or process name (notepad or notepad.exe); a name shared by several processes is reported with their ids. |
| `sections` | string |  |  | Comma-separated parts to report: modules, regions, threads, stacks (stacks implies threads), or all (default). |
| `thread` | string |  |  | Only this thread: id (decimal or 0x hex) or thread name. |
| `modulesOffset` | integer |  | `0` | Index of the first module listed. |
| `modulesLimit` | integer |  | `50` | Max modules listed (default 50). |
| `regionsOffset` | integer |  | `0` | Index of the first region listed (after regionFilter). |
| `regionsLimit` | integer |  | `100` | Max regions listed (default 100). |
| `regionFilter` | string |  |  | Regions listed: committed (default), all (with reserved and free), executable, writable, image, private or mapped. Values: committed, all, executable, writable, image, private, mapped. |
| `threadsOffset` | integer |  | `0` | Index of the first thread listed. |
| `threadsLimit` | integer |  | `20` | Max threads listed (default 20). |
| `maxFrames` | integer |  | `32` | Max frames walked per thread (default 32, up to 256). |
| `imageDirectories` | string |  |  | Folders with the program's binaries (';'-separated), searched by file name when a module's own file is not readable; the executable's folder is always searched. |
| `timeoutSeconds` | integer |  | `20` | Time limit in seconds (default 20, up to 120); on expiry every handle is closed and a timeout error is returned. |

Structured output: `processId`, `name`, `path`, `architecture`, `wow64`, `startTimeUtc`, `runtime`, `access`, `moduleCount`, `modulesOffset`, `modulesTruncated`, `modules`, `regionCount`, `regionsTotal`, `regionFilter`, `regionsOffset`, `regionsTruncated`, `regions`, `threadCount`, `threadsOffset`, `threadsTruncated`, `threads`, `detached`, `handlesOpened`, `handlesClosed`, `stillRunning`, `elapsedMs`, `notes`.
