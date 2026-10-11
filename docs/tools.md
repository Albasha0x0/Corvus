# Tools

<!-- Generated from the tool catalog by DocsTests; run the tests with CORVUS_UPDATE_DOCS=1 to update. -->

155 tools in 13 toolsets. A server registers every tool unless it is started with `--toolsets` (README, "Server options"). From a terminal, `NetDecompilerMcp describe <tool>` prints the same reference and `NetDecompilerMcp <tool> name=value ...` calls a tool ([cli.md](cli.md)).

Annotations: **read-only** tools change nothing; **edit** tools change the in-memory workspace; **destructive** tools can remove or overwrite state; **long-running** tools can take more than 10 s and have no call deadline.

| Toolset | In `core` | Tools |
|---|---|---|
| [session](#session) | yes | 9: workspace and server state |
| [dotnet](#dotnet) | yes | 25: .NET browse, decompile, search, navigate, resources, ReadyToRun, project export |
| [containers](#containers) | yes | 7: file inspection, containers and wrapped apps, Unity overview |
| [edit](#edit) | yes | 15: .NET edits, edit history and saving |
| [il2cpp](#il2cpp) | yes | 5: Il2Cpp metadata, addresses, symbols and bindings |
| [native](#native) | yes | 32: native PE analysis, symbols and decompilation |
| [native-edit](#native-edit) | yes | 9: native names, comments, patches and saving |
| [builds](#builds) | yes | 10: build-to-build comparison and carrying work to a new build |
| [notes](#notes) | yes | 3: analyst notes kept per binary across sessions |
| [engine](#engine) | no | 12: edits inside the decompiler engine's database: types, locals, frames, declarations, scripting |
| [android](#android) | no | 20: Android packages: manifest, resources, DEX code, Java decompilation, Java / .NET mapping, devices |
| [dumps](#dumps) | no | 7: crash dumps and crash text |
| [live](#live) | no | 1: read-only inspection of a running process |

## session

Workspace and server state.

### load_assembly

**Load assembly** (edit, idempotent, long-running)

Load a .NET assembly (.dll/.exe) or every assembly in a directory (an application folder, a Unity *_Data/Managed or Il2CppDumper DummyDll folder). A native PE, ELF or Mach-O file given by path loads as a native image for the native tools (a universal Mach-O: one slice, as name[slice]); folder loads take only .NET assemblies and list the native files skipped. An Il2Cpp game (its folder or global-metadata.dat, an .apk/.xapk/.aab/.ipa, an iOS .app, or a memory dump of the binary) is read by the built-in metadata reader (v24-39): dummy assemblies with addresses, offsets and tokens, cached per user, plus the binary as a native image; unreadable metadata is an error with a reason. Files are read into memory, never locked; the directory joins the reference search path; loading a path twice is a no-op.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `path` | string | yes |  | Absolute path to an assembly file or a directory. |
| `recursive` | boolean |  | `false` | When path is a directory, also load assemblies in subdirectories. |
| `loadProviders` | boolean |  | `false` | For a file: also load the DLLs its imports bind to (one level, at most 16), so the call tools continue into them. |
| `slice` | string |  |  | Universal Mach-O slice (name or index; default arm64e, arm64, x86_64), or an Android Il2Cpp game's ABI (default arm64-v8a). Values: arm64e, arm64, x86_64, x86_64h, arm64_32, armv7, armv7s, armv7k, i386, arm64-v8a, armeabi-v7a, x86. |

### unload_assembly

**Unload assembly** (destructive, idempotent)

Remove an assembly from the workspace (unsaved edits are discarded).

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `assembly` | string | yes |  | Assembly id, name, file name or path. |

### reload_assembly

**Reload assembly** (destructive, idempotent)

Re-read an assembly from disk (after an update or an overwriting save_assembly), discarding unsaved edits.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `assembly` | string | yes |  | Assembly id, name, file name or path. |

### add_search_directory

**Add reference search directory** (edit, idempotent)

Add a directory for resolving referenced assemblies that are not loaded (an application or framework folder), for decompilation, navigation and C# patching.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `directory` | string | yes |  | Directory path. |

### list_assemblies

**List loaded assemblies** (read-only, idempotent)

Loaded assemblies with their ids (for other tools), versions, paths, Il2Cpp dummy, ReadyToRun and merged (ILMerge / ILRepack) flags and unsaved edits; plus the reference search directories. With path: the managed assemblies inside a container file (single-file bundle, .nupkg, .apk / .aab, Costura host, zip) without extracting them (unpack_container extracts and loads them).

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `path` | string |  |  | A container file to list instead of the workspace. |
| `filter` | string |  |  | Id, name or path substring (case-insensitive). |
| `offset` | integer |  | `0` | Index of the first assembly. |
| `limit` | integer |  | `100` | Max assemblies. |

Structured output: `assemblies`, `searchDirectories`, `backgroundIndexing`, `container`, `total`, `nativeImages`.

### server_status

**Server status** (read-only, idempotent, open-world)

Which server runs (version, program, install kind, client), a catalog digest, what is loaded, limits, long-running tools, capabilities with the fix when missing, tool families, unusable tools, and engine sessions (busy op, queue). expectedCatalogDigest detects a stale server; expectedExecutable checks the registered copy.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `expectedCatalogDigest` | string |  |  | Catalog digest to compare (t92-0123456789ab.p5-01234567). |
| `expectedExecutable` | string |  |  | Registered server program path, compared with the running one. |

Structured output: `version`, `informationalVersion`, `executable`, `executableMatches`, `installKind`, `startedAt`, `uptimeSeconds`, `protocolVersion`, `client`, `catalogDigest`, `catalogMatches`, `catalogDifference`, `tools`, `loadedAssemblies`, `backgroundIndexing`, `maxOutputChars`, `timeoutSeconds`, `workingSetMB`, `capabilities`, `longRunningTools`, `toolsets`, `unavailableTools`, `notes`, `engineTimeLimits`, `engineSessions`, `toolsFileAndTrace`.

### read_result

**Read a kept result** (read-only, idempotent)

Page through a result too large to send (named by a limit_exceeded error); kept while memory allows.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `id` | string | yes |  | Result id from the error, e.g. r3. |
| `offset` | integer |  | `0` | Character offset from the truncation footer. |
| `maxChars` | integer |  |  | Page size in characters (default ~60000). |

### save_session

**Save the session** (destructive, idempotent)

Write this session's work to one JSON file: every loaded file (path, relative path, SHA-256), .NET edits, native patches, names and comments, notes, Il2Cpp games and open minidumps. load_session restores it here or on another machine.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `path` | string | yes |  | Output file path (.json). |
| `overwrite` | boolean |  | `false` | Replace the file if it exists. |
| `include` | string |  |  | Comma-separated parts: edits, patches, annotations, notes or all (default); files are always listed. |

Structured output: `path`, `files`, `editedAssemblies`, `edits`, `patchedImages`, `patches`, `names`, `comments`, `notes`.

### load_session

**Load a session** (destructive, long-running)

Restore a save_session file: find each file (recorded path, relative path, else by SHA-256 under searchRoots), load it, then apply names and comments (never replacing a different user name), patches and edits, and import notes; one outcome per item with a reason. A changed file is refused unless targetBuild=other, which carries the work to the build now at the recorded path (edits by name, native work through the function match, which needs the old build found under searchRoots).

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `path` | string | yes |  | The session file. |
| `dryRun` | boolean |  | `true` | Report only. |
| `targetBuild` | string |  |  | same (default) or other. Values: same, other. |
| `searchRoots` | string |  |  | ';'-separated folders searched recursively for moved files, by SHA-256. |
| `include` | string |  |  | Comma-separated parts: edits, patches, annotations, notes or all (default); files are always loaded. |
| `offset` | integer |  | `0` | Items to skip. |
| `limit` | integer |  | `200` | Items to return (max 2000). |

Structured output: `path`, `dryRun`, `targetBuild`, `outcomes`, `offset`, `total`, `truncated`, `items`, `notes`.

## dotnet

.NET browse, decompile, search, navigate, resources, ReadyToRun, project export.

### list_namespaces

**List namespaces** (read-only, idempotent)

List namespaces with their type counts (nested types under their outer type's namespace).

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `assembly` | string |  |  | Assembly id, name, file name or path; omit for all loaded. |
| `filter` | string |  |  | Substring (case-insensitive). |
| `offset` | integer |  | `0` | Index of the first namespace. |
| `limit` | integer |  | `2000` | Max namespaces. |

Structured output: `items`, `offset`, `total`, `truncated`.

### list_types

**List types** (read-only, idempotent)

List types, optionally by namespace, name filter and kind.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `assembly` | string |  |  | Assembly id, name, file name or path; omit for all loaded. |
| `namespace` | string |  |  | Exact namespace ('' or '<global>' for the global one). |
| `filter` | string |  |  | Name substring or wildcard (*, ?), or a regex with regex=true. |
| `regex` | boolean |  | `false` | Treat filter as a regular expression. |
| `kind` | string |  |  | Only this kind. Values: class, struct, interface, enum, delegate. |
| `includeNested` | boolean |  | `true` | Include nested types. |
| `offset` | integer |  | `0` | Index of the first result. |
| `limit` | integer |  | `300` | Max results. |

Structured output: `items`, `offset`, `total`, `truncated`, `notEvaluated`.

### get_type_info

**Type outline** (read-only, idempotent)

Outline of a type without decompiling: declaration, attributes, nested types, fields (constants, enum values with hex, Il2Cpp offsets), properties, events and method signatures with tokens, IL sizes and Il2Cpp RVAs.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `type` | string | yes |  | Type or member: 'Ns.Type', 'Ns.Outer+Inner', 'Ns.Type::Method(int, string)', a short name or a token (0x06000123). |
| `assembly` | string |  |  | Assembly id, name, file name or path; omit for all loaded. |
| `includeCompilerGenerated` | boolean |  | `false` | Include compiler-generated members (backing fields, lambdas, state machines). |

Structured output: `type`, `fullName`, `declaration`, `declaringType`, `attributes`, `nestedTypes`, `fields`, `properties`, `events`, `methods`, `compilerGeneratedHidden`, `truncated`.

### get_assembly_info

**Assembly overview** (read-only, idempotent)

Assembly overview: identity (MVID, SHA-256), target framework, entry point, counts, references (resolved or not), PE headers and sections, metadata streams, tables and heaps, metadata problems with file offsets, attributes, Il2Cpp detection, invalid IL bodies, unsaved edits.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `assembly` | string | yes |  | Assembly id, name, file name or path. |

Structured output: `id`, `fullName`, `file`, `sha256`, `mvid`, `runtime`, `kind`, `machine`, `targetFramework`, `entryPoint`, `types`, `nestedTypes`, `namespaces`, `methods`, `fields`, `resources`, `referenceAssembly`, `il2CppAddressedMethods`, `invalidBodies`, `invalidExceptionClauses`, `unsavedEdits`, `references`, `attributes`, `tables`, `heaps`, `metadataIssueCount`, `metadataIssues`.

### get_attributes

**Custom attributes** (read-only, idempotent)

Custom attributes with arguments on a type, member (with parameter and return attributes), or the assembly / module when symbol is omitted. Everything carrying an attribute: find_references on the attribute type.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `symbol` | string |  |  | Type or member: 'Ns.Type', 'Ns.Outer+Inner', 'Ns.Type::Method(int, string)', a short name or a token (0x06000123). Omit for assembly-level attributes. |
| `assembly` | string |  |  | Assembly id, name, file name or path; omit for all loaded. Required when symbol is omitted. |
| `filter` | string |  |  | Only attributes whose type name contains this text. |

### get_type_hierarchy

**Type hierarchy** (read-only, idempotent)

A type's base chain, all implemented interfaces, and the types deriving from (or implementing) it directly across loaded assemblies.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `type` | string | yes |  | Type or member: 'Ns.Type', 'Ns.Outer+Inner', 'Ns.Type::Method(int, string)', a short name or a token (0x06000123). |
| `assembly` | string |  |  | Assembly id, name, file name or path; omit for all loaded. |
| `limit` | integer |  | `200` | Max derived types listed. |

### resolve_symbol

**Resolve symbol** (read-only, idempotent)

What a symbol string or token resolves to: every match with kind, assembly, token and signature, to disambiguate before other calls.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `symbol` | string | yes |  | Type or member: 'Ns.Type', 'Ns.Outer+Inner', 'Ns.Type::Method(int, string)', a short name or a token (0x06000123). |
| `assembly` | string |  |  | Assembly id, name, file name or path; omit for all loaded. |
| `kind` | string |  |  | Restrict to this kind. Values: any, type, method, field, property, event, member. |

Structured output: `items`, `offset`, `total`, `truncated`, `notEvaluated`.

### decompile_type

**Decompile type to C#** (read-only, idempotent)

Decompile a whole type (nested types included) to C#; decompile_member is cheaper for one method. A method that breaks the decompiler is shown as IL.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `type` | string | yes |  | Type or member: 'Ns.Type', 'Ns.Outer+Inner', 'Ns.Type::Method(int, string)', a short name or a token (0x06000123). |
| `assembly` | string |  |  | Assembly id, name, file name or path; omit for all loaded. |
| `simplified` | boolean |  | `false` | Show the code as simplify_methods would leave it, without changing the assembly. |
| `offset` | integer |  | `0` | Character offset from the truncation footer. |
| `maxChars` | integer |  |  | Page size in characters (default ~60000). |

### decompile_member

**Decompile member to C#** (read-only, idempotent)

Decompile a method, property, field, event or constructor to C#: every overload unless a parameter list narrows it; async / iterator state machines and lambdas fold back into the method. A type name decompiles the whole type.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `member` | string | yes |  | Type or member: 'Ns.Type', 'Ns.Outer+Inner', 'Ns.Type::Method(int, string)', a short name or a token (0x06000123). |
| `assembly` | string |  |  | Assembly id, name, file name or path; omit for all loaded. |
| `kind` | string |  |  | Restrict to this kind (default any). Values: any, method, field, property, event. |
| `simplified` | boolean |  | `false` | Show the code as simplify_methods would leave it, without changing the assembly. |
| `provenance` | boolean |  | `false` | Start with comments pinning the output to its build: SHA-256, MVID, tokens, IL hashes (docs/il-hash.md). |
| `offset` | integer |  | `0` | Character offset from the truncation footer. |
| `maxChars` | integer |  |  | Page size in characters (default ~60000). |

### decompile_assembly_attributes

**Decompile assembly attributes** (read-only, idempotent)

Decompile assembly- and module-level attributes (InternalsVisibleTo, versions, TargetFramework...) to C#.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `assembly` | string | yes |  | Assembly id, name, file name or path. |

### get_il

**IL disassembly** (read-only, idempotent)

IL disassembly (ildasm style, /* token */ comments, offsets, try blocks) of a member or type; each method starts with its normalized IL hash (stable across rebuilds) and raw IL SHA-256. For when the C# looks wrong, transformed code, or as patch_method_il input.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `symbol` | string | yes |  | Type or member: 'Ns.Type', 'Ns.Outer+Inner', 'Ns.Type::Method(int, string)', a short name or a token (0x06000123). |
| `assembly` | string |  |  | Assembly id, name, file name or path; omit for all loaded. |
| `offset` | integer |  | `0` | Character offset from the truncation footer. |
| `maxChars` | integer |  |  | Page size in characters (default ~60000). |

### search_symbols

**Search symbols by name** (read-only, idempotent)

Find types and members by name across loaded assemblies: a case-insensitive substring, wildcard (Get*Value?) or regex; queries with '.' or '::' also match full names; exact matches first.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `query` | string | yes |  | Name, substring, wildcard or regex. |
| `kind` | string |  |  | Restrict to this kind. Values: any, type, method, field, property, event, member. |
| `assembly` | string |  |  | Assembly id, name, file name or path; omit for all loaded. |
| `namespace` | string |  |  | Only types in namespaces starting with this. |
| `regex` | boolean |  | `false` | Treat query as a regular expression. |
| `limit` | integer |  | `100` | Max results. |
| `offset` | integer |  | `0` | Index of the first result. |

Structured output: `items`, `offset`, `total`, `truncated`, `notEvaluated`.

### search_strings

**Search string literals** (read-only, idempotent)

Find string literals (ldstr and string constants) by substring, wildcard or regex, with the method and IL offset using each: code from UI text, log messages, URLs, keys. For Il2Cpp dummy DLLs: the game's literals with their slot RVA and, with the binary, the native functions that load them, by method name.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `query` | string | yes |  | Substring, wildcard or regex. |
| `assembly` | string |  |  | Assembly id, name, file name or path; omit for all loaded. |
| `regex` | boolean |  | `false` | Treat query as a regular expression. |
| `limit` | integer |  | `200` | Max results. |
| `offset` | integer |  | `0` | Index of the first result. |
| `usesPerLiteral` | integer |  | `10` | Il2Cpp: max functions listed per literal. |

Structured output: `items`, `offset`, `total`, `truncated`, `notEvaluated`.

### search_constants

**Search numeric constants** (read-only, idempotent)

Find a numeric constant (magic number, opcode id, flag, crypto constant) in IL literals, const and enum values, attribute arguments and static array data (lookup and crypto tables, read as the array's element type).

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `value` | string | yes |  | Decimal, 0x hex, negative or floating-point. |
| `assembly` | string |  |  | Assembly id, name, file name or path; omit for all loaded. |
| `limit` | integer |  | `200` | Max results. |
| `offset` | integer |  | `0` | Index of the first result. |

Structured output: `value`, `items`, `offset`, `total`, `truncated`.

### search_il

**Search IL instruction patterns** (read-only, idempotent)

Find methods containing an IL instruction sequence: elements separated by ';' or newlines, each 'opcode [operand]' with * and ? wildcards (operands match member and type names, strings, numbers); '...' skips up to 16 instructions. Example: 'ldstr *password*; ...; call *::Hash*'.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `pattern` | string | yes |  | Instruction pattern. |
| `assembly` | string |  |  | Assembly id, name, file name or path; omit for all loaded. |
| `limit` | integer |  | `100` | Max matches. |
| `offset` | integer |  | `0` | Index of the first match. |

Structured output: `items`, `offset`, `total`, `truncated`.

### find_references

**Find usages (xrefs to)** (read-only, idempotent)

Every usage of a symbol across loaded assemblies ('Used By'): a method's call sites (also through the base / interface method it implements), a field's reads, writes and address-taken uses, accessor calls, a type's every use (bases, signatures, locals, casts, attributes, ...). A native export lists its P/Invoke declarations with their call sites and native call sites in loaded images; C++/CLI native callers are included.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `symbol` | string | yes |  | Type or member: 'Ns.Type', 'Ns.Outer+Inner', 'Ns.Type::Method(int, string)', a short name or a token (0x06000123). Or a native export ('kernel32.dll!CreateFileW', 'native:<image>!<name\|#ordinal\|address>'): its P/Invoke declarations and their callers. |
| `assembly` | string |  |  | Assembly defining the symbol (only to disambiguate; all loaded ones are searched). |
| `kind` | string |  |  | Restrict symbol resolution to this kind. Values: type, method, field, property, event. |
| `includeVirtualCalls` | boolean |  | `true` | Methods: include calls through base / interface declarations. |
| `limit` | integer |  | `300` | Max results. |
| `offset` | integer |  | `0` | Index of the first reference. |

Structured output: `target`, `items`, `nativeCallSites`, `offset`, `total`, `truncated`.

### find_callees

**What a method uses (xrefs from)** (read-only, idempotent)

What a method uses ('Uses'): calls, field reads / writes, types instantiated or cast, and strings, in IL order with offsets. P/Invoke calls show the native code they bind to ('native: module!export -> PROVIDER!export at VA [image]'); for a P/Invoke or native export, its native callees.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `method` | string | yes |  | Type or member: 'Ns.Type', 'Ns.Outer+Inner', 'Ns.Type::Method(int, string)', a short name or a token (0x06000123). Or a native export ('kernel32.dll!CreateFileW', 'native:<image>!<name\|#ordinal\|address>'): its P/Invoke declarations and their callers. |
| `assembly` | string |  |  | Assembly id, name, file name or path; omit for all loaded. |
| `distinct` | boolean |  | `false` | Collapse repeated targets into one line with a count. |
| `offset` | integer |  | `0` | Index of the first entry. |
| `limit` | integer |  | `2000` | Max entries. |

Structured output: `method`, `items`, `nativeLines`, `offset`, `total`, `truncated`.

### find_overrides

**Find overrides / implementations** (read-only, idempotent)

Methods overriding a virtual / abstract method or implementing an interface method (explicitly or implicitly), across loaded assemblies.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `method` | string | yes |  | Type or member: 'Ns.Type', 'Ns.Outer+Inner', 'Ns.Type::Method(int, string)', a short name or a token (0x06000123). |
| `assembly` | string |  |  | Assembly id, name, file name or path; omit for all loaded. |
| `limit` | integer |  | `200` | Max results. |
| `offset` | integer |  | `0` | Index of the first result. |

Structured output: `method`, `items`, `offset`, `total`, `truncated`.

### get_call_tree

**Call tree (callers / callees)** (read-only, idempotent)

Multi-level callers or callees of a method across loaded assemblies; callers include calls through base / interface methods it implements, repeats and recursion are marked. Callees continue through P/Invokes and C++/CLI native bodies into loaded native images ('native: module!export -> PROVIDER!export at VA [image]'); native callers (C++/CLI thunks) are listed too. Given a native export, callers are its native call sites and its P/Invoke declarations with their managed callers.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `method` | string | yes |  | Type or member: 'Ns.Type', 'Ns.Outer+Inner', 'Ns.Type::Method(int, string)', a short name or a token (0x06000123). Or a native export ('kernel32.dll!CreateFileW', 'native:<image>!<name\|#ordinal\|address>'): its P/Invoke declarations and their callers. |
| `direction` | string |  | `callers` | callers or callees. Values: callers, callees. |
| `depth` | integer |  | `3` | Levels to expand (1-8). |
| `maxNodes` | integer |  | `300` | Stop after this many nodes. |
| `includeExternal` | boolean |  | `false` | Callees: also calls into assemblies not loaded (framework). |
| `assembly` | string |  |  | Assembly id, name, file name or path; omit for all loaded. |
| `offset` | integer |  | `0` | Character offset from the truncation footer. |
| `maxChars` | integer |  |  | Page size in characters (default ~60000). |

Structured output: `root`, `direction`, `depth`, `items`, `total`, `truncated`.

### find_call_paths

**Call paths to a method** (read-only, idempotent)

How execution reaches a method: call chains from 'from' to 'to', or from entry points (methods nothing loaded calls: Main, callbacks, event handlers). Shortest first, direct calls preferred; hops through virtual dispatch are marked. 'to' may be native (an export, an import of an unloaded library, native:<image>!<address or function>): chains then run through native callers across loaded images (calls, imports, engine references, RTTI virtual calls, function pointers) back to native roots and to managed callers through P/Invoke, each step with its call site and edge kind.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `to` | string | yes |  | Target. Type or member: 'Ns.Type', 'Ns.Outer+Inner', 'Ns.Type::Method(int, string)', a short name or a token (0x06000123). Or a native export ('kernel32.dll!CreateFileW', 'native:<image>!<name\|#ordinal\|address>'): its P/Invoke declarations and their callers. |
| `from` | string |  |  | Start method, same forms as to (native only when to is native). |
| `maxDepth` | integer |  | `8` | Max chain length (max 30). |
| `maxPaths` | integer |  | `10` | Max paths. |
| `includeVirtual` | boolean |  | `true` | Follow virtual dispatch (native: RTTI virtual calls, resolved function pointers); false avoids chains through widely overridden methods. |
| `assembly` | string |  |  | Assembly id, name, file name or path; omit for all loaded. |

Structured output: `target`, `from`, `items`, `total`, `truncated`.

### list_resources

**List manifest resources** (read-only, idempotent)

List manifest resources: embedded files, .resources containers (with entry counts), linked resources. For a native image, its Win32 resources as TYPE/NAME/LANGUAGE.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `assembly` | string | yes |  | Assembly id, name, file name or path. |

Structured output: `assembly`, `items`, `total`, `truncated`.

### get_resource

**Read / extract resource** (destructive, idempotent)

Read a resource: text as text, binary as hex preview, .resources as an entry list (entry reads one; .baml as XAML); savePath extracts the raw bytes. Native images: TYPE/NAME[/LANGUAGE], version info and string tables decoded.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `assembly` | string | yes |  | Assembly id, name, file name or path. |
| `name` | string | yes |  | Name from list_resources. |
| `entry` | string |  |  | Entry inside a .resources container. |
| `savePath` | string |  |  | Write the raw bytes to this file. |
| `overwrite` | boolean |  | `false` | Replace savePath if it exists. |
| `offset` | integer |  | `0` | Character offset from the truncation footer. |
| `maxChars` | integer |  |  | Page size in characters (default ~60000). |

### export_project

**Export C# project** (edit, idempotent, long-running)

Decompile an assembly into a C# project on disk (.cs per type, .csproj, resources), to grep or browse a large codebase with file tools. An .apk / .aab path gives a Gradle project (decoded manifest and resources, Java through JADX when configured, else smali).

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `assembly` | string | yes |  | Assembly id, name, file name or path. |
| `outputDirectory` | string | yes |  | Empty or new output directory. |

### get_r2r_code

**ReadyToRun native code of a method** (read-only, idempotent)

The precompiled native code of a method in a ReadyToRun assembly (including the shared framework): entry address, code ranges (hot, funclets, cold), the fixup import cells, and x86 / x64 disassembly with cells named by what they resolve to (methods, type handles, helpers, strings). Generic methods show each compiled instantiation; composite images are read from the composite file.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `method` | string | yes |  | Type or member: 'Ns.Type', 'Ns.Outer+Inner', 'Ns.Type::Method(int, string)', a short name or a token (0x06000123). |
| `assembly` | string |  |  | Assembly id, name, file name or path; omit for all loaded. A full path to an assembly that is not loaded yet loads it. |
| `instantiation` | string |  |  | Only bodies whose name contains this text ('Int32', '__Canon'). |
| `maxBodies` | integer |  | `4` | Max bodies disassembled; the rest are listed with addresses. |
| `maxInstructions` | integer |  | `5000` | Max instructions per body. |
| `offset` | integer |  | `0` | Character offset from the truncation footer. |
| `maxChars` | integer |  |  | Page size in characters (default ~60000). |

### find_r2r_method

**Managed method at a ReadyToRun address** (read-only, idempotent)

The managed method whose ReadyToRun code contains a native address (from a dump, profiler or debugger): name, token, range, offset and the instruction there; an import cell is described by what it resolves to. Addresses are in the file holding the code.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `assembly` | string | yes |  | Assembly id, name, file name or path. A full path to an assembly that is not loaded yet loads it. |
| `address` | string | yes |  | A VA or RVA in the code image (rva:/va:/off: prefix). |

## containers

File inspection, containers and wrapped apps, Unity overview.

### summarize_file

**Summarize file** (read-only, idempotent)

First look at any file or loaded assembly, without executing it: hashes, type, entropy; per managed assembly identity, signature (strong name, Authenticode), toolchain markers, container wrapping, features with ATT&CK techniques, extracted values and entry points (Main, module initializer, exports, installer / service / COM hooks). Containers (single-file bundles, packages, APKs, zips, Costura) are opened: the app's assembly in full, up to 7 more in brief; an apphost's .dll is summarized as the app. Also: NativeAOT runtime and recovery counts, ELF / Mach-O format, signature and encryption, packers and protectors, Android package, SDKs, runtimes, ABIs and exported components, and for a loaded native image triage (entry points, top functions, strings, import groups).

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `path` | string |  |  | Any file (assembly, bundle, .nupkg, .apk, zip, native executable); pass this or assembly. |
| `assembly` | string |  |  | A loaded assembly; pass this or path. |

Structured output: `file`, `container`, `assemblies`, `highlights`, `notes`, `nativeAot`, `nativeImage`, `packers`, `android`, `triage`.

### survey_features

**Survey features** (read-only, idempotent)

Rule-based (capa-style) survey of the APIs an assembly calls, its P/Invokes and strings: network, execution, registry, persistence, collection, anti-analysis, evasion, code loading, injection, discovery, crypto; each feature with its ATT&CK technique and evidence (up to 5 locations). Native images get the same rules over static and GetProcAddress imports, call arguments, strings, sections and RTTI names, by address and function.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `assembly` | string |  |  | A loaded assembly; pass this or path. |
| `path` | string |  |  | A .NET or native file to analyze without loading it; pass this, assembly or image. |
| `category` | string |  |  | Only this category (network, injection, ...) or ATT&CK technique prefix (T1055). |
| `image` | string |  |  | A loaded native image (instead of assembly). |

Structured output: `assembly`, `methodsScanned`, `features`, `notes`.

### extract_strings

**Extract typed strings** (destructive, idempotent)

Typed values (URLs, domains, IPs, emails, file paths, pipes, registry keys, mutexes, user agents, crypto keys) from an assembly's literals, constants, resource text and decoded base64 / hex / compressed text, each with count, locations and the APIs it is passed to; savePath exports JSON or CSV.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `assembly` | string |  |  | A loaded assembly; pass this or path. |
| `path` | string |  |  | A .NET assembly file to analyze without loading it; pass this or assembly. |
| `types` | string |  |  | Only these comma-separated types: url, domain, ipv4, ipv6, email, file_path, named_pipe, registry_key, mutex, user_agent, crypto_key. |
| `savePath` | string |  |  | Write the values to this file. |
| `format` | string |  |  | json (default) or csv (implied by a .csv savePath). Values: json, csv. |
| `overwrite` | boolean |  | `false` | Replace savePath if it exists. |

Structured output: `assembly`, `total`, `values`, `savedTo`, `notes`.

### extract_embedded

**Extract embedded content** (edit, idempotent)

Embedded content of an assembly (resources, static byte arrays, long string literals) decoded through hex, base64, compression and XOR (key from a known header) until a PE, archive, ELF / Mach-O or text appears, plus high-entropy blobs; each with its source and encoding chain. save=true writes them (defanged names), load=true also loads the .NET ones. Nothing is executed.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `assembly` | string |  |  | A loaded assembly; pass this or path. |
| `path` | string |  |  | A .NET assembly file to analyze without loading it; pass this or assembly. |
| `save` | boolean |  | `false` | Write the items to disk. |
| `outputDirectory` | string |  |  | New or empty directory (or an earlier extraction of the same file); default under temp. |
| `load` | boolean |  | `false` | Load the .NET assemblies found into the workspace (implies save). |
| `xorText` | boolean |  | `false` | Also recover 1-16 byte XOR keys over unreadable data, keeping clearly natural text or configuration (heuristic, slower). |
| `includeMedia` | boolean |  | `false` | Also list and save images (else only counted). |

Structured output: `assembly`, `contents`, `outputDirectory`, `notes`.

### search_container

**Search inside a container** (read-only, idempotent)

Find types and members by name in every managed assembly inside a container (bundle, .nupkg, .apk / .aab, Costura, zip, nested) or an assembly, without extracting or loading: a case-insensitive substring with * / ? wildcards ('.' or ':' also match full names); each match with its inner path, assembly, full name and kind.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `path` | string | yes |  | Absolute path to the container or assembly file. |
| `query` | string | yes |  | Name or part of a name. |
| `kind` | string |  |  | Restrict to this kind; omit for all (events included). Values: type, method, field, property. |
| `limit` | integer |  | `200` | Max matches (max 5000). |

Structured output: `source`, `container`, `assembliesSearched`, `matches`, `total`, `truncated`, `notes`.

### unpack_container

**Unpack container** (edit, idempotent, long-running)

Extract the .NET assemblies inside a container and load them: single-file bundles, Costura.Fody, NuGet packages, Xamarin / MAUI .apk / .aab (compressed assemblies and assembly stores, per ABI), zips, and .NET images embedded elsewhere; nested containers too. Nothing is executed; names cannot escape the output directory and runnable extensions get .bin. NativeAOT executables (no IL) are reported.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `path` | string | yes |  | Absolute path to the container file. |
| `outputDirectory` | string |  |  | New or empty directory, or an earlier unpack of the same file; default under temp. |
| `load` | boolean |  | `true` | Load the extracted assemblies (ids in loadedAs). |

Structured output: `source`, `container`, `outputDirectory`, `files`, `notes`.

### unity_overview

**Unity title overview** (read-only, idempotent, open-world)

Overview of a Unity title in seconds, without loading it (listings, headers and version resources only): engine version per source with their agreement, scripting backend (il2cpp / mono) with evidence, metadata version and state (readable, encrypted, header_tampered, unsupported_version, missing), toolchain and middleware markers, platform, architecture, notable folders, and the next calls (load_assembly the Managed folder or the metadata, or dump from memory). Not Unity: unsupported, reason not_a_unity_title.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `path` | string | yes |  | The title's folder, executable, *_Data folder, UnityPlayer.dll, GameAssembly.dll or global-metadata.dat; an extracted APK folder or a macOS / iOS .app. |
| `detectItEasy` | boolean |  | `false` | Also run Detect It Easy (diec, CORVUS_DIE or PATH) on the main binaries; launches it, about a second per file. |

Structured output: `input`, `gameDirectory`, `dataDirectory`, `executable`, `company`, `product`, `platform`, `architecture`, `architectureSource`, `engine`, `backend`, `markers`, `folders`, `nextSteps`, `notes`, `elapsedSeconds`.

## edit

.NET edits, edit history and saving.

### rename_symbol

**Rename symbol** (destructive)

Rename a type, method, field, property (with its accessors) or event in memory. Other assemblies referencing the old name are not updated.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `symbol` | string | yes |  | Type or member: 'Ns.Type', 'Ns.Outer+Inner', 'Ns.Type::Method(int, string)', a short name or a token (0x06000123). |
| `newName` | string | yes |  | New name (for a type: the simple name without namespace). |
| `assembly` | string |  |  | Assembly id, name, file name or path; omit for all loaded. |
| `kind` | string |  |  | Restrict symbol resolution to this kind. Values: type, method, field, property, event. |
| `dryRun` | boolean |  | `false` | Preview the change without applying it. |

### rename_namespace

**Rename namespace** (destructive)

Move every type of a namespace (optionally its sub-namespaces) to a new namespace, in memory.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `assembly` | string | yes |  | Assembly id, name, file name or path. |
| `oldNamespace` | string | yes |  | Existing namespace ('' for the global namespace). |
| `newNamespace` | string | yes |  | New namespace. |
| `includeSubNamespaces` | boolean |  | `false` | Also rewrite namespaces that start with oldNamespace + '.'. |
| `dryRun` | boolean |  | `false` | Preview the change without applying it. |

### stub_method

**Stub method (return constant)** (destructive)

Replace a method's body with 'return <value>;' (or 'return;' for void) in memory: force a check to return true, disable a call.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `method` | string | yes |  | Type or member: 'Ns.Type', 'Ns.Outer+Inner', 'Ns.Type::Method(int, string)', a short name or a token (0x06000123). |
| `value` | string |  |  | true/false, an integer (decimal or 0x hex), a float, a "quoted string" or null; omit for void or default(T). |
| `assembly` | string |  |  | Assembly id, name, file name or path; omit for all loaded. |
| `dryRun` | boolean |  | `false` | Preview the change without applying it. |

### patch_method_csharp

**Replace method body with C#** (destructive)

Replace a method's body with C# statements compiled against the assembly and its references (private / internal members accessible). Methods, constructors and accessors; lambdas, LINQ, local functions, async and yield work. Compile errors give lines relative to your code. Returns the decompiled result.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `method` | string | yes |  | Type or member: 'Ns.Type', 'Ns.Outer+Inner', 'Ns.Type::Method(int, string)', a short name or a token (0x06000123). |
| `code` | string | yes |  | The new body's statements only. |
| `assembly` | string |  |  | Assembly id, name, file name or path; omit for all loaded. |
| `dryRun` | boolean |  | `false` | Preview the change without applying it. Shows the IL that would be written. |

### patch_method_il

**Rewrite method body in IL** (destructive)

Rewrite a method body from IL text, in memory (stack-validated first). Easiest: edit get_il's lines and pass them back (header lines ignored; /* token */ comments resolve operands exactly). Lines: '[label:] opcode [operand]'; operands are numbers, "strings", labels, switch (L1, L2), arg / local index or name, members ('Ns.Type::Method(int)') or tokens; '.local <type>' adds a local. mode=replace swaps the whole body (no try/catch); prepend inserts before the original code and can branch to its IL_xxxx labels.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `method` | string | yes |  | Type or member: 'Ns.Type', 'Ns.Outer+Inner', 'Ns.Type::Method(int, string)', a short name or a token (0x06000123). |
| `il` | string | yes |  | IL instructions, one per line. |
| `mode` | string |  | `replace` | replace or prepend. Values: replace, prepend. |
| `assembly` | string |  |  | Assembly id, name, file name or path; omit for all loaded. |
| `dryRun` | boolean |  | `false` | Preview the change without applying it. |

### add_members_csharp

**Add members to a type (C#)** (edit)

Add members written in C# to an existing class or struct: methods, fields, properties, events, constructors, nested types; compiled against the assembly (private / internal members accessible). Field and property initializers are not supported (initialize from a method).

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `type` | string | yes |  | The type to extend. Type or member: 'Ns.Type', 'Ns.Outer+Inner', 'Ns.Type::Method(int, string)', a short name or a token (0x06000123). |
| `code` | string | yes |  | C# member declarations. |
| `assembly` | string |  |  | Assembly id, name, file name or path; omit for all loaded. |
| `dryRun` | boolean |  | `false` | Preview the change without applying it. |

### add_types_csharp

**Add new types (C#)** (edit)

Add classes, structs, interfaces, enums or delegates written in C# (with their namespace) to an assembly; they can use its private / internal types. patch_method_csharp then calls into them from existing methods.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `assembly` | string | yes |  | Assembly id, name, file name or path. |
| `code` | string | yes |  | C# source declaring the new types. |
| `dryRun` | boolean |  | `false` | Preview the change without applying it. |

### simplify_methods

**Simplify method bodies** (destructive, long-running)

Compiler-style cleanup of method bodies in memory, for transformed code. Passes: fold (string decoder calls with constant inputs run in a safe IL interpreter and become literals), cfg (constant branches and switches, dead code, flattened control flow made sequential), inline (forwarders and static delegate call proxies call their real target). Each body is stack-verified or left unchanged; everything left alone is reported with a reason code (guide edits topic, docs/simplify.md). 5 s and 16 MB simulated memory per method. Preview without editing: decompile_member / decompile_type simplified=true.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `symbol` | string |  |  | A method, or a type (nested types included). Type or member: 'Ns.Type', 'Ns.Outer+Inner', 'Ns.Type::Method(int, string)', a short name or a token (0x06000123). Omit for the whole assembly. |
| `assembly` | string |  |  | Assembly id, name, file name or path; omit for all loaded. Required when symbol is omitted. |
| `passes` | string |  |  | Comma-separated passes: fold, cfg, inline (default: all). |
| `maxDepth` | integer |  |  | Max evaluation call depth (default 8). |
| `budget` | integer |  |  | Max IL instructions per evaluated call, nested calls included (default 100000). |
| `dryRun` | boolean |  | `false` | Preview the change without applying it. |
| `deterministicEnvironment` | boolean |  | `false` | Evaluate machine reads (module path, directories, special folders, environment, machine / user names) against fixed stand-ins (docs/simplify.md), so code depending on them folds; results then hold for that environment. Without it they are reported (external-io). |

### list_edits

**List unsaved edits** (read-only, idempotent)

The unsaved edits of an assembly, numbered in order (for undo_edit and diff_edits).

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `assembly` | string | yes |  | Assembly id, name, file name or path. |

### diff_edits

**Diff edits (before/after C#)** (read-only, idempotent)

Unified diff of the decompiled C# of every member the edits touched (or one edit's), before and after. Review before save_assembly.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `assembly` | string | yes |  | Assembly id, name, file name or path. |
| `number` | integer |  |  | Only this edit (number from list_edits). |
| `offset` | integer |  | `0` | Character offset from the truncation footer. |
| `maxChars` | integer |  |  | Page size in characters (default ~60000). |

### undo_edit

**Undo an edit** (destructive)

Undo the last edit or any earlier one by number: the remaining edits are re-applied to the original image; if one depended on the undone edit, nothing changes and the conflict is reported.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `assembly` | string | yes |  | Assembly id, name, file name or path. |
| `number` | integer |  |  | Edit number from list_edits; omit for the last. |

### revert_edits

**Discard all edits** (destructive, idempotent)

Discard every unsaved edit of an assembly (export_edits first keeps them as a script).

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `assembly` | string | yes |  | Assembly id, name, file name or path. |

### export_edits

**Export edits as a script** (destructive, idempotent)

Save an assembly's edits as a JSON edit script bound to its build (SHA-256, MVID, identity), for apply_edits on that build or, with targetBuild=other, on another one.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `assembly` | string | yes |  | Assembly id, name, file name or path. |
| `path` | string | yes |  | Output .json path. |
| `overwrite` | boolean |  | `false` | Replace path if it exists. |

### apply_edits

**Apply an edit script** (destructive)

Replay a JSON edit script (export_edits) onto an assembly; each edit reports ok/FAILED. On its own build recorded tokens are used; another build is refused unless targetBuild=other, which re-resolves symbols by name (following renames when the source build is loaded) and lists what was remapped. Scripts without a build binding apply with a warning.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `path` | string | yes |  | The .json edit script. |
| `assembly` | string |  |  | Target assembly; omit for the one named in the script. |
| `dryRun` | boolean |  | `false` | Apply every edit for real (compiled, stack-checked), report, then roll back. |
| `stopOnError` | boolean |  | `true` | Roll everything back on the first failure. |
| `targetBuild` | string |  | `same` | same: only the script's build; other: another build, symbols re-resolved by name. Values: same, other. |

### save_assembly

**Save patched assembly** (destructive, idempotent)

Write an assembly with its edits to a new file, atomically. Overwriting needs overwrite=true; the original is first copied to '<file>.bak', and one changed on disk since load is refused. Bodies and signatures no edit touched keep their original bytes; the result lists, with reason codes (docs/saving.md), members 'Changed by the writer' without an edit asking for it and those 'Kept byte-for-byte although invalid in the original'.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `assembly` | string | yes |  | Assembly id, name, file name or path. |
| `outputPath` | string |  |  | Output file path. Omit for '<original>.patched.dll'. |
| `overwrite` | boolean |  | `false` | Allow replacing an existing file. |
| `strict` | boolean |  | `false` | Write nothing when any member would be changed by the writer (default: save and list them). |

## il2cpp

Il2Cpp metadata, addresses, symbols and bindings.

### get_il2cpp_info

**Il2Cpp addresses and offsets** (read-only, idempotent)

Il2Cpp dummy DLLs (built-in reader, Il2CppDumper or Cpp2IL): native addresses (RVA, VA, file offset, vtable slot) of a method or every method of a type, field offsets and tokens. With script.json (always for the built-in reader): function bounds, methods sharing the code, MethodInfo slot, generic instantiations, a type's metadata slots (Ns.Type_TypeInfo), and names only script.json has ('List`1<int>::Add', 'Method$Ns.Type.M()'). With stringliteral.json and the binary: the string literals a method's code loads.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `symbol` | string | yes |  | Type or member: 'Ns.Type', 'Ns.Outer+Inner', 'Ns.Type::Method(int, string)', a short name or a token (0x06000123). Or a script.json name of an instantiation or metadata slot. |
| `assembly` | string |  |  | Assembly id, name, file name or path; omit for all loaded. |
| `slot` | string |  |  | With a type: a vtable slot number to resolve to its implementing method, or 'all'. |
| `offset` | integer |  | `0` | Index of the first entry of each long list. |
| `limit` | integer |  | `20` | Max entries of each long list. |

### find_method_by_address

**Native address to method** (read-only, idempotent)

Map a native address (from IDA, Ghidra or a crash log) of an Il2Cpp game to the method(s) whose function contains it, or the string literal, type metadata or MethodInfo slot at it; generic instantiations are named with script.json (without it a containing method is a guess). Code shared by many methods is paged.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `address` | string | yes |  | Hex as IDA / Ghidra show it ('0x1A2B3C', '1A2B3Ch', '00000001`8001A2B3'); 'd:' prefix for decimal. |
| `kind` | string |  | `auto` | auto: a VA at or above the image base, else an RVA, else a file offset. Values: auto, rva, va, offset. |
| `assembly` | string |  |  | Assembly id, name, file name or path; omit for all loaded. |
| `offset` | integer |  | `0` | Index of the first method to list when many share the code. |
| `limit` | integer |  | `20` | Max methods listed. |

### export_il2cpp_symbols

**Export IDA/Ghidra scripts** (destructive, idempotent, long-running)

Export Il2Cpp dummy-DLL metadata for native analysis: IDA Python and Ghidra scripts that create, name (Ns.Type$$Method) and comment every function (RVAs, so any image base works), a C header of struct layouts, and an Il2CppDumper-style script.json.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `outputDirectory` | string | yes |  | Output directory. |
| `formats` | string |  | `all` | Comma-separated: ida, ghidra, header, json or all. |
| `baseName` | string |  | `il2cpp` | Base name of the generated files. |
| `assembly` | string |  |  | Assembly id, name, file name or path; omit for all loaded. |
| `overwrite` | boolean |  | `false` | Replace files of the same names if they exist. |

### generate_cpp_binding

**Generate C++ binding** (read-only, idempotent)

Generate C++ binding code for a managed type of a Mono or Il2Cpp application: a struct that resolves the class, field offsets, static fields and methods once, with typed field accessors, property getters and invoke wrappers; class lookup strings come from the metadata. style=mono: a self-contained header on the Mono embedding API exports. style=il2cpp: one on the Il2Cpp runtime exports, plus each method's native code pointer (to hook) and a typed direct call. style=hostapi: for a host that passes a function table (FindClass, GetMethod, FieldOffset, StaticFieldOffset, GetStaticFieldData, Invoke). Without style it is detected from projectDir (such a table, or its own il2cpp_* / mono_* calls), an Il2Cpp dummy assembly, the server's --binding-style, else mono; the first output line says which and why. A generic definition (List`1) binds as a C++ template resolved with Resolve(api, instanceClass).

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `type` | string | yes |  | Type or member: 'Ns.Type', 'Ns.Outer+Inner', 'Ns.Type::Method(int, string)', a short name or a token (0x06000123). |
| `assembly` | string |  |  | Assembly id, name, file name or path; omit for all loaded. |
| `members` | string |  |  | Only these members (comma-separated names); default all but compiler-generated ones. |
| `includeInherited` | boolean |  | `false` | Also bind property getters inherited from base classes (base members named in members are bound anyway). |
| `style` | string |  |  | Omit to detect it. Values: mono, il2cpp, hostapi. |
| `projectDir` | string |  |  | The C/C++ project the header is for, scanned for a host function table and helpers. |
| `headerPath` | string |  |  | Where the header will be saved (absolute or relative to projectDir; default projectDir); #include paths are relative to it. |
| `offset` | integer |  | `0` | Character offset from the truncation footer. |
| `maxChars` | integer |  |  | Page size in characters (default ~60000). |

### apply_il2cpp_names

**Name a native Il2Cpp binary from its metadata** (destructive, idempotent, long-running)

Name the functions and data of a native Il2Cpp binary (GameAssembly, libil2cpp.so) from the loaded dummy assemblies, script.json (function starts, generic instantiations, TypeInfo and MethodInfo slots) and stringliteral.json. Functions become Ns_Type__Method (a C identifier; a duplicate gets _<RVA>), commented with Ns.Type::Method(args) and the methods sharing the code; every native tool and the engines show them, below user and PDB names. Saved per file hash and reapplied on load; applying again replaces them. Run it once the binary and the dummy assemblies are loaded.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `image` | string | yes |  | Native image id, file name or path (a path is loaded). |
| `assembly` | string |  |  | Dummy assemblies to use; omit for every loaded one with Il2Cpp metadata. |
| `clear` | boolean |  | `false` | Remove the il2cpp names (and their saved copy) instead of applying them. |

## native

Native PE analysis, symbols and decompilation.

### get_pe_info

**Native image overview** (read-only, idempotent)

Overview of a native image. PE: machine, kind, subsystem, base, entry point, timestamps, linker, sections (flags, entropy), packers, mitigations (ASLR, DEP, CFG, CET...), import / export counts, TLS callbacks, PDB identity, load config, version, manifest, rich header, checksum, overlay, signature, anything malformed. ELF: program headers, soname, build id, relocations, hardening. Mach-O: slice, segments, libraries, fixups, code signature, entitlements, encryption. Capabilities the imports imply. With the code index (not waited for): function statistics, RTTI classes, the most called and largest functions.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `image` | string | yes |  | Native image id, file name or path (a path is loaded). |
| `offset` | integer |  | `0` | Character offset from the truncation footer. |
| `maxChars` | integer |  |  | Page size in characters (default ~60000). |

Structured output: `image`, `path`, `machine`, `kind`, `format`, `subsystem`, `fileSize`, `sha256`, `imageBase`, `entryPoint`, `timestamp`, `dotNet`, `mitigationsOn`, `mitigationsOff`, `sections`, `importModules`, `importFunctions`, `delayImportModules`, `exports`, `tlsCallbacks`, `pdbPath`, `pdbGuid`, `pdbAge`, `signer`, `checksumMatches`, `overlaySize`, `issues`, `capabilities`, `code`.

### get_engine_status

**Engine status of a native image** (read-only, idempotent, open-world)

IDA and Ghidra sessions of a native image: opening (stage, seconds), failed, not started, or open with the engine's view (language, compiler, analysis complete or partial, warnings, counts, entry points, hashes, blocks, database, worker, unsaved edits). Starts no engine.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `image` | string | yes |  | Native image id, file name or path (a path is loaded). |
| `engine` | string |  |  | Default auto: both. Values: auto, ida, ghidra. |

Structured output: `image`, `engines`.

### list_imports

**List native imports** (read-only, idempotent, long-running)

Functions a native image imports, per DLL or library (delay-loaded and lazy binding marked), with the IAT slot address code calls through; API set names show the DLL they resolve to. bind=true binds each import like the loader to its export: 'at VA [image]' when the provider is loaded, its path when not (load it, or load_assembly loadProviders=true), or the reason it does not resolve. includeDynamic adds GetProcAddress imports with a constant name, marked [dynamic].

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `image` | string | yes |  | Native image id, file name or path (a path is loaded). |
| `module` | string |  |  | Only this DLL (name with or without .dll). |
| `filter` | string |  |  | Name substring (case-insensitive). |
| `bind` | boolean |  | `false` | Bind each import to the export it reaches, with a summary. |
| `offset` | integer |  | `0` | Index of the first row. |
| `limit` | integer |  | `500` | Max rows. |
| `includeDynamic` | boolean |  | `false` | Also list late-bound imports (waits for the code index). |

Structured output: `image`, `items`, `offset`, `total`, `truncated`, `bindings`.

### list_exports

**List native exports** (read-only, idempotent)

A native image's exported functions and data: ordinal, VA, name (demangled C++ form, ELF symbol version), forwarders and re-exports.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `image` | string | yes |  | Native image id, file name or path (a path is loaded). |
| `filter` | string |  |  | Name substring (case-insensitive; the demangled form too). |
| `offset` | integer |  | `0` | Index of the first row. |
| `limit` | integer |  | `500` | Max rows. |

Structured output: `image`, `items`, `offset`, `total`, `truncated`.

### resolve_address

**Resolve native address** (read-only, idempotent)

What an address in a native image is: RVA, VA and file offset, section and permissions, nearest export or import, name and its source; the Il2Cpp method or metadata slot, or the NativeAOT MethodTable, object or method; an IAT slot's bound export, an export's importers. With the code index: containing function and offset, instruction start, mid-instruction or data item, comment, references by kind. In a PDB global, the field there.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `image` | string | yes |  | Native image id, file name or path (a path is loaded). |
| `address` | string | yes |  | Hex VA or RVA (rva:/va:/off: prefix), export, module!import or function name. |

Structured output: `image`, `rva`, `va`, `fileOffset`, `section`, `access`, `name`, `nameSource`, `import`, `boundTo`, `export`, `lines`, `function`, `status`, `containingInstruction`, `dataItem`, `comment`, `referencesTo`.

### search_bytes

**Search native bytes** (read-only, idempotent)

Find a byte pattern in a native image's mapped sections (hex with ?? wildcards, or text as ASCII and UTF-16): each hit's VA, section and file offset.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `image` | string | yes |  | Native image id, file name or path (a path is loaded). |
| `pattern` | string | yes |  | Hex bytes with ?? wildcards ('48 8B 05 ?? ?? ?? ??'), or text when text=true. |
| `text` | boolean |  | `false` | pattern is text (ASCII and UTF-16LE). |
| `section` | string |  |  | Only this section (e.g. .text, .rdata). |
| `limit` | integer |  | `200` | Max hits. |
| `offset` | integer |  | `0` | Index of the first hit. |

### read_bytes

**Read native bytes or values** (read-only, idempotent)

Hex dump (with ASCII) of a native image's bytes at an address, as the loader maps them (.bss as ??). type= reads length values instead: u8-u64, i8-i64 (be suffix: u32be), f32, f64, ptr (target named), C names (int, DWORD, char *), cstr or wstr. Structs: get_native_type read=true.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `image` | string | yes |  | Native image id, file name or path (a path is loaded). |
| `address` | string | yes |  | Hex VA or RVA (rva:/va:/off: prefix), export, module!import or function name. |
| `length` | integer |  |  | Bytes to dump (default 256, max 65536); with type, values to read (default 1, max 4096). |
| `offset` | integer |  | `0` | Character offset from the truncation footer. |
| `maxChars` | integer |  |  | Page size in characters (default ~60000). |
| `type` | string |  |  | Value type to read instead of dumping bytes. |

### convert_number

**Convert a number** (read-only, idempotent)

Exact number conversions instead of mental arithmetic: signed and unsigned decimal, hex, binary and octal at a width, LE and BE bytes and their ASCII, the bits as float or double. Input: decimal, 0x or h-suffixed hex, 0b, 0o, negative, _ separators, C suffixes, 'ABCD' (C multi-character constant) or "text" (bytes in memory order).

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `numbers` | string[] | yes |  | Numbers to convert. |
| `size` | integer |  |  | Width in bytes: 1, 2, 4 or 8 (default: the smallest that fits). |

Structured output: `items`.

### list_functions

**List native functions** (read-only, idempotent, open-world, long-running)

Functions of a native image (x86 / x64 / ARM): address, size, name (user, PDB, Il2Cpp, export, module!import thunk or sub_<rva>), flags (thunk, arm (A32), noreturn, unresolved jumps, invalid code, funclets and exception chunks), how it was found and its caller count; an exact name filter adds an open engine's function record. The first call on an image waits for its code index (seconds; minutes for a very large image).

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `image` | string | yes |  | Native image id, file name or path (a path is loaded). |
| `filter` | string |  |  | Name filter: substring (case-insensitive), glob with * and ?, or /regex/ (flags i, m, s). |
| `sort` | string |  |  | address (default), name, size (largest first) or callers (most called first). Values: address, name, size, callers. |
| `offset` | integer |  | `0` | Index of the first row. |
| `limit` | integer |  | `300` | Max rows. |
| `engine` | string |  |  | auto (default): a finished IDA / Ghidra analysis of this session, else ours (the built-in index); never starts one. ida / ghidra: that engine, started when needed. Values: auto, ours, ida, ghidra. |
| `minSize` | integer |  |  | Smallest size in bytes. |
| `maxSize` | integer |  |  | Largest size in bytes. |
| `from` | string |  |  | Lowest start address. |
| `to` | string |  |  | Start addresses below this one. |
| `hasType` | boolean |  |  | Engines: true keeps functions with a prototype, false those without. |
| `descending` | boolean |  |  | Sort direction instead of the sort's default. |
| `view` | string |  |  | functions (default), or candidates: IDA or Ghidra code in no function, most referenced first. Values: functions, candidates. |

Structured output: `image`, `functions`, `items`, `offset`, `total`, `truncated`, `coverage`, `engine`, `engineNote`.

### list_globals

**List native globals** (read-only, idempotent, open-world, long-running)

Named data items of a native image outside code, from every name source (PDB with type and size, user names and types, Il2Cpp, NativeAOT, exports, symbol tables); with an engine also its defined data with type and value. get_native_type read=true reads one's fields.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `image` | string | yes |  | Native image id, file name or path (a path is loaded). |
| `filter` | string |  |  | Name substring (case-insensitive). |
| `section` | string |  |  | Only this section, e.g. .data. |
| `offset` | integer |  | `0` | Index of the first row. |
| `limit` | integer |  | `300` | Max rows. |
| `engine` | string |  |  | auto (default): a finished IDA / Ghidra analysis of this session, else ours (the built-in index); never starts one. ida / ghidra: that engine, started when needed. Values: auto, ours, ida, ghidra. |

Structured output: `image`, `items`, `offset`, `total`, `truncated`, `engine`.

### disassemble

**Disassemble native code** (read-only, idempotent, open-world, long-running)

MASM-syntax disassembly of the native function containing an address (with block labels), or of maxInstructions from the address when it is in no function or function=false. References are named, strings shown as comments, calls commented with their recovered arguments (see get_call_arguments); NativeAOT string loads and vtable slots are named too. Data in the way (strings, pointers, IAT slots, switch tables, gaps between blocks) is rendered as data; warnings (mid-instruction, data, bss) repeat in a footer. The first call on an image waits for its code index (seconds; minutes for a very large image).

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `image` | string | yes |  | Native image id, file name or path (a path is loaded). |
| `address` | string | yes |  | Hex VA or RVA (rva:/va:/off: prefix), export, module!import or function name. |
| `function` | boolean |  | `true` | The whole containing function; false: maxInstructions from the address. |
| `maxInstructions` | integer |  | `2000` | Max instructions. |
| `offset` | integer |  | `0` | Character offset from the truncation footer. |
| `maxChars` | integer |  |  | Page size in characters (default ~60000). |
| `engine` | string |  |  | auto (default): a finished IDA / Ghidra analysis of this session, else ours (the built-in index); never starts one. ida / ghidra: that engine, started when needed. Values: auto, ours, ida, ghidra. |

### inspect_instruction

**Inspect native instructions** (read-only, idempotent, open-world, long-running)

What is at an address of a native image, instruction by instruction: decoded, mid_instruction (with the covering one), data (string, IAT / GOT slot, switch table, pointer, literal; with its extent), not_in_function, unmapped, outside_image or invalid. For an instruction: bytes, prefixes, encoding, CPU features; operands (kind, size, access, registers, memory parts, effective address named); registers and flags read and written; memory accesses; stack change; flow; references from and to; a call's arguments; a switch's table. count > 1 walks forward. Other instruction sets through IDA or Ghidra (fields they lack are null). The first call on an image waits for its code index (seconds; minutes for a very large image).

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `image` | string | yes |  | Native image id, file name or path (a path is loaded). |
| `address` | string | yes |  | Hex VA or RVA (rva:/va:/off: prefix), export, module!import or function name. |
| `count` | integer |  | `1` | Instructions to inspect (1-64). |
| `offset` | integer |  | `0` | Character offset from the truncation footer. |
| `maxChars` | integer |  |  | Page size in characters (default ~60000). |
| `engine` | string |  |  | auto (default): the built-in decoder for x86 / x64 / ARM, else IDA, else Ghidra. Values: auto, ours, ida, ghidra. |

Structured output: `image`, `engine`, `engineNote`, `items`, `notes`.

### search_instructions

**Search native instructions** (read-only, idempotent, open-world, long-running)

Find instructions by mnemonic, operand or whole-line regex (case-insensitive) and an operand value (immediate, displacement or target) in every function, one function, or an address range; a scan budget's end is named in the result (continue with start=). The first call on an image waits for its code index (seconds; minutes for a very large image).

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `image` | string | yes |  | Native image id, file name or path (a path is loaded). |
| `mnemonic` | string |  |  | Mnemonic regex, e.g. '^(call\|jmp)$'. |
| `operands` | string |  |  | Operand text regex, e.g. 'rsp\+\|fs:'. |
| `text` | string |  |  | Regex over the whole instruction text. |
| `value` | string |  |  | An operand value: 0x10B, 267, or an address. |
| `function` | string |  |  | Only this function: Hex VA or RVA (rva:/va:/off: prefix), export, module!import or function name. |
| `start` | string |  |  | Range start (with end, or alone: to the end of its section). |
| `end` | string |  |  | Range end (exclusive). |
| `offset` | integer |  | `0` | Index of the first match to return. |
| `limit` | integer |  | `100` | Max matches (max 2000). |
| `maxInstructions` | integer |  | `500000` | Max instructions scanned (max 5000000). |
| `engine` | string |  |  | auto (default): a finished IDA / Ghidra analysis of this session, else ours (the built-in index); never starts one. ida / ghidra: that engine, started when needed. Values: auto, ours, ida, ghidra. |

### get_cfg

**Native control-flow graph** (read-only, idempotent, open-world, long-running)

Basic blocks of the native function containing an address: range, instruction count, how each ends and its successors; switch tables with values per target; unresolved indirect jumps with the reason. The first call on an image waits for its code index (seconds; minutes for a very large image).

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `image` | string | yes |  | Native image id, file name or path (a path is loaded). |
| `address` | string | yes |  | Hex VA or RVA (rva:/va:/off: prefix), export, module!import or function name. |
| `offset` | integer |  | `0` | Character offset from the truncation footer. |
| `maxChars` | integer |  |  | Page size in characters (default ~60000). |
| `engine` | string |  |  | auto (default): a finished IDA / Ghidra analysis of this session, else ours (the built-in index); never starts one. ida / ghidra: that engine, started when needed. Values: auto, ours, ida, ghidra. |

Structured output: `image`, `function`, `address`, `engine`, `blocks`, `switches`, `unresolvedJumps`, `tailCalls`, `truncated`.

### find_xrefs

**Native cross-references** (read-only, idempotent, open-world, long-running)

What references an address in a native image: calls (also through import slots and thunks), jumps, data reads and writes, address-taken uses, switch tables and relocated pointers, each with its function and, for calls, the recovered arguments; for a virtual method, the RTTI virtual call sites reaching it (VirtualExact / VirtualPossible). An import (module!name): its call sites and binding; an export: also call sites in other loaded images; a GetProcAddress import: where it is resolved and its calls. direction=from: what the address (or whole function) references. A struct member (Type::member, Type+0x18): its uses in the pseudocode of functions whose prototype names the type, through IDA or Ghidra (scope=all: every function). The first call on an image waits for its code index (seconds; minutes for a very large image).

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `image` | string | yes |  | Native image id, file name or path (a path is loaded). |
| `address` | string | yes |  | Hex VA or RVA (rva:/va:/off: prefix), export, module!import or function name. Or a struct member: Type::member, Type.member, Type+0xOFFSET. |
| `offset` | integer |  | `0` | Index of the first row. |
| `limit` | integer |  | `500` | Max rows. |
| `engine` | string |  |  | auto (default): a finished IDA / Ghidra analysis of this session, else ours (the built-in index); never starts one. ida / ghidra: that engine, started when needed. Adds the RTTI virtual calls an engine lacks. Values: auto, ours, ida, ghidra. |
| `direction` | string |  |  | to (default), from or both. Values: to, from, both. |
| `kind` | string |  |  | any (default); code: calls, jumps; data: reads, writes, pointers, address-taken. Values: any, code, data. |
| `scope` | string |  |  | Struct member: typed (default) or all (every function; call again to continue). Values: typed, all. |

Structured output: `image`, `target`, `items`, `offset`, `total`, `truncated`, `boundTo`, `engine`, `engineNote`.

### native_call_tree

**Native call tree** (read-only, idempotent, open-world, long-running)

Callers or callees of a native function, several levels deep, through thunks and import slots; callers of module!import: the functions calling through it. Across loaded images: an import continues into the provider's export (forwarders and thunks followed), and callers include importing call sites in other images. Callees include GetProcAddress pointers ([dynamic]) and RTTI-resolved virtual targets ([virtual]: the only one; [virtual?: one of n]). Repeats and recursion are marked, not expanded. direction=both: one level each way with call sites and edge flags. The first call on an image waits for its code index (seconds; minutes for a very large image).

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `image` | string | yes |  | Native image id, file name or path (a path is loaded). |
| `function` | string | yes |  | Hex VA or RVA (rva:/va:/off: prefix), export, module!import or function name. |
| `direction` | string |  | `callees` | both: depth 1, with call sites. Values: callers, callees, both. |
| `depth` | integer |  | `3` | Levels (1-8). |
| `maxNodes` | integer |  | `500` | Max nodes. |
| `offset` | integer |  | `0` | Character offset from the truncation footer. |
| `maxChars` | integer |  |  | Page size in characters (default ~60000). |
| `calls` | string |  |  | Call edges to follow: all (default), direct (no virtual edges) or virtual (only virtual edges). Values: all, direct, virtual. |
| `engine` | string |  |  | auto (default): a finished IDA / Ghidra analysis of this session, else ours (the built-in index); never starts one. ida / ghidra: that engine, started when needed. An engine's edges get the RTTI virtual calls it lacks; other images use the built-in index. Values: auto, ours, ida, ghidra. |

### find_virtual_calls

**Native virtual calls** (read-only, idempotent, open-world, long-running)

Virtual call sites resolved through RTTI (MSVC or Itanium): calls through a vftable slot, also through stack spills, this adjustments and CFG dispatch. The receiver's class comes from a vftable stored into the object (also by its constructor), this of a virtual method, or decorated names; the slot's implementations in it and its derived classes are the targets: one is exact, several possible, else unresolved with the reason. The edges feed the call graph tools. crossCheck=true compares a sample with IDA (else Ghidra) and reports the agreement rate.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `image` | string | yes |  | Native image id, file name or path (a path is loaded). |
| `function` | string |  |  | Only sites in this function: Hex VA or RVA (rva:/va:/off: prefix), export, module!import or function name. |
| `status` | string |  |  | Only sites with this status. Values: exact, possible, unresolved. |
| `offset` | integer |  | `0` | Index of the first site. |
| `limit` | integer |  | `100` | Max sites (max 1000). |
| `crossCheck` | boolean |  | `false` | Compare a sample with the engine's view (runs IDA or Ghidra; minutes on a large image the first time). |
| `sampleFunctions` | integer |  | `100` | Cross-check: functions to sample. |
| `seconds` | integer |  | `300` | Cross-check: time budget in seconds. |

Structured output: `image`, `sites`, `exact`, `possible`, `unresolved`, `edges`, `directEdges`, `rttiClasses`, `total`, `offset`, `truncated`, `items`, `crossCheck`, `notes`.

### search_native_strings

**Search native strings** (read-only, idempotent, open-world, long-running)

Strings (ASCII and UTF-16) a native image's code or data references, with address, reference count and first referencing function. Also Il2Cpp literals (after apply_il2cpp_names) and NativeAOT frozen strings, by the slot or object code loads; with an engine, its unreferenced strings in other encodings too. The first call on an image waits for its code index (seconds; minutes for a very large image).

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `image` | string | yes |  | Native image id, file name or path (a path is loaded). |
| `query` | string |  |  | Case-insensitive substring, or a regex with regex=true; omit to list all. |
| `regex` | boolean |  | `false` | Treat query as a regular expression. |
| `offset` | integer |  | `0` | Index of the first row. |
| `limit` | integer |  | `300` | Max rows (default 300). |
| `engine` | string |  |  | auto (default): a finished IDA / Ghidra analysis of this session, else ours (the built-in index); never starts one. ida / ghidra: that engine, started when needed. Values: auto, ours, ida, ghidra. |

Structured output: `image`, `items`, `offset`, `total`, `truncated`, `notEvaluated`.

### get_call_arguments

**Native call arguments** (read-only, idempotent, long-running)

Call sites of a native image (x86 / x64 / ARM) with their argument values, recovered by constant propagation in the caller under the platform calling convention: immediates, strings, named addresses, earlier call results, globals (differing merges are unknown). Known Win32 / CRT / libc APIs give parameter names and decoded constants. Pass address and/or callee.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `image` | string | yes |  | Native image id, file name or path (a path is loaded). |
| `address` | string |  |  | A call instruction, or an address in a function (all calls in it): Hex VA or RVA (rva:/va:/off: prefix), export, module!import or function name. |
| `callee` | string |  |  | Only calls to this API, module!name or function; without address, every call to it in the image. |
| `offset` | integer |  | `0` | Index of the first call site. |
| `limit` | integer |  | `100` | Max call sites (max 1000). |

Structured output: `image`, `scope`, `total`, `offset`, `calls`, `notes`.

### trace_native_values

**Native value trace** (read-only, idempotent, open-world, long-running)

Traces a value through native code (x86 / x64 / ARM) across functions. Backward (where it comes from): constants, strings, function pointers, API results, through copies, stack slots, merges and loops; parameters bind to every caller's argument, call results to the callee's returns, writable globals to their writers and initial contents. Forward (where it goes): API arguments (decoded), callees' parameters, globals and their readers, returns, compares, switch indexes, dereferences. Crosses loaded images through imports and exports, struct fields through parameter types. What the budgets leave out is a frontier entry with the follow-up call; pages reuse the built graph.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `image` | string | yes |  | Native image id, file name or path (a path is loaded). |
| `address` | string | yes |  | An instruction, a call, a function start (with argument) or a writable global. Hex VA or RVA (rva:/va:/off: prefix), export, module!import or function name. |
| `location` | string |  |  | The value at address: a register (rdx, ecx, xmm1; ARM64 x1, w2, d0), a stack or frame slot ([rsp+28h], [ebp-8]; ARM64 [sp+10h], [x29-8]), op1 / op2 (an operand of the instruction) or result (the value the call at address returns). |
| `argument` | string |  |  | An argument of the call at address, or a parameter of the function starting there: 1-based position or API parameter name. |
| `direction` | string |  |  | backward (default: the values that reach it), forward (its uses) or both. Values: backward, forward, both. |
| `maxDepth` | integer |  | `3` | Function boundaries to cross (0-8). |
| `maxFunctions` | integer |  | `32` | Functions to slice (1-256). |
| `maxNodes` | integer |  | `500` | Nodes in the graph (1-5000). |
| `maxCallers` | integer |  | `16` | Call sites bound per parameter or return (1-256). |
| `maxWriters` | integer |  | `16` | Writers (backward) or readers (forward) per global (1-256). |
| `followGlobals` | boolean |  | `true` | Follow writable globals into their writers / readers. |
| `offset` | integer |  | `0` | Index of the first node. |
| `limit` | integer |  | `200` | Nodes per page (max 1000). |
| `engine` | string |  |  | Per-function slices: ours (built-in), ida or ghidra (that decompiler's IR, started when needed; built-in where it cannot place the seed), or auto (default: an engine whose analysis is complete in this session, else ours). Values: auto, ours, ida, ghidra. |

Structured output: `image`, `engine`, `seed`, `direction`, `values`, `nodes`, `edges`, `frontier`, `totalNodes`, `totalEdges`, `functions`, `offset`, `truncated`, `notes`.

### resolve_call_targets

**Native call targets** (read-only, idempotent, open-world, long-running)

Targets of call and tail-jump sites in native code (x86 / x64 / ARM), each with its basis and confidence: direct branches, import and GOT slots, thunks, constant pointers (also through CFG dispatch), GetProcAddress pointers, RTTI virtual calls, NativeAOT dispatch cells, global function pointers' writers, relocated pointer tables, and with deep=true pointers callers pass in. Several targets are listed, never collapsed; unresolved sites carry the reason and the trace_native_values call to follow. engine=ida or ghidra merges that engine's targets (a disagreement is ambiguous).

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `image` | string | yes |  | Native image id, file name or path (a path is loaded). |
| `address` | string |  |  | A call instruction, or an address in a function (its sites): Hex VA or RVA (rva:/va:/off: prefix), export, module!import or function name. |
| `scope` | string |  |  | Default: site at a call, else function; image (every indirect site) without address. Values: site, function, image. |
| `status` | string |  |  | Default all; indirect: all but direct branches. Values: all, resolved, possible, ambiguous, unresolved, indirect. |
| `deep` | boolean |  | `false` | Trace pointers that arrive as parameters back into the callers (slower). |
| `engine` | string |  |  | auto (default): a finished IDA / Ghidra analysis of this session, else ours (the built-in index); never starts one. ida / ghidra: that engine, started when needed. Values: auto, ours, ida, ghidra. |
| `offset` | integer |  | `0` | Index of the first site. |
| `limit` | integer |  | `100` | Max sites (max 1000). |
| `timeoutSeconds` | integer |  |  | Seconds per engine request (default CORVUS_ENGINE_REQUEST_TIMEOUT); scans then answer partial. |

Structured output: `image`, `scope`, `engine`, `total`, `byStatus`, `byMechanism`, `topUnresolved`, `offset`, `truncated`, `items`, `notes`.

### analyze_native_function

**Native function dossier** (read-only, idempotent, open-world, long-running)

Everything known about one native function, in sections bounded by maxItems with totals: identity (names, sources, ranges, flags, prototypes, vftable slots), signature (parameters read at entry, this class, result use), frame (unwind, saved registers, address-taken locals, EH), callers (edge kinds, other images, roots), callees (targets, basis, arguments), data (strings, globals, import slots), flow (blocks, loops, switches, complexity), annotations. Optional: constants, params (values callers pass), pseudocode. Several addresses: a dossier each, or with component=true how they work together.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `image` | string | yes |  | Native image id, file name or path (a path is loaded). |
| `address` | string | yes |  | An address inside the function, or up to 16 comma-separated: Hex VA or RVA (rva:/va:/off: prefix), export, module!import or function name. |
| `sections` | string |  |  | Comma-separated section names (default all but constants, params and pseudocode). |
| `maxItems` | integer |  | `40` | Facts per section (1-500). |
| `pseudocode` | boolean |  | `false` | Add the pseudocode section. |
| `component` | boolean |  | `false` | With several addresses: one component view (internal calls, shared data, interface). |
| `engine` | string |  |  | Pseudocode engine (default auto). Values: auto, ida, ghidra. |
| `offset` | integer |  | `0` | Character offset from the truncation footer. |
| `maxChars` | integer |  |  | Page size in characters (default ~60000). |

Structured output: `image`, `address`, `name`, `size`, `end`, `sections`, `next`, `batch`, `component`.

### trace_native_feature

**Trace a native feature** (read-only, idempotent, long-running)

Finds the native code behind a behaviour from a text or value: strings, function and data names, imports (also late-bound), exports, RTTI classes and, for a number, constants matching query ("quoted": exact) are followed to their references (with decoded API arguments), grouped by function and ranked; hubs are callers within callerDepth reaching several of them. An open IDA / Ghidra session adds its strings, references and matching pseudocode lines. Pages reuse the computed trace.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `image` | string | yes |  | Native image id, file name or path (a path is loaded). |
| `query` | string | yes |  | Case-insensitive substring, or a regex with regex=true. |
| `regex` | boolean |  | `false` | Treat query as a regular expression. |
| `kinds` | string |  |  | Seed kinds, comma-separated: strings, names, imports, exports, classes, constants (default all). |
| `maxSeeds` | integer |  | `50` | Matches followed (1-500); the rest are counted. |
| `callerDepth` | integer |  | `1` | Caller levels searched for hubs (0-3). |
| `offset` | integer |  | `0` | Index of the first function. |
| `limit` | integer |  | `50` | Functions per page (max 500). |

Structured output: `image`, `query`, `seeds`, `totalSeeds`, `functions`, `totalFunctions`, `offset`, `truncated`, `hubs`, `notes`.

### get_exception_info

**Native exception handling** (read-only, idempotent, long-running)

Exception handling of the native function containing an address. ELF / Mach-O: FDE or compact unwind, personality, LSDA call sites with landing pads and caught types. MSVC: the handler, try blocks with caught types, unwind map, SEH scopes, IP-to-state map, and the catch blocks, funclets, filters and chained fragments it reaches. Without an address: image counts and the metadata that failed its checks.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `image` | string | yes |  | Native image id, file name or path (a path is loaded). |
| `address` | string |  |  | Hex VA or RVA (rva:/va:/off: prefix), export, module!import or function name. Omit for an image summary. |
| `offset` | integer |  | `0` | Character offset from the truncation footer. |
| `maxChars` | integer |  |  | Page size in characters (default ~60000). |

### list_cpp_classes

**C++ classes from RTTI** (read-only, idempotent, open-world)

C++ classes recovered from RTTI (MSVC on PE, Itanium on ELF / Mach-O): demangled names, base classes (offsets, virtual and multiple inheritance) and vftables with slot targets; rejects are counted with the reason. engine=ghidra lists Ghidra's class namespaces instead (PDB classes too), ida its C++ structs.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `image` | string | yes |  | Native image id, file name or path (a path is loaded). |
| `filter` | string |  |  | Name substring (case-insensitive). |
| `slots` | boolean |  | `false` | Include each vftable's slot addresses. |
| `offset` | integer |  | `0` | Character offset from the truncation footer. |
| `maxChars` | integer |  |  | Page size in characters (default ~60000). |
| `engine` | string |  |  | auto or ours (default: RTTI), ida or ghidra. Values: auto, ours, ida, ghidra. |
| `namespaces` | boolean |  | `false` | engine=ghidra: plain namespaces and libraries too. |

### get_native_type

**Native type layout** (read-only, idempotent, open-world, long-running)

A native type's layout (fields with offset, size and bit fields, bases, padding; enums by value) from the PDB, MSVC RTTI (bases, vftables with named slots), Il2Cpp layouts (after apply_il2cpp_names) or the engine's types (source=engine opens IDA or Ghidra; auto reads an analyzed one for names the others lack). By name (exact, case-insensitive, then substring candidates), id, or typed address (a PDB global gives the field path, e.g. g.players[3].pos.y; also vftables and Il2Cpp metadata slots). read=true adds each field's value from the image's bytes (pointers named, strings, enumerators, bit fields); no engine needed.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `image` | string | yes |  | Native image id, file name or path (a path is loaded). |
| `name` | string |  |  | Type name (Packet, ns::Widget, Ns.Type for Il2Cpp). |
| `id` | string |  |  | Type id from a result (pdb:0x1A2B, rtti:0x140012000, il2cpp:Ns.Type). |
| `address` | string |  |  | A typed address: Hex VA or RVA (rva:/va:/off: prefix), export, module!import or function name. |
| `at` | string |  |  | Hex offset of a field to name (all union members); 0x48.0x10 reads through the pointer at 0x48. |
| `depth` | integer |  | `0` | Levels of by-value members to inline (0-4). |
| `source` | string |  |  | Type source (default auto). Values: auto, pdb, rtti, il2cpp, engine. |
| `format` | string |  |  | table (default) or c (a C declaration). Values: table, c. |
| `offset` | integer |  | `0` | Index of the first row (field, enumerator, slot, candidate). |
| `limit` | integer |  | `200` | Max rows (max 5000). |
| `engine` | string |  |  | Engine for source=engine (default auto). Values: auto, ida, ghidra. |
| `read` | boolean |  | `false` | Add the field values at address (with name or id: that type read there). |

Structured output: `image`, `query`, `type`, `candidates`, `totalCandidates`, `owner`, `ownerAddress`, `paths`, `offset`, `truncated`, `notes`, `readAddress`, `value`.

### decompile_native

**Decompile native function** (read-only, idempotent, open-world, long-running)

C pseudocode of the native function containing an address, through IDA (Hex-Rays) or Ghidra. The first call on an image runs the engine's auto-analysis (seconds to minutes) and keeps the database per file hash. Names, comments, PDB types and prototypes are pushed first (the first line names the type source); user types apply last and win. functions= decompiles several in one request, each within perFunctionSeconds; a failure affects only its item.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `image` | string | yes |  | Native image id, file name or path (a path is loaded). |
| `address` | string |  |  | Hex VA or RVA (rva:/va:/off: prefix), export, module!import or function name. Required unless functions is given. |
| `engine` | string |  |  | auto (default): an engine open on this image, else IDA, else Ghidra (or the server's --engine). Values: auto, ida, ghidra. |
| `addresses` | boolean |  | `false` | Prefix each line with the address it was generated from. |
| `offset` | integer |  | `0` | Character offset from the truncation footer. |
| `maxChars` | integer |  |  | Page size in characters (default ~60000). |
| `functions` | string[] |  |  | Several functions instead of address: addresses or names, in the order wanted. |
| `perFunctionSeconds` | integer |  | `60` | With functions: seconds per function (1-600). |
| `maxFunctions` | integer |  | `32` | With functions: most decompiled (1-200); the rest get a follow-up call. |
| `refs` | boolean |  | `false` | With address: a footer listing the globals, functions, strings and imports used. |
| `timeoutSeconds` | integer |  |  | Seconds per engine request (1-600; default CORVUS_ENGINE_REQUEST_TIMEOUT); Ghidra retries once with 4x. |
| `callersOf` | string |  |  | Instead of address: decompile the functions calling this one (engine references). |

Structured output: `image`, `engine`, `items`, `total`, `succeeded`, `failed`, `skipped`, `next`.

### search_decompiled

**Search native pseudocode** (read-only, idempotent, open-world, long-running)

Regex (case-insensitive; (?-i) for exact case) per line of the IDA or Ghidra pseudocode of every function (or filtered ones), in address order; parallel where the engine allows, cached. Stops at maxFunctions, seconds or limit hits; cursor= continues.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `image` | string | yes |  | Native image id, file name or path (a path is loaded). |
| `pattern` | string | yes |  | Regex. |
| `engine` | string |  |  | auto, ida or ghidra. Values: auto, ida, ghidra. |
| `filter` | string |  |  | Function name filter: substring (case-insensitive), glob with * and ?, or /regex/ (flags i, m, s). |
| `maxFunctions` | integer |  | `500` | Max 20000. |
| `seconds` | integer |  | `60` | Max 600. |
| `cursor` | integer |  | `0` | From the previous result. |
| `limit` | integer |  | `100` | Max hits (max 2000). |

Structured output: `image`, `engine`, `pattern`, `hits`, `functions`, `from`, `searched`, `failed`, `cursor`, `stoppedBy`.

### verify_native_imports

**Verify P/Invoke imports** (read-only, idempotent)

Check a .NET assembly's P/Invoke declarations ([DllImport]) against the exports of the libraries they bind to, with the runtime's lookup rules: DLL search order, API sets, A/W suffixes, stdcall decoration, ordinals and forwarders; for Linux / macOS / Android / iOS targets (platform=, or detected) .so / .dylib probing along the RID chain and __Internal in an Il2Cpp binary. Verdict per declaration with a reason code: verified, contradicted (e.g. missing_export, arch_mismatch), unresolved (e.g. dll_not_found with the places searched), dynamic_only (the assembly loads the library itself), not_checked (runtime-internal). Run-time loading found in the IL is listed too.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `assembly` | string | yes |  | Assembly id, name, file name or path. |
| `status` | string |  |  | Only declarations with this status or reason code (e.g. contradicted, missing_export). |
| `offset` | integer |  | `0` | Index of the first row. |
| `limit` | integer |  | `500` | Max rows (max 5000). |
| `platform` | string |  |  | Target platform (default auto). Values: auto, windows, linux, osx, android, ios. |

Structured output: `assembly`, `declarations`, `counts`, `filter`, `offset`, `total`, `truncated`, `items`, `dynamicLoads`, `dynamicLoadsTotal`, `metadataIssues`, `notes`.

### load_pdb

**Load native debug symbols** (destructive, idempotent, open-world, long-running)

Load the PDB of a native image: function and data names (publics, globals, procedures, thunks), checked against the image's GUID and age. Searched: path, the image's folder, its recorded path, _NT_SYMBOL_PATH, the Visual Studio / WinDbg / IDA caches and C:\symbols; download=true fetches it from a symbol server into a per-user cache. Names show as source 'pdb' everywhere (user names win); missed functions become function starts; decompile_native loads its types. A matching local PDB is read automatically anyway. The names are saved with the image's annotations and reapplied when the file loads again; clear=true removes them.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `image` | string | yes |  | Native image id, file name or path (a path is loaded). |
| `path` | string |  |  | PDB file, or a directory (or symbol store) to look in first. |
| `download` | boolean |  | `false` | Download from a symbol server when no local PDB matches (network). |
| `server` | string |  |  | Symbol server URL for download (default: _NT_SYMBOL_PATH servers, else https://msdl.microsoft.com/download/symbols). |
| `force` | boolean |  | `false` | Use the PDB at path even when its GUID or age differs from the image (names may be wrong). |
| `timeoutSeconds` | integer |  | `120` | Download time limit in seconds. |
| `maxMegabytes` | integer |  | `2048` | Download size limit in MB. |
| `clear` | boolean |  | `false` | Remove the PDB names and their saved copy instead (not read again this session). |

### search_pdb_symbols

**Search native debug symbols** (read-only, idempotent)

Symbols of the PDB loaded for a native image (load_pdb, or found automatically): address, kind, size, name, the signature undecorated from the public name, and the object file.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `image` | string | yes |  | Native image id, file name or path (a path is loaded). |
| `query` | string |  |  | Name or decorated name substring (case-insensitive); empty for all. |
| `kind` | string |  |  | Only this kind (default all). Values: function, data, public, all. |
| `offset` | integer |  | `0` | Index of the first row. |
| `limit` | integer |  | `200` | Max rows. |

### get_nativeaot_info

**NativeAOT metadata** (read-only, idempotent, long-running)

What a NativeAOT image's own metadata recovers (.NET 7-10; PE, ELF, Mach-O). view=summary: versions, header, each recovery stage's status and counts. sections: module sections. types: MethodTables (name, origin, kind, base). type: one MethodTable's flags, bases, interfaces and slots. methods: named method bodies. strings: frozen strings with references. statics: statics bases with known fields. Its names apply on load as the nativeaot layer.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `image` | string | yes |  | Native image id, file name or path (a path is loaded). |
| `view` | string |  |  | What to show (default summary). Values: summary, sections, types, type, methods, strings, statics. |
| `query` | string |  |  | view=type: a type name or MethodTable address; list views: substring filter. |
| `offset` | integer |  | `0` | First row for the list views; character offset for summary and type. |
| `limit` | integer |  | `200` | Max rows for the list views. |

Structured output: `image`, `view`, `summary`, `coverage`, `items`, `offset`, `total`, `truncated`.

## native-edit

Native names, comments, patches and saving.

### rename_native

**Name a native address** (destructive, idempotent, open-world, long-running)

Name a native address: used by every native tool, pushed to the engines and kept per file SHA-256. C-identifier-like (<=255 chars), unique unless allowDuplicate. Empty clears. items: many in one sidecar write and one engine push, each reported.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `image` | string | yes |  | Native image id, file name or path (a path is loaded). |
| `address` | string |  |  | Hex VA or RVA (rva:/va:/off: prefix), export, module!import or function name. |
| `name` | string |  |  | The new name; empty to clear the name at this address. |
| `allowDuplicate` | boolean |  | `false` | Allow a name already used at another address. |
| `items` | string |  |  | Lines 'address = name', or JSON [{address, name}]. |
| `dryRun` | boolean |  | `false` | Check only; record nothing. |
| `stopOnError` | boolean |  | `false` | Stop at the first failing item. |
| `showDecompile` | string |  |  | The function's pseudocode after the edit (after) or its unified diff (diff). Values: none, after, diff. |
| `engine` | string |  |  | Engine to push the change to now (default: one with this image open, else at its next use). Values: auto, ida, ghidra. |

### comment_native

**Comment a native address** (destructive, idempotent, open-world, long-running)

Comment a native address (kept, pushed to engines). scope: line (repeatable: also where the address is referenced), eol, pre or plate (engine kinds; Ghidra's decompiler shows pre), pseudocode (on the statement made from the address), function, or auto (function at a function start, else line and pseudocode). append adds a line (dedupe skips one it has). Empty clears. items: many in one sidecar write and one engine push, each reported.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `image` | string | yes |  | Native image id, file name or path (a path is loaded). |
| `address` | string |  |  | Hex VA or RVA (rva:/va:/off: prefix), export, module!import or function name. |
| `text` | string |  |  | The comment text; empty to clear it. |
| `scope` | string |  |  | See the description; default auto. Values: auto, line, eol, pre, plate, pseudocode, function. |
| `append` | boolean |  | `false` | Add text as a new line of the existing comment. |
| `dedupe` | boolean |  | `true` | With append: skip a line already there. |
| `items` | string |  |  | Lines 'address = text', or JSON [{address, text, scope?, append?}]. |
| `dryRun` | boolean |  | `false` | Check only; record nothing. |
| `stopOnError` | boolean |  | `false` | Stop at the first failing item. |
| `engine` | string |  |  | Engine to push the change to now (default: one with this image open, else at its next use). Values: auto, ida, ghidra. |

### export_native_annotations

**Export native annotations** (destructive, idempotent, long-running)

Write the image's names and comments (with the NativeAOT and Il2Cpp names) as an IDAPython script, a Ghidra script or JSON; the IDA script and JSON carry the user's engine types too. Scripts apply by rebased RVA. header: a C header of declared types, prototypes and typed globals.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `image` | string | yes |  | Native image id, file name or path (a path is loaded). |
| `outputPath` | string | yes |  | Output file path. |
| `format` | string |  |  | Default json. Values: ida, ghidra, json, header. |
| `overwrite` | boolean |  | `false` | Replace outputPath if it exists. |

### patch_bytes

**Patch native bytes** (destructive, long-running)

Replace bytes at a native address in memory, as an undoable edit that every read path then sees. A partly overwritten instruction is padded with NOPs; mid-instruction, past the function end or on header / zero-fill bytes needs force. ELF / Mach-O: loader-rewritten bytes need force, encrypted ones are refused, signatures become invalid.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `image` | string | yes |  | Native image id, file name or path (a path is loaded). |
| `address` | string | yes |  | Hex VA or RVA (rva:/va:/off: prefix), export, module!import or function name. |
| `hex` | string |  |  | Replacement bytes as hex ('90 90', '9090' or '0x90,0x90'). |
| `value` | string |  |  | Instead of hex: a number of type (range-checked); ptr: or a name. |
| `type` | string |  |  | With value: i8-i64, u8-u64, f32, f64 or ptr; a be suffix for big-endian. Values: i8, u8, i16, u16, i32, u32, i64, u64, f32, f64, ptr, i16be, u16be, i32be, u32be, i64be, u64be, f32be, f64be. |
| `force` | boolean |  | `false` | Override the safety checks (mid-instruction, past function end, header bytes, no free relocation slot). |
| `dryRun` | boolean |  | `false` | Preview only; do not record the patch. |
| `relocations` | string |  |  | PE base relocations under the patch: auto (default) keeps entries whose new bytes still hold an address, neutralizes the rest and adds entries for new absolute addresses; keep leaves them; neutralize clears all. Undo restores them; ignored with extend. Values: auto, keep, neutralize. |
| `extend` | boolean |  | `false` | Put the new code in a stub (see placement); the site becomes a jump to it and control returns after the site. For code larger than the site, or to keep it intact. Refused with a reason code when unsafe; PE only. |
| `stubMode` | string |  |  | With extend: replace (default; the new code instead of the displaced instructions), before (new code, then them) or after. Values: replace, before, after. |
| `placement` | string |  |  | With extend: auto (default; a code cave if one fits, else a new section), cave or section (headers and checksum updated; undo restores the file). Values: auto, cave, section. |

### patch_asm

**Assemble and patch native code** (destructive, long-running)

Assemble x86/x64 instructions (multi-line; labels, numeric and symbol branch targets; 'db <hex>') and write them at a native address in memory, branches and RIP-relative references computed for that address. Same safety rules, NOP padding and undo as patch_bytes; PE absolute addresses ([addr], 'offset name', imm64) get base relocations.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `image` | string | yes |  | Native image id, file name or path (a path is loaded). |
| `address` | string | yes |  | Hex VA or RVA (rva:/va:/off: prefix), export, module!import or function name. |
| `assembly` | string | yes |  | Assembly, one instruction per line. |
| `force` | boolean |  | `false` | Override the safety checks (mid-instruction, past function end, header bytes, no free relocation slot). |
| `dryRun` | boolean |  | `false` | Preview only; do not record the patch. |
| `relocations` | string |  |  | PE base relocations under the patch: auto (default) keeps entries whose new bytes still hold an address, neutralizes the rest and adds entries for new absolute addresses; keep leaves them; neutralize clears all. Undo restores them; ignored with extend. Values: auto, keep, neutralize. |
| `extend` | boolean |  | `false` | Put the new code in a stub (see placement); the site becomes a jump to it and control returns after the site. For code larger than the site, or to keep it intact. Refused with a reason code when unsafe; PE only. |
| `stubMode` | string |  |  | With extend: replace (default; the new code instead of the displaced instructions), before (new code, then them) or after. Values: replace, before, after. |
| `placement` | string |  |  | With extend: auto (default; a code cave if one fits, else a new section), cave or section (headers and checksum updated; undo restores the file). Values: auto, cave, section. |

### list_native_edits

**List native byte patches** (read-only, idempotent, long-running)

The in-memory byte patches of a native image, numbered (undo_native_edit, save_native). Then the names by source: the user's (rename_native / comment_native) and each imported layer (pdb, il2cpp, ida) with counts, origin, identity and whether it was saved or restored when the image loaded.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `image` | string | yes |  | Native image id, file name or path (a path is loaded). |
| `search` | string |  |  | Instead: the names and comments (user and layers) whose text matches: substring (case-insensitive), glob with * and ?, or /regex/ (flags i, m, s). |

### undo_native_edit

**Undo a native byte patch** (destructive, long-running)

Undo one in-memory byte patch of a native image — the last by default, or any earlier one by number (from list_native_edits).

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `image` | string | yes |  | Native image id, file name or path (a path is loaded). |
| `number` | integer |  |  | Patch number (1-based, from list_native_edits); omit for the last. |

### save_native

**Save patched native image** (destructive, idempotent, long-running)

Write the patched native image to a new file: unpatched bytes identical, PE checksum recomputed, a signature invalidated (stripSignature removes it). Atomic and verified before it replaces the target; overwrite=true keeps a .bak and refuses a file changed on disk.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `image` | string | yes |  | Native image id, file name or path (a path is loaded). |
| `outputPath` | string | yes |  | Output file path. |
| `overwrite` | boolean |  | `false` | Allow replacing an existing file. |
| `stripSignature` | boolean |  | `false` | Remove the Authenticode certificate table from the output. |

### export_native_patches

**Export native patches** (destructive, idempotent)

Write the image's in-memory byte patches for other tools: ida an IDAPython script (each patch at its rebased RVA, only where the original bytes are found), dif IDA's .dif, ips (file offsets below 16 MB) or ips32, json the full patch set (migrate_native_patches reads it). Relocation edits and the PE checksum are included, so a .dif or IPS applied to the original gives save_native's bytes.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `image` | string | yes |  | Native image id, file name or path (a path is loaded). |
| `outputPath` | string | yes |  | Output file path. |
| `format` | string |  |  | Default json. Values: ida, dif, ips, ips32, json. |
| `overwrite` | boolean |  | `false` | Replace outputPath if it exists. |

Structured output: `image`, `outputPath`, `format`, `patches`, `relocationEdits`, `changedBytes`, `records`, `checksumUpdated`, `bytes`, `originalSha256`, `notes`.

## builds

Build-to-build comparison and carrying work to a new build.

### compare_assemblies

**Compare two builds** (destructive, idempotent, long-running)

Compare two builds of an assembly (load both; the second gets an id like Name#2): renamed / moved types and members (matched by content, in tiers, only when unique on both sides; else ambiguous with candidates), added and removed ones, and how each matched member changed: name, signature, body (normalized IL hash), metadata, field type, Il2Cpp field offset / address.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `oldAssembly` | string | yes |  | The old build (id, name or path). |
| `newAssembly` | string | yes |  | The new build (id, name or path). |
| `namespace` | string |  |  | Only types whose old or new full name starts with this. |
| `changes` | string |  |  | Change kinds to list, comma-separated: renamed, moved, signature, body, metadata, type, offset, address, added, removed, ambiguous, unknown (unpaired for lack of evidence) or all; default all except address. |
| `listAddedRemovedTypes` | boolean |  | `true` | List added and removed type names (else counts). |
| `includeCompilerGenerated` | boolean |  | `false` | Also show compiler-generated types and members (closures, state machines, backing fields), which change with every recompile. |
| `tokenMapPath` | string |  |  | Write the whole assembly's token map (old -> new token, status, tier, confidence, body hash equality) to this JSON file. |
| `overwrite` | boolean |  | `false` | Replace an existing token map file. |
| `offset` | integer |  | `0` | Character offset from the truncation footer. |
| `maxChars` | integer |  |  | Page size in characters (default ~60000). |

Structured output: `old`, `new`, `oldTypes`, `matchedTypes`, `typeChanges`, `memberChanges`, `memberMatches`, `ambiguousMembers`, `oldSkippedBodies`, `newSkippedBodies`, `hiddenCompilerGenerated`, `items`, `total`, `truncated`, `tokenMapFile`, `tokenMapEntries`.

### find_counterpart

**Find symbol in another build** (read-only, idempotent, long-running)

Where a type or member of the old build went in the new build: matched by name, then by content (only when unique on both sides; else candidates). Shows the new name and token, tier and confidence, whether the body changed (normalized IL hash) and Il2Cpp offset / address changes. diff=true adds a unified diff of the pair's C# (a type: of each changed, added or removed member), il=true of their normalized IL; renames are rewritten first, so a pure rename is no change.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `symbol` | string | yes |  | In the old build. Type or member: 'Ns.Type', 'Ns.Outer+Inner', 'Ns.Type::Method(int, string)', a short name or a token (0x06000123). |
| `oldAssembly` | string | yes |  | The old build (id, name or path). |
| `newAssembly` | string | yes |  | The new build (id, name or path). |
| `diff` | boolean |  | `false` | Add a unified diff of the old and new decompiled C# of each matched pair (cut at 300 lines). |
| `il` | boolean |  | `false` | Add a unified diff of the matched methods' normalized IL (docs/il-hash.md). |

### compare_native_images

**Compare native builds** (read-only, idempotent, long-running)

Match the functions of two builds of one native image (x86 / x64 / ARM64). Tiers, each accepting a pair only when unique on both sides: 1 same name, import thunk or identical bytes (addresses masked); 2 same control-flow graph and instruction shapes; 3 same imports, strings and constants; 4 call-graph propagation from matched pairs (callees, callers, vtable slots, moved neighbours) to a fixed point; 5 fuzzy similarity above minScore with a margin over the runner-up. Returns per-tier counts and one paged list (view). The first call waits for both code indexes; results are cached until names change.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `oldImage` | string | yes |  | The older build: native image id or path (load both; the second gets an id like app.dll#2). |
| `newImage` | string | yes |  | The newer build: native image id or path. |
| `view` | string |  |  | pairs (default), changed (pairs whose code differs), unmatched or ambiguous (with candidates). Values: pairs, changed, unmatched, ambiguous. |
| `tier` | integer |  | `0` | Only pairs of this tier (1-5); 0 for all. |
| `useNames` | boolean |  | `true` | Match functions by export, PDB, Il2Cpp and user names first (tier 1); false: code only. |
| `minScore` | number |  | `0.7` | Least similarity for a fuzzy match (0-1). |
| `offset` | integer |  | `0` | Items to skip. |
| `limit` | integer |  | `100` | Items to return (max 2000). |

Structured output: `oldImage`, `newImage`, `oldFunctions`, `newFunctions`, `matched`, `identical`, `changed`, `unmatchedOld`, `unmatchedNew`, `ambiguous`, `tiers`, `view`, `offset`, `total`, `truncated`, `pairs`, `unmatched`, `ambiguousFunctions`, `notes`, `seconds`.

### diff_function

**Diff a function between builds** (read-only, idempotent, open-world, long-running)

What changed in one function between two builds (paired through compare_native_images). view=asm: both instruction lists aligned, rows = (same), ~ (other operands), - or +, with build-independent operands (branch labels, matched callee names, string text, mapped data) so moved code and relocations do not show; only changed regions with context. view=pseudocode: a unified diff of both functions' pseudocode, addresses replaced the same way. An unmatched function returns the reason and candidates.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `oldImage` | string | yes |  | The older build: native image id or path (load both; the second gets an id like app.dll#2). |
| `newImage` | string | yes |  | The newer build: native image id or path. |
| `address` | string | yes |  | An address in the function: Hex VA or RVA (rva:/va:/off: prefix), export, module!import or function name. |
| `side` | string |  |  | Which build the address is in (default old). Values: old, new. |
| `view` | string |  |  | asm (default) or pseudocode (needs an engine). Values: asm, pseudocode. |
| `context` | integer |  | `4` | Unchanged rows or lines around each change (0-50). |
| `maxLines` | integer |  | `300` | Most rows or lines returned (max 5000). |
| `useNames` | boolean |  | `true` | Match functions by export, PDB, Il2Cpp and user names first (tier 1); false: code only. |
| `engine` | string |  |  | view=pseudocode: auto (default): a finished IDA / Ghidra analysis of this session, else ours (the built-in index); never starts one. ida / ghidra: that engine, started when needed. Values: auto, ida, ghidra. |

Structured output: `oldImage`, `newImage`, `oldFunction`, `newFunction`, `oldAddress`, `newAddress`, `tier`, `basis`, `score`, `view`, `summary`, `same`, `changed`, `removed`, `added`, `rows`, `unified`, `candidates`, `truncated`, `notes`.

### map_address_between_builds

**Map an address to a new build** (read-only, idempotent, long-running)

Where an address of the old build is in the new build: a function start to the matched function, an address inside one to the aligned instruction, a string to the same string, other data through the references of matched instructions. Returns the new address with confidence and reason, or null with why and nearby candidates.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `oldImage` | string | yes |  | The older build: native image id or path (load both; the second gets an id like app.dll#2). |
| `newImage` | string | yes |  | The newer build: native image id or path. |
| `address` | string | yes |  | Address in the old build: Hex VA or RVA (rva:/va:/off: prefix), export, module!import or function name. |
| `useNames` | boolean |  | `true` | Match functions by export, PDB, Il2Cpp and user names first (tier 1); false: code only. |

Structured output: `oldImage`, `newImage`, `oldAddress`, `newAddress`, `confidence`, `reason`, `detail`, `oldFunction`, `newFunction`, `tier`, `candidates`.

### make_code_pattern

**Make a code pattern** (read-only, idempotent, open-world, long-running)

A byte pattern for an address that survives rebuilds: instruction bytes with displacements and relocated addresses as ?? ('48 8B 05 ?? ?? ?? ??'), extended until it is unique in the executable sections. anchor=reference (or auto when the code is not unique): the pattern starts at an instruction referencing the address, with the operand offset to recover it from a hit. anchor=xrefs: a signature at each referencing instruction, so a rebuild that changed one site keeps others. anchor=range: [address, end), unique or not. search_code_pattern finds it in another build.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `image` | string | yes |  | Native image id, file name or path (a path is loaded). |
| `address` | string | yes |  | Hex VA or RVA (rva:/va:/off: prefix), export, module!import or function name. |
| `anchor` | string |  |  | auto (default): the address, else a reference to it; xrefs: one per reference. Values: auto, address, reference, xrefs, range. |
| `maxBytes` | integer |  | `64` | Longest pattern in bytes (8-512). |
| `maxPatterns` | integer |  | `8` | anchor=xrefs: most signatures (1-32). |
| `engine` | string |  |  | anchor=xrefs: auto (default): a finished IDA / Ghidra analysis of this session, else ours (the built-in index); never starts one. ida / ghidra: that engine, started when needed. Values: auto, ours, ida, ghidra. |
| `format` | string |  |  | Syntax: ida (default), x64dbg, mask (\x48\x00 x?) or bitmask (0x48, 0x00 0b01). Values: ida, x64dbg, mask, bitmask. |
| `end` | string |  |  | anchor=range: exclusive end, an address or +length. |

Structured output: `image`, `address`, `pattern`, `length`, `fixedBytes`, `unique`, `hits`, `anchor`, `patternAddress`, `referenceOffset`, `operandOffset`, `operandSize`, `operandKind`, `instructionEnd`, `note`, `references`, `engine`.

### search_code_pattern

**Search a code pattern** (read-only, idempotent, long-running)

Find a byte pattern with ?? wildcards (as make_code_pattern writes it) in the executable sections of the loaded native images, with the function and offset of each hit.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `pattern` | string | yes |  | Hex bytes with ?? wildcards. |
| `images` | string |  |  | Comma-separated image ids or paths; omit for every loaded native image. |
| `allSections` | boolean |  | `false` | Search every section, not only executable ones. |
| `limit` | integer |  | `200` | Max hits (max 5000). |

Structured output: `pattern`, `length`, `images`, `total`, `truncated`, `hits`, `notes`.

### migrate_native_names

**Carry names to a new build** (edit, idempotent, long-running)

Copy names and comments from the old build to the new build's user annotations through the function matches and address mapping (map_address_between_builds). Sources: the old build's user annotations with its engine types, optionally its pdb and il2cpp names. Never replaces a user name, comment or type of the new build; every skipped item has a reason code.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `oldImage` | string | yes |  | The older build: native image id or path (load both; the second gets an id like app.dll#2). |
| `newImage` | string | yes |  | The newer build: native image id or path. |
| `dryRun` | boolean |  | `false` | Preview the change without applying it. |
| `minTier` | integer |  | `5` | Weakest match tier accepted: 1 (names and identical bytes) to 5 (all). |
| `minScore` | number |  | `0` | Least mapping confidence accepted (0-1). |
| `sources` | string |  |  | Comma-separated layers to copy: user (default), pdb, il2cpp. |
| `comments` | boolean |  | `true` | Copy comments too. |
| `useNames` | boolean |  | `true` | Match functions by export, PDB, Il2Cpp and user names first (tier 1); false: code only. |
| `offset` | integer |  | `0` | Entries to skip in the report. |
| `limit` | integer |  | `200` | Entries to return (max 5000). |

Structured output: `oldImage`, `newImage`, `dryRun`, `considered`, `set`, `skipped`, `skippedBy`, `offset`, `total`, `truncated`, `entries`, `notes`.

### migrate_native_patches

**Migrate patches to a new build** (destructive, long-running)

Carry byte patches from an old build to a new one through the build matcher (compare_native_images). A patch is reapplied only where the new build's original bytes at the mapped address match what it expected (patch_asm patches ignore relocated and displacement bytes and are re-assembled there), through the normal patch path; each is reported applied or refused with a reason code. The same image as old and new with patchSet replays a patch set on its own build (an export, or an unsaved session's journal).

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `oldImage` | string | yes |  | The old build: native image id or path (its in-memory patches are the source unless patchSet). |
| `newImage` | string | yes |  | The new build: native image id or path (load both; the second gets an id like name#2). |
| `patchSet` | string |  |  | A JSON patch set (export_native_patches format=json): path or text. |
| `dryRun` | boolean |  | `true` | Preview the change without applying it. |
| `useNames` | boolean |  | `true` | Match functions by export, PDB, Il2Cpp and user names first; false: code only. |
| `offset` | integer |  | `0` | Entries to skip in the report. |
| `limit` | integer |  | `200` | Entries to return (max 5000). |

Structured output: `oldImage`, `newImage`, `source`, `dryRun`, `patches`, `applied`, `wouldApply`, `refused`, `refusedBy`, `offset`, `total`, `truncated`, `entries`, `notes`.

### update_to_new_build

**Update work to a new build** (destructive, idempotent, long-running)

Carry everything done on an old build of a native image (x86 / x64 / ARM64) to its new build in one call, through one function match (compare_native_images): user names, comments and engine types (migrate_native_names rules); the PDB layer (re-imported only from the new build's matching PDB) and the Il2Cpp layer (re-applied from the new build's metadata, else mapped through the match); byte patches (migrate_native_patches rules; stubs re-created after the displaced instructions are verified); code patterns at every carried site, checked for drift; for Il2Cpp the method -> RVA mapping by metadata identity; and notes. dryRun=false applies names, layers, then patches; a re-run reports already_present. Returns a summary, per-category counts with reason codes and a paged item list. .NET assemblies: compare_assemblies, find_counterpart, export_edits + apply_edits.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `oldImage` | string | yes |  | The old build: native image id or path (the source of names, layers and patches). |
| `newImage` | string | yes |  | The new build: native image id or path (load both; the second gets an id like name#2). |
| `dryRun` | boolean |  | `true` | Report what would carry over without changing the new build. |
| `include` | string |  |  | Comma-separated: names, pdb, il2cpp (names layer and method mapping), patches, patterns, notes; default all. |
| `patchSet` | string |  |  | A JSON patch set (export_native_patches format=json; path or text) instead of the old build's in-memory patches. |
| `stubPlacement` | string |  |  | Where re-created patch stubs go: auto (default: a cave, else a new section), cave or section. Values: auto, cave, section. |
| `oldIl2Cpp` | string |  |  | The old build's Il2Cpp dummy assemblies (comma-separated ids); omit to find them (a dump of this binary, the metadata beside it, or what apply_il2cpp_names used). |
| `newIl2Cpp` | string |  |  | The new build's Il2Cpp dummy assemblies (comma-separated ids); omit to find them the same way. |
| `useNames` | boolean |  | `true` | Match functions by export, PDB, Il2Cpp and user names first; false: code only. |
| `maxPatterns` | integer |  | `100` | Most sites (names and patches) to make code patterns for (0-1000). |
| `category` | string |  |  | Only items of this category. Values: names, pdb, il2cpp_names, patches, patterns, il2cpp_mapping, notes, dotnet. |
| `outcome` | string |  |  | Only items with this outcome. Values: carried, would_carry, already_present, refused, not_applicable, ambiguous. |
| `offset` | integer |  | `0` | Items to skip. |
| `limit` | integer |  | `100` | Items to return (max 2000). |

Structured output: `summary`, `oldImage`, `newImage`, `dryRun`, `included`, `oldFunctions`, `newFunctions`, `functionsMatched`, `categories`, `il2CppMapping`, `category`, `outcome`, `offset`, `total`, `truncated`, `items`, `notes`, `seconds`.

## notes

Analyst notes kept per binary across sessions.

### record_note

**Record a note** (edit)

Record a finding, question, hypothesis or todo anchored to a native address, a .NET member, a file or a dump; notes persist per user, keyed by SHA-256 / MVID so they follow the binary, and decompile_member / decompile_native count a target's open ones.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `text` | string | yes |  | At most 4,000 characters. |
| `kind` | string |  |  | Default finding. Values: finding, question, hypothesis, todo. |
| `status` | string |  |  | Default open. Values: open, confirmed, refuted, answered, dropped. |
| `anchor` | string |  |  | '<image>@<address>', '<assembly>:<symbol or token>', an image or assembly id (the whole file), 'dump:<id or path>', or empty (session-wide). |
| `tags` | string |  |  | Comma-separated tags (at most 10). |
| `evidence` | string |  |  | Where it was seen, ';'-separated (at most 10), e.g. a tool call. |

Structured output: `id`, `kind`, `status`, `text`, `tags`, `evidence`, `anchor`, `revision`, `created`, `updated`, `author`.

### update_note

**Update a note** (destructive, idempotent)

Change a note in part: status, kind, text, tags, evidence. A note changed since expectedRevision fails with a conflict carrying it (details.current).

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `id` | string | yes |  | Note id. |
| `expectedRevision` | integer | yes |  | The revision last read. |
| `status` | string |  |  | New status. Values: open, confirmed, refuted, answered, dropped. |
| `kind` | string |  |  | New kind. Values: finding, question, hypothesis, todo. |
| `text` | string |  |  | Replacement text. |
| `appendText` | string |  |  | Text appended on a new line. |
| `addTags` | string |  |  | Comma-separated tags to add. |
| `removeTags` | string |  |  | Comma-separated tags to remove. |
| `addEvidence` | string |  |  | ';'-separated evidence entries to add. |

Structured output: `id`, `kind`, `status`, `text`, `tags`, `evidence`, `anchor`, `revision`, `created`, `updated`, `author`.

### list_notes

**List notes** (read-only, idempotent)

Notes, newest first, by status, kind, anchor, tag and text. A file anchor lists all its notes, '<image>@<address>' those in the containing function, '<assembly>:<type>' those on its members too.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `status` | string |  |  | Default open; all for every status. Values: open, confirmed, refuted, answered, dropped, all. |
| `kind` | string |  |  | Only this kind. Values: finding, question, hypothesis, todo. |
| `anchor` | string |  |  | '<image>@<address>', '<assembly>:<symbol or token>', an image or assembly id (the whole file), 'dump:<id or path>', or empty (session-wide). |
| `tag` | string |  |  | Only notes with this tag. |
| `text` | string |  |  | Text substring (case-insensitive). |
| `offset` | integer |  | `0` | Notes to skip. |
| `limit` | integer |  | `50` | Notes to return (max 500). |

Structured output: `items`, `offset`, `total`, `truncated`, `notes`.

## engine

Edits inside the decompiler engine's database: types, locals, frames, declarations, scripting.

### set_native_type

**Set a native prototype or global type** (destructive, idempotent, open-world, long-running)

Set the prototype of a native function ('int __fastcall Parse(Packet *p, int len)') or the type of a global ('Handler *[8]') in the engine. Named types must exist there (pushed PDB, RTTI and Il2Cpp types, or declare_native_types). User types win over recovered ones; empty clears. A prototype's name renames the function unless rename=false. Kept with the image's annotations.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `image` | string | yes |  | Native image id, file name or path (a path is loaded). |
| `address` | string |  |  | A function start or a global: Hex VA or RVA (rva:/va:/off: prefix), export, module!import or function name. |
| `type` | string |  |  | C prototype for a function, C type for a global; empty to clear the user type. |
| `items` | string |  |  | Instead of address and type: lines 'address = type'. |
| `rename` | boolean |  | `true` | Name the function as its prototype does. |
| `guess` | boolean |  | `false` | Report the engine's guess at address without applying it. |
| `showDecompile` | string |  |  | The function's pseudocode after the edit (after) or its unified diff (diff). Values: none, after, diff. |
| `engine` | string |  |  | auto (default): the engine with this image open, else IDA when installed, else Ghidra. Values: auto, ida, ghidra. |

### set_native_local

**Rename or retype a decompiler local** (destructive, idempotent, open-world, long-running)

Rename and/or retype a local or argument in a native function's pseudocode, named as decompile_native shows it (v3, a1) or stack:0x28. Later edits may use its new name; its first name again, or clear, drops the edit. A type that does not fit is refused. Kept with the image's annotations.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `image` | string | yes |  | Native image id, file name or path (a path is loaded). |
| `function` | string | yes |  | The function: Hex VA or RVA (rva:/va:/off: prefix), export, module!import or function name. |
| `local` | string |  |  | The variable: its name in the pseudocode, or stack:<offset> (hex). |
| `newName` | string |  |  | New name (a C identifier). |
| `type` | string |  |  | New C type. |
| `clear` | boolean |  | `false` | Drop the user's name and type of the variable. |
| `items` | string |  |  | Instead of local: lines 'local = newName', or JSON [{local, newName?, type?, clear?}]. |
| `showDecompile` | string |  |  | The function's pseudocode after the edit (after) or its unified diff (diff). Values: none, after, diff. |
| `engine` | string |  |  | auto (default): the engine with this image open, else IDA when installed, else Ghidra. Values: auto, ida, ghidra. |

### set_native_stack_var

**Rename, retype or delete a stack variable** (destructive, idempotent, open-world, long-running)

Rename and/or retype a stack frame member, by its get_native_frame name (var_28) or frame offset (0x20, from the lowest address); a type at an empty offset creates one. The return address and saved registers are refused. Kept with the image's annotations.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `image` | string | yes |  | Native image id, file name or path (a path is loaded). |
| `function` | string | yes |  | The function: Hex VA or RVA (rva:/va:/off: prefix), export, module!import or function name. |
| `variable` | string | yes |  | The member: its name, or its frame offset (hex). |
| `newName` | string |  |  | New name (a C identifier). |
| `type` | string |  |  | New C type. |
| `delete` | boolean |  | `false` | Delete the member. |
| `clear` | boolean |  | `false` | Drop the user's edit, restoring the engine's member. |
| `showDecompile` | string |  |  | The function's pseudocode after the edit (after) or its unified diff (diff). Values: none, after, diff. |
| `engine` | string |  |  | auto (default): the engine with this image open, else IDA when installed, else Ghidra. Values: auto, ida, ghidra. |

### get_native_frame

**Native stack frame and locals** (read-only, idempotent, open-world, long-running)

A native function's stack frame as the engine has it (members: offset, name, type, size; Ghidra counts saved registers as locals) and its decompiler locals (name, type, register or stack offset, user edits). Offsets count from the frame's lowest address; brackets give the offset from the return address (IDA's var_/arg_).

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `image` | string | yes |  | Native image id, file name or path (a path is loaded). |
| `function` | string | yes |  | The function: Hex VA or RVA (rva:/va:/off: prefix), export, module!import or function name. |
| `engine` | string |  |  | auto (default): the engine with this image open, else IDA when installed, else Ghidra. Values: auto, ida, ghidra. |

### declare_native_types

**Declare C types in the engine** (destructive, idempotent, open-world, long-running)

Declare C types (structs, unions, enums, typedefs, function types) in the engine; a type of the same name is replaced, and declarations win over recovered types. Errors carry the engine's messages and are not saved. typeName with members upserts or removes enum members, with fields struct or union members; delete or rename edits a named type. Kept with the image's annotations.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `image` | string | yes |  | Native image id, file name or path (a path is loaded). |
| `declarations` | string |  |  | C declarations; types they name must exist or be declared too. |
| `typeName` | string |  |  | Enum, struct or union to edit. |
| `members` | string |  |  | Enum: 'NAME=value, ...' (hex or decimal; or lines); 'NAME=' removes. |
| `fields` | string |  |  | Struct or union: 'name: type; name@0x10: type; @0x10: type' (or lines); 'name:' removes. |
| `delete` | string |  |  | A type to delete. |
| `rename` | string |  |  | 'Old=New'; kept edits naming it follow. |
| `engine` | string |  |  | auto (default): the engine with this image open, else IDA when installed, else Ghidra. Values: auto, ida, ghidra. |

### list_native_types

**Browse the engine's types** (read-only, idempotent, open-world, long-running)

The named types of the engine's database (PDB, RTTI, Il2Cpp, type libraries, declare_native_types) with size and member count; name= shows one type as a C declaration with member offsets.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `image` | string | yes |  | Native image id, file name or path (a path is loaded). |
| `filter` | string |  |  | Name filter: substring (case-insensitive), glob with * and ?, or /regex/ (flags i, m, s). |
| `kind` | string |  |  | udt: struct or union. Values: struct, union, udt, enum, typedef, func, ptr. |
| `name` | string |  |  | Show this one type in full instead of a list. |
| `offset` | integer |  | `0` | Index of the first row. |
| `limit` | integer |  | `200` | Max rows (max 5000). |
| `engine` | string |  |  | auto (default): the engine with this image open, else IDA when installed, else Ghidra. Values: auto, ida, ghidra. |
| `sort` | string |  |  | Default: the engine's order. Values: name, size. |
| `descending` | boolean |  | `false` | Reverse the order. |
| `members` | boolean |  | `false` | List each type's first 32 members (enums: name = value). |
| `related` | boolean |  | `false` | Add the types each one refers to. |

### define_native

**Redefine code or data in the engine** (destructive, idempotent, open-world, long-running)

Change the engine's analysis at an address. code decodes instructions (to end, else following the flow); function makes a function (with end: its extent; on one: moves its end); undefine makes unknown bytes (to end, else the item; at a function start the function); data makes a data item of type. Data and undefine replace a user type on a global there. Kept with the image's annotations.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `image` | string | yes |  | Native image id, file name or path (a path is loaded). |
| `address` | string | yes |  | Start: Hex VA or RVA (rva:/va:/off: prefix), export, module!import or function name. |
| `kind` | string | yes |  | What to make. Values: code, function, undefine, data. |
| `end` | string |  |  | Exclusive end address (same forms as address). |
| `type` | string |  |  | kind=data: byte, word, dword, qword, float, double, string, string16 (UTF-16) or a C type, with an optional [count] (dword[8]). |
| `engine` | string |  |  | auto (default): the engine with this image open, else IDA when installed, else Ghidra. Values: auto, ida, ghidra. |

### reanalyze_native

**Re-run native auto-analysis** (destructive, open-world, long-running)

Run IDA's or Ghidra's auto-analysis again over an image (or start-end) and save the database; a full run also completes a Ghidra analysis the open's budget cut short. options= sets analyzers for this run only; analyzers=true lists them with their values.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `image` | string | yes |  | Native image id, file name or path (a path is loaded). |
| `engine` | string |  |  | Default: the engine with this image open, else IDA, else Ghidra. Values: auto, ida, ghidra. |
| `analyzers` | boolean |  | `false` | List the analyzer options and values instead of running. |
| `filter` | string |  |  | With analyzers: name filter. |
| `options` | string[] |  |  | name=value per option (AF_FLIRT=false, 'Decompiler Parameter ID=true'). |
| `start` | string |  |  | Range start (default: the whole image). |
| `end` | string |  |  | Range end (exclusive). |
| `seconds` | integer |  | `600` | Seconds (max 3600); what is left runs on the next run. |

### set_native_operand

**Set how an operand displays** (destructive, idempotent, open-world, long-running)

Set how an instruction operand displays in the engine's disassembly and, where the decompiler follows it, the pseudocode: offset (the constant as an address), stack (a stack variable), enum (type: the enum; a member of the constant's value), struct (type: 'Packet' or 'Packet+0x10'; IDA only) or default (the engine's). Ghidra shows numbers and enum members as equates. Kept with the image's annotations.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `image` | string | yes |  | Native image id, file name or path (a path is loaded). |
| `address` | string | yes |  | The instruction: Hex VA or RVA (rva:/va:/off: prefix), export, module!import or function name. |
| `operand` | integer | yes |  | Operand index, 0 for the first. |
| `display` | string | yes |  | How to display it (see the description). Values: hex, dec, oct, bin, char, offset, stack, enum, struct, default. |
| `type` | string |  |  | display=enum or struct: the type's name (struct: optionally +delta). |
| `engine` | string |  |  | auto (default): the engine with this image open, else IDA when installed, else Ghidra. Values: auto, ida, ghidra. |

### ida_python

**Run IDAPython on a native image** (destructive, open-world, long-running)

Run Python in the IDA worker holding a native image's database (idalib): IDAPython modules imported, base is the image base, globals persist between calls (reset=true clears them); returns a final expression's value, stdout and stderr. Off unless the server runs with --ida-scripting (CORVUS_IDA_SCRIPTING=1): the code has the server's rights and can destroy the database. Changes are not journaled: a worker restart loses them unless persist=true saves the database.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `image` | string | yes |  | Native image id, file name or path (a path is loaded). |
| `code` | string |  |  | Python source (or pass file). |
| `reset` | boolean |  | `false` | Clear the globals earlier calls left. |
| `engine` | string |  |  | Default auto. Values: auto, ida. |
| `file` | string |  |  | A .py file to run instead of code. |
| `maxOutput` | integer |  | `20000` | Characters kept of the result, stdout and stderr each (100-200000). |
| `persist` | boolean |  | `false` | Save the database after the script. |

### ghidra_script

**Run a Ghidra script on a native image** (destructive, open-world, long-running)

Run Java in the Ghidra worker holding a native image's program: a GhidraScript class, or run()'s body with imports first (currentProgram, println, FlatProgramAPI). One transaction, committed when the script returns, then saved. Off unless the server runs with --ghidra-scripting (CORVUS_GHIDRA_SCRIPTING=1): the code has the server's rights. Changes are not in the annotation sidecar.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `image` | string | yes |  | Native image id, file name or path (a path is loaded). |
| `code` | string | yes |  | Java source: a class extending GhidraScript, or statements for run(). |
| `timeout` | integer |  | `120` | Seconds before the script is cancelled (1-3600). |
| `engine` | string |  |  | Default auto. Values: auto, ghidra. |

### export_engine_database

**Export the engine database** (destructive, idempotent, open-world, long-running)

Write a native image's engine database (analysis plus the names, comments and types pushed from here) for the engine's GUI: IDA a compressed .i64 copy, Ghidra a packed .gzf archive; Ghidra's own types also as a .h header or .gdt archive. The worker keeps its own.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `image` | string | yes |  | Native image id, file name or path (a path is loaded). |
| `outputPath` | string | yes |  | The .i64 (IDA), .gzf, .h or .gdt (Ghidra) file to write. |
| `force` | boolean |  | `false` | Replace outputPath if it exists. |
| `engine` | string |  |  | Default: the extension's engine, else IDA. Values: auto, ida, ghidra. |

Structured output: `image`, `engine`, `path`, `bytes`, `note`.

## android

Android packages: manifest, resources, DEX code, Java decompilation, Java / .NET mapping, devices.

### get_android_manifest

**Android manifest** (read-only, idempotent)

AndroidManifest.xml of an Android package, decoded: package, versions, SDKs; used and declared permissions; application flags (debuggable, allowBackup, cleartext traffic, network security config); each component with its effective exported state and why, permissions, intent filters, deep links, meta-data; queries, features, libraries; highlights. The raw XML: get_android_resource.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `path` | string | yes |  | An .apk, .aab (base module) or split set (.apks, .xapk, .apkm). |

Structured output: `package`, `versionCode`, `versionName`, `minSdk`, `targetSdk`, `maxSdk`, `compileSdk`, `split`, `permissions`, `declaredPermissions`, `application`, `components`, `queries`, `features`, `libraries`, `metaData`, `highlights`, `issues`.

### list_android_resources

**List Android resources** (read-only, idempotent)

Compiled resources of an Android package (resources.arsc or a bundle's resources.pb): a row per resource and configuration with id, type, name, qualifiers ('' is the default), value type and value (references by name); types counts each type.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `path` | string | yes |  | An .apk, .aab (base module) or split set (.apks, .xapk, .apkm). |
| `type` | string |  |  | Only this type (string, layout, xml, ...). |
| `name` | string |  |  | Only names matching this (* and ? wildcards). |
| `config` | string |  |  | Only this configuration: qualifiers as in a directory name (pt-rBR), or default. |
| `offset` | integer |  | `0` | Rows to skip. |
| `limit` | integer |  | `500` | Most rows to return. |

Structured output: `items`, `offset`, `total`, `truncated`, `types`.

### get_android_resource

**Get Android resource** (destructive, idempotent)

One file or resource of an Android package: an entry path is read with binary XML decoded and references named, text as text, other data as a hex preview; @type/name or 0x7f... gives the resource's value in every configuration. savePath writes the raw bytes.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `path` | string | yes |  | An .apk, .aab (base module) or split set (.apks, .xapk, .apkm). |
| `name` | string | yes |  | An entry path (res/xml/x.xml, assets/...), @type/name or a resource id 0x7f... |
| `savePath` | string |  |  | Write the entry's bytes to this file. |
| `overwrite` | boolean |  | `false` | Replace savePath if it exists. |
| `offset` | integer |  | `0` | Character offset from the truncation footer. |
| `maxChars` | integer |  |  | Page size in characters (default ~60000). |

### list_dex_classes

**List DEX classes** (read-only, idempotent)

Classes defined in the DEX code of an Android package (every classes*.dex): descriptor, Java name, DEX file, access, superclass, interfaces, member counts, source file. No Java tools needed.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `path` | string | yes |  | An Android package (.apk, .aab, .apks, .xapk, .apkm), a .dex, or a jar / zip with classes*.dex. |
| `query` | string |  |  | Only classes whose Java name or descriptor contains this, or matches it (* and ? wildcards). |
| `package` | string |  |  | Only this package and its subpackages. |
| `offset` | integer |  | `0` | Classes to skip. |
| `limit` | integer |  | `500` | Most classes to return. |

Structured output: `items`, `offset`, `total`, `truncated`, `notes`.

### get_dex_class

**DEX class** (read-only, idempotent)

One DEX class in full: superclass, interfaces, generic signature, enclosing and inner classes, Kotlin @Metadata, annotations; fields with type and static initial value; methods with their exact id (Lpkg/C;->name(params)ret, unique per overload), Java signature, code size, registers and parameter names.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `path` | string | yes |  | An Android package (.apk, .aab, .apks, .xapk, .apkm), a .dex, or a jar / zip with classes*.dex. |
| `class` | string | yes |  | Class: Lpkg/Name;, pkg.Name, or pkg.Outer.Inner / pkg.Outer$Inner. |

Structured output: `descriptor`, `javaName`, `dexFile`, `access`, `super`, `interfaces`, `sourceFile`, `genericSignature`, `enclosingClass`, `enclosingMethod`, `innerClasses`, `kotlin`, `annotations`, `fields`, `methods`.

### disassemble_dex

**Disassemble DEX** (read-only, idempotent)

Smali of a method or class of an Android package's DEX code, in baksmali's layout. format=annotated adds code offsets and units.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `path` | string | yes |  | An Android package (.apk, .aab, .apks, .xapk, .apkm), a .dex, or a jar / zip with classes*.dex. |
| `symbol` | string | yes |  | A method (Lpkg/C;->name(params)ret, or pkg.C::name with optional (int, String)) or a class (pkg.C, Lpkg/C;). |
| `format` | string |  |  | Output layout (default smali). Values: smali, annotated. |
| `offset` | integer |  | `0` | Character offset from the truncation footer. |
| `maxChars` | integer |  |  | Page size in characters (default ~60000). |

### decompile_java

**Decompile Java** (read-only, idempotent, open-world, long-running)

Java source of a class or one method of an Android package through JADX (CORVUS_JAVA_DECOMPILER, JDK 17+; one session per package kept loaded). Without JADX: provider_unavailable; disassemble_dex gives smali.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `path` | string | yes |  | An Android package (.apk, .aab, .apks, .xapk, .apkm), a .dex, or a jar / zip with classes*.dex. |
| `symbol` | string | yes |  | A class (pkg.C, Lpkg/C;) or a method (Lpkg/C;->name(params)ret, or pkg.C::name with optional (int, String)). |
| `smaliFallback` | boolean |  | `true` | Return smali where JADX fails. |
| `engine` | string |  |  | Decompiler. Values: jadx. |
| `offset` | integer |  | `0` | Character offset from the truncation footer. |
| `maxChars` | integer |  |  | Page size in characters (default ~60000). |

### search_dex

**Search DEX code** (read-only, idempotent, long-running)

Search the DEX code of an Android package. kind=string: string literals with the method and offset of each use; type: defined classes and type uses; method / field: defined and referenced members with use counts; const: numeric constants; opcode: instructions by mnemonic (invoke-static).

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `path` | string | yes |  | An Android package (.apk, .aab, .apks, .xapk, .apkm), a .dex, or a jar / zip with classes*.dex. |
| `kind` | string | yes |  | What to search. Values: string, type, method, field, const, opcode. |
| `query` | string | yes |  | Case-insensitive substring or * / ? pattern; for const a number. |
| `offset` | integer |  | `0` | Hits to skip. |
| `limit` | integer |  | `200` | Most hits to return. |

Structured output: `items`, `offset`, `total`, `truncated`, `notes`.

### find_dex_references

**Find DEX references** (read-only, idempotent, long-running)

Cross-references in DEX code with the method and code offset of each instruction. direction=to: callers of a method, readers and writers of a field, uses of a class or a string literal. direction=from: what a method (or every method of a class) calls, reads, writes and loads. Methods match by exact id, never another overload.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `path` | string | yes |  | An Android package (.apk, .aab, .apks, .xapk, .apkm), a .dex, or a jar / zip with classes*.dex. |
| `target` | string | yes |  | A class, a method (Lpkg/C;->m(I)V, or pkg.C::m with optional parameters (int, String)), a field (Lpkg/C;->f:I or pkg.C::f), or a string in double quotes. |
| `direction` | string |  |  | to (default: who refers to the target) or from (what it refers to). Values: to, from. |
| `kind` | string |  |  | How to read target (default auto; string: taken literally). Values: auto, class, method, field, string. |
| `offset` | integer |  | `0` | References to skip. |
| `limit` | integer |  | `500` | Most references to return. |

Structured output: `target`, `targetKind`, `direction`, `items`, `offset`, `total`, `truncated`, `notes`.

### map_java_dotnet

**Map Java and .NET** (read-only, idempotent)

The other side of a Java / .NET bridge, ready for decompile_member or get_dex_class. .NET for Android (Xamarin / MAUI): a Java wrapper class or method gives its .NET type or method and back ([Register] names and crc64 wrapper names). Unity Mono: the C# reaching a Java class or member through AndroidJavaClass / AndroidJavaObject / AndroidJavaProxy / AndroidJNI, and back, with a confidence. Reads the loaded assemblies, and the package's with path.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `symbol` | string | yes |  | A Java class (Lpkg/C; or pkg.C), Java method id (Lpkg/C;->m(I)V), or a .NET type or member. |
| `path` | string |  |  | The .apk / .aab whose assemblies to read without loading; optional when they are loaded. |

Structured output: `query`, `direction`, `items`, `notes`.

### list_jni_bindings

**List JNI bindings** (read-only, idempotent, long-running)

Java native methods of an Android package paired with their code in lib/<abi>/*.so: Java_ exports by JNI name mangling and RegisterNatives tables in the libraries' data; also unbound methods and stray Java_ exports.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `path` | string | yes |  | An .apk, .aab (base module) or split set (.apks, .xapk, .apkm). |
| `abi` | string |  |  | ABI to read, or all; default arm64-v8a, else the first. |
| `class` | string |  |  | Only rows naming this class (pkg.C or pkg/C). |
| `kind` | string |  |  | Only this kind. Values: static_export, registered, unresolved, export_only. |
| `offset` | integer |  | `0` | Rows to skip. |
| `limit` | integer |  | `200` | Most rows. |

Structured output: `items`, `offset`, `total`, `truncated`, `libraries`, `notes`.

### list_android_devices

**List Android devices** (read-only, idempotent, open-world)

Android devices and emulators adb sees: serial, state, product, model, transport. adb: CORVUS_ADB, else PATH, else the SDK's platform-tools.

No parameters.

Structured output: `items`, `unparsed`.

### get_android_device_info

**Android device info** (read-only, idempotent, open-world)

A device's properties (getprop), paged and filterable, with a summary: SDK, release, model, ABIs, fingerprint, security patch, build type, ro.debuggable, ro.secure, and whether it is an emulator.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `serial` | string |  |  | Device serial (list_android_devices); optional with one ready device. |
| `query` | string |  |  | Only properties whose name or value contains this. |
| `offset` | integer |  | `0` | Properties to skip. |
| `limit` | integer |  | `200` | Most properties to return. |

Structured output: `serial`, `summary`, `properties`, `offset`, `total`, `truncated`.

### list_android_packages

**List installed packages** (read-only, idempotent, open-world)

Packages installed on a device (pm list packages -f -U -i): name, APK path, uid and installer.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `serial` | string |  |  | Device serial (list_android_devices); optional with one ready device. |
| `query` | string |  |  | Only package names containing this. |
| `user` | integer |  |  | Android user id (default: the current one). |
| `offset` | integer |  | `0` | Packages to skip. |
| `limit` | integer |  | `500` | Most packages to return. |

Structured output: `serial`, `items`, `offset`, `total`, `truncated`.

### get_android_package_info

**Installed package info** (read-only, idempotent, open-world)

One installed package (dumpsys package): versions, SDKs, paths, ABI, flags, install times, installer, uid, requested permissions with their grant state, and per-user state.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `package` | string | yes |  | Package name, e.g. com.example.app. |
| `serial` | string |  |  | Device serial (list_android_devices); optional with one ready device. |

Structured output: `serial`, `package`, `versionName`, `versionCode`, `minSdk`, `targetSdk`, `codePath`, `dataDir`, `primaryCpuAbi`, `flags`, `firstInstallTime`, `lastUpdateTime`, `installer`, `uid`, `permissions`, `users`.

### pull_android_package

**Pull installed package** (edit, idempotent, open-world, long-running)

Copies every APK of an installed package (base and splits) into a new or empty directory, with size and SHA-256 each, then summarizes the base APK as summarize_file does. A failed pull leaves no files.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `package` | string | yes |  | Package name, e.g. com.example.app. |
| `outputDirectory` | string | yes |  | A new or empty directory to write the APKs to. |
| `serial` | string |  |  | Device serial (list_android_devices); optional with one ready device. |

Structured output: `serial`, `package`, `files`, `summary`.

### pull_android_file

**Pull device file** (destructive, idempotent, open-world, long-running)

Copies one file from a device (directories are refused) to outputPath, with its size and SHA-256; a failed pull leaves nothing behind.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `remotePath` | string | yes |  | The file's path on the device. |
| `outputPath` | string | yes |  | The local file to write. |
| `overwrite` | boolean |  | `false` | Replace outputPath if it exists. |
| `serial` | string |  |  | Device serial (list_android_devices); optional with one ready device. |

Structured output: `remote`, `local`, `size`, `sha256`.

### read_android_log

**Read device log** (read-only, idempotent, open-world)

The device log so far (logcat -d), narrowed by process, tag, priority and start time; beyond maxBytes it is cut (truncated=true).

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `serial` | string |  |  | Device serial (list_android_devices); optional with one ready device. |
| `pid` | integer |  |  | Only this process id. |
| `tag` | string |  |  | Only this log tag. |
| `priority` | string |  |  | Lowest priority. Values: V, D, I, W, E, F. |
| `since` | string |  |  | Only lines since this time (logcat -t form, '01-31 12:00:00.000') or the last N lines. |
| `maxBytes` | integer |  | `262144` | Most bytes of log to return. |

### install_android_package

**Install package on device** (destructive, open-world, long-running)

Installs an APK, a split set or a directory of APKs on a device in one session; failures come back by their INSTALL_FAILED_ code. Changes the device: off unless the server runs with --allow-device-changes.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `path` | string | yes |  | An .apk, a split set (.apks, .xapk, .apkm) or a directory of APKs. |
| `replace` | boolean |  | `true` | Replace an installed app. |
| `downgrade` | boolean |  | `false` | Allow a lower version code. |
| `grantPermissions` | boolean |  | `false` | Grant every runtime permission the manifest requests. |
| `serial` | string |  |  | Device serial (list_android_devices); optional with one ready device. |

### uninstall_android_package

**Uninstall package from device** (destructive, idempotent, open-world)

Removes an app from a device, with its data unless keepData. Changes the device: off unless the server runs with --allow-device-changes.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `package` | string | yes |  | Package name, e.g. com.example.app. |
| `keepData` | boolean |  | `false` | Keep the app's data and cache. |
| `serial` | string |  |  | Device serial (list_android_devices); optional with one ready device. |

## dumps

Crash dumps and crash text.

### open_minidump

**Open a crash dump** (read-only, idempotent, open-world, long-running)

Summary of a Windows minidump (.dmp): OS, CPU, process; the exception (code, faulting thread, module!function, instruction, registers, a C++ exception's thrown type); the .NET state (managed exception with stack and inner chain, threads, heap); modules (version, PDB identity, whether a matching image is here) and threads, paged; unloaded modules, captured memory, parse issues. Gives the id the other dump tools take. Nothing from the dump runs; .NET decoding loads Microsoft's signature-checked DAC for that runtime build.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `path` | string | yes |  | The .dmp path (or an open dump's id). |
| `imageDirectories` | string |  |  | Folders with the crashed program's binaries (';'-separated), for modules whose recorded path is missing or holds another build; the dump's folder is always searched. |
| `modulesOffset` | integer |  | `0` | First module listed. |
| `modulesLimit` | integer |  | `50` | Max modules listed. |
| `threadsOffset` | integer |  | `0` | First thread listed. |
| `threadsLimit` | integer |  | `50` | Max threads listed. |
| `dacPath` | string |  |  | The dumped runtime's DAC (mscordaccore.dll / mscordacwks.dll) or its folder, when that runtime build is not installed here. |
| `downloadDac` | boolean |  | `false` | Download the DAC from a symbol server when no local copy matches (network; refused under CORVUS_OFFLINE=1). |

Structured output: `id`, `path`, `fileSize`, `timeUtc`, `dumpType`, `system`, `process`, `exception`, `managed`, `moduleCount`, `modulesOffset`, `modulesTruncated`, `modules`, `threadCount`, `threadsOffset`, `threadsTruncated`, `threads`, `unloadedModuleCount`, `unloadedModules`, `memory`, `handleCount`, `handleTypes`, `streams`, `comments`, `issues`, `notes`.

### dump_stack

**Crash dump stack** (read-only, idempotent)

Call stack of a minidump thread: x64 unwind data, x86 call targets and the EBP chain; JIT code without unwind data adds heuristic scanned frames. Names from loaded images (code index, PDB, Il2Cpp) or exports (nearest_export is a guess). .NET frames come from the DAC with token, IL offset, the loaded assembly and the C# statement; Mono JIT frames from the runtime's report beside the dump.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `dump` | string | yes |  | A .dmp path or the id open_minidump returned. |
| `thread` | string |  |  | Thread id, '#index', name or 'exception'. Default: the faulting thread, else the first. |
| `exceptionContext` | boolean |  | `true` | Faulting thread: start at the exception context (.ecxr) or, false, at the thread's context when the dump was written. |
| `maxFrames` | integer |  | `256` | Max frames walked (up to 1024). |
| `offset` | integer |  | `0` | First frame returned. |
| `limit` | integer |  | `100` | Max frames returned. |
| `imageDirectories` | string |  |  | Folders with the crashed program's binaries (';'-separated), for modules whose recorded path is missing or holds another build; the dump's folder is always searched. |
| `managed` | string |  | `auto` | auto: .NET frames through a local DAC (or the one open_minidump loaded); off: native walk only. Values: auto, off. |

Structured output: `dump`, `threadId`, `threadName`, `context`, `architecture`, `registers`, `total`, `offset`, `truncated`, `frames`, `stop`, `heuristicFrames`, `managed`, `notes`.

### dump_heap

**Crash dump .NET heap** (read-only, idempotent, long-running)

The .NET GC heap of a minidump (through the DAC). stats: count and size per type, largest first; objects: matching objects (address, type, size, a string's value). Needs heap memory in the dump (else heap_not_captured).

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `dump` | string | yes |  | A .dmp path or the id open_minidump returned. |
| `mode` | string |  | `stats` | stats (per type) or objects (one row each). Values: stats, objects. |
| `type` | string |  |  | Type full name, '*' / '?' wildcards; default all. |
| `minSize` | integer |  | `0` | Only objects of at least this many bytes. |
| `offset` | integer |  | `0` | First row returned. |
| `limit` | integer |  | `50` | Max rows returned (up to 1000). |
| `maxObjects` | integer |  | `5000000` | Max objects walked. |

Structured output: `dump`, `mode`, `type`, `minSize`, `walked`, `walkStopped`, `total`, `offset`, `truncated`, `matchedBytes`, `types`, `objects`, `notes`.

### dump_object

**Crash dump .NET object** (read-only, idempotent)

One .NET object of a minidump (through the DAC): type, size, fields (references expanded depth levels), a string's or boxed value, or array elements.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `dump` | string | yes |  | A .dmp path or the id open_minidump returned. |
| `address` | string | yes |  | Hex address of the object. |
| `depth` | integer |  | `1` | Levels of referenced objects expanded (up to 3). |
| `maxFields` | integer |  | `100` | Max fields listed, nested ones included. |
| `maxArrayItems` | integer |  | `32` | Max array elements listed. |

Structured output: `dump`, `address`, `type`, `size`, `assembly`, `token`, `buildCheck`, `value`, `length`, `fields`, `truncated`, `notes`.

### read_dump_memory

**Read crash dump memory** (read-only, idempotent)

Hex dump of a dump's memory at an address, with what is there (module!function, captured range, protection). With imageFallback, bytes the dump lacks come from the module image (writable data then shows initial values); the source is reported.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `dump` | string | yes |  | A .dmp path or the id open_minidump returned. |
| `address` | string | yes |  | Hex address, 'module+0x1234', or a module name (its base). |
| `length` | integer |  | `256` | Bytes to read (up to 65536). |
| `imageFallback` | boolean |  | `true` | Read bytes the dump does not hold from the module image. |

Structured output: `dump`, `address`, `requested`, `length`, `source`, `location`, `region`, `protection`, `hex`, `bytes`, `note`.

### symbolize_stack_text

**Symbolize crash text** (read-only, idempotent, long-running)

Resolves crash text against the loaded build: Unity Player.log / error.log backtraces, Mono and Il2Cpp managed lines, .NET exception text, Report.wer, Event Log 1000/1026 text, debugger stacks and Android tombstones. Each frame gets our name, a buildCheck (time stamp, MVID, BuildId or the text's own name; a mismatch means another build) and the C# statement at an IL offset.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `text` | string |  |  | The crash text (up to 1 MiB). This or path. |
| `path` | string |  |  | A log or report file; its last 8 MiB are read. |
| `format` | string |  | `auto` | Text format (auto detects it). Values: auto, unity, dotnet, wer, eventlog, windbg, android. |
| `images` | string |  |  | Native image ids or paths (';'-separated); default every loaded one. |
| `moduleBases` | string |  |  | Module load addresses, 'name=0xBASE;...', when the text has no module list. |
| `offset` | integer |  | `0` | First frame returned. |
| `limit` | integer |  | `200` | Max frames returned. |

Structured output: `format`, `exception`, `total`, `offset`, `truncated`, `frames`, `unrecognizedLines`, `unrecognizedSample`, `modulesMissing`, `notes`.

### bucket_minidumps

**Group crash dumps** (read-only, idempotent, long-running)

Groups a folder of minidumps by signature: exception code | faulting module!function | next frames (raising frames skipped); .NET: clr | exception type | top managed frames; no exception: hang | top frames. Names, not offsets, so rebases do not split a bucket. Each bucket lists its dump ids and its newest dump as representative. Cached per file: re-runs parse only new dumps.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `folder` | string | yes |  | Folder of .dmp files. |
| `recursive` | boolean |  | `false` | Also search subfolders. |
| `pattern` | string |  |  | File patterns, ';'-separated (default *.dmp;*.mdmp). |
| `topFrames` | integer |  | `3` | Frames after the faulting one in the signature. |
| `skipModules` | string |  |  | More frames to skip, ';'-separated: module or module!function, '*' wildcards. |
| `splitByVersion` | boolean |  | `false` | Put the faulting module's version in the signature. |
| `managed` | string |  | `auto` | auto: managed signatures for CLR exceptions when a local DAC is found; off: native only. Values: auto, off. |
| `maxDumps` | integer |  | `1000` | Most dumps bucketed, newest first. |
| `imageDirectories` | string |  |  | Folders with the crashed program's binaries (';'-separated), for modules not at their recorded paths. |
| `offset` | integer |  | `0` | First bucket returned. |
| `limit` | integer |  | `50` | Max buckets returned. |

Structured output: `folder`, `dumps`, `total`, `offset`, `truncated`, `buckets`, `failed`, `notes`.

## live

Read-only inspection of a running process.

### inspect_process

**Inspect a running process (read-only)** (read-only, idempotent, open-world)

A running local process (Windows), as open_minidump / dump_stack show a dump: modules (PDB, matching file on disk), memory regions (VirtualQuery view, paged and filtered), threads (TEB, stack range, start address, registers) and their call stacks, every address named as dump_stack names it. Read-only: opened with PROCESS_QUERY_INFORMATION | PROCESS_VM_READ and THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION only; nothing is written, suspended or attached, and every handle is closed before returning. Threads keep running, so registers are a snapshot.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `process` | string | yes |  | Process id (decimal or 0x hex) or name (notepad or notepad.exe); a shared name is refused with the candidate ids. |
| `sections` | string |  |  | Comma-separated: modules, regions, threads, stacks (implies threads) or all (default). |
| `thread` | string |  |  | Only this thread: id or name. |
| `modulesOffset` | integer |  | `0` | First module listed. |
| `modulesLimit` | integer |  | `50` | Max modules listed. |
| `regionsOffset` | integer |  | `0` | First region listed (after regionFilter). |
| `regionsLimit` | integer |  | `100` | Max regions listed. |
| `regionFilter` | string |  |  | Regions listed (default committed; all adds reserved and free). Values: committed, all, executable, writable, image, private, mapped. |
| `threadsOffset` | integer |  | `0` | First thread listed. |
| `threadsLimit` | integer |  | `20` | Max threads listed. |
| `maxFrames` | integer |  | `32` | Max frames walked per thread (up to 256). |
| `imageDirectories` | string |  |  | Folders with the program's binaries (';'-separated) for modules whose own file is not readable. |
| `timeoutSeconds` | integer |  | `20` | Time limit in seconds (up to 120). |

Structured output: `processId`, `name`, `path`, `architecture`, `wow64`, `startTimeUtc`, `runtime`, `access`, `moduleCount`, `modulesOffset`, `modulesTruncated`, `modules`, `regionCount`, `regionsTotal`, `regionFilter`, `regionsOffset`, `regionsTruncated`, `regions`, `threadCount`, `threadsOffset`, `threadsTruncated`, `threads`, `detached`, `handlesOpened`, `handlesClosed`, `stillRunning`, `elapsedMs`, `notes`.
