# Tools

<!-- Generated from the tool catalog by DocsTests; run the tests with CORVUS_UPDATE_DOCS=1 to update. -->

155 tools in 13 toolsets. A server registers every tool unless it is started with `--toolsets` ([server options](installation.md#server-options)). From a terminal, `corvus describe <tool>` prints the same reference and `corvus <tool> name=value ...` calls a tool ([cli.md](cli.md)).

Annotations: **read-only** tools change nothing; **edit** tools change the in-memory workspace; **destructive** tools can remove or overwrite state; **long-running** tools can take more than 10 s and have no call deadline.

| Toolset | In `core` | In `lean` | Tools |
|---|---|---|---|
| [session](#session) | 9 | 5 | 9: workspace and server state |
| [dotnet](#dotnet) | 22 | 9 | 22: .NET browse, decompile, search, navigate, resources, ReadyToRun, project export |
| [containers](#containers) | 7 | 2 | 7: file inspection, containers and wrapped apps, Unity overview |
| [edit](#edit) | 15 | 5 | 15: .NET edits, edit history and saving |
| [il2cpp](#il2cpp) | 5 | 1 | 5: Il2Cpp metadata, addresses, symbols and bindings |
| [native](#native) | 33 | 12 | 33: native PE analysis, symbols and decompilation |
| [native-edit](#native-edit) | 9 | 4 | 9: native names, comments, patches and saving |
| [builds](#builds) | 0 | 0 | 11: build-to-build comparison and carrying work to a new build |
| [notes](#notes) | 0 | 2 | 3: analyst notes kept per binary across sessions |
| [engine](#engine) | 0 | 0 | 13: edits inside the decompiler engine's database: types, locals, frames, declarations, scripting |
| [android](#android) | 0 | 0 | 20: Android packages: manifest, resources, DEX code, Java decompilation, Java / .NET mapping, devices |
| [dumps](#dumps) | 0 | 0 | 7: crash dumps and crash text |
| [live](#live) | 0 | 0 | 1: read-only inspection of a running process |

## session

Workspace and server state.

### load_assembly

**Load assembly** (edit, idempotent, long-running)

Load a .NET assembly (.dll/.exe) or every assembly in a directory (app folder, Unity *_Data/Managed, DummyDll). A native PE, ELF or Mach-O file loads as a native image (universal Mach-O: one slice, name[slice]); format=raw maps headerless code; folder loads skip native files. An Il2Cpp game (folder, global-metadata.dat, .apk/.xapk/.aab/.ipa, iOS .app, memory dump) is read by the built-in reader (metadata v24-39): dummy assemblies with addresses, offsets and tokens, plus the binary as a native image. Files are read into memory, never locked; loading a path twice is a no-op.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `path` | string | yes |  | Absolute path to an assembly file or a directory. |
| `recursive` | boolean |  |  | When path is a directory, also load assemblies in subdirectories. |
| `loadProviders` | boolean |  |  | For a file: also load the DLLs its imports bind to (one level, at most 16), so the call tools continue into them. |
| `slice` | string |  |  | Universal Mach-O slice (name or index; default arm64e, arm64, x86_64), or an Android Il2Cpp game's ABI (default arm64-v8a). Values: arm64e, arm64, x86_64, x86_64h, arm64_32, armv7, armv7s, armv7k, i386, arm64-v8a, armeabi-v7a, x86. |
| `format` | string |  | `auto` | auto, or raw (headerless code). |
| `arch` | string |  |  | raw: x86, x64, arm, thumb or arm64. |
| `base` | string |  |  | raw: load address (default 0). |
| `entry` | string |  |  | raw: entry address or file offset (default start). |

Structured output: `ids`, `text`.

### unload_assembly

**Unload assembly** (destructive, idempotent)

Remove an assembly from the workspace (unsaved edits are discarded).

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `assembly` | string | yes |  | Assembly id, name, file name or path. |

Structured output: `ids`, `text`.

### reload_assembly

**Reload assembly** (destructive, idempotent)

Re-read an assembly from disk (after an update or an overwriting save_assembly), discarding unsaved edits.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `assembly` | string | yes |  | Assembly id, name, file name or path. |

Structured output: `ids`, `text`.

### add_search_directory

**Add reference search directory** (edit, idempotent)

Add a directory for resolving referenced assemblies that are not loaded (an application or framework folder), for decompilation, navigation and C# patching.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `directory` | string | yes |  | Directory path. |

Structured output: `ids`, `text`.

### list_assemblies

**List loaded assemblies** (read-only, idempotent)

Loaded assemblies and native images with their ids (for other tools), versions, paths, Il2Cpp dummy, ReadyToRun and merged (ILMerge / ILRepack) flags and unsaved edits; plus the reference search directories. With path: the managed assemblies inside a container file (single-file bundle, .nupkg, .apk / .aab, Costura host, zip) without extracting them (unpack_container extracts and loads them); archives (Electron .asar with integrity verdicts, Unity WebGL .data, HAR / mitmproxy captures) list their files.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `path` | string |  |  | A container file (or Blazor _framework folder) to list instead of the workspace. |
| `filter` | string |  |  | Id, name or path substring (case-insensitive). |
| `offset` | integer |  |  | Rows to skip. |
| `limit` | integer |  | `100` | Rows per page (default 100). |

Structured output: `items`, `offset`, `total`, `searchDirectories`, `backgroundIndexing`, `container`, `limit`, `totalExact`, `hasMore`, `nextOffset`.

### server_status

**Server status** (read-only, idempotent, open-world)

Which server runs (version, program, install kind, client), a catalog digest, what is loaded, limits, long-running tools, capabilities with the fix when missing, tool families, unusable tools, and engine sessions (busy op, analysis, queue). expectedCatalogDigest detects a stale server; expectedExecutable checks the registered copy.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `expectedCatalogDigest` | string |  |  | Catalog digest to compare (t92-0123456789ab.p5-01234567). |
| `expectedExecutable` | string |  |  | Registered server program path, compared with the running one. |

Structured output: `server`, `version`, `informationalVersion`, `executable`, `executableMatches`, `installKind`, `startedAt`, `uptimeSeconds`, `protocolVersion`, `client`, `catalogDigest`, `catalogMatches`, `catalogDifference`, `tools`, `loadedAssemblies`, `backgroundIndexing`, `workingSetMB`, `capabilities`, `longRunningTools`, `toolsets`, `unavailableTools`, `notes`, `engineTimeLimits`, `engineSessions`, `toolsFileAndTrace`, `sections`.

### read_result

**Read a kept result** (destructive, idempotent)

Read a kept result (resultId; kept on disk 7 days): page it, search it with query, or write it whole to outputPath.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `id` | string | yes |  | Result id, e.g. r-0123456789ab. |
| `offset` | integer |  |  | Character offset (nextOffset). |
| `maxTokens` | integer |  |  | Page size in tokens (default 6000). |
| `query` | string |  |  | Only lines containing this text (/regex/ for a pattern), with their offsets. |
| `format` | string |  | `text` | text; json: the structured record; jsonl: its items, one per line. Values: text, json, jsonl. |
| `outputPath` | string |  |  | Write the whole result to this file; returns path, bytes and SHA-256. |
| `overwrite` | boolean |  |  | Replace outputPath if it exists. |

Structured output: `id`, `tool`, `totalChars`, `offset`, `nextOffset`, `code`, `matches`, `path`, `bytes`, `sha256`.

### save_session

**Save the session** (destructive, idempotent)

Write this session's work to one JSON file: every loaded file (path, relative path, SHA-256), .NET edits, native patches, names and comments, notes, Il2Cpp games and open minidumps. load_session restores it here or on another machine.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `outputPath` | string | yes |  | Output file path (.json). |
| `overwrite` | boolean |  |  | Replace the file if it exists. |
| `include` | string |  |  | Comma-separated parts: edits, patches, annotations, notes or all (default); files are always listed. |

Structured output: `outputPath`, `files`, `editedAssemblies`, `edits`, `patchedImages`, `patches`, `names`, `comments`, `notes`.

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
| `offset` | integer |  |  | Rows to skip. |
| `limit` | integer |  | `200` | Items to return (max 2000). |

Structured output: `path`, `dryRun`, `targetBuild`, `outcomes`, `offset`, `total`, `items`, `notes`, `limit`, `totalExact`, `hasMore`, `nextOffset`.

## dotnet

.NET browse, decompile, search, navigate, resources, ReadyToRun, project export.

### list_namespaces

**List namespaces** (read-only, idempotent)

List namespaces with their type counts (nested types under their outer type's namespace).

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `assembly` | string |  |  | Assembly id, name, file name or path; omit for all loaded. |
| `filter` | string |  |  | Substring (case-insensitive). |
| `offset` | integer |  |  | Rows to skip. |
| `limit` | integer |  | `200` | Max rows. |
| `maxTokens` | integer |  |  | Page size in tokens. |

Structured output: `items`, `offset`, `total`, `limit`, `totalExact`, `hasMore`, `nextOffset`.

### list_types

**List types** (read-only, idempotent)

List types, optionally by namespace, name filter and kind.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `assembly` | string |  |  | Assembly id, name, file name or path; omit for all loaded. |
| `namespace` | string |  |  | Exact namespace ('' or '<global>' for the global one). |
| `filter` | string |  |  | Name substring or wildcard (*, ?), or a regex with regex=true. |
| `regex` | boolean |  |  | Treat filter as a regular expression. |
| `kind` | string |  |  | Only this kind. Values: class, struct, interface, enum, delegate. |
| `topLevelOnly` | boolean |  |  | Leave out nested types. |
| `offset` | integer |  |  | Rows to skip. |
| `limit` | integer |  | `150` | Max rows. |
| `maxTokens` | integer |  |  | Page size in tokens. |

Structured output: `items`, `offset`, `total`, `notEvaluated`, `totalExact`, `limit`, `hasMore`, `nextOffset`.

### get_type_info

**Type outline** (read-only, idempotent)

Outline of a type without decompiling: declaration, attributes, member counts and the first members of each kind; a section pages one kind (constants, enum values, signatures, tokens, IL sizes, Il2Cpp RVAs).

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `type` | string | yes |  | Type or member: 'Ns.Type', 'Ns.Outer+Inner', 'Ns.Type::Method(int, string)', a short name or a token (0x06000123). |
| `assembly` | string |  |  | Assembly id, name, file name or path; omit for all loaded. |
| `section` | string |  | `summary` | summary, nested, fields, properties, events, methods or all. Values: summary, nested, fields, properties, events, methods, all. |
| `includeCompilerGenerated` | boolean |  |  | Include compiler-generated members. |
| `offset` | integer |  |  | Rows to skip. |
| `limit` | integer |  | `100` | Max rows. |
| `maxTokens` | integer |  |  | Page size in tokens. |

Structured output: `type`, `declaration`, `counts`, `section`, `items`, `offset`, `total`, `declaringType`, `attributes`, `compilerGeneratedHidden`, `limit`, `totalExact`, `hasMore`, `nextOffset`.

### get_assembly_info

**Assembly overview** (read-only, idempotent)

Assembly overview: identity (MVID, SHA-256), framework, entry point, counts, Il2Cpp, invalid IL, edits; view=references: where references resolve; view=metadata: PE headers, streams, tables, heaps, metadata problems, attributes.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `assembly` | string | yes |  | Assembly id, name, file name or path. |
| `view` | string |  | `summary` | summary, references, metadata or all. Values: summary, references, metadata, all. |

Structured output: `id`, `fullName`, `file`, `sha256`, `mvid`, `runtime`, `kind`, `machine`, `targetFramework`, `entryPoint`, `types`, `nestedTypes`, `namespaces`, `methods`, `fields`, `resources`, `referenceAssembly`, `il2CppAddressedMethods`, `invalidBodies`, `invalidExceptionClauses`, `unsavedEdits`, `referenceCount`, `unresolvedReferences`, `metadataIssueCount`, `references`, `attributes`, `tables`, `heaps`, `metadataIssues`.

### get_attributes

**Custom attributes** (read-only, idempotent)

Custom attributes with arguments on a type or member (parameters and return value included), or on the assembly and module (symbol omitted; format=csharp decompiles them).

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `symbol` | string |  |  | Type or member: 'Ns.Type', 'Ns.Outer+Inner', 'Ns.Type::Method(int, string)', a short name or a token (0x06000123). Omit for assembly-level attributes. |
| `assembly` | string |  |  | Assembly id, name, file name or path; omit for all loaded. Required when symbol is omitted. |
| `filter` | string |  |  | Only attributes whose type name contains this text. |
| `format` | string |  | `rows` | rows, or csharp (symbol omitted). Values: rows, csharp. |
| `offset` | integer |  |  | Rows to skip (characters with format=csharp). |
| `limit` | integer |  | `200` | Max rows. |
| `maxTokens` | integer |  |  | Page size in tokens. |

Structured output: `items`, `offset`, `total`, `code`, `nextOffset`, `totalChars`, `limit`, `totalExact`, `hasMore`.

### get_type_hierarchy

**Type hierarchy** (read-only, idempotent)

Returns a type's base chain, all implemented interfaces, and the types deriving from (or implementing) it directly across loaded assemblies.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `type` | string | yes |  | Type or member: 'Ns.Type', 'Ns.Outer+Inner', 'Ns.Type::Method(int, string)', a short name or a token (0x06000123). |
| `assembly` | string |  |  | Assembly id, name, file name or path; omit for all loaded. |
| `offset` | integer |  |  | Rows to skip. |
| `limit` | integer |  | `200` | Max rows. |
| `maxTokens` | integer |  |  | Page size in tokens. |

Structured output: `type`, `baseChain`, `interfaces`, `items`, `offset`, `total`, `limit`, `totalExact`, `hasMore`, `nextOffset`.

### resolve_symbol

**Resolve symbol** (read-only, idempotent)

What a symbol string or token resolves to: every match with kind, assembly, token and signature, to disambiguate before other calls.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `symbol` | string | yes |  | Type or member: 'Ns.Type', 'Ns.Outer+Inner', 'Ns.Type::Method(int, string)', a short name or a token (0x06000123). |
| `assembly` | string |  |  | Assembly id, name, file name or path; omit for all loaded. |
| `kind` | string |  |  | Restrict to this kind. Values: any, type, method, field, property, event, member. |
| `offset` | integer |  |  | Rows to skip. |
| `limit` | integer |  | `50` | Max rows. |
| `maxTokens` | integer |  |  | Page size in tokens. |

Structured output: `items`, `offset`, `total`, `notEvaluated`, `totalExact`, `limit`, `hasMore`, `nextOffset`.

### decompile_member

**Decompile to C#** (read-only, idempotent)

Decompile a type or member to C#: every overload unless a parameter list narrows it; async / iterator state machines and lambdas fold back into their method; a type whole, nested types included. Code the decompiler fails on is shown as IL.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `member` | string | yes |  | Type or member: 'Ns.Type', 'Ns.Outer+Inner', 'Ns.Type::Method(int, string)', a short name or a token (0x06000123). |
| `assembly` | string |  |  | Assembly id, name, file name or path; omit for all loaded. |
| `kind` | string |  |  | Restrict to this kind (default any). Values: any, method, field, property, event. |
| `simplified` | boolean |  |  | Show the code as simplify_methods would leave it, without changing the assembly. |
| `provenance` | boolean |  |  | Start with comments pinning the output to its build: SHA-256, MVID, tokens, IL hashes (docs/il-hash.md). |
| `offset` | integer |  |  | Character offset (a page's nextOffset). |
| `maxTokens` | integer |  |  | Page size in tokens. |

Structured output: `language`, `code`, `offset`, `nextOffset`, `totalChars`, `symbols`, `methods`, `bodies`.

### get_il

**IL disassembly** (read-only, idempotent)

IL disassembly (ildasm style, tokens, offsets, try blocks) of a member or type; each method starts with its normalized IL hash (stable across rebuilds) and raw IL SHA-256. For when the C# looks wrong, or as patch_method_il input.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `symbol` | string | yes |  | Type or member: 'Ns.Type', 'Ns.Outer+Inner', 'Ns.Type::Method(int, string)', a short name or a token (0x06000123). |
| `assembly` | string |  |  | Assembly id, name, file name or path; omit for all loaded. |
| `offset` | integer |  |  | Character offset (a page's nextOffset). |
| `maxTokens` | integer |  |  | Page size in tokens. |

Structured output: `language`, `code`, `offset`, `nextOffset`, `totalChars`, `symbols`, `methods`, `bodies`.

### search_symbols

**Search symbols by name** (read-only, idempotent)

Find types and members by name across loaded assemblies: a case-insensitive substring, wildcard (Get*Value?) or regex; queries with '.' or '::' also match full names. Exact matches first, then by name length; ties by assembly and token.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `query` | string | yes |  | Name, substring, wildcard or regex. |
| `kind` | string |  |  | Restrict to this kind. Values: any, type, method, field, property, event, member. |
| `assembly` | string |  |  | Assembly id, name, file name or path; omit for all loaded. |
| `namespace` | string |  |  | Only types in namespaces starting with this. |
| `regex` | boolean |  |  | Treat query as a regular expression. |
| `limit` | integer |  | `100` | Max rows. |
| `maxTokens` | integer |  |  | Page size in tokens. |
| `offset` | integer |  |  | Rows to skip. |

Structured output: `items`, `offset`, `total`, `notEvaluated`, `totalExact`, `limit`, `hasMore`, `nextOffset`.

### search_strings

**Search string literals** (read-only, idempotent)

Find string literals (ldstr, string constants) by substring, wildcard or regex, with the method and IL offset using each. Il2Cpp dummy DLLs: the game's literals with slot RVAs and, with the binary, the functions loading them.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `query` | string | yes |  | Substring, wildcard or regex. |
| `assembly` | string |  |  | Assembly id, name, file name or path; omit for all loaded. |
| `regex` | boolean |  |  | Treat query as a regular expression. |
| `limit` | integer |  | `100` | Max rows. |
| `maxTokens` | integer |  |  | Page size in tokens. |
| `offset` | integer |  |  | Rows to skip. |
| `usesPerLiteral` | integer |  | `10` | Il2Cpp: max functions listed per literal. |

Structured output: `items`, `offset`, `total`, `notEvaluated`, `totalExact`, `limit`, `hasMore`, `nextOffset`.

### search_constants

**Search numeric constants** (read-only, idempotent)

Find a numeric constant (magic number, opcode id, flag, crypto constant) in IL literals, const and enum values, attribute arguments and static array data (lookup and crypto tables, read as the array's element type).

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `value` | string | yes |  | Decimal, 0x hex, negative or floating-point. |
| `assembly` | string |  |  | Assembly id, name, file name or path; omit for all loaded. |
| `limit` | integer |  | `100` | Max rows. |
| `maxTokens` | integer |  |  | Page size in tokens. |
| `offset` | integer |  |  | Rows to skip. |

Structured output: `value`, `items`, `offset`, `total`, `limit`, `totalExact`, `hasMore`, `nextOffset`.

### search_il

**Search IL instruction patterns** (read-only, idempotent)

Find methods containing an IL instruction sequence: ';'-separated 'opcode [operand]' elements with * and ? wildcards (operands match names, strings, numbers); '...' skips up to 16 instructions, e.g. 'ldstr *password*; ...; call *::Hash*'.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `pattern` | string | yes |  | Instruction pattern. |
| `assembly` | string |  |  | Assembly id, name, file name or path; omit for all loaded. |
| `limit` | integer |  | `100` | Max rows. |
| `maxTokens` | integer |  |  | Page size in tokens. |
| `offset` | integer |  |  | Rows to skip. |
| `context` | integer |  | `8` | Instructions shown per match (1-24). |

Structured output: `items`, `offset`, `total`, `limit`, `totalExact`, `hasMore`, `nextOffset`.

### find_references

**Find usages (xrefs to)** (read-only, idempotent)

Every usage of a symbol across loaded assemblies: a method's call sites (also through base / interface methods), a field's reads, writes and address uses, a type's every use (bases, signatures, locals, casts, attributes). kind=overrides: a method's overrides. A native export: its P/Invoke callers and native call sites.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `symbol` | string | yes |  | Type or member ('Ns.Type::Method(int)', short name, token) or native export ('kernel32.dll!CreateFileW', 'native:<image>!<name\|#ord\|addr>'). |
| `assembly` | string |  |  | Assembly defining the symbol (only to disambiguate; all loaded ones are searched). |
| `kind` | string |  |  | Symbol kind; overrides: the method's overrides and implementations. Values: type, method, field, property, event, overrides. |
| `directOnly` | boolean |  |  | Methods: no calls through base / interface declarations. |
| `limit` | integer |  | `150` | Max rows. |
| `maxTokens` | integer |  |  | Page size in tokens. |
| `offset` | integer |  |  | Rows to skip. |

Structured output: `target`, `items`, `offset`, `total`, `limit`, `totalExact`, `hasMore`, `nextOffset`.

### find_callees

**What a method uses (xrefs from)** (read-only, idempotent)

What a method uses ('Uses'): calls, field reads / writes, types instantiated or cast, and strings, in IL order with offsets. P/Invoke calls show the native code they bind to; for a P/Invoke or native export, its native callees as call-tree rows.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `method` | string | yes |  | Type or member ('Ns.Type::Method(int)', short name, token) or native export ('kernel32.dll!CreateFileW', 'native:<image>!<name\|#ord\|addr>'). |
| `assembly` | string |  |  | Assembly id, name, file name or path; omit for all loaded. |
| `distinct` | boolean |  |  | Collapse repeated targets into one row with a count. |
| `offset` | integer |  |  | Rows to skip. |
| `limit` | integer |  | `200` | Max rows. |
| `maxTokens` | integer |  |  | Page size in tokens. |

Structured output: `method`, `items`, `offset`, `total`, `limit`, `totalExact`, `hasMore`, `nextOffset`.

### get_call_tree

**Call tree (callers / callees)** (read-only, idempotent)

Multi-level callers or callees of a method across loaded assemblies, one row per node in tree order; calls through base / interface methods, repeats and recursion are marked. Continues through P/Invokes and C++/CLI into loaded native code; takes a native export too.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `method` | string | yes |  | Type or member ('Ns.Type::Method(int)', short name, token) or native export ('kernel32.dll!CreateFileW', 'native:<image>!<name\|#ord\|addr>'). |
| `direction` | string |  | `callers` | callers or callees. Values: callers, callees. |
| `depth` | integer |  | `3` | Levels to expand (1-8). |
| `includeExternal` | boolean |  |  | Callees: also calls into assemblies not loaded (framework). |
| `assembly` | string |  |  | Assembly id, name, file name or path; omit for all loaded. |
| `offset` | integer |  |  | Rows to skip. |
| `limit` | integer |  | `200` | Max rows. |
| `maxTokens` | integer |  |  | Page size in tokens. |

Structured output: `root`, `direction`, `depth`, `items`, `offset`, `total`, `totalExact`, `limit`, `hasMore`, `nextOffset`.

### find_call_paths

**Call paths to a method** (read-only, idempotent)

How execution reaches a method: call chains from 'from', or from entry points (methods nothing loaded calls), shortest first, direct calls preferred. A native 'to' follows native callers across loaded images and P/Invokes back to managed code (guide dotnet).

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `to` | string | yes |  | Target. Type or member ('Ns.Type::Method(int)', short name, token) or native export ('kernel32.dll!CreateFileW', 'native:<image>!<name\|#ord\|addr>'). |
| `from` | string |  |  | Start method, same forms as to (native only when to is native). |
| `maxDepth` | integer |  | `8` | Max chain length (max 30). |
| `limit` | integer |  | `10` | Max rows. |
| `maxTokens` | integer |  |  | Page size in tokens. |
| `offset` | integer |  |  | Rows to skip. |
| `directOnly` | boolean |  |  | No hops through virtual dispatch (native: RTTI virtual calls, pointers). |
| `assembly` | string |  |  | Assembly id, name, file name or path; omit for all loaded. |

Structured output: `target`, `items`, `offset`, `total`, `from`, `totalExact`, `engine`, `limit`, `hasMore`, `nextOffset`.

### list_resources

**List manifest resources** (read-only, idempotent)

List manifest resources (embedded, .resources with entry counts, linked) with SHA-256 and file offsets; for a native image its Win32 resources as TYPE/NAME/LANGUAGE (icon groups name their icons).

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `assembly` | string | yes |  | Assembly id, name, file name or path. |
| `offset` | integer |  |  | Rows to skip. |
| `limit` | integer |  | `200` | Max rows. |
| `maxTokens` | integer |  |  | Page size in tokens. |

Structured output: `assembly`, `items`, `offset`, `total`, `limit`, `totalExact`, `hasMore`, `nextOffset`.

### get_resource

**Read / extract resource** (destructive, idempotent)

Read a resource: text as text, binary as hex preview, .resources as an entry list (entry reads one; .baml as XAML); outputPath extracts the raw bytes. Native images: TYPE/NAME[/LANGUAGE], version info and string tables decoded.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `assembly` | string | yes |  | Assembly id, name, file name or path. |
| `name` | string | yes |  | Name from list_resources. |
| `entry` | string |  |  | Entry inside a .resources container. |
| `outputPath` | string |  |  | Write the raw bytes to this file. |
| `overwrite` | boolean |  |  | Replace outputPath if it exists. |
| `offset` | integer |  |  | Character offset (a page's nextOffset). |
| `maxTokens` | integer |  |  | Page size in tokens. |

Structured output: `name`, `kind`, `code`, `offset`, `nextOffset`, `totalChars`, `savedTo`, `size`.

### export_project

**Export C# project** (destructive, idempotent, long-running)

Decompile an assembly into a C# project on disk (.cs per type, .csproj, resources) to browse with file tools; an .apk / .aab gives a Gradle project (manifest, resources, Java through JADX or smali). Written whole or not at all.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `assembly` | string | yes |  | Assembly id, name, file name or path. |
| `outputDirectory` | string | yes |  | Empty or new output directory. |
| `overwrite` | boolean |  |  | Replace a previous export in outputDirectory. |

Structured output: `applied`, `source`, `outputDirectory`, `files`, `projectFile`, `failedTypes`, `replaced`, `notes`.

### get_r2r_code

**ReadyToRun native code of a method** (read-only, idempotent)

Precompiled native code of a method in a ReadyToRun assembly (the shared framework too): entry, code ranges, fixup cells and x86 / x64 disassembly with cells named by what they resolve to; generics per compiled instantiation, composite images included.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `method` | string | yes |  | Type or member: 'Ns.Type', 'Ns.Outer+Inner', 'Ns.Type::Method(int, string)', a short name or a token (0x06000123). |
| `assembly` | string |  |  | Assembly id, name, file name or path; omit for all loaded. |
| `instantiation` | string |  |  | Only bodies whose name contains this text ('Int32', '__Canon'). |
| `maxBodies` | integer |  | `4` | Max bodies disassembled; the rest are listed with addresses. |
| `maxInstructions` | integer |  | `1500` | Max instructions per body. |
| `offset` | integer |  |  | Character offset (a page's nextOffset). |
| `maxTokens` | integer |  |  | Page size in tokens. |

Structured output: `language`, `code`, `offset`, `nextOffset`, `totalChars`, `symbols`, `methods`, `bodies`.

### find_r2r_method

**Managed method at a ReadyToRun address** (read-only, idempotent)

Managed method whose ReadyToRun code holds a native address (from a dump, profiler or debugger): name, token, range, offset and instruction, or what an import cell resolves to. Addresses are in the file holding the code.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `assembly` | string | yes |  | Assembly id, name, file name or path. |
| `address` | string | yes |  | A VA or RVA in the code image (rva:/va:/off: prefix). |

Structured output: `address`, `file`, `kind`, `begin`, `end`, `offset`, `methods`, `instruction`, `importCell`.

## containers

File inspection, containers and wrapped apps, Unity overview.

### summarize_file

**Summarize file** (read-only, idempotent)

First look at any file or loaded assembly, without executing it: type, hashes, signature, container wrapping (bundles, packages, APKs, zips, Costura are opened), its assemblies, highlights (toolchain markers, ATT&CK features, packers), entry points and typed value counts. view= gives the details: managed (identity, markers, features, values per assembly), native (ELF / Mach-O, packers, NativeAOT; a loaded image's triage), android, electron, go, all; views lists those that apply.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `path` | string |  |  | Any file (assembly, bundle, .nupkg, .apk, zip, .asar, native executable); pass this or assembly. |
| `assembly` | string |  |  | A loaded assembly; pass this or path. |
| `view` | string |  | `overview` | overview (default) or a view the overview lists. Values: overview, managed, android, electron, go, native, all. |

Structured output: `path`, `size`, `type`, `sha256`, `container`, `view`, `views`, `md5`, `sha1`, `entropy`, `signature`, `assemblies`, `highlights`, `highlightTotal`, `entryPoints`, `values`, `detail`, `notes`.

### survey_features

**Survey features** (read-only, idempotent)

Rule-based (capa-style) survey of the APIs an assembly calls, its P/Invokes and strings: network, execution, registry, persistence, collection, anti-analysis, evasion, code loading, injection, crypto; each feature with its ATT&CK technique and match count, evidence (up to 5 locations) with category=. Native images: the same rules over imports, call arguments, strings, sections and RTTI names.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `assembly` | string |  |  | A loaded assembly; pass this or path. |
| `path` | string |  |  | A .NET or native file to analyze without loading it; pass this, assembly or image. |
| `category` | string |  |  | Only this category (network, ...) or ATT&CK prefix (T1055), with evidence; all: every feature with evidence. |
| `image` | string |  |  | A native image, loaded or a path (instead of assembly). |

Structured output: `assembly`, `methodsScanned`, `features`, `category`, `notes`.

### extract_strings

**Extract typed strings** (read-only, idempotent)

Typed values (URLs, domains, IPs, emails, file paths, pipes, registry keys, mutexes, user agents, crypto keys) from an assembly's literals, constants, resource text and decoded base64 / hex / compressed text, each with count, locations and the APIs it is passed to. All values are kept: read_result outputPath exports them (text: CSV, json).

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `assembly` | string |  |  | A loaded assembly; pass this or path. |
| `path` | string |  |  | A .NET assembly file to analyze without loading it; pass this or assembly. |
| `types` | string[] |  |  | Only these types. |
| `offset` | integer |  |  | Rows to skip. |
| `limit` | integer |  | `100` | Max rows. |

Structured output: `assembly`, `items`, `offset`, `total`, `byType`, `valuesResultId`, `notes`, `limit`, `totalExact`, `hasMore`, `nextOffset`.

### extract_embedded

**Extract embedded content** (edit, idempotent)

Embedded content of an assembly, or of every assembly in a container (resources, static byte arrays, long string literals) decoded through hex, base64, compression and XOR (key from a known header) until a PE, archive, ELF / Mach-O or text appears, plus high-entropy blobs; each with its source and encoding chain. save=true writes them all (defanged names), load=true also loads the .NET ones. Nothing is executed.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `assembly` | string |  |  | A loaded assembly; pass this or path. |
| `path` | string |  |  | An assembly or container file, read without loading; pass this or assembly. |
| `save` | boolean |  |  | Write the items to disk. |
| `outputDirectory` | string |  |  | New or empty directory (or an earlier extraction of the same file); default under temp. |
| `load` | boolean |  |  | Load the .NET assemblies found (implies save). |
| `xorText` | boolean |  |  | Also brute-force 1-16 byte XOR keys over unreadable data, keeping natural text or configuration (slower). |
| `includeMedia` | boolean |  |  | Also list and save images (else counted). |
| `offset` | integer |  |  | Rows to skip. |
| `limit` | integer |  | `100` | Max rows. |

Structured output: `assembly`, `items`, `offset`, `total`, `outputDirectory`, `notes`, `limit`, `totalExact`, `hasMore`, `nextOffset`.

### search_container

**Search inside a container** (read-only, idempotent)

Find types and members by name in every managed assembly inside a container (bundle, .nupkg, .apk / .aab, Costura, zip, nested) or an assembly, without extracting or loading: a case-insensitive substring with * / ? wildcards ('.' or ':' also match full names), exact matches first; kind=file matches inner file names and paths.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `path` | string | yes |  | Absolute path to the container or assembly file. |
| `query` | string | yes |  | Name or part of a name. |
| `kind` | string |  |  | Restrict to this kind; omit for all members (events included). Values: type, method, field, property, file. |
| `limit` | integer |  | `100` | Max rows. |
| `offset` | integer |  |  | Rows to skip. |

Structured output: `source`, `container`, `searched`, `items`, `offset`, `total`, `notes`, `limit`, `totalExact`, `hasMore`, `nextOffset`.

### unpack_container

**Unpack container** (edit, idempotent, long-running)

Extract the .NET assemblies inside a container and load them: single-file bundles, Costura.Fody, NuGet packages, Xamarin / MAUI .apk / .aab (assembly stores per ABI), zips, embedded .NET images, nested containers. Electron .asar, Unity WebGL .data and HAR / mitmproxy captures give every file. Nothing is executed; names stay in the output directory, runnable extensions get .bin. Nothing to extract: next names the call.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `path` | string | yes |  | Container file, or a Blazor _framework folder. |
| `outputDirectory` | string |  |  | New or empty directory, or an earlier unpack of this file; default under temp. |
| `extractOnly` | boolean |  |  | Extract without loading the assemblies; default: loaded, ids in loadedAs. |
| `offset` | integer |  |  | Rows to skip. |
| `limit` | integer |  | `100` | Max rows. |

Structured output: `source`, `container`, `outputDirectory`, `items`, `offset`, `total`, `next`, `notes`, `limit`, `totalExact`, `hasMore`, `nextOffset`.

### unity_overview

**Unity title overview** (read-only, idempotent, open-world)

Overview of a Unity title in seconds, without loading it (listings, headers and version resources only): engine version per source with their agreement, scripting backend (il2cpp / mono) with evidence, metadata version and state (readable, encrypted, header_tampered, unsupported_version, missing), toolchain and middleware markers, platform, architecture, notable folders, and the next calls (load_assembly the Managed folder or the metadata, or dump from memory). Not Unity: unsupported, reason not_a_unity_title.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `path` | string | yes |  | The title's folder, executable, *_Data folder, UnityPlayer.dll, GameAssembly.dll or global-metadata.dat; an extracted APK folder or a macOS / iOS .app. |
| `detectItEasy` | boolean |  |  | Also run Detect It Easy (diec, CORVUS_DIE or PATH) on the main binaries; launches it, about a second per file. |

Structured output: `input`, `gameDirectory`, `dataDirectory`, `executable`, `company`, `product`, `platform`, `architecture`, `architectureSource`, `engine`, `backend`, `markers`, `folders`, `nextSteps`, `notes`.

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
| `dryRun` | boolean |  | `true` | Default true: preview; pass dryRun=false to apply. |

Structured output: `applied`, `dryRun`, `changes`, `editIds`, `failed`.

### rename_namespace

**Rename namespace** (destructive)

Move every type of a namespace (optionally its sub-namespaces) to a new namespace, in memory.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `assembly` | string | yes |  | Assembly id, name, file name or path. |
| `oldNamespace` | string | yes |  | Existing namespace ('' for the global namespace). |
| `newNamespace` | string | yes |  | New namespace. |
| `includeSubNamespaces` | boolean |  |  | Also rewrite namespaces that start with oldNamespace + '.'. |
| `dryRun` | boolean |  | `true` | Default true: preview; pass dryRun=false to apply. |

Structured output: `applied`, `dryRun`, `changes`, `editIds`, `failed`.

### stub_method

**Stub method (return constant)** (destructive)

Replace a method's body with 'return <value>;' (or 'return;' for void) in memory: force a check to return true, disable a call.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `method` | string | yes |  | Type or member: 'Ns.Type', 'Ns.Outer+Inner', 'Ns.Type::Method(int, string)', a short name or a token (0x06000123). |
| `value` | string |  |  | true/false, an integer (decimal or 0x hex), a float, a "quoted string" or null; omit for void or default(T). |
| `assembly` | string |  |  | Assembly id, name, file name or path; omit for all loaded. |
| `dryRun` | boolean |  | `true` | Default true: preview; pass dryRun=false to apply. |

Structured output: `applied`, `dryRun`, `changes`, `editIds`, `failed`.

### patch_method_csharp

**Replace method body with C#** (destructive, long-running)

Replace a method's body (methods, constructors, accessors) with C# compiled against the assembly; private members accessible, lambdas, LINQ, async and yield work. Errors name lines of your code.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `method` | string | yes |  | Type or member: 'Ns.Type', 'Ns.Outer+Inner', 'Ns.Type::Method(int, string)', a short name or a token (0x06000123). |
| `code` | string | yes |  | The new body's statements only. |
| `assembly` | string |  |  | Assembly id, name, file name or path; omit for all loaded. |
| `dryRun` | boolean |  | `true` | Default true: preview the IL that would be written; pass dryRun=false to apply. |

Structured output: `applied`, `dryRun`, `changes`, `editIds`, `failed`.

### patch_method_il

**Rewrite method body in IL** (destructive)

Rewrite a method body from IL text (stack-validated): edit get_il's lines and pass them back (syntax: guide edits). replace swaps the body; prepend runs before it and can branch to its IL_xxxx labels.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `method` | string | yes |  | Type or member: 'Ns.Type', 'Ns.Outer+Inner', 'Ns.Type::Method(int, string)', a short name or a token (0x06000123). |
| `il` | string | yes |  | IL instructions, one per line. |
| `mode` | string |  | `replace` | replace or prepend. Values: replace, prepend. |
| `assembly` | string |  |  | Assembly id, name, file name or path; omit for all loaded. |
| `dryRun` | boolean |  | `true` | Default true: preview; pass dryRun=false to apply. |

Structured output: `applied`, `dryRun`, `changes`, `editIds`, `failed`.

### add_members_csharp

**Add members to a type (C#)** (edit, long-running)

Add C# members (methods, fields, properties, events, constructors, nested types) to a class or struct; private members accessible. No field or property initializers.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `type` | string | yes |  | The type to extend. Type or member: 'Ns.Type', 'Ns.Outer+Inner', 'Ns.Type::Method(int, string)', a short name or a token (0x06000123). |
| `code` | string | yes |  | C# member declarations. |
| `assembly` | string |  |  | Assembly id, name, file name or path; omit for all loaded. |
| `dryRun` | boolean |  | `true` | Default true: preview; pass dryRun=false to apply. |

Structured output: `applied`, `dryRun`, `changes`, `editIds`, `failed`.

### add_types_csharp

**Add new types (C#)** (edit, long-running)

Add C# types (with their namespace) to an assembly; they can use its internal types, and patch_method_csharp can call them.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `assembly` | string | yes |  | Assembly id, name, file name or path. |
| `code` | string | yes |  | C# source declaring the new types. |
| `dryRun` | boolean |  | `true` | Default true: preview; pass dryRun=false to apply. |

Structured output: `applied`, `dryRun`, `changes`, `editIds`, `failed`.

### simplify_methods

**Simplify method bodies** (destructive, long-running)

Clean transformed method bodies: fold (string decoders with constant inputs run in a safe IL interpreter), cfg (constant branches, dead code, flattened control flow), inline (forwarders, delegate call proxies). Bodies are stack-verified; what is left has a reason code (docs/simplify.md).

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `symbol` | string |  |  | A method or a type (nested types included): 'Ns.Type', 'Ns.Type::Method(int)', a short name or a token. Omit for the whole assembly. |
| `assembly` | string |  |  | Assembly id, name, file name or path; omit for all loaded. Required when symbol is omitted. |
| `passes` | string[] |  |  | Passes to run; omit for all three. |
| `maxDepth` | integer |  | `8` | Max evaluation call depth. |
| `budget` | integer |  | `100000` | Max IL instructions per evaluated call, nested calls included. |
| `dryRun` | boolean |  | `true` | Default true: preview; pass dryRun=false to apply. |
| `deterministicEnvironment` | boolean |  |  | Fold machine reads (paths, environment, names) against fixed stand-ins (docs/simplify.md). |

Structured output: `applied`, `dryRun`, `changes`, `editIds`, `failed`.

### list_edits

**List unsaved edits** (read-only, idempotent)

Unsaved edits of an assembly in order; each number (editId <assembly>#<n>) stays when other edits are undone.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `assembly` | string | yes |  | Assembly id, name, file name or path. |
| `offset` | integer |  |  | Rows to skip. |
| `limit` | integer |  | `200` | Max rows (default 200). |
| `maxTokens` | integer |  |  | Page size in tokens. |

Structured output: `assembly`, `items`, `offset`, `total`, `limit`, `totalExact`, `hasMore`, `nextOffset`.

### diff_edits

**Diff edits (before/after C#)** (read-only, idempotent)

Unified diff of the decompiled C# of every member the edits touched (or one edit's), before and after. Review before save_assembly.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `assembly` | string | yes |  | Assembly id, name, file name or path. |
| `number` | integer |  |  | Only this edit (number from list_edits). |
| `offset` | integer |  |  | Character offset (a page's nextOffset). |
| `maxTokens` | integer |  |  | Page size in tokens. |

Structured output: `code`, `offset`, `nextOffset`, `totalChars`.

### undo_edit

**Undo an edit** (destructive, long-running)

Undo the last edit or one by number: the others are replayed on the original image; a conflict changes nothing.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `assembly` | string | yes |  | Assembly id, name, file name or path. |
| `number` | integer |  |  | Edit number from list_edits (the #n of its editId); omit for the last. |

Structured output: `applied`, `dryRun`, `changes`, `editIds`, `failed`.

### revert_edits

**Discard all edits** (destructive, idempotent)

Discard every unsaved edit of an assembly; resultId keeps them as a script (read_result outputPath=x.json, apply_edits path=x.json).

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `assembly` | string | yes |  | Assembly id, name, file name or path. |

Structured output: `applied`, `dryRun`, `changes`, `editIds`, `failed`.

### export_edits

**Export edits as a script** (destructive, idempotent)

Save an assembly's edits as a JSON script bound to its build (SHA-256, MVID) for apply_edits.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `assembly` | string | yes |  | Assembly id, name, file name or path. |
| `outputPath` | string | yes |  | Output .json path. |
| `overwrite` | boolean |  |  | Replace outputPath if it exists. |

Structured output: `outputPath`, `edits`, `sha256`, `mvid`, `identity`.

### apply_edits

**Apply an edit script** (destructive, long-running)

Replay an export_edits script, each edit with its outcome. Another build needs targetBuild=other: symbols by name, renames followed when the source build is loaded.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `path` | string | yes |  | The .json edit script. |
| `assembly` | string |  |  | Target assembly; omit for the one named in the script. |
| `dryRun` | boolean |  | `true` | Default true: apply every edit (compiled, stack-checked), report, roll back; pass dryRun=false to keep them. |
| `continueOnError` | boolean |  |  | Apply the edits that succeed; default: roll all back on the first failure. |
| `targetBuild` | string |  | `same` | same: only the script's build; other: another build, symbols re-resolved by name. Values: same, other. |

Structured output: `applied`, `dryRun`, `changes`, `editIds`, `failed`, `items`, `pushedTo`.

### save_assembly

**Save patched assembly** (destructive, idempotent)

Write an assembly with its edits to a new file, atomically (overwrite=true keeps a .bak; a file changed since load is refused). Untouched bodies keep their bytes; members the writer changed are listed with reason codes (docs/saving.md).

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `assembly` | string | yes |  | Assembly id, name, file name or path. |
| `outputPath` | string |  |  | Output file path; a .wasm path writes Webcil (Blazor). Omit for '<original>.patched.dll'. |
| `overwrite` | boolean |  |  | Allow replacing an existing file. |
| `strict` | boolean |  |  | Write nothing when any member would be changed by the writer (default: save and list them). |

Structured output: `outputPath`, `bytes`, `sha256`, `edits`, `backup`.

## il2cpp

Il2Cpp metadata, addresses, symbols and bindings.

### get_il2cpp_info

**Il2Cpp addresses and offsets** (read-only, idempotent)

Il2Cpp dummy DLLs (built-in reader, Il2CppDumper or Cpp2IL): native addresses (RVA, VA, file offset, vtable slot) of a method or every method of a type, field offsets and tokens. With script.json (always for the built-in reader): function bounds, methods sharing the code, MethodInfo slot, generic instantiations, a type's metadata slots (Ns.Type_TypeInfo), and names only script.json has ('List`1<int>::Add', 'Method$Ns.Type.M()'). With stringliteral.json and the binary: the string literals a method's code loads.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `symbol` | string | yes |  | Type or member ('Ns.Type', 'Ns.Type::Method(int)', short name, token), or a script.json name of an instantiation or metadata slot. |
| `assembly` | string |  |  | Assembly id, name, file name or path; omit for all loaded. |
| `slot` | string |  |  | With a type: a vtable slot number to resolve to its implementing method, or 'all'. |
| `offset` | integer |  |  | Index of the first entry of each long list. |
| `limit` | integer |  | `20` | Max entries of each long list. |

Structured output: `symbol`, `members`, `items`, `offset`, `total`, `limit`, `totalExact`, `hasMore`, `nextOffset`.

### find_method_by_address

**Native address to method** (read-only, idempotent)

Map a native address (from IDA, Ghidra or a crash log) of an Il2Cpp game to the method(s) whose function contains it, or the string literal, type metadata or MethodInfo slot at it; generic instantiations are named with script.json (without it a containing method is a guess).

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `address` | string | yes |  | Hex as IDA / Ghidra show it ('0x1A2B3C', '1A2B3Ch', '00000001`8001A2B3'); 'd:' prefix for decimal. |
| `kind` | string |  | `auto` | auto: a VA at or above the image base, else an RVA, else a file offset. Values: auto, rva, va, offset. |
| `assembly` | string |  |  | Assembly id, name, file name or path; omit for all loaded. |
| `offset` | integer |  |  | Rows to skip. |
| `limit` | integer |  | `20` | Max methods listed. |
| `maxTokens` | integer |  |  | Page size in tokens. |

Structured output: `address`, `items`, `offset`, `total`, `limit`, `totalExact`, `hasMore`, `nextOffset`.

### export_il2cpp_symbols

**Export IDA/Ghidra scripts** (destructive, idempotent, long-running)

Export Il2Cpp dummy-DLL metadata for native analysis: IDA Python and Ghidra scripts that create, name (Ns.Type$$Method) and comment every function (RVAs, so any image base works), a C header of struct layouts, and an Il2CppDumper-style script.json.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `outputDirectory` | string | yes |  | Output directory. |
| `formats` | string |  | `all` | Comma-separated: ida, ghidra, header, json or all. |
| `baseName` | string |  | `il2cpp` | Base name of the generated files. |
| `assembly` | string |  |  | Assembly id, name, file name or path; omit for all loaded. |
| `overwrite` | boolean |  |  | Replace files of the same names if they exist. |

Structured output: `functions`, `structs`, `files`.

### generate_cpp_binding

**Generate C++ binding** (read-only, idempotent)

Generate C++ binding code for a managed type of a Mono or Il2Cpp application: a struct that resolves the class, field offsets, static fields and methods once, with typed field accessors, property getters and invoke wrappers. style: mono (embedding API), il2cpp (runtime exports and direct calls) or hostapi (a host's function table; guide il2cpp). Without style: detected from projectDir, an Il2Cpp dummy assembly or --binding-style, else mono; the first line says which. A generic definition binds as a template.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `type` | string | yes |  | Type or member: 'Ns.Type', 'Ns.Outer+Inner', 'Ns.Type::Method(int, string)', a short name or a token (0x06000123). |
| `assembly` | string |  |  | Assembly id, name, file name or path; omit for all loaded. |
| `members` | string |  |  | Only these members (comma-separated names); default all but compiler-generated ones. |
| `includeInherited` | boolean |  |  | Also bind property getters inherited from base classes (base members named in members are bound anyway). |
| `style` | string |  |  | Omit to detect it. Values: mono, il2cpp, hostapi. |
| `projectDir` | string |  |  | The C/C++ project the header is for, scanned for a host function table and helpers. |
| `headerPath` | string |  |  | Where the header will be saved (absolute or relative to projectDir; default projectDir); #include paths are relative to it. |
| `offset` | integer |  |  | Character offset (a page's nextOffset). |
| `maxTokens` | integer |  |  | Page size in tokens. |

Structured output: `code`, `offset`, `nextOffset`, `totalChars`.

### apply_il2cpp_names

**Name a native Il2Cpp binary from its metadata** (destructive, idempotent, long-running)

Name the functions and data of a native Il2Cpp binary (GameAssembly, libil2cpp.so) from the loaded dummy assemblies, script.json (function starts, generic instantiations, TypeInfo and MethodInfo slots) and stringliteral.json. Functions become Ns_Type__Method (a C identifier; a duplicate gets _<RVA>), commented with Ns.Type::Method(args) and the methods sharing the code; every native tool and the engines show them, below user and PDB names. Saved per file hash and reapplied on load; applying again replaces them.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `image` | string | yes |  | Native image id, file name or path. |
| `assembly` | string |  |  | Dummy assemblies to use; omit for every loaded one with Il2Cpp metadata. |
| `clear` | boolean |  |  | Remove the il2cpp names (and their saved copy) instead of applying them. |

Structured output: `image`, `applied`, `assemblies`, `functions`, `labels`, `sharedFunctions`, `strings`, `metadataSlots`, `methodInfoSlots`, `userNamesKept`, `suffixed`, `misses`, `saved`, `removed`, `notes`.

## native

Native PE analysis, symbols and decompilation.

### get_pe_info

**Native image overview** (read-only, idempotent)

Overview of a native image. PE: machine, kind, subsystem, base, entry point, timestamps, linker, sections (flags, entropy), packers, mitigations (ASLR, DEP, CFG, CET...), import / export counts, TLS callbacks, PDB identity, load config, version, manifest, rich header, checksum, overlay, signature, anything malformed. ELF: program headers, soname, build id, relocations, hardening. Mach-O: slice, segments, libraries, fixups, code signature, entitlements, encryption. Go build info. Capabilities the imports imply. view=code: code index statistics and late-bound imports.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `image` | string | yes |  | Native image id, file name or path. |
| `offset` | integer |  |  | Character offset (a page's nextOffset). |
| `maxTokens` | integer |  |  | Page size in tokens. |
| `view` | string |  |  | summary, or code (waits for the code index). Values: summary, code. |

Structured output: `image`, `path`, `machine`, `kind`, `format`, `subsystem`, `fileSize`, `sha256`, `imageBase`, `entryPoint`, `timestamp`, `dotNet`, `mitigationsOn`, `mitigationsOff`, `sections`, `importModules`, `importFunctions`, `delayImportModules`, `exports`, `tlsCallbacks`, `pdbPath`, `pdbGuid`, `pdbAge`, `signer`, `checksumMatches`, `overlaySize`, `issues`, `capabilities`, `code`.

### list_imports

**List native imports** (read-only, idempotent, long-running)

Functions a native image imports, per DLL or library (delay-loaded and lazy binding marked), with the IAT slot address code calls through; API set names show the DLL they resolve to. bind=true binds each import like the loader to its export: 'at VA [image]' when the provider is loaded, its path when not (load it, or load_assembly loadProviders=true), or the reason it does not resolve. includeDynamic adds GetProcAddress imports with a constant name, marked [dynamic].

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `image` | string | yes |  | Native image id, file name or path. |
| `library` | string |  |  | Only this library (name with or without .dll). |
| `filter` | string |  |  | Name substring (case-insensitive). |
| `bind` | boolean |  |  | Bind each import to the export it reaches, with a summary. |
| `offset` | integer |  |  | Rows to skip. |
| `limit` | integer |  | `200` | Max rows. |
| `includeDynamic` | boolean |  |  | Also list late-bound imports (waits for the code index). |
| `maxTokens` | integer |  |  | Page size in tokens. |

Structured output: `image`, `items`, `offset`, `total`, `bindings`, `limit`, `totalExact`, `hasMore`, `nextOffset`.

### list_exports

**List native exports** (read-only, idempotent)

Exported functions and data of a native image: ordinal, VA, name (demangled C++ form, ELF symbol version), forwarders and re-exports.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `image` | string | yes |  | Native image id, file name or path. |
| `filter` | string |  |  | Name substring (case-insensitive; the demangled form too). |
| `offset` | integer |  |  | Rows to skip. |
| `limit` | integer |  | `300` | Max rows. |
| `maxTokens` | integer |  |  | Page size in tokens. |

Structured output: `image`, `items`, `offset`, `total`, `limit`, `totalExact`, `hasMore`, `nextOffset`.

### resolve_address

**Resolve native address** (read-only, idempotent)

What a native address is: RVA, VA, file offset, section and access, nearest export or import, name and source; the Il2Cpp method or metadata slot, or NativeAOT MethodTable, object or method; an IAT slot's bound export, an export's importers. With the code index: function and offset, instruction start, mid-instruction or data item, comment, references by kind. In a PDB global, the field.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `image` | string | yes |  | Native image id, file name or path. |
| `address` | string |  |  | Hex VA or RVA (rva:/va:/off: prefix), export, module!import or function name. |
| `addresses` | string[] |  |  | Instead of address: up to 100 addresses. |

Structured output: `image`, `rva`, `va`, `fileOffset`, `section`, `access`, `name`, `nameSource`, `import`, `boundTo`, `export`, `function`, `status`, `containingInstruction`, `dataItem`, `comment`, `referencesTo`, `results`, `failed`.

### search_bytes

**Search native bytes** (read-only, idempotent)

Find a byte pattern in a native image's mapped sections (hex with ?? wildcards, or text as ASCII and UTF-16): each hit's VA, section and file offset.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `image` | string | yes |  | Native image id, file name or path. |
| `pattern` | string |  |  | Hex bytes with ?? wildcards ('48 8B 05 ?? ?? ?? ??'), or text when text=true. |
| `text` | boolean |  |  | pattern is text (ASCII and UTF-16LE). |
| `section` | string |  |  | Only this section (e.g. .text, .rdata). |
| `limit` | integer |  | `200` | Max hits. |
| `offset` | integer |  |  | Rows to skip. |
| `patterns` | string[] |  |  | Instead of pattern: up to 50 patterns. |
| `maxTokens` | integer |  |  | Page size in tokens. |

Structured output: `image`, `items`, `offset`, `total`, `patterns`, `failed`, `limit`, `totalExact`, `hasMore`, `nextOffset`.

### read_bytes

**Read native bytes or values** (read-only, idempotent)

Hex dump (with ASCII) of a native image's bytes at an address, as the loader maps them (.bss as ??). type= reads length values instead: u8-u64, i8-i64 (be suffix: u32be), f32, f64, ptr (target named), C names (int, DWORD, char *), cstr or wstr. Structs: get_native_type read=true.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `image` | string | yes |  | Native image id, file name or path. |
| `address` | string | yes |  | Hex VA or RVA (rva:/va:/off: prefix), export, module!import or function name. |
| `length` | integer |  |  | Bytes to dump (default 256, max 65536); with type, values to read (default 1, max 4096). |
| `offset` | integer |  |  | Bytes from address (a page's nextOffset). |
| `maxTokens` | integer |  |  | Page size in tokens. |
| `type` | string |  |  | Value type to read instead of dumping bytes. |

Structured output: `image`, `address`, `length`, `code`, `nextOffset`, `nextAddress`, `totalBytes`, `offset`, `totalChars`.

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

Functions of a native image (x86 / x64 / ARM): address, size, name (user, PDB, Il2Cpp, export, module!import thunk or sub_<rva>), flags (thunk, arm (A32), noreturn, unresolved jumps, invalid code, funclets and exception chunks), how it was found and its caller count; an exact name filter adds an open engine's function record.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `image` | string | yes |  | Native image id, file name or path. |
| `filter` | string |  |  | Name filter: substring (case-insensitive), glob with * and ?, or /regex/ (flags i, m, s). |
| `sort` | string |  |  | address (default), name, size (largest first) or callers (most called first). Values: address, name, size, callers. |
| `offset` | integer |  |  | Rows to skip. |
| `limit` | integer |  | `150` | Max rows. |
| `engine` | string |  |  | auto (default): IDA, else Ghidra, if it has analyzed these bytes, else ours. ida / ghidra: that engine, started when needed. Values: auto, ours, ida, ghidra. |
| `minSize` | integer |  |  | Smallest size in bytes. |
| `maxSize` | integer |  |  | Largest size in bytes. |
| `from` | string |  |  | Lowest start address. |
| `to` | string |  |  | Start addresses below this one. |
| `hasType` | boolean |  |  | Engines: true keeps functions with a prototype, false those without. |
| `descending` | boolean |  |  | Sort direction instead of the sort's default. |
| `view` | string |  |  | functions (default), or candidates: IDA or Ghidra code in no function, most referenced first. Values: functions, candidates. |
| `maxTokens` | integer |  |  | Page size in tokens. |

Structured output: `image`, `functions`, `items`, `offset`, `total`, `engine`, `engineNote`, `limit`, `totalExact`, `hasMore`, `nextOffset`.

### list_globals

**List native globals** (read-only, idempotent, open-world, long-running)

Named data items of a native image outside code, from every name source (PDB with type and size, user names and types, Il2Cpp, NativeAOT, exports, symbol tables); with an engine also its defined data with type and value. get_native_type read=true reads one's fields.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `image` | string | yes |  | Native image id, file name or path. |
| `filter` | string |  |  | Name substring (case-insensitive). |
| `section` | string |  |  | Only this section, e.g. .data. |
| `offset` | integer |  |  | Rows to skip. |
| `limit` | integer |  | `200` | Max rows (default 200). |
| `engine` | string |  |  | auto (default): IDA, else Ghidra, if it has analyzed these bytes, else ours. ida / ghidra: that engine, started when needed. Values: auto, ours, ida, ghidra. |
| `maxTokens` | integer |  |  | Page size in tokens. |

Structured output: `image`, `items`, `offset`, `total`, `engine`, `limit`, `totalExact`, `hasMore`, `nextOffset`.

### disassemble

**Disassemble native code** (read-only, idempotent, open-world, long-running)

MASM-syntax disassembly of the native function containing an address (with block labels), or of maxInstructions from the address when it is in no function or fromAddress=true. References and NativeAOT loads are named, strings shown as comments, calls commented with their recovered arguments. Data in the way (strings, pointers, IAT slots, switch tables, gaps) is rendered as data; warnings (mid-instruction, data, bss) repeat in a footer.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `image` | string | yes |  | Native image id, file name or path. |
| `address` | string | yes |  | Hex VA or RVA (rva:/va:/off: prefix), export, module!import or function name. |
| `fromAddress` | boolean |  |  | maxInstructions from the address, not the whole containing function. |
| `maxInstructions` | integer |  | `2000` | Max instructions. |
| `offset` | integer |  |  | Character offset (a page's nextOffset). |
| `maxTokens` | integer |  |  | Page size in tokens. |
| `engine` | string |  |  | auto (default): IDA, else Ghidra, if it has analyzed these bytes, else ours. ida / ghidra: that engine, started when needed. Values: auto, ours, ida, ghidra. |

Structured output: `code`, `offset`, `nextOffset`, `totalChars`, `image`, `function`, `address`, `engine`.

### inspect_instruction

**Inspect native instructions** (read-only, idempotent, open-world, long-running)

What is at an address of a native image, instruction by instruction: decoded, mid_instruction (with the covering one), data (string, IAT / GOT slot, switch table, pointer, literal), not_in_function, unmapped, outside_image or invalid. An instruction: bytes, prefixes, encoding; operands (kind, size, access, registers, memory parts); registers and flags read and written; memory accesses; stack change; flow; references; a call's arguments; a switch's table. limit > 1 walks forward.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `image` | string | yes |  | Native image id, file name or path. |
| `address` | string | yes |  | Hex VA or RVA (rva:/va:/off: prefix), export, module!import or function name. |
| `limit` | integer |  | `1` | Instructions to inspect (1-64). |
| `offset` | integer |  |  | Character offset (a page's nextOffset). |
| `maxTokens` | integer |  |  | Page size in tokens. |
| `engine` | string |  |  | auto (default): IDA, else Ghidra, if it has analyzed these bytes, else ours. ida / ghidra: that engine, started when needed. Values: auto, ours, ida, ghidra. |

Structured output: `image`, `engine`, `engineNote`, `items`, `notes`, `code`, `offset`, `nextOffset`, `totalChars`.

### search_instructions

**Search native instructions** (read-only, idempotent, open-world, long-running)

Find instructions by mnemonic, operand or whole-line regex (case-insensitive) and an operand value (immediate, displacement or target) in every function, one function, or an address range; a page stopped by the scan budget goes on at nextOffset.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `image` | string | yes |  | Native image id, file name or path. |
| `mnemonic` | string |  |  | Mnemonic regex, e.g. '^(call\|jmp)$'. |
| `operands` | string |  |  | Operand text regex, e.g. 'rsp\+\|fs:'. |
| `text` | string |  |  | Regex over the whole instruction text. |
| `value` | string |  |  | An operand value: 0x10B, 267, or an address. |
| `function` | string |  |  | Only this function: Hex VA or RVA (rva:/va:/off: prefix), export, module!import or function name. |
| `from` | string |  |  | Range start (with to, or alone: to the end of its section). |
| `to` | string |  |  | Range end (exclusive). |
| `offset` | integer |  |  | Rows to skip. |
| `limit` | integer |  | `100` | Max matches (max 2000). |
| `maxInstructions` | integer |  | `500000` | Instructions scanned per page (max 5000000). |
| `engine` | string |  |  | auto (default): IDA, else Ghidra, if it has analyzed these bytes, else ours. ida / ghidra: that engine, started when needed. Values: auto, ours, ida, ghidra. |
| `maxTokens` | integer |  |  | Page size in tokens. |

Structured output: `image`, `items`, `offset`, `total`, `scanned`, `engine`, `engineNote`, `totalExact`, `limit`, `hasMore`, `nextOffset`.

### get_cfg

**Native control-flow graph** (read-only, idempotent, open-world, long-running)

Basic blocks of the native function containing an address, paged: range, instruction count, how each ends and its successors; switch tables with values per target; unresolved indirect jumps with the reason.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `image` | string | yes |  | Native image id, file name or path. |
| `address` | string | yes |  | Hex VA or RVA (rva:/va:/off: prefix), export, module!import or function name. |
| `offset` | integer |  |  | Rows to skip. |
| `limit` | integer |  | `150` | Blocks per page (default 150). |
| `maxTokens` | integer |  |  | Page size in tokens. |
| `engine` | string |  |  | auto (default): IDA, else Ghidra, if it has analyzed these bytes, else ours. ida / ghidra: that engine, started when needed. Values: auto, ours, ida, ghidra. |

Structured output: `image`, `function`, `address`, `engine`, `items`, `offset`, `total`, `switches`, `unresolvedJumps`, `tailCalls`, `cut`, `summary`, `limit`, `totalExact`, `hasMore`, `nextOffset`.

### find_xrefs

**Native cross-references** (read-only, idempotent, open-world, long-running)

What references a native address: calls (also via import slots and thunks), jumps, data reads/writes, address-taken uses, switch tables, relocated pointers, each with its function and, for calls, recovered arguments; RTTI virtual call sites. An import (module!name): call sites and binding; an export: also callers in other loaded images. direction=from: what it references. A struct member (Type::member, Type+0x18): its uses in typed pseudocode, via IDA or Ghidra.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `image` | string | yes |  | Native image id, file name or path. |
| `address` | string |  |  | Hex VA or RVA (rva:/va:/off: prefix), export, module!import or function name. Or a struct member: Type::member, Type.member, Type+0xOFFSET. |
| `offset` | integer |  |  | Rows to skip. |
| `limit` | integer |  | `200` | Max rows. |
| `addresses` | string[] |  |  | Instead of address: up to 100 targets. |
| `engine` | string |  |  | auto (default): IDA, else Ghidra, if it has analyzed these bytes, else ours. ida / ghidra: that engine, started when needed. Adds RTTI virtual calls. Values: auto, ours, ida, ghidra. |
| `direction` | string |  |  | to (default), from or both. Values: to, from, both. |
| `kind` | string |  |  | any, code (calls, jumps), data (reads, writes, pointers) or metadata (.pdata, CFG, export tables). Values: any, code, data, metadata. |
| `scope` | string |  |  | Struct member: typed (default) or all (every function; call again to continue). Values: typed, all. |
| `maxTokens` | integer |  |  | Page size in tokens. |

Structured output: `image`, `target`, `items`, `offset`, `total`, `boundTo`, `engine`, `engineNote`, `targets`, `failed`, `limit`, `totalExact`, `hasMore`, `nextOffset`.

### native_call_tree

**Native call tree** (read-only, idempotent, open-world, long-running)

Callers or callees of a native function, several levels deep, through thunks and import slots, as nodes paged in tree order. Callers of module!import: the functions calling through it. Imports continue into loaded providers' exports; callers span loaded images. Callees include GetProcAddress pointers ([dynamic]) and RTTI virtual targets ([virtual], [virtual?: one of n]). Repeats are not expanded; frontier lists nodes cut by depth or maxNodes. direction=both: one level each way by call site.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `image` | string | yes |  | Native image id, file name or path. |
| `function` | string | yes |  | Hex VA or RVA (rva:/va:/off: prefix), export, module!import or function name. |
| `direction` | string |  | `callees` | callees (default), callers, or both (depth 1, by call site). Values: callers, callees, both. |
| `depth` | integer |  | `3` | Levels (1-8). |
| `maxNodes` | integer |  | `250` | Max nodes in the tree (default 250). |
| `offset` | integer |  |  | Rows to skip. |
| `limit` | integer |  | `200` | Max nodes per page. |
| `calls` | string |  |  | Call edges: all (default), direct or virtual. Values: all, direct, virtual. |
| `engine` | string |  |  | auto (default): IDA, else Ghidra, if it has analyzed these bytes, else ours. ida / ghidra: that engine, started when needed. Values: auto, ours, ida, ghidra. |
| `maxTokens` | integer |  |  | Page size in tokens. |

Structured output: `image`, `root`, `direction`, `items`, `offset`, `total`, `frontier`, `engine`, `engineNote`, `limit`, `totalExact`, `hasMore`, `nextOffset`.

### find_virtual_calls

**Native virtual calls** (read-only, idempotent, open-world, long-running)

Virtual call sites resolved through RTTI (MSVC or Itanium) or NativeAOT MethodTables: calls through a vftable slot, also through stack spills, this adjustments and CFG dispatch. The receiver's class comes from a vftable stored into the object, this of a virtual method, or decorated names; the slot's implementations are the targets: one is exact, several possible, else unresolved with the reason. crossCheck=true compares a sample with IDA (else Ghidra).

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `image` | string | yes |  | Native image id, file name or path. |
| `function` | string |  |  | Only sites in this function: Hex VA or RVA (rva:/va:/off: prefix), export, module!import or function name. |
| `status` | string |  |  | Only sites with this status. Values: exact, possible, unresolved. |
| `offset` | integer |  |  | Rows to skip. |
| `limit` | integer |  | `100` | Max sites (max 1000). |
| `crossCheck` | boolean |  |  | Compare a sample with the engine's view (runs IDA or Ghidra; minutes on a large image the first time). |
| `sampleFunctions` | integer |  | `100` | Cross-check: functions to sample. |
| `timeoutSeconds` | integer |  | `300` | Cross-check: time budget in seconds. |
| `maxTokens` | integer |  |  | Page size in tokens. |

Structured output: `image`, `sites`, `exact`, `possible`, `unresolved`, `edges`, `directEdges`, `rttiClasses`, `total`, `offset`, `items`, `crossCheck`, `notes`, `limit`, `totalExact`, `hasMore`, `nextOffset`.

### search_native_strings

**Search native strings** (read-only, idempotent, open-world, long-running)

Strings (ASCII and UTF-16) a native image's code or data references, with address, reference count and first referencing function. Also Il2Cpp literals (after apply_il2cpp_names) and NativeAOT frozen strings, by the slot or object code loads; with an engine, its unreferenced strings in other encodings too.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `image` | string | yes |  | Native image id, file name or path. |
| `query` | string |  |  | Case-insensitive substring, or a regex with regex=true; omit to list all. |
| `regex` | boolean |  |  | Treat query as a regular expression. |
| `offset` | integer |  |  | Rows to skip. |
| `limit` | integer |  | `100` | Max rows. |
| `engine` | string |  |  | auto (default): IDA, else Ghidra, if it has analyzed these bytes, else ours. ida / ghidra: that engine, started when needed. Values: auto, ours, ida, ghidra. |
| `maxLength` | integer |  | `200` | Characters per string (max 4000); longer ones are clipped. |
| `maxTokens` | integer |  |  | Page size in tokens. |

Structured output: `image`, `items`, `offset`, `total`, `notEvaluated`, `limit`, `totalExact`, `hasMore`, `nextOffset`.

### get_call_arguments

**Native call arguments** (read-only, idempotent, long-running)

Call sites of a native image (x86 / x64 / ARM) with their argument values, recovered by constant propagation in the caller under the platform calling convention: immediates, strings, named addresses, earlier call results, globals (differing merges are unknown). Known Win32 / CRT / libc APIs give parameter names and decoded constants. Pass address and/or callee.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `image` | string | yes |  | Native image id, file name or path. |
| `address` | string |  |  | A call instruction, or an address in a function (all calls in it): Hex VA or RVA (rva:/va:/off: prefix), export, module!import or function name. |
| `callee` | string |  |  | Only calls to this API, module!name or function; without address, every call to it in the image. |
| `offset` | integer |  |  | Rows to skip. |
| `limit` | integer |  | `50` | Max call sites (default 50, max 1000). |
| `maxTokens` | integer |  |  | Page size in tokens. |

Structured output: `image`, `scope`, `items`, `offset`, `total`, `notes`, `limit`, `totalExact`, `hasMore`, `nextOffset`.

### trace_native_values

**Native value trace** (read-only, idempotent, open-world, long-running)

Traces a value through native code (x86 / x64 / ARM) across functions. Backward: constants, strings, function pointers, API results, through copies, stack slots, merges and loops; parameters bind to every caller's argument, call results to the callee's returns, globals to their writers. Forward: API arguments, callees' parameters, globals and their readers, returns, compares, switch indexes, dereferences. Crosses loaded images; what the budgets leave out is a frontier entry with the follow-up call.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `image` | string | yes |  | Native image id, file name or path. |
| `address` | string | yes |  | An instruction, a call, a function start (with argument) or a writable global. Hex VA or RVA (rva:/va:/off: prefix), export, module!import or function name. |
| `location` | string |  |  | The value at address: a register (rdx, xmm1, x1, w2, r1), a stack slot ([rsp+28h], [ebp-8], [x29-8]), op1 / op2 (an operand) or result (the call's return). |
| `argument` | string |  |  | An argument of the call at address, or a parameter of the function starting there: 1-based position or API parameter name. |
| `direction` | string |  |  | backward (default: the values that reach it), forward (its uses) or both. Values: backward, forward, both. |
| `maxDepth` | integer |  | `3` | Function boundaries to cross (0-8). |
| `maxFunctions` | integer |  | `32` | Functions to slice (1-256). |
| `maxNodes` | integer |  | `500` | Nodes in the graph (1-5000). |
| `maxCallers` | integer |  | `16` | Call sites bound per parameter or return (1-256). |
| `maxWriters` | integer |  | `16` | Writers (backward) or readers (forward) per global (1-256). |
| `stopAtGlobals` | boolean |  |  | Stop at writable globals, not following their writers / readers. |
| `offset` | integer |  |  | Rows to skip. |
| `limit` | integer |  | `200` | Nodes per page (max 1000). |
| `engine` | string |  |  | Slices: ours, ida or ghidra (its IR, started when needed; ours where it cannot place the seed), or auto (default: an engine that analyzed the bytes, else ours). Values: auto, ours, ida, ghidra. |
| `maxTokens` | integer |  |  | Page size in tokens. |

Structured output: `image`, `engine`, `seed`, `direction`, `values`, `nodes`, `edges`, `frontier`, `totalNodes`, `totalEdges`, `functions`, `offset`, `truncated`, `notes`.

### resolve_call_targets

**Native call targets** (read-only, idempotent, open-world, long-running)

Targets of call and tail-jump sites in native code (x86 / x64 / ARM) with basis and confidence: direct branches, import and GOT slots, thunks, constant pointers (also through CFG dispatch), GetProcAddress pointers, RTTI virtual calls, NativeAOT dispatch cells, global function pointers' writers, pointer tables; deep=true: pointers callers pass in. Unresolved sites carry the reason and the trace_native_values call to follow. engine=ida or ghidra merges that engine's targets.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `image` | string | yes |  | Native image id, file name or path. |
| `address` | string |  |  | A call instruction, or an address in a function (its sites): Hex VA or RVA (rva:/va:/off: prefix), export, module!import or function name. |
| `scope` | string |  |  | Default: site at a call, else function; image (every indirect site) without address. Values: site, function, image. |
| `status` | string |  |  | Default all; indirect: all but direct branches. Values: all, resolved, possible, ambiguous, unresolved, indirect. |
| `deep` | boolean |  |  | Trace pointers that arrive as parameters back into the callers (slower). |
| `engine` | string |  |  | auto (default): IDA, else Ghidra, if it has analyzed these bytes, else ours. ida / ghidra: that engine, started when needed. Values: auto, ours, ida, ghidra. |
| `offset` | integer |  |  | Rows to skip. |
| `limit` | integer |  | `75` | Max sites (default 75, max 1000). |
| `timeoutSeconds` | integer |  |  | Seconds per engine request (default CORVUS_ENGINE_REQUEST_TIMEOUT); scans then answer partial. |
| `maxTokens` | integer |  |  | Page size in tokens. |

Structured output: `image`, `scope`, `engine`, `total`, `byStatus`, `byMechanism`, `topUnresolved`, `offset`, `items`, `notes`, `limit`, `totalExact`, `hasMore`, `nextOffset`.

### analyze_native_function

**Native function dossier** (read-only, idempotent, open-world, long-running)

Everything known about one native function, in sections bounded by maxItems with totals: identity (names, ranges, flags, prototypes, vftable slots), signature (parameters, this class, result use), frame (unwind, saved registers, locals, EH), callers, callees (targets, basis, arguments), data (strings, globals, import slots), flow (blocks, loops, switches), annotations. Optional: constants, params (values callers pass), pseudocode. Several addresses: a dossier each, or component=true for how they interact.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `image` | string | yes |  | Native image id, file name or path. |
| `address` | string | yes |  | An address inside the function, or up to 16 comma-separated: Hex VA or RVA (rva:/va:/off: prefix), export, module!import or function name. |
| `sections` | string |  |  | Comma-separated section names (default all but constants, params and pseudocode). |
| `maxItems` | integer |  | `40` | Facts per section (1-500). |
| `pseudocode` | boolean |  |  | Add the pseudocode section. |
| `component` | boolean |  |  | With several addresses: one component view (internal calls, shared data, interface). |
| `engine` | string |  |  | Pseudocode engine (default auto). Values: auto, ida, ghidra. |
| `offset` | integer |  |  | Character offset (a page's nextOffset). |
| `maxTokens` | integer |  |  | Page size in tokens. |

Structured output: `image`, `address`, `name`, `size`, `end`, `sections`, `next`, `batch`, `component`.

### trace_native_feature

**Trace a native feature** (read-only, idempotent, open-world, long-running)

Finds the native code behind a behaviour from a text or value: strings, function and data names, imports (also late-bound), exports, RTTI classes and, for a number, constants matching query ("quoted": exact) are followed to their references (with decoded API arguments), grouped by function and ranked; hubs are callers within callerDepth reaching several of them. An engine (engine=, or auto: one that analyzed these bytes) adds its strings, references and matching pseudocode lines. Pages reuse the trace.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `image` | string | yes |  | Native image id, file name or path. |
| `query` | string | yes |  | Case-insensitive substring, or a regex with regex=true. |
| `regex` | boolean |  |  | Treat query as a regular expression. |
| `kinds` | string |  |  | Seed kinds, comma-separated: strings, names, imports, exports, classes, constants (default all). |
| `maxSeeds` | integer |  | `50` | Matches followed (1-500); the rest are counted. |
| `callerDepth` | integer |  | `1` | Caller levels searched for hubs (0-3). |
| `offset` | integer |  |  | Rows to skip. |
| `limit` | integer |  | `50` | Functions per page (max 500). |
| `maxTokens` | integer |  |  | Page size in tokens. |
| `engine` | string |  |  | auto (default): IDA, else Ghidra, if it has analyzed these bytes, else ours. ida / ghidra: that engine, started when needed. Values: auto, ours, ida, ghidra. |

Structured output: `image`, `query`, `seeds`, `totalSeeds`, `functions`, `totalFunctions`, `offset`, `nextOffset`, `hubs`, `notes`.

### find_similar_functions

**Find similar functions** (read-only, idempotent, long-running)

Functions like a given one in a native image, ranked by score with evidence: instruction-shape similarity (registers, addresses, constants ignored), containment, CFG shape, shared strings, constants, imports, callees. scope=all: every loaded image of the architecture. view=duplicates: same-shape groups; view=clusters: near-duplicates image-wide.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `image` | string | yes |  | Native image id, file name or path. |
| `address` | string |  |  | view=similar: an address in the function. |
| `view` | string |  |  | similar (default with address), duplicates or clusters (default without). Values: similar, duplicates, clusters. |
| `scope` | string |  |  | image (default) or all (view=similar). Values: image, all. |
| `minScore` | number |  |  | Least score 0-1 (default 0.5; clusters 0.8). |
| `minInstructions` | integer |  | `5` | Smallest function compared, in instructions (1-1000). |
| `offset` | integer |  |  | Rows to skip. |
| `limit` | integer |  | `20` | Items to return (max 500). |
| `maxTokens` | integer |  |  | Page size in tokens. |

Structured output: `image`, `view`, `function`, `address`, `compared`, `offset`, `total`, `items`, `notes`, `limit`, `totalExact`, `hasMore`, `nextOffset`.

### get_exception_info

**Native exception handling** (read-only, idempotent, long-running)

Exception handling of the native function containing an address. ELF / Mach-O: FDE, compact unwind or ARM EHABI entry, personality, LSDA call sites with landing pads and caught types. MSVC: the handler, try blocks with caught types, unwind map, SEH scopes, IP-to-state map, and the catch blocks, funclets, filters and chained fragments it reaches. Without an address: image counts and the metadata that failed its checks.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `image` | string | yes |  | Native image id, file name or path. |
| `address` | string |  |  | Hex VA or RVA (rva:/va:/off: prefix), export, module!import or function name. Omit for an image summary. |
| `offset` | integer |  |  | Character offset (a page's nextOffset). |
| `maxTokens` | integer |  |  | Page size in tokens. |

Structured output: `image`, `function`, `address`, `format`, `scheme`, `parent`, `handlers`, `ranges`, `counts`.

### list_cpp_classes

**C++ classes from RTTI** (read-only, idempotent, open-world)

C++ classes recovered from RTTI (MSVC on PE, Itanium on ELF / Mach-O): demangled names, base classes (offsets, virtual and multiple inheritance) and vftables with slot targets; rejects are counted with the reason. Mach-O: also ObjC classes, categories, protocols and Swift types. engine=ghidra lists Ghidra's class namespaces instead (PDB classes too), ida its C++ structs.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `image` | string | yes |  | Native image id, file name or path. |
| `filter` | string |  |  | Name substring (case-insensitive). |
| `slots` | boolean |  |  | Include each vftable's slot addresses. |
| `offset` | integer |  |  | Rows to skip. |
| `limit` | integer |  | `100` | Max classes (default 100). |
| `maxTokens` | integer |  |  | Page size in tokens. |
| `engine` | string |  |  | auto or ours (default: RTTI), ida or ghidra. Values: auto, ours, ida, ghidra. |
| `namespaces` | boolean |  |  | engine=ghidra: plain namespaces and libraries too. |

Structured output: `image`, `source`, `items`, `offset`, `total`, `notes`, `limit`, `totalExact`, `hasMore`, `nextOffset`.

### get_native_type

**Native type layout** (read-only, idempotent, open-world, long-running)

Layout of a native type (fields with offset, size and bit fields, bases, padding; enums by value) from the PDB, MSVC RTTI (vftables with named slots), Il2Cpp, ObjC and Swift metadata, or the engine (source=engine). By name (exact, case-insensitive, substring candidates, or a glob listing matches), id, or typed address (a PDB global gives the field path, e.g. g.players[3].pos.y). read=true adds each field's value from the image's bytes.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `image` | string | yes |  | Native image id, file name or path. |
| `name` | string |  |  | Type name (Packet, ns::Widget, Ns.Type for Il2Cpp), or a glob listing the matches (_IMAGE_*, *Widget*). |
| `id` | string |  |  | Type id from a result (pdb:0x1A2B, rtti:0x140012000, il2cpp:Ns.Type). |
| `address` | string |  |  | A typed address: Hex VA or RVA (rva:/va:/off: prefix), export, module!import or function name. |
| `at` | string |  |  | Hex offset of a field to name (all union members); 0x48.0x10 reads through the pointer at 0x48. |
| `depth` | integer |  | `0` | Levels of by-value members to inline (0-4). |
| `source` | string |  |  | Type source (default auto). Values: auto, pdb, rtti, il2cpp, objc, swift, engine. |
| `format` | string |  |  | table (default) or c (a C declaration). Values: table, c. |
| `offset` | integer |  |  | Index of the first row (field, enumerator, slot, candidate). |
| `limit` | integer |  | `200` | Max rows (max 5000). |
| `engine` | string |  |  | auto (default): IDA, else Ghidra, if it has analyzed these bytes, else ours. ida / ghidra: that engine, started when needed. Values: auto, ida, ghidra. |
| `read` | boolean |  |  | Add the field values at address (with name or id: that type read there). |
| `maxTokens` | integer |  |  | Page size in tokens. |

Structured output: `image`, `query`, `type`, `candidates`, `totalCandidates`, `owner`, `ownerAddress`, `paths`, `offset`, `truncated`, `notes`, `readAddress`, `value`.

### decompile_native

**Decompile native function** (read-only, idempotent, open-world, long-running)

C pseudocode of a native function via IDA (Hex-Rays) or Ghidra. The first call runs the engine's auto-analysis (seconds to minutes); database and answers are kept per file hash. Names, comments and types in effect are pushed first; user types win. functions=: several in one request, each within perFunctionSeconds; a failure affects only its item.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `image` | string | yes |  | Native image id, file name or path. |
| `address` | string |  |  | Hex VA or RVA (rva:/va:/off: prefix), export, module!import or function name. Required unless functions is given. |
| `engine` | string |  |  | auto (default), ida or ghidra. Values: auto, ida, ghidra. |
| `addresses` | boolean |  |  | Prefix each line with the address it was generated from. |
| `offset` | integer |  |  | Character offset; with functions/callersOf the first input (nextInput). |
| `maxTokens` | integer |  |  | Page size in tokens. |
| `functions` | string[] |  |  | Several functions instead of address: addresses or names, in the order wanted. |
| `perFunctionSeconds` | integer |  | `60` | With functions: seconds per function (1-600). |
| `maxFunctions` | integer |  | `32` | With functions: most decompiled (1-200); the rest get a follow-up call. |
| `refs` | boolean |  |  | With address: a footer listing the globals, functions, strings and imports used. |
| `timeoutSeconds` | integer |  |  | Seconds per engine request (1-600; default CORVUS_ENGINE_REQUEST_TIMEOUT); Ghidra retries once with 4x. |
| `callersOf` | string |  |  | Instead of address: decompile the functions calling this one (engine references). |

Structured output: `image`, `engine`, `items`, `inputs`, `succeeded`, `failed`, `skipped`, `nextInput`, `offset`, `engineNote`, `code`, `nextOffset`, `totalChars`.

### search_decompiled

**Search native pseudocode** (read-only, idempotent, open-world, long-running)

Regex (case-insensitive; (?-i) for exact case) per line of the IDA or Ghidra pseudocode of every function (or filtered ones), in address order; parallel where the engine allows, cached. Stops at maxFunctions, timeoutSeconds or limit hits; offset continues.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `image` | string | yes |  | Native image id, file name or path. |
| `pattern` | string | yes |  | Regex. |
| `engine` | string |  |  | auto (default), ida or ghidra. Values: auto, ida, ghidra. |
| `filter` | string |  |  | Function name filter: substring (case-insensitive), glob with * and ?, or /regex/ (flags i, m, s). |
| `maxFunctions` | integer |  | `500` | Max 20000. |
| `timeoutSeconds` | integer |  | `60` | Max 600. |
| `offset` | integer |  |  | First function (nextOffset). |
| `limit` | integer |  | `100` | Max hits (max 2000). |

Structured output: `image`, `engine`, `pattern`, `items`, `functionsTotal`, `offset`, `functionsSearched`, `failed`, `nextOffset`, `hasMore`, `totalExact`, `stoppedBy`, `engineNote`.

### emulate_native

**Emulate native code** (read-only, idempotent, open-world, long-running)

Emulates native code in Ghidra's p-code emulator (nothing runs on the host; memory is the image, a stack and the writes given): string decoders, hashes, computed constants. Stops on return, stopAt or a budget. Calls step into the image or return stubs= values; an unmodelled call or unmapped read is an error with the address. Reports return value, registers, written memory as strings, reads, trace.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `image` | string | yes |  | Native image id, file name or path. |
| `address` | string | yes |  | Start. Hex VA or RVA (rva:/va:/off: prefix), export, module!import or function name. |
| `args` | string |  |  | By the calling convention: integer, address, 'text' or u'text' (pointer to a copy), buf:N (pointer to N zero bytes), hex:41A0 (pointer to bytes). |
| `registers` | string |  |  | rcx=0x10, rdx='key' (values as args). |
| `memory` | string |  |  | ADDR=VALUE: 'text', u'text', hex:.., zero:N, u32:5, ptr:..; outside the image va:0x10000000. |
| `stopAt` | string |  |  | Addresses to stop at. |
| `stubs` | string |  |  | Calls answered without running: name=value (GetTickCount=5, kernel32!Sleep=0, 0x180001000=1; *=0 any call). |
| `read` | string |  |  | Shown after the run: ADDR or register, space, length (rcx 64). |
| `maxInstructions` | integer |  | `1000000` | Instruction budget (1-50000000). |
| `timeoutSeconds` | integer |  | `10` | Time budget, s (1-300). |
| `trace` | integer |  | `0` | Last instructions listed (0-2000). |
| `engine` | string |  |  | auto or ghidra. Values: auto, ghidra. |

Structured output: `image`, `engine`, `instructions`, `stop`, `stoppedAt`, `returnRegister`, `returnValue`, `registers`, `callCount`, `calls`, `written`, `reads`, `trace`.

### verify_native_imports

**Verify P/Invoke imports** (read-only, idempotent, long-running)

Check a .NET assembly's P/Invoke declarations against the exports of their libraries, with the runtime's lookup rules (search order, API sets, A/W suffixes, stdcall decoration, ordinals, forwarders; .so/.dylib probing along the RID chain, __Internal in Il2Cpp). Verdict per declaration with a reason: verified, contradicted (missing_export, arch_mismatch), unresolved (dll_not_found with places searched), dynamic_only, not_checked. Run-time loading found in the IL is listed too.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `assembly` | string | yes |  | Assembly id, name, file name or path. |
| `status` | string |  |  | Only declarations with this status or reason code (e.g. contradicted, missing_export). |
| `offset` | integer |  |  | Rows to skip. |
| `limit` | integer |  | `100` | Max rows (default 100, max 5000). |
| `platform` | string |  |  | Target platform (default auto). Values: auto, windows, linux, osx, android, ios. |
| `maxTokens` | integer |  |  | Page size in tokens. |

Structured output: `assembly`, `declarations`, `counts`, `filter`, `offset`, `total`, `items`, `dynamicLoads`, `dynamicLoadsTotal`, `metadataIssues`, `notes`, `limit`, `totalExact`, `hasMore`, `nextOffset`.

### load_pdb

**Load native debug symbols** (destructive, idempotent, open-world, long-running)

Load the PDB of a native image: function and data names (publics, globals, procedures, thunks), checked against its GUID and age. Searched: path, the image's folder, its recorded path, _NT_SYMBOL_PATH, the debugger caches and C:\symbols; download=true fetches it from a symbol server. Names show as source 'pdb' (user names win); missed functions become function starts. A matching local PDB is read automatically. Names are saved and reapplied when the file loads again; clear=true removes them.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `image` | string | yes |  | Native image id, file name or path. |
| `path` | string |  |  | PDB file, or a directory (or symbol store) to look in first. |
| `download` | boolean |  |  | Download from a symbol server when no local PDB matches (network). |
| `server` | string |  |  | Symbol server URL for download (default: _NT_SYMBOL_PATH servers, else https://msdl.microsoft.com/download/symbols). |
| `allowMismatch` | boolean |  |  | Use the PDB at path even when its GUID or age differs from the image (names may be wrong). |
| `timeoutSeconds` | integer |  | `120` | Download time limit in seconds. |
| `maxMegabytes` | integer |  | `2048` | Download size limit in MB. |
| `clear` | boolean |  |  | Remove the PDB names and their saved copy instead (not read again this session). |

Structured output: `applied`, `dryRun`, `changes`, `editIds`, `failed`.

### search_pdb_symbols

**Search native debug symbols** (read-only, idempotent)

Symbols of the PDB loaded for a native image (load_pdb, or found automatically): address, kind, size, name, the signature undecorated from the public name, and the object file.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `image` | string | yes |  | Native image id, file name or path. |
| `query` | string |  |  | Name or decorated name substring (case-insensitive); empty for all. |
| `kind` | string |  |  | Only this kind (default all). Values: function, data, public, all. |
| `offset` | integer |  |  | Rows to skip. |
| `limit` | integer |  | `150` | Max rows (default 150). |
| `maxTokens` | integer |  |  | Page size in tokens. |

Structured output: `image`, `items`, `offset`, `total`, `limit`, `totalExact`, `hasMore`, `nextOffset`.

### get_nativeaot_info

**NativeAOT metadata** (read-only, idempotent, long-running)

What a NativeAOT image's own metadata recovers (.NET 7-10; PE, ELF, Mach-O). view=summary: versions, header, recovery stages and counts. sections: module sections. types: MethodTables (name, origin, kind, base). type: one MethodTable's flags, bases, interfaces and slots. methods: named method bodies. strings: frozen strings with references. statics: statics bases with known fields. Its names apply on load as the nativeaot layer.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `image` | string | yes |  | Native image id, file name or path. |
| `view` | string |  |  | What to show (default summary). Values: summary, sections, types, type, methods, strings, statics. |
| `query` | string |  |  | view=type: a type name or MethodTable address; list views: substring filter. |
| `offset` | integer |  |  | Rows to skip. |
| `limit` | integer |  | `75` | Max rows. |
| `maxTokens` | integer |  |  | Page size in tokens. |

Structured output: `image`, `view`, `summary`, `items`, `offset`, `total`, `limit`, `totalExact`, `hasMore`, `nextOffset`.

## native-edit

Native names, comments, patches and saving.

### rename_native

**Name a native address** (destructive, idempotent, open-world, long-running)

Name a native address: used by every native tool, pushed to the engines, kept per file SHA-256, undoable by editId. C-identifier-like (<=255 chars), unique unless allowDuplicate. Empty clears. items: many in one sidecar write and one engine push, each reported.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `image` | string | yes |  | Native image id, file name or path. |
| `address` | string |  |  | Hex VA or RVA (rva:/va:/off: prefix), export, module!import or function name. |
| `name` | string |  |  | The new name; empty to clear the name at this address. |
| `allowDuplicate` | boolean |  |  | Allow a name already used at another address. |
| `items` | string |  |  | Lines 'address = name', or JSON [{address, name}]. |
| `dryRun` | boolean |  | `true` | Default true: preview; pass dryRun=false to apply. |
| `stopOnError` | boolean |  |  | Stop at the first failing item. |
| `showDecompile` | string |  |  | The function's pseudocode after the edit (after) or its unified diff (diff). Values: none, after, diff. |
| `engine` | string |  |  | Engine to push the change to now (default: one with this image open, else at its next use). Values: auto, ida, ghidra. |

Structured output: `applied`, `dryRun`, `changes`, `editIds`, `failed`, `items`, `pushedTo`.

### comment_native

**Comment a native address** (destructive, idempotent, open-world, long-running)

Comment a native address (kept, pushed to engines, undoable). scope: line (repeatable: also where the address is referenced), eol, pre or plate (engine kinds; Ghidra's decompiler shows pre), pseudocode (on the statement made from the address), function, or auto (function at a function start, else line and pseudocode). append adds a line. Empty clears. items: many in one sidecar write and one engine push, each reported.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `image` | string | yes |  | Native image id, file name or path. |
| `address` | string |  |  | Hex VA or RVA (rva:/va:/off: prefix), export, module!import or function name. |
| `text` | string |  |  | The comment text; empty to clear it. |
| `scope` | string |  |  | See the description; default auto. Values: auto, line, eol, pre, plate, pseudocode, function. |
| `append` | boolean |  |  | Add text as a new line of the existing comment; a line it has is skipped. |
| `repeatLine` | boolean |  |  | With append: add the line even when the comment has it. |
| `items` | string |  |  | Lines 'address = text', or JSON [{address, text, scope?, append?}]. |
| `dryRun` | boolean |  | `true` | Default true: preview; pass dryRun=false to apply. |
| `stopOnError` | boolean |  |  | Stop at the first failing item. |
| `engine` | string |  |  | Engine to push the change to now (default: one with this image open, else at its next use). Values: auto, ida, ghidra. |

Structured output: `applied`, `dryRun`, `changes`, `editIds`, `failed`, `items`, `pushedTo`.

### export_native_annotations

**Export native annotations** (destructive, idempotent, long-running)

Write the image's names and comments (with the NativeAOT, Il2Cpp, ObjC and Swift names) as an IDAPython script, a Ghidra script or JSON; the IDA script and JSON carry the user's engine types too. Scripts apply by rebased RVA. header: a C header of declared types, prototypes and typed globals.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `image` | string | yes |  | Native image id, file name or path. |
| `outputPath` | string | yes |  | Output file path. |
| `format` | string |  |  | Default json. Values: ida, ghidra, json, header. |
| `overwrite` | boolean |  |  | Replace outputPath if it exists. |

Structured output: `outputPath`, `format`, `names`, `comments`, `pseudoComments`, `types`, `imported`, `bytes`, `sha256`.

### patch_bytes

**Patch native bytes** (destructive, long-running)

Replace bytes at a native address in memory, as an undoable edit every read path sees. A partly overwritten instruction is padded with NOPs; mid-instruction, past the function end, header bytes or ELF/Mach-O loader-rewritten bytes need allowUnsafe; encrypted bytes are refused; signatures become invalid.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `image` | string | yes |  | Native image id, file name or path. |
| `address` | string | yes |  | Hex VA or RVA (rva:/va:/off: prefix), export, module!import or function name. |
| `hex` | string |  |  | Replacement bytes as hex ('90 90', '9090' or '0x90,0x90'). |
| `value` | string |  |  | Instead of hex: a number of type (range-checked); ptr: or a name. |
| `type` | string |  |  | With value: i8-i64, u8-u64, f32, f64 or ptr; a be suffix for big-endian. Values: i8, u8, i16, u16, i32, u32, i64, u64, f32, f64, ptr, i16be, u16be, i32be, u32be, i64be, u64be, f32be, f64be. |
| `allowUnsafe` | boolean |  |  | Allow what the safety checks refuse: mid-instruction, past the function end, header or loader-written bytes. |
| `dryRun` | boolean |  | `true` | Default true: preview; pass dryRun=false to apply. |
| `relocations` | string |  |  | PE base relocations under the patch: auto (default) keeps those still holding an address, clears the rest, adds new ones; keep; neutralize clears all. Values: auto, keep, neutralize. |
| `extend` | boolean |  |  | Put the new code in a stub (see placement) the site jumps to; control returns after the site. For code larger than the site. Refused when unsafe. |
| `stubMode` | string |  |  | With extend: replace (default; the new code instead of the displaced instructions), before (new code, then them) or after. Values: replace, before, after. |
| `placement` | string |  |  | With extend: auto (default; a code cave if one fits, else a new section), cave or section (a new PE section or ELF/Mach-O segment; undo restores it). Values: auto, cave, section. |

Structured output: `applied`, `dryRun`, `changes`, `editIds`, `failed`, `items`, `pushedTo`.

### patch_asm

**Assemble and patch native code** (destructive, long-running)

Assemble x86/x64 instructions (multi-line; labels, numeric and symbol branch targets; 'db <hex>') and write them at a native address in memory, branches and RIP-relative references computed for that address. Same safety rules, NOP padding and undo as patch_bytes; PE absolute addresses ([addr], 'offset name', imm64) get base relocations.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `image` | string | yes |  | Native image id, file name or path. |
| `address` | string | yes |  | Hex VA or RVA (rva:/va:/off: prefix), export, module!import or function name. |
| `assembly` | string | yes |  | Assembly, one instruction per line. |
| `allowUnsafe` | boolean |  |  | Allow what the safety checks refuse: mid-instruction, past the function end, header or loader-written bytes. |
| `dryRun` | boolean |  | `true` | Default true: preview; pass dryRun=false to apply. |
| `relocations` | string |  |  | PE base relocations under the patch: auto (default) keeps those still holding an address, clears the rest, adds new ones; keep; neutralize clears all. Values: auto, keep, neutralize. |
| `extend` | boolean |  |  | Put the new code in a stub (see placement) the site jumps to; control returns after the site. For code larger than the site. Refused when unsafe. |
| `stubMode` | string |  |  | With extend: replace (default; the new code instead of the displaced instructions), before (new code, then them) or after. Values: replace, before, after. |
| `placement` | string |  |  | With extend: auto (default; a code cave if one fits, else a new section), cave or section (a new PE section or ELF/Mach-O segment; undo restores it). Values: auto, cave, section. |

Structured output: `applied`, `dryRun`, `changes`, `editIds`, `failed`, `items`, `pushedTo`.

### list_native_edits

**List native edits** (read-only, idempotent, long-running)

Native edits of an image in the order made, each with the editId undo_native_edit takes: byte patches, names, comments, engine type edits. Then the name layers (user, pdb, il2cpp, ida, ...) with counts and origin. search: the names and comments that match instead.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `image` | string | yes |  | Native image id, file name or path. |
| `search` | string |  |  | Instead: the names and comments (user and layers) whose text matches: substring (case-insensitive), glob with * and ?, or /regex/ (flags i, m, s). |
| `offset` | integer |  |  | Rows to skip. |
| `limit` | integer |  | `100` | Rows per page (default 100). |

Structured output: `image`, `items`, `total`, `layers`, `offset`, `limit`, `totalExact`, `hasMore`, `nextOffset`.

### undo_native_edit

**Undo a native edit** (destructive, long-running)

Undo native edits by editId (list_native_edits), the last by default: a patch, name, comment or engine type edit gets its previous value back, pushed to the engines. Refused while a later edit changed the same item.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `image` | string | yes |  | Native image id, file name or path. |
| `editId` | string |  |  | Edit id (image#n, or #n); comma-separated for several, undone in that order; omit for the last. |

Structured output: `applied`, `dryRun`, `changes`, `editIds`, `failed`, `items`, `pushedTo`.

### save_native

**Save patched native image** (destructive, idempotent, long-running)

Write the patched native image to a new file: unpatched bytes identical, PE checksum recomputed, a signature invalidated (stripSignature removes it). Atomic and verified before it replaces the target; overwrite=true keeps a .bak and refuses a file changed on disk.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `image` | string | yes |  | Native image id, file name or path. |
| `outputPath` | string | yes |  | Output file path. |
| `overwrite` | boolean |  |  | Allow replacing an existing file. |
| `stripSignature` | boolean |  |  | Remove the Authenticode certificate table from the output. |

Structured output: `outputPath`, `bytes`, `patches`, `sha256`, `checksum`, `backup`, `verified`, `notes`.

### export_native_patches

**Export native patches** (destructive, idempotent)

Write the image's in-memory byte patches for other tools: ida an IDAPython script (each patch at its rebased RVA, only where the original bytes are found), dif IDA's .dif, ips (file offsets below 16 MB) or ips32, json the full patch set (migrate_native_patches reads it). Relocation edits and the PE checksum are included, so a .dif or IPS applied to the original gives save_native's bytes.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `image` | string | yes |  | Native image id, file name or path. |
| `outputPath` | string | yes |  | Output file path. |
| `format` | string |  |  | Default json. Values: ida, dif, ips, ips32, json. |
| `overwrite` | boolean |  |  | Replace outputPath if it exists. |

Structured output: `image`, `outputPath`, `format`, `patches`, `relocationEdits`, `changedBytes`, `records`, `checksumUpdated`, `bytes`, `originalSha256`, `notes`.

## builds

Build-to-build comparison and carrying work to a new build.

### compare_assemblies

**Compare two builds** (read-only, idempotent, long-running)

Compare two builds of an assembly: renamed, moved, added and removed types and members (matched by content in tiers, unique-only; else ambiguous) and how each matched member changed (signature, body by IL hash, metadata, Il2Cpp offset).

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `oldAssembly` | string | yes |  | The old build (id, name or path). |
| `newAssembly` | string | yes |  | The new build (id, name or path). |
| `namespace` | string |  |  | Only types whose old or new full name starts with this. |
| `changes` | string[] |  |  | Change kinds to list (unknown: unpaired for lack of evidence); default all except address. |
| `typeCountsOnly` | boolean |  |  | Count added and removed types without listing them. |
| `includeCompilerGenerated` | boolean |  |  | Also list compiler-generated types and members (closures, state machines). |
| `tokenMap` | boolean |  |  | Keep the whole old -> new token map as a result (tokenMapResultId). |
| `offset` | integer |  |  | Rows to skip. |
| `limit` | integer |  | `100` | Changes per page (default 100). |
| `maxTokens` | integer |  |  | Page size in tokens. |

Structured output: `old`, `new`, `oldTypes`, `matchedTypes`, `typeChanges`, `memberChanges`, `memberMatches`, `ambiguousMembers`, `oldSkippedBodies`, `newSkippedBodies`, `hiddenCompilerGenerated`, `items`, `offset`, `total`, `tokenMapResultId`, `tokenMapEntries`, `limit`, `totalExact`, `hasMore`, `nextOffset`.

### find_counterpart

**Find symbol in another build** (read-only, idempotent, long-running)

Where a type or member of the old build went in the new one (by name, then content, unique-only; else candidates): new name and token, tier, confidence, body change. diff=true / il=true add unified diffs of the pair's C# / normalized IL with renames applied first.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `symbol` | string | yes |  | In the old build. Type or member: 'Ns.Type', 'Ns.Outer+Inner', 'Ns.Type::Method(int, string)', a short name or a token (0x06000123). |
| `oldAssembly` | string | yes |  | The old build (id, name or path). |
| `newAssembly` | string | yes |  | The new build (id, name or path). |
| `diff` | boolean |  |  | C# diff of each pair (cut at 300 lines). |
| `il` | boolean |  |  | Normalized IL diff of each method pair. |
| `symbols` | string[] |  |  | Instead of symbol: up to 100 symbols. |
| `offset` | integer |  |  | Rows to skip. |
| `limit` | integer |  | `25` | Symbols per page (default 25). |
| `maxTokens` | integer |  |  | Page size in tokens. |

Structured output: `old`, `new`, `items`, `offset`, `total`, `limit`, `totalExact`, `hasMore`, `nextOffset`.

### compare_folders

**Compare two folders or packages** (read-only, idempotent, long-running)

Compare two folders, zip-family archives or files per entry: modified, added, removed, moved, case-only renames, links, unreadable; changed binaries with MVID and version, text with a diff.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `oldPath` | string | yes |  | Old folder, archive or file. |
| `newPath` | string | yes |  | New folder, archive or file. |
| `change` | string |  | `changed` | Entries listed. Values: changed, modified, added, removed, moved, renamed, unreadable, unchanged, all. |
| `exclude` | string[] |  |  | Globs of paths to skip. |
| `caseSensitive` | boolean |  |  | Default: false on Windows and macOS, true elsewhere. |
| `maxEntries` | integer |  | `200000` | Per side; past it, incomplete. |
| `offset` | integer |  |  | Rows to skip. |
| `limit` | integer |  | `100` | Max entries per page. |

Structured output: `old`, `new`, `hashBasis`, `caseSensitive`, `counts`, `view`, `offset`, `total`, `entries`, `notes`, `limit`, `totalExact`, `hasMore`, `nextOffset`.

### compare_native_images

**Compare native builds** (read-only, idempotent, long-running)

Match the functions of two builds of one native image (x86 / x64 / ARM64) in tiers: 1 same name, import or identical bytes; 2 same control flow; 3 same imports, strings and constants; 4 call-graph neighbours; 5 fuzzy above minScore. A pair is taken only when unique on both sides. Returns per-tier counts and one view's rows by old address (unmatched: old, then new). The first call waits for both code indexes.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `oldImage` | string | yes |  | The older build: native image id or path (load both; the second gets an id like app.dll#2). |
| `newImage` | string | yes |  | The newer build: native image id or path. |
| `view` | string |  | `pairs` | pairs, changed (code differs), unmatched or ambiguous (with candidates). Values: pairs, changed, unmatched, ambiguous. |
| `tier` | integer |  | `0` | Only pairs of this tier (1-5); 0 for all. |
| `codeOnly` | boolean |  |  | Match functions by code only, not by names. |
| `minScore` | number |  | `0.7` | Least similarity for a fuzzy match (0-1). |
| `offset` | integer |  |  | Rows to skip. |
| `limit` | integer |  | `40` | Max rows. |
| `maxTokens` | integer |  |  | Page size in tokens. |

Structured output: `oldImage`, `newImage`, `oldFunctions`, `newFunctions`, `matched`, `identical`, `changed`, `unmatchedOld`, `unmatchedNew`, `ambiguous`, `tiers`, `view`, `items`, `offset`, `total`, `notes`, `limit`, `totalExact`, `hasMore`, `nextOffset`.

### diff_function

**Diff a function between builds** (read-only, idempotent, open-world, long-running)

What changed in one function between two builds (paired through compare_native_images). view=asm: both instruction lists aligned, rows = (same), ~ (other operands), - or +, with build-independent operands (branch labels, matched callee names, string text, mapped data) so moved code and relocations do not show; changed regions with context. view=pseudocode: a unified diff of both functions' pseudocode. addresses: a summary per function.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `oldImage` | string | yes |  | The older build: native image id or path (load both; the second gets an id like app.dll#2). |
| `newImage` | string | yes |  | The newer build: native image id or path. |
| `address` | string |  |  | An address in the function: Hex VA or RVA (rva:/va:/off: prefix), export, module!import or function name. |
| `addresses` | string[] |  |  | Instead of address: up to 20 functions, one summary each. |
| `side` | string |  | `old` | Which build the address is in. Values: old, new. |
| `view` | string |  | `asm` | asm, or pseudocode (needs an engine). Values: asm, pseudocode. |
| `context` | integer |  | `4` | Unchanged rows or lines around each change (0-50). |
| `codeOnly` | boolean |  |  | Match functions by code only, not by names. |
| `engine` | string |  |  | view=pseudocode: auto, ida or ghidra. Values: auto, ida, ghidra. |
| `offset` | integer |  |  | Rows to skip. |
| `limit` | integer |  | `500` | Max rows. |
| `maxTokens` | integer |  |  | Page size in tokens. |

Structured output: `oldImage`, `newImage`, `oldFunction`, `newFunction`, `oldAddress`, `newAddress`, `tier`, `basis`, `score`, `view`, `summary`, `same`, `changed`, `removed`, `added`, `items`, `offset`, `total`, `candidates`, `functions`, `notes`, `limit`, `totalExact`, `hasMore`, `nextOffset`.

### map_address_between_builds

**Map an address to a new build** (read-only, idempotent, long-running)

Where addresses of the old build are in the new build: a function start to the matched function, an address inside one to the aligned instruction, a string to the same string, other data through the references of matched instructions. Each result has the new address with confidence and reason, or why not and nearby candidates.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `oldImage` | string | yes |  | The older build: native image id or path (load both; the second gets an id like app.dll#2). |
| `newImage` | string | yes |  | The newer build: native image id or path. |
| `address` | string |  |  | Address in the old build: Hex VA or RVA (rva:/va:/off: prefix), export, module!import or function name. |
| `addresses` | string[] |  |  | Instead of address: up to 100 addresses. |
| `codeOnly` | boolean |  |  | Match functions by code only, not by names. |

Structured output: `oldImage`, `newImage`, `results`, `failed`.

### make_code_pattern

**Make a code pattern** (read-only, idempotent, open-world, long-running)

Make a byte pattern for an address that survives rebuilds: instruction bytes with displacements and relocated addresses as ?? ('48 8B 05 ?? ?? ?? ??'), extended until unique in the executable sections. anchor=auto starts at the address, else at an instruction referencing it (with the operand offset to recover it); xrefs: one per referencing instruction; range: [address, end). search_code_pattern finds it in another build.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `image` | string | yes |  | Native image id, file name or path. |
| `address` | string |  |  | Hex VA or RVA (rva:/va:/off: prefix), export, module!import or function name. |
| `addresses` | string[] |  |  | Instead of address: up to 50 addresses. |
| `anchor` | string |  | `auto` | auto, address, reference, xrefs or range. Values: auto, address, reference, xrefs, range. |
| `maxBytes` | integer |  | `64` | Longest pattern in bytes (8-512). |
| `maxPatterns` | integer |  | `8` | anchor=xrefs: most signatures (1-32). |
| `engine` | string |  |  | anchor=xrefs: auto, ours, ida or ghidra (engine references added). Values: auto, ours, ida, ghidra. |
| `format` | string |  | `ida` | ida, x64dbg, mask (\x48\x00 x?) or bitmask (0x48, 0x00 0b01). Values: ida, x64dbg, mask, bitmask. |
| `end` | string |  |  | anchor=range: exclusive end, an address or +length. |

Structured output: `image`, `format`, `results`, `failed`.

### search_code_pattern

**Search a code pattern** (read-only, idempotent, long-running)

Find a byte pattern with ?? wildcards (as make_code_pattern writes it) in the executable sections of loaded native images, by image then address, with the function and offset of each hit.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `pattern` | string | yes |  | Hex bytes with ?? wildcards. |
| `images` | string[] |  |  | Image ids or paths; omit for every loaded native image. |
| `allSections` | boolean |  |  | Search every section, not only executable ones. |
| `offset` | integer |  |  | Rows to skip. |
| `limit` | integer |  | `100` | Max rows. |
| `maxTokens` | integer |  |  | Page size in tokens. |

Structured output: `pattern`, `items`, `offset`, `total`, `failed`, `notes`, `limit`, `totalExact`, `hasMore`, `nextOffset`.

### migrate_native_names

**Carry names to a new build** (edit, idempotent, long-running)

Copy the old build's names, comments and engine types to the new build's user annotations through the function match (map_address_between_builds). Never replaces a user name, comment or type of the new build; each skipped item has a reason code. Applied as undoable edits (editIds).

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `oldImage` | string | yes |  | The older build: native image id or path (load both; the second gets an id like app.dll#2). |
| `newImage` | string | yes |  | The newer build: native image id or path. |
| `dryRun` | boolean |  | `true` | Default true: preview; pass dryRun=false to apply. |
| `minTier` | integer |  | `5` | Weakest match tier accepted: 1 (names, identical bytes) to 5 (all). |
| `minScore` | number |  | `0` | Least mapping confidence accepted (0-1). |
| `sources` | string[] |  |  | Layers to copy (default user). |
| `namesOnly` | boolean |  |  | Names only, no comments. |
| `codeOnly` | boolean |  |  | Match functions by code only, not by names. |
| `offset` | integer |  |  | Rows to skip. |
| `limit` | integer |  | `100` | Max rows. |
| `maxTokens` | integer |  |  | Page size in tokens. |

Structured output: `oldImage`, `newImage`, `dryRun`, `applied`, `editIds`, `set`, `skipped`, `skippedBy`, `items`, `offset`, `total`, `notes`, `limit`, `totalExact`, `hasMore`, `nextOffset`.

### migrate_native_patches

**Migrate patches to a new build** (destructive, long-running)

Carry byte patches from an old build to a new one through the build matcher (compare_native_images). A patch is reapplied only where the new build's original bytes at the mapped address match what it expected (patch_asm patches are re-assembled there), each applied or refused with a reason code. The same image as old and new with patchSet replays a patch set on its own build.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `oldImage` | string | yes |  | The old build: native image id or path (its in-memory patches are the source unless patchSet). |
| `newImage` | string | yes |  | The new build: native image id or path (load both; the second gets an id like name#2). |
| `patchSet` | string |  |  | A JSON patch set (export_native_patches format=json): path or text. |
| `dryRun` | boolean |  | `true` | Default true: preview; pass dryRun=false to apply. |
| `codeOnly` | boolean |  |  | Match functions by code only, not by names. |
| `offset` | integer |  |  | Rows to skip. |
| `limit` | integer |  | `100` | Max rows. |
| `maxTokens` | integer |  |  | Page size in tokens. |

Structured output: `oldImage`, `newImage`, `source`, `dryRun`, `applied`, `editIds`, `patches`, `carried`, `refused`, `refusedBy`, `items`, `offset`, `total`, `notes`, `limit`, `totalExact`, `hasMore`, `nextOffset`.

### update_to_new_build

**Update work to a new build** (destructive, idempotent, long-running)

Carry the work on an old native build to its new build through one function match: names, comments and engine types, PDB and Il2Cpp layers, patches (stubs re-created), code-pattern drift, the Il2Cpp method mapping, notes. Returns per-category counts with reason codes and the items; a re-run reports already_present. Two .NET assemblies: notes via find_counterpart. Rules: guide topic builds.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `oldImage` | string | yes |  | The old build: native image id or path. |
| `newImage` | string | yes |  | The new build: native image id or path. |
| `dryRun` | boolean |  | `true` | Default true: preview; pass dryRun=false to apply. |
| `include` | string[] |  |  | Categories to carry (default all). |
| `patchSet` | string |  |  | Patch set (export_native_patches json): text or path. |
| `stubPlacement` | string |  |  | Re-created patch stubs: auto, cave or section. Values: auto, cave, section. |
| `oldIl2Cpp` | string[] |  |  | Old build's Il2Cpp dummy assemblies. |
| `newIl2Cpp` | string[] |  |  | New build's Il2Cpp dummy assemblies. |
| `codeOnly` | boolean |  |  | Match functions by code only, not by names. |
| `maxPatterns` | integer |  | `100` | Most code patterns made (0-1000). |
| `category` | string |  |  | Only items of this category. Values: names, pdb, il2cpp_names, patches, patterns, il2cpp_mapping, notes, dotnet. |
| `outcome` | string |  |  | Only items with this outcome. Values: carried, would_carry, already_present, refused, not_applicable, ambiguous. |
| `offset` | integer |  |  | Rows to skip. |
| `limit` | integer |  | `100` | Max rows. |
| `maxTokens` | integer |  |  | Page size in tokens. |

Structured output: `summary`, `oldImage`, `newImage`, `dryRun`, `editIds`, `included`, `oldFunctions`, `newFunctions`, `functionsMatched`, `categories`, `il2CppMapping`, `items`, `offset`, `total`, `notes`, `limit`, `totalExact`, `hasMore`, `nextOffset`.

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
| `tags` | string[] |  |  | At most 10. |
| `evidence` | array |  |  | Where it was seen (at most 10): {tool, args} of a call made here (its resultSha256 is filled in), or {text}. |

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
| `addTags` | string[] |  |  | Tags to add. |
| `removeTags` | string[] |  |  | Tags to remove. |
| `addEvidence` | array |  |  | Where it was seen (at most 10): {tool, args} of a call made here (its resultSha256 is filled in), or {text}. |

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
| `offset` | integer |  |  | Rows to skip. |
| `limit` | integer |  | `50` | Notes per page (default 50). |

Structured output: `items`, `offset`, `total`, `notes`, `limit`, `totalExact`, `hasMore`, `nextOffset`.

## engine

Edits inside the decompiler engine's database: types, locals, frames, declarations, scripting.

### get_engine_status

**Engine status of a native image** (read-only, idempotent, open-world)

IDA and Ghidra sessions of a native image: opening (stage, seconds), failed, not started, or open with the engine's view (language, compiler, analysis state, warnings, counts, entry points, hashes, blocks, database, worker, unsaved edits). Starts no engine.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `image` | string | yes |  | Native image id, file name or path. |
| `engine` | string |  |  | Default auto: both. Values: auto, ida, ghidra. |

Structured output: `image`, `engines`.

### set_native_type

**Set a native prototype or global type** (destructive, idempotent, open-world, long-running)

Set the prototype of a native function ('int __fastcall Parse(Packet *p, int len)') or the type of a global ('Handler *[8]') in the engine. Named types must exist there (pushed PDB, RTTI and Il2Cpp types, or declare_native_types). User types win over recovered ones; empty clears. rename=true also names the function as its prototype does. Kept with the image's annotations.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `image` | string | yes |  | Native image id, file name or path. |
| `address` | string |  |  | A function start or a global: Hex VA or RVA (rva:/va:/off: prefix), export, module!import or function name. |
| `type` | string |  |  | C prototype for a function, C type for a global; empty to clear the user type. |
| `items` | string |  |  | Instead of address and type: lines 'address = type'. |
| `rename` | boolean |  |  | Name the function as its prototype does. |
| `guess` | boolean |  |  | Report the engine's guess at address without applying it. |
| `showDecompile` | string |  |  | The function's pseudocode after the edit (after) or its unified diff (diff). Values: none, after, diff. |
| `engine` | string |  |  | auto (default), ida or ghidra. Values: auto, ida, ghidra. |

Structured output: `applied`, `dryRun`, `changes`, `editIds`, `failed`.

### set_native_local

**Rename or retype a decompiler local** (destructive, idempotent, open-world, long-running)

Rename and/or retype a local or argument in a native function's pseudocode, named as decompile_native shows it (v3, a1) or stack:0x28. Later edits may use its new name; its first name again, or clear, drops the edit. A type that does not fit is refused. Kept with the image's annotations.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `image` | string | yes |  | Native image id, file name or path. |
| `function` | string | yes |  | The function: Hex VA or RVA (rva:/va:/off: prefix), export, module!import or function name. |
| `local` | string |  |  | The variable: its name in the pseudocode, or stack:<offset> (hex). |
| `newName` | string |  |  | New name (a C identifier). |
| `type` | string |  |  | New C type. |
| `clear` | boolean |  |  | Drop the user's name and type of the variable. |
| `items` | string |  |  | Instead of local: lines 'local = newName', or JSON [{local, newName?, type?, clear?}]. |
| `showDecompile` | string |  |  | The function's pseudocode after the edit (after) or its unified diff (diff). Values: none, after, diff. |
| `engine` | string |  |  | auto (default), ida or ghidra. Values: auto, ida, ghidra. |

Structured output: `applied`, `dryRun`, `changes`, `editIds`, `failed`.

### set_native_stack_var

**Rename, retype or delete a stack variable** (destructive, idempotent, open-world, long-running)

Rename and/or retype a stack frame member, by its get_native_frame name (var_28) or frame offset (0x20, from the lowest address); a type at an empty offset creates one. The return address and saved registers are refused. Kept with the image's annotations.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `image` | string | yes |  | Native image id, file name or path. |
| `function` | string | yes |  | The function: Hex VA or RVA (rva:/va:/off: prefix), export, module!import or function name. |
| `variable` | string | yes |  | The member: its name, or its frame offset (hex). |
| `newName` | string |  |  | New name (a C identifier). |
| `type` | string |  |  | New C type. |
| `delete` | boolean |  |  | Delete the member. |
| `clear` | boolean |  |  | Drop the user's edit, restoring the engine's member. |
| `showDecompile` | string |  |  | The function's pseudocode after the edit (after) or its unified diff (diff). Values: none, after, diff. |
| `engine` | string |  |  | auto (default), ida or ghidra. Values: auto, ida, ghidra. |

Structured output: `applied`, `dryRun`, `changes`, `editIds`, `failed`.

### get_native_frame

**Native stack frame and locals** (read-only, idempotent, open-world, long-running)

Stack frame of a native function as the engine has it (members: offset, name, type, size; Ghidra counts saved registers as locals); locals=true adds the decompiler's locals (name, type, register or stack offset, user edits). Offsets count from the lowest address; brackets from the return address.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `image` | string | yes |  | Native image id, file name or path. |
| `function` | string | yes |  | The function: Hex VA or RVA (rva:/va:/off: prefix), export, module!import or function name. |
| `engine` | string |  |  | auto (default), ida or ghidra. Values: auto, ida, ghidra. |
| `locals` | boolean |  |  | Decompile for the locals too. |
| `offset` | integer |  |  | Rows to skip. |
| `limit` | integer |  | `200` | Max rows (max 5000). |

Structured output: `image`, `engine`, `function`, `name`, `localSize`, `savedRegisters`, `returnAddressOffset`, `members`, `locals`, `localsNote`, `items`, `offset`, `total`, `limit`, `totalExact`, `hasMore`, `nextOffset`.

### declare_native_types

**Declare C types in the engine** (destructive, idempotent, open-world, long-running)

Declare C types (structs, unions, enums, typedefs, function types) in the engine; a type of the same name is replaced, and declarations win over recovered types. Errors carry the engine's messages and are not saved. typeName with members upserts or removes enum members, with fields struct or union members; delete or rename edits a named type. Kept with the image's annotations.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `image` | string | yes |  | Native image id, file name or path. |
| `declarations` | string |  |  | C declarations; types they name must exist or be declared too. |
| `typeName` | string |  |  | Enum, struct or union to edit. |
| `members` | string |  |  | Enum: 'NAME=value, ...' (hex or decimal; or lines); 'NAME=' removes. |
| `fields` | string |  |  | Struct or union: 'name: type; name@0x10: type; @0x10: type' (or lines); 'name:' removes. |
| `delete` | string |  |  | A type to delete. |
| `rename` | string |  |  | 'Old=New'; kept edits naming it follow. |
| `engine` | string |  |  | auto (default), ida or ghidra. Values: auto, ida, ghidra. |

Structured output: `applied`, `dryRun`, `changes`, `editIds`, `failed`.

### list_native_types

**Browse the engine's types** (read-only, idempotent, open-world, long-running)

Named types of the engine's database (PDB, RTTI, Il2Cpp, type libraries, declare_native_types) with size and member count; name= shows one type as a C declaration with member offsets.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `image` | string | yes |  | Native image id, file name or path. |
| `filter` | string |  |  | Name filter: substring (case-insensitive), glob with * and ?, or /regex/ (flags i, m, s). |
| `kind` | string |  |  | udt: struct or union. Values: struct, union, udt, enum, typedef, func, ptr. |
| `name` | string |  |  | Show this one type in full instead of a list. |
| `offset` | integer |  |  | Rows to skip. |
| `limit` | integer |  | `200` | Max rows (max 5000). |
| `engine` | string |  |  | auto (default), ida or ghidra. Values: auto, ida, ghidra. |
| `sort` | string |  |  | name (default), size, or ordinal (the engine's order). Values: name, size. |
| `descending` | boolean |  |  | Reverse the order. |
| `members` | boolean |  |  | List each type's first 32 members (enums: name = value). |
| `related` | boolean |  |  | Add the types each one refers to. |

Structured output: `engine`, `items`, `offset`, `total`, `limit`, `totalExact`, `hasMore`, `nextOffset`.

### define_native

**Redefine code or data in the engine** (destructive, idempotent, open-world, long-running)

Change the engine's analysis at an address. code decodes instructions (to end, else following the flow); function makes a function (with end: its extent; on one: moves its end); undefine makes unknown bytes (to end, else the item; at a function start the function); data makes a data item of type. Data and undefine replace a user type on a global there. Kept with the image's annotations.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `image` | string | yes |  | Native image id, file name or path. |
| `address` | string | yes |  | Start: Hex VA or RVA (rva:/va:/off: prefix), export, module!import or function name. |
| `kind` | string | yes |  | What to make. Values: code, function, undefine, data. |
| `end` | string |  |  | Exclusive end address (same forms as address). |
| `type` | string |  |  | kind=data: byte, word, dword, qword, float, double, string, string16 (UTF-16) or a C type, with an optional [count] (dword[8]). |
| `engine` | string |  |  | auto (default), ida or ghidra. Values: auto, ida, ghidra. |

Structured output: `applied`, `dryRun`, `changes`, `editIds`, `failed`.

### reanalyze_native

**Re-run native auto-analysis** (destructive, open-world, long-running)

Re-run IDA's or Ghidra's auto-analysis over an image (or from-to) and save; a full run also completes a Ghidra analysis the open's budget cut short. options= sets analyzers for this run; analyzers=true lists them.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `image` | string | yes |  | Native image id, file name or path. |
| `engine` | string |  |  | auto (default), ida or ghidra. Values: auto, ida, ghidra. |
| `analyzers` | boolean |  |  | List the analyzer options and values instead of running. |
| `filter` | string |  |  | With analyzers: name filter. |
| `options` | string[] |  |  | name=value per option (AF_FLIRT=false, 'Decompiler Parameter ID=true'). |
| `from` | string |  |  | Range start (default: the whole image). |
| `to` | string |  |  | Range end (exclusive). |
| `timeoutSeconds` | integer |  | `600` | Seconds (1-3600); what is left runs on the next run. |
| `offset` | integer |  |  | With analyzers: rows to skip. |
| `limit` | integer |  | `200` | With analyzers: max rows. |

Structured output: `image`, `engine`, `scope`, `complete`, `functionsBefore`, `functionsAfter`, `options`, `items`, `offset`, `total`, `limit`, `totalExact`, `hasMore`, `nextOffset`.

### set_native_operand

**Set how an operand displays** (destructive, idempotent, open-world, long-running)

Set how an instruction operand displays in the engine's disassembly and, where the decompiler follows it, the pseudocode: offset (the constant as an address), stack (a stack variable), enum (type: the enum; a member of the constant's value), struct (type: 'Packet' or 'Packet+0x10'; IDA only) or default (the engine's). Ghidra shows numbers and enum members as equates. Kept with the image's annotations.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `image` | string | yes |  | Native image id, file name or path. |
| `address` | string | yes |  | The instruction: Hex VA or RVA (rva:/va:/off: prefix), export, module!import or function name. |
| `operand` | integer | yes |  | Operand index, 0 for the first. |
| `display` | string | yes |  | How to display it (see the description). Values: hex, dec, oct, bin, char, offset, stack, enum, struct, default. |
| `type` | string |  |  | display=enum or struct: the type's name (struct: optionally +delta). |
| `engine` | string |  |  | auto (default), ida or ghidra. Values: auto, ida, ghidra. |

Structured output: `applied`, `dryRun`, `changes`, `editIds`, `failed`.

### ida_python

**Run IDAPython on a native image** (destructive, open-world, long-running)

Run Python in the IDA worker holding a native image's database (idalib): IDAPython modules imported, base = image base, globals persist (reset=true clears); returns a final expression's value, stdout and stderr. Off unless --ida-scripting (CORVUS_IDA_SCRIPTING=1): the code has the server's rights. Not journaled: persist=true saves.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `image` | string | yes |  | Native image id, file name or path. |
| `code` | string |  |  | Python source (or pass scriptPath). |
| `reset` | boolean |  |  | Clear the globals earlier calls left. |
| `engine` | string |  |  | Default auto. Values: auto, ida. |
| `scriptPath` | string |  |  | A .py file to run instead of code. |
| `maxTokens` | integer |  |  | Page size in tokens. |
| `persist` | boolean |  |  | Save the database after the script. |
| `allowError` | boolean |  |  | Return an exception as the result instead of an error. |

Structured output: `image`, `engine`, `result`, `stdout`, `stderr`, `error`, `saved`.

### ghidra_script

**Run a Ghidra script on a native image** (destructive, open-world, long-running)

Run Java in the Ghidra worker holding a native image's program: a GhidraScript class, or run()'s body with imports first (currentProgram, println, FlatProgramAPI). One transaction, committed when the script returns, then saved; an exception rolls it back. Off unless --ghidra-scripting (CORVUS_GHIDRA_SCRIPTING=1): the code has the server's rights.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `image` | string | yes |  | Native image id, file name or path. |
| `code` | string | yes |  | Java source: a class extending GhidraScript, or statements for run(). |
| `timeoutSeconds` | integer |  | `120` | Seconds before the script is cancelled (1-3600). |
| `engine` | string |  |  | Default auto. Values: auto, ghidra. |
| `maxTokens` | integer |  |  | Page size in tokens. |
| `allowError` | boolean |  |  | Return an exception as the result instead of an error. |

Structured output: `image`, `engine`, `result`, `stdout`, `stderr`, `error`, `saved`.

### export_engine_database

**Export the engine database** (destructive, idempotent, open-world, long-running)

Write a native image's engine database (analysis plus names, comments and types pushed from here) for the engine's GUI: IDA a compressed .i64, Ghidra a packed .gzf; Ghidra's own types also as .h or .gdt. Written whole or not at all.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `image` | string | yes |  | Native image id, file name or path. |
| `outputPath` | string | yes |  | The .i64 (IDA), .gzf, .h or .gdt (Ghidra) file to write. |
| `overwrite` | boolean |  |  | Replace outputPath if it exists. |
| `engine` | string |  |  | Default: the extension's engine, else IDA. Values: auto, ida, ghidra. |

Structured output: `image`, `engine`, `path`, `bytes`, `note`.

## android

Android packages: manifest, resources, DEX code, Java decompilation, Java / .NET mapping, devices.

### get_android_manifest

**Android manifest** (read-only, idempotent)

AndroidManifest.xml of an Android package, decoded. view=summary (default): package, versions, SDKs, permissions, application flags, component counts, exported components and why, queries, features, libraries, highlights. view=components: each component with intent filters, deep links, meta-data. Raw XML: get_android_resource.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `path` | string | yes |  | An .apk, .aab or split set (.apks, .xapk, .apkm). |
| `view` | string |  |  | summary (default) or components. |
| `offset` | integer |  |  | Rows to skip. |
| `limit` | integer |  | `50` | Most components. |

Structured output: `package`, `versionCode`, `versionName`, `minSdk`, `targetSdk`, `maxSdk`, `compileSdk`, `split`, `application`, `permissions`, `declaredPermissions`, `componentCounts`, `exported`, `exportedTotal`, `queries`, `features`, `libraries`, `metaData`, `highlights`, `issues`, `items`, `offset`, `total`, `limit`, `totalExact`, `hasMore`, `nextOffset`.

### list_android_resources

**List Android resources** (read-only, idempotent)

Compiled resources of an Android package (resources.arsc, or a bundle's resources.pb): a row per resource and configuration with id, type, name, qualifiers, value type and value (cut at 200 characters); counts per type.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `path` | string | yes |  | An .apk, .aab or split set (.apks, .xapk, .apkm). |
| `type` | string |  |  | Only this type (string, layout, xml, ...). |
| `name` | string |  |  | Only names matching this (* and ? wildcards). |
| `config` | string |  |  | Only this configuration (pt-rBR, or default). |
| `offset` | integer |  |  | Rows to skip. |
| `limit` | integer |  | `100` | Most rows. |

Structured output: `items`, `offset`, `total`, `types`, `limit`, `totalExact`, `hasMore`, `nextOffset`.

### get_android_resource

**Get Android resource** (destructive, idempotent)

One entry or resource of an Android package: an entry path (binary XML decoded, references named; text; else a hex preview), or @type/name / 0x7f... for its value in every configuration. outputPath writes the raw bytes.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `path` | string | yes |  | An .apk, .aab or split set (.apks, .xapk, .apkm). |
| `name` | string | yes |  | An entry path (res/xml/x.xml, assets/...), @type/name or a resource id 0x7f... |
| `outputPath` | string |  |  | Write the entry's bytes to this file. |
| `overwrite` | boolean |  |  | Replace outputPath if it exists. |
| `offset` | integer |  |  | Character offset (a page's nextOffset). |
| `maxTokens` | integer |  |  | Page size in tokens. |

Structured output: `entry`, `outputPath`, `bytes`, `sha256`, `code`, `offset`, `nextOffset`, `totalChars`.

### list_dex_classes

**List DEX classes** (read-only, idempotent)

Classes defined in an Android package's DEX code (every classes*.dex): descriptor, DEX file, access, superclass, interfaces, member counts, source file; unfiltered, the largest packages.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `path` | string | yes |  | An Android package, a .dex, or a jar with classes*.dex. |
| `query` | string |  |  | Only classes whose name contains or matches (* ?) this. |
| `package` | string |  |  | Only this package and its subpackages. |
| `offset` | integer |  |  | Rows to skip. |
| `limit` | integer |  | `100` | Most classes. |

Structured output: `items`, `offset`, `total`, `notes`, `packages`, `limit`, `totalExact`, `hasMore`, `nextOffset`.

### get_dex_class

**DEX class** (read-only, idempotent)

One DEX class: superclass, interfaces, generic signature, enclosing and inner classes, Kotlin @Metadata, annotations; then its members, paged: fields (type, static value) and methods (exact id Lpkg/C;->name(params)ret, Java signature, code size, registers, parameter names).

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `path` | string | yes |  | An Android package, a .dex, or a jar with classes*.dex. |
| `class` | string | yes |  | Class: Lpkg/Name;, pkg.Name, or pkg.Outer.Inner / pkg.Outer$Inner. |
| `members` | string |  |  | all (default), fields or methods. |
| `query` | string |  |  | Only members whose name contains this. |
| `offset` | integer |  |  | Rows to skip. |
| `limit` | integer |  | `150` | Most members. |

Structured output: `descriptor`, `javaName`, `dexFile`, `access`, `super`, `interfaces`, `sourceFile`, `genericSignature`, `enclosingClass`, `enclosingMethod`, `innerClasses`, `kotlin`, `annotations`, `fields`, `methods`, `items`, `offset`, `total`, `limit`, `totalExact`, `hasMore`, `nextOffset`.

### disassemble_dex

**Disassemble DEX** (read-only, idempotent)

Smali (baksmali layout) of a DEX method or class; a class starts with its method ids and sizes. format=annotated adds code offsets and units.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `path` | string | yes |  | An Android package, a .dex, or a jar with classes*.dex. |
| `symbol` | string | yes |  | A method (Lpkg/C;->m(I)V, or pkg.C::m with optional (int, String)) or a class (pkg.C, Lpkg/C;). |
| `format` | string |  |  | Output layout (default smali). Values: smali, annotated. |
| `offset` | integer |  |  | Character offset (a page's nextOffset). |
| `maxTokens` | integer |  |  | Page size in tokens. |

Structured output: `code`, `offset`, `nextOffset`, `totalChars`.

### decompile_java

**Decompile Java** (read-only, idempotent, open-world, long-running)

Java source of a class or method of an Android package or a jar through JADX (CORVUS_JAVA_DECOMPILER, JDK 17+). A member, anonymous or lambda class comes from the code JADX writes it in. Without JADX, disassemble_dex gives smali.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `path` | string | yes |  | An .apk, .aab or split set, a .dex, or a jar (DEX or .class files). |
| `symbol` | string | yes |  | A class (pkg.C, Lpkg/C;) or method (Lpkg/C;->m(I)V, or pkg.C::m with optional (int, String)). |
| `javaOnly` | boolean |  |  | Partial Java where JADX fails; default: smali there. |
| `engine` | string |  |  | Decompiler. Values: jadx. |
| `offset` | integer |  |  | Character offset (a page's nextOffset). |
| `maxTokens` | integer |  |  | Page size in tokens. |

Structured output: `code`, `offset`, `nextOffset`, `totalChars`.

### search_dex

**Search DEX code** (read-only, idempotent, long-running)

Search DEX code. kind=string: literals with the method and offset of each use; type: defined classes and type uses; method / field: defined and referenced members with use counts; const: numeric constants; opcode: instructions by mnemonic.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `path` | string | yes |  | An Android package, a .dex, or a jar with classes*.dex. |
| `kind` | string | yes |  | What to search. Values: string, type, method, field, const, opcode. |
| `query` | string | yes |  | Case-insensitive substring or * / ? pattern; for const a number. |
| `offset` | integer |  |  | Rows to skip. |
| `limit` | integer |  | `100` | Most hits. |

Structured output: `items`, `offset`, `total`, `notes`, `limit`, `totalExact`, `hasMore`, `nextOffset`.

### find_dex_references

**Find DEX references** (read-only, idempotent, long-running)

Cross-references in DEX code, with the method and code offset of each instruction. direction=to: callers of a method, readers and writers of a field, uses of a class or string. direction=from: what a method (or each method of a class) calls, reads, writes and loads. Methods match by exact id.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `path` | string | yes |  | An Android package, a .dex, or a jar with classes*.dex. |
| `target` | string | yes |  | A class, method (Lpkg/C;->m(I)V or pkg.C::m(int)), field (Lpkg/C;->f:I or pkg.C::f) or a "quoted" string. |
| `direction` | string |  |  | to (default; who refers to target) or from. Values: to, from. |
| `kind` | string |  |  | How to read target (default auto; string: taken literally). Values: auto, class, method, field, string. |
| `offset` | integer |  |  | Rows to skip. |
| `limit` | integer |  | `100` | Most references. |

Structured output: `target`, `targetKind`, `direction`, `items`, `offset`, `total`, `notes`, `limit`, `totalExact`, `hasMore`, `nextOffset`.

### map_java_dotnet

**Map Java and .NET** (read-only, idempotent)

Pairs across a Java / .NET bridge. .NET for Android (Xamarin / MAUI): a Java wrapper class or method to its .NET type or method and back ([Register] and crc64 names). Unity Mono: the C# reaching a Java class or member through AndroidJavaClass / AndroidJavaObject / AndroidJavaProxy / AndroidJNI, and back, with a confidence. A * / ? pattern lists matching pairs. Reads loaded assemblies, and the package's with path.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `symbol` | string | yes |  | A Java class (Lpkg/C; or pkg.C), Java method id (Lpkg/C;->m(I)V), a .NET type or member, or a pattern (crc64*). |
| `path` | string |  |  | The package whose assemblies to read; optional when they are loaded. |
| `offset` | integer |  |  | Rows to skip. |
| `limit` | integer |  | `100` | Most pairs. |

Structured output: `query`, `direction`, `items`, `offset`, `total`, `notes`, `limit`, `totalExact`, `hasMore`, `nextOffset`.

### list_jni_bindings

**List JNI bindings** (read-only, idempotent, long-running)

Java native methods of an Android package paired with their code in lib/<abi>/*.so: Java_ exports by JNI name mangling and RegisterNatives tables in the libraries' data; also unbound methods and stray Java_ exports.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `path` | string | yes |  | An .apk, .aab or split set (.apks, .xapk, .apkm). |
| `abi` | string |  |  | ABI to read, or all; default arm64-v8a, else the first. |
| `class` | string |  |  | Only rows naming this class (pkg.C or pkg/C). |
| `kind` | string |  |  | Only this kind. Values: static_export, registered, unresolved, export_only. |
| `offset` | integer |  |  | Rows to skip. |
| `limit` | integer |  | `75` | Most rows. |

Structured output: `items`, `offset`, `total`, `libraries`, `notes`, `limit`, `totalExact`, `hasMore`, `nextOffset`.

### list_android_devices

**List Android devices** (read-only, idempotent, open-world)

Android devices and emulators adb sees: serial, state, product, model, transport. adb: CORVUS_ADB, else PATH, else the SDK's platform-tools.

No parameters.

Structured output: `items`, `unparsed`.

### get_android_device_info

**Android device info** (read-only, idempotent, open-world)

Device properties (getprop) with a summary: SDK, release, model, ABIs, fingerprint, patch level, build type, ro.debuggable, ro.secure, emulator or not.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `serial` | string |  |  | Device serial; optional with one device ready. |
| `query` | string |  |  | Only properties whose name or value contains this. |
| `offset` | integer |  |  | Rows to skip. |
| `limit` | integer |  | `100` | Most properties. |

Structured output: `serial`, `summary`, `properties`, `offset`, `total`, `limit`, `totalExact`, `hasMore`, `nextOffset`.

### list_android_packages

**List installed packages** (read-only, idempotent, open-world)

Packages installed on a device (pm list packages -f -U -i): name, APK path, uid and installer.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `serial` | string |  |  | Device serial; optional with one device ready. |
| `query` | string |  |  | Only package names containing this. |
| `user` | integer |  |  | Android user id (default: the current one). |
| `offset` | integer |  |  | Rows to skip. |
| `limit` | integer |  | `150` | Most packages. |

Structured output: `serial`, `items`, `offset`, `total`, `limit`, `totalExact`, `hasMore`, `nextOffset`.

### get_android_package_info

**Installed package info** (read-only, idempotent, open-world)

One installed package (dumpsys package): versions, SDKs, paths, ABI, flags, install times, installer, uid, requested permissions with their grant state, and per-user state.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `package` | string | yes |  | Package name, e.g. com.example.app. |
| `serial` | string |  |  | Device serial; optional with one device ready. |

Structured output: `serial`, `package`, `versionName`, `versionCode`, `minSdk`, `targetSdk`, `codePath`, `dataDir`, `primaryCpuAbi`, `flags`, `firstInstallTime`, `lastUpdateTime`, `installer`, `uid`, `permissions`, `users`.

### pull_android_package

**Pull installed package** (edit, idempotent, open-world, long-running)

Copies every APK of an installed package (base and splits) into a new or empty directory, with size and SHA-256 each, and summarizes the base APK. A failed pull leaves no files.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `package` | string | yes |  | Package name, e.g. com.example.app. |
| `outputDirectory` | string | yes |  | A new or empty directory to write the APKs to. |
| `serial` | string |  |  | Device serial; optional with one device ready. |

Structured output: `serial`, `package`, `files`, `summary`.

### pull_android_file

**Pull device file** (destructive, idempotent, open-world, long-running)

Copies one device file (not a directory) to outputPath with its size and SHA-256; a failed pull leaves nothing.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `remotePath` | string | yes |  | The file's path on the device. |
| `outputPath` | string | yes |  | The local file to write. |
| `overwrite` | boolean |  |  | Replace outputPath if it exists. |
| `serial` | string |  |  | Device serial; optional with one device ready. |

Structured output: `remote`, `local`, `size`, `sha256`.

### read_android_log

**Read device log** (read-only, idempotent, open-world)

Device log (logcat -d), newest lines first, by buffer, process, tag, priority and start time.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `serial` | string |  |  | Device serial; optional with one device ready. |
| `pid` | integer |  |  | Only this process id. |
| `tag` | string |  |  | Only this log tag. |
| `priority` | string |  |  | Lowest priority. Values: V, D, I, W, E, F. |
| `since` | string |  |  | Only lines since this time ('01-31 12:00:00.000') or the last N lines. |
| `buffer` | string |  |  | Log buffer (default: main, system, crash). Values: main, system, crash, events, radio, all, default. |
| `offset` | integer |  |  | Lines to skip from the newest. |
| `limit` | integer |  | `500` | Most lines. |

Structured output: `serial`, `items`, `offset`, `total`, `limit`, `totalExact`, `hasMore`, `nextOffset`.

### install_android_package

**Install package on device** (destructive, open-world, long-running)

Installs an APK, a split set or a directory of APKs on a device in one session; failures come back by their INSTALL_FAILED_ code. Changes the device: needs the server option --allow-device-changes.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `path` | string | yes |  | An .apk, split set or folder of APKs. |
| `keepInstalled` | boolean |  |  | Fail when the app is installed instead of replacing it. |
| `downgrade` | boolean |  |  | Allow a lower version code. |
| `grantPermissions` | boolean |  |  | Grant all requested runtime permissions. |
| `serial` | string |  |  | Device serial; optional with one device ready. |

Structured output: `applied`, `dryRun`, `changes`, `editIds`, `failed`, `items`, `pushedTo`.

### uninstall_android_package

**Uninstall package from device** (destructive, idempotent, open-world)

Removes an app from a device, with its data unless keepData. Changes the device: needs the server option --allow-device-changes.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `package` | string | yes |  | Package name, e.g. com.example.app. |
| `keepData` | boolean |  |  | Keep the app's data and cache. |
| `serial` | string |  |  | Device serial; optional with one device ready. |

Structured output: `applied`, `dryRun`, `changes`, `editIds`, `failed`, `items`, `pushedTo`.

## dumps

Crash dumps and crash text.

### open_minidump

**Open a crash dump** (read-only, idempotent, open-world, long-running)

Reads a Windows minidump (.dmp). view=summary: OS, process, the exception (faulting thread, module!function, instruction, registers, a C++ exception's thrown type), faulting module and thread, the .NET state (managed exception with stack and inner chain, heap), counts. modules (version, PDB, whether a matching image is here), threads, memory, unloaded: paged rows. Gives the id the other dump tools take. .NET decoding loads Microsoft's signature-checked DAC.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `path` | string | yes |  | The .dmp path (or an open dump's id). |
| `view` | string |  | `summary` | summary, modules, threads, memory or unloaded. |
| `offset` | integer |  |  | Rows to skip. |
| `limit` | integer |  | `50` | Max rows. |
| `imageDirectories` | string |  |  | Folders (';'-separated) with the program's binaries, kept for the dump; its own folder is always searched. |
| `dacPath` | string |  |  | The runtime's DAC (mscordaccore.dll / mscordacwks.dll) or its folder, when that build is not installed here. |
| `downloadDac` | boolean |  |  | Fetch the DAC from a symbol server when none matches here (network; refused under CORVUS_OFFLINE=1). |
| `maxTokens` | integer |  |  | Page size in tokens. |

Structured output: `id`, `view`, `path`, `fileSize`, `timeUtc`, `dumpType`, `system`, `process`, `exception`, `managed`, `counts`, `faultingModule`, `faultingThread`, `handleTypes`, `issues`, `notes`, `items`, `offset`, `total`, `limit`, `totalExact`, `hasMore`, `nextOffset`.

### dump_stack

**Crash dump stack** (read-only, idempotent)

Call stack of a minidump thread: x64 unwind data, x86 call targets and the EBP chain; JIT code without unwind data adds scanned frames (basis inferred). Names from loaded images (code index, PDB, Il2Cpp) or exports. .NET frames (DAC): token, IL offset, assembly, C# statement; Mono JIT frames from the runtime's report beside the dump.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `dump` | string | yes |  | A .dmp path or the id open_minidump returned. |
| `thread` | string |  |  | Thread id, '#index', name or 'exception'. Default: the faulting thread, else the first. |
| `dumpTimeContext` | boolean |  |  | Faulting thread: its context at dump time, not the exception context (.ecxr). |
| `maxFrames` | integer |  | `256` | Max frames walked (up to 1024). |
| `offset` | integer |  |  | Rows to skip. |
| `limit` | integer |  | `100` | Max rows. |
| `imageDirectories` | string |  |  | Folders (';'-separated) with the program's binaries, kept for the dump; its own folder is always searched. |
| `managed` | string |  | `auto` | auto: .NET frames through the DAC; off: native walk only. Values: auto, off. |
| `maxTokens` | integer |  |  | Page size in tokens. |

Structured output: `dump`, `threadId`, `threadName`, `context`, `architecture`, `registers`, `items`, `offset`, `total`, `stop`, `scannedFrames`, `managed`, `notes`, `limit`, `totalExact`, `hasMore`, `nextOffset`.

### dump_heap

**Crash dump .NET heap** (read-only, idempotent, long-running)

Lists the .NET GC heap of a minidump (through the DAC). stats: count and size per type, largest first; objects: matching objects (address, type, size, a string's value). Needs heap memory in the dump (else heap_not_captured).

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `dump` | string | yes |  | A .dmp path or the id open_minidump returned. |
| `mode` | string |  | `stats` | stats (per type) or objects (one row each). Values: stats, objects. |
| `type` | string |  |  | Type full name, '*' / '?' wildcards; default all. |
| `minSize` | integer |  | `0` | Min object size in bytes. |
| `offset` | integer |  |  | Rows to skip. |
| `limit` | integer |  | `50` | Max rows. |
| `maxObjects` | integer |  | `5000000` | Max objects walked. |
| `maxTokens` | integer |  |  | Page size in tokens. |

Structured output: `dump`, `mode`, `type`, `minSize`, `walked`, `matchedBytes`, `items`, `offset`, `total`, `totalExact`, `notes`, `limit`, `hasMore`, `nextOffset`.

### dump_object

**Crash dump .NET object** (read-only, idempotent)

One .NET object of a dump (DAC): type, size, fields (references expanded depth levels), a string's or boxed value, or array elements.

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

Hex dump of a dump's memory at an address with what is there (module!function, captured range, protection). Bytes the dump lacks come from the module image (writable data shows initial values) unless dumpOnly.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `dump` | string | yes |  | A .dmp path or the id open_minidump returned. |
| `address` | string | yes |  | Hex address, 'module+0x1234', or a module name (its base). |
| `length` | integer |  | `256` | Bytes to read (up to 65536). |
| `dumpOnly` | boolean |  |  | Only the bytes the dump holds, none from the module image. |
| `offset` | integer |  |  | Byte offset into the read (a page's nextOffset). |
| `maxTokens` | integer |  |  | Page size in tokens. |

Structured output: `dump`, `address`, `requested`, `length`, `source`, `location`, `region`, `protection`, `code`, `offset`, `note`, `nextOffset`, `nextAddress`, `totalChars`.

### symbolize_stack_text

**Symbolize crash text** (read-only, idempotent, long-running)

Resolves crash text against the loaded build: Unity Player.log / error.log, Mono and Il2Cpp lines, .NET exception text, Report.wer, Event Log 1000/1026, debugger stacks, Android tombstones. Each frame gets our name, a buildCheck (time stamp, MVID, BuildId or the text's own name; mismatch: another build) and the C# statement at an IL offset.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `text` | string |  |  | The crash text (up to 1 MiB). This or path. |
| `path` | string |  |  | A log or report file; its last 8 MiB are read. |
| `format` | string |  | `auto` | Text format (auto detects it). Values: auto, unity, dotnet, wer, eventlog, windbg, android. |
| `images` | string |  |  | Native image ids or paths (';'-separated); default all loaded. |
| `moduleBases` | string |  |  | Module load addresses, 'name=0xBASE;...', when the text has no module list. |
| `offset` | integer |  |  | Rows to skip. |
| `limit` | integer |  | `50` | Max rows. |
| `allFrames` | boolean |  |  | One row per frame; default folds 3+ matching native frames of one image into one row. |
| `maxTokens` | integer |  |  | Page size in tokens. |

Structured output: `format`, `exception`, `frames`, `items`, `offset`, `total`, `unrecognizedLines`, `unrecognizedSample`, `modulesMissing`, `notes`, `limit`, `totalExact`, `hasMore`, `nextOffset`.

### bucket_minidumps

**Group crash dumps** (read-only, idempotent, long-running)

Groups a folder of minidumps by signature: code | faulting module!function | next frames (raising frames skipped); .NET: clr | exception type | top managed frames; no exception: hang | top frames. Names, not offsets, so rebases do not split a bucket. Each bucket names its dumps and newest representative. Cached per file.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `folder` | string | yes |  | Folder of .dmp files. |
| `recursive` | boolean |  |  | Also search subfolders. |
| `pattern` | string |  |  | File patterns, ';'-separated (default *.dmp;*.mdmp). |
| `topFrames` | integer |  | `3` | Frames after the faulting one in the signature. |
| `skipModules` | string |  |  | More frames to skip, ';'-separated: module or module!function, '*' wildcards. |
| `splitByVersion` | boolean |  |  | Put the faulting module's version in the signature. |
| `managed` | string |  | `auto` | auto: managed signatures through a local DAC; off: native only. Values: auto, off. |
| `maxDumps` | integer |  | `1000` | Most dumps bucketed, newest first. |
| `imageDirectories` | string |  |  | Folders (';'-separated) with the program's binaries. |
| `offset` | integer |  |  | Rows to skip. |
| `limit` | integer |  | `50` | Max rows. |
| `maxTokens` | integer |  |  | Page size in tokens. |

Structured output: `folder`, `dumps`, `items`, `offset`, `total`, `failed`, `notes`, `limit`, `totalExact`, `hasMore`, `nextOffset`.

## live

Read-only inspection of a running process.

### inspect_process

**Inspect a running process (read-only)** (read-only, idempotent, open-world)

Inspects a running local process (Windows) read-only, every address named as dump_stack names a dump. view=summary: identity, counts, main module, largest committed regions; modules (PDB, matching file on disk), regions, threads (TEB, stack, start), stacks (one thread's registers and frames): paged rows. Opens PROCESS_QUERY_INFORMATION | PROCESS_VM_READ and THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION only; nothing is written, suspended or attached, and every handle is closed before returning.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `process` | string | yes |  | Process id (decimal or 0x hex) or name (notepad or notepad.exe); a shared name is refused with the candidate ids. |
| `view` | string |  | `summary` | summary, modules, regions, threads or stacks. |
| `thread` | string |  |  | threads: only this one; stacks: the thread walked (default the first). Id or name. |
| `offset` | integer |  |  | Rows to skip. |
| `limit` | integer |  | `50` | Max rows. |
| `regionFilter` | string |  |  | view=regions: committed (default), all, executable, writable, image, private or mapped. Values: committed, all, executable, writable, image, private, mapped. |
| `maxFrames` | integer |  | `64` | view=stacks: max frames walked (up to 256). |
| `imageDirectories` | string |  |  | Folders with the program's binaries (';'-separated) for modules whose own file is not readable. |
| `timeoutSeconds` | integer |  | `20` | Time limit in seconds (up to 120). |
| `maxTokens` | integer |  |  | Page size in tokens. |

Structured output: `processId`, `name`, `view`, `path`, `architecture`, `wow64`, `runtime`, `access`, `detached`, `handlesOpened`, `handlesClosed`, `stillRunning`, `notes`, `startTimeUtc`, `counts`, `mainModule`, `largestRegions`, `thread`, `stackStop`, `items`, `offset`, `total`, `limit`, `totalExact`, `hasMore`, `nextOffset`.
