# Tools

<!-- Generated from the tool catalog by DocsTests; run the tests with CORVUS_UPDATE_DOCS=1 to update. -->

165 tools in 14 toolsets. A server registers every tool unless it is started with `--toolsets` ([server options](configuration.md#server-options)). From a terminal, `corvus describe <tool>` prints the same reference and `corvus <tool> name=value ...` calls a tool ([cli.md](cli.md)).

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
| [live](#live) | 0 | 0 | 10: running programs: read-only inspection, and sessions with stop points, call recording, code coverage, activity traces, scripted console runs and user scripts |
| [web](#web) | 0 | 0 | 1: JavaScript bundles and their source maps |

## session

Workspace and server state.

### load_assembly

**Load assembly** (edit, idempotent, long-running)

Load a .NET assembly or every assembly in a folder (app folder, Unity *_Data/Managed, DummyDll). PE, ELF, Mach-O or wasm files load as native images (universal Mach-O: one slice, name[slice]); format=raw maps headerless code; folder loads skip native files. An Il2Cpp game (folder, global-metadata.dat, .apk/.xapk/.aab/.ipa/.app, memory dump) loads as dummy assemblies with addresses (metadata v24-39) plus the binary as a native image. A .gzf or .gpr program (copied) opens in Ghidra. A repeat load is a no-op.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `path` | string | yes |  | Absolute path to an assembly file or a folder. |
| `recursive` | boolean |  |  | Also load assemblies in subdirectories. |
| `loadProviders` | boolean |  |  | Also load the DLLs the imports bind to (one level, at most 16). |
| `slice` | string |  |  | Mach-O slice (or index; default arm64e, arm64, x86_64) or Il2Cpp APK ABI (default arm64-v8a). Values: arm64e, arm64, x86_64, x86_64h, arm64_32, armv7, armv7s, armv7k, i386, arm64-v8a, armeabi-v7a, x86. |
| `format` | string |  | `auto` | auto, or raw (headerless code). |
| `arch` | string |  |  | raw: x86, x64, arm, thumb, arm64; mips, ppc, riscv64, 6502 etc. via IDA or Ghidra. |
| `base` | string |  |  | raw: load address (default 0). |
| `entry` | string |  |  | raw: entry address or file offset (default start). |
| `processor` | string |  |  | IDA processor (-p): metapc, arm, mipsl... |
| `language` | string |  |  | Ghidra language id: x86:LE:32:default... |
| `compilerSpec` | string |  |  | Ghidra compiler spec (also the IDA compiler): windows, gcc, borlandcpp, borlanddelphi... |
| `seeds` | string[] |  |  | Starts before analysis: [function\|code\|label:]address[=name]. |
| `disableAnalyzers` | string[] |  |  | Analyzers off at import (AF_FLIRT, "Decompiler Switch Analysis"). |
| `program` | string |  |  | Program path in a .gpr, e.g. /app.exe (default: its only one). |

Structured output: `ids`, `entries`, `skipped`, `discardedEdits`.

### unload_assembly

**Unload assembly** (destructive, idempotent)

Remove an assembly (unsaved edits are discarded) or close a dump id.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `assembly` | string | yes |  | Assembly id, name or path. |

Structured output: `ids`, `discardedEdits`.

### reload_assembly

**Reload assembly** (destructive, idempotent)

Re-read an assembly from disk (after an update or an overwriting save), discarding unsaved edits.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `assembly` | string | yes |  | Assembly id, name or path. |

Structured output: `ids`, `entries`, `skipped`, `discardedEdits`.

### add_search_directory

**Add reference search directory** (edit, idempotent)

Add a folder (application or framework) where unloaded referenced assemblies are resolved for decompilation, navigation and C# patching.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `directory` | string | yes |  | Directory path. |

Structured output: `searchDirectories`, `suggested`.

### list_assemblies

**List loaded assemblies** (read-only, idempotent)

Loaded assemblies and native images: ids, versions, paths, Il2Cpp dummy / ReadyToRun / merged flags, unsaved edits; plus reference search directories. With path: the managed assemblies inside a container (bundle, .nupkg, .apk / .aab, Costura, zip), not extracted; archives (.asar with integrity, WebGL .data, HAR / mitmproxy) list their files.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `path` | string |  |  | Container file, Blazor or ClickOnce folder to list instead of the workspace. |
| `filter` | string |  |  | Id, name or path substring (case-insensitive). |
| `offset` | integer |  |  |  |
| `limit` | integer |  | `100` | Rows per page (default 100). |
| `maxTokens` | integer |  |  |  |

Structured output: `items`, `offset`, `total`, `searchDirectories`, `backgroundIndexing`, `container`, `limit`, `totalExact`, `hasMore`, `nextOffset`.

### server_status

**Server status** (read-only, idempotent, open-world)

Which server runs (version, program, install kind, client), catalog digest, what is loaded, limits, long-running tools, capabilities with fixes, tool families, unusable tools, engine sessions. expectedCatalogDigest detects a stale server; expectedExecutable checks the registered copy.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `expectedCatalogDigest` | string |  |  | Catalog digest to compare (t92-0123456789ab.p5-01234567). |
| `expectedExecutable` | string |  |  | Registered server path, compared with the running one. |

Structured output: `server`, `version`, `informationalVersion`, `executable`, `executableMatches`, `installKind`, `startedAt`, `uptimeSeconds`, `protocolVersion`, `client`, `catalogDigest`, `catalogMatches`, `catalogDifference`, `tools`, `loadedAssemblies`, `backgroundIndexing`, `workingSetMB`, `capabilities`, `longRunningTools`, `toolsets`, `unavailableTools`, `notes`, `engineTimeLimits`, `engineSessions`, `toolsFileAndTrace`, `sections`.

### read_result

**Read a kept result** (destructive, idempotent)

Read a kept result (resultId; kept on disk 7 days): page it, search it with query, or write it whole to outputPath. format=evidence: results (r-... or last:N) and their calls to outputPath; verify re-runs a bundle, entry (file.json#r-...) or result, or compares it with against.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `id` | string | yes |  | Result id, e.g. r-0123456789ab. |
| `offset` | integer |  |  | Character offset (nextOffset). |
| `maxTokens` | integer |  |  | Page size in tokens (default 6000). |
| `query` | string |  |  | Only lines containing this text (/regex/ for a pattern), with offsets. |
| `format` | string |  | `text` | text; json: the structured record; jsonl: its items, one per line. Values: text, json, jsonl, evidence, verify. |
| `outputPath` | string |  |  | Write the whole result to this file; returns path, bytes, SHA-256. |
| `overwrite` | boolean |  |  | Replace outputPath if it exists. |
| `against` | string |  |  | format=verify: compare with this, not a re-run: a kept result (r-...), last:N (recent call) or bundle entry (file.json#r-...). |

Structured output: `id`, `tool`, `totalChars`, `offset`, `nextOffset`, `code`, `matches`, `checks`, `input`, `path`, `bytes`, `sha256`.

### save_session

**Save the session** (destructive, idempotent)

Write the session's work to one JSON file: loaded files (path, relative path, SHA-256), .NET edits, native patches, names, comments, notes, Il2Cpp games, open minidumps; load_session restores it anywhere.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `outputPath` | string | yes |  | Output file path (.json). |
| `overwrite` | boolean |  |  | Replace the file if it exists. |
| `include` | string |  |  | Comma-separated: edits, patches, annotations, notes or all (default). |

Structured output: `outputPath`, `files`, `editedAssemblies`, `edits`, `patchedImages`, `patches`, `names`, `comments`, `notes`.

### load_session

**Load a session** (destructive, long-running)

Restore a save_session file: find each file (recorded path, relative path, else SHA-256 under searchRoots), load it, apply names, comments (never over a user name), patches, edits and notes; one outcome per item. A changed file is refused unless targetBuild=other (native work then needs the old build under searchRoots).

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `path` | string | yes |  | The session file. |
| `dryRun` | boolean |  | `true` | Report only. |
| `targetBuild` | string |  |  | Default same. Values: same, other. |
| `searchRoots` | string |  |  | ;-separated folders searched recursively for moved files, by SHA-256. |
| `include` | string |  |  | Comma-separated: edits, patches, annotations, notes or all (default). |
| `offset` | integer |  |  |  |
| `limit` | integer |  | `200` | Items to return (max 2000). |

Structured output: `path`, `dryRun`, `targetBuild`, `outcomes`, `offset`, `total`, `items`, `notes`, `limit`, `totalExact`, `hasMore`, `nextOffset`.

## dotnet

.NET browse, decompile, search, navigate, resources, ReadyToRun, project export.

### list_namespaces

**List namespaces** (read-only, idempotent)

List namespaces with their type counts (nested types under the namespace of their outer type).

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `assembly` | string |  |  | Assembly id, name or path; omit for all loaded. |
| `filter` | string |  |  | Substring (case-insensitive). |
| `offset` | integer |  |  |  |
| `limit` | integer |  | `200` |  |
| `maxTokens` | integer |  |  |  |

Structured output: `items`, `offset`, `total`, `limit`, `totalExact`, `hasMore`, `nextOffset`.

### list_types

**List types** (read-only, idempotent)

List types, optionally by namespace, name filter and kind.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `assembly` | string |  |  | Assembly id, name or path; omit for all loaded. |
| `namespace` | string |  |  | Exact namespace ("" or <global> for the global one). |
| `filter` | string |  |  | Name substring or wildcard (*, ?), or regex with regex=true. |
| `regex` | boolean |  |  | filter is a regex. |
| `kind` | string |  |  | Only this kind. Values: class, struct, interface, enum, delegate. |
| `topLevelOnly` | boolean |  |  | Leave out nested types. |
| `offset` | integer |  |  |  |
| `limit` | integer |  | `150` |  |
| `maxTokens` | integer |  |  |  |

Structured output: `items`, `offset`, `total`, `notEvaluated`, `totalExact`, `limit`, `hasMore`, `nextOffset`.

### get_type_info

**Type outline** (read-only, idempotent)

Outline of a type without decompiling: declaration, attributes, member counts, the first members of each kind; section= pages one kind (constants, enum values, signatures, tokens, IL sizes, Il2Cpp RVAs). A field: its value or FieldRVA data (file offset, SHA-256, readers, typed elements).

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `type` | string | yes |  | Type or member: Ns.Type, Ns.Outer+Inner, Ns.Type::Method(int, string), short name or token (0x06000123). |
| `assembly` | string |  |  | Assembly id, name or path; omit for all loaded. |
| `section` | string |  | `summary` | A kind to page, or all. Values: summary, nested, fields, properties, events, methods, all. |
| `includeCompilerGenerated` | boolean |  |  | Include compiler-generated members. |
| `offset` | integer |  |  |  |
| `limit` | integer |  | `100` |  |
| `maxTokens` | integer |  |  |  |

Structured output: `type`, `declaration`, `counts`, `section`, `items`, `offset`, `total`, `declaringType`, `attributes`, `compilerGeneratedHidden`, `initialData`, `limit`, `totalExact`, `hasMore`, `nextOffset`.

### get_assembly_info

**Assembly overview** (read-only, idempotent)

Assembly overview: identity (MVID, SHA-256), framework, entry point, counts, Il2Cpp, invalid IL, protection product, edits; view=references: where references resolve; metadata: PE headers, streams, tables, heaps, metadata problems.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `assembly` | string | yes |  | Assembly id, name or path. |
| `view` | string |  | `summary` | What to show. Values: summary, references, metadata, all. |

Structured output: `id`, `fullName`, `file`, `sha256`, `mvid`, `runtime`, `kind`, `machine`, `targetFramework`, `entryPoint`, `types`, `nestedTypes`, `namespaces`, `methods`, `fields`, `resources`, `referenceAssembly`, `il2CppAddressedMethods`, `invalidBodies`, `invalidExceptionClauses`, `unsavedEdits`, `referenceCount`, `unresolvedReferences`, `metadataIssueCount`, `transformers`, `references`, `attributes`, `tables`, `heaps`, `metadataIssues`.

### get_attributes

**Custom attributes** (read-only, idempotent)

Custom attributes with arguments on a type or member (parameters and return value included), or on the assembly and module (symbol omitted; format=csharp decompiles them).

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `symbol` | string |  |  | Type or member: Ns.Type, Ns.Outer+Inner, Ns.Type::Method(int, string), short name or token (0x06000123). Omit for assembly-level attributes. |
| `assembly` | string |  |  | Assembly id, name or path; omit for all loaded. Required when symbol is omitted. |
| `filter` | string |  |  | Only attributes whose type name contains this. |
| `format` | string |  | `rows` | rows, or csharp (symbol omitted). Values: rows, csharp. |
| `offset` | integer |  |  | Rows to skip (characters with format=csharp). |
| `limit` | integer |  | `200` |  |
| `maxTokens` | integer |  |  |  |

Structured output: `items`, `offset`, `total`, `code`, `nextOffset`, `totalChars`, `limit`, `totalExact`, `hasMore`.

### get_type_hierarchy

**Type hierarchy** (read-only, idempotent)

Base chain, interfaces and directly derived or implementing loaded types of a type.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `type` | string | yes |  | Type or member: Ns.Type, Ns.Outer+Inner, Ns.Type::Method(int, string), short name or token (0x06000123). |
| `assembly` | string |  |  | Assembly id, name or path; omit for all loaded. |
| `offset` | integer |  |  |  |
| `limit` | integer |  | `200` |  |
| `maxTokens` | integer |  |  |  |

Structured output: `type`, `baseChain`, `interfaces`, `items`, `offset`, `total`, `limit`, `totalExact`, `hasMore`, `nextOffset`.

### resolve_symbol

**Resolve symbol** (read-only, idempotent)

Every match of a symbol string or token, with kind, assembly, token and signature: disambiguate before other calls.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `symbol` | string | yes |  | Type or member: Ns.Type, Ns.Outer+Inner, Ns.Type::Method(int, string), short name or token (0x06000123). |
| `assembly` | string |  |  | Assembly id, name or path; omit for all loaded. |
| `kind` | string |  |  | Restrict to this kind. Values: any, type, method, field, property, event, member. |
| `offset` | integer |  |  |  |
| `limit` | integer |  | `50` |  |
| `maxTokens` | integer |  |  |  |

Structured output: `items`, `offset`, `total`, `notEvaluated`, `totalExact`, `limit`, `hasMore`, `nextOffset`.

### decompile_member

**Decompile to C#** (read-only, idempotent)

Decompile a type or member to C#: every overload unless a parameter list narrows it; async and iterator state machines and lambdas fold back into their method; a type whole, nested types included. Code the decompiler fails on shows as IL.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `member` | string | yes |  | Type or member: Ns.Type, Ns.Outer+Inner, Ns.Type::Method(int, string), short name or token (0x06000123). |
| `assembly` | string |  |  | Assembly id, name or path; omit for all loaded. |
| `kind` | string |  |  | Restrict to this kind (default any). Values: any, method, field, property, event. |
| `simplified` | boolean |  |  | Show the code as simplify_methods would leave it, assembly unchanged. |
| `provenance` | boolean |  |  | Start with build-pinning comments: SHA-256, MVID, tokens, IL hashes. |
| `offset` | integer |  |  |  |
| `maxTokens` | integer |  |  |  |

Structured output: `language`, `code`, `offset`, `nextOffset`, `totalChars`, `symbols`, `methods`, `bodies`.

### get_il

**IL disassembly** (read-only, idempotent)

IL disassembly (ildasm style, tokens, offsets, try blocks) of a member or type; each method starts with its normalized IL hash (stable across rebuilds) and raw IL SHA-256. For when the C# looks wrong, or as patch_method_il input.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `symbol` | string | yes |  | Type or member: Ns.Type, Ns.Outer+Inner, Ns.Type::Method(int, string), short name or token (0x06000123). |
| `assembly` | string |  |  | Assembly id, name or path; omit for all loaded. |
| `source` | boolean |  |  | Portable PDB source lines at IL offsets, local names, SourceLink URLs. |
| `offset` | integer |  |  |  |
| `maxTokens` | integer |  |  |  |

Structured output: `language`, `code`, `offset`, `nextOffset`, `totalChars`, `symbols`, `methods`, `bodies`.

### search_symbols

**Search symbols by name** (read-only, idempotent)

Find types and members by name across loaded assemblies: case-insensitive substring, wildcard (Get*Value?) or regex; queries with . or :: match full names. Exact matches first, then by name length, assembly and token.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `query` | string | yes |  | Name, substring, wildcard or regex. |
| `kind` | string |  |  | Restrict to this kind. Values: any, type, method, field, property, event, member. |
| `assembly` | string |  |  | Assembly id, name or path; omit for all loaded. |
| `namespace` | string |  |  | Only namespaces starting with this. |
| `regex` | boolean |  |  | query is a regex. |
| `limit` | integer |  | `100` |  |
| `maxTokens` | integer |  |  |  |
| `offset` | integer |  |  |  |

Structured output: `items`, `offset`, `total`, `notEvaluated`, `totalExact`, `limit`, `hasMore`, `nextOffset`.

### search_strings

**Search string literals** (read-only, idempotent)

Find string literals (ldstr, string constants) by substring, wildcard or regex, with the method and IL offset using each. Il2Cpp dummy DLLs: the game literals with slot RVAs and, with the binary, the functions loading them.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `query` | string | yes |  | Substring, wildcard or regex. |
| `assembly` | string |  |  | Assembly id, name or path; omit for all loaded. |
| `regex` | boolean |  |  | query is a regex. |
| `limit` | integer |  | `100` |  |
| `maxTokens` | integer |  |  |  |
| `offset` | integer |  |  |  |
| `usesPerLiteral` | integer |  | `10` | Il2Cpp: max functions per literal. |

Structured output: `items`, `offset`, `total`, `notEvaluated`, `totalExact`, `limit`, `hasMore`, `nextOffset`.

### search_constants

**Search numeric constants** (read-only, idempotent)

Find a number (magic, opcode id, flag, crypto constant) in IL literals, const and enum values, attribute arguments and static arrays (read as their element type).

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `value` | string | yes |  | Decimal, 0x hex, negative or floating-point. |
| `assembly` | string |  |  | Assembly id, name or path; omit for all loaded. |
| `limit` | integer |  | `100` |  |
| `maxTokens` | integer |  |  |  |
| `offset` | integer |  |  |  |

Structured output: `value`, `items`, `offset`, `total`, `limit`, `totalExact`, `hasMore`, `nextOffset`.

### search_il

**Search IL instruction patterns** (read-only, idempotent)

Find methods containing an IL instruction sequence: ;-separated opcode [operand] elements with * and ? wildcards (operands match names, strings, numbers); ... skips up to 16 instructions, e.g. "ldstr *password*; ...; call *::Hash*".

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `pattern` | string | yes |  | Instruction pattern. |
| `assembly` | string |  |  | Assembly id, name or path; omit for all loaded. |
| `limit` | integer |  | `100` |  |
| `maxTokens` | integer |  |  |  |
| `offset` | integer |  |  |  |
| `context` | integer |  | `8` | Instructions shown per match (1-24). |

Structured output: `items`, `offset`, `total`, `limit`, `totalExact`, `hasMore`, `nextOffset`.

### find_references

**Find usages (xrefs to)** (read-only, idempotent)

Every usage of a symbol across loaded assemblies: call sites of a method (also via base or interface methods), reads, writes and address uses of a field, every use of a type (bases, signatures, locals, casts, attributes). A native export: P/Invoke callers and native call sites.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `symbol` | string | yes |  | Type or member (Ns.Type::Method(int), short name, token) or native export (kernel32.dll!CreateFileW, native:<image>!<name\|#ord\|addr>). |
| `assembly` | string |  |  | Assembly defining the symbol, to disambiguate; all loaded are searched. |
| `kind` | string |  |  | Symbol kind; overrides: overrides and implementations of the method. Values: type, method, field, property, event, overrides. |
| `directOnly` | boolean |  |  | Methods: no calls through base / interface declarations. |
| `limit` | integer |  | `150` |  |
| `maxTokens` | integer |  |  |  |
| `offset` | integer |  |  |  |

Structured output: `target`, `items`, `offset`, `total`, `limit`, `totalExact`, `hasMore`, `nextOffset`.

### find_callees

**What a method uses (xrefs from)** (read-only, idempotent)

What a method uses: calls, field reads / writes, types instantiated or cast, strings, in IL order with offsets. P/Invoke calls show the native code they bind to; a P/Invoke or native export gives its native callees as call-tree rows.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `method` | string | yes |  | Type or member (Ns.Type::Method(int), short name, token) or native export (kernel32.dll!CreateFileW, native:<image>!<name\|#ord\|addr>). |
| `assembly` | string |  |  | Assembly id, name or path; omit for all loaded. |
| `distinct` | boolean |  |  | One row per target, with a count. |
| `offset` | integer |  |  |  |
| `limit` | integer |  | `200` |  |
| `maxTokens` | integer |  |  |  |

Structured output: `method`, `items`, `offset`, `total`, `limit`, `totalExact`, `hasMore`, `nextOffset`.

### get_call_tree

**Call tree (callers / callees)** (read-only, idempotent)

Multi-level callers or callees of a method across loaded assemblies, one row per node in tree order; calls via base / interface methods, repeats and recursion marked. Continues through P/Invokes and C++/CLI into loaded native code; takes a native export too.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `method` | string | yes |  | Type or member (Ns.Type::Method(int), short name, token) or native export (kernel32.dll!CreateFileW, native:<image>!<name\|#ord\|addr>). |
| `direction` | string |  | `callers` | callers or callees. Values: callers, callees. |
| `depth` | integer |  | `3` | Levels to expand (1-8). |
| `includeExternal` | boolean |  |  | Callees: also calls into assemblies not loaded (framework). |
| `assembly` | string |  |  | Assembly id, name or path; omit for all loaded. |
| `offset` | integer |  |  |  |
| `limit` | integer |  | `200` |  |
| `maxTokens` | integer |  |  |  |

Structured output: `root`, `direction`, `depth`, `items`, `offset`, `total`, `totalExact`, `limit`, `hasMore`, `nextOffset`.

### find_call_paths

**Call paths to a method** (read-only, idempotent)

How execution reaches a method: call chains from from=, or from entry points (methods nothing loaded calls), shortest first, direct calls preferred. A native to= follows native callers across loaded images and P/Invokes back to managed code.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `to` | string | yes |  | Type or member (Ns.Type::Method(int), short name, token) or native export (kernel32.dll!CreateFileW, native:<image>!<name\|#ord\|addr>). |
| `from` | string |  |  | Start method, same forms as to (native only when to is native). |
| `maxDepth` | integer |  | `8` | Max chain length (max 30). |
| `limit` | integer |  | `10` |  |
| `maxTokens` | integer |  |  |  |
| `offset` | integer |  |  |  |
| `directOnly` | boolean |  |  | No hops through virtual dispatch (native: RTTI virtual calls, pointers). |
| `assembly` | string |  |  | Assembly id, name or path; omit for all loaded. |

Structured output: `target`, `items`, `offset`, `total`, `from`, `totalExact`, `engine`, `limit`, `hasMore`, `nextOffset`.

### list_resources

**List manifest resources** (read-only, idempotent)

Manifest resources (embedded, .resources with entry counts, linked) with SHA-256 and file offsets; for a native image its Win32 resources as TYPE/NAME/LANGUAGE with file ranges (icon groups paired with icons, image headers decoded).

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `assembly` | string | yes |  | Assembly id, name or path. |
| `offset` | integer |  |  |  |
| `limit` | integer |  | `200` |  |
| `maxTokens` | integer |  |  |  |

Structured output: `assembly`, `items`, `offset`, `total`, `limit`, `totalExact`, `hasMore`, `nextOffset`.

### get_resource

**Read / extract resource** (destructive, idempotent)

Read a resource: text as text, binary as hex preview, .resources as an entry list (entry reads one; .baml as XAML); outputPath extracts the raw bytes. Native images: TYPE/NAME[/LANGUAGE], version info and string tables decoded.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `assembly` | string | yes |  | Assembly id, name or path. |
| `name` | string | yes |  | Name from list_resources. |
| `entry` | string |  |  | Entry inside a .resources container. |
| `outputPath` | string |  |  | Write the raw bytes to this file. |
| `overwrite` | boolean |  |  | Replace outputPath if it exists. |
| `offset` | integer |  |  |  |
| `maxTokens` | integer |  |  |  |

Structured output: `name`, `kind`, `code`, `offset`, `nextOffset`, `totalChars`, `savedTo`, `size`.

### export_project

**Export C# project** (destructive, idempotent, long-running)

Decompile an assembly into a C# project on disk (.cs per type, .csproj, resources) to browse with file tools; an .apk or .aab gives a Gradle project (manifest, resources, Java via JADX or smali). Written whole or not at all.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `assembly` | string | yes |  | Assembly id, name or path. |
| `outputDirectory` | string | yes |  | Empty or new output directory. |
| `overwrite` | boolean |  |  | Replace a previous export in outputDirectory. |

Structured output: `applied`, `source`, `outputDirectory`, `files`, `projectFile`, `failedTypes`, `replaced`, `notes`.

### get_r2r_code

**ReadyToRun native code of a method** (read-only, idempotent)

Precompiled native code of a method in a ReadyToRun assembly (shared framework too): entry, code ranges, fixup cells and x86 / x64 disassembly with cells named by their targets; generics per compiled instantiation, composite images included.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `method` | string | yes |  | Type or member: Ns.Type, Ns.Outer+Inner, Ns.Type::Method(int, string), short name or token (0x06000123). |
| `assembly` | string |  |  | Assembly id, name or path; omit for all loaded. |
| `instantiation` | string |  |  | Only bodies whose name contains this text (Int32, __Canon). |
| `maxBodies` | integer |  | `4` | Max bodies disassembled; the rest listed with addresses. |
| `maxInstructions` | integer |  | `1500` | Max instructions per body. |
| `offset` | integer |  |  |  |
| `maxTokens` | integer |  |  |  |

Structured output: `language`, `code`, `offset`, `nextOffset`, `totalChars`, `symbols`, `methods`, `bodies`.

### find_r2r_method

**Managed method at a ReadyToRun address** (read-only, idempotent)

Managed method whose ReadyToRun code holds a native address (from a dump, profiler or debugger): name, token, range, offset and instruction, or what an import cell resolves to. Addresses are in the file holding the code.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `assembly` | string | yes |  | Assembly id, name or path. |
| `address` | string | yes |  | A VA or RVA in the code image (rva:/va:/off: prefix). |

Structured output: `address`, `file`, `kind`, `begin`, `end`, `offset`, `methods`, `instruction`, `importCell`.

## containers

File inspection, containers and wrapped apps, Unity overview.

### summarize_file

**Summarize file** (read-only, idempotent)

First look at a file or loaded assembly (never executed): type, hashes, signature, containers, assemblies, highlights (toolchain, capability features, packaging tools), entry points. view=: managed, native, android, apple, electron, flutter, go, layers, nib, pcap, package (review before install), plist, protobuf, rust, script (layers peeled), sqlite (table= pages rows), sqlite-recover, all; views lists those that apply.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `path` | string |  |  | File (assembly, bundle, .nupkg, .apk, .ipa, zip, .asar, executable) or .app folder. |
| `assembly` | string |  |  | A loaded assembly; pass this or path. |
| `view` | string |  | `overview` | A view the overview lists. Values: overview, managed, android, apple, electron, firmware, flutter, go, hermes, installer, layers, lnk, native, nib, office, package, pcap, pdf, plist, protobuf, rust, script, sqlite, sqlite-recover, wasm, all. |
| `table` | string |  |  | sqlite, sqlite-recover: table to page. |
| `columns` | string[] |  |  | With table=: these columns (rowid too). |
| `offset` | integer |  |  |  |
| `limit` | integer |  |  |  |

Structured output: `path`, `size`, `type`, `sha256`, `container`, `view`, `views`, `md5`, `sha1`, `entropy`, `signature`, `assemblies`, `highlights`, `highlightTotal`, `entryPoints`, `values`, `detail`, `notes`.

### survey_features

**Survey features** (read-only, idempotent)

Rules over API calls, P/Invokes and strings (network, execution, registry, persistence, collection, system changes, code loading, cross-process, crypto); category= adds evidence. Native: imports, call arguments, strings, sections, RTTI. Apps: MASVS findings (WebView, TLS, pinning, root checks, code loading, weak crypto, keys) by method offset.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `assembly` | string |  |  | A loaded assembly; pass this or path. |
| `path` | string |  |  | A .NET, native or app file, read without loading. |
| `category` | string |  |  | Category or MASVS prefix: with evidence; all: everything. |
| `image` | string |  |  | A native image, loaded or a path (instead of assembly). |

Structured output: `assembly`, `methodsScanned`, `features`, `category`, `notes`.

### extract_strings

**Extract typed strings** (read-only, idempotent)

Typed values (URLs, domains, IPs, emails, file paths, pipes, registry keys, mutexes, user agents, crypto keys) from assembly literals, constants, resource text and decoded base64 / hex / compressed text, with count, locations and receiving APIs. read_result outputPath exports all (text: CSV).

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `assembly` | string |  |  | A loaded assembly; pass this or path. |
| `path` | string |  |  | A .NET assembly file to analyze without loading; pass this or assembly. |
| `types` | string[] |  |  | Only these types. |
| `offset` | integer |  |  |  |
| `limit` | integer |  | `100` |  |
| `maxTokens` | integer |  |  |  |

Structured output: `assembly`, `items`, `offset`, `total`, `byType`, `valuesResultId`, `notes`, `limit`, `totalExact`, `hasMore`, `nextOffset`.

### extract_embedded

**Extract embedded content** (edit, idempotent)

Embedded content of an assembly or of every assembly in a container (resources, byte arrays, long literals), decoded through hex, base64, compression and XOR until a PE, archive, ELF, Mach-O or text appears, plus high-entropy blobs, each with its encoding chain. save=true writes them (defanged names).

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `assembly` | string |  |  | A loaded assembly; pass this or path. |
| `path` | string |  |  | An assembly or container file, read without loading; pass this or assembly. |
| `save` | boolean |  |  | Write the items to disk. |
| `outputDirectory` | string |  |  | New or empty directory, or an earlier extraction of this file; default under temp. |
| `load` | boolean |  |  | Load the .NET assemblies found (implies save). |
| `xorText` | boolean |  |  | Also brute-force 1-16 byte XOR keys over unreadable data for text (slower). |
| `includeMedia` | boolean |  |  | Also list and save images (else counted). |
| `offset` | integer |  |  |  |
| `limit` | integer |  | `100` |  |
| `maxTokens` | integer |  |  |  |

Structured output: `assembly`, `items`, `offset`, `total`, `outputDirectory`, `notes`, `limit`, `totalExact`, `hasMore`, `nextOffset`.

### search_container

**Search inside a container** (read-only, idempotent)

Find types and members by name in every managed assembly inside a container (bundle, .nupkg, .apk, .aab, Costura, zip, nested) or an assembly, without extracting: substring or * / ? wildcards. kind=file: inner file paths; packet: a pcap display filter; endpoint: endpoints in code or a capture; request: capture requests; feature: JS text to native code.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `path` | string | yes |  | Container or assembly file (absolute). |
| `query` | string | yes |  | Name or part of a name. |
| `kind` | string |  |  | Restrict to this kind; omit for all members (events included). Values: type, method, field, property, dart, electron, endpoint, feature, file, hermes, packet, request. |
| `limit` | integer |  | `100` |  |
| `maxTokens` | integer |  |  |  |
| `offset` | integer |  |  |  |
| `capture` | string |  |  | kind=endpoint: a HAR, mitmproxy, .saz or pcap capture to join, or to compare when path is a capture. |
| `values` | boolean |  |  | kind=request: show header, cookie and query values. |

Structured output: `source`, `container`, `searched`, `items`, `offset`, `total`, `notes`, `limit`, `totalExact`, `hasMore`, `nextOffset`.

### unpack_container

**Extract container** (edit, idempotent, long-running)

Extract the .NET assemblies inside a container and load them: single-file bundles, Costura.Fody, .nupkg, Xamarin / MAUI .apk / .aab (per ABI), zips, embedded .NET images, nested containers; Electron .asar, Unity WebGL .data, HAR / mitmproxy captures: every file; pcap: HTTP objects and TCP streams; JS: modules and the original tree of the source map. Nothing runs; runnable extensions get .bin.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `path` | string | yes |  | Container file, Blazor or ClickOnce folder. |
| `outputDirectory` | string |  |  | New or empty directory, or an earlier extract of this file; default under temp. |
| `extractOnly` | boolean |  |  | Extract without loading the assemblies; default: loaded, ids in loadedAs. |
| `offset` | integer |  |  |  |
| `limit` | integer |  | `100` |  |
| `keyLog` | string |  |  | TLS key log of a pcap (SSLKEYLOGFILE) to decrypt with. |

Structured output: `source`, `container`, `outputDirectory`, `items`, `offset`, `total`, `next`, `notes`, `limit`, `totalExact`, `hasMore`, `nextOffset`.

### unity_overview

**Unity title overview** (read-only, idempotent, open-world)

Overview of a Unity title in seconds, without loading it: engine version per source, scripting backend (il2cpp / mono) with evidence, metadata version and state (readable, encrypted, header_tampered, unsupported_version, missing), toolchain, middleware, platform, architecture, folders, next calls.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `path` | string | yes |  | Game folder, executable, *_Data, GameAssembly, global-metadata.dat, .apk, .ipa, zip, WebGL, .app. |
| `detectItEasy` | boolean |  |  | Also run Detect It Easy (CORVUS_DIE or PATH) on the main binaries; about 1 s per file. |

Structured output: `input`, `gameDirectory`, `dataDirectory`, `executable`, `company`, `product`, `platform`, `architecture`, `architectureSource`, `engine`, `backend`, `markers`, `folders`, `nextSteps`, `notes`.

## edit

.NET edits, edit history and saving.

### rename_symbol

**Rename symbol** (destructive)

Rename a type, method, field, property (and accessors) or event in memory; other assemblies keep the old name.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `symbol` | string | yes |  | Type or member: Ns.Type, Ns.Outer+Inner, Ns.Type::Method(int, string), short name or token (0x06000123). |
| `newName` | string | yes |  | New name (a type: simple name without namespace). |
| `assembly` | string |  |  | Assembly id, name or path; omit for all loaded. |
| `kind` | string |  |  | Only resolve symbols of this kind. Values: type, method, field, property, event. |
| `dryRun` | boolean |  | `true` | true previews; false applies. |

Structured output: `applied`, `dryRun`, `changes`, `editIds`, `failed`, `digest`.

### rename_namespace

**Rename namespace** (destructive)

Move every type of a namespace (optionally its sub-namespaces) to a new namespace, in memory.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `assembly` | string | yes |  | Assembly id, name or path. |
| `oldNamespace` | string | yes |  | Existing namespace ("" for the global one). |
| `newNamespace` | string | yes |  | New namespace. |
| `includeSubNamespaces` | boolean |  |  | Also rewrite the namespaces under oldNamespace. |
| `dryRun` | boolean |  | `true` | true previews; false applies. |

Structured output: `applied`, `dryRun`, `changes`, `editIds`, `failed`, `digest`.

### stub_method

**Stub method (return constant)** (destructive)

Replace a method body with "return <value>;" ("return;" for void) in memory: force a check true, disable a call.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `method` | string | yes |  | Type or member: Ns.Type, Ns.Outer+Inner, Ns.Type::Method(int, string), short name or token (0x06000123). |
| `value` | string |  |  | true/false, integer (decimal or 0x), float, "string" or null; omit for void or default(T). |
| `assembly` | string |  |  | Assembly id, name or path; omit for all loaded. |
| `dryRun` | boolean |  | `true` | true previews; false applies. |

Structured output: `applied`, `dryRun`, `changes`, `editIds`, `failed`, `digest`.

### patch_method_csharp

**Replace method body with C#** (destructive, long-running)

Replace a method body (methods, constructors, accessors) with C# compiled against the assembly; private members accessible, lambdas, LINQ, async and yield work. Errors name lines of your code.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `method` | string | yes |  | Type or member: Ns.Type, Ns.Outer+Inner, Ns.Type::Method(int, string), short name or token (0x06000123). |
| `code` | string | yes |  | Statements of the new body only. |
| `assembly` | string |  |  | Assembly id, name or path; omit for all loaded. |
| `dryRun` | boolean |  | `true` | true previews the IL to be written; false applies. |

Structured output: `applied`, `dryRun`, `changes`, `editIds`, `failed`, `digest`.

### patch_method_il

**Rewrite method body in IL** (destructive)

Rewrite a method body from IL text (stack-validated): edit the get_il lines and pass them back (syntax: guide edits). replace swaps the body; prepend runs before it and can branch to its IL_xxxx labels.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `method` | string | yes |  | Type or member: Ns.Type, Ns.Outer+Inner, Ns.Type::Method(int, string), short name or token (0x06000123). |
| `il` | string | yes |  | IL instructions, one per line. |
| `mode` | string |  | `replace` | replace or prepend. Values: replace, prepend. |
| `assembly` | string |  |  | Assembly id, name or path; omit for all loaded. |
| `dryRun` | boolean |  | `true` | true previews; false applies. |

Structured output: `applied`, `dryRun`, `changes`, `editIds`, `failed`, `digest`.

### add_members_csharp

**Add members to a type (C#)** (edit, long-running)

Add C# members (methods, fields, properties, events, constructors, nested types) to a class or struct; private members accessible. No field or property initializers.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `type` | string | yes |  | Type or member: Ns.Type, Ns.Outer+Inner, Ns.Type::Method(int, string), short name or token (0x06000123). |
| `code` | string | yes |  | C# member declarations. |
| `assembly` | string |  |  | Assembly id, name or path; omit for all loaded. |
| `dryRun` | boolean |  | `true` | true previews; false applies. |

Structured output: `applied`, `dryRun`, `changes`, `editIds`, `failed`, `digest`.

### add_types_csharp

**Add new types (C#)** (edit, long-running)

Add C# types (with namespace) to an assembly; they see its internal types and patch_method_csharp can call them.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `assembly` | string | yes |  | Assembly id, name or path. |
| `code` | string | yes |  | C# source declaring the new types. |
| `dryRun` | boolean |  | `true` | true previews; false applies. |

Structured output: `applied`, `dryRun`, `changes`, `editIds`, `failed`, `digest`.

### simplify_methods

**Simplify method bodies** (destructive, long-running)

Clean transformed method bodies: fold (string decoders with constant inputs run in a safe IL interpreter), cfg (constant branches, dead code, flattened control flow), inline (forwarders, delegate call proxies). Bodies are stack-verified; what is left has a reason code (docs/simplify.md).

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `symbol` | string |  |  | Method or type (nested included): Ns.Type::M(int), short name or token; omit: whole assembly. |
| `assembly` | string |  |  | Assembly id, name or path; omit for all loaded. Required when symbol is omitted. |
| `passes` | string[] |  |  | Passes to run; omit for all three. |
| `maxDepth` | integer |  | `8` | Max evaluation call depth. |
| `budget` | integer |  | `100000` | Max IL instructions per evaluated call, nested calls included. |
| `dryRun` | boolean |  | `true` | true previews; false applies. |
| `deterministicEnvironment` | boolean |  |  | Fold machine reads (paths, environment, names) against fixed stand-ins. |

Structured output: `applied`, `dryRun`, `changes`, `editIds`, `failed`, `digest`.

### list_edits

**List unsaved edits** (read-only, idempotent)

Unsaved edits of an assembly in order; each number (editId <assembly>#<n>) stays when other edits are undone.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `assembly` | string | yes |  | Assembly id, name or path. |
| `offset` | integer |  |  |  |
| `limit` | integer |  | `200` |  |
| `maxTokens` | integer |  |  |  |

Structured output: `assembly`, `items`, `offset`, `total`, `limit`, `totalExact`, `hasMore`, `nextOffset`.

### diff_edits

**Diff edits (before/after C#)** (read-only, idempotent)

Unified diff of the decompiled C# of each member the edits (or one edit) touched, before and after; review before save_assembly.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `assembly` | string | yes |  | Assembly id, name or path. |
| `number` | integer |  |  | Only this edit (list_edits number). |
| `offset` | integer |  |  |  |
| `maxTokens` | integer |  |  |  |

Structured output: `code`, `offset`, `nextOffset`, `totalChars`.

### undo_edit

**Undo an edit** (destructive, long-running)

Undo the last edit or one by number: the others are replayed on the original image; a conflict changes nothing.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `assembly` | string | yes |  | Assembly id, name or path. |
| `number` | integer |  |  | Edit number from list_edits (#n of its editId); omit for the last. |

Structured output: `applied`, `dryRun`, `changes`, `editIds`, `failed`, `digest`.

### revert_edits

**Discard all edits** (destructive, idempotent)

Discard every unsaved edit of an assembly; resultId keeps them as a script (read_result outputPath=, then apply_edits).

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `assembly` | string | yes |  | Assembly id, name or path. |

Structured output: `applied`, `dryRun`, `changes`, `editIds`, `failed`, `digest`.

### export_edits

**Export edits as a script** (destructive, idempotent)

Save an assembly's edits as a JSON script bound to its build (SHA-256, MVID) for apply_edits.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `assembly` | string | yes |  | Assembly id, name or path. |
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
| `dryRun` | boolean |  | `true` | true: apply every edit, report, roll back; false keeps them. |
| `continueOnError` | boolean |  |  | Apply the edits that succeed; default: roll all back on the first failure. |
| `targetBuild` | string |  | `same` | same: the script build only; other: another build, symbols by name. Values: same, other. |

Structured output: `applied`, `dryRun`, `changes`, `editIds`, `failed`, `items`, `pushedTo`, `digest`.

### save_assembly

**Save patched assembly** (destructive, idempotent)

Write an assembly with its edits to a new file, atomically (replaceOriginal=true keeps a .bak; a file changed since load is refused). Untouched bodies keep their bytes; members the writer changed are listed with reason codes (docs/saving.md).

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `assembly` | string | yes |  | Assembly id, name or path. |
| `outputPath` | string |  |  | Output path (.wasm writes Webcil for Blazor); default <original>.patched.dll. |
| `overwrite` | boolean |  |  | Replace an existing file, not the original. |
| `strict` | boolean |  |  | Write nothing if the writer would change any member (default: save, list them). |
| `replaceOriginal` | boolean |  |  | Replace the loaded file (needs --allow-replace-original). |
| `versioned` | boolean |  |  | Write <name>.N.dll, the first free N. |

Structured output: `outputPath`, `bytes`, `sha256`, `edits`, `backup`, `editList`.

## il2cpp

Il2Cpp metadata, addresses, symbols and bindings.

### get_il2cpp_info

**Il2Cpp addresses and offsets** (read-only, idempotent)

Native addresses (RVA, VA, file offset, vtable slot) of an Il2Cpp method or all methods of a type, field offsets and tokens. With script.json: function bounds, methods sharing the code, MethodInfo slot, generic instantiations, metadata slots. With stringliteral.json and the binary: literals a method loads.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `symbol` | string | yes |  | Type or member (Ns.Type::M(int), short name, token) or script.json name (List`1<int>::Add). |
| `assembly` | string |  |  | Assembly id, name or path; omit for all loaded. |
| `slot` | string |  |  | With a type: a vtable slot number to resolve to its method, or all. |
| `offset` | integer |  |  | First entry of each long list. |
| `limit` | integer |  | `20` | Max entries of each long list. |

Structured output: `symbol`, `members`, `items`, `offset`, `total`, `limit`, `totalExact`, `hasMore`, `nextOffset`.

### find_method_by_address

**Native address to method** (read-only, idempotent)

Map a native address (IDA, Ghidra, crash log) of an Il2Cpp game to the method(s) whose function contains it, or the string literal, type metadata or MethodInfo slot at it; script.json names generic instantiations (without it, a guess).

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `address` | string | yes |  | Hex as IDA / Ghidra show it (0x1A2B3C, 1A2B3Ch, 00000001`8001A2B3); d: prefix for decimal. |
| `kind` | string |  | `auto` | auto: a VA at or above the image base, else an RVA, else a file offset. Values: auto, rva, va, offset. |
| `assembly` | string |  |  | Assembly id, name or path; omit for all loaded. |
| `offset` | integer |  |  |  |
| `limit` | integer |  | `20` | Max methods listed. |
| `maxTokens` | integer |  |  |  |

Structured output: `address`, `items`, `offset`, `total`, `limit`, `totalExact`, `hasMore`, `nextOffset`.

### export_il2cpp_symbols

**Export IDA/Ghidra scripts** (destructive, idempotent, long-running)

Export Il2Cpp dummy-DLL metadata for native analysis: IDA Python and Ghidra scripts that create, name (Ns.Type$$Method) and comment every function (by RVA), a C header of struct layouts, and an Il2CppDumper-style script.json.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `outputDirectory` | string | yes |  | Output directory. |
| `formats` | string |  | `all` | Comma-separated: ida, ghidra, header, json or all. |
| `baseName` | string |  | `il2cpp` | Base name of the generated files. |
| `assembly` | string |  |  | Assembly id, name or path; omit for all loaded. |
| `overwrite` | boolean |  |  | Replace same-named files. |

Structured output: `functions`, `structs`, `files`.

### generate_cpp_binding

**Generate C++ binding** (read-only, idempotent)

C++ binding code for a managed type of a Mono or Il2Cpp app: a struct resolving the class, field offsets, static fields and methods once, with typed accessors, property getters and invoke wrappers. style: mono (embedding API), il2cpp (runtime exports) or hostapi (a host function table); default: detected, else mono.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `type` | string | yes |  | Type or member: Ns.Type, Ns.Outer+Inner, Ns.Type::Method(int, string), short name or token (0x06000123). |
| `assembly` | string |  |  | Assembly id, name or path; omit for all loaded. |
| `members` | string |  |  | Comma-separated member names; default all but compiler-generated. |
| `includeInherited` | boolean |  |  | Also bind inherited property getters. |
| `style` | string |  |  | Omit to detect it. Values: mono, il2cpp, hostapi. |
| `projectDir` | string |  |  | C/C++ project of the header, scanned for a host function table and helpers. |
| `headerPath` | string |  |  | Header path (absolute or under projectDir; default projectDir); #include base. |
| `offset` | integer |  |  |  |
| `maxTokens` | integer |  |  |  |

Structured output: `code`, `offset`, `nextOffset`, `totalChars`.

### apply_il2cpp_names

**Name a native Il2Cpp binary from its metadata** (destructive, idempotent, long-running)

Name the functions and data of a native Il2Cpp binary (GameAssembly, libil2cpp.so) from the loaded dummy assemblies, script.json and stringliteral.json: Ns_Type__Method (duplicates get _<RVA>), commented with Ns.Type::Method(args) and methods sharing the code; below user and PDB names. Saved per file hash, reapplied on load.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `image` | string | yes |  | Image id, name or path. |
| `assembly` | string |  |  | Dummy assemblies to use; omit for every loaded one with Il2Cpp metadata. |
| `clear` | boolean |  |  | Remove the il2cpp names and saved copy instead. |

Structured output: `image`, `applied`, `assemblies`, `functions`, `labels`, `sharedFunctions`, `strings`, `metadataSlots`, `methodInfoSlots`, `userNamesKept`, `suffixed`, `misses`, `saved`, `removed`, `notes`.

## native

Native PE analysis, symbols and decompilation.

### get_pe_info

**Native image overview** (read-only, idempotent)

Overview of a native image: headers, sections, packaging tools, mitigations, import and export counts, TLS, PDB, load config, version, manifest, rich header, overlay, signature, anomalies; ELF soname, build id, hardening; Mach-O slices, libraries, entitlements; Go build info; implied capabilities. view=code: code index statistics, late-bound imports.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `image` | string | yes |  | Image id, name or path. |
| `offset` | integer |  |  |  |
| `maxTokens` | integer |  |  |  |
| `view` | string |  |  | code waits for the code index. Values: summary, code. |

Structured output: `image`, `path`, `machine`, `kind`, `format`, `subsystem`, `fileSize`, `sha256`, `imageBase`, `entryPoint`, `timestamp`, `dotNet`, `mitigationsOn`, `mitigationsOff`, `sections`, `importModules`, `importFunctions`, `delayImportModules`, `exports`, `tlsCallbacks`, `pdbPath`, `pdbGuid`, `pdbAge`, `signer`, `checksumMatches`, `overlaySize`, `issues`, `capabilities`, `code`.

### list_imports

**List native imports** (read-only, idempotent, long-running)

Imports of a native image per library (delay-load, lazy binding marked), with the IAT slot code calls through; API sets show their DLL. bind=true: the export each binds to (at VA [image] when loaded, else its path; load_assembly loadProviders=true loads them) or why not.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `image` | string | yes |  | Image id, name or path. |
| `library` | string |  |  | Only this library (.dll optional). |
| `filter` | string |  |  | Name substring (case-insensitive). |
| `bind` | boolean |  |  | Bind each import to the export it reaches, with a summary. |
| `offset` | integer |  |  |  |
| `limit` | integer |  | `200` |  |
| `includeDynamic` | boolean |  |  | Also GetProcAddress imports, marked [dynamic] (waits for the code index). |
| `maxTokens` | integer |  |  |  |

Structured output: `image`, `items`, `offset`, `total`, `bindings`, `limit`, `totalExact`, `hasMore`, `nextOffset`.

### list_exports

**List native exports** (read-only, idempotent)

Exported functions and data of a native image: ordinal, VA, name (demangled C++ form, ELF symbol version), forwarders and re-exports.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `image` | string | yes |  | Image id, name or path. |
| `filter` | string |  |  | Name substring (case-insensitive; demangled form too). |
| `offset` | integer |  |  |  |
| `limit` | integer |  | `300` |  |
| `maxTokens` | integer |  |  |  |

Structured output: `image`, `items`, `offset`, `total`, `limit`, `totalExact`, `hasMore`, `nextOffset`.

### resolve_address

**Resolve native address** (read-only, idempotent)

What a native address is: RVA, VA, file offset, section, nearest export or import, name, source; Il2Cpp method or metadata slot; NativeAOT MethodTable, object or method; IAT slot export, export importers. Code index: function and offset, instruction or data, comment, references. PDB global: the field. DWARF: source line, inlined calls.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `image` | string | yes |  | Image id, name or path. |
| `address` | string |  |  | Hex VA or RVA (rva:/va:/off: prefix), export, module!import or function. |
| `addresses` | string[] |  |  | Instead of address: up to 100 addresses. |

Structured output: `image`, `rva`, `va`, `fileOffset`, `section`, `access`, `name`, `nameSource`, `import`, `boundTo`, `export`, `function`, `status`, `containingInstruction`, `dataItem`, `comment`, `referencesTo`, `source`, `inlined`, `results`, `failed`.

### search_bytes

**Search native bytes** (read-only, idempotent)

Find a byte pattern in the mapped sections of a native image (hex, or text as ASCII and UTF-16): VA, section and file offset per hit; memory=engine searches the engine's loaded bytes.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `image` | string | yes |  | Image id, name or path. |
| `pattern` | string |  |  | Hex (48 8B 05 ?? ?? ?? ??): ?? any byte, 4? a nibble, 40&F8 masked bits. |
| `text` | boolean |  |  | pattern is text (ASCII and UTF-16LE). |
| `section` | string |  |  | Only this section, e.g. .text. |
| `limit` | integer |  | `200` | Max hits. |
| `offset` | integer |  |  |  |
| `patterns` | string[] |  |  | Instead of pattern: up to 50. |
| `mask` | string |  |  | Bit mask per pattern byte (FF F0 FF). |
| `memory` | string |  | `file` | file, or engine / ida / ghidra: its loaded bytes. |
| `maxTokens` | integer |  |  |  |

Structured output: `image`, `items`, `offset`, `total`, `patterns`, `failed`, `memory`, `limit`, `totalExact`, `hasMore`, `nextOffset`.

### read_bytes

**Read native bytes or values** (read-only, idempotent)

Hex dump (with ASCII) of native image bytes at an address, as the loader maps them (.bss as ??). type= reads length values instead: u8-u64, i8-i64 (be suffix: u32be), f32, f64, ptr (target named), C names (int, DWORD, char *), cstr or wstr. Structs: get_native_type read=true.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `image` | string | yes |  | Image id, name or path. |
| `address` | string | yes |  | Hex VA or RVA (rva:/va:/off: prefix), export, module!import or function. |
| `length` | integer |  |  | Bytes (default 256, max 65536); with type: values (default 1, max 4096). |
| `offset` | integer |  |  | Bytes from address (a page's nextOffset). |
| `maxTokens` | integer |  |  |  |
| `type` | string |  |  | Value type to read instead of a dump. |

Structured output: `image`, `address`, `length`, `code`, `nextOffset`, `nextAddress`, `totalBytes`, `offset`, `totalChars`.

### convert_number

**Convert a number** (read-only, idempotent)

Exact number conversions: signed and unsigned decimal, hex, binary, octal at a width, LE and BE bytes and their ASCII, the bits as float or double. Input: decimal, 0x or h-suffixed hex, 0b, 0o, negative, _ separators, C suffixes, 'ABCD' (C multi-character constant) or "text" (bytes in memory order).

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `numbers` | string[] | yes |  | Numbers to convert. |
| `size` | integer |  |  | Width in bytes: 1, 2, 4 or 8 (default: smallest that fits). |

Structured output: `items`.

### list_functions

**List native functions** (read-only, idempotent, open-world, long-running)

Functions of a native image (x86, x64, ARM): address, size, name (user, PDB, Il2Cpp, export, module!import thunk or sub_<rva>), flags (thunk, arm (A32), noreturn, unresolved jumps, invalid code, funclets, exception chunks), how found, caller count; an exact name filter adds the engine's function record.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `image` | string | yes |  | Image id, name or path. |
| `filter` | string |  |  | Name filter: substring (case-insensitive), * ? glob, or /regex/ (flags i, m, s). |
| `sort` | string |  |  | Default address; size and callers: largest first. Values: address, name, size, callers. |
| `offset` | integer |  |  |  |
| `limit` | integer |  | `150` |  |
| `engine` | string |  |  | auto (default): IDA or Ghidra if it analyzed these bytes, else ours. Values: auto, ours, ida, ghidra. |
| `minSize` | integer |  |  | Smallest size in bytes. |
| `maxSize` | integer |  |  | Largest size in bytes. |
| `from` | string |  |  | Lowest start address. |
| `to` | string |  |  | Start addresses below this one. |
| `hasType` | boolean |  |  | Engines: true keeps functions with a prototype, false those without. |
| `descending` | boolean |  |  | Reverse the default direction of sort. |
| `view` | string |  |  | candidates: engine code in no function, by references. Values: functions, candidates. |
| `maxTokens` | integer |  |  |  |

Structured output: `image`, `functions`, `items`, `offset`, `total`, `engine`, `engineNote`, `limit`, `totalExact`, `hasMore`, `nextOffset`.

### list_globals

**List native globals** (read-only, idempotent, open-world, long-running)

Named data of a native image outside code, from every name source (PDB with type and size, user names and types, Il2Cpp, NativeAOT, exports, symbol tables); an engine adds its defined data with type and value. get_native_type read=true reads fields.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `image` | string | yes |  | Image id, name or path. |
| `filter` | string |  |  | Name substring (case-insensitive). |
| `section` | string |  |  | Only this section, e.g. .data. |
| `offset` | integer |  |  |  |
| `limit` | integer |  | `200` |  |
| `engine` | string |  |  | auto (default): IDA or Ghidra if it analyzed these bytes, else ours. Values: auto, ours, ida, ghidra. |
| `maxTokens` | integer |  |  |  |

Structured output: `image`, `items`, `offset`, `total`, `engine`, `limit`, `totalExact`, `hasMore`, `nextOffset`.

### disassemble

**Disassemble native code** (read-only, idempotent, open-world, long-running)

MASM-syntax disassembly of the native function containing an address (block labels), or of maxInstructions from the address when in no function or fromAddress=true. References named, strings as comments, calls with recovered arguments; data in the way (strings, pointers, IAT slots, switch tables) shown as data.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `image` | string | yes |  | Image id, name or path. |
| `address` | string | yes |  | Hex VA or RVA (rva:/va:/off: prefix), export, module!import or function. |
| `fromAddress` | boolean |  |  | maxInstructions from the address, not the containing function. |
| `maxInstructions` | integer |  | `2000` | Max instructions. |
| `offset` | integer |  |  |  |
| `maxTokens` | integer |  |  |  |
| `engine` | string |  |  | auto (default): IDA or Ghidra if it analyzed these bytes, else ours. Values: auto, ours, ida, ghidra. |

Structured output: `code`, `offset`, `nextOffset`, `totalChars`, `image`, `function`, `address`, `engine`.

### inspect_instruction

**Inspect native instructions** (read-only, idempotent, open-world, long-running)

What is at an address of a native image, instruction by instruction (decoded, mid_instruction, data...): bytes, prefixes, encoding; operands (kind, size, access, registers, memory parts); registers and flags read and written; memory accesses; stack change; flow; references; call arguments; switch table. Up to 64 per walk.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `image` | string | yes |  | Image id, name or path. |
| `address` | string | yes |  | Hex VA or RVA (rva:/va:/off: prefix), export, module!import or function. |
| `limit` | integer |  | `1` | Positions (1-64). |
| `offset` | integer |  |  |  |
| `maxTokens` | integer |  |  |  |
| `engine` | string |  |  | auto (default): IDA or Ghidra if it analyzed these bytes, else ours. Values: auto, ours, ida, ghidra. |

Structured output: `image`, `engine`, `engineNote`, `items`, `notes`, `offset`, `total`, `limit`, `totalExact`, `hasMore`, `nextOffset`.

### search_instructions

**Search native instructions** (read-only, idempotent, open-world, long-running)

Find instructions by mnemonic, operand or whole-line regex (case-insensitive) and an operand value (immediate, displacement or target) in every function, one function or an address range; a page the scan budget stopped goes on at nextOffset.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `image` | string | yes |  | Image id, name or path. |
| `mnemonic` | string |  |  | Mnemonic regex, e.g. ^(call\|jmp)$ |
| `operands` | string |  |  | Operand text regex, e.g. rsp\+\|fs: |
| `text` | string |  |  | Regex over the whole instruction text. |
| `value` | string |  |  | Operand value: 0x10B, 267, an address, or range 0x100..0x1FF. |
| `function` | string |  |  | Only this function: Hex VA or RVA (rva:/va:/off: prefix), export, module!import or function. |
| `from` | string |  |  | Range start (with to, or alone: to the end of its section). |
| `to` | string |  |  | Range end (exclusive). |
| `offset` | integer |  |  |  |
| `limit` | integer |  | `100` | Max matches (max 2000). |
| `maxInstructions` | integer |  | `500000` | Instructions scanned per page (max 5000000). |
| `engine` | string |  |  | auto (default): IDA or Ghidra if it analyzed these bytes, else ours. Values: auto, ours, ida, ghidra. |
| `maxTokens` | integer |  |  |  |

Structured output: `image`, `items`, `offset`, `total`, `scanned`, `engine`, `engineNote`, `totalExact`, `limit`, `hasMore`, `nextOffset`.

### get_cfg

**Native control-flow graph** (read-only, idempotent, open-world, long-running)

Basic blocks of the native function containing an address, paged: range, instruction count, how each ends and its successors; switch tables with values per target; unresolved indirect jumps with the reason.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `image` | string | yes |  | Image id, name or path. |
| `address` | string | yes |  | Hex VA or RVA (rva:/va:/off: prefix), export, module!import or function. |
| `offset` | integer |  |  |  |
| `limit` | integer |  | `150` | Blocks per page. |
| `maxTokens` | integer |  |  |  |
| `engine` | string |  |  | auto (default): IDA or Ghidra if it analyzed these bytes, else ours. Values: auto, ours, ida, ghidra. |

Structured output: `image`, `function`, `address`, `engine`, `items`, `offset`, `total`, `switches`, `unresolvedJumps`, `tailCalls`, `cut`, `summary`, `limit`, `totalExact`, `hasMore`, `nextOffset`.

### find_xrefs

**Native cross-references** (read-only, idempotent, open-world, long-running)

What references a native address: calls (also via import slots, thunks), jumps, reads/writes, address uses, switch tables, relocations, RTTI virtual calls; each with its function and call arguments. Imports: call sites, binding; exports: other loaded images too. direction=from: what it references. Struct members: engine pseudocode uses.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `image` | string | yes |  | Image id, name or path. |
| `address` | string |  |  | Hex VA or RVA (rva:/va:/off: prefix), export, module!import or function. Or Type::member, Type.member, Type+0xOFFSET. |
| `offset` | integer |  |  |  |
| `limit` | integer |  | `200` |  |
| `addresses` | string[] |  |  | Instead of address: up to 100. |
| `engine` | string |  |  | auto (default): IDA or Ghidra if it analyzed these bytes, else ours. Adds RTTI virtual calls. Values: auto, ours, ida, ghidra. |
| `direction` | string |  |  | Default to. Values: to, from, both. |
| `kind` | string |  |  | any, code (calls, jumps), data (reads, writes, pointers), metadata (.pdata, CFG, exports). Values: any, code, data, metadata. |
| `scope` | string |  |  | Struct member: typed (default) or all (every function; call again to go on). Values: typed, all. |
| `maxTokens` | integer |  |  |  |

Structured output: `image`, `target`, `items`, `offset`, `total`, `boundTo`, `engine`, `engineNote`, `targets`, `failed`, `limit`, `totalExact`, `hasMore`, `nextOffset`.

### native_call_tree

**Native call tree** (read-only, idempotent, open-world, long-running)

Callers or callees of a native function, several levels deep, through thunks and import slots, as nodes paged in tree order; module!import gives its callers. Crosses loaded images. Callees include GetProcAddress pointers ([dynamic]) and RTTI virtual targets ([virtual], [virtual?: one of n]). Repeats not expanded.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `image` | string | yes |  | Image id, name or path. |
| `function` | string | yes |  | Hex VA or RVA (rva:/va:/off: prefix), export, module!import or function. |
| `direction` | string |  | `callees` | both: depth 1, by call site. Values: callers, callees, both. |
| `depth` | integer |  | `3` | Levels (1-8). |
| `maxNodes` | integer |  | `250` | Max nodes in the tree. |
| `offset` | integer |  |  |  |
| `limit` | integer |  | `200` | Max nodes per page. |
| `calls` | string |  |  | Call edges (default all). Values: all, direct, virtual. |
| `engine` | string |  |  | auto (default): IDA or Ghidra if it analyzed these bytes, else ours. Values: auto, ours, ida, ghidra. |
| `maxTokens` | integer |  |  |  |

Structured output: `image`, `root`, `direction`, `items`, `offset`, `total`, `frontier`, `engine`, `engineNote`, `limit`, `totalExact`, `hasMore`, `nextOffset`.

### find_virtual_calls

**Native virtual calls** (read-only, idempotent, open-world, long-running)

Virtual call sites resolved through RTTI (MSVC, Itanium) or NativeAOT MethodTables: calls through a vftable slot, also via stack spills, this adjustments, CFG dispatch. Receiver class from a stored vftable, the this of a virtual method or decorated names; targets: the slot implementations (exact, possible, else unresolved).

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `image` | string | yes |  | Image id, name or path. |
| `function` | string |  |  | Only sites in this function: Hex VA or RVA (rva:/va:/off: prefix), export, module!import or function. |
| `status` | string |  |  | Only sites with this status. Values: exact, possible, unresolved. |
| `offset` | integer |  |  |  |
| `limit` | integer |  | `100` | Max sites (max 1000). |
| `crossCheck` | boolean |  |  | Compare a sample with IDA (else Ghidra); minutes on a large image at first. |
| `sampleFunctions` | integer |  | `100` | Cross-check: functions to sample. |
| `timeoutSeconds` | integer |  | `300` | Cross-check: time budget in seconds. |
| `maxTokens` | integer |  |  |  |

Structured output: `image`, `sites`, `exact`, `possible`, `unresolved`, `edges`, `directEdges`, `rttiClasses`, `total`, `offset`, `items`, `crossCheck`, `notes`, `limit`, `totalExact`, `hasMore`, `nextOffset`.

### search_native_strings

**Search native strings** (read-only, idempotent, open-world, long-running)

Strings (ASCII, UTF-16) referenced by the code or data of a native image, with address, reference count and first referencing function. Also Il2Cpp literals (after apply_il2cpp_names) and NativeAOT frozen strings; an engine adds unreferenced strings in other encodings.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `image` | string | yes |  | Image id, name or path. |
| `query` | string |  |  | Case-insensitive substring, or regex with regex=true; omit for all. |
| `regex` | boolean |  |  | query is a regex. |
| `offset` | integer |  |  |  |
| `limit` | integer |  | `100` |  |
| `engine` | string |  |  | auto (default): IDA or Ghidra if it analyzed these bytes, else ours. Values: auto, ours, ida, ghidra. |
| `maxLength` | integer |  | `200` | Characters per string (max 4000); longer ones are clipped. |
| `maxTokens` | integer |  |  |  |

Structured output: `image`, `items`, `offset`, `total`, `notEvaluated`, `limit`, `totalExact`, `hasMore`, `nextOffset`.

### get_call_arguments

**Native call arguments** (read-only, idempotent, long-running)

Call sites (x86, x64, ARM) with argument values, by constant propagation under the calling convention: immediates, strings, named addresses, earlier call results, globals (differing merges are unknown). Known Win32, CRT and libc APIs name parameters and decode constants. Pass address and/or callee.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `image` | string | yes |  | Image id, name or path. |
| `address` | string |  |  | A call, or an address in a function (all its calls): Hex VA or RVA (rva:/va:/off: prefix), export, module!import or function. |
| `callee` | string |  |  | Only calls to this API, module!name or function; without address, image-wide. |
| `offset` | integer |  |  |  |
| `limit` | integer |  | `50` | Max call sites (max 1000). |
| `maxTokens` | integer |  |  |  |

Structured output: `image`, `scope`, `items`, `offset`, `total`, `notes`, `limit`, `totalExact`, `hasMore`, `nextOffset`.

### trace_native_values

**Native value trace** (read-only, idempotent, open-world, long-running)

Trace a value through native code (x86, x64, ARM) across functions and images. Backward: constants, strings, function pointers, API results, via copies, stack, merges, loops; parameters bind to caller arguments, results to returns, globals to writers. Forward: API and callee arguments, global readers, returns, compares, switches, dereferences.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `image` | string | yes |  | Image id, name or path. |
| `address` | string | yes |  | An instruction, call, function start (with argument) or writable global: Hex VA or RVA (rva:/va:/off: prefix), export, module!import or function. |
| `location` | string |  |  | The value at address: a register (rdx, xmm1, x1, w2, r1), a stack slot ([rsp+28h], [ebp-8], [x29-8]), op1 / op2 (an operand) or result (the call return). |
| `argument` | string |  |  | Argument of the call or parameter of the function at address: 1-based or API name. |
| `direction` | string |  |  | backward (default: the values that reach it), forward (its uses) or both. Values: backward, forward, both. |
| `maxDepth` | integer |  | `3` | Function boundaries to cross (0-8). |
| `maxFunctions` | integer |  | `32` | Functions to slice (1-256). |
| `maxNodes` | integer |  | `500` | Nodes in the graph (1-5000). |
| `maxCallers` | integer |  | `16` | Call sites bound per parameter or return (1-256). |
| `maxWriters` | integer |  | `16` | Writers (backward) or readers (forward) per global (1-256). |
| `stopAtGlobals` | boolean |  |  | Stop at writable globals instead of following writers / readers. |
| `offset` | integer |  |  |  |
| `limit` | integer |  | `200` | Nodes per page (max 1000). |
| `engine` | string |  |  | ida or ghidra: its IR (ours where it cannot place the seed); ours; auto (default): an analyzing engine, else ours. Values: auto, ours, ida, ghidra. |
| `maxTokens` | integer |  |  |  |

Structured output: `image`, `engine`, `seed`, `direction`, `values`, `nodes`, `edges`, `frontier`, `totalNodes`, `totalEdges`, `functions`, `offset`, `truncated`, `notes`.

### resolve_call_targets

**Native call targets** (read-only, idempotent, open-world, long-running)

Targets of call and tail-jump sites (x86, x64, ARM) with basis and confidence: branches, import and GOT slots, thunks, constant pointers, CFG dispatch, GetProcAddress, RTTI virtual calls, NativeAOT dispatch cells, global writers, pointer tables. Unresolved: reason, trace_native_values call. engine= merges its targets.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `image` | string | yes |  | Image id, name or path. |
| `address` | string |  |  | A call, or an address in a function (its sites): Hex VA or RVA (rva:/va:/off: prefix), export, module!import or function. |
| `scope` | string |  |  | image: all indirect sites. Default: site at a call, else function. Values: site, function, image. |
| `status` | string |  |  | Default all; indirect: all but direct branches. Values: all, resolved, possible, ambiguous, unresolved, indirect. |
| `deep` | boolean |  |  | Trace pointers passed as parameters back into the callers (slower). |
| `engine` | string |  |  | auto (default): IDA or Ghidra if it analyzed these bytes, else ours. Values: auto, ours, ida, ghidra. |
| `offset` | integer |  |  |  |
| `limit` | integer |  | `75` | Max sites (max 1000). |
| `timeoutSeconds` | integer |  |  | Seconds per engine request (default CORVUS_ENGINE_REQUEST_TIMEOUT); scans then answer partial. |
| `maxTokens` | integer |  |  |  |

Structured output: `image`, `scope`, `engine`, `engineNote`, `total`, `byStatus`, `byMechanism`, `topUnresolved`, `offset`, `items`, `notes`, `limit`, `totalExact`, `hasMore`, `nextOffset`.

### analyze_native_function

**Native function dossier** (read-only, idempotent, open-world, long-running)

Everything known about one native function, in sections of at most maxItems facts: identity, signature (parameters, this class, result use), frame (unwind, locals, EH), callers, callees (targets, arguments), data (strings, globals, imports), flow (blocks, loops, switches), annotations; optional constants, params, pseudocode.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `image` | string | yes |  | Image id, name or path. |
| `address` | string | yes |  | In the function; up to 16 comma-separated (a dossier each): Hex VA or RVA (rva:/va:/off: prefix), export, module!import or function. |
| `sections` | string |  |  | Comma-separated sections (default all but constants, params, pseudocode). |
| `maxItems` | integer |  | `40` | Facts per section (1-500). |
| `pseudocode` | boolean |  |  | Add the pseudocode section. |
| `component` | boolean |  |  | Several addresses: one component view (internal calls, shared data, interface). |
| `engine` | string |  |  | Pseudocode engine (default auto). Values: auto, ida, ghidra. |
| `offset` | integer |  |  |  |
| `maxTokens` | integer |  |  |  |

Structured output: `image`, `address`, `name`, `size`, `end`, `sections`, `next`, `batch`, `component`.

### trace_native_feature

**Trace a native feature** (read-only, idempotent, open-world, long-running)

Native code behind a behaviour: strings, names, imports (also late-bound), exports, RTTI classes and constants matching query ("quoted": exact) lead to their references, ranked by function; hubs: callers within callerDepth reaching several. An engine adds strings, references, pseudocode.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `image` | string | yes |  | Image id, name or path. |
| `query` | string | yes |  | Case-insensitive substring, or regex with regex=true. |
| `regex` | boolean |  |  | query is a regex. |
| `kinds` | string |  |  | Comma-separated: strings, names, imports, exports, classes, constants (default all). |
| `maxSeeds` | integer |  | `50` | Matches followed (1-500); the rest are counted. |
| `callerDepth` | integer |  | `1` | Caller levels searched for hubs (0-3). |
| `offset` | integer |  |  |  |
| `limit` | integer |  | `50` | Functions per page (max 500). |
| `maxTokens` | integer |  |  |  |
| `engine` | string |  |  | auto (default): IDA or Ghidra if it analyzed these bytes, else ours. Values: auto, ours, ida, ghidra. |

Structured output: `image`, `query`, `seeds`, `totalSeeds`, `functions`, `totalFunctions`, `offset`, `nextOffset`, `hubs`, `notes`.

### find_similar_functions

**Find similar functions** (read-only, idempotent, long-running)

Functions like a given one, ranked by score with evidence: instruction-shape similarity (registers, addresses, constants ignored), containment, CFG shape, shared strings, constants, imports, callees. scope=all: every loaded image of the architecture. view=duplicates: same-shape groups; clusters: near-duplicates image-wide.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `image` | string | yes |  | Image id, name or path. |
| `address` | string |  |  | view=similar: an address in the function. |
| `view` | string |  |  | similar (default with address), duplicates or clusters (default without). Values: similar, duplicates, clusters. |
| `scope` | string |  |  | image (default) or all (view=similar). Values: image, all. |
| `minScore` | number |  |  | Least score 0-1 (default 0.5; clusters 0.8). |
| `minInstructions` | integer |  | `5` | Smallest function compared, in instructions (1-1000). |
| `offset` | integer |  |  |  |
| `limit` | integer |  | `20` | Items to return (max 500). |
| `maxTokens` | integer |  |  |  |

Structured output: `image`, `view`, `function`, `address`, `compared`, `offset`, `total`, `items`, `notes`, `limit`, `totalExact`, `hasMore`, `nextOffset`.

### get_exception_info

**Native exception handling** (read-only, idempotent, long-running)

Exception handling of the native function at an address. ELF, Mach-O: FDE, compact unwind or EHABI entry, personality, LSDA call sites, landing pads, caught types. MSVC: handler, try blocks, caught types, unwind map, SEH scopes, IP-to-state, funclets, filters. No address: image counts, failed metadata checks.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `image` | string | yes |  | Image id, name or path. |
| `address` | string |  |  | Hex VA or RVA (rva:/va:/off: prefix), export, module!import or function. Omit for an image summary. |
| `offset` | integer |  |  |  |
| `maxTokens` | integer |  |  |  |

Structured output: `image`, `function`, `address`, `format`, `scheme`, `parent`, `handlers`, `ranges`, `counts`.

### list_cpp_classes

**C++ classes from RTTI** (read-only, idempotent, open-world)

C++ classes from RTTI (MSVC on PE, Itanium on ELF, Mach-O): demangled names, bases (offsets, virtual, multiple inheritance), vftables with slot targets; rejects by reason. Delphi, Free Pascal: VMT classes. Mach-O: ObjC classes, categories, protocols, Swift types. engine=ghidra: its class namespaces; ida: its C++ structs.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `image` | string | yes |  | Image id, name or path. |
| `filter` | string |  |  | Name substring (case-insensitive). |
| `slots` | boolean |  |  | Slot addresses (Pascal: methods, fields). |
| `offset` | integer |  |  |  |
| `limit` | integer |  | `100` | Max classes. |
| `maxTokens` | integer |  |  |  |
| `engine` | string |  |  | auto or ours (default: RTTI), ida or ghidra. Values: auto, ours, ida, ghidra. |
| `namespaces` | boolean |  |  | engine=ghidra: plain namespaces and libraries too. |

Structured output: `image`, `source`, `items`, `offset`, `total`, `notes`, `limit`, `totalExact`, `hasMore`, `nextOffset`.

### get_native_type

**Native type layout** (read-only, idempotent, open-world, long-running)

Layout of a native type (fields with offset, size, bits; bases, padding; enums by value) from PDB, RTTI (vftables, named slots), Il2Cpp, ObjC or Swift metadata, or the engine (source=engine). By name (exact, case-insensitive, else substring candidates), id or typed address (PDB global: field path g.players[3].pos.y). read=true adds values.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `image` | string | yes |  | Image id, name or path. |
| `name` | string |  |  | Type name (Packet, ns::Widget, Il2Cpp Ns.Type), or a glob listing matches (*Widget*). |
| `id` | string |  |  | Type id from a result (pdb:0x1A2B, rtti:0x140012000, il2cpp:Ns.Type). |
| `address` | string |  |  | A typed address: Hex VA or RVA (rva:/va:/off: prefix), export, module!import or function. |
| `at` | string |  |  | Hex field offset to name (all union members); 0x48.0x10 goes through the pointer at 0x48. |
| `depth` | integer |  | `0` | Levels of by-value members inlined (0-4). |
| `source` | string |  |  | Type source (default auto). Values: auto, pdb, rtti, il2cpp, objc, swift, engine. |
| `format` | string |  |  | c: a C declaration (default table). Values: table, c. |
| `offset` | integer |  |  | First row (field, enumerator, slot, candidate). |
| `limit` | integer |  | `200` | Max rows (max 5000). |
| `engine` | string |  |  | auto (default): IDA or Ghidra if it analyzed these bytes, else ours. Values: auto, ida, ghidra. |
| `read` | boolean |  |  | Add the field values at address (with name or id: that type read there). |
| `maxTokens` | integer |  |  |  |

Structured output: `image`, `query`, `type`, `candidates`, `totalCandidates`, `owner`, `ownerAddress`, `paths`, `offset`, `truncated`, `notes`, `readAddress`, `value`.

### decompile_native

**Decompile native function** (read-only, idempotent, open-world, long-running)

C pseudocode of a native function via IDA (Hex-Rays) or Ghidra. The first call runs auto-analysis (seconds to minutes); database and answers are kept per file. Names, comments and types in effect are pushed first; user types win. functions=: several per request, failures per item.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `image` | string | yes |  | Image id, name or path. |
| `address` | string |  |  | Hex VA or RVA (rva:/va:/off: prefix), export, module!import or function. |
| `engine` | string |  |  | Default auto. Values: auto, ida, ghidra. |
| `addresses` | boolean |  |  | Prefix lines with their source address. |
| `offset` | integer |  |  | Character offset; with functions/callersOf the first input (nextInput). |
| `maxTokens` | integer |  |  |  |
| `functions` | string[] |  |  | Several functions instead of address: addresses or names, in order. |
| `perFunctionSeconds` | integer |  | `60` | With functions: seconds per function (1-600). |
| `maxFunctions` | integer |  | `32` | With functions: most decompiled (1-200); the rest follow. |
| `refs` | boolean |  |  | With address: a footer of the globals, functions, strings and imports used. |
| `timeoutSeconds` | integer |  |  | Seconds per engine request (1-600); Ghidra retries once with 4x. |
| `callersOf` | string |  |  | Instead of address: decompile the callers of this function (engine references). |
| `view` | string |  | `c` | c, or pcode (Ghidra high p-code per block). |

Structured output: `image`, `engine`, `items`, `inputs`, `succeeded`, `failed`, `skipped`, `nextInput`, `offset`, `engineNote`, `code`, `nextOffset`, `totalChars`.

### search_decompiled

**Search native pseudocode** (read-only, idempotent, open-world, long-running)

Regex (case-insensitive; (?-i) for exact case) per line of the IDA or Ghidra pseudocode of every function (or filtered ones), in address order; parallel where the engine allows, cached. Stops at maxFunctions, timeoutSeconds or limit hits.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `image` | string | yes |  | Image id, name or path. |
| `pattern` | string | yes |  | Regex. |
| `engine` | string |  |  | Default auto. Values: auto, ida, ghidra. |
| `filter` | string |  |  | substring (case-insensitive), * ? glob, or /regex/ (flags i, m, s). |
| `maxFunctions` | integer |  | `500` | Max 20000. |
| `timeoutSeconds` | integer |  | `60` | Max 600. |
| `offset` | integer |  |  | First function (nextOffset). |
| `limit` | integer |  | `100` | Max hits (max 2000). |
| `maxTokens` | integer |  |  |  |

Structured output: `image`, `engine`, `pattern`, `items`, `functionsTotal`, `offset`, `functionsSearched`, `failed`, `nextOffset`, `hasMore`, `totalExact`, `stoppedBy`, `engineNote`.

### emulate_native

**Emulate native code** (read-only, idempotent, open-world, long-running)

Emulate native code in the Ghidra p-code emulator: string decoders, hashes, computed constants. Memory: image, stack, given writes. Stops on return, stopAt or a budget. Calls run in the image or return stubs= values; an unmodelled call or unmapped read is an error. Reports return value, registers, written strings, reads, trace.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `image` | string | yes |  | Image id, name or path. |
| `address` | string | yes |  | Hex VA or RVA (rva:/va:/off: prefix), export, module!import or function. |
| `args` | string |  |  | Per calling convention: integer, address, or pointer to 'text', u'text', buf:N (zeros) or hex:41A0. |
| `registers` | string |  |  | rcx=0x10, rdx='key' (values as args). |
| `memory` | string |  |  | ADDR=VALUE: 'text', u'text', hex:.., zero:N, u32:5, ptr:..; outside the image va:0x10000000. |
| `stopAt` | string |  |  | Addresses to stop at. |
| `stubs` | string |  |  | Calls not run: name=value (GetTickCount=5, kernel32!Sleep=0, 0x180001000=1; *=0 any call). |
| `read` | string |  |  | Shown after the run: ADDR or register, space, length (rcx 64). |
| `maxInstructions` | integer |  | `1000000` | Instruction budget (1-50000000). |
| `timeoutSeconds` | integer |  | `10` | Time budget, s (1-300). |
| `trace` | integer |  | `0` | Last instructions listed (0-2000). |
| `candidates` | string |  |  | Argument sets, ;-separated, each as args; one timeoutSeconds covers all. |
| `engine` | string |  |  | Default auto. Values: auto, ghidra. |

Structured output: `image`, `engine`, `instructions`, `stop`, `stoppedAt`, `returnRegister`, `returnValue`, `registers`, `callCount`, `calls`, `written`, `reads`, `trace`, `candidates`.

### verify_native_imports

**Verify P/Invoke imports** (read-only, idempotent, long-running)

Check imports against library exports. .NET: each P/Invoke by the runtime lookup (search order, API sets, A/W, stdcall names, ordinals, forwarders, RID, __Internal) and run-time loading in IL. Mach-O: each load command as dyld resolves it. Verdicts: verified, contradicted (with reason), unresolved, dynamic_only, not_checked.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `assembly` | string | yes |  | Assembly id, name or path. |
| `status` | string |  |  | Only this verdict or reason (contradicted, missing_export...). |
| `offset` | integer |  |  |  |
| `limit` | integer |  | `100` | Max rows (max 5000). |
| `platform` | string |  |  | Target platform (default auto). Values: auto, windows, linux, osx, android, ios. |
| `maxTokens` | integer |  |  |  |

Structured output: `assembly`, `declarations`, `counts`, `filter`, `offset`, `total`, `items`, `dynamicLoads`, `dynamicLoadsTotal`, `metadataIssues`, `notes`, `limit`, `totalExact`, `hasMore`, `nextOffset`.

### load_pdb

**Load native debug symbols** (destructive, idempotent, open-world, long-running)

Load debug symbols for a native image: PDB (GUID and age checked) or DWARF (own sections, build-id, .gnu_debuglink, dSYM): names, types, source lines. Searched: path, image folder, symbol paths and caches, CORVUS_DEBUG_DIRS. Names get source pdb (user names win). Local matches load on their own.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `image` | string | yes |  | Image id, name or path. |
| `path` | string |  |  | PDB or debug file, dSYM, or a folder or symbol store to look in first. |
| `download` | boolean |  |  | If nothing local matches: symbol server (PDB), debuginfod (ELF). |
| `server` | string |  |  | Default: _NT_SYMBOL_PATH servers, else Microsoft (PDB); CORVUS_DEBUGINFOD_URLS (DWARF). |
| `allowMismatch` | boolean |  |  | Use the path file even if GUID/age or build-id differs. |
| `timeoutSeconds` | integer |  | `120` | Download time limit, seconds. |
| `maxMegabytes` | integer |  | `2048` | Download size limit in MB. |
| `clear` | boolean |  |  | Remove the PDB names and saved copy instead. |

Structured output: `applied`, `dryRun`, `changes`, `editIds`, `failed`, `digest`.

### search_pdb_symbols

**Search native debug symbols** (read-only, idempotent)

Symbols of the PDB or DWARF loaded for a native image (load_pdb, or found automatically): address, kind, size, name, signature (undecorated or demangled), object file or unit.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `image` | string | yes |  | Image id, name or path. |
| `query` | string |  |  | Name or decorated name substring (case-insensitive); empty for all. |
| `kind` | string |  |  | Only this kind (default all). Values: function, data, public, all. |
| `offset` | integer |  |  |  |
| `limit` | integer |  | `150` |  |
| `maxTokens` | integer |  |  |  |

Structured output: `image`, `items`, `offset`, `total`, `limit`, `totalExact`, `hasMore`, `nextOffset`.

### get_nativeaot_info

**NativeAOT metadata** (read-only, idempotent, long-running)

What NativeAOT metadata recovers (.NET 7-10; PE, ELF, Mach-O). view=summary: versions, header, stages, counts. types: MethodTables (name, origin, kind, base). type: flags, bases, interfaces, slots. methods: named bodies. strings: frozen strings, references. statics: bases, known fields. Names apply as the nativeaot layer.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `image` | string | yes |  | Image id, name or path. |
| `view` | string |  |  | What to show (default summary). Values: summary, sections, types, type, methods, strings, statics. |
| `query` | string |  |  | view=type: a type name or MethodTable address; list views: substring. |
| `offset` | integer |  |  |  |
| `limit` | integer |  | `75` |  |
| `maxTokens` | integer |  |  |  |

Structured output: `image`, `view`, `summary`, `items`, `offset`, `total`, `limit`, `totalExact`, `hasMore`, `nextOffset`.

## native-edit

Native names, comments, patches and saving.

### rename_native

**Name a native address** (destructive, idempotent, open-world, long-running)

Name a native address: used by every native tool, pushed to the engines, kept per file SHA-256, undoable by editId. C-identifier-like (max 255 chars), unique unless allowDuplicate. Empty clears. items: many in one push.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `image` | string | yes |  | Image id, name or path. |
| `address` | string |  |  | Hex VA or RVA (rva:/va:/off: prefix), export, module!import or function. |
| `name` | string |  |  | New name; empty clears the name here. |
| `allowDuplicate` | boolean |  |  | Allow a name already used at another address. |
| `items` | string |  |  | Lines address = name, or JSON [{address, name}]. |
| `dryRun` | boolean |  | `true` | true previews; false applies. |
| `stopOnError` | boolean |  |  | Stop at the first failing item. |
| `showDecompile` | string |  |  | after: the pseudocode after the edit; diff: its unified diff. Values: none, after, diff. |
| `engine` | string |  |  | Engine to push to now (default: one with this image open, else at its next use). Values: auto, ida, ghidra. |

Structured output: `applied`, `dryRun`, `changes`, `editIds`, `failed`, `items`, `pushedTo`, `digest`.

### comment_native

**Comment a native address** (destructive, idempotent, open-world, long-running)

Comment a native address (undoable, pushed to engines). scope: line (repeatable: also where referenced), eol, pre or plate (engine kinds; Ghidra pseudocode shows pre), pseudocode (on its statement), function, or auto (function at a function start, else line and pseudocode). append adds a line; empty clears. items: many in one push.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `image` | string | yes |  | Image id, name or path. |
| `address` | string |  |  | Hex VA or RVA (rva:/va:/off: prefix), export, module!import or function. |
| `text` | string |  |  | Comment text; empty clears. |
| `scope` | string |  |  | See the description; default auto. Values: auto, line, eol, pre, plate, pseudocode, function. |
| `append` | boolean |  |  | Add text as a new line of the comment; a line it has is skipped. |
| `repeatLine` | boolean |  |  | With append: add the line even if the comment has it. |
| `items` | string |  |  | Lines address = text, or JSON [{address, text, scope?, append?}]. |
| `dryRun` | boolean |  | `true` | true previews; false applies. |
| `stopOnError` | boolean |  |  | Stop at the first failing item. |
| `engine` | string |  |  | Engine to push to now (default: one with this image open, else at its next use). Values: auto, ida, ghidra. |

Structured output: `applied`, `dryRun`, `changes`, `editIds`, `failed`, `items`, `pushedTo`, `digest`.

### export_native_annotations

**Export native annotations** (destructive, idempotent, long-running)

Write the image's names and comments (also NativeAOT, Il2Cpp, ObjC, Swift) as IDAPython, a Ghidra script or JSON (IDA and JSON add user engine types; scripts apply by rebased RVA). header: C header of declared types, prototypes, typed globals. objc-header: class-dump style Objective-C (Mach-O), Swift types as comments.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `image` | string | yes |  | Image id, name or path. |
| `outputPath` | string | yes |  | Output file path. |
| `format` | string |  |  | Default json. Values: ida, ghidra, json, header, objc-header. |
| `overwrite` | boolean |  |  | Replace outputPath if it exists. |

Structured output: `outputPath`, `format`, `names`, `comments`, `pseudoComments`, `types`, `imported`, `bytes`, `sha256`.

### patch_bytes

**Patch native bytes** (destructive, long-running)

Replace bytes at a native address in memory, as an undoable edit every read path sees. A partly overwritten instruction is padded with NOPs; mid-instruction, past the function end, header or ELF/Mach-O loader-rewritten bytes need allowUnsafe; encrypted bytes are refused; signatures become invalid.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `image` | string | yes |  | Image id, name or path. |
| `address` | string | yes |  | Hex VA or RVA (rva:/va:/off: prefix), export, module!import or function. |
| `hex` | string |  |  | Replacement bytes as hex (90 90, 9090 or 0x90,0x90). |
| `value` | string |  |  | Instead of hex: a number of type (range-checked); ptr: or a name. |
| `type` | string |  |  | With value: i8-i64, u8-u64, f32, f64 or ptr; be suffix: big-endian. Values: i8, u8, i16, u16, i32, u32, i64, u64, f32, f64, ptr, i16be, u16be, i32be, u32be, i64be, u64be, f32be, f64be. |
| `allowUnsafe` | boolean |  |  | Allow mid-instruction, past-function-end, header or loader-written bytes. |
| `dryRun` | boolean |  | `true` | true previews; false applies. |
| `relocations` | string |  |  | PE relocations: auto (default) keeps valid, clears stale, adds new; neutralize clears all. Values: auto, keep, neutralize. |
| `extend` | boolean |  |  | Put code larger than the site in a stub (placement) it jumps to and back. Refused when unsafe. |
| `stubMode` | string |  |  | With extend: replace (default; the displaced instructions), before or after them. Values: replace, before, after. |
| `placement` | string |  |  | With extend: auto (default): cave, else section (a new PE section or ELF/Mach-O segment). Values: auto, cave, section. |

Structured output: `applied`, `dryRun`, `changes`, `editIds`, `failed`, `items`, `pushedTo`, `digest`.

### patch_asm

**Assemble and patch native code** (destructive, long-running)

Assemble x86/x64 instructions (multi-line; labels, branch targets; db <hex>) and write them at a native address in memory, branches and RIP-relative references computed for that address. Safety rules, NOP padding and undo as patch_bytes; PE absolute addresses ([addr], offset name, imm64) get relocations.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `image` | string | yes |  | Image id, name or path. |
| `address` | string | yes |  | Hex VA or RVA (rva:/va:/off: prefix), export, module!import or function. |
| `assembly` | string | yes |  | Instructions, one per line. |
| `allowUnsafe` | boolean |  |  | Allow mid-instruction, past-function-end, header or loader-written bytes. |
| `dryRun` | boolean |  | `true` | true previews; false applies. |
| `relocations` | string |  |  | PE relocations: auto (default) keeps valid, clears stale, adds new; neutralize clears all. Values: auto, keep, neutralize. |
| `extend` | boolean |  |  | Put code larger than the site in a stub (placement) it jumps to and back. Refused when unsafe. |
| `stubMode` | string |  |  | With extend: replace (default; the displaced instructions), before or after them. Values: replace, before, after. |
| `placement` | string |  |  | With extend: auto (default): cave, else section (a new PE section or ELF/Mach-O segment). Values: auto, cave, section. |

Structured output: `applied`, `dryRun`, `changes`, `editIds`, `failed`, `items`, `pushedTo`, `digest`.

### list_native_edits

**List native edits** (read-only, idempotent, long-running)

Native edits of an image in order, each with the editId undo_native_edit takes: byte patches, names, comments, engine type edits. Then the name layers (user, pdb, il2cpp, ida...) with counts and origin. search: matching names and comments instead.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `image` | string | yes |  | Image id, name or path. |
| `search` | string |  |  | Instead: matching names and comments: substring (case-insensitive), * ? glob, or /regex/ (flags i, m, s). |
| `offset` | integer |  |  |  |
| `limit` | integer |  | `100` |  |
| `maxTokens` | integer |  |  |  |

Structured output: `image`, `items`, `total`, `layers`, `offset`, `limit`, `totalExact`, `hasMore`, `nextOffset`.

### undo_native_edit

**Undo a native edit** (destructive, long-running)

Undo native edits by editId (list_native_edits), the last by default: a patch, name, comment or engine type edit gets its previous value back, pushed to the engines. Refused while a later edit changed the same item.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `image` | string | yes |  | Image id, name or path. |
| `editId` | string |  |  | image#n or #n; comma-separated for several, undone in order; default the last. |

Structured output: `applied`, `dryRun`, `changes`, `editIds`, `failed`, `items`, `pushedTo`, `digest`.

### save_native

**Save patched native image** (destructive, idempotent, long-running)

Write the patched native image to a new file: unpatched bytes identical, PE checksum recomputed, a signature invalidated (stripSignature removes it). Atomic and verified; replaceOriginal=true keeps a .bak and refuses a file changed on disk.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `image` | string | yes |  | Image id, name or path. |
| `outputPath` | string | yes |  | Output file path. |
| `overwrite` | boolean |  |  | Replace an existing file, not the original. |
| `stripSignature` | boolean |  |  | Remove the Authenticode certificate table from the output. |
| `replaceOriginal` | boolean |  |  | Replace the loaded file (needs --allow-replace-original). |
| `versioned` | boolean |  |  | Write <name>.N.dll, the first free N. |

Structured output: `outputPath`, `bytes`, `patches`, `sha256`, `checksum`, `backup`, `verified`, `notes`, `editList`.

### export_native_patches

**Export native patches** (destructive, idempotent)

Write the image's byte patches for other tools: ida an IDAPython script (at rebased RVAs, where the original bytes are found), dif an IDA .dif, ips (offsets below 16 MB) or ips32, json the full set (for migrate_native_patches). Relocation edits and PE checksum included: a .dif or IPS applied to the original gives the save_native bytes.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `image` | string | yes |  | Image id, name or path. |
| `outputPath` | string | yes |  | Output file path. |
| `format` | string |  |  | Default json. Values: ida, dif, ips, ips32, json. |
| `overwrite` | boolean |  |  | Replace outputPath if it exists. |

Structured output: `image`, `outputPath`, `format`, `patches`, `relocationEdits`, `changedBytes`, `records`, `checksumUpdated`, `bytes`, `originalSha256`, `notes`.

## builds

Build-to-build comparison and carrying work to a new build.

### compare_assemblies

**Compare two builds** (read-only, idempotent, long-running)

Compare two builds of an assembly: renamed, moved, added and removed types and members (matched by content in tiers, unique-only; else ambiguous) and how each matched member changed (signature, body by IL hash, metadata, Il2Cpp offset). oldResult / newResult compare kept results.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `oldAssembly` | string |  |  | Old build: id, name or path. |
| `newAssembly` | string |  |  | New build: id, name or path. |
| `namespace` | string |  |  | Only types whose old or new full name starts with this. |
| `changes` | string[] |  |  | Kinds to list (unknown: unpaired for lack of evidence); default all but address. |
| `typeCountsOnly` | boolean |  |  | Count added and removed types, not listed. |
| `includeCompilerGenerated` | boolean |  |  | Also compiler-generated types and members (closures, state machines). |
| `tokenMap` | boolean |  |  | Keep the whole old-to-new token map as a result (tokenMapResultId). |
| `offset` | integer |  |  |  |
| `limit` | integer |  | `100` | Changes per page. |
| `maxTokens` | integer |  |  |  |
| `oldResult` | string |  |  | Instead: a kept result (r-...), last:N (recent call) or bundle entry (file.json#r-...). |
| `newResult` | string |  |  | The new side, from the same tool. |

Structured output: `old`, `new`, `oldTypes`, `matchedTypes`, `typeChanges`, `memberChanges`, `memberMatches`, `ambiguousMembers`, `oldSkippedBodies`, `newSkippedBodies`, `hiddenCompilerGenerated`, `items`, `offset`, `total`, `tokenMapResultId`, `tokenMapEntries`, `evidence`, `changes`, `limit`, `totalExact`, `hasMore`, `nextOffset`.

### find_counterpart

**Find symbol in another build** (read-only, idempotent, long-running)

Where a type or member of the old build went in the new one (by name, then content, unique-only; else candidates): new name and token, tier, confidence, body change. diff=true and il=true add unified C# and normalized IL diffs of each pair, renames applied first.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `symbol` | string | yes |  | Old build: Type or member: Ns.Type, Ns.Outer+Inner, Ns.Type::Method(int, string), short name or token (0x06000123). |
| `oldAssembly` | string | yes |  | Old build: id, name or path. |
| `newAssembly` | string | yes |  | New build: id, name or path. |
| `diff` | boolean |  |  | C# diff of each pair (cut at 300 lines). |
| `il` | boolean |  |  | Normalized IL diff of each method pair. |
| `symbols` | string[] |  |  | Instead of symbol: up to 100. |
| `offset` | integer |  |  |  |
| `limit` | integer |  | `25` | Symbols per page. |
| `maxTokens` | integer |  |  |  |

Structured output: `old`, `new`, `items`, `offset`, `total`, `limit`, `totalExact`, `hasMore`, `nextOffset`.

### compare_folders

**Compare two folders or packages** (read-only, idempotent, long-running)

Compare two folders, zip-family archives or files: modified, added, removed, moved, case-only renames, links, unreadable; changed binaries with MVID and version, text with a diff. oldResult / newResult compare kept results.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `oldPath` | string |  |  | Old folder, archive or file. |
| `newPath` | string |  |  | New folder, archive or file. |
| `change` | string |  | `changed` | Entries listed. Values: changed, modified, added, removed, moved, renamed, unreadable, unchanged, all. |
| `exclude` | string[] |  |  | Path globs to skip. |
| `caseSensitive` | boolean |  |  | Default: false on Windows and macOS. |
| `maxEntries` | integer |  | `200000` | Per side; past it, incomplete. |
| `offset` | integer |  |  |  |
| `limit` | integer |  | `100` | Entries per page. |
| `oldResult` | string |  |  | Instead: a kept result (r-...), last:N (recent call) or bundle entry (file.json#r-...). |
| `newResult` | string |  |  | The new side, from the same tool. |
| `noDiffs` | boolean |  |  | Leave out text diffs. |

Structured output: `old`, `new`, `hashBasis`, `caseSensitive`, `counts`, `view`, `offset`, `total`, `entries`, `notes`, `evidence`, `changes`, `limit`, `totalExact`, `hasMore`, `nextOffset`.

### compare_native_images

**Compare native builds** (read-only, idempotent, long-running)

Match the functions of two native builds (x86, x64, ARM64) in tiers: 1 same name, import or bytes; 2 control flow; 3 imports, strings, constants; 4 call-graph neighbours; 5 fuzzy above minScore; unique pairs only. Per-tier counts and one view's rows by old address. oldResult / newResult compare two kept results.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `oldImage` | string |  |  | Older build: image id or path (load both; the second is app.dll#2). |
| `newImage` | string |  |  | Newer build: image id or path. |
| `view` | string |  | `pairs` | changed: code differs; ambiguous: with candidates; wasm: interface. Values: pairs, changed, unmatched, ambiguous. |
| `tier` | integer |  | `0` | Only pairs of this tier (1-5); 0 for all. |
| `codeOnly` | boolean |  |  | Match functions by code, not names. |
| `minScore` | number |  | `0.7` | Least similarity for a fuzzy match (0-1). |
| `offset` | integer |  |  |  |
| `limit` | integer |  | `40` |  |
| `maxTokens` | integer |  |  |  |
| `oldResult` | string |  |  | Instead: a kept result (r-...), last:N (recent call) or bundle entry (file.json#r-...). |
| `newResult` | string |  |  | The new side, from the same tool. |

Structured output: `oldImage`, `newImage`, `oldFunctions`, `newFunctions`, `matched`, `identical`, `changed`, `unmatchedOld`, `unmatchedNew`, `ambiguous`, `tiers`, `view`, `items`, `offset`, `total`, `notes`, `evidence`, `changes`, `limit`, `totalExact`, `hasMore`, `nextOffset`.

### diff_function

**Diff a function between builds** (read-only, idempotent, open-world, long-running)

Changes to one function between two builds. view=asm: aligned instruction rows = (same), ~ (other operands), - or +, operands made build-independent. view=pseudocode: a unified diff. addresses: one summary each. oldResult / newResult: kept code.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `oldImage` | string |  |  | Older build: image id or path (load both; the second is app.dll#2). |
| `newImage` | string |  |  | Newer build: image id or path. |
| `address` | string |  |  | In the function: Hex VA or RVA (rva:/va:/off: prefix), export, module!import or function. |
| `addresses` | string[] |  |  | Instead of address: up to 20 functions, one summary each. |
| `side` | string |  | `old` | Which build the address is in. Values: old, new. |
| `view` | string |  | `asm` | pseudocode needs an engine. Values: asm, pseudocode. |
| `context` | integer |  | `4` | Unchanged rows around each change (0-50). |
| `codeOnly` | boolean |  |  | Match functions by code, not names. |
| `engine` | string |  |  | view=pseudocode: the engine. Values: auto, ida, ghidra. |
| `offset` | integer |  |  |  |
| `limit` | integer |  | `500` |  |
| `maxTokens` | integer |  |  |  |
| `oldResult` | string |  |  | Instead: old code as a kept result (r-...), last:N (recent call) or bundle entry (file.json#r-...). |
| `newResult` | string |  |  | Same tool; or one result plus the other image and address. |

Structured output: `oldImage`, `newImage`, `oldFunction`, `newFunction`, `oldAddress`, `newAddress`, `tier`, `basis`, `score`, `view`, `summary`, `same`, `changed`, `removed`, `added`, `items`, `offset`, `total`, `candidates`, `functions`, `notes`, `evidence`, `limit`, `totalExact`, `hasMore`, `nextOffset`.

### map_address_between_builds

**Map an address to a new build** (read-only, idempotent, long-running)

Where addresses of the old build are in the new one: a function start to the matched function, an address inside one to the aligned instruction, a string to the same string, other data through references of matched instructions. Each: new address, confidence and reason, or why not with candidates.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `oldImage` | string | yes |  | Older build: image id or path (load both; the second is app.dll#2). |
| `newImage` | string | yes |  | Newer build: image id or path. |
| `address` | string |  |  | Old build: Hex VA or RVA (rva:/va:/off: prefix), export, module!import or function. |
| `addresses` | string[] |  |  | Instead of address: up to 100 addresses. |
| `codeOnly` | boolean |  |  | Match functions by code, not names. |

Structured output: `oldImage`, `newImage`, `results`, `failed`.

### make_code_pattern

**Make a code pattern** (read-only, idempotent, open-world, long-running)

Make a rebuild-proof byte pattern for an address: displacements and relocated addresses as ??, unique in the executable sections. anchor=auto: at the address, else at a referencing instruction (with operand offset); xrefs: one per referencing instruction; range: [address, end). search_code_pattern finds it.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `image` | string | yes |  | Image id, name or path. |
| `address` | string |  |  | Hex VA or RVA (rva:/va:/off: prefix), export, module!import or function. |
| `addresses` | string[] |  |  | Instead of address: up to 50. |
| `anchor` | string |  | `auto` | Where to anchor. Values: auto, address, reference, xrefs, range. |
| `maxBytes` | integer |  | `64` | Longest pattern in bytes (8-512). |
| `maxPatterns` | integer |  | `8` | anchor=xrefs: most signatures (1-32). |
| `engine` | string |  |  | anchor=xrefs: ida or ghidra add engine references. Values: auto, ours, ida, ghidra. |
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
| `offset` | integer |  |  |  |
| `limit` | integer |  | `100` |  |
| `maxTokens` | integer |  |  |  |

Structured output: `pattern`, `items`, `offset`, `total`, `failed`, `notes`, `limit`, `totalExact`, `hasMore`, `nextOffset`.

### migrate_native_names

**Carry names to a new build** (edit, idempotent, long-running)

Copy names, comments and engine types of the old build to the user annotations of the new one through the function match (map_address_between_builds). Never replaces a user name, comment or type of the new build; skipped items have a reason code. Applied as undoable edits.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `oldImage` | string | yes |  | Older build: image id or path (load both; the second is app.dll#2). |
| `newImage` | string | yes |  | Newer build: image id or path. |
| `dryRun` | boolean |  | `true` | true previews; false applies. |
| `minTier` | integer |  | `5` | Weakest match tier accepted: 1 (names, identical bytes) to 5 (all). |
| `minScore` | number |  | `0` | Least mapping confidence accepted (0-1). |
| `sources` | string[] |  |  | Layers to copy (default user). |
| `namesOnly` | boolean |  |  | Names only, no comments. |
| `codeOnly` | boolean |  |  | Match functions by code, not names. |
| `offset` | integer |  |  |  |
| `limit` | integer |  | `100` |  |
| `maxTokens` | integer |  |  |  |

Structured output: `oldImage`, `newImage`, `dryRun`, `applied`, `editIds`, `set`, `skipped`, `skippedBy`, `items`, `offset`, `total`, `notes`, `limit`, `totalExact`, `hasMore`, `nextOffset`.

### migrate_native_patches

**Migrate patches to a new build** (destructive, long-running)

Carry byte patches from an old build to a new one through the build match (compare_native_images). A patch is reapplied only where the mapped address holds the expected original bytes (patch_asm patches re-assembled), else refused with a reason code. Same image as old and new with patchSet: replays the set.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `oldImage` | string | yes |  | Old build: image id or path (its in-memory patches are the source unless patchSet). |
| `newImage` | string | yes |  | New build: image id or path (the second load gets an id like name#2). |
| `patchSet` | string |  |  | A JSON patch set (export_native_patches format=json): path or text. |
| `dryRun` | boolean |  | `true` | true previews; false applies. |
| `codeOnly` | boolean |  |  | Match functions by code, not names. |
| `offset` | integer |  |  |  |
| `limit` | integer |  | `100` |  |
| `maxTokens` | integer |  |  |  |

Structured output: `oldImage`, `newImage`, `source`, `dryRun`, `applied`, `editIds`, `patches`, `carried`, `refused`, `refusedBy`, `items`, `offset`, `total`, `notes`, `limit`, `totalExact`, `hasMore`, `nextOffset`.

### update_to_new_build

**Update work to a new build** (destructive, idempotent, long-running)

Carry work from an old native build to the new one through one function match: names, comments, engine types, PDB and Il2Cpp layers, patches, code-pattern drift, Il2Cpp method mapping, notes. Per-category counts with reason codes; a re-run reports already_present. .NET: notes via find_counterpart.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `oldImage` | string | yes |  | Old build: image id or path. |
| `newImage` | string | yes |  | New build: image id or path. |
| `dryRun` | boolean |  | `true` | true previews; false applies. |
| `include` | string[] |  |  | Categories to carry (default all). |
| `patchSet` | string |  |  | Patch set (export_native_patches json): text or path. |
| `stubPlacement` | string |  |  | Placement of re-created patch stubs. Values: auto, cave, section. |
| `oldIl2Cpp` | string[] |  |  | Il2Cpp dummy assemblies, old build. |
| `newIl2Cpp` | string[] |  |  | Il2Cpp dummy assemblies, new build. |
| `codeOnly` | boolean |  |  | Match functions by code, not names. |
| `maxPatterns` | integer |  | `100` | Most code patterns made (0-1000). |
| `category` | string |  |  | Only items of this category. Values: names, pdb, il2cpp_names, patches, patterns, il2cpp_mapping, notes, dotnet. |
| `outcome` | string |  |  | Only items with this outcome. Values: carried, would_carry, already_present, refused, not_applicable, ambiguous. |
| `offset` | integer |  |  |  |
| `limit` | integer |  | `100` |  |
| `maxTokens` | integer |  |  |  |

Structured output: `summary`, `oldImage`, `newImage`, `dryRun`, `editIds`, `included`, `oldFunctions`, `newFunctions`, `functionsMatched`, `categories`, `il2CppMapping`, `items`, `offset`, `total`, `notes`, `limit`, `totalExact`, `hasMore`, `nextOffset`.

## notes

Analyst notes kept per binary across sessions.

### record_note

**Record a note** (edit)

Record a finding, question, hypothesis or todo anchored to a native address, .NET member, file or dump; notes persist per user, keyed by SHA-256 or MVID so they follow the binary; decompile_member and decompile_native count open notes of a target.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `text` | string | yes |  | At most 4,000 characters. |
| `kind` | string |  |  | Default finding. Values: finding, question, hypothesis, todo. |
| `status` | string |  |  | Default open. Values: open, confirmed, refuted, answered, dropped. |
| `anchor` | string |  |  | <image>@<address>, <assembly>:<symbol or token>, image or assembly id, dump:<id or path>, or empty (session-wide). |
| `tags` | string[] |  |  | At most 10. |
| `evidence` | object[] |  |  | At most 10: {result: r-... or last:N, expect: supports\|refutes}, {tool, args} of a call made here, or {text}. |

Structured output: `id`, `kind`, `status`, `text`, `tags`, `evidence`, `anchor`, `revision`, `created`, `updated`, `author`.

### update_note

**Update a note** (destructive, idempotent)

Change part of a note: status, kind, text, tags, evidence; verify=true re-checks linked records and sets a hypothesis confirmed or refuted when they verify and name its anchor, else open. A stale expectedRevision is a conflict carrying the note.

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
| `addEvidence` | object[] |  |  | At most 10: {result: r-... or last:N, expect: supports\|refutes}, {tool, args} of a call made here, or {text}. |
| `verify` | boolean |  |  | Re-check linked records after the other changes. |

Structured output: `id`, `kind`, `status`, `text`, `tags`, `evidence`, `anchor`, `revision`, `created`, `updated`, `author`.

### list_notes

**List notes** (read-only, idempotent)

Notes, newest first, by status, kind, anchor, tag and text. A file anchor lists all its notes, <image>@<address> those in the containing function, <assembly>:<type> those on its members too.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `status` | string |  |  | Default open; all for every status. Values: open, confirmed, refuted, answered, dropped, all. |
| `kind` | string |  |  | Only this kind. Values: finding, question, hypothesis, todo. |
| `anchor` | string |  |  | <image>@<address>, <assembly>:<symbol or token>, image or assembly id, dump:<id or path>, or empty (session-wide). |
| `tag` | string |  |  | Only notes with this tag. |
| `text` | string |  |  | Text substring (case-insensitive). |
| `offset` | integer |  |  |  |
| `limit` | integer |  | `50` | Notes per page. |
| `maxTokens` | integer |  |  |  |

Structured output: `items`, `offset`, `total`, `notes`, `limit`, `totalExact`, `hasMore`, `nextOffset`.

## engine

Edits inside the decompiler engine's database: types, locals, frames, declarations, scripting.

### get_engine_status

**Engine status of a native image** (read-only, idempotent, open-world)

IDA and Ghidra sessions of a native image: opening (stage, seconds), failed, not started, or open with the engine view (language, compiler, analysis state, warnings, counts, entry points, hashes, database, worker, unsaved edits). Starts no engine.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `image` | string | yes |  | Image id, name or path. |
| `engine` | string |  |  | Default auto: both. Values: auto, ida, ghidra. |
| `bookmarks` | boolean |  |  | Ghidra: every Error and Warning bookmark (default: the first 5). |

Structured output: `image`, `engines`.

### set_native_type

**Set a native prototype or global type** (destructive, idempotent, open-world, long-running)

Set a native function prototype (int __fastcall Parse(Packet *p, int len)) or global type (Handler *[8]) in the engine. Named types must exist there (PDB, RTTI, Il2Cpp or declare_native_types). User types win; empty clears; __noreturn ends caller flow at the call. Kept in the annotations.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `image` | string | yes |  | Image id, name or path. |
| `address` | string |  |  | Hex VA or RVA (rva:/va:/off: prefix), export, module!import or function. |
| `type` | string |  |  | C prototype for a function, C type for a global; empty clears the user type. |
| `items` | string |  |  | Instead of address and type: lines address = type. |
| `rename` | boolean |  |  | Name the function as its prototype does. |
| `guess` | boolean |  |  | Report the engine guess at address, not applied. |
| `showDecompile` | string |  |  | after: the pseudocode after the edit; diff: its unified diff. Values: none, after, diff. |
| `engine` | string |  |  | Default auto. Values: auto, ida, ghidra. |

Structured output: `applied`, `dryRun`, `changes`, `editIds`, `failed`, `digest`.

### set_native_local

**Rename or retype a decompiler local** (destructive, idempotent, open-world, long-running)

Rename and/or retype a local or argument in native pseudocode, named as decompile_native shows it (v3, a1) or stack:0x28. Later edits may use the new name; the first name again, or clear, drops the edit. A type that does not fit is refused. Kept in the annotations.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `image` | string | yes |  | Image id, name or path. |
| `function` | string | yes |  | Hex VA or RVA (rva:/va:/off: prefix), export, module!import or function. |
| `local` | string |  |  | The variable: its pseudocode name, or stack:<offset> (hex). |
| `newName` | string |  |  | New name (a C identifier). |
| `type` | string |  |  | New C type. |
| `clear` | boolean |  |  | Drop the user name and type. |
| `items` | string |  |  | Instead: lines local = newName, or JSON [{local, newName?, type?, clear?}]. |
| `showDecompile` | string |  |  | after: the pseudocode after the edit; diff: its unified diff. Values: none, after, diff. |
| `engine` | string |  |  | Default auto. Values: auto, ida, ghidra. |
| `inferStruct` | string |  |  | Ghidra: declare this struct from the local's accesses; the local points to it. |
| `storage` | string |  |  | Move an argument to this register; auto: where the convention puts it. |

Structured output: `applied`, `dryRun`, `changes`, `editIds`, `failed`, `digest`.

### set_native_stack_var

**Rename, retype or delete a stack variable** (destructive, idempotent, open-world, long-running)

Rename and/or retype a stack frame member by its get_native_frame name (var_28) or frame offset (0x20, from the lowest address); a type at an empty offset creates one. Return address and saved registers are refused. Kept in the annotations.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `image` | string | yes |  | Image id, name or path. |
| `function` | string | yes |  | Hex VA or RVA (rva:/va:/off: prefix), export, module!import or function. |
| `variable` | string |  |  | The member: name or frame offset (hex). |
| `newName` | string |  |  | New name (a C identifier). |
| `type` | string |  |  | New C type. |
| `delete` | boolean |  |  | Delete the member. |
| `clear` | boolean |  |  | Drop the user edit, restoring the engine member. |
| `showDecompile` | string |  |  | after: the pseudocode after the edit; diff: its unified diff. Values: none, after, diff. |
| `engine` | string |  |  | Default auto. Values: auto, ida, ghidra. |
| `items` | string |  |  | Instead: lines member = newName, or JSON [{variable, newName?, type?, delete?, clear?}]. |

Structured output: `applied`, `dryRun`, `changes`, `editIds`, `failed`, `digest`.

### get_native_frame

**Native stack frame and locals** (read-only, idempotent, open-world, long-running)

Stack frame of a native function as the engine has it (members: offset, name, type, size; Ghidra counts saved registers as locals); locals=true adds decompiler locals (name, type, register or stack offset, user edits). Offsets from the lowest address; brackets from the return address.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `image` | string | yes |  | Image id, name or path. |
| `function` | string | yes |  | Hex VA or RVA (rva:/va:/off: prefix), export, module!import or function. Comma-separated for several. |
| `engine` | string |  |  | Default auto. Values: auto, ida, ghidra. |
| `locals` | boolean |  |  | Decompile for the locals too. |
| `offset` | integer |  |  |  |
| `limit` | integer |  | `200` | Max rows (max 5000). |

Structured output: `image`, `engine`, `function`, `name`, `localSize`, `savedRegisters`, `returnAddressOffset`, `members`, `locals`, `localsNote`, `items`, `offset`, `total`, `frames`, `limit`, `totalExact`, `hasMore`, `nextOffset`.

### declare_native_types

**Declare C types in the engine** (destructive, idempotent, open-world, long-running)

Declare C types (structs, unions, enums, typedefs, function types) in the engine, replacing same-named ones; they win over recovered types. Engine errors save nothing. typeName edits one type: members (enum), fields (struct, union), resize, nameGaps; delete or rename edits any named type. Kept in the annotations.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `image` | string | yes |  | Image id, name or path. |
| `declarations` | string |  |  | C declarations; named types must exist or be declared too. |
| `typeName` | string |  |  | Enum, struct or union to edit. |
| `members` | string |  |  | Enum: NAME=value, ... (hex or decimal; or lines); NAME= removes. |
| `fields` | string |  |  | Struct or union: name: type; name@0x10: type; @0x10: type (or lines); name: removes; +name@0x10: type inserts. |
| `resize` | string |  |  | Struct: new size (hex or decimal); goes alone. |
| `nameGaps` | boolean |  |  | Struct: name unnamed gaps gap_<offset>. |
| `delete` | string |  |  | A type to delete. |
| `rename` | string |  |  | Old=New; kept edits naming it follow. |
| `engine` | string |  |  | Default auto. Values: auto, ida, ghidra. |

Structured output: `applied`, `dryRun`, `changes`, `editIds`, `failed`, `digest`.

### list_native_types

**Browse the engine's types** (read-only, idempotent, open-world, long-running)

Named types of the engine database (PDB, RTTI, Il2Cpp, type libraries, declare_native_types) with size and member count; name= shows one as a C declaration with member offsets.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `image` | string | yes |  | Image id, name or path. |
| `filter` | string |  |  | substring (case-insensitive), * ? glob, or /regex/ (flags i, m, s). |
| `kind` | string |  |  | udt: struct or union. Values: struct, union, udt, enum, typedef, func, ptr. |
| `name` | string |  |  | Show this one type in full instead of a list. |
| `offset` | integer |  |  |  |
| `limit` | integer |  | `200` | Max rows (max 5000). |
| `maxTokens` | integer |  |  |  |
| `engine` | string |  |  | Default auto. Values: auto, ida, ghidra. |
| `sort` | string |  |  | Default name; ordinal: the engine's order. Values: name, size. |
| `descending` | boolean |  |  | Reverse the order. |
| `members` | boolean |  |  | List the first 32 members of each (enums: name = value). |
| `related` | boolean |  |  | Add the types each refers to. |

Structured output: `engine`, `items`, `offset`, `total`, `limit`, `totalExact`, `hasMore`, `nextOffset`.

### define_native

**Redefine code or data in the engine** (destructive, idempotent, open-world, long-running)

Redefine an address in the engine by kind: code (to end, else along the flow), function (make one to end, or move a function end), undefine (to end, else the item or function), data (of type), flow (Ghidra: type branch, call, call_return or return; else clears). data and undefine drop a global's user type. Kept in the annotations.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `image` | string | yes |  | Image id, name or path. |
| `address` | string | yes |  | Hex VA or RVA (rva:/va:/off: prefix), export, module!import or function. |
| `kind` | string | yes |  | What to make. Values: code, function, undefine, data. |
| `end` | string |  |  | Exclusive end address (same forms as address). |
| `type` | string |  |  | kind=data: byte, word, dword, qword, float, double, string, string16 (UTF-16), a C type; dword[8] arrays. |
| `engine` | string |  |  | Default auto. Values: auto, ida, ghidra. |

Structured output: `applied`, `dryRun`, `changes`, `editIds`, `failed`, `digest`.

### reanalyze_native

**Re-run native auto-analysis** (destructive, open-world, long-running)

Re-run IDA or Ghidra auto-analysis over an image (or from-to) and save; a full run also completes a Ghidra analysis the open budget cut short. options= sets analyzers for this run; analyzers=true lists them.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `image` | string | yes |  | Image id, name or path. |
| `engine` | string |  |  | Default auto. Values: auto, ida, ghidra. |
| `analyzers` | boolean |  |  | List analyzer options and values instead of running. |
| `filter` | string |  |  | With analyzers: name filter. |
| `options` | string[] |  |  | name=value per option (AF_FLIRT=false, Decompiler Parameter ID=true). |
| `preset` | string |  |  | full (Ghidra defaults) or a preset in analysis-presets.json. |
| `background` | boolean |  |  | Run with no caller waiting; other engine calls conflict until done. |
| `from` | string |  |  | Range start (default: whole image). |
| `to` | string |  |  | Range end (exclusive). |
| `timeoutSeconds` | integer |  | `600` | Seconds (1-3600); the rest runs on the next run. |
| `offset` | integer |  |  | With analyzers: rows to skip. |
| `limit` | integer |  | `200` | With analyzers: max rows. |

Structured output: `image`, `engine`, `scope`, `complete`, `functionsBefore`, `functionsAfter`, `options`, `items`, `offset`, `total`, `limit`, `totalExact`, `hasMore`, `nextOffset`.

### set_native_operand

**Set how an operand displays** (destructive, idempotent, open-world, long-running)

Set how an instruction operand displays in engine disassembly and, where the decompiler follows, pseudocode: offset (as an address), stack (a stack variable), enum (type: the enum), struct (type: Packet or Packet+0x10; IDA only) or default. Ghidra shows numbers and enum members as equates. Kept in the annotations.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `image` | string | yes |  | Image id, name or path. |
| `address` | string | yes |  | Hex VA or RVA (rva:/va:/off: prefix), export, module!import or function. |
| `operand` | integer |  | `0` | Operand index, 0 for the first. |
| `display` | string |  |  | How to display it. Values: hex, dec, oct, bin, char, offset, stack, enum, struct, default. |
| `type` | string |  |  | display=enum or struct: the type name (struct: optionally +delta). |
| `engine` | string |  |  | Default auto. Values: auto, ida, ghidra. |
| `items` | string |  |  | Instead: lines address operand display [type], or JSON [{address, operand, display, type?}]. |

Structured output: `applied`, `dryRun`, `changes`, `editIds`, `failed`, `digest`.

### ida_python

**Run IDAPython on a native image** (destructive, open-world, long-running)

Run Python in the IDA worker holding the image database (idalib): IDAPython imported, base = image base, globals persist (reset=true clears); returns the final expression value, stdout, stderr. Off unless --ida-scripting (CORVUS_IDA_SCRIPTING=1): the code has server rights. Not journaled: persist=true saves.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `image` | string | yes |  | Image id, name or path. |
| `code` | string |  |  | Python source (or scriptPath). |
| `reset` | boolean |  |  | Clear globals of earlier calls. |
| `engine` | string |  |  | Default auto. Values: auto, ida. |
| `scriptPath` | string |  |  | A .py file to run instead of code. |
| `maxTokens` | integer |  |  |  |
| `persist` | boolean |  |  | Save the database afterwards. |
| `allowError` | boolean |  |  | Return an exception as the result, not an error. |

Structured output: `image`, `engine`, `result`, `stdout`, `stderr`, `error`, `saved`.

### ghidra_script

**Run a Ghidra script on a native image** (destructive, open-world, long-running)

Run Java or Python (PyGhidra, CORVUS_GHIDRA_PYTHON) in the Ghidra worker: a GhidraScript class, a run() body (imports first; currentProgram, println, FlatProgramAPI) or name= an installed script. One transaction: saved on return, rolled back on an exception. Off unless --ghidra-scripting (CORVUS_GHIDRA_SCRIPTING=1): the code has server rights.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `image` | string | yes |  | Image id, name or path. |
| `code` | string |  |  | Java (a GhidraScript class, or statements for run()) or Python source. |
| `name` | string |  |  | Instead of code: a script in the Ghidra script folders or <data>/ghidra_scripts. |
| `args` | string[] |  |  | With name: script arguments (getScriptArgs). |
| `timeoutSeconds` | integer |  | `120` | Seconds before the script is cancelled (1-3600). |
| `language` | string |  |  | java (default) or python; name *.py is Python. |
| `engine` | string |  |  | Default auto. Values: auto, ghidra. |
| `maxTokens` | integer |  |  |  |
| `allowError` | boolean |  |  | Return an exception as the result, not an error. |

Structured output: `image`, `engine`, `result`, `stdout`, `stderr`, `error`, `saved`.

### export_engine_database

**Export the engine database** (destructive, idempotent, open-world, long-running)

Write the engine database of a native image (analysis plus names, comments and types pushed from here) for the engine GUI: IDA .i64, Ghidra .gzf; Ghidra types also as .h or .gdt. Written whole or not at all.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `image` | string | yes |  | Image id, name or path. |
| `outputPath` | string | yes |  | The .i64 (IDA), .gzf, .h or .gdt (Ghidra) to write. |
| `overwrite` | boolean |  |  | Replace outputPath if it exists. |
| `engine` | string |  |  | Default: the engine of the extension, else IDA. Values: auto, ida, ghidra. |

Structured output: `image`, `engine`, `path`, `bytes`, `note`.

## android

Android packages: manifest, resources, DEX code, Java decompilation, Java / .NET mapping, devices.

### get_android_manifest

**Android manifest** (read-only, idempotent)

AndroidManifest.xml decoded. view=summary: package, versions, SDKs, permissions, application flags, component counts, exported components and why, queries, features, libraries, highlights. components: each with intent filters, deep links, meta-data.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `path` | string | yes |  | An .apk, .aab or split set (.apks, .xapk, .apkm). |
| `view` | string |  |  | summary (default) or components. |
| `offset` | integer |  |  |  |
| `limit` | integer |  | `50` | Most components. |

Structured output: `package`, `versionCode`, `versionName`, `minSdk`, `targetSdk`, `maxSdk`, `compileSdk`, `split`, `application`, `permissions`, `declaredPermissions`, `componentCounts`, `exported`, `exportedTotal`, `queries`, `features`, `libraries`, `metaData`, `highlights`, `issues`, `items`, `offset`, `total`, `limit`, `totalExact`, `hasMore`, `nextOffset`.

### list_android_resources

**List Android resources** (read-only, idempotent)

Compiled resources of an Android package (resources.arsc, or resources.pb in a bundle): a row per resource and configuration with id, type, name, qualifiers, value type and value (cut at 200 characters); counts per type.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `path` | string | yes |  | An .apk, .aab or split set (.apks, .xapk, .apkm). |
| `type` | string |  |  | Only this type (string, layout, xml...). |
| `name` | string |  |  | Only names matching this (* and ? wildcards). |
| `config` | string |  |  | Only this configuration (pt-rBR, or default). |
| `offset` | integer |  |  |  |
| `limit` | integer |  | `100` | Most rows. |
| `maxTokens` | integer |  |  |  |

Structured output: `items`, `offset`, `total`, `types`, `limit`, `totalExact`, `hasMore`, `nextOffset`.

### get_android_resource

**Get Android resource** (destructive, idempotent)

One entry or resource of an Android package: an entry path (binary XML decoded, references named; text; else a hex preview), or @type/name / 0x7f... for its value in every configuration.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `path` | string | yes |  | An .apk, .aab or split set (.apks, .xapk, .apkm). |
| `name` | string | yes |  | Entry path (res/xml/x.xml, assets/...), @type/name or resource id 0x7f... |
| `outputPath` | string |  |  | Write the entry bytes to this file. |
| `overwrite` | boolean |  |  | Replace outputPath if it exists. |
| `offset` | integer |  |  |  |
| `maxTokens` | integer |  |  |  |

Structured output: `entry`, `outputPath`, `bytes`, `sha256`, `code`, `offset`, `nextOffset`, `totalChars`.

### list_dex_classes

**List DEX classes** (read-only, idempotent)

Classes defined in the DEX code of an Android package (every classes*.dex): descriptor, DEX file, access, superclass, interfaces, member counts, source file; unfiltered, the largest packages.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `path` | string | yes |  | An Android package, a .dex, or a jar with classes*.dex. |
| `query` | string |  |  | Only classes whose name contains or matches (* ?) this. |
| `package` | string |  |  | Only this package and its subpackages. |
| `offset` | integer |  |  |  |
| `limit` | integer |  | `100` | Most classes. |
| `maxTokens` | integer |  |  |  |
| `mapping` | string |  |  | R8/ProGuard mapping.txt: shows and accepts original names; kept per package. |

Structured output: `items`, `offset`, `total`, `notes`, `packages`, `limit`, `totalExact`, `hasMore`, `nextOffset`.

### get_dex_class

**DEX class** (read-only, idempotent)

One DEX class: superclass, interfaces, generic signature, enclosing and inner classes, Kotlin @Metadata, annotations; then its members, paged: fields (type, static value), methods (id, Java signature, code size, registers, parameters).

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `path` | string | yes |  | An Android package, a .dex, or a jar with classes*.dex. |
| `class` | string | yes |  | Class: Lpkg/Name;, pkg.Name, or pkg.Outer.Inner / pkg.Outer$Inner. |
| `members` | string |  |  | all (default), fields or methods. |
| `query` | string |  |  | Only members whose name contains this. |
| `offset` | integer |  |  |  |
| `limit` | integer |  | `150` | Most members. |
| `mapping` | string |  |  | R8/ProGuard mapping.txt: shows and accepts original names; kept per package. |

Structured output: `descriptor`, `javaName`, `dexFile`, `access`, `super`, `interfaces`, `sourceFile`, `genericSignature`, `enclosingClass`, `enclosingMethod`, `innerClasses`, `kotlin`, `annotations`, `fields`, `methods`, `items`, `offset`, `total`, `original`, `limit`, `totalExact`, `hasMore`, `nextOffset`.

### disassemble_dex

**Disassemble DEX** (read-only, idempotent)

Smali (baksmali layout) of a DEX method or class (a class lists its method ids and sizes first); format=annotated adds code offsets. A jar or .class: the javap -c -p listing.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `path` | string | yes |  | An Android package, .dex, jar or .class. |
| `symbol` | string | yes |  | Method (Lpkg/C;->m(I)V, pkg.C::m, pkg.C::m(int)) or class (pkg.C, Lpkg/C;). |
| `format` | string |  |  | Output layout (default smali). Values: smali, annotated. |
| `offset` | integer |  |  |  |
| `maxTokens` | integer |  |  |  |
| `mapping` | string |  |  | R8/ProGuard mapping.txt: shows and accepts original names; kept per package. |

Structured output: `code`, `offset`, `nextOffset`, `totalChars`.

### decompile_java

**Decompile Java** (read-only, idempotent, open-world, long-running)

Java source of a class or method of an Android package or jar via JADX (CORVUS_JAVA_DECOMPILER, JDK 17+), or of a jar or .class via Vineflower (engine=vineflower, CORVUS_JAVA_DECOMPILER2). Members, anonymous and lambda classes come from the code they are written in. Without them: disassemble_dex.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `path` | string | yes |  | An .apk, .aab or split set, a .dex, a jar or a .class. |
| `symbol` | string | yes |  | Class (pkg.C, Lpkg/C;) or method (Lpkg/C;->m(I)V, pkg.C::m, pkg.C::m(int)). |
| `javaOnly` | boolean |  |  | Partial Java where JADX fails; default: smali there. |
| `engine` | string |  |  | jadx (default) or vineflower (class files only). Values: jadx. |
| `offset` | integer |  |  |  |
| `maxTokens` | integer |  |  |  |
| `mapping` | string |  |  | R8/ProGuard mapping.txt: shows and accepts original names; kept per package. |

Structured output: `code`, `offset`, `nextOffset`, `totalChars`.

### search_dex

**Search DEX code** (read-only, idempotent, long-running)

Search DEX code. kind=string: literals with method and offset per use; type: defined classes and type uses; method / field: defined and referenced members with use counts; const: numeric constants; opcode: instructions by mnemonic.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `path` | string | yes |  | An Android package, a .dex, or a jar with classes*.dex. |
| `kind` | string | yes |  | What to search. Values: string, type, method, field, const, opcode. |
| `query` | string | yes |  | Case-insensitive substring or * / ? pattern; for const a number. |
| `offset` | integer |  |  |  |
| `limit` | integer |  | `100` | Most hits. |
| `maxTokens` | integer |  |  |  |
| `mapping` | string |  |  | R8/ProGuard mapping.txt: shows and accepts original names; kept per package. |

Structured output: `items`, `offset`, `total`, `notes`, `limit`, `totalExact`, `hasMore`, `nextOffset`.

### find_dex_references

**Find DEX references** (read-only, idempotent, long-running)

Cross-references in DEX code, with method and code offset per instruction. direction=to: callers of a method, readers and writers of a field, uses of a class or string. from: what a method (or each method of a class) calls, reads, writes and loads. Methods match by exact id.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `path` | string | yes |  | An Android package, a .dex, or a jar with classes*.dex. |
| `target` | string | yes |  | Class, method (Lpkg/C;->m(I)V, pkg.C::m(int)), field (Lpkg/C;->f:I, pkg.C::f), "string". |
| `direction` | string |  |  | Default to: who refers to target. Values: to, from. |
| `kind` | string |  |  | How to read target (default auto; string: taken literally). Values: auto, class, method, field, string. |
| `offset` | integer |  |  |  |
| `limit` | integer |  | `100` | Most references. |
| `maxTokens` | integer |  |  |  |

Structured output: `target`, `targetKind`, `direction`, `items`, `offset`, `total`, `notes`, `limit`, `totalExact`, `hasMore`, `nextOffset`.

### map_java_dotnet

**Map Java and .NET** (read-only, idempotent)

Pairs across a Java / .NET bridge. .NET for Android (Xamarin, MAUI): Java wrapper classes and methods to .NET types and methods and back ([Register], crc64 names). Unity Mono: C# reaching Java via AndroidJavaClass / Object / Proxy / AndroidJNI, and back, with a confidence. A * / ? pattern lists pairs.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `symbol` | string | yes |  | Java class (Lpkg/C;, pkg.C) or method (Lpkg/C;->m(I)V), .NET symbol, or pattern. |
| `path` | string |  |  | Package whose assemblies to read; optional when they are loaded. |
| `offset` | integer |  |  |  |
| `limit` | integer |  | `100` | Most pairs. |
| `maxTokens` | integer |  |  |  |

Structured output: `query`, `direction`, `items`, `offset`, `total`, `notes`, `limit`, `totalExact`, `hasMore`, `nextOffset`.

### list_jni_bindings

**List JNI bindings** (read-only, idempotent, long-running)

Java native methods of an Android package paired with their code in lib/<abi>/*.so: Java_ exports by JNI name mangling and RegisterNatives tables; also unbound methods and stray Java_ exports.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `path` | string | yes |  | An .apk, .aab or split set (.apks, .xapk, .apkm). |
| `abi` | string |  |  | ABI to read, or all; default arm64-v8a, else the first. |
| `class` | string |  |  | Only rows naming this class (pkg.C or pkg/C). |
| `kind` | string |  |  | Only this kind. Values: static_export, registered, unresolved, export_only. |
| `offset` | integer |  |  |  |
| `limit` | integer |  | `75` | Most rows. |
| `maxTokens` | integer |  |  |  |

Structured output: `items`, `offset`, `total`, `libraries`, `notes`, `limit`, `totalExact`, `hasMore`, `nextOffset`.

### list_android_devices

**List Android devices** (read-only, idempotent, open-world)

Android devices and emulators adb sees: serial, state, product, model, transport. adb: CORVUS_ADB, else PATH, else SDK platform-tools.

No parameters.

Structured output: `items`, `unparsed`.

### get_android_device_info

**Android device info** (edit, open-world, long-running)

Device properties (getprop) with a summary: SDK, release, model, ABIs, fingerprint, patch level, build type, ro.debuggable, ro.secure, emulator; view=: processes, features, services, settings, files, screen (PNG), window (focused activity), display, bugreport (zip). Read-only.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `serial` | string |  |  | Device serial; optional with one device. |
| `query` | string |  |  | Name or value filter; view=files: directory (default /data/local/tmp); window: local APK. |
| `offset` | integer |  |  |  |
| `limit` | integer |  | `100` | Most rows. |
| `view` | string |  | `props` | What to read. Values: props, processes, features, services, settings, files, screen, window, display, bugreport. |
| `outputPath` | string |  |  | view=screen: new PNG path; bugreport: new or empty directory; default under temp. |

Structured output: `serial`, `summary`, `properties`, `offset`, `total`, `limit`, `totalExact`, `hasMore`, `nextOffset`.

### list_android_packages

**List installed packages** (read-only, idempotent, open-world)

Packages installed on a device (pm list packages -f -U -i): name, APK path, uid and installer.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `serial` | string |  |  | Device serial; optional with one device. |
| `query` | string |  |  | Only package names containing this. |
| `user` | integer |  |  | Android user id (default: current). |
| `offset` | integer |  |  |  |
| `limit` | integer |  | `150` | Most packages. |
| `maxTokens` | integer |  |  |  |

Structured output: `serial`, `items`, `offset`, `total`, `limit`, `totalExact`, `hasMore`, `nextOffset`.

### get_android_package_info

**Installed package info** (read-only, idempotent, open-world)

One installed package (dumpsys package): versions, SDKs, paths, ABI, flags, install times, installer, uid, requested permissions with their grant state, and per-user state.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `package` | string | yes |  | Package name, e.g. com.example.app. |
| `serial` | string |  |  | Device serial; optional with one device. |

Structured output: `serial`, `package`, `versionName`, `versionCode`, `minSdk`, `targetSdk`, `codePath`, `dataDir`, `primaryCpuAbi`, `flags`, `firstInstallTime`, `lastUpdateTime`, `installer`, `uid`, `permissions`, `users`.

### pull_android_package

**Pull installed package** (edit, idempotent, open-world, long-running)

Copy every APK of an installed package (base and splits) into a new or empty directory, with size and SHA-256 each, and summarize the base APK. A failed pull leaves no files.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `package` | string | yes |  | Package name, e.g. com.example.app. |
| `outputDirectory` | string | yes |  | A new or empty directory to write the APKs to. |
| `serial` | string |  |  | Device serial; optional with one device. |

Structured output: `serial`, `package`, `files`, `summary`.

### pull_android_file

**Pull device file** (destructive, idempotent, open-world, long-running)

Copies one device file (not a directory) to outputPath with its size and SHA-256; a failed pull leaves nothing.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `remotePath` | string | yes |  | Path on the device. |
| `outputPath` | string | yes |  | The local file to write. |
| `overwrite` | boolean |  |  | Replace outputPath if it exists. |
| `serial` | string |  |  | Device serial; optional with one device. |

Structured output: `remote`, `local`, `size`, `sha256`.

### read_android_log

**Read device log** (read-only, idempotent, open-world)

Device log (logcat -d), newest lines first, by buffer, process, tag, priority and start time.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `serial` | string |  |  | Device serial; optional with one device. |
| `pid` | integer |  |  | Only this process id. |
| `tag` | string |  |  | Only this log tag. |
| `priority` | string |  |  | Lowest priority. Values: V, D, I, W, E, F. |
| `since` | string |  |  | Only lines since this time ("01-31 12:00:00.000") or the last N lines. |
| `buffer` | string |  |  | Log buffer (default: main, system, crash). Values: main, system, crash, events, radio, all, default. |
| `offset` | integer |  |  | Lines to skip from the newest. |
| `limit` | integer |  | `500` | Most lines. |

Structured output: `serial`, `items`, `offset`, `total`, `limit`, `totalExact`, `hasMore`, `nextOffset`.

### install_android_package

**Install package on device** (destructive, open-world, long-running)

Install an APK, a split set or a folder of APKs on a device in one session; failures come back by INSTALL_FAILED_ code. Changes the device: needs the server option --allow-device-changes.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `path` | string | yes |  | An .apk, split set or folder of APKs. |
| `keepInstalled` | boolean |  |  | Fail if the app is installed instead of replacing it. |
| `downgrade` | boolean |  |  | Allow a lower version code. |
| `grantPermissions` | boolean |  |  | Grant all requested runtime permissions. |
| `serial` | string |  |  | Device serial; optional with one device. |

Structured output: `applied`, `dryRun`, `changes`, `editIds`, `failed`, `items`, `pushedTo`, `digest`.

### uninstall_android_package

**Uninstall package from device** (destructive, idempotent, open-world)

Remove an app (and its data unless keepData) from a device; needs the server option --allow-device-changes.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `package` | string | yes |  | Package name, e.g. com.example.app. |
| `keepData` | boolean |  |  | Keep app data and cache. |
| `serial` | string |  |  | Device serial; optional with one device. |

Structured output: `applied`, `dryRun`, `changes`, `editIds`, `failed`, `items`, `pushedTo`, `digest`.

## dumps

Crash dumps and crash text.

### open_minidump

**Open a crash dump** (read-only, idempotent, open-world, long-running)

Reads a Windows minidump (.dmp) or Linux/Android ELF core; returns the dump id. view=summary: OS, process, exception (thread, module!function, registers, C++ type), .NET state (managed exception and heap); modules (version, PDB, image match), threads, memory, unloaded: paged rows. .NET loads Microsoft's signature-checked DAC.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `path` | string | yes |  | The .dmp path (or an open dump's id). |
| `view` | string |  | `summary` | summary, modules, threads, memory or unloaded. |
| `offset` | integer |  |  |  |
| `limit` | integer |  | `50` |  |
| `imageDirectories` | string |  |  | Program binary folders (';'-separated), kept for the dump, plus its own folder. |
| `dacPath` | string |  |  | DAC (mscordaccore.dll / mscordacwks.dll) file or folder for a build not installed. |
| `downloadDac` | boolean |  |  | Fetch a matching DAC from a symbol server (network; refused under CORVUS_OFFLINE=1). |
| `maxTokens` | integer |  |  |  |

Structured output: `id`, `view`, `path`, `fileSize`, `timeUtc`, `dumpType`, `system`, `process`, `exception`, `managed`, `counts`, `faultingModule`, `faultingThread`, `handleTypes`, `issues`, `notes`, `items`, `offset`, `total`, `limit`, `totalExact`, `hasMore`, `nextOffset`.

### dump_stack

**Crash dump stack** (read-only, idempotent)

Call stack of a minidump thread: x64 unwind data, x86 call targets and EBP chain; JIT code without unwind data adds scanned frames. Names from loaded images (code index, PDB, Il2Cpp) or exports. .NET frames (DAC): token, IL offset, assembly, C# statement; Mono JIT frames from the runtime's report beside the dump. ELF cores: CFI, then frame pointer.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `dump` | string | yes |  | A .dmp path or the id open_minidump returned. |
| `thread` | string |  |  | Thread id, '#index', name or 'exception' (default: faulting thread, else first). |
| `dumpTimeContext` | boolean |  |  | Faulting thread: its context at dump time, not the exception context (.ecxr). |
| `maxFrames` | integer |  | `256` | Max frames walked (up to 1024). |
| `offset` | integer |  |  |  |
| `limit` | integer |  | `100` |  |
| `imageDirectories` | string |  |  | Program binary folders (';'-separated), kept for the dump, plus its own folder. |
| `managed` | string |  | `auto` | auto: .NET frames through the DAC; off: native walk only. Values: auto, off. |
| `maxTokens` | integer |  |  |  |

Structured output: `dump`, `threadId`, `threadName`, `context`, `architecture`, `registers`, `items`, `offset`, `total`, `stop`, `scannedFrames`, `managed`, `notes`, `limit`, `totalExact`, `hasMore`, `nextOffset`.

### dump_heap

**.NET heap of a dump or session** (read-only, idempotent, long-running)

Lists the .NET GC heap of a minidump or session (through the DAC). stats: count and size per type, largest first; objects: matching objects (address, type, size, a string's value). Needs heap memory in the dump (else heap_not_captured).

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `dump` | string | yes |  | A .dmp path, open_minidump's id, or a session id (live-1): its program, read while it runs. |
| `mode` | string |  | `stats` | stats (per type) or objects (one row each). Values: stats, objects. |
| `type` | string |  |  | Type full name, '*' / '?' wildcards; default all. |
| `minSize` | integer |  | `0` | Min object size in bytes. |
| `offset` | integer |  |  |  |
| `limit` | integer |  | `50` |  |
| `maxObjects` | integer |  | `5000000` | Max objects walked. |
| `maxTokens` | integer |  |  |  |

Structured output: `dump`, `mode`, `type`, `minSize`, `walked`, `matchedBytes`, `items`, `offset`, `total`, `totalExact`, `notes`, `limit`, `hasMore`, `nextOffset`.

### dump_object

**.NET object of a dump or session** (read-only, idempotent)

One .NET object of a dump or session (DAC): type, size, fields (references expanded depth levels), a string's or boxed value, or array elements.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `dump` | string | yes |  | A .dmp path, open_minidump's id, or a session id (live-1): its program, read while it runs. |
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
| `maxTokens` | integer |  |  |  |

Structured output: `dump`, `address`, `requested`, `length`, `source`, `location`, `region`, `protection`, `code`, `offset`, `note`, `nextOffset`, `nextAddress`, `totalChars`.

### symbolize_stack_text

**Symbolize crash text** (read-only, idempotent, long-running)

Resolve crash text against the loaded build: Unity Player.log, Mono and Il2Cpp lines, .NET exception text, Report.wer, Event Log 1000/1026, debugger stacks, Android tombstones. Each frame gets our name, a buildCheck (time stamp, MVID, BuildId or the text name; mismatch: another build) and the C# statement at an IL offset.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `text` | string |  |  | Crash text (up to 1 MiB); this or path. |
| `path` | string |  |  | A log or report file; its last 8 MiB are read. |
| `format` | string |  | `auto` | Text format (auto detects it). Values: auto, unity, dotnet, wer, eventlog, windbg, android. |
| `images` | string |  |  | Image ids or paths, ;-separated; default all loaded. |
| `moduleBases` | string |  |  | Module load addresses (name=0xBASE;...) when the text has no module list. |
| `offset` | integer |  |  |  |
| `limit` | integer |  | `50` |  |
| `allFrames` | boolean |  |  | One row per frame; default folds 3+ matching native frames of an image. |
| `maxTokens` | integer |  |  |  |

Structured output: `format`, `exception`, `frames`, `items`, `offset`, `total`, `unrecognizedLines`, `unrecognizedSample`, `modulesMissing`, `notes`, `limit`, `totalExact`, `hasMore`, `nextOffset`.

### bucket_minidumps

**Group crash dumps** (read-only, idempotent, long-running)

Group a folder of minidumps by signature: code | faulting module!function | next frames (raising frames skipped); .NET: clr | exception type | top managed frames; no exception: hang | top frames. Names, not offsets, so rebases do not split a bucket. Each bucket lists its dumps and newest one. Cached per file.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `folder` | string | yes |  | Folder of .dmp or core files. |
| `recursive` | boolean |  |  | Also search subfolders. |
| `pattern` | string |  |  | File patterns, ;-separated (default *.dmp;*.mdmp;*.core;core.*). |
| `topFrames` | integer |  | `3` | Frames after the faulting one in the signature. |
| `skipModules` | string |  |  | More frames to skip, ;-separated: module or module!function, * wildcards. |
| `splitByVersion` | boolean |  |  | Add the faulting module version to the signature. |
| `managed` | string |  | `auto` | auto: managed signatures through a local DAC; off: native only. Values: auto, off. |
| `maxDumps` | integer |  | `1000` | Most dumps bucketed, newest first. |
| `imageDirectories` | string |  |  | Program binary folders, ;-separated. |
| `offset` | integer |  |  |  |
| `limit` | integer |  | `50` |  |
| `maxTokens` | integer |  |  |  |

Structured output: `folder`, `dumps`, `items`, `offset`, `total`, `failed`, `notes`, `limit`, `totalExact`, `hasMore`, `nextOffset`.

## live

Running programs: read-only inspection, and sessions with stop points, call recording, code coverage, activity traces, scripted console runs and user scripts.

### inspect_process

**Inspect a running process (read-only)** (read-only, idempotent, open-world)

Inspects a running Windows process read-only, addresses named as in dumps. view=summary: identity, counts, main module, largest committed regions; modules (PDB, file on disk), regions, threads (TEB, stack, start), stacks (registers and frames): paged rows. Query, VM-read and get-context access only; nothing is written, suspended or connected.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `process` | string | yes |  | Process id (decimal or 0x hex), name (notepad[.exe]; a shared name is refused with the ids) or session id (live-1). |
| `view` | string |  | `summary` | summary, modules, regions, threads or stacks. |
| `thread` | string |  |  | threads: only this one; stacks: the thread walked (default first). Id or name. |
| `offset` | integer |  |  |  |
| `limit` | integer |  | `50` |  |
| `regionFilter` | string |  |  | regions: committed (default), all, executable, writable, image, private or mapped. Values: committed, all, executable, writable, image, private, mapped. |
| `maxFrames` | integer |  | `64` | view=stacks: max frames walked (up to 256). |
| `imageDirectories` | string |  |  | Program binary folders (';'-separated), for modules whose file is unreadable. |
| `timeoutSeconds` | integer |  | `20` | Time limit in seconds (up to 120). |
| `maxTokens` | integer |  |  |  |

Structured output: `processId`, `name`, `view`, `path`, `architecture`, `wow64`, `runtime`, `access`, `detached`, `handlesOpened`, `handlesClosed`, `stillRunning`, `notes`, `startTimeUtc`, `counts`, `mainModule`, `largestRegions`, `thread`, `stackStop`, `items`, `offset`, `total`, `limit`, `totalExact`, `hasMore`, `nextOffset`.

### live_session

**Session on a local program** (edit, open-world)

Open, list, inspect or close a session on a program: its id, backend and modules matched to images; snapshot saves the process as a dump.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `action` | string |  | `list` | What to do. Values: list, processes, attach, spawn, status, snapshot, close, children, attach_child, release_child. |
| `program` | string |  |  | attach: pid or name; spawn: program path (started suspended); processes: name filter; *_child: child pid. |
| `arguments` | string[] |  |  | spawn: program arguments. |
| `environment` | string[] |  |  | spawn: NAME=value variables. |
| `session` | string |  |  | Session id from live_session. |
| `outputPath` | string |  |  | snapshot: dump file (default: temp). |
| `overwrite` | boolean |  |  | Overwrite outputPath. |
| `childNames` | string[] |  |  | Hold child processes by image name (* any) at start. |
| `downloadDac` | boolean |  |  | Download a missing DAC. |

Structured output: `action`, `session`, `backend`, `program`, `processId`, `state`, `modules`, `sessions`, `processes`, `snapshot`.

### live_break

**Stop points in a session** (edit, open-world)

Set, list or clear stop points (name, module!export, file:line, address); continue resumes held threads; wait returns the next stop with a named stack.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `session` | string | yes |  | Session id from live_session. |
| `action` | string |  | `list` | What to do. Values: list, set, clear, continue. |
| `at` | string |  |  | set: a name, module!export, address or file:line. |
| `stopPoint` | string |  |  | clear: stop point id. |
| `thread` | string |  |  | continue: thread id; default all. |
| `wait` | boolean |  |  | Wait for the next stop. |
| `waitSeconds` | integer |  | `30` | wait: seconds (1-300). |

Structured output: `session`, `stopPoints`, `stop`, `namedAddresses`.

### live_watch

**Record calls in a session** (edit, open-world)

Record every call of a function with arguments and return value, decoded by prototype (PDB, DWARF) or known API, as events (live_events from=<watch>).

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `session` | string | yes |  | Session id from live_session. |
| `action` | string |  | `list` | What to do. Values: list, set, clear. |
| `at` | string |  |  | set: name, module!export or address. |
| `watch` | string |  |  | clear: watch id. |
| `rateLimit` | integer |  | `10000` | set: calls/s recorded (1-100000); the rest are counted. |
| `arguments` | integer |  | `4` | set: raw values without a prototype (0-16). |

Structured output: `session`, `watches`, `namedAddresses`.

### live_read

**Read a stopped thread** (read-only, idempotent, open-world)

Read a held thread's registers and program memory as typed values, named through the loaded images.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `session` | string | yes |  | Session id from live_session. |
| `thread` | string |  |  | Thread id; default the earliest held one. |
| `registers` | string |  |  | Register names, comma-separated; default all. |
| `memory` | string |  |  | An address, register or name to read. |
| `type` | string |  |  | memory: int8..uint64, float, double, pointer, cstring, utf16; [n] for arrays. |
| `length` | integer |  |  | memory: untyped bytes, or a string's limit (max 4096). |

Structured output: `session`, `thread`, `registers`, `memory`, `namedAddresses`, `code`, `offset`, `nextOffset`, `totalChars`.

### live_events

**Session events** (read-only, idempotent, open-world)

Page a session's event ring with a cursor and filters, so polling never re-sends earlier events.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `session` | string | yes |  | Session id from live_session. |
| `cursor` | string |  |  | Cursor from an earlier page; default the oldest event kept. |
| `kind` | string |  |  | Only this kind. Values: stop, call, script, exception, module, thread, child, output, error, exit. |
| `thread` | string |  |  | Only this thread id. |
| `from` | string |  |  | Only events of this watch or script id. |
| `limit` | integer |  | `100` |  |
| `maxTokens` | integer |  |  |  |

Structured output: `session`, `items`, `cursor`, `dropped`, `namedAddresses`.

### live_script

**User script in a session** (destructive, open-world)

Load, list or unload your own Frida script in a session's program; its messages become events (live_events from=<script>). Needs --live-scripting.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `session` | string | yes |  | Session id from live_session. |
| `action` | string |  | `list` | What to do. Values: list, load, unload. |
| `source` | string |  |  | load: JavaScript source. |
| `path` | string |  |  | load: a .js file instead. |
| `script` | string |  |  | unload: script id. |

Structured output: `session`, `scripts`.

### live_coverage

**Code coverage of a session** (edit, open-world)

Collect code coverage in a session: which functions of an image ran and how often, drawn on the static call graph; diff compares two runs.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `session` | string |  |  | Session id; start only. |
| `action` | string |  | `list` | What to do. Values: start, stop, list, report, diff. |
| `run` | string |  |  | Coverage run id (cov-1; omitted: the only run); diff: the first run. |
| `other` | string |  |  | diff: the run compared with. |
| `match` | string |  |  | Only functions whose name contains this; start: module!part for another module. |
| `hitLimit` | integer |  | `100` | start: stops counted per function before its point is cleared. |
| `show` | string |  | `ran` | report: ran, missed or all. Values: ran, missed, all. |
| `format` | string |  | `text` | report: text, or dot (call graph; offset counts characters). Values: text, dot. |
| `offset` | integer |  |  |  |
| `limit` | integer |  | `100` |  |

Structured output: `run`, `items`, `offset`, `total`, `runs`, `namedAddresses`, `code`, `nextOffset`, `totalChars`, `diff`, `limit`, `totalExact`, `hasMore`.

### live_timeline

**Activity trace of a session** (edit, open-world)

Collect a timestamped trace of the files, registry keys, endpoints and child processes a session's program opens, from the OS diagnostics channel (event tracing on Windows); entries page with a cursor, report counts each name, diff lists the names unique to each of two traces.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `session` | string |  |  | Session id; start only. |
| `action` | string |  | `list` | What to do. Values: start, stop, list, report, diff. |
| `run` | string |  |  | Timeline id (tl-1; omitted: the only one); list without it or a filter shows the timelines. |
| `a` | string |  |  | diff: the first timeline. |
| `b` | string |  |  | diff: the second timeline. |
| `category` | string |  |  | Only file, registry, network or process. Values: file, registry, network, process. |
| `match` | string |  |  | Only names containing this. |
| `cursor` | string |  |  | list: cursor from an earlier page; default the oldest entry kept. |
| `offset` | integer |  |  | Rows to skip. (report). |
| `limit` | integer |  | `100` |  |

Structured output: `run`, `items`, `cursor`, `runs`, `dropped`, `names`, `diff`.

### live_console

**Scripted console run** (edit, open-world)

Run a program under a console host (the pseudoconsole on Windows) driven by a script of send, wait, resize and delay steps; reports each step's outcome and pages the transcript with a cursor.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `action` | string |  | `list` | What to do. Values: start, stop, list, status, transcript. |
| `program` | string |  |  | start: program path. |
| `arguments` | string[] |  |  | start: program arguments. |
| `script` | string[] |  |  | start: steps, one per line: send TEXT, wait TEXT (output contains it), resize COLUMNS ROWS, delay MS; TEXT takes \r (Enter), \n, \t, \e, \xHH. |
| `run` | string |  |  | Console run id (con-1; omitted: the only one). |
| `timeoutSeconds` | integer |  | `10` | Seconds each wait step waits (1-300). |
| `cursor` | string |  |  | transcript: cursor from an earlier page; default the oldest line kept. |
| `limit` | integer |  | `100` |  |

Structured output: `run`, `items`, `cursor`, `runs`, `steps`, `dropped`.

## web

JavaScript bundles and their source maps.

### analyze_js

**Analyze a JavaScript bundle** (read-only, idempotent)

Bundler, modules and source map of a JavaScript file, statically. position: to the original; diff: with source=; runtime: webpack chunks; flow: values through calls, returns, closures, promises to effects, origins: back, unknowns marked. Hermes too.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `path` | string | yes |  | A .js or Hermes bundle, or an APK/.ipa. |
| `view` | string |  | `summary` | View. Values: summary, modules, module, search, refs, position, sources, source, endpoints, secrets, diff, runtime, flow, origins, functions, decompile, disassemble, xrefs. |
| `line` | integer |  |  | position, flow: 1-based generated line. |
| `column` | integer |  |  | See line. |
| `source` | string |  |  | source: path or index; diff: old bundle. |
| `query` | string |  |  | Module id; search filter; Hermes #id or name; flow: name, quoted literal, sinks, sink:KIND or module:ID. |
| `limit` | integer |  |  | flow: max flows (50). |
| `offset` | integer |  |  |  |
| `maxTokens` | integer |  |  |  |

Structured output: `view`, `summary`, `position`, `modules`, `total`, `hermes`, `functions`, `endpoints`, `secrets`, `diff`, `runtime`, `flow`.
