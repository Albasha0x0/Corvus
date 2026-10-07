# NetDecompilerMcp

A headless .NET decompiler for AI agents, served over the [Model Context Protocol](https://modelcontextprotocol.io).
It decompiles, searches, cross-references and patches .NET assemblies, including Unity Mono games and
Il2CppDumper / Cpp2IL dummy DLLs. No GUI, no dnSpy instance, no admin rights and no network port.

- **Decompiler:** the ILSpy engine (`ICSharpCode.Decompiler`), the same engine dnSpy uses.
- **Metadata and patching:** [dnlib](https://github.com/0xd4d/dnlib), plus a fast `System.Reflection.Metadata` IL scanner.
- **C# method patching:** Roslyn.
- **Transport:** stdio, using the official [MCP C# SDK](https://github.com/modelcontextprotocol/csharp-sdk).

## What it covers

**MCP features:** 54 tools (every one with a title and read-only / destructive / closed-world annotations),
resources and resource templates, 5 prompts, argument completion, progress notifications, structured output
(`list_assemblies`, `unpack_container`, `search_container`, `summarize_file`, `survey_features`, `extract_strings`, `extract_embedded`), cancellation, server instructions, and workspace notices (files reloaded from disk) at the top
of the next tool result, plus best-effort `resources/list_changed` and log notifications.

| Area | Tools |
|---|---|
| Workspace | `load_assembly` (a file or a whole folder; reports progress) · `list_assemblies` (ids, versions, ReadyToRun, merged-assembly label, unsaved edits; `filter` / `offset` / `limit` for big folders; with `path`, the managed assemblies inside a container file without extracting them) · `unload_assembly` · `reload_assembly` · `add_search_directory` · `get_assembly_info` (identity, TFM, references and whether each resolves (to the loaded build in the same folder first), PE headers and sections, metadata streams, attributes, Il2Cpp detection, method bodies that are not valid IL — encrypted or dumped before decryption, also flagged in decompiled code and comparisons) |
| Browse | `list_namespaces` · `list_types` · `get_type_info` (outline with tokens, constants, hex enum values, IL sizes, Il2Cpp RVAs and offsets) · `get_type_hierarchy` · `get_attributes` (type, member, parameter, return value, assembly or module) · `resolve_symbol` |
| Decompile | `decompile_type` · `decompile_member` (overloads, async, iterators and lambdas folded back) · `get_il` (tokens, offsets, structured EH) · `decompile_assembly_attributes` · `export_project` (whole assembly → .csproj; reports progress and failed types) |
| Search | `search_symbols` (substring, wildcard or regex) · `search_strings` · `search_constants` (IL literals, const and enum values, attribute arguments, and elements of static array data such as crypto round constants and CRC tables for values of 0x10000 and up) · `search_il` (instruction-sequence patterns with wildcards and gaps) |
| Cross-references | `find_references` (methods, including calls dispatched through base/interface methods; fields with read/write/address; properties; events; types in every position: base, interface, constraint, field/param/return/local, catch, attribute, cast, newobj) · `find_callees` · `find_overrides` (paged) |
| Call graph | `get_call_tree` (callers or callees N levels deep, breadth-first so a node budget cuts the deepest level; repeats, recursion and virtual dispatch marked) · `find_call_paths` (shortest call chains from a method or from entry points to a target; direct calls preferred, virtual-dispatch hops marked, `includeVirtual=false` for direct calls only) |
| Compare builds | `compare_assemblies` (added/removed/renamed types and members, signature, body, field-offset and RVA changes; renamed members matched by IL fingerprints and strings; compiler-generated closures, state machines, backing fields and array data are hidden and counted unless `includeCompilerGenerated=true`) · `find_counterpart` (where did this type/member go in the new build) |
| Resources | `list_resources` · `get_resource` (text, hex, `.resources` entries, WPF `.baml` entries as XAML; extract to disk) |
| Containers | `unpack_container` (single-file bundles, Costura, NuGet, Xamarin / MAUI APKs, embedded images; extracts and loads the assemblies, each labelled ReadyToRun / merged) · `search_container` (types and members by name across every assembly in a container, without extracting; capped, with a truncation flag). See [Unpacking containers](#unpacking-containers) |
| File inspection | `summarize_file` (one report: hashes, identity, strong name and Authenticode with digest check, protector markers, packing, features, typed strings, entry points; opens containers) · `survey_features` (capa-style rules over APIs, P/Invoke imports and strings, with ATT&CK techniques and evidence) · `extract_strings` (URLs, domains, IPs, paths, registry keys, mutexes, user agents, crypto keys; JSON / CSV export) · `extract_embedded` (resources, static arrays and strings decoded through base64 / hex / gzip / deflate / XOR). See [File inspection](#file-inspection) |
| Il2Cpp | `get_il2cpp_info` (RVA, VA, file offset, slot, field offsets, tokens) · `find_method_by_address` (IDA/Ghidra address formats; exact start or containing method; dumper garbage addresses of methods without native code are ignored) · `export_il2cpp_symbols` (IDA and Ghidra scripts that name every function, a C header with struct layouts, and JSON) |
| Native bindings | `generate_cpp_binding` (C++ binding for a type in a Mono game or app: class lookup, field/static offsets, method lookups with exact overloads, typed accessors and invoke wrappers; base-class members named in `members` (e.g. a singleton's static `Instance` on a generic base) bound through the hierarchy. Style `mono`: a self-contained header on the standard Mono embedding API. Style `hostapi`: for projects whose host passes a function table; with `projectDir`, the table, its handle types, the helpers' headers and namespace are detected and `#include` paths are computed relative to `headerPath`; value types use the table's `EmbeddedStructOffset` / `GetValueTypeSize` when it has them. Without `style`: detected from `projectDir`, else the server's `--binding-style`, else `mono`; the header's first line says which and why) |
| Patch (in memory, `dryRun` on all) | `rename_symbol` · `rename_namespace` · `stub_method` · `patch_method_csharp` (new body in C#: lambdas, async, `yield`, LINQ, private/internal members accessible) · `add_members_csharp` (new methods, fields, properties, nested types) · `add_types_csharp` (whole new classes) · `patch_method_il` (IL assembler that accepts edited `get_il` output; replace or prepend) · `save_assembly` (never overwrites without `overwrite=true`, keeps `.bak`, atomic write) |
| Edit history | `list_edits` · `diff_edits` (before/after decompiled C# of pending edits) · `undo_edit` · `revert_edits` · `export_edits` / `apply_edits` (replayable JSON edit scripts: re-apply a patch set to a new game build; a dry run applies and compiles every edit, then rolls back) |

**Resources:** `netdecomp://assemblies`, `netdecomp://assembly/{assembly}/info`, `netdecomp://assembly/{assembly}/type/{type}`
(decompiled C#), `netdecomp://assembly/{assembly}/il/{symbol}`.

**Prompts:** `analyze_assembly`, `find_feature`, `explain_type`, `plan_patch`, `map_native_address`.

**Completion:** assembly ids, type names (full or short), and file paths for prompt and resource-template arguments.

### Compared with [tuna1999/dnspy-mcp](https://github.com/tuna1999/dnspy-mcp)

| | dnspy-mcp | NetDecompilerMcp |
|---|---|---|
| Runs without dnSpy / GUI | headless mode only (36 tools) | always (54 tools) |
| Cross-references | methods and fields (`get_xrefs_to`) | methods (incl. virtual/interface dispatch), fields (read/write/address), properties, events, types in every position, overrides, hierarchy with derived types |
| Search | types, methods, strings, `grep` | symbols (wildcard/regex, all member kinds), strings, numeric constants, IL instruction patterns |
| Method patching | C# statements (`update_method_body`) | C# bodies with lambdas/async/LINQ (Roslyn, private access, ctor initializers preserved), new members and types, IL assembler (accepts edited `get_il` output, prepend hooks), constant stubs |
| Undo, diffs, edit scripts | — | undo / revert, before/after C# diffs, replayable edit scripts |
| Call trees, build comparison | — | multi-level call trees and call paths; build-to-build diff with rename matching |
| Saving patched DLLs | no (in-memory only) | yes: `.bak`, atomic write, stable tokens |
| Il2Cpp dummy DLLs | not supported | addresses, field offsets, native address → method, IDA/Ghidra scripts and C header, C++ bindings |
| Resources | list and raw bytes | text/hex view, `.resources` entries, extraction |
| Whole-project export | `decompile_assembly` (first 10 types) | full .csproj with progress |
| MCP resources / prompts / completion / progress | — | yes |
| Large output | truncation | paging with cached pages |

## Reliability

| Concern | How it is handled |
|---|---|
| Locked game files | Assemblies are read into memory; files on disk are never locked. |
| Concurrency | Reads share a lock; edits take it exclusively. Stress-tested with interleaved readers and writers, and with 40 parallel MCP calls. |
| Corrupt or obfuscated bodies | The IL scanner stops at invalid opcodes instead of throwing; `decompile_type` falls back to member-by-member output with IL for the broken part. |
| Huge output | Paged (`offset` / `maxChars`); pages come from a cache. |
| Files changing on disk | Watched: clean assemblies reload automatically; ones with unsaved edits are left alone and the agent is told. |
| Slow first queries | Method bodies are indexed and the call graph is built in the background after loading, in small chunks that never block edits. |
| Runaway work | Per-call timeout (default 180 s) and MCP cancellation. |
| Vague names | A symbol resolver accepts many spellings and tokens; ambiguity and misses return candidates. |
| Unexpected exceptions | Returned as tool errors; the server keeps running. |
| Invalid patches | IL is stack-validated, C# is compiled (errors point at your line), and nothing changes on failure. Patched assemblies are executed in the tests to prove the IL is valid at runtime. |

Measured on a real game (36 assemblies, 40,895 types, ~300k methods):

- Load all assemblies: 94 ms.
- Decompile every one of 23,327 game types concurrently: 40 s, with 0 failures.
- First full string search: 2.7 s; repeat searches: 0.3 s.
- Type cross-references across everything: 1.9 s.
- Compare two builds of the main game assembly (11k types): about 5 s.
- Export IDA/Ghidra scripts and a C header for a whole Il2Cpp dump (93k functions, 9k structs): 3.6 s; the header compiles with clang.

## Unpacking containers

`unpack_container` takes a file, extracts the .NET code inside it, and loads the assemblies it finds (`load=false`
to only extract). It reads bytes only and never runs the file. When an extracted file is itself a container
(for example a Costura-packed app inside a single-file bundle, or a `.nupkg` inside a zip), it is opened too,
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
lists the entries before the damage, read from their local headers, with a note. A container with nothing readable
returns a tool error that says what is wrong. Without
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

Malformed and hostile input is expected:

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
| `summarize_file` | File hashes, type and entropy; per assembly: identity (name, version, MVID, target framework, GUI / console / library, architecture, ReadyToRun, merged), strong name and Authenticode signature, protector markers and heuristics, packing (embedded assemblies, decoded embedded content, high-entropy sections), features, a summary of typed strings, and entry points (Main, module initializers, native exports, installer / service / AppDomainManager / COM hooks). `highlights` lists the notable findings. |
| `survey_features` | Rules over the APIs the code calls, the native functions it imports and its string literals, in categories: network, execution, registry, persistence, collection, credential access, anti-analysis, defense evasion, code loading, injection, discovery, crypto. Each matched feature has its evidence (pattern, count, up to 5 locations) and an ATT&CK technique where the operation is the technique itself. `category` filters by category or technique prefix. |
| `extract_strings` | URLs, domains, IPv4 / IPv6, email addresses, file paths, named pipes, registry keys, mutex names, user agents and crypto keys from string literals, constants, resource text and decoded embedded text, with the APIs each value is passed to. `savePath` exports JSON or CSV (it refuses to replace a file unless `overwrite=true`). |
| `extract_embedded` | Embedded resources, `.resources` entries, static byte arrays and string literals of 64+ characters, decoded through hex, base64, gzip / zlib / deflate and XOR until a recognized kind appears (PE / .NET images, archives, ELF / Mach-O, text), plus high-entropy blobs. Each item shows its source and encoding chain, e.g. `base64 > xor key 5a > gzip`. `save=true` writes them with defanged names; `load=true` also loads the .NET ones; `xorText=true` adds a single-byte XOR search over text (see below); images (png, jpeg, gif, ico) are only counted unless `includeMedia=true`. |

Limits:

- **Features describe API use.** A rule matches when the code calls, imports or contains what the rule lists (an
  HTTP client call matches "send HTTP requests"); it does not tell whether or when the code runs.
- **XOR keys are recovered from known file headers** (PE, ZIP, gzip), so XOR is undone when it covers a binary or
  compressed item, with keys up to the header's length (up to 3 bytes for gzip, 4 for ZIP, 16 for PE). XOR straight
  over plain text has no known plaintext to recover a key from, so by default it is not decoded.
- **`xorText=true`** (`extract_embedded`, off by default) tries all 255 single-byte keys on resources and arrays that
  are not readable as they are. A decode is kept only when it is ASCII text of 32 bytes or more with 3-40% spaces,
  mostly letters, spaces and common punctuation, clearly better than the input, and not UTF-16-shaped (one byte value
  in 40% or more of the even or odd positions). Such items show `xor key NN (brute-forced)` in their chain. Multi-byte
  keys, UTF-16 and non-ASCII text are not recovered; the search costs up to 255 passes over each candidate (sampled to
  4 KB).
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
patch_method_csharp  method="Game.Player::TakeDamage(int)"
                     code="if (amount < 0) return; _health -= amount / 2;"
```

The body is compiled as a static helper against the real assembly (with accessibility checks off), `this` and implicit
members rewritten to the instance. The new IL is then transplanted, with references mapped back to the original
definitions and reference scopes. Lambdas, closures, async, `yield`, LINQ and local functions work: the compiler-generated
closure and state-machine types are copied into the target. Members that would be inaccessible at runtime are relaxed,
or an `IgnoresAccessChecksTo` attribute is added for other assemblies.

**New members and types:**

```
add_members_csharp  type="Game.Shop"  code="private int _bonus; public int Bonus(int x) => x + _bonus;"
add_types_csharp    assembly="Game"   code="namespace Mods { public static class Cheats { public static void On() { } } }"
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

## Build, test, publish

Requires the .NET 10 SDK.

```powershell
dotnet test                    # 344 tests: services, IL/C# patching (with runtime execution), edit history,
                               # build comparison, call graph, IDA/Ghidra/C/C++ generation (compiled with clang),
                               # background indexing, file watching, every tool over stdio, real-assembly stress,
                               # container unpacking and listing (fixtures built at test time, incl. crossgen2 ReadyToRun
                               # output) with truncation/fuzz/path-traversal cases, merged-assembly detection,
                               # file inspection (features, typed strings, embedded-content decoding, Authenticode, fuzzed inputs),
                               # invalid-IL detection, reference binding across side-by-side builds
./publish.ps1                  # -> publish/NetDecompilerMcp.exe (needs the .NET 10 runtime)
./publish.ps1 -SelfContained   # no runtime needed
```

Some tests run against real-world data, found through environment variables. Each is skipped when its variables
are unset:

| Variable | What it points to | Tests |
|---|---|---|
| `NDM_MONO_GAME_DIR` | A Mono game's `Managed` folder (or any folder of real .NET assemblies) | decompile / search / xrefs / C# patch of the app's own code; call-path timing |
| `NDM_CALLPATH_TARGET` | Optional: a method in that game to search call paths to (default: picked automatically) | call-path timing |
| `NDM_IL2CPP_DUMMY_DIR` | An Il2CppDumper / Cpp2IL `DummyDll` folder | address round-trips; IDA / Ghidra / C header export |
| `NDM_COMPARE_OLD_DIR`, `NDM_COMPARE_NEW_DIR` | Two builds of the same app | build comparison |
| `NDM_COMPARE_ASSEMBLY` | Optional: the assembly to compare (default: the largest application assembly in both) | build comparison |
| `NDM_COMPARE_EXPECT` | Optional: known type moves to check, `Old.Name=>New.Name;Old2=>New2` | build comparison |
| `NDM_HOSTAPI_PROJECT_DIR` | Root of a C/C++ project with a host function table | `hostapi` detection on a real project; bindings compile against its headers |

The generated C, C++ and Python are compiled or parsed with clang (`C:\Program Files\LLVM\bin`) and python when
they are installed.

CI (`.github/workflows/ci.yml`) runs the tests on Windows, Linux and macOS. The tests publish hello-world apps and
download runtime / crossgen2 packs and NuGet packages at test time; CI keeps them in one package folder, cached per OS,
SDK version and project files. Real-data tests have no data there and report as skipped. Pushing a `v*` tag runs
`release.yml`, which attaches self-contained single-file builds for win-x64, linux-x64 and osx-arm64 to a GitHub release.

## Configure an MCP client

Claude Code:

```powershell
claude mcp add net-decompiler -s user -- "C:\path\to\publish\NetDecompilerMcp.exe"
# per project, preloading a game:
claude mcp add net-decompiler -s local -- "C:\path\to\publish\NetDecompilerMcp.exe" --load "D:\Game\Game_Data\Managed"
```

Generic `mcpServers` JSON (Claude Desktop, Cursor, and others):

```json
{ "mcpServers": { "net-decompiler": { "command": "C:\\path\\to\\publish\\NetDecompilerMcp.exe", "args": ["--load", "D:\\Game\\Managed"] } } }
```

Codex (`config.toml`):

```toml
[mcp_servers.net-decompiler]
command = 'C:\path\to\publish\NetDecompilerMcp.exe'
args = ['--load', 'D:\Game\Managed']
```

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

## Layout

```
src/NetDecompilerMcp/
  Core/      workspace (loading, locking, reference resolution), symbol resolver, formatting, paging
  Services/  decompiler, search, references, fast IL reader, call graph, assembly comparer, Il2Cpp (+ IDA/Ghidra/C
             export), C++ binding generator, resources, assembly report, edits and edit history, IL assembler,
             C# patcher (module merger, access fixer), background indexing, file watching
    Analysis/  bounds-checked PE parsing, byte-level helpers (identification, bounded decompression, carving, safe
               output paths), container formats, unpacking
  Tools/     thin MCP tool classes: resolve input, call a service, format text
  Mcp/       resources, prompts, completion
tests/
  TestFixture/            sample assembly covering every feature (inheritance, async, resources, fake Il2Cpp attributes)
  TestFixture.Consumer/   second assembly that uses the first (cross-assembly and virtual-dispatch references)
  NetDecompilerMcp.Tests/ service, patching, concurrency, protocol and real-assembly tests
```

To add a tool, put the logic in a service, then add a `[McpServerTool]` method in `Tools/` that wraps it in
`ToolSupport.Read`, `Write` or `Edit` and returns text. Throw `ToolError` for anything the agent should read and
act on. `McpProtocolTests.ToolCases` must get an entry, or the coverage test fails.

## License

MIT. See [LICENSE](LICENSE).
