# NetDecompilerMcp

A headless .NET decompiler for AI agents, served over the [Model Context Protocol](https://modelcontextprotocol.io).
It decompiles, searches, cross-references and patches .NET assemblies, including Unity Mono games and
Il2CppDumper / Cpp2IL dummy DLLs. No GUI, no dnSpy instance, no admin rights and no network port.

- **Decompiler:** the ILSpy engine (`ICSharpCode.Decompiler`), the same engine dnSpy uses.
- **Metadata and patching:** [dnlib](https://github.com/0xd4d/dnlib), plus a fast `System.Reflection.Metadata` IL scanner.
- **C# method patching:** Roslyn.
- **Transport:** stdio, using the official [MCP C# SDK](https://github.com/modelcontextprotocol/csharp-sdk).

## What it covers

**MCP features:** 48 tools (every one with a title and read-only / destructive / closed-world annotations),
resources and resource templates, 5 prompts, argument completion, progress notifications, structured output
(`list_assemblies`), cancellation, server instructions, and workspace notices (files reloaded from disk) at the top
of the next tool result, plus best-effort `resources/list_changed` and log notifications.

| Area | Tools |
|---|---|
| Workspace | `load_assembly` (a file or a whole folder; reports progress) · `list_assemblies` · `unload_assembly` · `reload_assembly` · `add_search_directory` · `get_assembly_info` (identity, TFM, references and whether each resolves, PE headers and sections, metadata streams, attributes, Il2Cpp detection) |
| Browse | `list_namespaces` · `list_types` · `get_type_info` (outline with tokens, constants, hex enum values, IL sizes, Il2Cpp RVAs and offsets) · `get_type_hierarchy` · `get_attributes` (type, member, parameter, return value, assembly or module) · `resolve_symbol` |
| Decompile | `decompile_type` · `decompile_member` (overloads, async, iterators and lambdas folded back) · `get_il` (tokens, offsets, structured EH) · `decompile_assembly_attributes` · `export_project` (whole assembly → .csproj; reports progress and failed types) |
| Search | `search_symbols` (substring, wildcard or regex) · `search_strings` · `search_constants` (IL literals, const and enum values, attribute arguments) · `search_il` (instruction-sequence patterns with wildcards and gaps) |
| Cross-references | `find_references` (methods, including calls dispatched through base/interface methods; fields with read/write/address; properties; events; types in every position: base, interface, constraint, field/param/return/local, catch, attribute, cast, newobj) · `find_callees` · `find_overrides` |
| Call graph | `get_call_tree` (callers or callees N levels deep; repeats, recursion and virtual dispatch marked) · `find_call_paths` (shortest call chains from a method or from entry points to a target) |
| Compare builds | `compare_assemblies` (added/removed/renamed types and members, signature, body, field-offset and RVA changes; renamed members matched by IL fingerprints and strings) · `find_counterpart` (where did this type/member go in the new build) |
| Resources | `list_resources` · `get_resource` (text, hex, `.resources` entries; extract to disk) |
| Il2Cpp | `get_il2cpp_info` (RVA, VA, file offset, slot, field offsets, tokens) · `find_method_by_address` (IDA/Ghidra address formats; exact start or containing method) · `export_il2cpp_symbols` (IDA and Ghidra scripts that name every function, a C header with struct layouts, and JSON) |
| Native bindings | `generate_cpp_binding` (ModHost-style C++: `FindClass`, field/static offsets, `GetMethod`/`GetMethodExact` lookups, typed accessors and invoke wrappers) |
| Patch (in memory, `dryRun` on all) | `rename_symbol` · `rename_namespace` · `stub_method` · `patch_method_csharp` (new body in C#: lambdas, async, `yield`, LINQ, private/internal members accessible) · `add_members_csharp` (new methods, fields, properties, nested types) · `add_types_csharp` (whole new classes) · `patch_method_il` (IL assembler that accepts edited `get_il` output; replace or prepend) · `save_assembly` (never overwrites without `overwrite=true`, keeps `.bak`, atomic write) |
| Edit history | `list_edits` · `diff_edits` (before/after decompiled C# of pending edits) · `undo_edit` · `revert_edits` · `export_edits` / `apply_edits` (replayable JSON edit scripts: re-apply a patch set to a new game build) |

**Resources:** `netdecomp://assemblies`, `netdecomp://assembly/{assembly}/info`, `netdecomp://assembly/{assembly}/type/{type}`
(decompiled C#), `netdecomp://assembly/{assembly}/il/{symbol}`.

**Prompts:** `analyze_assembly`, `find_feature`, `explain_type`, `plan_patch`, `map_native_address`.

**Completion:** assembly ids, type names (full or short), and file paths for prompt and resource-template arguments.

### Compared with [tuna1999/dnspy-mcp](https://github.com/tuna1999/dnspy-mcp)

| | dnspy-mcp | NetDecompilerMcp |
|---|---|---|
| Runs without dnSpy / GUI | headless mode only (36 tools) | always (48 tools) |
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
and by name on a new one.

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
dotnet test                    # 208 tests: services, IL/C# patching (with runtime execution), edit history,
                               # build comparison, call graph, IDA/Ghidra/C/C++ generation (compiled with clang),
                               # background indexing, file watching, every tool over stdio, real-assembly stress
./publish.ps1                  # -> publish/NetDecompilerMcp.exe (needs the .NET 10 runtime)
./publish.ps1 -SelfContained   # no runtime needed
```

Some tests use real-world data that only exists on the author's machine (a game folder, an Il2CppDumper output,
clang). They are skipped automatically when the paths are missing.

CI (`.github/workflows/ci.yml`) runs the tests on Windows, Linux and macOS. Pushing a `v*` tag runs
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

Logs go to stderr; stdout is reserved for the protocol.

## Layout

```
src/NetDecompilerMcp/
  Core/      workspace (loading, locking, reference resolution), symbol resolver, formatting, paging
  Services/  decompiler, search, references, fast IL reader, call graph, assembly comparer, Il2Cpp (+ IDA/Ghidra/C
             export), C++ binding generator, resources, assembly report, edits and edit history, IL assembler,
             C# patcher (module merger, access fixer), background indexing, file watching
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
