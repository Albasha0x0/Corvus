# NetDecompilerMcp

A headless .NET decompiler for AI agents, served over the [Model Context Protocol](https://modelcontextprotocol.io).
It decompiles, searches, cross-references and patches .NET assemblies, including Unity Mono games and
Il2CppDumper / Cpp2IL dummy DLLs. No GUI, no dnSpy instance, no admin rights and no network port.

- **Decompiler:** the ILSpy engine (`ICSharpCode.Decompiler`), the same one dnSpy uses.
- **Metadata, analysis and patching:** [dnlib](https://github.com/0xd4d/dnlib).
- **Transport:** stdio, using the official [MCP C# SDK](https://github.com/modelcontextprotocol/csharp-sdk).

## Why

Most dnSpy MCP integrations run inside the dnSpy GUI. That means dnSpy has to stay open, the HTTP listener needs
administrator rights, there's a dialog to click through on startup, and older MCP clients need an SSE↔stdio proxy.
This server is a single process that the MCP client starts and stops by itself.

Reliability features:

| Concern | How it is handled |
|---|---|
| Locked game files | Assemblies are read into memory; files on disk are never locked and can be replaced while loaded. |
| Concurrent tool calls | Reads share a lock; edits/loads take it exclusively, so no call sees a half-edited module. Covered by a parallel-calls test. |
| One broken method | `decompile_type` falls back to member-by-member output with IL for the part that fails. |
| Huge output | Every long result is paged (`offset` / `maxChars`); pages come from a cache, so paging doesn't re-decompile. |
| Runaway decompilation | Per-call timeout (default 180 s) with a clear message. |
| Vague symbol names | A resolver accepts many spellings and tokens; ambiguity and misses return candidate lists. |
| Unexpected exceptions | Returned to the agent as tool errors; the server keeps running. |
| Writing patches | Never overwrites the original without `overwrite=true`, keeps a `.bak`, and writes atomically. |

## Tools (32)

**Workspace:** `load_assembly` (file or whole folder) · `list_assemblies` · `unload_assembly` · `reload_assembly` ·
`add_search_directory` · `get_assembly_info` (identity, TFM, references and whether each resolves, PE headers and
sections, metadata streams, Il2Cpp detection)

**Browse:** `list_namespaces` · `list_types` (namespace, kind, wildcard or regex filter, paging) · `get_type_info` (outline
with tokens, constants, enum values, field offsets and RVAs) · `get_type_hierarchy` (base chain, interfaces, derived
types or implementors) · `get_attributes` (type, member, parameter, return value, assembly or module) · `resolve_symbol`

**Decompile:** `decompile_type` · `decompile_member` (all overloads, or one picked by parameter list; async, iterators and
lambdas are folded back into the original method) · `get_il` (ildasm-style, with tokens and structured try/catch
blocks) · `decompile_assembly_attributes` · `export_project` (whole assembly → .csproj plus one file per type)

**Search and cross-references:** `search_symbols` (substring, wildcard or regex) · `search_strings` (ldstr and string
constants) · `search_constants` (IL literals, const and enum values, attribute arguments) · `find_references`
(methods, fields with read/write/address-taken, properties, events, types in any position) · `find_callees` ·
`find_overrides` (virtual overrides and interface implementations)

**Resources:** `list_resources` · `get_resource` (text, hex dump or `.resources` entries; extract to disk)

**Il2Cpp:** `get_il2cpp_info` (RVA, VA, file offset and slot for methods; field offsets; tokens) ·
`find_method_by_address` (accepts IDA/Ghidra address formats; exact start, or the method that contains the address)

**Edit (in memory until saved):** `rename_symbol` · `rename_namespace` · `stub_method` (`return <value>;`) ·
`patch_method_il` (IL assembler, replace or prepend, stack-validated) · `save_assembly`.
Every edit tool supports `dryRun`.

### Symbol syntax

```
Ns.Type          Ns.Outer+Inner   Ns.Outer/Inner   Ns.Outer.Inner   Type (short name)
List`1           List<T>
Ns.Type::Method  Ns.Type.Method   Ns.Type::Method(int, string)      Ns.Type::.ctor
0x06000123       (metadata token; pass `assembly` when several assemblies are loaded)
```

### Patching IL

The easiest workflow is to call `get_il` on the method, edit the instruction lines, and pass them back to
`patch_method_il`. Header lines are ignored. The `/* 0A000025 */` token comments that `get_il` prints resolve
operands exactly. You can also write IL by hand:

```
ldarg.0
call System.String::IsNullOrEmpty(string)   // framework members resolve through the module's references
brtrue.s fail
ldc.i4.1
ret
fail:
ldc.i4.0
ret
```

`mode=prepend` inserts the code in front of the original body and can branch into it by its offsets (`bge IL_0000`).
`.local <type>` declares a new local variable.

## Requirements

- .NET 10 SDK (to build). The published server needs the .NET 10 runtime, or none at all if you publish it self-contained.
- Windows, Linux or macOS. `publish.ps1` targets win-x64; use `dotnet publish -r <rid>` for other platforms.

## Build and test

```powershell
dotnet test                 # 74 tests, including stdio end-to-end and parallel-call tests
./publish.ps1               # -> publish/NetDecompilerMcp.exe
./publish.ps1 -SelfContained
```

## Configure an MCP client

Claude Code:

```powershell
claude mcp add net-decompiler -s user -- "C:\path\to\publish\NetDecompilerMcp.exe"
```

Generic `mcpServers` JSON (Claude Desktop, Cursor, and others):

```json
{
  "mcpServers": {
    "net-decompiler": {
      "command": "C:\\path\\to\\publish\\NetDecompilerMcp.exe",
      "args": ["--load", "D:\\Game\\Game_Data\\Managed"]
    }
  }
}
```

Command-line options:

| Option | Meaning |
|---|---|
| `--load <path>` | Assembly file or folder to load at startup (repeatable). The `NETDECOMP_LOAD` env var takes `;`-separated paths. |
| `--search-dir <dir>` | Extra directory for resolving references (repeatable). |
| `--max-output <chars>` | Page size for long results (default 60000). |
| `--timeout <seconds>` | Decompilation timeout per call (default 180; `export_project` gets 10×). |

Logs go to stderr. stdout is reserved for the protocol.

## Layout

```
src/NetDecompilerMcp/
  Core/       workspace (loading, locking, reference resolution), symbol resolver, formatting, paging
  Services/   decompiler, analysis (search/xrefs), Il2Cpp, resources, edits, IL assembler
  Tools/      thin MCP tool classes; each one resolves input, calls a service, and formats text
tests/
  TestFixture/              sample assembly covering every feature (inheritance, async, resources, fake Il2Cpp attributes)
  NetDecompilerMcp.Tests/   service tests and stdio end-to-end tests
```

To add a tool, put the logic in a service, then add a `[McpServerTool]` method in `Tools/` that wraps it in
`ToolSupport.Read` (or `Write` if it mutates) and returns text. Throw `ToolError` for anything the agent should
read and act on.
