---
name: net-decompiler
description: "Reverse engineering of compiled .NET assemblies and native PE, ELF and Mach-O binaries with the net-decompiler MCP server or its NetDecompilerMcp command line: decompile, search, follow calls, compare builds, read crash dumps, patch and save a copy. Use when an answer depends on what a compiled program does (an .exe or .dll, a Unity or Il2Cpp game build, a package without source, a crash dump, two builds of one app). Skip it when the source code is at hand."
---

# net-decompiler

<!-- Generated from src/NetDecompilerMcp/Mcp/Guide.cs; run the tests with NDM_UPDATE_DOCS=1 to update. -->

## Server guidance

Reverse engineering of .NET assemblies and native PE files (x86/x64). Reads bytes only; nothing is executed.
Start: load_assembly(path) takes a file or a folder (.NET or native .exe/.dll/.sys); results name an id (app.dll, app.dll#2) that later calls take as assembly or image. Unknown file: summarize_file. Wrapped apps (single-file, .apk, .nupkg, Costura): list_assemblies path=..., unpack_container. Unity: unity_overview. Il2Cpp: load the game folder or global-metadata.dat.
.NET: find with search_symbols, search_strings, search_constants, search_il; outline with get_type_info; read with decompile_member (one method, cheapest), decompile_type, get_il; follow with find_references, find_callees, get_call_tree, find_call_paths, find_overrides, get_type_hierarchy.
Native: get_pe_info, list_imports, list_exports, list_functions, find_xrefs ('kernel32!CreateFileW'), disassemble, native_call_tree, decompile_native (IDA or Ghidra; server_status says which).
Edit in memory, dryRun=true first: rename_symbol, stub_method, patch_method_csharp, patch_method_il, simplify_methods (folds string decoders); native rename_native, patch_bytes, patch_asm. Review list_edits / diff_edits, undo_edit; save_assembly / save_native write a new file.
New build: load both, then update_to_new_build (dryRun) or compare_assemblies / compare_native_images.
Rules: an error reads "Error (<code>)" with a Next: line; follow it. limit_exceeded returns an id: read_result pages it. Long text: pass the footer's offset=N. Lists also return structured items/offset/total. Symbols: Ns.Type::Method(int), short names, or tokens (0x06000123).
More: the guide prompt or netdecomp://guide/{topic} (dotnet, native, il2cpp, containers, edits, builds, dumps, errors); server_status for version, engines, limits, toolsets and a stale-server check.

## Connect only when needed

If the net-decompiler tools are available, use them. If they are not:

1. `NetDecompilerMcp status --client <id>` says whether this client has the server registered and whether it starts.
2. `NetDecompilerMcp install --client <id> --yes` registers it; then restart the client and call `server_status`.

Without the `NetDecompilerMcp` command, install it first (see the project README); this skill does not include the server.

## Terminal fallback

With only a shell, every tool runs from the command line through the same server code:

```sh
NetDecompilerMcp tools                                   # the tools by toolset
NetDecompilerMcp describe decompile_member               # parameters and an example
NetDecompilerMcp decompile_member --load app.dll member=Ns.Type::Method
NetDecompilerMcp find_references --load app.dll symbol=Ns.Type::Method --json
NetDecompilerMcp batch steps.jsonl                       # several calls in one session
```

A batch file holds one `{"tool": "...", "args": {...}}` object per line; ids such as `app.dll#2` and unsaved
edits carry from line to line. Exit codes: 0 success, 1 tool error, 2 usage or invalid argument, 3 engine
missing or unsupported, 124 timeout, 130 cancelled.

## Evidence

- Separate what a tool showed (cite the token, address or file offset and the tool) from inferences and unknowns.
- A search that finds nothing is not proof of absence: name what was searched and what was not loaded.
- Edits stay in memory until saved; preview with `dryRun=true`, and save to a new file.

## Topics

The full guidance per area, also served by the `guide` prompt and `netdecomp://guide/{topic}`:

- [dotnet](references/guide-dotnet.md)
- [il2cpp](references/guide-il2cpp.md)
- [containers](references/guide-containers.md)
- [edits](references/guide-edits.md)
- [builds](references/guide-builds.md)
- [native](references/guide-native.md)
- [dumps](references/guide-dumps.md)
- [errors](references/guide-errors.md)
