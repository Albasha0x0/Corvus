# Guide: dotnet

<!-- Generated from src/Corvus/Mcp/Guide.cs; run the tests with CORVUS_UPDATE_DOCS=1 to update. -->

.NET assemblies.
- load_assembly takes a file or a folder (application folder, dummy assembly folder).
- Load related assemblies too: references and inherited members see only what is loaded or resolvable; add_search_directory adds a folder.
- Files that change on disk reload automatically; notices appear as "[workspace] ..." lines at the top of a result.
- reload_assembly re-reads a file and unload_assembly drops it, both discarding unsaved edits; list_assemblies lists what is loaded.
- Find: search_symbols, search_strings, search_constants, search_il, list_namespaces, list_types, resolve_symbol.
- Outline: get_type_info (section= pages one kind), get_assembly_info (view=references or metadata), get_attributes.
- Read: decompile_member (one method is cheapest, or a whole type); get_il for raw IL.
- Follow: find_references, find_callees, get_call_tree, find_call_paths, get_type_hierarchy.
- find_references includes calls through base and interface methods (basis=derived); kind=overrides lists implementations.
- find_call_paths to=<native export> or native:<image>!<function> follows native callers to roots and to managed callers through P/Invoke.
- find_callees and get_call_tree follow P/Invokes into loaded native code; .NET call tools take native exports as symbols ('kernel32.dll!CreateFileW').
- verify_native_imports checks [DllImport]s against the DLLs' real exports.
- list_resources, get_resource: managed and Win32 resources; outputPath writes one to a file.
- ReadyToRun: get_r2r_code shows a method's precompiled code; find_r2r_method maps a native address to its method.
- Mixed-mode C++/CLI assemblies load as .NET plus a native view.
- export_project writes a buildable C# project into an empty directory (overwrite=true replaces an export).
- Past the client deadline export_project returns a partial and finishes in the background.
- get_assembly_info names malformed metadata by stream, table, row, token and file offset.
