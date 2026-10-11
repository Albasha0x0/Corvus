# Guide: dotnet

<!-- Generated from src/Corvus/Mcp/Guide.cs; run the tests with CORVUS_UPDATE_DOCS=1 to update. -->

.NET assemblies.
Load: load_assembly takes a file or a whole folder (an application folder, a Unity *_Data/Managed folder, an Il2CppDumper
DummyDll folder). Load related assemblies too: cross-references and inherited members only see what is loaded or resolvable;
add_search_directory adds a folder for reference resolution. Method bodies are indexed in the background after loading; files
that change on disk are reloaded automatically (notices appear as "[workspace] ..." lines at the top of a tool result).
reload_assembly re-reads a file, unload_assembly drops it (both discard unsaved edits); list_assemblies lists what is loaded.
Discover: search_symbols, search_strings, search_constants, search_il, list_namespaces, list_types, get_type_info (cheap
outline), get_assembly_info, resolve_symbol (what a name resolves to), get_attributes, decompile_assembly_attributes.
Read: decompile_member (one method) is faster and smaller than decompile_type; get_il for raw IL.
Navigate: find_references (who uses X, incl. calls through base/interface methods), find_callees, get_call_tree (multi-level
callers/callees), find_call_paths (how execution reaches a method), find_overrides, get_type_hierarchy.
P/Invokes: find_callees / get_call_tree follow them into loaded native code ('native: kernel32.dll!CreateFileW -> ...'); the
.NET call tools take native exports as symbols ('kernel32.dll!CreateFileW', 'native:<image>!<name|#ord|addr>').
verify_native_imports checks [DllImport]s against the real DLL exports (verified, contradicted, unresolved, dynamic_only,
not_checked, each with a reason).
Resources: list_resources, get_resource (managed and Win32 resources; savePath writes one to a file).
ReadyToRun: get_r2r_code shows a method's precompiled native code (calls named as managed methods); find_r2r_method maps a
native address back to its method. Mixed-mode C++/CLI assemblies load as .NET plus a native view.
Export: export_project writes a buildable C# project into an empty directory.
Malformed metadata is named with stream / table / row / token / file offset in get_assembly_info.
