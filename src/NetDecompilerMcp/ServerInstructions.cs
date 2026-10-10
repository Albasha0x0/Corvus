namespace NetDecompilerMcp;

internal static class ServerInstructions
{
    public const string Text = """
        Headless .NET decompiler (ILSpy engine + dnlib + Roslyn) and native PE analyzer. No GUI, no dnSpy needed.

        Workflow:
        1. load_assembly with a file or a whole folder (e.g. an application folder, a Unity *_Data/Managed folder, or an Il2CppDumper DummyDll folder).
           Load related assemblies too: cross-references and inherited members only see what is loaded or resolvable.
           Method bodies are indexed in the background after loading; files that change on disk are reloaded automatically
           (notices appear as "[workspace] ..." lines at the top of a tool result).
           An app that ships wrapped in a container (single-file .exe, Costura, .nupkg, Xamarin/MAUI .apk): list_assemblies with path shows the
           assemblies inside, search_container finds types/members in them by name, and unpack_container extracts and loads them.
           list_assemblies and unpack_container flag ReadyToRun and merged (ILMerge/ILRepack) assemblies; get_r2r_code shows a ReadyToRun
           method's precompiled native code (calls named as managed methods) and find_r2r_method maps a native address back to its method.
           summarize_file reports signature, markers, container wrapping, features, typed strings and entry points of a file in one call;
           survey_features, extract_strings and extract_embedded give the details. Nothing is executed.
        2. Discover: search_symbols, search_strings, search_constants, search_il, list_namespaces, list_types, get_type_info (cheap outline).
        3. Read code: decompile_member (one method) is faster and smaller than decompile_type; get_il for raw IL.
        4. Navigate: find_references (who uses X, incl. calls through base/interface methods), find_callees, get_call_tree
           (multi-level callers/callees), find_call_paths (how execution reaches a method), find_overrides, get_type_hierarchy, get_attributes.
        5. New versions: load both builds (the second gets an id like Name#2), then compare_assemblies and find_counterpart to carry
           renamed types/members and changed offsets forward; export_edits + apply_edits re-applies a patch set to the new build.
        6. Il2Cpp dummy DLLs have empty bodies: get_il2cpp_info (RVAs, field offsets; slot=N for the method implementing a vtable slot),
           find_method_by_address (native address -> method), export_il2cpp_symbols (IDA/Ghidra scripts + C struct header).
           With Il2CppDumper's script.json next to the DummyDll folder, functions are bounded by the next function start, generic
           instantiations are named both ways (get_il2cpp_info 'List`1<int>::Add'; overloads told apart by the C signature, or
           reported as ambiguous), and type metadata / MethodInfo slots resolve.
           With stringliteral.json and GameAssembly.dll too, search_strings finds the game's literals and the methods whose native code loads them. generate_cpp_binding emits C++ binding code for a Mono type
           (standard Mono embedding API, or a host function table detected in projectDir with the include paths computed).
        7. Patch in memory (dryRun=true previews): rename_symbol, rename_namespace, stub_method, patch_method_csharp (C# body; lambdas,
           async, LINQ supported), add_members_csharp, add_types_csharp, patch_method_il, simplify_methods (transformed code: folds
           string-decoder calls to literals, removes dead branches, normalizes switch dispatchers, inlines forwarders;
           decompile_member simplified=true previews it).
           Review with list_edits / diff_edits, undo with undo_edit / revert_edits, then save_assembly (never overwrites the original
           without overwrite=true; keeps a .bak; what no edit touched is written byte-for-byte, and anything that cannot be is
           listed with a reason; strict=true refuses such a save instead).

        8. Native PE files (.exe/.dll/.sys without .NET metadata; x86 and x64): load_assembly with the file path (or pass the path as image
           to any native tool). get_pe_info (headers, mitigations, PDB, version, rich header, signature, anything malformed), list_imports,
           list_exports (MSVC names demangled), list_resources / get_resource (Win32 resources), list_functions, disassemble, get_cfg,
           find_xrefs (incl. every call site of an import: 'kernel32!CreateFileW'), native_call_tree, search_native_strings, search_bytes
           (?? wildcards), read_bytes, resolve_address, list_cpp_classes (RTTI classes, bases, vftables), decompile_native (C pseudocode
           through IDA when installed; server_status says whether it is). Addresses: hex VA or RVA, rva:/va:/off: prefixes, export names,
           module!import, sub_<rva>. The code index is built in the background after loading. verify_native_imports checks a .NET
           assembly's [DllImport]s against the real DLL exports.

        Errors start with "Error (<code>)" (not_found, ambiguous, invalid_argument, unsupported, not_loaded, limit_exceeded, timeout,
        provider_unavailable, ...) and usually a "Next:" line with the call that can succeed. A result too large to send comes back as
        limit_exceeded with an id: read_result pages through it. server_status reports version, limits and available engines.

        Symbols: 'Ns.Type', 'Ns.Outer+Inner', 'Ns.Type::Method', 'Ns.Type::Method(int, string)', 'Ns.Type::.ctor', short names,
        or tokens like '0x06000123'. The assembly parameter is optional unless a name is ambiguous; errors list candidates.
        Long output is paged: follow the footer's offset=N.
        Resources: netdecomp://assemblies, netdecomp://assembly/{id}/info, netdecomp://assembly/{id}/type/{Ns.Type}, netdecomp://assembly/{id}/il/{symbol}.
        """;
}
