namespace NetDecompilerMcp;

internal static class ServerInstructions
{
    public const string Text = """
        Headless .NET decompiler (ILSpy engine + dnlib + Roslyn). No GUI, no dnSpy needed.

        Workflow:
        1. load_assembly with a file or a whole folder (e.g. an application folder, a Unity *_Data/Managed folder, or an Il2CppDumper DummyDll folder).
           Load related assemblies too: cross-references and inherited members only see what is loaded or resolvable.
           Method bodies are indexed in the background after loading; files that change on disk are reloaded automatically
           (notices appear as "[workspace] ..." lines at the top of a tool result).
           An app that ships wrapped in a container (single-file .exe, Costura, .nupkg, Xamarin/MAUI .apk): list_assemblies with path shows the
           assemblies inside, search_container finds types/members in them by name, and unpack_container extracts and loads them.
           list_assemblies and unpack_container flag ReadyToRun and merged (ILMerge/ILRepack) assemblies.
           summarize_file reports signature, markers, container wrapping, features, typed strings and entry points of a file in one call;
           survey_features, extract_strings and extract_embedded give the details. Nothing is executed.
        2. Discover: search_symbols, search_strings, search_constants, search_il, list_namespaces, list_types, get_type_info (cheap outline).
        3. Read code: decompile_member (one method) is faster and smaller than decompile_type; get_il for raw IL.
        4. Navigate: find_references (who uses X, incl. calls through base/interface methods), find_callees, get_call_tree
           (multi-level callers/callees), find_call_paths (how execution reaches a method), find_overrides, get_type_hierarchy, get_attributes.
        5. New versions: load both builds (the second gets an id like Name#2), then compare_assemblies and find_counterpart to carry
           renamed types/members and changed offsets forward; export_edits + apply_edits re-applies a patch set to the new build.
        6. Il2Cpp dummy DLLs have empty bodies: get_il2cpp_info (RVAs, field offsets), find_method_by_address (native address -> method),
           export_il2cpp_symbols (IDA/Ghidra scripts + C struct header). generate_cpp_binding emits C++ binding code for a Mono type
           (standard Mono embedding API, or a host function table detected in projectDir with the include paths computed).
        7. Patch in memory (dryRun=true previews): rename_symbol, rename_namespace, stub_method, patch_method_csharp (C# body; lambdas,
           async, LINQ supported), add_members_csharp, add_types_csharp, patch_method_il, simplify_methods (transformed code: folds
           string-decoder calls to literals, removes dead branches, normalizes switch dispatchers, inlines forwarders;
           decompile_member simplified=true previews it).
           Review with list_edits / diff_edits, undo with undo_edit / revert_edits, then save_assembly (never overwrites the original
           without overwrite=true; keeps a .bak; what no edit touched is written byte-for-byte, and anything that cannot be is
           listed with a reason; strict=true refuses such a save instead).

        Symbols: 'Ns.Type', 'Ns.Outer+Inner', 'Ns.Type::Method', 'Ns.Type::Method(int, string)', 'Ns.Type::.ctor', short names,
        or tokens like '0x06000123'. The assembly parameter is optional unless a name is ambiguous; errors list candidates.
        Long output is paged: follow the footer's offset=N.
        Resources: netdecomp://assemblies, netdecomp://assembly/{id}/info, netdecomp://assembly/{id}/type/{Ns.Type}, netdecomp://assembly/{id}/il/{symbol}.
        """;
}
