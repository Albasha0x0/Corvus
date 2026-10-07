namespace NetDecompilerMcp;

internal static class ServerInstructions
{
    public const string Text = """
        Headless .NET decompiler (ILSpy engine + dnlib + Roslyn). No GUI, no dnSpy needed.

        Workflow:
        1. load_assembly with a file or a whole folder (e.g. a Unity game's *_Data/Managed, or an Il2CppDumper DummyDll folder).
           Load related assemblies too: cross-references and inherited members only see what is loaded or resolvable.
        2. Discover: search_symbols, search_strings, search_constants, search_il, list_namespaces, list_types, get_type_info (cheap outline).
        3. Read code: decompile_member (one method) is faster and smaller than decompile_type; get_il for raw IL.
        4. Navigate: find_references (who uses X, incl. calls through base/interface methods), find_callees (what X uses),
           find_overrides, get_type_hierarchy, get_attributes.
        5. Il2Cpp dummy DLLs have empty bodies: use get_il2cpp_info for RVAs/field offsets and find_method_by_address to map
           native addresses (IDA/Ghidra/crash logs) back to methods.
        6. Patch in memory, preview with dryRun=true: rename_symbol, rename_namespace, stub_method (return constant),
           patch_method_csharp (new body in C#), patch_method_il (IL text, replace or prepend). Then save_assembly — it never
           overwrites the original without overwrite=true and keeps a .bak.

        Symbols: 'Ns.Type', 'Ns.Outer+Inner', 'Ns.Type::Method', 'Ns.Type::Method(int, string)', 'Ns.Type::.ctor', short names,
        or tokens like '0x06000123'. The assembly parameter is optional unless a name is ambiguous; errors list candidates.
        Long output is paged: follow the footer's offset=N.
        Resources: netdecomp://assemblies, netdecomp://assembly/{id}/info, netdecomp://assembly/{id}/type/{Ns.Type}, netdecomp://assembly/{id}/il/{symbol}.
        """;
}
