namespace NetDecompilerMcp;

internal static class ServerInstructions
{
    public const string Text = """
        Headless .NET decompiler (ILSpy engine + dnlib). No GUI needed.

        Workflow:
        1. load_assembly with a file or a whole folder (e.g. a Unity game's *_Data/Managed). Load related assemblies too:
           cross-references and decompilation of inherited members only see what is loaded or resolvable.
        2. Discover: search_symbols, search_strings, list_namespaces, list_types, get_type_info (cheap outline).
        3. Read code: decompile_member (one method) is faster and smaller than decompile_type. get_il for raw IL.
        4. Navigate: find_references (who uses X), find_callees (what X uses), find_overrides, get_type_hierarchy.
        5. Il2Cpp dummy DLLs (Il2CppDumper/Cpp2IL) have empty bodies: use get_il2cpp_info for RVAs/field offsets and
           find_method_by_address to map native addresses back to methods.

        Symbols: 'Ns.Type', 'Ns.Outer+Inner', 'Ns.Type::Method', 'Ns.Type::Method(int, string)', 'Ns.Type::.ctor', short names,
        or tokens like '0x06000123'. The assembly parameter is optional unless the name is ambiguous; errors list candidates.

        Long output is paged: follow the footer's offset=N. Edits (rename_symbol, stub_method, rename_namespace) stay in memory
        until save_assembly, which never overwrites the original without overwrite=true (and then keeps a .bak).
        """;
}
