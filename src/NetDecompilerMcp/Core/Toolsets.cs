namespace NetDecompilerMcp.Core;

/// <summary>
/// Tool families. A server registers every tool unless started with --toolsets / NDM_TOOLSETS, which lets a client with
/// a small context see a smaller catalog with full schemas. Every tool is in exactly one family; session is always on.
/// </summary>
public static class Toolsets
{
    public const string Option = "--toolsets";
    public const string Variable = "NDM_TOOLSETS";
    public const string Session = "session";

    /// <summary>InCore: part of the core profile (--toolsets core).</summary>
    public sealed record Family(string Name, bool InCore, string Description, string[] Tools);

    public static readonly IReadOnlyList<Family> Families =
    [
        new(Session, true, "workspace and server state",
            ["load_assembly", "unload_assembly", "reload_assembly", "add_search_directory", "list_assemblies", "server_status", "read_result"]),
        new("dotnet", true, ".NET browse, decompile, search, navigate, resources, ReadyToRun, project export",
            ["list_namespaces", "list_types", "get_type_info", "get_assembly_info", "get_attributes", "get_type_hierarchy", "resolve_symbol",
             "decompile_type", "decompile_member", "decompile_assembly_attributes", "get_il", "search_symbols", "search_strings", "search_constants",
             "search_il", "find_references", "find_callees", "find_overrides", "get_call_tree", "find_call_paths", "list_resources", "get_resource",
             "export_project", "get_r2r_code", "find_r2r_method"]),
        new("containers", true, "file inspection, containers and wrapped apps, Unity overview",
            ["summarize_file", "survey_features", "extract_strings", "extract_embedded", "search_container", "unpack_container", "unity_overview"]),
        new("edit", true, ".NET edits, edit history and saving",
            ["rename_symbol", "rename_namespace", "stub_method", "patch_method_csharp", "patch_method_il", "add_members_csharp", "add_types_csharp",
             "simplify_methods", "list_edits", "diff_edits", "undo_edit", "revert_edits", "export_edits", "apply_edits", "save_assembly"]),
        new("il2cpp", true, "Il2Cpp metadata, addresses, symbols and bindings",
            ["get_il2cpp_info", "find_method_by_address", "export_il2cpp_symbols", "generate_cpp_binding", "apply_il2cpp_names"]),
        new("native", true, "native PE analysis, symbols and decompilation",
            ["get_pe_info", "list_imports", "list_exports", "resolve_address", "search_bytes", "read_bytes", "list_functions", "disassemble", "inspect_instruction", "get_cfg",
             "find_xrefs", "native_call_tree", "find_virtual_calls", "search_native_strings", "get_call_arguments", "trace_native_values", "resolve_call_targets", "get_exception_info",
             "list_cpp_classes", "get_native_type", "decompile_native", "verify_native_imports", "load_pdb", "search_pdb_symbols"]),
        new("native-edit", true, "native names, comments, patches and saving",
            ["rename_native", "comment_native", "export_native_annotations", "patch_bytes", "patch_asm", "list_native_edits", "undo_native_edit",
             "save_native", "export_native_patches"]),
        new("builds", true, "build-to-build comparison and carrying work to a new build",
            ["compare_assemblies", "find_counterpart", "compare_native_images", "map_address_between_builds", "make_code_pattern", "search_code_pattern",
             "migrate_native_names", "migrate_native_patches", "update_to_new_build"]),
        new("engine", false, "edits inside the decompiler engine's database: types, locals, frames, declarations, scripting",
            ["set_native_type", "set_native_local", "set_native_stack_var", "get_native_frame", "declare_native_types", "list_native_types", "ida_python"]),
        new("dumps", false, "crash dumps", ["open_minidump", "dump_stack", "read_dump_memory"]),
        new("live", false, "read-only inspection of a running process", ["inspect_process"]),
    ];

    private static readonly Dictionary<string, string> FamilyByTool =
        Families.SelectMany(f => f.Tools.Select(t => (Tool: t, f.Name))).ToDictionary(x => x.Tool, x => x.Name, StringComparer.Ordinal);

    public static IReadOnlySet<string> All { get; } = Families.Select(f => f.Name).ToHashSet(StringComparer.Ordinal);

    /// <summary>What a server registers without --toolsets: every family.</summary>
    public static IReadOnlySet<string> Default => All;

    /// <summary>The reduced profile for small-context clients: .NET and native core, without engine edits, dumps and live processes.</summary>
    public static IReadOnlySet<string> CoreProfile { get; } = Families.Where(f => f.InCore).Select(f => f.Name).ToHashSet(StringComparer.Ordinal);

    /// <summary>The family of a tool, or null for a tool no family lists.</summary>
    public static string? FamilyOf(string tool) => FamilyByTool.GetValueOrDefault(tool);

    /// <summary>Whether a server started with <paramref name="enabled"/> registers <paramref name="tool"/>; a tool no family lists is kept.</summary>
    public static bool Registers(IReadOnlySet<string> enabled, string tool) => FamilyOf(tool) is not { } family || enabled.Contains(family);

    /// <summary>
    /// Family names separated by commas or spaces; "all" (also "default") and "core" stand for those sets, session is always added.
    /// An unknown name is an <see cref="ArgumentException"/> naming the families.
    /// </summary>
    public static IReadOnlySet<string> Parse(string text)
    {
        var result = new HashSet<string>(StringComparer.Ordinal) { Session };
        foreach (var raw in text.Split([',', ' ', ';'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            var name = raw.ToLowerInvariant();
            if (name is "all" or "default") result.UnionWith(All);
            else if (name == "core") result.UnionWith(CoreProfile);
            else if (All.Contains(name)) result.Add(name);
            else throw new ArgumentException($"{Option} (or {Variable}): unknown toolset '{raw}'; use all, core or {string.Join(", ", All)}");
        }
        return result;
    }

    /// <summary>The shortest spelling of a set, for a client's args: "all", "core" plus extra names, or the names in table order.</summary>
    public static string Format(IReadOnlySet<string> enabled)
    {
        if (enabled.IsSupersetOf(All)) return "all";
        bool withCore = enabled.IsSupersetOf(CoreProfile);
        var names = Families.Where(f => f.Name != Session && enabled.Contains(f.Name) && !(withCore && f.InCore)).Select(f => f.Name);
        return string.Join(",", withCore ? names.Prepend("core") : names);
    }
}
