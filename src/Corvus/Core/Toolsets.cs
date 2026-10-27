namespace Corvus.Core;

/// <summary>Tool families and profiles for --toolsets; each tool is in one family, the core and lean profiles cross families.</summary>
/// <remarks>A smaller catalog keeps full schemas for clients with a small context; Mcp.Profiles reads profile members from the contract table.</remarks>
public static class Toolsets
{
    public const string Option = "--toolsets";
    public const string Variable = "CORVUS_TOOLSETS";
    public const string Session = "session";

    /// <summary>Profile names: full is every family; core (≤ 100 tools) and lean (≤ 40) are per-tool sets.</summary>
    public const string Full = "full", CoreName = "core", Lean = "lean";

    public sealed record Family(string Name, string Description, string[] Tools);

    public static readonly IReadOnlyList<Family> Families =
    [
        new(Session, "workspace and server state",
            ["load_assembly", "unload_assembly", "reload_assembly", "add_search_directory", "list_assemblies", "server_status", "read_result",
             "save_session", "load_session"]),
        new("dotnet", ".NET browse, decompile, search, navigate, resources, ReadyToRun, project export",
            ["list_namespaces", "list_types", "get_type_info", "get_assembly_info", "get_attributes", "get_type_hierarchy", "resolve_symbol",
             "decompile_member", "get_il", "search_symbols", "search_strings", "search_constants",
             "search_il", "find_references", "find_callees", "get_call_tree", "find_call_paths", "list_resources", "get_resource",
             "export_project", "get_r2r_code", "find_r2r_method"]),
        new("containers", "file inspection, containers and wrapped apps, build summary",
            ["summarize_file", "survey_features", "extract_strings", "extract_embedded", "search_container", "unpack_container", "summarize_build"]),
        new("edit", ".NET edits, edit history and saving",
            ["rename_symbol", "rename_namespace", "stub_method", "patch_method_csharp", "patch_method_il", "add_members_csharp", "add_types_csharp",
             "simplify_methods", "list_edits", "diff_edits", "undo_edit", "revert_edits", "export_edits", "apply_edits", "save_assembly"]),
        new("aot", "AOT metadata, addresses, symbols and bindings",
            ["get_method_addresses", "find_method_by_address", "export_method_symbols", "generate_cpp_binding", "apply_metadata_names"]),
        new("native", "native PE analysis, symbols and decompilation",
            ["get_pe_info", "list_imports", "list_exports", "resolve_address", "search_bytes", "read_bytes", "convert_number", "list_functions", "list_globals", "disassemble", "inspect_instruction",
             "search_instructions", "get_cfg",
             "find_xrefs", "native_call_tree", "find_virtual_calls", "search_native_strings", "get_call_arguments", "trace_native_values", "resolve_call_targets", "analyze_native_function", "trace_native_feature", "find_similar_functions", "get_exception_info",
             "list_cpp_classes", "get_native_type", "decompile_native", "search_decompiled", "emulate_native", "verify_native_imports", "load_pdb", "search_pdb_symbols", "get_nativeaot_info"]),
        new("native-edit", "native names, comments, patches and saving",
            ["rename_native", "comment_native", "export_native_annotations", "patch_bytes", "patch_asm", "list_native_edits", "undo_native_edit",
             "save_native", "export_native_patches"]),
        new("builds", "build-to-build comparison and carrying work to a new build",
            ["compare_assemblies", "find_counterpart", "compare_folders", "compare_native_images", "diff_function", "map_address_between_builds", "make_code_pattern", "search_code_pattern",
             "migrate_native_names", "migrate_native_patches", "update_to_new_build"]),
        new("notes", "analyst notes kept per binary across sessions", ["record_note", "update_note", "list_notes"]),
        new("engine", "edits inside the decompiler engine's database: types, locals, frames, declarations, scripting",
            ["get_engine_status", "set_native_type", "set_native_local", "set_native_stack_var", "get_native_frame", "declare_native_types", "list_native_types", "define_native", "reanalyze_native",
             "set_native_operand", "ida_python", "ghidra_script", "export_engine_database"]),
        new("android", "Android packages: manifest, resources, DEX code, Java decompilation, Java / .NET mapping, devices",
            ["get_android_manifest", "list_android_resources", "get_android_resource", "list_dex_classes", "get_dex_class", "disassemble_dex", "decompile_java",
             "search_dex", "find_dex_references", "map_java_dotnet", "list_jni_bindings", "list_android_devices", "get_android_device_info", "list_android_packages",
             "get_android_package_info", "pull_android_package", "pull_android_file", "read_android_log", "install_android_package", "uninstall_android_package"]),
        new("dumps", "crash dumps and crash text", ["open_minidump", "dump_stack", "dump_heap", "dump_object", "read_dump_memory", "symbolize_stack_text", "bucket_minidumps"]),
        new("live", "running programs: read-only inspection, and sessions with stop points, call recording, code coverage, activity traces, scripted console runs and user scripts",
            ["inspect_process", "live_session", "live_break", "live_watch", "live_read", "live_events", "live_script", "live_coverage", "live_timeline", "live_console"]),
        new("web", "JavaScript bundles and their source maps", ["analyze_js"]),
    ];

    private static readonly Dictionary<string, string> FamilyByTool =
        Families.SelectMany(f => f.Tools.Select(t => (Tool: t, f.Name))).ToDictionary(x => x.Tool, x => x.Name, StringComparer.Ordinal);

    public static IReadOnlySet<string> All { get; } = Families.Select(f => f.Name).ToHashSet(StringComparer.Ordinal);

    /// <summary>What a server registers without --toolsets: every family.</summary>
    public static IReadOnlySet<string> Default => All;

    /// <summary>The core profile (--toolsets core): the tools the contract table marks Core.</summary>
    public static IReadOnlySet<string> CoreProfile { get; } = new HashSet<string>([CoreName], StringComparer.Ordinal);

    /// <summary>The lean profile (--toolsets lean): the tools the contract table marks Lean; the default of clients that cap tool counts.</summary>
    public static IReadOnlySet<string> LeanProfile { get; } = new HashSet<string>([Lean], StringComparer.Ordinal);

    /// <summary>The family of a tool, or null for a tool no family lists.</summary>
    public static string? FamilyOf(string tool) => FamilyByTool.GetValueOrDefault(tool);

    /// <summary>Parses comma- or space-separated family and profile names; an unknown name is an <see cref="ArgumentException"/>.</summary>
    /// <remarks>Names: all (also full, default), core, lean, or families, which bring the session family along.</remarks>
    public static IReadOnlySet<string> Parse(string text)
    {
        var result = new HashSet<string>(StringComparer.Ordinal);
        foreach (var raw in text.Split([',', ' ', ';'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            var name = raw.ToLowerInvariant();
            if (name is "all" or Full or "default") result.UnionWith(All);
            else if (name is CoreName or Lean) result.Add(name);
            else if (All.Contains(name)) result.UnionWith([name, Session]);
            else throw new ArgumentException($"{Option} (or {Variable}): unknown toolset '{raw}'; use {Full}, {CoreName}, {Lean} or {string.Join(", ", All)}");
        }
        if (result.Count == 0) result.Add(Session);
        return result;
    }

    public const string ToolsFileOption = "--tools-file";
    public const string ToolsFileVariable = "CORVUS_TOOLS_FILE";

    /// <summary>Named --tools-file lists: readonly (tools that change and write nothing, no device or live-process tools) and triage (a first look at a binary).</summary>
    public static readonly IReadOnlyDictionary<string, string[]> ToolLists = new Dictionary<string, string[]>(StringComparer.Ordinal)
    {
        ["readonly"] =
        [
            "list_namespaces", "list_types", "get_type_info", "get_assembly_info", "get_attributes", "get_type_hierarchy", "resolve_symbol",
            "decompile_member", "get_il", "search_symbols", "search_strings", "search_constants", "search_il", "find_references",
            "find_callees", "get_call_tree", "find_call_paths", "list_resources", "get_r2r_code", "find_r2r_method",
            "summarize_file", "survey_features", "extract_strings", "search_container", "summarize_build", "analyze_js", "list_edits", "diff_edits",
            "get_method_addresses", "find_method_by_address", "generate_cpp_binding",
            "get_pe_info", "get_engine_status", "get_nativeaot_info", "list_imports", "list_exports", "resolve_address", "search_bytes", "read_bytes", "convert_number",
            "list_functions", "list_globals", "disassemble", "search_instructions",
            "inspect_instruction", "get_cfg", "find_xrefs", "native_call_tree", "find_virtual_calls", "search_native_strings", "get_call_arguments",
            "trace_native_values", "resolve_call_targets", "analyze_native_function", "trace_native_feature", "find_similar_functions", "get_exception_info", "list_cpp_classes",
            "get_native_type", "decompile_native", "search_decompiled", "emulate_native", "verify_native_imports", "search_pdb_symbols", "list_native_edits", "get_native_frame", "list_native_types",
            "compare_assemblies", "compare_native_images", "find_counterpart", "compare_folders", "map_address_between_builds", "diff_function", "make_code_pattern", "search_code_pattern",
            "get_android_manifest", "list_android_resources", "list_dex_classes", "get_dex_class", "disassemble_dex", "map_java_dotnet", "decompile_java",
            "search_dex", "find_dex_references", "list_jni_bindings",
            "open_minidump", "dump_stack", "dump_heap", "dump_object", "read_dump_memory", "symbolize_stack_text", "bucket_minidumps", "list_notes",
        ],
        ["triage"] =
        [
            "summarize_file", "survey_features", "get_type_info", "search_symbols", "search_strings", "decompile_member", "find_references",
            "get_pe_info", "list_imports", "list_functions", "search_native_strings", "find_xrefs", "disassemble", "decompile_native", "analyze_native_function",
        ],
    };

    /// <summary>A --tools-file whitelist from a <see cref="ToolLists"/> name or a file; an unknown name is an <see cref="ArgumentException"/>.</summary>
    /// <remarks>A file holds tool names, '#' starts a comment; applied after the toolsets, session tools stay.</remarks>
    public static IReadOnlySet<string> LoadToolList(string pathOrName)
    {
        var value = pathOrName.Trim();
        if (ToolLists.TryGetValue(value.ToLowerInvariant(), out var named)) return named.ToHashSet(StringComparer.Ordinal);
        if (!File.Exists(value))
            throw new ArgumentException($"{ToolsFileOption} (or {ToolsFileVariable}): no file '{value}' and no list of that name; use {string.Join(", ", ToolLists.Keys)} or a file of tool names");
        return ParseToolList(File.ReadAllText(value), value);
    }

    public static IReadOnlySet<string> ParseToolList(string text, string source)
    {
        var names = new HashSet<string>(StringComparer.Ordinal);
        var unknown = new List<string>();
        foreach (var line in text.Split('\n'))
        {
            var content = line.Split('#')[0];
            foreach (var name in content.Split([',', ' ', '\t', ';', '\r'], StringSplitOptions.RemoveEmptyEntries))
                if (FamilyByTool.ContainsKey(name)) names.Add(name);
                else unknown.Add(name);
        }
        if (unknown.Count > 0) throw new ArgumentException($"{ToolsFileOption} {source}: unknown tool(s) {string.Join(", ", unknown.Distinct())}");
        return names;
    }

    /// <summary>The shortest spelling of a set, for a client's args: "all", the profiles, then family names in table order.</summary>
    public static string Format(IReadOnlySet<string> enabled)
    {
        if (enabled.IsSupersetOf(All)) return "all";
        var families = Families.Where(f => f.Name != Session && enabled.Contains(f.Name)).Select(f => f.Name).ToList();
        var names = new[] { CoreName, Lean }.Where(enabled.Contains).Concat(families).ToList();
        return names.Count == 0 ? Session : string.Join(",", names);
    }
}
