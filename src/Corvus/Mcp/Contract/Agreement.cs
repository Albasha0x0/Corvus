namespace Corvus.Mcp;

/// <summary>A tool and the field of its result that carries the shared fact.</summary>
public sealed record Answer(string Tool, string Field);

/// <summary>Tools that answer one question: they report one shared fact, so their answers must agree on it.</summary>
/// <param name="Question">The fact the tools share, with its scope (managed or native).</param>
/// <param name="Answers">The tools and fields that report it.</param>
/// <param name="Fixture">The input the agreement test builds to exercise it.</param>
/// <param name="Test">The agreement test in Corvus.Tests that compares the answers on the fixture; null while none exists.</param>
public sealed record AgreementGroup(string Question, IReadOnlyList<Answer> Answers, string Fixture, string? Test);

/// <summary>The agreement groups of the catalog; every tool is in a group or has a reason in <see cref="SingleAnswer"/>.</summary>
public static class ToolAgreement
{
    /// <summary>Groups of tools that report one fact; each compares them as sets after normalizing the format.</summary>
    public static readonly IReadOnlyList<AgreementGroup> Groups =
    [
        new("native virtual call sites",
            [new("find_virtual_calls", "items.address"), new("disassemble", "slot notes"), new("analyze_native_function", "calls")],
            "x64 function with slot-indexed virtual calls and dummy assemblies",
            "Find_virtual_calls_and_disassemble_notes_list_the_same_slot_call_sites"),
        new("managed callers and callees",
            [new("find_references", "uses"), new("find_callees", "uses"), new("get_call_tree", "nodes"), new("find_call_paths", "paths")],
            "compiled assembly with a call chain", null),
        new("native callers and callees",
            [new("find_xrefs", "references"), new("native_call_tree", "nodes"), new("resolve_call_targets", "targets")],
            "assembled image with direct, tail and indirect calls",
            "Native_call_tools_report_the_same_callees_and_callers_of_a_built_image"),
        new("native function bounds and names",
            [new("list_functions", "start, end, name"), new("resolve_address", "function"),
             new("search_pdb_symbols", "address, size, name"), new("disassemble", "header")],
            "assembled image with two functions and a symbol file",
            "Function_bound_tools_report_the_same_start_size_and_name_of_each_function_of_a_built_image"),
        new("strings",
            [new("search_strings", "matches"), new("extract_strings", "strings"), new("search_native_strings", "matches")],
            "assembly and image holding the same literals", null),
        new("imports and exports",
            [new("list_imports", "items"), new("list_exports", "items"), new("get_pe_info", "import and export counts"), new("verify_native_imports", "imports")],
            "built image with an import and an export table",
            "Import_and_export_tools_list_the_same_imports_and_exports_of_a_built_image"),
        new("method addresses",
            [new("get_method_addresses", "members.rva, size"), new("find_method_by_address", "items.function, size")],
            "dummy assembly with a script.json of function starts",
            "Method_address_tools_map_a_method_to_its_function_and_back"),
        new("ReadyToRun method addresses",
            [new("get_r2r_code", "bodies"), new("find_r2r_method", "methods")],
            "ReadyToRun assembly",
            "ReadyToRun_tools_map_a_method_to_its_code_and_back"),
        new("native type layouts",
            [new("get_native_type", "fields"), new("list_native_types", "items")],
            "engine types with members",
            "Native_type_tools_report_the_same_layout_of_an_engine_type"),
        new("managed type and member names",
            [new("search_symbols", "matches"), new("list_types", "items"), new("list_namespaces", "type counts"), new("resolve_symbol", "matches"), new("get_type_info", "members")],
            "compiled assembly with nested types", null),
        new("managed edits",
            [new("list_edits", "edits"), new("diff_edits", "changes")],
            "assembly with a rename and a patch", null),
        new("native edits",
            [new("list_native_edits", "edits"), new("export_native_patches", "patches")],
            "image with two byte patches and a rename",
            "Native_edit_tools_list_the_same_patches_of_an_edited_image"),
    ];

    /// <summary>Tools whose fact no other tool reports, each with the reason an agreement check cannot apply.</summary>
    public static readonly IReadOnlyDictionary<string, string> SingleAnswer = Build(
        ("changes the session and reports the change it made",
            "add_members_csharp add_types_csharp apply_edits apply_metadata_names comment_native declare_native_types define_native " +
            "migrate_native_names migrate_native_patches patch_asm patch_bytes patch_method_csharp patch_method_il reanalyze_native " +
            "record_note rename_namespace rename_native rename_symbol revert_edits set_native_local set_native_operand " +
            "set_native_stack_var set_native_type simplify_methods stub_method undo_edit undo_native_edit update_note update_to_new_build"),
        ("writes or extracts a file and reports the output",
            "export_edits export_engine_database export_method_symbols export_native_annotations export_project extract_embedded " +
            "generate_cpp_binding pull_android_file pull_android_package save_assembly save_native save_session unpack_container"),
        ("controls the session, an engine or a process and reports no analysis fact",
            "add_search_directory convert_number get_engine_status install_android_package live_break live_console live_coverage " +
            "live_events live_read live_script live_session live_timeline live_watch load_assembly load_pdb load_session open_minidump " +
            "read_result reload_assembly server_status uninstall_android_package unload_assembly"),
        ("the only reader of its source or view",
            "analyze_js bucket_minidumps decompile_java disassemble_dex dump_heap dump_object dump_stack find_dex_references " +
            "get_android_device_info get_android_manifest get_android_package_info get_android_resource get_assembly_info get_attributes " +
            "get_call_arguments get_cfg get_dex_class get_exception_info get_native_frame get_nativeaot_info get_resource " +
            "get_type_hierarchy inspect_instruction inspect_process list_android_devices list_android_packages list_android_resources " +
            "list_assemblies list_cpp_classes list_dex_classes list_globals list_jni_bindings list_notes list_resources " +
            "make_code_pattern read_android_log read_bytes read_dump_memory summarize_build survey_features symbolize_stack_text"),
        ("compares two inputs; the difference is its own fact",
            "compare_assemblies compare_folders compare_native_images diff_function find_counterpart find_similar_functions " +
            "map_address_between_builds map_java_dotnet"),
        ("returns a code body; bounds and names come from the listing tools",
            "decompile_member decompile_native get_il"),
        ("runs code or an engine script and reports the run",
            "emulate_native ghidra_script ida_python trace_native_feature trace_native_values"),
        ("matches a caller-given pattern; its hits are not a shared fact",
            "search_bytes search_code_pattern search_constants search_container search_decompiled search_dex search_il search_instructions"),
        ("reports file identity and contained parts, not import or export rows",
            "summarize_file"));

    private static IReadOnlyDictionary<string, string> Build(params (string Reason, string Names)[] rows)
    {
        var map = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var (reason, names) in rows)
            foreach (var name in names.Split(' ', StringSplitOptions.RemoveEmptyEntries))
                map.Add(name, reason);
        return map;
    }
}
