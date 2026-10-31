using R = Corvus.Mcp.FileReads;

namespace Corvus.Mcp;

/// <summary>
/// Where a tool parses the analyzed file's bytes; a tool can read in several
/// places, depending on its arguments.
/// </summary>
[Flags]
public enum FileReads
{
    /// <summary>
    /// Reads no analyzed file: server state, notes, kept results, devices or
    /// running programs.
    /// </summary>
    None = 0,
    /// <summary>In the server process, where a crafted file can end it.</summary>
    Server = 1,
    /// <summary>In the "files" <c>corvus worker</c> (its op table).</summary>
    FileWorker = 2,
    /// <summary>In an IDA, Ghidra or JADX worker.</summary>
    EngineWorker = 4,
    /// <summary>In a session's Python worker with Frida's bindings.</summary>
    SessionWorker = 8,
    /// <summary>
    /// In a helper program Corvus starts (Detect It Easy, TShark, pycdc, capa,
    /// speakeasy).
    /// </summary>
    Helper = 16,
}

public sealed partial record ToolContract
{
    /// <summary>
    /// Where this tool parses the analyzed file; a tool the table does not list
    /// counts as reading in the server.
    /// </summary>
    public FileReads Reads => FileReadTable.TryGetValue(Tool, out var reads) ? reads : R.Server;

    /// <summary>
    /// Every tool's <see cref="FileReads"/>, by family; FileReadsTests requires
    /// a row for each tool.
    /// </summary>
    internal static readonly IReadOnlyDictionary<string, FileReads> FileReadTable = new Dictionary<string, FileReads>(StringComparer.Ordinal)
    {
        // session
        ["load_assembly"] = R.Server,
        ["unload_assembly"] = R.None,
        ["reload_assembly"] = R.Server,
        ["add_search_directory"] = R.None,
        ["list_assemblies"] = R.FileWorker,
        ["server_status"] = R.None,
        ["read_result"] = R.None,
        ["save_session"] = R.None,
        ["load_session"] = R.Server,
        // dotnet
        ["list_namespaces"] = R.Server,
        ["list_types"] = R.Server,
        ["get_type_info"] = R.Server,
        ["get_assembly_info"] = R.Server,
        ["get_attributes"] = R.Server,
        ["get_type_hierarchy"] = R.Server,
        ["resolve_symbol"] = R.Server,
        ["decompile_member"] = R.Server,
        ["get_il"] = R.Server,
        ["search_symbols"] = R.Server,
        ["search_strings"] = R.Server,
        ["search_constants"] = R.Server,
        ["search_il"] = R.Server,
        ["find_references"] = R.Server,
        ["find_callees"] = R.Server,
        ["get_call_tree"] = R.Server,
        ["find_call_paths"] = R.Server,
        ["list_resources"] = R.Server,
        ["get_resource"] = R.Server,
        ["export_project"] = R.FileWorker | R.Server,
        ["get_r2r_code"] = R.Server,
        ["find_r2r_method"] = R.Server,
        // containers
        ["summarize_file"] = R.FileWorker | R.Helper,
        ["survey_features"] = R.FileWorker | R.Server | R.Helper,
        ["extract_strings"] = R.FileWorker | R.Server,
        ["extract_embedded"] = R.FileWorker | R.Server,
        ["search_container"] = R.FileWorker | R.Helper,
        // Extraction reads in the worker; loading what it found reads in the server.
        ["unpack_container"] = R.FileWorker | R.Server,
        ["summarize_build"] = R.Server | R.Helper,
        // edit
        ["rename_symbol"] = R.Server,
        ["rename_namespace"] = R.Server,
        ["stub_method"] = R.Server,
        ["patch_method_csharp"] = R.Server,
        ["patch_method_il"] = R.Server,
        ["add_members_csharp"] = R.Server,
        ["add_types_csharp"] = R.Server,
        ["simplify_methods"] = R.Server,
        ["list_edits"] = R.None,
        ["diff_edits"] = R.Server,
        ["undo_edit"] = R.Server,
        ["revert_edits"] = R.Server,
        ["export_edits"] = R.None,
        ["apply_edits"] = R.Server,
        ["save_assembly"] = R.Server,
        // aot
        ["get_method_addresses"] = R.Server,
        ["find_method_by_address"] = R.Server,
        ["export_method_symbols"] = R.Server,
        ["generate_cpp_binding"] = R.Server,
        ["apply_metadata_names"] = R.Server,
        // native
        ["get_pe_info"] = R.Server,
        ["list_imports"] = R.Server,
        ["list_exports"] = R.Server,
        ["resolve_address"] = R.Server,
        ["search_bytes"] = R.Server,
        ["read_bytes"] = R.Server,
        ["convert_number"] = R.None,
        ["list_functions"] = R.Server | R.EngineWorker,
        ["list_globals"] = R.Server | R.EngineWorker,
        ["disassemble"] = R.Server | R.EngineWorker,
        ["inspect_instruction"] = R.Server | R.EngineWorker,
        ["search_instructions"] = R.Server | R.EngineWorker,
        ["get_cfg"] = R.Server | R.EngineWorker,
        ["find_xrefs"] = R.Server | R.EngineWorker,
        ["native_call_tree"] = R.Server | R.EngineWorker,
        ["find_virtual_calls"] = R.Server | R.EngineWorker,
        ["search_native_strings"] = R.Server | R.EngineWorker,
        ["get_call_arguments"] = R.Server,
        ["trace_native_values"] = R.Server | R.EngineWorker,
        ["resolve_call_targets"] = R.Server | R.EngineWorker,
        ["analyze_native_function"] = R.Server | R.EngineWorker,
        ["trace_native_feature"] = R.Server | R.EngineWorker,
        ["find_similar_functions"] = R.Server,
        ["get_exception_info"] = R.Server,
        ["list_cpp_classes"] = R.Server | R.EngineWorker,
        ["get_native_type"] = R.Server | R.EngineWorker,
        ["decompile_native"] = R.EngineWorker,
        ["search_decompiled"] = R.EngineWorker,
        // engine=ours reads in the server, Ghidra in its worker, speakeasy as a helper.
        ["emulate_native"] = R.Server | R.EngineWorker | R.Helper,
        ["verify_native_imports"] = R.Server,
        ["load_pdb"] = R.Server,
        ["search_pdb_symbols"] = R.Server,
        ["get_nativeaot_info"] = R.Server,
        // native-edit
        ["rename_native"] = R.Server | R.EngineWorker,
        ["comment_native"] = R.Server | R.EngineWorker,
        ["export_native_annotations"] = R.None,
        ["patch_bytes"] = R.Server,
        ["patch_asm"] = R.Server,
        ["list_native_edits"] = R.None,
        ["undo_native_edit"] = R.None,
        ["save_native"] = R.Server,
        ["export_native_patches"] = R.None,
        // builds
        ["compare_assemblies"] = R.Server,
        ["find_counterpart"] = R.Server,
        ["compare_folders"] = R.FileWorker | R.Server,
        ["compare_native_images"] = R.FileWorker | R.Server | R.EngineWorker,
        ["diff_function"] = R.Server | R.EngineWorker,
        ["map_address_between_builds"] = R.Server,
        ["make_code_pattern"] = R.Server | R.EngineWorker,
        ["search_code_pattern"] = R.Server,
        ["migrate_native_names"] = R.Server,
        ["migrate_native_patches"] = R.Server,
        ["update_to_new_build"] = R.Server,
        // notes
        ["record_note"] = R.None,
        ["update_note"] = R.None,
        ["list_notes"] = R.None,
        // engine; get_engine_status never starts an engine.
        ["get_engine_status"] = R.None,
        ["set_native_type"] = R.EngineWorker,
        ["set_native_local"] = R.EngineWorker,
        ["set_native_stack_var"] = R.EngineWorker,
        ["get_native_frame"] = R.EngineWorker,
        ["declare_native_types"] = R.EngineWorker,
        ["list_native_types"] = R.EngineWorker,
        ["define_native"] = R.EngineWorker,
        ["reanalyze_native"] = R.EngineWorker,
        ["set_native_operand"] = R.EngineWorker,
        ["ida_python"] = R.EngineWorker,
        ["ghidra_script"] = R.EngineWorker,
        ["export_engine_database"] = R.EngineWorker,
        // android; the device tools read the device, not a file.
        ["get_android_manifest"] = R.FileWorker | R.Server,
        ["list_android_resources"] = R.FileWorker | R.Server,
        // Writing the entry to outputPath stays in the server under a sandboxed worker.
        ["get_android_resource"] = R.FileWorker | R.Server,
        ["list_dex_classes"] = R.FileWorker | R.Server,
        ["get_dex_class"] = R.FileWorker | R.Server,
        ["disassemble_dex"] = R.FileWorker | R.Server,
        ["decompile_java"] = R.Server | R.EngineWorker,
        ["search_dex"] = R.FileWorker | R.Server,
        ["find_dex_references"] = R.FileWorker | R.Server,
        ["map_java_dotnet"] = R.Server,
        ["list_jni_bindings"] = R.Server,
        ["list_android_devices"] = R.None,
        ["get_android_device_info"] = R.None,
        ["list_android_packages"] = R.None,
        ["get_android_package_info"] = R.None,
        ["pull_android_package"] = R.None,
        ["pull_android_file"] = R.None,
        ["read_android_log"] = R.None,
        ["install_android_package"] = R.None,
        ["uninstall_android_package"] = R.None,
        // dumps; a read in the worker moves to the server while images are loaded.
        ["open_minidump"] = R.FileWorker | R.Server,
        ["dump_stack"] = R.FileWorker | R.Server,
        ["dump_heap"] = R.FileWorker | R.Server,
        ["dump_object"] = R.FileWorker | R.Server,
        ["read_dump_memory"] = R.FileWorker | R.Server,
        ["symbolize_stack_text"] = R.FileWorker | R.Server,
        ["bucket_minidumps"] = R.FileWorker | R.Server,
        // live; a session reads its program through Frida in its worker.
        ["inspect_process"] = R.None,
        ["live_session"] = R.SessionWorker,
        ["live_break"] = R.SessionWorker,
        ["live_watch"] = R.SessionWorker,
        ["live_read"] = R.SessionWorker,
        ["live_events"] = R.SessionWorker,
        ["live_script"] = R.SessionWorker,
        ["live_coverage"] = R.SessionWorker,
        ["live_timeline"] = R.None,
        ["live_console"] = R.None,
        // web
        ["analyze_js"] = R.Server,
    };
}
