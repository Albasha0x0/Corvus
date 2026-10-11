using System.Text.Json.Nodes;
using ModelContextProtocol.Protocol;
using ModelContextProtocol.Server;

namespace NetDecompilerMcp.Mcp;

/// <summary>
/// What each tool does to its environment: the one source of the tools' MCP annotations (applied at startup by
/// <see cref="Apply"/>; [McpServerTool] attributes set none). Audited against each tool's code.
/// <list type="bullet">
/// <item>ReadOnly: changes nothing loaded and writes no file. Loading an image named by path (the native and ReadyToRun tools
/// accept a path) counts as reading: it adds the file to the session as load_assembly would. Private caches (the IDA
/// database, downloaded reference packs and PDBs) do not count.</item>
/// <item>Destructive: can replace or discard existing state: method bodies, names, bytes or edits in the workspace, or an
/// existing file. False for tools that only add (new members, a newly loaded file, files in an empty directory).</item>
/// <item>Idempotent: the same call again has no further effect.</item>
/// <item>OpenWorld: some argument value can make the call launch a process (IDA through idalib, Python, a Ghidra JVM, diec), reach the network
/// or read another running process; so every tool with an engine parameter is open-world. Not counted: server-wide settings
/// (--engine, --prewarm) and a reference pack download (any .NET tool can trigger one when an assembly targets a .NET
/// version that is not installed; NDM_OFFLINE=1 turns it off).</item>
/// <item>LongRunning (not an MCP annotation): a call can run for more than ~10 s on large inputs: whole-assembly or whole-image
/// work, an external engine, or the first use of a native image, which waits for its code index. Advertised as a
/// description suffix, as _meta "net-decompiler/longRunning": true, and in server_status.</item>
/// </list>
/// </summary>
public static class ToolEffects
{
    public sealed record Effects(bool ReadOnly, bool Destructive, bool Idempotent, bool OpenWorld, bool LongRunning);

    private static Effects Reads(bool longRunning = false, bool openWorld = false) => new(true, false, true, openWorld, longRunning);

    private static Effects Changes(bool destructive, bool idempotent, bool longRunning = false, bool openWorld = false) =>
        new(false, destructive, idempotent, openWorld, longRunning);

    public const string LongRunningMetaKey = "net-decompiler/longRunning";
    public const string LongRunningSuffix = " [Long-running: can take more than 10 s on large inputs.]";

    /// <summary>Every tool, by name.</summary>
    public static readonly IReadOnlyDictionary<string, Effects> Table = new Dictionary<string, Effects>(StringComparer.Ordinal)
    {
        // Workspace
        ["load_assembly"] = Changes(destructive: false, idempotent: true, longRunning: true), // adds files and a search directory; same path again: no-op
        ["unload_assembly"] = Changes(destructive: true, idempotent: true), // discards unsaved edits
        ["reload_assembly"] = Changes(destructive: true, idempotent: true), // discards unsaved edits
        ["add_search_directory"] = Changes(destructive: false, idempotent: true),
        ["list_assemblies"] = Reads(),
        ["server_status"] = Reads(openWorld: true), // probes the Python idalib uses (a process launch, once per server)
        ["read_result"] = Reads(),
        ["save_session"] = Changes(destructive: true, idempotent: true), // overwrite=true replaces the file at path
        ["load_session"] = Changes(destructive: true, idempotent: false, longRunning: true), // loads files and applies edits, patches and names; dryRun by default

        // .NET browse, decompile, search, navigate
        ["list_namespaces"] = Reads(),
        ["list_types"] = Reads(),
        ["get_type_info"] = Reads(),
        ["get_assembly_info"] = Reads(),
        ["get_attributes"] = Reads(),
        ["get_type_hierarchy"] = Reads(),
        ["resolve_symbol"] = Reads(),
        ["decompile_type"] = Reads(),
        ["decompile_member"] = Reads(),
        ["decompile_assembly_attributes"] = Reads(),
        ["get_il"] = Reads(),
        ["search_symbols"] = Reads(),
        ["search_strings"] = Reads(),
        ["search_constants"] = Reads(),
        ["search_il"] = Reads(),
        ["find_references"] = Reads(),
        ["find_callees"] = Reads(),
        ["find_overrides"] = Reads(),
        ["get_call_tree"] = Reads(),
        ["find_call_paths"] = Reads(),
        ["list_resources"] = Reads(),
        ["get_resource"] = Changes(destructive: true, idempotent: true), // savePath; overwrite=true replaces a file
        ["export_project"] = Changes(destructive: false, idempotent: true, longRunning: true), // refuses a non-empty directory

        // Files and containers (nothing executed)
        ["summarize_file"] = Reads(),
        ["survey_features"] = Reads(),
        ["extract_strings"] = Changes(destructive: true, idempotent: true), // savePath; overwrite=true replaces a file
        ["extract_embedded"] = Changes(destructive: false, idempotent: true), // writes unique names, never over a different file
        ["search_container"] = Reads(),
        ["unpack_container"] = Changes(destructive: false, idempotent: true, longRunning: true), // extracts into an empty directory (or its own earlier unpack) and loads
        ["unity_overview"] = Reads(openWorld: true), // headers and listings only; detectItEasy=true launches diec

        // Android packages (read natively; nothing executed)
        ["get_android_manifest"] = Reads(),
        ["list_android_resources"] = Reads(),
        ["get_android_resource"] = Changes(destructive: true, idempotent: true), // savePath; overwrite=true replaces a file
        ["list_dex_classes"] = Reads(),
        ["get_dex_class"] = Reads(),
        ["disassemble_dex"] = Reads(),
        ["map_java_dotnet"] = Reads(),
        ["decompile_java"] = Reads(longRunning: true, openWorld: true), // runs the JADX server (java -jar); its first call loads the package
        ["search_dex"] = Reads(longRunning: true), // the first call builds the package's code index
        ["find_dex_references"] = Reads(longRunning: true),
        ["list_jni_bindings"] = Reads(longRunning: true), // indexes the DEX code, and a library's code when a table's class needs it

        // Android devices through adb (open-world: they reach a device); install and uninstall need --allow-device-changes
        ["list_android_devices"] = Reads(openWorld: true),
        ["get_android_device_info"] = Reads(openWorld: true),
        ["list_android_packages"] = Reads(openWorld: true),
        ["get_android_package_info"] = Reads(openWorld: true),
        ["read_android_log"] = Reads(openWorld: true),
        ["pull_android_package"] = Changes(destructive: false, idempotent: true, longRunning: true, openWorld: true), // writes into a new or empty directory
        ["pull_android_file"] = Changes(destructive: true, idempotent: true, longRunning: true, openWorld: true), // overwrite=true replaces a file
        ["install_android_package"] = Changes(destructive: true, idempotent: false, longRunning: true, openWorld: true), // replaces an installed app
        ["uninstall_android_package"] = Changes(destructive: true, idempotent: true, openWorld: true),

        // Builds
        ["compare_assemblies"] = Changes(destructive: true, idempotent: true, longRunning: true), // tokenMapPath; overwrite=true replaces a file
        ["find_counterpart"] = Reads(longRunning: true),

        // .NET edits (in memory until save_assembly)
        ["rename_symbol"] = Changes(destructive: true, idempotent: false),
        ["rename_namespace"] = Changes(destructive: true, idempotent: false),
        ["stub_method"] = Changes(destructive: true, idempotent: false),
        ["patch_method_csharp"] = Changes(destructive: true, idempotent: false),
        ["patch_method_il"] = Changes(destructive: true, idempotent: false),
        ["add_members_csharp"] = Changes(destructive: false, idempotent: false),
        ["add_types_csharp"] = Changes(destructive: false, idempotent: false),
        ["simplify_methods"] = Changes(destructive: true, idempotent: false, longRunning: true),
        ["list_edits"] = Reads(),
        ["diff_edits"] = Reads(),
        ["undo_edit"] = Changes(destructive: true, idempotent: false),
        ["revert_edits"] = Changes(destructive: true, idempotent: true),
        ["export_edits"] = Changes(destructive: true, idempotent: true), // overwrite=true replaces the file at path
        ["apply_edits"] = Changes(destructive: true, idempotent: false),
        ["save_assembly"] = Changes(destructive: true, idempotent: true), // overwrite=true replaces a file (the original's .bak is made once)

        // Il2Cpp
        ["get_il2cpp_info"] = Reads(),
        ["find_method_by_address"] = Reads(),
        ["export_il2cpp_symbols"] = Changes(destructive: true, idempotent: true, longRunning: true), // overwrite=true replaces the files it writes
        ["generate_cpp_binding"] = Reads(),
        ["apply_il2cpp_names"] = Changes(destructive: true, idempotent: true, longRunning: true), // replaces the image's il2cpp names

        // Native images
        ["get_pe_info"] = Reads(),
        ["get_engine_status"] = Reads(openWorld: true), // never starts an engine; asks an open one for its view
        ["get_nativeaot_info"] = Reads(longRunning: true), // the first call reads the metadata of a large image
        ["list_imports"] = Reads(longRunning: true), // call sites wait for the code index
        ["list_exports"] = Reads(),
        ["resolve_address"] = Reads(),
        ["search_bytes"] = Reads(),
        ["read_bytes"] = Reads(),
        ["convert_number"] = Reads(),
        ["list_functions"] = Reads(longRunning: true, openWorld: true), // engine=ida runs IDA
        ["disassemble"] = Reads(longRunning: true, openWorld: true), // engine=ida runs IDA
        ["inspect_instruction"] = Reads(longRunning: true, openWorld: true), // engine=ida runs IDA
        ["search_instructions"] = Reads(longRunning: true, openWorld: true), // engine=ida or ghidra runs that engine
        ["list_globals"] = Reads(longRunning: true, openWorld: true), // engine=ida or ghidra runs that engine
        ["get_cfg"] = Reads(longRunning: true, openWorld: true), // engine=ida runs IDA
        ["find_xrefs"] = Reads(longRunning: true, openWorld: true), // engine=ida runs IDA
        ["native_call_tree"] = Reads(longRunning: true, openWorld: true), // engine=ida runs IDA
        ["find_virtual_calls"] = Reads(longRunning: true, openWorld: true), // crossCheck=true runs IDA
        ["search_native_strings"] = Reads(longRunning: true, openWorld: true), // engine=ida or ghidra runs that engine
        ["get_call_arguments"] = Reads(longRunning: true),
        ["trace_native_values"] = Reads(longRunning: true, openWorld: true), // engine=ida runs IDA
        ["resolve_call_targets"] = Reads(longRunning: true, openWorld: true), // engine=ida runs IDA
        ["analyze_native_function"] = Reads(longRunning: true, openWorld: true), // pseudocode=true runs IDA or Ghidra
        ["trace_native_feature"] = Reads(longRunning: true),
        ["get_exception_info"] = Reads(longRunning: true),
        ["list_cpp_classes"] = Reads(openWorld: true), // engine=ida|ghidra runs the engine
        ["get_native_type"] = Reads(longRunning: true, openWorld: true), // source=engine runs IDA
        ["decompile_native"] = Reads(longRunning: true, openWorld: true), // runs IDA (idalib) in a worker process; its database is a private cache
        ["search_decompiled"] = Reads(longRunning: true, openWorld: true), // decompiles many functions through IDA or Ghidra
        ["verify_native_imports"] = Reads(),
        ["load_pdb"] = Changes(destructive: true, idempotent: true, longRunning: true, openWorld: true), // download=true fetches from a symbol server; clear=true deletes the saved PDB names
        ["search_pdb_symbols"] = Reads(),
        ["get_r2r_code"] = Reads(),
        ["find_r2r_method"] = Reads(),

        // Native builds
        ["compare_native_images"] = Reads(longRunning: true),
        ["map_address_between_builds"] = Reads(longRunning: true),
        ["diff_function"] = Reads(longRunning: true, openWorld: true), // view=pseudocode runs IDA
        ["make_code_pattern"] = Reads(longRunning: true, openWorld: true), // anchor=xrefs with engine=ida runs IDA
        ["search_code_pattern"] = Reads(longRunning: true),
        ["migrate_native_names"] = Changes(destructive: false, idempotent: true, longRunning: true), // never replaces a name; saved to the sidecar

        // Native annotations and edits (names and comments are saved to a per-user sidecar file)
        ["rename_native"] = Changes(destructive: true, idempotent: true, longRunning: true, openWorld: true),
        ["comment_native"] = Changes(destructive: true, idempotent: true, longRunning: true, openWorld: true),
        ["export_native_annotations"] = Changes(destructive: true, idempotent: true, longRunning: true), // overwrite=true replaces the file at outputPath

        // User types in the decompiler engine (saved to the sidecar; runs IDA)
        ["set_native_type"] = Changes(destructive: true, idempotent: true, longRunning: true, openWorld: true),
        ["set_native_local"] = Changes(destructive: true, idempotent: true, longRunning: true, openWorld: true),
        ["set_native_stack_var"] = Changes(destructive: true, idempotent: true, longRunning: true, openWorld: true),
        ["get_native_frame"] = Reads(longRunning: true, openWorld: true),
        ["declare_native_types"] = Changes(destructive: true, idempotent: true, longRunning: true, openWorld: true), // replaces a type of the same name
        ["list_native_types"] = Reads(longRunning: true, openWorld: true),
        ["define_native"] = Changes(destructive: true, idempotent: true, longRunning: true, openWorld: true), // replaces the engine's items in the range
        ["reanalyze_native"] = Changes(destructive: true, idempotent: false, longRunning: true, openWorld: true), // analysis creates and removes the engine's items
        ["set_native_operand"] = Changes(destructive: true, idempotent: true, longRunning: true, openWorld: true),
        ["ida_python"] = Changes(destructive: true, idempotent: false, longRunning: true, openWorld: true), // arbitrary code; off unless --ida-scripting
        ["export_engine_database"] = Changes(destructive: true, idempotent: true, longRunning: true, openWorld: true), // starts IDA or Ghidra; force=true replaces outputPath
        ["ghidra_script"] = Changes(destructive: true, idempotent: false, longRunning: true, openWorld: true), // arbitrary code; off unless --ghidra-scripting
        ["patch_bytes"] = Changes(destructive: true, idempotent: false, longRunning: true),
        ["patch_asm"] = Changes(destructive: true, idempotent: false, longRunning: true),
        ["list_native_edits"] = Reads(longRunning: true),
        ["undo_native_edit"] = Changes(destructive: true, idempotent: false, longRunning: true),
        ["save_native"] = Changes(destructive: true, idempotent: true, longRunning: true), // overwrite=true replaces a file (the original's .bak is made once)
        ["export_native_patches"] = Changes(destructive: true, idempotent: true), // overwrite=true replaces the file at outputPath
        ["migrate_native_patches"] = Changes(destructive: true, idempotent: false, longRunning: true), // patches the new build; matches through both code indexes
        ["update_to_new_build"] = Changes(destructive: true, idempotent: true, longRunning: true), // dryRun=false patches the new build and replaces its imported layers; a re-run reports already_present

        // Crash dumps (an open dump gets an id, as loading an image does)
        ["open_minidump"] = Reads(longRunning: true, openWorld: true), // downloadDac=true fetches the runtime's DAC from a symbol server
        ["dump_stack"] = Reads(),
        ["dump_heap"] = Reads(longRunning: true),
        ["dump_object"] = Reads(),
        ["read_dump_memory"] = Reads(),
        ["symbolize_stack_text"] = Reads(longRunning: true), // waits for the code index of the images it names
        ["bucket_minidumps"] = Reads(longRunning: true), // caches signatures privately

        // Notes (kept per user beside the annotation sidecars)
        ["record_note"] = Changes(destructive: false, idempotent: false),
        ["update_note"] = Changes(destructive: true, idempotent: true), // replaces text or status; a repeat with the same revision is a conflict
        ["list_notes"] = Reads(),

        ["inspect_process"] = Reads(openWorld: true), // query and read handles to a running process only (docs/live-inspection.md); idempotent for the target
    };

    /// <summary>MCP's defaults for a tool the table does not list: may change, destroy and reach anything.</summary>
    public static readonly Effects Unlisted = new(false, true, false, true, false);

    public static Effects Of(string tool) => Table.TryGetValue(tool, out var e) ? e : Unlisted;

    /// <summary>Tools that can run long, by name.</summary>
    public static IEnumerable<string> LongRunning => Table.Where(t => t.Value.LongRunning).Select(t => t.Key).Order(StringComparer.Ordinal);

    /// <summary>
    /// Claude Code saves a text result over 50,000 characters to a file unless the tool raises this limit (capped at 500,000).
    /// This value is over the default page plus ResponseBudget.Slack, so a default page stays in context.
    /// </summary>
    public const string MaxResultSizeMetaKey = "anthropic/maxResultSizeChars";
    public const int MaxResultSizeChars = 100_000;

    /// <summary>Claude Code loads these tools' definitions up front instead of behind tool search.</summary>
    public const string AlwaysLoadMetaKey = "anthropic/alwaysLoad";
    public static readonly IReadOnlySet<string> AlwaysLoad = new HashSet<string>(StringComparer.Ordinal) { "load_assembly", "server_status" };

    /// <summary>Sets every tool's annotations (keeping its title), marks long-running tools in the description and _meta, and sets the client _meta keys.</summary>
    public static void Apply(IEnumerable<McpServerTool> tools)
    {
        foreach (var tool in tools)
        {
            var t = tool.ProtocolTool;
            var e = Of(t.Name);
            t.Annotations = new ToolAnnotations
            {
                Title = t.Annotations?.Title ?? t.Title,
                ReadOnlyHint = e.ReadOnly,
                DestructiveHint = e.Destructive,
                IdempotentHint = e.Idempotent,
                OpenWorldHint = e.OpenWorld,
            };
            t.Meta ??= new JsonObject();
            t.Meta[MaxResultSizeMetaKey] = MaxResultSizeChars;
            if (AlwaysLoad.Contains(t.Name)) t.Meta[AlwaysLoadMetaKey] = true;
            if (!e.LongRunning) continue;
            if (t.Description is { } d && !d.EndsWith(LongRunningSuffix, StringComparison.Ordinal)) t.Description = d + LongRunningSuffix;
            t.Meta[LongRunningMetaKey] = true;
        }
    }
}
