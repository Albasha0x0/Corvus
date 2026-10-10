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
/// <item>OpenWorld: reaches the network or launches a process. A reference pack download (any .NET tool can trigger one when
/// an assembly targets a .NET version that is not installed; NDM_OFFLINE=1 turns it off) is not counted.</item>
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
        ["get_resource"] = Changes(destructive: true, idempotent: true), // savePath replaces an existing file
        ["export_project"] = Changes(destructive: false, idempotent: true, longRunning: true), // refuses a non-empty directory

        // Files and containers (nothing executed)
        ["summarize_file"] = Reads(),
        ["survey_features"] = Reads(),
        ["extract_strings"] = Changes(destructive: true, idempotent: true), // savePath; overwrite=true replaces a file
        ["extract_embedded"] = Changes(destructive: false, idempotent: true), // writes unique names, never over a different file
        ["search_container"] = Reads(),
        ["unpack_container"] = Changes(destructive: false, idempotent: true, longRunning: true), // extracts into an empty directory (or its own earlier unpack) and loads
        ["unity_overview"] = Reads(openWorld: true), // headers and listings only; detectItEasy=true launches diec

        // Builds
        ["compare_assemblies"] = Reads(longRunning: true),
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
        ["export_edits"] = Changes(destructive: true, idempotent: true), // replaces the file at path
        ["apply_edits"] = Changes(destructive: true, idempotent: false),
        ["save_assembly"] = Changes(destructive: true, idempotent: true), // overwrite=true replaces a file (the original's .bak is made once)

        // Il2Cpp
        ["get_il2cpp_info"] = Reads(),
        ["find_method_by_address"] = Reads(),
        ["export_il2cpp_symbols"] = Changes(destructive: true, idempotent: true, longRunning: true), // replaces the files it writes
        ["generate_cpp_binding"] = Reads(),
        ["apply_il2cpp_names"] = Changes(destructive: true, idempotent: true, longRunning: true), // replaces the image's il2cpp names

        // Native images
        ["get_pe_info"] = Reads(),
        ["list_imports"] = Reads(longRunning: true), // call sites wait for the code index
        ["list_exports"] = Reads(),
        ["resolve_address"] = Reads(),
        ["search_bytes"] = Reads(),
        ["read_bytes"] = Reads(),
        ["list_functions"] = Reads(longRunning: true),
        ["disassemble"] = Reads(longRunning: true),
        ["get_cfg"] = Reads(longRunning: true),
        ["find_xrefs"] = Reads(longRunning: true),
        ["native_call_tree"] = Reads(longRunning: true),
        ["search_native_strings"] = Reads(longRunning: true),
        ["get_call_arguments"] = Reads(longRunning: true),
        ["get_exception_info"] = Reads(longRunning: true),
        ["list_cpp_classes"] = Reads(),
        ["decompile_native"] = Reads(longRunning: true, openWorld: true), // runs IDA (idalib) in a worker process; its database is a private cache
        ["verify_native_imports"] = Reads(),
        ["load_pdb"] = Changes(destructive: false, idempotent: true, longRunning: true, openWorld: true), // download=true fetches from a symbol server
        ["search_pdb_symbols"] = Reads(),
        ["get_r2r_code"] = Reads(),
        ["find_r2r_method"] = Reads(),

        // Native builds
        ["compare_native_images"] = Reads(longRunning: true),
        ["map_address_between_builds"] = Reads(longRunning: true),
        ["make_code_pattern"] = Reads(longRunning: true),
        ["search_code_pattern"] = Reads(longRunning: true),
        ["migrate_native_names"] = Changes(destructive: false, idempotent: true, longRunning: true), // never replaces a name; saved to the sidecar

        // Native annotations and edits (names and comments are saved to a per-user sidecar file)
        ["rename_native"] = Changes(destructive: true, idempotent: true, longRunning: true),
        ["comment_native"] = Changes(destructive: true, idempotent: true, longRunning: true),
        ["export_native_annotations"] = Changes(destructive: true, idempotent: true, longRunning: true), // replaces the file at outputPath
        ["patch_bytes"] = Changes(destructive: true, idempotent: false, longRunning: true),
        ["patch_asm"] = Changes(destructive: true, idempotent: false, longRunning: true),
        ["list_native_edits"] = Reads(longRunning: true),
        ["undo_native_edit"] = Changes(destructive: true, idempotent: false, longRunning: true),
        ["save_native"] = Changes(destructive: true, idempotent: true, longRunning: true), // overwrite=true replaces a file (the original's .bak is made once)
        ["export_native_patches"] = Changes(destructive: true, idempotent: true), // replaces the file at outputPath
        ["migrate_native_patches"] = Changes(destructive: true, idempotent: false, longRunning: true), // patches the new build; matches through both code indexes

        // Crash dumps (an open dump gets an id, as loading an image does)
        ["open_minidump"] = Reads(),
        ["dump_stack"] = Reads(),
        ["read_dump_memory"] = Reads(),
        ["inspect_process"] = Reads(), // query and read handles to a running process only (docs/live-inspection.md); idempotent for the target
    };

    /// <summary>MCP's defaults for a tool the table does not list: may change, destroy and reach anything.</summary>
    public static readonly Effects Unlisted = new(false, true, false, true, false);

    public static Effects Of(string tool) => Table.TryGetValue(tool, out var e) ? e : Unlisted;

    /// <summary>Tools that can run long, by name.</summary>
    public static IEnumerable<string> LongRunning => Table.Where(t => t.Value.LongRunning).Select(t => t.Key).Order(StringComparer.Ordinal);

    /// <summary>Sets every tool's annotations (keeping its title), and marks long-running tools in the description and _meta.</summary>
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
            if (!e.LongRunning) continue;
            if (t.Description is { } d && !d.EndsWith(LongRunningSuffix, StringComparison.Ordinal)) t.Description = d + LongRunningSuffix;
            t.Meta ??= new JsonObject();
            t.Meta[LongRunningMetaKey] = true;
        }
    }
}
