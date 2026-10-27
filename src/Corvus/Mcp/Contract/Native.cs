using L = Corvus.Mcp.LatencyClass;
using O = Corvus.Mcp.OutputClass;

namespace Corvus.Mcp;

// Contract rows of the native family (Core/Toolsets.cs); the tables and their rules are in ToolEffects.cs, ParameterDomains.cs and ToolContract.cs.

public static partial class ToolEffects
{
    private static Dictionary<string, Effects> NativeTools() => new(StringComparer.Ordinal)
    {
        // Native images
        ["get_pe_info"] = Reads(),
        // The first call reads the metadata of a large image.
        ["get_nativeaot_info"] = Reads(longRunning: true),
        // Call sites wait for the code index.
        ["list_imports"] = Reads(longRunning: true),
        ["list_exports"] = Reads(),
        ["resolve_address"] = Reads(),
        ["search_bytes"] = Reads(),
        ["read_bytes"] = Reads(),
        ["convert_number"] = Reads(),
        // engine=ida runs IDA.
        ["list_functions"] = Reads(longRunning: true, openWorld: true),
        // engine=ida runs IDA.
        ["disassemble"] = Reads(longRunning: true, openWorld: true),
        // engine=ida runs IDA.
        ["inspect_instruction"] = Reads(longRunning: true, openWorld: true),
        // engine=ida or ghidra runs that engine.
        ["search_instructions"] = Reads(longRunning: true, openWorld: true),
        // engine=ida or ghidra runs that engine.
        ["list_globals"] = Reads(longRunning: true, openWorld: true),
        // engine=ida runs IDA.
        ["get_cfg"] = Reads(longRunning: true, openWorld: true),
        // engine=ida runs IDA.
        ["find_xrefs"] = Reads(longRunning: true, openWorld: true),
        // engine=ida runs IDA.
        ["native_call_tree"] = Reads(longRunning: true, openWorld: true),
        // crossCheck=true runs IDA.
        ["find_virtual_calls"] = Reads(longRunning: true, openWorld: true),
        // engine=ida or ghidra runs that engine.
        ["search_native_strings"] = Reads(longRunning: true, openWorld: true),
        ["get_call_arguments"] = Reads(longRunning: true),
        // engine=ida runs IDA.
        ["trace_native_values"] = Reads(longRunning: true, openWorld: true),
        // engine=ida runs IDA.
        ["resolve_call_targets"] = Reads(longRunning: true, openWorld: true),
        // pseudocode=true runs IDA or Ghidra.
        ["analyze_native_function"] = Reads(longRunning: true, openWorld: true),
        // engine=ida or ghidra runs that engine.
        ["trace_native_feature"] = Reads(longRunning: true, openWorld: true),
        ["find_similar_functions"] = Reads(longRunning: true),
        ["get_exception_info"] = Reads(longRunning: true),
        // engine=ida|ghidra runs the engine.
        ["list_cpp_classes"] = Reads(openWorld: true),
        // source=engine runs IDA.
        ["get_native_type"] = Reads(longRunning: true, openWorld: true),
        // Runs IDA (idalib) in a worker process; its database is a private cache.
        ["decompile_native"] = Reads(longRunning: true, openWorld: true),
        // Decompiles many functions through IDA or Ghidra.
        ["search_decompiled"] = Reads(longRunning: true, openWorld: true),
        // Emulation in the Ghidra worker, in process or in speakeasy; the program is not changed.
        ["emulate_native"] = Reads(longRunning: true, openWorld: true),
        // The whole IL and every library the declarations bind to.
        ["verify_native_imports"] = Reads(longRunning: true),
        // download=true fetches from a symbol server; clear=true deletes the saved PDB names.
        ["load_pdb"] = Changes(destructive: true, idempotent: true, longRunning: true, openWorld: true),
        ["search_pdb_symbols"] = Reads(),
    };
}

public static partial class ParameterDomains
{
    private static Dictionary<string, IReadOnlyDictionary<string, Domain>> NativeTools() => new(StringComparer.Ordinal)
    {
        ["verify_native_imports"] = new Dictionary<string, Domain> { ["platform"] = Of(["auto", "windows", "linux", "osx", "android", "ios"], "macos") },
        ["get_nativeaot_info"] = new Dictionary<string, Domain> { ["view"] = Of(["summary", "sections", "types", "type", "methods", "strings", "statics"]) },
        ["get_pe_info"] = new Dictionary<string, Domain> { ["view"] = Of(["summary", "code"]) },
        ["trace_native_feature"] = new Dictionary<string, Domain> { ["engine"] = Engine },
        ["list_functions"] = new Dictionary<string, Domain> { ["sort"] = Of(["address", "name", "size", "callers"]), ["engine"] = Engine,
            ["view"] = Of(["functions", "candidates"]) },
        ["disassemble"] = new Dictionary<string, Domain> { ["engine"] = Engine },
        ["inspect_instruction"] = new Dictionary<string, Domain> { ["engine"] = Engine },
        ["search_instructions"] = new Dictionary<string, Domain> { ["engine"] = Engine },
        ["list_globals"] = new Dictionary<string, Domain> { ["engine"] = Engine },
        ["search_native_strings"] = new Dictionary<string, Domain> { ["engine"] = Engine },
        ["list_cpp_classes"] = new Dictionary<string, Domain> { ["engine"] = Of(["auto", "ours", "ida", "ghidra"], "built-in", "builtin") },
        ["get_cfg"] = new Dictionary<string, Domain> { ["engine"] = Engine },
        ["find_xrefs"] = new Dictionary<string, Domain> { ["engine"] = Engine, ["direction"] = Of(["to", "from", "both"]), ["kind"] = Of(["any", "code", "data", "metadata"]), ["scope"] = Of(["typed", "all"]) },
        ["native_call_tree"] = new Dictionary<string, Domain> { ["direction"] = Of(["callers", "callees", "both"]), ["calls"] = Of(["all", "direct", "virtual"]), ["engine"] = Engine },
        ["decompile_native"] = new Dictionary<string, Domain> { ["engine"] = Of(["auto", "ida", "ghidra", "all"]) },
        ["search_decompiled"] = new Dictionary<string, Domain> { ["engine"] = DecompilerEngine },
        ["emulate_native"] = new Dictionary<string, Domain> { ["engine"] = Of(["auto", "ghidra", "ours", "speakeasy"], "built-in", "builtin") },
        ["get_native_type"] = new Dictionary<string, Domain>
        {
            ["source"] = Of(["auto", "pdb", "rtti", "metadata", "objc", "swift", "engine"]), ["format"] = Of(["table", "c"]), ["engine"] = DecompilerEngine,
        },
        ["find_virtual_calls"] = new Dictionary<string, Domain> { ["status"] = Of(["exact", "possible", "unresolved"]) },
        ["trace_native_values"] = new Dictionary<string, Domain> { ["direction"] = Of(["backward", "forward", "both"], "back", "fwd"), ["engine"] = Engine },
        ["resolve_call_targets"] = new Dictionary<string, Domain>
        {
            ["scope"] = Of(["site", "function", "image"]),
            ["status"] = Of(["all", "resolved", "possible", "ambiguous", "unresolved", "indirect"]),
            ["engine"] = Engine,
        },
        ["analyze_native_function"] = new Dictionary<string, Domain> { ["engine"] = DecompilerEngine },
        ["search_pdb_symbols"] = new Dictionary<string, Domain> { ["kind"] = Of(["function", "data", "public", "all"], "functions", "publics") },
        ["find_similar_functions"] = new Dictionary<string, Domain> { ["view"] = Of(["similar", "duplicates", "clusters"]), ["scope"] = Of(["image", "all"]) },
    };
}

public sealed partial record ToolContract
{
    private static Dictionary<string, ToolContract> NativeTools() => new(StringComparer.Ordinal)
    {
        ["get_pe_info"] = Row(O.Report, L.Instant, lean: true, core: true),
        ["list_imports"] = Row(O.List, L.Interactive, lean: true, core: true, sort: "import directory order"),
        ["list_exports"] = Row(O.List, L.Instant, lean: true, core: true, sort: "ordinal"),
        ["resolve_address"] = Row(O.Report, L.Instant, lean: true, core: true),
        ["search_bytes"] = Row(O.List, L.Interactive, lean: true, core: true, sort: "section, address"),
        ["read_bytes"] = Row(O.Bytes, L.Instant, lean: true, core: true),
        ["convert_number"] = Row(O.Report, L.Instant, core: true),
        ["list_functions"] = Row(O.List, L.Interactive, lean: true, core: true, sort: "address (sort= changes it)"),
        ["list_globals"] = Row(O.List, L.Interactive, core: true, sort: "address"),
        ["disassemble"] = Row(O.Bytes, L.Interactive, lean: true, core: true),
        ["inspect_instruction"] = Row(O.Bytes, L.Interactive, core: true),
        ["search_instructions"] = Row(O.List, L.Interactive, core: true, sort: "function address"),
        ["get_cfg"] = Row(O.Bytes, L.Interactive, core: true),
        ["find_xrefs"] = Row(O.List, L.Interactive, lean: true, core: true, sort: "source address"),
        ["native_call_tree"] = Row(O.List, L.Interactive, core: true, sort: "call-site address at each level"),
        ["find_virtual_calls"] = Row(O.List, L.Interactive, core: true, sort: "call-site address"),
        ["search_native_strings"] = Row(O.List, L.Interactive, lean: true, core: true, sort: "address"),
        ["get_call_arguments"] = Row(O.List, L.Interactive, core: true, sort: "call-site address"),
        ["trace_native_values"] = Row(O.Report, L.Interactive, core: true),
        ["resolve_call_targets"] = Row(O.List, L.Interactive, core: true, sort: "call-site address"),
        ["analyze_native_function"] = Row(O.Report, L.Interactive, lean: true, core: true),
        ["trace_native_feature"] = Row(O.Report, L.Interactive, core: true),
        ["find_similar_functions"] = Row(O.List, L.Interactive, core: true, sort: "score descending, image, address"),
        ["get_exception_info"] = Row(O.Report, L.Interactive, core: true),
        ["list_cpp_classes"] = Row(O.List, L.Interactive, core: true, sort: "name, type descriptor address"),
        ["get_native_type"] = Row(O.Report, L.Interactive, core: true),
        ["decompile_native"] = Row(O.Code, L.Engine, lean: true, core: true),
        ["search_decompiled"] = Row(O.List, L.Long, core: true, sort: "function address"),
        ["emulate_native"] = Row(O.Report, L.Engine, core: true),
        ["verify_native_imports"] = Row(O.List, L.Long, core: true, sort: "status severity, module, entry point"),
        ["load_pdb"] = Row(O.Edit, L.Interactive, core: true, noDryRun: "clear=true removes the saved PDB names"),
        ["search_pdb_symbols"] = Row(O.List, L.Instant, core: true, sort: "address"),
        ["get_nativeaot_info"] = Row(O.Report, L.Interactive, core: true),
    };
}
