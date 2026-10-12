namespace Corvus.Mcp;

// Contract rows of the native family (Core/Toolsets.cs); the tables and their rules are in ToolEffects.cs and ParameterDomains.cs.

public static partial class ToolEffects
{
    private static Dictionary<string, Effects> NativeTools() => new(StringComparer.Ordinal)
    {
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
        ["find_similar_functions"] = Reads(longRunning: true),
        ["get_exception_info"] = Reads(longRunning: true),
        ["list_cpp_classes"] = Reads(openWorld: true), // engine=ida|ghidra runs the engine
        ["get_native_type"] = Reads(longRunning: true, openWorld: true), // source=engine runs IDA
        ["decompile_native"] = Reads(longRunning: true, openWorld: true), // runs IDA (idalib) in a worker process; its database is a private cache
        ["search_decompiled"] = Reads(longRunning: true, openWorld: true), // decompiles many functions through IDA or Ghidra
        ["emulate_native"] = Reads(longRunning: true, openWorld: true), // p-code emulation in the Ghidra worker; the program is not changed
        ["verify_native_imports"] = Reads(longRunning: true), // the whole IL and every library the declarations bind to
        ["load_pdb"] = Changes(destructive: true, idempotent: true, longRunning: true, openWorld: true), // download=true fetches from a symbol server; clear=true deletes the saved PDB names
        ["search_pdb_symbols"] = Reads(),
    };
}

public static partial class ParameterDomains
{
    private static Dictionary<string, IReadOnlyDictionary<string, Domain>> NativeTools() => new(StringComparer.Ordinal)
    {
        ["verify_native_imports"] = new Dictionary<string, Domain> { ["platform"] = Of(["auto", "windows", "linux", "osx", "android", "ios"], "macos") },
        ["get_nativeaot_info"] = new Dictionary<string, Domain> { ["view"] = Of(["summary", "sections", "types", "type", "methods", "strings", "statics"]) },
        ["list_functions"] = new Dictionary<string, Domain> { ["sort"] = Of(["address", "name", "size", "callers"]), ["engine"] = Engine,
            ["view"] = Of(["functions", "candidates"]) },
        ["disassemble"] = new Dictionary<string, Domain> { ["engine"] = Engine },
        ["inspect_instruction"] = new Dictionary<string, Domain> { ["engine"] = Engine },
        ["search_instructions"] = new Dictionary<string, Domain> { ["engine"] = Engine },
        ["list_globals"] = new Dictionary<string, Domain> { ["engine"] = Engine },
        ["search_native_strings"] = new Dictionary<string, Domain> { ["engine"] = Engine },
        ["list_cpp_classes"] = new Dictionary<string, Domain> { ["engine"] = Of(["auto", "ours", "ida", "ghidra"], "built-in", "builtin") },
        ["get_cfg"] = new Dictionary<string, Domain> { ["engine"] = Engine },
        ["find_xrefs"] = new Dictionary<string, Domain> { ["engine"] = Engine, ["direction"] = Of(["to", "from", "both"]), ["kind"] = Of(["any", "code", "data"]), ["scope"] = Of(["typed", "all"]) },
        ["native_call_tree"] = new Dictionary<string, Domain> { ["direction"] = Of(["callers", "callees", "both"]), ["calls"] = Of(["all", "direct", "virtual"]), ["engine"] = Engine },
        ["decompile_native"] = new Dictionary<string, Domain> { ["engine"] = DecompilerEngine },
        ["search_decompiled"] = new Dictionary<string, Domain> { ["engine"] = DecompilerEngine },
        ["emulate_native"] = new Dictionary<string, Domain> { ["engine"] = Of(["auto", "ghidra"]) },
        ["get_engine_status"] = new Dictionary<string, Domain> { ["engine"] = DecompilerEngine },
        ["get_native_type"] = new Dictionary<string, Domain>
        {
            ["source"] = Of(["auto", "pdb", "rtti", "il2cpp", "objc", "swift", "engine"]), ["format"] = Of(["table", "c"]), ["engine"] = DecompilerEngine,
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
