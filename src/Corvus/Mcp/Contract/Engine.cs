namespace Corvus.Mcp;

// Contract rows of the engine family (Core/Toolsets.cs); the tables and their rules are in ToolEffects.cs and ParameterDomains.cs.

public static partial class ToolEffects
{
    private static Dictionary<string, Effects> EngineTools() => new(StringComparer.Ordinal)
    {
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
    };
}

public static partial class ParameterDomains
{
    private static Dictionary<string, IReadOnlyDictionary<string, Domain>> EngineTools() => new(StringComparer.Ordinal)
    {
        ["get_native_frame"] = new Dictionary<string, Domain> { ["engine"] = DecompilerEngine },
        ["reanalyze_native"] = new Dictionary<string, Domain> { ["engine"] = DecompilerEngine },
        ["define_native"] = new Dictionary<string, Domain> { ["kind"] = Of(["code", "function", "undefine", "data"]), ["engine"] = DecompilerEngine },
        ["set_native_operand"] = new Dictionary<string, Domain> { ["display"] = Of(Native.Providers.NativeOperandEdit.Displays), ["engine"] = DecompilerEngine },
        ["set_native_stack_var"] = new Dictionary<string, Domain> { ["showDecompile"] = ShowDecompile, ["engine"] = DecompilerEngine },
        ["set_native_type"] = new Dictionary<string, Domain> { ["showDecompile"] = ShowDecompile, ["engine"] = DecompilerEngine },
        ["set_native_local"] = new Dictionary<string, Domain> { ["showDecompile"] = ShowDecompile, ["engine"] = DecompilerEngine },
        ["declare_native_types"] = new Dictionary<string, Domain> { ["engine"] = DecompilerEngine },
        ["list_native_types"] = new Dictionary<string, Domain> { ["engine"] = DecompilerEngine, ["kind"] = Of(["struct", "union", "udt", "enum", "typedef", "func", "ptr"]), ["sort"] = Of(["name", "size"], "ordinal") },
        ["ida_python"] = new Dictionary<string, Domain> { ["engine"] = IdaEngine },
        ["export_engine_database"] = new Dictionary<string, Domain> { ["engine"] = DecompilerEngine },
        ["ghidra_script"] = new Dictionary<string, Domain> { ["engine"] = Of(["auto", "ghidra"]) },
    };
}
