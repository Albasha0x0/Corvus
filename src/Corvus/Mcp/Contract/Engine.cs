using L = Corvus.Mcp.LatencyClass;
using O = Corvus.Mcp.OutputClass;

namespace Corvus.Mcp;

// Contract rows of the engine family (Core/Toolsets.cs); the tables and their rules are in ToolEffects.cs, ParameterDomains.cs and ToolContract.cs.

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

public sealed partial record ToolContract
{
    private static Dictionary<string, ToolContract> EngineTools() => new(StringComparer.Ordinal)
    {
        ["set_native_type"] = Row(O.Edit, L.Engine, noDryRun: "N13: the native edit journal undoes it (EL-6)"),
        ["set_native_local"] = Row(O.Edit, L.Engine, noDryRun: "N13: the native edit journal undoes it (EL-6)"),
        ["set_native_stack_var"] = Row(O.Edit, L.Engine, noDryRun: "N13: the native edit journal undoes it (EL-6)"),
        ["get_native_frame"] = Row(O.Report, L.Engine),
        ["declare_native_types"] = Row(O.Edit, L.Engine, noDryRun: "N13: the native edit journal undoes it (EL-6)"),
        ["list_native_types"] = Row(O.List, L.Engine, sort: "engine order (sort= changes it)"),
        ["define_native"] = Row(O.Edit, L.Engine, noDryRun: "N13: the native edit journal undoes it (EL-6)"),
        ["reanalyze_native"] = Row(O.Edit, L.Long, noDryRun: "N13: the native edit journal undoes it (EL-6)"),
        ["set_native_operand"] = Row(O.Edit, L.Engine, noDryRun: "N13: the native edit journal undoes it (EL-6)"),
        ["ida_python"] = Row(O.Report, L.Long, noDryRun: "runs arbitrary code; off unless --ida-scripting"),
        ["ghidra_script"] = Row(O.Report, L.Long, noDryRun: "runs arbitrary code; off unless --ghidra-scripting"),
        ["export_engine_database"] = Row(O.Edit, L.Long, noDryRun: "writes only to the path it is given; overwrite=false refuses an existing file"),
    };
}
