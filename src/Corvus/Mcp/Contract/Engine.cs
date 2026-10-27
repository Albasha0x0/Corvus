using L = Corvus.Mcp.LatencyClass;
using O = Corvus.Mcp.OutputClass;

namespace Corvus.Mcp;

// Contract rows of the engine family (Core/Toolsets.cs); the tables and their rules are in ToolEffects.cs, ParameterDomains.cs and ToolContract.cs.

public static partial class ToolEffects
{
    private static Dictionary<string, Effects> EngineTools() => new(StringComparer.Ordinal)
    {
        // Never starts an engine; asks an open one for its view.
        ["get_engine_status"] = Reads(openWorld: true),
        // User types in the decompiler engine (saved to the sidecar; runs IDA)
        ["set_native_type"] = Changes(destructive: true, idempotent: true, longRunning: true, openWorld: true),
        ["set_native_local"] = Changes(destructive: true, idempotent: true, longRunning: true, openWorld: true),
        ["set_native_stack_var"] = Changes(destructive: true, idempotent: true, longRunning: true, openWorld: true),
        ["get_native_frame"] = Reads(longRunning: true, openWorld: true),
        // Replaces a type of the same name.
        ["declare_native_types"] = Changes(destructive: true, idempotent: true, longRunning: true, openWorld: true),
        ["list_native_types"] = Reads(longRunning: true, openWorld: true),
        // Replaces the engine's items in the range.
        ["define_native"] = Changes(destructive: true, idempotent: true, longRunning: true, openWorld: true),
        // Analysis creates and removes the engine's items.
        ["reanalyze_native"] = Changes(destructive: true, idempotent: false, longRunning: true, openWorld: true),
        ["set_native_operand"] = Changes(destructive: true, idempotent: true, longRunning: true, openWorld: true),
        // Arbitrary code; off unless --ida-scripting.
        ["ida_python"] = Changes(destructive: true, idempotent: false, longRunning: true, openWorld: true),
        // Starts IDA or Ghidra; force=true replaces outputPath.
        ["export_engine_database"] = Changes(destructive: true, idempotent: true, longRunning: true, openWorld: true),
        // Arbitrary code; off unless --ghidra-scripting.
        ["ghidra_script"] = Changes(destructive: true, idempotent: false, longRunning: true, openWorld: true),
    };
}

public static partial class ParameterDomains
{
    private static Dictionary<string, IReadOnlyDictionary<string, Domain>> EngineTools() => new(StringComparer.Ordinal)
    {
        ["get_engine_status"] = new Dictionary<string, Domain> { ["engine"] = DecompilerEngine },
        ["get_native_frame"] = new Dictionary<string, Domain> { ["engine"] = DecompilerEngine },
        ["reanalyze_native"] = new Dictionary<string, Domain> { ["engine"] = DecompilerEngine },
        ["define_native"] = new Dictionary<string, Domain> { ["kind"] = Of(["code", "function", "undefine", "data", "flow"]), ["engine"] = DecompilerEngine },
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
        ["get_engine_status"] = Row(O.Report, L.Instant),
        ["set_native_type"] = Row(O.Edit, L.Engine, noDryRun: "the native edit journal undoes it"),
        ["set_native_local"] = Row(O.Edit, L.Engine, noDryRun: "the native edit journal undoes it"),
        ["set_native_stack_var"] = Row(O.Edit, L.Engine, noDryRun: "the native edit journal undoes it"),
        ["get_native_frame"] = Row(O.Report, L.Engine),
        ["declare_native_types"] = Row(O.Edit, L.Engine, noDryRun: "the native edit journal undoes it"),
        ["list_native_types"] = Row(O.List, L.Engine, sort: "engine order (sort= changes it)"),
        ["define_native"] = Row(O.Edit, L.Engine, noDryRun: "the native edit journal undoes it"),
        ["reanalyze_native"] = Row(O.Edit, L.Long, noDryRun: "the native edit journal undoes it"),
        ["set_native_operand"] = Row(O.Edit, L.Engine, noDryRun: "the native edit journal undoes it"),
        ["ida_python"] = Row(O.Report, L.Long, noDryRun: "runs arbitrary code; off unless --ida-scripting"),
        ["ghidra_script"] = Row(O.Report, L.Long, noDryRun: "runs arbitrary code; off unless --ghidra-scripting"),
        ["export_engine_database"] = Row(O.Edit, L.Long, noDryRun: "writes only to the path it is given; overwrite=false refuses an existing file"),
    };
}
