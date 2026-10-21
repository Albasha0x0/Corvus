using Corvus.Core;
using Corvus.Services;

namespace Corvus.Tools;

/// <summary>
/// Which engine answers a native call (ours, ida or ghidra) and why: the Engine line of the text and the Engine /
/// EngineNote fields. One rule for every engine-backed tool, independent of what earlier calls opened: (1) the engine
/// the call names, else the server's --engine; (2) the preferred installed engine (IDA, then Ghidra) that has analyzed
/// these bytes, live in this process or saved in the analysis cache; (3) a tool with a built-in path for the image:
/// ours; an engine-only tool: the first engine installed.
/// </summary>
internal sealed record EngineChoice(string Engine, string Note)
{
    /// <summary>The engine parameter text shared by the tools with a built-in path.</summary>
    public const string Description = "auto (default): IDA or Ghidra if analyzed, else ours.";

    /// <summary>The engine parameter text shared by the engine-only tools.</summary>
    public const string EngineOnlyDescription = "Default auto.";

    /// <summary>Whether an external engine answers (not the built-in index).</summary>
    public bool External => Engine != "ours";

    public string Line => $"Engine: {Engine} ({Note})";

    /// <summary>The mode a call asks for (its engine, else the server default) and whether it named one; unknown names are invalid_argument.</summary>
    public static (EngineMode Mode, bool Named) Mode(string? engine, NativeEngineService? engines) =>
        (EngineModes.Resolve(engine, engines?.DefaultMode ?? EngineMode.Auto), !string.IsNullOrWhiteSpace(engine));

    private static string Origin(EngineMode mode, bool named) => named ? $"engine={EngineModes.Name(mode)}" : $"server default {EngineModes.Name(mode)}";

    /// <summary>
    /// The engine of a call on a tool with a built-in path. <paramref name="builtInGap"/>: why the built-in path cannot
    /// answer for this image (an instruction set it does not decode), or null when it can. ida / ghidra that are not
    /// installed are provider_unavailable; ours is returned as asked (the tool refuses what it cannot answer).
    /// </summary>
    public static EngineChoice Of(EngineMode mode, bool named, NativeEngineService? engines, LoadedNative native, string? builtInGap)
    {
        var origin = Origin(mode, named);
        switch (mode)
        {
            case EngineMode.Ours:
                return new("ours", $"{origin}: the built-in index; no engine consulted");
            case EngineMode.Ida or EngineMode.Ghidra:
                return Named(EngineModes.ProviderId(mode)!, origin, engines);
            default:
                if (engines?.AnalyzedBy(native) is { } analyzed)
                    return new(analyzed, $"{origin}: {NativeEngineService.DisplayName(analyzed)} has analyzed these bytes");
                if (builtInGap != null)
                    return engines?.FirstAvailable() is { } first
                        ? new(first, $"{origin}: {builtInGap}; {NativeEngineService.DisplayName(first)} is the first engine installed")
                        : new("ours", $"{origin}: {builtInGap}, and no engine (IDA, Ghidra) is available");
                return new("ours", $"{origin}: no engine has analyzed these bytes");
        }
    }

    /// <summary>
    /// The engine of a call on an engine-only tool (decompile_native, the engine edits and scripts): the named or server
    /// engine, else the first that has analyzed these bytes, else the first installed; provider_unavailable without one.
    /// </summary>
    public static EngineChoice EngineOnly(string? engine, NativeEngineService engines, LoadedNative native)
    {
        var (mode, named) = Mode(engine, engines);
        var origin = Origin(mode, named);
        if (named && mode == EngineMode.Ours)
            throw new ToolError(ErrorCode.InvalidArgument, "engine=ours: this tool needs an engine (IDA or Ghidra); the built-in analysis has no such view.",
                "use engine=auto, ida or ghidra");
        if (EngineModes.ProviderId(mode) is { } id) return Named(id, origin, engines);
        // ours as the server default leaves the choice to auto: these tools have no built-in path
        var first = engines.FirstAvailable();
        // the preferred engine gets one note whether or not it has analyzed the bytes yet: the answer is the same
        if (engines.AnalyzedBy(native) is { } analyzed && analyzed != first)
            return new(analyzed, $"{origin}: {NativeEngineService.DisplayName(analyzed)} has analyzed these bytes");
        if (first != null)
            return new(first, $"{origin}: {NativeEngineService.DisplayName(first)}, the preferred engine installed");
        var u = engines.Unavailability!.Value;
        throw new ToolError(ErrorCode.ProviderUnavailable, $"No native decompiler engine is available: {u.Reason}", u.Remediation);
    }

    private static EngineChoice Named(string id, string origin, NativeEngineService? engines)
    {
        var display = NativeEngineService.DisplayName(id);
        if (engines == null)
            throw new ToolError(ErrorCode.ProviderUnavailable, $"engine={id}: no analysis engine is set up in this server.", "use engine=auto or engine=ours");
        if (engines.UnavailabilityOf(id) is { } u)
            throw new ToolError(ErrorCode.ProviderUnavailable, $"engine={id}: {display} is not available: {u.Reason}",
                (u.Remediation is { } r ? r + "; or " : "") + "use engine=auto or engine=ours for the built-in analysis");
        return new(id, $"{origin}: {display}'s analysis");
    }
}
