using Corvus.Core;
using Corvus.Services;

namespace Corvus.Tools;

/// <summary>The engine that answers a native call and why: the named or server engine, else one that analyzed these bytes, else ours or the first installed.</summary>
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

    /// <summary>The engine for a tool with a built-in path; <paramref name="builtInGap"/> says why ours cannot answer, null when it can.</summary>
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
                    return new(analyzed, Analyzed(origin, engines!, native, analyzed));
                if (builtInGap != null)
                    return engines?.FirstAvailable() is { } first
                        ? new(first, $"{origin}: {builtInGap}; {NativeEngineService.DisplayName(first)} is the first engine installed")
                        : new("ours", $"{origin}: {builtInGap}, and no engine (IDA, Ghidra) is available");
                return new("ours", $"{origin}: no engine has analyzed these bytes");
        }
    }

    /// <summary>The engine for an engine-only tool; throws provider_unavailable when none is installed.</summary>
    public static EngineChoice EngineOnly(string? engine, NativeEngineService engines, LoadedNative native)
    {
        var (mode, named) = Mode(engine, engines);
        var origin = Origin(mode, named);
        if (named && mode == EngineMode.Ours)
            throw new ToolError(ErrorCode.InvalidArgument, "engine=ours: this tool needs IDA or Ghidra.",
                "use engine=auto, ida or ghidra");
        if (EngineModes.ProviderId(mode) is { } id) return Named(id, origin, engines);
        // A server default of ours falls back to auto; these tools have no built-in path.
        var first = engines.FirstAvailable();
        // The preferred engine gets one note whether or not it has analyzed the bytes yet.
        if (engines.AnalyzedBy(native) is { } analyzed && analyzed != first)
            return new(analyzed, Analyzed(origin, engines, native, analyzed));
        if (first != null)
            return new(first, $"{origin}: {NativeEngineService.DisplayName(first)}, the preferred engine installed");
        var u = engines.Unavailability!.Value;
        throw new ToolError(ErrorCode.ProviderUnavailable, $"No native decompiler engine is available: {u.Reason}", u.Remediation);
    }

    private static string Analyzed(string origin, NativeEngineService engines, LoadedNative native, string id) =>
        engines.IsPartial(native, id)
            ? $"{origin}: {NativeEngineService.DisplayName(id)}'s analysis of these bytes is partial (an open's time ran out); reanalyze_native completes it"
            : $"{origin}: {NativeEngineService.DisplayName(id)} has analyzed these bytes";

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
