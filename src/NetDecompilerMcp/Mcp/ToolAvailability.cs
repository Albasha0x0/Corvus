using NetDecompilerMcp.Native.Providers;

namespace NetDecompilerMcp.Mcp;

/// <summary>
/// Tools, and modes of tools, that cannot work on this machine, with the reason and the fix (server_status unavailableTools).
/// The catalog itself is the same everywhere, so its digest does not depend on the machine.
/// </summary>
public static class ToolAvailability
{
    public sealed record Unavailable(string Tool, string? Mode, string Reason, string? Remediation);

    /// <summary>Tools whose every call runs a decompiler engine, by provider id.</summary>
    public static readonly IReadOnlyDictionary<string, string> EngineOnly = new Dictionary<string, string>(StringComparer.Ordinal)
    {
        ["decompile_native"] = "ida",
        ["set_native_type"] = "ida",
        ["set_native_local"] = "ida",
        ["set_native_stack_var"] = "ida",
        ["get_native_frame"] = "ida",
        ["declare_native_types"] = "ida",
        ["list_native_types"] = "ida",
        ["ida_python"] = "ida",
    };

    /// <summary>Modes that run an engine although the tool has no engine parameter: (tool, mode, provider id).</summary>
    public static readonly IReadOnlyList<(string Tool, string Mode, string Provider)> EngineModes = [("find_virtual_calls", "crossCheck=true", "ida")];

    public static readonly IReadOnlyList<string> WindowsOnly = ["inspect_process"];

    /// <summary>Modes that launch a program found on this machine: (tool, mode, found, reason, fix).</summary>
    private static IEnumerable<(string Tool, string Mode, bool Found, string Reason, string Remediation)> ExternalPrograms()
    {
        yield return ("unity_overview", "detectItEasy=true", Services.Analysis.UnityOverview.FindDie() != null,
            "Detect It Easy (diec) was not found in NDM_DIE or on PATH", "set NDM_DIE to the Detect It Easy folder (or diec.exe)");
    }

    /// <summary>Every tool these tables name, for the drift test.</summary>
    public static IEnumerable<string> NamedTools =>
        EngineOnly.Keys.Concat(EngineModes.Select(m => m.Tool)).Concat(WindowsOnly).Concat(ExternalPrograms().Select(p => p.Tool)).Distinct();

    /// <summary>What does not work here among <paramref name="registered"/> tools, given the engines' static availability.</summary>
    public static List<Unavailable> Of(IReadOnlySet<string> registered, IReadOnlyList<ProviderAvailability> engines, bool idaScripting, bool isWindows)
    {
        var result = new List<Unavailable>();
        ProviderAvailability? Missing(string provider) => engines.FirstOrDefault(e => e.ProviderId == provider && !e.IsAvailable)
            ?? (engines.Any(e => e.ProviderId == provider) ? null : new ProviderAvailability(provider, false, $"no {provider} provider in this build", null, new Dictionary<string, string>()));

        foreach (var (tool, provider) in EngineOnly.Where(e => registered.Contains(e.Key)))
        {
            if (Missing(provider) is { } m) result.Add(new(tool, null, m.Reason ?? $"{provider} is not available", m.Remediation));
            else if (tool == "ida_python" && !idaScripting)
                result.Add(new(tool, null, "off: it runs arbitrary Python with the server's rights", $"start the server with --ida-scripting (or {Core.ServerOptions.IdaScriptingVariable}=1)"));
        }
        // Engine values of the engine parameters, e.g. engine=ida on disassemble.
        foreach (var tool in registered.Where(t => !EngineOnly.ContainsKey(t)).Order(StringComparer.Ordinal))
            if (ParameterDomains.Table.TryGetValue(tool, out var parameters) && parameters.TryGetValue("engine", out var domain))
                foreach (var value in domain.Values)
                    if (engines.FirstOrDefault(e => e.ProviderId == value) is { IsAvailable: false } m)
                        result.Add(new(tool, $"engine={value}", m.Reason ?? $"{value} is not available", m.Remediation));
        foreach (var (tool, mode, provider) in EngineModes)
            if (registered.Contains(tool) && Missing(provider) is { } m) result.Add(new(tool, mode, m.Reason ?? $"{provider} is not available", m.Remediation));
        foreach (var tool in WindowsOnly)
            if (registered.Contains(tool) && !isWindows)
                result.Add(new(tool, null, "it uses the Windows process API; this server is not running on Windows", "inspect a minidump instead, or run the server on Windows"));
        foreach (var (tool, mode, found, reason, fix) in ExternalPrograms())
            if (registered.Contains(tool) && !found) result.Add(new(tool, mode, reason, fix));
        return result;
    }
}
