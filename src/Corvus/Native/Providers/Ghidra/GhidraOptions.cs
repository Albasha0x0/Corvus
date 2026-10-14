using System.Security.Cryptography;
using System.Text;
using Corvus.Core;

namespace Corvus.Native.Providers.Ghidra;

/// <summary>How much auto-analysis a first open runs.</summary>
public enum GhidraAnalysisProfile
{
    /// <summary>Ghidra's analyzers with short decompiler timeouts, no resource script, no ordinal search on PATH.</summary>
    Standard,
    /// <summary>Ghidra's defaults.</summary>
    Full,
    /// <summary>Disassembly and functions; the decompiler-based analyzers are off.</summary>
    Minimal,
}

/// <summary>
/// Every Ghidra-native option string the provider uses (loader arguments, analyzer option names), the environment
/// variables that configure it, and the analysis profile key that names a project in the cache.
/// </summary>
public static class GhidraOptions
{
    public const string DirectoryVariable = "CORVUS_GHIDRA_DIR";
    public const string JavaVariable = "CORVUS_GHIDRA_JAVA";
    public const string MaxMemoryVariable = "CORVUS_GHIDRA_MAXMEM";
    public const string ProfileVariable = "CORVUS_GHIDRA_ANALYSIS";
    /// <summary>Extra analyzer options, "Name=value;Name=value", applied after the profile's.</summary>
    public const string OptionsVariable = "CORVUS_GHIDRA_OPTIONS";
    /// <summary>A directory of Ghidra extensions (zips or unpacked) installed into the workers' private settings (see <see cref="GhidraExtensions"/>).</summary>
    public const string ExtensionsVariable = "CORVUS_GHIDRA_EXTENSIONS";

    /// <summary>Bumped when the worker protocol or what the worker stores in a project changes; part of the profile key.</summary>
    public const int ProtocolVersion = 1;

    /// <summary>Seconds the decompiler may spend on one function (1-600, default 60); not in the profile key, it does not change the project.</summary>
    public const string DecompileTimeoutVariable = "CORVUS_GHIDRA_DECOMPILE_TIMEOUT";
    /// <summary>Decompiler response limit in MB (16-2048, default 200); Ghidra's own 50 fails on large functions.</summary>
    public const string DecompilePayloadVariable = "CORVUS_GHIDRA_DECOMPILE_PAYLOAD_MB";

    public const int MaxDecompileSeconds = 600;

    /// <summary>The per-function decompiler limit: the configured seconds, else 60.</summary>
    public static TimeSpan DecompileTimeout(string? configured)
    {
        if (string.IsNullOrWhiteSpace(configured)) return TimeSpan.FromSeconds(60);
        if (!int.TryParse(configured.Trim(), out var s) || s < 1 || s > MaxDecompileSeconds)
            throw new ToolError(ErrorCode.InvalidArgument, $"'{configured}' is not a decompiler timeout.", $"Set {DecompileTimeoutVariable} to seconds from 1 to {MaxDecompileSeconds}.");
        return TimeSpan.FromSeconds(s);
    }

    /// <summary>The decompiler payload limit: the configured MB, else 200 (measured: an 18 KB function needs more than 50).</summary>
    public static int DecompilePayloadMb(string? configured)
    {
        if (string.IsNullOrWhiteSpace(configured)) return 200;
        if (!int.TryParse(configured.Trim(), out var mb) || mb < 16 || mb > 2048)
            throw new ToolError(ErrorCode.InvalidArgument, $"'{configured}' is not a decompiler payload size.", $"Set {DecompilePayloadVariable} to MB from 16 to 2048.");
        return mb;
    }

    /// <summary>The one retry after a timeout or a full response buffer: four times the first limit, at most <see cref="MaxDecompileSeconds"/>.</summary>
    public static TimeSpan RetryTimeout(TimeSpan first) => TimeSpan.FromSeconds(Math.Min(4 * Math.Ceiling(first.TotalSeconds), MaxDecompileSeconds));

    /// <summary>The request limit of one decompile: both attempts plus a margin for the wait on a decompiler and the reply.</summary>
    public static TimeSpan DecompileRequestTimeout(TimeSpan first, TimeSpan floor)
    {
        var total = first + RetryTimeout(first) + TimeSpan.FromSeconds(30);
        return total > floor ? total : floor;
    }

    private const string DecompilerTimeout = "Analysis Decompiler Timeout (sec)";
    private const string ParameterId = "Decompiler Parameter ID";
    private const string SwitchAnalysis = "Decompiler Switch Analysis";
    private const string CallConventionId = "Call Convention ID";
    private const string ResourceReference = "WindowsResourceReference";
    private const string PdbAnalyzer = "PDB Universal";

    /// <summary>Loader arguments; ones a loader does not offer are skipped by the worker.</summary>
    public static IReadOnlyList<KeyValuePair<string, string>> LoaderArguments(GhidraAnalysisProfile profile) => profile == GhidraAnalysisProfile.Full
        ? [new("-loader-loadLibraries", "false")]
        : [new("-loader-loadLibraries", "false"), new("-loader-ordinalLookup", "false")];

    /// <summary>The ELF loader's base override, so a base-0 shared object loads at its file base instead of 0x100000.</summary>
    public const string ElfImageBaseArgument = "-loader-imagebase";

    /// <summary>Analyzer options set before the first analysis; names the program does not register are reported and skipped.</summary>
    public static IReadOnlyList<KeyValuePair<string, string>> AnalyzerOptions(GhidraAnalysisProfile profile, SymbolMode symbols, string? extra)
    {
        var list = new List<KeyValuePair<string, string>>();
        switch (profile)
        {
            case GhidraAnalysisProfile.Standard:
                // Measured: these analyzers spend most of a default analysis waiting on one function's 60 s decompiler timeout.
                list.Add(new($"{ParameterId}.{DecompilerTimeout}", "10"));
                list.Add(new($"{SwitchAnalysis}.{DecompilerTimeout}", "10"));
                list.Add(new($"{CallConventionId}.{DecompilerTimeout}", "10"));
                list.Add(new(ResourceReference, "false")); // compiles a script per import: 35-42 s
                break;
            case GhidraAnalysisProfile.Minimal:
                list.Add(new(ParameterId, "false"));
                list.Add(new(SwitchAnalysis, "false"));
                list.Add(new(CallConventionId, "false"));
                list.Add(new(ResourceReference, "false"));
                break;
        }
        if (symbols == SymbolMode.Off) list.Add(new(PdbAnalyzer, "false"));
        list.AddRange(ParseExtra(extra));
        return list;
    }

    /// <summary>"Name=value;Name=value" (whitespace around names and values trimmed); malformed entries are InvalidArgument.</summary>
    public static IReadOnlyList<KeyValuePair<string, string>> ParseExtra(string? text)
    {
        var list = new List<KeyValuePair<string, string>>();
        if (string.IsNullOrWhiteSpace(text)) return list;
        foreach (var part in text.Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            int eq = part.IndexOf('=');
            if (eq <= 0)
                throw new ToolError(ErrorCode.InvalidArgument, $"'{part}' in {OptionsVariable} is not Name=value.",
                    $"Set {OptionsVariable} to entries like 'Decompiler Parameter ID=false' separated by ';'.");
            list.Add(new(part[..eq].Trim(), part[(eq + 1)..].Trim()));
        }
        return list;
    }

    public static GhidraAnalysisProfile Profile(string? value) => value?.Trim().ToLowerInvariant() switch
    {
        null or "" or "standard" => GhidraAnalysisProfile.Standard,
        "full" => GhidraAnalysisProfile.Full,
        "minimal" => GhidraAnalysisProfile.Minimal,
        _ => throw new ToolError(ErrorCode.InvalidArgument, $"'{value}' is not an analysis profile.", $"Set {ProfileVariable} to standard, full or minimal."),
    };

    /// <summary>JVM heap: the configured size (a -Xmx value such as 6G), else 4G, or 8G for images over 50 MB (measured peaks: 2.7 GB on 25 MB).</summary>
    public static string MaxMemory(string? configured, long imageBytes)
    {
        if (!string.IsNullOrWhiteSpace(configured))
        {
            var v = configured.Trim();
            if (v.Length < 2 || !long.TryParse(v[..^1], out _) || char.ToUpperInvariant(v[^1]) is not ('G' or 'M'))
                throw new ToolError(ErrorCode.InvalidArgument, $"'{configured}' is not a heap size.", $"Set {MaxMemoryVariable} to a size such as 6G or 4096M.");
            return v;
        }
        return imageBytes > 50L << 20 ? "8G" : "4G";
    }

    /// <summary>
    /// Names the project of one image under one configuration: Ghidra version and revision, protocol, loader arguments,
    /// analyzer options and extensions. A change to any of them analyzes again into a new project. 16 hex digits.
    /// </summary>
    public static string ProfileKey(GhidraInstallation ghidra, GhidraAnalysisProfile profile, IEnumerable<KeyValuePair<string, string>> loaderArguments,
        IEnumerable<KeyValuePair<string, string>> analyzerOptions, IEnumerable<GhidraExtension>? extensions = null)
    {
        var sb = new StringBuilder();
        sb.Append("ghidra=").Append(ghidra.Version).Append('@').Append(ghidra.Revision).Append('\n');
        sb.Append("protocol=").Append(ProtocolVersion).Append('\n');
        sb.Append("profile=").Append(profile).Append('\n');
        foreach (var (k, v) in loaderArguments) sb.Append("loader ").Append(k).Append('=').Append(v).Append('\n');
        foreach (var (k, v) in analyzerOptions) sb.Append("option ").Append(k).Append('=').Append(v).Append('\n');
        foreach (var e in (extensions ?? []).OrderBy(e => e.Name, StringComparer.Ordinal)) sb.Append("extension ").Append(e.Name).Append('=').Append(e.Hash).Append('\n');
        return Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(sb.ToString())))[..16];
    }
}
