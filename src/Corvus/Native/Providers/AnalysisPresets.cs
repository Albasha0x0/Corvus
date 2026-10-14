using System.Text.Json;
using Corvus.Core;

namespace Corvus.Native.Providers;

/// <summary>
/// Named analyzer option sets for reanalyze_native preset=: built in, plus analysis-presets.json in the data folder,
/// {"name": {"ida": ["OPTION=value", ...], "ghidra": [...]}}; a file entry replaces a built-in one of the same name.
/// </summary>
public static class AnalysisPresets
{
    public const string FileName = "analysis-presets.json";

    // full: what Ghidra's standard profile caps or turns off, back at Ghidra's defaults; IDA's analysis has no profile
    private static readonly Dictionary<string, Dictionary<string, string[]>> BuiltIn = new(StringComparer.OrdinalIgnoreCase)
    {
        ["full"] = new(StringComparer.OrdinalIgnoreCase)
        {
            ["ghidra"] =
            [
                "Decompiler Parameter ID.Analysis Decompiler Timeout (sec)=60",
                "Decompiler Switch Analysis.Analysis Decompiler Timeout (sec)=60",
                "Call Convention ID.Analysis Decompiler Timeout (sec)=60",
                "WindowsResourceReference=true",
            ],
            ["ida"] = [],
        },
    };

    /// <summary>The preset's options for <paramref name="engine"/> as name/value pairs, in file order.</summary>
    public static List<KeyValuePair<string, string>> Options(string preset, string engine, string? path = null)
    {
        var all = Load(path ?? DataFolder.Combine(FileName));
        if (!all.TryGetValue(preset.Trim(), out var byEngine))
            throw new ToolError(ErrorCode.NotFound, $"No analysis preset '{preset.Trim()}'; known: {string.Join(", ", all.Keys.Order(StringComparer.OrdinalIgnoreCase))}.",
                $"pass one of those, or add it to {FileName} in the data folder");
        if (!byEngine.TryGetValue(engine, out var options))
            throw new ToolError(ErrorCode.InvalidArgument, $"Preset '{preset.Trim()}' has no options for {engine}.", $"add a \"{engine}\" list to it in {FileName}");
        var pairs = new List<KeyValuePair<string, string>>();
        foreach (var o in options)
        {
            int eq = o.IndexOf('=');
            if (eq <= 0) throw new ToolError(ErrorCode.MalformedInput, $"Preset '{preset.Trim()}' option '{o}' is not name=value.", $"fix it in {FileName}");
            pairs.Add(new(o[..eq].Trim(), o[(eq + 1)..].Trim()));
        }
        return pairs;
    }

    private static Dictionary<string, Dictionary<string, string[]>> Load(string path)
    {
        var all = new Dictionary<string, Dictionary<string, string[]>>(BuiltIn, StringComparer.OrdinalIgnoreCase);
        if (!File.Exists(path)) return all;
        try
        {
            var file = JsonSerializer.Deserialize<Dictionary<string, Dictionary<string, string[]>>>(File.ReadAllText(path)) ?? [];
            foreach (var (name, byEngine) in file) all[name] = new(byEngine, StringComparer.OrdinalIgnoreCase);
        }
        catch (JsonException e)
        {
            throw new ToolError(ErrorCode.MalformedInput, $"{path} is not a preset file: {e.Message}", "{\"name\": {\"ghidra\": [\"Option=value\"], \"ida\": [...]}}");
        }
        return all;
    }
}
