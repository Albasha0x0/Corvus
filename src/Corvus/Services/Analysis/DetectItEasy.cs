using System.Text.Json;
using Corvus.Core;
using Corvus.Native.Providers;

namespace Corvus.Services.Analysis;

/// <summary>Reads the detections of Detect It Easy (diec) on one file.</summary>
internal static class DetectItEasy
{
    private const long MaxOutput = 4 * 1024 * 1024;

    internal sealed record Detection(string Type, string Text);

    /// <summary>Detections read from diec output; Problem names why none were read, null when read.</summary>
    internal sealed record Result(IReadOnlyList<Detection> Detections, string? Problem);

    /// <summary>The program found through CORVUS_DIE (a file or its folder) or PATH; null when absent.</summary>
    internal static string? Find() => ExternalTools.Locate(ExternalTools.Die)?.Path;

    /// <summary>Whether CORVUS_DIE is set, the opt-in that lets file views run diec unasked.</summary>
    internal static bool Configured() => ExternalTools.ReadVariable(ExternalTools.Die.Variable) is { Length: > 0 };

    /// <summary>Runs diec on a file; a stall (default: the shared window) ends the run and the problem names the bytes reached.</summary>
    internal static Result Scan(string die, string file, CancellationToken ct, TimeSpan? stallWindow = null)
    {
        var window = stallWindow ?? ServerOptions.StallWindow();
        var name = Path.GetFileName(file);
        var run = ExternalTools.Run(die, ExternalTools.Arguments(ExternalTools.Die, "scan", ("file", file)), Timeout.InfiniteTimeSpan, MaxOutput, ct,
            watch: new(new StallRule(window)));
        if (run.StartError != null) return new([], $"Detect It Easy on {name}: {run.StartError}.");
        if (run.StalledAt is { } reached)
            return new([], $"Detect It Easy on {name}: no output for {window.TotalSeconds:0.###} s and under 1% of a core after {reached:N0} bytes; repeat the call or raise {ServerOptions.StallWindowVariable}.");
        if (run.Truncated) return new([], $"Detect It Easy on {name}: output over {MaxOutput / (1024 * 1024)} MiB.");
        var found = new List<Detection>();
        try
        {
            using var doc = JsonDocument.Parse(run.Output);
            foreach (var detect in doc.RootElement.GetProperty("detects").EnumerateArray())
                foreach (var value in detect.TryGetProperty("values", out var values) ? values.EnumerateArray() : default)
                {
                    var type = value.TryGetProperty("type", out var t) ? t.GetString() ?? "" : "";
                    var text = value.TryGetProperty("string", out var s) ? s.GetString() ?? "" : "";
                    if (text.Length > 0) found.Add(new(type, text));
                }
        }
        catch (Exception ex) when (ex is JsonException or KeyNotFoundException or InvalidOperationException)
        {
            return new([], run.ExitCode is { } c and not 0 ? $"Detect It Easy on {name}: exit {c}." : $"Detect It Easy on {name}: unreadable output ({ex.Message}).");
        }
        if (run.ExitCode is { } code and not 0 && found.Count == 0) return new([], $"Detect It Easy on {name}: exit {code}.");
        return new(found, null);
    }

    /// <summary>The marker category of a detection type.</summary>
    internal static string Category(string type) => type.ToLowerInvariant() switch
    {
        "packer" or "protector" or "protection" => "packing",
        "obfuscator" or "(heur)obfuscator" => "transformer",
        "cryptor" => "encryption",
        _ => "toolchain",
    };
}
