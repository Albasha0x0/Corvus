using System.Text.Json;
using Corvus.Core;
using Corvus.Native.Providers;

namespace Corvus.Services.Web.Packages;

/// <summary>Findings of an installed workflow auditor (zizmor) over one workflow file.</summary>
internal static class WorkflowAuditor
{
    private const long MaxOutput = 4 * 1024 * 1024;

    /// <summary>Findings read from the auditor; Problem names why none were read, null when read.</summary>
    internal sealed record Result(IReadOnlyList<PackageFinding> Findings, string? Problem);

    /// <summary>The program found through CORVUS_ZIZMOR (a file or its folder) or PATH; null when absent.</summary>
    internal static string? Find() => ExternalTools.Locate(ExternalTools.Zizmor)?.Path;

    /// <summary>Whether CORVUS_ZIZMOR is set, the opt-in that lets workflow review run the auditor.</summary>
    internal static bool Configured() => ExternalTools.ReadVariable(ExternalTools.Zizmor.Variable) is { Length: > 0 };

    /// <summary>Audits workflow <paramref name="text"/> through a private copy; a missing program, stall, exit code or unreadable output is the problem, never no findings.</summary>
    internal static Result Audit(string text, string path, CancellationToken ct, TimeSpan? stallWindow = null)
    {
        if (Find() is not { } exe) return new([], $"{path}: workflow auditor not found in {ExternalTools.Zizmor.Variable} or on PATH");
        var window = stallWindow ?? ServerOptions.StallWindow();
        var extension = path.EndsWith(".yaml", StringComparison.OrdinalIgnoreCase) ? ".yaml" : ".yml";
        var copy = PrivateFolder.Temp("workflow-audit", Guid.NewGuid().ToString("N") + extension);
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(copy)!);
            File.WriteAllText(copy, text);
            var run = ExternalTools.Run(exe, ExternalTools.Arguments(ExternalTools.Zizmor, "audit", ("file", copy)), Timeout.InfiniteTimeSpan, MaxOutput, ct,
                watch: new(new StallRule(window)));
            if (run.StartError != null) return new([], $"{path}: workflow auditor: {run.StartError}");
            if (run.StalledAt is { } reached)
                return new([], $"{path}: workflow auditor: no output for {window.TotalSeconds:0.###} s and under 1% of a core after {reached:N0} bytes; repeat the call or raise {ServerOptions.StallWindowVariable}");
            if (run.Truncated) return new([], $"{path}: workflow auditor: output over {MaxOutput / (1024 * 1024)} MiB");
            if (run.ExitCode is { } code and not 0) return new([], $"{path}: workflow auditor: exit {code}");
            return Read(run.Output, path);
        }
        finally
        {
            try { File.Delete(copy); }
            catch (IOException) { }
            catch (UnauthorizedAccessException) { }
        }
    }

    private static Result Read(byte[] output, string path)
    {
        var found = new List<PackageFinding>();
        try
        {
            using var doc = JsonDocument.Parse(output);
            foreach (var item in doc.RootElement.EnumerateArray())
            {
                var id = Text(item, "ident") ?? Text(item, "id") ?? "unknown";
                var severity = item.TryGetProperty("determinations", out var d) ? Text(d, "severity") : Text(item, "severity");
                var detail = $"workflow auditor {id}" + (severity != null ? $" ({severity})" : "") + (Text(item, "desc") is { } desc ? ": " + desc : "");
                foreach (var line in Lines(item).DefaultIfEmpty(null))
                    found.Add(new PackageFinding("package/workflow-auditor", "review", "agent configuration", detail, path, line));
            }
        }
        catch (Exception ex) when (ex is JsonException or InvalidOperationException)
        {
            return new([], $"{path}: workflow auditor: unreadable output ({ex.Message})");
        }
        return new(found, null);
    }

    // Start rows are 0-based in the auditor's report.
    private static IEnumerable<int?> Lines(JsonElement item)
    {
        if (!item.TryGetProperty("locations", out var locations) || locations.ValueKind != JsonValueKind.Array) yield break;
        foreach (var at in locations.EnumerateArray())
            if (at.TryGetProperty("concrete", out var c) && c.TryGetProperty("location", out var l)
                && l.TryGetProperty("start_point", out var s) && s.TryGetProperty("row", out var row) && row.TryGetInt32(out var r))
                yield return r + 1;
    }

    private static string? Text(JsonElement e, string name) => e.ValueKind == JsonValueKind.Object && e.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() : null;
}
