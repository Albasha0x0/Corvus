using System.Text.Json;
using Corvus.Native.Providers;

namespace Corvus.Services.Web.Packages;

/// <summary>GuardDog rule matches over an npm or PyPI package as "rule match" findings (threat-* rules noteworthy);
/// silent when GuardDog is absent and CORVUS_GUARDDOG unset, and a configured GuardDog that cannot run is named.</summary>
internal static class GuardDogRules
{
    private static readonly TimeSpan Timeout = TimeSpan.FromMinutes(3);
    private const long MaxOutput = 32L << 20;
    private const int MaxMatches = 200;

    /// <summary>The findings and a note for <paramref name="path"/>; empty with a null note when GuardDog is not set up.</summary>
    public static (List<PackageFinding> Findings, string? Note) Scan(string path, string ecosystem, CancellationToken ct)
    {
        var target = ecosystem == "npm" ? "npm" : ecosystem.StartsWith("pypi", StringComparison.Ordinal) ? "pypi" : null;
        if (target == null) return ([], null);
        var tool = ExternalTools.GuardDog;
        var probe = ExternalTools.Probe(tool);
        if (!probe.Usable)
            return ([], ExternalTools.ReadVariable(tool.Variable) is { Length: > 0 } || probe.Found ? $"GuardDog rules not checked: {probe.Problem}; {probe.Remediation}" : null);
        var run = ExternalTools.Run(probe.Path!, ExternalTools.Arguments(tool, "scan", ("ecosystem", target), ("file", Path.GetFullPath(path))), Timeout, MaxOutput, ct);
        return Read(run, $"GuardDog {probe.Version ?? "(version unknown)"}");
    }

    /// <summary>The findings in GuardDog's JSON report, or none with the reason it could not be read.</summary>
    internal static (List<PackageFinding> Findings, string Note) Read(ExternalTools.RunResult run, string checker)
    {
        if (run.StartError != null || run.TimedOut || run.Truncated)
            return ([], $"{checker} rules not checked: " + (run.StartError ?? (run.TimedOut ? $"no answer within {Timeout.TotalMinutes:0} min" : $"a report over {MaxOutput >> 20} MiB")));
        var findings = new List<PackageFinding>();
        var errors = new List<string>();
        int more = 0;
        try
        {
            using var doc = JsonDocument.Parse(run.Output);
            if (doc.RootElement.TryGetProperty("errors", out var errs) && errs.ValueKind == JsonValueKind.Object)
                errors.AddRange(errs.EnumerateObject().Select(e => $"{e.Name}: {(e.Value.ValueKind == JsonValueKind.String ? e.Value.GetString() : e.Value.GetRawText())}"));
            if (!doc.RootElement.TryGetProperty("results", out var results) || results.ValueKind != JsonValueKind.Object)
                return ([], $"{checker} rules not checked: the report has no results (exit {run.ExitCode}: {Last(run.Stderr)})");
            foreach (var rule in results.EnumerateObject())
            {
                var level = rule.Name.StartsWith("threat-", StringComparison.Ordinal) ? "noteworthy" : "review";
                // Source rules give a list of matches; metadata rules give a message, empty when they do not apply.
                if (rule.Value.ValueKind == JsonValueKind.String && rule.Value.GetString() is { Length: > 0 } message)
                    findings.Add(new PackageFinding(level, "rule match", $"GuardDog {rule.Name}: {PackageReview.Clip(message, 200)}"));
                if (rule.Value.ValueKind != JsonValueKind.Array) continue;
                foreach (var match in rule.Value.EnumerateArray())
                {
                    if (findings.Count >= MaxMatches) { more++; continue; }
                    var (file, line) = Location(Text(match, "location"));
                    var text = Text(match, "match");
                    findings.Add(new PackageFinding(level, "rule match",
                        $"GuardDog {rule.Name}: {PackageReview.Clip(Text(match, "message") ?? "matched", 160)}" + (text != null ? $" ({PackageReview.Clip(text.Trim(), 120)})" : ""), file, line));
                }
            }
        }
        catch (JsonException ex)
        {
            return ([], $"{checker} rules not checked: its report could not be read ({ex.Message}; exit {run.ExitCode}: {Last(run.Stderr)})");
        }
        var note = $"{checker}: {findings.Count + more} rule match(es)" + (more > 0 ? $", the first {MaxMatches} listed" : "") +
                   (errors.Count > 0 ? $"; rules that did not run: {string.Join("; ", errors.Take(3))}" + (errors.Count > 3 ? $" (+{errors.Count - 3} more)" : "") : "");
        return (findings, note);
    }

    /// <summary>"package/setup.js:8" as its path and 1-based line; the path alone when no line follows.</summary>
    private static (string? Path, int? Line) Location(string? location)
    {
        if (location == null) return (null, null);
        int colon = location.LastIndexOf(':');
        return colon > 0 && int.TryParse(location.AsSpan(colon + 1), out int line) ? (location[..colon], line) : (location, null);
    }

    private static string? Text(JsonElement e, string name) =>
        e.ValueKind == JsonValueKind.Object && e.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() : null;

    private static string Last(string stderr) => PackageReview.Clip(stderr.Trim().Split('\n').LastOrDefault()?.Trim(), 200) is { Length: > 0 } l ? l : "no message";
}
