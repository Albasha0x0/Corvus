using System.Globalization;
using System.Text.Json.Nodes;
using ModelContextProtocol.Protocol;

namespace Corvus.Setup;

/// <summary>
/// batch --file: a fixed set of read-only steps over one file, written as one corvus.batch/1 document. Steps go through
/// the same tool calls as an agent's, so they keep the server's checks, limits and isolation.
/// </summary>
internal static partial class ToolCli
{
    /// <summary>The document's schema: a new field keeps it, a renamed or removed field moves it to corvus.batch/2.</summary>
    public const string FileBatchSchema = "corvus.batch/1";

    /// <summary>Section statuses; complete and not_applicable are the only ones a complete document holds.</summary>
    public static class SectionStatus
    {
        public const string Complete = "complete";
        public const string Partial = "partial";
        public const string NotApplicable = "not_applicable";
        public const string Unavailable = "unavailable";
        public const string Error = "error";
        public const string Timeout = "timeout";
    }

    /// <summary>The named limits and their defaults; --limit name=N overrides one, --time-limit sets timeSeconds.</summary>
    private static Dictionary<string, double> FileBatchLimits() => new(StringComparer.Ordinal)
    {
        ["timeSeconds"] = 120,
        ["containerFiles"] = 500,
        ["strings"] = 500,
        ["summaryHighlights"] = Corvus.Tools.ContainerText.MaxHighlights,
    };

    private sealed record FileBatchStep(string Name, string Tool, string? Limit);

    private static readonly FileBatchStep[] FileBatchSteps =
    [
        new("summary", "summarize_file", "summaryHighlights"),
        new("container", "search_container", "containerFiles"),
        new("strings", "extract_strings", "strings"),
        new("yara", "yara", null),
    ];

    /// <summary>
    /// Writes the document and returns 0, or 124 when the time limit ended the run (finished sections kept, the rest
    /// marked timeout). A missing file or a bad option is a usage error with nothing on stdout.
    /// </summary>
    private static async Task<int> FileBatchAsync(CliArgs a, CliIo io, CancellationToken cancellationToken)
    {
        if (a.Positionals.Count > 0) throw new UsageException("batch takes a steps file or --file, not both.");
        var path = Path.GetFullPath(a.BatchFile!);
        if (!File.Exists(path) && !Directory.Exists(path)) throw new UsageException($"No such file: {a.BatchFile}.");
        var limits = FileBatchLimits();
        foreach (var spec in a.Limits)
        {
            var (name, value) = spec.IndexOf('=') is var eq and > 0 ? (spec[..eq], spec[(eq + 1)..]) : (spec, "");
            if (!limits.ContainsKey(name) || name == "timeSeconds" || name == "summaryHighlights")
                throw new UsageException($"Unknown limit '{name}'. Limits: containerFiles, strings.");
            limits[name] = int.TryParse(value, CultureInfo.InvariantCulture, out var n) && n > 0 ? n : throw new UsageException($"--limit {name} needs a positive count.");
        }
        if (a.TimeLimit != null)
            limits["timeSeconds"] = double.TryParse(a.TimeLimit, NumberStyles.Float, CultureInfo.InvariantCulture, out var s) && s > 0 && s <= 86_400
                ? s : throw new UsageException("--time-limit needs a number of seconds above 0, at most 86400.");

        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(TimeSpan.FromSeconds(limits["timeSeconds"]));
        var sections = new JsonArray();
        JsonNode? summary = null;
        bool timedOut = false;
        ToolSession? session = null;
        try
        {
            try { session = await ToolSession.StartAsync(a.Server(oneShot: true), deadline.Token); }
            catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested) { timedOut = true; }
            foreach (var step in FileBatchSteps)
            {
                if (timedOut && step.Name != "yara")
                {
                    sections.Add(Section(step, SectionStatus.Timeout, "The time limit ended the run before this step."));
                    continue;
                }
                var (arguments, skip) = Arguments(step, path, summary, limits);
                if (skip != null)
                {
                    sections.Add(skip);
                    continue;
                }
                CallToolResult? result;
                try { result = await Invoke(session!, step.Tool, arguments!, io, deadline.Token); }
                catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
                {
                    timedOut = true;
                    sections.Add(Section(step, SectionStatus.Timeout, "The time limit ended this step."));
                    continue;
                }
                var section = Section(step, result);
                if (step.Name == "summary") summary = section["result"];
                sections.Add(section);
            }
        }
        finally
        {
            if (session != null) await session.DisposeAsync();
        }

        var file = new JsonObject { ["path"] = path };
        if (summary != null)
            foreach (var key in new[] { "size", "sha256", "type" })
                file[key] = summary[key]?.DeepClone();
        var document = new JsonObject
        {
            ["schema"] = FileBatchSchema,
            ["corvus"] = Installation.Version,
            ["file"] = file,
            ["complete"] = sections.All(s => (string?)s!["status"] is SectionStatus.Complete or SectionStatus.NotApplicable),
            ["limits"] = new JsonObject([.. limits.Select(l => KeyValuePair.Create(l.Key, (JsonNode?)JsonValue.Create(l.Value)))]),
            ["sections"] = sections,
        };
        io.Out.WriteLine(document.ToJsonString(Compact));
        return timedOut ? Exit.Timeout : Exit.Ok;
    }

    /// <summary>A step's arguments, or the section that says why it does not run on this file.</summary>
    private static (Dictionary<string, object?>? Arguments, JsonObject? Skip) Arguments(FileBatchStep step, string path, JsonNode? summary, Dictionary<string, double> limits)
    {
        if (step.Name == "summary") return (new() { ["path"] = path }, null);
        // YARA-X is not in this build yet; the section keeps its place so readers of the document need no change.
        if (step.Name == "yara") return (null, Section(step, SectionStatus.Unavailable, "YARA-X is not in this build."));
        if (summary == null) return (null, Section(step, SectionStatus.Error, "The summary failed, so whether this step applies is unknown."));
        if (step.Name == "container")
            return (string?)summary["container"] is { } container && !container.StartsWith("none", StringComparison.Ordinal)
                ? (new() { ["path"] = path, ["kind"] = "file", ["query"] = "*", ["limit"] = (int)limits["containerFiles"] }, null)
                : (null, Section(step, SectionStatus.NotApplicable, "The file is not a container."));
        return ((string?)summary["type"])?.StartsWith(".NET assembly", StringComparison.Ordinal) == true
            ? (new() { ["path"] = path, ["limit"] = (int)limits["strings"] }, null)
            : (null, Section(step, SectionStatus.NotApplicable, "Typed strings are read from .NET assemblies."));
    }

    private static JsonObject Section(FileBatchStep step, string status, string reason)
    {
        var section = new JsonObject { ["name"] = step.Name };
        if (step.Name != "yara") section["tool"] = step.Tool;
        section["status"] = status;
        section["reason"] = reason;
        return section;
    }

    /// <summary>
    /// A finished step's section: an error result by its code, a page with more rows (or capped highlights) as partial
    /// with the limit it reached; every row read is kept.
    /// </summary>
    private static JsonObject Section(FileBatchStep step, CallToolResult? result)
    {
        if (result == null) return Section(step, SectionStatus.Error, "The server refused the call.");
        var structured = result.StructuredContent is { } s ? JsonNode.Parse(s.GetRawText()) : null;
        var section = new JsonObject { ["name"] = step.Name, ["tool"] = step.Tool };
        if (result.IsError == true)
        {
            var (text, _, error) = Split(result);
            var code = (string?)error?["code"];
            section["status"] = code switch
            {
                "timeout" => SectionStatus.Timeout,
                "provider_unavailable" or "unsupported" => SectionStatus.Unavailable,
                _ => (bool?)error?["partial"] == true ? SectionStatus.Partial : SectionStatus.Error,
            };
            section["error"] = error?.DeepClone() ?? new JsonObject { ["message"] = text };
            section["result"] = structured;
            return section;
        }
        bool more = (bool?)structured?["hasMore"] == true || structured?["highlightTotal"] != null;
        section["status"] = more ? SectionStatus.Partial : SectionStatus.Complete;
        if (more) section["limit"] = step.Limit;
        section["result"] = structured;
        return section;
    }
}
