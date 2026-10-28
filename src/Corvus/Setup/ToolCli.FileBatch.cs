using System.Globalization;
using System.Text.Json.Nodes;
using Corvus.Core;
using Corvus.Services.Analysis;
using ModelContextProtocol.Protocol;

namespace Corvus.Setup;

/// <summary>batch --file: fixed read-only steps over one file, through the server's own tool calls, as one corvus.batch/1 document.</summary>
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
        ["yaraMatches"] = 500,
        // Asset files read by the strings step; a direct extract_strings call reads up to 4 GiB.
        ["assetBytes"] = 1 << 30,
        ["summaryHighlights"] = Corvus.Tools.ContainerText.MaxHighlights,
        // Files --recurse reads under a folder.
        ["members"] = 10_000,
        ["embeddedItems"] = 500,
    };

    internal sealed record FileBatchStep(string Name, string Tool, string? Limit);

    private static readonly FileBatchStep[] FileBatchSteps =
    [
        new("summary", "summarize_file", "summaryHighlights"),
        new("container", "search_container", "containerFiles"),
        new("strings", "extract_strings", "strings"),
        new("yara", "search_container", "yaraMatches"),
        new("build", "summarize_build", null),
    ];

    /// <summary>Writes the document and returns 0, 124 after the time limit, or the gate's code; bad input is a usage error with empty stdout.</summary>
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
                throw new UsageException($"Unknown limit '{name}'. Limits: containerFiles, strings, yaraMatches, assetBytes, members, embeddedItems.");
            limits[name] = int.TryParse(value, CultureInfo.InvariantCulture, out var n) && n > 0 ? n : throw new UsageException($"--limit {name} needs a positive count.");
        }
        if (a.TimeLimit != null)
            limits["timeSeconds"] = double.TryParse(a.TimeLimit, NumberStyles.Float, CultureInfo.InvariantCulture, out var s) && s > 0 && s <= 86_400
                ? s : throw new UsageException("--time-limit needs a number of seconds above 0, at most 86400.");
        var rules = a.Rules == null ? null : Path.GetFullPath(a.Rules);
        if (rules != null && !File.Exists(rules) && !Directory.Exists(rules)) throw new UsageException($"No such rule file or folder: {a.Rules}.");
        if (a.FailOn is not (null or FindingLevel.Noteworthy or FindingLevel.Review)) throw new UsageException("--fail-on takes noteworthy or review.");
        if (a.AllowIncomplete && a.FailOn == null) throw new UsageException("--allow-incomplete goes with --fail-on.");
        var extract = OutputPath("--extract", a.Extract);
        if (extract != null && (File.Exists(extract) || Directory.Exists(extract) && Directory.EnumerateFileSystemEntries(extract).Any()))
            throw new UsageException($"--extract needs a new or empty folder: {a.Extract}.");
        var report = OutputPath("--report", a.Report);
        if (report != null && Directory.Exists(report)) throw new UsageException($"--report names a file, not a folder: {a.Report}.");
        if (a.Out != null && !a.JsonLines) throw new UsageException("--out goes with --jsonl.");
        var lines = OutputPath("--out", a.Out);
        if (lines != null && Directory.Exists(lines)) throw new UsageException($"--out names a file, not a folder: {a.Out}.");

        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(TimeSpan.FromSeconds(limits["timeSeconds"]));
        var baseline = a.Baseline == null ? null : ReadBaseline(Path.GetFullPath(a.Baseline), DateOnly.FromDateTime(DateTime.UtcNow));
        var run = new FileBatchRun(limits, rules, io, deadline.Token, cancellationToken) { Extract = extract, Baseline = baseline };
        if (extract != null) Directory.CreateDirectory(extract);
        JsonObject document;
        try
        {
            try { run.Session = await ToolSession.StartAsync(a.Server(oneShot: true), deadline.Token); }
            catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested) { run.TimedOut = true; }
            document = a.Recurse ? await RecordsDocument(run, path) : await FileDocument(run, path);
        }
        finally
        {
            if (run.Session != null) await run.Session.DisposeAsync();
        }
        WriteExtractIndex(run);
        if (baseline != null) document["baseline"] = baseline.Record(Path.GetFullPath(a.Baseline!));
        int exit = run.TimedOut ? Exit.Timeout : Exit.Ok;
        if (a.FailOn != null)
        {
            var failures = GateFailures(document, a.FailOn, a.AllowIncomplete);
            document["gate"] = new JsonObject
            {
                ["failOn"] = a.FailOn,
                ["allowIncomplete"] = a.AllowIncomplete,
                ["failed"] = failures.Count > 0,
                ["reasons"] = new JsonArray([.. failures.Select(f => (JsonNode?)f)]),
            };
            exit = failures.Count > 0 ? Exit.ToolError : Exit.Ok;
        }
        if (report != null) await File.WriteAllTextAsync(report, Report(document), CancellationToken.None);
        if (!a.JsonLines) io.Out.WriteLine(document.ToJsonString(Compact));
        else
        {
            var records = document["records"] is JsonArray all ? all.Select(r => r!.AsObject()) : [RecordOf(document)];
            using var writer = lines == null ? null : new StreamWriter(lines, append: false, new System.Text.UTF8Encoding(false));
            var target = writer ?? io.Out;
            foreach (var record in records) target.Write(record.ToJsonString(Compact) + "\n");
        }
        return exit;
    }

    /// <summary>The full path of an output option, checked by the output refusal rules; null when the option is absent.</summary>
    private static string? OutputPath(string option, string? value)
    {
        if (value == null) return null;
        try { return SafeFile.Output(value); }
        catch (ToolError ex) { throw new UsageException($"{option}: {ex.Message}"); }
    }

    /// <summary>Why the gate fails: findings at or above the level, then unless allowed what was not read whole; empty to pass.</summary>
    internal static List<string> GateFailures(JsonObject document, string failOn, bool allowIncomplete)
    {
        var failures = new List<string>();
        var records = document["records"] is JsonArray all
            ? all.Select(r => ((string?)r!["file"]!["paths"]?[0] ?? "", r!))
            : [((string?)document["file"]?["path"] ?? "", (JsonNode)document)];
        int threshold = FindingLevel.Rank(failOn);
        foreach (var (label, record) in records)
        {
            var findings = record["findings"] as JsonArray ?? [];
            foreach (var finding in findings)
                if (FindingLevel.Rank((string?)finding!["level"]) >= threshold)
                    failures.Add($"{label}: {(string?)finding["level"]} finding {(string?)finding["rule"]}, key {(string?)finding["key"]}");
            if (allowIncomplete) continue;
            // The overview lists the strongest findings first, so an unlisted one
            // is at most as strong as the last listed.
            var listed = findings.Concat(record["suppressed"] as JsonArray ?? []).ToList();
            if ((int?)record["summary"]?["findingTotal"] is { } total && total > listed.Count
                && (listed.Count == 0 || listed.Min(f => FindingLevel.Rank((string?)f!["level"])) >= threshold))
                failures.Add($"{label}: {total - listed.Count} findings past the first {listed.Count} are not listed");
            foreach (var section in record["sections"] as JsonArray ?? [])
                if ((string?)section!["status"] is { } status and not (SectionStatus.Complete or SectionStatus.NotApplicable))
                    failures.Add($"{label}: {(string?)section["name"]} {status}");
            foreach (var entry in record["unread"] as JsonArray ?? [])
                if (record != document) failures.Add($"{label}: {(string?)entry}");
        }
        if (!allowIncomplete)
            foreach (var entry in document["unread"] as JsonArray ?? [])
                failures.Add($"unread: {(string?)entry}");
        return failures;
    }

    /// <summary>The run's shared state: limits, rules, session and deadline; TimedOut is set once the deadline ends a step.</summary>
    private sealed class FileBatchRun(Dictionary<string, double> limits, string? rules, CliIo io, CancellationToken deadline, CancellationToken cancellation)
    {
        public Dictionary<string, double> Limits { get; } = limits;
        public string? Rules { get; } = rules;
        public CliIo Io { get; } = io;
        public CancellationToken Deadline { get; } = deadline;
        public CancellationToken Cancellation { get; } = cancellation;
        public System.Diagnostics.Stopwatch Clock { get; } = System.Diagnostics.Stopwatch.StartNew();
        public ToolSession? Session { get; set; }
        public bool TimedOut { get; set; }
        public string? Extract { get; init; }
        public Baseline? Baseline { get; init; }
        public JsonArray Index { get; } = [];
    }

    /// <summary>The single-file document: run fields, the file, its summary, its keyed findings and its sections.</summary>
    private static async Task<JsonObject> FileDocument(FileBatchRun run, string path)
    {
        var (sections, summary) = await Steps(run, path);
        var extracted = await Extract(run, path, (string?)summary?["sha256"], summary, sections, [path]);
        var file = new JsonObject { ["path"] = path };
        if (summary != null)
            foreach (var key in new[] { "size", "sha256", "type" })
                file[key] = summary[key]?.DeepClone();
        var document = RunFields(run, (string?)summary?["ruleTable"]);
        document["file"] = file;
        document["complete"] = Complete(sections);
        var sha = (string?)summary?["sha256"];
        var (findings, suppressed) = ApplyBaseline(KeyedFindings(sha, summary), sha, run.Baseline);
        document["summary"] = Verdict(summary, findings, suppressed);
        document["findings"] = findings;
        if (run.Baseline != null) document["suppressed"] = suppressed;
        document["sections"] = sections;
        if (extracted != null) document["extracted"] = extracted;
        return document;
    }

    /// <summary>The fields every document starts with: schema, version, limits, rule table digest and rule packs.</summary>
    private static JsonObject RunFields(FileBatchRun run, string? ruleTable) => new()
    {
        ["schema"] = FileBatchSchema,
        ["corvus"] = Installation.Version,
        ["limits"] = new JsonObject([.. run.Limits.Select(l => KeyValuePair.Create(l.Key, (JsonNode?)JsonValue.Create(l.Value)))]),
        ["ruleTable"] = ruleTable ?? "unknown",
        ["rulePacks"] = new JsonArray([.. RulePacks.Installed(RulePacks.Root).Select(p => new JsonObject { ["name"] = p.Name, ["version"] = p.Version, ["digest"] = p.Digest ?? "unknown" })]),
    };

    private static bool Complete(JsonArray sections) => sections.All(s => (string?)s!["status"] is SectionStatus.Complete or SectionStatus.NotApplicable);

    /// <summary>Runs every step over one path; after the deadline the steps left are timeout sections.</summary>
    private static async Task<(JsonArray Sections, JsonNode? Summary)> Steps(FileBatchRun run, string path)
    {
        var sections = new JsonArray();
        JsonNode? summary = null;
        foreach (var step in FileBatchSteps)
        {
            if (step.Name == "yara" && run.Rules == null)
            {
                sections.Add(Section(step, SectionStatus.NotApplicable, "No rules were given; --rules names a rule file or folder."));
                continue;
            }
            if (run.TimedOut)
            {
                sections.Add(Section(step, SectionStatus.Timeout, "The time limit ended the run before this step."));
                continue;
            }
            var (arguments, skip) = Arguments(step, path, run.Rules, summary, run.Limits, run.Limits["timeSeconds"] - run.Clock.Elapsed.TotalSeconds);
            if (skip != null)
            {
                sections.Add(skip);
                continue;
            }
            JsonObject section;
            try
            {
                (section, var timedOut) = await Step(run.Session!, step, arguments!, run.Io, run.Deadline, run.Cancellation);
                run.TimedOut |= timedOut;
            }
            catch (OperationCanceledException) when (!run.Cancellation.IsCancellationRequested)
            {
                run.TimedOut = true;
                sections.Add(Section(step, SectionStatus.Timeout, "The time limit ended this step."));
                continue;
            }
            if (step.Name == "summary") summary = section["result"];
            sections.Add(section);
        }
        return (sections, summary);
    }

    /// <summary>The file's level and the findings at that level as reasons; level unknown when the summary step gave no result.</summary>
    internal static JsonObject Verdict(JsonNode? summary)
    {
        var level = (string?)summary?["level"] ?? "unknown";
        var reasons = new JsonArray([.. (summary?["findings"] as JsonArray ?? []).Where(f => (string?)f?["level"] == level).Select(f => f!.DeepClone())]);
        var verdict = new JsonObject { ["level"] = level, ["reasons"] = reasons };
        // The overview keeps the strongest 50 findings, so the reasons may be cut too.
        if (summary?["findingTotal"] is { } total) verdict["findingTotal"] = total.DeepClone();
        return verdict;
    }

    /// <summary>A step's arguments, or the section that says why it does not run on this file.</summary>
    private static (Dictionary<string, object?>? Arguments, JsonObject? Skip) Arguments(FileBatchStep step, string path, string? rules, JsonNode? summary,
        Dictionary<string, double> limits, double remaining)
    {
        if (step.Name == "summary") return (new() { ["path"] = path }, null);
        if (step.Name == "yara") return (new() { ["path"] = path, ["kind"] = "yara", ["query"] = rules, ["limit"] = (int)limits["yaraMatches"] }, null);
        // A build with asset files spans a folder: a single file holds one only as a package or zip; neighbours are not read.
        if (step.Name == "build")
            return Directory.Exists(path) || PackageFiles.IsPlayerPackage(path)
                ? (new() { ["path"] = path }, null)
                : (null, Section(step, SectionStatus.NotApplicable, "A build with asset files is read from a folder, package or zip that holds it."));
        // Asset data needs no summary; extract_strings refuses a folder without a build as not_a_build.
        // The asset read gets half the time left, so the steps after it still run, and stops with the rows read.
        if (step.Name == "strings" && (Directory.Exists(path) || PackageFiles.HoldsPlayerData(path) || Core.Assets.SerializedFile.IsAssetFile(path)))
            return (new()
            {
                ["path"] = path, ["limit"] = (int)limits["strings"], ["maxAssetBytes"] = (long)limits["assetBytes"],
                ["timeLimit"] = Math.Max(1, Math.Round(remaining / 2, 1)),
            }, null);
        if (summary == null) return (null, Section(step, SectionStatus.Error, "The summary failed, so whether this step applies is unknown."));
        if (step.Name == "container")
            return (string?)summary["container"] is { } container && !container.StartsWith("none", StringComparison.Ordinal)
                ? (new() { ["path"] = path, ["kind"] = "file", ["query"] = "*", ["limit"] = (int)limits["containerFiles"] }, null)
                : (null, Section(step, SectionStatus.NotApplicable, "The file is not a container."));
        return HoldsManagedCode(path, summary)
            ? (new() { ["path"] = path, ["limit"] = (int)limits["strings"] }, null)
            : (null, Section(step, SectionStatus.NotApplicable, "Typed strings are read from .NET assemblies, files that hold them, and serialized asset files."));
    }

    private static bool HoldsManagedCode(string path, JsonNode summary) =>
        ((string?)summary["type"])?.StartsWith(".NET assembly", StringComparison.Ordinal) == true
        || (!Directory.Exists(path) && (string?)summary["container"] is { } holder && !holder.StartsWith("none", StringComparison.Ordinal)
            && summary["assemblies"] is JsonArray { Count: > 0 });

    private static JsonObject Section(FileBatchStep step, string status, string reason)
    {
        var section = new JsonObject { ["name"] = step.Name, ["tool"] = step.Tool };
        section["status"] = status;
        section["reason"] = reason;
        return section;
    }

    /// <summary>Runs one step, paging until its limit or the last row; a time limit on a later page keeps the rows read.</summary>
    private static async Task<(JsonObject Section, bool TimedOut)> Step(ToolSession session, FileBatchStep step, Dictionary<string, object?> arguments,
        CliIo io, CancellationToken deadline, CancellationToken cancellationToken)
    {
        var result = await Invoke(session, step.Tool, arguments, io, deadline);
        if (result == null || result.IsError == true || arguments.GetValueOrDefault("limit") is not int limit) return (Section(step, result), false);
        var record = Structured(result);
        var gaps = Gaps(record).ToList();
        bool timedOut = false;
        while (record?["items"] is JsonArray items && (bool?)record["hasMore"] == true && items.Count < limit)
        {
            int offset = (int?)arguments.GetValueOrDefault("offset") ?? 0;
            if ((int?)record["nextOffset"] is not { } next || next <= offset)
            {
                gaps.Insert(0, $"The tool named no page after offset {offset}.");
                break;
            }
            arguments["offset"] = next;
            arguments["limit"] = limit - items.Count;
            CallToolResult? page;
            try { page = await Invoke(session, step.Tool, arguments, io, deadline); }
            catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
            {
                timedOut = true;
                break;
            }
            if (page == null || page.IsError == true)
            {
                var failed = page == null ? "the server refused the call" : (string?)Split(page).Error?["message"] ?? Split(page).Text.Trim();
                gaps.Insert(0, $"The page at offset {next} failed: {failed}");
                break;
            }
            var more = Structured(page);
            foreach (var row in (more?["items"] as JsonArray)?.ToArray() ?? []) items.Add(row?.DeepClone());
            record["hasMore"] = more?["hasMore"]?.DeepClone();
            if (more?["nextOffset"] is { } after) record["nextOffset"] = after.DeepClone();
            else record.AsObject().Remove("nextOffset");
            gaps.AddRange(Gaps(more));
        }
        if (arguments.ContainsKey("offset") && record != null) record["limit"] = limit;
        var section = new JsonObject { ["name"] = step.Name, ["tool"] = step.Tool };
        int read = (record?["items"] as JsonArray)?.Count ?? 0;
        if (timedOut)
        {
            section["status"] = SectionStatus.Timeout;
            section["reason"] = $"The time limit ended this step after {read} rows.";
            section["result"] = record;
        }
        else Finish(section, step, record, (bool?)record?["hasMore"] == true && read >= limit, gaps);
        return (section, timedOut);
    }

    private static JsonNode? Structured(CallToolResult result) => result.StructuredContent is { } s ? JsonNode.Parse(s.GetRawText()) : null;

    /// <summary>Why a record is not whole: partial or unknown coverage, an unavailable facet, or cut rows; empty for a whole record.</summary>
    private static IEnumerable<string> Gaps(JsonNode? record)
    {
        if (record?["coverage"] is JsonObject coverage)
        {
            if ((string?)coverage["status"] is "partial" or "unknown")
                yield return (string?)coverage["reason"] is { Length: > 0 } reason ? reason : $"coverage is {(string?)coverage["status"]}";
            if (coverage["facets"] is JsonObject facets)
                foreach (var (name, value) in facets)
                    if ((string?)value is { } state && state.StartsWith("unavailable", StringComparison.Ordinal)) yield return $"{name} {state}";
        }
        if (record?["warnings"] is JsonArray warnings)
            foreach (var warning in warnings)
                if ((string?)warning is { } text && text.StartsWith("Cut to fit", StringComparison.Ordinal)) yield return text;
    }

    /// <summary>Sets a successful step's status: partial with the reason rows went unread, else complete; every row read is kept.</summary>
    private static void Finish(JsonObject section, FileBatchStep step, JsonNode? record, bool reached, IReadOnlyCollection<string> gaps)
    {
        section["status"] = reached || gaps.Count > 0 ? SectionStatus.Partial : SectionStatus.Complete;
        if (reached) section["limit"] = step.Limit;
        if (gaps.Count > 0) section["reason"] = string.Join("; ", gaps.Distinct());
        section["result"] = record;
    }

    /// <summary>A finished call's section: an error result by its code, otherwise as <see cref="Finish"/> sets it.</summary>
    internal static JsonObject Section(FileBatchStep step, CallToolResult? result)
    {
        if (result == null) return Section(step, SectionStatus.Error, "The server refused the call.");
        var structured = Structured(result);
        var section = new JsonObject { ["name"] = step.Name, ["tool"] = step.Tool };
        if (result.IsError == true)
        {
            var (text, _, error) = Split(result);
            var code = (string?)error?["code"];
            // The step does not apply to an input without a build.
            if (code == "unsupported" && ((string?)error?["details"]?["reason"] == "not_a_build" || text.Contains("reason not_a_build", StringComparison.Ordinal)))
                return Section(step, SectionStatus.NotApplicable, (string?)error?["message"] ?? text);
            section["status"] = code switch
            {
                "timeout" => SectionStatus.Timeout,
                "provider_unavailable" or "unsupported" => SectionStatus.Unavailable,
                _ => (bool?)error?["partial"] == true ? SectionStatus.Partial : SectionStatus.Error,
            };
            // An unavailable section names its reason, such as the worker host being off, as the skipped ones do.
            if ((string?)section["status"] == SectionStatus.Unavailable) section["reason"] = (string?)error?["message"] ?? text;
            section["error"] = error?.DeepClone() ?? new JsonObject { ["message"] = text };
            section["result"] = structured;
            return section;
        }
        Finish(section, step, structured, (bool?)structured?["hasMore"] == true || structured?["highlightTotal"] != null, Gaps(structured).ToList());
        return section;
    }
}
