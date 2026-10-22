using System.Globalization;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Corvus.Core;
using Corvus.Native.Providers.Worker;
using Corvus.Native.Providers.Worker.Yara;

namespace Corvus.Services.Analysis;

/// <summary>
/// search_container kind=yara: the query is a YARA rule file or a folder of them, compiled and run by YARA-X in a
/// <c>corvus worker</c> process over the file and each container member; rows are the rules that matched, with the file
/// or member path, tags, metadata and pattern offsets. Rules that do not compile are named with their file, line and
/// rule, and the rest still run.
/// </summary>
internal sealed class YaraSearchKind : IContainerSearchKind
{
    /// <summary>A scan's hard limit; YARA-X's own timeout is whole seconds and best effort.</summary>
    private static readonly TimeSpan ScanLimit = TimeSpan.FromMinutes(10);

    public IReadOnlyList<string> Kinds => ["yara"];

    public IEnumerable<ContainerMatch> Search(ContainerScope scope, string kind, Func<string, bool> matches, CancellationToken ct) => [];

    public UnpackService.ContainerSearch SearchFile(string path, string query, int offset, int limit, ContainerSearchArgs args, CancellationToken ct)
    {
        // A folder is a deployment (Blazor, ClickOnce) whose members the worker reads.
        var source = Directory.Exists(Path.GetFullPath(path)) ? Path.GetFullPath(path) : InputFiles.RequireRegularFile(path, "file");
        if (!File.Exists(source) && !Directory.Exists(source)) throw Targets.FileNotFound(source);
        if (string.IsNullOrWhiteSpace(query))
            throw new ToolError(ErrorCode.InvalidArgument, "kind=yara takes the rules as query.", "pass a .yar file or a folder of .yar and .yara files as query");
        var request = new JsonObject { ["rules"] = Path.GetFullPath(query.Trim().Trim('"')), ["path"] = source };
        var answer = WorkerPool.Shared.RunAsync("yara", YaraOps.ScanOp, request, ScanLimit, ct, source).GetAwaiter().GetResult();
        var result = answer.Deserialize<YaraScanResult>(YaraOps.Json)
                     ?? throw new ToolError(ErrorCode.Failed, "The yara worker answered without a result.");
        var rows = result.Hits.SelectMany(h => h.Rules.Select(r => Row(h.Path, r))).ToList();
        var files = (Directory.Exists(source) ? 0 : 1) + result.Members;
        return new UnpackService.ContainerSearch(source, "file", files, rows.Skip(Math.Max(0, offset)).Take(limit).ToList(), Math.Max(0, offset), rows.Count,
            Notes(result));
    }

    private static ContainerMatch Row(string path, YaraRuleMatch rule) => new(path, rule.Namespace is "default" or "" ? rule.Rule : $"{rule.Namespace}:{rule.Rule}", "yara")
    {
        Detail = Detail(rule),
    };

    /// <summary>Tags, metadata, then each pattern with its matches as offset+length, in rule order.</summary>
    internal static string? Detail(YaraRuleMatch rule)
    {
        var parts = new List<string>();
        if (rule.Tags.Count > 0) parts.Add("tags: " + string.Join(", ", rule.Tags));
        if (rule.Meta.Count > 0) parts.Add("meta: " + string.Join(", ", rule.Meta.Select(m => $"{m.Key}={m.Value}")));
        foreach (var pattern in rule.Patterns.GroupBy(p => p.Pattern))
            parts.Add($"{pattern.Key} at " + string.Join(", ", pattern.Select(p => $"0x{p.Offset.ToString("X", CultureInfo.InvariantCulture)}+{p.Length}")));
        return parts.Count == 0 ? null : string.Join("; ", parts);
    }

    private static List<string> Notes(YaraScanResult result)
    {
        var notes = new List<string>(result.Notes);
        var summary = new StringBuilder($"YARA-X {YaraX.Version}: {result.Rules:N0} rules from {result.RuleFiles:N0} file{(result.RuleFiles == 1 ? "" : "s")}");
        if (result.Members > 0) summary.Append($"; {result.Members:N0} container members scanned");
        if (result.Errors.Count > 0) summary.Append($"; {result.Errors.Count:N0} errors, their rules not run");
        notes.Insert(0, summary.Append($"; at most {YaraRules.MaxMatchesPerPattern} matches kept per pattern; {result.ElapsedMs:N0} ms").ToString());
        foreach (var e in result.Errors)
            notes.Add($"{e.File}:{e.Line}:{e.Column}{(e.Rule != null ? $" rule {e.Rule}" : "")}: {e.Code} {e.Message}");
        return notes;
    }
}
