using System.Diagnostics;
using System.Text.Json;
using System.Text.Json.Nodes;
using Corvus.Core;
using Corvus.Native.Providers.Worker;
using Corvus.Native.Providers.Worker.Yara;

namespace Corvus.Services.Analysis;

/// <summary>Where a scan found matches: the file or member path, the rules that matched there.</summary>
public sealed record YaraHit(string Path, IReadOnlyList<YaraRuleMatch> Rules);

/// <summary>
/// A worker scan's answer: rules compiled and files read, the rules that did not compile, the hits in scan order, and notes
/// naming what was not read.
/// </summary>
public sealed record YaraScanResult(int Rules, int RuleFiles, IReadOnlyList<YaraRuleError> Errors, IReadOnlyList<YaraHit> Hits, IReadOnlyList<string> Notes,
    long ElapsedMs)
{
    /// <summary>Container members scanned besides the file itself.</summary>
    public int Members { get; init; }
}

/// <summary>The worker ops of YARA scanning; their arguments are paths, as bytes never cross the worker pipe.</summary>
internal sealed class YaraOps : IWorkerOps
{
    public const string ScanOp = "yara_scan";

    /// <summary>Server and worker read and write the result with these options.</summary>
    public static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);

    public IReadOnlyDictionary<string, WorkerOp> Ops => new Dictionary<string, WorkerOp> { [ScanOp] = Scan };

    /// <summary>Largest file whose container members are read; a larger one is scanned as one file.</summary>
    public static long MaxWalkBytes => AnalysisLimits.Default.MaxItemBytes;

    /// <summary>
    /// Scans the file <c>path</c> with the rules at <c>rules</c> (a file or folder), then each member of the container it
    /// is, nested containers opened and compressed members decompressed; a folder (a Blazor or ClickOnce deployment) is
    /// scanned by its members only.
    /// </summary>
    public static Task<JsonNode?> Scan(JsonObject args, CancellationToken cancellationToken)
    {
        var rulesPath = Arg(args, "rules");
        var target = Arg(args, "path");
        var started = Stopwatch.StartNew();
        using var rules = YaraRules.Compile(rulesPath);
        using var scanner = rules.Scanner(TimeSpan.FromMinutes(10));
        cancellationToken.ThrowIfCancellationRequested();
        var hits = new List<YaraHit>();
        var notes = new List<string>(rules.Notes);
        var folder = Directory.Exists(target);
        if (!folder && scanner.ScanFile(target) is { Count: > 0 } matched) hits.Add(new YaraHit(target, matched));
        var members = 0;
        if (!folder && new FileInfo(target).Length > MaxWalkBytes)
            notes.Add($"Container members not read: the file is larger than {MaxWalkBytes / (1024 * 1024):N0} MB; it was scanned as one file.");
        else if (Members(target, notes, cancellationToken) is { } items)
            foreach (var item in items)
            {
                cancellationToken.ThrowIfCancellationRequested();
                members++;
                if (scanner.Scan(item.Bytes, item.Bytes.Length) is { Count: > 0 } found) hits.Add(new YaraHit(item.Path, found));
            }
        var result = new YaraScanResult(rules.Count, rules.Files, rules.Errors, hits, notes, started.ElapsedMilliseconds) { Members = members };
        return Task.FromResult(JsonSerializer.SerializeToNode(result, Json));
    }

    /// <summary>The container's members, or null with a note when they could not be read.</summary>
    private static IReadOnlyList<ContainerItem>? Members(string target, List<string> notes, CancellationToken cancellationToken)
    {
        try
        {
            var (scope, walkNotes) = UnpackService.Scope(target, AnalysisLimits.Default, cancellationToken);
            notes.AddRange(walkNotes);
            return scope.Items;
        }
        catch (ToolError e) when (e.Code is not (ErrorCode.Timeout or ErrorCode.Cancelled))
        {
            notes.Add($"Container members not read: {e.Message}");
            return null;
        }
    }

    private static string Arg(JsonObject args, string name) =>
        args[name]?.GetValueKind() == JsonValueKind.String && args[name]!.GetValue<string>() is { Length: > 0 } value
            ? value
            : throw new ToolError(ErrorCode.InvalidArgument, $"{ScanOp} needs '{name}'.");
}
