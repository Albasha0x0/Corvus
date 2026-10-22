using System.Diagnostics;
using System.Text.Json;
using System.Text.Json.Nodes;
using Corvus.Core;

namespace Corvus.Native.Providers.Worker.Yara;

/// <summary>Where a scan found matches: the file or member path, the rules that matched there.</summary>
public sealed record YaraHit(string Path, IReadOnlyList<YaraRuleMatch> Rules);

/// <summary>
/// A worker scan's answer: rules compiled and files read, the rules that did not compile, the hits in scan order, and notes
/// naming what was not read.
/// </summary>
public sealed record YaraScanResult(int Rules, int RuleFiles, IReadOnlyList<YaraRuleError> Errors, IReadOnlyList<YaraHit> Hits, IReadOnlyList<string> Notes,
    long ElapsedMs);

/// <summary>The worker ops of YARA scanning; their arguments are paths, as bytes never cross the worker pipe.</summary>
internal static class YaraOps
{
    public const string ScanOp = "yara_scan";

    /// <summary>Server and worker read and write the result with these options.</summary>
    public static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);

    /// <summary>Scans the file <c>path</c> with the rules at <c>rules</c> (a file or folder); <c>timeout</c> comes from the request.</summary>
    public static Task<JsonNode?> Scan(JsonObject args, CancellationToken cancellationToken)
    {
        var rulesPath = Arg(args, "rules");
        var target = Arg(args, "path");
        var started = Stopwatch.StartNew();
        using var rules = YaraRules.Compile(rulesPath);
        using var scanner = rules.Scanner(TimeSpan.FromMinutes(10));
        cancellationToken.ThrowIfCancellationRequested();
        var matched = scanner.ScanFile(target);
        List<YaraHit> hits = matched.Count > 0 ? [new YaraHit(target, matched)] : [];
        var result = new YaraScanResult(rules.Count, rules.Files, rules.Errors, hits, rules.Notes, started.ElapsedMilliseconds);
        return Task.FromResult(JsonSerializer.SerializeToNode(result, Json));
    }

    private static string Arg(JsonObject args, string name) =>
        args[name]?.GetValueKind() == JsonValueKind.String && args[name]!.GetValue<string>() is { Length: > 0 } value
            ? value
            : throw new ToolError(ErrorCode.InvalidArgument, $"{ScanOp} needs '{name}'.");
}
