using System.Collections.Concurrent;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Corvus.Core;
using Corvus.Native.Providers.Worker;

namespace Corvus.Services.Analysis;

/// <summary>Malcontent behaviours one build matches and the other does not; needs the pack (<c>corvus rules fetch malcontent</c>).</summary>
// A behaviour is a rule file's pack path without extension (net/http/request); its risk is the highest risk tag of its
// matching rules. Scans run in a yara worker and are kept per file while its size and write time hold.
internal static partial class MalcontentChanges
{
    public const string Pack = "malcontent";

    /// <summary>Both scans together; past it the behaviours are reported not compared.</summary>
    internal static TimeSpan Limit { get; set; } = TimeSpan.FromMinutes(2);

    private const int MaxRows = 300, MaxTextRows = 20;
    private static readonly string[] Risks = ["low", "medium", "high", "critical"];

    private sealed record Behaviour(int Risk, string? Description, SortedSet<string> Rules);

    private static readonly ConcurrentDictionary<(string File, long Length, DateTime Written, string Rules), Dictionary<string, Behaviour>> Kept = new();
    private static readonly ConcurrentDictionary<string, Dictionary<string, string>> Ids = new(StringComparer.Ordinal);

    /// <summary>Added or removed rows keyed "malcontent/&lt;behaviour&gt;" and a text line; empty with null text when the pack is absent.</summary>
    public static (IReadOnlyList<EvidenceChange> Rows, string? Text) Between(string oldFile, string newFile, CancellationToken ct, string? root = null,
        WorkerPool? pool = null)
    {
        var folder = RulePacks.Folder(root ?? RulePacks.Root, Pack);
        if (folder == null) return ([], null);
        var version = Path.GetFileName(folder);
        Dictionary<string, Behaviour> before, after;
        using var timer = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timer.CancelAfter(Limit);
        try
        {
            var scans = new[] { oldFile, newFile }.Select(f => Task.Run(() => Behaviours(f, folder, pool ?? WorkerPool.Shared, timer.Token), timer.Token)).ToArray();
            Task.WaitAll(scans, timer.Token);
            (before, after) = (scans[0].Result, scans[1].Result);
        }
        catch (Exception e) when (!ct.IsCancellationRequested && e is OperationCanceledException or ToolError or AggregateException)
        {
            var why = e is OperationCanceledException ? $"scanning both builds takes over {Limit.TotalSeconds:0} s"
                : (e is AggregateException a ? a.InnerExceptions[0] : e).Message;
            return ([], $"malcontent {version} behaviours not compared: {why}; search_container kind=yara query=pack:{Pack} on each build lists them.\n");
        }
        var rows = before.Keys.Union(after.Keys, StringComparer.Ordinal).Where(k => before.ContainsKey(k) != after.ContainsKey(k))
            .OrderByDescending(k => (after.GetValueOrDefault(k) ?? before[k]).Risk).ThenBy(k => k, StringComparer.Ordinal)
            .Select(k => new EvidenceChange(after.ContainsKey(k) ? "added" : "removed", $"{Pack}/{k}",
                before.TryGetValue(k, out var o) ? Evidence(o) : null, after.TryGetValue(k, out var n) ? Evidence(n) : null, null)).ToList();
        var text = new System.Text.StringBuilder($"malcontent {version} behaviours: {rows.Count(r => r.Kind == "added")} added, {rows.Count(r => r.Kind == "removed")} removed" +
                                                 (rows.Count > MaxRows ? $"; the {MaxRows} of highest risk kept" : "") +
                                                 (rows.Count > MaxTextRows ? $"; the {MaxTextRows} of highest risk shown, the rest in changes" : "") + ".\n");
        rows = rows.Take(MaxRows).ToList();
        foreach (var r in rows.Take(MaxTextRows)) text.Append($"  {r.Kind} {r.Key}: {r.New ?? r.Old}\n");
        return (rows, text.ToString());
    }

    private static string Evidence(Behaviour b) =>
        (b.Risk > 0 ? Risks[b.Risk - 1] : "no risk tag") + (b.Description != null ? $": {b.Description}" : "") + $" ({string.Join(", ", b.Rules.Take(3))}" +
        (b.Rules.Count > 3 ? $" +{b.Rules.Count - 3}" : "") + ")";

    private static Dictionary<string, Behaviour> Behaviours(string file, string folder, WorkerPool pool, CancellationToken ct)
    {
        var info = new FileInfo(file);
        var key = (info.FullName, info.Exists ? info.Length : -1, info.Exists ? info.LastWriteTimeUtc : default, folder);
        if (Kept.TryGetValue(key, out var kept)) return kept;
        var ids = Ids.GetOrAdd(folder, RuleIds);
        var request = new JsonObject { ["path"] = info.FullName, ["rules"] = folder };
        var result = pool.RunAsync("yara", YaraOps.ScanOp, request, Limit, ct, file).GetAwaiter().GetResult().Deserialize<YaraScanResult>(YaraOps.Json)
                     ?? throw new ToolError(ErrorCode.Failed, "The yara worker answered without a result.");
        var behaviours = new Dictionary<string, Behaviour>(StringComparer.Ordinal);
        foreach (var rule in result.Hits.SelectMany(h => h.Rules))
        {
            // Rules under false_positives/ lower other rules' risk in malcontent; they are not behaviours.
            if (!ids.TryGetValue(rule.Rule, out var id) || id.StartsWith("false_positives/", StringComparison.Ordinal)) continue;
            int risk = rule.Tags.Select(t => Array.IndexOf(Risks, t) + 1).DefaultIfEmpty(0).Max();
            var description = rule.Meta.FirstOrDefault(m => m.Key == "description").Value;
            if (!behaviours.TryGetValue(id, out var b)) behaviours[id] = b = new Behaviour(risk, description, new SortedSet<string>(StringComparer.Ordinal));
            else if (risk > b.Risk) behaviours[id] = b = b with { Risk = risk, Description = description ?? b.Description };
            b.Rules.Add(rule.Rule);
        }
        Kept[key] = behaviours;
        return behaviours;
    }

    /// <summary>Each rule name in the pack's files mapped to its file's path without the extension.</summary>
    private static Dictionary<string, string> RuleIds(string folder)
    {
        var ids = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var file in Directory.EnumerateFiles(folder, "*.yar*", SearchOption.AllDirectories).Where(f => f.EndsWith(".yar", StringComparison.OrdinalIgnoreCase) || f.EndsWith(".yara", StringComparison.OrdinalIgnoreCase)))
        {
            var id = Path.ChangeExtension(Path.GetRelativePath(folder, file), null).Replace('\\', '/');
            foreach (Match m in RuleName().Matches(File.ReadAllText(file))) ids.TryAdd(m.Groups[1].Value, id);
        }
        return ids;
    }

    [GeneratedRegex(@"(?m)^[ \t]*(?:(?:private|global)[ \t]+)*rule[ \t]+([A-Za-z_][A-Za-z0-9_]*)")]
    private static partial Regex RuleName();
}
