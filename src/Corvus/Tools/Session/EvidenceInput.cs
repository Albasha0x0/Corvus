using System.ComponentModel;
using System.Text.Json;
using System.Text.Json.Nodes;
using Corvus.Core;

namespace Corvus.Tools;

/// <summary>
/// Evidence as input: a kept result (r-…), one of this session's latest calls (last:N) or an evidence bundle entry
/// (bundle.json#r-…), read instead of running its producer again; comparisons of two of them by item or by line.
/// </summary>
public static class EvidenceInput
{
    public const string ReferenceDescription = "a kept result (r-…), last:N (a recent call) or a bundle entry (file.json#r-…)";

    /// <summary>A resolved input: its source, text and structured record (JSON) when it had one.</summary>
    public sealed record Item(EvidenceSource Source, string Text, string? Record);

    public static Item Resolve(string reference, ResultStore? store, RecentCalls? recent)
    {
        var r = reference.Trim();
        if (r.StartsWith("last:", StringComparison.OrdinalIgnoreCase))
        {
            if (!int.TryParse(r[5..], out int n) || n < 1) throw new ToolError(ErrorCode.InvalidArgument, $"'{r}' is not last:N with N of 1 or more.", "last:1 is the latest call");
            var calls = recent?.Last(n) ?? [];
            if (calls.Count < n) throw new ToolError(ErrorCode.NotFound, $"This session has {calls.Count} recent call(s); {r} is not among them.", "make the call first, or name a kept result (r-…)");
            var c = calls[0];
            return new(new(r, "recent", c.Info.Tool, c.Info.Arguments, c.Info.Inputs, c.Info.Created), c.Text, c.Record);
        }
        int hash = r.LastIndexOf('#');
        if (hash > 0 || File.Exists(r))
        {
            var (path, id) = hash > 0 ? (r[..hash], r[(hash + 1)..]) : (r, "");
            var bundle = EvidenceBundle.Load(path);
            var record = id.Length > 0 ? bundle.Records.FirstOrDefault(x => x.Id.Equals(id, StringComparison.OrdinalIgnoreCase))
                : bundle.Records.Count == 1 ? bundle.Records[0] : null;
            if (record == null)
                throw new ToolError(id.Length > 0 ? ErrorCode.NotFound : ErrorCode.Ambiguous,
                    $"{Path.GetFileName(path)} {(id.Length > 0 ? $"has no record {id}" : $"holds {bundle.Records.Count} records")}: {string.Join(", ", bundle.Records.Select(x => $"{x.Id} {x.Tool}"))}.",
                    $"name one entry: {path}#<id>");
            return new(new(r, "bundle", record.Tool, record.Arguments, record.Inputs, bundle.Created), record.Text, record.Structured);
        }
        if (store == null) throw new ToolError(ErrorCode.Unsupported, "This server keeps no results.", "pass last:N or an evidence bundle entry");
        var kept = store.Read(r);
        return new(new(r, "kept", kept.Info.Tool, kept.Info.Arguments, kept.Info.Inputs, kept.Info.Created), kept.Text, kept.Record);
    }

    /// <summary>Both sides of a comparison, from one tool.</summary>
    public static (Item Old, Item New) ResolvePair(string oldRef, string newRef, ResultStore? store, RecentCalls? recent)
    {
        var (a, b) = (Resolve(oldRef, store, recent), Resolve(newRef, store, recent));
        if (a.Source.Tool != b.Source.Tool)
            throw new ToolError(ErrorCode.InvalidArgument, $"{oldRef} is a {a.Source.Tool} result and {newRef} a {b.Source.Tool} result.", "compare two results of one tool");
        return (a, b);
    }

    /// <summary>The code a result carries: its record's code, else its text.</summary>
    public static string Code(Item item) =>
        item.Record != null && JsonNode.Parse(item.Record) is JsonObject o && o["code"] is JsonValue v && v.TryGetValue(out string? code) ? code : item.Text;

    public static string Describe(EvidenceSource s) =>
        $"{s.Ref} ({s.Kind} {s.Tool}{(s.Inputs.Count > 0 ? " of " + string.Join(", ", s.Inputs.Select(i => $"{i.Id} {i.Sha256[..Math.Min(12, i.Sha256.Length)]}")) : "")}" +
        $"{(s.Created is { } t ? $", {t:yyyy-MM-dd HH:mm}Z" : "")})";

    // fields that name an item, in order of preference; the first every item of both sides has is the key
    private static readonly string[] KeyFields = ["address", "rva", "start", "token", "fullName", "member", "symbol", "name", "path", "id", "target", "input", "offset", "value", "text"];

    private const int MaxValueChars = 300;

    /// <summary>Compares two results: by their items when both records have them, else by the lines of their code.</summary>
    public static (EvidenceSummary EvidenceSummary, IReadOnlyList<EvidenceChange> Changes) Compare(Item a, Item b)
    {
        var (ra, rb) = (Parse(a.Record), Parse(b.Record));
        // a facet either side lacks: what it would show is unknown on both
        var gaps = FacetGaps(ra, rb);
        if (ra?["items"] is JsonArray ia && rb?["items"] is JsonArray ib)
        {
            bool partial = Partial(ra, ia) || Partial(rb, ib) || gaps.Count > 0;
            var by = KeyFields.FirstOrDefault(k => ia.Concat(ib).All(x => x is JsonObject o && o[k] is JsonValue));
            var oldItems = Keyed(ia, by);
            var newItems = Keyed(ib, by);
            var changes = new List<EvidenceChange>();
            int same = 0;
            foreach (var (key, x) in oldItems)
            {
                if (!newItems.TryGetValue(key, out var y)) changes.Add(new(Partial(rb, ib) || gaps.Count > 0 ? "unknown" : "removed", key, Clip(x), null, null));
                else if (ResultHashes.Canonical(x) == ResultHashes.Canonical(y)) same++;
                else changes.Add(new(gaps.Count > 0 ? "unknown" : "changed", key, Clip(x), Clip(y), Fields(x, y)));
            }
            foreach (var (key, y) in newItems.Where(n => !oldItems.ContainsKey(n.Key)))
                changes.Add(new(Partial(ra, ia) || gaps.Count > 0 ? "unknown" : "added", key, null, Clip(y), null));
            return Result("items", by, partial, same, changes);
        }
        var lines = TextDiff.Unified(Code(a), Code(b), a.Source.Ref, b.Source.Ref, 0).ReplaceLineEndings("\n").TrimEnd('\n').Split('\n')
            .Where(l => !l.StartsWith("---", StringComparison.Ordinal) && !l.StartsWith("+++", StringComparison.Ordinal)).ToList();
        var rows = new List<EvidenceChange>();
        int at = 0, bt = 0;
        foreach (var l in lines)
        {
            if (l.StartsWith("@@", StringComparison.Ordinal))
            {
                var m = System.Text.RegularExpressions.Regex.Match(l, @"-(\d+)(?:,\d+)? \+(\d+)");
                if (m.Success) (at, bt) = (int.Parse(m.Groups[1].Value), int.Parse(m.Groups[2].Value));
            }
            else if (l.StartsWith('-')) rows.Add(new("removed", $"line {at++}", l[1..], null, null));
            else if (l.StartsWith('+')) rows.Add(new("added", $"line {bt++}", null, l[1..], null));
        }
        if (gaps.Count > 0) rows = [.. rows.Select(r => r with { Kind = "unknown" })];
        bool paged = (ra?["nextOffset"] is JsonValue) || (rb?["nextOffset"] is JsonValue) || gaps.Count > 0 || Incomplete(ra) || Incomplete(rb);
        int oldLines = Code(a).ReplaceLineEndings("\n").TrimEnd('\n').Split('\n').Length;
        return Result("text", null, paged, Math.Max(0, oldLines - rows.Count(r => r.Kind == "removed")), rows);

        (EvidenceSummary, IReadOnlyList<EvidenceChange>) Result(string basis, string? key, bool partial, int same, List<EvidenceChange> changes) => (new(a.Source, b.Source, basis, key,
            partial ? "partial" : "complete", same, changes.Count(c => c.Kind == "changed"), changes.Count(c => c.Kind == "removed"),
            changes.Count(c => c.Kind == "added"), changes.Count(c => c.Kind == "unknown")), changes);
    }

    public static string Text(EvidenceSummary c)
    {
        var sb = new System.Text.StringBuilder($"{c.Old.Tool} results compared by {(c.Basis == "items" ? c.By != null ? $"item {c.By}" : "whole item" : "line")}:\n" +
            $"  old: {Describe(c.Old)}\n  new: {Describe(c.New)}\n" +
            $"{c.Same} same, {c.Changed} changed, {c.Removed} removed, {c.Added} added{(c.Unknown > 0 ? $", {c.Unknown} unknown" : "")}; {c.Completeness}.\n");
        if (c.Completeness == "partial") sb.Append("Note: a side holds one page of its result, is not complete, or lacks a facet; what it does not show is unknown, not removed, added or changed.\n");
        return sb.ToString();
    }

    public static string RowText(EvidenceChange r) => r.Kind switch
    {
        "changed" => $"~ {r.Key}: {string.Join(", ", r.Fields ?? [])}  {r.Old}  ->  {r.New}",
        "removed" => $"- {r.Key}  {r.Old}",
        "added" => $"+ {r.Key}  {r.New}",
        _ => $"? {r.Key}  {r.Old ?? r.New}",
    };

    /// <summary>
    /// The comparison of <paramref name="oldRef"/> and <paramref name="newRef"/> when given (both, and not with the tool's
    /// own inputs, named in <paramref name="sides"/>); null when neither is given.
    /// </summary>
    public static (EvidenceSummary EvidenceSummary, IReadOnlyList<EvidenceChange> Changes)? FromArguments(string? oldRef, string? newRef, bool sidesGiven, string sides, IServiceProvider? services)
    {
        bool o = !string.IsNullOrWhiteSpace(oldRef), n = !string.IsNullOrWhiteSpace(newRef);
        if (!o && !n)
        {
            if (!sidesGiven) throw new ToolError(ErrorCode.InvalidArgument, $"Pass {sides}, or oldResult and newResult.", $"{sides} name what to compare; oldResult and newResult compare kept results");
            return null;
        }
        if (!o || !n) throw new ToolError(ErrorCode.InvalidArgument, "Pass oldResult and newResult (both).", "each is " + ReferenceDescription);
        if (sidesGiven) throw new ToolError(ErrorCode.InvalidArgument, $"Pass {sides} or oldResult and newResult, not both.", "results are compared as they were kept: drop the other inputs");
        var (a, b) = ResolvePair(oldRef!, newRef!, services?.GetService(typeof(ResultStore)) as ResultStore, services?.GetService(typeof(RecentCalls)) as RecentCalls);
        return Compare(a, b);
    }

    private static JsonObject? Parse(string? record)
    {
        if (record == null) return null;
        try { return JsonNode.Parse(record) as JsonObject; }
        catch (JsonException) { return null; }
    }

    // one page of a longer result, or a result that says it is not complete: the items past it are not known
    private static bool Partial(JsonObject record, JsonArray items) =>
        (record["total"] is JsonValue t && t.TryGetValue(out int total) && total > items.Count) ||
        (record["hasMore"] is JsonValue h && h.TryGetValue(out bool more) && more) || record["nextOffset"] is JsonValue || Incomplete(record);

    private static bool Incomplete(JsonObject? record) =>
        record?["coverage"]?["status"] is JsonValue s && s.TryGetValue(out string? status) && status != "complete";

    /// <summary>Facets unavailable on either side (by name).</summary>
    internal static IReadOnlyList<string> FacetGaps(JsonObject? a, JsonObject? b)
    {
        static Dictionary<string, string> Of(JsonObject? r) => r?["coverage"]?["facets"] is JsonObject f
            ? f.Where(x => x.Value is JsonValue).ToDictionary(x => x.Key, x => x.Value!.ToString(), StringComparer.Ordinal) : [];
        var (fa, fb) = (Of(a), Of(b));
        return [.. fa.Keys.Union(fb.Keys).Where(k => fa.GetValueOrDefault(k, "available") != "available" || fb.GetValueOrDefault(k, "available") != "available").Order()];
    }

    private static Dictionary<string, JsonNode?> Keyed(JsonArray items, string? by)
    {
        var map = new Dictionary<string, JsonNode?>(StringComparer.Ordinal);
        foreach (var x in items)
        {
            var key = by != null ? x![by]!.ToString() : ResultHashes.Canonical(x);
            var unique = key;
            for (int n = 2; map.ContainsKey(unique); n++) unique = $"{key}#{n}";
            map[unique] = x;
        }
        return map;
    }

    private static IReadOnlyList<string>? Fields(JsonNode? x, JsonNode? y) => x is JsonObject a && y is JsonObject b
        ? [.. a.Select(p => p.Key).Union(b.Select(p => p.Key)).Where(k => ResultHashes.Canonical(a[k]) != ResultHashes.Canonical(b[k])).Order(StringComparer.Ordinal)]
        : null;

    private static string Clip(JsonNode? x) => Format.Clip(ResultHashes.Canonical(x), MaxValueChars);
}
