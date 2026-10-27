using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization;
using ModelContextProtocol.Protocol;
using Corvus.Core;

namespace Corvus.Mcp;

/// <summary>Builds tool results: text and a record that each carry the whole answer, fitted to the budget with one continuation.</summary>
// Outside the call filter (tests) the builders return the same text and drop the record.
public static partial class ToolOutput
{
    /// <summary>The list envelope fields every list record carries.</summary>
    public static readonly string[] ListFields = ["offset", "limit", "total", "totalExact", "hasMore", "nextOffset", "notEvaluated"];

    /// <summary>Hands <paramref name="record"/> over as the call's structured content and returns <paramref name="text"/>.</summary>
    public static string With(string text, object record)
    {
        OutputCall.Current?.Record = record;
        return text;
    }

    /// <summary>A page of rows from <paramref name="offset"/> that fits the budget in both parts, the same rows in text and record, with one footer.</summary>
    /// <param name="record">The tool's record for the rows shown; the list envelope fields are set on it.</param>
    /// <param name="totalExact">False when the enumeration stopped early: <paramref name="total"/> is a lower bound.</param>
    public static string List<TRow>(IReadOnlyList<TRow> page, int offset, int limit, int total, Func<TRow, string> renderRow,
        Func<IReadOnlyList<TRow>, object> record, string noun, string? header = null, bool totalExact = true)
    {
        var rows = page.Take(Math.Max(0, limit)).ToList();
        var lines = rows.Select(r => Line(renderRow(r))).ToList();
        string Render(int shown) => (header ?? "") + RowsText(lines, offset, shown, total, totalExact, noun);
        int k = rows.Count;
        if (OutputCall.Current is { } call)
        {
            if (call.Tokens > 0) k = FitCount(rows.Count, n => call.Fits(Render(n)), RecordCost(call, record([]), rows.Select(r => Serialize(r!)).ToList()));
            call.Record = record(rows.Take(k).ToList());
            call.RowPage = new RowPageState(offset, limit, k, total, Render(k), Render);
            call.Limit ??= limit;
            if (!totalExact) call.Coverage ??= ("partial", "the enumeration stopped early; total is a lower bound", ["row-cap"]);
        }
        return Render(k);
    }

    /// <summary>A list of all rows (offset applied here).</summary>
    public static string List<TRow>(IReadOnlyList<TRow> all, int offset, int limit, Func<TRow, string> renderRow,
        Func<IReadOnlyList<TRow>, object> record, string noun, string? header = null) =>
        List(all.Skip(Math.Max(0, offset)).Take(Math.Max(0, limit)).ToList(), offset, limit, all.Count, renderRow, record, noun, header);

    /// <summary>Code or bytes text from <paramref name="offset"/> characters, cut at a line to the budget; the record carries the same page as "code".</summary>
    public static string Text(OutputPager pager, string body, int offset, object? record = null, int? maxTokens = null)
    {
        var text = pager.Page(body, offset, maxTokens);
        if (OutputCall.Current is { } call && record != null)
        {
            call.Record = record;
            call.RecordHasBody = true;
        }
        return text;
    }

    /// <summary>A report: past the budget, its head with the whole result kept under a resultId.</summary>
    public static string Report(string text, object record) => With(text, record);

    /// <summary>A mutating tool's outcome: the record is <paramref name="outcome"/>.</summary>
    public static string Edit(EditOutcome outcome, string text) => With(text, outcome);

    /// <summary>Collects the record of direct tool calls (tests) without a budget: pages stay the server's character page.</summary>
    public static OutputCall Collect() => OutputCall.Begin(new OutputCall(null, 0, null));

    /// <summary>A warning in both parts (regex time-outs, incomplete input).</summary>
    public static void Warn(string text) => OutputCall.Current?.Warnings.Add(text);

    /// <summary>The result is not complete: <paramref name="status"/> is partial or unknown; limitations are from the closed vocabulary.</summary>
    public static void Coverage(string status, string reason, params string[] limitations) => OutputCall.Current?.Coverage = (status, reason, limitations);

    /// <summary>The reader read all of its input: a scan tool's result reports complete coverage instead of unknown.</summary>
    public static void Complete() => OutputCall.Current?.Whole = true;

    /// <summary>The facets a function result can have; comparisons treat a facet missing on either side as unknown.</summary>
    public static readonly IReadOnlyList<string> FacetNames = ["pseudocode", "callers", "callees", "xrefs", "strings", "cfg"];

    /// <summary>Records whether a facet of the result is available (<paramref name="unavailable"/> null) or why it is not.</summary>
    public static void Facet(string name, string? unavailable = null)
    {
        if (OutputCall.Current is not { } call) return;
        call.Facets ??= new(StringComparer.Ordinal);
        // Unavailable on any part of a batch stays unavailable.
        if (!call.Facets.TryGetValue(name, out var was) || was == null) call.Facets[name] = unavailable;
    }

    /// <summary>Which engine answered, and why.</summary>
    public static void Engine(string engine, string? note) => OutputCall.Current?.Engine = (engine, note);

    // A row's line breaks continue it, indented, so file text cannot start a marker line (a type named "x\nNext: ...").
    internal static string Line(string row) => Format.EscapeMarkers(row).Replace("\r\n", "\n").TrimEnd('\r').Replace('\r', '\n').Replace("\n", "\n    ");

    private static string RowsText(List<string> lines, int offset, int shown, int total, bool totalExact, string noun)
    {
        var sb = new StringBuilder();
        string count = (totalExact ? "" : "≥") + total;
        sb.Append($"{count} {OutputPager.Noun(total, noun)}");
        sb.Append(shown == 0 ? (offset > 0 ? $" (none from offset {offset})" : "") : $" (showing {offset + 1}-{offset + shown})").Append(":\n");
        foreach (var l in lines.Take(shown)) sb.Append("  ").Append(l).Append('\n');
        sb.Append(offset + shown < total || !totalExact && shown > 0 && offset + shown >= total
            ? OutputPager.More(offset + shown) : OutputPager.End(total, noun)).Append('\n');
        return sb.ToString();
    }

    /// <summary>The largest n ≤ <paramref name="max"/> for which <paramref name="fits"/> holds and the record cost allows; at least 1.</summary>
    private static int FitCount(int max, Func<int, bool> fits, int recordMax)
    {
        int hi = Math.Min(max, recordMax);
        if (hi <= 1) return Math.Min(max, 1);
        if (fits(hi)) return hi;
        int lo = 1;
        while (lo < hi)
        {
            int mid = (lo + hi + 1) / 2;
            if (fits(mid)) lo = mid; else hi = mid - 1;
        }
        return lo;
    }

    /// <summary>How many of <paramref name="items"/> the record holds within the budget, beside <paramref name="empty"/>: the record of no rows, whichever field holds them.</summary>
    private static int RecordCost(OutputCall call, object empty, List<JsonNode?> items) =>
        Fitting(call, Serialize(empty)?.ToJsonString(Wire) ?? "{}", items.Select(i => i?.ToJsonString(Wire) ?? "null").ToList());

    /// <summary>How many item JSONs fit beside a record of <paramref name="emptyJson"/> (items empty) in the budget.</summary>
    private static int Fitting(OutputCall call, string emptyJson, List<string> items)
    {
        // Room for the envelope fields, warnings and notices set later; item estimates do not add up exactly.
        long tokens = call.Tokens - TokenEstimate.Of(emptyJson) - 60 - call.Tokens / 50, chars = (call.Chars ?? int.MaxValue) - emptyJson.Length - 200L;
        int n = 0;
        foreach (var item in items)
        {
            tokens -= TokenEstimate.Of(item) + 1;
            chars -= item.Length + 1;
            if (tokens < 0 || chars < 0) break;
            n++;
        }
        return n;
    }

    /// <summary>Compact JSON with relaxed escaping; nulls are dropped by <see cref="StripNulls"/>.</summary>
    internal static readonly JsonSerializerOptions Json = Catalog.ToolSerializerOptions;

    /// <summary>The transport's encoding (it escapes non-ASCII and HTML-sensitive characters): sizes are measured in it.</summary>
    internal static readonly JsonSerializerOptions Wire = ModelContextProtocol.McpJsonUtilities.DefaultOptions;

    internal static JsonNode? Serialize(object value) => value is JsonNode n ? n.DeepClone() : JsonSerializer.SerializeToNode(value, value.GetType(), Json);
}
