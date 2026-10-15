using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Corvus.Core;
using Corvus.Mcp;

namespace Corvus.Tools;

/// <summary>read_result's views of a kept result: the body in a format, a page within a token budget, and a line search.</summary>
/// <summary>A line of a kept result matching read_result's query, at its character offset.</summary>
public sealed record ReadResultMatch(int Offset, string Line);

/// <summary>
/// read_result's record: a page of the kept result (code, offset, nextOffset, totalChars), the matching lines of a query, or
/// the file the whole result was written to.
/// </summary>
public sealed record ReadResultRecord(string Id, string Tool, int TotalChars)
{
    public int? Offset { get; init; }
    public int? NextOffset { get; init; }
    [System.ComponentModel.Description("The page of the kept result.")] public string? Code { get; init; }
    public IReadOnlyList<ReadResultMatch>? Matches { get; init; }
    public IReadOnlyList<EvidenceBundle.Check>? Checks { get; init; }
    [System.ComponentModel.Description("format=verify: what each record was checked against (a re-run, or the result named by against).")] public string? Input { get; init; }
    public string? Path { get; init; }
    public long? Bytes { get; init; }
    public string? Sha256 { get; init; }
}

internal static class ReadResultView
{
    /// <summary>Characters of a matching line shown by a search; the offset reaches the rest.</summary>
    private const int MaxMatchChars = 500;

    public static string Body(KeptResult kept, string? format) => (format?.Trim().ToLowerInvariant() ?? "text") switch
    {
        "" or "text" => kept.Text,
        "json" => kept.Record ?? throw NoRecord(kept),
        "jsonl" => JsonLines(kept.Record ?? throw NoRecord(kept)),
        var other => throw new ToolError(ErrorCode.InvalidArgument, $"format must be text, json or jsonl, not '{other}'.", "pass format=text, json or jsonl"),
    };

    private static ToolError NoRecord(KeptResult kept) =>
        new(ErrorCode.InvalidArgument, $"{kept.Id} ({kept.Info.Tool}) was kept as text only; it has no structured record.", "pass format=text");

    /// <summary>One compact line per item: the root array, else the items array, else the largest array, else the record itself.</summary>
    internal static string JsonLines(string record)
    {
        using var doc = JsonDocument.Parse(record);
        var root = doc.RootElement;
        JsonElement? items = root.ValueKind == JsonValueKind.Array ? root : null;
        if (items == null && root.ValueKind == JsonValueKind.Object)
            items = root.TryGetProperty("items", out var i) && i.ValueKind == JsonValueKind.Array ? i
                : root.EnumerateObject().Where(p => p.Value.ValueKind == JsonValueKind.Array).OrderByDescending(p => p.Value.GetArrayLength())
                    .Select(p => (JsonElement?)p.Value).FirstOrDefault();
        var sb = new StringBuilder();
        foreach (var item in items?.EnumerateArray() ?? Enumerable.Repeat(root, 1))
            sb.Append(item.GetRawText().Contains('\n') ? JsonSerializer.Serialize(item) : item.GetRawText()).Append('\n');
        return sb.ToString();
    }

    /// <summary>The text from <paramref name="offset"/> that fits <paramref name="tokens"/>, cut at a line end when one fits, with a [More:]/[End:] footer.</summary>
    public static string Page(string body, int offset, long tokens) => Page(body, offset, tokens, out _);

    /// <param name="end">Where the page ends; the next page's offset when it is before the end of the body.</param>
    public static string Page(string body, int offset, long tokens, out int end)
    {
        end = body.Length;
        if (offset >= body.Length) return $"[End: {body.Length:N0} chars]";
        end = offset;
        long used = 0;
        while (end < body.Length)
        {
            int nl = body.IndexOf('\n', end);
            int lineEnd = nl < 0 ? body.Length : nl + 1;
            long cost = CallLog.EstimateTokens(body.AsSpan(end, lineEnd - end));
            if (used + cost > tokens)
            {
                // A line longer than the whole page: as much of it as fits, so paging always advances.
                if (end == offset) end = PrefixWithin(body, offset, lineEnd, tokens);
                break;
            }
            used += cost;
            end = lineEnd;
        }
        if (end > offset && end < body.Length && char.IsHighSurrogate(body[end - 1])) end--;
        if (end == offset) end = offset + 1;
        var page = body[offset..end];
        return page + (page.EndsWith('\n') ? "" : "\n") + (end < body.Length ? $"[More: offset={end}]" : $"[End: {body.Length:N0} chars]");
    }

    private static int PrefixWithin(string body, int start, int limit, long tokens)
    {
        int lo = start, hi = limit;
        while (lo < hi)
        {
            int mid = lo + (hi - lo + 1) / 2;
            if (CallLog.EstimateTokens(body.AsSpan(start, mid - start)) <= tokens) lo = mid;
            else hi = mid - 1;
        }
        return lo;
    }

    /// <summary>Lines from <paramref name="offset"/> on that match <paramref name="query"/>, each with its character offset.</summary>
    public static string Search(string body, string query, int offset, long tokens) => Search(body, query, offset, tokens, null, out _);

    /// <param name="hits">Receives each matching line with its offset.</param>
    /// <param name="next">The offset to search on from, when the page stopped before the end.</param>
    public static string Search(string body, string query, int offset, long tokens, List<ReadResultMatch>? hits, out int? next)
    {
        next = null;
        Func<string, bool> matches;
        if (query.Length > 2 && query.StartsWith('/') && query.EndsWith('/'))
        {
            Regex regex;
            try { regex = new Regex(query[1..^1], RegexOptions.CultureInvariant, TimeSpan.FromSeconds(2)); }
            catch (ArgumentException e)
            {
                throw new ToolError(ErrorCode.InvalidArgument, $"query is not a valid regular expression: {e.Message}", "fix the pattern, or drop the slashes to search for the text");
            }
            matches = line => regex.IsMatch(line);
        }
        else matches = line => line.Contains(query, StringComparison.OrdinalIgnoreCase);

        var sb = new StringBuilder();
        long used = 0;
        int found = 0, at = Math.Min(offset, body.Length);
        while (at < body.Length)
        {
            int nl = body.IndexOf('\n', at);
            int lineEnd = nl < 0 ? body.Length : nl;
            var line = body[at..lineEnd];
            bool hit;
            try { hit = matches(line); }
            catch (RegexMatchTimeoutException)
            {
                throw new ToolError(ErrorCode.Timeout, $"the pattern took over 2 s on the line at offset {at}.", "simplify the pattern");
            }
            if (hit)
            {
                var shown = line.Length > MaxMatchChars ? line[..MaxMatchChars] + "..." : line;
                var row = $"{at}: {shown}\n";
                long cost = CallLog.EstimateTokens(row);
                if (found > 0 && used + cost > tokens)
                {
                    next = at;
                    return sb.Append($"[More: offset={at}]").ToString();
                }
                hits?.Add(new ReadResultMatch(at, shown));
                sb.Append(row);
                used += cost;
                found++;
            }
            at = lineEnd + 1;
        }
        return sb.Append($"[End: {found} matching line{(found == 1 ? "" : "s")} from offset {offset}]").ToString();
    }
}
