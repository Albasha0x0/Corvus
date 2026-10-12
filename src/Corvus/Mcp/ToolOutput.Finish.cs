using System.Text.Json;
using System.Text.Json.Nodes;
using ModelContextProtocol.Protocol;
using Corvus.Core;

namespace Corvus.Mcp;

public static partial class ToolOutput
{
    /// <summary>The fitted result, or a smaller limit to call the tool again with (its text and record pages disagree).</summary>
    internal sealed record Finished(CallToolResult Result, int? RetryLimit);

    /// <summary>Top-level record fields that hold timings: moved to _meta (results stay deterministic).</summary>
    private static readonly string[] TimingFields = ["elapsed", "elapsedSeconds", "elapsedMs", "durationMs"];

    /// <summary>
    /// Fits a successful result to the call's budget, each part on its own: a list record and its text keep the same rows
    /// with the list envelope; text pages carry their position; anything else past the budget keeps its head and names
    /// the whole result by resultId. The text block is readable text, never a copy of the record.
    /// </summary>
    /// <param name="canRetry">The tool is read-only with a limit parameter: it can be called again for a smaller page.</param>
    internal static Finished Finish(OutputCall call, CallToolResult result, bool readOnly, bool canRetry, ResultStore? store, JsonObject meta,
        KeptOrigin? origin = null)
    {
        var tool = call.Tool ?? "?";
        var others = result.Content.Where(b => b is not TextContentBlock).ToList();
        string text = string.Concat(result.Content.OfType<TextContentBlock>().Select(b => b.Text)).Replace("\r\n", "\n");
        // A tool returning its record: the SDK put the record's JSON in the text block, which the renderer replaces.
        bool bare = call.Record == null && result.StructuredContent is not null && text.TrimStart().StartsWith('{');
        var record = call.Record != null ? Serialize(call.Record) as JsonObject
            : result.StructuredContent is { } s ? JsonNode.Parse(s.GetRawText()) as JsonObject : null;
        if (record != null)
        {
            StripNulls(record);
            foreach (var f in TimingFields)
                if (record.Remove(f, out var t) && t != null) (meta["corvus/timings"] ??= new JsonObject())[f] = t.DeepClone();
        }
        if (bare) text = "";

        if (record != null && RowsKey(record, tool) is { } rowsKey)
        {
            if (FitList(call, record, rowsKey, ref text, bare, canRetry, store, origin) is { } retry) return new Finished(result, retry);
        }
        else if (call.TextPage is { } page && record != null)
            PageRecord(call, record, page, ref text, call.RecordHasBody || ToolContract.Of(tool).Output is OutputClass.Code or OutputClass.Bytes);
        else if (bare) text = RecordText.Render(record!, null);
        // D3: a code or bytes record carries the text it stands beside.
        else if (record != null && record["code"] is null && ToolContract.Of(tool).Output is OutputClass.Code or OutputClass.Bytes) record["code"] = text;

        Annotate(call, record, ref text);
        Bound(call, tool, record, ref text, store, readOnly, origin);
        if (call.JsonMode && record != null) text = record.ToJsonString(Json);
        if (text.Length == 0 && record == null && others.Count == 0) text = "Done.";
        return new Finished(new CallToolResult
        {
            Content = [new TextContentBlock { Text = text }, .. others],
            StructuredContent = record != null ? JsonSerializer.SerializeToElement(record, Json) : null,
            IsError = result.IsError,
            Meta = result.Meta,
        }, null);
    }

    /// <summary>
    /// A character page's position in its record and, for code and bytes, the page itself (D3); where the escaped body makes
    /// the record larger than the text, both parts end at an earlier line.
    /// </summary>
    private static void PageRecord(OutputCall call, JsonObject record, TextPageState page, ref string text, bool body)
    {
        int end = page.End;
        string slice = page.Slice;
        void Set(int to, string s)
        {
            record["offset"] = page.Offset;
            if (to < page.Total) record["nextOffset"] = to; else record.Remove("nextOffset");
            record["totalChars"] = page.Total;
            if (body) record["code"] = s;
        }
        Set(end, slice);
        if (!body || page.Render == null || call.Fits(record.ToJsonString(Wire)) || !text.Contains(page.Rendered, StringComparison.Ordinal)) return;
        int lo = page.Offset + 1, hi = end;
        while (lo < hi)
        {
            int mid = (lo + hi + 1) / 2;
            Set(mid, page.Render(mid).Slice);
            if (call.Fits(record.ToJsonString(Wire))) lo = mid; else hi = mid - 1;
        }
        // Back to the last whole line, when the page has one.
        int nl = slice.LastIndexOf('\n', Math.Max(0, lo - page.Offset - 1));
        if (nl >= 0) lo = page.Offset + nl + 1;
        var (rendered, cut) = page.Render(lo);
        Set(lo, cut);
        text = text.Replace(page.Rendered, rendered);
    }

    /// <summary>
    /// The rows array of a list record: "items" (or the tool's row arrays in <see cref="RowArrays"/>, the first non-empty one)
    /// beside a total; else null.
    /// </summary>
    internal static string? RowsKey(JsonObject record, string? tool)
    {
        if (record["total"] is not JsonValue t || !t.TryGetValue<long>(out _)) return null;
        string[] keys = tool != null && RowArrays.TryGetValue(tool, out var named) ? named : ["items"];
        var present = keys.Where(k => record[k] is JsonArray).ToList();
        return present.FirstOrDefault(k => record[k]!.AsArray().Count > 0) ?? present.FirstOrDefault();
    }

    /// <summary>
    /// Fits a list's rows to both parts; null when done, else the smaller limit to call again with. A list without a row
    /// offset (its tool pages the text by characters, or not at all) continues through a kept result instead of nextOffset.
    /// </summary>
    private static int? FitList(OutputCall call, JsonObject record, string key, ref string text, bool bare, bool canRetry, ResultStore? store,
        KeptOrigin? origin)
    {
        var items = (JsonArray)record[key]!;
        bool rowOffset = record["offset"] is JsonValue ov && ov.TryGetValue<int>(out _);
        int offset = rowOffset ? (int)record["offset"]! : 0, total = (int)Math.Min(int.MaxValue, (long)record["total"]!), count = items.Count;
        bool truncated = record.Remove("truncated", out var tr) && tr?.GetValueKind() == JsonValueKind.True;
        var itemJson = items.Select(i => i?.ToJsonString(Wire) ?? "null").ToList();
        var empty = (JsonObject)record.DeepClone();
        ((JsonArray)empty[key]!).Clear();
        (string Text, string Record)? whole = rowOffset ? null : (text, record.ToJsonString(Json));
        int recordMax = Math.Max(1, Fitting(call, empty.ToJsonString(Wire), itemJson));
        int k;
        var rows = call.RowPage;
        if (rows != null && rows.Offset == offset && rows.Rendered is var rendered && text.Contains(rendered, StringComparison.Ordinal))
        {
            // The text is a PageRows page: re-render it with fewer rows where the record needs that.
            var before = text;
            k = FitCount(Math.Min(rows.Shown, count), n => call.Fits(before.Replace(rendered, rows.Render(n))), recordMax);
            text = before.Replace(rendered, rows.Render(k));
        }
        else if (bare)
        {
            var all = record;
            k = FitCount(count, n => call.Fits(RecordText.Render(Take(all, key, n), key, Envelope(offset, n, total, truncated, count))), recordMax);
            text = RecordText.Render(Take(record, key, k), key, Envelope(offset, k, total, truncated, count));
        }
        // Without a row offset the tool's text keeps its own paging.
        else if (!rowOffset) k = Math.Min(count, recordMax);
        else
        {
            bool textCut = call.TextPage is { Cut: true };
            bool textFits = !textCut && call.Fits(text);
            if (textFits && recordMax >= count) k = count;
            else if (canRetry && count > 1)
            {
                double ratio = Math.Min(recordMax / (double)count,
                    textCut ? call.TextPage!.End / (double)Math.Max(1, call.TextPage.Total) : textFits ? 1 : call.Tokens / (double)Math.Max(1, TokenEstimate.Of(text)));
                return Math.Clamp((int)(count * ratio * 0.85), 1, count - 1);
            }
            else
            {
                // The tool's text cannot be cut by rows: the text shows the record's rows instead.
                k = FitCount(count, n => call.Fits(RecordText.Render(Take(record, key, n), key, Envelope(offset, n, total, truncated, count))), recordMax);
                text = RecordText.Render(Take(record, key, k), key, Envelope(offset, k, total, truncated, count));
            }
        }
        while (items.Count > k) items.RemoveAt(items.Count - 1);
        bool exact = record["totalExact"] is JsonValue e ? e.GetValue<bool>() : !(truncated && offset + count >= total);
        bool more = offset + k < total || !exact && k > 0 && k == count && truncated;
        record["limit"] = call.Limit ?? rows?.Limit ?? Math.Max(count, 1);
        record["totalExact"] = exact;
        record["hasMore"] = more;
        if (record["notEvaluated"] is JsonValue ne && ne.TryGetValue<int>(out var notEvaluated) && notEvaluated == 0) record.Remove("notEvaluated");
        if (!rowOffset)
        {
            // No row offset to continue at: the whole result is kept and named.
            if (more && store != null && whole is { } w)
            {
                var id = store.Keep(w.Text.Length > 0 ? w.Text : w.Record, origin ?? new KeptOrigin(call.Tool ?? "?"), w.Record);
                record["resultId"] = id;
                if (!text.Contains(id, StringComparison.Ordinal)) text = text.TrimEnd('\n') + $"\n[More: read_result id={id}]\n";
            }
            return null;
        }
        if (more) record["nextOffset"] = offset + k;
        else record.Remove("nextOffset");
        if (more && !text.Contains($"offset={offset + k}", StringComparison.Ordinal)) text = text.TrimEnd('\n') + "\n" + OutputPager.More(offset + k) + "\n";
        return null;
    }

    private static (int Offset, int Shown, int Total, bool Truncated, int Count)? Envelope(int offset, int shown, int total, bool truncated, int count) =>
        (offset, shown, total, truncated, count);

    /// <summary>A copy of a list record with its first <paramref name="n"/> items.</summary>
    private static JsonObject Take(JsonObject record, string key, int n)
    {
        var copy = (JsonObject)record.DeepClone();
        var items = (JsonArray)copy[key]!;
        while (items.Count > n) items.RemoveAt(items.Count - 1);
        return copy;
    }

    /// <summary>Warnings, coverage and the engine into both parts.</summary>
    private static void Annotate(OutputCall call, JsonObject? record, ref string text)
    {
        // Tools that state incompleteness in their own text: the same lines become the record's warnings.
        if (record != null && record["warnings"] is null)
        {
            var stated = text.Split('\n').Where(l => l.StartsWith("Incomplete:", StringComparison.Ordinal) || l.StartsWith("Partial:", StringComparison.Ordinal)).ToList();
            if (stated.Count > 0) record["warnings"] = new JsonArray(stated.Select(l => (JsonNode)JsonValue.Create(l)!).ToArray());
        }
        if (call.Warnings.Count > 0)
        {
            text = text.TrimEnd('\n') + "\n" + string.Join("\n", call.Warnings.Select(w => "Warning: " + w)) + "\n";
            if (record != null) record["warnings"] = new JsonArray(call.Warnings.Select(w => (JsonNode)JsonValue.Create(w)!).ToArray());
        }
        if (call.Coverage is { } c)
        {
            text = $"[{(c.Status == "partial" ? "Partial" : "Coverage unknown")}: {c.Reason}]\n" + text;
            if (record != null)
                record["coverage"] = new JsonObject
                {
                    ["status"] = c.Status,
                    ["reason"] = c.Reason,
                    ["limitations"] = new JsonArray(c.Limitations.Select(l => (JsonNode)JsonValue.Create(l)!).ToArray()),
                };
        }
        if (call.Engine is { } en && record != null)
        {
            record["engine"] ??= en.Engine;
            if (en.Note != null) record["engineNote"] ??= en.Note;
        }
    }

    /// <summary>
    /// The last guard: a part still over the budget keeps its head (text) or its first rows (record) and both name the whole
    /// result, kept for read_result. Read-only or not, it stays a success (D2, S1.6).
    /// </summary>
    private static void Bound(OutputCall call, string tool, JsonObject? record, ref string text, ResultStore? store, bool readOnly, KeptOrigin? origin)
    {
        bool textOver = !call.Fits(text);
        bool recordOver = record != null && !call.Fits(record.ToJsonString(Wire));
        if (!textOver && !recordOver) return;
        var whole = text.Length > 0 ? text : record!.ToJsonString(new JsonSerializerOptions(Json) { WriteIndented = true });
        var id = store?.Keep(whole, origin ?? new KeptOrigin(tool), record?.ToJsonString(Json));
        var note = id != null
            ? $"[Cut to fit the response: the whole {(readOnly ? "result" : "outcome")} ({whole.Length:N0} chars) is kept as {id}; read_result id={id} pages through it]"
            : $"[Cut to fit the response: {whole.Length:N0} chars in all]";
        if (textOver)
        {
            int end = OutputPager.FitEnd(text, 0, call.Tokens - TokenEstimate.Of(note) - 8, call.Chars is { } c ? c - note.Length - 4 : null);
            text = text[..end].TrimEnd('\n') + "\n" + note;
        }
        if (record == null) return;
        if (id != null) record["resultId"] = id;
        while (!call.Fits(record.ToJsonString(Wire)) && TrimLargest(record)) { }
    }

    /// <summary>Removes the last element of the record's largest array, else shortens its longest string; false when nothing is left to trim.</summary>
    private static bool TrimLargest(JsonObject record)
    {
        JsonNode? best = null;
        int size = 0;
        void Visit(JsonNode? node)
        {
            switch (node)
            {
                case JsonArray a when a.Count > 0:
                    int s = a.ToJsonString(Json).Length;
                    if (s > size) { size = s; best = a; }
                    foreach (var child in a) Visit(child);
                    break;
                case JsonObject o:
                    foreach (var (_, child) in o) Visit(child);
                    break;
                case JsonValue v when v.GetValueKind() == JsonValueKind.String && v.GetValue<string>().Length > 200:
                    int len = v.GetValue<string>().Length;
                    if (len > size) { size = len; best = v; }
                    break;
            }
        }
        Visit(record);
        switch (best)
        {
            case JsonArray a:
                a.RemoveAt(a.Count - 1);
                return true;
            case JsonValue v:
                var str = v.GetValue<string>();
                v.ReplaceWith(str[..(str.Length / 2)] + "…");
                return true;
            default:
                return false;
        }
    }

    /// <summary>Drops null members everywhere: an optional field is omitted, never null (S4.4).</summary>
    internal static void StripNulls(JsonNode? node)
    {
        switch (node)
        {
            case JsonObject o:
                foreach (var key in o.Where(p => p.Value is null).Select(p => p.Key).ToList()) o.Remove(key);
                foreach (var (_, child) in o) StripNulls(child);
                break;
            case JsonArray a:
                foreach (var child in a) StripNulls(child);
                break;
        }
    }
}
