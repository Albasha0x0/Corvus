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
    private static readonly string[] TimingFields = ["elapsed", "elapsedSeconds", "elapsedMs", "durationMs", "seconds"];

    /// <summary>Fits each part of a successful result to the call's budget; over-budget parts keep their head and name the whole result by resultId.</summary>
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
            if (OmittedDefaults.TryGetValue(tool, out var omitted)) StripDefaults(record, omitted);
            foreach (var f in TimingFields)
                if (record.Remove(f, out var t) && t != null) (meta["corvus/timings"] ??= new JsonObject())[f] = t.DeepClone();
        }
        if (bare) text = "";
        // A text tool declaring a record (TextPageRecord) returned only its text: the record is made from the page.
        bool textRecord = record == null && result.StructuredContent is { ValueKind: JsonValueKind.String };
        if (textRecord)
        {
            record = new JsonObject();
            if (call.TextPage == null)
            {
                record["code"] = text;
                record["offset"] = 0;
                record["totalChars"] = text.Length;
            }
        }

        if (record != null && RowsKey(record, tool) is { } rowsKey)
        {
            if (FitList(call, record, rowsKey, ref text, bare, canRetry, store, origin) is { } retry) return new Finished(result, retry);
        }
        else if (call.TextPage is { } page && record != null)
            PageRecord(call, record, page, ref text, textRecord || call.RecordHasBody || ToolContract.Of(tool).Output is OutputClass.Code or OutputClass.Bytes);
        else if (bare) text = RecordText.Render(record!, null);
        // D3: a code or bytes record carries the text it stands beside.
        else if (record != null && record["code"] is null && ToolContract.Of(tool).Output is OutputClass.Code or OutputClass.Bytes) record["code"] = text;

        Annotate(call, record, ref text, ToolContract.Of(tool).Output is OutputClass.Code or OutputClass.Bytes);
        Bound(call, tool, record, ref text, store, readOnly, origin);
        // Both parts are escaped here, after fitting, so they carry the same escapes of the file text.
        text = Format.EscapeInvisible(text);
        Format.EscapeInvisible(record);
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

    /// <summary>Writes a character page's position, and for code and bytes the page, into the record; both parts end earlier when escaping makes the record larger.</summary>
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
        // The rest of the record alone is over the budget: shortening the page cannot help, the record is trimmed later.
        Set(page.Offset + 1, page.Render(page.Offset + 1).Slice);
        if (!call.Fits(record.ToJsonString(Wire)))
        {
            Set(end, slice);
            return;
        }
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

    /// <summary>The key of a list record's rows array beside a total: "items" or the first non-empty one in <see cref="RowArrays"/>; else null.</summary>
    internal static string? RowsKey(JsonObject record, string? tool)
    {
        if (record["total"] is not JsonValue t || !t.TryGetValue<long>(out _)) return null;
        string[] keys = tool != null && RowArrays.TryGetValue(tool, out var named) ? named : ["items"];
        var present = keys.Where(k => record[k] is JsonArray).ToList();
        return present.FirstOrDefault(k => record[k]!.AsArray().Count > 0) ?? present.FirstOrDefault();
    }

    /// <summary>Fits a list's rows to both parts; null when done, else the smaller limit to call again with.</summary>
    // A list without a row offset continues through a kept result instead of nextOffset.
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
    private static void Annotate(OutputCall call, JsonObject? record, ref string text, bool body)
    {
        // Tools that state incompleteness in their own text: the same lines become the record's warnings.
        if (record != null && record["warnings"] is null)
        {
            var stated = text.Split('\n').Where(l => l.StartsWith("Incomplete:", StringComparison.Ordinal) || l.StartsWith("Partial:", StringComparison.Ordinal)
                || l.StartsWith("Skipped:", StringComparison.Ordinal)).ToList();
            if (stated.Count > 0) record["warnings"] = new JsonArray(stated.Select(l => (JsonNode)JsonValue.Create(l)!).ToArray());
        }
        if (call.Warnings.Count > 0)
        {
            text = text.TrimEnd('\n') + "\n" + string.Join("\n", call.Warnings.Select(w => "Warning: " + w)) + "\n";
            if (record != null) record["warnings"] = new JsonArray(call.Warnings.Select(w => (JsonNode)JsonValue.Create(w)!).ToArray());
        }
        if (call.Notes.Count > 0)
        {
            text = text.TrimEnd('\n') + "\n" + string.Join("\n", call.Notes) + "\n";
            if (record != null) AddNotes(record, call.Notes);
        }
        if (call.Coverage == null && record != null && Stopped(record) is { } why) call.Coverage = ("partial", why, ["row-cap"]);
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
        if (call.Facets is { Count: > 0 } facets)
        {
            var missing = facets.Where(f => f.Value != null).ToList();
            if (missing.Count > 0) text = $"[Unavailable: {string.Join("; ", missing.Select(f => $"{f.Key} ({f.Value})"))}]\n" + text;
            if (record != null)
            {
                var cov = record["coverage"] as JsonObject ?? new JsonObject { ["status"] = "complete" };
                cov["facets"] = Facets(facets);
                record["coverage"] = cov;
            }
        }
        if (call.Engine is { } en && record != null)
        {
            record["engine"] ??= en.Engine;
            if (en.Note != null) record["engineNote"] ??= en.Note;
        }
        if (record != null) LiftNotes(record, text, call.Notes, body);
    }

    /// <summary>Line starts that mark a line the reader acts on or must not miss.</summary>
    private static readonly string[] ActionStarts =
    [
        "Next:", "Note:", "Notes:", "Hint:", "Dry run:", "Warning:",
        "Incomplete:", "Partial:", "Skipped:",
        "[More:", "[Cut", "[Partial:", "[Coverage unknown:", "[Unavailable:",
        NoticePrefix,
    ];

    /// <summary>Markers a tool prints before a line its record holds without them.</summary>
    private static readonly string[] BarePrefixes = ["Warning: ", "Note: ", "Notes: ", "Hint: ", "Next: "];

    /// <summary>Text longer than this is scanned at its head and tail only, where tool-added lines sit.</summary>
    private const int ScanEdge = 8192;

    /// <summary>The action lines of <paramref name="text"/>: a marker at column 0 with the indented lines that continue it (row text is indented or escaped, so file text never starts one).</summary>
    public static IEnumerable<string> ActionLines(string text)
    {
        if (text.Length > 2 * ScanEdge)
        {
            var head = text[..ScanEdge];
            head = head[..(head.LastIndexOf('\n') + 1)];
            var tail = text[^ScanEdge..];
            tail = tail[(tail.IndexOf('\n') + 1)..];
            foreach (var l in ActionLines(head).Concat(ActionLines(tail))) yield return l;
            yield break;
        }
        var lines = text.Split('\n').Select(l => l.TrimEnd('\r')).ToList();
        for (int i = 0; i < lines.Count; i++)
        {
            var line = lines[i];
            if (!ActionStarts.Any(s => line.StartsWith(s, StringComparison.Ordinal))) continue;
            int end = i + 1;
            // A dry-run block continues through its Before and After headers.
            while (end < lines.Count && (lines[end].StartsWith("  ", StringComparison.Ordinal)
                || (line.StartsWith("Dry run:", StringComparison.Ordinal) && lines[end] is "Before:" or "After:"))) end++;
            yield return string.Join("\n", lines.Skip(i).Take(end - i));
            i = end - 1;
        }
    }

    /// <summary>Whether <paramref name="record"/> states <paramref name="line"/>: in a string value, or through the field its kind maps to.</summary>
    public static bool Carries(JsonObject record, string line)
    {
        if (line.StartsWith("[More:", StringComparison.Ordinal) || line.StartsWith("[Cut", StringComparison.Ordinal))
            return record["nextOffset"] is not null || record["resultId"] is not null;
        if (line.StartsWith("[Partial:", StringComparison.Ordinal) || line.StartsWith("[Coverage unknown:", StringComparison.Ordinal) || line.StartsWith("[Unavailable:", StringComparison.Ordinal))
            return record["coverage"] is not null;
        if (line.StartsWith(NoticePrefix, StringComparison.Ordinal)) return record["notices"] is not null;
        // A text line carries its marker ("Warning: ", "Note: ") where the record's entry does not.
        var bare = BarePrefixes.FirstOrDefault(m => line.StartsWith(m, StringComparison.Ordinal)) is { } marker ? line[marker.Length..] : line;
        var strings = Strings(record).ToList();
        if (strings.Any(s => s.Contains(bare, StringComparison.Ordinal))) return true;
        // A marker line over indented entries is carried when the record holds each entry.
        var rows = line.Split('\n');
        return rows.Length > 1 && rows[0].EndsWith(':') && rows.Skip(1).All(r => r.Trim() is { Length: > 0 } t && strings.Any(s => s.Contains(t, StringComparison.Ordinal)));
    }

    private static IEnumerable<string> Strings(JsonNode? node)
    {
        switch (node)
        {
            case JsonValue v when v.TryGetValue<string>(out var s): yield return s; break;
            case JsonObject o:
                foreach (var (_, child) in o) foreach (var s in Strings(child)) yield return s;
                break;
            case JsonArray a:
                foreach (var child in a) foreach (var s in Strings(child)) yield return s;
                break;
        }
    }

    /// <summary>Lifts unstated action lines into <c>notes</c> and counts row advice.</summary>
    private static void LiftNotes(JsonObject record, string text, IReadOnlyCollection<string> added, bool body)
    {
        var missing = ActionLines(text).Where(l => !added.Contains(l) && !Carries(record, l)).Distinct(StringComparer.Ordinal).ToList();
        var carried = new List<string>();
        if (!body)
            foreach (var advice in RowAdvice(text))
            {
                if (RowField(record, advice) is { } field) carried.Add(field);
                else if (!missing.Contains(advice)) missing.Add(advice);
            }
        if (carried.Count > 0)
        {
            var fields = carried.Distinct(StringComparer.Ordinal).ToList();
            missing.Add($"Note: {carried.Count} row advice {(carried.Count == 1 ? "entry is" : "entries are")} in the {string.Join(", ", fields.Select(f => $"'{f}'"))} field{(fields.Count == 1 ? "" : "s")}.");
        }
        if (missing.Count > 0) AddNotes(record, missing);
    }

    private static readonly System.Text.RegularExpressions.Regex RowAdviceLine =
        new(@"^(?:[ \t]*(?:note|warning|hint|next): (?<text>\S.*)|.*?; next: (?<text>[a-z][a-z0-9]*(?:_[a-z0-9]+)+\b.*))$", System.Text.RegularExpressions.RegexOptions.Multiline | System.Text.RegularExpressions.RegexOptions.NonBacktracking);

    /// <summary>The lower-case advice lines and <c>; next:</c> clauses of a text.</summary>
    public static IEnumerable<string> RowAdvice(string text) =>
        RowAdviceLine.Matches(text).Where(m => !ActionStarts.Any(s => m.Value.StartsWith(s, StringComparison.Ordinal))).Select(m => m.Groups["text"].Value.TrimEnd((char)13))
            // Backstop: a number alone is a field value, not advice.
            .Where(t => !t.All(char.IsAsciiDigit));

    /// <summary>The row field that states <paramref name="advice"/>, else null.</summary>
    public static string? RowField(JsonObject record, string advice)
    {
        foreach (var (name, child) in record)
            if (name is not ("notes" or "actionNotes" or "text" or "lines" or "code" or "output") && Field(child, name, advice) is { } found) return found;
        return null;
    }

    private static string? Field(JsonNode? node, string name, string advice)
    {
        switch (node)
        {
            case JsonValue v when v.TryGetValue<string>(out var s):
                return name is "text" or "lines" or "code" or "output" ? null
                    : s.Trim() == advice || s.TrimEnd().EndsWith("; next: " + advice, StringComparison.Ordinal) ? name : null;
            case JsonObject o:
                foreach (var (key, child) in o) if (Field(child, key, advice) is { } f) return f;
                return null;
            case JsonArray a:
                foreach (var child in a) if (Field(child, name, advice) is { } f) return f;
                return null;
            default: return null;
        }
    }

    /// <summary>Appends to the record's string <c>notes</c>; a tool whose own notes has another shape takes them in <c>actionNotes</c>.</summary>
    private static void AddNotes(JsonObject record, IEnumerable<string> lines)
    {
        var own = record["notes"] is null || record["notes"] is JsonArray a && a.All(n => n is JsonValue);
        var key = own ? "notes" : "actionNotes";
        var list = record[key] as JsonArray ?? new JsonArray();
        foreach (var l in lines) list.Add(l);
        record[key] = list;
    }

    /// <summary>Why a record says it stopped early (truncated, cut, incomplete, or a partial reason), else null.</summary>
    private static string? Stopped(JsonObject record)
    {
        foreach (var flag in (string[])["truncated", "cut", "incomplete"])
            if (record[flag] is JsonValue v && v.TryGetValue(out bool b) && b) return $"the result is {(flag == "cut" ? "cut short" : flag)} (its {flag} field)";
        return record["partial"] is JsonValue p && p.TryGetValue(out string? s) && !string.IsNullOrEmpty(s) ? s : null;
    }

    /// <summary>Facets as {name: "available" or "unavailable: why"}.</summary>
    internal static JsonObject Facets(IEnumerable<KeyValuePair<string, string?>> facets) =>
        new(facets.Select(f => KeyValuePair.Create(f.Key, (JsonNode?)JsonValue.Create(f.Value == null ? "available" : "unavailable: " + f.Value))));

    /// <summary>The last guard: a part still over budget keeps its head or first rows and names the whole kept result; it stays a success.</summary>
    private static void Bound(OutputCall call, string tool, JsonObject? record, ref string text, ResultStore? store, bool readOnly, KeptOrigin? origin)
    {
        bool textOver = !call.Fits(text);
        bool recordOver = record != null && !call.Fits(record.ToJsonString(Wire));
        if (!textOver && !recordOver) return;
        // The part that is cut is kept: a text page that fits already carries its own continuation.
        var whole = textOver && text.Length > 0 ? text : record!.ToJsonString(new JsonSerializerOptions(Json) { WriteIndented = true });
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
        // Every array that loses rows is named in a warning, so a cut record never reads as complete.
        var cut = new Dictionary<string, (int Kept, int Total)>(StringComparer.Ordinal);
        var warnings = record["warnings"] as JsonArray;
        int stated = warnings?.Count ?? 0;
        while (record.ToJsonString(Wire) is var json && !call.Fits(json)
            && (TrimLargest(record, cut, Excess(call, json), keepOne: true) || TrimLargest(record, cut, Excess(call, json), keepOne: false)))
        {
            call.CutPasses++;
            warnings ??= (JsonArray)(record["warnings"] = new JsonArray());
            while (warnings.Count > stated) warnings.RemoveAt(warnings.Count - 1);
            warnings.Add("Cut to fit: " + string.Join(", ", cut.Select(c => $"{c.Key} {c.Value.Kept} of {c.Value.Total}")) +
                (id != null ? $" kept; read_result id={id} has the whole record" : " kept"));
        }
    }

    /// <summary>Characters to take off <paramref name="json"/> in one step: half the estimated excess, at least 1.</summary>
    // Halving reaches the budget in a few passes instead of one per row (87 s for a 20,000-node frontier before).
    private static int Excess(OutputCall call, string json)
    {
        double over = call.Tokens > 0 ? json.Length * (1 - call.Tokens / (double)Math.Max(1, TokenEstimate.Of(json))) : 0;
        if (call.Chars is { } c) over = Math.Max(over, json.Length - c);
        return (int)Math.Clamp(over / 2, 1, int.MaxValue);
    }

    /// <summary>Takes about <paramref name="chars"/> characters off the record by shortening the lists inside oversized items, then trimming the largest arrays or halving the largest string; false when nothing changed. With <paramref name="keepOne"/> an array keeps its first item.</summary>
    private static bool TrimLargest(JsonObject record, Dictionary<string, (int Kept, int Total)> cut, int chars, bool keepOne)
    {
        var (best, arrays, groups) = Parts(record, record["warnings"]);
        // An item larger than the page loses list entries before any item is
        // dropped: items of a short array, and items well above the median.
        if (ShortenNested(groups, cut, chars)) return true;
        if (best is JsonValue v)
        {
            var str = v.GetValue<string>();
            // Named like an array, in characters.
            var key = v.GetPath().TrimStart('$', '.') + " characters";
            int whole = cut.TryGetValue(key, out var was) ? was.Total : str.Length;
            v.ReplaceWith(str[..(str.Length / 2)] + "…");
            cut[key] = (str.Length / 2, whole);
            return true;
        }
        if (arrays.Count == 0) return false;
        bool changed = false;
        // The level that leaves the arrays above it `chars` smaller in all.
        arrays.Sort((a, b) => b.Size.CompareTo(a.Size));
        long sum = 0, level = 0;
        for (int k = 0; k < arrays.Count; k++)
        {
            sum += arrays[k].Size;
            level = Math.Max(0, (sum - chars) / (k + 1));
            if (k + 1 == arrays.Count || level >= arrays[k + 1].Size) break;
        }
        bool first = true;
        foreach (var (a, size) in arrays)
        {
            if (size <= level && !first) break;
            var path = a.GetPath().TrimStart('$', '.');
            int total = cut.TryGetValue(path, out var c) ? c.Total : a.Count;
            int removed = 0, count = a.Count;
            // An array's size is its elements plus a comma each.
            while (count > (keepOne ? 1 : 0) && (first && removed == 0 || size - removed > level))
            {
                removed += (a[count - 1]?.ToJsonString(Json).Length ?? 4) + 1;
                count--;
            }
            first = false;
            if (count == a.Count) continue;
            changed = true;
            for (int i = a.Count - 1; i >= count; i--) a.RemoveAt(i);
            cut[path] = (count, total);
            foreach (var gone in cut.Keys.Where(k => Index(k, path) >= count).ToList()) cut.Remove(gone);
        }
        return changed;

        // The element index of a path below `prefix` ("prefix[3].x" -> 3), else -1.
        static int Index(string key, string prefix) =>
            key.Length > prefix.Length + 1 && key.StartsWith(prefix, StringComparison.Ordinal) && key[prefix.Length] == '['
            && key.IndexOf(']', prefix.Length) is var end and > 0 && int.TryParse(key.AsSpan(prefix.Length + 1, end - prefix.Length - 1), out var i) ? i : -1;
    }

    /// <summary>Removes list entries from the lists inside oversized items, largest list first, keeping the first entry; false when none is left to shorten.</summary>
    private static bool ShortenNested(List<List<(long Size, List<(JsonArray Array, long Size)> Lists)>> groups, Dictionary<string, (int Kept, int Total)> cut, int chars)
    {
        var candidates = new List<(JsonArray Array, long Size)>();
        foreach (var items in groups)
        {
            var sizes = items.Select(i => i.Size).OrderBy(x => x).ToList();
            long median = sizes[sizes.Count / 2];
            foreach (var (size, lists) in items)
                if (items.Count <= 8 || size > 2 * median) candidates.AddRange(lists);
        }
        if (candidates.Count == 0) return false;
        candidates.Sort((x, y) => y.Size.CompareTo(x.Size));
        long left = chars;
        bool changed = false;
        foreach (var (a, size) in candidates)
        {
            if (left <= 0) break;
            if (a.Count < 2) continue;
            var path = a.GetPath().TrimStart('$', '.');
            int total = cut.TryGetValue(path, out var was) ? was.Total : a.Count;
            long removed = 0;
            int count = a.Count;
            while (count > 1 && removed < left)
            {
                removed += (a[count - 1]?.ToJsonString(Json).Length ?? 4) + 1;
                count--;
            }
            for (int i = a.Count - 1; i >= count; i--) a.RemoveAt(i);
            cut[path] = (count, total);
            left -= removed;
            changed = true;
        }
        return changed;
    }

    /// <summary>The largest part and the outermost non-empty arrays, from one bottom-up pass, leaving out <paramref name="own"/>.</summary>
    private static (JsonNode? Best, List<(JsonArray Array, long Size)> Arrays, List<List<(long Size, List<(JsonArray Array, long Size)> Lists)>> Groups) Parts(JsonObject record, JsonNode? own)
    {
        JsonNode? best = null;
        long largest = 0;
        var arrays = new List<(JsonArray, long)>();
        // Per outermost array: each item's size and the lists inside it.
        var groups = new List<List<(long, List<(JsonArray, long)>)>>();
        List<(JsonArray, long)>? lists = null;
        Measure(record, inArray: false);
        return (best, arrays, groups);

        long Measure(JsonNode? node, bool inArray)
        {
            switch (node)
            {
                case null:
                    return 4;
                case JsonArray a:
                    long s = 2 + Math.Max(0, a.Count - 1);
                    var items = !inArray && a.Count > 0 && a != own ? new List<(long, List<(JsonArray, long)>)>() : null;
                    foreach (var child in a)
                    {
                        var before = lists;
                        if (items != null) lists = [];
                        long size = Measure(child, true);
                        s += size;
                        if (items != null) { items.Add((size, lists!)); lists = before; }
                    }
                    if (a.Count > 0 && a != own)
                    {
                        if (s > largest) { largest = s; best = a; }
                        if (!inArray) arrays.Add((a, s));
                        else if (a.Count > 1) lists?.Add((a, s));
                    }
                    if (items != null) groups.Add(items);
                    return s;
                case JsonObject o:
                    long t = 2 + Math.Max(0, o.Count - 1);
                    foreach (var (key, child) in o) t += key.Length + 3 + Measure(child, inArray);
                    return t;
                default:
                    var v = (JsonValue)node;
                    if (v.GetValueKind() != JsonValueKind.String) return v.ToJsonString(Json).Length;
                    var str = v.GetValue<string>();
                    if (str.Length > 200 && str.Length > largest) { largest = str.Length; best = v; }
                    return str.Length + 2;
            }
        }
    }

    /// <summary>Drops null members everywhere: an optional field is omitted, never null.</summary>
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
