namespace Corvus.Core;

/// <summary>
/// The output state of one tool call: its budget per part (text and structured content each) and what the tool's paging
/// produced, read by the call filter to fit both parts together. Flows into the tool's tasks.
/// </summary>
public sealed class OutputCall
{
    private static readonly AsyncLocal<OutputCall?> Active = new();

    public OutputCall(string? tool, int tokens, int? chars, bool jsonMode = false)
    {
        Tool = tool;
        Tokens = tokens;
        Chars = chars;
        JsonMode = jsonMode;
    }

    /// <summary>The call in progress, or null outside the call filter (direct calls, tests).</summary>
    public static OutputCall? Current => Active.Value;

    /// <summary>The current call when it has a budget (a collector without one pages like a direct call).</summary>
    public static OutputCall? Budgeted => Active.Value is { Tokens: > 0 } c ? c : null;

    /// <summary>Makes <paramref name="call"/> the current call for this flow.</summary>
    public static OutputCall Begin(OutputCall call) => Active.Value = call;

    public string? Tool { get; }

    /// <summary>Estimated tokens each part may take.</summary>
    public int Tokens { get; }

    /// <summary>The client's character cap per part, if any.</summary>
    public int? Chars { get; }

    /// <summary>CORVUS_RESULT_MODE=json: the text block is the compact structured JSON.</summary>
    public bool JsonMode { get; }

    /// <summary>The structured record the tool handed over with its text.</summary>
    public object? Record { get; set; }

    /// <summary>Same as <see cref="Record"/>.</summary>
    public object? Value => Record;

    /// <summary>The record carries the text page as its "code" field (code and bytes results).</summary>
    public bool RecordHasBody { get; set; }

    /// <summary>The last character page the tool cut.</summary>
    public TextPageState? TextPage { get; set; }

    /// <summary>The last row page the tool rendered.</summary>
    public RowPageState? RowPage { get; set; }

    /// <summary>The limit argument after clamping, when the filter clamped it.</summary>
    public int? Limit { get; set; }

    public List<string> Warnings { get; } = [];

    public (string Status, string Reason, IReadOnlyList<string> Limitations)? Coverage { get; set; }

    public (string Engine, string? Note)? Engine { get; set; }

    public bool Fits(string text) => Tokens <= 0 || (Chars is not { } c || text.Length <= c) && TokenEstimate.Of(text) <= Tokens;
}

/// <summary>A character page: <see cref="Slice"/> is text[Offset..End] of <see cref="Total"/> characters.</summary>
public sealed record TextPageState(int Offset, int End, int Total, bool Complete, string Slice)
{
    /// <summary>The page as the tool returned it (header, slice, footer).</summary>
    public string Rendered { get; init; } = Slice;

    /// <summary>The page cut at another end: (rendered, slice).</summary>
    public Func<int, (string Text, string Slice)>? Render { get; init; }

    public bool Cut => Offset > 0 || End < Total;
}

/// <summary>A row page: <see cref="Rendered"/> shows rows Offset..Offset+Shown; <see cref="Render"/> renders it with fewer rows.</summary>
public sealed record RowPageState(int Offset, int Limit, int Shown, int Total, string Rendered, Func<int, string> Render);

/// <summary>
/// Pages long tool output and keeps an LRU cache of produced texts so later pages are not regenerated. Inside a call the
/// page size is the call's token budget; outside one (direct calls) it is the server's character page.
/// </summary>
public sealed class OutputPager(ServerOptions options)
{
    private const int CacheCapacity = 24;
    /// <summary>Characters the cache holds at most.</summary>
    public const long CacheMaxChars = 32L * 1024 * 1024;
    private readonly LinkedList<(string Key, string Text)> _cache = new();
    private long _cacheChars;

    /// <summary>Cached texts and their characters, for server_status.</summary>
    public (int Count, long Chars) CacheSize
    {
        get { lock (_cache) return (_cache.Count, _cacheChars); }
    }

    public bool TryGet(string key, out string text)
    {
        lock (_cache)
            for (var node = _cache.First; node != null; node = node.Next)
                if (node.Value.Key == key)
                {
                    text = node.Value.Text;
                    return true;
                }
        text = "";
        return false;
    }

    public string GetOrCreate(string key, Func<string> produce)
    {
        lock (_cache)
        {
            for (var node = _cache.First; node != null; node = node.Next)
                if (node.Value.Key == key)
                {
                    _cache.Remove(node);
                    _cache.AddFirst(node);
                    return node.Value.Text;
                }
        }

        var text = produce();
        lock (_cache)
        {
            _cache.AddFirst((key, text));
            _cacheChars += text.Length;
            while (_cache.Count > 1 && (_cache.Count > CacheCapacity || _cacheChars > CacheMaxChars))
            {
                _cacheChars -= _cache.Last!.Value.Text.Length;
                _cache.RemoveLast();
            }
        }
        return text;
    }

    /// <summary>Pages rows by offset/limit with a count header and one footer, fitted to the page size.</summary>
    public string PageRows(IReadOnlyList<string> rows, int offset, int limit, string noun)
    {
        limit = Math.Clamp(limit, 1, 5_000);
        offset = Math.Max(0, offset);
        var page = rows.Skip(offset).Take(limit).Select(r => r.Replace("\r\n", "\n")).ToList();
        int fit = FitRows(page.Select(r => "  " + r).ToList(), 1_000); // room for the caller's header lines too
        string Render(int shown)
        {
            shown = Math.Min(shown, page.Count);
            var sb = new System.Text.StringBuilder()
                .Append($"{rows.Count} {(rows.Count == 1 ? noun : noun + "s")} (showing {(shown == 0 ? 0 : offset + 1)}-{offset + shown}):\n");
            foreach (var r in page.Take(shown)) sb.Append("  ").Append(r).Append('\n');
            sb.Append(offset + shown < rows.Count ? More(offset + shown) : End(rows.Count, noun)).Append('\n');
            return sb.ToString();
        }
        var text = Render(fit);
        if (OutputCall.Current is { } call) call.RowPage = new RowPageState(offset, limit, Math.Min(fit, page.Count), rows.Count, text, Render);
        return text;
    }

    /// <summary>The one continuation footer of a page.</summary>
    public static string More(int next) => $"[More: offset={next}]";

    /// <summary>The footer of a last page.</summary>
    public static string End(int total, string noun) => $"[End: {total} {(total == 1 ? noun : noun + "s")}]";

    /// <summary>
    /// A character count that holds a page: the token budget at the densest text (2 characters per token) inside a call,
    /// else maxTokens at 4 characters per token, else the server's page.
    /// </summary>
    public int MaxChars(int? maxTokens = null) => OutputCall.Budgeted is { } call
        ? Math.Min(call.Tokens * 4, call.Chars ?? int.MaxValue)
        : maxTokens is > 0 ? Math.Clamp(maxTokens.Value * 4, 1_000, 500_000) : Math.Clamp(options.MaxOutputChars, 1_000, 500_000);

    /// <summary>How many of <paramref name="lines"/> fit in the page beside <paramref name="reserve"/> characters of header and footer.</summary>
    public int FitRows(IReadOnlyList<string> lines, int reserve, int? maxTokens = null)
    {
        int n = 0;
        if (OutputCall.Budgeted is { } call)
        {
            long tokens = call.Tokens - reserve / 3, chars = (call.Chars ?? int.MaxValue) - reserve;
            foreach (var line in lines)
            {
                tokens -= TokenEstimate.Of(line) + 1;
                chars -= line.Length + 1;
                if (tokens < 0 || chars < 0) break;
                n++;
            }
        }
        else
        {
            long room = MaxChars(maxTokens) - reserve;
            foreach (var line in lines)
            {
                room -= line.Length + 1;
                if (room < 0) break;
                n++;
            }
        }
        return Math.Max(n, Math.Min(1, lines.Count)); // at least one row, so paging always advances
    }

    /// <summary>The footer of a row list cut by the page size: the next offset.</summary>
    public static string CapNote(int fit, int asked, int next) => More(next);

    /// <summary>
    /// The slice starting at <paramref name="offset"/> that fits the page, cut at a line break when possible, with one footer:
    /// [More: offset=N] to continue, [End: N chars] on a last page past the first.
    /// </summary>
    /// <param name="complete">False when <paramref name="text"/> was produced only past the page: the total is not known.</param>
    public string Page(string text, int offset = 0, int? maxTokens = null, bool complete = true)
    {
        if (offset < 0) throw new ToolError(ErrorCode.InvalidArgument, $"offset must be 0 or more, not {offset}.");
        if (offset >= text.Length && text.Length > 0)
            throw new ToolError(ErrorCode.InvalidArgument, $"offset {offset} is past the end of the output ({text.Length} chars).");
        text = text.Replace("\r\n", "\n");
        offset = Math.Min(offset, text.Length);
        var call = OutputCall.Budgeted;
        int end = PageEnd(text, offset, call, maxTokens);
        string Render(int to)
        {
            if (offset == 0 && to == text.Length) return text;
            var footer = to < text.Length
                ? $"\n{More(to)} (chars {offset}-{to} of {text.Length}{(complete ? "" : "+")})"
                : $"\n[End: {text.Length} chars]";
            var header = offset > 0 ? $"[Continuing from offset {offset}]\n" : "";
            return header + text[offset..to] + footer;
        }
        var page = Render(end);
        call?.TextPage = new TextPageState(offset, end, text.Length, complete, text[offset..end]) { Rendered = page, Render = to => (Render(to), text[offset..to]) };
        return page;
    }

    /// <summary>The end of the last whole line in text[offset..end] at or before <paramref name="max"/>, else max.</summary>
    public static int LineEnd(string text, int offset, int max)
    {
        int nl = max > offset ? text.LastIndexOf('\n', max - 1, max - offset) : -1;
        return nl >= offset ? nl + 1 : max;
    }

    /// <summary>Where the page from <paramref name="offset"/> ends.</summary>
    private int PageEnd(string text, int offset, OutputCall? call, int? maxTokens)
    {
        if (call == null && maxTokens is not > 0)
        {
            int max = MaxChars();
            if (text.Length - offset <= max) return text.Length;
            int end = offset + max;
            int nl = text.LastIndexOf('\n', end - 1, Math.Min(end - offset, 4_000));
            return nl > offset ? nl + 1 : end;
        }
        // Room for a header and footer line beside the page.
        return FitEnd(text, offset, (call?.Tokens ?? maxTokens!.Value) - 40, call?.Chars is { } c ? c - 160 : null);
    }

    /// <summary>
    /// The end of the longest run of whole lines from <paramref name="offset"/> within <paramref name="tokens"/> estimated
    /// tokens and <paramref name="chars"/> characters; a first line larger than that is cut inside (never empty).
    /// </summary>
    public static int FitEnd(string text, int offset, long tokens, long? chars)
    {
        long room = chars ?? long.MaxValue;
        int at = offset;
        while (at < text.Length)
        {
            int nl = text.IndexOf('\n', at);
            int next = nl < 0 ? text.Length : nl + 1;
            int cost = TokenEstimate.Of(text.AsSpan(at, next - at));
            if (cost > tokens || next - at > room)
            {
                if (at > offset) return at;
                int lo = at + 1, hi = next;
                while (lo < hi)
                {
                    int mid = (lo + hi + 1) / 2;
                    if (TokenEstimate.Of(text.AsSpan(at, mid - at)) <= tokens && mid - at <= room) lo = mid; else hi = mid - 1;
                }
                if (lo < text.Length && char.IsLowSurrogate(text[lo]) && lo > at + 1) lo--;
                return lo;
            }
            tokens -= cost;
            room -= next - at;
            at = next;
        }
        return text.Length;
    }
}
