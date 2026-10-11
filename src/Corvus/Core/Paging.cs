namespace Corvus.Core;

/// <summary>
/// Pages long tool output and keeps an LRU cache of produced texts so later pages are not regenerated.
/// </summary>
public sealed class OutputPager(ServerOptions options)
{
    private const int CacheCapacity = 24;
    private readonly LinkedList<(string Key, string Text)> _cache = new();

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
            while (_cache.Count > CacheCapacity)
                _cache.RemoveLast();
        }
        return text;
    }

    /// <summary>Pages rows by offset/limit with a count header and continuation hint, then applies the character limit.</summary>
    public string PageRows(IReadOnlyList<string> rows, int offset, int limit, string noun)
    {
        limit = Math.Clamp(limit, 1, 5_000);
        offset = Math.Max(0, offset);
        var page = rows.Skip(offset).Take(limit).ToList();
        var fit = FitRows(page.Select(r => "  " + r).ToList(), 1_000); // room for the caller's header lines too
        var sb = new System.Text.StringBuilder()
            .AppendLine($"{rows.Count} {(rows.Count == 1 ? noun : noun + "s")} (showing {(fit == 0 ? 0 : offset + 1)}-{offset + fit}):");
        foreach (var r in page.Take(fit)) sb.Append("  ").AppendLine(r);
        if (fit < page.Count)
            sb.AppendLine(CapNote(fit, page.Count, offset + fit));
        else if (offset + page.Count < rows.Count)
            sb.AppendLine($"[More: call again with offset={offset + page.Count}]");
        return Page(sb.ToString());
    }

    /// <summary>The output limit of a call (maxChars when given, else the server's).</summary>
    public int MaxChars(int? maxChars = null) => Math.Clamp(maxChars is > 0 ? maxChars.Value : options.MaxOutputChars, 1_000, 500_000);

    /// <summary>How many of <paramref name="lines"/> fit in the output limit beside <paramref name="reserve"/> characters of header and footer.</summary>
    public int FitRows(IReadOnlyList<string> lines, int reserve, int? maxChars = null)
    {
        long room = MaxChars(maxChars) - reserve;
        int n = 0;
        foreach (var line in lines)
        {
            room -= line.Length + Environment.NewLine.Length;
            if (room < 0) break;
            n++;
        }
        return Math.Max(n, Math.Min(1, lines.Count)); // at least one row, so paging always advances
    }

    /// <summary>The footer of a row list cut by the output limit: "473 of 532 rows fit; use offset=473".</summary>
    public static string CapNote(int fit, int asked, int next) =>
        $"[{fit} of {asked} rows fit in the output limit; use offset={next} (or a larger maxChars / smaller limit)]";

    /// <summary>Returns the character slice starting at <paramref name="offset"/>, cut at a line break when possible.</summary>
    /// <param name="complete">False when <paramref name="text"/> was produced only past the page: the total is not known.</param>
    public string Page(string text, int offset = 0, int? maxChars = null, bool complete = true)
    {
        int max = MaxChars(maxChars);
        if (offset < 0) offset = 0;
        if (offset >= text.Length && text.Length > 0)
            throw new ToolError(ErrorCode.InvalidArgument, $"offset {offset} is past the end of the output ({text.Length} chars).");
        if (offset == 0 && text.Length <= max)
            return text;

        int end = Math.Min(text.Length, offset + max);
        if (end < text.Length)
        {
            int nl = text.LastIndexOf('\n', end - 1, Math.Min(end - offset, 4_000));
            if (nl > offset)
                end = nl + 1;
        }

        var slice = text[offset..end];
        var footer = end < text.Length
            ? $"\n\n[Output truncated: chars {offset}-{end} of {text.Length}{(complete ? "" : "+")}. Call again with offset={end} for the next page.]"
            : $"\n\n[End of output: chars {offset}-{end} of {text.Length}.]";
        var header = offset > 0 ? $"[Continuing from offset {offset}]\n" : "";
        return header + slice + footer;
    }
}
