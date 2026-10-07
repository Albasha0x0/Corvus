namespace NetDecompilerMcp.Core;

/// <summary>
/// Splits long tool output into pages and caches recently produced texts so that
/// requesting page 2 of a big decompilation does not decompile again.
/// </summary>
public sealed class OutputPager(ServerOptions options)
{
    private const int CacheCapacity = 24;
    private readonly LinkedList<(string Key, string Text)> _cache = new();

    /// <summary>Returns the cached text for <paramref name="key"/> or produces and caches it.</summary>
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

    /// <summary>
    /// Pages a list of rows by index (offset/limit), with a header line and a "more" hint, then applies the character limit.
    /// </summary>
    public string PageRows(IReadOnlyList<string> rows, int offset, int limit, string noun)
    {
        limit = Math.Clamp(limit, 1, 5_000);
        offset = Math.Max(0, offset);
        var page = rows.Skip(offset).Take(limit).ToList();
        var sb = new System.Text.StringBuilder()
            .AppendLine($"{rows.Count} {(rows.Count == 1 ? noun : noun + "s")} (showing {(page.Count == 0 ? 0 : offset + 1)}-{offset + page.Count}):");
        foreach (var r in page) sb.Append("  ").AppendLine(r);
        if (offset + page.Count < rows.Count)
            sb.AppendLine($"[More: call again with offset={offset + page.Count}]");
        return Page(sb.ToString());
    }

    /// <summary>Returns the slice starting at <paramref name="offset"/>, cut at a line break when possible.</summary>
    public string Page(string text, int offset = 0, int? maxChars = null)
    {
        int max = Math.Clamp(maxChars is > 0 ? maxChars.Value : options.MaxOutputChars, 1_000, 500_000);
        if (offset < 0) offset = 0;
        if (offset >= text.Length && text.Length > 0)
            throw new ToolError($"offset {offset} is past the end of the output ({text.Length} chars).");
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
            ? $"\n\n[Output truncated: chars {offset}-{end} of {text.Length}. Call again with offset={end} for the next page.]"
            : $"\n\n[End of output: chars {offset}-{end} of {text.Length}.]";
        var header = offset > 0 ? $"[Continuing from offset {offset}]\n" : "";
        return header + slice + footer;
    }
}
