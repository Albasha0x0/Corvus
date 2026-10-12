namespace Corvus.Mcp;

/// <summary>Per-tool tables kept as one partial file per tool family, so changes to different families never touch the same file.</summary>
internal static class FamilyTables
{
    /// <summary>The rows of every family in one table; a tool listed twice is an <see cref="ArgumentException"/>.</summary>
    public static Dictionary<string, T> Join<T>(IReadOnlyDictionary<string, IReadOnlyDictionary<string, T>> byFamily)
    {
        var all = new Dictionary<string, T>(StringComparer.Ordinal);
        foreach (var rows in byFamily.Values)
            foreach (var (tool, row) in rows)
                all.Add(tool, row);
        return all;
    }
}
