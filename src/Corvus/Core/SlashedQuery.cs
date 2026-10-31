namespace Corvus.Core;

/// <summary>Reads search queries written as /pattern/.</summary>
public static class SlashedQuery
{
    /// <summary>Reads a query wrapped in slashes (at least one character between them) as a regex; returns false and leaves the query when it is not.</summary>
    public static bool Read(ref string query, ref bool regex)
    {
        if (regex || query is not { Length: > 2 } || query[0] != '/' || query[^1] != '/') return false;
        query = query[1..^1];
        return regex = true;
    }
}
