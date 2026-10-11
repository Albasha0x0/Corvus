namespace Corvus.Core;

/// <summary>Case-insensitive '*' / '?' matching of a whole name, without regular expressions (linear in practice, no backtracking blow-up).</summary>
public static class Wildcard
{
    public static bool IsPattern(string text) => text.AsSpan().IndexOfAny('*', '?') >= 0;

    public static bool Matches(string name, string pattern)
    {
        int n = 0, p = 0, star = -1, mark = 0;
        while (n < name.Length)
        {
            if (p < pattern.Length && (pattern[p] == '?' || char.ToUpperInvariant(pattern[p]) == char.ToUpperInvariant(name[n]))) { n++; p++; }
            else if (p < pattern.Length && pattern[p] == '*') { star = p++; mark = n; }
            else if (star >= 0) { p = star + 1; n = ++mark; }
            else return false;
        }
        while (p < pattern.Length && pattern[p] == '*') p++;
        return p == pattern.Length;
    }
}
