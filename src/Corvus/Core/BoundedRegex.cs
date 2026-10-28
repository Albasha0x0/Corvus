using System.Text.RegularExpressions;

namespace Corvus.Core;

/// <summary>
/// A backtracking regex whose pattern is checked to match in linear time: literals, anchors, bounded repeats and at most
/// one unbounded loop over a single-character atom whose start is fixed by the token before it (\b before \w, or a
/// literal outside the loop's set). Throws <see cref="ArgumentException"/> for any other pattern.
/// </summary>
/// <remarks>Built for many small rules, where NonBacktracking construction (about 1.3 MB each) dominates.</remarks>
public sealed class BoundedRegex : Regex
{
    /// <summary>Checks <paramref name="pattern"/> and builds it with <paramref name="options"/>, which must not include NonBacktracking.</summary>
    public BoundedRegex(string pattern, RegexOptions options = RegexOptions.None)
        : base(Check(pattern, options), options) { }

    /// <summary>Why <paramref name="pattern"/> is not linear under backtracking, or null when it is.</summary>
    public static string? Problem(string pattern, RegexOptions options = RegexOptions.None)
    {
        if ((options & RegexOptions.NonBacktracking) != 0) return "NonBacktracking needs no bound";
        int depth = 0, unbounded = 0;
        // The last token at depth 0 and the atom before a quantifier.
        string? previous = null, atom = null;
        for (int i = 0; i < pattern.Length;)
        {
            char c = pattern[i];
            string token;
            if (c == '\\')
            {
                if (i + 1 >= pattern.Length) return "a trailing backslash";
                char e = pattern[i + 1];
                if (e is 'b') token = @"\b";
                else if (e is 'w' or 's' or 'd' or 'W' or 'S' or 'D' or 't' or 'n' or 'r' or 'f' || !char.IsLetterOrDigit(e)) token = pattern.Substring(i, 2);
                else return $"the escape \\{e}";
                i += 2;
            }
            else if (c == '[')
            {
                int end = i + 1;
                if (end < pattern.Length && pattern[end] == '^') end++;
                if (end < pattern.Length && pattern[end] == ']') end++;
                while (end < pattern.Length && pattern[end] != ']') end += pattern[end] == '\\' ? 2 : 1;
                if (end >= pattern.Length) return "an unclosed character class";
                token = pattern[i..(end + 1)];
                i = end + 1;
            }
            else if (c == '(')
            {
                if (!pattern.AsSpan(i).StartsWith("(?:")) return "a group other than (?:...)";
                depth++;
                i += 3;
                previous = atom = null;
                continue;
            }
            else if (c == ')')
            {
                if (--depth < 0) return "an unbalanced )";
                i++;
                previous = null;
                atom = "(group)";
                continue;
            }
            else if (c == '|')
            {
                i++;
                previous = atom = null;
                continue;
            }
            else if (c is '?' or '*' or '+' or '{')
            {
                if (atom == null) return $"a quantifier at {i} with nothing to repeat";
                int end = i + 1;
                bool open = c is '*' or '+';
                if (c == '{')
                {
                    end = pattern.IndexOf('}', i);
                    if (end < 0) return "an unclosed {";
                    open = pattern[(i + 1)..end].EndsWith(',');
                    end++;
                }
                if (end < pattern.Length && pattern[end] == '?') end++;
                if (open)
                {
                    if (depth > 0) return "an unbounded loop inside a group";
                    if (++unbounded > 1) return "more than one unbounded loop";
                    if (atom == "(group)" || atom == @"\b") return "an unbounded loop over a group or anchor";
                    if (!StartFixed(previous, atom, options)) return $"the loop {atom}{pattern[i..end]} has no fixed start";
                }
                i = end;
                previous = atom = depth == 0 ? atom + "~" : null;
                continue;
            }
            else if (c is '^' or '$' or '.')
            {
                if (c == '.') { token = "."; i++; }
                else return $"the anchor {c}";
            }
            else
            {
                token = c.ToString();
                i++;
            }
            previous = depth == 0 ? atom : null;
            atom = token;
            if (depth > 0) previous = null;
        }
        return depth != 0 ? "an unclosed group" : null;
    }

    // The loop's starts are distinct: \b before \w starts it only at a word's
    // first character; a literal outside the loop's set ends every earlier run.
    private static bool StartFixed(string? before, string loop, RegexOptions options)
    {
        if (before == @"\b") return loop == @"\w";
        if (before == null || before.EndsWith('~') || before == "(group)") return false;
        var single = before.Length == 1 ? before : before.Length == 2 && before[0] == '\\' && !char.IsLetterOrDigit(before[1]) ? before[1..] : null;
        return single != null && !IsMatch(single, "^(?:" + loop + ")$", options);
    }

    private static string Check(string pattern, RegexOptions options) =>
        Problem(pattern, options) is { } problem ? throw new ArgumentException($"{pattern}: {problem}", nameof(pattern)) : pattern;
}
