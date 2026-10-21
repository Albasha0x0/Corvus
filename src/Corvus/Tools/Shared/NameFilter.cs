using System.Text.RegularExpressions;
using Corvus.Core;

namespace Corvus.Tools;

/// <summary>
/// A name filter as list tools take it: /regex/flags (i, m, s; case-insensitive when no flag is given), a glob when it
/// has * or ? (whole name, case-insensitive), else a case-insensitive substring.
/// </summary>
internal sealed class NameFilter
{
    public const string Description = "substring (case-insensitive), * ? glob, or /regex/ (flags i, m, s)";

    private readonly string? _substring;
    private readonly RegexTimeouts _timeouts = new();

    /// <summary>The regex a glob or /regex/ compiles to; null for a substring.</summary>
    public Regex? Pattern { get; }

    /// <summary>The filter as given.</summary>
    public string Text { get; }

    private NameFilter(string text, Regex? pattern, string? substring) => (Text, Pattern, _substring) = (text, pattern, substring);

    /// <summary>The filter, or null for none; a malformed regex is an invalid_argument error.</summary>
    public static NameFilter? Parse(string? text)
    {
        if (string.IsNullOrWhiteSpace(text)) return null;
        var t = text.Trim();
        int last = t.LastIndexOf('/');
        if (t.Length > 2 && t[0] == '/' && last > 0)
        {
            var options = RegexOptions.CultureInvariant;
            var flags = t[(last + 1)..];
            foreach (var f in flags)
                options |= f switch
                {
                    'i' => RegexOptions.IgnoreCase,
                    'm' => RegexOptions.Multiline,
                    's' => RegexOptions.Singleline,
                    _ => throw new ToolError(ErrorCode.InvalidArgument, $"Unknown regex flag '{f}' in {t}.", "use i, m or s after the closing /"),
                };
            if (flags.Length == 0) options |= RegexOptions.IgnoreCase;
            try { return new NameFilter(t, new Regex(t[1..last], options, RegexTimeouts.Limit), null); }
            catch (ArgumentException ex) { throw new ToolError(ErrorCode.InvalidArgument, $"Invalid regex {t}: {ex.Message}", "fix the pattern between the slashes"); }
        }
        if (t.Contains('*') || t.Contains('?'))
            return new NameFilter(t, new Regex("^" + Regex.Escape(t).Replace(@"\*", ".*").Replace(@"\?", ".") + "$",
                RegexOptions.IgnoreCase | RegexOptions.CultureInvariant | RegexOptions.Singleline, RegexTimeouts.Limit), null);
        return new NameFilter(t, null, t);
    }

    public bool IsMatch(string name) =>
        _substring != null ? name.Contains(_substring, StringComparison.OrdinalIgnoreCase) : _timeouts.IsMatch(Pattern!, name);

    /// <summary>Names the regex timed out on (left out), as a note; empty when none.</summary>
    public string Note(string what) => _timeouts.Note(what);
}
