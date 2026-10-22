using System.Text.RegularExpressions;

namespace Corvus.Core;

/// <summary>Counts the inputs a user regex timed out on: they are left out of a search, which is then incomplete.</summary>
public sealed class RegexTimeouts
{
    private static readonly AsyncLocal<TimeSpan?> Override = new();

    /// <summary>Time limit per input.</summary>
    public static TimeSpan Limit => Override.Value ?? TimeSpan.FromSeconds(1);

    /// <summary>Tests: a shorter limit for the calling flow only, so timeouts do not cost a second each.</summary>
    internal static IDisposable UseLimit(TimeSpan limit)
    {
        Override.Value = limit;
        return new Reset();
    }

    private sealed class Reset : IDisposable
    {
        public void Dispose() => Override.Value = null;
    }

    /// <summary>
    /// A regex for a pattern a caller or an analyzed script supplies: NonBacktracking, which matches in linear time with no
    /// timeout, when the pattern and options allow it; else backtracking under <paramref name="limit"/> (default
    /// <see cref="Limit"/>). Throws ArgumentException for a malformed pattern.
    /// </summary>
    public static Regex Create(string pattern, RegexOptions options = RegexOptions.None, TimeSpan? limit = null)
    {
        // NonBacktracking refuses lookarounds, backreferences, atomic groups,
        // conditionals and automata over its size limit; those patterns keep a
        // time limit. It takes no RightToLeft or ECMAScript option.
        if ((options & (RegexOptions.RightToLeft | RegexOptions.ECMAScript)) == 0)
            try { return new Regex(pattern, options | RegexOptions.NonBacktracking); }
            catch (NotSupportedException) { }
        return new Regex(pattern, options, limit ?? Limit);
    }

    /// <summary>
    /// The error for a pattern that ran out of time on <paramref name="input"/>: a timeout, not retryable, naming the
    /// pattern and its limit.
    /// </summary>
    public static ToolError TimedOut(Regex regex, string input = "an input") =>
        new(ErrorCode.Timeout, $"The regex '{regex}' ran out of time on {input} ({LimitText(regex.MatchTimeout)} limit).",
            "drop lookarounds and backreferences: without them a pattern matches in linear time") { Retryable = false };

    /// <summary>Whether <paramref name="regex"/> matches <paramref name="input"/>; a timeout throws <see cref="TimedOut"/>.</summary>
    public static bool IsMatchOrThrow(Regex regex, string input)
    {
        try { return regex.IsMatch(input); }
        catch (RegexMatchTimeoutException) { throw TimedOut(regex); }
    }

    private static string LimitText(TimeSpan limit) => limit.TotalSeconds >= 1 ? $"{limit.TotalSeconds:0} s" : $"{limit.TotalMilliseconds:0} ms";

    private int _count;

    public int Count => Volatile.Read(ref _count);

    /// <summary>Whether <paramref name="regex"/> matches <paramref name="input"/>; a timeout is counted and does not match.</summary>
    public bool IsMatch(Regex regex, string input)
    {
        try { return regex.IsMatch(input); }
        catch (RegexMatchTimeoutException)
        {
            Interlocked.Increment(ref _count);
            return false;
        }
    }

    /// <summary>A line saying the result is incomplete, or "" when nothing timed out.</summary>
    public string Note(string noun) => Count == 0 ? "" :
        $"Incomplete: the regex timed out on {Count:N0} {noun}{(Count == 1 ? "" : "s")} ({LimitText(Limit)} limit each), left out of the results; a simpler pattern evaluates them.\n";
}
