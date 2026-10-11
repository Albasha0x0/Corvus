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
        $"Incomplete: the regex timed out on {Count:N0} {noun}{(Count == 1 ? "" : "s")} ({(Limit.TotalSeconds >= 1 ? $"{Limit.TotalSeconds:0} s" : $"{Limit.TotalMilliseconds:0} ms")} limit each), left out of the results; a simpler pattern evaluates them.\n";
}
