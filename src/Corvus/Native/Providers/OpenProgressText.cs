namespace Corvus.Native.Providers;

/// <summary>The one wording of an engine open's progress, shared by every tool and the lock conflict.</summary>
public static class OpenProgressText
{
    /// <summary>The stage, the seconds so far and the estimate; without earlier opens of the same image the estimate is named as none.</summary>
    public static string Describe(string stage, double seconds, double? expectedSeconds, string? basis)
    {
        var head = $"{stage}, {seconds:0} s";
        if (expectedSeconds is not { } expected) return $"{head}, no estimate (no earlier open of this image)";
        var of = $"{expected:0} s expected from {basis ?? "earlier opens"}";
        return seconds < expected ? $"{head}, about {Math.Round(expected - seconds):0} s left of {of}" : $"{head}, {Math.Round(seconds - expected):0} s past {of}";
    }
}
