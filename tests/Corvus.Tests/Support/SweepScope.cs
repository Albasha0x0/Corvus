namespace Corvus.Tests;

/// <summary>Routine full runs sweep an even quarter of each sweep's inputs; CORVUS_SWEEP=exhaustive sweeps all; a sweep's CORVUS_*_LIMIT wins.</summary>
internal static class SweepScope
{
    public const string Variable = "CORVUS_SWEEP";

    public static bool Exhaustive => string.Equals(Environment.GetEnvironmentVariable(Variable), "exhaustive", StringComparison.OrdinalIgnoreCase);

    /// <summary>The input count a sweep takes: <paramref name="exhaustive"/> (0 = all) when exhaustive, else a quarter of it.</summary>
    public static int Count(int exhaustive) => Exhaustive || exhaustive <= 0 ? exhaustive : Math.Max(1, exhaustive / 4);

    /// <summary>Every input when exhaustive, else an evenly spread quarter of them in a stable order.</summary>
    public static List<string> Pick(IEnumerable<string> inputs)
    {
        var all = inputs.ToList();
        return Exhaustive ? all : NativeToolSweepTests.Sample(all, Math.Max(1, all.Count / 4));
    }
}
