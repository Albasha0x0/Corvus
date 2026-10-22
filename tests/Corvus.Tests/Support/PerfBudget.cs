using Xunit.Abstractions;

namespace Corvus.Tests;

/// <summary>
/// Timing assertions of performance measurements. A measurement is always written to the test output; it fails the
/// test only in the perf run (<see cref="Variable"/> = 1), so gating runs check the mechanism and report the time.
/// Tests that call it carry <c>[Trait(PerfBudget.Trait, PerfBudget.Timing)]</c>, which the perf run selects.
/// </summary>
internal static class PerfBudget
{
    public const string Trait = "Perf";
    public const string Timing = "Timing";
    public const string Variable = "CORVUS_PERF";

    /// <summary>True in the perf run, where a measurement over its budget fails the test.</summary>
    public static bool Enforced => Environment.GetEnvironmentVariable(Variable) == "1";

    /// <summary>
    /// Reports <paramref name="message"/> with its outcome; throws when <paramref name="within"/> is false and the
    /// budget is <see cref="Enforced"/>.
    /// </summary>
    public static void Check(bool within, string message, ITestOutputHelper? output = null)
    {
        output?.WriteLine($"perf: {(within ? "within budget" : "over budget")}: {message}");
        if (Enforced) Assert.True(within, message);
    }
}
