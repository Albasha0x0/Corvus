using System.Globalization;
using Xunit.Abstractions;

namespace Corvus.Tests;

/// <summary>
/// Performance measurements. Each writes one line to the test output, <c>perf: name value unit (budget op limit unit)</c>,
/// which the perf run reads to compare medians with <c>Ratchets/perf-baseline.txt</c>; it fails the test only in the perf
/// run (<see cref="Variable"/> = 1), so gating runs check the mechanism and report the time. Tests that measure carry
/// <c>[Trait(PerfBudget.Trait, PerfBudget.Timing)]</c>, which the perf run selects.
/// </summary>
internal static class PerfBudget
{
    public const string Trait = "Perf";
    public const string Timing = "Timing";
    public const string Variable = "CORVUS_PERF";

    /// <summary>True in the perf run, where a measurement over its budget fails the test.</summary>
    public static bool Enforced => Environment.GetEnvironmentVariable(Variable) == "1";

    /// <summary>Reports an elapsed time against its budget, in milliseconds.</summary>
    public static void Time(string name, TimeSpan measured, TimeSpan budget, ITestOutputHelper output, string? note = null) =>
        AtMost(name, measured.TotalMilliseconds, budget.TotalMilliseconds, "ms", output, note);

    /// <summary>Reports <paramref name="value"/>, which the budget allows up to <paramref name="limit"/>.</summary>
    public static void AtMost(string name, double value, double limit, string unit, ITestOutputHelper output, string? note = null) =>
        Report(name, value, limit, unit, "<=", value <= limit, output, note);

    /// <summary>Reports a rate <paramref name="value"/>, which the budget requires to be at least <paramref name="limit"/>.</summary>
    public static void AtLeast(string name, double value, double limit, string unit, ITestOutputHelper output, string? note = null) =>
        Report(name, value, limit, unit, ">=", value >= limit, output, note);

    private static void Report(string name, double value, double limit, string unit, string op, bool within, ITestOutputHelper output, string? note)
    {
        if (name.Length == 0 || name.Any(char.IsWhiteSpace) || name.Any(char.IsUpper))
            throw new ArgumentException($"perf name '{name}': lower case, no spaces", nameof(name));
        var line = string.Create(CultureInfo.InvariantCulture,
            $"perf: {name} {value:0.###} {unit} (budget {op} {limit:0.###} {unit}){(within ? "" : " over budget")}{(note is { Length: > 0 } ? "; " + note : "")}");
        output.WriteLine(line);
        if (Enforced) Assert.True(within, line);
    }
}
