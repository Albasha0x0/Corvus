namespace Corvus.Tests;

/// <summary>
/// The wait budgets of the live real tests. Each wait states its local budget and
/// <see cref="Scale"/> stretches it on slower machines.
/// </summary>
internal static class LiveWaits
{
    public const string Variable = "CORVUS_TEST_WAIT_SCALE";

    /// <summary>The factor of <see cref="Variable"/>; 1 when unset, unparsable or below 1.</summary>
    public static double Scale { get; } =
        double.TryParse(Environment.GetEnvironmentVariable(Variable), System.Globalization.NumberStyles.Float,
            System.Globalization.CultureInfo.InvariantCulture, out var v) && v >= 1 ? v : 1;

    /// <summary>The seconds of a tool wait, scaled and capped at the 300 s the tools accept.</summary>
    public static int Seconds(int local) => (int)Math.Min(300, Math.Ceiling(local * Scale));

    /// <summary>The count of fixed-interval polls that spans the scaled local budget.</summary>
    public static int Polls(int local) => (int)Math.Ceiling(local * Scale);
}
