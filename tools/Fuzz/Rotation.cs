namespace Corvus.Fuzz;

/// <summary>
/// The fuzz queues: the nightly rotation and the weekly sweep, each target once.
/// </summary>
public static class FuzzRotation
{
    /// <summary>The nights of the rotation; every target runs on one of them.</summary>
    public const int Nights = 7;

    /// <summary>The queue modes `queue` takes.</summary>
    public static readonly string[] Modes = ["nightly", "sweep"];

    /// <summary>
    /// The targets of <paramref name="mode"/> on <paramref name="date"/>, in target
    /// order: `sweep` is every target, `nightly` the targets of that date's night.
    /// Null for another mode.
    /// </summary>
    public static IReadOnlyList<FuzzTarget>? Queue(string mode, DateOnly date)
    {
        var all = FuzzTargets.All;
        return mode switch
        {
            "sweep" => all,
            "nightly" => all.Where((_, i) => i % Nights == date.DayNumber % Nights).ToList(),
            _ => null,
        };
    }
}
