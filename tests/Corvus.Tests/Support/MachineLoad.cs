using System.Diagnostics;
using System.Security.Cryptography;

namespace Corvus.Tests;

/// <summary>
/// How much slower this machine runs now than the quiet machine the timing budgets were set on: a fixed calibration
/// workload (hashing, random memory reads, small allocations) timed against its quiet time. Timing tests scale their
/// budgets by it, so a loaded machine (a suite or another build beside) stretches them and a quiet one keeps them as written.
/// </summary>
internal static class MachineLoad
{
    /// <summary>The calibration workload's best time on the quiet reference machine.</summary>
    internal static readonly TimeSpan QuietCalibration = TimeSpan.FromMilliseconds(50);

    // Below this the machine counts as quiet: run-to-run noise never loosens a budget.
    private const double QuietThreshold = 1.25;

    private static readonly byte[] Data = RandomNumberGenerator.GetBytes(4 << 20);
    private static readonly int[] Table = Enumerable.Range(0, 8 << 20).Select(i => (int)((i * 2654435761u) >> 9)).ToArray();

    /// <summary>The best of three runs of the calibration workload.</summary>
    public static TimeSpan Calibrate()
    {
        var best = TimeSpan.MaxValue;
        for (int i = 0; i < 3; i++)
        {
            var watch = Stopwatch.StartNew();
            GC.KeepAlive(Work());
            best = TimeSpan.FromTicks(Math.Min(best.Ticks, watch.Elapsed.Ticks));
        }
        return best;
    }

    /// <summary>The slowdown factor now: calibration time over the quiet time, 1 when under <see cref="QuietThreshold"/>.</summary>
    public static double Factor()
    {
        var ratio = Calibrate() / QuietCalibration;
        return ratio < QuietThreshold ? 1 : ratio;
    }

    /// <summary>
    /// The budget for work timed on a machine whose load was measured before and after it: <paramref name="quiet"/>
    /// times the larger of the two factors. The text names both, for the failure message.
    /// </summary>
    public static (TimeSpan Budget, string Note) Budget(TimeSpan quiet, double before, double after)
    {
        var factor = Math.Max(before, after);
        return (quiet * factor, factor == 1 ? "quiet machine" : $"machine load x{before:0.00} before, x{after:0.00} after");
    }

    /// <summary>
    /// Whether <paramref name="elapsed"/> is within <paramref name="quiet"/> scaled by the load: the load is measured
    /// only when the quiet budget is exceeded, and <paramref name="before"/> is the factor taken before the work. Note
    /// names the budget and the load, for the failure message.
    /// </summary>
    public static (bool Within, string Note) Check(TimeSpan elapsed, TimeSpan quiet, double before)
    {
        if (elapsed < quiet) return (true, $"{elapsed.TotalMilliseconds:0} ms, budget {quiet.TotalMilliseconds:0} ms");
        var (budget, load) = Budget(quiet, before, Factor());
        return (elapsed < budget, $"{elapsed.TotalMilliseconds:0} ms, budget {budget.TotalMilliseconds:0} ms ({load})");
    }

    private static object Work()
    {
        int sum = 0;
        for (int i = 0; i < 4; i++) sum += SHA256.HashData(Data)[0];
        for (int i = 0, at = 1; i < 2_000_000; i++)
        {
            at = Table[at & (Table.Length - 1)];
            sum += at;
        }
        var keep = new List<string>();
        for (int i = 0; i < 200_000; i++)
        {
            var s = new string('x', i & 15);
            if ((i & 1023) == 0) keep.Add(s);
        }
        return sum + keep.Count;
    }
}
