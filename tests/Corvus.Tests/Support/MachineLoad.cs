using System.Diagnostics;
using System.Security.Cryptography;

namespace Corvus.Tests;

/// <summary>How much slower the machine runs now than when budgets were set, from a fixed calibration workload; timing tests report it beside measurements.</summary>
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
