using System.Diagnostics;

namespace Corvus.Tests;

/// <summary>CPU time of the calling thread (<see cref="Core.ThreadCpuTime"/>), which machine load does not inflate.</summary>
internal static class ThreadCpuClock
{
    public static TimeSpan Now() => Core.ThreadCpuTime.Now();
}

public class ThreadCpuClockTests
{
    [Fact]
    public void Waiting_costs_no_CPU_time_and_spinning_does()
    {
        var start = ThreadCpuClock.Now();
        Thread.Sleep(300);
        var slept = ThreadCpuClock.Now() - start;
        Assert.True(slept < TimeSpan.FromMilliseconds(150), $"{slept}");
        start = ThreadCpuClock.Now();
        var wall = Stopwatch.StartNew();
        // The thread clock advances in scheduler ticks; a loaded machine can give a short spin none.
        while (ThreadCpuClock.Now() == start && wall.ElapsedMilliseconds < 5000) Thread.SpinWait(1000);
        Assert.True(ThreadCpuClock.Now() - start > TimeSpan.Zero, $"no CPU time after {wall.ElapsedMilliseconds} ms of spinning");
    }
}
