using System.Diagnostics;
using System.Runtime.InteropServices;

namespace Corvus.Tests;

/// <summary>
/// CPU time of the calling thread: a per-call work bound that a loaded machine does not inflate, as it does a wall
/// clock when the thread waits for a processor. Wall time where the platform has no thread clock.
/// </summary>
internal static class ThreadCpuClock
{
    public static TimeSpan Now()
    {
        try
        {
            if (OperatingSystem.IsWindows())
                return GetThreadTimes(GetCurrentThread(), out _, out _, out long kernel, out long user) ? TimeSpan.FromTicks(kernel + user) : Wall();
            int clock = OperatingSystem.IsLinux() ? 3 : OperatingSystem.IsMacOS() ? 16 : -1; // CLOCK_THREAD_CPUTIME_ID
            if (clock >= 0 && clock_gettime(clock, out var t) == 0) return TimeSpan.FromTicks(t.Seconds * TimeSpan.TicksPerSecond + t.Nanoseconds / 100);
        }
        catch (Exception ex) when (ex is DllNotFoundException or EntryPointNotFoundException) { }
        return Wall();
    }

    private static TimeSpan Wall() => Stopwatch.GetElapsedTime(0);

    [StructLayout(LayoutKind.Sequential)]
    private struct TimeSpec
    {
        public long Seconds;
        public long Nanoseconds;
    }

    [DllImport("kernel32.dll")]
    private static extern IntPtr GetCurrentThread();

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetThreadTimes(IntPtr thread, out long creation, out long exit, out long kernel, out long user);

    [DllImport("libc", SetLastError = true)]
    private static extern int clock_gettime(int clock, out TimeSpec time);
}

public class ThreadCpuClockTests
{
    [Fact]
    public void WaitingCostsNoCpuTimeAndSpinningDoes()
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
