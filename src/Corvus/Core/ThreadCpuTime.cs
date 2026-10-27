using System.Diagnostics;
using System.Runtime.InteropServices;

namespace Corvus.Core;

/// <summary>The calling thread's CPU time, else wall time; only differences on the same thread mean anything.</summary>
/// <remarks>Work limits use it so a busy machine's wait time is not counted.</remarks>
public static class ThreadCpuTime
{
    /// <summary>The calling thread's CPU time so far, or a wall-clock reading where it cannot be read.</summary>
    public static TimeSpan Now()
    {
        try
        {
            if (OperatingSystem.IsWindows())
                return GetThreadTimes(GetCurrentThread(), out _, out _, out long kernel, out long user) ? TimeSpan.FromTicks(kernel + user) : Wall();
            // CLOCK_THREAD_CPUTIME_ID.
            int clock = OperatingSystem.IsLinux() ? 3 : OperatingSystem.IsMacOS() ? 16 : -1;
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
