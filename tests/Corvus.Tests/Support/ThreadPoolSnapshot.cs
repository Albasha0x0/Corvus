using Microsoft.Diagnostics.Runtime;

namespace Corvus.Tests;

/// <summary>
/// This process's thread pool at one moment: its thread and pending work counts, and the stack of every thread pool
/// thread that is running work rather than waiting for it. Timing tests name it in a failure, so work an earlier test
/// left running is seen with its caller; the stacks read "unknown" where the process cannot be read.
/// </summary>
internal static class ThreadPoolSnapshot
{
    /// <summary>The counts and the busy threads' top frames, one line each; never throws.</summary>
    public static string Describe()
    {
        var text = $"thread pool: {ThreadPool.ThreadCount} threads, {ThreadPool.PendingWorkItemCount} pending";
        try
        {
            using var target = DataTarget.CreateSnapshotAndAttach(Environment.ProcessId);
            using var runtime = target.ClrVersions[0].CreateRuntime();
            var busy = new List<string>();
            foreach (var thread in runtime.Threads.Where(t => t.IsAlive))
            {
                var frames = thread.EnumerateStackTrace().Take(40).Select(f => f.Method?.Signature).OfType<string>().ToList();
                // A pool worker that runs nothing waits in WorkerThreadStart; other threads are not the pool's.
                if (!frames.Any(f => f.Contains("PortableThreadPool+WorkerThread.WorkerThreadStart", StringComparison.Ordinal))
                    || frames.Any(f => f.Contains("LowLevelLifoSemaphore.WaitForSignal", StringComparison.Ordinal))) continue;
                // The runner's own workers and this snapshot's thread are not test work.
                var own = frames.Select(f => f.Split('(')[0]).Where(f => !f.StartsWith("System.", StringComparison.Ordinal)).ToList();
                if (own.Count == 0 || own.Any(f => f.StartsWith("Xunit.", StringComparison.Ordinal) || f.StartsWith("Microsoft.VisualStudio.TestPlatform.", StringComparison.Ordinal)
                    || f.StartsWith(typeof(ThreadPoolSnapshot).FullName!, StringComparison.Ordinal))) continue;
                busy.Add(string.Join(" < ", own.Take(4)));
            }
            return busy.Count == 0 ? text + ", none busy"
                : text + $", {busy.Count} busy:\n" + string.Join("\n", busy.GroupBy(b => b).Select(g => $"  {g.Count()} x {g.Key}"));
        }
        catch (Exception e) when (e is ClrDiagnosticsException or InvalidOperationException or IOException or UnauthorizedAccessException or IndexOutOfRangeException or NotSupportedException)
        {
            return text + ", busy threads unknown (" + e.GetType().Name + ")";
        }
    }
}
