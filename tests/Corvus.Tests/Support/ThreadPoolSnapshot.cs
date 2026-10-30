using System.Diagnostics;
using System.Globalization;
using Microsoft.Diagnostics.Runtime;

namespace Corvus.Tests;

/// <summary>This process's pool counts and the stacks of threads running work, named in timing failures; "unknown" where unreadable or off Windows.</summary>
internal static class ThreadPoolSnapshot
{
    /// <summary>The entry point's flag for a child that reads a process's stacks (<see cref="Main"/>).</summary>
    public const string Flag = "--thread-stacks";

    // An unfinished stack read is killed: a looping DAC holds the lock MiniDumpWriteDump takes.
    private static readonly TimeSpan ReadLimit = TimeSpan.FromSeconds(20);

    /// <summary>The counts and the busy threads' top frames, one line each; never throws.</summary>
    public static string Describe() => Counts() + Read("busy", 0, "busy threads");

    /// <summary>
    /// The pool counts and the stack of every thread with a Corvus frame, waiting or running: up to
    /// <paramref name="frames"/> frames each, the innermost first, so a blocked call shows what it waits on. Never throws.
    /// </summary>
    public static string ProductStacks(int frames = 16) => Counts() + Read("product", frames, "stacks");

    /// <summary>The stacks of <paramref name="pid"/>'s threads with a Corvus frame, as <see cref="ProductStacks"/> reads them; never throws.</summary>
    public static string StacksOf(int pid, int frames = 16) => $"process {pid}" + Read("product", frames, "stacks", pid);

    private static string Counts() => $"thread pool: {ThreadPool.ThreadCount} threads, {ThreadPool.PendingWorkItemCount} pending";

    /// <summary>The <paramref name="mode"/> read of <paramref name="pid"/>'s stacks (this process's when null), done in a child process within <see cref="ReadLimit"/>.</summary>
    private static string Read(string mode, int frames, string what, int? pid = null)
    {
        // Off Windows the snapshot is a dump written through the diagnostics port, which a changed TMPDIR cannot reach.
        if (!OperatingSystem.IsWindows()) return $", {what} unknown (read on Windows only)";
        // A snapshot attach can fail once on a loaded machine; a second failure is named.
        var first = ReadOnce(mode, frames, what, pid);
        return first.Exited is null or 0 ? first.Text : ReadOnce(mode, frames, what, pid).Text;
    }

    private static (string Text, int? Exited) ReadOnce(string mode, int frames, string what, int? pid)
    {
        try
        {
            var info = new ProcessStartInfo(Environment.GetEnvironmentVariable("DOTNET_HOST_PATH") ?? "dotnet")
            {
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
            };
            foreach (var a in new[] { "exec", typeof(ThreadPoolSnapshot).Assembly.Location, Flag, mode,
                         (pid ?? Environment.ProcessId).ToString(CultureInfo.InvariantCulture), frames.ToString(CultureInfo.InvariantCulture) })
                info.ArgumentList.Add(a);
            using var child = Process.Start(info)!;
            var output = child.StandardOutput.ReadToEndAsync();
            _ = child.StandardError.ReadToEndAsync();
            if (!child.WaitForExit(ReadLimit))
            {
                child.Kill(entireProcessTree: true);
                child.WaitForExit();
                return ($", {what} unknown (the read ran past {ReadLimit.TotalSeconds:0} s)", null);
            }
            return child.ExitCode == 0 ? (output.Result.TrimEnd(), 0)
                : ($", {what} unknown (the read exited with {child.ExitCode}: {output.Result.Trim()})", child.ExitCode);
        }
        // A failed read never fails the test the snapshot describes.
        catch (Exception e)
        {
            return ($", {what} unknown ({e.GetType().Name})", null);
        }
    }

    /// <summary>
    /// In the child: writes the <paramref name="args"/> read (mode, process id, frames) of that process to standard
    /// output as the text after the counts; exit code 0, or 1 and the exception's type name when the process could not be read.
    /// </summary>
    public static int Main(string[] args)
    {
        try
        {
            var mode = args[0];
            var pid = int.Parse(args[1], CultureInfo.InvariantCulture);
            var frames = int.Parse(args[2], CultureInfo.InvariantCulture);
            using var target = DataTarget.CreateSnapshotAndAttach(pid);
            using var runtime = target.ClrVersions[0].CreateRuntime();
            Console.Out.Write(mode == "busy" ? Busy(runtime) : Product(runtime, frames));
            return 0;
        }
        catch (Exception e)
        {
            Console.Out.Write(e.GetType().Name);
            return 1;
        }
    }

    private static string Busy(ClrRuntime runtime)
    {
        var busy = new List<string>();
        foreach (var thread in runtime.Threads.Where(t => t.IsAlive))
        {
            var frames = thread.EnumerateStackTrace().Take(40).Select(f => f.Method?.Signature).OfType<string>().ToList();
            // A pool worker that runs nothing waits in WorkerThreadStart; other threads are not the pool's.
            if (!frames.Any(f => f.Contains("PortableThreadPool+WorkerThread.WorkerThreadStart", StringComparison.Ordinal))
                || frames.Any(f => f.Contains("LowLevelLifoSemaphore.WaitForSignal", StringComparison.Ordinal))) continue;
            // The runner's own workers and the thread waiting for this read are not test work.
            var own = frames.Select(f => f.Split('(')[0]).Where(f => !f.StartsWith("System.", StringComparison.Ordinal)).ToList();
            if (own.Count == 0 || own.Any(f => f.StartsWith("Xunit.", StringComparison.Ordinal) || f.StartsWith("Microsoft.VisualStudio.TestPlatform.", StringComparison.Ordinal)
                || f.StartsWith(typeof(ThreadPoolSnapshot).FullName!, StringComparison.Ordinal))) continue;
            busy.Add(string.Join(" < ", own.Take(4)));
        }
        return busy.Count == 0 ? ", none busy"
            : $", {busy.Count} busy:\n" + string.Join("\n", busy.GroupBy(b => b).Select(g => $"  {g.Count()} x {g.Key}"));
    }

    private static string Product(ClrRuntime runtime, int frames)
    {
        var stacks = new List<string>();
        foreach (var thread in runtime.Threads.Where(t => t.IsAlive))
        {
            var all = thread.EnumerateStackTrace().Take(200).Select(f => f.Method?.Signature).OfType<string>().ToList();
            if (!all.Any(f => f.StartsWith("Corvus.", StringComparison.Ordinal) && !f.StartsWith("Corvus.Tests.", StringComparison.Ordinal))) continue;
            stacks.Add($"thread {thread.ManagedThreadId}:\n    " + string.Join("\n    ", all.Take(frames)));
        }
        // An async wait holds no thread: a call with no stack here is waiting on a task.
        return stacks.Count == 0 ? ", no thread runs product code" : $", {stacks.Count} threads in product code:\n" + string.Join("\n", stacks);
    }
}
