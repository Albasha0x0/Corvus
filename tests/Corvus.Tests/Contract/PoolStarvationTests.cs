using Corvus.Native.Providers;

namespace Corvus.Tests;

/// <summary>Work that must not wait for the thread pool, checked with every pool thread blocked; runs alone, as it starves the process.</summary>
[CollectionDefinition(nameof(PoolStarvationTests), DisableParallelization = true)]
public class PoolStarvationCollection;

[Collection(nameof(PoolStarvationTests))]
public class PoolStarvationTests
{
    /// <summary>
    /// Blocks the pool: more queued blockers than it injects threads during a test. The event is never disposed: blockers
    /// still queued at the release start later and wait on it.
    /// </summary>
    internal static ManualResetEventSlim Starve()
    {
        var release = new ManualResetEventSlim();
        for (int i = 0; i < ThreadPool.ThreadCount + 1000; i++) ThreadPool.UnsafeQueueUserWorkItem(_ => release.Wait(), null);
        return release;
    }

    [WindowsFact]
    public void Captured_process_reports_its_exit_and_output_on_a_starved_pool()
    {
        var cmd = Path.Combine(Environment.SystemDirectory, "cmd.exe");
        PythonLocator.CaptureResult run;
        var release = Starve();
        try { run = PythonLocator.RunCapture(cmd, ["/d", "/c", "echo out& echo err 1>&2& exit 3"], TimeSpan.FromSeconds(10)); }
        finally { release.Set(); }
        Assert.False(run.TimedOut);
        Assert.Equal(3, run.ExitCode);
        Assert.Equal("out", run.Stdout.Trim());
        Assert.Equal("err", run.Stderr.Trim());
    }

    [WindowsFact]
    public void External_tool_reports_its_exit_and_output_on_a_starved_pool()
    {
        var cmd = Path.Combine(Environment.SystemDirectory, "cmd.exe");
        ExternalTools.RunResult run;
        var release = Starve();
        try { run = ExternalTools.Run(cmd, ["/d", "/c", "echo out& exit 3"], TimeSpan.FromSeconds(10), 1000, default); }
        finally { release.Set(); }
        Assert.False(run.TimedOut);
        Assert.Equal(3, run.ExitCode);
        Assert.Equal("out", run.Text.Trim());
    }

    /// <summary>
    /// Visitors of a search that block (waiting on a reference pack download) run on at most one thread per core, so the
    /// threads the pool injects stay free for the work they wait on.
    /// </summary>
    [Fact]
    public void Blocked_search_visitors_take_one_thread_per_core()
    {
        using var workspace = new Corvus.Core.AssemblyWorkspace(new Corvus.Core.ServerOptions());
        var asm = workspace.Load(typeof(Corvus.Core.AssemblyWorkspace).Assembly.Location);
        int running = 0, peak = 0;
        Assert.Throws<Corvus.Core.ToolError>(() => Corvus.Core.MetadataUtil.ParallelCollect<int>([asm], (_, _, _) =>
        {
            int now = Interlocked.Increment(ref running);
            for (int seen = Volatile.Read(ref peak); now > seen; seen = Volatile.Read(ref peak)) Interlocked.CompareExchange(ref peak, now, seen);
            Thread.Sleep(100);
            Interlocked.Decrement(ref running);
        }, default, TimeSpan.FromSeconds(4), null));
        Assert.InRange(peak, 1, Environment.ProcessorCount);
    }
}
