using Corvus.Native.Providers;

namespace Corvus.Tests;

/// <summary>The target state a failed live test reports.</summary>
public sealed class LiveTargetDiagnosticsTests
{
    [Fact]
    public void A_running_program_s_threads_cpu_time_and_worker_quiet_time_are_listed()
    {
        // The fake tool's spin mode waits on stdin once it has used 0 ms.
        using var child = ChildProcess.Start(new ChildProcessStart(FakeTool.Executable, ["spin", "0"]));
        try
        {
            Assert.Equal("done", new StreamReader(child.StandardOutput).ReadLine());
            var text = LiveTargetDiagnostics.Describe(child.Id, TimeSpan.FromSeconds(3));
            Assert.StartsWith($"process {child.Id}: cpu ", text);
            Assert.Contains("worker's last line 3.0 s ago", text);
            Assert.Matches(@"\n  thread \d+ \w+", text);
            if (OperatingSystem.IsWindows())
            {
                Assert.Contains(", suspend 0: ", text);
                Assert.Contains("ntdll.dll+0x", text, StringComparison.OrdinalIgnoreCase);
            }
        }
        finally { child.Kill(); }
    }

    [Fact]
    public async Task An_ended_program_is_named_as_ended()
    {
        using var child = ChildProcess.Start(new ChildProcessStart(FakeTool.Executable, ["-version"]));
        await child.Exited.WaitAsync(TimeSpan.FromSeconds(30));
        var id = child.Id;
        child.Dispose();
        Assert.StartsWith($"process {id}: ended", LiveTargetDiagnostics.Describe(id, null));
    }
}
