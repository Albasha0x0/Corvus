using System.Diagnostics;
using Xunit.Abstractions;

namespace Corvus.Tests;

public class ThreadPoolSnapshotTests(ITestOutputHelper output)
{
    // Regression: a self-snapshot whose DAC call looped held the DAC's lock, and MiniDumpWriteDump in the same test
    // process waited on it until the run was killed.
    [Fact]
    public void A_stack_read_never_loads_the_DAC_into_the_process_it_reads()
    {
        if (!OperatingSystem.IsWindows() || ChildTest.Rerun(this, output)) return;
        var stacks = ThreadPoolSnapshot.ProductStacks();
        Assert.StartsWith("thread pool: ", stacks);
        Assert.DoesNotContain("unknown", stacks);
        Assert.DoesNotContain(Process.GetCurrentProcess().Modules.Cast<ProcessModule>(),
            m => m.ModuleName.Equals("mscordaccore.dll", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task A_server_this_process_started_is_found_and_its_stacks_are_read()
    {
        if (!OperatingSystem.IsWindows()) return;
        var started = DateTime.Now;
        await using var client = await McpProtocolTests.StartServerAsync();
        // Another test's server started in the same moment is found too; either is a server this process started.
        var pid = ServerDump.Servers(started).FirstOrDefault(-1);
        Assert.True(pid > 0);
        var stacks = ThreadPoolSnapshot.StacksOf(pid);
        Assert.StartsWith($"process {pid}, ", stacks);
        Assert.DoesNotContain("unknown", stacks);
    }
}
