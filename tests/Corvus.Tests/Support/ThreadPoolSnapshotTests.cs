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
}
