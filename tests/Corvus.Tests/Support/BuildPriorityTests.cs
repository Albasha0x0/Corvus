using System.Diagnostics;
using Xunit.Abstractions;

namespace Corvus.Tests;

/// <summary>The dotnet builds tests start keep their worker nodes at the test run's lowered priority.</summary>
public sealed class BuildPriorityTests(ITestOutputHelper output)
{
    [Fact]
    public void A_build_started_below_normal_priority_asks_MSBuild_for_low_priority_nodes()
    {
        // The child changes its own priority, never the test host's.
        if (ChildTest.Rerun(this, output)) return;
        using var self = Process.GetCurrentProcess();
        // Raising a process's priority needs privileges off Windows, so only Windows checks both directions.
        if (OperatingSystem.IsWindows())
        {
            self.PriorityClass = ProcessPriorityClass.Normal;
            Assert.Empty(Tools.BuildPriority());
        }
        if (self.PriorityClass != ProcessPriorityClass.Idle) self.PriorityClass = ProcessPriorityClass.BelowNormal;
        Assert.Equal(["-lowPriority:true"], Tools.BuildPriority());
    }
}
