using Corvus.Native.Dump;

namespace Corvus.Tests;

/// <summary>The program that loads an assembly from a byte array and dumps itself.</summary>
public sealed class InMemoryAssemblyProgramTests
{
    /// <summary>A fact skipped, with the reason, where the dump cannot be written.</summary>
    [Xunit.Sdk.XunitTestCaseDiscoverer(RunTimeSkips.FactDiscoverer, RunTimeSkips.Assembly)]
    private sealed class DumpFactAttribute : FactAttribute, IRunTimeSkip
    {
        public string? RunTimeSkip() => InMemoryAssemblyProgram.Unavailable;
    }

    [DumpFact]
    public void The_program_writes_a_dump_that_opens_as_a_minidump()
    {
        using var dir = new TempDir();
        var dump = InMemoryAssemblyProgram.WriteDump(dir);
        using var file = MinidumpFile.Open(dump);
        Assert.True(new FileInfo(dump).Length > 0);
    }
}
