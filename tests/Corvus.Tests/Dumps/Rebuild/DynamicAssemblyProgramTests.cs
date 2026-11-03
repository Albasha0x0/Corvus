using Corvus.Native.Dump;
using Corvus.Native.Dump.Rebuild;

namespace Corvus.Tests;

/// <summary>The program that emits a dynamic assembly and dumps itself.</summary>
public sealed class DynamicAssemblyProgramTests
{
    /// <summary>A fact skipped, with the reason, where the dump cannot be written.</summary>
    [Xunit.Sdk.XunitTestCaseDiscoverer(RunTimeSkips.FactDiscoverer, RunTimeSkips.Assembly)]
    private sealed class DumpFactAttribute : FactAttribute, IRunTimeSkip
    {
        public string? RunTimeSkip() => DynamicAssemblyProgram.Unavailable;
    }

    [DumpFact]
    public void The_emitting_program_holds_one_dynamic_module_in_its_dump()
    {
        using var dir = new TempDir();
        using var dump = MinidumpFile.Open(DynamicAssemblyProgram.WriteDump(dir));
        var target = Assert.Single(ManagedImages.InMemoryAssemblies(dump, default), t => t.Base == 0);
        Assert.Equal(ModuleOrigin.Managed, target.Origin);
    }
}
