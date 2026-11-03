using Corvus.Native.Dump;
using Corvus.Native.Pe;

namespace Corvus.Tests;

/// <summary>The test program writes code into a section that has no raw data.</summary>
[Trait("Speed", "Slow")]
[Permit("live")]
[Collection(ExternalToolEnvironmentCollection.Name)]
public sealed class RuntimeWritesProgramTests : IDisposable
{
    private readonly TempDir _dir = new();

    public void Dispose() => _dir.Dispose();

    private void Check(LiveTarget target)
    {
        var result = RuntimeWritesProgram.Dump(_dir, target);
        var section = PeFile.Open(result.Program).Sections.Single(s => s.Name == RuntimeWritesProgram.SectionName);
        Assert.True(section.RawSize < section.VirtualSize, $"raw {section.RawSize}, virtual {section.VirtualSize}");

        using var dump = MinidumpFile.Open(result.Dump);
        var bytes = new byte[RuntimeWritesProgram.Function.Length];
        Assert.Equal(bytes.Length, dump.ReadMemory(result.Address, bytes));
        Assert.Equal(RuntimeWritesProgram.Function, bytes);
    }

    [Fact]
    public void The_test_program_writes_code_into_a_section_without_raw_data()
    {
        if (LiveTarget.WinX64.Missing is not null) return;
        Check(LiveTarget.WinX64);
    }

    [Fact]
    public void The_32_bit_test_program_writes_code_into_a_section_without_raw_data()
    {
        if (LiveTarget.WinX86.Missing is not null) return;
        Check(LiveTarget.WinX86);
    }
}
