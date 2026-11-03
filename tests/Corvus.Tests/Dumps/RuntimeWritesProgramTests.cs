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

    private static byte[] Jump(LiveTarget target, ulong destination)
    {
        if (!target.Is64) return [0x68, .. BitConverter.GetBytes((uint)destination), 0xC3];
        return [0x48, 0xB8, .. BitConverter.GetBytes(destination), 0xFF, 0xE0];
    }

    private static byte[] Read(MinidumpFile dump, ulong address, int length)
    {
        var bytes = new byte[length];
        Assert.Equal(length, dump.ReadMemory(address, bytes));
        return bytes;
    }

    private void CheckTableAndStubs(LiveTarget target)
    {
        var result = RuntimeWritesProgram.Dump(_dir, target);
        using var dump = MinidumpFile.Open(result.Dump);
        var size = target.Is64 ? 8 : 4;
        Assert.Equal(7, result.TableEntries.Length);

        var table = Read(dump, result.Table, size * (result.TableEntries.Length + 1));
        for (var i = 0; i < result.TableEntries.Length; i++)
        {
            var entry = target.Is64 ? BitConverter.ToUInt64(table, i * size) : BitConverter.ToUInt32(table, i * size);
            Assert.Equal(result.TableEntries[i], entry);
            Assert.NotNull(dump.ModuleAt(entry));
        }
        Assert.Equal(2, result.TableEntries.Select(e => dump.ModuleAt(e)!.Path).Distinct(StringComparer.OrdinalIgnoreCase).Count());
        Assert.All(table.Skip(result.TableEntries.Length * size), b => Assert.Equal(0, b));

        for (var i = 0; i < RuntimeWritesProgram.StubCount; i++)
        {
            var expected = Jump(target, result.TableEntries[i % result.TableEntries.Length]);
            Assert.Equal(expected, Read(dump, result.Stubs + (ulong)(i * result.StubStride), expected.Length));
        }

        Assert.Equal(Jump(target, result.FirstStub), Read(dump, result.Patched, result.PatchLength));
        Assert.Equal(Jump(target, result.SecondStub), Read(dump, result.FirstStub, result.PatchLength));
        Assert.Equal(Jump(target, result.Export), Read(dump, result.SecondStub, result.PatchLength));
        Assert.Equal(result.TableEntries[0], result.Export);
    }

    [Fact]
    public void The_test_program_fills_its_table_and_patches_through_two_stubs()
    {
        if (LiveTarget.WinX64.Missing is not null) return;
        CheckTableAndStubs(LiveTarget.WinX64);
    }

    [Fact]
    public void The_32_bit_test_program_fills_its_table_and_patches_through_two_stubs()
    {
        if (LiveTarget.WinX86.Missing is not null) return;
        CheckTableAndStubs(LiveTarget.WinX86);
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
