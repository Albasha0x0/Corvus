using System.Buffers.Binary;
using Corvus.Native.Dump;

namespace Corvus.Tests;

/// <summary>The stub fixtures write each form at its address in the dump and lead where they say.</summary>
public sealed class StubFixturesTests : IDisposable
{
    private readonly TempDir _dir = new();

    public void Dispose() => _dir.Dispose();

    public static TheoryData<ushort, StubForm, int> Forms()
    {
        var data = new TheoryData<ushort, StubForm, int>();
        foreach (int hops in new[] { 1, 2 })
        {
            data.Add(0x8664, StubForm.X64MovJmp, hops);
            data.Add(0x8664, StubForm.X64JmpRip, hops);
            data.Add(0x8664, StubForm.X64PushRet, hops);
            data.Add(0x14C, StubForm.X86Jmp32, hops);
            data.Add(0x14C, StubForm.X86PushRet, hops);
            data.Add(0x14C, StubForm.X86JmpAbs, hops);
            data.Add(0xAA64, StubForm.Arm64LdrBr, hops);
            data.Add(0xAA64, StubForm.Arm64B, hops);
        }
        return data;
    }

    // Where the code at an address transfers control, read back from the dump.
    private static ulong Target(IProcessMemory memory, StubForm form, ulong at)
    {
        var b = new byte[16];
        Assert.Equal(b.Length, memory.ReadMemory(at, b));
        switch (form)
        {
            case StubForm.X64MovJmp:
                Assert.Equal([0x48, 0xB8], b[..2]);
                Assert.Equal([0xFF, 0xE0], b[10..12]);
                return BinaryPrimitives.ReadUInt64LittleEndian(b.AsSpan(2));
            case StubForm.X64JmpRip:
                Assert.Equal([0xFF, 0x25, 0, 0, 0, 0], b[..6]);
                return BinaryPrimitives.ReadUInt64LittleEndian(b.AsSpan(6));
            case StubForm.X64PushRet:
            case StubForm.X86PushRet:
                Assert.Equal(0x68, b[0]);
                Assert.Equal(0xC3, b[5]);
                return BinaryPrimitives.ReadUInt32LittleEndian(b.AsSpan(1));
            case StubForm.X86Jmp32:
                Assert.Equal(0xE9, b[0]);
                return at + 5 + (ulong)(long)BinaryPrimitives.ReadInt32LittleEndian(b.AsSpan(1));
            case StubForm.X86JmpAbs:
                Assert.Equal([0xFF, 0x25], b[..2]);
                Assert.True(memory.TryReadU32(BinaryPrimitives.ReadUInt32LittleEndian(b.AsSpan(2)), out uint pointer));
                return pointer;
            case StubForm.Arm64LdrBr:
                Assert.Equal(0x58000050u, BinaryPrimitives.ReadUInt32LittleEndian(b));
                Assert.Equal(0xD61F0200u, BinaryPrimitives.ReadUInt32LittleEndian(b.AsSpan(4)));
                return BinaryPrimitives.ReadUInt64LittleEndian(b.AsSpan(8));
            default:
                uint word = BinaryPrimitives.ReadUInt32LittleEndian(b);
                Assert.Equal(0x14000000u, word & 0xFC000000);
                long words = ((int)(word << 6)) >> 6;
                return at + (ulong)(words * 4);
        }
    }

    [Theory]
    [MemberData(nameof(Forms))]
    public void Each_stub_form_is_written_at_its_address_in_the_dump(ushort machine, StubForm form, int hops)
    {
        var set = StubFixtures.Chain(_dir, machine, form, hops);
        using var dump = MinidumpFile.Open(set.DumpPath);

        Assert.Equal(hops, set.Stubs.Count);
        Assert.Equal(set.Stubs[0], Target(dump, form, set.PatchSite));
        for (int i = 0; i + 1 < hops; i++) Assert.Equal(set.Stubs[i + 1], Target(dump, form, set.Stubs[i]));
        Assert.Equal(set.Export, Target(dump, form, set.Stubs[^1]));
        Assert.Equal(set.Export, dump.ModuleAt(set.Export)!.Base + StubFixtures.ExportRva);
        Assert.Null(dump.ModuleAt(set.Stubs[0]));
        Assert.True(File.Exists(Path.Combine(set.ImageFolder, "main.dll")));
        Assert.True(File.Exists(Path.Combine(set.ImageFolder, "provider.dll")));
    }

    [Fact]
    public void A_loop_has_two_stubs_that_jump_to_each_other()
    {
        var set = StubFixtures.Loop(_dir, 0x8664, StubForm.X64MovJmp);
        using var dump = MinidumpFile.Open(set.DumpPath);

        Assert.Equal(set.Stubs[0], Target(dump, StubForm.X64MovJmp, set.PatchSite));
        Assert.Equal(set.Stubs[1], Target(dump, StubForm.X64MovJmp, set.Stubs[0]));
        Assert.Equal(set.Stubs[0], Target(dump, StubForm.X64MovJmp, set.Stubs[1]));
    }

    [Fact]
    public void A_form_of_another_machine_is_refused()
    {
        Assert.Throws<ArgumentException>(() => StubFixtures.Chain(_dir, 0x14C, StubForm.X64MovJmp, 1));
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void Repeated_stubs_differ_only_in_their_displacements(bool is64)
    {
        var set = StubFixtures.Repeated(_dir, is64, 4);
        using var dump = MinidumpFile.Open(set.DumpPath);
        var file = File.ReadAllBytes(Path.Combine(set.ImageFolder, "main.dll"));

        var displacements = new List<int>();
        foreach (var (stub, target) in set.Stubs.Zip(set.Targets))
        {
            var b = new byte[5];
            Assert.Equal(5, dump.ReadMemory(stub, b));
            Assert.Equal(0xE9, b[0]);
            int displacement = BinaryPrimitives.ReadInt32LittleEndian(b.AsSpan(1));
            Assert.Equal(target, stub + 5 + (ulong)(long)displacement);
            displacements.Add(displacement);
        }

        Assert.Equal(4, displacements.Distinct().Count());
        // The file holds zeros where memory holds the stubs.
        Assert.All(file.AsSpan(0x200, 0x40).ToArray(), x => Assert.Equal(0, x));
    }
}
