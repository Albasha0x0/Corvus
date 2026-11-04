using Corvus.Native;
using Corvus.Native.Dump;
using Corvus.Native.Dump.Rebuild;
using Corvus.Native.Pe;
using Corvus.Services;

namespace Corvus.Tests;

/// <summary>A changed code range without a known instruction start is shown as code only when the bytes are code.</summary>
public sealed class CodeChangeUnanchoredTests : IDisposable
{
    private readonly TempDir _dir = new();

    public void Dispose() => _dir.Dispose();

    private static string? Names(ulong address) => null;

    [Theory]
    [InlineData(NativeArch.X86)]
    [InlineData(NativeArch.X64)]
    public void A_range_of_undecodable_bytes_without_a_start_reads_as_bytes_changed(NativeArch machine)
    {
        // ret then an invalid pair after the first changed byte.
        byte[] file = [0x90, 0x90, 0x90, 0x90];
        byte[] memory = [0x90, 0xC3, 0x0F, 0x04];
        var text = CodeChangeText.Describe(memory, file, 0x401000, machine, -1, Names);
        Assert.Equal("bytes changed: 3 bytes, no instruction start known before the range", text);
    }

    [Theory]
    [InlineData(NativeArch.X86)]
    [InlineData(NativeArch.X64)]
    public void A_range_the_file_holds_as_data_without_a_start_reads_as_bytes_changed(NativeArch machine)
    {
        // The file holds an invalid pair where memory holds ret and nop.
        byte[] file = [0x0F, 0x04, 0x0F, 0x04];
        byte[] memory = [0x0F, 0x04, 0xC3, 0x90];
        var text = CodeChangeText.Describe(memory, file, 0x401000, machine, -1, Names);
        Assert.Equal(CodeChangeText.NoStart(2), text);
    }

    [Theory]
    [InlineData(NativeArch.X86)]
    [InlineData(NativeArch.X64)]
    public void A_range_that_decodes_cleanly_without_a_start_keeps_the_suffix(NativeArch machine)
    {
        byte[] file = [0x90, 0x90, 0x90, 0x90];
        byte[] memory = [0x90, 0xC3, 0x90, 0x90];
        var text = CodeChangeText.Describe(memory, file, 0x401000, machine, -1, Names);
        Assert.Equal("ret; nop; nop " + CodeChangeText.FromRangeStart, text);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void An_export_address_before_the_range_gives_a_known_start(bool is64)
    {
        // The section start lies 2000 bytes before the range; the export is 10
        // bytes before it.
        var code = Enumerable.Repeat((byte)0x90, 3000).ToArray();
        var spec = new PeSpec(is64, [new SectionSpec(".text", 0x60000020, code)], Exports: [new ExportSpec("fn", 0x1000 + 2000)]);
        var file = RebuildFixtures.Pe(spec);
        var memory = RebuildFixtures.Mapped(file);
        var disk = PeFile.FromBytes(file);
        uint rva = 0x1000 + 2010;
        Assert.Equal(-1, MinidumpService.LeadIn(disk.RuntimeFunctions, 0x1000, rva));
        int leadIn = MinidumpService.LeadIn(disk.RuntimeFunctions, 0x1000, rva, MinidumpService.StartFacts(disk));
        Assert.Equal(10, leadIn);

        memory[rva] = 0xC3;
        var reference = RebuildFixtures.Mapped(file);
        var window = MinidumpService.Window((r, n) => memory.AsSpan((int)r, n).ToArray(),
            (r, n) => reference.AsSpan((int)r, n).ToArray(), spec.Base + rva, rva, 1, leadIn, memory.Length);
        var builder = new MinidumpBuilder();
        builder.Memory.Add((0x10000, new byte[0x1000]));
        string path = _dir.File("probe.dmp");
        File.WriteAllBytes(path, builder.Build());
        using var process = MinidumpFile.Open(path);
        var text = MinidumpService.CodeText(window.Memory, window.File, window.Address, disk.Arch, window.KnownStart,
            process, new ExportMap(process), window.RangeStart, window.RangeEnd);
        Assert.Equal("code changed: ret", text);
    }
}