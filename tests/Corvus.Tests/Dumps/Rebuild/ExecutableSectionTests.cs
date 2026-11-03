using System.Buffers.Binary;
using Corvus.Native.Dump;
using Corvus.Native.Dump.Rebuild;

namespace Corvus.Tests;

/// <summary>Sections marked executable from the protection of their pages in a minidump.</summary>
public sealed class ExecutableSectionTests : IDisposable
{
    private const uint Uninitialized = 0xC0000080, Executable = 0x20000000, Code = 0x20;
    private const uint ReadWriteExecute = 0x40, ReadWrite = 0x04;
    private const uint SectionRva = 0x2000;

    private readonly TempDir _dir = new();

    public void Dispose() => _dir.Dispose();

    // The test section is the second one, at RVA 0x2000, 0x1000 bytes long.
    private (RebuiltModule Module, uint Flags, uint TextFlags) Run(bool is64, uint flags, uint? protect, int rawSize = 0,
        bool captured = true, bool layoutFile = true)
    {
        var spec = new PeSpec(is64,
        [
            new SectionSpec(".text", 0x60000020, [0xC3]),
            new SectionSpec(".rt", flags, Enumerable.Repeat((byte)0x90, 0x1000).ToArray()),
        ]);
        var mapped = RebuildFixtures.Mapped(RebuildFixtures.Pe(spec));
        int nt = BinaryPrimitives.ReadInt32LittleEndian(mapped.AsSpan(0x3C));
        int table = nt + 24 + BinaryPrimitives.ReadUInt16LittleEndian(mapped.AsSpan(nt + 20));
        BinaryPrimitives.WriteUInt32LittleEndian(mapped.AsSpan(table + 40 + 16), (uint)rawSize);
        if (rawSize == 0) BinaryPrimitives.WriteUInt32LittleEndian(mapped.AsSpan(table + 40 + 20), 0);

        uint stamp = BinaryPrimitives.ReadUInt32LittleEndian(mapped.AsSpan(nt + 8));
        var builder = new MinidumpBuilder { ProcessorArchitecture = is64 ? (ushort)9 : (ushort)0 };
        builder.Modules.Add(new MinidumpBuilder.Module(spec.Base, (uint)mapped.Length, stamp, "mark.dll"));
        for (int page = 0; page * 0x1000 < mapped.Length; page++)
        {
            if (!captured && page * 0x1000 == SectionRva) continue;
            builder.Memory.Add((spec.Base + (ulong)page * 0x1000, mapped.AsSpan(page * 0x1000, 0x1000).ToArray()));
        }
        if (protect is { } p)
        {
            builder.Regions.Add(new MinidumpBuilder.Region(spec.Base, 0x1000, 0x02));
            builder.Regions.Add(new MinidumpBuilder.Region(spec.Base + 0x1000, 0x1000, 0x20));
            builder.Regions.Add(new MinidumpBuilder.Region(spec.Base + SectionRva, 0x1000, p));
        }
        string path = _dir.File($"mark-{Guid.NewGuid():N}.dmp");
        File.WriteAllBytes(path, builder.Build());

        using var dump = MinidumpFile.Open(path);
        var target = Assert.Single(ModuleRebuild.Select(dump, "mark.dll", default));
        var options = RebuildOptions.Default with { Layout = layoutFile ? OutputLayout.File : OutputLayout.Mapped, CompareWithDisk = false };
        var module = ModuleRebuild.Rebuild(dump, target, options, default);
        Assert.Null(module.Refused);
        var bytes = module.Bytes!;
        int t = BinaryPrimitives.ReadInt32LittleEndian(bytes.AsSpan(0x3C)) + 24 + BinaryPrimitives.ReadUInt16LittleEndian(bytes.AsSpan(BinaryPrimitives.ReadInt32LittleEndian(bytes.AsSpan(0x3C)) + 20));
        return (module, BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(t + 40 + 36)), BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(t + 36)));
    }

    private static string Layout(RebuiltModule m) => Assert.Single(m.Checks, c => c.Name == "layout").Detail;

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void A_section_with_no_raw_data_in_an_executable_region_is_marked_executable(bool is64)
    {
        var r = Run(is64, Uninitialized, ReadWriteExecute);
        Assert.Equal(Executable | Code, r.Flags & (Executable | Code));
        Assert.Equal(0u, r.Flags & 0x80);
        Assert.Contains("1 sections marked executable from memory protection", Layout(r.Module));
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void A_section_with_short_raw_data_in_an_executable_region_is_marked_executable(bool is64)
    {
        var r = Run(is64, 0xC0000040, ReadWriteExecute, rawSize: 0x200);
        Assert.Equal(Executable | Code, r.Flags & (Executable | Code));
        Assert.Contains("1 sections marked", Layout(r.Module));
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void A_section_with_full_raw_data_in_an_executable_region_is_marked_executable(bool is64)
    {
        var r = Run(is64, 0xC0000040, ReadWriteExecute, rawSize: 0x1000);
        Assert.Equal(Executable | Code, r.Flags & (Executable | Code));
    }

    [Fact]
    public void A_mapped_layout_marks_the_section_too()
    {
        var r = Run(true, Uninitialized, ReadWriteExecute, layoutFile: false);
        Assert.Equal(Executable | Code, r.Flags & (Executable | Code));
    }

    [Fact]
    public void A_section_already_executable_is_unchanged()
    {
        var r = Run(true, 0x60000020, ReadWriteExecute);
        Assert.Equal(0x60000020u, r.Flags);
        Assert.DoesNotContain("marked executable", Layout(r.Module));
    }

    [Fact]
    public void A_section_with_no_executable_page_is_unchanged()
    {
        var r = Run(true, Uninitialized, ReadWrite);
        Assert.Equal(Uninitialized, r.Flags);
        Assert.DoesNotContain("marked executable", Layout(r.Module));
    }

    [Fact]
    public void A_section_with_unknown_protection_is_unchanged_and_not_claimed()
    {
        var r = Run(true, Uninitialized, null);
        Assert.Equal(Uninitialized, r.Flags);
        Assert.DoesNotContain("marked executable", Layout(r.Module));
    }

    [Fact]
    public void A_section_whose_executable_pages_were_not_captured_is_unchanged()
    {
        var r = Run(true, Uninitialized, ReadWriteExecute, captured: false);
        Assert.Equal(Uninitialized, r.Flags);
        Assert.DoesNotContain("marked executable", Layout(r.Module));
    }
}
