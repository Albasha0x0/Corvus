using System.Buffers.Binary;
using Corvus.Native.Dump.Rebuild;

namespace Corvus.Tests;

/// <summary>Modules rebuilt in file layout from a synthetic minidump.</summary>
public sealed class FileLayoutTests : IDisposable
{
    private readonly TempDir _dir = new();

    public void Dispose() => _dir.Dispose();

    private static PeSpec Spec() => new(true,
    [
        new SectionSpec(".text", 0x60000020, Enumerable.Range(1, 0x300).Select(i => (byte)i).ToArray()),
        new SectionSpec(".data", 0xC0000040, Enumerable.Range(1, 0x1200).Select(i => (byte)(i * 7)).ToArray()),
    ]);

    private RebuiltModule Rebuild(Placed placed)
    {
        using var dump = RebuildFixtures.Dump(_dir, placed);
        var target = Assert.Single(ModuleRebuild.Select(dump, placed.Name, default));
        return ModuleRebuild.Rebuild(dump, target, RebuildOptions.Default with { Layout = OutputLayout.File, Base = BaseMode.Preferred, CompareWithDisk = false }, default);
    }

    [Fact]
    public void A_mapped_module_rebuilt_in_file_layout_matches_the_original_file()
    {
        var original = RebuildFixtures.Pe(Spec());
        var rebuilt = Rebuild(new Placed("lay.dll", RebuildFixtures.Build(Spec()), 0x180000000));

        Assert.Null(rebuilt.Refused);
        // The fixture file has no checksum; the rebuilt file carries a recomputed one.
        var unsealed = (byte[])rebuilt.Bytes!.Clone();
        int checksumField = BinaryPrimitives.ReadInt32LittleEndian(unsealed.AsSpan(0x3C)) + 24 + 64;
        unsealed.AsSpan(checksumField, 4).Clear();
        Assert.Equal(original, unsealed);
        Assert.Contains(rebuilt.Checks, c => c.Name == "layout" && c.State == "ok" && c.Detail.Contains("overlay"));
        Assert.Contains(rebuilt.Checks, c => c.Name == "parse" && c.State == "ok");
    }

    // Reproduces the shift seen after 601bd06c9: one more section header moves
    // every raw offset by 512, so each debug entry offset differs from the file's.
    [Fact]
    public void A_debug_entry_file_offset_set_for_the_new_layout_is_not_a_difference_from_the_file()
    {
        var file = RebuildFixtures.Pe(new PeSpec(true,
            [new SectionSpec(".text", 0x60000020, Enumerable.Repeat((byte)0x90, 0x40).ToArray()), new SectionSpec(".rdata", 0x40000040, new byte[0x100])]));
        int opt = BinaryPrimitives.ReadInt32LittleEndian(file.AsSpan(0x3C)) + 24;
        int table = opt + BinaryPrimitives.ReadUInt16LittleEndian(file.AsSpan(opt - 4));
        uint rva = BinaryPrimitives.ReadUInt32LittleEndian(file.AsSpan(table + 40 + 12));
        int raw = BinaryPrimitives.ReadInt32LittleEndian(file.AsSpan(table + 40 + 20));
        BinaryPrimitives.WriteUInt32LittleEndian(file.AsSpan(raw + 12), 2);
        BinaryPrimitives.WriteUInt32LittleEndian(file.AsSpan(raw + 16), 8);
        BinaryPrimitives.WriteUInt32LittleEndian(file.AsSpan(raw + 20), rva + 0x40);
        BinaryPrimitives.WriteUInt32LittleEndian(file.AsSpan(raw + 24), (uint)raw + 0x40);
        BinaryPrimitives.WriteUInt32LittleEndian(file.AsSpan(opt + 112 + 6 * 8), rva);
        BinaryPrimitives.WriteUInt32LittleEndian(file.AsSpan(opt + 112 + 6 * 8 + 4), 28);
        var mapped = RebuildFixtures.Mapped(file);
        BinaryPrimitives.WriteUInt32LittleEndian(mapped.AsSpan(table + 8), 0x1000);
        var target = new RebuildTarget("lay.dll", 0x140000000, (uint)mapped.Length, ModuleOrigin.Listed);
        var captured = new CapturedImage(target, mapped, Enumerable.Repeat(true, mapped.Length / 0x1000).ToArray(), "mapped");
        var rebuilt = PeFileLayout.ToFileLayout(mapped, captured, []);
        string folder = Directory.CreateDirectory(_dir.File("bin")).FullName;
        File.WriteAllBytes(Path.Combine(folder, "lay.dll"), file);

        int rebuiltRaw = BinaryPrimitives.ReadInt32LittleEndian(rebuilt.AsSpan(table + 40 + 20));
        var rebuiltOffset = BinaryPrimitives.ReadUInt32LittleEndian(rebuilt.AsSpan(rebuiltRaw + 24));
        var checks = new List<RebuildCheck>();
        var disk = DiskCompare.Compare(rebuilt, captured, RebuildOptions.Default with { ImageDirectories = folder }, checks);

        Assert.NotEqual((uint)raw + 0x40, rebuiltOffset);
        Assert.Equal(0, disk!.DifferingBytes);
    }

    [Fact]
    public void A_section_with_missing_pages_is_written_with_zeros_and_reported_partial()
    {
        var built = RebuildFixtures.Build(Spec());
        var rebuilt = Rebuild(new Placed("gap.dll", built, 0x180000000, OmittedPages: [0x3000]));

        var layout = Assert.Single(rebuilt.Checks, c => c.Name == "layout");
        Assert.Equal("partial", layout.State);
        Assert.Contains(".data 512 bytes", layout.Detail);
        int nt = BinaryPrimitives.ReadInt32LittleEndian(rebuilt.Bytes.AsSpan(0x3C));
        int table = nt + 24 + BinaryPrimitives.ReadUInt16LittleEndian(rebuilt.Bytes.AsSpan(nt + 20));
        int raw = (int)BinaryPrimitives.ReadUInt32LittleEndian(rebuilt.Bytes.AsSpan(table + 40 + 20));
        Assert.Equal(RebuildFixtures.Pe(Spec()).AsSpan(raw, 0x1000).ToArray(), rebuilt.Bytes.AsSpan(raw, 0x1000).ToArray());
        Assert.All(rebuilt.Bytes.AsSpan(raw + 0x1000, 0x200).ToArray(), b => Assert.Equal(0, b));
    }
}