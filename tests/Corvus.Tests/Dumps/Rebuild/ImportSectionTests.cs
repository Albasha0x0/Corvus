using System.Buffers.Binary;
using Corvus.Native.Dump.Rebuild;
using Corvus.Native.Pe;

namespace Corvus.Tests;

/// <summary>Import names written into a section of the rebuilt image.</summary>
public sealed class ImportSectionTests : IDisposable
{
    private readonly TempDir _dir = new();

    public void Dispose() => _dir.Dispose();

    // The first descriptor's lookup table field is zeroed, so its slots can only be named from exports.
    private static PeBuilt App()
    {
        var built = RebuildFixtures.Build(new PeSpec(
            true, [new SectionSpec(".text", 0x60000020, new byte[0x40])], Imports: [new ImportSpec("lib.dll", ["Alpha"])]));
        var bytes = (byte[])built.Bytes.Clone();
        uint idata = PeFile.FromBytes(bytes).Sections.First(s => s.Name == ".idata").Rva;
        int nt = BinaryPrimitives.ReadInt32LittleEndian(bytes.AsSpan(0x3C));
        int table = nt + 24 + BinaryPrimitives.ReadUInt16LittleEndian(bytes.AsSpan(nt + 20));
        int count = BinaryPrimitives.ReadUInt16LittleEndian(bytes.AsSpan(nt + 6));
        for (int i = 0; i < count; i++)
        {
            int h = table + 40 * i;
            if (BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(h + 12)) != idata) continue;
            BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan((int)BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(h + 20))), 0);
        }
        return new PeBuilt(bytes, built.IatSlots);
    }

    private static PeBuilt Library() => RebuildFixtures.Build(new PeSpec(
        true, [new SectionSpec(".text", 0x60000020, new byte[0x40])], Exports: [new ExportSpec("Alpha", 0x1000)]));

    private (ImportSummary? Summary, byte[] Image, CapturedImage Captured, List<RebuildCheck> Checks) Restore(bool shrinkHeaders)
    {
        using var dump = RebuildFixtures.Dump(_dir, new Placed("app.exe", App(), 0x140000000), new Placed("lib.dll", Library(), 0x180000000));
        var target = RebuildTarget.Of(dump.Modules.First(m => m.FileName == "app.exe"));
        var captured = CapturedImageReader.Read(dump, target, CancellationToken.None)!;
        var image = (byte[])captured.Image.Clone();
        if (shrinkHeaders)
        {
            int nt = BinaryPrimitives.ReadInt32LittleEndian(image.AsSpan(0x3C));
            int opt = nt + 24;
            int tableEnd = opt + BinaryPrimitives.ReadUInt16LittleEndian(image.AsSpan(nt + 20)) + 40 * BinaryPrimitives.ReadUInt16LittleEndian(image.AsSpan(nt + 6));
            BinaryPrimitives.WriteUInt32LittleEndian(image.AsSpan(opt + 60), (uint)tableEnd);
        }
        var checks = new List<RebuildCheck>();
        var summary = PeImportRestore.Restore(ref image, ref captured, dump, ImportMode.Restore, checks, CancellationToken.None);
        return (summary, image, captured, checks);
    }

    [Fact]
    public void Resolved_import_names_are_written_into_a_section_the_PE_reader_lists()
    {
        var (summary, image, captured, checks) = Restore(false);

        Assert.True(summary!.DirectoryRebuilt);
        var file = PeFileLayout.ToFileLayout(image, captured, checks);
        var pe = PeFile.FromBytes(file);
        Assert.Contains(pe.Sections, s => s.Name == ".idata2");
        var import = Assert.Single(pe.Imports);
        Assert.Equal("Alpha", import.Name);
        Assert.Equal("lib.dll", import.Module);
    }

    [Fact]
    public void A_section_table_without_room_leaves_the_names_in_the_result_only()
    {
        var (summary, image, captured, checks) = Restore(true);

        Assert.False(summary!.DirectoryRebuilt);
        Assert.Single(summary.Names);
        Assert.Equal(captured.Image.Length, image.Length);
        var check = Assert.Single(checks);
        Assert.Equal("partial", check.State);
        Assert.Contains("no room for an import section", check.Detail);
    }
}
