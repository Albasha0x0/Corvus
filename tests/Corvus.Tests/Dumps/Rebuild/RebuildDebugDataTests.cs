using System.Buffers.Binary;
using System.Text;
using Corvus.Native.Dump;
using Corvus.Native.Dump.Rebuild;
using Corvus.Native.Pe;

namespace Corvus.Tests;

/// <summary>The debug directory of a rebuilt image names its data at the new file offsets.</summary>
public sealed class RebuildDebugDataTests
{
    // A file whose .rdata holds a debug entry and its CodeView record; in
    // memory .text spans a whole page, so the file layout moves .rdata.
    private static (byte[] File, byte[] Mapped) Image()
    {
        var file = RebuildFixtures.Pe(new PeSpec(true,
            [new SectionSpec(".text", 0x60000020, Enumerable.Repeat((byte)0x90, 0x40).ToArray()), new SectionSpec(".rdata", 0x40000040, new byte[0x100])]));
        int opt = BinaryPrimitives.ReadInt32LittleEndian(file.AsSpan(0x3C)) + 24;
        int table = opt + BinaryPrimitives.ReadUInt16LittleEndian(file.AsSpan(opt - 4));
        uint rva = BinaryPrimitives.ReadUInt32LittleEndian(file.AsSpan(table + 40 + 12));
        int raw = BinaryPrimitives.ReadInt32LittleEndian(file.AsSpan(table + 40 + 20));
        var record = Encoding.ASCII.GetBytes("RSDS").Concat(Enumerable.Range(1, 16).Select(i => (byte)i)).Concat(new byte[] { 1, 0, 0, 0 }).Concat(Encoding.ASCII.GetBytes("a.pdb\0")).ToArray();
        record.CopyTo(file, raw + 0x40);
        var entry = file.AsSpan(raw, 28);
        BinaryPrimitives.WriteUInt32LittleEndian(entry[12..], 2);
        BinaryPrimitives.WriteUInt32LittleEndian(entry[16..], (uint)record.Length);
        BinaryPrimitives.WriteUInt32LittleEndian(entry[20..], rva + 0x40);
        BinaryPrimitives.WriteUInt32LittleEndian(entry[24..], (uint)raw + 0x40);
        BinaryPrimitives.WriteUInt32LittleEndian(file.AsSpan(opt + 112 + 6 * 8), rva);
        BinaryPrimitives.WriteUInt32LittleEndian(file.AsSpan(opt + 112 + 6 * 8 + 4), 28);
        var mapped = RebuildFixtures.Mapped(file);
        BinaryPrimitives.WriteUInt32LittleEndian(mapped.AsSpan(table + 8), 0x1000);
        return (file, mapped);
    }

    private static CapturedImage Captured(byte[] mapped) =>
        new(new RebuildTarget("app.exe", 0x140000000, (uint)mapped.Length, ModuleOrigin.Listed), mapped, Enumerable.Repeat(true, mapped.Length / 0x1000).ToArray(), "mapped");

    // Regression: a module whose sections moved in the rebuild kept file
    // offsets of the original file in its debug directory.
    [Fact]
    public void A_file_layout_that_moves_a_section_keeps_the_CodeView_record_readable()
    {
        var (file, mapped) = Image();

        var rebuilt = PeFileLayout.ToFileLayout(mapped, Captured(mapped), []);

        Assert.NotNull(PeFile.FromBytes(file).BuildId);
        Assert.Equal(PeFile.FromBytes(file).BuildId, PeFile.FromBytes(rebuilt).BuildId);
    }

    [Fact]
    public void A_mapped_layout_names_the_CodeView_record_at_its_RVA()
    {
        var (file, mapped) = Image();

        var rebuilt = PeFileLayout.AsMapped(mapped, Captured(mapped), []);

        Assert.Equal(PeFile.FromBytes(file).BuildId, PeFile.FromBytes(rebuilt).BuildId);
    }
}
