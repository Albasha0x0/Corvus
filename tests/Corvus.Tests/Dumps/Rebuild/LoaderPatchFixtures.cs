using System.Buffers.Binary;

namespace Corvus.Tests;

/// <summary>A 64-bit image with a load configuration and a dynamic value relocation table, as linked and as a loader leaves it.</summary>
internal sealed record LoaderPatchImage(byte[] Linked, byte[] Patched, uint ThunkRva, uint SlotRva, ulong LinkedBase)
{
    private const uint ThunkOffset = 0x10, ConfigOffset = 0x40, TableOffset = 0x200;

    /// <summary>The image; <paramref name="withTable"/> false leaves out the load configuration and the table.</summary>
    public static LoaderPatchImage Build(bool withTable = true)
    {
        var text = new byte[0x40];
        text[ThunkOffset] = 0xE9;
        BinaryPrimitives.WriteInt32LittleEndian(text.AsSpan((int)ThunkOffset + 1), 0x20);
        var rdata = new byte[0x300];
        var pointers = new List<PointerSite> { new(".rdata", 0, 0x1020) };
        if (withTable)
        {
            var config = rdata.AsSpan((int)ConfigOffset);
            BinaryPrimitives.WriteUInt32LittleEndian(config, 0x130);
            BinaryPrimitives.WriteUInt32LittleEndian(config[0xE0..], TableOffset);
            BinaryPrimitives.WriteUInt16LittleEndian(config[0xE4..], 2);
            pointers.Add(new PointerSite(".rdata", (int)ConfigOffset + 0x70, 0x2000));
            Table(rdata.AsSpan((int)TableOffset), 0x1000 + ThunkOffset);
        }
        var spec = new PeSpec(true, [new SectionSpec(".text", 0x60000020, text), new SectionSpec(".rdata", 0x40000040, rdata)], pointers);
        var linked = RebuildFixtures.Pe(spec);
        if (withTable) BinaryPrimitives.WriteUInt32LittleEndian(linked.AsSpan(DirectoryAt(linked, 10)), 0x2000 + ConfigOffset);
        var patched = (byte[])linked.Clone();
        BinaryPrimitives.WriteInt32LittleEndian(patched.AsSpan(RawAt(patched, 0x1000 + ThunkOffset) + 1), 0x7FFF0000);
        BinaryPrimitives.WriteUInt64LittleEndian(patched.AsSpan(RawAt(patched, 0x2000)), 0x1818B8140UL);
        return new LoaderPatchImage(linked, patched, 0x1000 + ThunkOffset, 0x2000, spec.Base);
    }

    // A version 1 table with one function override record whose fixup is the rel32 operand of the jump at the thunk.
    private static void Table(Span<byte> at, uint thunk)
    {
        const int body = 4 + 16 + 4 + 12;
        BinaryPrimitives.WriteUInt32LittleEndian(at, 1);
        BinaryPrimitives.WriteUInt32LittleEndian(at[4..], 12 + body);
        BinaryPrimitives.WriteUInt64LittleEndian(at[8..], 7);
        BinaryPrimitives.WriteUInt32LittleEndian(at[16..], body);
        BinaryPrimitives.WriteUInt32LittleEndian(at[20..], body - 4);
        BinaryPrimitives.WriteUInt32LittleEndian(at[24..], 0x1000);
        BinaryPrimitives.WriteUInt32LittleEndian(at[32..], 4);
        BinaryPrimitives.WriteUInt32LittleEndian(at[36..], 12);
        BinaryPrimitives.WriteUInt32LittleEndian(at[40..], 0x1000);
        BinaryPrimitives.WriteUInt32LittleEndian(at[44..], thunk & ~0xFFFu);
        BinaryPrimitives.WriteUInt32LittleEndian(at[48..], 12);
        BinaryPrimitives.WriteUInt16LittleEndian(at[52..], (ushort)(0x1000 | ((thunk & 0xFFF) + 1)));
    }

    /// <summary>The file offset of data directory <paramref name="index"/> in a 64-bit PE file.</summary>
    public static int DirectoryAt(byte[] file, int index) => BinaryPrimitives.ReadInt32LittleEndian(file.AsSpan(0x3C)) + 24 + 112 + index * 8;

    /// <summary>The file offset of <paramref name="rva"/> inside a section's raw data; throws outside every section.</summary>
    public static int RawAt(byte[] file, uint rva)
    {
        int nt = BinaryPrimitives.ReadInt32LittleEndian(file.AsSpan(0x3C));
        int table = nt + 24 + BinaryPrimitives.ReadUInt16LittleEndian(file.AsSpan(nt + 20));
        for (int i = 0; i < BinaryPrimitives.ReadUInt16LittleEndian(file.AsSpan(nt + 6)); i++)
        {
            uint va = BinaryPrimitives.ReadUInt32LittleEndian(file.AsSpan(table + 40 * i + 12));
            uint size = BinaryPrimitives.ReadUInt32LittleEndian(file.AsSpan(table + 40 * i + 8));
            if (rva >= va && rva < va + size) return (int)(BinaryPrimitives.ReadUInt32LittleEndian(file.AsSpan(table + 40 * i + 20)) + rva - va);
        }
        throw new ArgumentException($"RVA 0x{rva:X} is outside every section.");
    }
}
