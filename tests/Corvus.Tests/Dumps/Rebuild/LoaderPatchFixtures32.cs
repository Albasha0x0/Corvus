using System.Buffers.Binary;

namespace Corvus.Tests;

/// <summary>A 32-bit image with a load configuration and a dynamic value relocation table, as linked and as a loader leaves it.</summary>
internal sealed record LoaderPatchImage32(byte[] Linked, byte[] Patched, uint ThunkRva, uint CheckSlotRva, uint DispatchSlotRva, uint LinkedBase)
{
    private const uint ThunkOffset = 0x10, ConfigOffset = 0x40, TableOffset = 0x200;

    /// <summary>The image; the guard slots hold function addresses and the thunk is a jump with a rel32 operand.</summary>
    public static LoaderPatchImage32 Build()
    {
        var text = new byte[0x40];
        text[ThunkOffset] = 0xE9;
        BinaryPrimitives.WriteInt32LittleEndian(text.AsSpan((int)ThunkOffset + 1), 0x20);
        var rdata = new byte[0x300];
        var config = rdata.AsSpan((int)ConfigOffset);
        BinaryPrimitives.WriteUInt32LittleEndian(config, 0xC0);
        BinaryPrimitives.WriteUInt32LittleEndian(config[136..], TableOffset);
        BinaryPrimitives.WriteUInt16LittleEndian(config[140..], 2);
        Table(rdata.AsSpan((int)TableOffset), 0x1000 + ThunkOffset);
        var pointers = new List<PointerSite>
        {
            new(".rdata", 0, 0x1020),
            new(".rdata", 4, 0x1030),
            new(".rdata", (int)ConfigOffset + 72, 0x2000),
            new(".rdata", (int)ConfigOffset + 76, 0x2004),
        };
        var spec = new PeSpec(false, [new SectionSpec(".text", 0x60000020, text), new SectionSpec(".rdata", 0x40000040, rdata)], pointers);
        var linked = RebuildFixtures.Pe(spec);
        BinaryPrimitives.WriteUInt32LittleEndian(linked.AsSpan(DirectoryAt(linked, 10)), 0x2000 + ConfigOffset);
        var patched = (byte[])linked.Clone();
        BinaryPrimitives.WriteInt32LittleEndian(patched.AsSpan(LoaderPatchImage.RawAt(patched, 0x1000 + ThunkOffset) + 1), 0x7FFF0000);
        BinaryPrimitives.WriteUInt32LittleEndian(patched.AsSpan(LoaderPatchImage.RawAt(patched, 0x2000)), 0x7FF01000);
        BinaryPrimitives.WriteUInt32LittleEndian(patched.AsSpan(LoaderPatchImage.RawAt(patched, 0x2004)), 0x7FF02000);
        return new LoaderPatchImage32(linked, patched, 0x1000 + ThunkOffset, 0x2000, 0x2004, (uint)spec.Base);
    }

    // A version 1 table with one function override record whose fixup is the
    // rel32 operand of the jump at the thunk.
    private static void Table(Span<byte> at, uint thunk)
    {
        const int body = 4 + 16 + 4 + 12;
        BinaryPrimitives.WriteUInt32LittleEndian(at, 1);
        BinaryPrimitives.WriteUInt32LittleEndian(at[4..], 8 + body);
        BinaryPrimitives.WriteUInt32LittleEndian(at[8..], 7);
        BinaryPrimitives.WriteUInt32LittleEndian(at[12..], body);
        BinaryPrimitives.WriteUInt32LittleEndian(at[16..], body - 4);
        BinaryPrimitives.WriteUInt32LittleEndian(at[20..], 0x1000);
        BinaryPrimitives.WriteUInt32LittleEndian(at[28..], 4);
        BinaryPrimitives.WriteUInt32LittleEndian(at[32..], 12);
        BinaryPrimitives.WriteUInt32LittleEndian(at[36..], 0x1000);
        BinaryPrimitives.WriteUInt32LittleEndian(at[40..], thunk & ~0xFFFu);
        BinaryPrimitives.WriteUInt32LittleEndian(at[44..], 12);
        BinaryPrimitives.WriteUInt16LittleEndian(at[48..], (ushort)(0x1000 | ((thunk & 0xFFF) + 1)));
    }

    /// <summary>The file offset of data directory <paramref name="index"/> in a 32-bit PE file.</summary>
    public static int DirectoryAt(byte[] file, int index) => BinaryPrimitives.ReadInt32LittleEndian(file.AsSpan(0x3C)) + 24 + 96 + index * 8;
}
