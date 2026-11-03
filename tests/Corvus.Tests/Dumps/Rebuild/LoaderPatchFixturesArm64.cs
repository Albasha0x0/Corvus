using System.Buffers.Binary;

namespace Corvus.Tests;

/// <summary>An ARM64 image with a load configuration and a dynamic value relocation table, as linked and as a loader leaves it.</summary>
internal sealed record LoaderPatchImageArm64(byte[] Linked, byte[] Patched)
{
    /// <summary>The offset of the first byte of .text that a record can name; the bytes before it are never patched.</summary>
    public const uint FirstSite = 0x10;

    private const uint ConfigOffset = 0x40, TableOffset = 0x200;
    private const ushort Arm64 = 0xAA64;

    /// <summary>The image with one table record per entry; the loader overwrites .text from <see cref="FirstSite"/> on.</summary>
    public static LoaderPatchImageArm64 Build(params (ulong Symbol, byte[] Body)[] records)
    {
        var text = new byte[0x40];
        for (int i = 0; i < text.Length; i++) text[i] = (byte)(i + 1);
        var rdata = new byte[0x300];
        var config = rdata.AsSpan((int)ConfigOffset);
        BinaryPrimitives.WriteUInt32LittleEndian(config, 0x130);
        BinaryPrimitives.WriteUInt32LittleEndian(config[0xE0..], TableOffset);
        BinaryPrimitives.WriteUInt16LittleEndian(config[0xE4..], 2);
        Table(rdata.AsSpan((int)TableOffset), records);
        var spec = new PeSpec(true, [new SectionSpec(".text", 0x60000020, text), new SectionSpec(".rdata", 0x40000040, rdata)],
            [new PointerSite(".rdata", 0, 0x1020)]);
        var linked = RebuildFixtures.Pe(spec);
        BinaryPrimitives.WriteUInt32LittleEndian(linked.AsSpan(LoaderPatchImage.DirectoryAt(linked, 10)), 0x2000 + ConfigOffset);
        BinaryPrimitives.WriteUInt16LittleEndian(linked.AsSpan(MachineAt(linked)), Arm64);
        var patched = (byte[])linked.Clone();
        patched.AsSpan(LoaderPatchImage.RawAt(patched, 0x1000 + FirstSite), (int)(text.Length - FirstSite)).Fill(0xEE);
        return new LoaderPatchImageArm64(linked, patched);
    }

    /// <summary>An ARM64X record body: one block on the first page of .text with the fixups in sequence.</summary>
    public static byte[] Arm64XBody(params ushort[] words)
    {
        var body = new byte[8 + words.Length * 2];
        BinaryPrimitives.WriteUInt32LittleEndian(body, 0x1000);
        BinaryPrimitives.WriteUInt32LittleEndian(body.AsSpan(4), (uint)body.Length);
        for (int i = 0; i < words.Length; i++) BinaryPrimitives.WriteUInt16LittleEndian(body.AsSpan(8 + i * 2), words[i]);
        return body;
    }

    /// <summary>An ARM64X fixup header word: the offset in .text, a type (0 zero fill, 1 value, 2 delta) and a size code (1, 2 or 3).</summary>
    public static ushort Fixup(uint textOffset, int type, int sizeCode) => (ushort)(textOffset | (uint)(type << 12) | (uint)(sizeCode << 14));

    /// <summary>An import control transfer record body: one block on the first page of .text with an entry at <paramref name="textOffset"/>.</summary>
    public static byte[] ImportTransferBody(uint textOffset)
    {
        var body = new byte[12];
        BinaryPrimitives.WriteUInt32LittleEndian(body, 0x1000);
        BinaryPrimitives.WriteUInt32LittleEndian(body.AsSpan(4), 12);
        BinaryPrimitives.WriteUInt32LittleEndian(body.AsSpan(8), textOffset | 0x1000);
        return body;
    }

    // A version 1 table of records, each a 64-bit symbol, a body size and the
    // body.
    private static void Table(Span<byte> at, (ulong Symbol, byte[] Body)[] records)
    {
        int size = 0;
        foreach (var (symbol, body) in records)
        {
            BinaryPrimitives.WriteUInt64LittleEndian(at[(8 + size)..], symbol);
            BinaryPrimitives.WriteUInt32LittleEndian(at[(16 + size)..], (uint)body.Length);
            body.CopyTo(at[(20 + size)..]);
            size += 12 + body.Length;
        }
        BinaryPrimitives.WriteUInt32LittleEndian(at, 1);
        BinaryPrimitives.WriteUInt32LittleEndian(at[4..], (uint)size);
    }

    private static int MachineAt(byte[] file) => BinaryPrimitives.ReadInt32LittleEndian(file.AsSpan(0x3C)) + 4;
}
