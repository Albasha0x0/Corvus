using System.Buffers.Binary;
using System.Text;

namespace Corvus.Tests;

/// <summary>Builds synthetic PE files with a CLR data directory for header tests.</summary>
internal static class ManagedHeaderFixtures
{
    public const uint ClrRva = 0x1000, MetadataRva = 0x1100;

    /// <summary>Returns a managed PE file whose first section holds a CLR header and a metadata root signature.</summary>
    public static byte[] Managed(bool is64, uint stamp = 0)
    {
        var text = new byte[0x400];
        BinaryPrimitives.WriteUInt32LittleEndian(text, 72);
        BinaryPrimitives.WriteUInt32LittleEndian(text.AsSpan(8), MetadataRva);
        BinaryPrimitives.WriteUInt32LittleEndian(text.AsSpan(12), 0x40);
        Encoding.ASCII.GetBytes("BSJB").CopyTo(text, (int)(MetadataRva - ClrRva));
        var pe = RebuildFixtures.Pe(new PeSpec(is64, [new SectionSpec(".text", 0x60000020, text)]));
        int nt = BinaryPrimitives.ReadInt32LittleEndian(pe.AsSpan(0x3C));
        BinaryPrimitives.WriteUInt32LittleEndian(pe.AsSpan(nt + 8), stamp);
        int entry = nt + 24 + (is64 ? 112 : 96) + 14 * 8;
        BinaryPrimitives.WriteUInt32LittleEndian(pe.AsSpan(entry), ClrRva);
        BinaryPrimitives.WriteUInt32LittleEndian(pe.AsSpan(entry + 4), 72);
        return pe;
    }

    /// <summary>Returns the file offset of the raw data of the first section.</summary>
    public static int TextAt(byte[] pe)
    {
        int nt = BinaryPrimitives.ReadInt32LittleEndian(pe.AsSpan(0x3C));
        int opt = BinaryPrimitives.ReadUInt16LittleEndian(pe.AsSpan(nt + 20));
        return (int)BinaryPrimitives.ReadUInt32LittleEndian(pe.AsSpan(nt + 24 + opt + 20));
    }
}
