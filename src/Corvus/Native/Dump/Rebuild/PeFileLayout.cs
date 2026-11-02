using System.Buffers.Binary;
using Corvus.Native.Pe;

namespace Corvus.Native.Dump.Rebuild;

/// <summary>Turns a mapped image into a PE file.</summary>
public static class PeFileLayout
{
    /// <summary>Null, with a skipped layout check: the file layout is not built yet.</summary>
    public static byte[]? ToFileLayout(byte[] image, CapturedImage captured, List<RebuildCheck> checks)
    {
        checks.Add(RebuildCheck.Skipped("layout", "file layout is not built yet"));
        return null;
    }

    /// <summary>The image as mapped: each section's file offset is its RVA.</summary>
    public static byte[] AsMapped(byte[] image, CapturedImage captured, List<RebuildCheck> checks)
    {
        var bytes = (byte[])image.Clone();
        int coff = (int)BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(0x3C)) + 4;
        ushort sections = BinaryPrimitives.ReadUInt16LittleEndian(bytes.AsSpan(coff + 2));
        ushort optSize = BinaryPrimitives.ReadUInt16LittleEndian(bytes.AsSpan(coff + 16));
        long table = coff + 20L + optSize;
        for (int i = 0; i < sections && i < PeLimits.MaxSections && table + i * 40L + 40 <= bytes.Length; i++)
        {
            var h = bytes.AsSpan((int)(table + i * 40L), 40);
            uint vsize = BinaryPrimitives.ReadUInt32LittleEndian(h[8..]), va = BinaryPrimitives.ReadUInt32LittleEndian(h[12..]);
            uint mapped = va >= bytes.Length ? 0 : (uint)Math.Min(Math.Max(vsize, BinaryPrimitives.ReadUInt32LittleEndian(h[16..])), bytes.Length - va);
            BinaryPrimitives.WriteUInt32LittleEndian(h[16..], mapped);
            BinaryPrimitives.WriteUInt32LittleEndian(h[20..], mapped == 0 ? 0 : va);
        }
        checks.Add(RebuildCheck.Ok("layout", "mapped: section offsets are RVAs"));
        return bytes;
    }
}
