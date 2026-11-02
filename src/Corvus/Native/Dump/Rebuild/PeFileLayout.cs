using System.Buffers.Binary;
using Corvus.Native.Pe;

namespace Corvus.Native.Dump.Rebuild;

/// <summary>Turns a mapped image into a PE file.</summary>
public static class PeFileLayout
{
    /// <summary>
    /// The image as a PE file: each section's raw data at a file-aligned offset, headers kept. Pages that were not
    /// captured are zero and reported as partial; a malformed header table returns the mapped bytes with a failed check.
    /// </summary>
    public static byte[] ToFileLayout(byte[] image, CapturedImage captured, List<RebuildCheck> checks)
    {
        if (!TryReadHeaders(image, out int opt, out int table, out int count))
        {
            checks.Add(RebuildCheck.Failed("layout", "the section table does not fit the captured headers"));
            return (byte[])image.Clone();
        }

        uint alignment = BinaryPrimitives.ReadUInt32LittleEndian(image.AsSpan(opt + 36));
        bool defaulted = alignment == 0 || (alignment & (alignment - 1)) != 0 || alignment > 0x10000;
        if (defaulted) alignment = DefaultFileAlignment;

        uint headersSize = BinaryPrimitives.ReadUInt32LittleEndian(image.AsSpan(opt + 60));
        uint tableEnd = (uint)(table + 40 * count);
        long cursor = Align(Math.Max(headersSize, tableEnd), alignment);
        var starts = new long[count];
        var sizes = new uint[count];
        long total = cursor;
        for (int i = 0; i < count; i++)
        {
            var h = image.AsSpan(table + 40 * i, 40);
            uint vsize = BinaryPrimitives.ReadUInt32LittleEndian(h[8..]);
            if (vsize == 0) vsize = BinaryPrimitives.ReadUInt32LittleEndian(h[16..]);
            sizes[i] = vsize;
            starts[i] = total;
            total += Align(vsize, alignment);
        }
        if (total > ModuleRebuild.MaxImageBytes)
        {
            checks.Add(RebuildCheck.Failed("layout", $"the file would exceed {ModuleRebuild.MaxImageBytes >> 20} MB"));
            return (byte[])image.Clone();
        }

        var file = new byte[total];
        image.AsSpan(0, (int)Math.Min(Math.Max(headersSize, tableEnd), image.Length)).CopyTo(file);
        BinaryPrimitives.WriteUInt32LittleEndian(file.AsSpan(opt + 36), alignment);
        BinaryPrimitives.WriteUInt32LittleEndian(file.AsSpan(opt + 60), (uint)Align(Math.Max(headersSize, tableEnd), alignment));

        var gaps = new List<string>();
        for (int i = 0; i < count; i++)
        {
            var h = file.AsSpan(table + 40 * i, 40);
            uint va = BinaryPrimitives.ReadUInt32LittleEndian(h[12..]);
            long copy = va >= image.Length ? 0 : Math.Min(sizes[i], image.Length - va);
            if (copy > 0) image.AsSpan((int)va, (int)copy).CopyTo(file.AsSpan((int)starts[i]));
            long missing = MissingBytes(captured, va, sizes[i]);
            if (missing > 0) gaps.Add($"{SectionName(h)} {missing} bytes");
            uint raw = (uint)Align(sizes[i], alignment);
            BinaryPrimitives.WriteUInt32LittleEndian(h[16..], raw);
            BinaryPrimitives.WriteUInt32LittleEndian(h[20..], raw == 0 ? 0 : (uint)starts[i]);
        }

        string note = defaulted ? $"; file alignment invalid, 0x{DefaultFileAlignment:X} used" : "";
        string overlay = "; overlay data past the last section is not in memory";
        checks.Add(gaps.Count == 0
            ? RebuildCheck.Ok("layout", "file layout" + note + overlay)
            : RebuildCheck.Partial("layout", $"file layout, pages not captured written as zeros: {string.Join(", ", gaps)}" + note + overlay));
        return file;
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

    private const uint DefaultFileAlignment = 0x200;

    private static long Align(uint value, uint alignment) => ((long)value + alignment - 1) / alignment * alignment;

    private static string SectionName(ReadOnlySpan<byte> header)
    {
        int length = header[..8].IndexOf((byte)0);
        return System.Text.Encoding.ASCII.GetString(header[..(length < 0 ? 8 : length)]);
    }

    private static bool TryReadHeaders(byte[] image, out int opt, out int table, out int count)
    {
        opt = table = count = 0;
        if (image.Length < 0x40) return false;
        long coff = (long)BinaryPrimitives.ReadUInt32LittleEndian(image.AsSpan(0x3C)) + 4;
        if (coff + 20 > image.Length) return false;
        count = BinaryPrimitives.ReadUInt16LittleEndian(image.AsSpan((int)coff + 2));
        long optSize = BinaryPrimitives.ReadUInt16LittleEndian(image.AsSpan((int)coff + 16));
        long start = coff + 20;
        long end = start + optSize + 40L * count;
        if (count > PeLimits.MaxSections || optSize < 64 || start + 64 > image.Length || end > image.Length) return false;
        opt = (int)start;
        table = (int)(start + optSize);
        return true;
    }

    // Bytes of [rva, rva + size) on pages that were not read, or past the buffer.
    private static long MissingBytes(CapturedImage captured, uint rva, uint size)
    {
        long missing = 0, end = (long)rva + size;
        for (long page = rva & ~0xFFFL; page < end; page += 0x1000)
        {
            if (captured.PageCaptured((uint)page)) continue;
            missing += Math.Min(end, page + 0x1000) - Math.Max(rva, page);
        }
        return missing;
    }
}