using System.Buffers.Binary;

namespace NetDecompilerMcp.Native.NativeAot;

/// <summary>
/// Finds NativeAOT module headers without symbols: a scan of the initialized non-executable sections for "RTR\0" at
/// 4-byte alignment whose shape is a NativeAOT header (row size 2 pointers + 8, row type 1, 1–127 rows with distinct
/// ids, starts and ends inside the image) and, when the image has base relocations, a relocation at every row start.
/// Several headers (multi-module images) are all returned.
/// </summary>
public static class NativeAotLocator
{
    public const uint Signature = 0x00525452; // "RTR\0"
    private const int MaxRows = 127;
    private static readonly byte[] SignatureBytes = "RTR\0"u8.ToArray();

    public static IReadOnlyList<NativeAotHeader> Find(INativeImage image, CancellationToken ct = default)
    {
        var found = new List<NativeAotHeader>();
        foreach (var section in image.Sections)
        {
            if (section.IsExecutable || section.RawSize == 0) continue;
            ct.ThrowIfCancellationRequested();
            var bytes = new byte[Math.Min(section.RawSize, section.MappedSize)];
            int n = image.Read(section.Rva, bytes);
            var span = bytes.AsSpan(0, n);
            for (int at = 0; ;)
            {
                int hit = span[at..].IndexOf(SignatureBytes);
                if (hit < 0) break;
                at += hit;
                uint rva = section.Rva + (uint)at;
                if (rva % 4 == 0 && TryRead(image, rva) is { } header) found.Add(header);
                at += 4;
            }
        }
        return found;
    }

    /// <summary>The header at <paramref name="rva"/>, or null when the bytes there are not a plausible NativeAOT header.</summary>
    public static NativeAotHeader? TryRead(INativeImage image, uint rva)
    {
        Span<byte> head = stackalloc byte[16];
        if (image.Read(rva, head) != head.Length || BinaryPrimitives.ReadUInt32LittleEndian(head) != Signature) return null;
        ushort major = BinaryPrimitives.ReadUInt16LittleEndian(head[4..]);
        ushort minor = BinaryPrimitives.ReadUInt16LittleEndian(head[6..]);
        uint flags = BinaryPrimitives.ReadUInt32LittleEndian(head[8..]);
        int rows = BinaryPrimitives.ReadUInt16LittleEndian(head[12..]);
        int pointer = image.Is64Bit ? 8 : 4;
        if (head[14] != 2 * pointer + 8 || head[15] != 1 || rows is 0 or > MaxRows) return null;

        var table = new byte[rows * head[14]];
        if (image.Read(rva + 16, table) != table.Length) return null;
        var relocations = image.RelocationRvas;
        bool relocated = relocations.Count > 0;
        var sections = new List<NativeAotSection>(rows);
        var ids = new HashSet<int>();
        for (int i = 0; i < rows; i++)
        {
            var row = table.AsSpan(i * head[14]);
            int id = BinaryPrimitives.ReadInt32LittleEndian(row);
            uint rowFlags = BinaryPrimitives.ReadUInt32LittleEndian(row[4..]);
            ulong start = pointer == 8 ? BinaryPrimitives.ReadUInt64LittleEndian(row[8..]) : BinaryPrimitives.ReadUInt32LittleEndian(row[8..]);
            ulong end = pointer == 8 ? BinaryPrimitives.ReadUInt64LittleEndian(row[16..]) : BinaryPrimitives.ReadUInt32LittleEndian(row[12..]);
            if (!ids.Add(id) || id is < 100 or > 1000) return null;
            if (!ToRva(image, start, image.SizeOfImage - 1, out uint startRva)) return null;
            uint endRva = 0;
            if ((rowFlags & 1) != 0 && (!ToRva(image, end, image.SizeOfImage, out endRva) || endRva < startRva)) return null;
            if (relocated && !BinarySearch(relocations, rva + 16 + (uint)(i * head[14]) + 8)) return null;
            sections.Add(new NativeAotSection(id, rowFlags, startRva, endRva));
        }
        return new NativeAotHeader(rva, major, minor, flags, sections, relocated);
    }

    /// <summary>
    /// The major version of the exported DotNetRuntimeDebugHeader ("DNDH" cookie, u16 major), or null when the image has
    /// no such export.
    /// </summary>
    public static int? DebugHeaderMajor(INativeImage image)
    {
        var export = image.Exports.FirstOrDefault(e => e.Name == "DotNetRuntimeDebugHeader" && e.ForwardedTo == null);
        if (export == null) return null;
        Span<byte> b = stackalloc byte[6];
        if (image.Read(export.Rva, b) != b.Length || !b[..4].SequenceEqual("DNDH"u8)) return null;
        return BinaryPrimitives.ReadUInt16LittleEndian(b[4..]);
    }

    private static bool ToRva(INativeImage image, ulong va, uint maxRva, out uint rva)
    {
        rva = 0;
        if (va < image.ImageBase || va - image.ImageBase > maxRva) return false;
        rva = (uint)(va - image.ImageBase);
        return true;
    }

    private static bool BinarySearch(IReadOnlyList<uint> sorted, uint value)
    {
        int lo = 0, hi = sorted.Count - 1;
        while (lo <= hi)
        {
            int mid = (lo + hi) >>> 1;
            if (sorted[mid] == value) return true;
            if (sorted[mid] < value) lo = mid + 1;
            else hi = mid - 1;
        }
        return false;
    }
}
