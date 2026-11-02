using System.Buffers.Binary;

namespace Corvus.Core;

/// <summary>
/// An NXPK archive (.npk): "NXPK", u32 entry count, two u32 fields, u32 index offset,
/// then 28-byte index entries (signature, offset, stored size, original size,
/// stored crc, crc, u16 compression flag, u16 file flag).
/// </summary>
public static class NxpkArchive
{
    public const string Kind = "nxpk archive";
    private const int HeaderSize = 20, EntrySize = 28, MaxEntries = 4_000_000;

    /// <summary>The magic, a count of 1 to 4,000,000 and an index offset past the header.</summary>
    public static bool Looks(ReadOnlySpan<byte> b) =>
        b.Length >= HeaderSize && b[..4].SequenceEqual("NXPK"u8)
        && BinaryPrimitives.ReadUInt32LittleEndian(b[4..]) is >= 1 and <= MaxEntries
        && BinaryPrimitives.ReadUInt32LittleEndian(b[16..]) >= HeaderSize;

    /// <summary>Lists the index entries by signature and reports the count, the index location and the compression kinds sniffed from each entry's first bytes.</summary>
    public static ContainerContents Open(byte[] data, string name, CancellationToken ct)
    {
        var notes = new List<string>();
        var entries = new List<ContainerEntry>();
        uint count = BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan(4));
        uint index = BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan(16));
        var kinds = new SortedDictionary<string, int>(StringComparer.Ordinal);
        int outside = 0;
        long listed = 0;
        for (uint i = 0; i < count; i++)
        {
            ct.ThrowIfCancellationRequested();
            long at = index + (long)i * EntrySize;
            if (at + EntrySize > data.Length) { notes.Add($"The index ends after {i:N0} of {count:N0} entries."); break; }
            var e = data.AsSpan((int)at, EntrySize);
            uint sign = BinaryPrimitives.ReadUInt32LittleEndian(e), offset = BinaryPrimitives.ReadUInt32LittleEndian(e[4..]);
            uint stored = BinaryPrimitives.ReadUInt32LittleEndian(e[8..]), original = BinaryPrimitives.ReadUInt32LittleEndian(e[12..]);
            string kind;
            if ((long)offset + stored > data.Length) { kind = "outside the file"; outside++; }
            else kind = Compression(data.AsSpan((int)offset, (int)Math.Min(stored, 8)), stored, original);
            kinds[kind] = kinds.GetValueOrDefault(kind) + 1;
            entries.Add(new ContainerEntry($"{sign:x8}", stored, kind));
            listed++;
        }
        notes.Insert(0, $"NXPK archive, {count:N0} entr(ies), index at 0x{index:X}" +
                        (kinds.Count > 0 ? " (" + string.Join(", ", kinds.OrderByDescending(k => k.Value).ThenBy(k => k.Key, StringComparer.Ordinal).Select(k => $"{k.Value:N0} {k.Key}")) + ")" : "") + ".");
        notes.Add("Entries are named by signature; the archive stores no file names.");
        if (outside > 0) notes.Add($"{outside:N0} entr(ies) lie outside the file.");
        return new ContainerContents(Kind, [], notes) { Entries = entries };
    }

    private static string Compression(ReadOnlySpan<byte> head, uint stored, uint original)
    {
        if (head.StartsWith(new byte[] { 0x28, 0xB5, 0x2F, 0xFD })) return "zstd";
        if (head.StartsWith(new byte[] { 0x04, 0x22, 0x4D, 0x18 })) return "lz4 frame";
        if (head.Length >= 2 && head[0] == 0x78 && head[1] is 0x01 or 0x5E or 0x9C or 0xDA) return "zlib";
        return stored == original ? "stored" : "unknown compression";
    }
}
