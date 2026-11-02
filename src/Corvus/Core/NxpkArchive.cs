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

    /// <summary>Lists the index entries by signature with offset, sizes and compression, and extracts the decoded entries within <paramref name="limits"/> (all with <paramref name="allFiles"/>, else those whose content is identified).</summary>
    public static ContainerContents Open(byte[] data, string name, bool allFiles, AnalysisLimits limits, CancellationToken ct)
    {
        var notes = new List<string>();
        var entries = new List<ContainerEntry>();
        var items = new List<ExtractedItem>();
        long total = 0;
        int undecoded = 0, skipped = 0;
        bool stopped = false;
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
            entries.Add(new ContainerEntry($"{sign:x8}", stored, $"{kind}, offset 0x{offset:X}, {stored:N0} stored, {original:N0} original"));
            if (kind == "outside the file" || stopped) continue;
            if (kind == "unknown compression") { undecoded++; continue; }
            if (items.Count >= limits.MaxItems || total + original > limits.MaxTotalBytes) { stopped = true; continue; }
            if (original > limits.MaxItemBytes) { skipped++; continue; }
            byte[]? content;
            try { content = Decode(data.AsSpan((int)offset, (int)stored), kind, original); }
            catch (InvalidDataException ex) { notes.Add($"{sign:x8}: damaged ({ex.Message})"); continue; }
            if (!allFiles && Blob.Identify(content) == "data") continue;
            total += content.Length;
            items.Add(new ExtractedItem($"{sign:x8}.bin", content, $"NXPK entry ({kind})"));
            listed++;
        }
        notes.Insert(0, $"NXPK archive, {count:N0} entr(ies), index at 0x{index:X}" +
                        (kinds.Count > 0 ? " (" + string.Join(", ", kinds.OrderByDescending(k => k.Value).ThenBy(k => k.Key, StringComparer.Ordinal).Select(k => $"{k.Value:N0} {k.Key}")) + ")" : "") + ".");
        notes.Add("Entries are named by signature; the archive stores no file names.");
        if (outside > 0) notes.Add($"{outside:N0} entr(ies) lie outside the file.");
        if (undecoded > 0) notes.Add($"{undecoded:N0} entr(ies) use an unknown compression; listed, not extracted.");
        if (skipped > 0) notes.Add($"{skipped:N0} entr(ies) are over the per-item limit of {limits.MaxItemBytes:N0} bytes; not extracted.");
        if (stopped) notes.Add("Stopped: the extraction limit was reached.");
        return new ContainerContents(Kind, items, notes) { Entries = entries };
    }

    private static string Compression(ReadOnlySpan<byte> head, uint stored, uint original)
    {
        if (head.StartsWith(new byte[] { 0x28, 0xB5, 0x2F, 0xFD })) return "zstd";
        if (head.StartsWith(new byte[] { 0x04, 0x22, 0x4D, 0x18 })) return "lz4 frame";
        if (head.Length >= 2 && head[0] == 0x78 && head[1] is 0x01 or 0x5E or 0x9C or 0xDA) return "zlib";
        return stored == original ? "stored" : "unknown compression";
    }

    // Most one byte expands: Deflate 1032, an LZ4 block 255, a Zstandard RLE block 32768.
    private static byte[] Decode(ReadOnlySpan<byte> packed, string kind, uint original)
    {
        if (kind == "stored") return packed.ToArray();
        long most = (packed.Length + 16L) * (kind switch { "lz4 frame" => 255, "zstd" => 32768, _ => 1032 });
        if (original > most) throw new InvalidDataException($"{original:N0} bytes declared from {packed.Length:N0}, more than {kind} can produce");
        var output = new byte[original];
        int written = kind == "lz4 frame" ? Lz4Frame(packed, output) : UnrealPak.Decode(kind == "zstd" ? "Zstd" : "Zlib", packed, output);
        if (written != original) throw new InvalidDataException($"{written:N0} of {original:N0} bytes decoded");
        return output;
    }

    private static int Lz4Frame(ReadOnlySpan<byte> f, byte[] output)
    {
        if (f.Length < 7) throw new InvalidDataException("truncated LZ4 frame");
        byte flg = f[4];
        bool blockCrc = (flg & 0x10) != 0;
        int at = 6 + ((flg & 0x08) != 0 ? 8 : 0) + ((flg & 0x01) != 0 ? 4 : 0) + 1;
        int written = 0;
        while (true)
        {
            if (at + 4 > f.Length) throw new InvalidDataException("truncated LZ4 frame");
            uint head = BinaryPrimitives.ReadUInt32LittleEndian(f[at..]);
            at += 4;
            if (head == 0) return written;
            int size = (int)(head & 0x7FFFFFFF);
            if (size > f.Length - at) throw new InvalidDataException("LZ4 block runs past the entry");
            var block = f.Slice(at, size);
            at += size + (blockCrc ? 4 : 0);
            if ((head & 0x80000000) != 0)
            {
                if (size > output.Length - written) throw new InvalidDataException("LZ4 frame exceeds the declared size");
                block.CopyTo(output.AsSpan(written));
                written += size;
            }
            else
            {
                int n = K4os.Compression.LZ4.LZ4Codec.Decode(block, output.AsSpan(written));
                if (n < 0) throw new InvalidDataException("corrupt LZ4 block");
                written += n;
            }
        }
    }
}