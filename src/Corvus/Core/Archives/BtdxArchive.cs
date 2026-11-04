using System.Buffers.Binary;
using System.Text;

namespace Corvus.Core.Archives;

/// <summary>
/// A BA2 archive (magic "BTDX"), versions 1 to 3: a header, one record per
/// file, file data, then a name table of 16-bit length strings. General
/// archives (GNRL) are extracted; texture archives (DX10) are listed.
/// </summary>
public static class BtdxArchive
{
    /// <summary>The container kind reported for a BA2 archive.</summary>
    public const string Kind = "ba2 archive";
    private const int GeneralRecord = 36, TextureRecord = 24, ChunkRecord = 24;

    /// <summary>True when the data starts with "BTDX", version 1 to 3 and a 4-letter type.</summary>
    public static bool Looks(ReadOnlySpan<byte> b) =>
        b.Length >= 24 && b[0] == 'B' && b[1] == 'T' && b[2] == 'D' && b[3] == 'X'
        && BinaryPrimitives.ReadUInt32LittleEndian(b[4..]) is >= 1 and <= 3
        && b[8..12].ToArray().All(c => c is >= (byte)'A' and <= (byte)'Z' or >= (byte)'0' and <= (byte)'9');

    /// <summary>Lists the files with sizes and extracts general archives within <paramref name="limits"/>; texture archives are listed with chunk counts; a name table or record past the file is named as malformed.</summary>
    public static ContainerContents Open(byte[] data, string name, bool allFiles, AnalysisLimits limits, CancellationToken ct) =>
        Open(new MemoryStream(data, writable: false), name, allFiles, limits, ct);

    /// <summary>Reads the archive from a seekable stream; only the records, the name table and the extracted files are held in memory.</summary>
    public static ContainerContents Open(Stream s, string name, bool allFiles, AnalysisLimits limits, CancellationToken ct)
    {
        long fileSize = s.Length;
        var listing = new PackedEntry.Listing(Kind);
        var (notes, items, entries, names) = (listing.Notes, listing.Items, listing.Entries, listing.Names);
        ContainerContents Done() => listing.Done();

        var h = PackedEntry.Range(s, 0, (int)Math.Min(fileSize, 40));
        if (h.Length < 24)
        {
            notes.Add($"BA2 archive cut short: {fileSize:N0} of 24 header bytes; entries unknown.");
            return Done();
        }
        uint version = BinaryPrimitives.ReadUInt32LittleEndian(h.AsSpan(4));
        string type = Encoding.ASCII.GetString(h, 8, 4);
        uint count = BinaryPrimitives.ReadUInt32LittleEndian(h.AsSpan(12));
        ulong nameTable = BinaryPrimitives.ReadUInt64LittleEndian(h.AsSpan(16));
        int header = version switch { 1 => 24, 2 => 32, _ => 36 };
        // Version 3 names its codec: 3 is an LZ4 block, otherwise zlib.
        bool lz4 = version == 3 && h.Length >= 36 && BinaryPrimitives.ReadUInt32LittleEndian(h.AsSpan(32)) == 3;
        notes.Add($"BA2 archive version {version}, type {type}, {count:N0} file(s).");
        if (type is not ("GNRL" or "DX10"))
        {
            notes.Add($"Archive type {type} is not read; entries unknown.");
            return Done();
        }
        if (fileSize < header || nameTable > (ulong)fileSize || count > fileSize / TextureRecord)
        {
            notes.Add($"BA2 index malformed: {count:N0} file(s) and a name table at {nameTable:N0} do not fit in {fileSize:N0} bytes; entries unknown.");
            return Done();
        }

        var table = new List<string>();
        long pos = (long)nameTable;
        for (uint i = 0; i < count; i++)
        {
            if (pos + 2 > fileSize) break;
            int len = BinaryPrimitives.ReadUInt16LittleEndian(PackedEntry.Range(s, pos, 2));
            if (pos + 2 + len > fileSize) break;
            table.Add(Encoding.UTF8.GetString(PackedEntry.Range(s, pos + 2, len)).Replace('\\', '/'));
            pos += 2 + len;
        }
        if (table.Count < count)
            notes.Add($"BA2 name table malformed: {table.Count:N0} of {count:N0} name(s) read; unnamed entries are numbered.");

        long at = header, total = 0;
        bool stopped = false;
        for (int i = 0; i < count; i++)
        {
            ct.ThrowIfCancellationRequested();
            string path = i < table.Count ? table[i] : $"file{i:D6}";
            names.Add(path);
            if (type == "DX10")
            {
                if (at + TextureRecord > fileSize) { notes.Add("BA2 records end early."); break; }
                var r = PackedEntry.Range(s, at, TextureRecord);
                int chunks = r[13];
                if (at + TextureRecord + (long)chunks * ChunkRecord > fileSize) { notes.Add("BA2 records end early."); break; }
                var cs = PackedEntry.Range(s, at + TextureRecord, chunks * ChunkRecord);
                long unpacked = 0;
                for (int c = 0; c < chunks; c++) unpacked += BinaryPrimitives.ReadUInt32LittleEndian(cs.AsSpan(c * ChunkRecord + 12));
                entries.Add(new ContainerEntry(path, unpacked, $"{chunks:N0} chunk(s), not extracted: texture chunks"));
                at += TextureRecord + (long)chunks * ChunkRecord;
                continue;
            }
            if (at + GeneralRecord > fileSize) { notes.Add("BA2 records end early."); break; }
            var g = PackedEntry.Range(s, at, GeneralRecord);
            at += GeneralRecord;
            // An offset past the signed range lies outside the file.
            ulong rawOffset = BinaryPrimitives.ReadUInt64LittleEndian(g.AsSpan(16));
            long offset = rawOffset > long.MaxValue / 2 ? long.MaxValue / 2 : (long)rawOffset;
            uint packed = BinaryPrimitives.ReadUInt32LittleEndian(g.AsSpan(24)), original = BinaryPrimitives.ReadUInt32LittleEndian(g.AsSpan(28));
            long stored = packed == 0 ? original : packed;
            var detail = $"offset 0x{offset:X}, {(packed == 0 ? "stored" : lz4 ? "lz4 block" : "zlib")}";
            if (offset + stored > fileSize)
            {
                entries.Add(new ContainerEntry(path, original, detail + ", outside the file"));
                notes.Add($"{path}: data lies outside the file; not extracted.");
                continue;
            }
            entries.Add(new ContainerEntry(path, original, detail));
            if (stopped) continue;
            if (items.Count >= limits.MaxItems || total + original > limits.MaxTotalBytes) { stopped = true; continue; }
            if (original > limits.MaxItemBytes) { notes.Add($"{path}: over the per-item limit of {limits.MaxItemBytes:N0} bytes; not extracted."); continue; }
            try
            {
                var content = Decode(PackedEntry.Range(s, offset, (int)stored), packed == 0, lz4, original);
                if (!allFiles && Blob.Identify(content) == "data") continue;
                total += content.Length;
                items.Add(new ExtractedItem(Blob.SafeRelativePath(path, "file"), content, "BA2 entry") { Member = true });
            }
            catch (InvalidDataException ex)
            {
                notes.Add($"{path}: {ex.Message}; not extracted.");
            }
        }
        if (stopped) notes.Add("Stopped: the extraction limit was reached.");
        return Done();
    }

    // BA2 stores LZ4 blocks, not frames.
    private static byte[] Decode(byte[] body, bool stored, bool lz4, uint original) =>
        stored ? body : PackedEntry.Decode(body, original, lz4 ? Lz4Block : null);

    private static byte[] Lz4Block(byte[] body, long original)
    {
        var output = new byte[original];
        int n = K4os.Compression.LZ4.LZ4Codec.Decode(body, output);
        if (n != original) throw new InvalidDataException($"{Math.Max(n, 0):N0} of {original:N0} bytes decoded");
        return output;
    }
}
