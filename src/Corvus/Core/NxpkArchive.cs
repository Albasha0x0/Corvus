using System.Buffers.Binary;
using Corvus.Core.Firmware;

namespace Corvus.Core;

/// <summary>
/// An NXPK archive (.npk): "NXPK", u32 entry count, three u32 fields, u32 index offset,
/// then 28-byte index entries (signature, offset, stored size, original size,
/// stored crc, crc, u16 compression flag, u16 file flag), then an optional
/// "NXFN" name table: u32 0, u32 size, u32 size, NUL-terminated paths in index order.
/// </summary>
public static class NxpkArchive
{
    /// <summary>The container kind reported for an NXPK archive.</summary>
    public const string Kind = "nxpk archive";
    private const int HeaderSize = 24, EntrySize = 28, MaxDamagedNotes = 5, MaxRefusedNotes = 5, MaxSamples = 4;
    private const long MaxNameTable = 256L << 20;

    /// <summary>The magic, a count of 1 to 4,000,000 and an index offset past the header.</summary>
    public static bool Looks(ReadOnlySpan<byte> b) =>
        b.Length >= HeaderSize && FirmwareSignatures.Holds(b, long.MaxValue, "NXPK archive");

    /// <summary>Lists the index entries by signature with offset, sizes and compression, and extracts the decoded entries within <paramref name="limits"/> (all with <paramref name="allFiles"/>, else those whose content is identified).</summary>
    public static ContainerContents Open(byte[] data, string name, bool allFiles, AnalysisLimits limits, CancellationToken ct, string? location = null) =>
        Open(new MemoryStream(data, writable: false), name, allFiles, limits, ct, location);

    /// <summary>Reads the archive from a seekable stream; only the index and the extracted entries are held in memory. With <paramref name="location"/>, a missing Zstandard dictionary is searched for in the executables of that file's folder.</summary>
    public static ContainerContents Open(Stream s, string name, bool allFiles, AnalysisLimits limits, CancellationToken ct, string? location = null)
    {
        long length = s.Length;
        var notes = new List<string>();
        if (length < HeaderSize)
        {
            notes.Add($"NXPK archive cut short: {length:N0} of {HeaderSize} header bytes; entries unknown.");
            return new ContainerContents(Kind, [], notes) { Entries = [] };
        }
        var header = Range(s, 0, HeaderSize);
        var entries = new List<ContainerEntry>();
        var items = new List<ExtractedItem>();
        long total = 0;
        int undecoded = 0, skipped = 0, damaged = 0;
        var dictionaries = new SortedDictionary<uint, List<Pending>>();
        bool stopped = false;
        uint count = BinaryPrimitives.ReadUInt32LittleEndian(header.AsSpan(4));
        uint index = BinaryPrimitives.ReadUInt32LittleEndian(header.AsSpan(20));
        var kinds = new SortedDictionary<string, int>(StringComparer.Ordinal);
        int outside = 0, refused = 0;
        var issues = new List<NameIssue>();
        var table = index >= length ? [] : Range(s, index, (int)Math.Min(length - index, (long)count * EntrySize));
        bool whole = table.Length == (long)count * EntrySize;
        var names = whole ? ReadNames(s, index + (long)count * EntrySize, count, notes, out bool hasTable) : NoTable(out hasTable);
        for (uint i = 0; i < count; i++)
        {
            ct.ThrowIfCancellationRequested();
            long at = (long)i * EntrySize;
            if (at + EntrySize > table.Length) { notes.Add($"The index ends after {i:N0} of {count:N0} entries."); break; }
            var e = table.AsSpan((int)at, EntrySize);
            uint sign = BinaryPrimitives.ReadUInt32LittleEndian(e), offset = BinaryPrimitives.ReadUInt32LittleEndian(e[4..]);
            uint stored = BinaryPrimitives.ReadUInt32LittleEndian(e[8..]), original = BinaryPrimitives.ReadUInt32LittleEndian(e[12..]);
            string label = $"{sign:x8}";
            bool named = false;
            if (i < names.Count && names[(int)i].Length > 0)
            {
                string given = names[(int)i];
                if (MemberNames.PathConcern(given) is { } why)
                {
                    issues.Add(new NameIssue("unsafe-path", given, why));
                    if (++refused <= MaxRefusedNotes) notes.Add($"{label}: name '{MemberNames.Show(given)}' refused ({why}); kept as the signature.");
                }
                else { label = given; named = true; }
            }
            string kind;
            if ((long)offset + stored > length) { kind = "outside the file"; outside++; }
            else kind = Compression(Range(s, offset, (int)Math.Min(stored, 8)), stored, original);
            kinds[kind] = kinds.GetValueOrDefault(kind) + 1;
            entries.Add(new ContainerEntry(label, stored, $"{kind}, offset 0x{offset:X}, {stored:N0} stored, {original:N0} original"));
            if (kind == "outside the file" || stopped) continue;
            if (kind == "unknown compression") { undecoded++; continue; }
            if (items.Count >= limits.MaxItems || total + original > limits.MaxTotalBytes) { stopped = true; continue; }
            // Bound the stored bytes too: they are read whole and must fit an array.
            if (original > limits.MaxItemBytes || stored > limits.MaxItemBytes || stored > int.MaxValue) { skipped++; continue; }
            var packed = Range(s, offset, (int)stored);
            if (kind == "zstd" && DictionaryId(packed) is { } dict and not 0)
            {
                if (!dictionaries.TryGetValue(dict, out var waiting)) dictionaries[dict] = waiting = [];
                waiting.Add(new Pending(sign, label, named, offset, stored, original, BinaryPrimitives.ReadUInt32LittleEndian(e[16..]), BinaryPrimitives.ReadUInt32LittleEndian(e[20..])));
                continue;
            }
            byte[] content;
            try { content = Decode(packed, kind, original); }
            catch (InvalidDataException ex)
            {
                if (++damaged <= MaxDamagedNotes) notes.Add($"{sign:x8}: damaged ({ex.Message})");
                continue;
            }
            if (!allFiles && Blob.Identify(content) == "data") continue;
            total += content.Length;
            items.Add(Item(sign, label, named, content, kind));
        }
        if (dictionaries.Count > 0 && location is { Length: > 0 } && Path.GetDirectoryName(Path.GetFullPath(location)) is { } folder)
        {
            foreach (var (id, waiting) in dictionaries.ToList())
            {
                var samples = waiting.Take(MaxSamples).Select(w => new ZstdSample(Range(s, w.Offset, (int)w.Stored), w.Original, w.CrcA, w.CrcB)).ToList();
                var found = ZstdDictionaryLocator.Find(folder, id, samples, notes, ct);
                if (found is null) continue;
                notes.Add($"Zstandard dictionary {id} read from {Path.GetFileName(found.File)} at offset 0x{found.Offset:X}, {found.Bytes.Length:N0} bytes; {waiting.Count:N0} entr(ies) decoded with it.");
                dictionaries.Remove(id);
                foreach (var w in waiting)
                {
                    ct.ThrowIfCancellationRequested();
                    if (stopped) break;
                    if (items.Count >= limits.MaxItems || total + w.Original > limits.MaxTotalBytes) { stopped = true; break; }
                    byte[] content;
                    try { content = ZstdDictionaryLocator.Decode(found.Bytes, Range(s, w.Offset, (int)w.Stored), w.Original); }
                    catch (InvalidDataException ex)
                    {
                        if (++damaged <= MaxDamagedNotes) notes.Add($"{w.Sign:x8}: damaged ({ex.Message})");
                        continue;
                    }
                    if (!allFiles && Blob.Identify(content) == "data") continue;
                    total += content.Length;
                    items.Add(Item(w.Sign, w.Label, w.Named, content, "zstd"));
                }
            }
        }
        notes.Insert(0, $"NXPK archive, {count:N0} entr(ies), index at 0x{index:X}" +
                        (kinds.Count > 0 ? " (" + string.Join(", ", kinds.OrderByDescending(k => k.Value).ThenBy(k => k.Key, StringComparer.Ordinal).Select(k => $"{k.Value:N0} {k.Key}")) + ")" : "") + ".");
        if (!hasTable) notes.Add(whole
            ? "Entries are named by signature; the archive stores no file names."
            : "Entries are named by signature; the name table is unknown because the index is cut short.");
        if (refused > MaxRefusedNotes) notes.Add($"{refused - MaxRefusedNotes:N0} more unsafe names not listed.");
        if (outside > 0) notes.Add($"{outside:N0} entr(ies) lie outside the file.");
        if (damaged > MaxDamagedNotes) notes.Add($"{damaged - MaxDamagedNotes:N0} more damaged entr(ies) not named.");
        if (dictionaries.Count > 0) notes.Add($"{dictionaries.Values.Sum(w => w.Count):N0} zstd entr(ies) need a trained dictionary the archive does not hold (ids {string.Join(", ", dictionaries.Take(8).Select(d => $"{d.Key} x{d.Value.Count:N0}"))}); listed, not extracted.");
        if (undecoded > 0) notes.Add($"{undecoded:N0} entr(ies) use an unknown compression; listed, not extracted.");
        if (skipped > 0) notes.Add($"{skipped:N0} entr(ies) are over the per-item limit of {limits.MaxItemBytes:N0} bytes; not extracted.");
        if (stopped) notes.Add("Stopped: the extraction limit was reached.");
        return new ContainerContents(Kind, items, notes) { Entries = entries, Names = hasTable ? issues : null };
    }

    private readonly record struct Pending(uint Sign, string Label, bool Named, uint Offset, uint Stored, uint Original, uint CrcA, uint CrcB);

    private static ExtractedItem Item(uint sign, string label, bool named, byte[] content, string kind) => named
        ? new ExtractedItem(Blob.SafeRelativePath(label, $"{sign:x8}"), content, $"NXPK entry ({kind})") { Member = true }
        : new ExtractedItem($"{sign:x8}.bin", content, $"NXPK entry ({kind})");

    private static List<string> NoTable(out bool hasTable)
    {
        hasTable = false;
        return [];
    }

    // The name table follows the index; a short or oversized table keeps the names read.
    private static List<string> ReadNames(Stream s, long at, uint count, List<string> notes, out bool hasTable)
    {
        var names = new List<string>();
        hasTable = false;
        if (at + 16 > s.Length || !Range(s, at, 4).AsSpan().SequenceEqual("NXFN"u8)) return names;
        hasTable = true;
        var head = Range(s, at + 4, 12);
        uint size = BinaryPrimitives.ReadUInt32LittleEndian(head.AsSpan(4)), again = BinaryPrimitives.ReadUInt32LittleEndian(head.AsSpan(8));
        long room = s.Length - (at + 16);
        long take = Math.Min(Math.Min(size, room), MaxNameTable);
        bool partial = false;
        if (size != again) { notes.Add($"NXPK name table declares two sizes ({size:N0}, {again:N0}); the first is used."); partial = true; }
        if (size > room) { notes.Add($"NXPK name table declares {size:N0} bytes, {room:N0} remain; partial."); partial = true; }
        else if (size > MaxNameTable) { notes.Add($"NXPK name table is over the limit of {MaxNameTable:N0} bytes; partial."); partial = true; }
        var block = Range(s, at + 16, (int)take);
        int pos = 0;
        while (pos < block.Length && names.Count < count)
        {
            int end = Array.IndexOf(block, (byte)0, pos);
            if (end < 0) { notes.Add("NXPK name table ends inside a name; the last name is dropped."); partial = true; break; }
            names.Add(System.Text.Encoding.UTF8.GetString(block, pos, end - pos));
            pos = end + 1;
        }
        if (names.Count < count)
        {
            notes.Add($"NXPK name table holds {names.Count:N0} of {count:N0} names; the rest keep the signature.");
            partial = true;
        }
        if (!partial) notes.Add($"NXPK name table: {names.Count:N0} names.");
        return names;
    }

    // The frame header names the dictionary in 0, 1, 2 or 4 bytes after the window descriptor.
    private static uint? DictionaryId(ReadOnlySpan<byte> frame)
    {
        if (frame.Length < 6) return null;
        byte fhd = frame[4];
        int size = (fhd & 3) switch { 0 => 0, 1 => 1, 2 => 2, _ => 4 };
        int at = 5 + ((fhd & 0x20) != 0 ? 0 : 1);
        if (at + size > frame.Length) return null;
        uint id = 0;
        for (int i = 0; i < size; i++) id |= (uint)frame[at + i] << (8 * i);
        return id;
    }

    private static byte[] Range(Stream s, long at, int n)
    {
        var b = new byte[n];
        s.Position = at;
        s.ReadExactly(b);
        return b;
    }

    private static string Compression(ReadOnlySpan<byte> head, uint stored, uint original)
    {
        // The index declares each entry's sizes, so the magic names the codec.
        if (FirmwareSignatures.StartsWithMagic(head, "Zstandard compressed data")) return "zstd";
        if (FirmwareSignatures.StartsWithMagic(head, "LZ4 compressed data")) return "lz4 frame";
        if (Blob.Identify(head) == "zlib") return "zlib";
        return stored == original ? "stored" : "unknown compression";
    }

    // The most one input byte expands to: Deflate 1032, an LZ4 block 255, a Zstandard RLE block 32768.
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
