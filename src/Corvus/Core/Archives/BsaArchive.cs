using System.Buffers.Binary;
using System.IO.Compression;
using System.Text;
using Corvus.Core.Firmware;

namespace Corvus.Core.Archives;

/// <summary>
/// A BSA archive, version 103, 104 or 105: a 36-byte header, folder records,
/// per folder a name and file records, a file-name block, then file data.
/// Version 105 compresses with LZ4 frames, earlier versions with zlib.
/// </summary>
public static class BsaArchive
{
    /// <summary>The container kind reported for a BSA archive.</summary>
    public const string Kind = "bsa archive";
    private const int HeaderSize = 36;
    private const uint DirNames = 1, FileNames = 2, Compressed = 4, EmbedNames = 0x100;

    /// <summary>True when the data starts with "BSA" and a NUL and version 103, 104 or 105.</summary>
    public static bool Looks(ReadOnlySpan<byte> b) =>
        b.Length >= HeaderSize && b[0] == 'B' && b[1] == 'S' && b[2] == 'A' && b[3] == 0
        && BinaryPrimitives.ReadUInt32LittleEndian(b[4..]) is 103 or 104 or 105;

    /// <summary>Lists the files with sizes and extracts them within <paramref name="limits"/>; a count or offset past the file is named as malformed and keeps the entries read.</summary>
    public static ContainerContents Open(byte[] data, string name, bool allFiles, AnalysisLimits limits, CancellationToken ct) =>
        Open(new MemoryStream(data, writable: false), name, allFiles, limits, ct);

    /// <summary>Reads the archive from a seekable stream; only the index and the extracted files are held in memory.</summary>
    public static ContainerContents Open(Stream s, string name, bool allFiles, AnalysisLimits limits, CancellationToken ct)
    {
        long fileSize = s.Length;
        var notes = new List<string>();
        var items = new List<ExtractedItem>();
        var entries = new List<ContainerEntry>();
        var names = new List<string>();
        ContainerContents Done()
        {
            notes.AddRange(MemberNames.Notes(names));
            return new ContainerContents(Kind, items, notes) { Entries = entries };
        }

        if (fileSize < HeaderSize)
        {
            notes.Add($"BSA archive cut short: {fileSize:N0} of {HeaderSize} header bytes; entries unknown.");
            return Done();
        }
        var h = Range(s, 0, HeaderSize);
        uint version = BinaryPrimitives.ReadUInt32LittleEndian(h.AsSpan(4));
        uint start = BinaryPrimitives.ReadUInt32LittleEndian(h.AsSpan(8));
        uint flags = BinaryPrimitives.ReadUInt32LittleEndian(h.AsSpan(12));
        uint folderCount = BinaryPrimitives.ReadUInt32LittleEndian(h.AsSpan(16));
        uint fileCount = BinaryPrimitives.ReadUInt32LittleEndian(h.AsSpan(20));
        uint fileNames = BinaryPrimitives.ReadUInt32LittleEndian(h.AsSpan(28));
        int folderRecord = version == 105 ? 24 : 16;
        bool compressed = (flags & Compressed) != 0;
        bool embedded = version >= 104 && (flags & EmbedNames) != 0;
        bool hasFileNames = (flags & FileNames) != 0;
        notes.Add($"BSA archive version {version}, {folderCount:N0} folder(s), {fileCount:N0} file(s).");

        long indexEnd = start + (long)folderCount * folderRecord;
        if (start != HeaderSize || folderCount > fileSize / folderRecord || fileCount > fileSize / 16
            || indexEnd + 16L * fileCount + fileNames > fileSize)
        {
            notes.Add($"BSA index malformed: {folderCount:N0} folder(s) and {fileCount:N0} file(s) do not fit in {fileSize:N0} bytes; entries unknown.");
            return Done();
        }
        if ((flags & (DirNames | FileNames)) != (DirNames | FileNames))
            notes.Add("Archive flags omit folder or file names; unnamed entries are numbered.");

        var index = Range(s, start, (int)(indexEnd - start));
        var folders = new List<(string Name, List<(uint Size, uint Offset)> Files)>();
        long listed = 0, namesAt = indexEnd;
        bool bad = false;
        for (int i = 0; i < folderCount && !bad; i++)
        {
            ct.ThrowIfCancellationRequested();
            var r = index.AsSpan(i * folderRecord, folderRecord);
            uint count = BinaryPrimitives.ReadUInt32LittleEndian(r[8..]);
            long offset = version == 105 ? (long)BinaryPrimitives.ReadUInt64LittleEndian(r[16..]) : BinaryPrimitives.ReadUInt32LittleEndian(r[12..]);
            // A folder offset counts the file-name block length.
            long at = offset - fileNames;
            if (at < indexEnd || at >= fileSize) { bad = true; break; }
            string folder = "";
            if ((flags & DirNames) != 0)
            {
                int len = Range(s, at, 1)[0];
                if (len == 0 || at + 1 + len > fileSize) { bad = true; break; }
                folder = Encoding.UTF8.GetString(Range(s, at + 1, len - 1)).Replace('\\', '/');
                at += 1 + len;
            }
            if (count > (fileSize - at) / 16) { bad = true; break; }
            var rec = Range(s, at, (int)(16 * count));
            var files = new List<(uint, uint)>();
            for (int k = 0; k < count; k++)
                files.Add((BinaryPrimitives.ReadUInt32LittleEndian(rec.AsSpan(k * 16 + 8)), BinaryPrimitives.ReadUInt32LittleEndian(rec.AsSpan(k * 16 + 12))));
            listed += count;
            namesAt = Math.Max(namesAt, at + 16L * count);
            folders.Add((folder, files));
        }
        if (bad || listed != fileCount)
            notes.Add($"BSA folder records malformed: {listed:N0} of {fileCount:N0} file(s) read.");

        // The name block follows the last folder's file records.
        var nameBlock = hasFileNames && namesAt + fileNames <= fileSize ? Range(s, namesAt, (int)fileNames) : [];
        int nameAt = 0, ordinal = 0;
        long total = 0;
        bool stopped = false;
        foreach (var (folder, files) in folders)
        {
            foreach (var (rawSize, offset) in files)
            {
                ct.ThrowIfCancellationRequested();
                string file;
                int e = hasFileNames && nameAt < nameBlock.Length ? Array.IndexOf(nameBlock, (byte)0, nameAt) : -1;
                if (e >= 0) { file = Encoding.UTF8.GetString(nameBlock, nameAt, e - nameAt); nameAt = e + 1; }
                else file = $"file{ordinal:D6}";
                ordinal++;
                string path = (folder.Length > 0 ? folder + "/" : "") + file;
                long size = rawSize & 0x3FFFFFFF;
                // Bit 30 of the size inverts the archive's compression flag.
                bool packed = compressed ^ ((rawSize & 0x40000000) != 0);
                names.Add(path);
                var detail = $"offset 0x{offset:X}, {(packed ? (version == 105 ? "lz4 frame" : "zlib") : "stored")}";
                if (offset + size > fileSize)
                {
                    entries.Add(new ContainerEntry(path, size, detail + ", outside the file"));
                    notes.Add($"{path}: data lies outside the file; not extracted.");
                    continue;
                }
                if (stopped) { entries.Add(new ContainerEntry(path, size, detail)); continue; }
                try
                {
                    var content = Read(s, offset, size, packed, embedded, version, limits, out long original);
                    entries.Add(new ContainerEntry(path, original, detail));
                    if (content == null) { notes.Add($"{path}: over the per-item limit of {limits.MaxItemBytes:N0} bytes; not extracted."); continue; }
                    if (items.Count >= limits.MaxItems || total + content.Length > limits.MaxTotalBytes) { stopped = true; continue; }
                    if (!allFiles && Blob.Identify(content) == "data") continue;
                    total += content.Length;
                    items.Add(new ExtractedItem(Blob.SafeRelativePath(path, "file"), content, "BSA entry") { Member = true });
                }
                catch (InvalidDataException ex)
                {
                    entries.Add(new ContainerEntry(path, size, detail));
                    notes.Add($"{path}: {ex.Message}; not extracted.");
                }
            }
        }
        if (stopped) notes.Add("Stopped: the extraction limit was reached.");
        return Done();
    }

    // Returns null when the file is over the per-item limit.
    private static byte[]? Read(Stream s, long offset, long size, bool packed, bool embedded, uint version, AnalysisLimits limits, out long original)
    {
        original = size;
        if (size > limits.MaxItemBytes && !packed) return null;
        var raw = Range(s, offset, (int)Math.Min(size, int.MaxValue / 2));
        int at = 0;
        if (embedded)
        {
            if (raw.Length < 1 || raw[0] + 1 > raw.Length) throw new InvalidDataException("embedded name runs past the entry");
            at = raw[0] + 1;
        }
        if (!packed)
        {
            original = raw.Length - at;
            return raw.AsSpan(at).ToArray();
        }
        if (raw.Length - at < 4) throw new InvalidDataException("compressed entry lacks its original size");
        original = BinaryPrimitives.ReadUInt32LittleEndian(raw.AsSpan(at));
        if (original > limits.MaxItemBytes) return null;
        var body = raw.AsSpan(at + 4);
        // The most one input byte expands to: Deflate 1032, an LZ4 block 255.
        if (original > (body.Length + 16L) * (version == 105 ? 255 : 1032))
            throw new InvalidDataException($"{original:N0} bytes declared from {body.Length:N0}, more than the codec can produce");
        byte[] output;
        try
        {
            if (version == 105) output = FsCodec.DecodeStream("lz4", body, original);
            else
            {
                using var z = new ZLibStream(new MemoryStream(body.ToArray(), writable: false), CompressionMode.Decompress);
                output = Blob.ReadBounded(z, original) ?? throw new InvalidDataException($"decodes past {original:N0} bytes");
            }
        }
        catch (Exception ex) when (ex is InvalidDataException or IOException)
        {
            throw new InvalidDataException($"damaged data: {ex.Message}", ex);
        }
        if (output.Length != original) throw new InvalidDataException($"{output.Length:N0} of {original:N0} bytes decoded");
        return output;
    }

    private static byte[] Range(Stream s, long at, int n)
    {
        var b = new byte[n];
        s.Position = at;
        s.ReadExactly(b);
        return b;
    }
}
