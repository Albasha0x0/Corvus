using System.Buffers.Binary;
using System.Text;

namespace Corvus.Core.Archives;

/// <summary>
/// A VPK package, version 1 or 2: a header, a directory tree of extension,
/// path and name strings with an 18-byte record each, then file data. Data
/// of archive index 0x7FFF follows the tree; other indexes name _NNN.vpk
/// siblings.
/// </summary>
public static class VpkArchive
{
    /// <summary>The container kind reported for a VPK package.</summary>
    public const string Kind = "vpk archive";
    private const uint Signature = 0x55AA1234;
    private const ushort InFile = 0x7FFF;
    private const int RecordSize = 18;

    /// <summary>True when the data starts with the signature 0x55AA1234 and version 1 or 2.</summary>
    public static bool Looks(ReadOnlySpan<byte> b) =>
        b.Length >= 12 && BinaryPrimitives.ReadUInt32LittleEndian(b) == Signature
        && BinaryPrimitives.ReadUInt32LittleEndian(b[4..]) is 1 or 2;

    /// <summary>Lists the directory paths with sizes and extracts files held in this file within <paramref name="limits"/>; files in sibling archives are listed and named as not opened; a cut directory is named as malformed and keeps the entries read.</summary>
    public static ContainerContents Open(byte[] data, string name, bool allFiles, AnalysisLimits limits, CancellationToken ct) =>
        Open(new MemoryStream(data, writable: false), name, allFiles, limits, ct);

    /// <summary>Reads the package from a seekable stream; only the directory tree and the extracted files are held in memory.</summary>
    public static ContainerContents Open(Stream s, string name, bool allFiles, AnalysisLimits limits, CancellationToken ct)
    {
        long fileSize = s.Length;
        var notes = new List<string>();
        var items = new List<ExtractedItem>();
        var entries = new List<ContainerEntry>();
        var head = Range(s, 0, (int)Math.Min(fileSize, 28));
        uint version = head.Length >= 8 ? BinaryPrimitives.ReadUInt32LittleEndian(head.AsSpan(4)) : 0;
        int header = version == 2 ? 28 : 12;
        if (fileSize < header)
        {
            notes.Add($"VPK archive cut short: {fileSize:N0} of {header} header bytes; entries unknown.");
            return new ContainerContents(Kind, items, notes) { Entries = entries };
        }
        uint treeSize = BinaryPrimitives.ReadUInt32LittleEndian(head.AsSpan(8));
        long treeEnd = (long)header + treeSize;
        long dataBase = treeEnd;
        // The tree is read whole, so a header naming a larger tree is read up to the per-item limit.
        long treeLimit = Math.Min(limits.MaxItemBytes, int.MaxValue / 2);
        bool overLimit = Math.Min(treeEnd, fileSize) > treeLimit;
        int end = (int)Math.Min(Math.Min(treeEnd, fileSize), treeLimit);
        bool cut = treeEnd > end;
        var data = Range(s, 0, end);
        var siblings = new SortedDictionary<int, int>();
        var names = new List<string>();
        long total = 0;
        bool stopped = false;
        int at = header, badRecord = 0;

        string? Text()
        {
            int e = Array.IndexOf(data, (byte)0, at, end - at);
            if (e < 0) return null;
            var s = Encoding.UTF8.GetString(data, at, e - at);
            at = e + 1;
            return s;
        }

        while (!cut || at < end)
        {
            var ext = Text();
            if (ext == null) { cut = true; break; }
            if (ext.Length == 0) break;
            string? dir, file = null;
            while ((dir = Text()) is { Length: > 0 })
            {
                while ((file = Text()) is { Length: > 0 })
                {
                    ct.ThrowIfCancellationRequested();
                    if (at + RecordSize > end) { cut = true; break; }
                    var r = data.AsSpan(at, RecordSize);
                    ushort preload = BinaryPrimitives.ReadUInt16LittleEndian(r[4..]), archive = BinaryPrimitives.ReadUInt16LittleEndian(r[6..]);
                    uint offset = BinaryPrimitives.ReadUInt32LittleEndian(r[8..]), length = BinaryPrimitives.ReadUInt32LittleEndian(r[12..]);
                    if (BinaryPrimitives.ReadUInt16LittleEndian(r[16..]) != 0xFFFF) { badRecord++; cut = true; break; }
                    at += RecordSize;
                    int preloadAt = at;
                    if (preload > end - at) { cut = true; break; }
                    at += preload;
                    string path = (dir == " " ? "" : dir + "/") + (file == " " ? "" : file) + (ext == " " ? "" : "." + ext);
                    long size = (long)preload + length;
                    names.Add(path);
                    bool here = archive == InFile;
                    string where = here ? $"offset 0x{dataBase + offset:X}" : $"archive {archive:000}, offset 0x{offset:X}";
                    if (preload > 0) where += $", {preload:N0} preload bytes";
                    if (!here)
                    {
                        siblings[archive] = siblings.GetValueOrDefault(archive) + 1;
                        entries.Add(new ContainerEntry(path, size, $"{where}, not opened"));
                        continue;
                    }
                    if (dataBase + offset + length > fileSize)
                    {
                        entries.Add(new ContainerEntry(path, size, $"{where}, outside the file"));
                        notes.Add($"{path}: data lies outside the file; not extracted.");
                        continue;
                    }
                    entries.Add(new ContainerEntry(path, size, where));
                    if (stopped) continue;
                    if (items.Count >= limits.MaxItems || total + size > limits.MaxTotalBytes) { stopped = true; continue; }
                    if (size > limits.MaxItemBytes) { notes.Add($"{path}: over the per-item limit of {limits.MaxItemBytes:N0} bytes; not extracted."); continue; }
                    var content = new byte[size];
                    Buffer.BlockCopy(data, preloadAt, content, 0, preload);
                    s.Position = dataBase + offset;
                    s.ReadExactly(content.AsSpan(preload));
                    if (!allFiles && Blob.Identify(content) == "data") continue;
                    total += size;
                    items.Add(new ExtractedItem(Blob.SafeRelativePath(path, "file"), content, "VPK entry") { Member = true });
                }
                if (cut || file == null) { cut = true; break; }
            }
            if (cut || dir == null) { cut = true; break; }
        }

        notes.Insert(0, $"VPK archive version {version}, {entries.Count:N0} entr(ies), directory of {treeSize:N0} bytes.");
        if (version == 2 && head.Length >= 28)
        {
            var h = head.AsSpan();
            notes.Add($"Version 2 sections, sizes only and not verified: file data {BinaryPrimitives.ReadUInt32LittleEndian(h[12..]):N0}, archive checksums {BinaryPrimitives.ReadUInt32LittleEndian(h[16..]):N0}, other checksums {BinaryPrimitives.ReadUInt32LittleEndian(h[20..]):N0}, signature {BinaryPrimitives.ReadUInt32LittleEndian(h[24..]):N0} bytes.");
        }
        if (overLimit)
            notes.Add($"VPK directory of {treeSize:N0} bytes is over the per-item limit of {treeLimit:N0} bytes; {entries.Count:N0} entr(ies) read from its start.");
        else if (cut)
            notes.Add(badRecord > 0
                ? $"VPK directory malformed: an entry record lacks its terminator; {entries.Count:N0} entr(ies) read."
                : $"VPK directory malformed: it ends early; {entries.Count:N0} entr(ies) read.");
        foreach (var (index, count) in siblings)
            notes.Add($"{count:N0} entr(ies) are in {SiblingName(name, index)}, not opened.");
        notes.AddRange(MemberNames.Notes(names));
        if (stopped) notes.Add("Stopped: the extraction limit was reached.");
        return new ContainerContents(Kind, items, notes) { Entries = entries };
    }

    private static byte[] Range(Stream s, long at, int n)
    {
        var b = new byte[n];
        s.Position = at;
        s.ReadExactly(b);
        return b;
    }

    // A directory file "x_dir.vpk" has data in "x_NNN.vpk".
    private static string SiblingName(string name, int index)
    {
        var file = Path.GetFileName(name);
        var stem = Path.GetFileNameWithoutExtension(file);
        if (stem.EndsWith("_dir", StringComparison.OrdinalIgnoreCase)) stem = stem[..^4];
        return $"{stem}_{index:000}.vpk";
    }
}
