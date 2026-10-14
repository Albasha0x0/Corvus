using System.Buffers.Binary;
using System.IO.Compression;
using System.Text;
using System.Xml;

namespace Corvus.Core.Archives;

/// <summary>Entries of a simple archive, extracted within the limits; shared by the xar and cpio readers.</summary>
internal static class ArchiveItems
{
    public static void Take(List<ExtractedItem> items, List<ContainerEntry> entries, string kind, string path, byte[] bytes, bool allFiles, AnalysisLimits limits, ref long total)
    {
        entries.Add(new ContainerEntry(path, bytes.Length));
        if (items.Count >= limits.MaxItems) return;
        total += bytes.Length;
        if (total > limits.MaxTotalBytes)
            throw new ToolError(ErrorCode.LimitExceeded, $"extracting {path} passes the {limits.MaxTotalBytes:N0}-byte total limit.", "unpack fewer files or raise the limits");
        if (allFiles || Blob.Identify(bytes) is ".NET assembly" or "native PE" or "NativeAOT executable" or "elf" or "mach-o" or "zip" or "gzip" or "7z" or "asar" or "wasm"
            || XarReader.IsXar(bytes) || CpioReader.IsCpio(bytes))
            items.Add(new ExtractedItem(path, bytes, $"{kind} entry"));
    }
}

/// <summary>xar archives (macOS .pkg, .xip): the zlib-compressed XML table of contents, then each file's data from the heap.</summary>
internal sealed class XarReader : IContainerReader
{
    public string Kind => "xar";

    public static bool IsXar(ReadOnlySpan<byte> b) => b.Length >= 28 && b.StartsWith("xar!"u8);

    public bool Accepts(ReadOnlySpan<byte> data, string name) => IsXar(data);

    public ContainerContents Open(byte[] data, string name, bool allFiles, AnalysisLimits limits, CancellationToken ct)
    {
        int headerSize = BinaryPrimitives.ReadUInt16BigEndian(data.AsSpan(4));
        long tocCompressed = (long)BinaryPrimitives.ReadUInt64BigEndian(data.AsSpan(8));
        // the length is unsigned on disk: one past 2^63 reads negative
        if (headerSize < 28 || tocCompressed < 0 || tocCompressed > data.Length || headerSize + tocCompressed > data.Length)
            throw new ToolError(ErrorCode.MalformedInput, $"{name}: the xar table of contents runs past the end.");
        var doc = new XmlDocument { XmlResolver = null };
        try
        {
            using var z = new ZLibStream(new MemoryStream(data, headerSize, (int)tocCompressed), CompressionMode.Decompress);
            using var xml = XmlReader.Create(z, new XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null, MaxCharactersInDocument = 64L * 1024 * 1024 });
            doc.Load(xml);
        }
        catch (Exception ex) when (ex is XmlException or InvalidDataException)
        {
            throw new ToolError(ErrorCode.MalformedInput, $"{name}: unreadable xar table of contents: {ex.Message}");
        }
        long heap = headerSize + tocCompressed;
        var items = new List<ExtractedItem>();
        var entries = new List<ContainerEntry>();
        var notes = new List<string>();
        long total = 0;
        void Walk(XmlNode parent, string prefix)
        {
            foreach (XmlNode file in parent.SelectNodes("file")!)
            {
                ct.ThrowIfCancellationRequested();
                var fileName = file["name"]?.InnerText ?? "";
                if (fileName.Length == 0 || fileName.Contains('/') || fileName is "." or "..") continue;
                var path = prefix + fileName;
                if (file["type"]?.InnerText == "directory") { Walk(file, path + "/"); continue; }
                if (file["data"] is not { } d) continue;
                if (!long.TryParse(d["offset"]?.InnerText, out long offset) || !long.TryParse(d["length"]?.InnerText, out long length)) { notes.Add($"{path}: no data offset"); continue; }
                var encoding = d["encoding"]?.GetAttribute("style") ?? "";
                if (offset < 0 || length < 0 || length > limits.MaxItemBytes || heap + offset + length > data.Length) { notes.Add($"{path}: data outside the archive or over the item limit"); continue; }
                byte[] bytes = data.AsSpan((int)(heap + offset), (int)length).ToArray();
                if (encoding.Contains("gzip", StringComparison.Ordinal))
                {
                    // xar's "gzip" style is a zlib stream
                    using var z = new ZLibStream(new MemoryStream(bytes), CompressionMode.Decompress);
                    using var copy = new MemoryStream();
                    var buffer = new byte[81920];
                    for (int n; (n = z.Read(buffer)) > 0;)
                    {
                        if (copy.Length + n > limits.MaxItemBytes) throw new ToolError(ErrorCode.LimitExceeded, $"{path} decompresses past the {limits.MaxItemBytes:N0}-byte item limit.");
                        copy.Write(buffer, 0, n);
                    }
                    bytes = copy.ToArray();
                }
                else if (encoding.Length > 0 && !encoding.Contains("octet-stream", StringComparison.Ordinal)) notes.Add($"{path}: {encoding} data kept as stored");
                ArchiveItems.Take(items, entries, "xar", path, bytes, allFiles, limits, ref total);
            }
        }
        if (doc.SelectSingleNode("/xar/toc") is { } toc) Walk(toc, "");
        return new ContainerContents("xar", items, notes) { Entries = entries };
    }
}

/// <summary>cpio archives, odc (070707) and newc / crc (070701, 070702): .pkg Payloads, initramfs, RPM payloads.</summary>
internal sealed class CpioReader : IContainerReader
{
    public string Kind => "cpio";

    public static bool IsCpio(ReadOnlySpan<byte> b) => b.Length >= 6 && (b.StartsWith("070707"u8) || b.StartsWith("070701"u8) || b.StartsWith("070702"u8));

    public bool Accepts(ReadOnlySpan<byte> data, string name) => IsCpio(data);

    public ContainerContents Open(byte[] data, string name, bool allFiles, AnalysisLimits limits, CancellationToken ct)
    {
        var items = new List<ExtractedItem>();
        var entries = new List<ContainerEntry>();
        var notes = new List<string>();
        long total = 0;
        int p = 0;
        while (p + 6 <= data.Length)
        {
            ct.ThrowIfCancellationRequested();
            bool newc = data.AsSpan(p, 6).SequenceEqual("070701"u8) || data.AsSpan(p, 6).SequenceEqual("070702"u8);
            bool odc = data.AsSpan(p, 6).SequenceEqual("070707"u8);
            if (!newc && !odc) { notes.Add($"no cpio header at offset {p}: stopped"); break; }
            int headerLength = newc ? 110 : 76;
            if (p + headerLength > data.Length) { notes.Add("truncated header"); break; }
            long mode = newc ? Hex(data, p + 14, 8) : Oct(data, p + 18, 6);
            long nameSize = newc ? Hex(data, p + 94, 8) : Oct(data, p + 59, 6);
            long fileSize = newc ? Hex(data, p + 54, 8) : Oct(data, p + 65, 11);
            int nameAt = p + headerLength;
            if (nameSize <= 0 || nameSize > 4096 || fileSize < 0 || fileSize > limits.MaxItemBytes || nameAt + nameSize > data.Length) { notes.Add($"bad header at offset {p}"); break; }
            var path = Encoding.UTF8.GetString(data, nameAt, (int)nameSize - 1).TrimStart('.', '/');
            int dataAt = newc ? Align4(nameAt + (int)nameSize) : nameAt + (int)nameSize;
            if (path == "TRAILER!!!") break;
            if (dataAt + fileSize > data.Length) { notes.Add($"{path}: data runs past the end"); break; }
            // regular files only (S_IFREG); directories, links and devices are skipped
            if ((mode & 0xF000) == 0x8000 && path.Length > 0 && !path.Split('/').Contains(".."))
                ArchiveItems.Take(items, entries, "cpio", path, data.AsSpan(dataAt, (int)fileSize).ToArray(), allFiles, limits, ref total);
            p = newc ? Align4(dataAt + (int)fileSize) : dataAt + (int)fileSize;
        }
        return new ContainerContents("cpio", items, notes) { Entries = entries };
    }

    private static int Align4(int n) => (n + 3) & ~3;

    private static long Hex(byte[] d, int at, int length) =>
        long.TryParse(Encoding.ASCII.GetString(d, at, length), System.Globalization.NumberStyles.HexNumber, null, out var v) ? v : -1;

    private static long Oct(byte[] d, int at, int length)
    {
        long v = 0;
        for (int i = 0; i < length; i++)
        {
            byte c = d[at + i];
            if (c is < (byte)'0' or > (byte)'7') return -1;
            v = v * 8 + (c - '0');
        }
        return v;
    }
}
