using System.Buffers.Binary;
using System.IO.Compression;
using System.Text;
using System.Xml;
using System.Runtime.CompilerServices;

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
        if (allFiles || Wanted(bytes)) items.Add(new ExtractedItem(path, bytes, $"{kind} entry"));
    }

    /// <summary>Binaries and nested packages (any format a container reader takes): what is extracted without allFiles.</summary>
    public static bool Wanted(byte[] bytes) =>
        Blob.Identify(bytes) is ".NET assembly" or "native PE" or "NativeAOT executable" or "elf" or "mach-o" or "zip" or "gzip" or "7z" or "asar" or "wasm"
        || Containers.ReaderFor(bytes, "") != null;
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
        // The length is unsigned on disk: one past 2^63 reads negative.
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
        bool deep = false;
        void Walk(XmlNode parent, string prefix)
        {
            if (!RuntimeHelpers.TryEnsureSufficientExecutionStack())
            {
                if (!deep) notes.Add($"{prefix}: folders nested deeper than the stack allows; the files below are not read");
                deep = true;
                return;
            }
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
                bool outside;
                try { outside = offset < 0 || length < 0 || length > limits.MaxItemBytes || checked(heap + offset + length) > data.Length; }
                catch (OverflowException ex)
                {
                    entries.Add(new ContainerEntry(path, length, EntryDamage.Detail(ex.GetType().Name)));
                    notes.Add(EntryDamage.Note(path, ex));
                    continue;
                }
                if (outside) { notes.Add($"{path}: data outside the archive or over the item limit"); continue; }
                byte[] bytes = data.AsSpan((int)(heap + offset), (int)length).ToArray();
                if (encoding.Contains("gzip", StringComparison.Ordinal))
                {
                    // xar's "gzip" style is a zlib stream.
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

/// <summary>cpio archives (odc, newc, crc, old binary in either byte order), read entry by entry from a stream.</summary>
internal sealed class CpioReader : IContainerReader
{
    public string Kind => "cpio";

    public static bool IsCpio(ReadOnlySpan<byte> b) =>
        b.Length >= 6 && (b.StartsWith("070707"u8) || b.StartsWith("070701"u8) || b.StartsWith("070702"u8))
        || b.Length >= 26 && (b.StartsWith((ReadOnlySpan<byte>)[0xC7, 0x71]) || b.StartsWith((ReadOnlySpan<byte>)[0x71, 0xC7])) && Binary(b, b[0] == 0x71) is { NameSize: > 1 and <= 4096 };

    public bool Accepts(ReadOnlySpan<byte> data, string name) => IsCpio(data);

    public ContainerContents Open(byte[] data, string name, bool allFiles, AnalysisLimits limits, CancellationToken ct) =>
        Read(Firmware.FsSource.Of(data, name), allFiles, limits, ct);

    public ContainerContents? Open(Stream stream, string name, bool allFiles, AnalysisLimits limits, CancellationToken ct) =>
        Read(new Firmware.FsSource(stream, 0, stream.Length, name), allFiles, limits, ct);

    /// <summary>The fields of an old binary header (26 bytes, 16-bit words, 32-bit values high word first).</summary>
    private static (int Mode, int NameSize, long FileSize) Binary(ReadOnlySpan<byte> h, bool big)
    {
        Span<int> w = stackalloc int[13];
        for (int i = 0; i < 13; i++) w[i] = big ? BinaryPrimitives.ReadUInt16BigEndian(h[(i * 2)..]) : BinaryPrimitives.ReadUInt16LittleEndian(h[(i * 2)..]);
        return (w[3], w[10], ((long)w[11] << 16) | (uint)w[12]);
    }

    private static ContainerContents Read(Firmware.FsSource src, bool allFiles, AnalysisLimits limits, CancellationToken ct)
    {
        var tree = new Firmware.FsTree("cpio", allFiles, limits, ct);
        long p = 0;
        while (p + 6 <= src.Length)
        {
            ct.ThrowIfCancellationRequested();
            var magic = src.ReadUpTo(p, 26);
            bool newc = magic.AsSpan().StartsWith("070701"u8) || magic.AsSpan().StartsWith("070702"u8);
            bool odc = magic.AsSpan().StartsWith("070707"u8);
            bool binLe = magic.AsSpan().StartsWith((ReadOnlySpan<byte>)[0xC7, 0x71]), binBe = magic.AsSpan().StartsWith((ReadOnlySpan<byte>)[0x71, 0xC7]);
            if (!newc && !odc && !binLe && !binBe) { tree.Notes.Add($"no cpio header at offset {p}: stopped"); break; }
            int headerLength = newc ? 110 : odc ? 76 : 26;
            if (p + headerLength > src.Length) { tree.Notes.Add("truncated header"); break; }
            var h = src.Read(p, headerLength);
            long mode, nameSize, fileSize;
            if (newc) (mode, nameSize, fileSize) = (Hex(h, 14, 8), Hex(h, 94, 8), Hex(h, 54, 8));
            else if (odc) (mode, nameSize, fileSize) = (Oct(h, 18, 6), Oct(h, 59, 6), Oct(h, 65, 11));
            else (mode, nameSize, fileSize) = Binary(h, binBe);
            long nameAt = p + headerLength;
            if (nameSize <= 0 || nameSize > 4096 || fileSize < 0 || nameAt + nameSize > src.Length) { tree.Notes.Add($"bad header at offset {p}"); break; }
            var path = Encoding.UTF8.GetString(src.Read(nameAt, (int)nameSize - 1)).TrimEnd('\0').TrimStart('.', '/');
            long dataAt = newc ? Align(nameAt + nameSize, 4) : binLe || binBe ? Align(nameAt + nameSize, 2) : nameAt + nameSize;
            if (path == "TRAILER!!!") break;
            if (dataAt + fileSize > src.Length) { tree.Notes.Add($"{path}: data runs past the end"); break; }
            bool usable = path.Length > 0 && !path.Split('/').Contains("..");
            // Regular files and symbolic links; directories and devices are skipped.
            if (usable && (mode & 0xF000) == 0x8000)
            {
                long at = dataAt, size = fileSize;
                tree.File(path, size, n => src.Read(at, (int)n), mode: mode);
            }
            else if (usable && (mode & 0xF000) == 0xA000 && fileSize <= 4096)
                tree.Link(path, Encoding.UTF8.GetString(src.Read(dataAt, (int)fileSize)), mode);
            p = newc ? Align(dataAt + fileSize, 4) : binLe || binBe ? Align(dataAt + fileSize, 2) : dataAt + fileSize;
        }
        return tree.Done();
    }

    private static long Align(long n, int to) => (n + to - 1) & ~(long)(to - 1);

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
