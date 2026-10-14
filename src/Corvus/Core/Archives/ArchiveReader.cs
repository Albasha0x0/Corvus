using SharpCompress.Archives;
using SharpCompress.Common;
using SharpCompress.Readers;

namespace Corvus.Core.Archives;

/// <summary>
/// tar (plain, .gz, .bz2, .xz), 7z, RAR and single gzip / bzip2 / xz files, read with SharpCompress: every entry listed,
/// files extracted within the limits (a decompression bomb stops at the item or total limit, naming the entry).
/// </summary>
internal sealed class ArchiveReader : IContainerReader
{
    public string Kind => "archive";

    public bool Accepts(ReadOnlySpan<byte> data, string name) => Format(data) != null;

    private static string? Format(ReadOnlySpan<byte> b)
    {
        if (b.Length > 262 && b[257..262].SequenceEqual("ustar"u8)) return "tar";
        if (b.StartsWith((ReadOnlySpan<byte>)[0x1F, 0x8B])) return "gzip";
        if (b.StartsWith((ReadOnlySpan<byte>)[0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00])) return "xz";
        if (b.StartsWith("BZh"u8)) return "bzip2";
        if (b.StartsWith((ReadOnlySpan<byte>)[0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C])) return "7z";
        if (b.StartsWith("Rar!\x1A\x07"u8)) return "rar";
        return null;
    }

    public ContainerContents Open(byte[] data, string name, bool allFiles, AnalysisLimits limits, CancellationToken ct)
    {
        var format = Format(data)!;
        var items = new List<ExtractedItem>();
        var entries = new List<ContainerEntry>();
        var notes = new List<string>();
        long total = 0;
        string kind = format;

        void Take(string path, long size, Func<Stream> open)
        {
            ct.ThrowIfCancellationRequested();
            entries.Add(new ContainerEntry(path, size));
            if (items.Count >= limits.MaxItems) return;
            using var s = open();
            var bytes = ReadBounded(s, path, limits.MaxItemBytes);
            total += bytes.Length;
            if (total > limits.MaxTotalBytes)
                throw new ToolError(ErrorCode.LimitExceeded, $"{name}: extracting {path} passes the {limits.MaxTotalBytes:N0}-byte total limit.", "unpack fewer files or raise the limits");
            if (allFiles || Wanted(bytes)) items.Add(new ExtractedItem(path, bytes, $"{kind} entry"));
        }

        try
        {
            if (format is "7z" or "rar")
            {
                using var archive = ArchiveFactory.OpenArchive(new MemoryStream(data, writable: false));
                foreach (var e in archive.Entries)
                    if (!e.IsDirectory && e.Key is { } key) Take(key.Replace('\\', '/'), e.Size, e.OpenEntryStream);
            }
            else
            {
                using var reader = ReaderFactory.OpenReader(new MemoryStream(data, writable: false));
                // a compressed tar reports its inner archive type
                kind = reader is SharpCompress.Readers.Tar.TarReader && format != "tar" ? "tar." + format switch { "gzip" => "gz", "bzip2" => "bz2", var f => f } : format;
                while (reader.MoveToNextEntry())
                    if (!reader.Entry.IsDirectory && reader.Entry.Key is { } key) Take(key.Replace('\\', '/'), reader.Entry.Size, reader.OpenEntryStream);
            }
        }
        catch (Exception ex) when (ex is InvalidFormatException or ArchiveOperationException or IncompleteArchiveException or InvalidDataException or EndOfStreamException
                                       or NotSupportedException or IOException)
        {
            if (entries.Count == 0)
                throw new ToolError(ErrorCode.MalformedInput, $"{name} is not a readable {kind} archive: {ex.Message}", $"summarize_file path={name} says what it holds");
            notes.Add($"{kind}: stopped reading at entry {entries.Count + 1}: {ex.Message}");
        }
        if (entries.Count > items.Count && !allFiles) notes.Add($"{entries.Count - items.Count} of {entries.Count} files not extracted (not binaries or packages; allFiles extracts every file).");
        return new ContainerContents(kind, items, notes) { Entries = entries };
    }

    /// <summary>Binaries and nested packages: what the container tools follow without allFiles.</summary>
    private static bool Wanted(byte[] bytes) =>
        Blob.Identify(bytes) is ".NET assembly" or "native PE" or "NativeAOT executable" or "elf" or "mach-o" or "zip" or "gzip" or "7z" or "rar" or "asar" or "wasm" or "webcil"
        || Format(bytes) != null;

    private static byte[] ReadBounded(Stream s, string path, long max)
    {
        using var copy = new MemoryStream();
        var buffer = new byte[81920];
        int n;
        while ((n = s.Read(buffer, 0, buffer.Length)) > 0)
        {
            if (copy.Length + n > max)
                throw new ToolError(ErrorCode.LimitExceeded, $"{path} decompresses past the {max:N0}-byte item limit.", "raise the limit, or extract it with a dedicated tool");
            copy.Write(buffer, 0, n);
        }
        return copy.ToArray();
    }
}
