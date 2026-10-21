namespace Corvus.Core.Firmware;

/// <summary>
/// A firmware image as a container: the filesystems, boot images, archives and executables its signatures find at their
/// offsets, each carved out by its header's size (an unsized one up to the next signature), and compressed streams decoded;
/// each part is then opened by its own reader. Taken only when a filesystem or boot image lies inside the file, or an archive
/// follows a vendor header.
/// </summary>
internal static class FirmwareCarve
{
    private const int MaxHits = 2000;

    private static readonly Dictionary<string, string> Extensions = new(StringComparer.Ordinal)
    {
        ["squashfs"] = "squashfs", ["cramfs"] = "cramfs", ["ext2/3/4"] = "ext", ["FAT12/FAT16"] = "fat", ["FAT32"] = "fat", ["JFFS2"] = "jffs2", ["UBI"] = "ubi",
        ["UBIFS"] = "ubifs", ["romfs"] = "romfs", ["ISO"] = "iso", ["cpio"] = "cpio", ["POSIX"] = "tar", ["zip"] = "zip", ["7-Zip"] = "7z", ["U-Boot"] = "uimage",
        ["flattened"] = "dtb", ["TRX"] = "trx", ["Android"] = "img", ["ELF"] = "elf", ["PE"] = "exe",
    };

    private static string Extension(string format) => Extensions.GetValueOrDefault(format.Split(' ')[0], "bin");

    public static ContainerContents? Open(byte[] data, string name, AnalysisLimits limits, CancellationToken ct, bool allFiles = false) =>
        Open(FsSource.Of(data, name), FirmwareSignatures.Scan(data, MaxHits, ct), limits, ct, allFiles);

    public static ContainerContents? Open(Stream stream, string name, AnalysisLimits limits, CancellationToken ct) =>
        Open(new FsSource(stream, 0, stream.Length, name), FirmwareSignatures.Scan(stream, stream.Length, MaxHits, ct), limits, ct, allFiles: false);

    private static ContainerContents? Open(FsSource src, List<SignatureHit> hits, AnalysisLimits limits, CancellationToken ct, bool allFiles)
    {
        // opened at this level, so the parts inside keep a nesting level for their own filesystems
        if (hits.FirstOrDefault(h => Wrapped(h, src.Length)) is { Size: { } wrappedSize } wrapped && wrappedSize <= limits.MaxItemBytes)
        {
            var inner = Containers.Open(src.Read(wrapped.Offset, (int)wrappedSize), $"0x{wrapped.Offset:X}.{Extension(wrapped.Format)}", limits, ct, allFiles: allFiles);
            return inner with { Kind = "firmware image", Notes = [$"firmware image: a {wrapped.Offset:N0}-byte vendor header, then a {inner.Kind} at 0x{wrapped.Offset:X}", .. inner.Notes] };
        }
        // the file's own format at offset 0, alone, is not a firmware image
        if (!hits.Any(h => h.Kind is SignatureKind.Filesystem or SignatureKind.Boot && (h.Offset > 0 || h.Size is { } s && s < src.Length)))
            return null;
        var items = new List<ExtractedItem>();
        var notes = new List<string> { $"firmware image: {hits.Count:N0} signatures ({string.Join(", ", hits.GroupBy(h => h.Format).Take(8).Select(g => g.Count() > 1 ? $"{g.Count()} {g.Key}" : g.Key))})" };
        long total = 0, covered = 0;
        for (int i = 0; i < hits.Count; i++)
        {
            ct.ThrowIfCancellationRequested();
            var h = hits[i];
            if (h.Offset < covered || items.Count >= limits.MaxItems) continue;
            long next = i + 1 < hits.Count ? hits[i + 1].Offset : src.Length;
            try
            {
                if (h.Kind is SignatureKind.Filesystem or SignatureKind.Boot or SignatureKind.Archive or SignatureKind.Executable)
                {
                    if (h.Kind == SignatureKind.Executable && h.Size == null) continue; // an unsized executable has no known end
                    long size = h.Size ?? next - h.Offset;
                    if (size <= 0 || size > limits.MaxItemBytes || h.Offset + size > src.Length) { notes.Add($"{h.Format} at 0x{h.Offset:X}: {size:N0} bytes, not carved"); continue; }
                    if ((total += size) > limits.MaxTotalBytes) { notes.Add("Stopped: the extraction limit was reached."); break; }
                    var part = src.Read(h.Offset, (int)size);
                    var partName = $"0x{h.Offset:X}.{Extension(h.Format)}";
                    items.Add(new ExtractedItem(partName, part, $"{h.Format} at 0x{h.Offset:X}" + (h.Size == null ? " (to the next signature)" : "") + (h.Detail != null ? $", {h.Detail}" : "")));
                    if (h.Kind == SignatureKind.Filesystem && Containers.ReaderFor(part, partName) == null)
                        notes.Add($"{partName}: {h.Format}{(h.Detail != null ? $" ({h.Detail})" : "")} is carved out, but no in-process reader opens it: its files are not listed");
                    // a region's own contents are its reader's to open
                    if (h.Size != null) covered = h.Offset + size;
                }
                else if (h.Kind == SignatureKind.Compressed && Codec(h.Format) is { } codec)
                {
                    var input = src.Read(h.Offset, (int)Math.Min(src.Length - h.Offset, Math.Min(limits.MaxItemBytes, 64L << 20)));
                    var decoded = FsCodec.DecodeStream(codec, input, limits.MaxItemBytes);
                    if (decoded.Length == 0) continue;
                    if ((total += decoded.Length) > limits.MaxTotalBytes) { notes.Add("Stopped: the extraction limit was reached."); break; }
                    items.Add(new ExtractedItem($"0x{h.Offset:X}.{codec}.out", decoded, $"{h.Format} at 0x{h.Offset:X}, decoded"));
                }
            }
            catch (InvalidDataException ex) { notes.Add($"{h.Format} at 0x{h.Offset:X}: not decoded ({ex.Message})"); }
        }
        if (items.Count == 0) notes.Add("no part of this firmware image could be carved: nothing extracted");
        return new ContainerContents("firmware image", items, notes);
    }

    /// <summary>A vendor header before one sized archive that runs to the end of the file (a factory image wrapping a zip).</summary>
    private static bool Wrapped(SignatureHit h, long length) =>
        h.Kind == SignatureKind.Archive && h.Offset is > 0 and <= HeaderMax && h.Size is { } size && h.Offset + size >= length - HeaderMax;

    /// <summary>Bytes of an unknown header before the payload, and of padding after it.</summary>
    private const int HeaderMax = 64 << 10;

    private static string? Codec(string format) => format switch
    {
        "gzip compressed data" => "gzip", "xz compressed data" => "xz", "LZMA compressed data" => "lzma", "bzip2 compressed data" => "bzip2",
        "Zstandard compressed data" => "zstd", "LZ4 compressed data" => "lz4", _ => null,
    };
}
