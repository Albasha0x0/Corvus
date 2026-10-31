using System.Text;
using Corvus.Core.Disks;
using SharpCompress.Archives;
using SharpCompress.Common;
using SharpCompress.Readers;

namespace Corvus.Core.Archives;

/// <summary>tar, 7z, RAR and single gzip, bzip2 or xz files; extraction stops at the item or total limit, naming the entry.</summary>
internal sealed class ArchiveReader : IContainerReader
{
    public string Kind => "archive";

    public bool Accepts(ReadOnlySpan<byte> data, string name) => Format(data) != null;

    private static string? Format(ReadOnlySpan<byte> b)
    {
        // A disk image's first chunk may be xz or bzip2: its koly trailer wins.
        if (Firmware.UdifReader.Looks(b)) return null;
        if (b.Length > 262 && b[257..262].SequenceEqual("ustar"u8)) return "tar";
        if (b.StartsWith((ReadOnlySpan<byte>)[0x1F, 0x8B])) return "gzip";
        if (b.StartsWith((ReadOnlySpan<byte>)[0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00])) return "xz";
        if (b.StartsWith("BZh"u8)) return "bzip2";
        if (b.StartsWith((ReadOnlySpan<byte>)[0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C])) return "7z";
        if (b.StartsWith("Rar!\x1A\x07"u8)) return "rar";
        return null;
    }

    public ContainerContents Open(byte[] data, string name, bool allFiles, AnalysisLimits limits, CancellationToken ct) =>
        Open(new MemoryStream(data, writable: false), name, allFiles, limits, ct)!;

    public ContainerContents? Open(Stream stream, string name, bool allFiles, AnalysisLimits limits, CancellationToken ct)
    {
        Span<byte> head = stackalloc byte[263];
        int got = stream.ReadAtLeast(head, head.Length, throwOnEndOfStream: false);
        stream.Position = 0;
        var format = Format(head[..got])!;
        var items = new List<ExtractedItem>();
        var entries = new List<ContainerEntry>();
        var notes = new List<string>();
        long total = 0;
        string kind = format;
        // Read before SharpCompress takes the stream; its entry list omits service records.
        var streamRecords = format == "rar" && stream.CanSeek ? Rar5Streams.Names(stream) : [];
        stream.Position = 0;

        var password = ContainerPassword.Current;

        void Take(string path, long size, Func<Stream> open, bool encrypted = false)
        {
            ct.ThrowIfCancellationRequested();
            entries.Add(new ContainerEntry(path, size));
            if (items.Count >= limits.MaxItems) return;
            byte[] bytes;
            try
            {
                using var s = open();
                bytes = ReadBounded(s, path, limits.MaxItemBytes);
            }
            catch (Exception ex) when (EntryDamage.Is(ex))
            {
                entries[^1] = entries[^1] with { Detail = EntryDamage.Detail(ex.GetType().Name) };
                notes.Add(EntryDamage.Note(path, ex));
                return;
            }
            // A wrong or missing password surfaces as a cipher, checksum or format fault depending on the scheme.
            catch (Exception ex) when (encrypted && ex is not (OperationCanceledException or ToolError or OutOfMemoryException))
            {
                entries[^1] = entries[^1] with { Detail = "encrypted; not read" };
                notes.Add(ContainerPassword.NotRead(path, password != null));
                return;
            }
            total += bytes.Length;
            if (total > limits.MaxTotalBytes)
                throw new ToolError(ErrorCode.LimitExceeded, $"{name}: extracting {path} passes the {limits.MaxTotalBytes:N0}-byte total limit.", "unpack fewer files or raise the limits");
            if (allFiles || Wanted(bytes)) items.Add(new ExtractedItem(path, bytes, $"{kind} entry"));
        }

        try
        {
            if (format is "7z" or "rar")
            {
                using var archive = ArchiveFactory.OpenArchive(stream, password == null ? null : new ReaderOptions { Password = password });
                foreach (var e in archive.Entries)
                    if (!e.IsDirectory && e.Key is { } key) Take(key.Replace('\\', '/'), e.Size, e.OpenEntryStream, e.IsEncrypted);
            }
            else if (format == "tar" && stream.CanSeek && TarParts(stream, ct) is { } parts)
            {
                // Each run of readable headers is read on its own, so the
                // entries past a damaged header are kept.
                foreach (var part in parts)
                {
                    if (part.Damaged is { } damaged)
                    {
                        entries.Add(new ContainerEntry(damaged, 0, part.Detail + "; size unknown"));
                        notes.Add($"{damaged}: {part.Detail}");
                        continue;
                    }
                    using var reader = ReaderFactory.OpenReader(new SubStream(stream, part.Start, part.Length));
                    while (reader.MoveToNextEntry())
                        if (!reader.Entry.IsDirectory && reader.Entry.Key is { } key) Take(key.Replace('\\', '/'), reader.Entry.Size, reader.OpenEntryStream);
                }
            }
            else
            {
                using var reader = ReaderFactory.OpenReader(stream);
                // A compressed tar reports its inner archive type.
                kind = reader is SharpCompress.Readers.Tar.TarReader && format != "tar" ? "tar." + format switch { "gzip" => "gz", "bzip2" => "bz2", var f => f } : format;
                while (reader.MoveToNextEntry())
                    if (!reader.Entry.IsDirectory && reader.Entry.Key is { } key) Take(key.Replace('\\', '/'), reader.Entry.Size, reader.OpenEntryStream);
            }
        }
        // SharpCompress reports damaged data with its own exceptions (ZlibException among them) and overflows on damaged tar sizes.
        catch (Exception ex) when (ex is SharpCompressException or InvalidDataException or EndOfStreamException
                                       or NotSupportedException or IOException or OverflowException)
        {
            if (entries.Count == 0 && password != null && format is "7z" or "rar")
                throw new ToolError(ErrorCode.MalformedInput, $"{name}: the {kind} archive did not open with the password; its entries are not read.", "check the password, or omit it to list what is readable");
            if (entries.Count == 0)
                throw new ToolError(ErrorCode.MalformedInput, $"{name} is not a readable {kind} archive: {ex.Message}", $"summarize_file path={name} says what it holds");
            notes.Add($"{kind}: stopped reading at entry {entries.Count + 1}: {ex.Message}");
        }
        notes.AddRange(MemberNames.Notes([.. entries.Select(e => e.Path), .. streamRecords]));
        if (entries.Count > items.Count && !allFiles) notes.Add($"{entries.Count - items.Count} of {entries.Count} files not extracted (not binaries or packages; allFiles extracts every file).");
        return new ContainerContents(kind, items, notes) { Entries = entries };
    }

    private const int MaxTarParts = 10_000;

    /// <summary>
    /// A run of a plain tar read as one archive, or one damaged header with its
    /// name and why.
    /// </summary>
    private sealed record TarPart(long Start, long Length, string? Damaged = null, string? Detail = null);

    /// <summary>
    /// A plain tar split at each damaged header (a bad checksum, or a size that
    /// overflows or runs past the end) into runs of readable headers; null when
    /// no header is damaged.
    /// </summary>
    private static List<TarPart>? TarParts(Stream s, CancellationToken ct)
    {
        var parts = new List<TarPart>();
        var block = new byte[512];
        long length = s.Length, start = 0, p = 0;
        bool damaged = false;
        while (p + 512 <= length && parts.Count < MaxTarParts)
        {
            ct.ThrowIfCancellationRequested();
            Block(s, p, block);
            if (Array.TrueForAll(block, b => b == 0)) break;
            string why;
            try
            {
                if (!ChecksumHolds(block)) why = "the header checksum does not hold";
                else if (Size(block) is not { } size) why = "the size field is not a number";
                else if (checked(p + 512 + (size + 511) / 512 * 512) is var next && next <= length)
                {
                    p = next;
                    continue;
                }
                else why = $"the size {size:N0} runs past the end";
            }
            catch (Exception ex) when (EntryDamage.Is(ex)) { why = ex.GetType().Name; }
            damaged = true;
            if (p > start) parts.Add(new TarPart(start, p - start));
            parts.Add(new TarPart(p, 512, Name(block, p), EntryDamage.Detail(why, p)));
            // A damaged header cannot place the next one: the next block with
            // the magic and a checksum that holds is taken as it.
            for (p += 512; p + 512 <= length; p += 512)
            {
                Block(s, p, block);
                if (block.AsSpan(257, 5).SequenceEqual("ustar"u8) && ChecksumHolds(block)) break;
            }
            start = p;
        }
        // The reader that follows starts where the walk began.
        s.Position = 0;
        if (!damaged) return null;
        if (length > start) parts.Add(new TarPart(start, length - start));
        return parts;
    }

    private static void Block(Stream s, long at, byte[] block)
    {
        s.Position = at;
        s.ReadExactly(block);
    }

    /// <summary>
    /// Whether the header checksum (POSIX ustar) holds: the byte sum with the
    /// checksum field read as spaces, signed or unsigned.
    /// </summary>
    private static bool ChecksumHolds(byte[] h)
    {
        long stored = 0;
        bool digits = false;
        foreach (byte c in h.AsSpan(148, 8))
        {
            if (c is >= (byte)'0' and <= (byte)'7') { stored = stored * 8 + (c - '0'); digits = true; }
            else if (digits || c is not ((byte)' ' or 0)) break;
        }
        long unsignedSum = 0, signedSum = 0;
        for (int i = 0; i < 512; i++)
        {
            byte c = i is >= 148 and < 156 ? (byte)' ' : h[i];
            unsignedSum += c;
            signedSum += (sbyte)c;
        }
        return digits && (stored == unsignedSum || stored == signedSum);
    }

    /// <summary>
    /// The size field: octal, or base-256 when its high bit is set (GNU); null
    /// when it is neither; throws <see cref="OverflowException"/> past 2^63.
    /// </summary>
    private static long? Size(byte[] h)
    {
        var field = h.AsSpan(124, 12);
        if ((field[0] & 0x80) != 0)
        {
            // 0xFF marks a negative base-256 value.
            if (field[0] == 0xFF) return null;
            long v = field[0] & 0x7F;
            foreach (byte b in field[1..]) v = checked(v * 256 + b);
            return v;
        }
        long o = 0;
        bool digits = false;
        foreach (byte c in field)
        {
            if (c is >= (byte)'0' and <= (byte)'7') { o = checked(o * 8 + (c - '0')); digits = true; }
            else if (c is 0 or (byte)' ') { if (digits) break; }
            else return null;
        }
        return digits ? o : null;
    }

    /// <summary>
    /// The header's path (ustar prefix and name), or "entry at 0x..." when it is
    /// empty.
    /// </summary>
    private static string Name(byte[] h, long at)
    {
        static string Field(ReadOnlySpan<byte> f) => Encoding.UTF8.GetString(f[..(f.IndexOf((byte)0) is var n and >= 0 ? n : f.Length)]);
        var name = Field(h.AsSpan(0, 100));
        if (h.AsSpan(257, 6).SequenceEqual("ustar\0"u8) && Field(h.AsSpan(345, 155)) is { Length: > 0 } prefix) name = prefix + "/" + name;
        return name.Length > 0 ? name : $"entry at 0x{at:X}";
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
