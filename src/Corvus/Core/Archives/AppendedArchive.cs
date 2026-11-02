using System.Buffers.Binary;

namespace Corvus.Core.Archives;

/// <summary>
/// Lists archives laid end to end in one image and the local zip entries
/// a central directory omits.
/// </summary>
internal static class AppendedArchive
{
    /// <summary>At most this many archives of one image are opened; the rest are counted.</summary>
    internal const int MaxArchives = 16;

    private const uint LocalHeader = 0x04034B50, CentralHeader = 0x02014B50;

    private static bool IsArchive(ReadOnlySpan<byte> rest) =>
        rest.Length >= 4 && Blob.Identify(rest) is "zip" or "7z" or "rar" or "gzip" or "xz" or "bzip2";

    /// <summary>
    /// The byte ranges of the archives laid end to end in a zip or 7z image;
    /// null for a single archive or any other kind.
    /// </summary>
    internal static List<(int Start, int End)>? Split(byte[] data, string kind)
    {
        var ends = kind == "zip" ? ZipEnds(data) : kind == "7z" ? SevenZipEnds(data) : [];
        if (ends.Count == 0) return null;
        // Bytes after the last end record count only when they start another archive.
        if (ends[^1] < data.Length && IsArchive(data.AsSpan(ends[^1]))) ends.Add(data.Length);
        if (ends.Count < 2) return null;
        var parts = new List<(int, int)>();
        int start = 0;
        foreach (int end in ends) { parts.Add((start, end)); start = end; }
        return parts;
    }

    private static ReadOnlySpan<byte> EndRecord => "PK\x05\x06"u8;

    /// <summary>
    /// Returns the count of zip end records and the first one's offset (-1 when
    /// none), scanned in 1 MiB windows.
    /// A record counts when its entry counts agree and its central directory
    /// fits before it, so a stored entry adds none unless it holds a whole
    /// archive.
    /// </summary>
    internal static (int Count, long First) CountEndRecords(Func<Stream> open, CancellationToken ct)
    {
        const int Window = 1 << 20, Record = 22;
        using var s = open();
        var buffer = new byte[Window + Record - 1];
        int count = 0, carry = 0;
        long first = -1, consumed = 0, decided = 0;
        while (true)
        {
            ct.ThrowIfCancellationRequested();
            int read = s.Read(buffer, carry, Window);
            if (read <= 0) return (count, first);
            int length = carry + read;
            // Offset of buffer[0] in the stream.
            long origin = consumed - carry;
            // A record is judged once all 22 bytes are in the buffer; later
            // positions wait for the next window.
            for (int at = buffer.AsSpan(0, length).IndexOf(EndRecord); at >= 0 && at + Record <= length;)
            {
                long position = origin + at;
                if (position >= decided && Plausible(buffer.AsSpan(at, Record), position) && count++ == 0) first = position;
                int next = buffer.AsSpan(at + 4, length - at - 4).IndexOf(EndRecord);
                at = next < 0 ? -1 : at + 4 + next;
            }
            decided = origin + length - (Record - 1);
            consumed += read;
            carry = Math.Min(Record - 1, length);
            Buffer.BlockCopy(buffer, length - carry, buffer, 0, carry);
        }
    }

    // The central directory (size, then offset from the archive start) ends at
    // the record; zip64 fields hold 0xFFFFFFFF.
    private static bool Plausible(ReadOnlySpan<byte> record, long position)
    {
        uint onDisk = BinaryPrimitives.ReadUInt16LittleEndian(record[8..]), total = BinaryPrimitives.ReadUInt16LittleEndian(record[10..]);
        uint size = BinaryPrimitives.ReadUInt32LittleEndian(record[12..]), offset = BinaryPrimitives.ReadUInt32LittleEndian(record[16..]);
        if (onDisk > total) return false;
        return size == uint.MaxValue || offset == uint.MaxValue || (long)size + offset <= position;
    }

    private static List<int> SevenZipEnds(byte[] data)
    {
        if (data.Length < 32) return [];
        // The start header gives the next header's offset and size, relative to byte 32.
        ulong offset = BinaryPrimitives.ReadUInt64LittleEndian(data.AsSpan(12));
        ulong size = BinaryPrimitives.ReadUInt64LittleEndian(data.AsSpan(20));
        ulong room = (ulong)data.Length - 32;
        return offset <= room && size <= room - offset ? [(int)(32 + offset + size)] : [];
    }

    // An end record counts when its central directory starts with a central
    // header at the size it states. Walking back from the last record, each
    // archive's start is taken from its directory offset, so end records
    // inside it (a stored zip entry) are not boundaries.
    private static List<int> ZipEnds(byte[] data)
    {
        var candidates = new List<(int End, int Directory, uint Offset)>();
        foreach (int p in Blob.FindAll(data, EndRecord, data.Length))
        {
            if (p + 22 > data.Length) continue;
            int end = p + 22 + BinaryPrimitives.ReadUInt16LittleEndian(data.AsSpan(p + 20));
            if (end > data.Length) continue;
            uint size = BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan(p + 12));
            uint offset = BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan(p + 16));
            if (size != uint.MaxValue)
            {
                if (size > p) continue;
                if (size > 0 && BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan(p - (int)size)) != CentralHeader) continue;
            }
            candidates.Add((end, p - (size == uint.MaxValue ? 0 : (int)size), offset));
        }
        var ends = new List<int>();
        int limit = int.MaxValue;
        for (int i = candidates.Count - 1; i >= 0; i--)
        {
            var (end, directory, offset) = candidates[i];
            if (end > limit) continue;
            ends.Add(end);
            // Without a usable directory offset (zip64) the previous record is the boundary.
            limit = offset != uint.MaxValue && directory >= offset ? directory - (int)offset : end - 1;
        }
        ends.Reverse();
        return ends;
    }

    /// <summary>
    /// Opens each archive of <paramref name="parts"/> and lists the later ones under archive_N/;
    /// a later archive that does not open is noted as not read, and an unreadable first one throws.
    /// </summary>
    internal static ContainerContents Join(
        byte[] data, List<(int Start, int End)> parts, string name, bool allFiles, AnalysisLimits limits, CancellationToken ct)
    {
        var first = Containers.Open(data[parts[0].Start..parts[0].End], name, limits, ct, allFiles: allFiles);
        var items = new List<ExtractedItem>(first.Items);
        var notes = new List<string>(first.Notes);
        var entries = first.Entries is null ? null : new List<ContainerEntry>(first.Entries);
        var names = first.Names is null ? null : new List<NameIssue>(first.Names);
        for (int i = 1; i < parts.Count && i < MaxArchives; i++)
        {
            ct.ThrowIfCancellationRequested();
            var (start, end) = parts[i];
            var label = $"archive_{i + 1}";
            ContainerContents next;
            try { next = Containers.Open(data[start..end], name, limits, ct, allFiles: allFiles); }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                notes.Add($"{label}: at 0x{start:X}, {end - start:N0} bytes, not read ({ex.Message}).");
                continue;
            }
            notes.Add($"{label}: {next.Kind} at 0x{start:X}, {end - start:N0} bytes, {next.Items.Count} file(s) extracted as {label}/.");
            items.AddRange(next.Items.Select(x => x with { Name = $"{label}/{x.Name}", Origin = $"{label} at 0x{start:X}: {x.Origin}" }));
            notes.AddRange(next.Notes.Select(n => $"{label}: {n}"));
            entries?.AddRange((next.Entries ?? []).Select(x => x with { Path = $"{label}/{x.Path}" }));
            if (next.Names is { } issues) (names ??= []).AddRange(issues.Select(x => x with { Name = $"{label}/{x.Name}" }));
        }
        if (parts.Count > MaxArchives)
        {
            var offsets = parts.Skip(MaxArchives).Take(MaxArchives).Select(p => $"0x{p.Start:X}");
            var more = parts.Count - 2 * MaxArchives;
            notes.Add($"Opened {MaxArchives} of {parts.Count} archives; unread archives start at {string.Join(", ", offsets)}"
                + (more > 0 ? $" and {more} more" : "") + ". Read one with a slice of the image from its offset.");
        }
        return first with { Items = items, Notes = notes, Entries = entries, Names = names };
    }

    /// <summary>
    /// Adds the local entries of a zip that its central directory omits, under
    /// unlisted/; returns the zip unchanged when there are none.
    /// </summary>
    internal static ContainerContents WithUnlisted(ContainerContents zip, byte[] data, bool allFiles, AnalysisLimits limits, CancellationToken ct)
    {
        var gaps = LocalGaps(data, out bool partial);
        if (gaps.Count == 0 && !partial) return zip;
        var items = new List<ExtractedItem>(zip.Items);
        var notes = new List<string>(zip.Notes);
        if (partial) notes.Add("A listed entry has no local header at its offset; the regions after it were not checked for unlisted entries.");
        int found = 0;
        foreach (var (start, end) in gaps.Take(MaxArchives))
        {
            ct.ThrowIfCancellationRequested();
            var local = Containers.ReadLocalHeaders(data[start..end], limits, ct, allFiles);
            found += local.Items.Count;
            notes.Add($"Local entries at 0x{start:X}, {end - start:N0} bytes, are not in the central directory; "
                + $"{local.Items.Count} file(s) extracted as unlisted/.");
            notes.AddRange(local.Notes.Select(n => $"unlisted: {n}"));
            items.AddRange(local.Items.Select(x => x with { Name = $"unlisted/{x.Name}", Origin = $"unlisted at 0x{start:X}: {x.Origin}" }));
        }
        if (gaps.Count > MaxArchives) notes.Add($"Read {MaxArchives} of {gaps.Count} unlisted regions; the later ones are not read.");
        return zip with { Items = items, Notes = notes };
    }

    // Regions between the end of one listed entry and the next offset that start another local header.
    private static List<(int Start, int End)> LocalGaps(byte[] data, out bool partial)
    {
        partial = false;
        var gaps = new List<(int, int)>();
        int eocd = data.AsSpan().LastIndexOf(EndRecord);
        if (eocd < 0 || eocd + 22 > data.Length) return gaps;
        int count = BinaryPrimitives.ReadUInt16LittleEndian(data.AsSpan(eocd + 10));
        long size = BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan(eocd + 12));
        long offset = BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan(eocd + 16));
        // A prefix, zip64 or multi-segment image shifts offsets: not checked.
        if (size == uint.MaxValue || offset == uint.MaxValue || count == ushort.MaxValue || offset + size != eocd) return gaps;
        var listed = new List<(long Offset, long Compressed, bool Descriptor)>();
        long at = offset;
        for (int i = 0; i < count; i++)
        {
            if (at + 46 > eocd || BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan((int)at)) != CentralHeader) return gaps;
            ushort flags = BinaryPrimitives.ReadUInt16LittleEndian(data.AsSpan((int)at + 8));
            uint compressed = BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan((int)at + 20));
            uint local = BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan((int)at + 42));
            if (compressed == uint.MaxValue || local == uint.MaxValue) return gaps;
            // Local headers precede the central directory.
            if (local >= offset) { partial = true; return gaps; }
            int name = BinaryPrimitives.ReadUInt16LittleEndian(data.AsSpan((int)at + 28));
            int extra = BinaryPrimitives.ReadUInt16LittleEndian(data.AsSpan((int)at + 30));
            int comment = BinaryPrimitives.ReadUInt16LittleEndian(data.AsSpan((int)at + 32));
            listed.Add((local, compressed, (flags & 8) != 0));
            at += 46 + name + extra + comment;
        }
        listed.Sort((a, b) => a.Offset.CompareTo(b.Offset));
        // Local headers before the first listed entry.
        if (listed.Count > 0 && listed[0].Offset >= 30 && BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan(0)) == LocalHeader)
            gaps.Add((0, (int)listed[0].Offset));
        for (int i = 0; i < listed.Count; i++)
        {
            var (local, compressed, descriptor) = listed[i];
            long boundary = i + 1 < listed.Count ? listed[i + 1].Offset : offset;
            if (local + 30 > data.Length || BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan((int)local)) != LocalHeader) { partial = true; break; }
            long end = local + 30 + compressed
                + BinaryPrimitives.ReadUInt16LittleEndian(data.AsSpan((int)local + 26))
                + BinaryPrimitives.ReadUInt16LittleEndian(data.AsSpan((int)local + 28));
            // A data descriptor of 12, 16 or 24 bytes may sit between the data and the next header.
            foreach (int skip in descriptor ? (int[])[0, 12, 16, 24] : [0])
            {
                long start = end + skip;
                if (start + 30 > boundary || start + 4 > data.Length) continue;
                if (BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan((int)start)) != LocalHeader) continue;
                gaps.Add(((int)start, (int)boundary));
                break;
            }
        }
        return gaps;
    }
}
