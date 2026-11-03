using System.Buffers.Binary;

namespace Corvus.Native.Dump.Rebuild;

/// <summary>Reads a module's pages from process memory into a buffer and tells whether they hold a mapped or a flat image.</summary>
public static class CapturedImageReader
{
    private const int Window = 32;

    /// <summary>
    /// The captured image of <paramref name="target"/>, missing pages zero; null when its headers are not captured.
    /// A module list entry is mapped by construction and is not inspected; other origins are detected. A flat image is returned mapped, with sections moved to their RVAs. Its <c>InputLayout</c> is mapped, flat or unknown, and one <c>capture</c> check is added to <paramref name="checks"/> when given.
    /// </summary>
    public static CapturedImage? Read(IProcessMemory memory, RebuildTarget target, CancellationToken ct, List<RebuildCheck>? checks = null)
    {
        var head = new byte[0x1000];
        if (memory.ReadMemory(target.Base, head) < 0x200 || !DumpImages.TryHeader(head, out _, out uint sizeOfImage, out _)) return null;
        uint size = (uint)Math.Min(target.Size != 0 ? target.Size : sizeOfImage, ModuleRebuild.MaxImageBytes);
        size = (size + 0xFFF) & ~0xFFFu;
        var image = new byte[size];
        var captured = new bool[size / 0x1000];
        for (uint page = 0; page < size; page += 0x1000)
        {
            ct.ThrowIfCancellationRequested();
            captured[page / 0x1000] = memory.ReadMemory(target.Base + page, image.AsSpan((int)page, 0x1000)) == 0x1000;
        }
        // A module list entry was mapped by the loader; only other inputs need
        // detection.
        bool loaded = target.Origin == ModuleOrigin.Listed;
        var (layout, reason) = loaded ? ("mapped", "") : DetectLayout(image, captured);
        if (layout == "flat") (image, captured) = MapFlat(memory, target.Base, image, sizeOfImage, ct);
        var result = new CapturedImage(target, image, captured, layout);
        checks?.Add(layout == "unknown"
            ? RebuildCheck.Unknown("capture", reason)
            : RebuildCheck.Ok("capture", $"{layout}{(loaded ? " (loaded module)" : "")}, {result.CapturedPercent}% captured"));
        return result;
    }

    // Copies each section of a file held in memory from its raw offset to its RVA.
    // A page counts as captured when every source byte behind it was read.
    private static (byte[] Image, bool[] Captured) MapFlat(IProcessMemory memory, ulong at, byte[] head, uint sizeOfImage, CancellationToken ct)
    {
        uint size = (uint)Math.Min(sizeOfImage, ModuleRebuild.MaxImageBytes);
        size = (size + 0xFFF) & ~0xFFFu;
        int nt = BinaryPrimitives.ReadInt32LittleEndian(head.AsSpan(0x3C));
        int count = BinaryPrimitives.ReadUInt16LittleEndian(head.AsSpan(nt + 6));
        int table = nt + 24 + BinaryPrimitives.ReadUInt16LittleEndian(head.AsSpan(nt + 20));
        long headers = BinaryPrimitives.ReadUInt32LittleEndian(head.AsSpan(nt + 24 + 60));
        var sections = new List<(uint Va, uint Virtual, uint RawSize, uint RawAt)>();
        long fileLength = headers;
        for (int i = 0; i < count; i++)
        {
            var h = head.AsSpan(table + 40 * i, 40);
            uint rawSize = BinaryPrimitives.ReadUInt32LittleEndian(h[16..]), rawAt = BinaryPrimitives.ReadUInt32LittleEndian(h[20..]);
            sections.Add((BinaryPrimitives.ReadUInt32LittleEndian(h[12..]), BinaryPrimitives.ReadUInt32LittleEndian(h[8..]), rawSize, rawAt));
            if (rawSize != 0) fileLength = Math.Max(fileLength, (long)rawAt + rawSize);
        }
        fileLength = Math.Min(fileLength, ModuleRebuild.MaxImageBytes);

        var file = new byte[fileLength];
        var read = new bool[(fileLength + 0xFFF) / 0x1000];
        for (long off = 0; off < fileLength; off += 0x1000)
        {
            ct.ThrowIfCancellationRequested();
            int n = (int)Math.Min(0x1000, fileLength - off);
            read[off / 0x1000] = memory.ReadMemory(at + (ulong)off, file.AsSpan((int)off, n)) == n;
        }

        var image = new byte[size];
        var touched = new bool[size / 0x1000];
        var bad = new bool[touched.Length];
        void Place(long to, long from, long copy, long extent)
        {
            long copied = Math.Max(0, Math.Min(copy, Math.Min(size - to, fileLength - from)));
            if (copied > 0) file.AsSpan((int)from, (int)copied).CopyTo(image.AsSpan((int)to));
            bool complete = copied == copy;
            for (long p = from / 0x1000; complete && copied > 0 && p <= (from + copied - 1) / 0x1000; p++)
                complete = read[p];
            long end = Math.Min(size, to + Math.Max(extent, copy));
            for (long p = to / 0x1000; p * 0x1000 < end; p++)
            {
                touched[p] = true;
                bad[p] |= !complete;
            }
        }

        Place(0, 0, headers, headers);
        foreach (var (va, virt, rawSize, rawAt) in sections)
            if (va < size) Place(va, rawAt, rawSize == 0 ? 0 : virt == 0 ? rawSize : Math.Min(rawSize, virt), virt);
        var captured = new bool[touched.Length];
        for (int p = 0; p < captured.Length; p++) captured[p] = touched[p] && !bad[p];
        return (image, captured);
    }

    /// <summary>
    /// Decides from the section table whether <paramref name="image"/> holds sections at their virtual addresses (mapped)
    /// or at their raw data offsets (flat). Returns unknown and the reason when no section can tell.
    /// </summary>
    internal static (string Layout, string Reason) DetectLayout(byte[] image, bool[] captured)
    {
        if (image.Length < 0x200 || !TrySections(image, out var sections, out int nt))
            return ("unknown", "the section table is not readable");

        int mapped = 0, flat = 0, compared = 0;
        foreach (var (va, rawSize, rawAt) in sections)
        {
            if (rawSize == 0 || rawAt == va) continue;
            int length = (int)Math.Min(rawSize, Window);
            bool atVa = HasData(image, captured, va, length), atRaw = HasData(image, captured, rawAt, length);
            if (atVa && !atRaw) mapped++;
            else if (atRaw && !atVa) flat++;
            if (atVa || atRaw) compared++;
        }

        switch (MetadataLayout(image, captured, sections, nt))
        {
            case "mapped": mapped++; compared++; break;
            case "flat": flat++; compared++; break;
        }

        if (compared == 0) return ("unknown", "no section with raw data to compare");
        if (mapped > 0 && flat == 0) return ("mapped", "");
        if (flat > 0 && mapped == 0) return ("flat", "");
        return ("unknown", mapped + flat == 0 ? "raw data and virtual address hold the same bytes" : "sections disagree on the layout");
    }

    // Reads the section table; false when it lies outside the captured headers.
    private static bool TrySections(byte[] image, out List<(uint Va, uint RawSize, uint RawAt)> sections, out int nt)
    {
        sections = [];
        nt = BinaryPrimitives.ReadInt32LittleEndian(image.AsSpan(0x3C));
        if (nt < 0 || nt + 24 > image.Length) return false;
        int count = BinaryPrimitives.ReadUInt16LittleEndian(image.AsSpan(nt + 6));
        int table = nt + 24 + BinaryPrimitives.ReadUInt16LittleEndian(image.AsSpan(nt + 20));
        if (table + 40L * count > Math.Min(image.Length, 0x1000)) return false;
        for (int i = 0; i < count; i++)
        {
            int h = table + 40 * i;
            sections.Add((BinaryPrimitives.ReadUInt32LittleEndian(image.AsSpan(h + 12)),
                BinaryPrimitives.ReadUInt32LittleEndian(image.AsSpan(h + 16)),
                BinaryPrimitives.ReadUInt32LittleEndian(image.AsSpan(h + 20))));
        }
        return true;
    }

    // True when the window lies in captured pages and holds a nonzero byte.
    private static bool HasData(byte[] image, bool[] captured, uint offset, int length)
    {
        if (offset + (long)length > image.Length) return false;
        for (uint page = offset / 0x1000; page <= (offset + (uint)length - 1) / 0x1000; page++)
            if (page >= captured.Length || !captured[page]) return false;
        return image.AsSpan((int)offset, length).IndexOfAnyExcept((byte)0) >= 0;
    }

    // Looks for the metadata signature at the RVA (mapped) or at its file offset (flat); null when it cannot tell.
    private static string? MetadataLayout(byte[] image, bool[] captured, List<(uint Va, uint RawSize, uint RawAt)> sections, int nt)
    {
        int magic = BinaryPrimitives.ReadUInt16LittleEndian(image.AsSpan(nt + 24));
        int dir = nt + 24 + (magic == 0x20B ? 112 : 96) + 14 * 8;
        if (dir + 8 > image.Length) return null;
        uint cliRva = BinaryPrimitives.ReadUInt32LittleEndian(image.AsSpan(dir));
        if (cliRva == 0) return null;
        uint? cliRaw = ToRaw(sections, cliRva);
        bool Signature(uint at) => at + 4L <= image.Length && HasData(image, captured, at, 4)
            && BinaryPrimitives.ReadUInt32LittleEndian(image.AsSpan((int)at)) == 0x424A5342;
        uint MetaAt(uint cli) => cli + 12L <= image.Length && HasData(image, captured, cli, 12)
            ? BinaryPrimitives.ReadUInt32LittleEndian(image.AsSpan((int)cli + 8)) : 0;

        uint metaRva = MetaAt(cliRva);
        if (metaRva != 0 && Signature(metaRva)) return "mapped";
        if (cliRaw is { } raw && MetaAt(raw) is var metaVa and not 0 && ToRaw(sections, metaVa) is { } metaRaw && Signature(metaRaw))
            return "flat";
        return null;
    }

    private static uint? ToRaw(List<(uint Va, uint RawSize, uint RawAt)> sections, uint rva)
    {
        foreach (var (va, rawSize, rawAt) in sections)
            if (rva >= va && rva - va < rawSize) return rawAt + (rva - va);
        return null;
    }
}