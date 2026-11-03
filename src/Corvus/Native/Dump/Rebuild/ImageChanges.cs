using static Corvus.Native.Dump.Rebuild.DiskCompare;

namespace Corvus.Native.Dump.Rebuild;

/// <summary>One range of a mapped image: its section, RVA, length, state (differs or unknown), whether it is code, and the bytes on both sides.</summary>
/// <param name="FileBytes">Hex of the file bytes, cut to <see cref="ImageChanges.MaxBytes"/>.</param>
/// <param name="MemoryBytes">Hex of the memory bytes, cut to <see cref="ImageChanges.MaxBytes"/>; empty for an unknown range.</param>
public sealed record ImageChange(string Section, string Rva, int Length, string State, bool Code, string FileBytes, string MemoryBytes);

/// <summary>Every range where an image differs from its file; <paramref name="Truncated"/> is true when <paramref name="Total"/> exceeds the listed ranges.</summary>
public sealed record ImageChangeSet(IReadOnlyList<ImageChange> Ranges, int Total, bool Truncated, int Limit);

/// <summary>Lists the ranges where a rebuilt image in mapped layout differs from its file.</summary>
public static class ImageChanges
{
    /// <summary>Most ranges listed.</summary>
    public const int MaxRanges = 100_000;

    /// <summary>Most bytes shown on each side of a range; the range keeps its full length.</summary>
    public const int MaxBytes = 64;

    /// <summary>Largest run of equal bytes that does not split a range.</summary>
    public const int MaxGap = 8;


    /// <summary>
    /// The differing ranges of <paramref name="rebuiltMapped"/> (offset = RVA) against <paramref name="file"/> (file layout), merged across
    /// gaps of at most <see cref="MaxGap"/> bytes. Fixup sites and the import address table are left out; bytes on pages not captured form
    /// <c>unknown</c> ranges. An unreadable image or file gives an empty set.
    /// </summary>
    public static ImageChangeSet Compare(byte[] rebuiltMapped, CapturedImage captured, byte[] file)
    {
        var ranges = new List<ImageChange>();
        int total = 0;
        if (!TryParse(file, out var disk) || !TryParse(rebuiltMapped, out var memory)) return new ImageChangeSet(ranges, 0, false, MaxRanges);
        var excluded = Excluded(file, disk);

        void Add(SectionInfo m, long start, long end, string state, Func<long, byte> fileAt)
        {
            total++;
            if (ranges.Count >= MaxRanges) return;
            long length = end - start;
            int shown = (int)Math.Min(length, MaxBytes);
            string memoryHex = state == "unknown" ? "" : Convert.ToHexStringLower(rebuiltMapped.AsSpan((int)(m.Rva + start), shown));
            var fileBytes = new byte[shown];
            for (int k = 0; k < shown; k++) fileBytes[k] = fileAt(start + k);
            ranges.Add(new ImageChange(m.Name, $"0x{m.Rva + start:X}", (int)length, state, DiskCompare.IsCode(m.Characteristics),
                Convert.ToHexStringLower(fileBytes), memoryHex));
        }

        foreach (var m in memory.Sections)
        {
            var d = disk.Sections.FirstOrDefault(s => s.Rva == m.Rva);
            if (d == null) continue;
            var (length, fileLength) = Extent(m, d, rebuiltMapped.Length, file.Length);
            byte FileAt(long i) => i < fileLength ? file[d.RawAt + i] : (byte)0;
            long diffStart = -1, lastDiff = -1, unknownStart = -1;
            for (long i = 0; i <= length; i++)
            {
                bool unknown = false, differs = false;
                if (i < length)
                {
                    long rva = m.Rva + i;
                    unknown = !captured.PageCaptured((uint)rva);
                    differs = !unknown && !(rva < excluded.Length && excluded[(int)rva]) && rebuiltMapped[rva] != FileAt(i);
                }
                if (unknown)
                {
                    if (diffStart >= 0)
                    {
                        Add(m, diffStart, lastDiff + 1, "differs", FileAt);
                        diffStart = -1;
                    }
                    if (unknownStart < 0) unknownStart = i;
                    continue;
                }
                if (unknownStart >= 0)
                {
                    Add(m, unknownStart, i, "unknown", FileAt);
                    unknownStart = -1;
                }
                if (differs)
                {
                    if (diffStart < 0) diffStart = i;
                    lastDiff = i;
                }
                else if (diffStart >= 0 && (i == length || i - lastDiff > MaxGap))
                {
                    Add(m, diffStart, lastDiff + 1, "differs", FileAt);
                    diffStart = -1;
                }
            }
        }
        return new ImageChangeSet(ranges, total, total > ranges.Count, MaxRanges);
    }
}
