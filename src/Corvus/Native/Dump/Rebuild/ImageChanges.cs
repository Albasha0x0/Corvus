using System.Buffers.Binary;
using System.Collections;
using Corvus.Native.Pe;

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

    private const uint CodeSection = 0x20000020;
    private const ushort HighLow = 3, Dir64 = 10;
    private const int ImportAddressTable = 12, RelocationTable = 5;

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

        void Add(SectionInfo m, long start, long end, string state, long fileAt)
        {
            total++;
            if (ranges.Count >= MaxRanges) return;
            long length = end - start;
            int shown = (int)Math.Min(length, MaxBytes);
            string memoryHex = state == "unknown" ? "" : Convert.ToHexStringLower(rebuiltMapped.AsSpan((int)(m.Rva + start), shown));
            ranges.Add(new ImageChange(m.Name, $"0x{m.Rva + start:X}", (int)length, state, (m.Characteristics & CodeSection) != 0,
                Convert.ToHexStringLower(file.AsSpan((int)(fileAt + start), shown)), memoryHex));
        }

        foreach (var m in memory.Sections)
        {
            var d = disk.Sections.FirstOrDefault(s => s.Rva == m.Rva);
            if (d == null) continue;
            long length = Math.Min(Math.Min(m.VirtualSize, m.RawSize), Math.Min(d.VirtualSize, d.RawSize));
            length = Math.Max(0, Math.Min(length, Math.Min(rebuiltMapped.Length - (long)m.Rva, file.Length - (long)d.RawAt)));
            long diffStart = -1, lastDiff = -1, unknownStart = -1;
            for (long i = 0; i <= length; i++)
            {
                bool unknown = false, differs = false;
                if (i < length)
                {
                    long rva = m.Rva + i;
                    unknown = !captured.PageCaptured((uint)rva);
                    differs = !unknown && !(rva < excluded.Length && excluded[(int)rva]) && rebuiltMapped[rva] != file[d.RawAt + i];
                }
                if (unknown)
                {
                    if (diffStart >= 0)
                    {
                        Add(m, diffStart, lastDiff + 1, "differs", d.RawAt);
                        diffStart = -1;
                    }
                    if (unknownStart < 0) unknownStart = i;
                    continue;
                }
                if (unknownStart >= 0)
                {
                    Add(m, unknownStart, i, "unknown", d.RawAt);
                    unknownStart = -1;
                }
                if (differs)
                {
                    if (diffStart < 0) diffStart = i;
                    lastDiff = i;
                }
                else if (diffStart >= 0 && (i == length || i - lastDiff > MaxGap))
                {
                    Add(m, diffStart, lastDiff + 1, "differs", d.RawAt);
                    diffStart = -1;
                }
            }
        }
        return new ImageChangeSet(ranges, total, total > ranges.Count, MaxRanges);
    }

    private static BitArray Excluded(byte[] file, PeLayout pe)
    {
        var excluded = new BitArray((int)Math.Min(pe.ImageSize, int.MaxValue));
        void Mark(long start, long length)
        {
            for (long i = Math.Max(0, start); i < start + length && i < excluded.Length; i++) excluded[(int)i] = true;
        }

        var (iat, iatSize) = pe.Directory(file, ImportAddressTable);
        Mark(iat, iatSize);
        var (reloc, relocSize) = pe.Directory(file, RelocationTable);
        long at = pe.Offset(reloc), end = at + relocSize;
        if (reloc == 0 || at < 0 || end > file.Length) return excluded;
        while (at + 8 <= end)
        {
            uint page = BinaryPrimitives.ReadUInt32LittleEndian(file.AsSpan((int)at));
            uint block = BinaryPrimitives.ReadUInt32LittleEndian(file.AsSpan((int)at + 4));
            if (block < 8 || (block & 1) != 0 || at + block > end) break;
            for (long e = at + 8; e < at + block; e += 2)
            {
                ushort entry = BinaryPrimitives.ReadUInt16LittleEndian(file.AsSpan((int)e));
                ushort type = (ushort)(entry >> 12);
                if (type == HighLow) Mark(page + (entry & 0xFFF), 4);
                else if (type == Dir64) Mark(page + (entry & 0xFFF), 8);
            }
            at += block;
        }
        return excluded;
    }

    private static bool TryParse(byte[] bytes, out PeLayout pe)
    {
        pe = default!;
        if (bytes.Length < 0x40) return false;
        int nt = BinaryPrimitives.ReadInt32LittleEndian(bytes.AsSpan(0x3C));
        if (nt < 0 || nt + 24 + 112 > bytes.Length || BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(nt)) != 0x4550) return false;
        int count = BinaryPrimitives.ReadUInt16LittleEndian(bytes.AsSpan(nt + 6));
        int optSize = BinaryPrimitives.ReadUInt16LittleEndian(bytes.AsSpan(nt + 20));
        int opt = nt + 24;
        ushort magic = BinaryPrimitives.ReadUInt16LittleEndian(bytes.AsSpan(opt));
        if (magic != 0x10B && magic != 0x20B) return false;
        long table = opt + optSize;
        if (count > PeLimits.MaxSections || table + 40L * count > bytes.Length) return false;
        var sections = new List<SectionInfo>();
        for (int i = 0; i < count; i++)
        {
            var h = bytes.AsSpan((int)table + 40 * i, 40);
            int nameLength = h[..8].IndexOf((byte)0);
            sections.Add(new SectionInfo(System.Text.Encoding.ASCII.GetString(h[..(nameLength < 0 ? 8 : nameLength)]),
                BinaryPrimitives.ReadUInt32LittleEndian(h[12..]), BinaryPrimitives.ReadUInt32LittleEndian(h[8..]),
                BinaryPrimitives.ReadUInt32LittleEndian(h[20..]), BinaryPrimitives.ReadUInt32LittleEndian(h[16..]),
                BinaryPrimitives.ReadUInt32LittleEndian(h[36..])));
        }
        pe = new PeLayout(opt, magic == 0x20B, BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(opt + 56)), sections);
        return true;
    }

    private sealed record SectionInfo(string Name, uint Rva, uint VirtualSize, uint RawAt, uint RawSize, uint Characteristics);

    private sealed record PeLayout(int Opt, bool Is64, uint ImageSize, List<SectionInfo> Sections)
    {
        public (long Rva, long Size) Directory(byte[] file, int index)
        {
            int dirs = Opt + (Is64 ? 112 : 96);
            uint count = BinaryPrimitives.ReadUInt32LittleEndian(file.AsSpan(Opt + (Is64 ? 108 : 92)));
            if (index >= count || dirs + index * 8 + 8 > file.Length) return (0, 0);
            return (BinaryPrimitives.ReadUInt32LittleEndian(file.AsSpan(dirs + index * 8)),
                BinaryPrimitives.ReadUInt32LittleEndian(file.AsSpan(dirs + index * 8 + 4)));
        }

        public long Offset(long rva)
        {
            foreach (var s in Sections)
                if (rva >= s.Rva && rva - s.Rva < s.RawSize) return s.RawAt + rva - s.Rva;
            return -1;
        }
    }
}
