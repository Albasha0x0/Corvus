using System.Buffers.Binary;
using System.Collections;
using Corvus.Native.Pe;

namespace Corvus.Native.Dump.Rebuild;

/// <summary>Compares a rebuilt image with the module's file on disk.</summary>
public static class DiskCompare
{
    /// <summary>Most differing ranges listed.</summary>
    public const int MaxRanges = 64;

    private const uint CodeSection = 0x20000020;
    private const ushort HighLow = 3, Dir64 = 10;
    private const int ImportAddressTable = 12, RelocationTable = 5;

    /// <summary>The comparison, or null when no file of the same build is found.</summary>
    public static DiskComparison? Compare(byte[] rebuilt, CapturedImage captured, RebuildOptions options, List<RebuildCheck> checks)
    {
        if (!options.CompareWithDisk)
        {
            checks.Add(RebuildCheck.Skipped("disk", "comparison with the file on disk is off"));
            return null;
        }
        var candidates = Candidates(captured.Target, options);
        if (!DumpImages.TryHeader(captured.Image, out uint stamp, out uint size, out _))
        {
            checks.Add(RebuildCheck.Unknown("disk", "the captured headers do not give a build"));
            return null;
        }
        foreach (var path in candidates)
        {
            if (!SameBuild(path, stamp, size)) continue;
            return CompareWith(path, rebuilt, captured, checks);
        }
        string searched = candidates.Count == 0 ? "no path recorded and no image directories" : string.Join("; ", candidates);
        checks.Add(RebuildCheck.Skipped("disk", $"no file of the same build found; searched {searched}"));
        return null;
    }

    // Fixup sites, the import address table and the checksum are left out; pages not captured are not compared.
    private static DiskComparison CompareWith(string path, byte[] rebuilt, CapturedImage captured, List<RebuildCheck> checks)
    {
        var file = ReadFile(path);
        if (file == null || !TryParse(file, out var disk) || !TryParse(rebuilt, out var memory))
        {
            checks.Add(RebuildCheck.Unknown("disk", $"file of the same build found, its sections are not readable: {path}"));
            return new DiskComparison(path, true, 0, 0, []);
        }

        var excluded = Excluded(file, disk);
        var ranges = new List<DiskDifference>();
        long bytes = 0, notCaptured = 0;
        int count = 0;
        foreach (var m in memory.Sections)
        {
            var d = disk.Sections.FirstOrDefault(s => s.Rva == m.Rva);
            if (d == null) continue;
            long length = Math.Min(Math.Min(m.VirtualSize, m.RawSize), Math.Min(d.VirtualSize, d.RawSize));
            length = Math.Max(0, Math.Min(length, Math.Min(rebuilt.Length - (long)m.RawAt, file.Length - (long)d.RawAt)));
            long runStart = -1;
            for (long i = 0; i <= length; i++)
            {
                bool differs = false;
                if (i < length)
                {
                    long rva = m.Rva + i;
                    if (!captured.PageCaptured((uint)rva)) notCaptured++;
                    else differs = !(rva < excluded.Length && excluded[(int)rva]) && rebuilt[m.RawAt + i] != file[d.RawAt + i];
                }
                if (differs)
                {
                    bytes++;
                    if (runStart < 0) runStart = i;
                    continue;
                }
                if (runStart < 0) continue;
                count++;
                if (ranges.Count < MaxRanges)
                    ranges.Add(new DiskDifference(m.Name, $"0x{m.Rva + runStart:X}", (int)(i - runStart), (m.Characteristics & CodeSection) != 0));
                runStart = -1;
            }
        }

        string left = notCaptured == 0 ? "" : $"; {notCaptured} bytes on pages not captured were not compared";
        checks.Add(bytes > 0
            ? RebuildCheck.Partial("disk", $"{bytes} bytes in {count} ranges differ from the file{left}")
            : notCaptured > 0
                ? RebuildCheck.Partial("disk", "same as the file where captured" + left)
                : RebuildCheck.Ok("disk", "same as the file"));
        return new DiskComparison(path, true, (int)Math.Min(bytes, int.MaxValue), count, ranges);
    }

    internal static BitArray Excluded(byte[] file, PeLayout pe)
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

    internal static byte[]? ReadFile(string path)
    {
        try
        {
            using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            if (stream.Length > ModuleRebuild.MaxImageBytes) return null;
            var bytes = new byte[stream.Length];
            stream.ReadExactly(bytes);
            return bytes;
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException)
        {
            return null;
        }
    }

    internal static bool TryParse(byte[] bytes, out PeLayout pe)
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

    internal sealed record SectionInfo(string Name, uint Rva, uint VirtualSize, uint RawAt, uint RawSize, uint Characteristics);

    internal sealed record PeLayout(int Opt, bool Is64, uint ImageSize, List<SectionInfo> Sections)
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

    /// <summary>The recorded path, its WOW64 system folder twin, then the module's file name in each image directory, without repeats.</summary>
    internal static List<string> Candidates(RebuildTarget target, RebuildOptions options)
    {
        var list = new List<string>();
        if (!string.IsNullOrWhiteSpace(target.Path))
        {
            list.Add(target.Path);
            if (WowTwin(target.Path) is { } twin) list.Add(twin);
        }
        string name = Path.GetFileName(target.Path ?? target.Name);
        if (name.Length == 0) name = target.Name;
        foreach (var dir in (options.ImageDirectories ?? "").Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            try { list.Add(Path.Combine(dir, name)); }
            catch (ArgumentException) { }
        }
        return [.. list.Distinct(StringComparer.OrdinalIgnoreCase)];
    }

    // A 32-bit module records System32 but its file is in the WOW64 folder; the
    // build check picks the right one.
    private static string? WowTwin(string path)
    {
        if (!OperatingSystem.IsWindows()) return null;
        var system = Environment.GetFolderPath(Environment.SpecialFolder.System);
        var wow = Environment.GetFolderPath(Environment.SpecialFolder.SystemX86);
        if (system.Length == 0 || wow.Length == 0 || system.Equals(wow, StringComparison.OrdinalIgnoreCase)) return null;
        var prefix = system.TrimEnd('\\') + "\\";
        return path.StartsWith(prefix, StringComparison.OrdinalIgnoreCase) ? Path.Combine(wow, path[prefix.Length..]) : null;
    }

    /// <summary>True when the file's time stamp and image size equal the captured headers; unreadable files are not the same build.</summary>
    internal static bool SameBuild(string path, uint stamp, uint size)
    {
        try
        {
            if (!File.Exists(path)) return false;
            var head = new byte[0x1000];
            using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            int got = stream.Read(head, 0, head.Length);
            return DumpImages.TryHeader(head.AsSpan(0, got), out uint fileStamp, out uint fileSize, out _) && fileStamp == stamp && fileSize == size;
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException)
        {
            return false;
        }
    }
}
