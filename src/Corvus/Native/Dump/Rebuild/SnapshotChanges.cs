using System.Buffers.Binary;
using Corvus.Native.Pe;

namespace Corvus.Native.Dump.Rebuild;

/// <summary>One range of a module that differs between two dumps: its section, RVA, length, state (differs or unknown), whether it is code, and the bytes on both sides.</summary>
/// <param name="Before">Hex of the bytes in the first dump, cut to <see cref="SnapshotChanges.MaxBytes"/>; empty for an unknown range.</param>
/// <param name="After">Hex of the bytes in the second dump, cut to <see cref="SnapshotChanges.MaxBytes"/>; empty for an unknown range.</param>
public sealed record SnapshotChange(string Section, string Rva, int Length, string State, bool Code, string Before, string After);

/// <summary>The comparison of one module across two dumps: <paramref name="State"/> is compared or refused, with the reason when refused.</summary>
public sealed record SnapshotChangeSet(string State, string Reason, IReadOnlyList<SnapshotChange> Ranges, int Total, bool Truncated, int Limit);

/// <summary>Lists the ranges where one module differs between two dumps of the same program.</summary>
public static class SnapshotChanges
{
    /// <summary>Most ranges listed.</summary>
    public const int MaxRanges = 100_000;

    /// <summary>Most bytes shown on each side of a range; the range keeps its full length.</summary>
    public const int MaxBytes = 64;

    /// <summary>Largest run of equal bytes that does not split a range.</summary>
    public const int MaxGap = 8;

    private const uint CodeSection = 0x20000020;

    /// <summary>
    /// The ranges of <paramref name="target"/> that differ between <paramref name="before"/> and <paramref name="after"/>,
    /// both read in mapped layout at the loaded base and merged across gaps of at most <see cref="MaxGap"/> bytes.
    /// A page captured in one dump only, or in neither, forms an <c>unknown</c> range. The result is <c>refused</c>
    /// with the reason when a header is not captured or the time stamp or image size differs.
    /// </summary>
    public static SnapshotChangeSet Compare(IProcessMemory before, IProcessMemory after, RebuildTarget target, CancellationToken ct = default)
    {
        var first = CapturedImageReader.Read(before, target, ct);
        var second = CapturedImageReader.Read(after, target, ct);
        if (first is null) return Refused("the module header is not captured in the first dump");
        if (second is null) return Refused("the module header is not captured in the second dump");
        if (!DumpImages.TryHeader(first.Image, out uint stamp1, out uint size1, out _)
            || !DumpImages.TryHeader(second.Image, out uint stamp2, out uint size2, out _))
            return Refused("the module header is not readable");
        if (stamp1 != stamp2 || size1 != size2)
            return Refused($"different build: first dump time stamp 0x{stamp1:X8} size 0x{size1:X}, second dump time stamp 0x{stamp2:X8} size 0x{size2:X}");

        var ranges = new List<SnapshotChange>();
        int total = 0;
        byte[] a = first.Image, b = second.Image;

        void Add(Section s, long start, long end, string state)
        {
            total++;
            if (ranges.Count >= MaxRanges) return;
            int shown = (int)Math.Min(end - start, MaxBytes);
            int at = (int)(s.Rva + start);
            ranges.Add(new SnapshotChange(s.Name, $"0x{at:X}", (int)(end - start), state, (s.Characteristics & CodeSection) != 0,
                state == "unknown" ? "" : Convert.ToHexStringLower(a.AsSpan(at, shown)),
                state == "unknown" ? "" : Convert.ToHexStringLower(b.AsSpan(at, shown))));
        }

        foreach (var s in Sections(a))
        {
            long length = Math.Max(0, Math.Min(s.Size, Math.Min(a.Length, b.Length) - (long)s.Rva));
            long diffStart = -1, lastDiff = -1, unknownStart = -1;
            for (long i = 0; i <= length; i++)
            {
                bool unknown = false, differs = false;
                if (i < length)
                {
                    uint rva = (uint)(s.Rva + i);
                    unknown = !first.PageCaptured(rva) || !second.PageCaptured(rva);
                    differs = !unknown && a[rva] != b[rva];
                }
                if (unknown)
                {
                    if (diffStart >= 0)
                    {
                        Add(s, diffStart, lastDiff + 1, "differs");
                        diffStart = -1;
                    }
                    if (unknownStart < 0) unknownStart = i;
                    continue;
                }
                if (unknownStart >= 0)
                {
                    Add(s, unknownStart, i, "unknown");
                    unknownStart = -1;
                }
                if (differs)
                {
                    if (diffStart < 0) diffStart = i;
                    lastDiff = i;
                }
                else if (diffStart >= 0 && (i == length || i - lastDiff > MaxGap))
                {
                    Add(s, diffStart, lastDiff + 1, "differs");
                    diffStart = -1;
                }
            }
        }
        return new SnapshotChangeSet("compared", "", ranges, total, total > ranges.Count, MaxRanges);
    }

    private static SnapshotChangeSet Refused(string reason) => new("refused", reason, [], 0, false, MaxRanges);

    private sealed record Section(string Name, uint Rva, uint Size, uint Characteristics);

    // Reads the section table of a mapped image; empty when it lies outside the
    // headers.
    private static List<Section> Sections(byte[] image)
    {
        var sections = new List<Section>();
        int nt = BinaryPrimitives.ReadInt32LittleEndian(image.AsSpan(0x3C));
        int count = BinaryPrimitives.ReadUInt16LittleEndian(image.AsSpan(nt + 6));
        int table = nt + 24 + BinaryPrimitives.ReadUInt16LittleEndian(image.AsSpan(nt + 20));
        if (count > PeLimits.MaxSections || table + 40L * count > Math.Min(image.Length, 0x1000)) return sections;
        for (int i = 0; i < count; i++)
        {
            var h = image.AsSpan(table + 40 * i, 40);
            int nameLength = h[..8].IndexOf((byte)0);
            uint virtualSize = BinaryPrimitives.ReadUInt32LittleEndian(h[8..]), rawSize = BinaryPrimitives.ReadUInt32LittleEndian(h[16..]);
            sections.Add(new Section(System.Text.Encoding.ASCII.GetString(h[..(nameLength < 0 ? 8 : nameLength)]),
                BinaryPrimitives.ReadUInt32LittleEndian(h[12..]), virtualSize != 0 ? virtualSize : rawSize,
                BinaryPrimitives.ReadUInt32LittleEndian(h[36..])));
        }
        return sections;
    }
}
