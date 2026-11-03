using Corvus.Native.Live;

namespace Corvus.Native.Dump.Rebuild;

/// <summary>An executable region with no image behind it; <see cref="Captured"/> has one flag per 4 KB page and uncaptured pages are zero in <see cref="Bytes"/>.</summary>
public sealed record CodeRegion(ulong Base, ulong Size, uint Protect, byte[] Bytes, bool[] Captured)
{
    public int CapturedPercent => Captured.Length == 0 ? 0 : (int)(Captured.Count(c => c) * 100L / Captured.Length);
}

/// <summary>The code regions read, and notes naming what was left out or could not be seen.</summary>
public sealed record CodeRegionSet(IReadOnlyList<CodeRegion> Regions, IReadOnlyList<string> Notes);

/// <summary>Reads executable memory that no mapped image backs, such as code generated at run time.</summary>
public static class CodeRegions
{
    /// <summary>Most regions a read returns.</summary>
    public const int MaxRegions = 256;

    /// <summary>Most bytes, over all regions, a read returns.</summary>
    public const long MaxBytes = 512L << 20;

    private const int Page = 0x1000;
    // Same rule as the unbacked memory view.
    private const uint ImageType = 0x1000000;

    /// <summary>
    /// The committed executable regions of <paramref name="memory"/> that are not mapped images, in address order.
    /// A region past <see cref="MaxRegions"/> or <see cref="MaxBytes"/> is left out and named in the notes;
    /// a source with no region list returns no regions and a note saying they are unknown.
    /// </summary>
    public static CodeRegionSet Read(IProcessMemory memory, CancellationToken ct) => Read(memory, MaxRegions, MaxBytes, ct);

    internal static CodeRegionSet Read(IProcessMemory memory, int maxRegions, long maxBytes, CancellationToken ct)
    {
        var notes = new List<string>();
        var list = RegionList(memory);
        if (list == null)
            return new CodeRegionSet([], ["The source holds no memory region list, so which regions are executable and unbacked is unknown."]);

        var regions = new List<CodeRegion>();
        long total = 0;
        int skippedCount = 0;
        long skippedBytes = 0;
        foreach (var r in list.Where(r => r.IsExecutable && r.Type != ImageType).OrderBy(r => r.Base))
        {
            ct.ThrowIfCancellationRequested();
            if (regions.Count >= maxRegions || r.Size > (ulong)(maxBytes - total))
            {
                skippedCount++;
                skippedBytes += (long)Math.Min(r.Size, long.MaxValue / 4);
                continue;
            }
            var bytes = new byte[r.Size];
            var captured = new bool[(r.Size + Page - 1) / Page];
            for (ulong off = 0; off < r.Size; off += Page)
            {
                ct.ThrowIfCancellationRequested();
                int n = (int)Math.Min(Page, r.Size - off);
                captured[off / Page] = memory.ReadMemory(r.Base + off, bytes.AsSpan((int)off, n)) == n;
            }
            total += bytes.Length;
            regions.Add(new CodeRegion(r.Base, r.Size, r.Protect, bytes, captured));
        }

        if (skippedCount > 0)
            notes.Add($"{skippedCount} region(s), {skippedBytes} bytes, were not read: the limit is {maxRegions} regions and {maxBytes} bytes in total.");
        if (regions.Any(r => r.Captured.Contains(false)))
            notes.Add("Pages the source does not hold are zero and flagged in the captured-page map.");
        return new CodeRegionSet(regions, notes);
    }

    // Regions as VirtualQuery rows; null when the source cannot list them.
    private static IReadOnlyList<DumpMemoryRegion>? RegionList(IProcessMemory memory) => memory switch
    {
        MinidumpFile dump => dump.MemoryRegions.Count > 0 ? dump.MemoryRegions : null,
        LiveProcess live => live.Regions(),
        CoreFile core => core.Segments.Select(g => new DumpMemoryRegion(g.Start, g.Start, 0, g.MemorySize, 0x1000,
            (g.Flags & 1) != 0 ? 0x20u : 0x02u, core.ModuleAt(g.Start) != null ? ImageType : 0x20000u)).ToList(),
        _ => null,
    };
}
