using System.Buffers.Binary;
using System.Text.Json;
using Corvus.Core;
using Corvus.Native.Dump;
using Corvus.Native.Providers.Worker.Yara;

namespace Corvus.Services.Analysis;

/// <summary>
/// YARA rules over captured memory (a dump file, or a running program's memory saved by its session): one block scan of every region at its virtual address, so a rule's
/// patterns may sit in different regions, then a scan of each region as a file of its own for what block scans leave
/// undefined (modules, <c>filesize</c>, <c>uint16(0)</c>). Hits are per region, offsets are virtual addresses.
/// </summary>
internal static class YaraMemoryScan
{
    /// <summary>Largest region scanned in one piece; a larger one is scanned in parts of this size.</summary>
    public const int MaxRegionBytes = 64 << 20;

    /// <summary>A scanned stretch of memory: contiguous captured ranges, cut at module bounds and at <see cref="MaxRegionBytes"/>.</summary>
    internal readonly record struct Region(ulong Start, int Size, string? Module)
    {
        public ulong End => Start + (ulong)Size;
        public string Name => $"0x{Start:X}-0x{End:X}{(Module != null ? " " + Module : "")}";
    }

    /// <summary>True when <paramref name="path"/> is a minidump or a core file.</summary>
    public static bool IsDump(string path)
    {
        try
        {
            using var f = File.OpenHandle(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            Span<byte> head = stackalloc byte[4];
            if (RandomAccess.Read(f, head, 0) == 4 && BinaryPrimitives.ReadUInt32LittleEndian(head) == MinidumpFile.Signature) return true;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { return false; }
        return CoreFile.IsCore(path);
    }

    /// <summary>The hits of <paramref name="rules"/> in the dump at <paramref name="path"/>, the regions scanned and notes.</summary>
    public static (List<YaraHit> Hits, int Regions, List<string> Notes) Scan(YaraRules rules, string path, TimeSpan timeout, CancellationToken ct)
    {
        IProcessMemory memory;
        IReadOnlyList<DumpMemoryRange> ranges;
        IDisposable owner;
        if (CoreFile.IsCore(path))
        {
            var core = CoreFile.Open(path);
            (memory, ranges, owner) = (core, core.MemoryRanges, core);
        }
        else
        {
            var minidump = MinidumpFile.Open(path);
            (memory, ranges, owner) = (minidump, minidump.MemoryRanges, minidump);
        }
        using var _ = owner;
        return Scan(rules, ranges, memory.Modules, memory.ReadMemory, timeout, ct);
    }

    /// <summary>
    /// The hits of <paramref name="rules"/> in a running program's memory saved by its session: <paramref name="capture"/>
    /// holds the bytes, <paramref name="index"/> each range's address, size and offset in it and the program's modules.
    /// </summary>
    public static (List<YaraHit> Hits, int Regions, List<string> Notes) ScanCapture(YaraRules rules, string capture, string index, TimeSpan timeout,
        CancellationToken ct)
    {
        var map = JsonSerializer.Deserialize<CaptureIndex>(File.ReadAllText(index), YaraOps.Json)
                  ?? throw new ToolError(ErrorCode.MalformedInput, $"{index} is not a memory capture index.");
        var ranges = map.Ranges.Select(r => new DumpMemoryRange(Hex(r.Base), r.Size, r.Offset)).OrderBy(r => r.Start).ToList();
        var modules = map.Modules.Select(m => new DumpModule(Hex(m.Base), m.Size, 0, 0, m.Path, null, null, null)).OrderBy(m => m.Base).ToList();
        using var file = File.OpenHandle(capture, FileMode.Open, FileAccess.Read, FileShare.Read);
        int Read(ulong address, Span<byte> destination)
        {
            var read = 0;
            while (read < destination.Length)
            {
                var at = address + (ulong)read;
                var i = ranges.FindLastIndex(r => r.Start <= at);
                if (i < 0 || at >= ranges[i].End) break;
                var n = (int)Math.Min((ulong)(destination.Length - read), ranges[i].End - at);
                if (RandomAccess.Read(file, destination.Slice(read, n), ranges[i].FileOffset + (long)(at - ranges[i].Start)) != n) break;
                read += n;
            }
            return read;
        }
        return Scan(rules, ranges, modules, Read, timeout, ct);
    }

    private static ulong Hex(string value) => Convert.ToUInt64(value.StartsWith("0x", StringComparison.OrdinalIgnoreCase) ? value[2..] : value, 16);

    /// <summary>A memory capture's index, as the session worker writes it: addresses are hex strings.</summary>
    private sealed record CaptureIndex(IReadOnlyList<CaptureRange> Ranges, IReadOnlyList<CaptureModule> Modules);

    private sealed record CaptureRange(string Base, ulong Size, long Offset);

    private sealed record CaptureModule(string Base, uint Size, string Path);

    private delegate int MemoryReader(ulong address, Span<byte> destination);

    private static (List<YaraHit> Hits, int Regions, List<string> Notes) Scan(YaraRules rules, IReadOnlyList<DumpMemoryRange> ranges,
        IReadOnlyList<DumpModule> modules, MemoryReader read, TimeSpan timeout, CancellationToken ct)
    {
        var regions = Regions(ranges, modules, out var split);
        var buffer = new byte[regions.Count == 0 ? 0 : regions.Max(r => r.Size)];

        // Rules a block scan matched are reported from it, the rest from the per-region scans.
        var byRegion = new SortedDictionary<int, List<YaraRuleMatch>>();
        var unplaced = new List<YaraRuleMatch>();
        var blockMatched = new HashSet<(string, string)>();
        using (var block = rules.Scanner(timeout))
        {
            foreach (var region in regions)
            {
                ct.ThrowIfCancellationRequested();
                block.ScanBlock(region.Start, buffer, read(region.Start, buffer.AsSpan(0, region.Size)));
            }
            foreach (var rule in block.Finish())
            {
                blockMatched.Add((rule.Namespace, rule.Rule));
                if (rule.Patterns.Count == 0) unplaced.Add(rule);
                foreach (var group in rule.Patterns.GroupBy(p => IndexOf(regions, (ulong)p.Offset)))
                    Add(byRegion, group.Key, rule with { Patterns = [.. group] });
            }
        }
        using (var each = rules.Scanner(timeout))
            for (int i = 0; i < regions.Count; i++)
            {
                ct.ThrowIfCancellationRequested();
                var region = regions[i];
                var n = read(region.Start, buffer.AsSpan(0, region.Size));
                foreach (var rule in each.Scan(buffer, n))
                    if (!blockMatched.Contains((rule.Namespace, rule.Rule)))
                        Add(byRegion, i, rule with { Patterns = [.. rule.Patterns.Select(p => p with { Offset = p.Offset + (long)region.Start })] });
            }

        var hits = new List<YaraHit>();
        if (unplaced.Count > 0) hits.Add(new YaraHit("process memory", unplaced));
        hits.AddRange(byRegion.Select(r => new YaraHit(regions[r.Key].Name, r.Value)));
        var bytes = regions.Sum(r => (long)r.Size);
        var notes = new List<string>
        {
            $"Process memory: {regions.Count:N0} regions, {bytes:N0} bytes from {ranges.Count:N0} captured ranges; offsets are virtual addresses. " +
            "Patterns that cross a region boundary are not matched; modules, filesize and uint16(0) read each region as a file of its own.",
        };
        if (split > 0) notes.Add($"{split:N0} regions over {MaxRegionBytes >> 20} MB were scanned in {MaxRegionBytes >> 20} MB parts.");
        return (hits, regions.Count, notes);
    }

    private static void Add(SortedDictionary<int, List<YaraRuleMatch>> byRegion, int region, YaraRuleMatch rule)
    {
        if (!byRegion.TryGetValue(region, out var list)) byRegion[region] = list = [];
        list.Add(rule);
    }

    /// <summary>The region holding <paramref name="address"/> (regions are sorted and disjoint).</summary>
    private static int IndexOf(List<Region> regions, ulong address)
    {
        int lo = 0, hi = regions.Count - 1;
        while (lo < hi)
        {
            int mid = (lo + hi + 1) >>> 1;
            if (regions[mid].Start <= address) lo = mid;
            else hi = mid - 1;
        }
        return lo;
    }

    /// <summary>Contiguous captured ranges joined, cut where a module starts or ends and at <see cref="MaxRegionBytes"/>.</summary>
    internal static List<Region> Regions(IReadOnlyList<DumpMemoryRange> ranges, IReadOnlyList<DumpModule> modules, out int split)
    {
        var cuts = new SortedSet<ulong>(modules.SelectMany(m => new[] { m.Base, m.Base + m.Size }));
        var regions = new List<Region>();
        var oversized = 0;
        ulong start = 0, end = 0;
        foreach (var range in ranges.Where(r => r.Size > 0).OrderBy(r => r.Start))
        {
            if (range.Start == end && end != 0) end = Math.Max(end, range.End);
            else
            {
                Emit(start, end);
                (start, end) = (range.Start, range.End);
            }
        }
        Emit(start, end);
        split = oversized;
        return regions;

        void Emit(ulong from, ulong to)
        {
            var cut = false;
            while (from < to)
            {
                var next = to - from >= 2 ? cuts.GetViewBetween(from + 1, to - 1).Min : 0;
                var stop = next > from ? next : to;
                if (stop - from > MaxRegionBytes)
                {
                    if (!cut) oversized++;
                    cut = true;
                    stop = from + MaxRegionBytes;
                }
                var module = modules.FirstOrDefault(m => from >= m.Base && from - m.Base < m.Size)?.FileName;
                regions.Add(new Region(from, (int)(stop - from), module));
                from = stop;
            }
        }
    }
}
