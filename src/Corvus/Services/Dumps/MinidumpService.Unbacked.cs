using System.Globalization;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Corvus.Core;
using Corvus.Native.Dump;
using Corvus.Native.Dump.Managed;
using Corvus.Services.Analysis;

namespace Corvus.Services;

/// <summary>Executable regions with no image behind them (regionFilter=unbacked), for dumps and running processes.</summary>
public sealed partial class MinidumpService
{
    /// <summary>open_minidump view=memory filters: every region, or the executable regions with no image.</summary>
    public static readonly string[] MemoryFilters = ["all", "unbacked"];

    private const uint ImageType = 0x1000000;
    private const int HeaderProbe = 0x1000;

    /// <summary>Largest part of a region and most bytes in total that a YARA scan of unbacked regions reads.</summary>
    private const long MaxScanRegion = 16L << 20, MaxScanBytes = 256L << 20;

    private static readonly Regex AddressRange = new(@"^0x(?<a>[0-9A-Fa-f]+)-0x(?<b>[0-9A-Fa-f]+)", RegexOptions.NonBacktracking | RegexOptions.CultureInvariant);

    /// <summary>True for a committed executable region that is not a mapped image.</summary>
    internal static bool IsUnbacked(DumpMemoryRegion r) => r.IsExecutable && r.Type != ImageType;

    /// <summary>The unbacked rows of a page, the count of all of them, and notes naming what was not checked.</summary>
    internal sealed record UnbackedPage(IReadOnlyList<UnbackedRegion> Rows, int Total, IReadOnlyList<string> Notes);

    /// <summary>The memory regions of a dump or core as VirtualQuery-style rows; null when it holds no region list.</summary>
    private static IReadOnlyList<DumpMemoryRegion>? RegionList(Session s)
    {
        if (s.Core is { } core)
            return core.Segments.Select(g => new DumpMemoryRegion(g.Start, g.Start, 0, g.MemorySize, 0x1000, (g.Flags & 1) != 0 ? 0x20u : 0x02u,
                core.ModuleAt(g.Start) != null ? ImageType : core.Files.Any(f => f.Start < g.End && g.Start < f.End) ? 0x40000u : 0x20000u)).ToList();
        return s.Dump.MemoryRegions.Count > 0 ? s.Dump.MemoryRegions : null;
    }

    /// <summary>The unbacked regions of a dump (open_minidump view=memory regionFilter=unbacked); runtime code heaps come from the DAC.</summary>
    internal async Task<(string Id, UnbackedPage Page)> UnbackedMemory(string path, int offset, int limit, string? yara, DacRequest request, CancellationToken ct)
    {
        using var s = Open(path, null);
        if (s.Regions != null)
            throw new ToolError(ErrorCode.Unsupported, "A region-set dump has no region types: whether a region has an image behind it is unknown.", "open_minidump view=memory lists its regions");
        var regions = RegionList(s);
        if (regions == null)
            return (s.Id, new UnbackedPage([], 0, ["The dump has no memory region list (MemoryInfoList), so which regions are executable and unbacked is unknown; write it with full memory info."]));
        IReadOnlyList<RuntimeCodeHeap>? heaps = null;
        string? note = null;
        if (HostsClr(s.Memory, out var runtime))
        {
            var decoder = runtime == "Mono" ? null : await Decoder(s, request, ct).ConfigureAwait(false);
            (heaps, note) = HeapsOf(decoder, runtime!);
        }
        Func<DumpMemoryRegion, ulong?> captured = s.Core != null ? r => null : r => Captured(s.Dump.MemoryRanges, r.Base, r.Base + r.Size);
        return (s.Id, await Unbacked(s, regions, captured, heaps, note, yara, offset, limit, ct).ConfigureAwait(false));
    }

    /// <summary>The runtime's code heaps, or null with the note that says why they are unknown.</summary>
    internal static (IReadOnlyList<RuntimeCodeHeap>? Heaps, string? Note) HeapsOf(ClrDecoder? decoder, string runtime)
    {
        if (decoder == null) return (null, $"{runtime}: its JIT ranges are not named, so executable regions the runtime owns stay listed as unbacked.");
        if (!decoder.Loaded) return (null, $"The {runtime} DAC was not loaded ({decoder.Dac.Status}: {decoder.Dac.Detail}); runtime code heaps are not labelled jit.");
        if (decoder.CodeHeaps() is { } heaps) return (heaps, null);
        return (null, $"{runtime} is decoded out of process (32-bit); runtime code heaps are not labelled jit.");
    }

    /// <summary>Classifies the unbacked regions among <paramref name="regions"/>: jit (inside runtime code heaps), or unbacked with its first bytes and YARA hits.</summary>
    internal async Task<UnbackedPage> Unbacked(Session s, IReadOnlyList<DumpMemoryRegion> regions, Func<DumpMemoryRegion, ulong?> captured,
        IReadOnlyList<RuntimeCodeHeap>? heaps, string? heapNote, string? yara, int offset, int limit, CancellationToken ct)
    {
        var notes = new List<string>();
        var candidates = regions.Where(IsUnbacked).OrderBy(r => r.Base).ToList();
        var kinds = new Dictionary<DumpMemoryRegion, string>();
        var headers = new Dictionary<DumpMemoryRegion, string>();
        var plain = new List<DumpMemoryRegion>();
        var inRuntime = new HashSet<DumpMemoryRegion>();
        foreach (var r in candidates)
        {
            ct.ThrowIfCancellationRequested();
            if (heaps != null && Overlap(heaps, r.Base, r.Base + r.Size) is var (covered, names) && names.Count > 0)
            {
                kinds[r] = (covered ? "jit: " : "partly inside ") + string.Join(", ", names);
                if (covered)
                {
                    inRuntime.Add(r);
                    continue;
                }
            }
            plain.Add(r);
            var head = new byte[HeaderProbe];
            int got = s.Memory.ReadMemory(r.Base, head.AsSpan(0, (int)Math.Min((ulong)HeaderProbe, r.Size)));
            headers[r] = got < 0x40 ? "unknown" : DumpImages.TryHeader(head.AsSpan(0, got), out _, out _, out _) ? "pe" : "none";
        }
        var hits = new Dictionary<DumpMemoryRegion, List<string>>();
        if (yara != null && plain.Count > 0) hits = await Task.Run(() => YaraRegions(s, plain.Where(r => headers[r] != "unknown").ToList(), yara, notes, ct), ct).ConfigureAwait(false);
        var rows = new List<UnbackedRegion>();
        int jit = 0, noteworthy = 0;
        foreach (var r in candidates)
        {
            var row = UnbackedRegion.Of(RegionRow(s.Memory, r, captured(r)));
            if (kinds.TryGetValue(r, out var kind) && inRuntime.Contains(r))
            {
                jit++;
                rows.Add(row with { Backing = "jit", Detail = kind["jit: ".Length..] });
                continue;
            }
            var matched = hits.GetValueOrDefault(r);
            bool flagged = headers[r] == "pe" || matched is { Count: > 0 };
            if (flagged) noteworthy++;
            rows.Add(row with
            {
                Backing = "unbacked", Header = headers[r], Yara = matched is { Count: > 0 } ? matched : null, Noteworthy = flagged, Detail = kind,
            });
        }
        notes.Insert(0, $"{rows.Count} executable region(s) with no image: {noteworthy} noteworthy (a PE header at the start or a YARA hit), {jit} jit, {rows.Count - noteworthy - jit} listed.");
        if (heapNote != null) notes.Add(heapNote);
        if (yara == null) notes.Add("No YARA rules were given: a region is noteworthy only with a PE header at its start.");
        if (headers.Values.Any(h => h == "unknown"))
            notes.Add("A region whose first bytes the dump does not hold has an unknown header and cannot be noteworthy.");
        return new UnbackedPage([.. rows.Skip(Math.Max(0, offset)).Take(limit)], rows.Count, notes);
    }

    /// <summary>Whether [start, end) lies wholly inside the sorted <paramref name="heaps"/>, and the kinds of those it touches.</summary>
    private static (bool Covered, List<string> Kinds) Overlap(IReadOnlyList<RuntimeCodeHeap> heaps, ulong start, ulong end)
    {
        var kinds = new SortedSet<string>(StringComparer.Ordinal);
        int lo = 0, hi = heaps.Count;
        while (lo < hi)
        {
            int mid = (lo + hi) >>> 1;
            if (heaps[mid].End <= start) lo = mid + 1; else hi = mid;
        }
        ulong cursor = start;
        bool gap = false;
        for (int i = lo; i < heaps.Count && heaps[i].Start < end; i++)
        {
            kinds.Add(heaps[i].Kind);
            if (heaps[i].Start > cursor) gap = true;
            cursor = Math.Max(cursor, heaps[i].End);
        }
        return (!gap && cursor >= end && kinds.Count > 0, [.. kinds]);
    }

    /// <summary>Runs the YARA rules <paramref name="query"/> names over the bytes of <paramref name="regions"/> and attributes each hit to its region.</summary>
    private static Dictionary<DumpMemoryRegion, List<string>> YaraRegions(Session s, List<DumpMemoryRegion> regions, string query, List<string> notes, CancellationToken ct)
    {
        var found = new Dictionary<DumpMemoryRegion, List<string>>();
        if (regions.Count == 0) return found;
        var dir = Native.Providers.PrivateFolder.Temp("region-yara", $"{Environment.ProcessId}-{Guid.NewGuid():N}");
        // The capture holds the program's memory: readable by this user only, and deleted after the scan.
        Native.Providers.PrivateFolder.Create(dir);
        try
        {
            var capture = Path.Combine(dir, "memory.bin");
            var ranges = new JsonArray();
            var scanned = new List<(DumpMemoryRegion Region, ulong Size)>();
            long total = 0;
            int left = 0;
            using (var file = new FileStream(capture, FileMode.CreateNew, FileAccess.Write, FileShare.None))
                foreach (var r in regions)
                {
                    ct.ThrowIfCancellationRequested();
                    long want = (long)Math.Min(r.Size, (ulong)MaxScanRegion);
                    if (total + want > MaxScanBytes) { left++; continue; }
                    var bytes = new byte[want];
                    int got = s.Memory.ReadMemory(r.Base, bytes);
                    if (got == 0) continue;
                    ranges.Add(new JsonObject { ["base"] = $"0x{r.Base:X}", ["size"] = (ulong)got, ["offset"] = file.Position });
                    file.Write(bytes, 0, got);
                    scanned.Add((r, (ulong)got));
                    total += got;
                }
            var index = Path.Combine(dir, "memory.json");
            File.WriteAllText(index, new JsonObject { ["ranges"] = ranges, ["modules"] = new JsonArray() }.ToJsonString());
            var request = new JsonObject { ["path"] = capture, ["capture"] = index };
            YaraSearchKind.WithRules(request, query);
            var result = YaraSearchKind.Run(request, "unbacked regions", ct);
            if (result.Errors.Count > 0 && result.Rules == 0)
                throw new ToolError(ErrorCode.InvalidArgument, $"The YARA rules do not compile: {result.Errors[0].Message}", "pass rule text, a .yar file or folder, or pack:<name>");
            foreach (var hit in result.Hits)
                foreach (var rule in hit.Rules)
                {
                    var label = rule.Namespace is "default" or "" ? rule.Rule : $"{rule.Namespace}:{rule.Rule}";
                    IEnumerable<DumpMemoryRegion> where;
                    if (rule.Patterns.Count > 0)
                        where = scanned.Where(e => rule.Patterns.Any(p => (ulong)p.Offset >= e.Region.Base && (ulong)p.Offset - e.Region.Base < e.Size)).Select(e => e.Region);
                    else if (AddressRange.Match(hit.Path) is { Success: true } m)
                    {
                        ulong from = ulong.Parse(m.Groups["a"].Value, NumberStyles.HexNumber, CultureInfo.InvariantCulture), to = ulong.Parse(m.Groups["b"].Value, NumberStyles.HexNumber, CultureInfo.InvariantCulture);
                        where = scanned.Where(e => e.Region.Base < to && from < e.Region.Base + e.Size).Select(e => e.Region);
                    }
                    else where = [];
                    foreach (var region in where)
                    {
                        if (!found.TryGetValue(region, out var names)) found[region] = names = [];
                        if (!names.Contains(label)) names.Add(label);
                    }
                }
            notes.Add($"YARA: {result.Rules:N0} rule(s) over {scanned.Count:N0} region(s), {total:N0} bytes; a region over {MaxScanRegion >> 20} MB is scanned in its first {MaxScanRegion >> 20} MB.");
            if (left > 0) notes.Add($"{left:N0} region(s) past the {MaxScanBytes >> 20} MB scan limit were not scanned: their YARA result is unknown.");
            return found;
        }
        finally
        {
            try { Directory.Delete(dir, recursive: true); }
            catch (Exception e) when (e is IOException or UnauthorizedAccessException) { }
        }
    }
}
