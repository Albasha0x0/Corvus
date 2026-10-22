using Corvus.Native;
using Corvus.Native.Dump;

namespace Corvus.Services;

/// <summary>The summary and read views of a region-set dump (see <see cref="RegionSetFile"/>).</summary>
public sealed partial class MinidumpService
{
    private static DumpReport SummarizeRegions(Session s, RegionSetFile regions)
    {
        int missing = regions.Regions.Count(r => r.Missing);
        var notes = new List<string>
        {
            $"Region-set dump (format {RegionSetFile.Format}, {ArchName(regions.Arch, 0)}){(regions.Source is { Length: > 0 } src ? $" from {src}" : "")}: " +
            $"{regions.Regions.Count} region(s), {regions.Modules.Count} module(s).",
            "Threads, exception, system and runtime state are unknown: a region set carries memory and modules only.",
        };
        if (missing > 0) notes.Add($"{missing} region file(s) missing: their ranges read as unknown (issues name them).");
        var main = regions.Modules.FirstOrDefault(m => m.FileName.EndsWith(".exe", StringComparison.OrdinalIgnoreCase));
        return new DumpReport(s.Id, "summary")
        {
            Path = regions.Path,
            FileSize = new FileInfo(regions.Path).Length,
            Process = new ProcessSummary(regions.ProcessId, main?.Path, null, null, false, null),
            Counts = new DumpTotals(regions.Modules.Count, 0, 0, regions.Regions.Count - missing, regions.Regions.Count, regions.CapturedBytes, false, 0),
            Issues = regions.Issues.Select(i => $"{i.Area}: {i.Message}").ToList(),
            Notes = notes,
        };
    }

    private async Task<MemoryBytes> RegionReadBytes(Session s, RegionSetFile d, string address, int length, bool imageFallback, CancellationToken ct)
    {
        ulong va = ParseAddress(d, address);
        length = Math.Clamp(length, 1, MaxReadLength);
        var buffer = new byte[length];
        int n = d.ReadMemory(va, buffer);
        string source = n > 0 ? "dump_memory" : "none";
        string? note = null;
        if (n < length && imageFallback && d.ModuleAt(va + (ulong)n) is { } m && s.Code(m) is { Image: { } image, Source: not "dump_memory" } mc && va >= m.Base)
        {
            var tmp = new byte[length];
            int k = image.Read((uint)(va - m.Base), tmp);
            if (k > n)
            {
                note = n == 0 ? $"not in the region files; bytes from the module image ({mc.Source})" : $"the regions hold {n} bytes here; the rest is from the module image ({mc.Source})";
                tmp.AsSpan(n, k - n).CopyTo(buffer.AsSpan(n));
                source = n > 0 ? $"dump_memory + module_image ({mc.Source})" : $"module_image ({mc.Source})";
                n = k;
            }
        }
        // A missing or short region file leaves its range unknown, not absent.
        if (n < length && note == null)
            note = d.RegionSetAt(va + (ulong)n) is { } gap
                ? $"{(n > 0 ? $"the regions hold {n} of the {length} bytes; " : "")}0x{va + (ulong)n:X} is in {gap.File}, " +
                  (gap.Missing ? "which is missing: its bytes are unknown" : $"which holds 0x{gap.Held:X} of its 0x{gap.Size:X} bytes: the rest is unknown")
                : n == 0 ? "no region holds this address" : $"the regions hold {n} of the {length} bytes; the rest is in no region";
        var location = await Locate(s, va, false, ct);
        var region = d.RegionSetAt(va);
        var head = new MemoryRead(s.Id, Hex(d, va), length, n, source, location.Symbol ?? location.Note,
            region is { } r ? $"{Hex(d, r.Base)}-{Hex(d, r.End)} ({r.File})" : null, region is { Protect: not 0 } p ? ProtectName(p.Protect) : null,
            Convert.ToHexString(buffer, 0, n), 0, note);
        return new MemoryBytes(head, va, buffer[..n], d.Is64Bit);
    }
}
