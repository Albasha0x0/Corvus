using Corvus.Core;
using Corvus.Native;

namespace Corvus.Services.Analysis;

/// <summary>
/// view=raw: the instruction sets headerless code reads as and the load bases its pointers imply (<see cref="RawCandidates"/>),
/// for a file with no known format, or for each region no firmware signature claims. Applies when at least one region
/// reads as an instruction set.
/// </summary>
internal sealed class RawCodeFileView : IFileSummaryView
{
    /// <summary>Most regions read; the rest are counted.</summary>
    public const int MaxRegions = 16;
    /// <summary>Most bytes read from one region.</summary>
    public const int MaxRegionBytes = 64 << 20;
    private const int MinBytes = 1024, MaxIsas = 4;

    /// <summary>
    /// One region read as headerless code: its instruction sets, best first, and the load bases the best one's pointers imply.
    /// <see cref="Load"/> is the load_assembly call for a region that is the whole file; null for a region inside it.
    /// </summary>
    public sealed record Region(string Offset, long Size, IReadOnlyList<IsaCandidate> Isas, IReadOnlyList<BaseCandidate> Bases, bool BaseClear,
        string? Load, IReadOnlyList<string> Notes);

    public sealed record Facts(IReadOnlyList<Region> Regions, IReadOnlyList<string> NotChecked, IReadOnlyList<string> Notes);

    public string Name => "raw";

    public FileView? Inspect(FileInput file, CancellationToken ct)
    {
        if (file.Length < MinBytes || file.Kind != "data" || Core.Pcap.PcapReader.Looks(file.Head) || SqliteDatabase.Looks(file.Head)) return null;
        var hits = file.Length >= 4096 ? FirmwareFileView.Hits(file, ct) : [];
        var spans = hits.Count == 0 || hits.All(h => h.Offset == 0)
            ? [new FirmwareFileView.Gap(0, file.Length)]
            : FirmwareFileView.Gaps(hits, file.Length);
        if (spans.Count == 0) return null;
        var notes = new List<string>();
        if (spans.Count > MaxRegions) notes.Add($"{spans.Count} regions without a signature; the first {MaxRegions} are read");
        var regions = new List<Region>();
        int none = 0;
        foreach (var span in spans.Take(MaxRegions))
        {
            ct.ThrowIfCancellationRequested();
            var regionNotes = new List<string>();
            int length = (int)Math.Min(span.Size, MaxRegionBytes);
            if (length < span.Size) regionNotes.Add($"the first {MaxRegionBytes >> 20} MiB of {span.Size:N0} bytes are read");
            ReadOnlyMemory<byte> bytes = file.Streamed ? file.ReadAt(span.Offset, length) : file.Bytes.AsMemory((int)span.Offset, length);
            var isas = RawCandidates.Isas(bytes.Span, ct);
            if (isas.Count == 0) { none++; continue; }
            var best = RawArch.Find(isas[0].Arch);
            var bases = RawCandidates.Bases(bytes.Span, best, ct);
            regionNotes.AddRange(bases.Notes);
            ulong? at = bases.Clear ? bases.Bases.First(b => b.Votes > 0).Base : bases.Bases.FirstOrDefault(b => b.Source == "vector table")?.Base;
            bool whole = span.Offset == 0 && span.Size == file.Length;
            if (!whole)
                regionNotes.Add($"bytes 0x{span.Offset:X}-0x{span.Offset + span.Size:X} are not a file of their own: saved as one, they load with " +
                                RawCandidates.LoadCall("<file>", best.Name, at));
            regions.Add(new Region($"0x{span.Offset:X}", span.Size, [.. isas.Take(MaxIsas)], bases.Bases, bases.Clear,
                whole ? RawCandidates.LoadCall(file.Path, best.Name, at) : null, regionNotes));
        }
        if (regions.Count == 0) return null;
        if (none > 0) notes.Add($"{none} region(s) read as no instruction set (score under {RawCandidates.MinScore})");
        notes.Add("scores are signature hits above twice chance per 64 KiB (returns, prologues, epilogues); bases are where the most " +
                  "distinct pointer values land on string starts");
        var first = regions[0];
        var top = first.Isas[0];
        string highlight = $"Headerless code{(regions.Count > 1 || first.Load == null ? $" at {first.Offset}" : "")}: reads as {top.Arch} (score {top.Score:0}" +
                           (first.Isas.Count > 1 ? $", next {first.Isas[1].Arch} {first.Isas[1].Score:0})" : ")") +
                           (first.BaseClear ? $", base 0x{first.Bases.First(b => b.Votes > 0).Base:X} ({first.Bases.First(b => b.Votes > 0).Votes:N0} pointers)." : ", no clear base.");
        return new FileView(new Facts(regions, RawCandidates.NotChecked, notes), [highlight]);
    }
}
