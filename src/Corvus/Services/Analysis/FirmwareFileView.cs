using Corvus.Core;
using Corvus.Core.Firmware;

namespace Corvus.Services.Analysis;

/// <summary>view=firmware: known formats at offsets inside a file, each checked against its header's fields (<see cref="FirmwareSignatures"/>).</summary>
internal sealed class FirmwareFileView : IFileSummaryView
{
    private const int MaxHits = 1000;

    /// <summary>One format at an offset; <see cref="Size"/> when its header declares one.</summary>
    public sealed record Hit(string Offset, string Format, long? Size, string? Detail);

    public sealed record Facts(IReadOnlyList<Hit> Signatures, IReadOnlyList<string> Notes);

    public string Name => "firmware";

    private const int Window = FirmwareSignatures.StreamWindow, Overlap = FirmwareSignatures.StreamOverlap;

    /// <summary>Gaps between signatures smaller than this are padding, not regions of their own.</summary>
    public const long MinGap = 4096;

    /// <summary>A file region no signature claims: <see cref="Offset"/> and <see cref="Size"/> in the file.</summary>
    public sealed record Gap(long Offset, long Size);

    private static readonly System.Runtime.CompilerServices.ConditionalWeakTable<FileInput, List<SignatureHit>> Scanned = new();

    /// <summary>The signatures in <paramref name="file"/>, scanned once per file for every view that reads them.</summary>
    internal static List<SignatureHit> Hits(FileInput file, CancellationToken ct)
    {
        if (Scanned.TryGetValue(file, out var kept)) return kept;
        List<SignatureHit> found;
        if (!file.Streamed) found = FirmwareSignatures.Scan(file.Bytes, MaxHits, ct);
        else
        {
            using var s = file.OpenRead();
            found = FirmwareSignatures.Scan(s, file.Length, MaxHits, ct, Window, Overlap);
        }
        Scanned.AddOrUpdate(file, found);
        return found;
    }

    /// <summary>Firmware is opaque data; an executable or a known container gets its own views.</summary>
    internal static bool Applies(FileInput file) =>
        file.Length >= 4096 && file.Kind == "data" && !Core.Pcap.PcapReader.Looks(file.Head) && !SqliteDatabase.Looks(file.Head);

    /// <summary>Regions of at least <see cref="MinGap"/> bytes no signature claims, in file order; an unsized format runs to the next.</summary>
    internal static List<Gap> Gaps(IReadOnlyList<SignatureHit> hits, long length)
    {
        var gaps = new List<Gap>();
        long covered = 0;
        bool open = false;
        foreach (var h in hits.OrderBy(h => h.Offset))
        {
            if (!open && h.Offset - covered >= MinGap) gaps.Add(new Gap(covered, h.Offset - covered));
            if (h.Offset + (h.Size ?? 0) < covered) continue;
            open = h.Size == null;
            covered = h.Offset + (h.Size ?? 0);
        }
        if (!open && length - covered >= MinGap) gaps.Add(new Gap(covered, length - covered));
        return gaps;
    }

    public FileView? Inspect(FileInput file, CancellationToken ct)
    {
        if (!Applies(file)) return null;
        var found = Hits(file, ct);

        // The file's own format at offset 0 alone is not firmware.
        if (found.Count == 0 || found.All(h => h.Offset == 0)) return null;
        var sorted = found.OrderBy(h => h.Offset).Select(h => new Hit($"0x{h.Offset:X}", h.Format, h.Size, h.Detail)).ToList();
        var notes = new List<string>();
        if (found.Count >= MaxHits) notes.Add($"stopped at {MaxHits} signatures");
        if (file.Streamed) notes.Add($"read in {Window >> 20} MiB windows");
        notes.Add($"{FirmwareSignatures.Count} formats checked; the inside of a sized filesystem, boot image or archive is not searched.");
        notes.Add("unpack_container extracts filesystems, boot images and archives; load_assembly format=raw (arch, base, entry) loads headerless code.");
        foreach (var g in Gaps(found, file.Length).Take(RawCodeFileView.MaxRegions))
            notes.Add($"0x{g.Offset:X}-0x{g.Offset + g.Size:X} ({g.Size:N0} bytes): no signature; view=raw reads it for an instruction set and load base.");
        var formats = sorted.GroupBy(h => h.Format).Select(g => g.Count() > 1 ? $"{g.Count()} {g.Key}" : $"{g.Key} at {g.First().Offset}");
        return new FileView(new Facts(sorted, notes), [$"Embedded formats: {string.Join(", ", formats.Take(8))}" + (formats.Count() > 8 ? ", ..." : "") + "."]);
    }
}
