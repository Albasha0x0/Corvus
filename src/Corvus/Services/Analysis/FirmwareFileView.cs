using Corvus.Core;
using Corvus.Core.Firmware;

namespace Corvus.Services.Analysis;

/// <summary>
/// view=firmware: known formats found at offsets inside a file (a firmware image is formats laid end to end): boot and
/// kernel headers, filesystems, archives, compressed streams, executables, keys and media, each checked against its
/// header's own fields (<see cref="FirmwareSignatures"/>).
/// </summary>
internal sealed class FirmwareFileView : IFileSummaryView
{
    private const int MaxHits = 1000;

    /// <summary>One format at an offset; <see cref="Size"/> when its header declares one.</summary>
    public sealed record Hit(string Offset, string Format, long? Size, string? Detail);

    public sealed record Facts(IReadOnlyList<Hit> Signatures, IReadOnlyList<string> Notes);

    public string Name => "firmware";

    /// <summary>A streamed file is scanned in windows this large, each overlapping the next by <see cref="Overlap"/>.</summary>
    private const int Window = 64 << 20, Overlap = 1 << 20;

    public FileView? Inspect(FileInput file, CancellationToken ct)
    {
        // firmware is opaque data; an executable or a known container gets its own views
        if (file.Length < 4096 || file.Kind != "data" || Core.Pcap.PcapReader.Looks(file.Head) || SqliteDatabase.Looks(file.Head)) return null;
        List<SignatureHit> found;
        if (!file.Streamed) found = FirmwareSignatures.Scan(file.Bytes, MaxHits, ct);
        else
        {
            using var s = file.OpenRead();
            found = FirmwareSignatures.Scan(s, file.Length, MaxHits, ct, Window, Overlap);
        }

        // the file's own format at offset 0 alone is not firmware
        if (found.Count == 0 || found.All(h => h.Offset == 0)) return null;
        var sorted = found.OrderBy(h => h.Offset).Select(h => new Hit($"0x{h.Offset:X}", h.Format, h.Size, h.Detail)).ToList();
        var notes = new List<string>();
        if (found.Count >= MaxHits) notes.Add($"stopped at {MaxHits} signatures");
        if (file.Streamed) notes.Add($"read in {Window >> 20} MiB windows");
        notes.Add($"{FirmwareSignatures.Count} formats are checked, each against its own header; inside a filesystem, boot image or archive with a known size nothing more is searched.");
        notes.Add("unpack_container carves out the filesystems, boot images and archives and reads each with its own reader; headerless code loads with load_assembly format=raw (arch, base, entry).");
        var formats = sorted.GroupBy(h => h.Format).Select(g => g.Count() > 1 ? $"{g.Count()} {g.Key}" : $"{g.Key} at {g.First().Offset}");
        return new FileView(new Facts(sorted, notes), [$"Embedded formats: {string.Join(", ", formats.Take(8))}" + (formats.Count() > 8 ? ", ..." : "") + "."]);
    }
}
