using Corvus.Core;
using Corvus.Core.Firmware.Esp32;

namespace Corvus.Services.Analysis;

/// <summary>
/// view=esp32: an ESP32-family flash image, partition table, NVS partition or app image, read as esptool image_info,
/// gen_esp32part.py and nvs_tool.py read them: the image headers, segments and app description, each partition and its
/// place in the file, then a page of NVS values (table= keeps one namespace; offset=, limit=).
/// </summary>
internal sealed class Esp32FileView : IFileSummaryView
{
    private const int DefaultLimit = 50, MaxLimit = 1000, PreviewBytes = 64, MaxText = 500;

    // FileOffset is image_info's: where the segment's 8-byte header starts in the image.
    public sealed record SegmentRow(string LoadAddress, string FileOffset, int Length, string Regions);

    public sealed record ImageRow(string? Partition, string Chip, string Entry, string? FlashMode, string? FlashSize, string? FlashFrequency,
        string ChipRevision, IReadOnlyList<SegmentRow> Segments, string Checksum, string Sha256, Esp32Image.AppDescription? App,
        Esp32Image.BootloaderDescription? Bootloader);

    public sealed record PartitionRow(string Label, string Type, string Subtype, string Offset, uint Size, string? Flags, string? InFile, string? Content);

    public sealed record ValueRow(string? Partition, string Namespace, string Key, string Type, string? Value, int? Size, string? Kind, string? Note);

    public sealed record NvsRow(string? Partition, int Pages, IReadOnlyDictionary<string, int> PageStates, int Written, int Erased, int Empty,
        IReadOnlyList<string> Namespaces);

    public sealed record Facts(string Kind, string? FlashBase, IReadOnlyList<ImageRow> Images, IReadOnlyList<PartitionRow> Partitions,
        IReadOnlyList<NvsRow> Nvs, string? Filter, int Matching, IReadOnlyList<ValueRow> Values, long Offset, long? Next, IReadOnlyList<string> Notes);

    public string Name => "esp32";

    public FileView? Inspect(FileInput file, CancellationToken ct)
    {
        var head = file.Head;
        var notes = new List<string>();
        var images = new List<ImageRow>();
        var partitions = new List<PartitionRow>();
        var nvs = new List<(string? Label, Esp32Nvs Nvs)>();
        string kind;
        string? flashBase = null;
        if (Esp32Flash.Find(head) is { } flash)
        {
            kind = "flash image";
            flashBase = $"0x{flash.Base:X}";
            images.Add(Row("bootloader", flash.Bootloader));
            foreach (var p in flash.Table.Partitions)
            {
                var (start, length) = flash.InFile(p, file.Length);
                string where = length == 0 ? "outside the file" : length < p.Size ? $"{length:N0} bytes in the file" : "in the file";
                string? content = null;
                if (length > 0 && !p.Encrypted)
                {
                    // An app or NVS partition is read whole; for the others the first page names the content.
                    bool whole = p.Type == 0 || (p.Type == 1 && p.Subtype == 2);
                    var bytes = Read(file, start, (int)(whole ? length : Math.Min(length, 4096)));
                    if (p.Type == 0 && Esp32Image.Looks(bytes))
                    {
                        try { var app = Esp32Image.Read(bytes); images.Add(Row(p.Label, app)); content = "app image"; }
                        catch (InvalidDataException ex) { notes.Add($"{p.Label}: app image not readable: {ex.Message}"); }
                    }
                    else if (p.Type == 1 && p.Subtype == 2 && Esp32Nvs.Looks(bytes)) { nvs.Add((p.Label, Esp32Nvs.Read(bytes))); content = "nvs"; }
                    else content = !bytes.AsSpan().ContainsAnyExcept((byte)0xFF) ? "erased (0xFF)" : Blob.Identify(bytes);
                }
                partitions.Add(Partition(p, where, content));
            }
            if (flash.Table.Md5Valid == false) notes.Add("the partition table's MD5 entry does not match its entries");
        }
        else if (Esp32PartitionTable.Is(head))
        {
            var table = Esp32PartitionTable.Read(head);
            kind = "partition table";
            partitions.AddRange(table.Partitions.Select(p => Partition(p, null, null)));
            if (table.Md5Valid == false) notes.Add("the MD5 entry does not match the entries");
        }
        else if (Esp32Nvs.Looks(head))
        {
            kind = "nvs partition";
            nvs.Add((null, Esp32Nvs.Read(file.Bytes)));
        }
        else if (Esp32Image.Looks(head))
        {
            Esp32Image image;
            try { image = Esp32Image.Read(head); }
            catch (InvalidDataException) { return null; }
            if (image.ChipInfo == null || image.Checksum != image.ComputedChecksum) return null;
            kind = image.App != null ? "app image" : image.Bootloader != null ? "bootloader image" : "image";
            images.Add(Row(null, image));
        }
        else return null;

        int limit = Math.Clamp(file.Options.Limit ?? DefaultLimit, 1, MaxLimit);
        long offset = Math.Max(0, file.Options.Offset);
        var filter = file.Options.View == Name && file.Options.Table is { Length: > 0 } t ? t.Trim() : null;
        var all = nvs.SelectMany(n => n.Nvs.Entries.Select(e => (n.Label, Entry: e)))
            .Where(x => filter == null || string.Equals(x.Entry.Namespace, filter, StringComparison.OrdinalIgnoreCase)).ToList();
        var page = all.Skip((int)Math.Min(offset, int.MaxValue)).Take(limit).Select(x => Value(x.Label, x.Entry)).ToList();
        long shown = offset + page.Count;
        long? next = shown < all.Count ? shown : null;
        foreach (var (label, n) in nvs) notes.AddRange(n.Notes.Select(x => label == null ? x : $"{label}: {x}"));
        if (next != null) notes.Add($"offset={next} lists the next values");
        var nvsRows = nvs.Select(n => new NvsRow(n.Label, n.Nvs.Pages.Count,
            n.Nvs.Pages.GroupBy(p => p.State).ToDictionary(g => g.Key, g => g.Count()),
            n.Nvs.Pages.Sum(p => p.Written), n.Nvs.Pages.Sum(p => p.Erased), n.Nvs.Pages.Sum(p => p.Empty),
            [.. n.Nvs.Namespaces.OrderBy(x => x.Key).Select(x => x.Value)])).ToList();

        var first = images.FirstOrDefault();
        var line = $"ESP32 {kind}" + (first != null ? $" ({first.Chip})" : "") +
            (partitions.Count > 0 ? $": {partitions.Count} partition(s), {string.Join(", ", partitions.Select(p => $"{p.Label} {p.Type}/{p.Subtype}"))}" : "") +
            (images.FirstOrDefault(i => i.App != null)?.App is { } a ? $"; app {a.ProjectName} {a.Version}, ESP-IDF {a.IdfVersion}" : "") +
            (nvsRows.Count > 0 ? $"; {all.Count:N0} NVS value(s) in {nvsRows.Sum(n => n.Namespaces.Count)} namespace(s)" : "") + ".";
        return new FileView(new Facts(kind, flashBase, images, partitions, nvsRows, filter, all.Count, page, offset, next, notes), [line]);
    }

    private static byte[] Read(FileInput file, long start, int length)
    {
        if (start + length <= file.Head.Length) return file.Head.AsSpan((int)start, length).ToArray();
        using var s = file.OpenRead();
        s.Position = start;
        var b = new byte[length];
        s.ReadExactly(b);
        return b;
    }

    private static PartitionRow Partition(Esp32Partition p, string? where, string? content)
    {
        var flags = string.Join(", ", new[] { p.Encrypted ? "encrypted" : null, p.ReadOnly ? "readonly" : null }.OfType<string>());
        return new PartitionRow(p.Label, p.TypeName, p.SubtypeName, $"0x{p.Offset:X}", p.Size, flags.Length > 0 ? flags : null, where, content);
    }

    private static ImageRow Row(string? partition, Esp32Image i) => new(partition,
        i.ChipInfo is { } c ? $"{c.Name} (chip id {i.ChipId})" : $"chip id {i.ChipId} (unknown)", $"0x{i.Entry:X}", i.FlashMode, i.FlashSize, i.FlashFrequency,
        $"{i.MinChipRevision} to {i.MaxChipRevision}",
        [.. i.Segments.Select(s => new SegmentRow($"0x{s.LoadAddress:X}", $"0x{s.FileOffset - 8:X}", s.Length, string.Join(", ", s.Regions)))],
        $"0x{i.Checksum:x2} " + (i.Checksum == i.ComputedChecksum ? "(valid)" : $"(invalid, computed 0x{i.ComputedChecksum:x2})"),
        i.Sha256 == null ? "not appended" : $"{i.Sha256} ({(i.Sha256Valid == true ? "valid" : "invalid")})", i.App, i.Bootloader);

    private static ValueRow Value(string? partition, Esp32Nvs.Entry e)
    {
        if (e.Data is { } data)
        {
            var preview = Convert.ToHexStringLower(data.AsSpan(0, Math.Min(PreviewBytes, data.Length))) + (data.Length > PreviewBytes ? "..." : "");
            return new ValueRow(partition, e.Namespace, e.Key, e.Type, preview, data.Length, Blob.Identify(data), e.Note);
        }
        var text = e.Text is { Length: > MaxText } t ? t[..MaxText] + $"... ({t.Length:N0} characters)" : e.Text;
        return new ValueRow(partition, e.Namespace, e.Key, e.Type, text, null, null, e.Note);
    }
}
