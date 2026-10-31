using System.Buffers.Binary;

namespace Corvus.Core.Archives;

/// <summary>
/// A package of a record count, offset and size records, then the blobs they
/// locate; mapped by structure alone and listed with sizes and entropy.
/// </summary>
internal sealed class IndexedBlobStoreReader : IContainerReader
{
    private const int MaxRecords = 65_535;

    private const int MinRecords = 2;

    private const int Alignment = 16;

    // Bits per byte above which a blob is labelled compressed or encrypted.
    private const double EncryptedEntropy = 7.5;

    // Share of the file the blobs must span, so unrelated data is not taken.
    private const double MinCoverage = 0.75;

    // Entries named in the summary note; list_assemblies pages the rest.
    private const int PreviewEntries = 8;

    public string Kind => "indexed blob store";

    public bool Accepts(ReadOnlySpan<byte> data, string name) => Layout(data) is not null;

    public ContainerContents Open(byte[] data, string name, bool allFiles, AnalysisLimits limits, CancellationToken ct)
    {
        var layout = Layout(data) ?? throw new ToolError($"{name}: not an indexed blob store.");
        var items = new List<ExtractedItem>();
        var entries = new List<ContainerEntry>();
        var notes = new List<string>();
        var preview = new List<string>();
        long total = 0;
        int packed = 0, measured = 0;
        bool stopped = false;
        for (int i = 0; i < layout.Records.Count; i++)
        {
            ct.ThrowIfCancellationRequested();
            var (offset, size) = layout.Records[i];
            string entry = $"entry_{i:D4}";
            if (!Fits(offset, size, data.Length))
            {
                entries.Add(new ContainerEntry(entry, size, EntryDamage.Detail("runs past the end of the file", offset)));
                if (preview.Count < PreviewEntries) preview.Add($"{entry} {size:N0} bytes, entropy unknown");
                notes.Add($"{entry}: unknown contents, only {Math.Max(0, data.Length - offset):N0} of {size:N0} bytes are in the file.");
                continue;
            }
            // Past a limit an entry is still listed, with its offset only.
            if (stopped || items.Count >= limits.MaxItems || size > limits.MaxItemBytes || total + size > limits.MaxTotalBytes)
            {
                if (!stopped) notes.Add("Stopped: the extraction limit was reached.");
                stopped = true;
                entries.Add(new ContainerEntry(entry, size, $"offset 0x{offset:X}"));
                if (preview.Count < PreviewEntries) preview.Add($"{entry} {size:N0} bytes, entropy unknown");
                continue;
            }
            var blob = data.AsSpan((int)offset, (int)size);
            double entropy = Blob.Entropy(blob);
            measured++;
            string label = entropy > EncryptedEntropy ? ", compressed or encrypted" : "";
            if (entropy > EncryptedEntropy) packed++;
            if (preview.Count < PreviewEntries) preview.Add($"{entry} {size:N0} bytes, entropy {entropy:F2}");
            entries.Add(new ContainerEntry(entry, size, $"offset 0x{offset:X}, entropy {entropy:F2}{label}"));
            items.Add(new ExtractedItem(entry, blob.ToArray(), "indexed blob") { Member = true });
            total += size;
        }
        string shown = preview.Count < entries.Count ? $"{preview.Count} of {entries.Count:N0} entries" : $"{entries.Count:N0} entries";
        int unknown = entries.Count - measured;
        string unknownNote = unknown > 0 ? $", {unknown:N0} with unknown entropy" : "";
        notes.Insert(0, $"{entries.Count:N0} entries, {packed:N0} of {measured:N0} measured above entropy {EncryptedEntropy}"
            + $" (compressed or encrypted){unknownNote}; {shown}: {string.Join("; ", preview)}.");
        // The reader has the item name only, so the calls say "this file".
        notes.Insert(1, "list_assemblies on this file pages every entry with size and entropy; unpack_container on this file writes the entries.");
        if (layout.Gap > 0) notes.Add($"{layout.Gap:N0} bytes between or after the blobs belong to no entry.");
        return new ContainerContents(Kind, items, notes) { Entries = entries };
    }

    private static bool Fits(long offset, long size, long length) => offset >= 0 && size >= 0 && offset + size <= length;

    private sealed record StoreLayout(List<(long Offset, long Size)> Records, long Gap);

    /// <summary>
    /// The records of an ascending, non-overlapping index plus blobs; null
    /// otherwise. Only the last record may run past the end.
    /// </summary>
    private static StoreLayout? Layout(ReadOnlySpan<byte> data)
    {
        if (data.Length < 4 + MinRecords * 8) return null;
        uint count = BinaryPrimitives.ReadUInt32LittleEndian(data);
        if (count < MinRecords || count > MaxRecords) return null;
        long indexEnd = 4 + 8L * count;
        if (indexEnd >= data.Length) return null;
        var records = new List<(long, long)>((int)count);
        long previousEnd = indexEnd, covered = 0;
        for (int i = 0; i < count; i++)
        {
            long offset = BinaryPrimitives.ReadUInt32LittleEndian(data[(4 + 8 * i)..]);
            long size = BinaryPrimitives.ReadUInt32LittleEndian(data[(8 + 8 * i)..]);
            // The first blob follows the index, allowing up to one alignment pad.
            if (i == 0 ? offset < indexEnd || offset >= indexEnd + Alignment : offset < previousEnd) return null;
            if (!Fits(offset, size, data.Length))
            {
                // A truncated file damages only its final record.
                if (i != count - 1 || offset > data.Length) return null;
                records.Add((offset, size));
                covered += data.Length - offset;
                break;
            }
            records.Add((offset, size));
            covered += size;
            previousEnd = offset + size;
        }
        if (covered < (long)(data.Length * MinCoverage)) return null;
        return new StoreLayout(records, Math.Max(0, data.Length - indexEnd - covered));
    }
}
