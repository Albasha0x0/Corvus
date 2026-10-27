using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;

namespace Corvus.Core.Firmware.Esp32;

/// <summary>A partition table entry as gen_esp32part.py names it; offsets and sizes are flash addresses.</summary>
internal sealed record Esp32Partition(string Label, int Type, int Subtype, uint Offset, uint Size, int Flags)
{
    public bool Encrypted => (Flags & 1) != 0;
    public bool ReadOnly => (Flags & 2) != 0;

    public string TypeName => Type switch { 0 => "app", 1 => "data", 2 => "bootloader", 3 => "partition_table", _ => $"0x{Type:x2}" };

    // esp_partition.h subtypes.
    public string SubtypeName => (Type, Subtype) switch
    {
        (0, 0) => "factory",
        (0, >= 0x10 and < 0x20) => $"ota_{Subtype - 0x10}",
        (0, 0x20) => "test",
        (1, 0) => "ota", (1, 1) => "phy", (1, 2) => "nvs", (1, 3) => "coredump", (1, 4) => "nvs_keys", (1, 5) => "efuse",
        (1, 6) => "undefined", (1, 0x80) => "esphttpd", (1, 0x81) => "fat", (1, 0x82) => "spiffs", (1, 0x83) => "littlefs",
        (2 or 3, 0) => "primary", (2 or 3, 1) => "ota", (2, 2) => "recovery",
        _ => $"0x{Subtype:x2}",
    };
}

/// <summary>An ESP-IDF partition table (gen_esp32part.py binary form): 32-byte entries, an optional MD5 entry, an end marker.</summary>
internal sealed class Esp32PartitionTable
{
    /// <summary>The flash sector the table occupies; entries end within its first 3 KiB.</summary>
    public const int Size = 0x1000;
    private const int MaxLength = 0xC00, EntrySize = 32;

    public required IReadOnlyList<Esp32Partition> Partitions { get; init; }
    /// <summary>Whether the MD5 entry matches the entries before it; null when the table has none.</summary>
    public bool? Md5Valid { get; init; }

    /// <summary>Whether <paramref name="b"/> starts with a partition entry.</summary>
    public static bool Looks(ReadOnlySpan<byte> b) => b.Length >= EntrySize && b[0] == 0xAA && b[1] == 0x50;

    /// <summary>Whether <paramref name="b"/> starts with a whole readable table.</summary>
    public static bool Is(ReadOnlySpan<byte> b)
    {
        if (!Looks(b)) return false;
        try { return Read(b).Partitions.Count > 0; }
        catch (InvalidDataException) { return false; }
    }

    /// <summary>Parses the table at the start of <paramref name="b"/>; throws <see cref="InvalidDataException"/> on a bad entry or no end marker.</summary>
    public static Esp32PartitionTable Read(ReadOnlySpan<byte> b)
    {
        if (!Looks(b)) throw new InvalidDataException("no partition entry (0xAA 0x50) at the start");
        var parts = new List<Esp32Partition>();
        bool? md5 = null;
        for (int o = 0; o + EntrySize <= Math.Min(b.Length, MaxLength); o += EntrySize)
        {
            var e = b.Slice(o, EntrySize);
            if (!e.ContainsAnyExcept((byte)0xFF)) return new Esp32PartitionTable { Partitions = parts, Md5Valid = md5 };
            if (e[0] == 0xEB && e[1] == 0xEB)
            {
                md5 = e[16..].SequenceEqual(MD5.HashData(b[..o]));
                continue;
            }
            if (e[0] != 0xAA || e[1] != 0x50) throw new InvalidDataException($"entry {o / EntrySize} at 0x{o:X} has magic 0x{e[0]:X2}{e[1]:X2}, not 0xAA50");
            var label = Encoding.UTF8.GetString(e.Slice(12, 16)).TrimEnd('\0');
            parts.Add(new Esp32Partition(label, e[2], e[3], BinaryPrimitives.ReadUInt32LittleEndian(e[4..]), BinaryPrimitives.ReadUInt32LittleEndian(e[8..]),
                (int)BinaryPrimitives.ReadUInt32LittleEndian(e[28..])));
        }
        throw new InvalidDataException("the partition table has no end marker in its first 3 KiB");
    }
}

/// <summary>An ESP-IDF NVS partition read as nvs_tool.py reads it; v2 blobs are joined from their chunks.</summary>
internal sealed class Esp32Nvs
{
    public const int PageSize = 4096;
    private const int EntrySize = 32, EntriesPerPage = 126;

    /// <summary>A page: its flash offset in the partition, state, sequence number, format version and header CRC result.</summary>
    public sealed record Page(int Offset, string State, uint Sequence, int Version, bool CrcValid, int Written, int Erased, int Empty);

    /// <summary>A written value: page and entry index, namespace, key, type and value (text, number or the joined blob).</summary>
    public sealed record Entry(int Page, int Index, string Namespace, string Key, string Type, string? Text, byte[]? Data, string? Note);

    public required IReadOnlyList<Page> Pages { get; init; }
    public required IReadOnlyList<Entry> Entries { get; init; }
    /// <summary>Namespace index to name, from the written namespace entries.</summary>
    public required IReadOnlyDictionary<int, string> Namespaces { get; init; }
    public required IReadOnlyList<string> Notes { get; init; }

    private static readonly Dictionary<int, string> Types = new()
    {
        [0x01] = "uint8_t", [0x11] = "int8_t", [0x02] = "uint16_t", [0x12] = "int16_t", [0x04] = "uint32_t", [0x14] = "int32_t",
        [0x08] = "uint64_t", [0x18] = "int64_t", [0x21] = "string", [0x41] = "blob", [0x42] = "blob_data", [0x48] = "blob_index",
    };

    private static string StateName(uint s) => s switch
    {
        0xFFFFFFFF => "Empty", 0xFFFFFFFE => "Active", 0xFFFFFFFC => "Full", 0xFFFFFFF8 => "Erasing", 0 => "Corrupted", _ => "Invalid",
    };

    /// <summary>zlib crc32(data, 0xFFFFFFFF), the CRC the NVS library writes.</summary>
    private static uint Crc(ReadOnlySpan<byte> data) => ~Firmware.Crc.Raw(0, data);

    /// <summary>Whether <paramref name="b"/> is page-aligned and its first used page has a known state, version and a valid header CRC.</summary>
    public static bool Looks(ReadOnlySpan<byte> b)
    {
        if (b.Length < PageSize || b.Length % PageSize != 0) return false;
        for (int at = 0; at + PageSize <= b.Length; at += PageSize)
        {
            var h = b.Slice(at, EntrySize);
            if (!h.ContainsAnyExcept((byte)0xFF)) continue;
            return StateName(BinaryPrimitives.ReadUInt32LittleEndian(h)) is not ("Invalid" or "Empty") && h[8] is 0xFE or 0xFF
                && Crc(h[4..28]) == BinaryPrimitives.ReadUInt32LittleEndian(h[28..]);
        }
        return false;
    }

    /// <summary>Reads every page of <paramref name="b"/>; a trailing partial page is noted and skipped, a damaged page or entry is kept and noted.</summary>
    public static Esp32Nvs Read(ReadOnlySpan<byte> b)
    {
        var notes = new List<string>();
        if (b.Length % PageSize != 0) notes.Add($"{b.Length % PageSize:N0} byte(s) after the last whole page are not read");
        var pages = new List<Page>();
        var raw = new List<(int Page, int Index, int Ns, int Type, int Chunk, string? Key, byte[] Data, byte[] Body, bool CrcOk)>();
        int badEntries = 0;
        Span<byte> covered = stackalloc byte[28];
        for (int at = 0; at + PageSize <= b.Length; at += PageSize)
        {
            var p = b.Slice(at, PageSize);
            int pageNo = at / PageSize;
            var states = new int[EntriesPerPage];
            for (int i = 0; i < EntriesPerPage; i++) states[i] = (p[EntrySize + i / 4] >> (i % 4 * 2)) & 3;
            bool empty = !p[..EntrySize].ContainsAnyExcept((byte)0xFF);
            int written = states.Count(s => s == 2), erased = states.Count(s => s == 0), free = states.Count(s => s == 3);
            pages.Add(new Page(at, empty ? "Empty" : StateName(BinaryPrimitives.ReadUInt32LittleEndian(p)), BinaryPrimitives.ReadUInt32LittleEndian(p[4..]),
                256 - p[8], empty || Crc(p[4..28]) == BinaryPrimitives.ReadUInt32LittleEndian(p[28..]), written, erased, free));
            if (empty) continue;
            for (int i = 0; i < EntriesPerPage;)
            {
                var e = p.Slice(2 * EntrySize + i * EntrySize, EntrySize);
                int span = e[2] is 0 or 0xFF ? 1 : e[2];
                if (states[i] == 2)
                {
                    int bodyEntries = Math.Min(span - 1, EntriesPerPage - i - 1);
                    var body = p.Slice(2 * EntrySize + (i + 1) * EntrySize, bodyEntries * EntrySize).ToArray();
                    e[..4].CopyTo(covered);
                    e[8..].CopyTo(covered[4..]);
                    bool ok = Crc(covered) == BinaryPrimitives.ReadUInt32LittleEndian(e[4..]);
                    if (!ok) badEntries++;
                    raw.Add((pageNo, i, e[0], e[1], e[3], Key(e.Slice(8, 16)), e[24..].ToArray(), body, ok));
                }
                i += span;
            }
        }
        if (badEntries > 0) notes.Add($"{badEntries:N0} written entr{(badEntries == 1 ? "y has" : "ies have")} a CRC mismatch; the NVS library skips such an entry");
        int badPages = pages.Count(p => !p.CrcValid);
        if (badPages > 0) notes.Add($"{badPages:N0} page header(s) have a CRC mismatch");

        var ns = new Dictionary<int, string>();
        foreach (var r in raw)
            if (r.Ns == 0 && r.Key != null) ns[r.Data[0]] = r.Key;
        var entries = new List<Entry>();
        foreach (var r in raw)
        {
            if (r.Ns == 0 || r.Type == 0x42) continue;
            string space = ns.GetValueOrDefault(r.Ns) ?? $"(namespace {r.Ns}, no namespace entry)";
            string type = Types.GetValueOrDefault(r.Type) ?? $"0x{r.Type:x2}";
            string? note = r.CrcOk ? null : "entry CRC mismatch";
            if (r.Key == null) { entries.Add(new(r.Page, r.Index, space, "(key not ASCII)", type, null, null, note)); continue; }
            switch (r.Type)
            {
                case < 0x20 when Types.ContainsKey(r.Type):
                    int size = r.Type & 0xF;
                    ulong u = 0;
                    for (int k = size - 1; k >= 0; k--) u = (u << 8) | r.Data[k];
                    string value = (r.Type & 0xF0) == 0 ? u.ToString() : (size == 8 ? (long)u : (long)u << (64 - size * 8) >> (64 - size * 8)).ToString();
                    entries.Add(new(r.Page, r.Index, space, r.Key, type, value, null, note));
                    break;
                case 0x21 or 0x41:
                    var (data, why) = Payload(r.Body, r.Data);
                    entries.Add(new(r.Page, r.Index, space, r.Key, type, r.Type == 0x21 ? Encoding.UTF8.GetString(data).TrimEnd('\0') : null,
                        r.Type == 0x41 ? data : null, Join(note, why)));
                    break;
                case 0x48:
                    uint total = BinaryPrimitives.ReadUInt32LittleEndian(r.Data);
                    int count = r.Data[4], start = r.Data[5];
                    var joined = new List<byte>();
                    var missing = new List<int>();
                    for (int c = start; c < start + count; c++)
                    {
                        var chunk = raw.FirstOrDefault(x => x.Type == 0x42 && x.Ns == r.Ns && x.Key == r.Key && x.Chunk == c);
                        if (chunk.Body == null) { missing.Add(c - start); continue; }
                        joined.AddRange(Payload(chunk.Body, chunk.Data).Data);
                    }
                    string? lack = missing.Count > 0 ? $"chunk(s) {string.Join(", ", missing)} of {count} not found" : null;
                    if (lack == null && joined.Count != total) lack = $"chunks hold {joined.Count:N0} bytes, the index declares {total:N0}";
                    entries.Add(new(r.Page, r.Index, space, r.Key, "blob", null, [.. joined], Join(note, lack)));
                    break;
                default:
                    entries.Add(new(r.Page, r.Index, space, r.Key, type, Convert.ToHexStringLower(r.Data), null, Join(note, "unknown type; the 8 data bytes are shown")));
                    break;
            }
        }
        return new Esp32Nvs { Pages = pages, Entries = entries, Namespaces = ns, Notes = notes };
    }

    private static string? Join(string? a, string? b) => a == null ? b : b == null ? a : $"{a}; {b}";

    // A variable-length item: its size and data CRC in the 8 data bytes, its bytes in the entries after it.
    private static (byte[] Data, string? Note) Payload(byte[] body, byte[] header)
    {
        int size = BinaryPrimitives.ReadUInt16LittleEndian(header);
        var data = body.AsSpan(0, Math.Min(size, body.Length)).ToArray();
        if (data.Length < size) return (data, $"{size:N0} bytes declared, {data.Length:N0} in the page");
        return (data, Crc(data) == BinaryPrimitives.ReadUInt32LittleEndian(header.AsSpan(4)) ? null : "data CRC mismatch");
    }

    private static string? Key(ReadOnlySpan<byte> k)
    {
        int n = k.IndexOf((byte)0);
        var text = n < 0 ? k : k[..n];
        return text.ContainsAnyExceptInRange((byte)0, (byte)0x7F) ? null : Encoding.ASCII.GetString(text);
    }
}

/// <summary>An ESP32-family flash layout; <see cref="Base"/> is the flash address of file offset 0.</summary>
internal sealed class Esp32Flash
{
    private const int MaxTableSearch = 1 << 20;
    private static readonly int[] BootloaderAt = [0, 0x1000, 0x2000];

    public required uint Base { get; init; }
    public required int BootloaderOffset { get; init; }
    public required Esp32Image Bootloader { get; init; }
    public required int TableOffset { get; init; }
    public required Esp32PartitionTable Table { get; init; }

    /// <summary>The file range a partition occupies, clipped to <paramref name="length"/>; Length 0 when it lies outside the file.</summary>
    public (long Start, long Length) InFile(Esp32Partition p, long length)
    {
        long start = (long)p.Offset - Base, end = start + p.Size;
        if (start < 0 || start >= length) return (Math.Max(0, start), 0);
        return (start, Math.Min(end, length) - start);
    }

    /// <summary>The layout of <paramref name="b"/> (the file's first bytes, at least through the table), or null when it is not an ESP32 flash image.</summary>
    public static Esp32Flash? Find(ReadOnlySpan<byte> b)
    {
        foreach (int boot in BootloaderAt)
        {
            if (boot + 24 > b.Length || !Esp32Image.Looks(b[boot..])) continue;
            int chipId = BinaryPrimitives.ReadUInt16LittleEndian(b[(boot + 12)..]);
            if (Array.Find(Esp32Image.Chips, c => c.Id == chipId) is not { } chip || chip.BootloaderOffset < boot) continue;
            Esp32Image image;
            try { image = Esp32Image.Read(b[boot..]); }
            catch (InvalidDataException) { continue; }
            int from = (boot + image.Length + Esp32PartitionTable.Size - 1) / Esp32PartitionTable.Size * Esp32PartitionTable.Size;
            for (int t = from; t + 32 <= Math.Min(b.Length, MaxTableSearch); t += Esp32PartitionTable.Size)
            {
                if (!Esp32PartitionTable.Looks(b[t..])) continue;
                try
                {
                    var table = Esp32PartitionTable.Read(b[t..]);
                    return new Esp32Flash { Base = chip.BootloaderOffset - (uint)boot, BootloaderOffset = boot, Bootloader = image, TableOffset = t, Table = table };
                }
                catch (InvalidDataException) { }
            }
        }
        return null;
    }
}

/// <summary>An ESP32-family flash image as a container; a partition past the end is cut and noted, one outside is only listed.</summary>
internal sealed class Esp32FlashReader : IContainerReader
{
    public string Kind => "esp32 flash";

    public bool Accepts(ReadOnlySpan<byte> data, string name) => Esp32Flash.Find(data) != null;

    public ContainerContents Open(byte[] data, string name, bool allFiles, AnalysisLimits limits, CancellationToken ct) =>
        Read(FsSource.Of(data, name), limits, ct);

    public ContainerContents? Open(Stream stream, string name, bool allFiles, AnalysisLimits limits, CancellationToken ct) =>
        Read(new FsSource(stream, 0, stream.Length, name), limits, ct);

    private ContainerContents Read(FsSource src, AnalysisLimits limits, CancellationToken ct) => FsTree.Guard(src, () =>
    {
        var flash = Esp32Flash.Find(src.ReadUpTo(0, 1 << 20)) ?? throw src.Malformed("no ESP32 bootloader and partition table");
        var items = new List<ExtractedItem>();
        var entries = new List<ContainerEntry>();
        var notes = new List<string>
        {
            $"{flash.Bootloader.ChipInfo?.Name ?? "ESP32"} flash image from flash address 0x{flash.Base:X}: bootloader at 0x{flash.Base + flash.BootloaderOffset:X}, " +
            $"partition table at 0x{flash.Base + flash.TableOffset:X} ({flash.Table.Partitions.Count} partitions)",
        };
        long total = 0;
        bool stopped = false;
        void Add(string path, long start, long length, string detail)
        {
            ct.ThrowIfCancellationRequested();
            entries.Add(new ContainerEntry(path, length, detail));
            if (length == 0 || stopped) return;
            if (items.Count >= limits.MaxItems || total + length > limits.MaxTotalBytes || length > limits.MaxItemBytes)
            {
                stopped = true;
                notes.Add($"Stopped after {items.Count:N0} files ({total:N0} bytes): the extraction limit was reached.");
                return;
            }
            items.Add(new ExtractedItem(path, src.Read(start, (int)length), detail));
            total += length;
        }
        Add("bootloader.bin", flash.BootloaderOffset, flash.Bootloader.Length, $"bootloader image at 0x{flash.Base + flash.BootloaderOffset:X}");
        Add("partition-table.bin", flash.TableOffset, Math.Min(Esp32PartitionTable.Size, src.Length - flash.TableOffset), $"partition table at 0x{flash.Base + flash.TableOffset:X}");
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var p in flash.Table.Partitions)
        {
            var (start, length) = flash.InFile(p, src.Length);
            string label = p.Label.Length > 0 ? string.Concat(p.Label.Select(c => char.IsAsciiLetterOrDigit(c) || c is '_' or '-' or '.' ? c : '_')) : $"0x{p.Offset:x}";
            string path = seen.Add(label) ? label + ".bin" : $"{label}@0x{p.Offset:x}.bin";
            string detail = $"{p.TypeName} {p.SubtypeName} at 0x{p.Offset:X}, {p.Size:N0} bytes" + (p.Encrypted ? ", encrypted" : "") + (p.ReadOnly ? ", read-only" : "");
            if (length == 0) notes.Add($"{path}: at 0x{p.Offset:X}, past the end of the file");
            else if (length < p.Size) notes.Add($"{path}: {length:N0} of {p.Size:N0} bytes are in the file");
            Add(path, start, length, detail);
        }
        if (flash.Table.Md5Valid == false) notes.Add("the partition table's MD5 entry does not match its entries");
        return new ContainerContents("esp32 flash", items, notes) { Entries = entries };
    });
}
