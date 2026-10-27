using System.Buffers.Binary;
using System.Text;

namespace Corvus.Core.Firmware;

/// <summary>The parts of a boot image: each payload decoded when its header names a codec, named with its architecture and addresses.</summary>
internal static class BootParts
{
    /// <summary>The raw-load architecture name (load_assembly format=raw arch=) for an architecture a header names.</summary>
    public static string? RawArch(string? arch) => arch?.ToLowerInvariant() switch
    {
        "arm" => "arm", "arm64" or "aarch64" => "arm64", "x86" or "i386" => "x86", "x86_64" or "amd64" => "x64",
        "mips" => "mips", "mips64" => "mips64", "powerpc" or "ppc" => "ppc", "riscv" => "riscv64",
        _ => null,
    };

    /// <summary>Adds one payload, decoded by <paramref name="codec"/> when given; a headerless kernel gets its load_assembly call.</summary>
    public static void Add(List<ExtractedItem> items, List<ContainerEntry> entries, List<string> notes, string name, byte[] stored, string? codec,
        string? arch, ulong? load, ulong? entry, string detail, AnalysisLimits limits)
    {
        byte[] bytes = stored;
        if (codec is { } c && c != "none")
        {
            try { bytes = FsCodec.DecodeStream(c, stored, limits.MaxItemBytes); detail += $", {c} decoded"; }
            catch (InvalidDataException ex) { notes.Add($"{name}: {c} data not decoded ({ex.Message}); kept as stored"); }
        }
        entries.Add(new ContainerEntry(name, bytes.Length, detail));
        items.Add(new ExtractedItem(name, bytes, detail));
        if (Blob.Identify(bytes) == "data" && RawArch(arch) is { } raw && load is { } at)
            notes.Add($"{name}: headerless {raw} code: load_assembly format=raw arch={raw} base=0x{at & ~0xFFFUL:X}" + (entry is { } e ? $" entry=0x{e:X}" : ""));
    }
}

/// <summary>U-Boot legacy images (uImage): CRC-checked header and decoded payloads; architecture and load address map the code.</summary>
internal sealed class UImageReader : IContainerReader
{
    public string Kind => "uImage";

    private static readonly string?[] Arches =
    [
        null, "alpha", "arm", "x86", "ia64", "mips", "mips64", "powerpc", "s390", "sh", "sparc", "sparc64", "m68k", "nios", "microblaze",
        "nios2", "blackfin", "avr32", "st200", "sandbox", "nds32", "openrisc", "arm64", "arc", "x86_64", "xtensa", "riscv",
    ];

    private static readonly string?[] Codecs = ["none", "gzip", "bzip2", "lzma", "lzo", "lz4", "zstd"];

    public static string? ArchName(byte code) => code < Arches.Length ? Arches[code] : null;

    public static bool Looks(ReadOnlySpan<byte> b) =>
        b.Length >= 64 && BinaryPrimitives.ReadUInt32BigEndian(b) == 0x27051956 && HeaderCrc(b[..64]) == BinaryPrimitives.ReadUInt32BigEndian(b[4..]);

    /// <summary>The header CRC-32 is taken with its own field zeroed.</summary>
    private static uint HeaderCrc(ReadOnlySpan<byte> header)
    {
        Span<byte> copy = stackalloc byte[64];
        header.CopyTo(copy);
        copy.Slice(4, 4).Clear();
        return ~Crc.Raw(0xFFFFFFFF, copy);
    }

    public bool Accepts(ReadOnlySpan<byte> data, string name) => Looks(data);

    public ContainerContents Open(byte[] data, string name, bool allFiles, AnalysisLimits limits, CancellationToken ct) => Read(FsSource.Of(data, name), limits);

    public ContainerContents? Open(Stream stream, string name, bool allFiles, AnalysisLimits limits, CancellationToken ct) =>
        Read(new FsSource(stream, 0, stream.Length, name), limits);

    private static ContainerContents Read(FsSource src, AnalysisLimits limits) => FsTree.Guard(src, () =>
    {
        var h = src.Read(0, 64);
        uint size = BinaryPrimitives.ReadUInt32BigEndian(h.AsSpan(12));
        ulong load = BinaryPrimitives.ReadUInt32BigEndian(h.AsSpan(16)), entry = BinaryPrimitives.ReadUInt32BigEndian(h.AsSpan(20));
        byte os = h[28], archCode = h[29], type = h[30], comp = h[31];
        var arch = ArchName(archCode);
        var codec = comp < Codecs.Length ? Codecs[comp] : null;
        var title = Encoding.ASCII.GetString(h, 32, 32).TrimEnd('\0');
        var notes = new List<string> { $"uImage '{title}', type {type}, OS {os}, arch {arch ?? archCode.ToString()}, load 0x{load:X}, entry 0x{entry:X}, {codec ?? $"compression {comp}"}" };
        if (size > src.Length - 64 || size > limits.MaxItemBytes) throw src.Malformed($"the uImage payload of {size:N0} bytes runs past the end");
        var items = new List<ExtractedItem>();
        var entries = new List<ContainerEntry>();
        string detail = $"uImage payload, arch {arch ?? archCode.ToString()}, load 0x{load:X}, entry 0x{entry:X}";
        if (type == 4)
        {
            // Multi-file: a zero-terminated list of sizes, then each file 4-byte aligned.
            var sizes = new List<uint>();
            for (long p = 64; sizes.Count < 64; p += 4)
            {
                uint s = BinaryPrimitives.ReadUInt32BigEndian(src.Read(p, 4));
                if (s == 0) break;
                sizes.Add(s);
            }
            long at = 64 + (sizes.Count + 1) * 4;
            for (int i = 0; i < sizes.Count; i++)
            {
                if (sizes[i] > src.Length - at) { notes.Add($"file {i} runs past the end"); break; }
                BootParts.Add(items, entries, notes, $"file_{i}", src.Read(at, (int)sizes[i]), i == 0 ? codec : null, arch, i == 0 ? load : null, i == 0 ? entry : null,
                    $"uImage multi-file part {i}", limits);
                at += (sizes[i] + 3) & ~3u;
            }
        }
        else BootParts.Add(items, entries, notes, type == 2 ? "kernel" : type == 3 ? "ramdisk" : type == 8 ? "fdt.dtb" : "payload", src.Read(64, (int)size), codec, arch,
            type is 2 or 14 or 5 ? load : null, entry, detail, limits);
        return new ContainerContents("uImage", items, notes) { Entries = entries };
    });
}

/// <summary>U-Boot FIT images: each /images entry's inline or external data, decoded by its compression property.</summary>
internal sealed class FitReader : IContainerReader
{
    public string Kind => "FIT";

    public static bool Looks(ReadOnlySpan<byte> b)
    {
        if (b.Length < 40 || BinaryPrimitives.ReadUInt32BigEndian(b) != 0xD00DFEED || BinaryPrimitives.ReadUInt32BigEndian(b[20..]) is < 16 or > 17) return false;
        int structAt = (int)Math.Min(BinaryPrimitives.ReadUInt32BigEndian(b[8..]), (uint)b.Length);
        return b[structAt..b.Length].Slice(0, Math.Min(b.Length - structAt, 1 << 16)).IndexOf("\0\0\0\u0001images\0"u8) >= 0;
    }

    public bool Accepts(ReadOnlySpan<byte> data, string name) => Looks(data);

    public ContainerContents Open(byte[] data, string name, bool allFiles, AnalysisLimits limits, CancellationToken ct) => Read(FsSource.Of(data, name), limits, ct);

    public ContainerContents? Open(Stream stream, string name, bool allFiles, AnalysisLimits limits, CancellationToken ct) =>
        Read(new FsSource(stream, 0, stream.Length, name), limits, ct);

    /// <summary>A node: its path, and each property's value (data properties as a range of the image).</summary>
    internal sealed record Node(string Path, Dictionary<string, (long At, int Length)> Props);

    /// <summary>Every node of a flattened device tree, its property values as ranges of the source.</summary>
    internal static List<Node> Parse(FsSource src, AnalysisLimits limits, CancellationToken ct)
    {
        var h = src.Read(0, 40);
        uint total = BinaryPrimitives.ReadUInt32BigEndian(h.AsSpan(4)), structAt = BinaryPrimitives.ReadUInt32BigEndian(h.AsSpan(8)),
            stringsAt = BinaryPrimitives.ReadUInt32BigEndian(h.AsSpan(12)), stringsSize = BinaryPrimitives.ReadUInt32BigEndian(h.AsSpan(32)),
            structSize = BinaryPrimitives.ReadUInt32BigEndian(h.AsSpan(36));
        if (total > src.Length || structAt > total || stringsAt > total || stringsSize > total - stringsAt || structSize > total - structAt || stringsSize > 16 << 20)
            throw src.Malformed("device tree blocks lie outside its total size");
        var strings = src.Read(stringsAt, (int)stringsSize);
        var nodes = new List<Node>();
        var stack = new Stack<Node>();
        long p = structAt, end = structAt + structSize;
        while (p + 4 <= end)
        {
            ct.ThrowIfCancellationRequested();
            uint token = BinaryPrimitives.ReadUInt32BigEndian(src.Read(p, 4));
            p += 4;
            switch (token)
            {
                case 1:
                    var nameBytes = src.ReadUpTo(p, 256);
                    int z = Array.IndexOf(nameBytes, (byte)0);
                    if (z < 0) throw src.Malformed("an unterminated device tree node name");
                    var name = Encoding.UTF8.GetString(nameBytes, 0, z);
                    p += (z + 1 + 3) & ~3;
                    if (stack.Count > 64 || nodes.Count > 100_000) throw src.Malformed("device tree nested or sized past its limits");
                    var node = new Node(stack.Count == 0 ? "" : stack.Peek().Path + "/" + name, []);
                    nodes.Add(node);
                    stack.Push(node);
                    break;
                case 2:
                    if (stack.Count == 0) throw src.Malformed("unbalanced device tree nodes");
                    stack.Pop();
                    break;
                case 3:
                    var prop = src.Read(p, 8);
                    uint length = BinaryPrimitives.ReadUInt32BigEndian(prop), nameOff = BinaryPrimitives.ReadUInt32BigEndian(prop.AsSpan(4));
                    if (length > end - p - 8 || nameOff >= strings.Length || stack.Count == 0) throw src.Malformed("a device tree property runs past its block");
                    int zero = Array.IndexOf(strings, (byte)0, (int)nameOff);
                    var propName = Encoding.UTF8.GetString(strings, (int)nameOff, (zero < 0 ? strings.Length : zero) - (int)nameOff);
                    stack.Peek().Props[propName] = (p + 8, (int)length);
                    p += 8 + ((length + 3) & ~3u);
                    break;
                case 4: break;
                case 9: return nodes;
                default: throw src.Malformed($"device tree token {token}");
            }
        }
        return nodes;
    }

    private static ContainerContents Read(FsSource src, AnalysisLimits limits, CancellationToken ct) => FsTree.Guard(src, () =>
    {
        var nodes = Parse(src, limits, ct);
        uint total = BinaryPrimitives.ReadUInt32BigEndian(src.Read(4, 4));
        string? Text(Node n, string prop) => n.Props.TryGetValue(prop, out var v) && v.Length is > 0 and <= 256 ? Encoding.UTF8.GetString(src.Read(v.At, v.Length)).TrimEnd('\0') : null;
        ulong? Number(Node n, string prop) => n.Props.TryGetValue(prop, out var v) && v.Length is 4 or 8 ? v.Length == 4
            ? BinaryPrimitives.ReadUInt32BigEndian(src.Read(v.At, 4)) : BinaryPrimitives.ReadUInt64BigEndian(src.Read(v.At, 8)) : null;
        var root = nodes.FirstOrDefault() ?? throw src.Malformed("an empty device tree");
        var notes = new List<string> { $"FIT image '{Text(root, "description")}'" };
        var items = new List<ExtractedItem>();
        var entries = new List<ContainerEntry>();
        foreach (var n in nodes.Where(n => n.Path.StartsWith("/images/", StringComparison.Ordinal) && n.Path.Count(c => c == '/') == 2))
        {
            ct.ThrowIfCancellationRequested();
            var name = n.Path["/images/".Length..];
            if (!FsTree.UsableName(name)) continue;
            long at;
            long length;
            if (n.Props.TryGetValue("data", out var inline)) (at, length) = (inline.At, inline.Length);
            else if (Number(n, "data-size") is { } size && (Number(n, "data-position") is { } position ? (long)position : Number(n, "data-offset") is { } offset ? ((total + 3) & ~3u) + (long)offset : -1) is var start and >= 0)
                (at, length) = (start, (long)size);
            else { notes.Add($"{name}: no data"); continue; }
            if (at < 0 || length < 0 || length > src.Length - at || length > limits.MaxItemBytes) { notes.Add($"{name}: data outside the image"); continue; }
            var type = Text(n, "type") ?? "image";
            var arch = Text(n, "arch");
            var codec = Text(n, "compression") is { } comp && comp != "none" ? comp switch { "lzma" => "lzma", "gzip" => "gzip", "bzip2" => "bzip2", "lz4" => "lz4", "zstd" => "zstd", "xz" => "xz", _ => null } : null;
            if (codec == null && Text(n, "compression") is { } other && other != "none") notes.Add($"{name}: {other} data kept as stored");
            ulong? load = Number(n, "load"), entry = Number(n, "entry");
            var detail = $"FIT {type} image" + (arch != null ? $", arch {arch}" : "") + (load is { } l ? $", load 0x{l:X}" : "") + (entry is { } e ? $", entry 0x{e:X}" : "");
            BootParts.Add(items, entries, notes, name, src.Read(at, (int)length), codec, arch, type is "kernel" or "firmware" or "standalone" ? load : null, entry, detail, limits);
        }
        if (entries.Count == 0) notes.Add("no images were recovered from this FIT: nothing extracted");
        return new ContainerContents("FIT", items, notes) { Entries = entries };
    });
}

/// <summary>Android boot images (ANDROID!, header versions 0-4): the kernel, ramdisk and second stage, decoded when compressed.</summary>
internal sealed class AndroidBootReader : IContainerReader
{
    public string Kind => "Android boot image";

    public static bool Looks(ReadOnlySpan<byte> b) => b.Length >= 1632 && b.StartsWith("ANDROID!"u8) && BinaryPrimitives.ReadUInt32LittleEndian(b[40..]) <= 8;

    public bool Accepts(ReadOnlySpan<byte> data, string name) => Looks(data);

    public ContainerContents Open(byte[] data, string name, bool allFiles, AnalysisLimits limits, CancellationToken ct) => Read(FsSource.Of(data, name), limits);

    public ContainerContents? Open(Stream stream, string name, bool allFiles, AnalysisLimits limits, CancellationToken ct) =>
        Read(new FsSource(stream, 0, stream.Length, name), limits);

    private static ContainerContents Read(FsSource src, AnalysisLimits limits) => FsTree.Guard(src, () =>
    {
        var h = src.Read(0, 1632);
        uint U(int at) => BinaryPrimitives.ReadUInt32LittleEndian(h.AsSpan(at));
        uint version = U(40);
        var notes = new List<string>();
        var items = new List<ExtractedItem>();
        var entries = new List<ContainerEntry>();
        var parts = new List<(string Name, uint Size)>();
        long page;
        if (version >= 3)
        {
            page = 4096;
            parts.Add(("kernel", U(8)));
            parts.Add(("ramdisk", U(12)));
            notes.Add($"Android boot image v{version}, header {U(20)} bytes");
        }
        else
        {
            page = U(36);
            parts.Add(("kernel", U(8)));
            parts.Add(("ramdisk", U(16)));
            parts.Add(("second", U(24)));
            notes.Add($"Android boot image v{version}, {page}-byte pages, kernel at 0x{U(12):X}, '{Encoding.ASCII.GetString(h, 48, 16).TrimEnd('\0')}'");
        }
        if (page is < 2048 or > 65536 || (page & (page - 1)) != 0) throw src.Malformed($"Android boot page size {page}");
        // The header takes the first page.
        long at = page;
        foreach (var (name, size) in parts)
        {
            if (size == 0) continue;
            if (size > src.Length - at || size > limits.MaxItemBytes) { notes.Add($"{name}: runs past the end"); break; }
            var stored = src.Read(at, (int)size);
            string? codec = Blob.Identify(stored) == "gzip" ? "gzip" : stored.AsSpan().StartsWith((ReadOnlySpan<byte>)[0x02, 0x21, 0x4C, 0x18]) ? "lz4-legacy"
                : stored.AsSpan().StartsWith((ReadOnlySpan<byte>)[0x04, 0x22, 0x4D, 0x18]) ? "lz4" : stored.AsSpan().StartsWith((ReadOnlySpan<byte>)[0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00]) ? "xz" : null;
            if (codec == "lz4-legacy") { notes.Add($"{name}: LZ4 legacy frames kept as stored"); codec = null; }
            BootParts.Add(items, entries, notes, name, stored, name == "ramdisk" ? codec : null, null, null, null, $"Android boot {name}", limits);
            at += (size + page - 1) / page * page;
        }
        return new ContainerContents("Android boot image", items, notes) { Entries = entries };
    });
}

/// <summary>Broadcom TRX images (HDR0, versions 1 and 2): the CRC-checked header and its partitions (loader, kernel, filesystem).</summary>
internal sealed class TrxReader : IContainerReader
{
    public string Kind => "TRX";

    public static bool Looks(ReadOnlySpan<byte> b) =>
        b.Length >= 28 && b.StartsWith("HDR0"u8) && BinaryPrimitives.ReadUInt32LittleEndian(b[4..]) is var length && length >= 28
        && (BinaryPrimitives.ReadUInt32LittleEndian(b[12..]) >> 16) is 1 or 2 && (length > b.Length || ~Crc.Raw(0xFFFFFFFF, b[12..(int)length]) == BinaryPrimitives.ReadUInt32LittleEndian(b[8..]));

    public bool Accepts(ReadOnlySpan<byte> data, string name) => Looks(data);

    public ContainerContents Open(byte[] data, string name, bool allFiles, AnalysisLimits limits, CancellationToken ct) => Read(FsSource.Of(data, name), limits);

    public ContainerContents? Open(Stream stream, string name, bool allFiles, AnalysisLimits limits, CancellationToken ct) =>
        Read(new FsSource(stream, 0, stream.Length, name), limits);

    private static ContainerContents Read(FsSource src, AnalysisLimits limits) => FsTree.Guard(src, () =>
    {
        var h = src.Read(0, 32);
        uint length = BinaryPrimitives.ReadUInt32LittleEndian(h.AsSpan(4));
        int version = (int)(BinaryPrimitives.ReadUInt32LittleEndian(h.AsSpan(12)) >> 16);
        if (length > src.Length) throw src.Malformed($"the TRX length {length:N0} runs past the end");
        var offsets = Enumerable.Range(0, version == 2 ? 4 : 3).Select(i => BinaryPrimitives.ReadUInt32LittleEndian(h.AsSpan(16 + i * 4))).Where(o => o != 0).ToList();
        var notes = new List<string> { $"TRX v{version}, {length:N0} bytes, {offsets.Count} partitions" };
        var items = new List<ExtractedItem>();
        var entries = new List<ContainerEntry>();
        for (int i = 0; i < offsets.Count; i++)
        {
            long start = offsets[i], end = i + 1 < offsets.Count ? offsets[i + 1] : length;
            if (start >= end || end > length || end - start > limits.MaxItemBytes) { notes.Add($"partition {i}: bad offsets"); continue; }
            var bytes = src.Read(start, (int)(end - start));
            string name = $"partition_{i}";
            entries.Add(new ContainerEntry(name, bytes.Length, $"TRX partition {i} at 0x{start:X}"));
            items.Add(new ExtractedItem(name, bytes, $"TRX partition {i} at 0x{start:X}"));
        }
        return new ContainerContents("TRX", items, notes) { Entries = entries };
    });
}
