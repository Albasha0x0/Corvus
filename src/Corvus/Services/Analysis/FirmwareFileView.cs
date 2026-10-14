using System.Buffers.Binary;
using System.Text;
using Corvus.Core;

namespace Corvus.Services.Analysis;

/// <summary>
/// view=firmware: known formats found at offsets inside a file (a firmware image is formats laid end to end): boot and
/// kernel headers, filesystems, compressed streams and executables, each checked against its header's own fields.
/// </summary>
internal sealed class FirmwareFileView : IFileSummaryView
{
    private const int MaxHits = 200;

    /// <summary>One format at an offset; <see cref="Size"/> when its header declares one.</summary>
    public sealed record Hit(string Offset, string Format, long? Size, string? Detail);

    public sealed record Facts(IReadOnlyList<Hit> Signatures, IReadOnlyList<string> Notes);

    public string Name => "firmware";

    public FileView? Inspect(FileInput file, CancellationToken ct)
    {
        var d = file.Bytes;
        // firmware is opaque data; an executable or a known container gets its own views
        if (d.Length < 4096 || file.Kind != "data") return null;
        var hits = new List<(long At, Hit Hit)>();
        void Scan(ReadOnlySpan<byte> magic, Func<int, Hit?> check)
        {
            for (int from = 0; hits.Count < MaxHits && from < d.Length;)
            {
                ct.ThrowIfCancellationRequested();
                int at = d.AsSpan(from).IndexOf(magic);
                if (at < 0) return;
                at += from;
                if (check(at) is { } hit) hits.Add((at, hit));
                from = at + 1;
            }
        }
        Hit H(int at, string format, long? size, string? detail = null) => new($"0x{at:X}", format, size, detail);
        bool Fits(int at, long size) => size > 0 && at + size <= d.Length;

        Scan([0x27, 0x05, 0x19, 0x56], at => at + 64 <= d.Length && BinaryPrimitives.ReadUInt32BigEndian(d.AsSpan(at + 12)) is var size && Fits(at + 64, size)
            ? H(at, "U-Boot uImage", size + 64, $"'{Encoding.ASCII.GetString(d, at + 32, 32).TrimEnd('\0')}', OS {d[at + 28]}, arch {d[at + 29]}, type {d[at + 30]}") : null);
        Scan("hsqs"u8, at => at + 96 <= d.Length && (long)BinaryPrimitives.ReadUInt64LittleEndian(d.AsSpan(at + 40)) is var size && Fits(at, size)
            ? H(at, "squashfs (little endian)", size, $"version {BinaryPrimitives.ReadUInt16LittleEndian(d.AsSpan(at + 28))}.{BinaryPrimitives.ReadUInt16LittleEndian(d.AsSpan(at + 30))}") : null);
        Scan("sqsh"u8, at => at + 96 <= d.Length && (long)BinaryPrimitives.ReadUInt64BigEndian(d.AsSpan(at + 40)) is var size && Fits(at, size) ? H(at, "squashfs (big endian)", size) : null);
        Scan([0x45, 0x3D, 0xCD, 0x28], at => at + 16 <= d.Length && BinaryPrimitives.ReadUInt32LittleEndian(d.AsSpan(at + 4)) is var size && Fits(at, size) ? H(at, "cramfs", size) : null);
        Scan([0xD0, 0x0D, 0xFE, 0xED], at => at + 40 <= d.Length && BinaryPrimitives.ReadUInt32BigEndian(d.AsSpan(at + 4)) is var size && size >= 40 && Fits(at, size)
            && BinaryPrimitives.ReadUInt32BigEndian(d.AsSpan(at + 20)) is >= 1 and <= 17 ? H(at, "flattened device tree", size) : null);
        Scan("HDR0"u8, at => at + 28 <= d.Length && BinaryPrimitives.ReadUInt32LittleEndian(d.AsSpan(at + 4)) is var size && Fits(at, size) ? H(at, "TRX", size) : null);
        Scan("UBI#"u8, at => at + 64 <= d.Length && d[at + 4] == 1 ? H(at, "UBI erase block", null) : null);
        Scan("ANDROID!"u8, at => at + 48 <= d.Length ? H(at, "Android boot image", null, $"kernel {BinaryPrimitives.ReadUInt32LittleEndian(d.AsSpan(at + 8)):N0} bytes") : null);
        Scan([0x1F, 0x8B, 0x08], at => d.Length > at + 10 && d[at + 3] < 0x20 ? H(at, "gzip", null) : null);
        Scan([0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00], at => H(at, "xz", null));
        Scan([0x5D, 0x00, 0x00], at => at + 13 <= d.Length && BinaryPrimitives.ReadUInt32LittleEndian(d.AsSpan(at + 1)) is var dict && dict >= 1 << 16 && dict <= 1 << 26 && (dict & (dict - 1)) == 0
            && (long)BinaryPrimitives.ReadUInt64LittleEndian(d.AsSpan(at + 5)) is var unpacked && (unpacked == -1 || unpacked is > 0 and < 1L << 32)
            ? H(at, "LZMA", null, $"dictionary {dict >> 10} KiB") : null);
        Scan("PK\x03\x04"u8, at => H(at, "zip local file", null));
        Scan([0x7F, (byte)'E', (byte)'L', (byte)'F'], at => at + 20 <= d.Length && d[at + 4] is 1 or 2 && d[at + 5] is 1 or 2 ? H(at, $"ELF{(d[at + 4] == 2 ? "64" : "32")}", null) : null);
        foreach (var pe in Blob.CarvePe(d, MaxHits))
            if (hits.Count < MaxHits) hits.Add((pe.Offset, new Hit($"0x{pe.Offset:X}", pe.IsDotNet ? ".NET PE image" : "PE image", pe.Length, null)));

        // the file's own format at offset 0 alone is not firmware
        if (hits.Count == 0 || hits.All(h => h.At == 0)) return null;
        var sorted = hits.OrderBy(h => h.At).Select(h => h.Hit).ToList();
        var notes = new List<string>();
        if (hits.Count >= MaxHits) notes.Add($"stopped at {MaxHits} signatures");
        notes.Add("Code regions load with load_assembly format=raw (arch, base, entry); compressed and filesystem parts need an extractor.");
        var formats = sorted.GroupBy(h => h.Format).Select(g => g.Count() > 1 ? $"{g.Count()} {g.Key}" : $"{g.Key} at {g.First().Offset}");
        return new FileView(new Facts(sorted, notes), [$"Embedded formats: {string.Join(", ", formats.Take(8))}" + (formats.Count() > 8 ? ", ..." : "") + "."]);
    }
}
