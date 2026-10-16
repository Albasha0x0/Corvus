using System.Buffers.Binary;
using System.Text;
using Corvus.Core.Firmware;

namespace Corvus.Core.Disks;

/// <summary>A read-only window of a seekable stream.</summary>
internal sealed class SubStream(Stream inner, long start, long length) : Stream
{
    private long _position;

    public override long Length => length;
    public override bool CanRead => true;
    public override bool CanSeek => true;
    public override bool CanWrite => false;
    public override long Position { get => _position; set => _position = value; }

    public override int Read(byte[] buffer, int offset, int count)
    {
        if (_position >= length) return 0;
        inner.Position = start + _position;
        int n = inner.Read(buffer, offset, (int)Math.Min(count, length - _position));
        _position += n;
        return n;
    }

    public override long Seek(long offset, SeekOrigin origin) => _position = origin switch
    {
        SeekOrigin.Begin => offset, SeekOrigin.Current => _position + offset, _ => length + offset,
    };

    public override void Flush() { }
    public override void SetLength(long value) => throw new NotSupportedException();
    public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
}

/// <summary>
/// The volumes of a disk: MBR (primary and extended partitions) or GPT partitions, or the whole disk when it starts with a
/// file system; each opened by the container reader its first sectors match (NTFS, FAT, ext, ISO 9660 / UDF, ...).
/// </summary>
internal static class DiskVolumes
{
    private const int MaxPartitions = 128;

    public sealed record Partition(int Index, long Offset, long Length, string Type);

    public static List<Partition> Partitions(Stream disk, List<string> notes)
    {
        var parts = new List<Partition>();
        var mbr = Read(disk, 0, 512);
        if (mbr.Length < 512 || mbr[510] != 0x55 || mbr[511] != 0xAA) return parts;
        // a boot sector of a file system, not a partition table
        if (mbr.AsSpan(3, 4).SequenceEqual("NTFS"u8) || mbr.AsSpan(54, 3).SequenceEqual("FAT"u8) || mbr.AsSpan(82, 5).SequenceEqual("FAT32"u8)) return parts;
        var gpt = Read(disk, 512, 512);
        if (gpt.Length >= 92 && gpt.AsSpan(0, 8).SequenceEqual("EFI PART"u8))
        {
            long entriesAt = BinaryPrimitives.ReadInt64LittleEndian(gpt.AsSpan(72)) * 512;
            int count = (int)Math.Min(BinaryPrimitives.ReadUInt32LittleEndian(gpt.AsSpan(80)), MaxPartitions);
            int size = (int)BinaryPrimitives.ReadUInt32LittleEndian(gpt.AsSpan(84));
            if (size is < 128 or > 1024) { notes.Add($"GPT entry size {size} is out of range"); return parts; }
            var table = Read(disk, entriesAt, count * size);
            for (int i = 0; i < count && (i + 1) * size <= table.Length; i++)
            {
                var e = table.AsSpan(i * size, size);
                var type = new Guid(e[..16]);
                if (type == Guid.Empty) continue;
                long first = BinaryPrimitives.ReadInt64LittleEndian(e[32..]), last = BinaryPrimitives.ReadInt64LittleEndian(e[40..]);
                var name = Encoding.Unicode.GetString(e.Slice(56, 72)).TrimEnd('\0');
                if (first > 0 && last >= first) parts.Add(new Partition(parts.Count + 1, first * 512, (last - first + 1) * 512, GptType(type) + (name.Length > 0 ? $" '{name}'" : "")));
            }
            return parts;
        }
        void Entries(byte[] sector, long baseLba, long extendedStart, int depth)
        {
            for (int i = 0; i < 4 && parts.Count < MaxPartitions; i++)
            {
                var e = sector.AsSpan(446 + i * 16, 16);
                byte type = e[4];
                long lba = BinaryPrimitives.ReadUInt32LittleEndian(e[8..]), sectors = BinaryPrimitives.ReadUInt32LittleEndian(e[12..]);
                if (type == 0 || sectors == 0) continue;
                if (type is 0x05 or 0x0F or 0x85)
                {
                    long ebr = (extendedStart > 0 ? extendedStart : 0) + lba;
                    if (depth < MaxPartitions && Read(disk, ebr * 512, 512) is { Length: 512 } next && next[510] == 0x55 && next[511] == 0xAA)
                        Entries(next, ebr, extendedStart > 0 ? extendedStart : ebr, depth + 1);
                    continue;
                }
                parts.Add(new Partition(parts.Count + 1, (baseLba + lba) * 512, sectors * 512, MbrType(type)));
            }
        }
        Entries(mbr, 0, 0, 0);
        return parts;
    }

    private static string MbrType(byte t) => t switch
    {
        0x01 => "FAT12", 0x04 or 0x06 or 0x0E => "FAT16", 0x0B or 0x0C => "FAT32", 0x07 => "NTFS / exFAT", 0x83 => "Linux", 0x82 => "Linux swap", 0xEF => "EFI system",
        0x27 => "Windows recovery", _ => $"type 0x{t:X2}",
    };

    private static string GptType(Guid g) => g.ToString().ToUpperInvariant() switch
    {
        "EBD0A0A2-B9E5-4433-87C0-68B6B72699C7" => "basic data", "C12A7328-F81F-11D2-BA4B-00A0C93EC93B" => "EFI system",
        "E3C9E316-0B5C-4DB8-817D-F92DF00215AE" => "Microsoft reserved", "DE94BBA4-06D1-4D40-A16A-BFD50179D6AC" => "Windows recovery",
        "0FC63DAF-8483-4772-8E79-3D69D8477DE4" => "Linux", _ => g.ToString(),
    };

    private static byte[] Read(Stream s, long at, int n)
    {
        if (at < 0 || at >= s.Length || n <= 0) return [];
        var b = new byte[(int)Math.Min(n, s.Length - at)];
        s.Position = at;
        s.ReadAtLeast(b, b.Length, throwOnEndOfStream: false);
        return b;
    }

    /// <summary>Every volume of the disk opened by its reader, files under partition&lt;n&gt;/ (no prefix for a disk that is one volume).</summary>
    public static ContainerContents Open(Stream disk, string kind, string name, bool allFiles, AnalysisLimits limits, CancellationToken ct)
    {
        var notes = new List<string>();
        var items = new List<ExtractedItem>();
        var entries = new List<ContainerEntry>();
        var parts = Partitions(disk, notes);
        bool whole = parts.Count == 0;
        if (whole) parts.Add(new Partition(0, 0, disk.Length, "volume"));
        else notes.Add($"{parts.Count} partition(s): {string.Join("; ", parts.Select(p => $"{p.Index} {p.Type} at 0x{p.Offset:X}, {p.Length:N0} bytes"))}");
        foreach (var p in parts)
        {
            ct.ThrowIfCancellationRequested();
            var prefix = whole ? "" : $"partition{p.Index}/";
            var window = new SubStream(disk, p.Offset, Math.Min(p.Length, disk.Length - p.Offset));
            var head = Read(window, 0, 1 << 20);
            var reader = Containers.ReaderFor(head, name);
            if (reader == null || reader is VirtualDiskReader)
            {
                notes.Add($"{(whole ? "the disk" : $"partition {p.Index}")} ({p.Type}): no file system this server reads");
                continue;
            }
            ContainerContents? inner;
            try
            {
                inner = reader.Open(window, name, allFiles, limits, ct);
                if (inner == null && window.Length <= limits.MaxItemBytes) inner = reader.Open(Read(window, 0, (int)window.Length), name, allFiles, limits, ct);
            }
            catch (ToolError ex) when (ex.Code == ErrorCode.MalformedInput) { notes.Add($"{prefix}{ex.Message}"); continue; }
            if (inner == null) { notes.Add($"{prefix}: too large to read without a stream reader"); continue; }
            notes.Add($"{(whole ? "volume" : $"partition {p.Index}")}: {inner.Kind}");
            notes.AddRange(inner.Notes.Select(n => prefix + n));
            items.AddRange(inner.Items.Select(i => i with { Name = prefix + i.Name }));
            if (inner.Entries != null) entries.AddRange(inner.Entries.Select(e => e with { Path = prefix + e.Path }));
            else entries.AddRange(inner.Items.Select(i => new ContainerEntry(prefix + i.Name, i.Bytes.Length)));
        }
        return new ContainerContents(kind, items, notes) { Entries = entries };
    }
}

/// <summary>VHD and VHDX virtual disks: the disk's partitions and the files of each volume.</summary>
internal sealed class VirtualDiskReader : IContainerReader
{
    public string Kind => "vhd";

    public bool Accepts(ReadOnlySpan<byte> data, string name) =>
        data.Length >= 512 && (data.StartsWith("vhdxfile"u8) || data.StartsWith("conectix"u8) || data[^512..].StartsWith("conectix"u8));

    public ContainerContents Open(byte[] data, string name, bool allFiles, AnalysisLimits limits, CancellationToken ct) =>
        Read(FsSource.Of(data, name), name, allFiles, limits, ct);

    public ContainerContents? Open(Stream stream, string name, bool allFiles, AnalysisLimits limits, CancellationToken ct) =>
        Read(new FsSource(stream, 0, stream.Length, name), name, allFiles, limits, ct);

    private static ContainerContents Read(FsSource src, string name, bool allFiles, AnalysisLimits limits, CancellationToken ct) => FsTree.Guard(src, () =>
    {
        using var disk = DiskStream.Open(src) ?? throw src.Malformed("not a VHD or VHDX disk");
        var c = DiskVolumes.Open(disk, disk.Format, name, allFiles, limits, ct);
        c.Notes.Insert(0, $"{disk.Format}, {disk.Length:N0}-byte disk");
        return c;
    });
}
