using System.Buffers.Binary;
using System.Text;

namespace Corvus.Core.Firmware;

/// <summary>
/// UBI images: erase blocks found by their erase-counter and volume-identifier headers (CRC-checked), the volume table,
/// and each volume rebuilt from its logical erase blocks (the newest copy of each by sequence number); every volume is an
/// item, opened in turn by its own reader (UBIFS, squashfs). Headers are read in ranges.
/// </summary>
internal sealed class UbiReader : IContainerReader
{
    public string Kind => "UBI";

    private const uint LayoutVolume = 0x7FFFEFFF;

    public static bool Looks(ReadOnlySpan<byte> b) =>
        b.Length >= 64 && b.StartsWith("UBI#"u8) && b[4] == 1 && Crc.Ubi(b[..60]) == BinaryPrimitives.ReadUInt32BigEndian(b[60..]);

    public bool Accepts(ReadOnlySpan<byte> data, string name) => Looks(data);

    public ContainerContents Open(byte[] data, string name, bool allFiles, AnalysisLimits limits, CancellationToken ct) =>
        Read(FsSource.Of(data, name), limits, ct);

    public ContainerContents? Open(Stream stream, string name, bool allFiles, AnalysisLimits limits, CancellationToken ct) =>
        Read(new FsSource(stream, 0, stream.Length, name), limits, ct);

    private sealed record Leb(long Peb, ulong Sequence, uint DataSize, uint UsedBlocks, byte Type);

    private static ContainerContents Read(FsSource src, AnalysisLimits limits, CancellationToken ct) => FsTree.Guard(src, () =>
    {
        var ec = src.Read(0, 64);
        if (!Looks(ec)) throw src.Malformed("no UBI erase-counter header");
        long vidAt = BinaryPrimitives.ReadUInt32BigEndian(ec.AsSpan(16)), dataAt = BinaryPrimitives.ReadUInt32BigEndian(ec.AsSpan(20));
        long peb = PebSize(src);
        if (vidAt < 64 || dataAt <= vidAt || dataAt >= peb) throw src.Malformed($"UBI header offsets (VID {vidAt}, data {dataAt}) do not fit a {peb:N0}-byte erase block");
        var notes = new List<string>();
        var lebs = new Dictionary<(uint Volume, uint Lnum), Leb>();
        int unmapped = 0, bad = 0;
        long blocks = src.Length / peb;
        for (long i = 0; i < blocks; i++)
        {
            ct.ThrowIfCancellationRequested();
            long at = i * peb;
            if (!Looks(src.Read(at, 64))) { bad++; continue; }
            var vid = src.Read(at + vidAt, 64);
            if (!vid.AsSpan().StartsWith("UBI!"u8)) { unmapped++; continue; }
            if (Crc.Ubi(vid.AsSpan(0, 60)) != BinaryPrimitives.ReadUInt32BigEndian(vid.AsSpan(60))) { bad++; continue; }
            uint volume = BinaryPrimitives.ReadUInt32BigEndian(vid.AsSpan(8)), lnum = BinaryPrimitives.ReadUInt32BigEndian(vid.AsSpan(12));
            var leb = new Leb(at, BinaryPrimitives.ReadUInt64BigEndian(vid.AsSpan(40)), BinaryPrimitives.ReadUInt32BigEndian(vid.AsSpan(20)),
                BinaryPrimitives.ReadUInt32BigEndian(vid.AsSpan(24)), vid[5]);
            if (!lebs.TryGetValue((volume, lnum), out var kept) || kept.Sequence < leb.Sequence) lebs[(volume, lnum)] = leb;
        }
        long lebSize = peb - dataAt;
        notes.Add($"UBI, {peb >> 10} KiB erase blocks ({lebSize:N0}-byte logical blocks), {blocks:N0} blocks, {unmapped:N0} unmapped" + (bad > 0 ? $", {bad} with damaged headers" : ""));

        // the volume table: one 172-byte record per volume id, CRC-checked
        var names = new Dictionary<uint, (string Name, uint DataPad)>();
        if (lebs.TryGetValue((LayoutVolume, 0), out var layout) || lebs.TryGetValue((LayoutVolume, 1), out layout))
        {
            var table = src.Read(layout.Peb + dataAt, (int)Math.Min(lebSize, 128 * 172));
            for (uint v = 0; (v + 1) * 172 <= table.Length; v++)
            {
                var r = table.AsSpan((int)v * 172, 172);
                if (BinaryPrimitives.ReadUInt32BigEndian(r) == 0 || Crc.Ubi(r[..168]) != BinaryPrimitives.ReadUInt32BigEndian(r[168..])) continue;
                int nameLength = Math.Min((int)BinaryPrimitives.ReadUInt16BigEndian(r[14..]), 127);
                names[v] = (Encoding.UTF8.GetString(r.Slice(16, nameLength)), BinaryPrimitives.ReadUInt32BigEndian(r[8..]));
            }
        }
        else notes.Add("no volume table found: volumes are named by id");

        var items = new List<ExtractedItem>();
        var entries = new List<ContainerEntry>();
        long total = 0;
        foreach (var group in lebs.Where(l => l.Key.Volume != LayoutVolume).GroupBy(l => l.Key.Volume).OrderBy(g => g.Key))
        {
            ct.ThrowIfCancellationRequested();
            var (name, pad) = names.TryGetValue(group.Key, out var n) ? n : ($"volume_{group.Key}", 0u);
            if (!FsTree.UsableName(name)) name = $"volume_{group.Key}";
            var map = group.ToDictionary(l => l.Key.Lnum, l => l.Value);
            bool isStatic = map.Values.First().Type == 2;
            long usable = lebSize - pad;
            uint count = isStatic ? map.Values.First().UsedBlocks : map.Keys.Max() + 1;
            long size = isStatic ? map.Where(l => l.Key < count).Sum(l => (long)l.Value.DataSize) : count * usable;
            var detail = $"{(isStatic ? "static" : "dynamic")} volume {group.Key}, {map.Count} of {count} logical blocks mapped";
            entries.Add(new ContainerEntry(name, size, detail));
            if (size <= 0 || size > limits.MaxItemBytes || usable <= 0) { notes.Add($"{name}: {size:N0} bytes, not extracted"); continue; }
            if ((total += size) > limits.MaxTotalBytes)
                throw new ToolError(ErrorCode.LimitExceeded, $"extracting {name} passes the {limits.MaxTotalBytes:N0}-byte total limit.", "unpack fewer files or raise the limits");
            var bytes = new byte[size];
            long o = 0;
            for (uint l = 0; l < count; l++)
            {
                long take = isStatic ? (map.TryGetValue(l, out var s) ? s.DataSize : 0) : usable;
                take = Math.Min(take, size - o);
                if (map.TryGetValue(l, out var leb)) src.Read(leb.Peb + dataAt, (int)Math.Min(take, src.Length - leb.Peb - dataAt)).CopyTo(bytes, o);
                else bytes.AsSpan((int)o, (int)take).Fill(0xFF); // an unmapped block reads as erased flash
                o += take;
            }
            items.Add(new ExtractedItem(name, bytes, $"UBI {detail}"));
        }
        if (entries.Count == 0) notes.Add("no UBI volumes were recovered from this image: nothing extracted");
        return new ContainerContents("UBI", items, notes) { Entries = entries };
    });

    /// <summary>The erase-block size: the distance to the next erase-counter header, else the whole image.</summary>
    private static long PebSize(FsSource src)
    {
        for (long size = 16 << 10; size <= 4 << 20 && size < src.Length; size <<= 1)
            if (src.Length >= size + 64 && Looks(src.Read(size, 64))) return size;
        return src.Length;
    }
}

/// <summary>
/// UBIFS volumes: every node of every logical erase block found by magic and CRC, the newest inode, directory entry and data
/// block by sequence number (a deletion entry removes its name), files rebuilt from 4 KiB data blocks (LZO, deflate,
/// Zstandard or stored); the index is not needed.
/// </summary>
internal sealed class UbifsReader : IContainerReader
{
    public string Kind => "UBIFS";

    private const uint Magic = 0x06101831;

    public static bool Looks(ReadOnlySpan<byte> b) =>
        b.Length >= 4096 && BinaryPrimitives.ReadUInt32LittleEndian(b) == Magic && b[20] == 6
        && BinaryPrimitives.ReadUInt32LittleEndian(b[16..]) is >= 64 and <= 4096
        && Crc.Ubi(b[8..(int)BinaryPrimitives.ReadUInt32LittleEndian(b[16..])]) == BinaryPrimitives.ReadUInt32LittleEndian(b[4..]);

    public bool Accepts(ReadOnlySpan<byte> data, string name) => Looks(data);

    public ContainerContents Open(byte[] data, string name, bool allFiles, AnalysisLimits limits, CancellationToken ct) =>
        Read(FsSource.Of(data, name), allFiles, limits, ct);

    public ContainerContents? Open(Stream stream, string name, bool allFiles, AnalysisLimits limits, CancellationToken ct) =>
        Read(new FsSource(stream, 0, stream.Length, name), allFiles, limits, ct);

    private sealed record Ino(ulong Sequence, long Size, uint Mode, uint Links, long DataAt, int DataLength);
    private sealed record Dent(ulong Sequence, ulong Inode, string Name);
    private sealed record Block(ulong Sequence, long At, int Length, int Size, int Codec);

    private static ContainerContents Read(FsSource src, bool allFiles, AnalysisLimits limits, CancellationToken ct) => FsTree.Guard(src, () =>
    {
        var sb = src.Read(0, 96);
        if (!Looks(src.ReadUpTo(0, 4096))) throw src.Malformed("no UBIFS superblock node");
        long lebSize = BinaryPrimitives.ReadUInt32LittleEndian(sb.AsSpan(36));
        if (lebSize < 4096 || lebSize > 16 << 20) throw src.Malformed($"UBIFS logical block size {lebSize:N0}");
        var tree = new FsTree("UBIFS", allFiles, limits, ct);
        var inodes = new Dictionary<uint, Ino>();
        var dents = new Dictionary<(uint, string), Dent>();
        var blocks = new Dictionary<(uint, uint), Block>();
        int bad = 0;
        for (long leb = 0; leb * lebSize < src.Length; leb++)
        {
            ct.ThrowIfCancellationRequested();
            var data = src.ReadUpTo(leb * lebSize, (int)lebSize);
            for (int p = 0; p + 24 <= data.Length;)
            {
                int at = data.AsSpan(p).IndexOf((ReadOnlySpan<byte>)[0x31, 0x18, 0x10, 0x06]);
                if (at < 0) break;
                p += at;
                if ((p & 7) != 0 || p + 24 > data.Length) { p++; continue; }
                int length = (int)BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan(p + 16));
                if (length < 24 || length > data.Length - p || Crc.Ubi(data.AsSpan(p + 8, length - 8)) != BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan(p + 4)))
                {
                    bad++;
                    p += 8;
                    continue;
                }
                ulong seq = BinaryPrimitives.ReadUInt64LittleEndian(data.AsSpan(p + 8));
                var n = data.AsSpan(p, length);
                uint key = length >= 32 ? BinaryPrimitives.ReadUInt32LittleEndian(n[24..]) : 0;
                switch (data[p + 20])
                {
                    case 0 when length >= 160:
                        var ino = new Ino(seq, (long)BinaryPrimitives.ReadUInt64LittleEndian(n[48..]), BinaryPrimitives.ReadUInt32LittleEndian(n[104..]),
                            BinaryPrimitives.ReadUInt32LittleEndian(n[92..]), leb * lebSize + p + 160, Math.Min((int)BinaryPrimitives.ReadUInt32LittleEndian(n[112..]), length - 160));
                        if (!inodes.TryGetValue(key, out var i0) || i0.Sequence < seq) inodes[key] = ino;
                        break;
                    case 2 when length >= 56:
                        int nameLength = Math.Min(BinaryPrimitives.ReadUInt16LittleEndian(n[50..]), length - 56);
                        var dent = new Dent(seq, BinaryPrimitives.ReadUInt64LittleEndian(n[40..]), Encoding.UTF8.GetString(n.Slice(56, nameLength)));
                        if (!dents.TryGetValue((key, dent.Name), out var d0) || d0.Sequence < seq) dents[(key, dent.Name)] = dent;
                        break;
                    case 1 when length >= 48:
                        uint index = BinaryPrimitives.ReadUInt32LittleEndian(n[28..]) & 0x1FFFFFFF;
                        var block = new Block(seq, leb * lebSize + p + 48, length - 48, (int)BinaryPrimitives.ReadUInt32LittleEndian(n[40..]), BinaryPrimitives.ReadUInt16LittleEndian(n[44..]));
                        if (!blocks.TryGetValue((key, index), out var b0) || b0.Sequence < seq) blocks[(key, index)] = block;
                        break;
                }
                p += (length + 7) & ~7;
            }
        }
        if (bad > 0) tree.Notes.Add($"{bad} damaged node(s) skipped");
        tree.Notes.Add($"UBIFS, {lebSize:N0}-byte logical blocks, {inodes.Count:N0} inodes, {dents.Count:N0} directory entries");
        var byInode = blocks.GroupBy(b => b.Key.Item1).ToDictionary(g => g.Key, g => g.ToDictionary(b => b.Key.Item2, b => b.Value));
        var children = dents.Where(d => d.Value.Inode != 0).GroupBy(d => d.Key.Item1)
            .ToDictionary(g => g.Key, g => g.Select(d => d.Value).OrderBy(d => d.Name, StringComparer.Ordinal).ToList());
        var visited = new HashSet<ulong>();
        void Walk(ulong dir, string path, int depth)
        {
            if (depth > FsTree.MaxDepth || dir > uint.MaxValue || !visited.Add(dir) || !children.TryGetValue((uint)dir, out var list)) return;
            foreach (var d in list)
            {
                ct.ThrowIfCancellationRequested();
                if (!FsTree.UsableName(d.Name) || d.Inode > uint.MaxValue || !inodes.TryGetValue((uint)d.Inode, out var ino) || ino.Links == 0) continue;
                var full = path.Length == 0 ? d.Name : path + "/" + d.Name;
                try
                {
                    switch (ino.Mode & 0xF000)
                    {
                        case 0x4000: Walk(d.Inode, full, depth + 1); break;
                        case 0x8000: tree.File(full, ino.Size, () => Data(src, byInode.GetValueOrDefault((uint)d.Inode), ino.Size, limits)); break;
                        case 0xA000: tree.Link(full, Encoding.UTF8.GetString(src.Read(ino.DataAt, Math.Max(0, ino.DataLength)))); break;
                    }
                }
                catch (Exception ex) when (FsTree.Damaged(ex)) { tree.Unreadable(full, ex); }
            }
        }
        Walk(1, "", 0);
        return tree.Done();
    });

    private static byte[] Data(FsSource src, Dictionary<uint, Block>? blocks, long size, AnalysisLimits limits)
    {
        if (size < 0 || size > limits.MaxItemBytes) throw new InvalidDataException($"{size:N0} bytes");
        var bytes = new byte[size];
        if (blocks == null) return bytes;
        var page = new byte[4096];
        foreach (var (index, b) in blocks)
        {
            long at = (long)index * 4096;
            if (at >= size) continue;
            if (b.Size > 4096) throw new InvalidDataException("a UBIFS data block over 4 KiB");
            var raw = src.Read(b.At, b.Length);
            string codec = b.Codec switch { 0 => "none", 1 => "lzo", 2 => "deflate", 3 => "zstd", _ => throw new InvalidDataException($"UBIFS compression {b.Codec}") };
            int n = FsCodec.Decode(codec, raw, page.AsSpan(0, b.Size));
            page.AsSpan(0, (int)Math.Min(n, size - at)).CopyTo(bytes.AsSpan((int)at));
        }
        return bytes;
    }
}
