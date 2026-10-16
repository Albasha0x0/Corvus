using System.Buffers.Binary;
using System.Text;

namespace Corvus.Core.Firmware;

/// <summary>
/// JFFS2 images in either byte order: every node found by its magic and header CRC, the newest version of each directory
/// entry and data range kept (a deleted entry removes its name), file data rebuilt from its nodes (zlib, LZMA, LZO, rtime,
/// zero and stored); the whole image is scanned in ranges.
/// </summary>
internal sealed class Jffs2Reader : IContainerReader
{
    public string Kind => "jffs2";

    private const ushort Magic = 0x1985;
    private const ushort Dirent = 0xE001, InodeNode = 0xE002;

    /// <summary>A first node header with a valid CRC.</summary>
    public static bool Looks(ReadOnlySpan<byte> b)
    {
        if (b.Length < 12) return false;
        foreach (bool big in (bool[])[false, true])
        {
            ushort magic = big ? BinaryPrimitives.ReadUInt16BigEndian(b) : BinaryPrimitives.ReadUInt16LittleEndian(b);
            if (magic != Magic) continue;
            uint crc = big ? BinaryPrimitives.ReadUInt32BigEndian(b[8..]) : BinaryPrimitives.ReadUInt32LittleEndian(b[8..]);
            if (Crc.Jffs2(b[..8]) == crc) return true;
        }
        return false;
    }

    public bool Accepts(ReadOnlySpan<byte> data, string name) => Looks(data);

    public ContainerContents Open(byte[] data, string name, bool allFiles, AnalysisLimits limits, CancellationToken ct) =>
        Read(FsSource.Of(data, name), allFiles, limits, ct);

    public ContainerContents? Open(Stream stream, string name, bool allFiles, AnalysisLimits limits, CancellationToken ct) =>
        Read(new FsSource(stream, 0, stream.Length, name), allFiles, limits, ct);

    private sealed record Entry(uint Parent, string Name, uint Version, uint Inode, byte Type);

    /// <summary>One data node: where its payload is, and what it covers.</summary>
    private sealed record Data(uint Version, long At, uint Offset, uint StoredSize, uint Size, byte Codec, uint Mode, uint FileSize);

    private static ContainerContents Read(FsSource src, bool allFiles, AnalysisLimits limits, CancellationToken ct) => FsTree.Guard(src, () =>
    {
        var head = src.ReadUpTo(0, 2);
        bool big = head.Length == 2 && BinaryPrimitives.ReadUInt16BigEndian(head) == Magic;
        var tree = new FsTree("jffs2", allFiles, limits, ct);
        var entries = new Dictionary<(uint, string), Entry>();
        var nodes = new Dictionary<uint, List<Data>>();
        int bad = 0;
        uint U32(byte[] b, int at) => big ? BinaryPrimitives.ReadUInt32BigEndian(b.AsSpan(at)) : BinaryPrimitives.ReadUInt32LittleEndian(b.AsSpan(at));
        ushort U16(byte[] b, int at) => big ? BinaryPrimitives.ReadUInt16BigEndian(b.AsSpan(at)) : BinaryPrimitives.ReadUInt16LittleEndian(b.AsSpan(at));

        // nodes are 4-byte aligned; the image is scanned a window at a time
        const int Window = 1 << 20;
        long resume = 0; // the first offset past the last node read
        for (long w = 0; w < src.Length; w += Window)
        {
            ct.ThrowIfCancellationRequested();
            if (resume >= w + Window) continue;
            var buf = src.ReadUpTo(w, Window + 12);
            for (int p = (int)Math.Max(0, resume - w); p + 12 <= buf.Length && p < Window; p += 4)
            {
                if (U16(buf, p) != Magic) continue;
                ushort type = U16(buf, p + 2);
                uint length = U32(buf, p + 4);
                if (Crc.Jffs2(buf.AsSpan(p, 8)) != U32(buf, p + 8)) continue;
                long at = w + p;
                if (length < 12 || length > src.Length - at) { bad++; continue; }
                if (type == Dirent && length >= 40)
                {
                    var d = src.Read(at, (int)Math.Min(length, 40 + 255));
                    int nameSize = d[28];
                    if (40 + nameSize > d.Length || Crc.Jffs2(d.AsSpan(0, 32)) != U32(d, 32)) { bad++; continue; }
                    var e = new Entry(U32(d, 12), Encoding.UTF8.GetString(d, 40, nameSize), U32(d, 16), U32(d, 20), d[29]);
                    if (!entries.TryGetValue((e.Parent, e.Name), out var kept) || kept.Version < e.Version) entries[(e.Parent, e.Name)] = e;
                }
                else if (type == InodeNode && length >= 68)
                {
                    var n = src.Read(at, 68);
                    if (Crc.Jffs2(n.AsSpan(0, 60)) != U32(n, 64)) { bad++; continue; }
                    uint ino = U32(n, 12);
                    var data = new Data(U32(n, 16), at + 68, U32(n, 44), U32(n, 48), U32(n, 52), n[56], U32(n, 20), U32(n, 28));
                    if (data.StoredSize > length - 68) { bad++; continue; }
                    if (!nodes.TryGetValue(ino, out var list)) nodes[ino] = list = [];
                    if (list.Count < 1 << 20) list.Add(data);
                }
                // the payload holds no node headers; skip it
                if (type is Dirent or InodeNode)
                {
                    resume = at + ((length + 3) & ~3u);
                    if (resume - w >= Window) break;
                    p = (int)(resume - w) - 4;
                }
            }
        }
        if (bad > 0) tree.Notes.Add($"{bad} damaged node(s) skipped");
        tree.Notes.Add($"JFFS2, {(big ? "big" : "little")} endian, {entries.Count:N0} directory entries, {nodes.Count:N0} inodes");

        var children = entries.Values.Where(e => e.Inode != 0).GroupBy(e => e.Parent).ToDictionary(g => g.Key, g => g.OrderBy(e => e.Name, StringComparer.Ordinal).ToList());
        var visited = new HashSet<uint>();
        void Walk(uint dir, string path, int depth)
        {
            if (depth > FsTree.MaxDepth || !visited.Add(dir) || !children.TryGetValue(dir, out var list)) return;
            foreach (var e in list)
            {
                ct.ThrowIfCancellationRequested();
                if (!FsTree.UsableName(e.Name)) continue;
                var full = path.Length == 0 ? e.Name : path + "/" + e.Name;
                nodes.TryGetValue(e.Inode, out var data);
                var latest = data?.MaxBy(d => d.Version);
                uint mode = latest?.Mode ?? (uint)(e.Type switch { 4 => 0x4000, 10 => 0xA000, _ => 0x8000 });
                try
                {
                    switch (mode & 0xF000)
                    {
                        case 0x4000: Walk(e.Inode, full, depth + 1); break;
                        case 0x8000: tree.File(full, latest?.FileSize ?? 0, n => Build(src, data ?? [], (uint)n, limits)); break;
                        case 0xA000: tree.Link(full, Encoding.UTF8.GetString(Build(src, data ?? [], Math.Min(latest?.FileSize ?? 0, 4096), limits))); break;
                    }
                }
                catch (Exception ex) when (FsTree.Damaged(ex)) { tree.Unreadable(full, ex); }
            }
        }
        Walk(1, "", 0);
        return tree.Done();
    });

    /// <summary>A file's bytes: its data nodes applied oldest first, so newer ranges overwrite older ones.</summary>
    private static byte[] Build(FsSource src, List<Data> nodes, uint size, AnalysisLimits limits)
    {
        if (size > limits.MaxItemBytes) throw new InvalidDataException($"{size:N0} bytes");
        var bytes = new byte[size];
        foreach (var d in nodes.OrderBy(n => n.Version))
        {
            if (d.Size == 0 || d.Offset >= size) continue;
            if (d.Size > 1 << 20) throw new InvalidDataException("a data node larger than 1 MiB");
            var output = new byte[d.Size];
            if (d.Codec != 1) // 1: a hole of zeros
            {
                var raw = src.Read(d.At, (int)d.StoredSize);
                switch (d.Codec)
                {
                    case 0: raw.AsSpan(0, Math.Min(raw.Length, output.Length)).CopyTo(output); break;
                    case 2: Rtime(raw, output); break;
                    case 6: FsCodec.Decode("zlib", raw, output); break;
                    case 7: FsCodec.Decode("lzo", raw, output); break;
                    case 8: Lzma(raw, output); break;
                    default: throw new InvalidDataException($"JFFS2 compression {d.Codec} is not read");
                }
            }
            output.AsSpan(0, (int)Math.Min(output.Length, size - d.Offset)).CopyTo(bytes.AsSpan((int)d.Offset));
        }
        return bytes;
    }

    /// <summary>JFFS2's own run-time coder: a literal byte, then a repeat count of the bytes after its last occurrence.</summary>
    private static void Rtime(byte[] src, byte[] dst)
    {
        Span<int> last = stackalloc int[256];
        int o = 0, i = 0;
        while (o < dst.Length)
        {
            if (i + 1 >= src.Length) throw new InvalidDataException("truncated rtime data");
            byte value = src[i++];
            int repeat = src[i++];
            dst[o] = value;
            int back = last[value];
            last[value] = ++o;
            if (repeat > dst.Length - o) throw new InvalidDataException("rtime run past the end");
            for (; repeat > 0; repeat--)
            {
                byte c = dst[back++];
                dst[o++] = c;
            }
        }
    }

    /// <summary>The kernel's LZMA settings for JFFS2 (lc 0, lp 0, pb 0, 32 KiB dictionary), stored without a header.</summary>
    private static void Lzma(byte[] raw, byte[] output)
    {
        var withHeader = new byte[13 + raw.Length];
        withHeader[0] = 0; // lc=0, lp=0, pb=0
        BinaryPrimitives.WriteUInt32LittleEndian(withHeader.AsSpan(1), 0x8000);
        BinaryPrimitives.WriteInt64LittleEndian(withHeader.AsSpan(5), output.Length);
        raw.CopyTo(withHeader, 13);
        FsCodec.Decode("lzma", withHeader, output);
    }
}

/// <summary>The CRC-32 variants of flash filesystems: the reflected 0xEDB88320 polynomial with the kernel's seeds and no final inversion.</summary>
internal static class Crc
{
    private static readonly uint[] Table = Enumerable.Range(0, 256).Select(n =>
    {
        uint c = (uint)n;
        for (int k = 0; k < 8; k++) c = (c & 1) != 0 ? 0xEDB88320 ^ (c >> 1) : c >> 1;
        return c;
    }).ToArray();

    public static uint Raw(uint seed, ReadOnlySpan<byte> data)
    {
        uint c = seed;
        foreach (byte b in data) c = Table[(c ^ b) & 0xFF] ^ (c >> 8);
        return c;
    }

    /// <summary>JFFS2: crc32(0, data).</summary>
    public static uint Jffs2(ReadOnlySpan<byte> data) => Raw(0, data);

    /// <summary>UBI and UBIFS: crc32(0xFFFFFFFF, data).</summary>
    public static uint Ubi(ReadOnlySpan<byte> data) => Raw(0xFFFFFFFF, data);
}
