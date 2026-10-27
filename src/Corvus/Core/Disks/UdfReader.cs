using System.Buffers.Binary;
using System.Text;
using Corvus.Core.Firmware;

namespace Corvus.Core.Disks;

/// <summary>UDF file systems (ECMA-167, UDF 1.02 to 2.01, type 1 partition maps) from the anchor at sector 256.</summary>
internal static class UdfReader
{
    private const int Sector = 2048;

    public static bool IsAnchor(ReadOnlySpan<byte> tag) => tag.Length >= 16 && BinaryPrimitives.ReadUInt16LittleEndian(tag) == 2 && Checksum(tag);

    /// <summary>The tag checksum: the sum of bytes 0-3 and 5-15 modulo 256 in byte 4.</summary>
    private static bool Checksum(ReadOnlySpan<byte> tag)
    {
        int sum = 0;
        for (int i = 0; i < 16; i++) if (i != 4) sum += tag[i];
        return (byte)sum == tag[4];
    }

    /// <summary>The UDF tree, or null when the image has no anchor or no type 1 partition (ISO 9660 is read instead).</summary>
    public static ContainerContents? Open(FsSource src, bool allFiles, AnalysisLimits limits, CancellationToken ct)
    {
        if (src.Length < 257L * Sector || !IsAnchor(src.ReadUpTo(256L * Sector, 16))) return null;
        var avdp = src.Read(256L * Sector, Sector);
        uint vdsLength = BinaryPrimitives.ReadUInt32LittleEndian(avdp.AsSpan(16)), vdsAt = BinaryPrimitives.ReadUInt32LittleEndian(avdp.AsSpan(20));
        long partitionStart = -1;
        int blockSize = Sector;
        (uint Lbn, ushort Part)? fileSet = null;
        string? label = null;
        bool otherMaps = false;
        for (uint s = 0; s < Math.Min(vdsLength / Sector, 64u); s++)
        {
            var d = src.ReadUpTo((long)(vdsAt + s) * Sector, Sector);
            if (d.Length < 512 || !Checksum(d)) break;
            int tag = BinaryPrimitives.ReadUInt16LittleEndian(d);
            if (tag == 5 && partitionStart < 0) partitionStart = BinaryPrimitives.ReadUInt32LittleEndian(d.AsSpan(188));
            else if (tag == 6)
            {
                blockSize = BinaryPrimitives.ReadUInt32LittleEndian(d.AsSpan(212)) is var bs and (512 or 1024 or 2048 or 4096) ? (int)bs : Sector;
                fileSet = (BinaryPrimitives.ReadUInt32LittleEndian(d.AsSpan(252)), BinaryPrimitives.ReadUInt16LittleEndian(d.AsSpan(256)));
                label = Dstring(d.AsSpan(84, 128));
                int maps = (int)BinaryPrimitives.ReadUInt32LittleEndian(d.AsSpan(268));
                otherMaps = maps > 0 && d[440] != 1;
            }
            else if (tag == 8) break;
        }
        if (partitionStart < 0 || fileSet == null) return null;
        // Virtual, sparable or metadata partitions: ISO 9660 covers these images.
        if (otherMaps) return null;
        var v = new Volume(src, partitionStart, blockSize, allFiles, limits, ct);
        v.Tree.Notes.Add($"UDF, volume '{label}'");
        return v.Walk(fileSet.Value.Lbn);
    }

    /// <summary>A dstring / d-characters field: compression id 8 (Latin-1) or 16 (UTF-16 big endian), length in the last byte.</summary>
    public static string Dstring(ReadOnlySpan<byte> field)
    {
        if (field.Length < 2) return "";
        int used = field[^1];
        if (used == 0 || used > field.Length - 1) used = field.Length - 1;
        return Characters(field[..used]);
    }

    private static string Characters(ReadOnlySpan<byte> s)
    {
        if (s.Length == 0) return "";
        return s[0] switch
        {
            16 => Encoding.BigEndianUnicode.GetString(s[1..][..((s.Length - 1) & ~1)]).TrimEnd('\0'),
            _ => Encoding.Latin1.GetString(s[1..]).TrimEnd('\0'),
        };
    }

    private sealed class Volume(FsSource src, long partitionStart, int blockSize, bool allFiles, AnalysisLimits limits, CancellationToken ct)
    {
        public FsTree Tree { get; } = new("UDF", allFiles, limits, ct);
        private readonly HashSet<uint> _seen = [];

        private long Offset(uint lbn) => (partitionStart + lbn) * blockSize;

        public ContainerContents Walk(uint fileSetLbn)
        {
            var fsd = src.Read(Offset(fileSetLbn), blockSize);
            if (BinaryPrimitives.ReadUInt16LittleEndian(fsd) != 256) throw src.Malformed("no file set descriptor where the volume names it");
            uint root = BinaryPrimitives.ReadUInt32LittleEndian(fsd.AsSpan(404));
            Directory(root, "", 0);
            return Tree.Done();
        }

        /// <summary>A file entry: whether it is a directory, its size, and its data extents as (byte offset, length) or its embedded bytes.</summary>
        private (bool Dir, long Size, List<(long At, long Length)> Extents, byte[]? Inline) Entry(uint lbn)
        {
            var fe = src.Read(Offset(lbn), blockSize);
            int tag = BinaryPrimitives.ReadUInt16LittleEndian(fe);
            if (tag is not (261 or 266)) throw src.Malformed($"no file entry at block {lbn}");
            bool dir = fe[16 + 11] == 4;
            int adType = BinaryPrimitives.ReadUInt16LittleEndian(fe.AsSpan(16 + 18)) & 7;
            long size = BinaryPrimitives.ReadInt64LittleEndian(fe.AsSpan(56));
            int ea = (int)BinaryPrimitives.ReadUInt32LittleEndian(fe.AsSpan(tag == 261 ? 168 : 208));
            int ad = (int)BinaryPrimitives.ReadUInt32LittleEndian(fe.AsSpan(tag == 261 ? 172 : 212));
            int at = (tag == 261 ? 176 : 216) + ea;
            if (ea < 0 || ad < 0 || at + ad > fe.Length) throw src.Malformed($"file entry at block {lbn} has descriptors past its block");
            var extents = new List<(long, long)>();
            if (adType == 3) return (dir, size, extents, fe.AsSpan(at, (int)Math.Min(ad, Math.Max(0, size))).ToArray());
            int step = adType == 0 ? 8 : 16;
            for (int p = at; p + step <= at + ad; p += step)
            {
                uint raw = BinaryPrimitives.ReadUInt32LittleEndian(fe.AsSpan(p));
                long length = raw & 0x3FFFFFFF;
                int kind = (int)(raw >> 30);
                if (length == 0) break;
                uint where = BinaryPrimitives.ReadUInt32LittleEndian(fe.AsSpan(p + 4));
                if (kind == 3) { Tree.Notes.Add($"block {lbn}: continued allocation descriptors are not followed"); break; }
                extents.Add((kind == 0 ? Offset(where) : -1, length));
            }
            return (dir, size, extents, null);
        }

        private byte[] Data((bool Dir, long Size, List<(long At, long Length)> Extents, byte[]? Inline) e, long max)
        {
            if (e.Inline != null) return e.Inline.Length > max ? e.Inline[..(int)max] : e.Inline;
            long want = Math.Min(e.Size, max);
            var o = new byte[want];
            long done = 0;
            foreach (var (at, length) in e.Extents)
            {
                if (done >= want) break;
                int n = (int)Math.Min(length, want - done);
                // An allocated but unrecorded extent reads as zeros.
                if (at >= 0) src.Read(at, n).CopyTo(o, done);
                done += n;
            }
            return o;
        }

        private void Directory(uint lbn, string prefix, int depth)
        {
            if (depth >= FsTree.MaxDepth || !_seen.Add(lbn)) return;
            var e = Entry(lbn);
            if (e.Size > 64L << 20) { Tree.Notes.Add($"{prefix}: a {e.Size:N0}-byte directory; not read"); return; }
            var d = Data(e, e.Size);
            int pos = 0;
            while (pos + 38 <= d.Length)
            {
                ct.ThrowIfCancellationRequested();
                if (BinaryPrimitives.ReadUInt16LittleEndian(d.AsSpan(pos)) != 257) break;
                int chars = d[pos + 18], nameLen = d[pos + 19];
                uint child = BinaryPrimitives.ReadUInt32LittleEndian(d.AsSpan(pos + 24));
                int iu = BinaryPrimitives.ReadUInt16LittleEndian(d.AsSpan(pos + 36));
                int total = (38 + iu + nameLen + 3) & ~3;
                if (pos + 38 + iu + nameLen > d.Length) break;
                var name = Characters(d.AsSpan(pos + 38 + iu, nameLen));
                pos += total;
                // Parent and deleted entries.
                if ((chars & 0x0C) != 0 || !FsTree.UsableName(name)) continue;
                var path = prefix.Length == 0 ? name : prefix + "/" + name;
                try
                {
                    if ((chars & 0x02) != 0) Directory(child, path, depth + 1);
                    else
                    {
                        var fe = Entry(child);
                        Tree.File(path, fe.Size, n => Data(fe, n));
                    }
                }
                catch (Exception ex) when (FsTree.Damaged(ex)) { Tree.Unreadable(path, ex); }
            }
        }
    }
}
