using System.Buffers.Binary;
using System.Text;

namespace Corvus.Core.Firmware;

/// <summary>FAT12, FAT16 and FAT32 volumes with long file names, read in ranges; deleted entries are skipped.</summary>
internal sealed class FatReader : IContainerReader
{
    public string Kind => "fat";

    /// <summary>A boot sector with a consistent BIOS parameter block.</summary>
    public static bool Looks(ReadOnlySpan<byte> b)
    {
        if (b.Length < 512 || b[510] != 0x55 || b[511] != 0xAA || b[0] is not (0xEB or 0xE9)) return false;
        int bytesPerSector = BinaryPrimitives.ReadUInt16LittleEndian(b[11..]);
        int perCluster = b[13];
        return bytesPerSector is 512 or 1024 or 2048 or 4096 && perCluster > 0 && (perCluster & (perCluster - 1)) == 0
               && BinaryPrimitives.ReadUInt16LittleEndian(b[14..]) > 0 && b[16] is 1 or 2
               && (b[54..].StartsWith("FAT"u8) || b[82..].StartsWith("FAT32"u8));
    }

    public bool Accepts(ReadOnlySpan<byte> data, string name) => Looks(data);

    public ContainerContents Open(byte[] data, string name, bool allFiles, AnalysisLimits limits, CancellationToken ct) =>
        Read(FsSource.Of(data, name), allFiles, limits, ct);

    public ContainerContents? Open(Stream stream, string name, bool allFiles, AnalysisLimits limits, CancellationToken ct) =>
        Read(new FsSource(stream, 0, stream.Length, name), allFiles, limits, ct);

    private static ContainerContents Read(FsSource src, bool allFiles, AnalysisLimits limits, CancellationToken ct) =>
        FsTree.Guard(src, () => new Volume(src, allFiles, limits, ct).Walk());

    private sealed class Volume
    {
        private readonly FsSource _src;
        private readonly FsTree _tree;
        private readonly int _bits, _clusterSize;
        private readonly long _fatAt, _rootAt, _dataAt;
        private readonly int _rootEntries;
        private readonly uint _rootCluster, _clusters;
        private readonly byte[] _fat;
        private readonly HashSet<uint> _dirs = [];

        public Volume(FsSource src, bool allFiles, AnalysisLimits limits, CancellationToken ct)
        {
            _src = src;
            var bs = src.Read(0, 512);
            int bytesPerSector = BinaryPrimitives.ReadUInt16LittleEndian(bs.AsSpan(11));
            int reserved = BinaryPrimitives.ReadUInt16LittleEndian(bs.AsSpan(14));
            int fats = bs[16];
            _rootEntries = BinaryPrimitives.ReadUInt16LittleEndian(bs.AsSpan(17));
            long sectors = BinaryPrimitives.ReadUInt16LittleEndian(bs.AsSpan(19)) is var s16 and not 0 ? s16 : BinaryPrimitives.ReadUInt32LittleEndian(bs.AsSpan(32));
            long fatSectors = BinaryPrimitives.ReadUInt16LittleEndian(bs.AsSpan(22)) is var f16 and not 0 ? f16 : BinaryPrimitives.ReadUInt32LittleEndian(bs.AsSpan(36));
            _clusterSize = bytesPerSector * bs[13];
            _fatAt = (long)reserved * bytesPerSector;
            _rootAt = _fatAt + fats * fatSectors * bytesPerSector;
            long rootBytes = (_rootEntries * 32L + bytesPerSector - 1) / bytesPerSector * bytesPerSector;
            _dataAt = _rootAt + rootBytes;
            long dataSectors = sectors - _dataAt / bytesPerSector;
            if (fatSectors <= 0 || dataSectors <= 0) throw src.Malformed("the FAT parameter block leaves no data area");
            _clusters = (uint)Math.Min(dataSectors / bs[13], uint.MaxValue - 16);
            // The FAT type follows from the cluster count alone.
            _bits = _clusters < 4085 ? 12 : _clusters < 65525 ? 16 : 32;
            _rootCluster = _bits == 32 ? BinaryPrimitives.ReadUInt32LittleEndian(bs.AsSpan(44)) : 0;
            long fatBytes = Math.Min(fatSectors * bytesPerSector, (_clusters + 2L) * _bits / 8 + 2);
            if (fatBytes > 512L << 20) throw src.Malformed("the allocation table is larger than 512 MiB");
            _fat = src.Read(_fatAt, (int)fatBytes);
            string label = Encoding.ASCII.GetString(bs, _bits == 32 ? 71 : 43, 11).TrimEnd();
            _tree = new FsTree($"FAT{_bits}", allFiles, limits, ct);
            _tree.Notes.Add($"FAT{_bits}, {_clusterSize:N0}-byte clusters, {_clusters:N0} clusters, volume '{label}'");
        }

        private uint Next(uint cluster)
        {
            switch (_bits)
            {
                case 12:
                    int at = (int)(cluster * 3 / 2);
                    if (at + 1 >= _fat.Length) return 0xFFF;
                    int v = _fat[at] | _fat[at + 1] << 8;
                    v = (cluster & 1) != 0 ? v >> 4 : v & 0xFFF;
                    return v >= 0xFF7 ? 0xFFFFFFFF : (uint)v;
                case 16:
                    if (cluster * 2 + 1 >= _fat.Length) return 0xFFFFFFFF;
                    uint w = BinaryPrimitives.ReadUInt16LittleEndian(_fat.AsSpan((int)cluster * 2));
                    return w >= 0xFFF7 ? 0xFFFFFFFF : w;
                default:
                    if (cluster * 4L + 3 >= _fat.Length) return 0xFFFFFFFF;
                    uint d = BinaryPrimitives.ReadUInt32LittleEndian(_fat.AsSpan((int)cluster * 4)) & 0x0FFFFFFF;
                    return d >= 0x0FFFFFF7 ? 0xFFFFFFFF : d;
            }
        }

        /// <summary>A cluster chain's bytes, at most <paramref name="max"/> (and exactly that many when <paramref name="exact"/>); a loop or a bad link ends it.</summary>
        private byte[] Chain(uint first, long max, bool exact)
        {
            var o = new MemoryStream();
            var seen = new HashSet<uint>();
            for (uint c = first; c >= 2 && c < _clusters + 2 && o.Length < max && seen.Add(c); c = Next(c))
            {
                _tree.Token.ThrowIfCancellationRequested();
                o.Write(_src.Read(_dataAt + (c - 2L) * _clusterSize, _clusterSize));
            }
            if (exact && o.Length < max) throw new InvalidDataException($"the cluster chain from {first} holds {o.Length:N0} of {max:N0} bytes");
            var b = o.ToArray();
            return b.Length > max ? b[..(int)max] : b;
        }

        public ContainerContents Walk()
        {
            var root = _bits == 32 ? Chain(_rootCluster, 64L << 20, exact: false) : _src.Read(_rootAt, _rootEntries * 32);
            Directory("", root, 0);
            return _tree.Done();
        }

        private void Directory(string path, byte[] listing, int depth)
        {
            if (depth > FsTree.MaxDepth) return;
            var longName = new List<(int Seq, string Part)>();
            for (int p = 0; p + 32 <= listing.Length; p += 32)
            {
                byte first = listing[p];
                if (first == 0) break;
                byte attr = listing[p + 11];
                if (first == 0xE5) { longName.Clear(); continue; }
                if (attr == 0x0F)
                {
                    var part = new StringBuilder();
                    foreach (var (at, n) in new[] { (1, 5), (14, 6), (28, 2) })
                        for (int i = 0; i < n; i++)
                        {
                            char ch = (char)BinaryPrimitives.ReadUInt16LittleEndian(listing.AsSpan(p + at + i * 2));
                            if (ch is '\0' or '￿') goto Done;
                            part.Append(ch);
                        }
                    Done:
                    longName.Add((first & 0x1F, part.ToString()));
                    continue;
                }
                if ((attr & 0x08) != 0) { longName.Clear(); continue; } // volume label
                string name = longName.Count > 0 ? string.Concat(longName.OrderBy(l => l.Seq).Select(l => l.Part)) : ShortName(listing, p);
                longName.Clear();
                if (!FsTree.UsableName(name)) continue;
                uint cluster = BinaryPrimitives.ReadUInt16LittleEndian(listing.AsSpan(p + 26)) | (uint)(_bits == 32 ? BinaryPrimitives.ReadUInt16LittleEndian(listing.AsSpan(p + 20)) << 16 : 0);
                long size = BinaryPrimitives.ReadUInt32LittleEndian(listing.AsSpan(p + 28));
                var full = path.Length == 0 ? name : path + "/" + name;
                try
                {
                    if ((attr & 0x10) != 0) { if (_dirs.Add(cluster)) Directory(full, Chain(cluster, 16L << 20, exact: false), depth + 1); }
                    else _tree.File(full, size, n => n == 0 ? [] : Chain(cluster, n, exact: true));
                }
                catch (Exception ex) when (FsTree.Damaged(ex)) { _tree.Unreadable(full, ex); }
            }
        }

        private static string ShortName(byte[] d, int p)
        {
            var b = d.AsSpan(p, 11).ToArray();
            if (b[0] == 0x05) b[0] = 0xE5;
            string name = Encoding.Latin1.GetString(b, 0, 8).TrimEnd(), ext = Encoding.Latin1.GetString(b, 8, 3).TrimEnd();
            // The case flags of byte 12 (lower-case base and extension).
            if ((d[p + 12] & 0x08) != 0) name = name.ToLowerInvariant();
            if ((d[p + 12] & 0x10) != 0) ext = ext.ToLowerInvariant();
            return ext.Length > 0 ? name + "." + ext : name;
        }
    }
}
