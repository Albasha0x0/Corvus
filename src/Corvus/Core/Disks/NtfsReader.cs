using System.Buffers.Binary;
using System.Text;
using Corvus.Core.Firmware;

namespace Corvus.Core.Disks;

/// <summary>
/// NTFS volumes: the MFT located from the boot sector and read along its own data runs; every in-use file record with its
/// update sequence fixups applied, attributes from extension records joined to their base record; names from $FILE_NAME
/// (Win32 over DOS), paths from parent references; file data resident or along data runs (sparse runs as zeros, LZNT1
/// compressed runs decompressed); named data streams (Zone.Identifier among them) listed as file:stream. System files are skipped.
/// </summary>
internal sealed class NtfsReader : IContainerReader
{
    public string Kind => "ntfs";

    public static bool Looks(ReadOnlySpan<byte> b) => b.Length >= 512 && b[3..].StartsWith("NTFS    "u8) && b[510] == 0x55 && b[511] == 0xAA;

    public bool Accepts(ReadOnlySpan<byte> data, string name) => Looks(data);

    public ContainerContents Open(byte[] data, string name, bool allFiles, AnalysisLimits limits, CancellationToken ct) =>
        Read(FsSource.Of(data, name), allFiles, limits, ct);

    public ContainerContents? Open(Stream stream, string name, bool allFiles, AnalysisLimits limits, CancellationToken ct) =>
        Read(new FsSource(stream, 0, stream.Length, name), allFiles, limits, ct);

    private static ContainerContents Read(FsSource src, bool allFiles, AnalysisLimits limits, CancellationToken ct) =>
        FsTree.Guard(src, () => new Volume(src, allFiles, limits, ct).Walk());

    private sealed record Attribute(int Type, string Name, bool Resident, byte[]? Value, List<(long Lcn, long Length)>? Runs, long Size, bool Compressed, bool Encrypted, int CompressionUnit, long StartVcn);

    private sealed class Record
    {
        public bool Directory;
        public long Parent = -1;
        public string? Name;
        public int NameSpace = -1;
        public List<Attribute> Attributes { get; } = [];
    }

    private sealed class Volume
    {
        private readonly FsSource _src;
        private readonly FsTree _tree;
        private readonly int _clusterSize, _recordSize, _sectorSize;
        private readonly List<(long Lcn, long Length)> _mftRuns;
        private readonly long _mftSize;
        private const int MaxRecords = 4_000_000;

        public Volume(FsSource src, bool allFiles, AnalysisLimits limits, CancellationToken ct)
        {
            _src = src;
            var bs = src.Read(0, 512);
            _sectorSize = BinaryPrimitives.ReadUInt16LittleEndian(bs.AsSpan(11));
            int spc = bs[13];
            if (spc > 0x80) spc = 1 << (256 - spc);
            if (_sectorSize is not (512 or 1024 or 2048 or 4096) || spc is < 1 or > 4096) throw src.Malformed("the NTFS boot sector gives no usable sector or cluster size");
            _clusterSize = _sectorSize * spc;
            sbyte perRecord = (sbyte)bs[64];
            _recordSize = perRecord < 0 ? 1 << -perRecord : perRecord * _clusterSize;
            if (_recordSize is < 256 or > 65536) throw src.Malformed($"NTFS file record size {_recordSize} is out of range");
            long mftCluster = BinaryPrimitives.ReadInt64LittleEndian(bs.AsSpan(48));
            _tree = new FsTree("NTFS", allFiles, limits, ct);
            // record 0 is $MFT itself: its data runs give where the rest of the table lies
            var first = Fixup(src.Read(mftCluster * _clusterSize, _recordSize), 0) ?? throw src.Malformed("the first MFT record is damaged");
            var data = Attributes(first).FirstOrDefault(a => a.Type == 0x80 && a.Name.Length == 0 && !a.Resident) ?? throw src.Malformed("$MFT has no data runs");
            _mftRuns = data.Runs!;
            _mftSize = data.Size;
            _tree.Notes.Add($"NTFS, {_clusterSize:N0}-byte clusters, {_mftSize / _recordSize:N0} file records");
        }

        private byte[]? Fixup(byte[] r, long number)
        {
            if (!r.AsSpan(0, 4).SequenceEqual("FILE"u8)) return null;
            int usaAt = BinaryPrimitives.ReadUInt16LittleEndian(r.AsSpan(4)), usaCount = BinaryPrimitives.ReadUInt16LittleEndian(r.AsSpan(6));
            if (usaCount < 1 || usaAt + usaCount * 2 > r.Length) return null;
            for (int i = 1; i < usaCount; i++)
            {
                int end = i * _sectorSize - 2;
                if (end + 2 > r.Length) break;
                if (r[end] != r[usaAt] || r[end + 1] != r[usaAt + 1]) return null; // torn write
                r[end] = r[usaAt + i * 2];
                r[end + 1] = r[usaAt + i * 2 + 1];
            }
            return r;
        }

        private List<Attribute> Attributes(byte[] r)
        {
            var list = new List<Attribute>();
            int pos = BinaryPrimitives.ReadUInt16LittleEndian(r.AsSpan(20));
            while (pos + 16 <= r.Length)
            {
                int type = (int)BinaryPrimitives.ReadUInt32LittleEndian(r.AsSpan(pos));
                if (type == -1) break;
                int len = (int)BinaryPrimitives.ReadUInt32LittleEndian(r.AsSpan(pos + 4));
                if (len < 16 || pos + len > r.Length) break;
                var a = r.AsSpan(pos, len);
                bool nonResident = a[8] != 0;
                int nameLen = a[9], nameAt = BinaryPrimitives.ReadUInt16LittleEndian(a[10..]);
                int flags = BinaryPrimitives.ReadUInt16LittleEndian(a[12..]);
                string name = nameLen > 0 && nameAt + nameLen * 2 <= len ? Encoding.Unicode.GetString(a.Slice(nameAt, nameLen * 2)) : "";
                if (!nonResident)
                {
                    int valueLen = (int)BinaryPrimitives.ReadUInt32LittleEndian(a[16..]), valueAt = BinaryPrimitives.ReadUInt16LittleEndian(a[20..]);
                    if (valueAt + valueLen <= len) list.Add(new Attribute(type, name, true, a.Slice(valueAt, valueLen).ToArray(), null, valueLen, false, false, 0, 0));
                }
                else if (len >= 64)
                {
                    long startVcn = BinaryPrimitives.ReadInt64LittleEndian(a[16..]);
                    int runsAt = BinaryPrimitives.ReadUInt16LittleEndian(a[32..]);
                    int unit = BinaryPrimitives.ReadUInt16LittleEndian(a[34..]);
                    long size = BinaryPrimitives.ReadInt64LittleEndian(a[48..]);
                    list.Add(new Attribute(type, name, false, null, Runs(a[Math.Min(runsAt, len)..]), size, (flags & 1) != 0, (flags & 0x4000) != 0, unit, startVcn));
                }
                pos += len;
            }
            return list;
        }

        /// <summary>Data runs: (cluster, count) pairs, cluster -1 for a sparse run.</summary>
        private static List<(long, long)> Runs(ReadOnlySpan<byte> r)
        {
            var runs = new List<(long, long)>();
            long lcn = 0;
            int pos = 0;
            while (pos < r.Length && r[pos] != 0 && runs.Count < 1 << 20)
            {
                int lenSize = r[pos] & 0x0F, offSize = r[pos] >> 4;
                pos++;
                if (lenSize is 0 or > 8 || offSize > 8 || pos + lenSize + offSize > r.Length) break;
                long length = 0;
                for (int i = 0; i < lenSize; i++) length |= (long)r[pos + i] << (8 * i);
                pos += lenSize;
                if (offSize == 0) { runs.Add((-1, length)); continue; }
                long delta = 0;
                for (int i = 0; i < offSize; i++) delta |= (long)r[pos + i] << (8 * i);
                if ((r[pos + offSize - 1] & 0x80) != 0 && offSize < 8) delta -= 1L << (8 * offSize);
                pos += offSize;
                lcn += delta;
                runs.Add((lcn, length));
            }
            return runs;
        }

        /// <summary>The first <paramref name="n"/> bytes along the runs; sparse runs and clusters past the volume read as zeros.</summary>
        private byte[] ReadRuns(List<(long Lcn, long Length)> runs, long n)
        {
            var o = new byte[n];
            long done = 0;
            foreach (var (lcn, length) in runs)
            {
                if (done >= n) break;
                long bytes = Math.Min(length * _clusterSize, n - done);
                if (lcn >= 0 && lcn * _clusterSize < _src.Length)
                {
                    var b = _src.ReadUpTo(lcn * _clusterSize, (int)bytes);
                    b.CopyTo(o, done);
                }
                done += bytes;
            }
            return o;
        }

        private byte[] Data(Attribute a, long n)
        {
            n = Math.Min(n, a.Size);
            if (a.Resident) return a.Value!.Length > n ? a.Value[..(int)n] : a.Value;
            if (!a.Compressed) return ReadRuns(a.Runs!, n);
            // compressed: units of 16 clusters, each LZNT1 data or stored as is when it fills the unit
            int unitClusters = 1 << a.CompressionUnit;
            long unitBytes = (long)unitClusters * _clusterSize;
            var o = new MemoryStream();
            var clusters = new List<long>();
            foreach (var (lcn, length) in a.Runs!) for (long k = 0; k < length && clusters.Count < 1 << 24; k++) clusters.Add(lcn < 0 ? -1 : lcn + k);
            for (int u = 0; u * unitClusters < clusters.Count && o.Length < n; u++)
            {
                var unit = clusters.Skip(u * unitClusters).Take(unitClusters).ToList();
                int stored = unit.Count(c => c >= 0);
                if (stored == 0) { o.Write(new byte[unitBytes]); continue; }
                var raw = new MemoryStream();
                foreach (var c in unit.Where(c => c >= 0)) raw.Write(_src.ReadUpTo(c * _clusterSize, _clusterSize));
                if (stored == unitClusters) o.Write(raw.ToArray());
                else o.Write(Lznt1(raw.ToArray(), unitBytes));
            }
            var all = o.ToArray();
            return all.Length > n ? all[..(int)n] : all;
        }

        public ContainerContents Walk()
        {
            long count = Math.Min(_mftSize / _recordSize, MaxRecords);
            var records = new Dictionary<long, Record>();
            var mft = new MftReader(this);
            for (long i = 0; i < count; i++)
            {
                if ((i & 0xFFF) == 0) _tree.Token.ThrowIfCancellationRequested();
                var raw = mft.Record(i);
                if (raw == null || Fixup(raw, i) is not { } r) continue;
                int flags = BinaryPrimitives.ReadUInt16LittleEndian(r.AsSpan(22));
                if ((flags & 1) == 0) continue; // not in use
                long baseRef = BinaryPrimitives.ReadInt64LittleEndian(r.AsSpan(32)) & 0xFFFFFFFFFFFF;
                long owner = baseRef != 0 ? baseRef : i;
                if (!records.TryGetValue(owner, out var rec)) records[owner] = rec = new Record();
                if (baseRef == 0) rec.Directory = (flags & 2) != 0;
                foreach (var a in Attributes(r))
                {
                    rec.Attributes.Add(a);
                    if (a.Type == 0x30 && a.Resident && a.Value!.Length >= 66)
                    {
                        int ns = a.Value[65], len = a.Value[64];
                        if (66 + len * 2 > a.Value.Length) continue;
                        // Win32 (1), Win32 and DOS (3) and POSIX (0) names over DOS (2) ones
                        int rank = ns == 2 ? 0 : 1;
                        if (rec.Name == null || rank > (rec.NameSpace == 2 ? 0 : 1))
                        {
                            rec.Name = Encoding.Unicode.GetString(a.Value, 66, len * 2);
                            rec.NameSpace = ns;
                            rec.Parent = BinaryPrimitives.ReadInt64LittleEndian(a.Value) & 0xFFFFFFFFFFFF;
                        }
                    }
                }
            }
            string? Path(long number)
            {
                var parts = new List<string>();
                for (int depth = 0; number != 5 && depth < FsTree.MaxDepth; depth++)
                {
                    if (!records.TryGetValue(number, out var r) || r.Name == null || !FsTree.UsableName(r.Name)) return null;
                    parts.Add(r.Name);
                    number = r.Parent;
                }
                if (number != 5) return null;
                parts.Reverse();
                return string.Join("/", parts);
            }
            int orphans = 0;
            foreach (var (number, rec) in records.OrderBy(r => r.Key))
            {
                if (number < 24 || rec.Directory || rec.Name == null) continue; // system files and directories
                var path = Path(number);
                if (path == null) { orphans++; continue; }
                if (path.StartsWith('$')) continue;
                var streams = rec.Attributes.Where(a => a.Type == 0x80).GroupBy(a => a.Name).ToList();
                if (streams.Count == 0) { _tree.File(path, 0, _ => []); continue; }
                foreach (var g in streams)
                {
                    // an attribute list splits large data over records: the pieces ordered by their first cluster
                    var pieces = g.OrderBy(a => a.StartVcn).ToList();
                    var a0 = pieces[0];
                    var a = pieces.Count == 1 ? a0 : a0 with { Runs = [.. pieces.Where(p => !p.Resident).SelectMany(p => p.Runs!)] };
                    var streamPath = g.Key.Length == 0 ? path : $"{path}:{g.Key}";
                    try
                    {
                        _tree.File(streamPath, a.Size, n => a.Encrypted ? throw new InvalidDataException("encrypted (EFS)") : Data(a, n),
                            a.Encrypted ? "encrypted" : a.Compressed ? "compressed" : g.Key.Length > 0 ? "alternate data stream" : null);
                    }
                    catch (Exception ex) when (FsTree.Damaged(ex)) { _tree.Unreadable(streamPath, ex); }
                }
            }
            if (orphans > 0) _tree.Notes.Add($"{orphans} file record(s) whose folder chain does not reach the root (deleted folders): not listed");
            // $Volume (record 3) holds the volume name
            if (records.TryGetValue(3, out var volume) && volume.Attributes.FirstOrDefault(a => a.Type == 0x60 && a.Resident) is { Value.Length: > 0 } label)
                _tree.Notes[0] += $", volume '{Encoding.Unicode.GetString(label.Value!)}'";
            return _tree.Done();
        }

        /// <summary>File records read along the $MFT runs.</summary>
        private sealed class MftReader(Volume v)
        {
            public byte[]? Record(long i)
            {
                long at = i * v._recordSize;
                foreach (var (lcn, length) in v._mftRuns)
                {
                    long bytes = length * v._clusterSize;
                    if (at < bytes)
                    {
                        if (lcn < 0) return null;
                        long offset = lcn * v._clusterSize + at;
                        return offset + v._recordSize <= v._src.Length ? v._src.Read(offset, v._recordSize) : null;
                    }
                    at -= bytes;
                }
                return null;
            }
        }
    }

    /// <summary>LZNT1 (MS-XCA 2.5): 4 KiB chunks, each stored or as flag groups of literals and copy tokens whose split follows the position in the chunk.</summary>
    public static byte[] Lznt1(byte[] src, long max)
    {
        var o = new List<byte>();
        int pos = 0;
        while (pos + 2 <= src.Length && o.Count < max)
        {
            int header = BinaryPrimitives.ReadUInt16LittleEndian(src.AsSpan(pos));
            if (header == 0) break;
            int size = (header & 0x0FFF) + 1;
            pos += 2;
            int end = Math.Min(pos + size, src.Length);
            int chunkStart = o.Count;
            if ((header & 0x8000) == 0)
            {
                for (int i = pos; i < end; i++) o.Add(src[i]);
                pos = end;
                continue;
            }
            while (pos < end)
            {
                byte flags = src[pos++];
                for (int bit = 0; bit < 8 && pos < end; bit++)
                {
                    if ((flags & (1 << bit)) == 0) { o.Add(src[pos++]); continue; }
                    if (pos + 2 > end) { pos = end; break; }
                    int token = BinaryPrimitives.ReadUInt16LittleEndian(src.AsSpan(pos));
                    pos += 2;
                    int written = o.Count - chunkStart;
                    int lengthBits = 12;
                    for (int w = written - 1; w >= 0x10; w >>= 1) lengthBits--;
                    int length = (token & ((1 << lengthBits) - 1)) + 3;
                    int offset = (token >> lengthBits) + 1;
                    int from = o.Count - offset;
                    if (from < chunkStart) return [.. o];
                    for (int k = 0; k < length; k++) o.Add(o[from + k]);
                }
            }
        }
        return [.. o];
    }
}
