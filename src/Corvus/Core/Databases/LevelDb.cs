using System.Buffers.Binary;
using System.Numerics;
using System.Text;

namespace Corvus.Core.Databases;

/// <summary>
/// LevelDB databases (a folder of CURRENT, MANIFEST, table and log files): the MANIFEST's version edits for the live files
/// per level, every record of the table files (.ldb, .sst) and write-ahead logs (.log), and the live state merged from
/// them by sequence number. Records the live state no longer shows (deleted keys, older versions, files no longer
/// listed) are kept and labelled, not dropped.
/// </summary>
internal static class LevelDb
{
    private const ulong TableMagic = 0xdb4775248b80fb57;
    private const int LogBlock = 32768;

    /// <summary>One record: a put (Deleted false) or a deletion of <see cref="Key"/> at <see cref="Sequence"/>, from <see cref="File"/>.</summary>
    public sealed record Record(byte[] Key, ulong Sequence, bool Deleted, byte[] Value, string File);

    /// <summary>A table or log file: its role in the database ("table, level 2", "log, live", "table, not in the MANIFEST") and record count.</summary>
    public sealed record FileFacts(string Name, string Role, long Size, int Records, bool Live);

    /// <summary>
    /// The database as read: comparator and last sequence from the MANIFEST (null when none was read), the files, every
    /// record, and for each key its newest record in the live files (<see cref="Live"/>, deletions included).
    /// </summary>
    public sealed record Database(string? Comparator, ulong? LastSequence, IReadOnlyList<FileFacts> Files, IReadOnlyList<Record> Records,
        IReadOnlyList<Record> Live, IReadOnlyList<string> Notes);

    /// <summary>Whether <paramref name="path"/> is a file of a LevelDB folder: CURRENT naming a MANIFEST, a MANIFEST, or a table or log beside them.</summary>
    public static bool IsDatabaseFile(string path, ReadOnlySpan<byte> head, Func<byte[]?> tail)
    {
        string name = Path.GetFileName(path);
        if (name == "CURRENT") return head.StartsWith("MANIFEST-"u8);
        if (name.StartsWith("MANIFEST-", StringComparison.Ordinal)) return true;
        string ext = Path.GetExtension(name);
        if (ext is ".ldb" or ".sst") return tail() is { Length: >= 48 } t && BinaryPrimitives.ReadUInt64LittleEndian(t.AsSpan(t.Length - 8)) == TableMagic;
        return ext == ".log" && Path.GetDirectoryName(path) is { } dir && File.Exists(Path.Combine(dir, "CURRENT"))
            && File.ReadAllBytes(Path.Combine(dir, "CURRENT")).AsSpan().StartsWith("MANIFEST-"u8);
    }

    /// <summary>
    /// Reads the database in <paramref name="folder"/>; without a CURRENT or MANIFEST only <paramref name="single"/> is read
    /// and the live state is that file's alone (noted). Reads at most <paramref name="maxBytes"/> of files, noting the rest.
    /// </summary>
    public static Database Read(string folder, string? single, long maxBytes, CancellationToken ct)
    {
        var notes = new List<string>();
        var files = new List<FileFacts>();
        var records = new List<Record>();
        var live = new List<Record>();
        string? manifestName = null;
        if (File.Exists(Path.Combine(folder, "CURRENT")))
            manifestName = Encoding.ASCII.GetString(File.ReadAllBytes(Path.Combine(folder, "CURRENT"))).Trim();
        else if (Directory.EnumerateFiles(folder, "MANIFEST-*").Select(Path.GetFileName).Order(StringComparer.Ordinal).LastOrDefault() is { } latest)
        {
            manifestName = latest;
            notes.Add($"no CURRENT file: read {latest}, the highest-numbered MANIFEST");
        }
        Manifest? manifest = null;
        if (manifestName != null && File.Exists(Path.Combine(folder, manifestName)))
        {
            manifest = ReadManifest(File.ReadAllBytes(Path.Combine(folder, manifestName)), notes);
            files.Add(new FileFacts(manifestName, "MANIFEST", new FileInfo(Path.Combine(folder, manifestName)).Length, manifest.Edits, true));
        }
        else if (manifestName != null) notes.Add($"CURRENT names {manifestName}, which is not in the folder");

        IEnumerable<string> candidates = manifest == null && single != null
            ? [single]
            : Directory.EnumerateFiles(folder).Where(f => Path.GetExtension(f) is ".ldb" or ".sst" or ".log").Order(StringComparer.Ordinal);
        if (manifest == null) notes.Add("no MANIFEST was read: the live state is that of the files read, which may be partial");
        long total = 0;
        foreach (var path in candidates)
        {
            ct.ThrowIfCancellationRequested();
            string name = Path.GetFileName(path);
            bool table = Path.GetExtension(name) is ".ldb" or ".sst";
            ulong number = ulong.TryParse(Path.GetFileNameWithoutExtension(name), out var n) ? n : 0;
            long size = new FileInfo(path).Length;
            if (total + size > maxBytes) { notes.Add($"{name}: not read, past the {maxBytes:N0}-byte read limit"); continue; }
            total += size;
            string role;
            bool isLive;
            if (manifest == null) { role = table ? "table" : "log"; isLive = true; }
            else if (table && manifest.Files.TryGetValue(number, out var f)) { role = $"table, level {f.Level}"; isLive = true; }
            else if (table) { role = "table, not in the MANIFEST"; isLive = false; }
            else
            {
                // The logs LevelDB replays on open: the MANIFEST's log number and later (and the previous log, if any).
                isLive = number >= manifest.LogNumber || number == manifest.PrevLogNumber && number != 0;
                role = isLive ? "log, live" : "log, older than the MANIFEST's log number";
            }
            int before = records.Count;
            ReadFile(File.ReadAllBytes(path), name, records, notes, ct);
            files.Add(new FileFacts(name, role, size, records.Count - before, isLive));
        }
        if (manifest != null)
            foreach (var (number, f) in manifest.Files)
                if (!files.Any(x => x.Name == $"{number:000000}.ldb" || x.Name == $"{number:000000}.sst"))
                    notes.Add($"table {number:000000} (level {f.Level}) is listed in the MANIFEST but its file was not read");

        var liveFiles = files.Where(f => f.Live).Select(f => f.Name).ToHashSet(StringComparer.Ordinal);
        live.AddRange(records.Where(r => liveFiles.Contains(r.File))
            .GroupBy(r => Convert.ToHexString(r.Key))
            .Select(g => g.MaxBy(r => r.Sequence)!)
            .OrderBy(r => r.Key, ByteOrder.Instance));
        if (manifest?.Comparator is { } cmp && cmp != "leveldb.BytewiseComparator")
            notes.Add($"comparator {cmp}: keys are listed in byte order, which may differ from the database's own order");
        return new Database(manifest?.Comparator, manifest?.LastSequence, files, records, live, notes);
    }

    /// <summary>
    /// Adds the records of one file, a table (.ldb, .sst) or log by its name, to <paramref name="records"/>; a MANIFEST
    /// adds none. Damage is noted, never thrown.
    /// </summary>
    internal static void ReadFile(byte[] data, string name, List<Record> records, List<string> notes, CancellationToken ct)
    {
        try
        {
            if (name.StartsWith("MANIFEST-", StringComparison.Ordinal)) ReadManifest(data, notes);
            else if (Path.GetExtension(name) is ".ldb" or ".sst") ReadTable(data, name, records, notes, ct);
            else ReadLog(data, name, records, notes);
        }
        catch (InvalidDataException ex) { notes.Add($"{name}: {ex.Message}"); }
    }

    private sealed class ByteOrder : IComparer<byte[]>
    {
        public static readonly ByteOrder Instance = new();
        public int Compare(byte[]? a, byte[]? b) => a.AsSpan().SequenceCompareTo(b);
    }

    private sealed record LiveFile(int Level, long Size);

    private sealed class Manifest
    {
        public string? Comparator;
        public ulong LogNumber, PrevLogNumber;
        public ulong? LastSequence;
        public int Edits;
        public readonly Dictionary<ulong, LiveFile> Files = [];
    }

    // Version edit tags (db/version_edit.cc).
    private static Manifest ReadManifest(byte[] data, List<string> notes)
    {
        var m = new Manifest();
        foreach (var edit in LogRecords(data, "MANIFEST", notes))
        {
            m.Edits++;
            var r = new Reader(edit);
            try
            {
                while (!r.End)
                    switch (r.Varint32())
                    {
                        case 1: m.Comparator = Encoding.UTF8.GetString(r.Prefixed()); break;
                        case 2: m.LogNumber = r.Varint64(); break;
                        case 3: r.Varint64(); break;
                        case 4: m.LastSequence = r.Varint64(); break;
                        case 5: r.Varint32(); r.Prefixed(); break;
                        case 6: r.Varint32(); m.Files.Remove(r.Varint64()); break;
                        case 7:
                            int level = (int)r.Varint32();
                            ulong number = r.Varint64();
                            long size = (long)r.Varint64();
                            r.Prefixed();
                            r.Prefixed();
                            m.Files[number] = new LiveFile(level, size);
                            break;
                        case 9: m.PrevLogNumber = r.Varint64(); break;
                        case var tag: throw new InvalidDataException($"unknown version edit tag {tag}");
                    }
            }
            catch (InvalidDataException ex) { notes.Add($"MANIFEST edit {m.Edits}: {ex.Message}"); }
        }
        return m;
    }

    /// <summary>The logical records of a log-format file (32 KiB blocks of checksummed fragments); damaged fragments are noted and skipped.</summary>
    internal static List<byte[]> LogRecords(byte[] data, string name, List<string> notes)
    {
        var result = new List<byte[]>();
        var pending = new List<byte>();
        bool inRecord = false;
        int bad = 0;
        for (int at = 0; at < data.Length;)
        {
            int left = LogBlock - at % LogBlock;
            // A block's last 6 bytes or fewer are zero padding.
            if (left < 7) { at += left; continue; }
            if (at + 7 > data.Length) break;
            uint crc = BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan(at));
            int length = BinaryPrimitives.ReadUInt16LittleEndian(data.AsSpan(at + 4));
            byte type = data[at + 6];
            if (type == 0 && length == 0) { at += left; continue; }
            if (at + 7 + length > data.Length || 7 + length > left)
            {
                notes.Add($"{name}: ends inside a record at 0x{at:X}");
                break;
            }
            var payload = data.AsSpan(at + 7, length);
            if (Unmask(crc) != Crc32C(data.AsSpan(at + 6, 1 + length)))
            {
                if (++bad <= 5) notes.Add($"{name}: checksum mismatch at 0x{at:X}; fragment skipped");
                pending.Clear();
                inRecord = false;
            }
            else
                switch (type)
                {
                    case 1: result.Add(payload.ToArray()); inRecord = false; pending.Clear(); break;
                    case 2: pending.Clear(); pending.AddRange(payload.ToArray()); inRecord = true; break;
                    case 3 when inRecord: pending.AddRange(payload.ToArray()); break;
                    case 4 when inRecord: pending.AddRange(payload.ToArray()); result.Add([.. pending]); pending.Clear(); inRecord = false; break;
                    default: if (++bad <= 5) notes.Add($"{name}: fragment type {type} out of order at 0x{at:X}"); break;
                }
            at += 7 + length;
        }
        if (inRecord) notes.Add($"{name}: ends inside a record");
        return result;
    }

    private static uint Unmask(uint masked)
    {
        uint rot = masked - 0xa282ead8u;
        return rot >> 17 | rot << 15;
    }

    /// <summary>CRC-32C (Castagnoli) of <paramref name="data"/>.</summary>
    internal static uint Crc32C(ReadOnlySpan<byte> data)
    {
        uint c = 0xFFFFFFFF;
        while (data.Length >= 8) { c = BitOperations.Crc32C(c, BinaryPrimitives.ReadUInt64LittleEndian(data)); data = data[8..]; }
        foreach (var b in data) c = BitOperations.Crc32C(c, b);
        return ~c;
    }

    // A log's records are write batches: sequence, count, then puts (tag 1) and deletions (tag 0).
    private static void ReadLog(byte[] data, string name, List<Record> records, List<string> notes)
    {
        foreach (var batch in LogRecords(data, name, notes))
        {
            if (batch.Length < 12) { notes.Add($"{name}: write batch of {batch.Length} bytes"); continue; }
            ulong seq = BinaryPrimitives.ReadUInt64LittleEndian(batch);
            uint count = BinaryPrimitives.ReadUInt32LittleEndian(batch.AsSpan(8));
            var r = new Reader(batch.AsSpan(12).ToArray());
            uint read = 0;
            try
            {
                for (; read < count && !r.End; read++, seq++)
                {
                    byte tag = r.Byte();
                    var key = r.Prefixed().ToArray();
                    if (tag == 1) records.Add(new Record(key, seq, false, r.Prefixed().ToArray(), name));
                    else if (tag == 0) records.Add(new Record(key, seq, true, [], name));
                    else throw new InvalidDataException($"record tag {tag}");
                }
            }
            catch (InvalidDataException ex) { notes.Add($"{name}: write batch at sequence {seq}: {ex.Message}"); }
            if (read < count) notes.Add($"{name}: write batch holds {read} of its {count} records");
        }
    }

    // A table: footer (metaindex and index block handles, magic), index block of data block handles, data blocks of
    // internal keys (user key, then sequence << 8 | type).
    private static void ReadTable(byte[] data, string name, List<Record> records, List<string> notes, CancellationToken ct)
    {
        if (data.Length < 48 || BinaryPrimitives.ReadUInt64LittleEndian(data.AsSpan(data.Length - 8)) != TableMagic) throw new InvalidDataException("no table footer");
        var footer = new Reader(data[^48..]);
        footer.Varint64();
        footer.Varint64();
        var index = Block(data, (long)footer.Varint64(), (long)footer.Varint64());
        int bad = 0;
        foreach (var (_, handle) in Entries(index))
        {
            ct.ThrowIfCancellationRequested();
            var h = new Reader(handle);
            long offset = (long)h.Varint64(), size = (long)h.Varint64();
            try
            {
                foreach (var (key, value) in Entries(Block(data, offset, size)))
                {
                    if (key.Length < 8) throw new InvalidDataException("internal key under 8 bytes");
                    ulong tag = BinaryPrimitives.ReadUInt64LittleEndian(key.AsSpan(key.Length - 8));
                    records.Add(new Record(key[..^8], tag >> 8, (tag & 0xFF) == 0, (tag & 0xFF) == 0 ? [] : value, name));
                }
            }
            catch (InvalidDataException ex) { if (++bad <= 5) notes.Add($"{name}: data block at 0x{offset:X}: {ex.Message}"); }
        }
    }

    // A block's contents after its 5-byte trailer (compression type, masked CRC-32C) is checked and decompressed.
    private static byte[] Block(byte[] data, long offset, long size)
    {
        if (offset < 0 || size < 0 || offset + size + 5 > data.Length) throw new InvalidDataException($"block at 0x{offset:X} runs past the file");
        var raw = data.AsSpan((int)offset, (int)size);
        uint crc = BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan((int)(offset + size + 1)));
        if (Unmask(crc) != Crc32C(data.AsSpan((int)offset, (int)size + 1))) throw new InvalidDataException($"block at 0x{offset:X}: checksum mismatch");
        return data[offset + size] switch
        {
            0 => raw.ToArray(),
            1 => Snappy.Decompress(raw, 1 << 28),
            2 => Firmware.FsCodec.DecodeStream("zstd", raw, 1 << 28),
            var t => throw new InvalidDataException($"block compression type {t} is not read"),
        };
    }

    // A block's entries: shared key prefix length, unshared length, value length, then the bytes; restart points at the end.
    private static IEnumerable<(byte[] Key, byte[] Value)> Entries(byte[] block)
    {
        if (block.Length < 4) throw new InvalidDataException("block under 4 bytes");
        long restarts = BinaryPrimitives.ReadUInt32LittleEndian(block.AsSpan(block.Length - 4));
        long end = block.Length - 4 - 4 * restarts;
        if (end < 0) throw new InvalidDataException("restart array larger than its block");
        var r = new Reader(block[..(int)end]);
        byte[] last = [];
        var result = new List<(byte[], byte[])>();
        while (!r.End)
        {
            int shared = (int)r.Varint32(), unshared = (int)r.Varint32(), valueLength = (int)r.Varint32();
            if (shared > last.Length) throw new InvalidDataException("key shares more than the previous key");
            var key = new byte[shared + unshared];
            last.AsSpan(0, shared).CopyTo(key);
            r.Bytes(unshared).CopyTo(key.AsSpan(shared));
            result.Add((key, r.Bytes(valueLength).ToArray()));
            last = key;
        }
        return result;
    }

    private sealed class Reader(byte[] data)
    {
        private int _at;
        public bool End => _at >= data.Length;

        public byte Byte() => _at < data.Length ? data[_at++] : throw new InvalidDataException("record ends early");

        public ReadOnlySpan<byte> Bytes(int n)
        {
            if (n < 0 || n > data.Length - _at) throw new InvalidDataException("record ends early");
            var s = data.AsSpan(_at, n);
            _at += n;
            return s;
        }

        public ulong Varint64()
        {
            ulong v = 0;
            for (int shift = 0; shift < 64; shift += 7)
            {
                byte b = Byte();
                v |= (ulong)(b & 0x7F) << shift;
                if (b < 0x80) return v;
            }
            throw new InvalidDataException("varint over 64 bits");
        }

        public uint Varint32() => Varint64() is var v && v <= uint.MaxValue ? (uint)v : throw new InvalidDataException("varint over 32 bits");

        public ReadOnlySpan<byte> Prefixed() => Bytes((int)Math.Min(Varint32(), int.MaxValue));
    }
}
