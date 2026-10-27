using System.Buffers.Binary;

namespace Corvus.Core.Databases;

/// <summary>A Berkeley DB file (btree, recno, hash, queue; either byte order) read without libdb; damaged pages are noted.</summary>
public sealed class BerkeleyDb : IDisposable
{
    private const uint BtreeMagic = 0x053162, HashMagic = 0x061561, QueueMagic = 0x042253, HeapMagic = 0x074582;
    private const byte PInvalid = 0, PHashUnsorted = 2, PIBtree = 3, PIRecno = 4, PLBtree = 5, PLRecno = 6, POverflow = 7,
        PHashMeta = 8, PBtreeMeta = 9, PQueueMeta = 10, PQueueData = 11, PLDup = 12, PHash = 13, PHeapMeta = 14;
    private const byte BKeyData = 1, BDuplicate = 2, BOverflow = 3, BDelete = 0x80;
    private const byte HKeyData = 1, HDuplicate = 2, HOffPage = 3, HOffDup = 4;
    private const uint BtmDup = 0x01, BtmRecno = 0x02, BtmSubDb = 0x20, BtmDupSort = 0x40;
    private const int MaxDepth = 32, MaxCached = 4096;
    private const long MaxValue = 64 << 20;

    private readonly Stream _stream;
    private readonly Dictionary<uint, byte[]?> _cache = [];
    private readonly List<string> _notes = [];
    private readonly int _overhead;
    private readonly HashSet<uint> _master = [];

    /// <summary>A database of the file: Name is empty for a file of one database; Kind is btree, recno, hash, queue or heap.</summary>
    public sealed record Database(string Name, string Kind, uint Meta, uint Root, uint Flags, long Keys, long Records,
        uint MaxBucket = 0, uint[]? Spares = null, int RecordLength = 0, int RecordsPerPage = 0, uint FirstRecno = 0, uint NextRecno = 0, uint Extent = 0)
    {
        public bool Duplicates => Kind is "btree" or "hash" && (Flags & (Kind == "hash" ? 0x01u : BtmDup)) != 0;
        public bool SortedDuplicates => (Flags & (Kind == "hash" ? 0x04u : BtmDupSort)) != 0;
    }

    /// <summary>A record: Key is null in recno and queue databases, where Number is the record number.</summary>
    public sealed record Record(string Database, byte[]? Key, byte[] Value, long? Number);

    /// <summary>A recovered record: Database is null when the page it came from belongs to no known tree.</summary>
    public sealed record Recovered(Record Record, string? Database, string Source);

    public int PageSize { get; }
    public bool BigEndian { get; }
    public uint Magic { get; }
    public uint Version { get; }
    public uint LastPage { get; }
    public bool Checksummed { get; }
    public bool Encrypted { get; }
    public IReadOnlyList<Database> Databases { get; }
    public IReadOnlyList<string> Notes => _notes;

    /// <summary>True when <paramref name="head"/> starts with a Berkeley DB meta page of a known access method.</summary>
    public static bool Looks(ReadOnlySpan<byte> head) => head.Length >= 72 && (Meta(head, false) || Meta(head, true));

    // A meta page in the given byte order: page 0, a power-of-two page size and a magic number matching the page type.
    private static bool Meta(ReadOnlySpan<byte> head, bool big)
    {
        uint magic = U32(head, 12, big), pageSize = U32(head, 20, big);
        byte type = head[25];
        if (U32(head, 8, big) != 0 || pageSize < 512 || pageSize > 65536 || (pageSize & (pageSize - 1)) != 0) return false;
        return magic == BtreeMagic && type == PBtreeMeta || magic == HashMagic && type == PHashMeta || magic == QueueMagic && type == PQueueMeta || magic == HeapMagic && type == PHeapMeta;
    }

    /// <summary>Opens the file in <paramref name="stream"/>; throws <see cref="InvalidDataException"/> when page 0 is not a meta page.</summary>
    public BerkeleyDb(Stream stream)
    {
        _stream = stream;
        var head = ReadAt(0, 512) ?? throw new InvalidDataException("file under 512 bytes");
        if (!Looks(head)) throw new InvalidDataException("no Berkeley DB meta page at offset 0");
        BigEndian = !Meta(head, false);
        Magic = U32(head, 12, BigEndian);
        Version = U32(head, 16, BigEndian);
        PageSize = (int)U32(head, 20, BigEndian);
        Encrypted = head[24] != 0;
        Checksummed = Encrypted || (head[26] & 0x01) != 0;
        LastPage = U32(head, 32, BigEndian);
        _overhead = Encrypted ? 64 : Checksummed ? 32 : 26;
        if (Encrypted)
        {
            Note("encrypted file: records not read");
            Databases = [];
            return;
        }
        var meta = Page(0) ?? throw new InvalidDataException($"file under one {PageSize}-byte page");
        var first = Describe("", 0, meta);
        if (first is { Kind: "btree" } && (first.Flags & BtmSubDb) != 0)
        {
            var named = new List<Database>();
            foreach (var (key, value, _, _) in Leaves(first, null, default))
            {
                string name = System.Text.Encoding.UTF8.GetString(key ?? []).TrimEnd('\0');
                // The master tree stores each database's meta page number in network byte order.
                if (value.Length != 4) { Note($"database '{name}': meta page reference of {value.Length} bytes"); continue; }
                uint pgno = BinaryPrimitives.ReadUInt32BigEndian(value);
                if (Page(pgno) is not { } p || Describe(name, pgno, p) is not { } d) { Note($"database '{name}': page {pgno} is not a meta page"); continue; }
                named.Add(d);
            }
            Databases = named;
            _master = TreePages(first.Root);
        }
        else Databases = first is null ? [] : [first];
    }

    public void Dispose() => _stream.Dispose();

    // Notes stay distinct and bounded: a damaged page met on every read is named once.
    private void Note(string text)
    {
        if (_notes.Count < 100 && !_notes.Contains(text)) _notes.Add(text);
    }

    private static uint U32(ReadOnlySpan<byte> b, int at, bool big) =>
        big ? BinaryPrimitives.ReadUInt32BigEndian(b[at..]) : BinaryPrimitives.ReadUInt32LittleEndian(b[at..]);

    private uint U32(byte[] b, int at) => U32(b, at, BigEndian);

    private int U16(byte[] b, int at) => BigEndian ? BinaryPrimitives.ReadUInt16BigEndian(b.AsSpan(at)) : BinaryPrimitives.ReadUInt16LittleEndian(b.AsSpan(at));

    private byte[]? ReadAt(long offset, int length)
    {
        if (offset < 0 || offset + length > _stream.Length) return null;
        var b = new byte[length];
        _stream.Position = offset;
        _stream.ReadExactly(b);
        return b;
    }

    private byte[]? Page(uint pgno)
    {
        if (_cache.TryGetValue(pgno, out var cached)) return cached;
        if (_cache.Count >= MaxCached) _cache.Clear();
        var p = ReadAt((long)pgno * PageSize, PageSize);
        // A page whose header names another number is not the page asked for.
        if (p != null && U32(p, 8) != pgno && p[25] != PInvalid) p = null;
        return _cache[pgno] = p;
    }

    private Database? Describe(string name, uint pgno, byte[] m)
    {
        uint magic = U32(m, 12), flags = U32(m, 48);
        long keys = U32(m, 40), records = U32(m, 44);
        switch (magic)
        {
            case BtreeMagic when m[25] == PBtreeMeta:
                return new Database(name, (flags & BtmRecno) != 0 ? "recno" : "btree", pgno, U32(m, 88), flags, keys, records);
            case HashMagic when m[25] == PHashMeta:
                var spares = new uint[32];
                for (int i = 0; i < 32; i++) spares[i] = U32(m, 96 + 4 * i);
                return new Database(name, "hash", pgno, 0, flags, keys, records, MaxBucket: U32(m, 72), Spares: spares);
            case QueueMagic when m[25] == PQueueMeta:
                int length = (int)U32(m, 80);
                int perPage = (int)U32(m, 88);
                return new Database(name, "queue", pgno, pgno + 1, flags, keys, records, RecordLength: length, RecordsPerPage: perPage,
                    FirstRecno: U32(m, 72), NextRecno: U32(m, 76), Extent: U32(m, 92));
            case HeapMagic when m[25] == PHeapMeta:
                return new Database(name, "heap", pgno, 0, flags, keys, records);
            default:
                return null;
        }
    }

    /// <summary>The records of <paramref name="db"/> in order; <paramref name="reached"/>, when given, collects the pages read.</summary>
    public IEnumerable<Record> Records(Database db, HashSet<uint>? reached, CancellationToken ct)
    {
        if (db.Kind == "queue")
        {
            foreach (var (number, valid, value, _) in Queue(db, reached, ct))
                if (valid) yield return new Record(db.Name, null, value, number);
            yield break;
        }
        foreach (var (key, value, number, deleted) in Leaves(db, reached, ct))
            if (!deleted) yield return new Record(db.Name, key, value, number);
    }

    // Every leaf item, deleted ones flagged: btree and hash pairs (one per duplicate), recno items by position.
    private IEnumerable<(byte[]? Key, byte[] Value, long? Number, bool Deleted)> Leaves(Database db, HashSet<uint>? reached, CancellationToken ct)
    {
        switch (db.Kind)
        {
            case "btree":
                foreach (var (p, _) in LeafChain(db.Root, PLBtree, reached, ct))
                    for (int i = 0; i + 1 < Entries(p); i += 2)
                    {
                        if (Item(p, i) is not { } k || Item(p, i + 1) is not { } v) continue;
                        bool deleted = (k.Type & BDelete) != 0 || (v.Type & BDelete) != 0;
                        var key = Bytes(k, reached);
                        if (key == null) continue;
                        if ((v.Type & ~BDelete) == BDuplicate)
                        {
                            foreach (var dup in Duplicates(v.Page, reached, ct)) yield return (key, dup, null, deleted);
                        }
                        else if (Bytes(v, reached) is { } value) yield return (key, value, null, deleted);
                    }
                break;
            case "recno":
                long number = 0;
                foreach (var (p, _) in LeafChain(db.Root, PLRecno, reached, ct))
                    for (int i = 0; i < Entries(p); i++)
                    {
                        number++;
                        if (Item(p, i) is { } v && Bytes(v, reached) is { } value) yield return (null, value, number, (v.Type & BDelete) != 0);
                    }
                break;
            case "hash":
                var visited = new HashSet<uint>();
                // Each bucket starts on a page of its own, so the file's page count bounds them.
                for (uint bucket = 0; bucket <= db.MaxBucket && bucket < Pages; bucket++)
                {
                    ct.ThrowIfCancellationRequested();
                    uint pgno = bucket + db.Spares![Log2(bucket + 1)];
                    while (pgno != 0 && visited.Add(pgno))
                    {
                        if (Page(pgno) is not { } p || p[25] is not (PHash or PHashUnsorted)) { Note($"{Label(db)}: bucket {bucket} page {pgno} is not a hash page"); break; }
                        reached?.Add(pgno);
                        for (int i = 0; i + 1 < Entries(p); i += 2)
                        {
                            if (HashItem(p, i, reached) is not { } key || key.Count != 1) continue;
                            if (HashItem(p, i + 1, reached) is not { } values) continue;
                            foreach (var value in values) yield return (key[0], value, null, false);
                        }
                        pgno = U32(p, 16);
                    }
                }
                break;
            case "heap":
                Note($"{Label(db)}: heap database; records not read");
                break;
        }
    }

    private static string Label(Database db) => db.Name == "" ? "database" : $"database '{db.Name}'";

    private int Entries(byte[] p) => Math.Min(U16(p, 20), (PageSize - _overhead) / 2);

    // Smallest i with 2^i >= n, as libdb's __db_log2 computes it.
    private static int Log2(uint n)
    {
        int i = 0;
        while (i < 31 && (1u << i) < n) i++;
        return i;
    }

    // Leaves left to right; a duplicate tree (PLDup) has duplicate leaves when sorted, recno leaves when not.
    private IEnumerable<(byte[] Page, uint Number)> LeafChain(uint root, byte leafType, HashSet<uint>? reached, CancellationToken ct)
    {
        uint pgno = root;
        for (int depth = 0; ; depth++)
        {
            if (depth > MaxDepth || Page(pgno) is not { } p) { Note($"page {pgno}: tree page not readable"); yield break; }
            reached?.Add(pgno);
            if (p[25] == leafType || leafType == PLDup && p[25] == PLRecno)
            {
                leafType = p[25];
                break;
            }
            if (p[25] is not (PIBtree or PIRecno) || Entries(p) == 0) { Note($"page {pgno}: type {p[25]} where a tree page was expected"); yield break; }
            int at = U16(p, _overhead);
            if (at + 8 > PageSize) yield break;
            pgno = p[25] == PIRecno ? U32(p, at) : U32(p, at + 4);
        }
        var visited = new HashSet<uint>();
        while (pgno != 0 && visited.Add(pgno))
        {
            ct.ThrowIfCancellationRequested();
            if (Page(pgno) is not { } p || p[25] != leafType) { Note($"page {pgno}: leaf chain ends at a page of another type"); yield break; }
            reached?.Add(pgno);
            yield return (p, pgno);
            pgno = U32(p, 16);
        }
    }

    private readonly record struct BItem(byte Type, byte[]? Data, uint Page, uint Length);

    // A btree item: on-page bytes, or the page and total length of an overflow item or off-page duplicate tree.
    private BItem? Item(byte[] p, int index)
    {
        int at = U16(p, _overhead + 2 * index);
        if (at < _overhead || at + 3 > PageSize) return null;
        byte type = p[at + 2];
        switch (type & ~BDelete)
        {
            case BKeyData:
                int len = U16(p, at);
                if (at + 3 + len > PageSize) return null;
                return new BItem(type, p[(at + 3)..(at + 3 + len)], 0, (uint)len);
            case BDuplicate or BOverflow:
                if (at + 12 > PageSize) return null;
                return new BItem(type, null, U32(p, at + 4), U32(p, at + 8));
            default:
                return null;
        }
    }

    private byte[]? Bytes(BItem item, HashSet<uint>? reached) =>
        (item.Type & ~BDelete) switch
        {
            BKeyData => item.Data,
            BOverflow => Overflow(item.Page, item.Length, reached),
            _ => null,
        };

    // An overflow item: the data of each page (its length in the free-offset field) along the next-page links.
    private byte[]? Overflow(uint pgno, uint total, HashSet<uint>? reached)
    {
        if (total > MaxValue) { Note($"overflow item of {total:N0} bytes at page {pgno}: over the {MaxValue:N0}-byte bound"); return null; }
        var o = new MemoryStream((int)total);
        var visited = new HashSet<uint>();
        while (o.Length < total && pgno != 0 && visited.Add(pgno))
        {
            if (Page(pgno) is not { } p || p[25] != POverflow) { Note($"overflow page {pgno}: not readable"); break; }
            reached?.Add(pgno);
            int len = Math.Min(U16(p, 22), PageSize - _overhead);
            o.Write(p, _overhead, (int)Math.Min(len, total - o.Length));
            pgno = U32(p, 16);
        }
        if (o.Length < total) Note($"overflow item holds {o.Length:N0} of its {total:N0} bytes");
        return o.ToArray();
    }

    // The values of an off-page duplicate tree, in order.
    private IEnumerable<byte[]> Duplicates(uint root, HashSet<uint>? reached, CancellationToken ct)
    {
        foreach (var (p, _) in LeafChain(root, PLDup, reached, ct))
            for (int i = 0; i < Entries(p); i++)
                if (Item(p, i) is { } v && (v.Type & BDelete) == 0 && Bytes(v, reached) is { } value) yield return value;
    }

    // A hash item: its value, or each value of a duplicate set. An item ends where the one before it on the page begins.
    private List<byte[]>? HashItem(byte[] p, int index, HashSet<uint>? reached)
    {
        int at = U16(p, _overhead + 2 * index);
        int end = index == 0 ? PageSize : U16(p, _overhead + 2 * (index - 1));
        if (at < _overhead || end > PageSize || end <= at) return null;
        switch (p[at])
        {
            case HKeyData:
                return [p[(at + 1)..end]];
            case HDuplicate:
                var values = new List<byte[]>();
                for (int k = at + 1; k + 2 <= end;)
                {
                    int len = U16(p, k);
                    if (k + 4 + len > end) break;
                    values.Add(p[(k + 2)..(k + 2 + len)]);
                    k += 4 + len;
                }
                return values;
            case HOffPage when at + 12 <= end:
                return Overflow(U32(p, at + 4), U32(p, at + 8), reached) is { } o ? [o] : null;
            case HOffDup when at + 8 <= end:
                return [.. Duplicates(U32(p, at + 4), reached, default)];
            default:
                return null;
        }
    }

    // Queue records by number: valid when set and not consumed or deleted.
    private IEnumerable<(long Number, bool Valid, byte[] Value, uint Page)> Queue(Database db, HashSet<uint>? reached, CancellationToken ct)
    {
        if (db.Extent != 0) { Note($"{Label(db)}: queue records in extent files; not read"); yield break; }
        int slot = (1 + db.RecordLength + 3) & ~3;
        int header = Encrypted ? 64 : Checksummed ? 48 : 28;
        if (db.RecordLength <= 0 || db.RecordsPerPage <= 0 || header + slot * db.RecordsPerPage > PageSize) { Note($"{Label(db)}: record layout not readable"); yield break; }
        // Queue files leave the meta page's last-page field unset; the file length bounds the data pages.
        for (uint pgno = db.Root; pgno < Pages; pgno++)
        {
            ct.ThrowIfCancellationRequested();
            if (Page(pgno) is not { } p || p[25] != PQueueData) continue;
            reached?.Add(pgno);
            for (int i = 0; i < db.RecordsPerPage; i++)
            {
                int at = header + i * slot;
                byte flags = p[at];
                if ((flags & 0x02) == 0) continue;
                yield return ((long)(pgno - db.Root) * db.RecordsPerPage + i + 1, (flags & 0x01) != 0, p[(at + 1)..(at + 1 + db.RecordLength)], pgno);
            }
        }
    }

    /// <summary>A record's identity for matching recovered ones against live ones.</summary>
    public static string Id(Record r) => $"{r.Database}\0{(r.Key == null ? "#" + r.Number : Convert.ToHexString(r.Key))}\0{Convert.ToHexString(r.Value)}";

    /// <summary>Records deleted items, free space and unreached pages still hold, live ones left out; an unknown key is null.</summary>
    public List<Recovered> Recover(HashSet<string> live, HashSet<uint> reached, int max, CancellationToken ct)
    {
        var result = new List<Recovered>();
        var seen = new HashSet<string>(live);
        // Free space keeps copies of live items that a delete or split moved; those are not recovered.
        var liveKeys = new HashSet<string>(StringComparer.Ordinal);
        var liveBytes = new HashSet<string>(StringComparer.Ordinal);
        foreach (var db in Databases)
            foreach (var r in Records(db, null, ct))
            {
                if (r.Key != null) liveKeys.Add(Convert.ToHexString(r.Key));
                liveBytes.Add(Convert.ToHexString(r.Value));
            }
        liveBytes.UnionWith(liveKeys);
        void Add(Record r, string? db, string source)
        {
            if (result.Count < max && seen.Add(Id(r))) result.Add(new Recovered(r, db, source));
        }
        foreach (var db in Databases)
        {
            if (db.Kind == "queue")
            {
                foreach (var (number, valid, value, page) in Queue(db, null, ct))
                    if (!valid) Add(new Record(db.Name, null, value, number), db.Name, $"consumed record, page {page}");
                continue;
            }
            foreach (var (key, value, number, deleted) in Leaves(db, null, ct))
                if (deleted) Add(new Record(db.Name, key, value, number), db.Name, value.Length == 0 ? "deleted item; value not kept" : "deleted item");
        }
        // Every page of each tree, to name the database a carved page belongs to; the master tree's pages hold names only.
        var owner = new Dictionary<uint, Database>();
        foreach (var db in Databases)
            if (db.Kind is "btree" or "recno")
                foreach (var pg in TreePages(db.Root)) owner.TryAdd(pg, db);
        var skip = new HashSet<uint>(_master);
        for (uint pgno = 1; pgno < Pages && result.Count < max; pgno++)
        {
            ct.ThrowIfCancellationRequested();
            if (skip.Contains(pgno) || Page(pgno) is not { } p) continue;
            bool known = owner.TryGetValue(pgno, out var db) || reached.Contains(pgno);
            bool pairs = db == null ? p[25] is PLBtree or PIBtree or PInvalid : db.Kind == "btree" && p[25] != PLDup;
            var keys = liveKeys;
            switch (p[25])
            {
                case PLBtree or PLRecno or PLDup or PIBtree or PIRecno when known:
                    foreach (var (key, value) in Carve(p, Math.Min(_overhead + 2 * Entries(p), PageSize), Math.Min(U16(p, 22), PageSize), pairs, keys, liveBytes))
                        Add(new Record(db?.Name ?? "", key, value, null), db?.Name, $"free space, page {pgno}");
                    break;
                case PLBtree or PLRecno or PLDup or PIBtree or PIRecno or PInvalid:
                    // A page no tree reaches, or one the free list holds: its items as written, read without the index.
                    foreach (var (key, value) in Carve(p, _overhead, PageSize, pairs, keys, liveBytes))
                        Add(new Record("", key, value, null), null, $"{(p[25] == PInvalid ? "free" : "unreachable")} page {pgno}");
                    break;
            }
        }
        return result;
    }

    /// <summary>The pages of the file, from its length.</summary>
    public long Pages => _stream.Length / PageSize;

    // Every page of a btree or recno tree: internal pages by their entries, leaves included.
    private HashSet<uint> TreePages(uint root)
    {
        var pages = new HashSet<uint>();
        var queue = new Queue<(uint Page, int Depth)>([(root, 0)]);
        while (queue.Count > 0 && pages.Count < 1 << 22)
        {
            var (pgno, depth) = queue.Dequeue();
            if (depth > MaxDepth || !pages.Add(pgno) || Page(pgno) is not { } p || p[25] is not (PIBtree or PIRecno)) continue;
            for (int i = 0; i < Entries(p); i++)
            {
                int at = U16(p, _overhead + 2 * i);
                if (at >= _overhead && at + 8 <= PageSize) queue.Enqueue((p[25] == PIRecno ? U32(p, at) : U32(p, at + 4), depth + 1));
            }
        }
        return pages;
    }

    // Btree items: 2-byte length, type 1 (0x81 deleted), bytes, 4-byte aligned; keys and values alternate, a live key fixes which.
    // Without one, only runs of three or more are taken as values: a lone item may be a header over other items' bytes.
    private IEnumerable<(byte[]? Key, byte[] Value)> Carve(byte[] p, int from, int to, bool pairs, HashSet<string> liveKeys, HashSet<string> liveBytes)
    {
        var runs = new List<List<(int At, int End, byte[] Data)>>();
        List<(int At, int End, byte[] Data)>? run = null;
        for (int at = (from + 3) & ~3; at + 3 < to;)
        {
            int len = U16(p, at);
            byte type = p[at + 2];
            if (len > 0 && (type & 0x7F) == BKeyData && at + 3 + len <= to)
            {
                if (run == null || run[^1].End != at) runs.Add(run = []);
                int end = (at + 3 + len + 3) & ~3;
                run.Add((at, end, p[(at + 3)..(at + 3 + len)]));
                at = end;
            }
            else
            {
                run = null;
                at += 4;
            }
        }
        foreach (var items in runs)
        {
            int parity = -1;
            if (pairs)
                for (int i = 1; i < items.Count && parity < 0; i++)
                    if (liveKeys.Contains(Convert.ToHexString(items[i].Data))) parity = i % 2;
            int stale = items.Count(x => !liveBytes.Contains(Convert.ToHexString(x.Data)));
            for (int i = 0; i < items.Count; i++)
            {
                var data = items[i].Data;
                if (parity >= 0 && i + 1 < items.Count && (i + 1) % 2 == parity)
                {
                    var key = items[i + 1].Data;
                    i++;
                    if (!liveBytes.Contains(Convert.ToHexString(data))) yield return (key, data);
                }
                else if ((parity >= 0 || stale >= 3) && !liveBytes.Contains(Convert.ToHexString(data))) yield return (null, data);
            }
        }
    }
}
