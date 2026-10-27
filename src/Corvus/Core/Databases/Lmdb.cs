using System.Buffers.Binary;
using System.Text;

namespace Corvus.Core.Databases;

/// <summary>LMDB environments (64-bit layout), pages read on demand; previous-commit and unreachable records are recovered and labelled.</summary>
internal sealed class Lmdb : IDisposable
{
    private const uint Magic = 0xBEEFC0DE;
    private const int Header = 16, MetaAt = 16, DbSize = 48;
    private const ushort Branch = 0x01, Leaf = 0x02, Overflow = 0x04, MetaPage = 0x08, Leaf2 = 0x20, SubPage = 0x40;
    private const ushort BigData = 0x01, SubData = 0x02, DupData = 0x04;
    private const ushort DupSort = 0x04, DupFixed = 0x10;
    private const int MaxDepth = 32;

    /// <summary>A database record: the database ("" for the main one), key and value.</summary>
    public sealed record Record(string Database, byte[] Key, byte[] Value);

    /// <summary>A recovered record and where it was found: "previous commit" or "unreachable page N".</summary>
    public sealed record Recovered(Record Record, string Source);

    /// <summary>A database as its MDB_db record describes it.</summary>
    public sealed record Database(string Name, ushort Flags, int Depth, long BranchPages, long LeafPages, long OverflowPages, long Entries, long Root, int FixedSize);

    /// <summary>A meta page: its transaction id, map size, last page and the free and main database records.</summary>
    public sealed record Meta(long TxnId, long MapSize, long LastPage, Database Free, Database Main);

    private readonly Stream _stream;
    private readonly Dictionary<long, byte[]> _cache = [];

    public int PageSize { get; }
    public Meta Current { get; }
    public Meta? Previous { get; }
    public List<string> Notes { get; } = [];

    /// <summary>Whether <paramref name="head"/> starts with a 64-bit LMDB meta page.</summary>
    public static bool Looks(ReadOnlySpan<byte> head) =>
        head.Length >= MetaAt + 8 && (BinaryPrimitives.ReadUInt16LittleEndian(head[10..]) & MetaPage) != 0
        && BinaryPrimitives.ReadUInt32LittleEndian(head[MetaAt..]) == Magic && BinaryPrimitives.ReadUInt32LittleEndian(head[(MetaAt + 4)..]) == 1;

    /// <summary>Opens the environment in <paramref name="stream"/>; throws <see cref="InvalidDataException"/> when neither meta page is readable.</summary>
    public Lmdb(Stream stream)
    {
        _stream = stream;
        var first = ReadAt(0, 4096) ?? throw new InvalidDataException("file under one page");
        // The page size is kept in the free database's md_pad field.
        int size = (int)BinaryPrimitives.ReadUInt32LittleEndian(first.AsSpan(MetaAt + 24));
        if (size < 512 || size > 65536 || (size & (size - 1)) != 0) throw new InvalidDataException($"page size {size} in the meta page");
        PageSize = size;
        Meta? a = ReadMeta(0), b = stream.Length >= 2L * size ? ReadMeta(1) : null;
        if (a == null && b == null) throw new InvalidDataException("no readable meta page");
        (Current, Previous) = b == null || a != null && a.TxnId >= b.TxnId ? (a!, b) : (b, a);
    }

    public void Dispose() => _stream.Dispose();

    private byte[]? ReadAt(long offset, int length)
    {
        if (offset < 0 || offset + length > _stream.Length) return null;
        var b = new byte[length];
        _stream.Position = offset;
        _stream.ReadExactly(b);
        return b;
    }

    private Meta? ReadMeta(long page)
    {
        var p = ReadAt(page * PageSize, PageSize);
        if (p == null || BinaryPrimitives.ReadUInt32LittleEndian(p.AsSpan(MetaAt)) != Magic) return null;
        var m = p.AsSpan(MetaAt);
        long mapSize = BinaryPrimitives.ReadInt64LittleEndian(m[16..]);
        var free = Db("(free)", m[24..]);
        var main = Db("", m[(24 + DbSize)..]);
        return new Meta(BinaryPrimitives.ReadInt64LittleEndian(m[(24 + 2 * DbSize + 8)..]), mapSize, BinaryPrimitives.ReadInt64LittleEndian(m[(24 + 2 * DbSize)..]), free, main);
    }

    private static Database Db(string name, ReadOnlySpan<byte> d) => new(name, BinaryPrimitives.ReadUInt16LittleEndian(d[4..]), BinaryPrimitives.ReadUInt16LittleEndian(d[6..]),
        BinaryPrimitives.ReadInt64LittleEndian(d[8..]), BinaryPrimitives.ReadInt64LittleEndian(d[16..]), BinaryPrimitives.ReadInt64LittleEndian(d[24..]),
        BinaryPrimitives.ReadInt64LittleEndian(d[32..]), BinaryPrimitives.ReadInt64LittleEndian(d[40..]), (int)BinaryPrimitives.ReadUInt32LittleEndian(d));

    private byte[] Page(long pgno)
    {
        if (_cache.TryGetValue(pgno, out var p)) return p;
        p = ReadAt(pgno * PageSize, PageSize) ?? throw new InvalidDataException($"page {pgno} is past the end of the file");
        if (_cache.Count >= 4096) _cache.Clear();
        return _cache[pgno] = p;
    }

    /// <summary>The named databases of a commit: the main database's leaf records that carry a database record.</summary>
    public List<Database> Named(Meta meta, HashSet<long>? reached, CancellationToken ct)
    {
        var result = new List<Database>();
        foreach (var (key, value, flags) in Nodes(meta.Main, reached, ct))
            if ((flags & SubData) != 0 && (flags & DupData) == 0 && value.Length >= DbSize)
                result.Add(Db(Encoding.UTF8.GetString(key), value));
        return result;
    }

    /// <summary>The records of <paramref name="db"/> in tree order, duplicate values one record each; <paramref name="reached"/> collects the pages read.</summary>
    public IEnumerable<Record> Records(Database db, HashSet<long>? reached, CancellationToken ct)
    {
        foreach (var (key, value, flags) in Nodes(db, reached, ct))
        {
            if (db.Name == "" && (flags & SubData) != 0 && (flags & DupData) == 0) continue;
            if ((flags & DupData) == 0) { yield return new Record(db.Name, key, value); continue; }
            if ((flags & SubData) != 0)
            {
                // A sub-database whose keys are the duplicate values.
                var sub = Db(db.Name, value) with { Flags = (ushort)(db.Flags & ~DupSort), FixedSize = (db.Flags & DupFixed) != 0 ? Db(db.Name, value).FixedSize : 0 };
                foreach (var (dup, _, _) in Nodes(sub, reached, ct)) yield return new Record(db.Name, key, dup);
            }
            else
            {
                List<(byte[] Dup, byte[], ushort)> dups;
                try { dups = [.. PageNodes(value, 0, ct)]; }
                catch (InvalidDataException ex) { Notes.Add($"database {Label(db)}: duplicates of one key: {ex.Message}"); continue; }
                foreach (var d in dups) yield return new Record(db.Name, key, d.Dup);
            }
        }
    }

    // Leaf nodes of the tree under db.Root, depth first; branch nodes lead to children, cycles and deep trees end with a note.
    private IEnumerable<(byte[] Key, byte[] Value, ushort Flags)> Nodes(Database db, HashSet<long>? reached, CancellationToken ct)
    {
        if (db.Root < 0 || db.Entries == 0 && db.Root == -1) yield break;
        var stack = new Stack<(long Page, int Depth)>();
        stack.Push((db.Root, 0));
        var seen = new HashSet<long>();
        while (stack.Count > 0)
        {
            ct.ThrowIfCancellationRequested();
            var (pgno, depth) = stack.Pop();
            if (!seen.Add(pgno) || depth > MaxDepth) { Notes.Add($"database {Label(db)}: page {pgno} reached twice or too deep; walk cut there"); continue; }
            byte[] page;
            try { page = Page(pgno); }
            catch (InvalidDataException ex) { Notes.Add($"database {Label(db)}: {ex.Message}"); continue; }
            reached?.Add(pgno);
            ushort flags = BinaryPrimitives.ReadUInt16LittleEndian(page.AsSpan(10));
            if ((flags & Branch) != 0)
            {
                List<(int, ushort, long Child)> children;
                try { children = [.. RawNodes(page, 0, branch: true)]; }
                catch (InvalidDataException ex) { Notes.Add($"database {Label(db)}: page {pgno}: {ex.Message}"); continue; }
                for (int i = children.Count - 1; i >= 0; i--) stack.Push((children[i].Child, depth + 1));
                continue;
            }
            if ((flags & Leaf) == 0) { Notes.Add($"database {Label(db)}: page {pgno} is neither branch nor leaf (flags 0x{flags:X})"); continue; }
            List<(byte[], byte[], ushort)> nodes;
            try { nodes = [.. PageNodes(page, db.FixedSize, ct, reached)]; }
            catch (InvalidDataException ex) { Notes.Add($"database {Label(db)}: page {pgno}: {ex.Message}"); continue; }
            foreach (var n in nodes) yield return n;
        }
    }

    private static string Label(Database db) => db.Name == "" ? "(main)" : db.Name;

    // The leaf nodes of a page or sub-page image: (key, value, node flags); a big value is read from its overflow pages.
    private IEnumerable<(byte[] Key, byte[] Value, ushort Flags)> PageNodes(byte[] page, int fixedSize, CancellationToken ct, HashSet<long>? reached = null)
    {
        if (page.Length < Header) throw new InvalidDataException("page image under 16 bytes");
        ushort flags = BinaryPrimitives.ReadUInt16LittleEndian(page.AsSpan(10));
        int lower = BinaryPrimitives.ReadUInt16LittleEndian(page.AsSpan(12));
        int count = (lower - Header) / 2;
        if (lower < Header || lower > page.Length) throw new InvalidDataException($"lower bound {lower} outside the page");
        var result = new List<(byte[], byte[], ushort)>();
        if ((flags & Leaf2) != 0)
        {
            // Fixed-size keys packed after the header; a sub-page keeps the size in mp_pad.
            int size = (flags & SubPage) != 0 ? BinaryPrimitives.ReadUInt16LittleEndian(page.AsSpan(8)) : fixedSize;
            if (size <= 0 || Header + (long)count * size > page.Length) throw new InvalidDataException($"packed keys of {size} bytes do not fit the page");
            for (int i = 0; i < count; i++) result.Add((page.AsSpan(Header + i * size, size).ToArray(), [], 0));
            return result;
        }
        foreach (var (node, nflags, size) in RawNodes(page, 0, branch: false))
        {
            ct.ThrowIfCancellationRequested();
            int ksize = BinaryPrimitives.ReadUInt16LittleEndian(page.AsSpan(node + 6));
            if (node + 8 + ksize > page.Length) throw new InvalidDataException("node key runs past the page");
            var key = page.AsSpan(node + 8, ksize).ToArray();
            int at = node + 8 + ksize;
            byte[] value;
            if ((nflags & BigData) != 0)
            {
                if (at + 8 > page.Length) throw new InvalidDataException("overflow page number runs past the page");
                value = OverflowValue(BinaryPrimitives.ReadInt64LittleEndian(page.AsSpan(at)), size, reached);
            }
            else
            {
                if (size > page.Length - at) throw new InvalidDataException("node value runs past the page");
                value = page.AsSpan(at, (int)size).ToArray();
            }
            result.Add((key, value, nflags));
        }
        return result;
    }

    // Node offsets of a page: (offset, flags, data size or child page number).
    private static IEnumerable<(int Node, ushort Flags, long Size)> RawNodes(byte[] page, int start, bool branch)
    {
        int lower = BinaryPrimitives.ReadUInt16LittleEndian(page.AsSpan(start + 12));
        if (lower < Header || start + lower > page.Length) throw new InvalidDataException($"lower bound {lower} outside the page");
        var result = new List<(int, ushort, long)>();
        for (int i = 0; i < (lower - Header) / 2; i++)
        {
            int node = start + BinaryPrimitives.ReadUInt16LittleEndian(page.AsSpan(start + Header + 2 * i));
            if (node < start + Header || node + 8 > page.Length) throw new InvalidDataException($"node {i} at {node} outside the page");
            long lo = BinaryPrimitives.ReadUInt16LittleEndian(page.AsSpan(node)), hi = BinaryPrimitives.ReadUInt16LittleEndian(page.AsSpan(node + 2));
            ushort flags = BinaryPrimitives.ReadUInt16LittleEndian(page.AsSpan(node + 4));
            // A branch node keeps its child page number in lo, hi and flags.
            result.Add(branch ? (node, (ushort)0, lo | hi << 16 | (long)flags << 32) : (node, flags, lo | hi << 16));
        }
        return result;
    }

    private byte[] OverflowValue(long pgno, long size, HashSet<long>? reached)
    {
        if (size < 0 || size > int.MaxValue - Header) throw new InvalidDataException($"overflow value of {size} bytes");
        var first = Page(pgno);
        if ((BinaryPrimitives.ReadUInt16LittleEndian(first.AsSpan(10)) & Overflow) == 0) throw new InvalidDataException($"page {pgno} is not an overflow page");
        long pages = BinaryPrimitives.ReadUInt32LittleEndian(first.AsSpan(12));
        if (pages < 1 || Header + size > pages * PageSize) throw new InvalidDataException($"overflow page {pgno} spans {pages} pages, short of {size} bytes");
        var bytes = ReadAt(pgno * PageSize + Header, (int)size) ?? throw new InvalidDataException($"overflow value at page {pgno} runs past the file");
        if (reached != null) for (long i = 0; i < pages; i++) reached.Add(pgno + i);
        return bytes;
    }

    /// <summary>Records of the previous commit and of freed leaf pages that no live tree shows; each page is read once.</summary>
    public List<Recovered> Recover(HashSet<string> live, HashSet<long> reached, int max, CancellationToken ct)
    {
        var result = new List<Recovered>();
        var seen = new HashSet<string>(live);
        // A record of an unreachable page has no database, so it matches a known record by key and value alone.
        static string Pair(string id) => id[(id.IndexOf('\0') + 1)..];
        var pairs = live.Select(Pair).ToHashSet();
        void Add(Record r, string source)
        {
            string id = Id(r);
            if (result.Count >= max || (r.Database == "(unknown)" ? pairs.Contains(Pair(id)) : !seen.Add(id))) return;
            pairs.Add(Pair(id));
            result.Add(new Recovered(r, source));
        }
        if (Previous is { } prev)
        {
            var dbs = new List<Database> { prev.Main };
            dbs.AddRange(Named(prev, reached, ct));
            foreach (var db in dbs)
                foreach (var r in Records(db, reached, ct)) Add(r, $"previous commit (transaction {prev.TxnId})");
            Reach(prev.Free, reached, ct);
        }
        Reach(Current.Free, reached, ct);
        long last = Math.Min(Current.LastPage, _stream.Length / PageSize - 1);
        for (long pgno = 2; pgno <= last && result.Count < max; pgno++)
        {
            ct.ThrowIfCancellationRequested();
            if (reached.Contains(pgno)) continue;
            var page = Page(pgno);
            ushort flags = BinaryPrimitives.ReadUInt16LittleEndian(page.AsSpan(10));
            if (BinaryPrimitives.ReadInt64LittleEndian(page) != pgno || (flags & (Leaf | Branch | Overflow | MetaPage | SubPage)) != Leaf) continue;
            try
            {
                foreach (var (key, value, nflags) in PageNodes(page, 0, ct))
                    if ((nflags & (SubData | DupData)) == 0 && !FreeListNode(key, value)) Add(new Record("(unknown)", key, value), $"unreachable page {pgno}");
            }
            catch (InvalidDataException) { }
        }
        return result;
    }

    // A free database leaf: a transaction id, then a count of page numbers and the numbers, all 8 bytes.
    private static bool FreeListNode(byte[] key, byte[] value) =>
        key.Length == 8 && value.Length >= 8 && value.Length % 8 == 0 && BinaryPrimitives.ReadInt64LittleEndian(value) == value.Length / 8 - 1;

    // Walks a tree only to mark its pages reached (the free database's pages are in use, not freed).
    private void Reach(Database db, HashSet<long> reached, CancellationToken ct)
    {
        foreach (var _ in Nodes(db, reached, ct)) { }
    }

    /// <summary>A record's identity across databases: database, key and value in hex.</summary>
    public static string Id(Record r) => $"{r.Database}\0{Convert.ToHexString(r.Key)}\0{Convert.ToHexString(r.Value)}";
}
