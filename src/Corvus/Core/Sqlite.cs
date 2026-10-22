using System.Buffers.Binary;
using System.Globalization;
using System.IO.MemoryMappedFiles;
using System.Text;
using System.Text.RegularExpressions;

namespace Corvus.Core;

/// <summary>A sqlite_schema row: type (table, index, view, trigger), name, the table it belongs to, root page and SQL as stored.</summary>
public sealed record SqliteSchemaEntry(string Type, string Name, string TableName, long RootPage, string? Sql);

/// <summary>A blob value: its full length and up to the first bytes read.</summary>
public sealed record SqliteBlob(long Length, byte[] Head);

/// <summary>A table row: rowid (null in a WITHOUT ROWID table) and its values (null, long, double, string or <see cref="SqliteBlob"/>).</summary>
public sealed record SqliteRow(long? RowId, IReadOnlyList<object?> Values);

/// <summary>
/// A table's shape from its CREATE TABLE: columns in declaration order with their type affinity, the INTEGER PRIMARY KEY
/// column (a rowid alias, -1 when none) and the column each stored value belongs to: primary key columns first in a
/// WITHOUT ROWID table, VIRTUAL generated columns left out (they are computed, not stored).
/// </summary>
public sealed record SqliteTable(string Name, long RootPage, IReadOnlyList<string> Columns, IReadOnlyList<char> Affinities, int RowIdAlias, bool WithoutRowId,
    IReadOnlyList<int> StoredOrder)
{
    /// <summary>Each column's DEFAULT literal (null when none or not a literal): a row stored before ALTER TABLE ADD COLUMN reads it.</summary>
    public IReadOnlyList<object?> Defaults { get; init; } = [];

    /// <summary>Generated columns by declaration index: 'V' (VIRTUAL, not stored) or 'S' (STORED).</summary>
    public IReadOnlyDictionary<int, char> Generated { get; init; } = new Dictionary<int, char>();

    /// <summary>The values of a stored row in declaration order: the rowid alias filled in, fields past a short record read as their default.</summary>
    public object?[] Shape(SqliteRow row)
    {
        var values = new object?[Math.Max(Columns.Count, row.Values.Count)];
        for (int i = 0; i < row.Values.Count; i++)
        {
            int c = i < StoredOrder.Count ? StoredOrder[i] : i;
            // a REAL column stores an integral value as an integer; it reads back as a real
            values[c] = row.Values[i] is long l && c < Affinities.Count && Affinities[c] == 'R' ? (double)l : row.Values[i];
        }
        for (int i = row.Values.Count; i < StoredOrder.Count; i++)
            if (StoredOrder[i] < Defaults.Count) values[StoredOrder[i]] = Defaults[StoredOrder[i]];
        if (RowIdAlias >= 0 && values[RowIdAlias] == null && row.RowId is { } id) values[RowIdAlias] = id;
        return values;
    }
}

/// <summary>Bytes read by offset: a byte array, or a read-only memory-mapped file read in place without a copy of the file.</summary>
public abstract class SqliteSource : IDisposable
{
    public abstract long Length { get; }

    /// <summary>Reads up to <paramref name="into"/>.Length bytes at <paramref name="offset"/>; the count read.</summary>
    public abstract int Read(long offset, Span<byte> into);

    public void Dispose()
    {
        Dispose(true);
        GC.SuppressFinalize(this);
    }

    protected virtual void Dispose(bool disposing) { }

    public static SqliteSource Of(byte[] data) => new ArraySource(data);

    /// <summary>The file mapped read-only (other writers allowed); null when it is missing or empty.</summary>
    public static SqliteSource? Map(string path)
    {
        if (!File.Exists(path) || new FileInfo(path).Length == 0) return null;
        var file = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
        try
        {
            var map = MemoryMappedFile.CreateFromFile(file, null, 0, MemoryMappedFileAccess.Read, HandleInheritability.None, leaveOpen: false);
            return new MappedSource(map, map.CreateViewAccessor(0, 0, MemoryMappedFileAccess.Read), file.Length);
        }
        catch { file.Dispose(); throw; }
    }

    private sealed class ArraySource(byte[] data) : SqliteSource
    {
        public override long Length => data.Length;

        public override int Read(long offset, Span<byte> into)
        {
            if (offset < 0 || offset >= data.Length) return 0;
            int n = (int)Math.Min(into.Length, data.Length - offset);
            data.AsSpan((int)offset, n).CopyTo(into);
            return n;
        }
    }

    private sealed class MappedSource(MemoryMappedFile map, MemoryMappedViewAccessor view, long length) : SqliteSource
    {
        public override long Length => length;

        public override int Read(long offset, Span<byte> into)
        {
            if (offset < 0 || offset >= length) return 0;
            int n = (int)Math.Min(into.Length, length - offset);
            view.SafeMemoryMappedViewHandle.ReadSpan((ulong)(offset + view.PointerOffset), into[..n]);
            return n;
        }

        protected override void Dispose(bool disposing)
        {
            view.Dispose();
            map.Dispose();
            base.Dispose(disposing);
        }
    }
}

/// <summary>
/// A SQLite 3 database file read through its own B-tree reader: header, sqlite_schema, row counts and rows by position,
/// with the committed frames of a -wal file applied when one is given. No SQL is run and no native library is used. Pages
/// are read on demand (a small cache), so a large file is never held whole. Every walk is bounded (page visits, cells,
/// payload bytes) and a page reached twice in one walk ends it, so a malformed file gives issues, never an exception.
/// </summary>
public sealed partial class SqliteDatabase
{
    public int PageSize { get; private set; }
    public int ReservedBytes { get; private set; }
    /// <summary>Pages in the database: the last WAL commit's count, else the header's count when valid, else the file length over the page size.</summary>
    public long PageCount { get; private set; }
    public long FileLength { get; private set; }
    public string TextEncoding { get; private set; } = "UTF-8";
    /// <summary>Header read/write versions 2: journal_mode=WAL.</summary>
    public bool Wal { get; private set; }
    public uint SchemaFormat { get; private set; }
    public uint FreelistPages { get; private set; }
    public uint FirstFreelistTrunk { get; private set; }
    public uint UserVersion { get; private set; }
    public uint ApplicationId { get; private set; }
    public bool AutoVacuum { get; private set; }
    /// <summary>SQLITE_VERSION_NUMBER of the library that last wrote the file, as 3.x.y.</summary>
    public string? WriterVersion { get; private set; }
    /// <summary>The -wal file given to <see cref="Open(SqliteSource, SqliteSource?, CancellationToken)"/>; its committed frames are applied.</summary>
    public SqliteWalLog? WalLog { get; private set; }
    public List<SqliteSchemaEntry> Schema { get; } = [];
    public List<string> Issues { get; } = [];

    public const int MaxPageVisits = 1_000_000;
    private const int MaxSchemaRows = 10_000;
    private const int MaxPayload = 64 * 1024;
    private const int MaxColumns = 2_000;
    private const int CachePages = 512;

    private readonly SqliteSource _db;
    private SqliteSource? _wal, _walFile;
    private readonly Dictionary<long, byte[]> _cache = [];
    private readonly Queue<long> _cached = new();
    private readonly Dictionary<long, long> _counts = [];
    private Encoding _text = Encoding.UTF8;
    private int _usable;
    private long _visits;

    private SqliteDatabase(SqliteSource db) => _db = db;

    public static bool Looks(ReadOnlySpan<byte> b) => b.Length >= 100 && b[..16].SequenceEqual("SQLite format 3\0"u8);

    /// <summary>The database, or null without the SQLite magic or with an impossible page size.</summary>
    public static SqliteDatabase? Open(byte[] data, CancellationToken ct = default) => Open(SqliteSource.Of(data), null, ct);

    /// <summary>
    /// The database read from <paramref name="db"/> with the committed frames of <paramref name="wal"/> (its -wal file) applied;
    /// null without the SQLite magic or with an impossible page size. The sources stay owned by the caller.
    /// </summary>
    public static SqliteDatabase? Open(SqliteSource db, SqliteSource? wal, CancellationToken ct = default)
    {
        var head = new byte[100];
        if (db.Read(0, head) < 100 || !Looks(head)) return null;
        int pageSize = BinaryPrimitives.ReadUInt16BigEndian(head.AsSpan(16));
        if (pageSize == 1) pageSize = 65536;
        if (pageSize < 512 || pageSize > 65536 || (pageSize & (pageSize - 1)) != 0) return null;
        var d = new SqliteDatabase(db) { FileLength = db.Length, PageSize = pageSize, ReservedBytes = head[20] };
        d._usable = pageSize - d.ReservedBytes;
        if (d._usable < 480) { d.Issues.Add($"usable page size {d._usable} is below 480"); return d; }
        if (wal != null && SqliteWalLog.Read(wal, ct) is { } log)
        {
            d.WalLog = log;
            if (log.PageSize != pageSize) d.Issues.Add($"the -wal file's page size {log.PageSize} differs from the database's {pageSize}: not applied");
            else
            {
                d._walFile = wal;
                if (log.Committed > 0) d._wal = wal;
            }
        }
        if (d.Raw(1) is { } first) first.AsSpan(0, 100).CopyTo(head); // page 1 as of the last WAL commit
        d.Wal = head[18] == 2 || head[19] == 2;
        uint headerPages = Be32(head, 28), changeCounter = Be32(head, 24), validFor = Be32(head, 92);
        long filePages = db.Length / pageSize;
        if (d._wal != null) d.PageCount = d.WalLog!.DatabasePages;
        else if (headerPages != 0 && changeCounter == validFor && headerPages <= filePages) d.PageCount = headerPages;
        else
        {
            d.PageCount = filePages;
            if (headerPages > filePages) d.Issues.Add($"header names {headerPages:N0} pages; the file holds {filePages:N0}");
        }
        if (db.Length % pageSize != 0) d.Issues.Add($"file length {db.Length:N0} is not a multiple of the page size");
        d.FirstFreelistTrunk = Be32(head, 32);
        d.FreelistPages = Be32(head, 36);
        d.SchemaFormat = Be32(head, 44);
        d.AutoVacuum = Be32(head, 52) != 0;
        d.UserVersion = Be32(head, 60);
        d.ApplicationId = Be32(head, 68);
        uint version = Be32(head, 96);
        if (version is >= 3_000_000 and < 4_000_000) d.WriterVersion = $"{version / 1_000_000}.{version / 1000 % 1000}.{version % 1000}";
        (d.TextEncoding, d._text) = Be32(head, 56) switch
        {
            2 => ("UTF-16le", (Encoding)Encoding.Unicode),
            3 => ("UTF-16be", Encoding.BigEndianUnicode),
            _ => ("UTF-8", Encoding.UTF8),
        };
        d.ReadSchema(ct);
        return d;
    }

    private void ReadSchema(CancellationToken ct)
    {
        foreach (var row in Rows(1, index: false, 0, MaxSchemaRows, ct))
        {
            var v = row.Values;
            string Text(int i) => i < v.Count && v[i] is string s ? s : "";
            long root = v.Count > 3 && v[3] is long r ? r : 0;
            Schema.Add(new SqliteSchemaEntry(Text(0), Text(1), Text(2), root, v.Count > 4 ? v[4] as string : null));
        }
    }

    /// <summary>The stored tables (not views or virtual tables) with their shapes.</summary>
    public IEnumerable<SqliteTable> Tables() => Schema.Where(e => e.Type == "table" && e.RootPage > 0).Select(TableOf);

    /// <summary>A table by name (case-insensitive, as SQL compares names), or null.</summary>
    public SqliteTable? Table(string name) =>
        Schema.FirstOrDefault(e => e.Type == "table" && e.RootPage > 0 && e.Name.Equals(name, StringComparison.OrdinalIgnoreCase)) is { } e ? TableOf(e) : null;

    private static SqliteTable TableOf(SqliteSchemaEntry e)
    {
        var shape = Shape(e.Sql);
        var order = Enumerable.Range(0, shape.Columns.Count).Where(i => shape.Columns[i].Generated != 'V').ToList();
        if (shape.WithoutRowId && shape.PrimaryKey.Count > 0)
        {
            var pk = shape.PrimaryKey.Select(k => shape.Columns.FindIndex(c => c.Name.Equals(k, StringComparison.OrdinalIgnoreCase))).Where(i => i >= 0).Distinct().ToList();
            order = [.. pk, .. order.Where(i => !pk.Contains(i))];
        }
        var affinities = shape.Columns.Select(c => Affinity(c.Type)).ToList();
        return new SqliteTable(e.Name, e.RootPage, [.. shape.Columns.Select(c => c.Name)], affinities,
            shape.WithoutRowId ? -1 : shape.Alias, shape.WithoutRowId, order)
        {
            Defaults = [.. shape.Columns.Select((c, i) => c.Default is { } d ? WithAffinity(d, affinities[i]) : null)],
            Generated = shape.Columns.Select((c, i) => (c.Generated, i)).Where(g => g.Generated != '\0').ToDictionary(g => g.i, g => g.Generated),
        };
    }

    /// <summary>Type affinity by SQLite's rules: I(nteger), T(ext), B(lob or none), R(eal), N(umeric).</summary>
    private static char Affinity(string type)
    {
        var t = type.ToUpperInvariant();
        if (t.Contains("INT", StringComparison.Ordinal)) return 'I';
        if (t.Contains("CHAR", StringComparison.Ordinal) || t.Contains("CLOB", StringComparison.Ordinal) || t.Contains("TEXT", StringComparison.Ordinal)) return 'T';
        if (t.Length == 0 || t.Contains("BLOB", StringComparison.Ordinal)) return 'B';
        if (t.Contains("REAL", StringComparison.Ordinal) || t.Contains("FLOA", StringComparison.Ordinal) || t.Contains("DOUB", StringComparison.Ordinal)) return 'R';
        return 'N';
    }

    /// <summary>The root page's kind: true for an index B-tree (an index or a WITHOUT ROWID table), false for a table B-tree, null when unreadable.</summary>
    public bool? IsIndexTree(long root)
    {
        if (Page(root) is not { } p) return null;
        return p.Type switch { 2 or 10 => true, 5 or 13 => false, _ => null };
    }

    /// <summary>Entries in the B-tree at <paramref name="root"/>; null when the walk ended early (issue recorded).</summary>
    public long? CountRows(long root, CancellationToken ct = default)
    {
        if (IsIndexTree(root) == null) { Issues.Add($"page {root}: not a B-tree page"); return null; }
        return Count(root, ct);
    }

    /// <summary>The first <paramref name="limit"/> rows of the B-tree at <paramref name="root"/> in key order.</summary>
    public List<SqliteRow> Rows(long root, int limit, CancellationToken ct = default) => Rows(root, 0, limit, ct);

    /// <summary>Up to <paramref name="limit"/> rows of the B-tree at <paramref name="root"/> in key order, from position <paramref name="offset"/>.</summary>
    public List<SqliteRow> Rows(long root, long offset, int limit, CancellationToken ct = default) =>
        IsIndexTree(root) is { } index ? Rows(root, index, offset, limit, ct) : [];

    private List<SqliteRow> Rows(long root, bool index, long offset, int limit, CancellationToken ct)
    {
        var rows = new List<SqliteRow>();
        if (limit <= 0) return rows;
        long skip = Math.Max(0, offset);
        var seen = new HashSet<long>();
        // A node is a page to open, or (Page, Cell >= 0) an interior index cell whose entry comes between its children.
        var stack = new Stack<(long Page, int Cell)>();
        stack.Push((root, -1));
        while (stack.Count > 0 && rows.Count < limit)
        {
            ct.ThrowIfCancellationRequested();
            var (pageNo, cell) = stack.Pop();
            if (Page(pageNo) is not { } p) { Issues.Add($"page {pageNo} is outside the file"); break; }
            if (cell >= 0)
            {
                if (skip > 0) { skip--; continue; }
                if (Entry(p, cell, interiorIndex: true) is { } e) rows.Add(e);
                continue;
            }
            // a whole subtree before the offset is skipped by its entry count
            if (skip > 0 && Count(pageNo, ct) is { } n && n <= skip) { skip -= n; continue; }
            if (!seen.Add(pageNo)) { Issues.Add($"page {pageNo} is reached twice (a cycle)"); break; }
            if (++_visits > MaxPageVisits) { Issues.Add($"page visit limit {MaxPageVisits:N0} reached"); break; }
            int cells = CellCount(p);
            switch (p.Type)
            {
                case 13 or 10:
                    int first = (int)Math.Min(skip, cells);
                    skip -= first;
                    for (int i = first; i < cells && rows.Count < limit; i++)
                        if (Entry(p, i, interiorIndex: false) is { } e) rows.Add(e);
                    break;
                case 5 or 2:
                    if ((p.Type == 2) != index) { Issues.Add($"page {pageNo}: page type {p.Type} in a {(index ? "index" : "table")} B-tree"); return rows; }
                    stack.Push((Be32(p.Data, p.Header + 8), -1));
                    for (int i = cells - 1; i >= 0; i--)
                    {
                        if (CellOffset(p, i) is not { } at) continue;
                        if (p.Type == 2) stack.Push((pageNo, i));
                        stack.Push((Be32(p.Data, at), -1));
                    }
                    break;
                default:
                    Issues.Add($"page {pageNo}: not a B-tree page (type {p.Type})");
                    return rows;
            }
        }
        return rows;
    }

    /// <summary>Entries under a B-tree page (leaf cells and interior index cells), memoized; null when the walk ended early.</summary>
    private long? Count(long top, CancellationToken ct)
    {
        if (_counts.TryGetValue(top, out var known)) return known;
        var onPath = new HashSet<long>();
        var stack = new Stack<(long Page, bool Expanded)>();
        stack.Push((top, false));
        while (stack.Count > 0)
        {
            ct.ThrowIfCancellationRequested();
            var (pageNo, expanded) = stack.Pop();
            if (!expanded && _counts.ContainsKey(pageNo)) continue;
            // a leaf's count is in its header: read 8 bytes, not the page
            if (LeafCells(pageNo) is { } leaf) { _counts[pageNo] = leaf; continue; }
            if (Page(pageNo) is not { } p) { Issues.Add($"page {pageNo} is outside the file"); return null; }
            if (p.Type is not (5 or 2)) { Issues.Add($"page {pageNo}: not a B-tree page (type {p.Type})"); return null; }
            var children = Children(p);
            if (!expanded)
            {
                if (!onPath.Add(pageNo)) { Issues.Add($"page {pageNo} is reached twice (a cycle)"); return null; }
                if (++_visits > MaxPageVisits) { Issues.Add($"page visit limit {MaxPageVisits:N0} reached"); return null; }
                stack.Push((pageNo, true));
                foreach (var c in children)
                {
                    if (onPath.Contains(c)) { Issues.Add($"page {c} is reached twice (a cycle)"); return null; }
                    if (!_counts.ContainsKey(c)) stack.Push((c, false));
                }
                continue;
            }
            long sum = p.Type == 2 ? CellCount(p) : 0;
            foreach (var c in children)
            {
                if (!_counts.TryGetValue(c, out var n)) return null;
                sum += n;
            }
            _counts[pageNo] = sum;
            onPath.Remove(pageNo);
        }
        return _counts.TryGetValue(top, out var count) ? count : null;
    }

    /// <summary>The child pages of an interior page, left to right.</summary>
    private List<long> Children(PageRef p)
    {
        var children = new List<long>();
        int cells = CellCount(p);
        for (int i = 0; i < cells; i++)
            if (CellOffset(p, i) is { } at) children.Add(Be32(p.Data, at));
        children.Add(Be32(p.Data, p.Header + 8));
        return children;
    }

    /// <summary>The leaf pages of a B-tree in key order (bounded like every walk).</summary>
    internal List<long> LeafPages(long root, CancellationToken ct)
    {
        var leaves = new List<long>();
        var seen = new HashSet<long>();
        var stack = new Stack<long>();
        stack.Push(root);
        while (stack.Count > 0)
        {
            ct.ThrowIfCancellationRequested();
            long pageNo = stack.Pop();
            if (Page(pageNo) is not { } p || !seen.Add(pageNo) || ++_visits > MaxPageVisits) break;
            if (p.Type is 13 or 10) { leaves.Add(pageNo); continue; }
            if (p.Type is not (5 or 2)) break;
            var children = Children(p);
            for (int i = children.Count - 1; i >= 0; i--) stack.Push(children[i]);
        }
        return leaves;
    }

    /// <summary>A page: its bytes (from the -wal file when a committed frame holds it), the B-tree header's offset and page type.</summary>
    internal readonly record struct PageRef(long Number, byte[] Data, int Header)
    {
        public byte Type => Data[Header];
    }

    internal PageRef? Page(long number)
    {
        if (number < 1 || number > PageCount || Raw(number) is not { } data) return null;
        return new PageRef(number, data, number == 1 ? 100 : 0);
    }

    /// <summary>A page's bytes as of the last committed WAL frame, else from the database file; null past its end.</summary>
    internal byte[]? Raw(long number)
    {
        if (_cache.TryGetValue(number, out var hit)) return hit;
        var data = new byte[PageSize];
        if (_wal != null && WalLog!.Latest.TryGetValue(number, out long at))
        {
            if (_wal.Read(at, data) < PageSize) return null;
        }
        else if (number < 1 || _db.Read((number - 1) * PageSize, data) < PageSize) return null;
        if (_cached.Count >= CachePages) _cache.Remove(_cached.Dequeue());
        _cache[number] = data;
        _cached.Enqueue(number);
        return data;
    }

    /// <summary>The cell count of a leaf page read from its header alone (as <see cref="CellCount"/> caps it); null for any other page.</summary>
    private int? LeafCells(long number)
    {
        if (number < 1 || number > PageCount) return null;
        if (_cache.TryGetValue(number, out var cached))
        {
            var p = new PageRef(number, cached, number == 1 ? 100 : 0);
            return p.Type is 13 or 10 ? CellCount(p) : null;
        }
        int header = number == 1 ? 100 : 0;
        Span<byte> h = stackalloc byte[8];
        long at = _wal != null && WalLog!.Latest.TryGetValue(number, out long frame) ? frame + header : (number - 1) * PageSize + header;
        if ((_wal != null && WalLog!.Latest.ContainsKey(number) ? _wal : _db).Read(at, h) < 8 || h[0] is not (13 or 10)) return null;
        int n = BinaryPrimitives.ReadUInt16BigEndian(h[3..]);
        return Math.Clamp(n, 0, Math.Max(0, (_usable - (header + 8)) / 2));
    }

    /// <summary>Cells on the page, capped by what its cell pointer array can hold.</summary>
    internal int CellCount(PageRef p)
    {
        int n = BinaryPrimitives.ReadUInt16BigEndian(p.Data.AsSpan(p.Header + 3));
        int room = (_usable - (p.Header + HeaderSize(p))) / 2;
        return Math.Clamp(n, 0, Math.Max(0, room));
    }

    internal static int HeaderSize(PageRef p) => p.Type is 2 or 5 ? 12 : 8;

    internal int? CellOffset(PageRef p, int i)
    {
        int headerSize = HeaderSize(p);
        int at = BinaryPrimitives.ReadUInt16BigEndian(p.Data.AsSpan(p.Header + headerSize + 2 * i));
        if (at < p.Header + headerSize || at + 4 > _usable) return null;
        return at;
    }

    /// <summary>The row of leaf cell <paramref name="i"/> (or of an interior index cell); null for an unreadable cell.</summary>
    internal SqliteRow? Entry(PageRef p, int i, bool interiorIndex)
    {
        if (CellOffset(p, i) is not { } at) return null;
        return CellAt(p.Data, at, p.Type == 13, interiorIndex);
    }

    /// <summary>A table-leaf (<paramref name="table"/>) or index cell at <paramref name="at"/> in a page's bytes.</summary>
    internal SqliteRow? CellAt(byte[] page, int at, bool table, bool interiorIndex = false)
    {
        if (interiorIndex) at += 4;
        if (!Varint(page, ref at, _usable, out long payload) || payload < 0) return null;
        long? rowid = null;
        if (table)
        {
            if (!Varint(page, ref at, _usable, out long r)) return null;
            rowid = r;
        }
        var bytes = Payload(page, at, payload, table);
        return bytes == null ? null : new SqliteRow(rowid, Record(bytes));
    }

    /// <summary>The bytes of a payload of <paramref name="size"/> kept on its B-tree page (the rest is on overflow pages).</summary>
    internal long Local(long size, bool table)
    {
        int u = _usable;
        long x = table ? u - 35 : (u - 12) * 64 / 255 - 23;
        if (size <= x) return size;
        long m = (u - 12) * 32 / 255 - 23;
        long k = m + (size - m) % (u - 4);
        return k <= x ? k : m;
    }

    /// <summary>
    /// The first <see cref="MaxPayload"/> bytes of a payload, following its overflow chain; a chain that leaves the file is
    /// an issue, or with <paramref name="carved"/> (a freed cell) ends the payload there, or null at its first page.
    /// </summary>
    internal byte[]? Payload(byte[] page, int at, long size, bool table, bool carved = false)
    {
        int u = _usable;
        long local = Local(size, table);
        if (at + local > u) return null;
        var buffer = new byte[(int)Math.Min(size, MaxPayload)];
        int take = (int)Math.Min(local, buffer.Length);
        page.AsSpan(at, take).CopyTo(buffer);
        int filled = take;
        if (local >= size || filled >= buffer.Length) return buffer;
        if (at + local + 4 > u) return null;
        long next = Be32(page, at + (int)local);
        long maxPages = (size - local) / (u - 4) + 1;
        for (long n = 0; filled < buffer.Length && n < maxPages; n++)
        {
            if (next < 1 || next > PageCount || Raw(next) is not { } o)
            {
                if (!carved) Issues.Add($"overflow page {next} is outside the file");
                return carved && n == 0 ? null : buffer[..filled];
            }
            int chunk = Math.Min(u - 4, buffer.Length - filled);
            o.AsSpan(4, chunk).CopyTo(buffer.AsSpan(filled));
            filled += chunk;
            next = Be32(o, 0);
        }
        return buffer[..filled];
    }

    /// <summary>Record format: a header of serial types, then the values; values past the bytes read are clipped or null.</summary>
    internal List<object?> Record(byte[] b)
    {
        var values = new List<object?>();
        int p = 0;
        if (!Varint(b, ref p, b.Length, out long headerSize) || headerSize < 1 || headerSize > b.Length) return values;
        int body = (int)headerSize;
        while (p < headerSize && values.Count < MaxColumns)
        {
            if (!Varint(b, ref p, (int)headerSize, out long serial)) break;
            long size = SerialSize(serial);
            values.Add(Value(b, body, serial, size));
            body = (int)Math.Min(int.MaxValue, body + size);
        }
        return values;
    }

    internal static long SerialSize(long serial) => serial switch
    {
        >= 12 => (serial - 12) / 2,
        5 => 6,
        6 or 7 => 8,
        >= 1 and <= 4 => serial,
        _ => 0,
    };

    private object? Value(byte[] b, int at, long serial, long size)
    {
        int available = (int)Math.Clamp(b.Length - (long)at, 0, size);
        at = Math.Min(at, b.Length);
        switch (serial)
        {
            case 0 or 10 or 11: return null;
            case 8: return 0L;
            case 9: return 1L;
            case >= 1 and <= 6:
                if (available < size) return null;
                long v = (sbyte)b[at];
                for (int i = 1; i < size; i++) v = (v << 8) | b[at + i];
                return v;
            case 7:
                return available < 8 ? null : BinaryPrimitives.ReadDoubleBigEndian(b.AsSpan(at));
            default:
                if (serial % 2 == 0) return new SqliteBlob(size, b.AsSpan(at, Math.Min(available, 64)).ToArray());
                return _text.GetString(b, at, available);
        }
    }

    /// <summary>SQLite varint: big-endian 7-bit groups, the ninth byte contributing all 8 bits.</summary>
    internal static bool Varint(byte[] b, ref int p, int end, out long value)
    {
        value = 0;
        for (int i = 0; i < 9; i++)
        {
            if (p >= end || p >= b.Length) return false;
            byte c = b[p++];
            if (i == 8) { value = (value << 8) | c; return true; }
            value = (value << 7) | (long)(c & 0x7F);
            if ((c & 0x80) == 0) return true;
        }
        return true;
    }

    internal static uint Be32(byte[] b, int at) => BinaryPrimitives.ReadUInt32BigEndian(b.AsSpan(at));

    /// <summary>Column names of a CREATE TABLE statement, with the INTEGER PRIMARY KEY column (a rowid alias) when there is one.</summary>
    public static (List<string> Columns, int RowIdAlias) Columns(string? sql)
    {
        var shape = Shape(sql);
        return ([.. shape.Columns.Select(c => c.Name)], shape.Alias);
    }

    private sealed record TableShape(List<(string Name, string Type, object? Default, char Generated)> Columns, int Alias, List<string> PrimaryKey, bool WithoutRowId);

    /// <summary>Columns with declared types, defaults and generated kinds, the rowid alias, the primary key's columns and WITHOUT ROWID, from CREATE TABLE.</summary>
    private static TableShape Shape(string? sql)
    {
        var shape = new TableShape([], -1, [], false);
        if (sql == null) return shape;
        int open = sql.IndexOf('(');
        if (open < 0) return shape;
        int depth = 0, start = open + 1, close = -1;
        char quote = '\0';
        var parts = new List<string>();
        for (int i = open; i < sql.Length; i++)
        {
            char c = sql[i];
            if (quote != '\0') { if (c == quote) quote = '\0'; continue; }
            switch (c)
            {
                case '\'' or '"' or '`': quote = c; break;
                case '[': quote = ']'; break;
                case '(': depth++; break;
                case ')':
                    if (--depth == 0) { parts.Add(sql[start..i]); close = i; i = sql.Length; }
                    break;
                case ',' when depth == 1: parts.Add(sql[start..i]); start = i + 1; break;
            }
        }
        int alias = -1;
        foreach (var raw in parts)
        {
            var part = raw.Trim();
            if (TableConstraint.IsMatch(part))
            {
                if (TablePrimaryKey.Match(part) is { Success: true } pk)
                    shape.PrimaryKey.AddRange(pk.Groups[1].Value.Split(',').Select(k => Unquote(ColumnName.Match(k.Trim()).Value)).Where(k => k.Length > 0));
                continue;
            }
            var m = ColumnName.Match(part);
            if (!m.Success) continue;
            string name = Unquote(m.Groups[1].Value);
            var rest = part[m.Length..];
            if (alias < 0 && IntegerPrimaryKey().IsMatch(rest)) alias = shape.Columns.Count;
            if (ColumnPrimaryKey.IsMatch(rest)) shape.PrimaryKey.Add(name);
            var (dflt, generated) = Clauses(rest);
            shape.Columns.Add((name, DeclaredType().Match(rest).Value.Trim(), dflt, generated));
        }
        bool withoutRowId = close > 0 && WithoutRowIdClause.IsMatch(sql[(close + 1)..]);
        // a table-level PRIMARY KEY(x) on an INTEGER column is also a rowid alias
        if (alias < 0 && !withoutRowId && shape.PrimaryKey.Count == 1)
        {
            int i = shape.Columns.FindIndex(c => c.Name.Equals(shape.PrimaryKey[0], StringComparison.OrdinalIgnoreCase));
            if (i >= 0 && shape.Columns[i].Type.Equals("INTEGER", StringComparison.OrdinalIgnoreCase)) alias = i;
        }
        return shape with { Alias = alias, WithoutRowId = withoutRowId };
    }

    /// <summary>A column definition's DEFAULT literal (null when absent or not a literal) and generated kind ('V', 'S', or '\0').</summary>
    private static (object? Default, char Generated) Clauses(string rest)
    {
        // quoted text blanked, so keywords inside strings and names are not matched
        var blank = rest.ToCharArray();
        char quote = '\0';
        for (int i = 0; i < blank.Length; i++)
        {
            char c = blank[i];
            if (quote != '\0') { if (c == quote) quote = '\0'; else blank[i] = ' '; continue; }
            if (c is '\'' or '"' or '`') quote = c;
            else if (c == '[') quote = ']';
        }
        var b = new string(blank);
        object? dflt = DefaultClause.Match(b) is { Success: true } d ? Literal(rest, d.Index + d.Length) : null;
        char generated = '\0';
        if (GeneratedClause.Match(b) is { Success: true } g)
        {
            int depth = 0, at = g.Index + g.Length - 1;
            for (; at < b.Length; at++)
                if (b[at] == '(') depth++;
                else if (b[at] == ')' && --depth == 0) break;
            generated = at < b.Length && StoredKeyword.IsMatch(b[(at + 1)..]) ? 'S' : 'V';
        }
        return (dflt, generated);
    }

    /// <summary>A literal at <paramref name="at"/> (a signed number, string, blob, NULL, TRUE or FALSE, optionally in parentheses); null otherwise.</summary>
    private static object? Literal(string s, int at)
    {
        var m = DefaultLiteral.Match(s, at);
        if (!m.Success || m.Index != at) return null;
        if (m.Groups["str"].Success) return m.Groups["str"].Value.Replace("''", "'", StringComparison.Ordinal);
        if (m.Groups["dq"].Success) return m.Groups["dq"].Value.Replace("\"\"", "\"", StringComparison.Ordinal);
        if (m.Groups["blob"].Success)
        {
            var hex = m.Groups["blob"].Value;
            if (hex.Length % 2 != 0) return null;
            var bytes = Convert.FromHexString(hex);
            return new SqliteBlob(bytes.Length, bytes[..Math.Min(bytes.Length, 64)]);
        }
        if (m.Groups["kw"].Success)
            return m.Groups["kw"].Value.ToUpperInvariant() switch { "TRUE" => 1L, "FALSE" => 0L, _ => null };
        var num = m.Groups["num"].Value.Replace(" ", "", StringComparison.Ordinal);
        bool negative = num.StartsWith('-');
        var digits = num.TrimStart('+', '-');
        var inv = CultureInfo.InvariantCulture;
        if (digits.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
            return ulong.TryParse(digits[2..], NumberStyles.HexNumber, inv, out var h) ? negative ? -(long)h : (long)h : null;
        if (!digits.Contains('.') && !digits.Contains('e') && !digits.Contains('E') && long.TryParse(num, NumberStyles.AllowLeadingSign, inv, out var l))
            return l;
        return double.TryParse(num, NumberStyles.Float, inv, out var x) ? x : null;
    }

    /// <summary>A default value converted by the column's affinity, as SQLite converts it when it reads the default.</summary>
    private static object? WithAffinity(object value, char affinity)
    {
        var inv = CultureInfo.InvariantCulture;
        switch (affinity, value)
        {
            case ('I' or 'N', string s) when long.TryParse(s.Trim(), NumberStyles.AllowLeadingSign, inv, out var l): return l;
            case ('I' or 'N', string s) when double.TryParse(s.Trim(), NumberStyles.Float, inv, out var x): return WithAffinity(x, affinity);
            case ('I' or 'N', double x) when x == Math.Floor(x) && Math.Abs(x) < 9.2e18: return (long)x;
            case ('R', long l): return (double)l;
            case ('R', string s) when double.TryParse(s.Trim(), NumberStyles.Float, inv, out var x): return x;
            case ('T', long l): return l.ToString(inv);
            case ('T', double x): return x.ToString("R", inv);
            default: return value;
        }
    }

    private static string Unquote(string name)
    {
        if (name.Length >= 2 && name[0] is '"' or '`' or '[' or '\'') return name[1..^1];
        return name;
    }

    // Schema text comes from the file: NonBacktracking matches in linear time,
    // so no match timeout. The two patterns with a lookahead are generated
    // regexes over one column definition, anchored at its start.
    [GeneratedRegex(@"^\s*INTEGER\s+(?:CONSTRAINT\s+\S+\s+)?PRIMARY\s+KEY(?!\s+DESC)", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex IntegerPrimaryKey();

    // Each word is tried once: the loop cannot fail, so it never backtracks.
    [GeneratedRegex(@"^\s*(?:(?!(?:CONSTRAINT|PRIMARY|NOT|NULL|UNIQUE|CHECK|DEFAULT|COLLATE|REFERENCES|GENERATED|AS)\b)[A-Za-z_][\w]*\s*)*(?:\([^)]*\))?", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex DeclaredType();

    private static readonly Regex TableConstraint = new(@"^(?:CONSTRAINT|PRIMARY\s+KEY|UNIQUE|CHECK|FOREIGN\s+KEY)\b", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant | RegexOptions.NonBacktracking);
    private static readonly Regex TablePrimaryKey = new(@"PRIMARY\s+KEY\s*\(([^)]*)\)", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant | RegexOptions.NonBacktracking);
    private static readonly Regex ColumnName = new(@"^(""(?:[^""]|"""")*""|`[^`]*`|\[[^\]]*\]|'[^']*'|[^\s(,]+)", RegexOptions.CultureInvariant | RegexOptions.NonBacktracking);
    private static readonly Regex ColumnPrimaryKey = new(@"\bPRIMARY\s+KEY\b", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant | RegexOptions.NonBacktracking);
    private static readonly Regex DefaultClause = new(@"\bDEFAULT\s*", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant | RegexOptions.NonBacktracking);
    private static readonly Regex DefaultLiteral = new(
        @"\(?\s*(?:'(?<str>(?:[^']|'')*)'|""(?<dq>(?:[^""]|"""")*)""|[xX]'(?<blob>[0-9a-fA-F]*)'|(?<kw>NULL|TRUE|FALSE)\b|(?<num>[+-]?\s*(?:0[xX][0-9a-fA-F]+|(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][+-]?\d+)?)))",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant | RegexOptions.NonBacktracking);
    private static readonly Regex GeneratedClause = new(@"(?:\bGENERATED\s+ALWAYS\s+)?\bAS\s*\(", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant | RegexOptions.NonBacktracking);
    private static readonly Regex StoredKeyword = new(@"^\s*STORED\b", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant | RegexOptions.NonBacktracking);
    private static readonly Regex WithoutRowIdClause = new(@"\bWITHOUT\s+ROWID\b", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant | RegexOptions.NonBacktracking);
}
