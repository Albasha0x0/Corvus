using System.Buffers.Binary;
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
/// A SQLite 3 database file read through its own B-tree reader: header, sqlite_schema, row counts and the first rows
/// of a table. No SQL is run and no native library is used; a -wal file is not read. Every walk is bounded (page visits,
/// cells, payload bytes) and a page reached twice in one walk ends it, so a malformed file gives issues, never an exception.
/// </summary>
public sealed class SqliteDatabase
{
    public int PageSize { get; private set; }
    public int ReservedBytes { get; private set; }
    /// <summary>Pages in the database: the header's count when valid, else the file length over the page size.</summary>
    public long PageCount { get; private set; }
    public long FileLength { get; private set; }
    public string TextEncoding { get; private set; } = "UTF-8";
    /// <summary>Header read/write versions 2: journal_mode=WAL.</summary>
    public bool Wal { get; private set; }
    public uint SchemaFormat { get; private set; }
    public uint FreelistPages { get; private set; }
    public uint UserVersion { get; private set; }
    public uint ApplicationId { get; private set; }
    public bool AutoVacuum { get; private set; }
    /// <summary>SQLITE_VERSION_NUMBER of the library that last wrote the file, as 3.x.y.</summary>
    public string? WriterVersion { get; private set; }
    public List<SqliteSchemaEntry> Schema { get; } = [];
    public List<string> Issues { get; } = [];

    public const int MaxPageVisits = 1_000_000;
    private const int MaxSchemaRows = 10_000;
    private const int MaxPayload = 64 * 1024;
    private const int MaxColumns = 2_000;

    private readonly byte[] _data;
    private Encoding _text = Encoding.UTF8;
    private int _usable;
    private long _visits;

    private SqliteDatabase(byte[] data) => _data = data;

    public static bool Looks(ReadOnlySpan<byte> b) => b.Length >= 100 && b[..16].SequenceEqual("SQLite format 3\0"u8);

    /// <summary>The database, or null without the SQLite magic or with an impossible page size.</summary>
    public static SqliteDatabase? Open(byte[] data, CancellationToken ct = default)
    {
        if (!Looks(data)) return null;
        var db = new SqliteDatabase(data) { FileLength = data.Length };
        int pageSize = BinaryPrimitives.ReadUInt16BigEndian(data.AsSpan(16));
        if (pageSize == 1) pageSize = 65536;
        if (pageSize < 512 || pageSize > 65536 || (pageSize & (pageSize - 1)) != 0) return null;
        db.PageSize = pageSize;
        db.ReservedBytes = data[20];
        db._usable = pageSize - db.ReservedBytes;
        if (db._usable < 480) { db.Issues.Add($"usable page size {db._usable} is below 480"); return db; }
        db.Wal = data[18] == 2 || data[19] == 2;
        uint headerPages = Be32(data, 28), changeCounter = Be32(data, 24), validFor = Be32(data, 92);
        long filePages = data.Length / pageSize;
        if (headerPages != 0 && changeCounter == validFor && headerPages <= filePages) db.PageCount = headerPages;
        else
        {
            db.PageCount = filePages;
            if (headerPages > filePages) db.Issues.Add($"header names {headerPages:N0} pages; the file holds {filePages:N0}");
        }
        if (data.Length % pageSize != 0) db.Issues.Add($"file length {data.Length:N0} is not a multiple of the page size");
        db.FreelistPages = Be32(data, 36);
        db.SchemaFormat = Be32(data, 44);
        db.AutoVacuum = Be32(data, 52) != 0;
        db.UserVersion = Be32(data, 60);
        db.ApplicationId = Be32(data, 68);
        uint version = Be32(data, 96);
        if (version is >= 3_000_000 and < 4_000_000) db.WriterVersion = $"{version / 1_000_000}.{version / 1000 % 1000}.{version % 1000}";
        (db.TextEncoding, db._text) = Be32(data, 56) switch
        {
            2 => ("UTF-16le", (Encoding)Encoding.Unicode),
            3 => ("UTF-16be", Encoding.BigEndianUnicode),
            _ => ("UTF-8", Encoding.UTF8),
        };
        db.ReadSchema(ct);
        return db;
    }

    private void ReadSchema(CancellationToken ct)
    {
        foreach (var row in Rows(1, index: false, MaxSchemaRows, ct))
        {
            var v = row.Values;
            string Text(int i) => i < v.Count && v[i] is string s ? s : "";
            long root = v.Count > 3 && v[3] is long r ? r : 0;
            Schema.Add(new SqliteSchemaEntry(Text(0), Text(1), Text(2), root, v.Count > 4 ? v[4] as string : null));
        }
    }

    /// <summary>The root page's kind: true for an index B-tree (an index or a WITHOUT ROWID table), false for a table B-tree, null when unreadable.</summary>
    public bool? IsIndexTree(long root)
    {
        if (Page(root) is not { } p) return null;
        return _data[p.Header] switch { 2 or 10 => true, 5 or 13 => false, _ => null };
    }

    /// <summary>Entries in the B-tree at <paramref name="root"/>; null when the walk ended early (issue recorded).</summary>
    public long? CountRows(long root, CancellationToken ct = default)
    {
        if (IsIndexTree(root) == null) { Issues.Add($"page {root}: not a B-tree page"); return null; }
        long count = 0;
        bool complete = Walk(root, ct, (page, type, cells) =>
        {
            if (type is 13 or 10 or 2) count += cells;
            return true;
        });
        return complete ? count : null;
    }

    /// <summary>The first <paramref name="limit"/> rows of the B-tree at <paramref name="root"/> in key order.</summary>
    public List<SqliteRow> Rows(long root, int limit, CancellationToken ct = default) =>
        IsIndexTree(root) is { } index ? Rows(root, index, limit, ct) : [];

    private List<SqliteRow> Rows(long root, bool index, int limit, CancellationToken ct)
    {
        var rows = new List<SqliteRow>();
        if (limit <= 0) return rows;
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
                if (Entry(p, cell, interiorIndex: true) is { } e) rows.Add(e);
                continue;
            }
            if (!seen.Add(pageNo)) { Issues.Add($"page {pageNo} is reached twice (a cycle)"); break; }
            if (++_visits > MaxPageVisits) { Issues.Add($"page visit limit {MaxPageVisits:N0} reached"); break; }
            byte type = _data[p.Header];
            int cells = CellCount(p);
            switch (type)
            {
                case 13 or 10:
                    for (int i = 0; i < cells && rows.Count < limit; i++)
                        if (Entry(p, i, interiorIndex: false) is { } e) rows.Add(e);
                    break;
                case 5 or 2:
                    if ((type == 2) != index) { Issues.Add($"page {pageNo}: page type {type} in a {(index ? "index" : "table")} B-tree"); return rows; }
                    stack.Push((Be32(_data, p.Header + 8), -1));
                    for (int i = cells - 1; i >= 0; i--)
                    {
                        if (CellOffset(p, i) is not { } at) continue;
                        if (type == 2) stack.Push((pageNo, i));
                        stack.Push((Be32(_data, at), -1));
                    }
                    break;
                default:
                    Issues.Add($"page {pageNo}: not a B-tree page (type {type})");
                    return rows;
            }
        }
        return rows;
    }

    /// <summary>Visits every page of a B-tree once; false when it ended early (cycle, bad page, limit), with the issue recorded.</summary>
    private bool Walk(long root, CancellationToken ct, Func<long, byte, int, bool> visit)
    {
        var seen = new HashSet<long>();
        var stack = new Stack<long>();
        stack.Push(root);
        while (stack.Count > 0)
        {
            ct.ThrowIfCancellationRequested();
            long pageNo = stack.Pop();
            if (Page(pageNo) is not { } p) { Issues.Add($"page {pageNo} is outside the file"); return false; }
            if (!seen.Add(pageNo)) { Issues.Add($"page {pageNo} is reached twice (a cycle)"); return false; }
            if (++_visits > MaxPageVisits) { Issues.Add($"page visit limit {MaxPageVisits:N0} reached"); return false; }
            byte type = _data[p.Header];
            if (type is not (2 or 5 or 10 or 13)) { Issues.Add($"page {pageNo}: not a B-tree page (type {type})"); return false; }
            int cells = CellCount(p);
            if (!visit(pageNo, type, cells)) return false;
            if (type is 2 or 5)
            {
                stack.Push(Be32(_data, p.Header + 8));
                for (int i = cells - 1; i >= 0; i--)
                    if (CellOffset(p, i) is { } at) stack.Push(Be32(_data, at));
            }
        }
        return true;
    }

    private readonly record struct PageRef(long Number, int Start, int Header);

    private PageRef? Page(long number)
    {
        if (number < 1 || number > PageCount) return null;
        long start = (number - 1) * PageSize;
        if (start + PageSize > _data.Length) return null;
        return new PageRef(number, (int)start, (int)start + (number == 1 ? 100 : 0));
    }

    /// <summary>Cells on the page, capped by what its cell pointer array can hold.</summary>
    private int CellCount(PageRef p)
    {
        int n = BinaryPrimitives.ReadUInt16BigEndian(_data.AsSpan(p.Header + 3));
        int headerSize = _data[p.Header] is 2 or 5 ? 12 : 8;
        int room = (p.Start + _usable - (p.Header + headerSize)) / 2;
        return Math.Clamp(n, 0, Math.Max(0, room));
    }

    private int? CellOffset(PageRef p, int i)
    {
        int headerSize = _data[p.Header] is 2 or 5 ? 12 : 8;
        int at = BinaryPrimitives.ReadUInt16BigEndian(_data.AsSpan(p.Header + headerSize + 2 * i));
        if (at < (p.Header - p.Start) + headerSize || at + 4 > _usable) return null;
        return p.Start + at;
    }

    /// <summary>The row of leaf cell <paramref name="i"/> (or of an interior index cell); null for an unreadable cell.</summary>
    private SqliteRow? Entry(PageRef p, int i, bool interiorIndex)
    {
        if (CellOffset(p, i) is not { } at) return null;
        int end = p.Start + _usable;
        byte type = _data[p.Header];
        bool table = type == 13;
        if (interiorIndex) at += 4;
        if (!Varint(_data, ref at, end, out long payload) || payload < 0) return null;
        long? rowid = null;
        if (table)
        {
            if (!Varint(_data, ref at, end, out long r)) return null;
            rowid = r;
        }
        var bytes = Payload(at, end, payload, table);
        return bytes == null ? null : new SqliteRow(rowid, Record(bytes));
    }

    /// <summary>The first <see cref="MaxPayload"/> bytes of a payload, following its overflow chain.</summary>
    private byte[]? Payload(int at, int end, long size, bool table)
    {
        int u = _usable;
        long x = table ? u - 35 : (u - 12) * 64 / 255 - 23;
        long m = (u - 12) * 32 / 255 - 23;
        long local = size;
        if (size > x)
        {
            long k = m + (size - m) % (u - 4);
            local = k <= x ? k : m;
        }
        if (at + local > end) return null;
        var buffer = new byte[(int)Math.Min(size, MaxPayload)];
        int take = (int)Math.Min(local, buffer.Length);
        _data.AsSpan(at, take).CopyTo(buffer);
        int filled = take;
        if (local >= size || filled >= buffer.Length) return buffer;
        if (at + local + 4 > end) return null;
        long next = Be32(_data, at + (int)local);
        long maxPages = (size - local) / (u - 4) + 1;
        for (long n = 0; filled < buffer.Length && n < maxPages; n++)
        {
            if (Page(next) is not { } o) { Issues.Add($"overflow page {next} is outside the file"); return buffer[..filled]; }
            int chunk = Math.Min(u - 4, buffer.Length - filled);
            _data.AsSpan(o.Start + 4, chunk).CopyTo(buffer.AsSpan(filled));
            filled += chunk;
            next = Be32(_data, o.Start);
        }
        return buffer[..filled];
    }

    /// <summary>Record format: a header of serial types, then the values; values past the bytes read are clipped or null.</summary>
    private List<object?> Record(byte[] b)
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

    private static long SerialSize(long serial) => serial switch
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

    private static uint Be32(byte[] b, int at) => BinaryPrimitives.ReadUInt32BigEndian(b.AsSpan(at));

    /// <summary>Column names of a CREATE TABLE statement, with the INTEGER PRIMARY KEY column (a rowid alias) when there is one.</summary>
    public static (List<string> Columns, int RowIdAlias) Columns(string? sql)
    {
        var columns = new List<string>();
        int alias = -1;
        if (sql == null) return (columns, alias);
        int open = sql.IndexOf('(');
        if (open < 0) return (columns, alias);
        int depth = 0, start = open + 1;
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
                    if (--depth == 0) { parts.Add(sql[start..i]); i = sql.Length; }
                    break;
                case ',' when depth == 1: parts.Add(sql[start..i]); start = i + 1; break;
            }
        }
        foreach (var raw in parts)
        {
            var part = raw.Trim();
            if (TableConstraint.IsMatch(part)) continue;
            var m = ColumnName.Match(part);
            if (!m.Success) continue;
            string name = m.Groups[1].Value;
            if (name.Length >= 2 && name[0] is '"' or '`' or '[') name = name[1..^1];
            if (name.Length >= 2 && name[0] == '\'') name = name[1..^1];
            if (alias < 0 && IntegerPrimaryKey.IsMatch(part[m.Length..])) alias = columns.Count;
            columns.Add(name);
        }
        return (columns, alias);
    }

    private static readonly Regex TableConstraint = new(@"^(?:CONSTRAINT|PRIMARY\s+KEY|UNIQUE|CHECK|FOREIGN\s+KEY)\b", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, RegexTimeouts.Limit);
    private static readonly Regex ColumnName = new(@"^(""(?:[^""]|"""")*""|`[^`]*`|\[[^\]]*\]|'[^']*'|[^\s(,]+)", RegexOptions.CultureInvariant, RegexTimeouts.Limit);
    private static readonly Regex IntegerPrimaryKey = new(@"^\s*INTEGER\s+(?:CONSTRAINT\s+\S+\s+)?PRIMARY\s+KEY(?!\s+DESC)", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, RegexTimeouts.Limit);
}
