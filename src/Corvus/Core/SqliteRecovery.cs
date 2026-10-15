using System.Buffers.Binary;

namespace Corvus.Core;

/// <summary>
/// A deleted-row candidate: the table it fits (null when several or none fit), its rowid when the cell header survived,
/// its values in declaration order, where it was found and how: a whole cell (cell), a record whose cell header was
/// overwritten (record), or a record whose header size and first types were overwritten by a freeblock and are inferred
/// (record, header inferred).
/// </summary>
public sealed record SqliteRecoveredRow(string? Table, long? RowId, IReadOnlyList<object?> Values, string Source, string Method);

/// <summary>
/// Deleted-row carving: what SQLite leaves behind when rows are deleted and secure_delete is off. Freed cells inside live
/// table pages (freeblocks, whose first 4 bytes SQLite overwrites, and the unallocated gap), freelist pages (trunk tails and
/// whole leaf pages), and -wal frames that are not the applied copy of their page (superseded, uncommitted, stale). Every
/// candidate is validated by its record header (serial types against the table's column count and affinities, body within
/// the free region, text that decodes) and dropped when it equals a live row.
/// </summary>
public sealed partial class SqliteDatabase
{
    public const int MaxRecovered = 10_000;

    private sealed class Carving(List<SqliteTable> tables)
    {
        public List<SqliteTable> Tables { get; } = tables;
        public Dictionary<string, HashSet<long>> Live { get; } = new(StringComparer.Ordinal);
        public HashSet<(string?, long)> Found { get; } = [];
        public List<SqliteRecoveredRow> Rows { get; } = [];
        public bool Full => Rows.Count >= MaxRecovered;
    }

    /// <summary>Deleted-row candidates, in page order; <paramref name="notes"/> gets what was scanned and any cap reached.</summary>
    public List<SqliteRecoveredRow> Recover(List<string> notes, CancellationToken ct = default)
    {
        var tables = Tables().Where(t => !t.WithoutRowId && t.Columns.Count > 0).ToList();
        var carving = new Carving(tables);
        var owner = new Dictionary<long, SqliteTable>();
        foreach (var t in tables)
        {
            var hashes = carving.Live[t.Name] = [];
            foreach (var leaf in LeafPages(t.RootPage, ct))
            {
                owner[leaf] = t;
                if (Page(leaf) is not { Type: 13 } p) continue;
                for (int i = 0; i < CellCount(p); i++)
                    if (Entry(p, i, interiorIndex: false) is { } row) hashes.Add(Hash(row.Values));
            }
        }
        int livePages = 0, freePages = 0, frames = 0;
        foreach (var (pageNo, t) in owner.OrderBy(o => o.Key))
        {
            ct.ThrowIfCancellationRequested();
            if (carving.Full || Page(pageNo) is not { Type: 13 } p) continue;
            livePages++;
            CarveFree(p.Data, p.Header, [t], t, $"page {pageNo}", carving, ct);
        }
        var (trunks, leaves) = Freelist(ct, notes);
        foreach (var trunk in trunks)
        {
            if (carving.Full || Raw(trunk) is not { } d) continue;
            freePages++;
            int used = 8 + 4 * (int)Math.Min(Be32(d, 4), (uint)(_usable / 4));
            Scan(d, Math.Min(used, _usable), _usable, tables, null, $"freelist trunk page {trunk}", carving, ct);
        }
        foreach (var leaf in leaves)
        {
            if (carving.Full || Raw(leaf) is not { } d) continue;
            freePages++;
            CarvePage(d, leaf == 1 ? 100 : 0, owner.GetValueOrDefault(leaf), $"freelist page {leaf}", carving, ct);
        }
        if (WalLog != null && _walFile != null)
            foreach (var f in WalLog.Frames.Where(f => f.State != "applied"))
            {
                ct.ThrowIfCancellationRequested();
                if (carving.Full) break;
                var d = new byte[PageSize];
                if (_walFile.Read(WalLog.DataOffset(f.Index), d) < PageSize) continue;
                frames++;
                CarvePage(d, f.Page == 1 ? 100 : 0, owner.GetValueOrDefault(f.Page), $"wal frame {f.Index} (page {f.Page}, {f.State})", carving, ct);
            }
        notes.Add($"scanned {livePages:N0} live table pages, {freePages:N0} freelist pages and {frames:N0} WAL frames that are not applied");
        if (carving.Full) notes.Add($"stopped at {MaxRecovered:N0} candidates");
        if (Tables().Any(t => t.WithoutRowId)) notes.Add("WITHOUT ROWID tables (index B-trees) are not carved");
        return carving.Rows;
    }

    /// <summary>The freelist: trunk pages and the leaf pages they list (bounded, cycles ended).</summary>
    public (List<long> Trunks, List<long> Leaves) Freelist(CancellationToken ct, List<string>? notes = null)
    {
        var trunks = new List<long>();
        var leaves = new List<long>();
        var seen = new HashSet<long>();
        for (long t = FirstFreelistTrunk; t != 0; )
        {
            ct.ThrowIfCancellationRequested();
            if (t > PageCount || !seen.Add(t) || Raw(t) is not { } d) { notes?.Add($"freelist trunk page {t} is outside the file or reached twice"); break; }
            trunks.Add(t);
            uint n = Math.Min(Be32(d, 4), (uint)(_usable / 4 - 2));
            for (int i = 0; i < n; i++)
            {
                long leaf = Be32(d, 8 + 4 * i);
                if (leaf >= 1 && leaf <= PageCount && seen.Add(leaf)) leaves.Add(leaf);
            }
            if (trunks.Count + leaves.Count > PageCount) break;
            t = Be32(d, 0);
        }
        return (trunks, leaves);
    }

    /// <summary>A page that is not part of a live tree: its cells when it still reads as a table leaf, then its free space.</summary>
    private void CarvePage(byte[] d, int header, SqliteTable? owner, string source, Carving carving, CancellationToken ct)
    {
        var p = new PageRef(0, d, header);
        int cells = p.Type == 13 ? CellCount(p) : 0;
        // a page off every tree belonged to the table its surviving cells fit
        owner ??= Enumerable.Range(0, cells).Select(i => CellOffset(p, i) is { } at && CellAt(d, at, table: true) is { } row ? Match(carving.Tables, row.Values) : null)
            .Where(m => m is { Unique: true }).GroupBy(m => m!.Value.Table).OrderByDescending(g => g.Count()).FirstOrDefault()?.Key;
        var tables = owner != null ? [owner, .. carving.Tables.Where(t => t != owner)] : carving.Tables;
        if (p.Type == 13)
        {
            for (int i = 0; i < cells && !carving.Full; i++)
            {
                if (CellOffset(p, i) is not { } at || CellAt(d, at, table: true) is not { } row) continue;
                if (Match(tables, row.Values) is { } match) Add(carving, Attributed(match, owner), row.RowId, row.Values, $"{source} cell {i}", "cell");
            }
            CarveFree(d, header, tables, owner, source, carving, ct);
        }
        else Scan(d, header, _usable, tables, owner, source, carving, ct);
    }

    /// <summary>A table leaf's free space: each freeblock (its first 4 bytes overwritten) and the gap before the cell content.</summary>
    private void CarveFree(byte[] d, int header, List<SqliteTable> tables, SqliteTable? owner, string source, Carving carving, CancellationToken ct)
    {
        int cells = BinaryPrimitives.ReadUInt16BigEndian(d.AsSpan(header + 3));
        int gapStart = header + 8 + 2 * cells;
        int content = BinaryPrimitives.ReadUInt16BigEndian(d.AsSpan(header + 5));
        if (content == 0) content = 65536;
        if (gapStart < content && content <= _usable) Scan(d, gapStart, content, tables, owner, $"{source} unallocated", carving, ct);
        var seen = new HashSet<int>();
        for (int fb = BinaryPrimitives.ReadUInt16BigEndian(d.AsSpan(header + 1)); fb != 0 && seen.Add(fb) && !carving.Full;)
        {
            if (fb < gapStart || fb + 4 > _usable) break;
            int size = BinaryPrimitives.ReadUInt16BigEndian(d.AsSpan(fb + 2));
            int end = Math.Min(fb + size, _usable);
            var at = $"{source} freeblock at 0x{fb:X}";
            int from = Inferred(d, fb, end, tables, owner, at, carving) ?? fb + 4;
            Scan(d, from, end, tables, owner, at, carving, ct);
            fb = BinaryPrimitives.ReadUInt16BigEndian(d.AsSpan(fb));
        }
    }

    /// <summary>
    /// The first cell of a freeblock lost its first 4 bytes (payload length, rowid, and the record header's start when those
    /// varints are short). Types still in place are read from byte 4; the header size, and a lost first type, are inferred
    /// from the table's columns (a rowid alias is always NULL) or from the freeblock's size. The record's end, or null.
    /// </summary>
    private int? Inferred(byte[] d, int fb, int end, List<SqliteTable> tables, SqliteTable? owner, string source, Carving carving)
    {
        // hypotheses by cell prefix length: 4 or more (the header intact at byte 4), 3 (the header size lost), 2 (the header size and first type lost)
        var found = new List<(SqliteTable Table, List<object?> Values, int End, string Method)>();
        int at = fb + 4;
        if (Varint(d, ref at, end, out long headerSize) && headerSize >= 2 && Parse(d, at, fb + 4 + (int)headerSize, -1, [], end) is { } r4
            && Match(tables, r4.Values) is { } m4)
            found.Add((m4.Table, r4.Values, r4.End, "record"));
        foreach (var t in tables)
        {
            int n = t.Columns.Count;
            if (Parse(d, fb + 4, -1, n, [], end) is { } r3 && Fits(t, r3.Values)) found.Add((t, r3.Values, r3.End, "record, header inferred"));
            foreach (var first in t.RowIdAlias == 0 ? [0L] : FirstTypes(d, fb, end, n))
                if (Parse(d, fb + 4, -1, n - 1, [first], end) is { } r2 && Fits(t, r2.Values)) found.Add((t, r2.Values, r2.End, "record, header inferred"));
        }
        if (found.Count == 0) return null;
        // a single freed cell fills its freeblock exactly
        var best = found.FirstOrDefault(f => f.End == end);
        if (best.Table == null) best = found[0];
        bool sure = best.Table == owner || found.Select(f => f.Table).Distinct().Count() == 1;
        Add(carving, sure ? best.Table : null, null, best.Values, source, best.Method);
        return best.End;
    }

    /// <summary>Serial types for a lost first column whose size fills the freeblock left by one cell of 2 prefix bytes.</summary>
    private List<long> FirstTypes(byte[] d, int fb, int end, int n)
    {
        if (n < 1) return [];
        var rest = new List<long>();
        int p = fb + 4;
        long body = 0;
        for (int i = 1; i < n; i++)
        {
            if (!Varint(d, ref p, end, out long s) || s is 10 or 11 || s < 0) return [];
            rest.Add(s);
            body += SerialSize(s);
        }
        long size0 = end - fb - 2 - (1 + 1 + (p - (fb + 4))) - body;
        return size0 switch
        {
            < 0 => [],
            0 => [0, 8, 9],
            1 or 2 or 3 or 4 => [size0],
            6 => [5],
            8 => [6, 7],
            _ => [size0 * 2 + 13, size0 * 2 + 12],
        };
    }

    /// <summary>Records from <paramref name="from"/> to <paramref name="end"/>: tried at every byte, skipped past each one found.</summary>
    private void Scan(byte[] d, int from, int end, List<SqliteTable> tables, SqliteTable? owner, string source, Carving carving, CancellationToken ct)
    {
        for (int p = Math.Max(0, from); p < end - 1 && !carving.Full;)
        {
            ct.ThrowIfCancellationRequested();
            int at = p;
            if (!Varint(d, ref at, end, out long headerSize) || headerSize < 2 || headerSize > Math.Min(end - p, 9 + 9 * MaxColumns)
                || Parse(d, at, p + (int)headerSize, -1, [], end) is not { } r || Match(tables, r.Values) is not { } match)
            {
                // an earlier freeblock absorbed into free space keeps its overwritten start: the types may begin here
                if (Headless(d, p, end, tables) is { } h)
                {
                    Add(carving, h.Table, null, h.Values, source, "record, header inferred");
                    p = h.End;
                }
                else p++;
                continue;
            }
            var (rowid, method) = CellHeader(d, from, p, r.End - p);
            Add(carving, Attributed(match, owner), rowid, r.Values, source, method);
            p = r.End;
        }
    }

    /// <summary>
    /// A record whose header size byte (and, before a rowid alias, first type) was overwritten: a table's serial types read
    /// from <paramref name="p"/>. Only a unique fit counts.
    /// </summary>
    private (SqliteTable Table, List<object?> Values, int End)? Headless(byte[] d, int p, int end, List<SqliteTable> tables)
    {
        (SqliteTable, List<object?>, int)? found = null;
        foreach (var t in tables)
        {
            int n = t.Columns.Count;
            var r = Parse(d, p, -1, n, [], end) is { } r3 && Fits(t, r3.Values) ? r3
                : t.RowIdAlias == 0 && Parse(d, p, -1, n - 1, [0], end) is { } r2 && Fits(t, r2.Values) ? r2 : ((List<object?>, int)?)null;
            if (r is not { } hit) continue;
            if (found != null) return null;
            found = (t, hit.Item1, hit.Item2);
        }
        return found;
    }

    /// <summary>The rowid when the payload length and rowid varints before the record survive (and agree with its length).</summary>
    private static (long? RowId, string Method) CellHeader(byte[] d, int from, int record, int length)
    {
        for (int r = 1; r <= 9; r++)
            for (int l = 1; l <= 3; l++)
            {
                int at = record - r - l;
                if (at < from) continue;
                int p = at;
                if (!Varint(d, ref p, record, out long payload) || p - at != l || payload != length) continue;
                if (!Varint(d, ref p, record, out long rowid) || p != record || rowid < 1) continue;
                return (rowid, "cell");
            }
        return (null, "record");
    }

    /// <summary>
    /// A record whose serial types start at <paramref name="typesAt"/>: up to <paramref name="headerEnd"/> when the header
    /// size is known, else exactly <paramref name="count"/> types; <paramref name="leading"/> are types assumed before them.
    /// The values and the record's end, or null when it is not a well-formed record inside the region.
    /// </summary>
    private (List<object?> Values, int End)? Parse(byte[] d, int typesAt, int headerEnd, int count, long[] leading, int end)
    {
        var types = new List<long>(leading);
        int p = typesAt;
        if (headerEnd >= 0)
        {
            if (headerEnd > end) return null;
            while (p < headerEnd)
            {
                if (!Varint(d, ref p, headerEnd, out long s) || types.Count >= MaxColumns) return null;
                types.Add(s);
            }
            if (p != headerEnd) return null;
        }
        else
        {
            for (int i = 0; i < count; i++)
            {
                if (!Varint(d, ref p, end, out long s)) return null;
                types.Add(s);
            }
        }
        if (types.Count == 0 || types.All(s => s == 0)) return null;
        long body = 0;
        foreach (var s in types)
        {
            if (s is 10 or 11 || s < 0) return null;
            body += SerialSize(s);
        }
        if (p + body > end) return null;
        var values = new List<object?>(types.Count);
        long at = p;
        foreach (var s in types)
        {
            long size = SerialSize(s);
            values.Add(Value(d, (int)at, s, size));
            at += size;
        }
        return (values, (int)at);
    }

    /// <summary>The first table whose shape the values fit (column count, rowid alias NULL, affinities, text that decodes).</summary>
    private static (SqliteTable Table, bool Unique)? Match(List<SqliteTable> tables, IReadOnlyList<object?> values)
    {
        SqliteTable? first = null;
        int fits = 0;
        foreach (var t in tables)
            if (Fits(t, values)) { first ??= t; fits++; }
        return first == null ? null : (first, fits == 1);
    }

    /// <summary>The table a match is credited to: the only one it fits, or the page's owner when that is one it fits.</summary>
    private static SqliteTable? Attributed((SqliteTable Table, bool Unique) match, SqliteTable? owner) => match.Unique || match.Table == owner ? match.Table : null;

    private static bool Fits(SqliteTable t, IReadOnlyList<object?> values)
    {
        if (values.Count != t.Columns.Count) return false;
        if (t.RowIdAlias >= 0 && values[t.RowIdAlias] != null) return false;
        bool any = false;
        for (int i = 0; i < values.Count; i++)
        {
            var v = values[i];
            if (v != null && i != t.RowIdAlias) any = true;
            bool ok = (v, t.Affinities[i]) switch
            {
                (null, _) => true,
                (string s, var a) => a is not ('I' or 'R') && Plausible(s),
                (long or double, 'T') => false,
                (SqliteBlob, not 'B') => false, // a blob in a typed column is possible but rare: carving keeps to the likely
                _ => true,
            };
            if (!ok) return false;
        }
        return any;
    }

    /// <summary>Text that decoded cleanly: no replacement characters, no control characters but tab and line ends.</summary>
    private static bool Plausible(string s)
    {
        foreach (var c in s)
            if (c == '�' || (c < 0x20 && c is not ('\t' or '\n' or '\r'))) return false;
        return true;
    }

    private void Add(Carving carving, SqliteTable? table, long? rowid, IReadOnlyList<object?> stored, string source, string method)
    {
        var hash = Hash(stored);
        if (table != null && carving.Live.TryGetValue(table.Name, out var live) && live.Contains(hash)) return;
        if (!carving.Found.Add((table?.Name, hash))) return;
        var values = table != null ? table.Shape(new SqliteRow(rowid, stored)) : [.. stored];
        carving.Rows.Add(new SqliteRecoveredRow(table?.Name, rowid, values, source, method));
    }

    /// <summary>A hash of a record's values (blobs by length and first bytes).</summary>
    private static long Hash(IReadOnlyList<object?> values)
    {
        var h = new HashCode();
        h.Add(values.Count);
        foreach (var v in values)
            switch (v)
            {
                case SqliteBlob b: h.Add(b.Length); h.AddBytes(b.Head); break;
                case double x: h.Add(BitConverter.DoubleToInt64Bits(x)); break;
                default: h.Add(v); break;
            }
        return h.ToHashCode();
    }
}
