using System.Buffers.Binary;

namespace Corvus.Core;

/// <summary>A deleted-row candidate; Table is null unless exactly one fits, RowId null unless the cell header survived.</summary>
/// <remarks>Method: cell, record (cell header lost) or record, header inferred (header overwritten by a freeblock).</remarks>
public sealed record SqliteRecoveredRow(string? Table, long? RowId, IReadOnlyList<object?> Values, string Source, string Method);

/// <summary>Deleted-row carving from free space, freelist pages and unapplied -wal frames when secure_delete is off.</summary>
/// <remarks>Each candidate is validated against the table's columns and affinities and dropped when it equals a live row.</remarks>
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
        public int Spilled { get; set; }
    }

    /// <summary>The fewest fields a live record of each table holds (fewer than its stored columns after ALTER TABLE ADD COLUMN).</summary>
    private readonly Dictionary<string, int> _shortest = new(StringComparer.Ordinal);

    /// <summary>Per table, what its live rows hold in each stored field: the integer range and the text length range.</summary>
    private readonly Dictionary<string, Profile> _profiles = new(StringComparer.Ordinal);

    private sealed class Profile(int fields)
    {
        private readonly (long Min, long Max)[] _ints = [.. Enumerable.Repeat((long.MaxValue, long.MinValue), fields)];
        private readonly (long Min, long Max)[] _texts = [.. Enumerable.Repeat((long.MaxValue, long.MinValue), fields)];

        public void Add(IReadOnlyList<object?> values)
        {
            for (int i = 0; i < values.Count && i < _ints.Length; i++)
                switch (values[i])
                {
                    case long l: _ints[i] = (Math.Min(_ints[i].Min, l), Math.Max(_ints[i].Max, l)); break;
                    case string s: _texts[i] = (Math.Min(_texts[i].Min, s.Length), Math.Max(_texts[i].Max, s.Length)); break;
                }
        }

        /// <summary>How many of the first <paramref name="count"/> values lie within what the live rows hold.</summary>
        public int Score(IReadOnlyList<object?> values, int count)
        {
            int score = 0;
            for (int i = 0; i < count && i < values.Count && i < _ints.Length; i++)
                if (values[i] switch { long l => l >= _ints[i].Min && l <= _ints[i].Max, string s => s.Length >= _texts[i].Min && s.Length <= _texts[i].Max, _ => false })
                    score++;
            return score;
        }
    }

    /// <summary>Deleted-row candidates, in page order; <paramref name="notes"/> gets what was scanned and any cap reached.</summary>
    public List<SqliteRecoveredRow> Recover(List<string> notes, CancellationToken ct = default)
    {
        var tables = Tables().Where(t => t.StoredOrder.Count > 0).ToList();
        var carving = new Carving(tables);
        var owner = new Dictionary<long, SqliteTable>();
        _shortest.Clear();
        _profiles.Clear();
        foreach (var t in tables)
        {
            var hashes = carving.Live[t.Name] = [];
            int shortest = t.StoredOrder.Count;
            var profile = _profiles[t.Name] = new Profile(t.StoredOrder.Count);
            foreach (var pageNo in TreePages(t.RootPage, ct))
            {
                if (Page(pageNo) is not { } p) continue;
                bool leaf = p.Type == (t.WithoutRowId ? 10 : 13);
                if (leaf) owner[pageNo] = t;
                // A WITHOUT ROWID table keeps whole rows in its interior cells too.
                if (!leaf && !(t.WithoutRowId && p.Type == 2)) continue;
                for (int i = 0; i < CellCount(p); i++)
                    if (Entry(p, i, interiorIndex: !leaf) is { } row)
                    {
                        hashes.Add(Hash(row.Values));
                        profile.Add(row.Values);
                        if (row.Values.Count > 0) shortest = Math.Min(shortest, row.Values.Count);
                    }
            }
            _shortest[t.Name] = shortest;
        }
        int livePages = 0, freePages = 0, frames = 0;
        foreach (var (pageNo, t) in owner.OrderBy(o => o.Key))
        {
            ct.ThrowIfCancellationRequested();
            if (carving.Full || Page(pageNo) is not { Type: 13 or 10 } p) continue;
            livePages++;
            CarveFree(p.Data, p.Header, [t], t, $"page {pageNo}", carving, ct);
        }
        var (trunks, leaves) = Freelist(ct, notes);
        foreach (var trunk in trunks)
        {
            if (carving.Full || Raw(trunk) is not { } d) continue;
            freePages++;
            int used = 8 + 4 * (int)Math.Min(Be32(d, 4), (uint)(_usable / 4));
            Scan(d, Math.Min(used, _usable), _usable, tables, null, $"freelist trunk page {trunk}", carving, ct, headless: false);
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
        if (carving.Spilled > 0) notes.Add($"{carving.Spilled:N0} records read on through their overflow pages");
        if (carving.Full) notes.Add($"stopped at {MaxRecovered:N0} candidates");
        if (tables.Any(t => t.Generated.Values.Contains('V'))) notes.Add("VIRTUAL generated columns are computed, not stored: they read NULL");
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

    /// <summary>Every page of a B-tree, interior and leaf (bounded like every walk).</summary>
    private List<long> TreePages(long root, CancellationToken ct)
    {
        var pages = new List<long>();
        var seen = new HashSet<long>();
        var stack = new Stack<long>();
        stack.Push(root);
        while (stack.Count > 0)
        {
            ct.ThrowIfCancellationRequested();
            long pageNo = stack.Pop();
            if (Page(pageNo) is not { } p || !seen.Add(pageNo) || ++_visits > MaxPageVisits) break;
            pages.Add(pageNo);
            if (p.Type is 5 or 2)
                foreach (var c in Children(p)) stack.Push(c);
            else if (p.Type is not (13 or 10)) break;
        }
        return pages;
    }

    /// <summary>Carves a page off the live trees: its cells while it reads as a leaf, then its free space.</summary>
    private void CarvePage(byte[] d, int header, SqliteTable? owner, string source, Carving carving, CancellationToken ct)
    {
        var p = new PageRef(0, d, header);
        bool leaf = p.Type is 13 or 10, rowid = p.Type == 13;
        var kind = leaf ? carving.Tables.Where(t => t.WithoutRowId != rowid).ToList() : carving.Tables;
        if (owner != null && !kind.Contains(owner)) owner = null;
        int cells = leaf ? CellCount(p) : 0;
        // A page off every tree belonged to the table its surviving cells fit.
        owner ??= Enumerable.Range(0, cells).Select(i => CellOffset(p, i) is { } at && CellAt(d, at, table: rowid) is { } row ? Match(kind, row.Values) : null)
            .Where(m => m is { Unique: true }).GroupBy(m => m!.Value.Table).OrderByDescending(g => g.Count()).FirstOrDefault()?.Key;
        var tables = owner != null ? [owner, .. kind.Where(t => t != owner)] : kind;
        if (tables.Count == 0) return;
        if (leaf)
        {
            for (int i = 0; i < cells && !carving.Full; i++)
            {
                if (CellOffset(p, i) is not { } at || CellAt(d, at, table: rowid) is not { } row) continue;
                if (Match(tables, row.Values) is { } match) Add(carving, Attributed(match, owner), row.RowId, row.Values, $"{source} cell {i}", "cell");
            }
            CarveFree(d, header, tables, owner, source, carving, ct);
        }
        else Scan(d, header, _usable, tables, owner, source, carving, ct, headless: false);
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
            var stale = StaleStarts(d, fb, end);
            int from = Inferred(d, fb, end, stale, tables, owner, at, carving) ?? fb + 4;
            Scan(d, from, end, tables, owner, at, carving, ct, stale);
            fb = BinaryPrimitives.ReadUInt16BigEndian(d.AsSpan(fb));
        }
    }

    /// <summary>Starts of earlier freeblocks absorbed into this one, found by their surviving 4-byte headers.</summary>
    private SortedSet<int> StaleStarts(byte[] d, int fb, int end)
    {
        var starts = new SortedSet<int>();
        for (int q = fb + 5; q + 4 <= end; q++)
        {
            int next = BinaryPrimitives.ReadUInt16BigEndian(d.AsSpan(q)), size = BinaryPrimitives.ReadUInt16BigEndian(d.AsSpan(q + 2));
            if (size >= 4 && q + size <= end && (next == 0 || (next >= q + size && next < _usable))) starts.Add(q);
        }
        return starts;
    }

    /// <summary>A freeblock's first cell with its lost 4 bytes inferred from the table or cell size; the record's end, or null.</summary>
    private int? Inferred(byte[] d, int fb, int end, SortedSet<int> stale, List<SqliteTable> tables, SqliteTable? owner, string source, Carving carving)
    {
        var ends = new List<int> { end };
        // The first cell ends at the nearest.
        if (fb + 5 <= end - 1) ends.AddRange(stale.GetViewBetween(fb + 5, end - 1).Take(3));
        // Cell prefix lengths tried: 4+ (header intact), 3 (header size lost), 2 (and first type), 1 (WITHOUT ROWID, two types).
        var found = new List<(SqliteTable Table, List<object?> Values, int End, string Method)>();
        int at = fb + 4;
        if (Varint(d, ref at, end, out long headerSize) && headerSize >= 2 && Parse(d, at, fb + 4 + (int)headerSize, -1, [], end) is { } r4
            && Match(tables, r4.Values) is { } m4)
            found.Add((m4.Table, r4.Values, r4.End, "record"));
        foreach (var t in tables)
            for (int n = Shortest(t); n <= t.StoredOrder.Count; n++)
            {
                if (Parse(d, fb + 4, -1, n, [], end) is { } r3 && Fits(t, r3.Values)) found.Add((t, r3.Values, r3.End, "record, header inferred"));
                else if (Spill(d, fb + 3, fb + 4, -1, n, end, [t]) is { } s3) found.Add((t, s3.Values, s3.End, "record, header inferred, overflow pages"));
                foreach (var e in ends)
                {
                    foreach (var first in AliasFirst(t) ? [0L] : FirstTypes(d, fb, e, n))
                        if (Parse(d, fb + 4, -1, n - 1, [first], e) is { } r2 && (e == end || r2.End == e) && Fits(t, r2.Values))
                            found.Add((t, r2.Values, r2.End, "record, header inferred"));
                    if (t.WithoutRowId && FirstTwo(d, fb, e, t, n) is { } r1) found.Add((t, r1.Values, e, "record, header inferred"));
                }
            }
        if (found.Count == 0) return null;
        // A single freed cell fills its freeblock exactly, or reaches the next absorbed one.
        var best = found.FirstOrDefault(f => f.End == end || stale.Contains(f.End));
        if (best.Table == null) best = found[0];
        bool sure = best.Table == owner || found.Select(f => f.Table).Distinct().Count() == 1;
        Add(carving, sure ? best.Table : null, null, best.Values, source, best.Method);
        return best.End;
    }

    /// <summary>A WITHOUT ROWID record with its first two types lost; counts only when one split fits within live row values.</summary>
    private (List<object?> Values, int End)? FirstTwo(byte[] d, int fb, int end, SqliteTable t, int n)
    {
        if (n < 2) return null;
        int p = fb + 4;
        long body = 0;
        for (int i = 2; i < n; i++)
        {
            if (!Varint(d, ref p, end, out long s) || s is 10 or 11 || s < 0) return null;
            body += SerialSize(s);
        }
        long both = end - p - body;
        // A payload under 128 bytes: one-byte types.
        if (both < 0 || both > 2 * 57) return null;
        var profile = _profiles.GetValueOrDefault(t.Name);
        (List<object?> Values, int End)? found = null;
        int best = -1;
        bool tie = false;
        for (long size1 = 0; size1 <= both; size1++)
            foreach (var t1 in TypesOfSize(size1))
                foreach (var t0 in TypesOfSize(both - size1))
                {
                    if (Parse(d, fb + 4, -1, n - 2, [t0, t1], end) is not { } r || r.End != end || !Fits(t, r.Values)
                        || !Shortest(r.Values[0], t0) || !Shortest(r.Values[1], t1)) continue;
                    int score = profile?.Score(r.Values, 2) ?? 0;
                    if (score == best) tie = true;
                    else if (score > best) (best, found, tie) = (score, r, false);
                }
        return tie ? null : found;
    }

    /// <summary>One-byte serial types whose value takes <paramref name="size"/> bytes.</summary>
    private static IEnumerable<long> TypesOfSize(long size)
    {
        switch (size)
        {
            case 0: yield return 0; yield return 8; yield return 9; break;
            case >= 1 and <= 4: yield return size; break;
            case 6: yield return 5; break;
            case 8: yield return 6; yield return 7; break;
        }
        if (size <= 57) { yield return size * 2 + 13; yield return size * 2 + 12; }
    }

    /// <summary>Whether an integer is stored in the shortest serial type for its value (SQLite never writes a longer one).</summary>
    private static bool Shortest(object? v, long serial)
    {
        if (v is not long x || serial is < 1 or > 6) return true;
        long need = x is 0 or 1 ? 1 : x is >= -128 and <= 127 ? 1 : x is >= -32768 and <= 32767 ? 2 : x is >= -8388608 and <= 8388607 ? 3
            : x is >= int.MinValue and <= int.MaxValue ? 4 : x is >= -140737488355328 and <= 140737488355327 ? 5 : 6;
        return serial == need;
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

    /// <summary>Records tried at every byte in the range; headless records only with <paramref name="headless"/> or after a found one.</summary>
    private void Scan(byte[] d, int from, int end, List<SqliteTable> tables, SqliteTable? owner, string source, Carving carving, CancellationToken ct,
        SortedSet<int>? stale = null, bool headless = true)
    {
        // A record's header holds one type per stored field: its size bounds the field count.
        int fewest = tables.Count == 0 ? 0 : tables.Min(Shortest), most = tables.Count == 0 ? 0 : tables.Max(t => t.StoredOrder.Count);
        // The end of the last record found.
        int last = int.MinValue / 2;
        for (int p = Math.Max(0, from); p < end - 1 && !carving.Full;)
        {
            ct.ThrowIfCancellationRequested();
            // A freeblock absorbed into this one: its first cell lost 4 bytes like a freeblock's.
            if (stale != null && stale.Contains(p)
                && Inferred(d, p, Math.Min(p + BinaryPrimitives.ReadUInt16BigEndian(d.AsSpan(p + 2)), end), stale, tables, owner, source, carving) is { } next)
            {
                p = next;
                continue;
            }
            int at = p;
            bool header = Varint(d, ref at, end, out long headerSize) && headerSize >= 2 && headerSize <= Math.Min(end - p, 9 + 9 * MaxColumns)
                && headerSize >= at - p + fewest && headerSize <= at - p + 9L * most;
            if (header && Spill(d, p, at, p + (int)headerSize, -1, end, tables) is { } s)
            {
                carving.Spilled++;
                Add(carving, Attributed(s.Match, owner), null, s.Values, source, "record, overflow pages");
                p = last = s.End;
                continue;
            }
            if (!header || Parse(d, at, p + (int)headerSize, -1, [], end) is not { } r || Match(tables, r.Values) is not { } match)
            {
                // An earlier freeblock absorbed into free space keeps its overwritten start: the types may begin here.
                if ((headless || p == last + 4) && Headless(d, p, end, tables) is { } h)
                {
                    Add(carving, h.Table, null, h.Values, source, "record, header inferred");
                    p = last = h.End;
                }
                else p++;
                continue;
            }
            var (rowid, method) = CellHeader(d, from, p, r.End - p, match.Table.WithoutRowId);
            Add(carving, Attributed(match, owner), rowid, r.Values, source, method);
            p = last = r.End;
        }
    }

    /// <summary>A freed record read on through its overflow chain; the values, matched table and cell end, or null.</summary>
    private ((SqliteTable Table, bool Unique) Match, List<object?> Values, int End)? Spill(byte[] d, int start, int typesAt, int headerEnd, int count,
        int end, List<SqliteTable> tables)
    {
        if (headerEnd > end) return null;
        var types = new List<long>();
        long body = 0;
        int p = typesAt;
        while (headerEnd >= 0 ? p < headerEnd : types.Count < count)
        {
            if (!Varint(d, ref p, headerEnd >= 0 ? headerEnd : end, out long s) || s is 10 or 11 || s < 0 || types.Count >= MaxColumns) return null;
            types.Add(s);
            body += SerialSize(s);
        }
        headerEnd = p;
        long size = headerEnd - start + body;
        if (types.Count == 0 || start + size <= end) return null;
        foreach (bool rowid in (bool[])[true, false])
        {
            var kind = tables.Where(t => t.WithoutRowId != rowid && types.Count <= t.StoredOrder.Count && types.Count >= Shortest(t)).ToList();
            if (kind.Count == 0) continue;
            long local = Local(size, rowid);
            if (local >= size || local < headerEnd - start || start + local + 4 > end) continue;
            long first = Be32(d, start + (int)local);
            if (first < 1 || first > PageCount) continue;
            if (Payload(d, start, size, rowid, carved: true) is not { } payload) continue;
            var values = new List<object?>(types.Count);
            long at = headerEnd - start;
            foreach (var s in types)
            {
                long n = SerialSize(s);
                values.Add(Value(payload, (int)Math.Min(at, int.MaxValue), s, n));
                at += n;
            }
            if (Match(kind, values) is { } match) return (match, values, start + (int)local + 4);
        }
        return null;
    }

    /// <summary>The fewest stored fields a record of the table can hold: its shortest live record (all its stored columns when none is shorter).</summary>
    private int Shortest(SqliteTable t) => _shortest.GetValueOrDefault(t.Name, t.StoredOrder.Count);

    /// <summary>Whether the table's first stored column is its rowid alias (stored as NULL).</summary>
    private static bool AliasFirst(SqliteTable t) => t.RowIdAlias >= 0 && t.StoredOrder.Count > 0 && t.StoredOrder[0] == t.RowIdAlias;

    /// <summary>A record with its header size byte overwritten, read from <paramref name="p"/>; only a unique fit counts.</summary>
    private (SqliteTable Table, List<object?> Values, int End)? Headless(byte[] d, int p, int end, List<SqliteTable> tables)
    {
        (SqliteTable, List<object?>, int)? found = null;
        foreach (var t in tables)
            for (int n = Shortest(t); n <= t.StoredOrder.Count; n++)
            {
                var r = Parse(d, p, -1, n, [], end) is { } r3 && Fits(t, r3.Values) ? r3
                    : AliasFirst(t) && Parse(d, p, -1, n - 1, [0], end) is { } r2 && Fits(t, r2.Values) ? r2 : ((List<object?>, int)?)null;
                if (r is not { } hit) continue;
                if (found != null) return null;
                found = (t, hit.Item1, hit.Item2);
            }
        return found;
    }

    /// <summary>The rowid when the cell header before the record survives; with <paramref name="index"/> the payload length only.</summary>
    private static (long? RowId, string Method) CellHeader(byte[] d, int from, int record, int length, bool index)
    {
        if (index)
        {
            for (int l = 1; l <= 3; l++)
            {
                int p = record - l;
                if (p >= from && Varint(d, ref p, record, out long payload) && p == record && payload == length) return (null, "cell");
            }
            return (null, "record");
        }
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

    /// <summary>The values and end of a record whose types start at <paramref name="typesAt"/>; null when malformed.</summary>
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

    /// <summary>The first table whose shape the values fit (stored column count, rowid alias NULL, affinities, text that decodes).</summary>
    private (SqliteTable Table, bool Unique)? Match(List<SqliteTable> tables, IReadOnlyList<object?> values)
    {
        SqliteTable? first = null;
        int fits = 0;
        foreach (var t in tables)
            if (Fits(t, values)) { first ??= t; fits++; }
        return first == null ? null : (first, fits == 1);
    }

    /// <summary>The table a match is credited to: the only one it fits, or the page's owner when that is one it fits.</summary>
    private static SqliteTable? Attributed((SqliteTable Table, bool Unique) match, SqliteTable? owner) => match.Unique || match.Table == owner ? match.Table : null;

    /// <summary>Whether values fit a table's stored columns and affinities, short rows allowed down to the shortest live one.</summary>
    private bool Fits(SqliteTable t, IReadOnlyList<object?> values)
    {
        int stored = t.StoredOrder.Count;
        if (values.Count > stored || values.Count < Shortest(t)) return false;
        bool any = false;
        for (int i = 0; i < values.Count; i++)
        {
            var v = values[i];
            int c = t.StoredOrder[i];
            if (c == t.RowIdAlias)
            {
                if (v != null) return false;
                continue;
            }
            if (v != null) any = true;
            bool ok = (v, t.Affinities[c]) switch
            {
                (null, _) => true,
                (string s, var a) => a is not ('I' or 'R') && Plausible(s),
                (long or double, 'T') => false,
                // A blob in a typed column is possible but rare: carving keeps to the likely.
                (SqliteBlob, not 'B') => false,
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
