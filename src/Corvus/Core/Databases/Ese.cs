using System.Buffers.Binary;
using System.Text;

namespace Corvus.Core.Databases;

/// <summary>An ESE database (.edb) read without esent.dll; no readable header throws <see cref="InvalidDataException"/>, later damage is noted.</summary>
public sealed class Ese : IDisposable
{
    private const uint Magic = 0x89ABCDEF;
    private const int HeaderRecord = 668, MaxDepth = 32, CachePages = 4096;
    private const uint FlagLeaf = 0x02, FlagSpaceTree = 0x20, FlagIndex = 0x40, FlagLongValue = 0x80;
    private const int TagDefunct = 0x02, TagCommonKey = 0x04;

    // Fixed column sizes of the catalog (MSysObjects), ids 1 to 13; its own catalog entries describe the same layout.
    private static readonly int[] CatalogFixed = [4, 2, 4, 4, 4, 4, 4, 1, 2, 4, 2, 4, 8];

    private readonly Stream _s;
    private readonly Dictionary<uint, Page?> _pages = [];
    private readonly bool _large;

    public int PageSize { get; }
    public uint Version { get; }
    public uint Revision { get; }
    public uint CreationRevision { get; }
    /// <summary>JET_dbstate: 1 just created, 2 dirty shutdown, 3 clean shutdown, 4 being converted, 5 force detach.</summary>
    public int State { get; }
    public ulong DatabaseTime { get; }
    /// <summary>The highest page number the file holds.</summary>
    public uint LastPage { get; }
    public bool HeaderFromShadow { get; }
    public List<string> Notes { get; } = [];
    public IReadOnlyList<Table> Tables { get; }

    /// <summary>A column as the catalog defines it; Flags are ESE's field flags (0x08 multi-valued, 0x1000 compressed).</summary>
    public sealed record Column(int Id, string Name, int Type, int Size, uint Flags, int Codepage, bool FromTemplate)
    {
        public bool Tagged => Id >= 256;
        public bool MultiValued => (Flags & 0x08) != 0;
        public bool Compressed => (Flags & 0x1000) != 0;
    }

    public sealed record IndexEntry(string Name, uint Root);

    public sealed record Table(int ObjectId, string Name, uint Root, IReadOnlyList<Column> Columns, IReadOnlyList<IndexEntry> Indexes, uint LongValueRoot, string? Template);

    /// <summary>One column's decoded instances; Stored before decompression, Problem names what was not read.</summary>
    public sealed record Field(Column Column, IReadOnlyList<byte[]> Values, IReadOnlyList<byte[]> Stored, bool Null, string? Problem, bool Separated = false);

    /// <summary>A record: its key in the table's tree, its fields in column order, the page that holds it and, for a recovered one, where it was found.</summary>
    public sealed record Row(byte[] Key, IReadOnlyList<Field> Fields, uint Page, string? Source = null);

    private sealed class Page
    {
        public uint Number, Flags, Fdp, Next;
        public byte[] Data = [];
        public int Header, Count;
    }

    private readonly record struct Node(byte[] Key, byte[] Data, uint Page, bool Defunct);

    /// <summary>True when the bytes start an ESE database header: the signature at offset 4 and a known page size.</summary>
    public static bool Looks(ReadOnlySpan<byte> head) =>
        head.Length >= 240 && BinaryPrimitives.ReadUInt32LittleEndian(head[4..]) == Magic && BinaryPrimitives.ReadUInt32LittleEndian(head[12..]) == 0
        && BinaryPrimitives.ReadUInt32LittleEndian(head[236..]) is 0 or 2048 or 4096 or 8192 or 16384 or 32768;

    public Ese(Stream s)
    {
        _s = s;
        var head = new byte[Math.Min(s.Length, 32768)];
        s.Position = 0;
        s.ReadExactly(head);
        if (!Looks(head)) throw new InvalidDataException("no ESE database signature");
        int pageSize = (int)BinaryPrimitives.ReadUInt32LittleEndian(head.AsSpan(236));
        PageSize = pageSize == 0 ? 4096 : pageSize;
        if (s.Length < PageSize * 3L) throw new InvalidDataException($"{s.Length:N0} bytes: shorter than the two header pages and one database page");
        var header = head.AsSpan(0, Math.Min(head.Length, PageSize));
        if (!HeaderValid(header))
        {
            var shadow = new byte[PageSize];
            s.Position = PageSize;
            s.ReadExactly(shadow);
            if (!Looks(shadow) || !HeaderValid(shadow)) throw new InvalidDataException("both header copies fail their checksum");
            header = shadow;
            HeaderFromShadow = true;
            Notes.Add("the primary header fails its checksum; the shadow copy in page 0 was read");
        }
        Version = BinaryPrimitives.ReadUInt32LittleEndian(header[8..]);
        DatabaseTime = BinaryPrimitives.ReadUInt64LittleEndian(header[16..]);
        State = (int)BinaryPrimitives.ReadUInt32LittleEndian(header[52..]);
        Revision = BinaryPrimitives.ReadUInt32LittleEndian(header[232..]);
        CreationRevision = BinaryPrimitives.ReadUInt32LittleEndian(header[344..]);
        LastPage = (uint)Math.Min(uint.MaxValue, s.Length / PageSize - 2);
        _large = PageSize >= 16384 && Revision >= 0x11;
        if (State == 2) Notes.Add("dirty shutdown: transactions still in the log files are not applied; pages are read as written");
        if (Version == 0x620 && Revision <= 2) Notes.Add($"format revision {Revision}: tagged columns of this revision are not read");
        Tables = ReadCatalog();
    }

    public void Dispose() => _s.Dispose();

    // XOR of the 32-bit words from offset 4, seeded with the signature; the 668-byte record suffices as the rest is zero.
    private static bool HeaderValid(ReadOnlySpan<byte> h)
    {
        uint stored = BinaryPrimitives.ReadUInt32LittleEndian(h), x = Magic, record = 0;
        for (int i = 4; i + 4 <= h.Length; i += 4)
        {
            x ^= BinaryPrimitives.ReadUInt32LittleEndian(h[i..]);
            if (i + 4 == HeaderRecord) record = x;
        }
        return stored == x || stored == record || BinaryPrimitives.ReadUInt32LittleEndian(h[52..]) == 2;
    }

    private Page? Read(uint number)
    {
        if (number < 1 || number > LastPage) return null;
        if (_pages.TryGetValue(number, out var cached)) return cached;
        if (_pages.Count >= CachePages) _pages.Clear();
        var data = new byte[PageSize];
        _s.Position = (number + 1L) * PageSize;
        _s.ReadExactly(data);
        Page? p = null;
        if (BinaryPrimitives.ReadUInt32LittleEndian(data) != 0 || BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan(4)) != 0)
        {
            int count = BinaryPrimitives.ReadUInt16LittleEndian(data.AsSpan(34)) & (Revision >= 0x122 ? 0x0FFF : 0xFFFF);
            int header = _large ? 80 : 40;
            if (header + count * 4 <= PageSize)
                p = new Page
                {
                    Number = number, Data = data, Header = header, Count = count, Next = BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan(20)),
                    Fdp = BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan(24)), Flags = BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan(36)),
                };
        }
        _pages[number] = p;
        return p;
    }

    // Tag i sits 4 * (i + 1) bytes from the page end: size, then offset; flags are the offset's top 3 bits on small pages,
    // the value's second byte's top 3 bits on 16 and 32 KiB pages.
    private (byte[] Value, int Flags)? Value(Page p, int i)
    {
        if (i >= p.Count) return null;
        int at = PageSize - 4 * (i + 1);
        int size = BinaryPrimitives.ReadUInt16LittleEndian(p.Data.AsSpan(at)), offset = BinaryPrimitives.ReadUInt16LittleEndian(p.Data.AsSpan(at + 2));
        int flags = 0;
        if (_large) { size &= 0x7FFF; offset &= 0x7FFF; }
        else { flags = offset >> 13; size &= 0x1FFF; offset &= 0x1FFF; }
        if (p.Header + offset + size > PageSize - 4 * p.Count) return null;
        var v = p.Data.AsSpan(p.Header + offset, size).ToArray();
        if (_large && v.Length >= 2) { flags = v[1] >> 5; v[1] &= 0x1F; }
        return (v, flags);
    }

    private Node? Entry(Page p, int i)
    {
        if (Value(p, i) is not var (v, flags)) return null;
        int pos = 0, common = 0;
        if ((flags & TagCommonKey) != 0)
        {
            if (v.Length < 2) return null;
            common = BinaryPrimitives.ReadUInt16LittleEndian(v);
            pos = 2;
        }
        if (v.Length < pos + 2) return null;
        int local = BinaryPrimitives.ReadUInt16LittleEndian(v.AsSpan(pos));
        pos += 2;
        if (pos + local > v.Length) return null;
        byte[] key = v[pos..(pos + local)];
        if (common > 0)
        {
            if (Value(p, 0) is not var (prefix, _) || prefix.Length < common) return null;
            key = [.. prefix.AsSpan(0, common), .. key];
        }
        return new Node(key, v[(pos + local)..], p.Number, (flags & TagDefunct) != 0);
    }

    /// <summary>The leaf nodes of the tree rooted at a page, in key order; defunct ones only when asked for.</summary>
    private IEnumerable<Node> Walk(uint root, HashSet<uint>? reached, bool defunct, CancellationToken ct)
    {
        var seen = new HashSet<uint>();
        var stack = new Stack<(uint Page, int Depth)>();
        stack.Push((root, 0));
        while (stack.Count > 0)
        {
            ct.ThrowIfCancellationRequested();
            var (number, depth) = stack.Pop();
            if (!seen.Add(number)) { Notes.Add($"page {number} is reached twice; read once"); continue; }
            reached?.Add(number);
            var p = Read(number);
            if (p == null) { Notes.Add($"page {number} is empty or unreadable; the records under it are not read"); continue; }
            if ((p.Flags & FlagLeaf) != 0)
            {
                for (int i = 1; i < p.Count; i++)
                    if (Entry(p, i) is { } n && (!n.Defunct || defunct)) yield return n;
                continue;
            }
            if (depth >= MaxDepth) { Notes.Add($"page {number}: deeper than {MaxDepth} levels; not followed"); continue; }
            var children = new List<uint>();
            for (int i = 1; i < p.Count; i++)
                if (Entry(p, i) is { Data.Length: >= 4 } n && !n.Defunct) children.Add(BinaryPrimitives.ReadUInt32LittleEndian(n.Data.AsSpan(n.Data.Length - 4)));
            for (int i = children.Count - 1; i >= 0; i--) stack.Push((children[i], depth + 1));
        }
    }

    private List<Table> ReadCatalog()
    {
        var rows = new List<(int Objid, int Type, int Id, uint Coltyp, int Space, uint Flags, int Locale, string Name, string? Template)>();
        var catalog = new Table(2, "MSysObjects", 4, [], [], 0, null);
        foreach (uint root in new uint[] { 4, 24 })
        {
            rows.Clear();
            foreach (var n in Walk(root, null, false, default))
            {
                var r = Decode(n.Data, id => id <= CatalogFixed.Length ? CatalogFixed[id - 1] : -1, out _);
                if (r == null) continue;
                int I(int id) => r.Fixed.TryGetValue(id, out var b) && b != null ? b.Length switch { 1 => b[0], 2 => BinaryPrimitives.ReadInt16LittleEndian(b), _ => BinaryPrimitives.ReadInt32LittleEndian(b) } : 0;
                string S(int id) => r.Variable.TryGetValue(id, out var b) && b != null ? System.Text.Encoding.Latin1.GetString(b) : "";
                rows.Add((I(1), I(2), I(3), (uint)I(4), I(5), (uint)I(6), I(7), S(128), r.Variable.ContainsKey(130) ? S(130) : null));
            }
            if (rows.Count > 0) break;
            Notes.Add(root == 4 ? "the catalog (page 4) holds no records; its shadow copy (page 24) was read" : "the shadow catalog holds no records either");
        }
        var tables = new List<Table>();
        foreach (var t in rows.Where(r => r.Type == 1))
        {
            var columns = rows.Where(r => r.Type == 2 && r.Objid == t.Objid).Select(r => new Column(r.Id, r.Name, (int)r.Coltyp, r.Space, r.Flags, r.Locale, false)).ToList();
            var indexes = rows.Where(r => r.Type == 3 && r.Objid == t.Objid).Select(r => new IndexEntry(r.Name, r.Coltyp)).ToList();
            uint lv = rows.FirstOrDefault(r => r.Type == 4 && r.Objid == t.Objid).Coltyp;
            tables.Add(new Table(t.Objid, t.Name, t.Coltyp, columns, indexes, lv, string.IsNullOrEmpty(t.Template) ? null : t.Template));
        }
        for (int i = 0; i < tables.Count; i++)
            if (tables[i].Template is { } name)
            {
                if (tables.FirstOrDefault(x => x.Name == name) is { } template)
                    tables[i] = tables[i] with { Columns = [.. template.Columns.Select(c => c with { FromTemplate = true }), .. tables[i].Columns] };
                else Notes.Add($"{tables[i].Name}: template table {name} is not in the catalog; its columns are unknown");
            }
        return tables;
    }

    /// <summary>A decoded record; MinEnd is the least length its offsets need (the last tagged value's start).</summary>
    private sealed record Decoded(Dictionary<int, byte[]?> Fixed, Dictionary<int, byte[]?> Variable, List<(int Id, bool Derived, byte[]? Data, int Header)> Tagged)
    {
        public int MinEnd { get; set; }
    }

    // Record: last fixed id, last variable id, fixed end; fixed columns and null bitmap; variable end offsets (top bit null)
    // and data; tagged (id, offset) pairs, offsets from the first pair, and data.
    private Decoded? Decode(byte[] rec, Func<int, int> fixedSize, out string? problem)
    {
        problem = null;
        if (rec.Length < 4) { problem = "record shorter than its header"; return null; }
        int lastFixed = rec[0], lastVar = rec[1], endFixed = BinaryPrimitives.ReadUInt16LittleEndian(rec.AsSpan(2));
        if (endFixed > rec.Length || endFixed < 4) { problem = "fixed data runs past the record"; return null; }
        var result = new Decoded([], [], []);
        int nullMap = endFixed - (lastFixed + 7) / 8, pos = 4;
        for (int id = 1; id <= lastFixed; id++)
        {
            int size = fixedSize(id);
            if (size < 0 || pos + size > nullMap) { problem = $"fixed column {id} is not in the catalog or runs past the fixed data"; return null; }
            bool isNull = (rec[nullMap + (id - 1) / 8] & (1 << ((id - 1) % 8))) != 0;
            result.Fixed[id] = isNull ? null : rec.AsSpan(pos, size).ToArray();
            pos += size;
        }
        if (pos != nullMap) { problem = "fixed column sizes do not fill the fixed data"; return null; }
        int vars = lastVar >= 128 ? lastVar - 127 : 0, varData = endFixed + 2 * vars, previous = 0;
        if (varData > rec.Length) { problem = "variable offsets run past the record"; return null; }
        for (int k = 0; k < vars; k++)
        {
            int end = BinaryPrimitives.ReadUInt16LittleEndian(rec.AsSpan(endFixed + 2 * k));
            bool isNull = (end & 0x8000) != 0;
            end &= 0x7FFF;
            if (end < previous || varData + end > rec.Length) { problem = $"variable column {128 + k} runs past the record"; return null; }
            result.Variable[128 + k] = isNull ? null : rec.AsSpan(varData + previous, end - previous).ToArray();
            previous = end;
        }
        int tagStart = varData + previous;
        result.MinEnd = tagStart;
        if (tagStart >= rec.Length || Version == 0x620 && Revision <= 2) return result;
        int mask = _large ? 0x7FFF : 0x1FFF;
        int first = tagStart + 4 <= rec.Length ? BinaryPrimitives.ReadUInt16LittleEndian(rec.AsSpan(tagStart + 2)) & mask : 0;
        if (first < 4 || first % 4 != 0 || tagStart + first > rec.Length) { problem = "tagged column array runs past the record"; return result; }
        int count = first / 4, lastId = 0;
        for (int k = 0; k < count; k++)
        {
            int id = BinaryPrimitives.ReadUInt16LittleEndian(rec.AsSpan(tagStart + 4 * k));
            int ib = BinaryPrimitives.ReadUInt16LittleEndian(rec.AsSpan(tagStart + 4 * k + 2));
            int start = ib & mask, end = k + 1 < count ? BinaryPrimitives.ReadUInt16LittleEndian(rec.AsSpan(tagStart + 4 * k + 6)) & mask : rec.Length - tagStart;
            if (id < 256 || id <= lastId && k > 0 || start < first || end < start || tagStart + end > rec.Length) { problem = $"tagged column {id} is out of order or runs past the record"; return result; }
            lastId = id;
            result.MinEnd = tagStart + start;
            bool derived = (ib & 0x8000) != 0;
            if (!_large && (ib & 0x2000) != 0) { result.Tagged.Add((id, derived, null, 0)); continue; }
            var data = rec.AsSpan(tagStart + start, end - start);
            int header = 0;
            if ((_large || (ib & 0x4000) != 0) && data.Length > 0) { header = data[0]; data = data[1..]; }
            result.Tagged.Add((id, derived, (header & 0x20) != 0 ? null : data.ToArray(), header));
        }
        return result;
    }

    private static int FixedSize(Column c) => c.Size > 0 ? c.Size : c.Type switch
    {
        1 or 2 => 1, 3 or 17 => 2, 4 or 6 or 14 => 4, 5 or 7 or 8 or 15 => 8, 16 => 16, _ => -1,
    };

    /// <summary>The table's records in key order; reached collects the pages the walk reads.</summary>
    public IEnumerable<Row> Rows(Table t, HashSet<uint>? reached, CancellationToken ct)
    {
        var byId = ById(t);
        foreach (var n in Walk(t.Root, reached, false, ct))
            if (ToRow(t, byId, n, null) is { } row) yield return row;
    }

    private static Dictionary<int, Column> ById(Table t)
    {
        var byId = new Dictionary<int, Column>();
        foreach (var c in t.Columns) byId.TryAdd(c.Id, c);
        return byId;
    }

    private Row? ToRow(Table t, Dictionary<int, Column> byId, Node n, string? source)
    {
        var d = Decode(n.Data, id => byId.TryGetValue(id, out var c) ? FixedSize(c) : -1, out var problem);
        if (d == null)
        {
            if (source == null) Notes.Add($"{t.Name}: record in page {n.Page}: {problem}");
            return null;
        }
        if (problem != null && source == null) Notes.Add($"{t.Name}: record in page {n.Page}: {problem}");
        var fields = new List<Field>(t.Columns.Count);
        foreach (var c in t.Columns)
        {
            if (!c.Tagged)
            {
                var map = c.Id < 128 ? d.Fixed : d.Variable;
                var b = map.GetValueOrDefault(c.Id);
                fields.Add(b == null ? new Field(c, [], [], true, null) : new Field(c, [b], [b], false, null));
                continue;
            }
            bool derivedTable = t.Template != null;
            var tag = d.Tagged.FirstOrDefault(x => x.Id == c.Id && (!derivedTable || x.Derived == c.FromTemplate));
            if (tag.Id == 0 || tag.Data == null) { fields.Add(new Field(c, [], [], true, null)); continue; }
            fields.Add(Tagged(t, c, tag.Data, tag.Header));
        }
        return new Row(n.Key, fields, n.Page, source);
    }

    // Header bits: 0x01 long value, 0x02 compressed (first instance only), 0x04 separated, 0x08 multi-value, 0x10 two values,
    // 0x40 encrypted; multi-value offsets are 2 bytes, top bit separated.
    private Field Tagged(Table t, Column c, byte[] data, int header)
    {
        if ((header & 0x40) != 0) return new Field(c, [], [data], false, "encrypted; not read");
        var instances = new List<(byte[] Data, bool Separated, bool Compressed)>();
        if ((header & 0x10) != 0)
        {
            if (data.Length < 1 || 1 + data[0] > data.Length) return new Field(c, [], [data], false, "two-value field shorter than its first value");
            instances.Add((data[1..(1 + data[0])], false, false));
            instances.Add((data[(1 + data[0])..], false, false));
        }
        else if ((header & 0x08) != 0)
        {
            if (data.Length < 2) return new Field(c, [], [data], false, "multi-value shorter than its offsets");
            int count = (BinaryPrimitives.ReadUInt16LittleEndian(data) & 0x7FFF) / 2;
            if (count == 0 || 2 * count > data.Length) return new Field(c, [], [data], false, "multi-value offsets run past the value");
            for (int k = 0; k < count; k++)
            {
                int word = BinaryPrimitives.ReadUInt16LittleEndian(data.AsSpan(2 * k)), start = word & 0x7FFF;
                int end = k + 1 < count ? BinaryPrimitives.ReadUInt16LittleEndian(data.AsSpan(2 * k + 2)) & 0x7FFF : data.Length;
                if (start < 2 * count || end < start || end > data.Length) return new Field(c, [], [data], false, $"multi-value instance {k + 1} runs past the value");
                instances.Add((data[start..end], (word & 0x8000) != 0, k == 0 && (header & 0x02) != 0));
            }
        }
        else instances.Add((data, (header & 0x04) != 0, (header & 0x02) != 0));

        var values = new List<byte[]>();
        var stored = new List<byte[]>();
        string? problem = null;
        foreach (var (raw, separated, compressed) in instances)
        {
            var bytes = raw;
            if (separated)
            {
                (bytes, var lvProblem, var chunkCompressed) = LongValue(t, raw);
                problem ??= lvProblem;
                stored.Add(bytes);
                if (chunkCompressed != null) { values.Add(chunkCompressed); continue; }
            }
            else stored.Add(bytes);
            if (compressed && bytes.Length > 0)
            {
                var (plain, why) = Decompress(bytes);
                problem ??= why;
                values.Add(plain ?? bytes);
            }
            else values.Add(bytes);
        }
        return new Field(c, values, stored, false, problem, instances.Any(i => i.Separated));
    }

    /// <summary>A separated long value's chunks joined, and the decoded bytes when a chunk is compressed.</summary>
    private (byte[] Stored, string? Problem, byte[]? Decoded) LongValue(Table t, byte[] lid)
    {
        if (lid.Length is not (4 or 8)) return (lid, $"long-value id of {lid.Length} bytes", null);
        if (t.LongValueRoot == 0) return (lid, "the table has no long-value tree", null);
        var key = lid.Reverse().ToArray();
        var chunks = new List<(uint Offset, byte[] Data)>();
        byte[]? root = null;
        foreach (var n in Seek(t.LongValueRoot, key))
        {
            if (!n.Key.AsSpan().StartsWith(key)) break;
            if (n.Key.Length == key.Length) root = n.Data;
            else if (n.Key.Length == key.Length + 4) chunks.Add((BinaryPrimitives.ReadUInt32BigEndian(n.Key.AsSpan(key.Length)), n.Data));
        }
        if (root == null || root.Length < 8) return (lid, $"long value 0x{Convert.ToHexStringLower(key)} is not in the long-value tree", null);
        if (root.Length >= 9 && (root[8] & 0x01) != 0) return (lid, "encrypted long value; not read", null);
        long size = BinaryPrimitives.ReadUInt32LittleEndian(root.AsSpan(4));
        chunks.Sort((a, b) => a.Offset.CompareTo(b.Offset));
        var joined = new MemoryStream();
        var decoded = new MemoryStream();
        bool anyCompressed = false;
        string? problem = null;
        for (int i = 0; i < chunks.Count; i++)
        {
            var (offset, data) = chunks[i];
            joined.Write(data);
            long expected = (i + 1 < chunks.Count ? chunks[i + 1].Offset : size) - offset;
            if (data.Length < expected && data.Length > 0)
            {
                anyCompressed = true;
                var (plain, why) = Decompress(data);
                problem ??= why;
                decoded.Write(plain ?? data);
            }
            else decoded.Write(data);
        }
        long held = anyCompressed ? decoded.Length : joined.Length;
        if (held != size) problem ??= $"long value holds {held:N0} of its {size:N0} bytes";
        return (joined.ToArray(), problem, anyCompressed ? decoded.ToArray() : null);
    }

    // Descends to the leaf that would hold the key, then yields nodes along the leaves' next-page links.
    private IEnumerable<Node> Seek(uint root, byte[] key)
    {
        uint number = root;
        for (int depth = 0; ; depth++)
        {
            var p = Read(number);
            if (p == null || depth > MaxDepth) yield break;
            if ((p.Flags & FlagLeaf) != 0) break;
            uint? child = null;
            for (int i = 1; i < p.Count && child == null; i++)
                if (Entry(p, i) is { Data.Length: >= 4 } n && !n.Defunct && (n.Key.Length == 0 || n.Key.AsSpan().SequenceCompareTo(key) >= 0))
                    child = BinaryPrimitives.ReadUInt32LittleEndian(n.Data.AsSpan(n.Data.Length - 4));
            if (child == null) yield break;
            number = child.Value;
        }
        var visited = new HashSet<uint>();
        while (number != 0 && visited.Add(number) && Read(number) is { } leaf && (leaf.Flags & FlagLeaf) != 0)
        {
            for (int i = 1; i < leaf.Count; i++)
                if (Entry(leaf, i) is { } n && !n.Defunct && n.Key.AsSpan().SequenceCompareTo(key) >= 0) yield return n;
            number = leaf.Next;
        }
    }

    /// <summary>Undoes ESE column compression (7-bit, Xpress, LZ4); Xpress9, Xpress10 and scrubbed data return null with the reason.</summary>
    public static (byte[]? Data, string? Problem) Decompress(ReadOnlySpan<byte> d)
    {
        if (d.Length == 0) return ([], null);
        int scheme = d[0] >> 3;
        switch (scheme)
        {
            case 1 or 2:
            {
                if (d.Length < 2) return (null, "7-bit data shorter than 2 bytes");
                int bits = (d.Length - 2) * 8 + (d[0] & 7) + 1, count = bits / 7;
                var o = new byte[scheme == 1 ? count : count * 2];
                for (int k = 0, bit = 8; k < count; k++, bit += 7)
                {
                    int at = bit >> 3, shift = bit & 7;
                    int word = d[at] | (at + 1 < d.Length ? d[at + 1] << 8 : 0);
                    o[scheme == 1 ? k : 2 * k] = (byte)((word >> shift) & 0x7F);
                }
                return (o, null);
            }
            case 3:
                if (d.Length < 3) return (null, "Xpress data shorter than its header");
                return PlainLz77(d[3..], BinaryPrimitives.ReadUInt16LittleEndian(d[1..]));
            case 7:
            {
                if (d.Length < 3) return (null, "LZ4 data shorter than its header");
                var o = new byte[BinaryPrimitives.ReadUInt16LittleEndian(d[1..])];
                int n = K4os.Compression.LZ4.LZ4Codec.Decode(d[3..], o);
                return n == o.Length ? (o, null) : (null, "LZ4 data does not decode to its stated size");
            }
            case 4: return (null, "scrubbed (zeroed by the database)");
            case 5: return (null, "Xpress9-compressed; not read");
            case 6: return (null, "Xpress10-compressed; not read");
            default: return (null, $"compression scheme {scheme} is unknown");
        }
    }

    // MS-XCA 2.4: 32-bit flag words; a match is offset - 1 (13 bits) and length - 3 (3 bits), longer lengths extended.
    private static (byte[]? Data, string? Problem) PlainLz77(ReadOnlySpan<byte> src, int size)
    {
        var o = new byte[size];
        int ip = 0, op = 0, flagCount = 0, halfByte = -1;
        uint flags = 0;
        while (op < size)
        {
            if (flagCount == 0)
            {
                if (ip + 4 > src.Length) break;
                flags = BinaryPrimitives.ReadUInt32LittleEndian(src[ip..]);
                ip += 4;
                flagCount = 32;
            }
            flagCount--;
            if ((flags & (1u << flagCount)) == 0)
            {
                if (ip >= src.Length) break;
                o[op++] = src[ip++];
                continue;
            }
            if (ip + 2 > src.Length) break;
            int match = BinaryPrimitives.ReadUInt16LittleEndian(src[ip..]);
            ip += 2;
            int length = match & 7, distance = (match >> 3) + 1;
            if (length == 7)
            {
                if (halfByte < 0)
                {
                    if (ip >= src.Length) break;
                    halfByte = ip;
                    length = src[ip++] & 15;
                }
                else { length = src[halfByte] >> 4; halfByte = -1; }
                if (length == 15)
                {
                    if (ip >= src.Length) break;
                    length = src[ip++];
                    if (length == 255)
                    {
                        if (ip + 2 > src.Length) break;
                        length = BinaryPrimitives.ReadUInt16LittleEndian(src[ip..]);
                        ip += 2;
                        if (length == 0)
                        {
                            if (ip + 4 > src.Length) break;
                            length = (int)Math.Min(BinaryPrimitives.ReadUInt32LittleEndian(src[ip..]), int.MaxValue);
                            ip += 4;
                        }
                        if (length < 22) return (null, "Xpress match length below its minimum");
                        length -= 22;
                    }
                    length += 15;
                }
                length += 7;
            }
            length += 3;
            if (distance > op) return (null, "Xpress match reaches before the data");
            for (int k = 0; k < length && op < size; k++, op++) o[op] = o[op - distance];
        }
        return op == size ? (o, null) : (null, $"Xpress data ends after {op:N0} of {size:N0} bytes");
    }

    // A node in untagged space is accepted when its header matches the table's fixed layout and ends at the next one.
    // Small pages lose the flags with the tag, so keys with and without a common-prefix size are tried.
    private IEnumerable<(Node Node, bool Whole)> Carve(Page p, Table t, Dictionary<int, Column> byId)
    {
        int top = PageSize - 4 * p.Count;
        var used = new List<(int Start, int End)>();
        for (int i = 0; i < p.Count; i++)
        {
            int at = PageSize - 4 * (i + 1);
            int size = BinaryPrimitives.ReadUInt16LittleEndian(p.Data.AsSpan(at)) & (_large ? 0x7FFF : 0x1FFF);
            int offset = BinaryPrimitives.ReadUInt16LittleEndian(p.Data.AsSpan(at + 2)) & (_large ? 0x7FFF : 0x1FFF);
            if (size > 0) used.Add((p.Header + offset, p.Header + offset + size));
        }
        used.Sort();
        int lastFixed = t.Columns.Where(c => c.Id < 128).Select(c => c.Id).DefaultIfEmpty(0).Max();
        var gaps = new List<(int Start, int End)>();
        int cursor = p.Header;
        foreach (var (start, end) in used)
        {
            if (start > cursor) gaps.Add((cursor, Math.Min(start, top)));
            cursor = Math.Max(cursor, end);
        }
        if (cursor < top) gaps.Add((cursor, top));
        foreach (var (gapStart, gapEnd) in gaps)
        {
            var found = new List<(int Start, int RecordAt, byte[] Key, int MinEnd)>();
            for (int at = gapStart; at + 8 <= gapEnd; at++)
            {
                if (found.Count > 0 && at < found[^1].MinEnd) continue;
                if (Candidate(p, t, byId, at, gapEnd, lastFixed) is { } c) found.Add(c);
            }
            for (int k = 0; k < found.Count; k++)
            {
                int end = k + 1 < found.Count ? found[k + 1].Start : gapEnd;
                // The gap's last node runs to the gap end; a run of 16 or more zero bytes there is unused space.
                int zeros = 0;
                while (end - zeros > found[k].MinEnd + 1 && p.Data[end - zeros - 1] == 0) zeros++;
                if (zeros >= 16) end -= zeros;
                bool whole = k + 1 < found.Count || zeros >= 16 || found[k].MinEnd == end;
                yield return (new Node(found[k].Key, p.Data[found[k].RecordAt..end], p.Number, true), whole);
            }
        }
    }

    private (int Start, int RecordAt, byte[] Key, int MinEnd)? Candidate(Page p, Table t, Dictionary<int, Column> byId, int at, int gapEnd, int lastFixed)
    {
        var d = p.Data;
        foreach (bool common in _large ? [(d[at + 1] >> 5 & TagCommonKey) != 0] : new[] { false, true })
        {
            int pos = at, prefix = 0;
            if (common) { prefix = BinaryPrimitives.ReadUInt16LittleEndian(d.AsSpan(pos)) & 0x1FFF; pos += 2; }
            if (pos + 2 > gapEnd) continue;
            int local = BinaryPrimitives.ReadUInt16LittleEndian(d.AsSpan(pos)) & (_large && !common ? 0x1FFF : 0xFFFF);
            pos += 2;
            int rec = pos + local;
            if (local == 0 || local > 255 || prefix > 255 || rec + 4 > gapEnd) continue;
            // The header must name the table's fixed columns and the exact end of their data and null bitmap.
            int recLastFixed = d[rec], end = BinaryPrimitives.ReadUInt16LittleEndian(d.AsSpan(rec + 2));
            if (recLastFixed > lastFixed || recLastFixed == 0 && lastFixed > 0) continue;
            int expected = 4 + t.Columns.Where(c => c.Id <= recLastFixed && c.Id < 128).Sum(FixedSize) + (recLastFixed + 7) / 8;
            if (end != expected || d[rec + 1] is > 0 and < 127 or > 255) continue;
            var record = d[rec..gapEnd];
            var decoded = Decode(record, id => byId.TryGetValue(id, out var c) ? FixedSize(c) : -1, out var problem);
            if (decoded == null || problem != null) continue;
            // A page emptied by a merge keeps no prefix; the key is then its local part only.
            byte[] key = d[pos..rec];
            if (prefix > 0 && Value(p, 0) is var (header, _) && header.Length >= prefix) key = [.. header.AsSpan(0, prefix), .. key];
            return (at, rec, key, rec + decoded.MinEnd);
        }
        return null;
    }

    /// <summary>A text column's value: UTF-16 for codepage 1200, else Latin-1, up to its NUL terminator (a fixed column pads after it).</summary>
    public static string Text(Column c, byte[] b)
    {
        string s = c.Codepage == 1200 && b.Length % 2 == 0 ? Encoding.Unicode.GetString(b) : Encoding.Latin1.GetString(b);
        int end = s.IndexOf('\0');
        return end >= 0 ? s[..end] : s;
    }

    /// <summary>A record's identity: the stored bytes of every field (a carved key may lack its prefix).</summary>
    public static string Id(Row r) =>
        string.Join("|", r.Fields.Select(f => f.Null ? "-" : string.Join(",", f.Stored.Select(Convert.ToHexStringLower))));

    /// <summary>A table's records that deleted nodes and unreached leaf pages still hold, live ones left out.</summary>
    public List<Row> Recover(Table t, HashSet<string> live, HashSet<uint> reached, int max, CancellationToken ct)
    {
        var found = new List<Row>();
        var seen = new HashSet<string>(live, StringComparer.Ordinal);
        var byId = ById(t);
        void Add(Node n, string source)
        {
            if (found.Count < max && ToRow(t, byId, n, source) is { } r && seen.Add(Id(r))) found.Add(r);
        }
        var leaves = new HashSet<uint>();
        foreach (var n in Walk(t.Root, leaves, true, ct))
            if (n.Defunct) Add(n, $"deleted node, page {n.Page}");
        foreach (uint number in leaves.Order())
            if (Read(number) is { } p && (p.Flags & FlagLeaf) != 0)
                foreach (var (n, whole) in Carve(p, t, byId)) Add(n, $"free space, page {number}{(whole ? "" : "; end unknown")}");
        for (uint number = 1; number <= LastPage && found.Count < max; number++)
        {
            ct.ThrowIfCancellationRequested();
            if (reached.Contains(number)) continue;
            // The header alone decides; a page of another tree is skipped before its tags are read.
            var head = new byte[40];
            _s.Position = (number + 1L) * PageSize;
            _s.ReadExactly(head);
            uint fdp = BinaryPrimitives.ReadUInt32LittleEndian(head.AsSpan(24)), flags = BinaryPrimitives.ReadUInt32LittleEndian(head.AsSpan(36));
            if (fdp != (uint)t.ObjectId || (flags & FlagLeaf) == 0 || (flags & (FlagIndex | FlagLongValue | FlagSpaceTree)) != 0) continue;
            if (Read(number) is not { } p) continue;
            for (int i = 1; i < p.Count; i++)
                if (Entry(p, i) is { } n) Add(n, $"unreachable page {number}");
            foreach (var (n, whole) in Carve(p, t, byId)) Add(n, $"free space, unreachable page {number}{(whole ? "" : "; end unknown")}");
        }
        return found;
    }
}
