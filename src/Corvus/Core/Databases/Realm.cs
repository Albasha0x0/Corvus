using System.Buffers.Binary;
using System.Numerics;
using System.Text;

namespace Corvus.Core.Databases;

/// <summary>A Realm file read without Realm Core: tables and typed objects of the current commit; damaged nodes are noted.</summary>
public sealed class Realm : IDisposable
{
    private const int HeaderSize = 24, MaxDepth = 24, MaxCached = 8192, MaxNotes = 100;
    private const long MaxNode = 64 << 20;
    private const ulong StreamingCookie = 0x3034125237E526C8UL;
    private const int TypeInt = 0, TypeBool = 1, TypeString = 2, TypeBinary = 4, TypeMixed = 6, TypeTimestamp = 8, TypeFloat = 9,
        TypeDouble = 10, TypeDecimal = 11, TypeLink = 12, TypeBackLink = 14, TypeObjectId = 15, TypeTypedLink = 16, TypeUuid = 17;
    private const int AttrNullable = 16, AttrList = 32, AttrDictionary = 64, AttrSet = 128;

    private readonly Stream _stream;
    private readonly Dictionary<long, Node?> _cache = [];
    private readonly List<string> _notes = [];
    private readonly Dictionary<long, string> _tableNames = [];

    /// <summary>A column: Type is the Realm column type code; Index is the column's slot in a cluster leaf.</summary>
    public sealed record Column(string Name, int Type, int Attributes, int Index, int SpecIndex, string? Target)
    {
        public bool Nullable => (Attributes & AttrNullable) != 0;
        public bool List => (Attributes & AttrList) != 0;
        public bool Set => (Attributes & AttrSet) != 0;
        public bool Dictionary => (Attributes & AttrDictionary) != 0;

        /// <summary>The column type as the Realm SDKs name it, with ? for optional and the collection kind.</summary>
        public string Kind
        {
            get
            {
                string t = Type switch
                {
                    TypeInt => "int", TypeBool => "bool", TypeString => "string", TypeBinary => "data", TypeMixed => "mixed",
                    TypeTimestamp => "date", TypeFloat => "float", TypeDouble => "double", TypeDecimal => "decimal128",
                    TypeLink => Target is { } target && target.StartsWith("class_", StringComparison.Ordinal) ? target[6..] : Target ?? "object", TypeObjectId => "objectId", TypeTypedLink => "link", TypeUuid => "uuid", _ => $"type {Type}",
                };
                if (Nullable && Type != TypeMixed) t += "?";
                return List ? t + "[]" : Set ? t + "<>" : Dictionary ? t + "{}" : t;
            }
        }
    }

    /// <summary>A table of a commit: Embedded tables hold objects that belong to one parent.</summary>
    public sealed record Table(string Name, long Key, long Ref, bool Embedded, IReadOnlyList<Column> Columns, long Objects, IReadOnlyDictionary<int, IReadOnlyList<string?>> Enums);

    /// <summary>An object: Key is null when the cluster leaf it came from has no known key offset.</summary>
    public sealed record Obj(long? Key, IReadOnlyList<object?> Values);

    /// <summary>A recovered object: Table is null when no table matched; Source names the commit or free block.</summary>
    public sealed record Recovered(string? Table, Obj Object, string Source);

    /// <summary>A timestamp: seconds since 1970-01-01 UTC and nanoseconds (same sign).</summary>
    public sealed record Timestamp(long Seconds, int Nanoseconds);

    /// <summary>A decimal128 value in its BSON text form.</summary>
    public sealed record Decimal(string Text);

    /// <summary>A link to the object with key Key in table Table (null when the table key is not in the file).</summary>
    public sealed record Link(string? Table, long Key);

    /// <summary>A fixed-size identifier: 12 bytes for an object id, 16 for a UUID.</summary>
    public sealed record Id(byte[] Bytes, bool Uuid);

    /// <summary>A list or set (Set true) of values.</summary>
    public sealed record Collection(IReadOnlyList<object?> Items, bool Set);

    /// <summary>A dictionary's entries in stored order.</summary>
    public sealed record Map(IReadOnlyList<KeyValuePair<string, object?>> Entries);

    /// <summary>A value this reader could not decode, with the reason.</summary>
    public sealed record Unread(string Reason);

    private sealed record Node(long Ref, byte Flags, int Width, int Size, byte[] Data)
    {
        public bool Inner => (Flags & 0x80) != 0;
        public bool HasRefs => (Flags & 0x40) != 0;
        public bool Context => (Flags & 0x20) != 0;
        public int WType => (Flags >> 3) & 3;
    }

    public long Length { get; }
    public int FileFormat { get; }
    public long TopRef { get; }
    public long PreviousTopRef { get; }
    public bool Streaming { get; }
    public IReadOnlyList<Table> Tables { get; }
    public IReadOnlyList<string> Notes => _notes;

    /// <summary>True when <paramref name="head"/> starts with a Realm file header ("T-DB" at offset 16).</summary>
    public static bool Looks(ReadOnlySpan<byte> head) =>
        head.Length >= HeaderSize && head[16] == (byte)'T' && head[17] == (byte)'-' && head[18] == (byte)'D' && head[19] == (byte)'B' && (head[23] & 0xFE) == 0;

    /// <summary>Opens the file in <paramref name="stream"/>; throws <see cref="InvalidDataException"/> when the header is not a Realm header.</summary>
    public Realm(Stream stream)
    {
        _stream = stream;
        Length = stream.Length;
        var head = ReadAt(0, HeaderSize) ?? throw new InvalidDataException("file under 24 bytes");
        if (!Looks(head)) throw new InvalidDataException("no Realm header at offset 0");
        int slot = head[23] & 1;
        FileFormat = head[20 + slot];
        long top = (long)BinaryPrimitives.ReadUInt64LittleEndian(head.AsSpan(slot * 8));
        long other = (long)BinaryPrimitives.ReadUInt64LittleEndian(head.AsSpan((1 - slot) * 8));
        if (top == -1 && ReadAt(Length - 16, 16) is { } footer && BinaryPrimitives.ReadUInt64LittleEndian(footer.AsSpan(8)) == StreamingCookie)
        {
            Streaming = true;
            top = (long)BinaryPrimitives.ReadUInt64LittleEndian(footer);
            other = 0;
        }
        TopRef = top;
        PreviousTopRef = other is > 0 && other != top ? other : 0;
        if (FileFormat is > 0 and < 10) Note($"file format {FileFormat}: column-based tables from before cluster trees; not read");
        Tables = FileFormat is > 0 and < 10 ? [] : ReadTables(top, true);
    }

    public void Dispose() => _stream.Dispose();

    private void Note(string text)
    {
        if (_notes.Count < MaxNotes && !_notes.Contains(text)) _notes.Add(text);
    }

    // The tables of the commit whose top array is at top: names, table refs, specs and object counts.
    private List<Table> ReadTables(long top, bool current)
    {
        var tables = new List<Table>();
        if (top == 0) return tables;
        if (Read(top) is not { HasRefs: true } t || t.Size < 2)
        {
            Note($"top array at {top}: unreadable");
            return tables;
        }
        var names = Strings(Ref(Int(t, 0)), null);
        if (Read(Ref(Int(t, 1))) is not { } refs || names == null || names.Count != refs.Size)
        {
            Note($"top array at {top}: table names and refs disagree");
            return tables;
        }
        var raw = new List<(string Name, long Key, long Ref, Node Top)>();
        for (int i = 0; i < refs.Size; i++)
        {
            long r = Ref(Int(refs, i));
            if (Read(r) is not { HasRefs: true } tt || tt.Size < 4)
            {
                if (current) Note($"table {names[i]}: top array at {r} unreadable");
                continue;
            }
            long key = Tagged(Int(tt, 3)) ?? i;
            raw.Add((names[i] ?? $"table {i}", key, r, tt));
            if (current) _tableNames[key & 0xFFFF] = names[i] ?? $"table {i}";
        }
        foreach (var (name, key, r, tt) in raw)
        {
            if (TableOf(name, key, r, tt) is { } table) tables.Add(table);
            else if (current) Note($"table {name}: spec unreadable");
        }
        return tables;
    }

    private Table? TableOf(string name, long key, long r, Node tt)
    {
        if (Read(Ref(Int(tt, 0))) is not { } spec || spec.Size < 3) return null;
        var types = Read(Ref(Int(spec, 0)));
        var names = Strings(Ref(Int(spec, 1)), null);
        var attrs = Read(Ref(Int(spec, 2)));
        if (types == null || names == null || attrs == null || attrs.Size < types.Size) return null;
        var colKeys = spec.Size > 5 && Ref(Int(spec, 5)) != 0 ? Read(Ref(Int(spec, 5))) : null;
        var enumKeys = spec.Size > 4 && Ref(Int(spec, 4)) != 0 ? Read(Ref(Int(spec, 4))) : null;
        var opposite = tt.Size > 7 && Ref(Int(tt, 7)) != 0 ? Read(Ref(Int(tt, 7))) : null;
        var columns = new List<Column>();
        var enums = new Dictionary<int, IReadOnlyList<string?>>();
        int named = 0;
        for (int i = 0; i < types.Size; i++)
        {
            int type = (int)Int(types, i);
            int index = colKeys != null && i < colKeys.Size ? (int)(Int(colKeys, i) & 0xFFFF) : i;
            // Backlink columns have no name; names list only the other columns, in spec order.
            string colName = type == TypeBackLink ? "" : named < names.Count ? names[named++] ?? "" : $"column {i}";
            string? target = null;
            if (type is TypeLink or TypeBackLink && opposite != null && index < opposite.Size)
                target = _tableNames.GetValueOrDefault(Int(opposite, index) & 0xFFFF);
            columns.Add(new Column(colName, type, (int)Int(attrs, i), index, i, target));
            if (enumKeys != null && i < enumKeys.Size && Ref(Int(enumKeys, i)) is var er and not 0 && Strings(er, null) is { } values) enums[i] = values;
        }
        bool embedded = tt.Size > 12 && ((Tagged(Int(tt, 12)) ?? 0) & 3) == 1;
        long objects = Ref(Int(tt, 2)) is var root and not 0 ? Count(root) : 0;
        return new Table(name, key, r, embedded, columns, objects, enums);
    }

    // Objects in a cluster tree: an inner node keeps its subtree size tagged at slot 2; a leaf has one key per object.
    private long Count(long root)
    {
        if (Read(root) is not { } n) return 0;
        if (n.Inner) return n.Size > 2 ? Tagged(Int(n, 2)) ?? 0 : 0;
        if (n.Size == 0) return 0;
        long k = Int(n, 0);
        return (k & 1) != 0 ? k >> 1 : Read(k) is { } keys ? keys.Size : 0;
    }

    /// <summary>The objects of <paramref name="table"/> in key order; values follow <see cref="Table.Columns"/>, backlink columns excluded.</summary>
    public IEnumerable<Obj> Objects(Table table, CancellationToken ct) => Objects(table, null, ct);

    private IEnumerable<Obj> Objects(Table table, HashSet<long>? reached, CancellationToken ct)
    {
        long root = Read(table.Ref) is { } tt && tt.Size > 2 ? Ref(Int(tt, 2)) : 0;
        if (root == 0) return [];
        return Leaves(table, root, 0, 0, reached, [], ct);
    }

    // A tree never shares a node: a child reached twice in one walk is skipped,
    // or shared children would be read once per path, exponential in depth.
    private IEnumerable<Obj> Leaves(Table table, long r, long offset, int depth, HashSet<long>? reached, HashSet<long> walked, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        if (depth > MaxDepth || Read(r) is not { HasRefs: true } n)
        {
            Note($"{table.Name}: cluster node at {r} unreadable");
            yield break;
        }
        if (!walked.Add(r))
        {
            Note($"{table.Name}: cluster node at {r} is reached twice; read once");
            yield break;
        }
        reached?.Add(r);
        if (n.Inner)
        {
            if (n.Size < 4) yield break;
            int depthBelow = (int)(Tagged(Int(n, 1)) ?? 0);
            var keys = Ref(Int(n, 0)) is var kr and not 0 ? Read(kr) : null;
            for (int i = 3; i < n.Size; i++)
            {
                long child = Ref(Int(n, i));
                // Child key offsets come from the keys array, or from the child's position when the tree is compact.
                long off = keys != null && i - 3 < keys.Size ? (long)UInt(keys, i - 3) : (long)(i - 3) << (depthBelow * 8);
                foreach (var o in Leaves(table, child, offset + off, depth + 1, reached, walked, ct)) yield return o;
            }
            yield break;
        }
        foreach (var o in Leaf(table, n, offset, reached)) yield return o;
    }

    // A cluster leaf: slot 0 holds the keys array (or a tagged count of compact keys 0..n-1); slot 1 + index holds a column.
    private List<Obj> Leaf(Table table, Node n, long? offset, HashSet<long>? reached)
    {
        var result = new List<Obj>();
        if (n.Size == 0) return result;
        long k = Int(n, 0);
        Node? keys = null;
        int count;
        if ((k & 1) != 0) count = (int)Math.Min(k >> 1, int.MaxValue);
        else if (Read(k) is { } kn) { keys = kn; count = kn.Size; reached?.Add(k); }
        else
        {
            Note($"{table.Name}: keys of cluster leaf {n.Ref} unreadable");
            return result;
        }
        // Keys are distinct, so a keys array of width w holds at most 2^w.
        if (keys is { Width: < 32 } && keys.Size > 1L << keys.Width)
        {
            Note($"{table.Name}: keys of cluster leaf {n.Ref}: {keys.Size:N0} keys of width {keys.Width} cannot be distinct");
            return result;
        }
        // A compact key count holds no bytes per object, so a count past the
        // file length is refused.
        if (keys == null && count > Length)
        {
            Note($"{table.Name}: cluster leaf {n.Ref} claims {count:N0} objects, more than the file's {Length:N0} bytes");
            return result;
        }
        var columns = table.Columns.Where(c => c.Type != TypeBackLink).ToList();
        var cols = columns.Select(c => c.Index + 1 < n.Size ? ColumnValues(table, c, Ref(Int(n, c.Index + 1)), count, reached) : null).ToList();
        if (count > 0 && columns.Count > 0 && cols.All(c => c == null)) Note($"{table.Name}: cluster leaf {n.Ref}: no column could be read");
        var unread = columns.Select(c => new Unread(c.Index + 1 < n.Size ? "column unreadable" : "column not in leaf")).ToList();
        var values = new List<object?>[count];
        for (int i = 0; i < count; i++)
        {
            values[i] = new List<object?>(columns.Count);
            for (int j = 0; j < cols.Count; j++) values[i].Add(cols[j] is { } col ? col[i] : unread[j]);
        }
        for (int i = 0; i < count; i++)
            result.Add(new Obj(offset == null ? null : offset + (keys == null ? i : (long)UInt(keys, i)), values[i]));
        return result;
    }

    // Values of one column for count objects; null when the column array does not hold count values.
    private object?[]? ColumnValues(Table table, Column c, long r, int count, HashSet<long>? reached)
    {
        if (Read(r) is not { } n) return null;
        reached?.Add(r);
        if (c.List || c.Set || c.Dictionary)
        {
            if (!n.HasRefs || n.Size < count) return null;
            var values = new object?[count];
            for (int i = 0; i < count; i++)
            {
                long cr = Ref(Int(n, i));
                if (cr == 0) values[i] = c.Dictionary ? new Map([]) : new Collection([], c.Set);
                else if (c.Dictionary) values[i] = DictionaryValues(cr, reached);
                else values[i] = Tree(c.Type, c.Nullable, c.Target, cr, reached, 0, []) is { } items ? new Collection(items, c.Set) : new Unread("collection unreadable");
            }
            return values;
        }
        // Checked before decoding, since the values are allocated by the size.
        if (Elements(c, n, count) is { } expected && n.Size != expected) return null;
        var items1 = LeafValues(c.Type, c.Nullable, c.Target, n, reached, table.Enums.GetValueOrDefault(c.SpecIndex), true);
        if (items1 == null || items1.Count != count) return null;
        return [.. items1];
    }

    // Size of a column array that holds count values itself; null when they
    // sit in arrays below it.
    private static long? Elements(Column c, Node n, int count) => c.Type switch
    {
        TypeInt => c.Nullable ? count + 1L : count,
        TypeTypedLink => 2L * count,
        TypeString => n.HasRefs ? null : count,
        TypeBinary or TypeTimestamp or TypeObjectId or TypeUuid or TypeMixed => null,
        _ => count,
    };

    // The values of a B+tree of one element type: inner nodes hold children between an offsets slot and a size slot.
    /// <param name="walked">Nodes of this tree read so far; a node reached
    /// twice makes the tree unreadable.</param>
    private List<object?>? Tree(int type, bool nullable, string? target, long r, HashSet<long>? reached, int depth, HashSet<long> walked)
    {
        if (depth > MaxDepth || !walked.Add(r) || Read(r) is not { } n) return null;
        reached?.Add(r);
        if (!n.Inner) return LeafValues(type, nullable, target, n, reached, null, false);
        var all = new List<object?>();
        for (int i = 1; i < n.Size - 1; i++)
        {
            if (Tree(type, nullable, target, Ref(Int(n, i)), reached, depth + 1, walked) is not { } part) return null;
            all.AddRange(part);
        }
        return all;
    }

    private Map DictionaryValues(long r, HashSet<long>? reached)
    {
        if (Read(r) is not { HasRefs: true, Size: >= 2 } top) return new Map([new("", new Unread("dictionary unreadable"))]);
        reached?.Add(r);
        var keys = Tree(TypeString, false, null, Ref(Int(top, 0)), reached, 0, []);
        var values = Tree(TypeMixed, true, null, Ref(Int(top, 1)), reached, 0, []);
        if (keys == null || values == null || keys.Count != values.Count) return new Map([new("", new Unread("dictionary unreadable"))]);
        return new Map([.. keys.Select((k, i) => new KeyValuePair<string, object?>(k as string ?? "", values[i]))]);
    }

    // A link column stores key + 1 with 0 for null; link lists store keys as they are.
    private List<object?>? LeafValues(int type, bool nullable, string? target, Node n, HashSet<long>? reached, IReadOnlyList<string?>? enums, bool column)
    {
        switch (type)
        {
            case TypeInt:
                if (n.WType != 0) return null;
                if (!nullable) return [.. Enumerable.Range(0, n.Size).Select(i => (object?)Int(n, i))];
                if (n.Size == 0) return null;
                {
                    long nul = Int(n, 0);
                    return [.. Enumerable.Range(1, n.Size - 1).Select(i => Int(n, i) is var v && v == nul ? null : (object?)v)];
                }
            case TypeBool:
                if (n.WType != 0) return null;
                return [.. Enumerable.Range(0, n.Size).Select(i => Int(n, i) switch { 0 => (object?)false, 1 => true, _ => null })];
            case TypeString:
                // Long strings keep an unreadable blob as an unread value; the other layouts read whole.
                if (n.HasRefs) return Blobs(n, true, reached)?.Select(b => b is byte[] bytes ? Encoding.UTF8.GetString(bytes) : b).ToList();
                return Strings(n.Ref, enums)?.Cast<object?>().ToList();
            case TypeBinary:
                return Blobs(n, false, reached);
            case TypeTimestamp:
            {
                if (!n.HasRefs || n.Size < 2 || Read(Ref(Int(n, 0))) is not { Size: > 0 } sec || Read(Ref(Int(n, 1))) is not { } nano) return null;
                reached?.Add(sec.Ref);
                reached?.Add(nano.Ref);
                long nul = Int(sec, 0);
                if (nano.Size < sec.Size - 1) return null;
                return [.. Enumerable.Range(0, sec.Size - 1).Select(i => Int(sec, i + 1) is var s && s == nul ? null : (object?)new Timestamp(s, (int)Int(nano, i)))];
            }
            case TypeFloat or TypeDouble:
            {
                int w = type == TypeFloat ? 4 : 8;
                if (n.WType != 1 || n.Width != w && n.Size > 0) return null;
                var list = new List<object?>(n.Size);
                for (int i = 0; i < n.Size; i++)
                {
                    if (w == 4)
                    {
                        uint bits = BinaryPrimitives.ReadUInt32LittleEndian(n.Data.AsSpan(i * 4));
                        list.Add(nullable && bits == 0x7fc000aa ? null : BitConverter.UInt32BitsToSingle(bits));
                    }
                    else
                    {
                        ulong bits = BinaryPrimitives.ReadUInt64LittleEndian(n.Data.AsSpan(i * 8));
                        list.Add(nullable && bits == 0x7ff80000000000aaUL ? null : BitConverter.UInt64BitsToDouble(bits));
                    }
                }
                return list;
            }
            case TypeDecimal:
            {
                var list = new List<object?>(n.Size);
                for (int i = 0; i < n.Size; i++) list.Add(DecimalAt(n, i));
                return list;
            }
            case TypeLink:
                if (n.WType != 0) return null;
                return [.. Enumerable.Range(0, n.Size).Select(i => Int(n, i) - (column ? 1 : 0) is var v && v < 0 ? null : (object?)new Link(target, v))];
            case TypeObjectId or TypeUuid:
                return FixedBytes(n, type == TypeUuid ? 16 : 12);
            case TypeMixed:
                return Mixed(n, reached);
            case TypeTypedLink:
                // Pairs of table key + 1 and object key + 1; a zero table key is null.
                if (n.WType != 0 || n.Size % 2 != 0) return null;
                return [.. Enumerable.Range(0, n.Size / 2).Select(i => Int(n, 2 * i) is var t && t == 0 ? null
                    : (object?)new Link(_tableNames.GetValueOrDefault((t - 1) & 0xFFFF), Int(n, 2 * i + 1) - 1))];
            default:
                return [.. Enumerable.Range(0, n.Size).Select(_ => (object?)new Unread($"column type {type}"))];
        }
    }

    // String layouts: short (fixed width, last byte counts padding), enumerated, medium (offsets, bytes, nulls), long (blobs).
    private List<string?>? Strings(long r, IReadOnlyList<string?>? enums)
    {
        if (Read(r) is not { } n) return null;
        if (!n.HasRefs)
        {
            if (n.WType == 1) return [.. ShortBytes(n).Select(b => b == null ? null : Encoding.UTF8.GetString(b))];
            if (enums == null || n.WType != 0) return null;
            return [.. Enumerable.Range(0, n.Size).Select(i => Int(n, i) is var v && v >= 0 && v < enums.Count ? enums[(int)v] : null)];
        }
        var blobs = Blobs(n, true, null);
        if (blobs == null || blobs.Any(b => b is Unread)) return null;
        return [.. blobs.Select(b => b is byte[] bytes ? Encoding.UTF8.GetString(bytes) : null)];
    }

    // Values of a short string array: fixed width, the last byte counts the padding, and padding of the full width is null.
    private static List<byte[]?> ShortBytes(Node n)
    {
        var list = new List<byte[]?>(n.Size);
        int w = n.Width;
        for (int i = 0; i < n.Size; i++)
        {
            if (w == 0) { list.Add([]); continue; }
            int pad = n.Data[i * w + w - 1];
            list.Add(pad == w ? null : pad > w - 1 ? [] : n.Data.AsSpan(i * w, w - 1 - pad).ToArray());
        }
        return list;
    }

    // Medium or long (0 for null) byte arrays; strings end in a zero byte that is not part of the value.
    private List<object?>? Blobs(Node n, bool strings, HashSet<long>? reached)
    {
        int term = strings ? 1 : 0;
        if (!n.HasRefs)
        {
            // A binary column whose values are all short is a plain byte array per value only in old files.
            return null;
        }
        var list = new List<object?>();
        if (!n.Context)
        {
            if (n.Size < 2 || Read(Ref(Int(n, 0))) is not { } offsets || Read(Ref(Int(n, 1))) is not { } blob) return null;
            var nulls = n.Size > 2 && Ref(Int(n, 2)) != 0 ? Read(Ref(Int(n, 2))) : null;
            reached?.Add(offsets.Ref);
            reached?.Add(blob.Ref);
            long start = 0;
            for (int i = 0; i < offsets.Size; i++)
            {
                long end = Int(offsets, i);
                if (end < start || end > blob.Data.Length) return null;
                if (nulls != null && i < nulls.Size && Int(nulls, i) != 0) list.Add(null);
                else list.Add(blob.Data.AsSpan((int)start, (int)Math.Max(0, end - start - term)).ToArray());
                start = end;
            }
            return list;
        }
        for (int i = 0; i < n.Size; i++)
        {
            long br = Ref(Int(n, i));
            if (br == 0) { list.Add(null); continue; }
            if (Read(br) is not { } b) { list.Add(new Unread($"blob at {br} unreadable")); continue; }
            reached?.Add(br);
            list.Add(b.Data.AsSpan(0, Math.Max(0, b.Data.Length - term)).ToArray());
        }
        return list;
    }

    // Object ids and UUIDs: blocks of one null-flag byte followed by eight values.
    private static List<object?>? FixedBytes(Node n, int width)
    {
        if (n.WType != 1 && n.Size > 0) return null;
        int block = width * 8 + 1, bytes = n.Data.Length;
        int count = bytes - (bytes + block - 1) / block;
        if (count < 0 || count % width != 0) return null;
        count /= width;
        var list = new List<object?>(count);
        for (int i = 0; i < count; i++)
        {
            int b = i / 8 * block, o = i % 8;
            bool isNull = (n.Data[b] & (1 << o)) != 0;
            list.Add(isNull ? null : new Id(n.Data.AsSpan(b + 1 + o * width, width).ToArray(), width == 16));
        }
        return list;
    }

    // Mixed: value << 8 | payload index << 5 | (type + 1); payload slots 1 numbers, 2 timestamp and decimal pairs,
    // 3 strings and bytes, 4 nested collections.
    private List<object?>? Mixed(Node n, HashSet<long>? reached)
    {
        if (!n.HasRefs || n.Size < 1 || Read(Ref(Int(n, 0))) is not { } composite) return null;
        reached?.Add(composite.Ref);
        Node? ints = n.Size > 1 && Ref(Int(n, 1)) != 0 ? Read(Ref(Int(n, 1))) : null;
        Node? pairs = n.Size > 2 && Ref(Int(n, 2)) != 0 ? Read(Ref(Int(n, 2))) : null;
        List<object?>? strings = n.Size > 3 && Ref(Int(n, 3)) != 0 && Read(Ref(Int(n, 3))) is { } sn ? (sn.HasRefs ? Blobs(sn, true, reached) : sn.WType == 1 ? [.. ShortBytes(sn)] : null) : null;
        var list = new List<object?>(composite.Size);
        for (int i = 0; i < composite.Size; i++)
        {
            long v = Int(composite, i);
            if (v == 0) { list.Add(null); continue; }
            int type = (int)(v & 0x1F) - 1, payload = (int)((v >> 5) & 7);
            long x = v >> 8;
            object? Pair(Func<long, long, object?> f) => pairs != null && 2 * x + 1 < pairs.Size ? f(Int(pairs, (int)(2 * x)), Int(pairs, (int)(2 * x + 1))) : new Unread("mixed pair missing");
            object? Small() => ints != null && x >= 0 && x < ints.Size ? Int(ints, (int)x) : null;
            byte[]? Bytes() => strings != null && x >= 0 && x < strings.Count ? strings[(int)x] as byte[] : null;
            list.Add(type switch
            {
                TypeInt => payload != 0 ? Small() : x,
                TypeBool => x != 0,
                TypeFloat => Small() is long f ? BitConverter.Int32BitsToSingle((int)f) : new Unread("mixed float missing"),
                TypeDouble => Small() is long d ? BitConverter.Int64BitsToDouble(d) : new Unread("mixed double missing"),
                TypeString => Bytes() is { } s ? Encoding.UTF8.GetString(s) : new Unread("mixed string missing"),
                TypeBinary => Bytes() is { } b ? b : new Unread("mixed bytes missing"),
                TypeTimestamp => Pair((s, ns) => new Timestamp(s, (int)ns)),
                TypeObjectId => Bytes() is { Length: >= 12 } o ? new Id(o[..12], false) : new Unread("mixed object id missing"),
                TypeUuid => Bytes() is { Length: >= 16 } u ? new Id(u[..16], true) : new Unread("mixed UUID missing"),
                TypeDecimal => Pair((lo, hi) => Bid128((ulong)lo, (ulong)hi)),
                TypeLink => Small() is long key ? new Link(null, key) : new Unread("mixed link missing"),
                TypeTypedLink => Pair((t, k) => new Link(_tableNames.GetValueOrDefault(t & 0xFFFF), k)),
                _ when payload == 4 => new Unread("nested collection"),
                _ => new Unread($"mixed type {type}"),
            });
        }
        return list;
    }

    // Decimal128 at the leaf width: 0 (all null or zero), 4 (BID32), 8 (BID64) or 16 (BID128) bytes.
    private static object? DecimalAt(Node n, int i)
    {
        if (n.WType != 1) return new Unread("decimal layout");
        switch (n.Width)
        {
            case 0: return n.Context ? new Decimal("0") : null;
            case 4:
            {
                uint w = BinaryPrimitives.ReadUInt32LittleEndian(n.Data.AsSpan(i * 4));
                if (w == 0x7c0000aa) return null;
                bool sign = (w >> 31) != 0;
                if ((w >> 26 & 0x1F) is 0x1F) return new Decimal("NaN");
                if ((w >> 26 & 0x1F) is 0x1E) return new Decimal(sign ? "-Infinity" : "Infinity");
                bool large = (w >> 29 & 3) == 3;
                int exp = (int)(large ? w >> 21 & 0xFF : w >> 23 & 0xFF) - 101;
                BigInteger coef = large ? (w & 0x1FFFFF) | 0x800000 : w & 0x7FFFFF;
                return new Decimal(DecimalText(sign, coef, exp));
            }
            case 8:
            {
                ulong w = BinaryPrimitives.ReadUInt64LittleEndian(n.Data.AsSpan(i * 8));
                if (w == 0x7c000000000000aaUL) return null;
                bool sign = (w >> 63) != 0;
                if ((w >> 58 & 0x1F) is 0x1F) return new Decimal("NaN");
                if ((w >> 58 & 0x1F) is 0x1E) return new Decimal(sign ? "-Infinity" : "Infinity");
                bool large = (w >> 61 & 3) == 3;
                int exp = (int)(large ? w >> 51 & 0x3FF : w >> 53 & 0x3FF) - 398;
                BigInteger coef = large ? (w & ((1UL << 51) - 1)) | (1UL << 53) : w & ((1UL << 53) - 1);
                return new Decimal(DecimalText(sign, coef, exp));
            }
            case 16:
                return Bid128(BinaryPrimitives.ReadUInt64LittleEndian(n.Data.AsSpan(i * 16)), BinaryPrimitives.ReadUInt64LittleEndian(n.Data.AsSpan(i * 16 + 8)));
            default:
                return new Unread($"decimal width {n.Width}");
        }
    }

    private static object? Bid128(ulong lo, ulong hi)
    {
        if (lo == 0xaa && hi == 0x7c00000000000000UL) return null;
        bool sign = (hi >> 63) != 0;
        if ((hi >> 58 & 0x1F) is 0x1F) return new Decimal("NaN");
        if ((hi >> 58 & 0x1F) is 0x1E) return new Decimal(sign ? "-Infinity" : "Infinity");
        // A coefficient with the implicit 0b100 prefix exceeds 10^34 - 1 and reads as zero, as BSON specifies.
        bool large = (hi >> 61 & 3) == 3;
        int exp = (int)(large ? hi >> 47 & 0x3FFF : hi >> 49 & 0x3FFF) - 6176;
        BigInteger coef = large ? BigInteger.Zero : (new BigInteger(hi & ((1UL << 49) - 1)) << 64) | lo;
        if (coef >= BigInteger.Pow(10, 34)) coef = BigInteger.Zero;
        return new Decimal(DecimalText(sign, coef, exp));
    }

    /// <summary>The BSON Decimal128 text of sign, coefficient and exponent: plain digits, or scientific when the exponent is positive or the adjusted exponent is under -6.</summary>
    public static string DecimalText(bool sign, BigInteger coefficient, int exponent)
    {
        string digits = coefficient.ToString(System.Globalization.CultureInfo.InvariantCulture);
        int adjusted = exponent + digits.Length - 1;
        var sb = new StringBuilder(sign ? "-" : "");
        if (exponent > 0 || adjusted < -6)
        {
            sb.Append(digits[0]);
            if (digits.Length > 1) sb.Append('.').Append(digits, 1, digits.Length - 1);
            sb.Append('E').Append(adjusted >= 0 ? "+" : "").Append(adjusted);
        }
        else if (exponent == 0) sb.Append(digits);
        else
        {
            int point = digits.Length + exponent;
            if (point > 0) sb.Append(digits, 0, point).Append('.').Append(digits, point, digits.Length - point);
            else sb.Append("0.").Append('0', -point).Append(digits);
        }
        return sb.ToString();
    }

    /// <summary>Objects the previous commit holds that changed, then matching cluster leaves in free space; at most <paramref name="max"/>.</summary>
    public List<Recovered> Recover(int max, CancellationToken ct)
    {
        var found = new List<Recovered>();
        var seen = new HashSet<string>(StringComparer.Ordinal);
        var reached = new HashSet<long>();
        var live = new Dictionary<string, Dictionary<long, string>>();
        foreach (var t in Tables)
        {
            var map = new Dictionary<long, string>();
            foreach (var o in Objects(t, reached, ct))
            {
                string id = Identity(o.Values);
                if (o.Key is long k) map[k] = id;
                seen.Add(t.Name + "\n" + id);
            }
            live[t.Name] = map;
        }
        if (PreviousTopRef != 0)
        {
            var previous = ReadTables(PreviousTopRef, false);
            foreach (var t in previous)
            {
                if (!live.TryGetValue(t.Name, out var map) || Tables.FirstOrDefault(x => x.Name == t.Name) is not { } now || !SameColumns(now, t)) continue;
                foreach (var o in Objects(t, null, ct))
                {
                    if (found.Count >= max) return found;
                    string id = Identity(o.Values);
                    if (o.Key is not long k || map.TryGetValue(k, out var cur) && cur == id) continue;
                    if (!seen.Add(t.Name + "\n" + id)) continue;
                    found.Add(new Recovered(t.Name, o, map.ContainsKey(k) ? "previous commit: changed since" : "previous commit: deleted since"));
                }
            }
        }
        foreach (var (start, end) in FreeSpace())
        {
            for (long p = start; p + 8 <= end; p += 8)
            {
                ct.ThrowIfCancellationRequested();
                if (found.Count >= max) return found;
                if (reached.Contains(p) || Read(p, false) is not { HasRefs: true, Inner: false } n || n.Size < 2) continue;
                foreach (var t in Tables)
                {
                    int slots = t.Columns.Where(c => c.Type != TypeBackLink).Select(c => c.Index + 2).DefaultIfEmpty(0).Max();
                    int all = t.Columns.Select(c => c.Index + 2).DefaultIfEmpty(0).Max();
                    if (n.Size != all && n.Size != slots) continue;
                    var objs = Leaf(t, n, null, null);
                    if (objs.Count == 0 || objs.Any(o => o.Values.Any(v => v is Unread))) continue;
                    foreach (var o in objs)
                    {
                        if (found.Count >= max) return found;
                        if (seen.Add(t.Name + "\n" + Identity(o.Values))) found.Add(new Recovered(t.Name, o, $"free space at {p}"));
                    }
                    break;
                }
            }
        }
        return found;
    }

    private static bool SameColumns(Table a, Table b) =>
        a.Columns.Count == b.Columns.Count && a.Columns.Zip(b.Columns).All(p => p.First.Name == p.Second.Name && p.First.Type == p.Second.Type && p.First.Attributes == p.Second.Attributes && p.First.Index == p.Second.Index);

    // Free blocks (top slots 3 and 4) and bytes past the logical size (slot 2), sorted and merged.
    private List<(long Start, long End)> FreeSpace()
    {
        var blocks = new List<(long, long)>();
        if (Read(TopRef) is { } t && t.Size > 4)
        {
            if (Read(Ref(Int(t, 3))) is { } pos && Read(Ref(Int(t, 4))) is { } size && pos.Size == size.Size)
                for (int i = 0; i < pos.Size; i++)
                {
                    long s = Int(pos, i), e = s + Int(size, i);
                    if (s >= HeaderSize && e <= Length && e > s) blocks.Add((s, e));
                }
            if (Tagged(Int(t, 2)) is long logical && logical < Length) blocks.Add((Math.Max(HeaderSize, logical), Length));
        }
        else if (Streaming) blocks.Clear();
        blocks.Sort();
        var merged = new List<(long Start, long End)>();
        foreach (var (s, e) in blocks)
        {
            if (merged.Count > 0 && s <= merged[^1].End) merged[^1] = (merged[^1].Start, Math.Max(merged[^1].End, e));
            else merged.Add((s, e));
        }
        return merged;
    }

    /// <summary>Identifies an object's values for matching recovered objects against live ones.</summary>
    public static string Identity(IReadOnlyList<object?> values) => string.Join("\u001f", values.Select(Text));

    /// <summary>A value as display text: null, numbers in invariant round-trip form, timestamps in ISO 8601 UTC, ids as hex, links as Class#key.</summary>
    public static string Text(object? v) => v switch
    {
        null => "null",
        bool b => b ? "true" : "false",
        long l => l.ToString(System.Globalization.CultureInfo.InvariantCulture),
        float f => f.ToString("R", System.Globalization.CultureInfo.InvariantCulture),
        double d => d.ToString("R", System.Globalization.CultureInfo.InvariantCulture),
        string s => s,
        byte[] bytes => Convert.ToHexStringLower(bytes),
        Timestamp t => TimestampText(t),
        Decimal m => m.Text,
        Id id => id.Uuid ? new Guid(id.Bytes, true).ToString() : Convert.ToHexStringLower(id.Bytes),
        Link k => $"{(k.Table is { } t && t.StartsWith("class_", StringComparison.Ordinal) ? t[6..] : k.Table ?? "?")}#{k.Key}",
        Collection c => "[" + string.Join(", ", c.Items.Select(Text)) + "]",
        Map m => "{" + string.Join(", ", m.Entries.Select(e => e.Key + ": " + Text(e.Value))) + "}",
        Unread u => $"(unread: {u.Reason})",
        _ => v.ToString() ?? "",
    };

    private static string TimestampText(Timestamp t)
    {
        try { return DateTimeOffset.FromUnixTimeSeconds(t.Seconds).AddTicks(t.Nanoseconds / 100).UtcDateTime.ToString("yyyy-MM-dd'T'HH:mm:ss.FFFFFFF'Z'", System.Globalization.CultureInfo.InvariantCulture); }
        catch (ArgumentOutOfRangeException) { return $"{t.Seconds}s {t.Nanoseconds}ns"; }
    }

    // A node at ref r: a 0x41414141 or capacity word, flags, and a 24-bit element count, then the payload.
    private Node? Read(long r, bool note = true)
    {
        if (r <= 0 || (r & 7) != 0 || r + 8 > Length) return null;
        if (_cache.TryGetValue(r, out var hit)) return hit;
        Node? node = null;
        if (ReadAt(r, 8) is { } h)
        {
            byte flags = h[4];
            int width = (1 << (flags & 7)) >> 1, size = (h[5] << 16) | (h[6] << 8) | h[7];
            long bytes = ((flags >> 3) & 3) switch { 0 => ((long)size * width + 7) / 8, 1 => (long)size * width, 2 => size, _ => -1 };
            // An array of width 0 holds no bytes, so its size is bounded by the
            // file length.
            if (bytes >= 0 && bytes <= MaxNode && r + 8 + bytes <= Length && (flags & 0x18) != 0x18 && !((flags & 0x40) != 0 && (flags & 0x18) != 0)
                && (width > 0 || size <= Length))
            {
                if (ReadAt(r + 8, (int)bytes) is { } data) node = new Node(r, flags, width, size, data);
            }
            else if (note && bytes > MaxNode) Note($"node at {r}: {bytes:N0} bytes, over the {MaxNode >> 20} MiB read limit");
            else if (note && width == 0 && size > Length) Note($"node at {r}: {size:N0} values of width 0, more than the file's {Length:N0} bytes");
        }
        if (_cache.Count >= MaxCached) _cache.Clear();
        _cache[r] = node;
        return node;
    }

    // Element i of an integer array: widths 1, 2 and 4 pack low bits first; 8 to 64 are signed little-endian.
    private static long Int(Node n, int i)
    {
        if (i < 0 || i >= n.Size || n.WType != 0) return 0;
        return n.Width switch
        {
            0 => 0,
            1 or 2 or 4 => (n.Data[i * n.Width / 8] >> (i * n.Width % 8)) & ((1 << n.Width) - 1),
            8 => (sbyte)n.Data[i],
            16 => BinaryPrimitives.ReadInt16LittleEndian(n.Data.AsSpan(i * 2)),
            32 => BinaryPrimitives.ReadInt32LittleEndian(n.Data.AsSpan(i * 4)),
            _ => BinaryPrimitives.ReadInt64LittleEndian(n.Data.AsSpan(i * 8)),
        };
    }

    // Element i of an unsigned array (cluster keys and key offsets).
    private static ulong UInt(Node n, int i) => n.Width switch
    {
        8 => n.Data[i],
        16 => BinaryPrimitives.ReadUInt16LittleEndian(n.Data.AsSpan(i * 2)),
        32 => BinaryPrimitives.ReadUInt32LittleEndian(n.Data.AsSpan(i * 4)),
        64 => BinaryPrimitives.ReadUInt64LittleEndian(n.Data.AsSpan(i * 8)),
        _ => (ulong)Int(n, i),
    };

    private static long Ref(long v) => (v & 1) == 0 && v > 0 ? v : 0;

    private static long? Tagged(long v) => (v & 1) != 0 ? (long)((ulong)v >> 1) : null;

    private byte[]? ReadAt(long offset, int count)
    {
        if (offset < 0 || count < 0 || offset + count > Length) return null;
        var buffer = new byte[count];
        _stream.Position = offset;
        _stream.ReadExactly(buffer);
        return buffer;
    }
}
