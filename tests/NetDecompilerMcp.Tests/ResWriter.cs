using System.Buffers.Binary;
using System.Text;

namespace NetDecompilerMcp.Tests;

/// <summary>Writes Android resource string pools the way aapt2 does (UTF-16 or UTF-8, 4-byte aligned).</summary>
internal sealed class ResStringPoolWriter(bool utf8)
{
    private readonly List<string> _strings = [];
    private readonly Dictionary<string, int> _index = new(StringComparer.Ordinal);

    public int Count => _strings.Count;

    /// <summary>Adds a new slot even when the text is already pooled (attribute names carrying distinct resource ids).</summary>
    public uint AddSlot(string s)
    {
        _strings.Add(s);
        _index.TryAdd(s, _strings.Count - 1);
        return (uint)(_strings.Count - 1);
    }

    public uint Add(string s)
    {
        if (!_index.TryGetValue(s, out int i)) { i = _strings.Count; _strings.Add(s); _index[s] = i; }
        return (uint)i;
    }

    public byte[] Build()
    {
        var data = new MemoryStream();
        var offsets = new List<int>();
        foreach (var s in _strings)
        {
            offsets.Add((int)data.Length);
            if (utf8)
            {
                var bytes = Encoding.UTF8.GetBytes(s);
                Length8(data, s.Length);
                Length8(data, bytes.Length);
                data.Write(bytes);
                data.WriteByte(0);
            }
            else
            {
                if (s.Length > 0x7FFF) { U16(data, (ushort)(0x8000 | s.Length >> 16)); U16(data, (ushort)s.Length); }
                else U16(data, (ushort)s.Length);
                data.Write(Encoding.Unicode.GetBytes(s));
                U16(data, 0);
            }
        }
        while (data.Length % 4 != 0) data.WriteByte(0);
        int header = 28, stringsStart = header + 4 * _strings.Count;
        var chunk = new byte[stringsStart + data.Length];
        BinaryPrimitives.WriteUInt16LittleEndian(chunk, 0x0001);
        BinaryPrimitives.WriteUInt16LittleEndian(chunk.AsSpan(2), (ushort)header);
        BinaryPrimitives.WriteUInt32LittleEndian(chunk.AsSpan(4), (uint)chunk.Length);
        BinaryPrimitives.WriteUInt32LittleEndian(chunk.AsSpan(8), (uint)_strings.Count);
        BinaryPrimitives.WriteUInt32LittleEndian(chunk.AsSpan(16), utf8 ? 0x100u : 0u);
        BinaryPrimitives.WriteUInt32LittleEndian(chunk.AsSpan(20), (uint)stringsStart);
        for (int i = 0; i < offsets.Count; i++) BinaryPrimitives.WriteUInt32LittleEndian(chunk.AsSpan(header + 4 * i), (uint)offsets[i]);
        data.ToArray().CopyTo(chunk, stringsStart);
        return chunk;
    }

    private static void Length8(Stream s, int length)
    {
        if (length > 0x7F) { s.WriteByte((byte)(0x80 | length >> 8)); s.WriteByte((byte)length); }
        else s.WriteByte((byte)length);
    }

    private static void U16(Stream s, ushort v) { s.WriteByte((byte)v); s.WriteByte((byte)(v >> 8)); }
}

/// <summary>Little-endian chunk assembly helpers.</summary>
internal static class Chunk
{
    public static byte[] Make(ushort type, byte[] header, params byte[][] bodies)
    {
        int size = 8 + header.Length + bodies.Sum(b => b.Length);
        var chunk = new byte[size];
        BinaryPrimitives.WriteUInt16LittleEndian(chunk, type);
        BinaryPrimitives.WriteUInt16LittleEndian(chunk.AsSpan(2), (ushort)(8 + header.Length));
        BinaryPrimitives.WriteUInt32LittleEndian(chunk.AsSpan(4), (uint)size);
        header.CopyTo(chunk, 8);
        int at = 8 + header.Length;
        foreach (var b in bodies) { b.CopyTo(chunk, at); at += b.Length; }
        return chunk;
    }

    public static byte[] U32s(params uint[] values)
    {
        var b = new byte[values.Length * 4];
        for (int i = 0; i < values.Length; i++) BinaryPrimitives.WriteUInt32LittleEndian(b.AsSpan(i * 4), values[i]);
        return b;
    }

    public static byte[] Value(byte type, uint data)
    {
        var b = new byte[8];
        BinaryPrimitives.WriteUInt16LittleEndian(b, 8);
        b[3] = type;
        BinaryPrimitives.WriteUInt32LittleEndian(b.AsSpan(4), data);
        return b;
    }
}

/// <summary>Writes Android binary XML from an element tree, laid out as aapt2 does (attribute names with ids first in the pool).</summary>
internal static class AxmlWriter
{
    public const string Android = "http://schemas.android.com/apk/res/android";

    public sealed record Attr(string? Ns, string Name, uint ResId, byte Type, uint Data, string? Raw = null);

    public sealed class Node(string name, params Attr[] attributes)
    {
        public string Name { get; } = name;
        public Attr[] Attributes { get; } = attributes;
        public List<Node> Children { get; } = [];
        public string? Text { get; init; }
        public Node Add(params Node[] children) { Children.AddRange(children); return this; }
    }

    public static Attr String(string name, string value, uint resId = 0, string? ns = Android) => new(ns, name, resId, 0x03, uint.MaxValue, value);
    public static Attr Int(string name, int value, uint resId = 0) => new(Android, name, resId, 0x10, (uint)value);
    public static Attr Bool(string name, bool value, uint resId = 0) => new(Android, name, resId, 0x12, value ? uint.MaxValue : 0);
    public static Attr Ref(string name, uint target, uint resId = 0) => new(Android, name, resId, 0x01, target);

    public static byte[] Write(Node root, bool utf8 = false, (string Prefix, string Uri)[]? namespaces = null)
    {
        namespaces ??= [("android", Android)];
        var pool = new ResStringPoolWriter(utf8);
        var ids = new List<uint>();
        var slots = new Dictionary<(string, uint), uint>();
        // Attribute names that carry resource ids come first, one slot per (name, id), in resource map order.
        foreach (var a in All(root).SelectMany(n => n.Attributes).Where(a => a.ResId != 0))
            if (!slots.ContainsKey((a.Name, a.ResId)))
            {
                slots[(a.Name, a.ResId)] = pool.AddSlot(a.Name);
                ids.Add(a.ResId);
            }
        var body = new List<byte[]>();
        foreach (var (prefix, uri) in namespaces)
            body.Add(Chunk.Make(0x0100, Chunk.U32s(1, uint.MaxValue), Chunk.U32s(pool.Add(prefix), pool.Add(uri))));
        Element(root, pool, slots, body, 2);
        foreach (var (prefix, uri) in Enumerable.Reverse(namespaces))
            body.Add(Chunk.Make(0x0101, Chunk.U32s(99, uint.MaxValue), Chunk.U32s(pool.Add(prefix), pool.Add(uri))));
        var map = Chunk.Make(0x0180, [], Chunk.U32s([.. ids]));
        return Chunk.Make(0x0003, [], [pool.Build(), map, .. body]);
    }

    private static IEnumerable<Node> All(Node n) => n.Children.SelectMany(All).Prepend(n);

    private static void Element(Node n, ResStringPoolWriter pool, Dictionary<(string, uint), uint> slots, List<byte[]> body, int line)
    {
        uint Ns(string? ns) => ns == null ? uint.MaxValue : pool.Add(ns);
        var attrs = new MemoryStream();
        foreach (var a in n.Attributes)
        {
            uint name = a.ResId != 0 ? slots[(a.Name, a.ResId)] : pool.Add(a.Name);
            uint raw = a.Raw == null ? uint.MaxValue : pool.Add(a.Raw);
            uint data = a.Type == 0x03 ? raw : a.Data;
            attrs.Write(Chunk.U32s(Ns(a.Ns), name, raw));
            attrs.Write(Chunk.Value(a.Type, data));
        }
        var ext = new byte[20];
        BinaryPrimitives.WriteUInt32LittleEndian(ext, uint.MaxValue);
        BinaryPrimitives.WriteUInt32LittleEndian(ext.AsSpan(4), pool.Add(n.Name));
        BinaryPrimitives.WriteUInt16LittleEndian(ext.AsSpan(8), 20);
        BinaryPrimitives.WriteUInt16LittleEndian(ext.AsSpan(10), 20);
        BinaryPrimitives.WriteUInt16LittleEndian(ext.AsSpan(12), (ushort)n.Attributes.Length);
        body.Add(Chunk.Make(0x0102, Chunk.U32s((uint)line, uint.MaxValue), ext, attrs.ToArray()));
        if (n.Text != null) body.Add(Chunk.Make(0x0104, Chunk.U32s((uint)line, uint.MaxValue), Chunk.U32s(pool.Add(n.Text)), Chunk.Value(0, 0)));
        foreach (var c in n.Children) Element(c, pool, slots, body, line + 1);
        body.Add(Chunk.Make(0x0103, Chunk.U32s((uint)line, uint.MaxValue), Chunk.U32s(uint.MaxValue, pool.Add(n.Name))));
    }
}

/// <summary>Builds a resources.arsc with one package; entries in the layouts aapt2 can emit (dense, sparse, 16-bit offsets, compact).</summary>
internal sealed class ArscWriter(uint packageId, string packageName)
{
    public enum Layout { Dense, Sparse, Offset16, Compact }

    private sealed record Item(string Type, string Key, byte[] Config, byte DataType, uint Data, string? Text, uint Parent, (uint Name, byte Type, uint Data)[]? Map);

    private readonly List<Item> _items = [];
    private readonly List<string> _types = [];
    private readonly Dictionary<string, List<string>> _keys = [];

    /// <summary>A 64-byte ResTable_config.</summary>
    public static byte[] Config(string? language = null, string? region = null, ushort density = 0, ushort sdk = 0, bool night = false, string? script = null)
    {
        var c = new byte[64];
        BinaryPrimitives.WriteUInt32LittleEndian(c, 64);
        if (language != null) { c[8] = (byte)language[0]; c[9] = (byte)language[1]; }
        if (region != null) { c[10] = (byte)region[0]; c[11] = (byte)region[1]; }
        BinaryPrimitives.WriteUInt16LittleEndian(c.AsSpan(14), density);
        BinaryPrimitives.WriteUInt16LittleEndian(c.AsSpan(24), sdk);
        if (night) c[29] = 0x20;
        if (script != null) Encoding.ASCII.GetBytes(script).CopyTo(c, 36);
        return c;
    }

    private uint Id(string type, string key)
    {
        if (!_types.Contains(type)) { _types.Add(type); _keys[type] = []; }
        var keys = _keys[type];
        if (!keys.Contains(key)) keys.Add(key);
        return packageId << 24 | (uint)(_types.IndexOf(type) + 1) << 16 | (uint)keys.IndexOf(key);
    }

    public uint Value(string type, string key, byte dataType, uint data, byte[]? config = null)
    {
        _items.Add(new(type, key, config ?? Config(), dataType, data, null, 0, null));
        return Id(type, key);
    }

    public uint String(string type, string key, string text, byte[]? config = null)
    {
        _items.Add(new(type, key, config ?? Config(), 0x03, 0, text, 0, null));
        return Id(type, key);
    }

    public uint Bag(string type, string key, uint parent, params (uint Name, byte Type, uint Data)[] map)
    {
        _items.Add(new(type, key, Config(), 0, 0, null, parent, map));
        return Id(type, key);
    }

    public byte[] Build(Layout layout = Layout.Dense, bool utf8 = false)
    {
        var values = new ResStringPoolWriter(utf8);
        var typePool = new ResStringPoolWriter(utf8);
        var keyPool = new ResStringPoolWriter(utf8);
        foreach (var t in _types) typePool.Add(t);
        foreach (var t in _types) foreach (var k in _keys[t]) keyPool.Add(k);
        var typeBytes = typePool.Build();
        var keyBytes = keyPool.Build();
        var chunks = new List<byte[]>();
        for (int ti = 0; ti < _types.Count; ti++)
        {
            var type = _types[ti];
            int count = _keys[type].Count;
            chunks.Add(Chunk.Make(0x0202, [(byte)(ti + 1), 0, 0, 0, .. Chunk.U32s((uint)count)], Chunk.U32s(new uint[count])));
            foreach (var group in _items.Where(i => i.Type == type).GroupBy(i => Convert.ToHexString(i.Config)))
                chunks.Add(TypeChunk(ti + 1, count, group.ToList(), values, keyPool, layout));
        }
        var header = new byte[288 - 8];
        BinaryPrimitives.WriteUInt32LittleEndian(header, packageId);
        Encoding.Unicode.GetBytes(packageName).CopyTo(header, 4);
        BinaryPrimitives.WriteUInt32LittleEndian(header.AsSpan(260), 288);
        BinaryPrimitives.WriteUInt32LittleEndian(header.AsSpan(264), (uint)_types.Count);
        BinaryPrimitives.WriteUInt32LittleEndian(header.AsSpan(268), (uint)(288 + typeBytes.Length));
        BinaryPrimitives.WriteUInt32LittleEndian(header.AsSpan(272), (uint)keyPool.Count);
        var package = Chunk.Make(0x0200, header, [typeBytes, keyBytes, .. chunks]);
        return Chunk.Make(0x0002, Chunk.U32s(1), values.Build(), package);
    }

    private byte[] TypeChunk(int typeId, int count, List<Item> items, ResStringPoolWriter values, ResStringPoolWriter keys, Layout layout)
    {
        var entries = new MemoryStream();
        var offsets = new Dictionary<int, int>();
        foreach (var item in items)
        {
            int index = _keys[item.Type].IndexOf(item.Key);
            offsets[index] = (int)entries.Length;
            uint key = keys.Add(item.Key);
            uint data = item.Text != null ? values.Add(item.Text) : item.Data;
            if (item.Map != null)
            {
                entries.Write([16, 0, 1, 0]);
                entries.Write(Chunk.U32s(key, item.Parent, (uint)item.Map.Length));
                foreach (var (name, type, value) in item.Map) { entries.Write(Chunk.U32s(name)); entries.Write(Chunk.Value(type, value)); }
            }
            else if (layout == Layout.Compact)
            {
                entries.Write([(byte)key, (byte)(key >> 8), 0x08, item.DataType]);
                entries.Write(Chunk.U32s(data));
            }
            else
            {
                entries.Write([8, 0, 0, 0]);
                entries.Write(Chunk.U32s(key));
                entries.Write(Chunk.Value(item.DataType, data));
            }
        }
        byte[] table;
        byte flags = 0;
        int slots = count;
        switch (layout)
        {
            case Layout.Sparse:
                flags = 0x01;
                slots = offsets.Count;
                table = new byte[slots * 4];
                int s = 0;
                foreach (var (index, off) in offsets.OrderBy(o => o.Key))
                {
                    BinaryPrimitives.WriteUInt16LittleEndian(table.AsSpan(s * 4), (ushort)index);
                    BinaryPrimitives.WriteUInt16LittleEndian(table.AsSpan(s * 4 + 2), (ushort)(off / 4));
                    s++;
                }
                break;
            case Layout.Offset16:
                flags = 0x02;
                table = new byte[(count * 2 + 3) & ~3];
                for (int i = 0; i < count; i++)
                    BinaryPrimitives.WriteUInt16LittleEndian(table.AsSpan(i * 2), offsets.TryGetValue(i, out var o) ? (ushort)(o / 4) : (ushort)0xFFFF);
                break;
            default:
                table = Chunk.U32s([.. Enumerable.Range(0, count).Select(i => offsets.TryGetValue(i, out var o) ? (uint)o : uint.MaxValue)]);
                break;
        }
        int headerSize = 20 + 64;
        var header = new byte[headerSize - 8];
        header[0] = (byte)typeId;
        header[1] = flags;
        BinaryPrimitives.WriteUInt32LittleEndian(header.AsSpan(4), (uint)slots);
        BinaryPrimitives.WriteUInt32LittleEndian(header.AsSpan(8), (uint)(headerSize + table.Length));
        items[0].Config.CopyTo(header, 12);
        return Chunk.Make(0x0201, header, table, entries.ToArray());
    }
}
