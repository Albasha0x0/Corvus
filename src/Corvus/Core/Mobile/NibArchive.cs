using System.Buffers.Binary;
using System.Text;

namespace Corvus.Core.Mobile;

/// <summary>A reference to another object of a nib's object graph, by index.</summary>
public sealed record NibRef(int Index);

/// <summary>One object of a compiled nib: its class and its fields in order; a field's value is a number, bool, string, byte[], <see cref="NibRef"/> or null.</summary>
public sealed record NibObject(int Index, string Class, IReadOnlyList<KeyValuePair<string, object?>> Fields)
{
    public object? this[string key] => Fields.FirstOrDefault(f => f.Key == key).Value;
}

/// <summary>Compiled nibs (NIBArchive or NSKeyedArchiver) as one object graph; malformed tables end the read with an issue.</summary>
public static class NibArchive
{
    private const int MaxCount = 1 << 20;

    public sealed record Graph(string Format, IReadOnlyList<NibObject> Objects, IReadOnlyList<string> Issues)
    {
        /// <summary>The object a value refers to, or null.</summary>
        public NibObject? Deref(object? value) => value is NibRef r && r.Index >= 0 && r.Index < Objects.Count ? Objects[r.Index] : null;

        /// <summary>A string value: inline, or an NSString-like object (NS.bytes, NS.string).</summary>
        public string? Text(object? value) => value switch
        {
            string s => s,
            byte[] b => Encoding.UTF8.GetString(b).TrimEnd('\0'),
            NibRef => Deref(value) is { } o ? Text(o["NS.bytes"] ?? o["NS.string"]) : null,
            _ => null,
        };
    }

    public static bool IsNibArchive(ReadOnlySpan<byte> b) => b.Length >= 50 && b.StartsWith("NIBArchive"u8);

    /// <summary>The graph of a NIBArchive file or a keyed archive; null when the bytes are neither.</summary>
    public static Graph? Read(byte[] data)
    {
        if (IsNibArchive(data)) return ReadNibArchive(data);
        return Keyed(Plist.Read(data));
    }

    /// <summary>The graph of a seekable stream: a keyed archive read without holding the file (values kept to <paramref name="maxValue"/> bytes), a NIBArchive read whole.</summary>
    public static Graph? Read(Stream data, int maxValue)
    {
        var head = new byte[50];
        data.Position = 0;
        int n = data.ReadAtLeast(head, head.Length, throwOnEndOfStream: false);
        data.Position = 0;
        if (IsNibArchive(head.AsSpan(0, n))) return ReadNibArchive(Blob.ReadBounded(data, Array.MaxLength) ?? []);
        return Keyed(Plist.Read(data, maxValue));
    }

    private static Graph? Keyed(PlistDocument doc) => KeyedArchive.IsKeyedArchive(doc.Root) && doc.Root is PlistDict root ? FromKeyedArchive(root) : null;

    private static Graph ReadNibArchive(byte[] d)
    {
        var issues = new List<string>();
        var objects = new List<NibObject>();
        uint U(int at) => BinaryPrimitives.ReadUInt32LittleEndian(d.AsSpan(at));
        uint objectCount = U(18), objectsAt = U(22), keyCount = U(26), keysAt = U(30), valueCount = U(34), valuesAt = U(38), classCount = U(42), classesAt = U(46);
        if (objectCount > MaxCount || keyCount > MaxCount || valueCount > MaxCount || classCount > MaxCount)
            return new Graph("NIBArchive", objects, ["a table count is out of range"]);
        try
        {
            var keys = new List<string>();
            int p = (int)keysAt;
            for (int i = 0; i < keyCount; i++)
            {
                int length = Varint(d, ref p);
                keys.Add(Encoding.UTF8.GetString(Slice(d, p, length)));
                p += length;
            }
            var classes = new List<string>();
            p = (int)classesAt;
            for (int i = 0; i < classCount; i++)
            {
                int length = Varint(d, ref p), extra = Varint(d, ref p);
                p += checked(extra * 4); // fallback classes
                classes.Add(Encoding.UTF8.GetString(Slice(d, p, length)).TrimEnd('\0'));
                p += length;
            }
            var values = new List<KeyValuePair<string, object?>>();
            p = (int)valuesAt;
            for (int i = 0; i < valueCount; i++)
            {
                int key = Varint(d, ref p);
                byte type = Slice(d, p, 1)[0];
                p++;
                object? value = type switch
                {
                    0 => (long)(sbyte)Slice(d, p, 1)[0],
                    1 => (long)BinaryPrimitives.ReadInt16LittleEndian(Slice(d, p, 2)),
                    2 => (long)BinaryPrimitives.ReadInt32LittleEndian(Slice(d, p, 4)),
                    3 => BinaryPrimitives.ReadInt64LittleEndian(Slice(d, p, 8)),
                    4 => false,
                    5 => true,
                    6 => (double)BinaryPrimitives.ReadSingleLittleEndian(Slice(d, p, 4)),
                    7 => BinaryPrimitives.ReadDoubleLittleEndian(Slice(d, p, 8)),
                    // Data is read below.
                    8 => null,
                    9 => null,
                    10 => new NibRef((int)BinaryPrimitives.ReadUInt32LittleEndian(Slice(d, p, 4))),
                    _ => throw new InvalidDataException($"value {i} has unknown type {type}"),
                };
                p += type switch { 0 => 1, 1 => 2, 2 or 6 or 10 => 4, 3 or 7 => 8, _ => 0 };
                if (type == 8)
                {
                    int length = Varint(d, ref p);
                    value = Slice(d, p, length).ToArray();
                    p += length;
                }
                values.Add(new(key < keys.Count ? keys[key] : $"key {key}", value));
            }
            p = (int)objectsAt;
            for (int i = 0; i < objectCount; i++)
            {
                int cls = Varint(d, ref p), start = Varint(d, ref p), count = Varint(d, ref p);
                if (start < 0 || count < 0 || (long)start + count > values.Count) throw new InvalidDataException($"object {i} names values past the table");
                objects.Add(new NibObject(i, cls < classes.Count ? classes[cls] : $"class {cls}", values.GetRange(start, count)));
            }
        }
        catch (Exception e) when (e is InvalidDataException or OverflowException or ArgumentOutOfRangeException)
        {
            issues.Add(e.Message);
        }
        return new Graph("NIBArchive", objects, issues);
    }

    private static ReadOnlySpan<byte> Slice(byte[] d, int at, int length) =>
        at >= 0 && length >= 0 && (long)at + length <= d.Length ? d.AsSpan(at, length) : throw new InvalidDataException($"a field at {at} runs past the end");

    private static int Varint(byte[] d, ref int p)
    {
        int value = 0;
        for (int shift = 0; shift < 32; shift += 7)
        {
            byte b = Slice(d, p++, 1)[0];
            value |= (b & 0x7F) << shift;
            if ((b & 0x80) != 0) return value;
        }
        throw new InvalidDataException("a varint is too long");
    }

    /// <summary>The raw $objects of a keyed archive as the same graph: $class resolved to its $classname, UIDs as references.</summary>
    private static Graph FromKeyedArchive(PlistDict root)
    {
        var issues = new List<string>();
        var items = (root["$objects"] as PlistArray)?.Items ?? [];
        var objects = new List<NibObject>(items.Count);
        string ClassOf(PlistDict o) => o["$class"] is PlistUid u && u.Value < (ulong)items.Count && items[(int)u.Value] is PlistDict c && c["$classname"] is PlistString n ? n.Value : "";
        object? Value(PlistNode n) => n switch
        {
            PlistUid u => u.Value < (ulong)items.Count ? new NibRef((int)u.Value) : null,
            PlistString s => s.Value,
            PlistInteger i => i.Value >= long.MinValue && i.Value <= long.MaxValue ? (long)i.Value : null,
            PlistReal r => r.Value,
            PlistBool b => b.Value,
            PlistData b => b.Value,
            _ => null,
        };
        for (int i = 0; i < items.Count; i++)
            objects.Add(items[i] switch
            {
                PlistDict o => new NibObject(i, ClassOf(o), o.Entries.Where(e => e.Key != "$class").Select(e => new KeyValuePair<string, object?>(e.Key, Value(e.Value))).ToList()),
                // A plain string object reads as NSString's NS.string field.
                PlistString s => new NibObject(i, "NSString", [new("NS.string", s.Value)]),
                _ => new NibObject(i, "", []),
            });
        return new Graph("keyed archive", objects, issues);
    }
}
