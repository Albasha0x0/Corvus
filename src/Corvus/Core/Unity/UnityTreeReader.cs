using System.Globalization;
using System.Text;

namespace Corvus.Core.Unity;

/// <summary>A top-level field an object's type tree reads: its name, type and value as text.</summary>
public sealed record UnityFieldValue(string Name, string Type, string Value);

/// <summary>A string an object's field holds, at any depth: its path ("hosts[2]", "readings[0].label") and whole text.</summary>
public readonly record struct UnityFieldText(string Field, string Text);

/// <summary>
/// Collects the whole strings an object's fields hold, up to <see cref="Max"/>; Dropped counts the rest. A field whose
/// read fails adds nothing; top-level fields named in <see cref="Skipped"/> add nothing either.
/// </summary>
internal sealed class UnityTextSink(int max, IReadOnlySet<string>? skipped = null)
{
    public readonly List<UnityFieldText> Texts = [];
    public int Dropped;
    public int Max => max;
    public IReadOnlySet<string>? Skipped => skipped;
}

/// <summary>
/// Reads an object's data through a type tree (the file's own or one built from a script's assembly) and shows each
/// top-level field as text. Values are clipped for display; every byte is still read, so the end position checks the
/// layout against the object's size. A <see cref="UnityTextSink"/> receives the strings whole.
/// </summary>
internal sealed class UnityTreeReader
{
    private const int MaxText = 120, MaxShown = 8, MaxValue = 400, MaxDepth = 64;
    private const long MaxElements = 4_000_000;
    // A longer string is kept to its first 1 MB, the length Values scans.
    private const int MaxTextBytes = 1 << 20;

    private readonly IReadOnlyList<UnityTypeNode> _nodes;
    private readonly int[] _end;
    private readonly UnityBinary _r;
    private readonly UnityTextSink? _sink;
    private readonly List<UnityFieldText> _pending = [];
    private long _elements;

    private UnityTreeReader(IReadOnlyList<UnityTypeNode> nodes, UnityBinary r, UnityTextSink? sink)
    {
        _nodes = nodes;
        _r = r;
        _sink = sink;
        _end = new int[nodes.Count];
        for (int i = nodes.Count - 1; i >= 0; i--)
        {
            int j = i + 1;
            while (j < nodes.Count && nodes[j].Level > nodes[i].Level) j = _end[j];
            _end[i] = j;
        }
    }

    /// <summary>
    /// The top-level fields of the tree's root read from <paramref name="r"/>, in order; throws
    /// <see cref="InvalidDataException"/> when the data ends early or a node has no size this reader knows.
    /// </summary>
    public static List<UnityFieldValue> Read(IReadOnlyList<UnityTypeNode> tree, UnityBinary r, UnityTextSink? sink = null)
    {
        var fields = new List<UnityFieldValue>();
        if (tree.Count == 0) return fields;
        var reader = new UnityTreeReader(tree, r, sink);
        for (int c = 1; c < reader._end[0]; c = reader._end[c])
        {
            fields.Add(new UnityFieldValue(tree[c].Name, tree[c].Type, Clip(reader.Value(c, 1, tree[c].Name), MaxValue)));
            reader.Commit(tree[c].Name);
        }
        if (tree[0].Align) r.Align();
        return fields;
    }

    /// <summary>
    /// The top-level fields read up to the first one the data does not fit, which <c>Field</c> and <c>Failure</c>
    /// name (both null when every field reads).
    /// </summary>
    public static (List<UnityFieldValue> Fields, string? Field, string? Failure) ReadUntilFailure(IReadOnlyList<UnityTypeNode> tree, UnityBinary r,
        UnityTextSink? sink = null)
    {
        var fields = new List<UnityFieldValue>();
        if (tree.Count == 0) return (fields, null, null);
        var reader = new UnityTreeReader(tree, r, sink);
        for (int c = 1; c < reader._end[0]; c = reader._end[c])
        {
            try
            {
                fields.Add(new UnityFieldValue(tree[c].Name, tree[c].Type, Clip(reader.Value(c, 1, tree[c].Name), MaxValue)));
                reader.Commit(tree[c].Name);
            }
            catch (InvalidDataException e)
            {
                reader._pending.Clear();
                return (fields, tree[c].Name, e.Message);
            }
        }
        if (tree[0].Align) r.Align();
        return (fields, null, null);
    }

    /// <summary>Moves the strings of the top-level field just read to the sink, up to its limit.</summary>
    private void Commit(string field)
    {
        if (_sink == null) return;
        if (_sink.Skipped?.Contains(field) != true)
        {
            int room = Math.Max(0, _sink.Max - _sink.Texts.Count);
            _sink.Texts.AddRange(_pending.Take(room));
            _sink.Dropped += Math.Max(0, _pending.Count - room);
        }
        _pending.Clear();
    }

    private string Value(int i, int depth, string path)
    {
        if (depth > MaxDepth) throw new InvalidDataException("a type tree nested deeper than this reader reads");
        var n = _nodes[i];
        int first = i + 1, stop = _end[i];
        string value;
        int array = n.IsArray ? i : first < stop && _nodes[first].IsArray && _end[first] == stop ? first : -1;
        if (first == stop) value = Leaf(n);
        else if (array >= 0) value = Array(array, n.Type == "string", depth, path);
        else
        {
            var parts = new List<string>();
            for (int c = first; c < stop; c = _end[c]) parts.Add($"{_nodes[c].Name} = {Value(c, depth + 1, _sink == null ? path : $"{path}.{_nodes[c].Name}")}");
            value = n.Type.StartsWith("PPtr<", StringComparison.Ordinal) && parts.Count == 2 ? Pointer(n.Type, parts) : "{" + string.Join(", ", parts) + "}";
        }
        if (n.Align) _r.Align();
        return value;
    }

    /// <summary>An array node: its size child, then that many elements of its data child.</summary>
    private string Array(int a, bool text, int depth, string path)
    {
        int size = a + 1, data = size < _end[a] ? _end[size] : -1;
        if (data < 0 || data >= _end[a]) throw new InvalidDataException($"array {_nodes[a].Name} has no element type");
        int count = _r.I32();
        var element = _nodes[data];
        bool leaf = data + 1 == _end[data];
        if (count < 0 || (leaf && element.ByteSize > 0 ? (long)count * element.ByteSize > _r.Remaining : count > _r.Remaining && element.ByteSize != 0))
            throw new InvalidDataException($"array {_nodes[a].Name} of {count} elements at 0x{_r.Position - 4:x} runs past the object");
        if ((_elements += count) > MaxElements) throw new InvalidDataException($"more than {MaxElements:N0} array elements in one object");
        string value;
        if (leaf && element.ByteSize == 1)
        {
            var bytes = _r.Bytes(count);
            if (text && _sink != null) _pending.Add(new UnityFieldText(path, Encoding.UTF8.GetString(bytes, 0, Math.Min(bytes.Length, MaxTextBytes))));
            value = text ? Quote(Encoding.UTF8.GetString(bytes)) : $"<{count} bytes>";
        }
        else
        {
            var shown = new List<string>();
            for (int k = 0; k < count; k++)
            {
                var v = Value(data, depth + 1, _sink == null ? path : $"{path}[{k}]");
                if (k < MaxShown) shown.Add(v);
            }
            value = $"[{count}] [{string.Join(", ", shown)}{(count > MaxShown ? ", ..." : "")}]";
        }
        if (_nodes[a].Align) _r.Align();
        return value;
    }

    private string Leaf(UnityTypeNode n) => n.Type switch
    {
        "bool" => _r.Bool() ? "true" : "false",
        "UInt8" when (n.MetaFlag & UnityTypeNode.BooleanFlag) != 0 => _r.Bool() ? "true" : "false",
        "SInt8" => ((sbyte)_r.U8()).ToString(CultureInfo.InvariantCulture),
        "UInt8" or "char" => _r.U8().ToString(CultureInfo.InvariantCulture),
        "SInt16" or "short" => _r.I16().ToString(CultureInfo.InvariantCulture),
        "UInt16" or "unsigned short" => _r.U16().ToString(CultureInfo.InvariantCulture),
        "int" or "SInt32" => _r.I32().ToString(CultureInfo.InvariantCulture),
        "UInt32" or "unsigned int" or "Type*" => _r.U32().ToString(CultureInfo.InvariantCulture),
        "long long" or "SInt64" => _r.I64().ToString(CultureInfo.InvariantCulture),
        "UInt64" or "unsigned long long" or "FileSize" => _r.U64().ToString(CultureInfo.InvariantCulture),
        "float" => _r.F32().ToString(CultureInfo.InvariantCulture),
        "double" => _r.F64().ToString(CultureInfo.InvariantCulture),
        "ReferencedObjectData" => throw new InvalidDataException("[SerializeReference] data, laid out by the type each reference names"),
        _ when n.ByteSize == 0 => "{}",
        _ when n.ByteSize > 0 => Skip(n.ByteSize),
        _ => throw new InvalidDataException($"type tree node {n.Type} {n.Name} has no size this reader knows"),
    };

    private string Skip(int size)
    {
        _r.Skip(size);
        return $"<{size} bytes>";
    }

    /// <summary>A PPtr as "null" or "PPtr&lt;T&gt;(file F, path P)"; file 0 is the same file.</summary>
    private static string Pointer(string type, List<string> parts)
    {
        string file = parts[0][(parts[0].IndexOf(" = ", StringComparison.Ordinal) + 3)..];
        string path = parts[1][(parts[1].IndexOf(" = ", StringComparison.Ordinal) + 3)..];
        return file == "0" && path == "0" ? "null" : $"{type}(file {file}, path {path})";
    }

    private static string Quote(string s) => "\"" + Clip(s.Replace("\\", "\\\\").Replace("\"", "\\\"").Replace("\n", "\\n").Replace("\r", "\\r"), MaxText) + "\"";

    private static string Clip(string s, int max) => s.Length <= max ? s : s[..max] + "...";
}
