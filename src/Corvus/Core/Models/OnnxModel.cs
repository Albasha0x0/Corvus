using System.Text;

namespace Corvus.Core.Models;

/// <summary>
/// An ONNX model (onnx.proto3 ModelProto) read field by field from a stream, tensor data skipped: the IR version,
/// producer, opsets, metadata, the main graph's inputs, outputs, operator counts and initializers, subgraph and function
/// counts, and the external data files initializers name. Values are those onnx.load(load_external_data=False) gives.
/// </summary>
public sealed class OnnxModel
{
    private const int MaxDepth = 32, MaxText = 500;
    private const long MaxItems = 5_000_000;

    /// <summary>A graph input or output: its name and type ("FLOAT[1,3,224,224]", "seq(INT64[N])").</summary>
    public sealed record Value(string Name, string Type);

    /// <summary>An initializer: its element type, dims, and the external file and offset its data is in (null when inline).</summary>
    public sealed record Initializer(string Name, string DataType, IReadOnlyList<long> Dims, string? Location, long? Offset, long? Length);

    private static readonly string[] DataTypes =
    [
        "UNDEFINED", "FLOAT", "UINT8", "INT8", "UINT16", "INT16", "INT32", "INT64", "STRING", "BOOL", "FLOAT16", "DOUBLE", "UINT32", "UINT64",
        "COMPLEX64", "COMPLEX128", "BFLOAT16", "FLOAT8E4M3FN", "FLOAT8E4M3FNUZ", "FLOAT8E5M2", "FLOAT8E5M2FNUZ", "UINT4", "INT4", "FLOAT4E2M1",
        "FLOAT8E8M0", "UINT2", "INT2", "FLOAT6E2M3", "FLOAT6E3M2",
    ];

    public long IrVersion { get; private set; }
    public string? ProducerName { get; private set; }
    public string? ProducerVersion { get; private set; }
    public string? Domain { get; private set; }
    public long ModelVersion { get; private set; }
    public string? DocString { get; private set; }
    /// <summary>Operator sets by domain ("" is the default ai.onnx domain).</summary>
    public List<(string Domain, long Version)> Opsets { get; } = [];
    public List<(string Key, string Value)> Metadata { get; } = [];
    public string? GraphName { get; private set; }
    public List<Value> Inputs { get; } = [];
    public List<Value> Outputs { get; } = [];
    /// <summary>Nodes of the main graph by "domain:op_type" (the default domain without a prefix).</summary>
    public SortedDictionary<string, int> Operators { get; } = new(StringComparer.Ordinal);
    public int Nodes { get; private set; }
    public List<Initializer> Initializers { get; } = [];
    public int SparseInitializers { get; private set; }
    /// <summary>Graphs held in node attributes (If, Loop, Scan bodies), at any depth, and their nodes.</summary>
    public int Subgraphs { get; private set; }
    public int SubgraphNodes { get; private set; }
    public List<string> Functions { get; } = [];
    public bool HasTrainingInfo { get; private set; }
    public List<string> Issues { get; } = [];

    private readonly Stream _s;
    private readonly CancellationToken _ct;
    private long _items;

    private OnnxModel(Stream s, CancellationToken ct)
    {
        _s = s;
        _ct = ct;
    }

    /// <summary>The head starts as a ModelProto does: ir_version (field 1) then a known ModelProto field.</summary>
    public static bool Looks(ReadOnlySpan<byte> head) =>
        head.Length >= 4 && head[0] == 0x08 && head[1] is >= 1 and <= 30 && head[2] is 0x12 or 0x1A or 0x22 or 0x28 or 0x32 or 0x3A or 0x42 or 0x72;

    /// <summary>The ONNX name of TensorProto.DataType <paramref name="type"/>, or its number.</summary>
    public static string DataType(long type) => type >= 0 && type < DataTypes.Length ? DataTypes[type] : type.ToString(System.Globalization.CultureInfo.InvariantCulture);

    /// <summary>Reads the model in <paramref name="s"/> (seekable, at its start); throws <see cref="InvalidDataException"/> when the top level is not a ModelProto.</summary>
    public static OnnxModel Read(Stream s, long length, CancellationToken ct = default)
    {
        var m = new OnnxModel(s, ct);
        var top = new Proto(m, 0, length);
        bool graph = false;
        while (top.Next(out var f))
            switch (f.Number, f.Wire)
            {
                case (1, 0): m.IrVersion = (long)f.Varint; break;
                case (2, 2): m.ProducerName = m.Text(f); break;
                case (3, 2): m.ProducerVersion = m.Text(f); break;
                case (4, 2): m.Domain = m.Text(f); break;
                case (5, 0): m.ModelVersion = (long)f.Varint; break;
                case (6, 2): m.DocString = m.Text(f); break;
                case (7, 2): graph = true; m.Graph(m.Sub(f), 0, main: true); break;
                case (8, 2): m.Opsets.Add(m.Opset(m.Sub(f))); break;
                case (14, 2): m.Metadata.Add(m.Pair(m.Sub(f))); break;
                case (20, 2): m.HasTrainingInfo = true; break;
                case (25, 2): m.Functions.Add(m.Function(m.Sub(f))); break;
                default:
                    if (f.Number is < 1 or > 26) throw new InvalidDataException($"field {f.Number} is not a ModelProto field");
                    break;
            }
        if (!graph && m.Opsets.Count == 0) throw new InvalidDataException("no graph and no opset_import");
        return m;
    }

    private readonly record struct Field(int Number, int Wire, ulong Varint, long Start, long Length);

    // A message's fields between two positions of the stream.
    private sealed class Proto(OnnxModel m, long start, long end)
    {
        private long _at = start;

        public bool Next(out Field f)
        {
            f = default;
            if (_at >= end) return false;
            if (++m._items > MaxItems) throw new InvalidDataException($"over {MaxItems:N0} fields");
            m._ct.ThrowIfCancellationRequested();
            ulong key = Varint();
            int wire = (int)(key & 7), number = (int)(key >> 3);
            switch (wire)
            {
                case 0: f = new Field(number, 0, Varint(), 0, 0); return true;
                case 1: f = new Field(number, 1, 0, _at, 8); _at += 8; break;
                case 2:
                    ulong n = Varint();
                    if (n > (ulong)(end - _at)) throw new InvalidDataException($"field {number} at {_at:N0} runs past its message");
                    f = new Field(number, 2, 0, _at, (long)n);
                    _at += (long)n;
                    break;
                case 5: f = new Field(number, 5, 0, _at, 4); _at += 4; break;
                default: throw new InvalidDataException($"wire type {wire} at {_at:N0}");
            }
            if (_at > end) throw new InvalidDataException($"field {number} runs past its message");
            return true;
        }

        private ulong Varint()
        {
            m._s.Position = _at;
            ulong v = 0;
            for (int shift = 0; shift < 64; shift += 7)
            {
                if (_at >= end) throw new InvalidDataException($"a varint at {_at:N0} runs past its message");
                int b = m._s.ReadByte();
                if (b < 0) throw new InvalidDataException("the file ends inside a varint");
                _at++;
                v |= (ulong)(b & 0x7F) << shift;
                if ((b & 0x80) == 0) return v;
            }
            throw new InvalidDataException($"a varint at {_at:N0} is over 10 bytes");
        }
    }

    private Proto Sub(Field f) => new(this, f.Start, f.Start + f.Length);

    private byte[] Bytes(Field f, int max)
    {
        var b = new byte[Math.Min(f.Length, max)];
        _s.Position = f.Start;
        _s.ReadExactly(b);
        return b;
    }

    private string Text(Field f)
    {
        var s = Encoding.UTF8.GetString(Bytes(f, MaxText * 4));
        return s.Length > MaxText || f.Length > MaxText * 4 ? s[..Math.Min(s.Length, MaxText)] + $"... ({f.Length:N0} bytes)" : s;
    }

    private (string, long) Opset(Proto p)
    {
        string domain = "";
        long version = 0;
        while (p.Next(out var f))
            if (f is { Number: 1, Wire: 2 }) domain = Text(f);
            else if (f is { Number: 2, Wire: 0 }) version = (long)f.Varint;
        return (domain, version);
    }

    private (string, string) Pair(Proto p)
    {
        string key = "", value = "";
        while (p.Next(out var f))
            if (f is { Number: 1, Wire: 2 }) key = Text(f);
            else if (f is { Number: 2, Wire: 2 }) value = Text(f);
        return (key, value);
    }

    private string Function(Proto p)
    {
        string name = "", domain = "";
        while (p.Next(out var f))
            if (f is { Number: 1, Wire: 2 }) name = Text(f);
            else if (f is { Number: 10, Wire: 2 }) domain = Text(f);
        return domain.Length > 0 ? $"{domain}:{name}" : name;
    }

    private void Graph(Proto p, int depth, bool main)
    {
        if (depth > MaxDepth) throw new InvalidDataException($"graphs nested deeper than {MaxDepth} levels");
        while (p.Next(out var f))
        {
            if (f.Wire != 2) continue;
            switch (f.Number)
            {
                case 1:
                    if (main) Nodes++; else SubgraphNodes++;
                    Node(Sub(f), depth, main);
                    break;
                case 2 when main: GraphName = Text(f); break;
                case 5 when main: Initializers.Add(Tensor(Sub(f))); break;
                case 11 when main: Inputs.Add(ValueInfo(Sub(f))); break;
                case 12 when main: Outputs.Add(ValueInfo(Sub(f))); break;
                case 15 when main: SparseInitializers++; break;
            }
        }
    }

    private void Node(Proto p, int depth, bool main)
    {
        string op = "", domain = "";
        while (p.Next(out var f))
        {
            if (f.Wire != 2) continue;
            if (f.Number == 4) op = Text(f);
            else if (f.Number == 7) domain = Text(f);
            else if (f.Number == 5) Attribute(Sub(f), depth);
        }
        if (main)
        {
            var key = domain is "" or "ai.onnx" ? op : $"{domain}:{op}";
            Operators[key] = Operators.GetValueOrDefault(key) + 1;
        }
    }

    // Attribute fields 6 (g) and 11 (graphs) hold subgraphs.
    private void Attribute(Proto p, int depth)
    {
        while (p.Next(out var f))
            if (f.Wire == 2 && f.Number is 6 or 11)
            {
                Subgraphs++;
                Graph(Sub(f), depth + 1, main: false);
            }
    }

    private Initializer Tensor(Proto p)
    {
        string name = "";
        long type = 0;
        var dims = new List<long>();
        string? location = null;
        long? offset = null, length = null;
        while (p.Next(out var f))
            switch (f.Number, f.Wire)
            {
                case (1, 0): dims.Add((long)f.Varint); break;
                case (1, 2): dims.AddRange(Packed(f)); break;
                case (2, 0): type = (long)f.Varint; break;
                case (8, 2): name = Text(f); break;
                case (13, 2):
                    var (k, v2) = Pair(Sub(f));
                    if (k == "location") location = v2;
                    else if (k == "offset" && long.TryParse(v2, out var o)) offset = o;
                    else if (k == "length" && long.TryParse(v2, out var l)) length = l;
                    break;
            }
        return new Initializer(name, DataType(type), dims, location, offset, length);
    }

    private IEnumerable<long> Packed(Field f)
    {
        var b = Bytes(f, int.MaxValue);
        int at = 0;
        while (at < b.Length)
        {
            ulong v = 0;
            for (int shift = 0; ; shift += 7)
            {
                if (at >= b.Length || shift >= 64) throw new InvalidDataException("a packed varint runs past its field");
                byte x = b[at++];
                v |= (ulong)(x & 0x7F) << shift;
                if ((x & 0x80) == 0) break;
            }
            yield return (long)v;
        }
    }

    private Value ValueInfo(Proto p)
    {
        string name = "", type = "";
        while (p.Next(out var f))
            if (f is { Number: 1, Wire: 2 }) name = Text(f);
            else if (f is { Number: 2, Wire: 2 }) type = Type(Sub(f), 0);
        return new Value(name, type);
    }

    // TypeProto: tensor_type 1, sequence_type 4, map_type 5, sparse_tensor_type 8, optional_type 9.
    private string Type(Proto p, int depth)
    {
        if (depth > MaxDepth) throw new InvalidDataException($"types nested deeper than {MaxDepth} levels");
        string type = "";
        while (p.Next(out var f))
        {
            if (f.Wire != 2) continue;
            switch (f.Number)
            {
                case 1: type = TensorType(Sub(f)); break;
                case 8: type = "sparse " + TensorType(Sub(f)); break;
                case 4 or 9:
                    string inner = "";
                    var q = Sub(f);
                    while (q.Next(out var g)) if (g is { Number: 1, Wire: 2 }) inner = Type(Sub(g), depth + 1);
                    type = (f.Number == 4 ? "seq(" : "optional(") + inner + ")";
                    break;
                case 5:
                    long key = 0;
                    string value = "";
                    var mp = Sub(f);
                    while (mp.Next(out var g))
                        if (g is { Number: 1, Wire: 0 }) key = (long)g.Varint;
                        else if (g is { Number: 2, Wire: 2 }) value = Type(Sub(g), depth + 1);
                    type = $"map({DataType(key)}, {value})";
                    break;
            }
        }
        return type;
    }

    private string TensorType(Proto p)
    {
        long elem = 0;
        List<string>? dims = null;
        while (p.Next(out var f))
            if (f is { Number: 1, Wire: 0 }) elem = (long)f.Varint;
            else if (f is { Number: 2, Wire: 2 })
            {
                dims = [];
                var shape = Sub(f);
                while (shape.Next(out var d))
                {
                    if (d is not { Number: 1, Wire: 2 }) continue;
                    string dim = "?";
                    var dp = Sub(d);
                    while (dp.Next(out var x))
                        if (x is { Number: 1, Wire: 0 }) dim = ((long)x.Varint).ToString(System.Globalization.CultureInfo.InvariantCulture);
                        else if (x is { Number: 2, Wire: 2 }) dim = Text(x);
                    dims.Add(dim);
                }
            }
        return DataType(elem) + (dims == null ? "" : "[" + string.Join(",", dims) + "]");
    }
}
