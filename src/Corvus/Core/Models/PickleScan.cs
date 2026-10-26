using System.Globalization;
using System.Numerics;
using System.Text;

namespace Corvus.Core.Models;

/// <summary>
/// A Python pickle (protocols 0 to 5) walked opcode by opcode on a symbolic stack; nothing it names is imported or called.
/// Reports the globals it imports, what each call opcode calls, the persistent ids, and how the result compares with
/// torch.load(weights_only=True): the imports outside its default allowlist and the opcodes it does not accept.
/// The symbolic result keeps the containers and calls, so a PyTorch checkpoint's tensors can be listed from it.
/// </summary>
public sealed class PickleScan
{
    private const long MaxOps = 100_000_000;
    private const int MaxKept = 100_000, MaxString = 1 << 16, MaxLine = 1 << 16;

    /// <summary>An imported global: "module.name", the opcode that names it, and how many times.</summary>
    public sealed record Import(string Name, string Opcode, int Count);

    // Symbolic values: primitives stay C# values (null, bool, BigInteger, double, string, Bytes).
    internal sealed record Bytes(long Length);
    internal sealed record Global(string Module, string Name)
    {
        public string Full => $"{Module}.{Name}";
    }
    internal sealed class PyList(List<object?> items) { public readonly List<object?> Items = items; public long Count = items.Count; }
    internal sealed class PyTuple(List<object?> items) { public readonly List<object?> Items = items; }
    internal sealed class PyDict { public readonly List<(object? Key, object? Value)> Pairs = []; public long Count; }
    internal sealed class PySet { public long Count; }
    internal sealed class Call(object? callee, object? args, string opcode)
    {
        public readonly object? Callee = callee, Args = args;
        public readonly string Opcode = opcode;
        public readonly PyDict Items = new();
        public readonly List<object?> Appended = [];
        public object? State;
    }
    internal sealed record Persistent(object? Id);
    private sealed record Opaque(string What);
    private sealed class Mark;

    // torch 2.14.1 torch._weights_only_unpickler._get_allowed_globals().
    private static readonly HashSet<string> WeightsOnlyGlobals = new(
        ("_codecs.encode builtins.bytearray builtins.complex builtins.set collections.Counter collections.OrderedDict torch.Size torch.Tensor " +
         "torch._tensor._rebuild_from_type_v2 torch._utils._rebuild_device_tensor_from_cpu_tensor torch._utils._rebuild_device_tensor_from_numpy " +
         "torch._utils._rebuild_meta_tensor_no_storage torch._utils._rebuild_nested_tensor torch._utils._rebuild_parameter " +
         "torch._utils._rebuild_parameter_with_state torch._utils._rebuild_qtensor torch._utils._rebuild_sparse_tensor torch._utils._rebuild_tensor " +
         "torch._utils._rebuild_tensor_v2 torch._utils._rebuild_tensor_v3 torch._utils._rebuild_wrapper_subclass torch.bcomplex32 torch.bfloat16 " +
         "torch.bits16 torch.bits1x8 torch.bits2x4 torch.bits4x2 torch.bits8 torch.bool torch.complex128 torch.complex32 torch.complex64 torch.device " +
         "torch.float16 torch.float32 torch.float4_e2m1fn_x2 torch.float64 torch.float8_e4m3fn torch.float8_e4m3fnuz torch.float8_e5m2 " +
         "torch.float8_e5m2fnuz torch.float8_e8m0fnu torch.int1 torch.int16 torch.int2 torch.int3 torch.int32 torch.int4 torch.int5 torch.int6 " +
         "torch.int64 torch.int7 torch.int8 torch.nn.parameter.Parameter torch.per_channel_affine torch.per_channel_affine_float_qparams " +
         "torch.per_channel_symmetric torch.per_tensor_affine torch.per_tensor_symmetric torch.qint32 torch.qint8 torch.quint2x4 torch.quint4x2 " +
         "torch.quint8 torch.serialization._get_layout torch.storage.TypedStorage torch.storage.UntypedStorage torch.uint1 torch.uint16 torch.uint2 " +
         "torch.uint3 torch.uint32 torch.uint4 torch.uint5 torch.uint6 torch.uint64 torch.uint7 torch.uint8 " +
         "torch.QInt32Storage torch.QInt8Storage torch.QUInt2x4Storage torch.QUInt4x2Storage torch.QUInt8Storage " +
         string.Join(" ", new[] { "BFloat16", "Bool", "Byte", "Char", "ComplexDouble", "ComplexFloat", "Double", "Float", "Half", "Int", "Long", "Short" }
             .SelectMany(t => new[] { $"torch.{t}Storage", $"torch.cuda.{t}Storage" })) + " " +
         string.Join(" ", new[] { "BFloat16", "Bool", "Byte", "Char", "Double", "Float", "Half", "Int", "Long", "Short" }
             .SelectMany(t => new[] { $"torch.{t}Tensor", $"torch.cuda.{t}Tensor" })) + " " +
         string.Join(" ", new[] { "BFloat16", "Byte", "Char", "Double", "Float", "Half", "Int", "Long", "Short" }
             .SelectMany(t => new[] { $"torch.sparse.{t}Tensor", $"torch.cuda.sparse.{t}Tensor" })))
        .Split(' ', StringSplitOptions.RemoveEmptyEntries), StringComparer.Ordinal);

    // The opcodes torch.load(weights_only=True) reads (torch 2.14.1 _weights_only_unpickler.Unpickler.load).
    private static readonly HashSet<string> WeightsOnlyOpcodes = new(
        ("GLOBAL NEWOBJ REDUCE BUILD APPEND APPENDS SETITEM SETITEMS MARK TUPLE TUPLE1 TUPLE2 TUPLE3 NONE NEWFALSE NEWTRUE EMPTY_TUPLE " +
         "EMPTY_LIST EMPTY_DICT EMPTY_SET BININT BININT1 BININT2 BINFLOAT BINUNICODE SHORT_BINSTRING BINPERSID BINGET LONG_BINGET BINPUT " +
         "LONG_BINPUT LONG1 PROTO STOP").Split(' '), StringComparer.Ordinal);

    private static readonly Dictionary<byte, string> Names = new()
    {
        [(byte)'I'] = "INT", [(byte)'J'] = "BININT", [(byte)'K'] = "BININT1", [(byte)'M'] = "BININT2", [(byte)'L'] = "LONG", [0x8a] = "LONG1",
        [0x8b] = "LONG4", [(byte)'S'] = "STRING", [(byte)'T'] = "BINSTRING", [(byte)'U'] = "SHORT_BINSTRING", [(byte)'B'] = "BINBYTES",
        [(byte)'C'] = "SHORT_BINBYTES", [0x8e] = "BINBYTES8", [0x96] = "BYTEARRAY8", [0x97] = "NEXT_BUFFER", [0x98] = "READONLY_BUFFER",
        [(byte)'N'] = "NONE", [0x88] = "NEWTRUE", [0x89] = "NEWFALSE", [(byte)'V'] = "UNICODE", [0x8c] = "SHORT_BINUNICODE",
        [(byte)'X'] = "BINUNICODE", [0x8d] = "BINUNICODE8", [(byte)'F'] = "FLOAT", [(byte)'G'] = "BINFLOAT", [(byte)']'] = "EMPTY_LIST",
        [(byte)'a'] = "APPEND", [(byte)'e'] = "APPENDS", [(byte)'l'] = "LIST", [(byte)')'] = "EMPTY_TUPLE", [(byte)'t'] = "TUPLE",
        [0x85] = "TUPLE1", [0x86] = "TUPLE2", [0x87] = "TUPLE3", [(byte)'}'] = "EMPTY_DICT", [(byte)'d'] = "DICT", [(byte)'s'] = "SETITEM",
        [(byte)'u'] = "SETITEMS", [0x8f] = "EMPTY_SET", [0x90] = "ADDITEMS", [0x91] = "FROZENSET", [(byte)'0'] = "POP", [(byte)'2'] = "DUP",
        [(byte)'('] = "MARK", [(byte)'1'] = "POP_MARK", [(byte)'g'] = "GET", [(byte)'h'] = "BINGET", [(byte)'j'] = "LONG_BINGET",
        [(byte)'p'] = "PUT", [(byte)'q'] = "BINPUT", [(byte)'r'] = "LONG_BINPUT", [0x94] = "MEMOIZE", [0x82] = "EXT1", [0x83] = "EXT2",
        [0x84] = "EXT4", [(byte)'c'] = "GLOBAL", [0x93] = "STACK_GLOBAL", [(byte)'R'] = "REDUCE", [(byte)'b'] = "BUILD", [(byte)'i'] = "INST",
        [(byte)'o'] = "OBJ", [0x81] = "NEWOBJ", [0x92] = "NEWOBJ_EX", [0x80] = "PROTO", [(byte)'.'] = "STOP", [0x95] = "FRAME",
        [(byte)'P'] = "PERSID", [(byte)'Q'] = "BINPERSID",
    };

    public int Protocol { get; private set; }
    public long Opcodes { get; private set; }
    /// <summary>The position after STOP; the end of the stream when the pickle does not end.</summary>
    public long End { get; private set; }
    public bool Complete { get; private set; }
    public List<Import> Imports { get; } = [];
    /// <summary>Calls (REDUCE, NEWOBJ, NEWOBJ_EX, OBJ, INST) by callee.</summary>
    public SortedDictionary<string, int> Calls { get; } = new(StringComparer.Ordinal);
    public int PersistentIds { get; private set; }
    /// <summary>Imports that torch.load(weights_only=True) refuses by default.</summary>
    public IEnumerable<string> OutsideWeightsOnly => Imports.Select(i => i.Name).Where(n => !WeightsOnlyGlobals.Contains(n));
    /// <summary>Opcodes in the pickle that torch.load(weights_only=True) does not read.</summary>
    public SortedSet<string> OpcodesOutsideWeightsOnly { get; } = new(StringComparer.Ordinal);
    public List<string> Issues { get; } = [];
    internal object? Result { get; private set; }

    private readonly Stream _s;
    private readonly long _end;
    private readonly Dictionary<string, int> _importAt = new(StringComparer.Ordinal);
    private readonly List<object?> _stack = [];
    private readonly Stack<List<object?>> _marks = new();
    private readonly Dictionary<long, object?> _memo = [];

    private PickleScan(Stream s, long end)
    {
        _s = s;
        _end = end;
    }

    /// <summary>The bytes start with a PROTO opcode of protocol 2 to 5.</summary>
    public static bool Looks(ReadOnlySpan<byte> head) => head.Length >= 3 && head[0] == 0x80 && head[1] is >= 2 and <= 5;

    /// <summary>
    /// Walks one pickle from the stream's position to STOP or <paramref name="end"/>. A malformed pickle ends the walk with
    /// its offset named in <see cref="Issues"/>; what was read before it is kept.
    /// </summary>
    public static PickleScan Read(Stream s, long end, CancellationToken ct = default)
    {
        var p = new PickleScan(s, end);
        long start = s.Position;
        try { p.Walk(ct); }
        catch (InvalidDataException ex) { p.Issues.Add($"{ex.Message} (offset {s.Position - start:N0})"); }
        catch (EndOfStreamException) { p.Issues.Add($"the pickle ends without STOP (offset {s.Position - start:N0})"); }
        p.End = s.Position;
        return p;
    }

    private void Walk(CancellationToken ct)
    {
        while (_s.Position < _end)
        {
            if (++Opcodes > MaxOps) throw new InvalidDataException($"over {MaxOps:N0} opcodes");
            if ((Opcodes & 0xFFFF) == 0) ct.ThrowIfCancellationRequested();
            int op = _s.ReadByte();
            if (op < 0) throw new EndOfStreamException();
            byte code = (byte)op;
            if (!Names.TryGetValue(code, out var name)) throw new InvalidDataException($"opcode 0x{code:X2} is not a pickle opcode");
            if (!WeightsOnlyOpcodes.Contains(name)) OpcodesOutsideWeightsOnly.Add(name);
            switch (code)
            {
                case 0x80: Protocol = U8(); break;
                case 0x95: ReadExactly(8); break;
                case (byte)'.': Result = Pop(); Complete = true; return;
                case (byte)'N': Push(null); break;
                case 0x88: Push(true); break;
                case 0x89: Push(false); break;
                case (byte)'I':
                    var line = Line();
                    Push(line is "00" ? false : line is "01" ? true : BigInteger.TryParse(line, CultureInfo.InvariantCulture, out var iv) ? iv : line);
                    break;
                case (byte)'L': Push(BigInteger.TryParse(Line().TrimEnd('L'), CultureInfo.InvariantCulture, out var lv) ? lv : null); break;
                case (byte)'J': Push(new BigInteger(BitConverter.ToInt32(ReadExactly(4)))); break;
                case (byte)'K': Push(new BigInteger(U8())); break;
                case (byte)'M': Push(new BigInteger(BitConverter.ToUInt16(ReadExactly(2)))); break;
                case 0x8a: Push(new BigInteger(ReadExactly(U8()), isUnsigned: false)); break;
                case 0x8b:
                    int n4 = BitConverter.ToInt32(ReadExactly(4));
                    if (n4 < 0 || n4 > MaxString) throw new InvalidDataException($"LONG4 of {n4:N0} bytes");
                    Push(new BigInteger(ReadExactly(n4), isUnsigned: false));
                    break;
                case (byte)'F': Push(double.TryParse(Line(), CultureInfo.InvariantCulture, out var fv) ? fv : null); break;
                case (byte)'G': var g = ReadExactly(8); Array.Reverse(g); Push(BitConverter.ToDouble(g)); break;
                case (byte)'S': Push(Unquote(Line())); break;
                case (byte)'V': Push(Line()); break;
                case (byte)'T': Push(Text(BitConverter.ToInt32(ReadExactly(4)))); break;
                case (byte)'U': Push(Text((ulong)U8())); break;
                case 0x8c: Push(Text((ulong)U8())); break;
                case (byte)'X': Push(Text(BitConverter.ToUInt32(ReadExactly(4)))); break;
                case 0x8d: Push(Text(BitConverter.ToUInt64(ReadExactly(8)))); break;
                case (byte)'C': Push(Blob((ulong)U8())); break;
                case (byte)'B': Push(Blob(BitConverter.ToUInt32(ReadExactly(4)))); break;
                case 0x8e or 0x96: Push(Blob(BitConverter.ToUInt64(ReadExactly(8)))); break;
                case 0x97: Push(new Opaque("out-of-band buffer")); break;
                case 0x98: break;
                case (byte)']': Push(new PyList([])); break;
                case (byte)')': Push(new PyTuple([])); break;
                case (byte)'}': Push(new PyDict()); break;
                case 0x8f: Push(new PySet()); break;
                case (byte)'l': Push(new PyList(Keep(PopMark()))); break;
                case (byte)'t': Push(new PyTuple(PopMark())); break;
                case 0x85: Push(new PyTuple([Pop()])); break;
                case 0x86: { var b = Pop(); var a = Pop(); Push(new PyTuple([a, b])); break; }
                case 0x87: { var c = Pop(); var b = Pop(); var a = Pop(); Push(new PyTuple([a, b, c])); break; }
                case (byte)'d':
                {
                    var items = PopMark();
                    var d = new PyDict();
                    SetItems(d, items);
                    Push(d);
                    break;
                }
                case 0x91: Push(new PySet { Count = PopMark().Count }); break;
                case (byte)'a': { var v = Pop(); Append(Top(), [v]); break; }
                case (byte)'e': { var items = PopMark(); Append(Top(), items); break; }
                case (byte)'s': { var v = Pop(); var k = Pop(); SetItems(Top(), [k, v]); break; }
                case (byte)'u': { var items = PopMark(); SetItems(Top(), items); break; }
                case 0x90: { var items = PopMark(); if (Top() is PySet set) set.Count += items.Count; break; }
                case (byte)'0':
                    if (_stack.Count > 0) _stack.RemoveAt(_stack.Count - 1);
                    else PopMark();
                    break;
                case (byte)'2': Push(Top()); break;
                case (byte)'(':
                    _marks.Push([.. _stack]);
                    _stack.Clear();
                    break;
                case (byte)'1': PopMark(); break;
                case (byte)'g': Push(Get(long.TryParse(Line(), CultureInfo.InvariantCulture, out var gi) ? gi : -1)); break;
                case (byte)'h': Push(Get(U8())); break;
                case (byte)'j': Push(Get(BitConverter.ToUInt32(ReadExactly(4)))); break;
                case (byte)'p': _memo[long.TryParse(Line(), CultureInfo.InvariantCulture, out var pi) ? pi : -1] = Top(); break;
                case (byte)'q': _memo[U8()] = Top(); break;
                case (byte)'r': _memo[BitConverter.ToUInt32(ReadExactly(4))] = Top(); break;
                case 0x94: _memo[_memo.Count] = Top(); break;
                case 0x82: Ext(U8()); break;
                case 0x83: Ext(BitConverter.ToUInt16(ReadExactly(2))); break;
                case 0x84: Ext(BitConverter.ToInt32(ReadExactly(4))); break;
                case (byte)'c':
                {
                    var module = Line();
                    Push(Name(module, Line(), "GLOBAL"));
                    break;
                }
                case 0x93:
                {
                    var n = Pop();
                    var m = Pop();
                    if (m is not string ms || n is not string ns) { Issues.Add("STACK_GLOBAL with operands that are not strings"); Push(new Global("?", "?")); }
                    else Push(Name(ms, ns, "STACK_GLOBAL"));
                    break;
                }
                case (byte)'i':
                {
                    var module = Line();
                    var cls = Name(module, Line(), "INST");
                    Push(Called(cls, new PyTuple(PopMark()), "INST"));
                    break;
                }
                case (byte)'o':
                {
                    var items = PopMark();
                    if (items.Count == 0) throw new InvalidDataException("OBJ without a class");
                    Push(Called(items[0], new PyTuple(items.GetRange(1, items.Count - 1)), "OBJ"));
                    break;
                }
                case (byte)'R': { var args = Pop(); var f = Pop(); Push(Called(f, args, "REDUCE")); break; }
                case 0x81: { var args = Pop(); var cls = Pop(); Push(Called(cls, args, "NEWOBJ")); break; }
                case 0x92: { Pop(); var args = Pop(); var cls = Pop(); Push(Called(cls, args, "NEWOBJ_EX")); break; }
                case (byte)'b': { var state = Pop(); if (Top() is Call c) c.State = state; break; }
                case (byte)'P': PersistentIds++; Push(new Persistent(Line())); break;
                case (byte)'Q': PersistentIds++; Push(new Persistent(Pop())); break;
            }
        }
        throw new EndOfStreamException();
    }

    private Global Name(string module, string name, string opcode)
    {
        var g = new Global(module, name);
        var full = g.Full;
        if (_importAt.TryGetValue(full, out var i)) Imports[i] = Imports[i] with { Count = Imports[i].Count + 1 };
        else
        {
            _importAt[full] = Imports.Count;
            Imports.Add(new Import(full, opcode, 1));
        }
        return g;
    }

    private Call Called(object? callee, object? args, string opcode)
    {
        var key = callee is Global g ? g.Full : "(not a global)";
        Calls[key] = Calls.GetValueOrDefault(key) + 1;
        return new Call(callee, args, opcode);
    }

    private void Ext(int code)
    {
        Issues.Add($"extension code {code} names a global through copyreg's registry, which a file does not record");
        Push(new Global("copyreg", $"extension {code}"));
    }

    private static List<object?> Keep(List<object?> items) => items.Count > MaxKept ? items.GetRange(0, MaxKept) : items;

    private static void Append(object? target, List<object?> items)
    {
        switch (target)
        {
            case PyList l:
                l.Count += items.Count;
                if (l.Items.Count < MaxKept) l.Items.AddRange(items.Take(MaxKept - l.Items.Count));
                break;
            case Call c when c.Appended.Count < MaxKept: c.Appended.AddRange(items.Take(MaxKept - c.Appended.Count)); break;
        }
    }

    private static void SetItems(object? target, List<object?> items)
    {
        var d = target switch { PyDict x => x, Call c => c.Items, _ => null };
        if (d == null) return;
        for (int i = 0; i + 1 < items.Count; i += 2)
        {
            d.Count++;
            if (d.Pairs.Count < MaxKept) d.Pairs.Add((items[i], items[i + 1]));
        }
    }

    private void Push(object? v) => _stack.Add(v);

    private object? Pop()
    {
        if (_stack.Count == 0) throw new InvalidDataException("the stack is empty");
        var v = _stack[^1];
        _stack.RemoveAt(_stack.Count - 1);
        return v;
    }

    private object? Top() => _stack.Count > 0 ? _stack[^1] : throw new InvalidDataException("the stack is empty");

    private List<object?> PopMark()
    {
        if (_marks.Count == 0) throw new InvalidDataException("no MARK to pop to");
        var items = new List<object?>(_stack);
        _stack.Clear();
        _stack.AddRange(_marks.Pop());
        return items;
    }

    private object? Get(long i) => _memo.TryGetValue(i, out var v) ? v : throw new InvalidDataException($"memo entry {i} is not set");

    private int U8()
    {
        int b = _s.ReadByte();
        return b < 0 ? throw new EndOfStreamException() : b;
    }

    private byte[] ReadExactly(int n)
    {
        if (n > _end - _s.Position) throw new EndOfStreamException();
        var b = new byte[n];
        _s.ReadExactly(b);
        return b;
    }

    private void Skip(long n)
    {
        if (n > _end - _s.Position) throw new EndOfStreamException();
        _s.Seek(n, SeekOrigin.Current);
    }

    private string Line()
    {
        var b = new List<byte>();
        while (true)
        {
            int c = _s.ReadByte();
            if (c < 0) throw new EndOfStreamException();
            if (c == '\n') break;
            if (b.Count >= MaxLine) throw new InvalidDataException($"a line over {MaxLine:N0} bytes");
            b.Add((byte)c);
        }
        return Encoding.UTF8.GetString([.. b]);
    }

    private string Text(ulong n)
    {
        if (n > (ulong)(_end - _s.Position)) throw new EndOfStreamException();
        if (n <= MaxString) return Encoding.UTF8.GetString(ReadExactly((int)n));
        var head = Encoding.UTF8.GetString(ReadExactly(MaxString));
        Skip((long)n - MaxString);
        return head + $"... ({n:N0} bytes)";
    }

    private string Text(int n) => n < 0 ? throw new InvalidDataException($"a string of {n} bytes") : Text((ulong)n);

    private Bytes Blob(ulong n)
    {
        if (n > (ulong)(_end - _s.Position)) throw new EndOfStreamException();
        Skip((long)n);
        return new Bytes((long)n);
    }

    private static string Unquote(string s) => s.Length >= 2 && (s[0] == '\'' || s[0] == '"') && s[^1] == s[0] ? s[1..^1] : s;

    /// <summary>A tensor of a PyTorch checkpoint: its path of dict keys, dtype, shape and storage.</summary>
    public sealed record TorchTensor(string Name, string Dtype, IReadOnlyList<long> Shape, string StorageKey, string? Location, long StorageOffset, long StorageElements);

    // torch.storage._dtype_to_storage_type_map, inverted.
    private static readonly Dictionary<string, string> StorageDtypes = new(StringComparer.Ordinal)
    {
        ["DoubleStorage"] = "float64", ["FloatStorage"] = "float32", ["HalfStorage"] = "float16", ["LongStorage"] = "int64", ["IntStorage"] = "int32",
        ["ShortStorage"] = "int16", ["CharStorage"] = "int8", ["ByteStorage"] = "uint8", ["BoolStorage"] = "bool", ["BFloat16Storage"] = "bfloat16",
        ["ComplexDoubleStorage"] = "complex128", ["ComplexFloatStorage"] = "complex64", ["QInt8Storage"] = "qint8", ["QInt32Storage"] = "qint32",
        ["QUInt8Storage"] = "quint8", ["QUInt4x2Storage"] = "quint4x2", ["QUInt2x4Storage"] = "quint2x4",
    };

    /// <summary>The tensors the result rebuilds with torch._utils._rebuild_tensor_v2 (directly or in a Parameter), named by their dict keys.</summary>
    public List<TorchTensor> TorchTensors(int max)
    {
        var found = new List<TorchTensor>();
        var seen = new HashSet<object>(ReferenceEqualityComparer.Instance);
        void Walk(object? v, string path, int depth)
        {
            if (found.Count >= max || depth > 64 || v == null || v is string || v.GetType().IsValueType || !seen.Add(v)) return;
            switch (v)
            {
                case Call { Callee: Global { Module: "torch._utils", Name: "_rebuild_tensor_v2" or "_rebuild_tensor" } } c when Tensor(c, path) is { } t:
                    found.Add(t);
                    return;
                case Call { Callee: Global { Module: "torch._utils", Name: "_rebuild_parameter" or "_rebuild_parameter_with_state" }, Args: PyTuple { Items.Count: > 0 } a }:
                    Walk(a.Items[0], path, depth + 1);
                    return;
                case Call c:
                    foreach (var (k, x) in c.Items.Pairs) Walk(x, Join(path, k), depth + 1);
                    if (c.State is PyDict st) foreach (var (k, x) in st.Pairs) Walk(x, Join(path, k), depth + 1);
                    return;
                case PyDict d:
                    foreach (var (k, x) in d.Pairs) Walk(x, Join(path, k), depth + 1);
                    return;
                case PyList l:
                    for (int i = 0; i < l.Items.Count; i++) Walk(l.Items[i], Join(path, i), depth + 1);
                    return;
                case PyTuple tu:
                    for (int i = 0; i < tu.Items.Count; i++) Walk(tu.Items[i], Join(path, i), depth + 1);
                    return;
            }
        }
        Walk(Result, "", 0);
        return found;
    }

    private static string Join(string path, object? key)
    {
        var k = key switch { string s => s, BigInteger b => b.ToString(CultureInfo.InvariantCulture), int i => i.ToString(CultureInfo.InvariantCulture), _ => "?" };
        return path.Length == 0 ? k : $"{path}.{k}";
    }

    // _rebuild_tensor_v2(storage, storage_offset, size, stride, ...); storage is a persistent id
    // ('storage', storage_type, key, location, numel).
    private static TorchTensor? Tensor(Call c, string path)
    {
        if (c.Args is not PyTuple { Items.Count: >= 3 } a || a.Items[0] is not Persistent { Id: PyTuple { Items.Count: >= 5 } id }) return null;
        var type = id.Items[1] is Global g ? g.Name : "?";
        var dtype = StorageDtypes.TryGetValue(type, out var d) ? d : type;
        var shape = a.Items[2] is PyTuple s ? s.Items.Select(x => x is BigInteger b ? (long)b : -1).ToList() : [];
        return new TorchTensor(path, dtype, shape, id.Items[2]?.ToString() ?? "?", id.Items[3] as string,
            a.Items[1] is BigInteger o ? (long)o : 0, id.Items[4] is BigInteger n ? (long)n : -1);
    }
}
