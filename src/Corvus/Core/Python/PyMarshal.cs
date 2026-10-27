using System.Buffers.Binary;
using System.Numerics;
using System.Text;

namespace Corvus.Core.Python;

/// <summary>Python's None, Ellipsis and StopIteration as marshal writes them.</summary>
public sealed class PySingleton
{
    public static readonly PySingleton None = new("None"), Ellipsis = new("Ellipsis"), StopIteration = new("StopIteration");
    private PySingleton(string name) => Name = name;
    public string Name { get; }
    public override string ToString() => Name;
}

/// <summary>A Python bytes object (a str in Python 2, interned or not; a Python 2 unicode reads as a string).</summary>
public sealed record PyBytes(byte[] Value);

/// <summary>A tuple, list, set or frozenset.</summary>
public sealed record PySequence(char Kind, object[] Items);

public sealed record PyDict(List<KeyValuePair<object, object>> Items);

public sealed record PySlice(object Start, object Stop, object Step);

/// <summary>A complex constant.</summary>
public sealed record PyComplex(double Real, double Imaginary);

/// <summary>A code object of any layout from 2.7 to 3.14; 3.11+ fills <see cref="LocalsPlusNames"/> instead of separate lists.</summary>
public sealed class PyCode
{
    public int ArgCount { get; set; }
    public int PosOnlyArgCount { get; set; }
    public int KwOnlyArgCount { get; set; }
    public int NLocals { get; set; }
    public int StackSize { get; set; }
    public int Flags { get; set; }
    public int FirstLineNo { get; set; }
    public byte[] Code { get; set; } = [];
    public object[] Consts { get; set; } = [];
    public object[] Names { get; set; } = [];
    public object[] VarNames { get; set; } = [];
    public object[] FreeVars { get; set; } = [];
    public object[] CellVars { get; set; } = [];
    public object[] LocalsPlusNames { get; set; } = [];
    public byte[] LocalsPlusKinds { get; set; } = [];
    public string Filename { get; set; } = "";
    public string Name { get; set; } = "";
    public string QualName { get; set; } = "";
    /// <summary>co_lnotab (before 3.10) or co_linetable.</summary>
    public byte[] LineTable { get; set; } = [];
    public byte[] ExceptionTable { get; set; } = [];
}

/// <summary>The marshal format of Python 2.7 to 3.14, read with checked counts, bounded nesting and back references to read objects only.</summary>
public sealed class PyMarshal
{
    private const int MaxDepth = 400;
    /// <summary>15-bit digits of one integer constant (about 74,000 decimal digits; the 3.3 standard library has 24,000).</summary>
    private const int MaxLongDigits = 16384;
    private readonly byte[] _data;
    private int _pos, _depth;
    private readonly List<object?> _refs = [];
    // Python 2 'R' references.
    private readonly List<PyBytes> _interned = [];
    private readonly (int Major, int Minor) _version;

    private PyMarshal(byte[] data, int start, (int, int) version)
    {
        _data = data;
        _pos = start;
        _version = version;
    }

    /// <summary>The bytes the object at the start used.</summary>
    public int Consumed => _pos;

    /// <summary>One object at <paramref name="start"/>, in the layout of Python <paramref name="version"/>.</summary>
    public static object Read(byte[] data, (int Major, int Minor) version, int start = 0) => Read(data, version, start, out _);

    public static object Read(byte[] data, (int Major, int Minor) version, int start, out int end)
    {
        var r = new PyMarshal(data, start, version);
        var o = r.Object();
        end = r._pos;
        return o;
    }

    /// <summary>The object, or null with the reason when the data is no marshal object of that version.</summary>
    public static object? TryRead(byte[] data, (int Major, int Minor) version, out string? error, int start = 0)
    {
        try { error = null; return Read(data, version, start); }
        catch (ToolError ex) { error = ex.Message; return null; }
    }

    private ToolError Bad(string what) => new(ErrorCode.MalformedInput, $"marshal data: {what} at byte {_pos}.");

    private ReadOnlySpan<byte> Take(int n)
    {
        if (n < 0 || _pos > _data.Length - n) throw Bad("truncated data");
        var s = _data.AsSpan(_pos, n);
        _pos += n;
        return s;
    }

    private byte Byte() => Take(1)[0];
    private int Int32() => BinaryPrimitives.ReadInt32LittleEndian(Take(4));

    private int Count()
    {
        int n = Int32();
        if (n < 0 || n > _data.Length - _pos) throw Bad($"count {n} past the data");
        return n;
    }

    private object Object()
    {
        if (++_depth > MaxDepth) throw Bad("nesting too deep");
        try { return ObjectCore(); }
        finally { _depth--; }
    }

    private object ObjectCore()
    {
        byte code = Byte();
        bool flag = (code & 0x80) != 0 && _version.Major >= 3;
        char type = (char)(code & (_version.Major >= 3 ? 0x7F : 0xFF));
        int slot = -1;
        if (flag && type is not ('r' or '0' or 'N' or 'F' or 'T' or '.' or 'S'))
        {
            slot = _refs.Count;
            _refs.Add(null);
        }
        object o = type switch
        {
            '0' => throw Bad("NULL object"),
            'N' => PySingleton.None,
            'F' => false,
            'T' => true,
            '.' => PySingleton.Ellipsis,
            'S' => PySingleton.StopIteration,
            'i' => (long)Int32(),
            'I' => BinaryPrimitives.ReadInt64LittleEndian(Take(8)),
            'l' => Long(),
            'f' => ParseFloat(Encoding.ASCII.GetString(Take(Byte()))),
            'g' => BinaryPrimitives.ReadDoubleLittleEndian(Take(8)),
            'x' => new PyComplex(ParseFloat(Encoding.ASCII.GetString(Take(Byte()))), ParseFloat(Encoding.ASCII.GetString(Take(Byte())))),
            'y' => new PyComplex(BinaryPrimitives.ReadDoubleLittleEndian(Take(8)), BinaryPrimitives.ReadDoubleLittleEndian(Take(8))),
            's' => new PyBytes(Take(Count()).ToArray()),
            't' when _version.Major == 2 => Interned(new PyBytes(Take(Count()).ToArray())),
            't' => Utf8(Take(Count())),
            'R' => InternedRef(),
            'u' => Utf8(Take(Count())),
            'a' or 'A' => Encoding.Latin1.GetString(Take(Count())),
            'z' or 'Z' => Encoding.Latin1.GetString(Take(Byte())),
            '(' or '[' or '<' or '>' => Sequence(type == '(' ? '(' : type, Count()),
            ')' => Sequence('(', Byte()),
            '{' => Dict(),
            ':' => new PySlice(Object(), Object(), Object()),
            'c' => Code(),
            'r' => Ref(),
            _ => throw Bad($"unknown type code 0x{code:X2}"),
        };
        if (slot >= 0) _refs[slot] = o;
        return o;
    }

    /// <summary>UTF-8 as marshal writes it, with surrogatepass: an encoded lone surrogate (ED A0..BF xx) stays a lone surrogate.</summary>
    private static string Utf8(ReadOnlySpan<byte> b)
    {
        if (b.IndexOf((byte)0xED) < 0) return Encoding.UTF8.GetString(b);
        var sb = new StringBuilder(b.Length);
        int i = 0;
        while (i < b.Length)
        {
            if (b[i] == 0xED && i + 2 < b.Length && b[i + 1] is >= 0xA0 and <= 0xBF && (b[i + 2] & 0xC0) == 0x80)
            {
                sb.Append((char)(0xD000 | (b[i + 1] & 0x3F) << 6 | b[i + 2] & 0x3F));
                i += 3;
                continue;
            }
            int next = b[(i + 1)..].IndexOf((byte)0xED);
            int end = next < 0 ? b.Length : i + 1 + next;
            sb.Append(Encoding.UTF8.GetString(b[i..end]));
            i = end;
        }
        return sb.ToString();
    }

    private static double ParseFloat(string s) => s switch
    {
        "inf" => double.PositiveInfinity,
        "-inf" => double.NegativeInfinity,
        "nan" or "-nan" => double.NaN,
        _ => double.TryParse(s, System.Globalization.NumberStyles.Float, System.Globalization.CultureInfo.InvariantCulture, out var d) ? d : double.NaN,
    };

    private PyBytes Interned(PyBytes s)
    {
        _interned.Add(s);
        return s;
    }

    private PyBytes InternedRef()
    {
        int i = Int32();
        return i >= 0 && i < _interned.Count ? _interned[i] : throw Bad($"string reference {i} not yet read");
    }

    private object Ref()
    {
        int i = Int32();
        return i >= 0 && i < _refs.Count && _refs[i] is { } o ? o : throw Bad($"reference {i} not yet read");
    }

    /// <summary>A long: a signed digit count, then 15-bit digits, least significant first.</summary>
    private object Long()
    {
        int n = Int32();
        int count = n == int.MinValue ? -1 : Math.Abs(n);
        if (count < 0 || count > MaxLongDigits || count > (_data.Length - _pos) / 2) throw Bad($"long of {n} digits");
        var digits = Take(count * 2);
        // Packed into little-endian bytes: building by shifts is quadratic in the digit count.
        var bits = new byte[(count * 15 + 7) / 8 + 1];
        for (int i = 0; i < count; i++)
        {
            int d = BinaryPrimitives.ReadUInt16LittleEndian(digits[(i * 2)..]);
            if (d > 0x7FFF) throw Bad("long digit out of range");
            int at = i * 15;
            int word = d << (at & 7);
            for (int k = at >> 3; word != 0; k++, word >>= 8) bits[k] |= (byte)word;
        }
        var v = new BigInteger(bits, isUnsigned: true);
        if (n < 0) v = -v;
        // A Python 2 long stays a BigInteger: its repr carries an L.
        return _version.Major >= 3 && v >= long.MinValue && v <= long.MaxValue ? (long)v : v;
    }

    private PySequence Sequence(char kind, int n)
    {
        if (n > _data.Length - _pos) throw Bad($"{n} items past the data");
        var items = new object[n];
        var seq = new PySequence(kind, items);
        for (int i = 0; i < n; i++) items[i] = Object();
        return seq;
    }

    private PyDict Dict()
    {
        var items = new List<KeyValuePair<object, object>>();
        while (true)
        {
            if (_pos < _data.Length && _data[_pos] == (byte)'0') { _pos++; return new PyDict(items); }
            var key = Object();
            items.Add(new(key, Object()));
        }
    }

    private PyCode Code()
    {
        var c = new PyCode();
        var v = _version;
        int major = v.Major;
        c.ArgCount = Int32();
        if (PyVersion.AtLeast(v, 3, 8)) c.PosOnlyArgCount = Int32();
        if (major >= 3) c.KwOnlyArgCount = Int32();
        if (!PyVersion.AtLeast(v, 3, 11)) c.NLocals = Int32();
        c.StackSize = Int32();
        c.Flags = Int32();
        c.Code = Bytes(Object(), "co_code");
        c.Consts = Tuple(Object());
        c.Names = Tuple(Object());
        if (PyVersion.AtLeast(v, 3, 11))
        {
            c.LocalsPlusNames = Tuple(Object());
            c.LocalsPlusKinds = Bytes(Object(), "co_localspluskinds");
        }
        else
        {
            c.VarNames = Tuple(Object());
            c.FreeVars = Tuple(Object());
            c.CellVars = Tuple(Object());
        }
        c.Filename = Str(Object());
        c.Name = Str(Object());
        c.QualName = PyVersion.AtLeast(v, 3, 11) ? Str(Object()) : c.Name;
        c.FirstLineNo = Int32();
        c.LineTable = Bytes(Object(), "co_linetable");
        if (PyVersion.AtLeast(v, 3, 11)) c.ExceptionTable = Bytes(Object(), "co_exceptiontable");
        return c;
    }

    private byte[] Bytes(object o, string field) => o is PyBytes b ? b.Value : throw Bad($"{field} is not bytes");
    private object[] Tuple(object o) => o is PySequence { Kind: '(' } t ? t.Items : throw Bad("a code field is not a tuple");

    /// <summary>A name: a str, or a Python 2 byte string read as Latin-1.</summary>
    public static string Str(object o) => o switch
    {
        string s => s,
        PyBytes b => Encoding.Latin1.GetString(b.Value),
        _ => "",
    };
}
