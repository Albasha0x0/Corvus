using System.Buffers.Binary;
using System.Globalization;
using System.Numerics;
using System.Text;

namespace Corvus.Core.Models;

/// <summary>
/// A GGUF file (versions 1 to 3, either byte order): the metadata key-value pairs and the tensor infos, with each tensor's
/// type, shape, place in the file and size, as the gguf Python package's GGUFReader reads them. Array values keep their
/// type, length and first values.
/// </summary>
public sealed class Gguf
{
    private const int MaxDepth = 8, Preview = 8, MaxText = 500;
    private const long MaxEntries = 10_000_000;

    /// <summary>A metadata value: its type ("u32", "string", "array[string]"), its text (or first values of an array) and an array's length.</summary>
    public sealed record Entry(string Key, string Type, string Value, long? Count);

    /// <summary>A tensor: <see cref="Shape"/> in file order (innermost dimension first); <see cref="Offset"/> is absolute.</summary>
    public sealed record Tensor(string Name, string Type, IReadOnlyList<ulong> Shape, long Offset, long? Size);

    /// <summary>GGML tensor types: name, elements per block, bytes per block (gguf.constants.GGML_QUANT_SIZES).</summary>
    private static readonly Dictionary<uint, (string Name, int Block, int Bytes)> Types = new()
    {
        [0] = ("F32", 1, 4), [1] = ("F16", 1, 2), [2] = ("Q4_0", 32, 18), [3] = ("Q4_1", 32, 20), [6] = ("Q5_0", 32, 22), [7] = ("Q5_1", 32, 24),
        [8] = ("Q8_0", 32, 34), [9] = ("Q8_1", 32, 40), [10] = ("Q2_K", 256, 84), [11] = ("Q3_K", 256, 110), [12] = ("Q4_K", 256, 144),
        [13] = ("Q5_K", 256, 176), [14] = ("Q6_K", 256, 210), [15] = ("Q8_K", 256, 292), [16] = ("IQ2_XXS", 256, 66), [17] = ("IQ2_XS", 256, 74),
        [18] = ("IQ3_XXS", 256, 98), [19] = ("IQ1_S", 256, 50), [20] = ("IQ4_NL", 32, 18), [21] = ("IQ3_S", 256, 110), [22] = ("IQ2_S", 256, 82),
        [23] = ("IQ4_XS", 256, 136), [24] = ("I8", 1, 1), [25] = ("I16", 1, 2), [26] = ("I32", 1, 4), [27] = ("I64", 1, 8), [28] = ("F64", 1, 8),
        [29] = ("IQ1_M", 256, 56), [30] = ("BF16", 1, 2), [34] = ("TQ1_0", 256, 54), [35] = ("TQ2_0", 256, 66), [39] = ("MXFP4", 32, 17),
        [40] = ("NVFP4", 64, 36), [41] = ("Q1_0", 128, 18),
    };

    private static readonly string[] ValueTypes = ["u8", "i8", "u16", "i16", "u32", "i32", "f32", "bool", "string", "array", "u64", "i64", "f64"];
    private static readonly int[] ValueSizes = [1, 1, 2, 2, 4, 4, 4, 1, 0, 0, 8, 8, 8];

    public uint Version { get; private set; }
    public bool BigEndian { get; private set; }
    public List<Entry> Metadata { get; } = [];
    public List<Tensor> Tensors { get; } = [];
    /// <summary>Where the tensor data starts: the end of the tensor infos aligned to <see cref="Alignment"/>.</summary>
    public long DataOffset { get; private set; }
    public uint Alignment { get; private set; } = 32;
    public List<string> Issues { get; } = [];

    private readonly Stream _s;
    private readonly long _length;
    private readonly byte[] _buf = new byte[8];
    private long _entries;

    private Gguf(Stream s, long length)
    {
        _s = s;
        _length = length;
    }

    /// <summary>The file starts with "GGUF".</summary>
    public static bool Looks(ReadOnlySpan<byte> head) => head.Length >= 8 && head.StartsWith("GGUF"u8);

    /// <summary>The name of GGML tensor type <paramref name="type"/>; null when the gguf package does not define it.</summary>
    public static string? TypeName(uint type) => Types.TryGetValue(type, out var t) ? t.Name : null;

    /// <summary>Reads the header from <paramref name="s"/> (at the file's start); throws <see cref="InvalidDataException"/> when it is not GGUF or ends early.</summary>
    public static Gguf Read(Stream s, long length, CancellationToken ct = default)
    {
        var g = new Gguf(new BufferedStream(s, 1 << 16), length);
        g.ReadHeader(ct);
        return g;
    }

    private void ReadHeader(CancellationToken ct)
    {
        Fill(4);
        if (!_buf.AsSpan(0, 4).SequenceEqual("GGUF"u8)) throw new InvalidDataException("no GGUF magic");
        Fill(4);
        uint v = BinaryPrimitives.ReadUInt32LittleEndian(_buf);
        // A big-endian file reads as a version with its low 16 bits clear.
        if ((v & 0xFFFF) == 0 && v != 0) { BigEndian = true; v = BinaryPrimitives.ReverseEndianness(v); }
        if (v is < 1 or > 3) throw new InvalidDataException($"GGUF version {v} is not 1 to 3");
        Version = v;
        ulong tensors = Count(), kvs = Count();
        if (kvs > (ulong)(_length - _s.Position) / 8 || tensors > (ulong)(_length - _s.Position) / 8)
            throw new InvalidDataException($"{tensors:N0} tensors and {kvs:N0} metadata entries cannot fit in the file");
        for (ulong i = 0; i < kvs; i++)
        {
            ct.ThrowIfCancellationRequested();
            var key = String();
            uint type = U32();
            var (text, count, typeName) = Value(type, 0);
            Metadata.Add(new Entry(key, typeName, text, count));
            if (key == "general.alignment" && type == 4 && uint.TryParse(text, CultureInfo.InvariantCulture, out var a))
            {
                if (a == 0 || (a & (a - 1)) != 0) Issues.Add($"general.alignment {a} is not a power of two; 32 is used");
                else Alignment = a;
            }
        }
        var infos = new List<(string Name, uint Type, ulong[] Dims, ulong Offset)>();
        for (ulong i = 0; i < tensors; i++)
        {
            ct.ThrowIfCancellationRequested();
            var name = String();
            uint n = U32();
            if (n > 16) throw new InvalidDataException($"{name}: {n} dimensions");
            var dims = new ulong[n];
            for (int d = 0; d < n; d++) dims[d] = Version == 1 ? U32() : U64();
            infos.Add((name, U32(), dims, U64()));
        }
        long end = _s.Position;
        DataOffset = (end + Alignment - 1) / Alignment * Alignment;
        foreach (var (name, type, dims, offset) in infos)
        {
            long at = DataOffset + (long)Math.Min(offset, (ulong)long.MaxValue / 2);
            long? size = null;
            if (Types.TryGetValue(type, out var t))
            {
                BigInteger elements = 1;
                foreach (var d in dims) elements *= d;
                if (elements % t.Block != 0) Issues.Add($"{name}: {elements} elements are not whole {t.Name} blocks of {t.Block}");
                var bytes = elements / t.Block * t.Bytes;
                if (bytes <= long.MaxValue) size = (long)bytes;
            }
            else Issues.Add($"{name}: unknown tensor type {type}");
            if (offset % Alignment != 0) Issues.Add($"{name}: offset {offset:N0} is not aligned to {Alignment}");
            if (size is { } sz && at + sz > _length) Issues.Add($"{name}: ends at {at + sz:N0}, past the file's {_length:N0} bytes");
            Tensors.Add(new Tensor(name, TypeName(type) ?? $"type {type}", dims, at, size));
        }
    }

    private (string Text, long? Count, string Type) Value(uint type, int depth)
    {
        if (++_entries > MaxEntries) throw new InvalidDataException($"over {MaxEntries:N0} metadata values");
        if (type >= ValueTypes.Length) throw new InvalidDataException($"metadata value type {type}");
        switch (type)
        {
            case 8:
                return (Clip(String()), null, "string");
            case 9:
                if (depth >= MaxDepth) throw new InvalidDataException($"arrays nested deeper than {MaxDepth} levels");
                uint item = U32();
                ulong count = Count();
                if (item >= ValueTypes.Length) throw new InvalidDataException($"array item type {item}");
                var shown = new List<string>();
                string itemType = item == 9 ? "array" : ValueTypes[item];
                if (ValueSizes[item] > 0)
                {
                    ulong bytes = count * (ulong)ValueSizes[item];
                    if (count > (ulong)_length || bytes > (ulong)(_length - _s.Position)) throw new InvalidDataException($"an array of {count:N0} {itemType} runs past the end");
                    for (ulong i = 0; i < Math.Min(count, Preview); i++) shown.Add(Scalar(item));
                    if (count > Preview) Skip((long)(bytes - (ulong)Math.Min(count, Preview) * (ulong)ValueSizes[item]));
                }
                else
                {
                    if (count > (ulong)(_length - _s.Position) / 8) throw new InvalidDataException($"an array of {count:N0} {itemType} values runs past the end");
                    for (ulong i = 0; i < count; i++)
                    {
                        var (text, _, t) = Value(item, depth + 1);
                        if (i < Preview) shown.Add(item == 8 ? Quote(text) : text);
                        if (item == 9 && i == 0) itemType = t;
                    }
                }
                return ("[" + string.Join(", ", shown) + (count > Preview ? ", ..." : "") + "]", (long)count, $"array[{itemType}]");
            default:
                return (Scalar(type), null, ValueTypes[type]);
        }
    }

    private static string Quote(string s) => "\"" + s.Replace("\\", "\\\\").Replace("\"", "\\\"") + "\"";

    private static string Clip(string s) => s.Length > MaxText ? s[..MaxText] + $"... ({s.Length:N0} characters)" : s;

    private string Scalar(uint type) => type switch
    {
        0 => Fill(1)[0].ToString(CultureInfo.InvariantCulture),
        1 => ((sbyte)Fill(1)[0]).ToString(CultureInfo.InvariantCulture),
        2 => U16().ToString(CultureInfo.InvariantCulture),
        3 => ((short)U16()).ToString(CultureInfo.InvariantCulture),
        4 => U32().ToString(CultureInfo.InvariantCulture),
        5 => ((int)U32()).ToString(CultureInfo.InvariantCulture),
        6 => BitConverter.UInt32BitsToSingle(U32()).ToString("R", CultureInfo.InvariantCulture),
        7 => Fill(1)[0] != 0 ? "true" : "false",
        10 => U64().ToString(CultureInfo.InvariantCulture),
        11 => ((long)U64()).ToString(CultureInfo.InvariantCulture),
        12 => BitConverter.UInt64BitsToDouble(U64()).ToString("R", CultureInfo.InvariantCulture),
        _ => throw new InvalidDataException($"value type {type}"),
    };

    private string String()
    {
        ulong n = Version == 1 ? U32() : U64();
        if (n > (ulong)(_length - _s.Position)) throw new InvalidDataException($"a string of {n:N0} bytes runs past the end");
        if (n > int.MaxValue / 2) throw new InvalidDataException($"a string of {n:N0} bytes");
        var b = new byte[n];
        _s.ReadExactly(b);
        return Encoding.UTF8.GetString(b);
    }

    private ulong Count() => Version == 1 ? U32() : U64();

    private byte[] Fill(int n)
    {
        try { _s.ReadExactly(_buf, 0, n); }
        catch (EndOfStreamException) { throw new InvalidDataException($"the header ends early at {_s.Position:N0}"); }
        if (BigEndian && n > 1) Array.Reverse(_buf, 0, n);
        return _buf;
    }

    private ushort U16() => BinaryPrimitives.ReadUInt16LittleEndian(Fill(2));
    private uint U32() => BinaryPrimitives.ReadUInt32LittleEndian(Fill(4));
    private ulong U64() => BinaryPrimitives.ReadUInt64LittleEndian(Fill(8));

    private void Skip(long n)
    {
        if (_s.CanSeek) _s.Seek(n, SeekOrigin.Current);
        else
        {
            var b = new byte[Math.Min(n, 1 << 16)];
            while (n > 0) { int r = _s.Read(b, 0, (int)Math.Min(n, b.Length)); if (r == 0) throw new InvalidDataException("the header ends early"); n -= r; }
        }
    }
}
