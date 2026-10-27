using System.Buffers.Binary;
using System.Globalization;
using System.Text;

namespace Corvus.Core.Lua;

/// <summary>A constant of a Lua function: its type letter (N nil, B boolean, F float, I integer, S string) and value.</summary>
public sealed record LuaConstant(char Type, string Text, byte[]? Bytes = null);

/// <summary>One function prototype of a Lua chunk; a stripped chunk has no locals and null <see cref="Lines"/>.</summary>
public sealed record LuaFunction(string Source, int Line, int LastLine, int Params, bool Vararg, int Slots, uint[] Code,
    IReadOnlyList<LuaConstant> Constants, int Upvalues, int Locals, IReadOnlyList<LuaFunction> Children, int[]? Lines);

/// <summary>A Lua chunk: the version, the function tree from the main function, and whether debug information is stripped.</summary>
public sealed record LuaChunk(string Version, LuaFunction Main, bool Stripped, string Layout);

/// <summary>Reads luac chunks of Lua 5.1 to 5.4; throws InvalidDataException on a damaged or unknown chunk.</summary>
public static class LuaBytecode
{
    public const string Kind = "Lua bytecode";
    private const int MaxCount = 50_000_000, MaxDepth = 200;

    // LUAC_DATA, written after the header from 5.2 on.
    private static readonly byte[] LuacData = [0x19, 0x93, 0x0D, 0x0A, 0x1A, 0x0A];

    public static bool Looks(ReadOnlySpan<byte> b) => b.Length >= 12 && b.StartsWith("\x1bLua"u8) && b[4] is 0x51 or 0x52 or 0x53 or 0x54;

    public static LuaChunk Read(byte[] data)
    {
        if (!Looks(data)) throw new InvalidDataException("no Lua 5.1-5.4 chunk header");
        var r = new Reader(data) { Version = data[4] };
        r.Pos = 5;
        int format = r.U8();
        if (format != 0) throw new InvalidDataException($"chunk format {format}; only the official format 0 is read");
        string layout;
        if (r.Version <= 0x52)
        {
            r.Little = r.U8() == 1;
            r.IntSize = r.U8();
            r.SizeTSize = r.U8();
            int instruction = r.U8();
            r.NumberSize = r.U8();
            r.Integral = r.U8() != 0;
            if (instruction != 4 || r.IntSize is not (4 or 8) || r.SizeTSize is not (4 or 8) || r.NumberSize is not (4 or 8))
                throw new InvalidDataException($"sizes int {r.IntSize}, size_t {r.SizeTSize}, instruction {instruction}, number {r.NumberSize}");
            if (r.Version == 0x52) r.Expect(LuacData);
            layout = $"{(r.Little ? "little" : "big")}-endian, {r.IntSize}-byte int, {r.SizeTSize}-byte size_t, {r.NumberSize}-byte {(r.Integral ? "integer" : "float")} numbers";
        }
        else
        {
            r.Expect(LuacData);
            if (r.Version == 0x53) { r.IntSize = r.U8(); r.SizeTSize = r.U8(); }
            int instruction = r.U8();
            r.IntegerSize = r.U8();
            r.NumberSize = r.U8();
            if (instruction != 4 || r.IntegerSize is not (4 or 8) || r.NumberSize is not (4 or 8) || (r.Version == 0x53 && (r.IntSize is not (4 or 8) || r.SizeTSize is not (4 or 8))))
                throw new InvalidDataException($"sizes instruction {instruction}, integer {r.IntegerSize}, number {r.NumberSize}");
            // The test integer 0x5678 tells the byte order.
            r.Little = r.U8() == 0x78;
            r.Skip(r.IntegerSize - 1 + r.NumberSize);
            // Upvalues of the main closure.
            r.U8();
            layout = $"{(r.Little ? "little" : "big")}-endian, {r.IntegerSize}-byte integers, {r.NumberSize}-byte floats";
        }
        var main = Function(r, "=?", 0);
        bool stripped = Stripped(main);
        return new LuaChunk($"{r.Version >> 4}.{r.Version & 15}", main, stripped, layout);
    }

    private static bool Stripped(LuaFunction f) => f.Lines == null && f.Children.All(Stripped);

    private static LuaFunction Function(Reader r, string parentSource, int depth)
    {
        if (depth > MaxDepth) throw new InvalidDataException($"functions nest past {MaxDepth} levels");
        int v = r.Version;
        string? source = null;
        int line, lastLine, nups = 0;
        if (v == 0x51) source = r.String() is { } s51 ? Latin1(s51) : null;
        else if (v >= 0x53) source = r.String() is { } s53 ? Latin1(s53) : null;
        line = r.Int();
        lastLine = r.Int();
        if (v == 0x51) nups = r.U8();
        int parameters = r.U8(), vararg = r.U8(), slots = r.U8();
        var code = new uint[r.Count()];
        for (int i = 0; i < code.Length; i++) code[i] = r.U32();
        var constants = new List<LuaConstant>();
        var children = new List<LuaFunction>();
        int upvalues = 0;
        int nk = r.Count();
        for (int i = 0; i < nk; i++) constants.Add(Constant(r));
        if (v == 0x51)
        {
            int np = r.Count();
            for (int i = 0; i < np; i++) children.Add(Function(r, source ?? parentSource, depth + 1));
        }
        else if (v == 0x52)
        {
            int np = r.Count();
            for (int i = 0; i < np; i++) children.Add(Function(r, "=?", depth + 1));
            upvalues = r.Count();
            r.Skip(2L * upvalues);
        }
        else
        {
            upvalues = r.Count();
            r.Skip((v == 0x54 ? 3L : 2L) * upvalues);
            int np = r.Count();
            for (int i = 0; i < np; i++) children.Add(Function(r, source ?? parentSource, depth + 1));
        }
        if (v == 0x52) source = r.String() is { } s52 ? Latin1(s52) : null;
        int[]? lines = null;
        int nl = r.Count();
        if (v == 0x54)
        {
            var deltas = new sbyte[nl];
            for (int i = 0; i < nl; i++) deltas[i] = (sbyte)r.U8();
            int nabs = r.Count();
            var abs = new Dictionary<int, int>();
            for (int i = 0; i < nabs; i++) { int pc = r.Count(); abs[pc] = r.Int(); }
            if (nl > 0)
            {
                // Each byte adds to the previous line; -128 takes the absolute line saved for that instruction.
                lines = new int[nl];
                int current = line;
                for (int pc = 0; pc < nl; pc++)
                {
                    if (deltas[pc] == -128) current = abs.TryGetValue(pc, out var a) ? a : throw new InvalidDataException($"no absolute line for instruction {pc}");
                    else current += deltas[pc];
                    lines[pc] = current;
                }
            }
        }
        else if (nl > 0)
        {
            lines = new int[nl];
            for (int i = 0; i < nl; i++) lines[i] = r.Int();
        }
        int locals = r.Count();
        for (int i = 0; i < locals; i++) { r.String(); r.Int(); r.Int(); }
        int names = r.Count();
        for (int i = 0; i < names; i++) r.String();
        if (v == 0x51) upvalues = nups;
        // A function without a source name shares its parent's, except in 5.2, which writes it in every function.
        string shown = source ?? (v != 0x52 && depth > 0 ? parentSource : "=?");
        return new LuaFunction(shown, line, lastLine, parameters, vararg != 0, slots, code, constants, upvalues, locals, children, lines);
    }

    private static LuaConstant Constant(Reader r)
    {
        int t = r.U8();
        switch (r.Version, t)
        {
            case (_, 0): return new LuaConstant('N', "nil");
            case (< 0x54, 1): return r.U8() != 0 ? new LuaConstant('B', "true") : new LuaConstant('B', "false");
            case (0x54, 1): return new LuaConstant('B', "false");
            case (0x54, 0x11): return new LuaConstant('B', "true");
            case (< 0x53, 3): return r.Integral ? new LuaConstant('I', r.Integer(r.NumberSize).ToString(CultureInfo.InvariantCulture)) : new LuaConstant('F', Float(r.Float(), false));
            case (0x53, 3) or (0x54, 0x13): return new LuaConstant('F', Float(r.Float(), true));
            case (0x53, 0x13) or (0x54, 3): return new LuaConstant('I', r.Integer(r.IntegerSize).ToString(CultureInfo.InvariantCulture));
            case (_, 4) or (>= 0x53, 0x14):
                var s = r.String() ?? [];
                return new LuaConstant('S', Quote(s), s);
            default: throw new InvalidDataException($"constant type {t} at 0x{r.Pos - 1:X}");
        }
    }

    /// <summary>A float as luac prints it: %.14g, and from 5.3 on ".0" after a value that reads as an integer.</summary>
    public static string Float(double d, bool markFloat)
    {
        string s = double.IsNaN(d) ? (BitConverter.DoubleToInt64Bits(d) < 0 ? "-nan" : "nan")
            : double.IsInfinity(d) ? (d > 0 ? "inf" : "-inf")
            : d.ToString("G14", CultureInfo.InvariantCulture).Replace('E', 'e');
        return markFloat && s.All(c => c == '-' || char.IsAsciiDigit(c)) ? s + ".0" : s;
    }

    /// <summary>A string as luac prints it: quoted, C escapes, other bytes outside printable ASCII as \ddd.</summary>
    public static string Quote(ReadOnlySpan<byte> s)
    {
        var sb = new StringBuilder(s.Length + 2).Append('"');
        foreach (byte c in s)
            sb.Append(c switch
            {
                (byte)'"' => "\\\"", (byte)'\\' => "\\\\", 7 => "\\a", 8 => "\\b", 12 => "\\f", 10 => "\\n", 13 => "\\r", 9 => "\\t", 11 => "\\v",
                >= 0x20 and < 0x7F => ((char)c).ToString(),
                _ => $"\\{c:D3}",
            });
        return sb.Append('"').ToString();
    }

    private static string Latin1(byte[] b) => Encoding.Latin1.GetString(b);

    /// <summary>The opcode table of a chunk version ("5.1" to "5.4").</summary>
    public static (string Name, string Mode)[] Opcodes(string version) => version switch
    {
        "5.1" => LuaOpcodes.Lua51, "5.2" => LuaOpcodes.Lua52, "5.3" => LuaOpcodes.Lua53, _ => LuaOpcodes.Lua54,
    };

    /// <summary>An instruction as "NAME operands" with the fields of its format.</summary>
    public static string Instruction(string version, uint i)
    {
        var ops = Opcodes(version);
        bool v54 = version == "5.4";
        int op = (int)(i & (v54 ? 0x7Fu : 0x3Fu));
        if (op >= ops.Length) return $"op{op} 0x{i:X8}";
        var (name, mode) = ops[op];
        if (v54)
        {
            int a = (int)(i >> 7) & 0xFF, k = (int)(i >> 15) & 1, b = (int)(i >> 16) & 0xFF, c = (int)(i >> 24) & 0xFF;
            return mode switch
            {
                "iABC" => $"{name} {a} {b} {c}{(k != 0 ? "k" : "")}",
                "iABx" => $"{name} {a} {i >> 15}",
                "iAsBx" => $"{name} {a} {(int)(i >> 15) - 65535}",
                "iAx" => $"{name} {i >> 7}",
                _ => $"{name} {(int)(i >> 7) - 16777215}",
            };
        }
        int a5 = (int)(i >> 6) & 0xFF, c5 = (int)(i >> 14) & 0x1FF, b5 = (int)(i >> 23) & 0x1FF;
        return mode switch
        {
            "iABC" => $"{name} {a5} {b5} {c5}",
            "iABx" => $"{name} {a5} {i >> 14}",
            "iAsBx" => $"{name} {a5} {(int)(i >> 14) - 131071}",
            _ => $"{name} {i >> 6}",
        };
    }

    private sealed class Reader(byte[] data)
    {
        public int Pos, Version, IntSize = 4, SizeTSize = 8, NumberSize = 8, IntegerSize = 8;
        public bool Little = true, Integral;

        private ReadOnlySpan<byte> Take(long n)
        {
            if (n < 0 || Pos > data.Length - n) throw new InvalidDataException($"{n:N0} bytes at 0x{Pos:X} run past the chunk");
            var s = data.AsSpan(Pos, (int)n);
            Pos += (int)n;
            return s;
        }

        public void Skip(long n) => Take(n);
        public void Expect(ReadOnlySpan<byte> b) { if (!Take(b.Length).SequenceEqual(b)) throw new InvalidDataException("the chunk's check bytes differ"); }
        public int U8() => Take(1)[0];
        public uint U32() => Little ? BinaryPrimitives.ReadUInt32LittleEndian(Take(4)) : BinaryPrimitives.ReadUInt32BigEndian(Take(4));

        private ulong Unsigned(int size)
        {
            var s = Take(size);
            return size == 4 ? (Little ? BinaryPrimitives.ReadUInt32LittleEndian(s) : BinaryPrimitives.ReadUInt32BigEndian(s))
                : Little ? BinaryPrimitives.ReadUInt64LittleEndian(s) : BinaryPrimitives.ReadUInt64BigEndian(s);
        }

        public long Integer(int size) => size == 4 ? (int)Unsigned(4) : (long)Unsigned(8);
        public double Float() => NumberSize == 4 ? BitConverter.Int32BitsToSingle((int)Unsigned(4)) : BitConverter.Int64BitsToDouble((long)Unsigned(8));

        // 5.4 writes sizes and counts as big-endian groups of 7 bits, the last byte marked by its high bit.
        private ulong Varint()
        {
            ulong x = 0;
            for (int n = 0; ; n++)
            {
                if (n > 9) throw new InvalidDataException($"a size at 0x{Pos:X} is too long");
                int b = U8();
                x = (x << 7) | (uint)(b & 0x7F);
                if ((b & 0x80) != 0) return x;
            }
        }

        public int Int()
        {
            if (Version != 0x54) return (int)Integer(IntSize);
            ulong x = Varint();
            return x <= int.MaxValue ? (int)x : throw new InvalidDataException($"a number at 0x{Pos:X} is past the int range");
        }

        public int Count()
        {
            long n = Version == 0x54 ? (long)Varint() : Integer(IntSize);
            if (n < 0 || n > MaxCount || n > data.Length - Pos) throw new InvalidDataException($"a count of {n:N0} at 0x{Pos:X} runs past the chunk");
            return (int)n;
        }

        /// <summary>A string, or null for an absent one; lengths count the terminator up to 5.3, and 5.3/5.4 store length + 1.</summary>
        public byte[]? String()
        {
            ulong size;
            if (Version == 0x54) size = Varint();
            else if (Version == 0x53) { size = (ulong)U8(); if (size == 0xFF) size = Unsigned(SizeTSize); }
            else size = Unsigned(SizeTSize);
            if (size == 0) return null;
            if (size > (ulong)(data.Length - Pos) + 1) throw new InvalidDataException($"a string of {size:N0} bytes at 0x{Pos:X} runs past the chunk");
            if (Version >= 0x53) return Take((long)size - 1).ToArray();
            var s = Take((long)size);
            return s[..^1].ToArray();
        }
    }
}
