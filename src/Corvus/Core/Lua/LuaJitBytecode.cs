using System.Buffers.Binary;
using System.Globalization;
using System.Text;

namespace Corvus.Core.Lua;

/// <summary>Reads LuaJIT dumps, versions 1 and 2, in file order with main last; throws InvalidDataException when damaged.</summary>
public static class LuaJitBytecode
{
    public const string Kind = "LuaJIT bytecode";
    private const int MaxCount = 50_000_000;
    private const uint BigEndian = 1, Strip = 2, Ffi = 4, TwoSlotFrames = 8;

    public static bool Looks(ReadOnlySpan<byte> b) => b.Length >= 5 && b.StartsWith("\x1bLJ"u8) && b[3] is 1 or 2;

    /// <summary>The chunk and its prototypes in file order.</summary>
    public static (LuaChunk Chunk, IReadOnlyList<LuaFunction> Prototypes) Read(byte[] data)
    {
        if (!Looks(data)) throw new InvalidDataException("no LuaJIT dump header");
        int p = 3, version = data[p++];
        uint flags = Uleb(data, ref p);
        if ((flags & BigEndian) != 0) throw new InvalidDataException("big-endian dumps are not read");
        bool stripped = (flags & Strip) != 0;
        string name = "=?";
        if (!stripped)
        {
            int length = Count(data, ref p);
            name = Encoding.Latin1.GetString(Take(data, ref p, length));
        }
        var stack = new List<LuaFunction>();
        var order = new List<LuaFunction>();
        while (true)
        {
            if (p >= data.Length) throw new InvalidDataException("the dump ends before its terminating zero");
            int size = Count(data, ref p);
            if (size == 0) break;
            int end = p + size;
            var f = Prototype(data, ref p, end, version, stripped, name, stack);
            if (p != end) throw new InvalidDataException($"a prototype at 0x{end - size:X} declares {size:N0} bytes and holds {p - (end - size):N0}");
            stack.Add(f);
            order.Add(f);
        }
        if (stack.Count != 1) throw new InvalidDataException($"{stack.Count} prototypes are left without a parent");
        string layout = string.Join(", ", new[] { stripped ? "stripped" : null, (flags & Ffi) != 0 ? "FFI constants" : null, (flags & TwoSlotFrames) != 0 ? "two-slot frames" : null }
            .Where(s => s != null)) is { Length: > 0 } l ? l : "debug information kept";
        return (new LuaChunk(version == 1 ? "LuaJIT 2.0" : "LuaJIT 2.1", stack[0], stripped, layout), order);
    }

    private static LuaFunction Prototype(byte[] d, ref int p, int end, int version, bool stripped, string name, List<LuaFunction> stack)
    {
        var head = Take(d, ref p, 4);
        int protoFlags = head[0], parameters = head[1], frame = head[2], upvalues = head[3];
        int kgc = Count(d, ref p), kn = Count(d, ref p), bc = Count(d, ref p);
        int debugSize = 0, firstLine = 0, lineCount = 0;
        if (!stripped)
        {
            debugSize = Count(d, ref p);
            if (debugSize > 0) { firstLine = Count(d, ref p); lineCount = Count(d, ref p); }
        }
        var code = new uint[bc];
        var raw = Take(d, ref p, 4L * bc);
        for (int i = 0; i < bc; i++) code[i] = BinaryPrimitives.ReadUInt32LittleEndian(raw[(4 * i)..]);
        Take(d, ref p, 2L * upvalues);
        var constants = new List<LuaConstant>();
        var children = new List<LuaFunction>();
        for (int i = 0; i < kgc; i++)
        {
            uint type = Uleb(d, ref p);
            switch (type)
            {
                case 0:
                    // A child is the most recent prototype not yet claimed.
                    if (stack.Count == 0) throw new InvalidDataException("a child constant with no prototype before it");
                    children.Add(stack[^1]);
                    stack.RemoveAt(stack.Count - 1);
                    break;
                case 1: Table(d, ref p); constants.Add(new LuaConstant('T', "table")); break;
                case 2 or 3:
                    ulong lo = Uleb(d, ref p), hi = Uleb(d, ref p), v = lo | (hi << 32);
                    constants.Add(new LuaConstant('C', type == 2 ? $"{(long)v}LL" : $"{v}ULL"));
                    break;
                case 4: for (int k = 0; k < 4; k++) Uleb(d, ref p); constants.Add(new LuaConstant('C', "complex")); break;
                default:
                    var s = Take(d, ref p, type - 5).ToArray();
                    constants.Add(new LuaConstant('S', LuaBytecode.Quote(s), s));
                    break;
            }
        }
        for (int i = 0; i < kn; i++)
        {
            // A 33-bit ULEB128: the low bit of the first byte marks a double, whose high word follows.
            bool isDouble = p < d.Length && (d[p] & 1) != 0;
            uint lo = Uleb33(d, ref p);
            if (isDouble)
            {
                uint hi = Uleb(d, ref p);
                constants.Add(new LuaConstant('F', LuaBytecode.Float(BitConverter.Int64BitsToDouble((long)(((ulong)hi << 32) | lo)), false)));
            }
            else constants.Add(new LuaConstant('I', ((int)lo).ToString(CultureInfo.InvariantCulture)));
        }
        if (debugSize > end - p) throw new InvalidDataException($"debug information of {debugSize:N0} bytes runs past its prototype");
        p += debugSize;
        bool vararg = (protoFlags & 2) != 0;
        return new LuaFunction(name, firstLine, firstLine + lineCount, parameters, vararg, frame, code, constants, upvalues, 0, children, null);
    }

    private static void Table(byte[] d, ref int p)
    {
        int array = Count(d, ref p), hash = Count(d, ref p);
        for (long i = 0; i < array + 2L * hash; i++)
        {
            uint t = Uleb(d, ref p);
            if (t == 3) Uleb(d, ref p);
            else if (t == 4) { Uleb(d, ref p); Uleb(d, ref p); }
            else if (t >= 5) Take(d, ref p, t - 5);
        }
    }

    /// <summary>An instruction as "NAME operands": A and D, or A, B and C.</summary>
    public static string Instruction(string version, uint i)
    {
        var ops = version == "LuaJIT 2.0" ? LuaOpcodes.LuaJit1 : LuaOpcodes.LuaJit2;
        int op = (int)(i & 0xFF);
        if (op >= ops.Length) return $"op{op} 0x{i:X8}";
        var (name, mode) = ops[op];
        uint a = (i >> 8) & 0xFF;
        return mode == "AD" ? $"{name} {a} {i >> 16}" : $"{name} {a} {i >> 24} {(i >> 16) & 0xFF}";
    }

    /// <summary>The opcode name of an instruction.</summary>
    public static string OpcodeName(string version, uint i)
    {
        var ops = version == "LuaJIT 2.0" ? LuaOpcodes.LuaJit1 : LuaOpcodes.LuaJit2;
        int op = (int)(i & 0xFF);
        return op < ops.Length ? ops[op].Name : $"op{op}";
    }

    private static ReadOnlySpan<byte> Take(byte[] d, ref int p, long n)
    {
        if (n < 0 || p > d.Length - n) throw new InvalidDataException($"{n:N0} bytes at 0x{p:X} run past the dump");
        var s = d.AsSpan(p, (int)n);
        p += (int)n;
        return s;
    }

    private static int Count(byte[] d, ref int p)
    {
        uint n = Uleb(d, ref p);
        if (n > MaxCount || n > d.Length) throw new InvalidDataException($"a count of {n:N0} at 0x{p:X} runs past the dump");
        return (int)n;
    }

    private static uint Uleb(byte[] d, ref int p)
    {
        uint v = 0;
        for (int shift = 0; ; shift += 7)
        {
            if (p >= d.Length || shift > 28) throw new InvalidDataException($"a number at 0x{p:X} runs past the dump");
            byte b = d[p++];
            v |= (uint)(b & 0x7F) << shift;
            if (b < 0x80) return v;
        }
    }

    private static uint Uleb33(byte[] d, ref int p)
    {
        if (p >= d.Length) throw new InvalidDataException("a number runs past the dump");
        uint v = (uint)d[p++] >> 1;
        if (v < 0x40) return v;
        v &= 0x3F;
        for (int shift = 6; ; shift += 7)
        {
            if (p >= d.Length || shift > 32) throw new InvalidDataException($"a number at 0x{p:X} runs past the dump");
            byte b = d[p++];
            v |= (uint)(b & 0x7F) << shift;
            if (b < 0x80) return v;
        }
    }
}
