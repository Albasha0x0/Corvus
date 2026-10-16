using System.Buffers.Binary;

namespace Corvus.Native.Dwarf;

/// <summary>
/// DWARF expressions (DWARF 5 section 2.5) on the address-sized generic type: evaluated against registers and memory
/// (CFI rules of a core's frames), or described as text (variable locations).
/// </summary>
internal static class DwarfExpression
{
    private const int MaxSteps = 4096;
    private const int MaxStack = 64;

    /// <summary>A register's value by DWARF number; false when unknown.</summary>
    public delegate bool RegisterReader(int dwarf, out ulong value);

    /// <summary><paramref name="size"/> bytes of memory at <paramref name="address"/> in the target's byte order; false when unreadable.</summary>
    public delegate bool MemoryReader(ulong address, int size, out ulong value);

    /// <summary>
    /// Evaluates <paramref name="expr"/> with <paramref name="push"/> (the CFA of a CFI rule) on the stack first; the
    /// result is the top of the stack. Register locations (DW_OP_reg*), pieces and operations that need a frame base or
    /// another unit fail with a reason.
    /// </summary>
    public static bool TryEvaluate(ReadOnlySpan<byte> expr, int addressSize, bool bigEndian, RegisterReader register, MemoryReader memory, ulong? push,
        out ulong result, out string? failure)
    {
        result = 0;
        failure = null;
        ulong mask = addressSize >= 8 ? ulong.MaxValue : (1UL << (addressSize * 8)) - 1;
        Span<ulong> stack = stackalloc ulong[MaxStack];
        int sp = 0;
        if (push is { } initial) stack[sp++] = initial & mask;
        var r = new LebReader(expr);
        for (int steps = 0; !r.AtEnd; steps++)
        {
            if (steps >= MaxSteps) return Fail("the expression runs longer than the walk allows", out failure);
            byte op = r.Byte();
            int need = op switch
            {
                0x06 or 0x12 or 0x13 or 0x19 or 0x1F or 0x20 or 0x23 or 0x28 or 0x94 => 1,
                0x14 or 0x16 or 0x1A or 0x1B or 0x1C or 0x1D or 0x1E or 0x21 or 0x22 or 0x24 or 0x25 or 0x26 or 0x27 or (>= 0x29 and <= 0x2E) => 2,
                0x17 => 3,
                _ => 0,
            };
            if (sp < need) return Fail($"DW_OP 0x{op:X2} needs {need} stack entries", out failure);
            if (sp >= MaxStack - 1) return Fail("the expression stack overflows", out failure);
            ulong a = sp > 0 ? stack[sp - 1] : 0, b = sp > 1 ? stack[sp - 2] : 0;
            switch (op)
            {
                case 0x03: stack[sp++] = Fixed(expr, ref r, addressSize, bigEndian); break; // addr
                case 0x06 or 0x94: // deref, deref_size
                {
                    int size = op == 0x06 ? addressSize : r.Byte();
                    if (size is < 1 or > 8) return Fail($"DW_OP_deref_size {size}", out failure);
                    if (!memory(a, size, out ulong v)) return Fail($"memory at 0x{a:X} is not in the dump", out failure);
                    stack[sp - 1] = v;
                    break;
                }
                case 0x08: stack[sp++] = r.Byte(); break;
                case 0x09: stack[sp++] = (ulong)(sbyte)r.Byte(); break;
                case 0x0A: stack[sp++] = Fixed(expr, ref r, 2, bigEndian); break;
                case 0x0B: stack[sp++] = (ulong)(short)Fixed(expr, ref r, 2, bigEndian); break;
                case 0x0C: stack[sp++] = Fixed(expr, ref r, 4, bigEndian); break;
                case 0x0D: stack[sp++] = (ulong)(int)Fixed(expr, ref r, 4, bigEndian); break;
                case 0x0E or 0x0F: stack[sp++] = Fixed(expr, ref r, 8, bigEndian); break;
                case 0x10: stack[sp++] = r.Uleb(); break;
                case 0x11: stack[sp++] = (ulong)r.Sleb(); break;
                case 0x12: stack[sp++] = a; break; // dup
                case 0x13: sp--; break; // drop
                case 0x14: stack[sp++] = b; break; // over
                case 0x15: // pick
                {
                    int index = r.Byte();
                    if (index >= sp) return Fail($"DW_OP_pick {index} is past the stack", out failure);
                    stack[sp] = stack[sp - 1 - index];
                    sp++;
                    break;
                }
                case 0x16: (stack[sp - 1], stack[sp - 2]) = (b, a); break; // swap
                case 0x17: (stack[sp - 1], stack[sp - 2], stack[sp - 3]) = (b, stack[sp - 3], a); break; // rot
                case 0x19: stack[sp - 1] = (ulong)Math.Abs(Signed(a, mask)); break;
                case 0x1A: Binary(stack, ref sp, b & a); break;
                case 0x1B or 0x1D: // div (signed), mod
                    if ((a & mask) == 0) return Fail("division by zero", out failure);
                    Binary(stack, ref sp, op == 0x1B ? (ulong)(Signed(b, mask) / Signed(a, mask)) : (b & mask) % (a & mask));
                    break;
                case 0x1C: Binary(stack, ref sp, b - a); break;
                case 0x1E: Binary(stack, ref sp, b * a); break;
                case 0x1F: stack[sp - 1] = (ulong)-Signed(a, mask); break;
                case 0x20: stack[sp - 1] = ~a; break;
                case 0x21: Binary(stack, ref sp, b | a); break;
                case 0x22: Binary(stack, ref sp, b + a); break;
                case 0x23: stack[sp - 1] = a + r.Uleb(); break;
                case 0x24: Binary(stack, ref sp, a >= 64 ? 0 : b << (int)a); break;
                case 0x25: Binary(stack, ref sp, a >= 64 ? 0 : (b & mask) >> (int)a); break;
                case 0x26: Binary(stack, ref sp, (ulong)(Signed(b, mask) >> (int)Math.Min(a, 63))); break;
                case 0x27: Binary(stack, ref sp, b ^ a); break;
                case 0x28 or 0x2F: // bra, skip
                {
                    short offset = (short)Fixed(expr, ref r, 2, bigEndian);
                    bool jump = op == 0x2F || (stack[--sp] & mask) != 0;
                    if (!jump) break;
                    long to = r.Position + (long)offset;
                    if (to < 0 || to > expr.Length) return Fail("a branch leaves the expression", out failure);
                    r.Position = (int)to;
                    break;
                }
                case >= 0x29 and <= 0x2E:
                {
                    long x = Signed(b, mask), y = Signed(a, mask);
                    bool v = op switch { 0x29 => x == y, 0x2A => x >= y, 0x2B => x > y, 0x2C => x <= y, 0x2D => x < y, _ => x != y };
                    Binary(stack, ref sp, v ? 1UL : 0);
                    break;
                }
                case >= 0x30 and <= 0x4F: stack[sp++] = (ulong)(op - 0x30); break; // lit
                case >= 0x70 and <= 0x8F or 0x92: // breg, bregx
                {
                    int reg = op == 0x92 ? (int)Math.Min(r.Uleb(), int.MaxValue) : op - 0x70;
                    long offset = r.Sleb();
                    if (!register(reg, out ulong value)) return Fail($"register {reg} is not known", out failure);
                    stack[sp++] = value + (ulong)offset;
                    break;
                }
                case 0x96: break; // nop
                case 0x9F: r.Position = expr.Length; break; // stack_value: the top is the value
                case >= 0x50 and <= 0x6F or 0x90: return Fail("the value is in a register (a location, not an address)", out failure);
                case 0x91: return Fail("DW_OP_fbreg needs the function's frame base", out failure);
                case 0x9C: return Fail("DW_OP_call_frame_cfa needs the frame's CFA", out failure);
                default: return Fail($"DW_OP 0x{op:X2} is not evaluated", out failure);
            }
            if (r.Failed || r.Position > expr.Length) return Fail("the expression ends inside an operation", out failure);
            if (sp > 0) stack[sp - 1] &= mask;
        }
        if (sp == 0) return Fail("the expression leaves an empty stack", out failure);
        result = stack[sp - 1] & mask;
        return true;
    }

    private static bool Fail(string why, out string? failure)
    {
        failure = why;
        return false;
    }

    private static void Binary(Span<ulong> stack, ref int sp, ulong value) => stack[--sp - 1] = value;

    private static long Signed(ulong value, ulong mask) => mask == ulong.MaxValue ? (long)value
        : (value & ((mask >> 1) + 1)) != 0 ? (long)(value | ~mask) : (long)(value & mask);

    private static ulong Fixed(ReadOnlySpan<byte> expr, ref LebReader r, int size, bool bigEndian)
    {
        if (r.Position + size > expr.Length) { r.Failed = true; r.Position = expr.Length; return 0; }
        var s = expr.Slice(r.Position, size);
        r.Position += size;
        return size switch
        {
            2 => bigEndian ? BinaryPrimitives.ReadUInt16BigEndian(s) : BinaryPrimitives.ReadUInt16LittleEndian(s),
            4 => bigEndian ? BinaryPrimitives.ReadUInt32BigEndian(s) : BinaryPrimitives.ReadUInt32LittleEndian(s),
            8 => bigEndian ? BinaryPrimitives.ReadUInt64BigEndian(s) : BinaryPrimitives.ReadUInt64LittleEndian(s),
            _ => s[0],
        };
    }
}
