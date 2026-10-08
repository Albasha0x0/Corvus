using dnlib.DotNet.Emit;

namespace NetDecompilerMcp.Services.Simplify;

/// <summary>
/// IL numeric semantics on evaluator stack values: int (int32), long (int64 / native int), double (F).
/// Operations whose result is undefined or would throw at run time (division by zero, overflow in checked
/// arithmetic, out-of-range float conversion, oversized shifts) bail out instead.
/// </summary>
internal static class Numeric
{
    private static EvaluationBailout Bail(string reason) => new(reason);

    /// <summary>The integer as a sign-extended 64-bit value.</summary>
    public static long Bits(object? value) => value switch
    {
        int i => i,
        long l => l,
        _ => throw Bail("expected an integer"),
    };

    public static long Index(object? value) => value switch
    {
        int i => i,
        long l => l,
        _ => throw Bail("index is not an integer"),
    };

    public static bool IsTrue(object? value) => value switch
    {
        int i => i != 0,
        long l => l != 0,
        double => throw Bail("branch on a float"),
        null => false,
        _ => true,
    };

    public static object Binary(Code op, object? a, object? b)
    {
        if (op is Code.Shl or Code.Shr or Code.Shr_Un)
            return Shift(op, a, Bits(b));
        return (a, b) switch
        {
            (int x, int y) => Int32(op, x, y),
            (int or long, int or long) => Int64(op, Bits(a), Bits(b)),
            (double x, double y) => Float(op, x, y),
            _ => throw Bail("arithmetic on unsupported operands"),
        };
    }

    private static object Shift(Code op, object? value, long amount)
    {
        switch (value)
        {
            case int x:
                if (amount is < 0 or >= 32) throw Bail("shift amount out of range");
                return op switch { Code.Shl => x << (int)amount, Code.Shr => x >> (int)amount, _ => (int)((uint)x >> (int)amount) };
            case long x:
                if (amount is < 0 or >= 64) throw Bail("shift amount out of range");
                return op switch { Code.Shl => x << (int)amount, Code.Shr => x >> (int)amount, _ => (long)((ulong)x >> (int)amount) };
            default:
                throw Bail("shift of a non-integer");
        }
    }

    private static object Int32(Code op, int x, int y)
    {
        try
        {
            return op switch
            {
                Code.Add => unchecked(x + y),
                Code.Sub => unchecked(x - y),
                Code.Mul => unchecked(x * y),
                Code.Div => y == 0 || (x == int.MinValue && y == -1) ? throw Bail("division by zero or overflow") : x / y,
                Code.Div_Un => y == 0 ? throw Bail("division by zero") : (int)((uint)x / (uint)y),
                Code.Rem => y == 0 || (x == int.MinValue && y == -1) ? throw Bail("division by zero or overflow") : x % y,
                Code.Rem_Un => y == 0 ? throw Bail("division by zero") : (int)((uint)x % (uint)y),
                Code.And => x & y,
                Code.Or => x | y,
                Code.Xor => x ^ y,
                Code.Add_Ovf => checked(x + y),
                Code.Sub_Ovf => checked(x - y),
                Code.Mul_Ovf => checked(x * y),
                Code.Add_Ovf_Un => unchecked((int)checked((uint)x + (uint)y)),
                Code.Sub_Ovf_Un => unchecked((int)checked((uint)x - (uint)y)),
                Code.Mul_Ovf_Un => unchecked((int)checked((uint)x * (uint)y)),
                _ => throw Bail($"unsupported operation {op}"),
            };
        }
        catch (OverflowException)
        {
            throw Bail("arithmetic overflow");
        }
    }

    private static object Int64(Code op, long x, long y)
    {
        try
        {
            return op switch
            {
                Code.Add => unchecked(x + y),
                Code.Sub => unchecked(x - y),
                Code.Mul => unchecked(x * y),
                Code.Div => y == 0 || (x == long.MinValue && y == -1) ? throw Bail("division by zero or overflow") : x / y,
                Code.Div_Un => y == 0 ? throw Bail("division by zero") : (long)((ulong)x / (ulong)y),
                Code.Rem => y == 0 || (x == long.MinValue && y == -1) ? throw Bail("division by zero or overflow") : x % y,
                Code.Rem_Un => y == 0 ? throw Bail("division by zero") : (long)((ulong)x % (ulong)y),
                Code.And => x & y,
                Code.Or => x | y,
                Code.Xor => x ^ y,
                Code.Add_Ovf => checked(x + y),
                Code.Sub_Ovf => checked(x - y),
                Code.Mul_Ovf => checked(x * y),
                Code.Add_Ovf_Un => unchecked((long)checked((ulong)x + (ulong)y)),
                Code.Sub_Ovf_Un => unchecked((long)checked((ulong)x - (ulong)y)),
                Code.Mul_Ovf_Un => unchecked((long)checked((ulong)x * (ulong)y)),
                _ => throw Bail($"unsupported operation {op}"),
            };
        }
        catch (OverflowException)
        {
            throw Bail("arithmetic overflow");
        }
    }

    private static object Float(Code op, double x, double y) => op switch
    {
        Code.Add => x + y,
        Code.Sub => x - y,
        Code.Mul => x * y,
        Code.Div => x / y,
        Code.Rem => x % y,
        _ => throw Bail($"{op} on floats"),
    };

    /// <summary>ceq, cgt, cgt.un, clt, clt.un. References compare only against null or by identity.</summary>
    public static bool Compare(Code op, object? a, object? b)
    {
        switch (a, b)
        {
            case (int x, int y):
                return op switch
                {
                    Code.Ceq => x == y,
                    Code.Cgt => x > y,
                    Code.Clt => x < y,
                    Code.Cgt_Un => (uint)x > (uint)y,
                    _ => (uint)x < (uint)y,
                };
            case (int or long, int or long):
            {
                long x = Bits(a), y = Bits(b);
                return op switch
                {
                    Code.Ceq => x == y,
                    Code.Cgt => x > y,
                    Code.Clt => x < y,
                    Code.Cgt_Un => (ulong)x > (ulong)y,
                    _ => (ulong)x < (ulong)y,
                };
            }
            case (double x, double y):
                bool unordered = double.IsNaN(x) || double.IsNaN(y);
                return op switch
                {
                    Code.Ceq => x == y,
                    Code.Cgt => x > y,
                    Code.Clt => x < y,
                    Code.Cgt_Un => unordered || x > y,
                    _ => unordered || x < y,
                };
        }
        if (a is int or long or double || b is int or long or double)
            throw Bail("comparison of a number with a reference");
        // References: equality, and 'x != null' compiled as cgt.un x, null.
        return op switch
        {
            Code.Ceq when a is string && b is string && !ReferenceEquals(a, b) => throw Bail("reference comparison of two strings"),
            Code.Ceq => ReferenceEquals(a, b),
            Code.Cgt_Un when b == null => a != null,
            Code.Clt_Un when a == null => b != null,
            _ => throw Bail("ordered comparison of references"),
        };
    }

    /// <summary>A two-operand conditional branch, expressed through the comparisons (ECMA-335 III.3.5-3.11).</summary>
    public static bool Branch(Code op, object? a, object? b)
    {
        bool isFloat = a is double || b is double;
        return op switch
        {
            Code.Beq or Code.Beq_S => Compare(Code.Ceq, a, b),
            Code.Bne_Un or Code.Bne_Un_S => !Compare(Code.Ceq, a, b),
            Code.Bgt or Code.Bgt_S => Compare(Code.Cgt, a, b),
            Code.Bgt_Un or Code.Bgt_Un_S => Compare(Code.Cgt_Un, a, b),
            Code.Blt or Code.Blt_S => Compare(Code.Clt, a, b),
            Code.Blt_Un or Code.Blt_Un_S => Compare(Code.Clt_Un, a, b),
            Code.Bge or Code.Bge_S => !Compare(isFloat ? Code.Clt_Un : Code.Clt, a, b),
            Code.Bge_Un or Code.Bge_Un_S => !Compare(isFloat ? Code.Clt : Code.Clt_Un, a, b),
            Code.Ble or Code.Ble_S => !Compare(isFloat ? Code.Cgt_Un : Code.Cgt, a, b),
            Code.Ble_Un or Code.Ble_Un_S => !Compare(isFloat ? Code.Cgt : Code.Cgt_Un, a, b),
            _ => throw Bail($"unsupported branch {op}"),
        };
    }

    public static object Convert(Code op, object? value)
    {
        bool unsignedSource = op is Code.Conv_R_Un or Code.Conv_Ovf_I1_Un or Code.Conv_Ovf_I2_Un or Code.Conv_Ovf_I4_Un or Code.Conv_Ovf_I8_Un
            or Code.Conv_Ovf_U1_Un or Code.Conv_Ovf_U2_Un or Code.Conv_Ovf_U4_Un or Code.Conv_Ovf_U8_Un or Code.Conv_Ovf_I_Un or Code.Conv_Ovf_U_Un;
        bool isChecked = op.ToString().StartsWith("Conv_Ovf", StringComparison.Ordinal);

        if (op is Code.Conv_R4 or Code.Conv_R8 or Code.Conv_R_Un)
        {
            double d = value switch
            {
                int i => unsignedSource ? (uint)i : i,
                long l => unsignedSource ? (ulong)l : l,
                double x => x,
                _ => throw Bail("conversion of a non-number"),
            };
            return op == Code.Conv_R4 ? (double)(float)d : d;
        }

        // Integer targets: compute the exact source value, then narrow.
        Int128 source;
        switch (value)
        {
            case int i:
                // conv.u8 / conv.u zero-extend an int32; the other conversions sign-extend it.
                source = unsignedSource || op is Code.Conv_U8 or Code.Conv_U ? (uint)i : i;
                break;
            case long l:
                source = unsignedSource ? (ulong)l : l;
                break;
            case double d:
                if (double.IsNaN(d) || Math.Abs(d) >= 1e30) throw Bail("float to integer conversion out of range");
                source = (Int128)Math.Truncate(d);
                break;
            default:
                throw Bail("conversion of a non-number");
        }

        var (min, max, wide) = op switch
        {
            Code.Conv_I1 or Code.Conv_Ovf_I1 or Code.Conv_Ovf_I1_Un => ((Int128)sbyte.MinValue, (Int128)sbyte.MaxValue, false),
            Code.Conv_U1 or Code.Conv_Ovf_U1 or Code.Conv_Ovf_U1_Un => (0, byte.MaxValue, false),
            Code.Conv_I2 or Code.Conv_Ovf_I2 or Code.Conv_Ovf_I2_Un => (short.MinValue, short.MaxValue, false),
            Code.Conv_U2 or Code.Conv_Ovf_U2 or Code.Conv_Ovf_U2_Un => (0, ushort.MaxValue, false),
            Code.Conv_I4 or Code.Conv_Ovf_I4 or Code.Conv_Ovf_I4_Un => (int.MinValue, int.MaxValue, false),
            Code.Conv_U4 or Code.Conv_Ovf_U4 or Code.Conv_Ovf_U4_Un => (0, uint.MaxValue, false),
            Code.Conv_I8 or Code.Conv_Ovf_I8 or Code.Conv_Ovf_I8_Un or Code.Conv_I or Code.Conv_Ovf_I or Code.Conv_Ovf_I_Un => (long.MinValue, long.MaxValue, true),
            _ => ((Int128)0, (Int128)ulong.MaxValue, true), // U8, U and their checked forms
        };
        if (source < min || source > max)
        {
            if (isChecked) throw Bail("checked conversion overflow");
            if (value is double) throw Bail("float to integer conversion out of range");
        }

        long bits = unchecked((long)source);
        if (wide) return bits;
        return op switch
        {
            Code.Conv_I1 or Code.Conv_Ovf_I1 or Code.Conv_Ovf_I1_Un => (int)unchecked((sbyte)bits),
            Code.Conv_U1 or Code.Conv_Ovf_U1 or Code.Conv_Ovf_U1_Un => (int)unchecked((byte)bits),
            Code.Conv_I2 or Code.Conv_Ovf_I2 or Code.Conv_Ovf_I2_Un => (int)unchecked((short)bits),
            Code.Conv_U2 or Code.Conv_Ovf_U2 or Code.Conv_Ovf_U2_Un => (int)unchecked((ushort)bits),
            _ => unchecked((int)bits),
        };
    }
}
