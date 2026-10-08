using dnlib.DotNet.Emit;

namespace NetDecompilerMcp.Services.Simplify;

/// <summary>
/// IL numeric semantics on evaluator stack values: int (int32), long (int64), nint (native int), float (F holding a
/// float32, which the JIT computes in single precision) and double (F). A native int always holds a value in the int32
/// range: operations whose native int result would differ between 32- and 64-bit platforms bail out. Operations whose
/// result is undefined or would throw at run time (division by zero, overflow in checked arithmetic, out-of-range float
/// conversion, oversized shifts) bail out too.
/// </summary>
internal static class Numeric
{
    private static EvaluationBailout Bail(FallbackReason reason, string message) => new(reason, message);

    /// <summary>The integer as a sign-extended 64-bit value.</summary>
    public static long Bits(object? value) => value switch
    {
        int i => i,
        long l => l,
        nint n => n,
        _ => throw Bail(FallbackReason.InvalidCode, "expected an integer"),
    };

    public static long Index(object? value) => value switch
    {
        int i => i,
        nint n => n,
        long l => l,
        _ => throw Bail(FallbackReason.InvalidCode, "index is not an integer"),
    };

    public static bool IsTrue(object? value) => value switch
    {
        int i => i != 0,
        long l => l != 0,
        nint n => n != 0,
        double or float => throw Bail(FallbackReason.InvalidCode, "branch on a float"),
        null => false,
        _ => true,
    };

    /// <summary>A native int value, which must be the same on 32- and 64-bit platforms.</summary>
    public static nint Native(long value) => value is >= int.MinValue and <= int.MaxValue
        ? (nint)value
        : throw Bail(FallbackReason.PlatformDependent, "native int value outside the 32-bit range");

    public static object Binary(Code op, object? a, object? b)
    {
        if (op is Code.Shl or Code.Shr or Code.Shr_Un)
            return Shift(op, a, b);
        return (a, b) switch
        {
            (int x, int y) => Int32(op, x, y),
            (long x, long y) => Int64(op, x, y),
            (nint or int, nint or int) => NativeOp(op, Bits(a), Bits(b)),
            (float x, float y) => Float32(op, x, y),
            (double or float, double or float) => Float64(op, Float(a), Float(b)),
            _ => throw Bail(FallbackReason.InvalidCode, "arithmetic on mismatched operands"),
        };
    }

    /// <summary>
    /// A native int operation: computed with 32- and with 64-bit native ints, which must agree (both values are in the
    /// int32 range, so they agree unless the result overflows 32 bits or depends on the width, as unsigned division does).
    /// </summary>
    private static nint NativeOp(Code op, long x, long y)
    {
        var narrow = Attempt(() => (long)(int)Int32(op, (int)x, (int)y));
        var wide = Attempt(() => (long)Int64(op, x, y));
        return (narrow, wide) switch
        {
            ({ Error: { } e }, { Error: not null }) => throw e,
            ({ Value: var n }, { Value: var w }) when narrow.Error == null && wide.Error == null && n == w => (nint)n,
            _ => throw Bail(FallbackReason.PlatformDependent, "native int result differs between 32- and 64-bit platforms"),
        };
    }

    private static (long Value, EvaluationBailout? Error) Attempt(Func<long> f)
    {
        try { return (f(), null); }
        catch (EvaluationBailout ex) { return (0, ex); }
    }

    private static object Shift(Code op, object? value, object? amountValue)
    {
        long amount = amountValue switch
        {
            int i => i,
            nint n => n,
            _ => throw Bail(FallbackReason.InvalidCode, "shift amount is not an int32 or native int"),
        };
        switch (value)
        {
            case int x:
                if (amount is < 0 or >= 32) throw Bail(FallbackReason.PlatformDependent, "shift amount out of range (unspecified result)");
                return op switch { Code.Shl => x << (int)amount, Code.Shr => x >> (int)amount, _ => (int)((uint)x >> (int)amount) };
            case long x:
                if (amount is < 0 or >= 64) throw Bail(FallbackReason.PlatformDependent, "shift amount out of range (unspecified result)");
                return op switch { Code.Shl => x << (int)amount, Code.Shr => x >> (int)amount, _ => (long)((ulong)x >> (int)amount) };
            case nint x:
            {
                if (amount is < 0 or >= 32) throw Bail(FallbackReason.PlatformDependent, "native int shift by 32 or more");
                int s = (int)amount;
                long narrow = op switch { Code.Shl => (int)x << s, Code.Shr => (int)x >> s, _ => (int)((uint)(int)x >> s) };
                long wide = op switch { Code.Shl => (long)x << s, Code.Shr => (long)x >> s, _ => (long)((ulong)(long)x >> s) };
                return narrow == wide ? (nint)narrow : throw Bail(FallbackReason.PlatformDependent, "native int result differs between 32- and 64-bit platforms");
            }
            default:
                throw Bail(FallbackReason.InvalidCode, "shift of a non-integer");
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
                Code.Div => y == 0 || (x == int.MinValue && y == -1) ? throw DivideError() : x / y,
                Code.Div_Un => y == 0 ? throw DivideError() : (int)((uint)x / (uint)y),
                Code.Rem => y == 0 || (x == int.MinValue && y == -1) ? throw DivideError() : x % y,
                Code.Rem_Un => y == 0 ? throw DivideError() : (int)((uint)x % (uint)y),
                Code.And => x & y,
                Code.Or => x | y,
                Code.Xor => x ^ y,
                Code.Add_Ovf => checked(x + y),
                Code.Sub_Ovf => checked(x - y),
                Code.Mul_Ovf => checked(x * y),
                Code.Add_Ovf_Un => unchecked((int)checked(unchecked((uint)x) + unchecked((uint)y))),
                Code.Sub_Ovf_Un => unchecked((int)checked(unchecked((uint)x) - unchecked((uint)y))),
                Code.Mul_Ovf_Un => unchecked((int)checked(unchecked((uint)x) * unchecked((uint)y))),
                _ => throw Bail(FallbackReason.InvalidCode, $"{op} on integers"),
            };
        }
        catch (OverflowException)
        {
            throw Bail(FallbackReason.RuntimeError, "arithmetic overflow");
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
                Code.Div => y == 0 || (x == long.MinValue && y == -1) ? throw DivideError() : x / y,
                Code.Div_Un => y == 0 ? throw DivideError() : (long)((ulong)x / (ulong)y),
                Code.Rem => y == 0 || (x == long.MinValue && y == -1) ? throw DivideError() : x % y,
                Code.Rem_Un => y == 0 ? throw DivideError() : (long)((ulong)x % (ulong)y),
                Code.And => x & y,
                Code.Or => x | y,
                Code.Xor => x ^ y,
                Code.Add_Ovf => checked(x + y),
                Code.Sub_Ovf => checked(x - y),
                Code.Mul_Ovf => checked(x * y),
                Code.Add_Ovf_Un => unchecked((long)checked(unchecked((ulong)x) + unchecked((ulong)y))),
                Code.Sub_Ovf_Un => unchecked((long)checked(unchecked((ulong)x) - unchecked((ulong)y))),
                Code.Mul_Ovf_Un => unchecked((long)checked(unchecked((ulong)x) * unchecked((ulong)y))),
                _ => throw Bail(FallbackReason.InvalidCode, $"{op} on integers"),
            };
        }
        catch (OverflowException)
        {
            throw Bail(FallbackReason.RuntimeError, "arithmetic overflow");
        }
    }

    private static EvaluationBailout DivideError() => Bail(FallbackReason.RuntimeError, "division by zero or overflow");

    private static object Float32(Code op, float x, float y) => op switch
    {
        Code.Add => x + y,
        Code.Sub => x - y,
        Code.Mul => x * y,
        Code.Div => x / y,
        Code.Rem => x % y,
        _ => throw Bail(FallbackReason.InvalidCode, $"{op} on floats"),
    };

    private static object Float64(Code op, double x, double y) => op switch
    {
        Code.Add => x + y,
        Code.Sub => x - y,
        Code.Mul => x * y,
        Code.Div => x / y,
        Code.Rem => x % y,
        _ => throw Bail(FallbackReason.InvalidCode, $"{op} on floats"),
    };

    public static object Negate(object? value) => value switch
    {
        int i => (object)unchecked(-i),
        long l => unchecked(-l),
        nint n => n == int.MinValue ? throw Bail(FallbackReason.PlatformDependent, "native int result differs between 32- and 64-bit platforms") : -n,
        float f => -f,
        double d => -d,
        _ => throw Bail(FallbackReason.InvalidCode, "neg on a non-number"),
    };

    public static object Not(object? value) => value switch
    {
        int i => (object)~i,
        long l => ~l,
        nint n => ~n, // ~x stays in the int32 range
        _ => throw Bail(FallbackReason.InvalidCode, "not on a non-integer"),
    };

    /// <summary>ckfinite: throws ArithmeticException on NaN and infinities.</summary>
    public static object CheckFinite(object? value) => value switch
    {
        float f => float.IsFinite(f) ? (object)f : throw Bail(FallbackReason.RuntimeError, "ckfinite on a non-finite value"),
        double d => double.IsFinite(d) ? d : throw Bail(FallbackReason.RuntimeError, "ckfinite on a non-finite value"),
        _ => throw Bail(FallbackReason.InvalidCode, "ckfinite on a non-float"),
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
            case (long, long) or (nint or int, nint or int):
            {
                // Native ints hold int32-range values: sign extension keeps signed and unsigned order on both platforms.
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
            case (double or float, double or float):
            {
                double x = Float(a), y = Float(b);
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
        }
        if (IsNumber(a) || IsNumber(b))
            throw Bail(FallbackReason.InvalidCode, "comparison of mismatched operands");
        // References: equality, and 'x != null' compiled as cgt.un x, null.
        return op switch
        {
            Code.Ceq when a is string && b is string && !ReferenceEquals(a, b) =>
                throw Bail(FallbackReason.PlatformDependent, "reference comparison of two strings (depends on interning)"),
            Code.Ceq => ReferenceEquals(a, b),
            Code.Cgt_Un when b == null => a != null,
            Code.Cgt_Un when a == null => false,
            Code.Clt_Un when a == null => b != null,
            Code.Clt_Un when b == null => false,
            _ => throw Bail(FallbackReason.InvalidCode, "ordered comparison of references"),
        };
    }

    private static double Float(object? v) => v is float f ? f : (double)v!;

    public static bool IsNumber(object? v) => v is int or long or nint or double or float;

    /// <summary>A two-operand conditional branch, expressed through the comparisons (ECMA-335 III.3.5-3.11).</summary>
    public static bool Branch(Code op, object? a, object? b)
    {
        bool isFloat = a is double or float || b is double or float;
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
            _ => throw Bail(FallbackReason.InvalidCode, $"unsupported branch {op}"),
        };
    }

    public static object Convert(Code op, object? value)
    {
        bool unsignedSource = op is Code.Conv_R_Un or Code.Conv_Ovf_I1_Un or Code.Conv_Ovf_I2_Un or Code.Conv_Ovf_I4_Un or Code.Conv_Ovf_I8_Un
            or Code.Conv_Ovf_U1_Un or Code.Conv_Ovf_U2_Un or Code.Conv_Ovf_U4_Un or Code.Conv_Ovf_U8_Un or Code.Conv_Ovf_I_Un or Code.Conv_Ovf_U_Un;
        bool isChecked = op is >= Code.Conv_Ovf_I1 and <= Code.Conv_Ovf_U8 or >= Code.Conv_Ovf_I1_Un and <= Code.Conv_Ovf_U_Un or Code.Conv_Ovf_I or Code.Conv_Ovf_U;
        bool nativeTarget = op is Code.Conv_I or Code.Conv_U or Code.Conv_Ovf_I or Code.Conv_Ovf_U or Code.Conv_Ovf_I_Un or Code.Conv_Ovf_U_Un;
        bool wideTarget = op is Code.Conv_I8 or Code.Conv_U8 or Code.Conv_Ovf_I8 or Code.Conv_Ovf_U8 or Code.Conv_Ovf_I8_Un or Code.Conv_Ovf_U8_Un
                          or Code.Conv_R_Un;

        // An unsigned view of a negative native int, or its extension to 64 bits, depends on the native size.
        if (value is nint { } n && n < 0 && (unsignedSource || wideTarget))
            throw Bail(FallbackReason.PlatformDependent, "conversion of a negative native int depends on the platform");

        if (op is Code.Conv_R4 or Code.Conv_R8 or Code.Conv_R_Un)
        {
            double d = value switch
            {
                int i => unsignedSource ? (uint)i : i,
                long l => unsignedSource ? (ulong)l : l,
                nint x => (long)x,
                float f => f,
                double x => x,
                _ => throw Bail(FallbackReason.InvalidCode, "conversion of a non-number"),
            };
            if (op == Code.Conv_R4)
                return value switch { long l when !unsignedSource => (float)l, int i => (float)i, _ => (float)d }; // single rounding from integers
            return d;
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
            case nint x:
                source = (long)x;
                break;
            case float or double:
                double d = Float(value);
                if (double.IsNaN(d) || Math.Abs(d) >= 1e30)
                    throw Bail(isChecked ? FallbackReason.RuntimeError : FallbackReason.PlatformDependent, "float to integer conversion out of range");
                source = (Int128)Math.Truncate(d);
                break;
            default:
                throw Bail(FallbackReason.InvalidCode, "conversion of a non-number");
        }

        var (min, max) = op switch
        {
            Code.Conv_I1 or Code.Conv_Ovf_I1 or Code.Conv_Ovf_I1_Un => ((Int128)sbyte.MinValue, (Int128)sbyte.MaxValue),
            Code.Conv_U1 or Code.Conv_Ovf_U1 or Code.Conv_Ovf_U1_Un => (0, byte.MaxValue),
            Code.Conv_I2 or Code.Conv_Ovf_I2 or Code.Conv_Ovf_I2_Un => (short.MinValue, short.MaxValue),
            Code.Conv_U2 or Code.Conv_Ovf_U2 or Code.Conv_Ovf_U2_Un => (0, ushort.MaxValue),
            Code.Conv_I4 or Code.Conv_Ovf_I4 or Code.Conv_Ovf_I4_Un => (int.MinValue, int.MaxValue),
            Code.Conv_U4 or Code.Conv_Ovf_U4 or Code.Conv_Ovf_U4_Un => (0, uint.MaxValue),
            Code.Conv_I8 or Code.Conv_Ovf_I8 or Code.Conv_Ovf_I8_Un => (long.MinValue, long.MaxValue),
            // Native targets: checked against the 32-bit range, where the conversion overflows on a 32-bit platform.
            Code.Conv_I or Code.Conv_Ovf_I or Code.Conv_Ovf_I_Un => (int.MinValue, int.MaxValue),
            Code.Conv_U or Code.Conv_Ovf_U or Code.Conv_Ovf_U_Un => (0, uint.MaxValue),
            _ => ((Int128)0, (Int128)ulong.MaxValue), // U8 and its checked forms
        };
        if (source < min || source > max)
        {
            if (nativeTarget)
            {
                // Out of the 64-bit range too: a checked conversion throws on every platform.
                bool signed = op is Code.Conv_I or Code.Conv_Ovf_I or Code.Conv_Ovf_I_Un;
                bool wideOverflow = signed ? source < long.MinValue || source > long.MaxValue : source < 0 || source > ulong.MaxValue;
                throw isChecked && wideOverflow
                    ? Bail(FallbackReason.RuntimeError, "checked conversion overflow")
                    : Bail(FallbackReason.PlatformDependent, "native int conversion of a value outside the 32-bit range");
            }
            if (isChecked) throw Bail(FallbackReason.RuntimeError, "checked conversion overflow");
            if (value is double or float) throw Bail(FallbackReason.PlatformDependent, "float to integer conversion out of range");
        }

        long bits = unchecked((long)source);
        if (nativeTarget) return Native(bits);
        if (op is Code.Conv_I8 or Code.Conv_U8 or Code.Conv_Ovf_I8 or Code.Conv_Ovf_U8 or Code.Conv_Ovf_I8_Un or Code.Conv_Ovf_U8_Un) return bits;
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
