using dnlib.DotNet;
using System.Text;

namespace NetDecompilerMcp.Services.Simplify;

/// <summary>
/// Framework methods the evaluator models directly, keyed by dnlib full name. All are deterministic and culture-independent
/// for the values they accept (number formatting bails out on negative values, whose sign depends on the culture).
/// Arguments include 'this' first for instance methods.
/// </summary>
internal sealed partial class IlEvaluator
{
    private static readonly Dictionary<string, Func<IlEvaluator, object?[], object?>> Intrinsics = BuildIntrinsics();

    public static IReadOnlySet<string> IntrinsicNames { get; } = Intrinsics.Keys.ToHashSet(StringComparer.Ordinal);

    /// <summary>The arguments (receiver first) an intrinsic modifies, or returns as an alias; the others are only read.</summary>
    public static IReadOnlyList<int> MutatedArguments(string intrinsic) => intrinsic switch
    {
        "System.Void System.Array::Reverse(System.Array)" => [0],
        "System.Void System.Array::Copy(System.Array,System.Array,System.Int32)" => [1],
        "System.Void System.Array::Copy(System.Array,System.Int32,System.Array,System.Int32,System.Int32)" => [2],
        "System.Void System.Runtime.CompilerServices.RuntimeHelpers::InitializeArray(System.Array,System.RuntimeFieldHandle)" => [0],
        "System.Void System.Buffer::BlockCopy(System.Array,System.Int32,System.Array,System.Int32,System.Int32)" => [2],
        _ when intrinsic.Contains("System.Text.StringBuilder::Append(", StringComparison.Ordinal) ||
               intrinsic.Contains("System.Text.StringBuilder::Insert(", StringComparison.Ordinal) ||
               intrinsic.Contains("System.Text.StringBuilder::set_Length(", StringComparison.Ordinal) => [0],
        // Algorithm objects change through their setters; Dispose closes whatever it is called on.
        _ when intrinsic.StartsWith("System.Void System.Security.Cryptography.", StringComparison.Ordinal) && (intrinsic.Contains("::set_", StringComparison.Ordinal) ||
               intrinsic.Contains("::Clear(", StringComparison.Ordinal)) => [0],
        "System.Void System.IDisposable::Dispose()" => [0],
        _ => [],
    };

    private static Dictionary<string, Func<IlEvaluator, object?[], object?>> BuildIntrinsics()
    {
        const string S = "System.String", I = "System.Int32", C = "System.Char", B = "System.Boolean", SB = "System.Text.StringBuilder";
        var t = new Dictionary<string, Func<IlEvaluator, object?[], object?>>(StringComparer.Ordinal);
        void Add(string ret, string type, string name, string parameters, Func<IlEvaluator, object?[], object?> f) =>
            t[$"{ret} {type}::{name}({parameters})"] = f;

        // System.String
        Add(S, S, "Concat", $"{S},{S}", (_, a) => string.Concat(NStr(a[0]), NStr(a[1])));
        Add(S, S, "Concat", $"{S},{S},{S}", (_, a) => string.Concat(NStr(a[0]), NStr(a[1]), NStr(a[2])));
        Add(S, S, "Concat", $"{S},{S},{S},{S}", (_, a) => string.Concat(NStr(a[0]), NStr(a[1]), NStr(a[2]), NStr(a[3])));
        Add(S, S, "Concat", $"{S}[]", (_, a) => string.Concat(Strings(a[0])));
        Add(S, S, "Concat", "System.Object,System.Object", (_, a) => string.Concat(NStr(a[0]), NStr(a[1])));
        Add(S, S, "Concat", "System.Object,System.Object,System.Object", (_, a) => string.Concat(NStr(a[0]), NStr(a[1]), NStr(a[2])));
        Add(S, S, "Join", $"{S},{S}[]", (_, a) => string.Join(NStr(a[0]), Strings(a[1])));
        Add(I, S, "get_Length", "", (_, a) => Str(a[0]).Length);
        Add(C, S, "get_Chars", I, (_, a) => (int)Str(a[0])[InRange(I4(a[1]), Str(a[0]).Length)]);
        Add(S, S, "Substring", I, (_, a) => Try(() => Str(a[0]).Substring(I4(a[1]))));
        Add(S, S, "Substring", $"{I},{I}", (_, a) => Try(() => Str(a[0]).Substring(I4(a[1]), I4(a[2]))));
        Add(S, S, "Insert", $"{I},{S}", (_, a) => Try(() => Str(a[0]).Insert(I4(a[1]), Str(a[2]))));
        Add(S, S, "Remove", I, (_, a) => Try(() => Str(a[0]).Remove(I4(a[1]))));
        Add(S, S, "Remove", $"{I},{I}", (_, a) => Try(() => Str(a[0]).Remove(I4(a[1]), I4(a[2]))));
        Add(S, S, "Replace", $"{S},{S}", (_, a) => Try(() => Str(a[0]).Replace(Str(a[1]), NStr(a[2]), StringComparison.Ordinal)));
        Add(S, S, "Replace", $"{C},{C}", (_, a) => Str(a[0]).Replace(Chr(a[1]), Chr(a[2])));
        Add(S, S, "Trim", "", (_, a) => Str(a[0]).Trim());
        Add(S, S, "ToUpperInvariant", "", (_, a) => Str(a[0]).ToUpperInvariant());
        Add(S, S, "ToLowerInvariant", "", (_, a) => Str(a[0]).ToLowerInvariant());
        Add(I, S, "IndexOf", C, (_, a) => Str(a[0]).IndexOf(Chr(a[1])));
        Add("System.Char[]", S, "ToCharArray", "", (e, a) => e.NewArray(Str(a[0]).ToCharArray()));
        Add(B, S, "op_Equality", $"{S},{S}", (_, a) => NullableStr(a[0]) == NullableStr(a[1]) ? 1 : 0);
        Add(B, S, "op_Inequality", $"{S},{S}", (_, a) => NullableStr(a[0]) != NullableStr(a[1]) ? 1 : 0);
        Add(B, S, "Equals", $"{S},{S}", (_, a) => NullableStr(a[0]) == NullableStr(a[1]) ? 1 : 0);
        Add(B, S, "Equals", S, (_, a) => Str(a[0]) == NullableStr(a[1]) ? 1 : 0);
        Add(B, S, "IsNullOrEmpty", S, (_, a) => string.IsNullOrEmpty(NullableStr(a[0])) ? 1 : 0);
        // The interned instance: equal strings are the same object, which evaluated code compares by value anyway.
        Add(S, S, "Intern", S, (_, a) => Str(a[0]));
        Add("System.Void", S, ".ctor", "System.Char[]", (_, a) => a[0] == null ? "" : new string(Chars(a[0])));
        Add("System.Void", S, ".ctor", $"System.Char[],{I},{I}", (_, a) => Try(() => new string(Chars(a[0]), I4(a[1]), I4(a[2]))));
        Add("System.Void", S, ".ctor", $"{C},{I}", (_, a) => Try(() => new string(Chr(a[0]), I4(a[1]))));

        // System.Object virtuals, dispatched on the modelled receivers (sb.ToString() compiles to callvirt Object::ToString)
        Add(S, "System.Object", "ToString", "", (_, a) => a[0] switch
        {
            string s => s,
            BuilderObject b => b.Text.ToString(),
            BoxedValue boxed => BoxedText(boxed),
            Pointer { } p when p.Get() is int i => NonNegative(i).ToString(System.Globalization.CultureInfo.InvariantCulture), // constrained. int32
            null => throw Bail(FallbackReason.RuntimeError, "null reference"),
            _ => throw Bail(FallbackReason.UnsupportedValue, "ToString of an object the interpreter does not model"),
        });

        // System.Char, System.Int32
        Add(S, C, "ToString", C, (_, a) => Chr(a[0]).ToString());
        Add(S, C, "ToString", "", (_, a) => Chr(Deref(a[0])).ToString());
        Add(S, I, "ToString", "", (_, a) => NonNegative(I4(Deref(a[0]))).ToString(System.Globalization.CultureInfo.InvariantCulture));

        // System.Text.StringBuilder
        Add("System.Void", SB, ".ctor", "", (e, _) => e.NewBuilder());
        Add("System.Void", SB, ".ctor", I, (e, _) => e.NewBuilder());
        Add("System.Void", SB, ".ctor", S, (e, a) => e.NewBuilder(NStr(a[0])));
        Add(SB, SB, "Append", S, (e, a) => e.Append(a[0], NStr(a[1])));
        Add(SB, SB, "Append", C, (e, a) => e.Append(a[0], Chr(a[1]).ToString()));
        Add(SB, SB, "Append", "System.Char[]", (e, a) => e.Append(a[0], a[1] == null ? "" : new string(Chars(a[1]))));
        Add(SB, SB, "Append", I, (e, a) => e.Append(a[0], NonNegative(I4(a[1])).ToString(System.Globalization.CultureInfo.InvariantCulture)));
        Add(SB, SB, "Insert", $"{I},{S}", (e, a) =>
        {
            var b = e.MutableBuilder(a[0]);
            e.Allocate(2L * NStr(a[2]).Length);
            int before = b.Text.Length;
            Try(() => b.Text.Insert(I4(a[1]), NStr(a[2])));
            e.Resized(b, before, b.Text.Length);
            return e.CheckLength(b);
        });
        Add(S, SB, "ToString", "", (_, a) => Builder(a[0]).Text.ToString());
        Add(I, SB, "get_Length", "", (_, a) => Builder(a[0]).Text.Length);
        Add("System.Void", SB, "set_Length", I, (e, a) =>
        {
            var b = e.MutableBuilder(a[0]);
            if (I4(a[1]) > b.Text.Length) e.Allocate(2L * (I4(a[1]) - b.Text.Length));
            Try(() => b.Text.Length = I4(a[1]));
            return e.CheckLength(b);
        });
        Add(C, SB, "get_Chars", I, (_, a) => (int)Builder(a[0]).Text[InRange(I4(a[1]), Builder(a[0]).Text.Length)]);

        // System.Text.Encoding: the static properties return immutable instances
        Add("System.Text.Encoding", "System.Text.Encoding", "get_UTF8", "", (_, _) => Encoding.UTF8);
        Add("System.Text.Encoding", "System.Text.Encoding", "get_ASCII", "", (_, _) => Encoding.ASCII);
        Add("System.Text.Encoding", "System.Text.Encoding", "get_Unicode", "", (_, _) => Encoding.Unicode);
        Add("System.Text.Encoding", "System.Text.Encoding", "get_BigEndianUnicode", "", (_, _) => Encoding.BigEndianUnicode);
        Add(S, "System.Text.Encoding", "GetString", "System.Byte[]", (_, a) => Enc(a[0]).GetString(Bytes(a[1])));
        Add(S, "System.Text.Encoding", "GetString", $"System.Byte[],{I},{I}", (_, a) => Try(() => Enc(a[0]).GetString(Bytes(a[1]), I4(a[2]), I4(a[3]))));
        Add("System.Byte[]", "System.Text.Encoding", "GetBytes", S, (e, a) => e.NewArray(Enc(a[0]).GetBytes(Str(a[1]))));

        // System.Convert
        Add("System.Byte[]", "System.Convert", "FromBase64String", S, (e, a) => e.NewArray(Try(() => Convert.FromBase64String(Str(a[0])))));
        Add(S, "System.Convert", "ToBase64String", "System.Byte[]", (_, a) => Convert.ToBase64String(Bytes(a[0])));
        // Only digits parse the same in every culture (signs and white space are the culture's own).
        Add(I, "System.Convert", "ToInt32", S, (_, a) => a[0] == null ? 0
            : Str(a[0]) is { Length: > 0 } digits && digits.All(char.IsAsciiDigit)
                ? int.TryParse(digits, System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out int v) ? v : throw Bail(FallbackReason.RuntimeError, "the number does not fit an int32")
                : throw Bail(FallbackReason.PlatformDependent, "parsing anything but digits depends on the culture"));

        // Integer conversions: checked, as the CLR's (out of range throws OverflowException).
        static object Checked(Func<object> f)
        {
            try { return f(); }
            catch (OverflowException) { throw Bail(FallbackReason.RuntimeError, "the value does not fit (OverflowException)"); }
        }
        Add(I, "System.Convert", "ToInt32", "System.Int64", (_, a) => Checked(() => checked((int)(a[0] as long? ?? throw Bail(FallbackReason.InvalidCode, "expected an int64")))));
        Add(I, "System.Convert", "ToInt32", "System.UInt32", (_, a) => Checked(() => checked((int)(uint)I4(a[0]))));
        Add(I, "System.Convert", "ToInt32", "System.Int16", (_, a) => (int)(short)I4(a[0]));
        Add(I, "System.Convert", "ToInt32", "System.Byte", (_, a) => (int)(byte)I4(a[0]));
        Add(I, "System.Convert", "ToInt32", C, (_, a) => (int)(char)I4(a[0]));
        Add("System.Int64", "System.Convert", "ToInt64", I, (_, a) => (long)I4(a[0]));
        Add("System.Byte", "System.Convert", "ToByte", I, (_, a) => Checked(() => (int)checked((byte)I4(a[0]))));
        Add(C, "System.Convert", "ToChar", I, (_, a) => Checked(() => (int)checked((char)I4(a[0]))));

        // System.Array, RuntimeHelpers
        Add(I, "System.Array", "get_Length", "", (_, a) => ArrayOf(a[0]).Data.Length);
        Add("System.Void", "System.Array", "Reverse", "System.Array", (e, a) =>
        {
            Array.Reverse(e.MutableArray(a[0]).Data);
            return null;
        });
        Add("System.Void", "System.Array", "Copy", "System.Array,System.Array,System.Int32", (e, a) =>
        {
            var target = e.MutableArray(a[1]);
            var before = e.Before(target, 0, I4(a[2]));
            Try(() => Array.Copy(ArrayOf(a[0]).Data, target.Data, I4(a[2])));
            e.Committed(target, 0, before);
            return null;
        });
        Add("System.Void", "System.Array", "Copy", "System.Array,System.Int32,System.Array,System.Int32,System.Int32", (e, a) =>
        {
            var target = e.MutableArray(a[2]);
            var before = e.Before(target, I4(a[3]), I4(a[4]));
            Try(() => Array.Copy(ArrayOf(a[0]).Data, I4(a[1]), target.Data, I4(a[3]), I4(a[4])));
            e.Committed(target, I4(a[3]), before);
            return null;
        });
        Add("System.Void", "System.Runtime.CompilerServices.RuntimeHelpers", "InitializeArray", "System.Array,System.RuntimeFieldHandle", (e, a) =>
        {
            var target = e.MutableArray(a[0]);
            var field = a[1] as FieldHandle ?? throw Bail(FallbackReason.InvalidCode, "InitializeArray without a field handle");
            var data = field.Field.InitialValue ?? throw Bail(FallbackReason.InvalidCode, "InitializeArray field has no data");
            if (target.Data is object?[]) throw Bail(FallbackReason.InvalidCode, "InitializeArray of a reference array");
            int size = Buffer.ByteLength(target.Data);
            if (data.Length < size) throw Bail(FallbackReason.InvalidCode, "InitializeArray data is shorter than the array");
            var before = e.Before(target, 0, target.Data.Length);
            Buffer.BlockCopy(data, 0, target.Data, 0, size);
            e.Committed(target, 0, before);
            return null;
        });

        // Buffer.BlockCopy copies bytes between arrays of primitives (native-size elements differ between platforms).
        Add("System.Void", "System.Buffer", "BlockCopy", "System.Array,System.Int32,System.Array,System.Int32,System.Int32", (e, a) =>
        {
            var source = ArrayOf(a[0]).Data;
            var targetArray = e.MutableArray(a[2]);
            var target = targetArray.Data;
            if (source is object?[] || target is object?[]) throw Bail(FallbackReason.RuntimeError, "Buffer.BlockCopy of an array of references (ArgumentException)");
            if (source is nint[] || target is nint[]) throw Bail(FallbackReason.PlatformDependent, "Buffer.BlockCopy of native-size integers");
            int width = Math.Max(Buffer.ByteLength(target) / Math.Max(target.Length, 1), 1);
            var before = e.Before(targetArray, I4(a[3]) / width, (I4(a[4]) + width - 1) / width + 1);
            Try(() => Buffer.BlockCopy(source, I4(a[1]), target, I4(a[3]), I4(a[4])));
            e.Committed(targetArray, I4(a[3]) / width, before);
            return null;
        });
        Add("System.Array", "System.Array", "CreateInstance", $"System.Type,{I}", (e, a) =>
        {
            int length = I4(a[1]);
            if (length < 0) throw Bail(FallbackReason.RuntimeError, "negative array length");
            if (length > MaxArrayLength) throw Bail(FallbackReason.MemoryLimit, $"array of {length:N0} elements is too large");
            return e.NewArray(Array.CreateInstance(e.ElementClrType(e.TypeOf(a[0]).Sig), length));
        });

        Add("System.Array", "System.Enum", "GetValues", "System.Type", (e, a) => e.EnumValues(a[0]));

        // System.Math
        Add(I, "System.Math", "Min", $"{I},{I}", (_, a) => Math.Min(I4(a[0]), I4(a[1])));
        Add(I, "System.Math", "Max", $"{I},{I}", (_, a) => Math.Max(I4(a[0]), I4(a[1])));
        Add(I, "System.Math", "Abs", I, (_, a) => I4(a[0]) == int.MinValue ? throw Bail(FallbackReason.RuntimeError, "Math.Abs overflow") : Math.Abs(I4(a[0])));

        // StringComparer, as dictionary comparers
        Add("System.StringComparer", "System.StringComparer", "get_Ordinal", "", (_, _) => new ComparerObject(false));
        Add("System.StringComparer", "System.StringComparer", "get_OrdinalIgnoreCase", "", (_, _) => new ComparerObject(true));

        // System.Threading.Monitor: evaluation is single-threaded, so lock always succeeds at once.
        Add("System.Void", "System.Threading.Monitor", "Enter", "System.Object", (_, a) => a[0] == null ? throw Bail(FallbackReason.RuntimeError, "null reference") : null);
        Add("System.Void", "System.Threading.Monitor", "Enter", "System.Object,System.Boolean&", (_, a) =>
        {
            if (a[0] == null) throw Bail(FallbackReason.RuntimeError, "null reference");
            (a[1] as Pointer ?? throw Bail(FallbackReason.InvalidCode, "Monitor.Enter without a lockTaken address")).Set(1);
            return null;
        });
        Add("System.Void", "System.Threading.Monitor", "Exit", "System.Object", (_, _) => null);

        AddReflection(Add);
        AddCrypto(Add);
        AddResourceManager(Add);
        return t;
    }

    private BuilderObject NewBuilder(string initial = "")
    {
        Allocate(32);
        var b = new BuilderObject { Shared = _cctorDepth > 0 };
        return Append(b, initial);
    }

    private BuilderObject Append(object? builder, string text)
    {
        var b = MutableBuilder(builder);
        Allocate(2L * text.Length);
        b.Text.Append(text);
        Resized(b, b.Text.Length - text.Length, b.Text.Length);
        return CheckLength(b);
    }

    private BuilderObject CheckLength(BuilderObject b) => b.Text.Length > MaxStringLength ? throw Bail(FallbackReason.MemoryLimit, "string too long") : b;

    private BuilderObject MutableBuilder(object? builder)
    {
        var b = Builder(builder);
        RequireMutable(b);
        return b;
    }

    private ArrayObject MutableArray(object? array)
    {
        var a = ArrayOf(array);
        RequireMutable(a);
        return a;
    }

    private static T Try<T>(Func<T> f)
    {
        try { return f(); }
        catch (Exception ex) when (ex is ArgumentException or FormatException or IndexOutOfRangeException or RankException or InvalidCastException or ArrayTypeMismatchException)
        {
            throw Bail(FallbackReason.RuntimeError, $"the call throws {ex.GetType().Name}");
        }
    }

    private static void Try(Action f) => Try(() => { f(); return 0; });

    private static int I4(object? v) => v as int? ?? throw Bail(FallbackReason.InvalidCode, "expected an int32");

    private static char Chr(object? v) => (char)I4(v);

    private static int NonNegative(int v) => v >= 0 ? v : throw Bail(FallbackReason.PlatformDependent, "formatting a negative number depends on the culture");

    private static int InRange(int i, int length) => (uint)i < (uint)length ? i : throw Bail(FallbackReason.RuntimeError, "index out of range");

    private static object? Deref(object? v) => v is Pointer p ? p.Get() : throw Bail(FallbackReason.InvalidCode, "expected a pointer to a value");

    private static string Str(object? v) => v switch
    {
        string s => s,
        null => throw Bail(FallbackReason.RuntimeError, "null reference"),
        _ => throw Bail(FallbackReason.InvalidCode, "expected a string"),
    };

    private static string? NullableStr(object? v) => v == null ? null : Str(v);

    /// <summary>String.Concat semantics: null becomes empty; a boxed value becomes its text.</summary>
    private static string NStr(object? v) => v switch
    {
        null => "",
        BoxedValue b => BoxedText(b),
        _ => Str(v),
    };

    /// <summary>
    /// ToString of a boxed integer, char or bool, which is the same in every culture (a negative number's sign is the
    /// culture's own); anything else is not modelled.
    /// </summary>
    private static string BoxedText(BoxedValue b)
    {
        var invariant = System.Globalization.CultureInfo.InvariantCulture;
        return (b.Type.ElementType, b.Value) switch
        {
            (ElementType.Boolean, int i) => i != 0 ? "True" : "False",
            (ElementType.Char, int i) => ((char)i).ToString(),
            (ElementType.I1 or ElementType.I2 or ElementType.I4 or ElementType.U1 or ElementType.U2, int i) => NonNegative(i).ToString(invariant),
            (ElementType.U4, int i) => ((uint)i).ToString(invariant),
            (ElementType.I8, long l) => l >= 0 ? l.ToString(invariant) : throw Bail(FallbackReason.PlatformDependent, "formatting a negative number depends on the culture"),
            (ElementType.U8, long l) => ((ulong)l).ToString(invariant),
            _ => throw Bail(FallbackReason.UnsupportedValue, $"the text of a boxed {b.Type.FullName}"),
        };
    }

    private static string?[] Strings(object? v) => ArrayOf(v).Data is object?[] items
        ? items.Select(NullableStr).ToArray()
        : throw Bail(FallbackReason.InvalidCode, "expected a string array");

    private static char[] Chars(object? v) => ArrayOf(v).Data as char[] ?? throw Bail(FallbackReason.InvalidCode, "expected a char array");

    private static byte[] Bytes(object? v) => ArrayOf(v).Data as byte[] ?? throw Bail(FallbackReason.InvalidCode, "expected a byte array");

    private static BuilderObject Builder(object? v) => v as BuilderObject ?? throw (v == null ? Bail(FallbackReason.RuntimeError, "null reference") : Bail(FallbackReason.InvalidCode, "expected a StringBuilder"));

    private static Encoding Enc(object? v) => v as Encoding ?? throw (v == null ? Bail(FallbackReason.RuntimeError, "null reference") : Bail(FallbackReason.InvalidCode, "expected an Encoding"));
}
