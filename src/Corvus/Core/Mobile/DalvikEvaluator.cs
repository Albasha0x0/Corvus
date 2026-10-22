using System.Text;

namespace Corvus.Core.Mobile;

/// <summary>The classes and methods an evaluation can reach: the code of the package's own DEX files.</summary>
public interface IDexProgram
{
    /// <summary>The method with this exact descriptor, or null when the program does not define it (a framework or library method).</summary>
    (DexFile File, DexClass Class, DexEncodedMethod Method)? FindMethod(string descriptor);

    /// <summary>The class with this descriptor, or null when the program does not define it.</summary>
    (DexFile File, DexClass Class)? FindClass(string descriptor);

    /// <summary>The methods whose code writes the static field (exact descriptors); empty when none does.</summary>
    IReadOnlyList<string> StaticWriters(string field);
}

/// <summary>How the evaluation of a decoder call ended: Partial when it stopped at a limit, Unknown when it is outside the evaluated subset.</summary>
public enum DexFoldStatus { Simplified, Partial, Unknown }

/// <summary>The string a decoder call returns (Simplified), or the reason it is not known: "code: detail".</summary>
public sealed record DexFold(DexFoldStatus Status, string? Value, string? Reason);

/// <summary>An array value of an evaluation: primitive elements are kept as their raw bits, normalized to the element type.</summary>
public sealed class DalvikArray
{
    /// <summary>The array descriptor, such as [C or [Ljava/lang/String;.</summary>
    public string Type { get; }
    public int Length { get; }
    internal long[]? Primitives { get; }
    internal object?[]? References { get; }
    /// <summary>Held by a static field: writing it changes state the next call sees.</summary>
    internal bool Shared { get; set; }

    /// <summary>A zero-filled array; throws ArgumentException for a type that is not an array descriptor.</summary>
    public DalvikArray(string type, int length)
    {
        if (type.Length < 2 || type[0] != '[') throw new ArgumentException($"{type} is not an array type.", nameof(type));
        Type = type;
        Length = length;
        if (type[1] is 'L' or '[') References = new object?[length];
        else Primitives = new long[length];
    }

    internal char Element => Type[1];

    /// <summary>An element: an int (boolean, byte, short, char, int, float bits), a long (long, double bits), or a reference.</summary>
    public object? this[int index]
    {
        get => References != null ? References[index] : Element is 'J' or 'D' ? Primitives![index] : (object)(int)Primitives![index];
        set
        {
            if (References != null) { References[index] = value; return; }
            long v = value switch { int i => i, long l => l, null => 0, _ => throw new ArgumentException("not a primitive value", nameof(value)) };
            Primitives![index] = Normalize(Element, v);
        }
    }

    internal static long Normalize(char element, long v) => element switch
    {
        'Z' => (byte)v,
        'B' => (sbyte)v,
        'S' => (short)v,
        'C' => (char)v,
        'I' or 'F' => (int)v,
        _ => v,
    };

    internal DalvikArray Copy()
    {
        var copy = new DalvikArray(Type, Length);
        if (References != null) Array.Copy(References, copy.References!, Length);
        else Array.Copy(Primitives!, copy.Primitives!, Length);
        return copy;
    }
}

/// <summary>
/// A bounded interpreter for static string decoder methods of DEX code: int, long and float arithmetic, arrays, branches,
/// switches, nested static calls of the program, its classes' static state as their static initializers leave it, and the
/// framework calls listed in the intrinsics. Anything else stops the evaluation with a reason; it never runs code outside
/// the program and never throws for malformed code.
/// </summary>
public sealed partial class DalvikEvaluator(IDexProgram program)
{
    /// <summary>Instructions per decoder call, nested calls included.</summary>
    public const int MaxSteps = 100_000;
    /// <summary>Instructions per static initializer, counted apart from the call that triggers it.</summary>
    public const int MaxInitializerSteps = 1_000_000;
    /// <summary>Array elements and string characters one call may create.</summary>
    public const int MaxElements = 1_000_000;
    public const int MaxDepth = 8;

    private sealed record Body(DexFile File, string Class, DexCode Code, List<DalvikInstruction> Instructions, Dictionary<int, int> At);

    private sealed class Statics
    {
        public readonly Dictionary<string, object?> Values = new(StringComparer.Ordinal);
        public string? Failure;
        public DexFoldStatus FailureStatus;
    }

    /// <summary>A value the interpreter does not model, kept in a static field until something reads it.</summary>
    private sealed record Unmodeled(string What);

    /// <summary>The object of new-instance before its constructor runs.</summary>
    private sealed record Uninitialized(string Type);

    /// <summary>A java.lang.Object instance, as static initializers create for locks.</summary>
    private sealed class PlainObject;

    private sealed class Stop(DexFoldStatus status, string code, string detail) : Exception(code + ": " + detail)
    {
        public DexFoldStatus Status { get; } = status;
    }

    private readonly Dictionary<string, Statics> _classes = new(StringComparer.Ordinal);
    private readonly Dictionary<(DexFile, uint), Body?> _bodies = [];
    private readonly List<string> _initializing = [];
    // Static fields one evaluation read, and the methods it ran.
    private readonly HashSet<string> _reads = new(StringComparer.Ordinal), _executed = new(StringComparer.Ordinal);
    private long _steps, _stepLimit = MaxSteps, _elements;
    private bool _stateChanged;

    /// <summary>
    /// Runs <paramref name="decoder"/> (a static method of the program returning a string) on constant arguments, twice: the
    /// string is Simplified only when both runs end within the limits and the second run, on the static state the first one
    /// left, returns the same string.
    /// </summary>
    public DexFold Fold(string decoder, IReadOnlyList<object?> arguments)
    {
        _reads.Clear();
        _executed.Clear();
        try
        {
            var first = Run(decoder, arguments);
            var second = Run(decoder, arguments);
            if (OtherWriter() is { } writer) return new(DexFoldStatus.Unknown, null, "mutable-static: " + writer);
            if (first is not string s) return new(DexFoldStatus.Unknown, null, first == null ? "unsupported-value: returns null" : "unsupported-value: returns no string");
            if (second is not string t || !string.Equals(s, t, StringComparison.Ordinal))
                return new(DexFoldStatus.Unknown, null, "cache-dependent: called again on the static state the first call left, it returns another string");
            return new(DexFoldStatus.Simplified, s, null);
        }
        catch (Stop e)
        {
            return new(e.Status, null, e.Message);
        }
        finally
        {
            // State one call changed is not the state the next call site starts from.
            if (_stateChanged) _classes.Clear();
            _stateChanged = false;
        }
    }

    /// <summary>The value of a static field of the program as its class's static initializer leaves it; false when that is not known.</summary>
    public bool TryReadStatic(string field, out object? value)
    {
        value = null;
        _reads.Clear();
        _executed.Clear();
        try
        {
            _steps = 0;
            _stepLimit = MaxSteps;
            _elements = 0;
            var f = ParseField(field);
            if (program.FindClass(f.Class) == null) return false;
            value = ReadStatic(f.Class, f.Name, f.Type, null);
            return value is not Unmodeled && OtherWriter() == null;
        }
        catch (Exception e) when (e is Stop or IndexOutOfRangeException or ArgumentException or InvalidCastException or OverflowException or FormatException)
        {
            return false;
        }
    }

    private object? Run(string decoder, IReadOnlyList<object?> arguments)
    {
        _steps = 0;
        _stepLimit = MaxSteps;
        _elements = 0;
        var target = program.FindMethod(decoder) ?? throw new Stop(DexFoldStatus.Unknown, "unsupported-call", decoder + " is not defined in the package");
        // Arrays the caller builds are new on every call; arrays from static state are shared between calls.
        var args = arguments.Select(a => a is DalvikArray { Shared: false } array ? DeepCopy(array) : a).ToArray();
        try
        {
            return Interpret(target.File, target.Class, target.Method, args, 0);
        }
        catch (Exception e) when (e is IndexOutOfRangeException or ArgumentException or InvalidCastException or OverflowException or FormatException)
        {
            throw new Stop(DexFoldStatus.Unknown, "invalid-code", e.Message);
        }
    }

    private static DalvikArray DeepCopy(DalvikArray a)
    {
        var copy = a.Copy();
        if (copy.References != null)
            for (int i = 0; i < copy.Length; i++)
                if (copy.References[i] is DalvikArray { Shared: false } inner) copy.References[i] = DeepCopy(inner);
        return copy;
    }

    private Body? Load(DexFile file, DexClass cls, DexEncodedMethod m)
    {
        if (_bodies.TryGetValue((file, m.CodeOffset), out var body)) return body;
        if (file.Code(m.CodeOffset) is { } code)
        {
            var insns = Dalvik.Decode(code.Instructions);
            var at = new Dictionary<int, int>(insns.Count);
            for (int k = 0; k < insns.Count; k++) at[insns[k].Offset] = k;
            body = new Body(file, cls.Descriptor, code, insns, at);
        }
        return _bodies[(file, m.CodeOffset)] = body;
    }

    private object? Interpret(DexFile file, DexClass cls, DexEncodedMethod method, object?[] args, int depth)
    {
        var descriptor = file.Method(method.MethodIndex).Descriptor;
        _executed.Add(descriptor);
        if (depth > MaxDepth) throw new Stop(DexFoldStatus.Partial, "call-depth", $"nested calls deeper than {MaxDepth} at {descriptor}");
        if ((method.Access & 0x8) == 0) throw new Stop(DexFoldStatus.Unknown, "instance-object", descriptor + " is an instance method");
        if ((method.Access & 0x100) != 0) throw new Stop(DexFoldStatus.Unknown, "no-code", descriptor + " is a native method");
        var body = method.CodeOffset == 0 ? null : Load(file, cls, method);
        if (body == null) throw new Stop(DexFoldStatus.Unknown, "no-code", descriptor + " has no code");
        var proto = file.Method(method.MethodIndex).Proto;
        var regs = new object?[body.Code.Registers];
        int r = body.Code.Registers - body.Code.Ins;
        if (r < 0 || args.Length != proto.Parameters.Count) throw Invalid(descriptor, "its parameters do not fit its registers");
        for (int k = 0; k < args.Length; k++)
        {
            if (r >= regs.Length) throw Invalid(descriptor, "its parameters do not fit its registers");
            regs[r] = args[k];
            r += proto.Parameters[k] is "J" or "D" ? 2 : 1;
        }
        return Execute(body, regs, depth, descriptor);
    }

    private static Stop Invalid(string method, string detail) => new(DexFoldStatus.Unknown, "invalid-code", $"{method}: {detail}");

    private static Stop Runtime(string detail) => new(DexFoldStatus.Unknown, "runtime-error", detail);

    private static Stop Unsupported(string code, string detail) => new(DexFoldStatus.Unknown, code, detail);

    private object? Execute(Body body, object?[] regs, int depth, string method)
    {
        var insns = body.Instructions;
        var code = body.Code.Instructions;
        object? result = null;
        int pc = 0;
        while (true)
        {
            if (pc < 0 || pc >= insns.Count) throw Invalid(method, "execution runs past the end of the code");
            if (++_steps > _stepLimit) throw new Stop(DexFoldStatus.Partial, "instruction-budget", $"more than {_stepLimit:N0} instructions");
            var i = insns[pc];
            int op = i.Opcode, next = pc + 1;
            if (i.IsPayload) throw Invalid(method, $"execution reaches a payload at {i.Offset:x}");
            int Jump(int target) => body.At.TryGetValue(target, out var k) ? k : throw Invalid(method, $"a branch to {target:x}, inside an instruction");
            object? Get(int reg) => (uint)reg < (uint)regs.Length ? regs[reg] : throw Invalid(method, $"register v{reg} is out of range");
            void Set(int reg, object? v) { if ((uint)reg >= (uint)regs.Length) throw Invalid(method, $"register v{reg} is out of range"); regs[reg] = v; }
            int I(int reg) => Get(reg) switch { int v => v, null => 0, var v => throw Invalid(method, $"v{reg} holds {Describe(v)}, not an int") };
            long L(int reg) => Get(reg) switch { long v => v, int v => v, null => 0, var v => throw Invalid(method, $"v{reg} holds {Describe(v)}, not a long") };
            object? O(int reg) => Get(reg) switch { 0 => null, int or long => throw Invalid(method, $"v{reg} holds a number, not a reference"), var v => v };
            switch (op)
            {
                case 0x00: break;
                case >= 0x01 and <= 0x09: Set(i.A, Get(i.B)); break;
                case >= 0x0a and <= 0x0c: Set(i.A, result); break;
                case 0x0d: throw Invalid(method, "move-exception outside a handler");
                case 0x0e: return null;
                case >= 0x0f and <= 0x11: return Get(i.A);
                case >= 0x12 and <= 0x15: Set(i.A, (int)i.Literal); break;
                case >= 0x16 and <= 0x19: Set(i.A, i.Literal); break;
                case 0x1a or 0x1b: Set(i.A, body.File.String(i.Index)); break;
                case 0x1c: throw Unsupported("unsupported-value", $"const-class {body.File.Type(i.Index)} (reflection)");
                case 0x1d or 0x1e:
                    if (O(i.A) == null) throw Runtime("monitor on null (NullPointerException)");
                    break;
                case 0x1f:
                {
                    var v = O(i.A);
                    if (v != null && !InstanceOf(v, body.File.Type(i.Index))) throw Runtime($"check-cast of {Describe(v)} to {body.File.Type(i.Index)} (ClassCastException)");
                    break;
                }
                case 0x20: Set(i.A, O(i.B) is { } v2 && InstanceOf(v2, body.File.Type(i.Index)) ? 1 : 0); break;
                case 0x21: Set(i.A, Array(O(i.B)).Length); break;
                case 0x22:
                {
                    var type = body.File.Type(i.Index);
                    if (type is not ("Ljava/lang/String;" or "Ljava/lang/StringBuilder;" or "Ljava/lang/StringBuffer;" or "Ljava/lang/Object;"))
                        throw Unsupported(program.FindClass(type) != null ? "instance-object" : "unsupported-call", $"new-instance {type}");
                    Set(i.A, new Uninitialized(type));
                    break;
                }
                case 0x23: Set(i.A, NewArray(body.File.Type(i.Index), I(i.B))); break;
                case 0x24 or 0x25:
                {
                    var type = body.File.Type(i.Index);
                    var array = NewArray(type, i.Arguments.Count);
                    if (array.Element is 'J' or 'D') throw Invalid(method, "filled-new-array of a wide type");
                    for (int k = 0; k < i.Arguments.Count; k++) array[k] = array.References != null ? O(i.Arguments[k]) : I(i.Arguments[k]);
                    result = array;
                    break;
                }
                case 0x26:
                {
                    var array = Array(O(i.A));
                    if (!body.At.TryGetValue(i.Target, out var p) || insns[p].Format != DalvikFormat.FillArrayPayload) throw Invalid(method, "fill-array-data without its payload");
                    var values = Dalvik.ArrayData(code, insns[p], out _);
                    if (array.Primitives == null) throw Invalid(method, "fill-array-data of a reference array");
                    if (values.Count > array.Length) throw Runtime("fill-array-data past the end of the array (ArrayIndexOutOfBoundsException)");
                    Write(array);
                    for (int k = 0; k < values.Count; k++) array.Primitives[k] = DalvikArray.Normalize(array.Element, values[k]);
                    break;
                }
                case 0x27: throw Runtime($"throws {Describe(O(i.A))}");
                case 0x28 or 0x29 or 0x2a: next = Jump(i.Target); break;
                case 0x2b or 0x2c:
                {
                    if (!body.At.TryGetValue(i.Target, out var p) || !insns[p].IsPayload) throw Invalid(method, "a switch without its payload");
                    int key = I(i.A);
                    foreach (var (k, target) in Dalvik.SwitchTargets(code, insns[p], i.Offset))
                        if (k == key) { next = Jump(target); break; }
                    break;
                }
                case 0x2d or 0x2e:
                {
                    float a = BitConverter.Int32BitsToSingle(I(i.B)), b = BitConverter.Int32BitsToSingle(I(i.C));
                    Set(i.A, a > b ? 1 : a == b ? 0 : a < b ? -1 : op == 0x2e ? 1 : -1);
                    break;
                }
                case 0x2f or 0x30:
                {
                    double a = BitConverter.Int64BitsToDouble(L(i.B)), b = BitConverter.Int64BitsToDouble(L(i.C));
                    Set(i.A, a > b ? 1 : a == b ? 0 : a < b ? -1 : op == 0x30 ? 1 : -1);
                    break;
                }
                case 0x31: Set(i.A, L(i.B).CompareTo(L(i.C))); break;
                case >= 0x32 and <= 0x37:
                {
                    bool taken;
                    if (op is 0x32 or 0x33 && (Get(i.A) is not (int or null) || Get(i.B) is not (int or null)))
                        taken = ReferenceEquals(O(i.A), O(i.B)) == (op == 0x32);
                    else
                    {
                        int a = I(i.A), b = I(i.B);
                        taken = op switch { 0x32 => a == b, 0x33 => a != b, 0x34 => a < b, 0x35 => a >= b, 0x36 => a > b, _ => a <= b };
                    }
                    if (taken) next = Jump(i.Target);
                    break;
                }
                case >= 0x38 and <= 0x3d:
                {
                    bool taken;
                    if (Get(i.A) is not (int or null)) taken = op == 0x39;
                    else
                    {
                        int a = I(i.A);
                        taken = op switch { 0x38 => a == 0, 0x39 => a != 0, 0x3a => a < 0, 0x3b => a >= 0, 0x3c => a > 0, _ => a <= 0 };
                    }
                    if (taken) next = Jump(i.Target);
                    break;
                }
                case >= 0x44 and <= 0x4a:
                {
                    var array = Array(O(i.B));
                    int index = Index(array, I(i.C));
                    Set(i.A, array[index]);
                    break;
                }
                case >= 0x4b and <= 0x51:
                {
                    var array = Array(O(i.B));
                    int index = Index(array, I(i.C));
                    Write(array);
                    if (array.References != null) array[index] = O(i.A);
                    else array[index] = array.Element is 'J' or 'D' ? L(i.A) : I(i.A);
                    break;
                }
                case >= 0x52 and <= 0x5f: throw Unsupported("instance-object", $"{i.Name} {body.File.Field(i.Index).Descriptor}");
                case >= 0x60 and <= 0x66:
                {
                    var f = body.File.Field(i.Index);
                    var v = ReadStatic(f.Class, f.Name, f.Type, body.Class);
                    if (v is Unmodeled u) throw Unsupported("unsupported-value", $"{f.Descriptor} holds {u.What}");
                    Set(i.A, v);
                    break;
                }
                case >= 0x67 and <= 0x6d:
                {
                    var f = body.File.Field(i.Index);
                    WriteStatic(f, f.Type is "J" or "D" ? L(i.A) : f.Type.Length > 1 ? O(i.A) : I(i.A), body.Class);
                    break;
                }
                case >= 0x6e and <= 0x72 or >= 0x74 and <= 0x78:
                {
                    var m = body.File.Method(i.Index);
                    bool isStatic = op is 0x71 or 0x77;
                    var args = new List<object?>();
                    int k = 0;
                    object? receiver = null;
                    if (!isStatic)
                    {
                        if (i.Arguments.Count == 0) throw Invalid(method, $"{m.Descriptor} without a receiver");
                        receiver = O(i.Arguments[k++]);
                    }
                    foreach (var p in m.Proto.Parameters)
                    {
                        if (k >= i.Arguments.Count) throw Invalid(method, $"{m.Descriptor} with too few registers");
                        int reg = i.Arguments[k];
                        args.Add(p is "J" or "D" ? L(reg) : p.Length > 1 ? O(reg) : I(reg));
                        k += p is "J" or "D" ? 2 : 1;
                    }
                    if (receiver is Uninitialized pending && m.Name == "<init>")
                    {
                        var created = Construct(pending, m, args);
                        // The verifier keeps an uninitialized object in this frame's registers only.
                        for (int x = 0; x < regs.Length; x++)
                            if (ReferenceEquals(regs[x], pending)) regs[x] = created;
                        result = null;
                    }
                    else result = Invoke(m, isStatic, receiver, [.. args], depth);
                    break;
                }
                case >= 0x7b and <= 0x8f: Set(i.A, Unary(op, Get(i.B) ?? 0)); break;
                case >= 0x90 and <= 0xaf: Set(i.A, Binary(op - 0x90, Get(i.B) ?? 0, Get(i.C) ?? 0)); break;
                case >= 0xb0 and <= 0xcf: Set(i.A, Binary(op - 0xb0, Get(i.A) ?? 0, Get(i.B) ?? 0)); break;
                case >= 0xd0 and <= 0xd7: Set(i.A, Literal(op - 0xd0, I(i.B), (int)i.Literal)); break;
                case >= 0xd8 and <= 0xe2: Set(i.A, Literal(op - 0xd8, I(i.B), (int)i.Literal)); break;
                default: throw Unsupported("unsupported-instruction", $"{i.Name} at {i.Offset:x} in {method}");
            }
            pc = next;
        }
    }

    private DalvikArray NewArray(string type, int length)
    {
        if (length < 0) throw Runtime($"an array of {length} elements (NegativeArraySizeException)");
        Allocate(length);
        try
        {
            return new DalvikArray(type, length);
        }
        catch (ArgumentException)
        {
            throw Unsupported("invalid-code", $"new-array of {type}");
        }
    }

    private void Allocate(long elements)
    {
        _elements += elements;
        if (_elements > MaxElements) throw new Stop(DexFoldStatus.Partial, "memory-limit", $"more than {MaxElements:N0} array elements and characters");
    }

    private static DalvikArray Array(object? v) => v switch
    {
        DalvikArray a => a,
        null => throw Runtime("an array access on null (NullPointerException)"),
        _ => throw Unsupported("invalid-code", $"{Describe(v)} used as an array"),
    };

    private static int Index(DalvikArray a, int index) =>
        (uint)index < (uint)a.Length ? index : throw Runtime($"index {index} of an array of {a.Length} (ArrayIndexOutOfBoundsException)");

    /// <summary>Notes a write to an array that static state holds, outside the initializer that builds it.</summary>
    private void Write(DalvikArray a)
    {
        if (a.Shared && _initializing.Count == 0) _stateChanged = true;
    }

    private static string Describe(object? v) => v switch
    {
        null => "null",
        string => "a string",
        DalvikArray a => "an array " + a.Type,
        StringBuilder => "a StringBuilder",
        Uninitialized u => "an uninitialized " + u.Type,
        int or long => "a number",
        _ => "a " + v.GetType().Name,
    };

    private static bool InstanceOf(object v, string type)
    {
        if (type == "Ljava/lang/Object;") return true;
        return v switch
        {
            string => type is "Ljava/lang/String;" or "Ljava/lang/CharSequence;" or "Ljava/lang/Comparable;" or "Ljava/io/Serializable;",
            StringBuilder => type is "Ljava/lang/StringBuilder;" or "Ljava/lang/StringBuffer;" or "Ljava/lang/CharSequence;" or "Ljava/lang/Appendable;"
                or "Ljava/io/Serializable;",
            DalvikArray a => type == a.Type || type is "Ljava/lang/Cloneable;" or "Ljava/io/Serializable;"
                || (type.StartsWith("[L", StringComparison.Ordinal) && a.Type.StartsWith("[L", StringComparison.Ordinal) && type == "[Ljava/lang/Object;"),
            Charset => type == "Ljava/nio/charset/Charset;",
            Base64Coder c => type == (c.Encoder ? "Ljava/util/Base64$Encoder;" : "Ljava/util/Base64$Decoder;"),
            _ => false,
        };
    }

    private object? Invoke(DexMethodRef m, bool isStatic, object? receiver, object?[] args, int depth)
    {
        if (isStatic && ResolveStatic(m) is { } target)
        {
            // A static initializer runs when its class's static state is first read, not on the first call.
            return Interpret(target.File, target.Class, target.Method, args, depth + 1);
        }
        if (!isStatic && program.FindClass(m.Class) != null && receiver is not (string or StringBuilder or DalvikArray))
            throw Unsupported("instance-object", m.Descriptor);
        return Intrinsic(m, isStatic, receiver, args);
    }

    private (DexFile File, DexClass Class, DexEncodedMethod Method)? ResolveStatic(DexMethodRef m)
    {
        var tail = "->" + m.Name + m.Proto.Descriptor;
        for (var (c, n) = (m.Class, 0); c != null && n < 16; n++)
        {
            if (program.FindMethod(c + tail) is { } found) return found;
            c = program.FindClass(c)?.Class.SuperClass;
        }
        return null;
    }

    private static (string Class, string Name, string Type) ParseField(string descriptor)
    {
        int arrow = descriptor.IndexOf("->", StringComparison.Ordinal), colon = descriptor.IndexOf(':', Math.Max(arrow, 0));
        if (arrow <= 0 || colon < 0) throw Unsupported("invalid-code", $"{descriptor} is not a field id");
        return (descriptor[..arrow], descriptor[(arrow + 2)..colon], descriptor[(colon + 1)..]);
    }

    /// <summary>The class in the program that declares a static field, searching superclasses as field resolution does.</summary>
    private (string Class, Statics State)? Declaring(string cls, string name, string type)
    {
        for (var (c, n) = (cls, 0); c != null && n < 16; n++)
        {
            if (program.FindClass(c) is not { } found) return null;
            var key = c + "->" + name + ":" + type;
            var state = Initialize(c, found.File, found.Class);
            if (state.Values.ContainsKey(key)) return (c, state);
            c = found.Class.SuperClass;
        }
        return null;
    }

    private object? ReadStatic(string cls, string name, string type, string? reader)
    {
        if (program.FindClass(cls) == null) return FrameworkStatic(cls + "->" + name + ":" + type);
        var (declaring, state) = Declaring(cls, name, type) ?? throw Unsupported("invalid-code", $"no static field {cls}->{name}:{type}");
        var key = declaring + "->" + name + ":" + type;
        _reads.Add(key);
        foreach (var writer in program.StaticWriters(key))
            if (!writer.StartsWith(declaring + "->", StringComparison.Ordinal)) throw Unsupported("mutable-static", $"{key} is also written by {writer}");
        return state.Values[key];
    }

    /// <summary>
    /// A writer of a static field the evaluation read other than its class's static initializer and the methods the evaluation
    /// ran ("field is also written by method"); null when there is none, so the value read is the one every run sees.
    /// </summary>
    private string? OtherWriter()
    {
        foreach (var key in _reads)
        {
            var initializer = key[..key.IndexOf("->", StringComparison.Ordinal)] + "-><clinit>()V";
            foreach (var writer in program.StaticWriters(key))
                if (writer != initializer && !_executed.Contains(writer)) return $"{key} is also written by {writer}";
        }
        return null;
    }

    private void WriteStatic(DexFieldRef f, object? value, string writer)
    {
        if (program.FindClass(f.Class) == null) throw Unsupported("mutable-static", $"writes {f.Descriptor}, a framework static");
        var (declaring, state) = Declaring(f.Class, f.Name, f.Type) ?? throw Unsupported("invalid-code", $"no static field {f.Descriptor}");
        bool initializer = _initializing.Contains(declaring);
        if (!initializer && declaring != writer) throw Unsupported("mutable-static", $"writes {f.Descriptor} of another class");
        if (!initializer) _stateChanged = true;
        if (value is DalvikArray a) MarkShared(a);
        state.Values[declaring + "->" + f.Name + ":" + f.Type] = value;
    }

    private static void MarkShared(DalvikArray a)
    {
        if (a.Shared) return;
        a.Shared = true;
        if (a.References != null)
            foreach (var x in a.References)
                if (x is DalvikArray inner) MarkShared(inner);
    }

    /// <summary>A class's static state: default and encoded initial values, then its static initializer run in the interpreter.</summary>
    private Statics Initialize(string descriptor, DexFile file, DexClass cls)
    {
        if (_classes.TryGetValue(descriptor, out var state))
        {
            if (state.Failure != null) throw new Stop(state.FailureStatus, "static-initializer", $"{descriptor}.<clinit>: {state.Failure}");
            // Initialized, or initializing further up the stack: Java reads the partly initialized state then.
            return state;
        }
        _classes[descriptor] = state = new Statics();
        var (fields, methods) = file.ClassData(cls);
        var encoded = file.StaticValues(cls);
        int n = 0;
        foreach (var f in fields.Where(f => f.IsStatic))
        {
            var r = file.Field(f.FieldIndex);
            state.Values[r.Descriptor] = n < encoded.Count ? Encoded(encoded[n], r.Type) : Default(r.Type);
            n++;
        }
        var clinit = methods.FirstOrDefault(m => file.Method(m.MethodIndex).Name == "<clinit>");
        if (clinit is { CodeOffset: not 0 })
        {
            var (steps, limit, elements, changed) = (_steps, _stepLimit, _elements, _stateChanged);
            _steps = 0;
            _stepLimit = MaxInitializerSteps;
            _elements = 0;
            _initializing.Add(descriptor);
            try
            {
                Interpret(file, cls, clinit, [], 0);
            }
            catch (Stop e)
            {
                state.Failure = e.Message;
                state.FailureStatus = e.Status;
                throw new Stop(e.Status, "static-initializer", $"{descriptor}.<clinit>: {e.Message}");
            }
            catch (Exception e) when (e is IndexOutOfRangeException or ArgumentException or InvalidCastException or OverflowException or FormatException)
            {
                state.Failure = "invalid-code: " + e.Message;
                throw new Stop(DexFoldStatus.Unknown, "static-initializer", $"{descriptor}.<clinit>: {state.Failure}");
            }
            finally
            {
                _initializing.Remove(descriptor);
                (_steps, _stepLimit, _elements, _stateChanged) = (steps, limit, elements, changed);
            }
        }
        foreach (var v in state.Values.Values)
            if (v is DalvikArray a) MarkShared(a);
        return state;
    }

    private static object? Default(string type) => type switch
    {
        "J" or "D" => (object)0L,
        _ when type.Length == 1 => (object)0,
        _ => null,
    };

    private static object? Encoded(DexValue v, string type) => v.Kind switch
    {
        "byte" => (int)(sbyte)v.Value!,
        "short" => (int)(short)v.Value!,
        "char" => (int)(char)v.Value!,
        "int" => type is "J" ? (object)(long)(int)v.Value! : (int)v.Value!,
        "long" => (long)v.Value!,
        "float" => BitConverter.SingleToInt32Bits((float)v.Value!),
        "double" => BitConverter.DoubleToInt64Bits((double)v.Value!),
        "boolean" => (bool)v.Value! ? 1 : 0,
        "string" => (string)v.Value!,
        "null" => Default(type),
        _ => new Unmodeled("an encoded " + v.Kind),
    };

    private static object Unary(int op, object v)
    {
        int I() => v is int i ? i : throw Unsupported("invalid-code", "a unary int operation on " + Describe(v));
        long L() => v switch { long l => l, int i => i, _ => throw Unsupported("invalid-code", "a unary long operation on " + Describe(v)) };
        float F() => BitConverter.Int32BitsToSingle(I());
        double D() => BitConverter.Int64BitsToDouble(L());
        // Each arm is boxed as its own type: int for 32-bit results, long for 64-bit ones.
        return op switch
        {
            0x7b => (object)(unchecked(-I())),
            0x7c => (object)(~I()),
            0x7d => (object)(unchecked(-L())),
            0x7e => (object)(~L()),
            0x7f => (object)(BitConverter.SingleToInt32Bits(-F())),
            0x80 => (object)(BitConverter.DoubleToInt64Bits(-D())),
            0x81 => (object)((long)I()),
            0x82 => (object)(BitConverter.SingleToInt32Bits(I())),
            0x83 => (object)(BitConverter.DoubleToInt64Bits(I())),
            0x84 => (object)(unchecked((int)L())),
            0x85 => (object)(BitConverter.SingleToInt32Bits(L())),
            0x86 => (object)(BitConverter.DoubleToInt64Bits(L())),
            0x87 => (object)(ToInt(F())),
            0x88 => (object)(ToLong(F())),
            0x89 => (object)(BitConverter.DoubleToInt64Bits(F())),
            0x8a => (object)(ToInt(D())),
            0x8b => (object)(ToLong(D())),
            0x8c => (object)(BitConverter.SingleToInt32Bits((float)D())),
            0x8d => (object)((int)(sbyte)I()),
            0x8e => (object)((int)(char)I()),
            _ => (object)((int)(short)I()),
        };
    }

    // Java narrows NaN to 0 and saturates out-of-range values.
    private static int ToInt(double d) => double.IsNaN(d) ? 0 : d >= int.MaxValue ? int.MaxValue : d <= int.MinValue ? int.MinValue : (int)d;

    private static long ToLong(double d) => double.IsNaN(d) ? 0 : d >= long.MaxValue ? long.MaxValue : d <= long.MinValue ? long.MinValue : (long)d;

    /// <summary>The binop at index <paramref name="n"/> of add-int .. rem-double.</summary>
    private static object Binary(int n, object x, object y)
    {
        if (n <= 10)
        {
            int a = x is int i ? i : throw Unsupported("invalid-code", "an int operation on " + Describe(x)), b = y is int j ? j : throw Unsupported("invalid-code", "an int operation on " + Describe(y));
            return IntOp(n, a, b);
        }
        if (n <= 21)
        {
            long a = x switch { long l => l, int i => i, _ => throw Unsupported("invalid-code", "a long operation on " + Describe(x)) };
            long b = y switch { long l => l, int i => i, _ => throw Unsupported("invalid-code", "a long operation on " + Describe(y)) };
            return unchecked(n switch
            {
                11 => a + b,
                12 => a - b,
                13 => a * b,
                14 => b == 0 ? throw Runtime("long division by zero (ArithmeticException)") : b == -1 ? -a : a / b,
                15 => b == 0 ? throw Runtime("long division by zero (ArithmeticException)") : b == -1 ? 0 : a % b,
                16 => a & b,
                17 => a | b,
                18 => a ^ b,
                19 => a << (int)(b & 63),
                20 => a >> (int)(b & 63),
                _ => (long)((ulong)a >> (int)(b & 63)),
            });
        }
        if (n <= 26)
        {
            float a = BitConverter.Int32BitsToSingle(x as int? ?? throw Unsupported("invalid-code", "a float operation on " + Describe(x)));
            float b = BitConverter.Int32BitsToSingle(y as int? ?? throw Unsupported("invalid-code", "a float operation on " + Describe(y)));
            return BitConverter.SingleToInt32Bits(n switch { 22 => a + b, 23 => a - b, 24 => a * b, 25 => a / b, _ => a % b });
        }
        double c = BitConverter.Int64BitsToDouble(x as long? ?? throw Unsupported("invalid-code", "a double operation on " + Describe(x)));
        double d = BitConverter.Int64BitsToDouble(y as long? ?? throw Unsupported("invalid-code", "a double operation on " + Describe(y)));
        return BitConverter.DoubleToInt64Bits(n switch { 27 => c + d, 28 => c - d, 29 => c * d, 30 => c / d, _ => c % d });
    }

    private static int IntOp(int n, int a, int b) => unchecked(n switch
    {
        0 => a + b,
        1 => a - b,
        2 => a * b,
        3 => b == 0 ? throw Runtime("division by zero (ArithmeticException)") : b == -1 ? -a : a / b,
        4 => b == 0 ? throw Runtime("division by zero (ArithmeticException)") : b == -1 ? 0 : a % b,
        5 => a & b,
        6 => a | b,
        7 => a ^ b,
        8 => a << (b & 31),
        9 => a >> (b & 31),
        _ => (int)((uint)a >> (b & 31)),
    });

    /// <summary>The lit16 (add .. xor) and lit8 (add .. ushr) operations, in binop order except index 1, rsub.</summary>
    private static int Literal(int n, int a, int literal) => n == 1 ? unchecked(literal - a) : IntOp(n, a, literal);
}
