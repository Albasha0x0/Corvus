using System.Text;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace NetDecompilerMcp.Services.Simplify;

/// <summary>Evaluation left the supported subset; the message says why.</summary>
internal sealed class EvaluationBailout(string reason) : Exception(reason);

/// <summary>Limits of one evaluation: call depth (frames, the evaluated call itself included) and executed instructions.</summary>
public sealed record EvaluationLimits(int MaxDepth = 8, int InstructionBudget = 100_000);

/// <summary>
/// Heap objects of the evaluator. Objects created by a static constructor are static state: later evaluations may read
/// them but not change them, because the real program sees the same objects.
/// </summary>
internal abstract class HeapObject
{
    public bool Shared { get; init; }
}

internal sealed class ArrayObject(Array data) : HeapObject
{
    public Array Data { get; } = data;
}

internal sealed class BuilderObject : HeapObject
{
    public StringBuilder Text { get; } = new();
}

/// <summary>The result of ldtoken on a field (only consumed by RuntimeHelpers.InitializeArray).</summary>
internal sealed record FieldHandle(FieldDef Field);

/// <summary>A managed pointer to a local, an argument or an array element.</summary>
internal sealed class Pointer(Func<object?> get, Action<object?> set)
{
    public object? Get() => get();
    public void Set(object? value) => set(value);
}

/// <summary>Value of a slot whose type the evaluator does not model (structs, pointers); reading it bails out.</summary>
internal sealed class Opaque
{
    public static readonly Opaque Instance = new();
}

/// <summary>
/// Interprets a safe subset of IL to compute values at analysis time: integer and floating-point arithmetic, bit
/// operations, conversions, branches, locals, arrays of primitives and strings, read-only static fields (after running
/// the static constructor), strings, StringBuilder, Encoding and Base64, and calls to static methods of the same module.
/// Anything else (I/O, reflection, exceptions, instance objects, calli, native code) throws <see cref="EvaluationBailout"/>.
/// Stack values: int (int32), long (int64 and native int), double (F), null, string and the heap types above.
/// Static state computed by static constructors is cached for the evaluator's lifetime.
/// </summary>
internal sealed partial class IlEvaluator(ModuleDef module, EvaluationLimits limits)
{
    private const int MaxArrayLength = 1 << 20;
    private const int MaxStringLength = 1 << 20;

    private readonly Dictionary<FieldDef, object?> _statics = new();
    private readonly Dictionary<TypeDef, string?> _initialized = new(); // null: initialized; otherwise why it failed
    private readonly HashSet<TypeDef> _initializing = new();
    private readonly Dictionary<MethodDef, Dictionary<Instruction, int>> _indexes = new();
    private int _budget;
    private int _depth;
    private int _cctorDepth;

    private static readonly object Void = new();

    public EvaluationLimits Limits => limits;

    /// <summary>
    /// A type whose static constructor is the code being simplified: its static state is not known at that point (the
    /// constructor is still running), so evaluations that need it bail out.
    /// </summary>
    public TypeDef? InitializingType { get; set; }

    /// <summary>
    /// Runs a straight-line instruction sequence (no branches, arguments or locals) on an empty stack and returns the
    /// resulting stack, bottom first.
    /// </summary>
    public List<object?> EvaluateSlice(IList<Instruction> slice)
    {
        _budget = limits.InstructionBudget;
        _depth = 0;
        var frame = new Frame(null, slice, [], [], [], []);
        try
        {
            Interpret(frame, sliceMode: true);
        }
        catch (Exception ex) when (ex is not (EvaluationBailout or OperationCanceledException))
        {
            // Malformed operands or metadata in the evaluated code.
            throw Bail($"evaluation failed ({ex.GetType().Name}: {ex.Message})");
        }
        return frame.Stack;
    }

    private sealed class Frame(MethodDef? method, IList<Instruction> code, object?[] args, Slot[] argSlots, object?[] locals, Slot[] localSlots)
    {
        public MethodDef? Method { get; } = method;
        public IList<Instruction> Code { get; } = code;
        public object?[] Args { get; } = args;
        public Slot[] ArgSlots { get; } = argSlots;
        public object?[] Locals { get; } = locals;
        public Slot[] LocalSlots { get; } = localSlots;
        public List<object?> Stack { get; } = new();
    }

    private static EvaluationBailout Bail(string reason) => new(reason);

    private object? Execute(MethodDef method, object?[] args)
    {
        if (_depth + 1 > limits.MaxDepth)
            throw Bail($"call depth exceeds the limit of {limits.MaxDepth}");
        if (method.Module != module)
            throw Bail($"calls {Describe(method)} in another module");
        if (method.IsPinvokeImpl || method.IsInternalCall || method.IsRuntime || method.IsNative || !method.HasBody)
            throw Bail($"calls {Describe(method)}, which has no IL body (native or runtime code)");
        if (method.HasGenericParameters || method.DeclaringType.HasGenericParameters)
            throw Bail($"calls generic {Describe(method)}");
        var body = method.Body;
        if (body.HasExceptionHandlers)
            throw Bail($"{Describe(method)} uses exception handling");

        var argSlots = method.Parameters.Select(p => SlotOf(p.Type)).ToArray();
        var actual = new object?[args.Length];
        for (int i = 0; i < args.Length; i++) actual[i] = Store(argSlots[i], args[i]);
        var localSlots = body.Variables.Select(v => SlotOf(v.Type)).ToArray();
        var locals = localSlots.Select(Default).ToArray();

        _depth++;
        try
        {
            return Interpret(new Frame(method, body.Instructions, actual, argSlots, locals, localSlots), sliceMode: false);
        }
        finally
        {
            _depth--;
        }
    }

    private Dictionary<Instruction, int> IndexOf(Frame frame)
    {
        if (frame.Method != null && _indexes.TryGetValue(frame.Method, out var cached)) return cached;
        var index = new Dictionary<Instruction, int>(frame.Code.Count);
        for (int i = 0; i < frame.Code.Count; i++) index[frame.Code[i]] = i;
        if (frame.Method != null) _indexes[frame.Method] = index;
        return index;
    }

    /// <summary>Runs a frame until ret (returns the value, or <see cref="Void"/>) or, in slice mode, the end of the code.</summary>
    private object? Interpret(Frame f, bool sliceMode)
    {
        var code = f.Code;
        var stack = f.Stack;
        Dictionary<Instruction, int>? index = null;
        int Target(Instruction target) => (index ??= IndexOf(f)).TryGetValue(target, out int i) ? i : throw Bail("branch target outside the method");
        object? Pop() => stack.Count > 0 ? Pop1(stack) : throw Bail("stack underflow");
        void Push(object? v) => stack.Add(v);

        int pc = 0;
        while (true)
        {
            if (pc >= code.Count)
            {
                if (sliceMode) return Void;
                throw Bail($"execution runs past the end of {Describe(f.Method!)}");
            }
            if (--_budget < 0)
                throw Bail($"instruction budget of {limits.InstructionBudget:N0} exhausted");
            var ins = code[pc++];
            var op = ins.OpCode.Code;
            switch (op)
            {
                case Code.Nop:
                    break;

                case Code.Ldarg: case Code.Ldarg_S: case Code.Ldarg_0: case Code.Ldarg_1: case Code.Ldarg_2: case Code.Ldarg_3:
                    Push(Load(f.Args, ArgIndex(f, ins)));
                    break;
                case Code.Starg: case Code.Starg_S:
                {
                    int i = ArgIndex(f, ins);
                    f.Args[i] = Store(f.ArgSlots[i], Pop());
                    break;
                }
                case Code.Ldarga: case Code.Ldarga_S:
                {
                    int i = ArgIndex(f, ins);
                    var args = f.Args;
                    var slot = f.ArgSlots[i];
                    Push(new Pointer(() => Load(args, i), v => args[i] = Store(slot, v)));
                    break;
                }
                case Code.Ldloc: case Code.Ldloc_S: case Code.Ldloc_0: case Code.Ldloc_1: case Code.Ldloc_2: case Code.Ldloc_3:
                    Push(Load(f.Locals, LocalIndex(f, ins)));
                    break;
                case Code.Stloc: case Code.Stloc_S: case Code.Stloc_0: case Code.Stloc_1: case Code.Stloc_2: case Code.Stloc_3:
                {
                    int i = LocalIndex(f, ins);
                    f.Locals[i] = Store(f.LocalSlots[i], Pop());
                    break;
                }
                case Code.Ldloca: case Code.Ldloca_S:
                {
                    int i = LocalIndex(f, ins);
                    var locals = f.Locals;
                    var slot = f.LocalSlots[i];
                    Push(new Pointer(() => Load(locals, i), v => locals[i] = Store(slot, v)));
                    break;
                }

                case Code.Ldc_I4: case Code.Ldc_I4_S: case Code.Ldc_I4_M1: case Code.Ldc_I4_0: case Code.Ldc_I4_1: case Code.Ldc_I4_2:
                case Code.Ldc_I4_3: case Code.Ldc_I4_4: case Code.Ldc_I4_5: case Code.Ldc_I4_6: case Code.Ldc_I4_7: case Code.Ldc_I4_8:
                    Push(ins.GetLdcI4Value());
                    break;
                case Code.Ldc_I8:
                    Push((long)ins.Operand);
                    break;
                case Code.Ldc_R4:
                    Push((double)(float)ins.Operand);
                    break;
                case Code.Ldc_R8:
                    Push((double)ins.Operand);
                    break;
                case Code.Ldnull:
                    Push(null);
                    break;
                case Code.Ldstr:
                    Push((string)ins.Operand);
                    break;
                case Code.Dup:
                {
                    var v = Pop();
                    Push(v);
                    Push(v);
                    break;
                }
                case Code.Pop:
                    Pop();
                    break;

                case Code.Add: case Code.Sub: case Code.Mul: case Code.Div: case Code.Div_Un: case Code.Rem: case Code.Rem_Un:
                case Code.And: case Code.Or: case Code.Xor: case Code.Shl: case Code.Shr: case Code.Shr_Un:
                case Code.Add_Ovf: case Code.Add_Ovf_Un: case Code.Sub_Ovf: case Code.Sub_Ovf_Un: case Code.Mul_Ovf: case Code.Mul_Ovf_Un:
                {
                    var b = Pop();
                    var a = Pop();
                    Push(Numeric.Binary(op, a, b));
                    break;
                }
                case Code.Neg:
                    Push(Pop() switch
                    {
                        int i => unchecked(-i),
                        long l => unchecked(-l),
                        double d => -d,
                        _ => throw Bail("neg on a non-number"),
                    });
                    break;
                case Code.Not:
                    Push(Pop() switch
                    {
                        int i => ~i,
                        long l => ~l,
                        _ => throw Bail("not on a non-integer"),
                    });
                    break;
                case Code.Ceq: case Code.Cgt: case Code.Cgt_Un: case Code.Clt: case Code.Clt_Un:
                {
                    var b = Pop();
                    var a = Pop();
                    Push(Numeric.Compare(op, a, b) ? 1 : 0);
                    break;
                }
                case Code.Conv_I1: case Code.Conv_I2: case Code.Conv_I4: case Code.Conv_I8: case Code.Conv_U1: case Code.Conv_U2:
                case Code.Conv_U4: case Code.Conv_U8: case Code.Conv_I: case Code.Conv_U: case Code.Conv_R4: case Code.Conv_R8: case Code.Conv_R_Un:
                case Code.Conv_Ovf_I1: case Code.Conv_Ovf_I2: case Code.Conv_Ovf_I4: case Code.Conv_Ovf_I8: case Code.Conv_Ovf_U1:
                case Code.Conv_Ovf_U2: case Code.Conv_Ovf_U4: case Code.Conv_Ovf_U8: case Code.Conv_Ovf_I: case Code.Conv_Ovf_U:
                case Code.Conv_Ovf_I1_Un: case Code.Conv_Ovf_I2_Un: case Code.Conv_Ovf_I4_Un: case Code.Conv_Ovf_I8_Un: case Code.Conv_Ovf_U1_Un:
                case Code.Conv_Ovf_U2_Un: case Code.Conv_Ovf_U4_Un: case Code.Conv_Ovf_U8_Un: case Code.Conv_Ovf_I_Un: case Code.Conv_Ovf_U_Un:
                    Push(Numeric.Convert(op, Pop()));
                    break;

                case Code.Br: case Code.Br_S:
                    pc = Target((Instruction)ins.Operand);
                    break;
                case Code.Brtrue: case Code.Brtrue_S:
                    if (Numeric.IsTrue(Pop())) pc = Target((Instruction)ins.Operand);
                    break;
                case Code.Brfalse: case Code.Brfalse_S:
                    if (!Numeric.IsTrue(Pop())) pc = Target((Instruction)ins.Operand);
                    break;
                case Code.Beq: case Code.Beq_S: case Code.Bne_Un: case Code.Bne_Un_S: case Code.Bge: case Code.Bge_S: case Code.Bge_Un: case Code.Bge_Un_S:
                case Code.Bgt: case Code.Bgt_S: case Code.Bgt_Un: case Code.Bgt_Un_S: case Code.Ble: case Code.Ble_S: case Code.Ble_Un: case Code.Ble_Un_S:
                case Code.Blt: case Code.Blt_S: case Code.Blt_Un: case Code.Blt_Un_S:
                {
                    var b = Pop();
                    var a = Pop();
                    if (Numeric.Branch(op, a, b)) pc = Target((Instruction)ins.Operand);
                    break;
                }
                case Code.Switch:
                {
                    var targets = (IList<Instruction>)ins.Operand;
                    var value = Pop() as int? ?? throw Bail("switch on a non-int32 value");
                    if ((uint)value < (uint)targets.Count) pc = Target(targets[value]);
                    break;
                }
                case Code.Ret:
                    if (sliceMode) throw Bail("ret in a slice");
                    return HasReturnValue(f.Method!) ? Pop() : Void;

                case Code.Newarr:
                {
                    var length = Numeric.Index(Pop());
                    if (length < 0) throw Bail("negative array length");
                    if (length > MaxArrayLength) throw Bail($"array of {length:N0} elements is too large");
                    Push(new ArrayObject(Array.CreateInstance(ElementClrType(((ITypeDefOrRef)ins.Operand).ToTypeSig()), (int)length)) { Shared = _cctorDepth > 0 });
                    break;
                }
                case Code.Ldlen:
                    Push((long)ArrayOf(Pop()).Data.Length);
                    break;
                case Code.Ldelem_I1: case Code.Ldelem_U1: case Code.Ldelem_I2: case Code.Ldelem_U2: case Code.Ldelem_I4: case Code.Ldelem_U4:
                case Code.Ldelem_I8: case Code.Ldelem_I: case Code.Ldelem_R4: case Code.Ldelem_R8: case Code.Ldelem_Ref: case Code.Ldelem:
                {
                    var i = Numeric.Index(Pop());
                    var array = ArrayOf(Pop());
                    if ((ulong)i >= (ulong)array.Data.Length) throw Bail("array index out of range");
                    var slot = op == Code.Ldelem ? SlotOf(((ITypeDefOrRef)ins.Operand).ToTypeSig()) : ElementSlot(op);
                    Push(Store(slot, NaturalElement(array.Data, (int)i)));
                    break;
                }
                case Code.Stelem_I1: case Code.Stelem_I2: case Code.Stelem_I4: case Code.Stelem_I8: case Code.Stelem_I:
                case Code.Stelem_R4: case Code.Stelem_R8: case Code.Stelem_Ref: case Code.Stelem:
                {
                    var value = Pop();
                    var i = Numeric.Index(Pop());
                    var array = ArrayOf(Pop());
                    RequireMutable(array);
                    if ((ulong)i >= (ulong)array.Data.Length) throw Bail("array index out of range");
                    SetElement(array.Data, (int)i, value);
                    break;
                }

                case Code.Ldind_I1: case Code.Ldind_U1: case Code.Ldind_I2: case Code.Ldind_U2: case Code.Ldind_I4: case Code.Ldind_U4:
                case Code.Ldind_I8: case Code.Ldind_I: case Code.Ldind_R4: case Code.Ldind_R8: case Code.Ldind_Ref:
                    Push(Store(IndirectSlot(op), PointerOf(Pop()).Get()));
                    break;
                case Code.Stind_I1: case Code.Stind_I2: case Code.Stind_I4: case Code.Stind_I8: case Code.Stind_I:
                case Code.Stind_R4: case Code.Stind_R8: case Code.Stind_Ref:
                {
                    var value = Pop();
                    PointerOf(Pop()).Set(value);
                    break;
                }

                case Code.Ldsfld:
                    Push(LoadStatic((IField)ins.Operand));
                    break;
                case Code.Stsfld:
                    StoreStatic((IField)ins.Operand, Pop());
                    break;
                case Code.Ldtoken:
                    Push(ins.Operand is FieldDef fd ? new FieldHandle(fd) : throw Bail("ldtoken of a type or method"));
                    break;

                case Code.Call: case Code.Callvirt: case Code.Newobj:
                {
                    var method = (IMethod)ins.Operand;
                    var sig = method.MethodSig ?? throw Bail("call without a signature");
                    int count = sig.Params.Count + (sig.HasThis && op != Code.Newobj ? 1 : 0);
                    if (sig.ExplicitThis || sig.CallingConvention == CallingConvention.VarArg) throw Bail("vararg or explicit-this call");
                    if (stack.Count < count) throw Bail("stack underflow");
                    var args = new object?[count];
                    for (int i = count - 1; i >= 0; i--) args[i] = Pop();
                    var result = Invoke(method, op, args);
                    if (result != Void) Push(result);
                    break;
                }

                default:
                    throw Bail($"unsupported instruction {ins.OpCode.Name}");
            }
        }
    }

    private static object? Pop1(List<object?> stack)
    {
        var v = stack[^1];
        stack.RemoveAt(stack.Count - 1);
        return v;
    }

    private static object? Load(object?[] slots, int i) =>
        slots[i] is Opaque ? throw Bail("reads a struct or pointer variable") : slots[i];

    private static int ArgIndex(Frame f, Instruction ins)
    {
        int i = ins.GetParameterIndex();
        return i >= 0 && i < f.Args.Length ? i : throw Bail("argument access outside a method");
    }

    private static int LocalIndex(Frame f, Instruction ins)
    {
        if (f.Method == null) throw Bail("local access outside a method");
        var local = ins.GetLocal(f.Method.Body.Variables);
        int i = local?.Index ?? -1;
        return i >= 0 && i < f.Locals.Length ? i : throw Bail("local access outside a method");
    }

    private static bool HasReturnValue(IMethod m) => m.MethodSig.RetType.RemovePinnedAndModifiers().ElementType != ElementType.Void;

    internal static string Describe(IMethod m) => $"{m.DeclaringType?.FullName}::{m.Name}({Core.Format.ParameterTypes(m.MethodSig)})";

    // ---- static state

    private object? LoadStatic(IField field)
    {
        if (field.FullName == "System.String System.String::Empty") return "";
        var fd = field as FieldDef;
        if (fd == null || fd.Module != module)
            throw Bail($"reads static field {field.FullName} of another module");
        if (!fd.IsStatic) throw Bail("ldsfld of an instance field");
        if (_cctorDepth == 0 && !fd.IsInitOnly)
            throw Bail($"reads mutable static field {fd.DeclaringType.FullName}::{fd.Name}");
        EnsureInitialized(fd.DeclaringType);
        return _statics.TryGetValue(fd, out var v) ? Load([v], 0) : Default(SlotOf(fd.FieldType));
    }

    private void StoreStatic(IField field, object? value)
    {
        if (_cctorDepth == 0)
            throw Bail($"writes static field {field.FullName}");
        var fd = field as FieldDef;
        if (fd == null || fd.Module != module || !fd.IsStatic)
            throw Bail($"writes static field {field.FullName} of another module");
        EnsureInitialized(fd.DeclaringType);
        _statics[fd] = Store(SlotOf(fd.FieldType), value);
    }

    /// <summary>Calling a static method of a type without beforefieldinit runs its static constructor.</summary>
    private void TriggerTypeInitializer(MethodDef method)
    {
        if (!method.DeclaringType.IsBeforeFieldInit) EnsureInitialized(method.DeclaringType);
    }

    /// <summary>
    /// Runs a type's static constructor once, with a fresh budget. If it cannot be evaluated, statics it wrote are rolled
    /// back and every later access to the type bails out with the same reason.
    /// </summary>
    private void EnsureInitialized(TypeDef type)
    {
        if (type == InitializingType)
            throw Bail($"needs the static state of {type.FullName} inside its own static constructor");
        if (_initialized.TryGetValue(type, out var failure))
        {
            if (failure != null) throw Bail(failure);
            return;
        }
        if (_initializing.Contains(type)) return; // recursive initialization sees the partially initialized type, as at run time
        if (type.HasGenericParameters) throw Bail($"static state of generic type {type.FullName}");
        var cctor = type.FindStaticConstructor();
        if (cctor == null)
        {
            _initialized[type] = null;
            return;
        }

        var snapshot = new Dictionary<FieldDef, object?>(_statics);
        var (budget, depth) = (_budget, _depth);
        _initializing.Add(type);
        _cctorDepth++;
        _budget = limits.InstructionBudget;
        _depth = 0;
        try
        {
            Execute(cctor, []);
            _initialized[type] = null;
        }
        catch (EvaluationBailout ex)
        {
            _statics.Clear();
            foreach (var (k, v) in snapshot) _statics[k] = v;
            var reason = $"static constructor of {type.FullName} cannot be evaluated: {ex.Message}";
            _initialized[type] = reason;
            throw Bail(reason);
        }
        finally
        {
            _cctorDepth--;
            _initializing.Remove(type);
            (_budget, _depth) = (budget, depth);
        }
    }

    private void RequireMutable(HeapObject obj)
    {
        if (obj.Shared && _cctorDepth == 0)
            throw Bail("modifies an object held in a static field");
    }

    // ---- slots: how values are stored in typed locations

    private enum Slot { I1, U1, I2, U2, Bool, I4, I8, R4, R8, Ref, Opaque }

    private Slot SlotOf(TypeSig? sig)
    {
        sig = sig?.RemovePinnedAndModifiers();
        switch (sig?.ElementType)
        {
            case ElementType.I1: return Slot.I1;
            case ElementType.U1: return Slot.U1;
            case ElementType.Boolean: return Slot.Bool;
            case ElementType.I2: return Slot.I2;
            case ElementType.U2: case ElementType.Char: return Slot.U2;
            case ElementType.I4: case ElementType.U4: return Slot.I4;
            case ElementType.I8: case ElementType.U8: case ElementType.I: case ElementType.U: return Slot.I8;
            case ElementType.R4: return Slot.R4;
            case ElementType.R8: return Slot.R8;
            case ElementType.String: case ElementType.Object: case ElementType.Class: case ElementType.SZArray:
            case ElementType.Array: case ElementType.ByRef:
                return Slot.Ref;
            case ElementType.GenericInst:
                return sig.IsValueType ? Slot.Opaque : Slot.Ref;
            case ElementType.ValueType:
                var td = sig.ToTypeDefOrRef()?.ResolveTypeDef();
                return td is { IsEnum: true } && td.GetEnumUnderlyingType() is { } underlying ? SlotOf(underlying) : Slot.Opaque;
            default:
                return Slot.Opaque;
        }
    }

    private static object? Default(Slot slot) => slot switch
    {
        Slot.I8 => 0L,
        Slot.R4 or Slot.R8 => 0.0,
        Slot.Ref => null,
        Slot.Opaque => Opaque.Instance,
        _ => 0,
    };

    /// <summary>The value as it reads back after being stored in a slot (small integers truncate, float rounds).</summary>
    private static object? Store(Slot slot, object? value) => slot switch
    {
        Slot.I1 => (int)unchecked((sbyte)Numeric.Bits(value)),
        Slot.U1 or Slot.Bool => (int)unchecked((byte)Numeric.Bits(value)),
        Slot.I2 => (int)unchecked((short)Numeric.Bits(value)),
        Slot.U2 => (int)unchecked((ushort)Numeric.Bits(value)),
        Slot.I4 => unchecked((int)Numeric.Bits(value)),
        Slot.I8 => Numeric.Bits(value),
        Slot.R4 => value is double d ? (double)(float)d : throw Bail("float slot holds a non-float"),
        Slot.R8 => value is double d ? d : throw Bail("double slot holds a non-float"),
        Slot.Ref => value is int or long or double ? throw Bail("reference slot holds a number") : value,
        _ => throw Bail("stores a struct or pointer value"),
    };

    private static Slot ElementSlot(Code op) => op switch
    {
        Code.Ldelem_I1 => Slot.I1,
        Code.Ldelem_U1 => Slot.U1,
        Code.Ldelem_I2 => Slot.I2,
        Code.Ldelem_U2 => Slot.U2,
        Code.Ldelem_I4 or Code.Ldelem_U4 => Slot.I4,
        Code.Ldelem_I8 or Code.Ldelem_I => Slot.I8,
        Code.Ldelem_R4 => Slot.R4,
        Code.Ldelem_R8 => Slot.R8,
        _ => Slot.Ref,
    };

    private static Slot IndirectSlot(Code op) => op switch
    {
        Code.Ldind_I1 => Slot.I1,
        Code.Ldind_U1 => Slot.U1,
        Code.Ldind_I2 => Slot.I2,
        Code.Ldind_U2 => Slot.U2,
        Code.Ldind_I4 or Code.Ldind_U4 => Slot.I4,
        Code.Ldind_I8 or Code.Ldind_I => Slot.I8,
        Code.Ldind_R4 => Slot.R4,
        Code.Ldind_R8 => Slot.R8,
        _ => Slot.Ref,
    };

    // ---- arrays

    private Type ElementClrType(TypeSig sig)
    {
        sig = sig.RemovePinnedAndModifiers();
        return sig.ElementType switch
        {
            ElementType.I1 => typeof(sbyte),
            ElementType.U1 => typeof(byte),
            ElementType.Boolean => typeof(bool),
            ElementType.I2 => typeof(short),
            ElementType.U2 => typeof(ushort),
            ElementType.Char => typeof(char),
            ElementType.I4 => typeof(int),
            ElementType.U4 => typeof(uint),
            ElementType.I8 => typeof(long),
            ElementType.U8 => typeof(ulong),
            ElementType.R4 => typeof(float),
            ElementType.R8 => typeof(double),
            _ => SlotOf(sig) == Slot.Ref ? typeof(object) : throw Bail($"array of {sig.FullName}"),
        };
    }

    private static ArrayObject ArrayOf(object? value) => value switch
    {
        ArrayObject a => a,
        null => throw Bail("null array access"),
        _ => throw Bail("array access on a non-array"),
    };

    private static Pointer PointerOf(object? value) => value as Pointer ?? throw Bail("indirect access through a non-pointer");

    /// <summary>An element as a stack value (small integers widen to int32).</summary>
    private static object? NaturalElement(Array data, int i) => data switch
    {
        byte[] a => (int)a[i],
        sbyte[] a => (int)a[i],
        bool[] a => a[i] ? 1 : 0,
        short[] a => (int)a[i],
        ushort[] a => (int)a[i],
        char[] a => (int)a[i],
        int[] a => a[i],
        uint[] a => unchecked((int)a[i]),
        long[] a => a[i],
        ulong[] a => unchecked((long)a[i]),
        float[] a => (double)a[i],
        double[] a => a[i],
        object?[] a => a[i],
        _ => throw Bail("unsupported array"),
    };

    private static void SetElement(Array data, int i, object? value)
    {
        switch (data)
        {
            case byte[] a: a[i] = unchecked((byte)Numeric.Bits(value)); break;
            case sbyte[] a: a[i] = unchecked((sbyte)Numeric.Bits(value)); break;
            case bool[] a: a[i] = Numeric.Bits(value) != 0; break;
            case short[] a: a[i] = unchecked((short)Numeric.Bits(value)); break;
            case ushort[] a: a[i] = unchecked((ushort)Numeric.Bits(value)); break;
            case char[] a: a[i] = unchecked((char)Numeric.Bits(value)); break;
            case int[] a: a[i] = unchecked((int)Numeric.Bits(value)); break;
            case uint[] a: a[i] = unchecked((uint)Numeric.Bits(value)); break;
            case long[] a: a[i] = Numeric.Bits(value); break;
            case ulong[] a: a[i] = unchecked((ulong)Numeric.Bits(value)); break;
            case float[] a: a[i] = value is double d ? (float)d : throw Bail("float element from a non-float"); break;
            case double[] a: a[i] = value is double e ? e : throw Bail("double element from a non-float"); break;
            case object?[] a: a[i] = value is int or long or double ? throw Bail("boxing is not supported") : value; break;
            default: throw Bail("unsupported array");
        }
    }

    // ---- calls

    private object? Invoke(IMethod method, Code op, object?[] args)
    {
        if (method is MethodSpec) throw Bail($"calls generic method {Describe(method)}");
        if (Intrinsics.TryGetValue(method.FullName, out var intrinsic))
        {
            if (op == Code.Callvirt && args.Length > 0 && args[0] == null) throw Bail("null reference");
            var result = intrinsic(this, args);
            if (result is string { Length: > MaxStringLength }) throw Bail("string result too long");
            return HasReturnValue(method) || op == Code.Newobj ? result : Void;
        }
        if (method is MethodDef md && md.Module == module)
        {
            if (op == Code.Newobj) throw Bail($"creates an instance of {md.DeclaringType.FullName}");
            if (!md.IsStatic) throw Bail($"calls instance method {Describe(md)}");
            TriggerTypeInitializer(md);
            var result = Execute(md, args);
            return HasReturnValue(md) ? result : Void;
        }
        throw Bail($"calls {Describe(method)}, which is not evaluable");
    }
}
