using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace NetDecompilerMcp.Services.Simplify;

/// <summary>
/// Constant propagation over one method body, through the stack and the locals and along the control flow (conditional
/// constant propagation: a branch whose condition is known only passes its state on to the successor it takes). It
/// finds the conditional branches and switches whose operands are the same on every run, however far apart the
/// instructions computing them are: <c>int k = 7; ...; if (k * k % 4 == 3)</c>.
/// <para>
/// Values are the evaluator's (int, long, native int, float, double, string, null); arithmetic, comparisons and
/// conversions use the evaluator's own semantics (<see cref="Numeric"/>), and calls with constant arguments and reads of
/// readonly static fields are evaluated by <see cref="IlEvaluator"/>. Anything else is unknown. Locals whose address is
/// taken, or that a finally or fault handler writes, are always unknown; a handler starts with every local the method
/// writes unknown. Arguments are unknown.
/// </para>
/// </summary>
internal sealed class ConstantFlow
{
    /// <summary>A value that is not the same on every run (or not modelled).</summary>
    public static readonly object Unknown = new();

    private readonly CilBody _body;
    private readonly BodyGraph _graph;
    private readonly IlEvaluator _evaluator;
    private readonly bool _hasReturnValue;
    private readonly IList<Instruction> _code;
    private readonly bool[] _untracked; // per local
    private readonly TypeSig?[] _localTypes;
    private readonly Dictionary<(Instruction, string), object?> _calls = new();
    private readonly Dictionary<IField, object?> _fields = new();

    /// <summary>Calls and static field reads whose value was evaluated to a constant (the code may drop them with their result).</summary>
    public HashSet<Instruction> Evaluated { get; } = new();

    public ConstantFlow(CilBody body, BodyGraph graph, bool hasReturnValue, IlEvaluator evaluator)
    {
        _body = body;
        _graph = graph;
        _code = graph.Instructions;
        _hasReturnValue = hasReturnValue;
        _evaluator = evaluator;
        var variables = body.Variables;
        _untracked = new bool[variables.Count];
        _localTypes = variables.Select(v => v.Type?.RemovePinnedAndModifiers()).ToArray();
        for (int i = 0; i < variables.Count; i++)
            _untracked[i] = Initial(_localTypes[i], true) == Unknown;
        for (int i = 0; i < _code.Count; i++)
        {
            var ins = _code[i];
            if (ins.OpCode.Code is Code.Ldloca or Code.Ldloca_S && ins.GetLocal(variables) is { } taken) _untracked[taken.Index] = true;
            if (ins.IsStloc() && ins.GetLocal(variables) is { } stored && InFinallyOrFault(i)) _untracked[stored.Index] = true;
        }
    }

    private bool InFinallyOrFault(int index)
    {
        foreach (int id in _graph.Regions(index))
            if (id % 3 == 1 && _graph.Handlers[id / 3].HandlerType is ExceptionHandlerType.Finally or ExceptionHandlerType.Fault)
                return true;
        return false;
    }

    /// <summary>The value a local starts with: its type's default when the body zero-initializes locals.</summary>
    private static object? Initial(TypeSig? type, bool initLocals)
    {
        if (!initLocals) return Unknown;
        return type?.ElementType switch
        {
            ElementType.Boolean or ElementType.Char or ElementType.I1 or ElementType.U1 or ElementType.I2 or ElementType.U2
                or ElementType.I4 or ElementType.U4 => 0,
            ElementType.I8 or ElementType.U8 => 0L,
            ElementType.I or ElementType.U => (nint)0,
            ElementType.R4 => 0f,
            ElementType.R8 => 0.0,
            ElementType.String or ElementType.Object or ElementType.Class or ElementType.SZArray or ElementType.Array => null,
            _ => Unknown,
        };
    }

    private sealed class State(object?[] locals, object?[] stack)
    {
        public object?[] Locals { get; } = locals;
        public object?[] Stack { get; } = stack;
    }

    /// <summary>
    /// Runs the analysis. Returns the reachable conditional branches and switches whose outcome is known, with the
    /// instruction they continue at (the branch target, or the next instruction when they fall through).
    /// </summary>
    public List<(Instruction Branch, Instruction Next)> Decisions(MethodMeter? meter)
    {
        int n = _code.Count;
        var leader = new bool[n];
        if (n > 0) leader[0] = true;
        for (int i = 0; i < n; i++)
        {
            var ins = _code[i];
            if (_graph.Targets.Contains(ins)) leader[i] = true;
            if (ins.OpCode.FlowControl is FlowControl.Branch or FlowControl.Cond_Branch or FlowControl.Return or FlowControl.Throw
                    && i + 1 < n) leader[i + 1] = true;
        }

        var entry = new State?[n];
        var queued = new bool[n];
        var work = new Stack<int>();
        void Flow(int to, object?[] locals, List<object?> stack)
        {
            if (to < 0 || to >= n) return;
            var old = entry[to];
            if (old == null)
            {
                entry[to] = new State((object?[])locals.Clone(), stack.ToArray());
            }
            else
            {
                if (old.Stack.Length != stack.Count) throw new InvalidOperationException("inconsistent stack depth");
                bool changed = Join(old.Locals, locals) | Join(old.Stack, stack);
                if (!changed) return;
            }
            if (!queued[to])
            {
                queued[to] = true;
                work.Push(to);
            }
        }

        var initial = _localTypes.Select((t, i) => _untracked[i] ? Unknown : Initial(t, _body.InitLocals)).ToArray();
        Flow(0, initial, []);
        var handlerLocals = initial.Select((v, i) => IsWritten(i) ? Unknown : v).ToArray();
        var pending = _graph.Handlers.Select((eh, h) => h).ToList();
        var reached = new bool[n];
        var decisions = new Dictionary<Instruction, Instruction?>();

        while (true)
        {
            while (work.Count > 0)
            {
                meter?.CheckTime();
                int start = work.Pop();
                queued[start] = false;
                var state = entry[start]!;
                var locals = (object?[])state.Locals.Clone();
                var stack = state.Stack.ToList();
                for (int i = start; i < n; i++)
                {
                    if (i > start && leader[i])
                    {
                        Flow(i, locals, stack);
                        break;
                    }
                    reached[i] = true;
                    var ins = _code[i];
                    var decided = Step(ins, locals, stack);
                    switch (ins.OpCode.FlowControl)
                    {
                        case FlowControl.Cond_Branch:
                            // The last visit sees the final (most general) state: it decides.
                            decisions[ins] = decided;
                            if (decided != null)
                            {
                                Flow(_graph.IndexOf(decided), locals, stack);
                            }
                            else
                            {
                                foreach (var t in BodyGraph.BranchTargets(ins)) Flow(_graph.IndexOf(t), locals, stack);
                                Flow(i + 1, locals, stack);
                            }
                            goto nextBlock;
                        case FlowControl.Branch:
                            Flow(_graph.IndexOf((Instruction)ins.Operand), locals, ins.OpCode.Code is Code.Leave or Code.Leave_S ? new List<object?>() : stack);
                            goto nextBlock;
                        case FlowControl.Return: case FlowControl.Throw:
                            goto nextBlock;
                    }
                    if (ins.OpCode.Code == Code.Jmp) goto nextBlock;
                }
                nextBlock: ;
            }

            // Handlers run when their try has reachable code; they start with the locals the method writes unknown.
            var entered = pending.Where(h => TryReached(h, reached)).ToList();
            if (entered.Count == 0) break;
            foreach (int h in entered)
            {
                pending.Remove(h);
                var eh = _graph.Handlers[h];
                object?[] exception = eh.HandlerType is ExceptionHandlerType.Catch or ExceptionHandlerType.Filter ? [Unknown] : [];
                Flow(_graph.IndexOf(eh.HandlerStart), handlerLocals, exception.ToList());
                if (eh.FilterStart != null) Flow(_graph.IndexOf(eh.FilterStart), handlerLocals, [Unknown]);
            }
        }

        return decisions.Where(d => d.Value != null).Select(d => (d.Key, d.Value!)).ToList();
    }

    private bool TryReached(int h, bool[] reached)
    {
        var eh = _graph.Handlers[h];
        int from = _graph.IndexOf(eh.TryStart), to = _graph.IndexOrEnd(eh.TryEnd);
        for (int i = Math.Max(from, 0); i < to; i++)
            if (reached[i]) return true;
        return false;
    }

    private bool IsWritten(int local)
    {
        foreach (var ins in _code)
            if (ins.IsStloc() && ins.GetLocal(_body.Variables)?.Index == local) return true;
        return false;
    }

    /// <summary>Joins <paramref name="incoming"/> into <paramref name="into"/>; true when <paramref name="into"/> changed.</summary>
    private static bool Join(object?[] into, IReadOnlyList<object?> incoming)
    {
        bool changed = false;
        for (int i = 0; i < into.Length; i++)
        {
            if (into[i] == Unknown || Same(into[i], incoming[i])) continue;
            into[i] = Unknown;
            changed = true;
        }
        return changed;
    }

    /// <summary>The same constant (floats by their bits: 0.0 and -0.0 differ, NaN equals itself).</summary>
    private static bool Same(object? a, object? b) => (a, b) switch
    {
        (null, null) => true,
        (double x, double y) => BitConverter.DoubleToInt64Bits(x) == BitConverter.DoubleToInt64Bits(y),
        (float x, float y) => BitConverter.SingleToInt32Bits(x) == BitConverter.SingleToInt32Bits(y),
        _ => a != Unknown && b != Unknown && a != null && a.GetType() == b?.GetType() && a.Equals(b),
    };

    private static bool IsConstant(object? v) => v != Unknown;

    /// <summary>
    /// Applies one instruction to the state. For a conditional branch or switch, returns the instruction execution
    /// continues at when its operands are known (null otherwise).
    /// </summary>
    private Instruction? Step(Instruction ins, object?[] locals, List<object?> stack)
    {
        object? Pop()
        {
            var v = stack[^1];
            stack.RemoveAt(stack.Count - 1);
            return v;
        }
        void Push(object? v) => stack.Add(v);
        object? Try(Func<object?> compute)
        {
            try { return compute(); }
            catch (EvaluationBailout) { return Unknown; }
        }

        var op = ins.OpCode.Code;
        switch (op)
        {
            case Code.Nop: case Code.Tailcall: case Code.Volatile: case Code.Unaligned: case Code.Readonly: case Code.Constrained:
                return null;
            case Code.Ldc_I4: case Code.Ldc_I4_S: case Code.Ldc_I4_M1: case Code.Ldc_I4_0: case Code.Ldc_I4_1: case Code.Ldc_I4_2:
            case Code.Ldc_I4_3: case Code.Ldc_I4_4: case Code.Ldc_I4_5: case Code.Ldc_I4_6: case Code.Ldc_I4_7: case Code.Ldc_I4_8:
                Push(ins.GetLdcI4Value());
                return null;
            case Code.Ldc_I8: Push((long)ins.Operand); return null;
            case Code.Ldc_R4: Push((float)ins.Operand); return null;
            case Code.Ldc_R8: Push((double)ins.Operand); return null;
            case Code.Ldnull: Push(null); return null;
            case Code.Ldstr: Push((string)ins.Operand); return null;
            case Code.Dup:
            {
                var v = Pop();
                Push(v);
                Push(v);
                return null;
            }
            case Code.Pop: Pop(); return null;
            case Code.Ldloc: case Code.Ldloc_S: case Code.Ldloc_0: case Code.Ldloc_1: case Code.Ldloc_2: case Code.Ldloc_3:
            {
                int i = ins.GetLocal(_body.Variables)?.Index ?? -1;
                Push(i >= 0 && i < locals.Length ? locals[i] : Unknown);
                return null;
            }
            case Code.Stloc: case Code.Stloc_S: case Code.Stloc_0: case Code.Stloc_1: case Code.Stloc_2: case Code.Stloc_3:
            {
                var v = Pop();
                int i = ins.GetLocal(_body.Variables)?.Index ?? -1;
                if (i >= 0 && i < locals.Length) locals[i] = _untracked[i] ? Unknown : Stored(_localTypes[i], v);
                return null;
            }
            case Code.Add: case Code.Sub: case Code.Mul: case Code.Div: case Code.Div_Un: case Code.Rem: case Code.Rem_Un:
            case Code.And: case Code.Or: case Code.Xor: case Code.Shl: case Code.Shr: case Code.Shr_Un:
            case Code.Add_Ovf: case Code.Add_Ovf_Un: case Code.Sub_Ovf: case Code.Sub_Ovf_Un: case Code.Mul_Ovf: case Code.Mul_Ovf_Un:
            {
                var b = Pop();
                var a = Pop();
                Push(IsConstant(a) && IsConstant(b) && Numeric.IsNumber(a) && Numeric.IsNumber(b) ? Try(() => Numeric.Binary(op, a, b)) : Unknown);
                return null;
            }
            case Code.Neg: case Code.Not: case Code.Ckfinite:
            {
                var a = Pop();
                Push(Numeric.IsNumber(a)
                    ? Try(() => op == Code.Neg ? Numeric.Negate(a) : op == Code.Not ? Numeric.Not(a) : Numeric.CheckFinite(a))
                    : Unknown);
                return null;
            }
            case Code.Ceq: case Code.Cgt: case Code.Cgt_Un: case Code.Clt: case Code.Clt_Un:
            {
                var b = Pop();
                var a = Pop();
                Push(Comparable(a, b) ? Try(() => Numeric.Compare(op, a, b) ? 1 : 0) : Unknown);
                return null;
            }
            case Code.Conv_I1: case Code.Conv_I2: case Code.Conv_I4: case Code.Conv_I8: case Code.Conv_U1: case Code.Conv_U2:
            case Code.Conv_U4: case Code.Conv_U8: case Code.Conv_I: case Code.Conv_U: case Code.Conv_R4: case Code.Conv_R8: case Code.Conv_R_Un:
            case Code.Conv_Ovf_I1: case Code.Conv_Ovf_I2: case Code.Conv_Ovf_I4: case Code.Conv_Ovf_I8: case Code.Conv_Ovf_U1:
            case Code.Conv_Ovf_U2: case Code.Conv_Ovf_U4: case Code.Conv_Ovf_U8: case Code.Conv_Ovf_I: case Code.Conv_Ovf_U:
            case Code.Conv_Ovf_I1_Un: case Code.Conv_Ovf_I2_Un: case Code.Conv_Ovf_I4_Un: case Code.Conv_Ovf_I8_Un: case Code.Conv_Ovf_U1_Un:
            case Code.Conv_Ovf_U2_Un: case Code.Conv_Ovf_U4_Un: case Code.Conv_Ovf_U8_Un: case Code.Conv_Ovf_I_Un: case Code.Conv_Ovf_U_Un:
            {
                var a = Pop();
                Push(Numeric.IsNumber(a) ? Try(() => Numeric.Convert(op, a)) : Unknown);
                return null;
            }
            case Code.Ldsfld:
            {
                var field = (IField)ins.Operand;
                var v = StaticValue(ins, field);
                Push(v);
                return null;
            }
            case Code.Call: case Code.Callvirt:
            {
                var method = ins.Operand as IMethod;
                ins.CalculateStackUsage(_hasReturnValue, out int pushes, out int pops);
                var args = new object?[Math.Max(pops, 0)];
                for (int k = args.Length - 1; k >= 0; k--) args[k] = Pop();
                for (int k = 0; k < pushes; k++) Push(k == 0 && method != null ? CallValue(ins, method, args) : Unknown);
                return null;
            }

            case Code.Brtrue: case Code.Brtrue_S: case Code.Brfalse: case Code.Brfalse_S:
            {
                var a = Pop();
                if (!IsConstant(a) || a is float or double) return null;
                bool taken = Numeric.IsTrue(a) == op is Code.Brtrue or Code.Brtrue_S;
                return taken ? (Instruction)ins.Operand : Next(ins);
            }
            case Code.Beq: case Code.Beq_S: case Code.Bne_Un: case Code.Bne_Un_S: case Code.Bge: case Code.Bge_S: case Code.Bge_Un: case Code.Bge_Un_S:
            case Code.Bgt: case Code.Bgt_S: case Code.Bgt_Un: case Code.Bgt_Un_S: case Code.Ble: case Code.Ble_S: case Code.Ble_Un: case Code.Ble_Un_S:
            case Code.Blt: case Code.Blt_S: case Code.Blt_Un: case Code.Blt_Un_S:
            {
                var b = Pop();
                var a = Pop();
                if (!Comparable(a, b)) return null;
                bool? taken = Try(() => Numeric.Branch(op, a, b)) as bool?;
                if (taken == null) return null;
                return taken.Value ? (Instruction)ins.Operand : Next(ins);
            }
            case Code.Switch:
            {
                var a = Pop();
                if (a is not int index) return null;
                var targets = (IList<Instruction>)ins.Operand;
                return (uint)index < (uint)targets.Count ? targets[index] : Next(ins);
            }
        }

        // Anything else: its results are unknown.
        {
            ins.CalculateStackUsage(_hasReturnValue, out int pushes, out int pops);
            if (pops < 0) stack.Clear();
            else for (int k = 0; k < pops && stack.Count > 0; k++) Pop();
            for (int k = 0; k < pushes; k++) Push(Unknown);
            return null;
        }
    }

    private Instruction? Next(Instruction ins)
    {
        int i = _graph.IndexOf(ins);
        return i + 1 < _code.Count ? _code[i + 1] : null;
    }

    /// <summary>
    /// Whether two known operands compare the same way on every run: numbers, or references of which at least one is
    /// null (two strings may or may not be the same object, depending on interning).
    /// </summary>
    private static bool Comparable(object? a, object? b) =>
        IsConstant(a) && IsConstant(b) && (Numeric.IsNumber(a) && Numeric.IsNumber(b) || (a is null or string && b is null or string && (a == null || b == null)));

    /// <summary>The value as it reads back from a local of the given type (small integers truncate); unknown when it does not fit.</summary>
    private static object? Stored(TypeSig? type, object? v)
    {
        if (!IsConstant(v)) return Unknown;
        try
        {
            return type?.ElementType switch
            {
                ElementType.I1 when v is int or long or nint => (int)unchecked((sbyte)Numeric.Bits(v)),
                ElementType.U1 or ElementType.Boolean when v is int or long or nint => (int)unchecked((byte)Numeric.Bits(v)),
                ElementType.I2 when v is int or long or nint => (int)unchecked((short)Numeric.Bits(v)),
                ElementType.U2 or ElementType.Char when v is int or long or nint => (int)unchecked((ushort)Numeric.Bits(v)),
                ElementType.I4 or ElementType.U4 when v is int or nint => unchecked((int)Numeric.Bits(v)),
                ElementType.I8 or ElementType.U8 when v is long => v,
                ElementType.I or ElementType.U when v is int or nint => Numeric.Native(Numeric.Bits(v)),
                ElementType.R4 when v is float or double => v is double d ? (float)d : v,
                ElementType.R8 when v is float or double => v is float f ? (double)f : v,
                ElementType.String when v is null or string => v,
                ElementType.Object or ElementType.Class or ElementType.SZArray or ElementType.Array when v is null => null,
                _ => Unknown,
            };
        }
        catch (EvaluationBailout)
        {
            return Unknown;
        }
    }

    /// <summary>A readonly static field of the module, as its static constructor leaves it (evaluated once per field).</summary>
    private object? StaticValue(Instruction ins, IField field)
    {
        if (field is not FieldDef { IsStatic: true, IsInitOnly: true } fd || !Modelled(fd.FieldType)) return Unknown;
        if (!_fields.TryGetValue(field, out var value))
        {
            value = Evaluate([new Instruction(OpCodes.Ldsfld, field)]);
            _fields[field] = value;
        }
        if (IsConstant(value)) Evaluated.Add(ins);
        return value;
    }

    /// <summary>The result of a call whose arguments are all known, evaluated by the interpreter (cached per call site and arguments).</summary>
    private object? CallValue(Instruction ins, IMethod method, object?[] args)
    {
        if (!args.All(IsConstant) || !Modelled(method.MethodSig?.RetType)) return Unknown;
        var key = (ins, string.Join("\u0001", args.Select(Key)));
        if (!_calls.TryGetValue(key, out var value))
        {
            var slice = new List<Instruction>();
            foreach (var a in args)
            {
                if (Materialize(a) is not { } load)
                {
                    slice = null;
                    break;
                }
                slice.AddRange(load);
            }
            value = slice == null ? Unknown : Evaluate([.. slice, new Instruction(ins.OpCode, ins.Operand)]);
            _calls[key] = value;
        }
        if (IsConstant(value)) Evaluated.Add(ins);
        return value;
    }

    private static string Key(object? v) => v switch
    {
        null => "null",
        double d => "d" + BitConverter.DoubleToInt64Bits(d),
        float f => "f" + BitConverter.SingleToInt32Bits(f),
        _ => v.GetType().Name + ":" + v,
    };

    private object? Evaluate(List<Instruction> slice)
    {
        try
        {
            return _evaluator.EvaluateSlice(slice) is [var v] && (v is null or string || Numeric.IsNumber(v)) ? v : Unknown;
        }
        catch (EvaluationBailout)
        {
            return Unknown;
        }
    }

    private static bool Modelled(TypeSig? type) => type?.RemovePinnedAndModifiers().ElementType is
        ElementType.Boolean or ElementType.Char or ElementType.I1 or ElementType.U1 or ElementType.I2 or ElementType.U2 or ElementType.I4
        or ElementType.U4 or ElementType.I8 or ElementType.U8 or ElementType.I or ElementType.U or ElementType.R4 or ElementType.R8 or ElementType.String;

    /// <summary>Instructions pushing a constant, or null for values that have none.</summary>
    private static Instruction[]? Materialize(object? v) => v switch
    {
        null => [OpCodes.Ldnull.ToInstruction()],
        int i => [OpCodes.Ldc_I4.ToInstruction(i)],
        long l => [OpCodes.Ldc_I8.ToInstruction(l)],
        nint n => [OpCodes.Ldc_I4.ToInstruction((int)n), OpCodes.Conv_I.ToInstruction()],
        float f => [OpCodes.Ldc_R4.ToInstruction(f)],
        double d => [OpCodes.Ldc_R8.ToInstruction(d)],
        string s => [OpCodes.Ldstr.ToInstruction(s)],
        _ => null,
    };
}
