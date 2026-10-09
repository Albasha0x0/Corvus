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
/// taken (other than to read them right away, <c>ldloca; ldind</c>), that a filter writes, or that a finally or fault
/// handler writes and other code uses, are always unknown; a handler starts with the join of the states over its try.
/// Arguments are unknown. Enum locals hold their underlying integers.
/// </para>
/// <para>
/// <see cref="Dispatch"/> analyzes a flattened switch dispatcher per state: every way into it is run through it, and the
/// case it selects is analyzed in a context of its own (the values the dispatcher leaves in its locals), so that what a
/// case computes from the state is known per case.
/// </para>
/// </summary>
internal sealed class ConstantFlow
{
    /// <summary>A value that is not the same on every run (or not modelled).</summary>
    public static readonly object Unknown = new();

    /// <summary>Contexts (dispatcher states) explored at most.</summary>
    public const int MaxContexts = 1024;

    /// <summary>Instructions analyzed at most, over all contexts.</summary>
    public const int MaxSteps = 4_000_000;

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

    /// <summary>
    /// After <see cref="Decisions"/>: the reads of locals through their address (the ldind of <c>ldloca; ldind</c>, which
    /// code transformers use to hide constants) that read the same value on every run.
    /// </summary>
    public Dictionary<Instruction, object?> AddressReads { get; } = new();

    /// <summary>The address of a local, pushed by an <c>ldloca</c> that an <c>ldind</c> reads right away.</summary>
    private sealed record LocalAddress(int Index);

    /// <summary>
    /// A non-null object read from static state the evaluator models (a singleton, say): the loads that reach it,
    /// <c>ldsfld S</c> then <c>ldfld F</c>.... Reading a number or string field through it evaluates the whole path.
    /// </summary>
    private sealed class FieldPath(IReadOnlyList<Instruction> loads)
    {
        public IReadOnlyList<Instruction> Loads { get; } = loads;
        public string Key => string.Join("/", Loads.Select(l => ((IField)l.Operand).FullName));
        public override bool Equals(object? obj) => obj is FieldPath other && Loads.SequenceEqual(other.Loads);
        public override int GetHashCode() => Loads.Count == 0 ? 0 : Loads[^1].GetHashCode();
    }

    private readonly Dictionary<string, object?> _paths = new(StringComparer.Ordinal);

    public ConstantFlow(CilBody body, BodyGraph graph, bool hasReturnValue, IlEvaluator evaluator)
    {
        _body = body;
        _graph = graph;
        _code = graph.Instructions;
        _hasReturnValue = hasReturnValue;
        _evaluator = evaluator;
        var variables = body.Variables;
        _untracked = new bool[variables.Count];
        _localTypes = variables.Select(v => ValueType(v.Type)).ToArray();
        for (int i = 0; i < variables.Count; i++)
            _untracked[i] = Initial(_localTypes[i], true) == Unknown;
        // A local a finally or fault handler writes changes on the way out of its try, which a leave's flow does not show:
        // it is tracked only when nothing outside that handler uses it.
        var finallyOf = new int?[variables.Count];
        var usedOutside = new bool[variables.Count];
        for (int i = 0; i < _code.Count; i++)
        {
            var ins = _code[i];
            if (ins.OpCode.Code is Code.Ldloca or Code.Ldloca_S && ins.GetLocal(variables) is { } taken && !ReadAtOnce(i, taken.Index))
                _untracked[taken.Index] = true;
            // A filter's stores are not seen by its handler, which starts from the try's states.
            if (ins.IsStloc() && ins.GetLocal(variables) is { } filtered && _graph.Regions(i).Any(id => id % 3 == 2)) _untracked[filtered.Index] = true;
            if (ins.IsStloc() && ins.GetLocal(variables) is { } stored && FinallyOrFault(i) is { } h)
            {
                if (finallyOf[stored.Index] is { } other && other != h) _untracked[stored.Index] = true;
                finallyOf[stored.Index] = h;
            }
        }
        for (int i = 0; i < _code.Count; i++)
        {
            var ins = _code[i];
            if (!(ins.IsLdloc() || ins.IsStloc() || ins.OpCode.Code is Code.Ldloca or Code.Ldloca_S) || ins.GetLocal(variables) is not { } local) continue;
            if (finallyOf[local.Index] is { } h && !_graph.Regions(i).Contains(h * 3 + 1)) usedOutside[local.Index] = true;
        }
        for (int l = 0; l < variables.Count; l++)
            if (finallyOf[l] != null && usedOutside[l]) _untracked[l] = true;
    }

    /// <summary>The type whose values a local holds: enums hold their underlying integer.</summary>
    private static TypeSig? ValueType(TypeSig? type)
    {
        type = type?.RemovePinnedAndModifiers();
        if (type?.ElementType == ElementType.ValueType && type.ToTypeDefOrRef()?.ResolveTypeDef() is { IsEnum: true } e)
            return e.GetEnumUnderlyingType()?.RemovePinnedAndModifiers();
        return type;
    }

    /// <summary><c>ldloca</c> at <paramref name="i"/> is read right away by an <c>ldind</c> of the local's own type.</summary>
    internal bool ReadAtOnce(int i, int local)
    {
        if (i + 1 >= _code.Count || _graph.Targets.Contains(_code[i + 1])) return false;
        return (_code[i + 1].OpCode.Code, _localTypes[local]?.ElementType) switch
        {
            (Code.Ldind_I1, ElementType.I1) or (Code.Ldind_U1, ElementType.U1 or ElementType.Boolean) or (Code.Ldind_I2, ElementType.I2)
                or (Code.Ldind_U2, ElementType.U2 or ElementType.Char) or (Code.Ldind_I4 or Code.Ldind_U4, ElementType.I4 or ElementType.U4)
                or (Code.Ldind_I8, ElementType.I8 or ElementType.U8) => true,
            _ => false,
        };
    }

    /// <summary>Whether the analysis tracks the local's value.</summary>
    public bool Tracks(int local) => local >= 0 && local < _untracked.Length && !_untracked[local];

    /// <summary>The innermost finally or fault handler containing code[index], or null.</summary>
    private int? FinallyOrFault(int index)
    {
        int? found = null;
        foreach (int id in _graph.Regions(index))
            if (id % 3 == 1 && _graph.Handlers[id / 3].HandlerType is ExceptionHandlerType.Finally or ExceptionHandlerType.Fault)
                found = id / 3;
        return found;
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

    /// <summary>The analysis stopped: the dispatcher cannot be analyzed per state (the message says why).</summary>
    private sealed class Stop(string why) : Exception(why);

    /// <summary>
    /// A switch dispatcher to analyze per state: its code (<see cref="Members"/>: the straight-line code before the
    /// switch at <see cref="Switch"/>, and tails such as <c>stloc state; br dispatcher</c> that only lead into it), and
    /// its locals (the state and the locals the dispatcher writes).
    /// </summary>
    public sealed record Dispatcher(int Switch, IReadOnlySet<int> Members, IReadOnlySet<int> Locals);

    /// <summary>What <see cref="Dispatch"/> found; <see cref="Failure"/> is set when the dispatcher cannot be removed.</summary>
    public sealed class DispatchResult
    {
        public string? Failure { get; set; }
        /// <summary>Each way into the dispatcher (from: -1 for the method entry; to: the instruction entered) and the case it selects on every run.</summary>
        public Dictionary<(int From, int To), Instruction> Edges { get; } = new();
        /// <summary>Reads of the dispatcher's locals outside it (the ldloc, or the ldind of ldloca; ldind), and the value they read on every run.</summary>
        public Dictionary<int, object?> Reads { get; } = new();
        public int States { get; set; }
    }

    /// <summary>
    /// Runs the analysis. Returns the reachable conditional branches and switches whose outcome is known, with the
    /// instruction they continue at (the branch target, or the next instruction when they fall through).
    /// </summary>
    public List<(Instruction Branch, Instruction Next)> Decisions(MethodMeter? meter)
    {
        var run = new Run(this, null, meter);
        run.Execute();
        foreach (var (i, value) in run.AddressReads)
            if (value != Unknown) AddressReads[_code[i]] = value;
        return run.Decided();
    }

    /// <summary>Analyzes the method with <paramref name="dispatcher"/> resolved per state.</summary>
    public DispatchResult Dispatch(Dispatcher dispatcher, MethodMeter? meter)
    {
        var run = new Run(this, dispatcher, meter);
        var result = new DispatchResult();
        try
        {
            run.Execute();
        }
        catch (Stop stop)
        {
            result.Failure = stop.Message;
            return result;
        }
        result.States = run.Contexts;
        foreach (var (edge, targets) in run.EdgeTargets)
        {
            if (targets.Count != 1)
            {
                result.Failure = $"the state on the way into the dispatcher at {Where(edge.From < 0 ? edge.To : edge.From)} depends on the path taken";
                return result;
            }
            result.Edges[edge] = targets.First();
        }
        foreach (var (index, value) in run.Reads)
        {
            if (value == Unknown)
            {
                result.Failure = $"the state is read at {Where(index)}, where its value depends on the path taken";
                return result;
            }
            result.Reads[index] = value;
        }
        return result;
    }

    private string Where(int index) => $"IL_{_code[index].Offset:X4}";

    /// <summary>One run of the analysis: block states per (leader, context), worked off to a fixed point.</summary>
    private sealed class Run(ConstantFlow flow, Dispatcher? dispatcher, MethodMeter? meter)
    {
        private readonly int _n = flow._code.Count;
        private readonly Dictionary<(int, int), State> _entry = new();
        private readonly HashSet<(int, int)> _queued = new();
        private readonly Stack<(int, int)> _work = new();
        private readonly Dictionary<string, int> _contexts = new() { [""] = 0 };
        private readonly Dictionary<(Instruction, int), Instruction?> _decisions = new();
        private bool[] _leader = [];
        private bool[] _reached = [];
        private long _steps;

        public Dictionary<(int From, int To), HashSet<Instruction>> EdgeTargets { get; } = new();
        public Dictionary<int, object?> Reads { get; } = new();
        public Dictionary<int, object?> AddressReads { get; } = new();
        public int Contexts => _contexts.Count - 1;

        public List<(Instruction Branch, Instruction Next)> Decided() => _decisions
            .GroupBy(d => d.Key.Item1)
            .Select(g => (Branch: g.Key, Next: g.Select(d => d.Value).Distinct().ToList()))
            .Where(g => g.Next is [{ } next])
            .Select(g => (g.Branch, g.Next[0]!)).ToList();

        public void Execute()
        {
            var code = flow._code;
            _leader = new bool[_n];
            _reached = new bool[_n];
            if (_n > 0) _leader[0] = true;
            for (int i = 0; i < _n; i++)
            {
                var ins = code[i];
                if (flow._graph.Targets.Contains(ins)) _leader[i] = true;
                if (ins.OpCode.FlowControl is FlowControl.Branch or FlowControl.Cond_Branch or FlowControl.Return or FlowControl.Throw
                        && i + 1 < _n) _leader[i + 1] = true;
            }

            _handlersOf = new List<int>?[_n];
            for (int h = 0; h < flow._graph.Handlers.Count; h++)
            {
                var eh = flow._graph.Handlers[h];
                for (int i = Math.Max(flow._graph.IndexOf(eh.TryStart), 0); i < flow._graph.IndexOrEnd(eh.TryEnd); i++)
                    (_handlersOf[i] ??= new List<int>()).Add(h);
            }

            var initial = flow._localTypes.Select((t, i) => flow._untracked[i] ? Unknown : Initial(t, flow._body.InitLocals)).ToArray();
            Flow(-1, 0, initial, [], 0);
            while (_work.Count > 0)
            {
                meter?.CheckTime();
                var key = _work.Pop();
                _queued.Remove(key);
                Block(key.Item1, key.Item2);
            }
        }

        private List<int>?[] _handlersOf = [];

        /// <summary>
        /// An exception at code[i] (or a leave from its try, for a finally) enters the handlers of the trys containing it
        /// with the locals as they are before code[i]: a handler starts with the join of those states over its try.
        /// </summary>
        private void Throwing(int i, object?[] locals, int context)
        {
            foreach (int h in _handlersOf[i] ?? [])
            {
                var eh = flow._graph.Handlers[h];
                object?[] exception = eh.HandlerType is ExceptionHandlerType.Catch or ExceptionHandlerType.Filter ? [Unknown] : [];
                Flow(-2, flow._graph.IndexOf(eh.HandlerStart), locals, exception.ToList(), context);
                if (eh.FilterStart != null) Flow(-2, flow._graph.IndexOf(eh.FilterStart), locals, [Unknown], context);
            }
        }

        private void Block(int start, int context)
        {
            var code = flow._code;
            var state = _entry[(start, context)];
            var locals = (object?[])state.Locals.Clone();
            var stack = state.Stack.ToList();
            bool changed = true; // the locals changed since the handlers last saw them
            for (int i = start; i < _n; i++)
            {
                if (i > start && _leader[i])
                {
                    Flow(i - 1, i, locals, stack, context);
                    return;
                }
                if (++_steps > MaxSteps) throw new Stop($"the method is too large to analyze per state ({MaxSteps:N0} instructions)");
                _reached[i] = true;
                var ins = code[i];
                if (changed && _handlersOf[i] != null) Throwing(i, locals, context);
                changed = ins.IsStloc();
                int read = dispatcher != null ? DispatcherRead(i, stack) : -1;
                bool viaAddress = ins.OpCode.Code is >= Code.Ldind_I1 and <= Code.Ldind_Ref && stack.Count > 0 && stack[^1] is LocalAddress;
                var decided = flow.Step(ins, locals, stack);
                if (read >= 0) Record(Reads, i, stack[^1]);
                if (viaAddress) Record(AddressReads, i, stack[^1]);
                switch (ins.OpCode.FlowControl)
                {
                    case FlowControl.Cond_Branch:
                        // The last visit sees the final (most general) state of its context: it decides.
                        _decisions[(ins, context)] = decided;
                        if (decided != null)
                        {
                            Flow(i, flow._graph.IndexOf(decided), locals, stack, context);
                        }
                        else
                        {
                            foreach (var t in BodyGraph.BranchTargets(ins)) Flow(i, flow._graph.IndexOf(t), locals, stack, context);
                            Flow(i, i + 1, locals, stack, context);
                        }
                        return;
                    case FlowControl.Branch:
                        Flow(i, flow._graph.IndexOf((Instruction)ins.Operand), locals,
                            ins.OpCode.Code is Code.Leave or Code.Leave_S ? new List<object?>() : stack, context);
                        return;
                    case FlowControl.Return: case FlowControl.Throw:
                        return;
                }
                if (ins.OpCode.Code == Code.Jmp) return;
            }
        }

        /// <summary>The dispatcher local code[i] reads (an ldloc, or the ldind of ldloca; ldind) outside the dispatcher, or -1.</summary>
        private int DispatcherRead(int i, List<object?> stack)
        {
            if (dispatcher!.Members.Contains(i)) return -1;
            var ins = flow._code[i];
            if (ins.IsLdloc() && ins.GetLocal(flow._body.Variables) is { } l && dispatcher.Locals.Contains(l.Index)) return l.Index;
            if (ins.OpCode.Code is >= Code.Ldind_I1 and <= Code.Ldind_Ref && stack.Count > 0 && stack[^1] is LocalAddress a && dispatcher.Locals.Contains(a.Index))
                return a.Index;
            return -1;
        }

        private static void Record(Dictionary<int, object?> reads, int i, object? value)
        {
            if (!reads.TryGetValue(i, out var old)) reads[i] = value;
            else if (old != Unknown && !Same(old, value)) reads[i] = Unknown;
        }

        private void Flow(int from, int to, object?[] locals, List<object?> stack, int context)
        {
            if (to < 0 || to >= _n) return;
            if (dispatcher != null && dispatcher.Members.Contains(to))
            {
                Dispatch(from, to, locals, stack);
                return;
            }
            var key = (to, context);
            if (!_entry.TryGetValue(key, out var old))
            {
                _entry[key] = new State((object?[])locals.Clone(), stack.ToArray());
            }
            else
            {
                if (old.Stack.Length != stack.Count) throw new InvalidOperationException("inconsistent stack depth");
                bool changed = Join(old.Locals, locals) | Join(old.Stack, stack);
                if (!changed) return;
            }
            if (_queued.Add(key)) _work.Push(key);
        }

        /// <summary>Runs the dispatcher from code[to] for one way into it, and goes on at the case it selects, in that case's context.</summary>
        private void Dispatch(int from, int to, object?[] incoming, List<object?> incomingStack)
        {
            string Where(int i) => flow.Where(i);
            if (from == -2) throw new Stop($"an exception handler starts in the dispatcher at {Where(to)}");
            var locals = (object?[])incoming.Clone();
            var stack = incomingStack.ToList();
            var code = flow._code;
            // Through the dispatcher to the case the state selects; a case that only transitions (a tail of the
            // dispatcher) is run through as well.
            int i = to, t;
            for (int guard = 0; ; guard++)
            {
                if (guard > 64 * code.Count) throw new Stop("the dispatcher's states loop without leaving it");
                _reached[i] = true;
                if (i == dispatcher!.Switch)
                {
                    var target = flow.Step(code[i], locals, stack);
                    if (target == null)
                        throw new Stop($"the state on the way into the dispatcher at {Where(from < 0 ? to : from)} is not known");
                    t = flow._graph.IndexOf(target);
                    if (!dispatcher.Members.Contains(t)) break;
                    i = t;
                    continue;
                }
                if (code[i].OpCode.Code is Code.Br or Code.Br_S)
                {
                    i = flow._graph.IndexOf((Instruction)code[i].Operand);
                    continue;
                }
                flow.Step(code[i], locals, stack);
                i++;
            }

            var edge = (from, to);
            if (!EdgeTargets.TryGetValue(edge, out var targets)) EdgeTargets[edge] = targets = new HashSet<Instruction>();
            targets.Add(code[t]);

            // The case's context: what the dispatcher leaves in its locals, and the case.
            var name = t + ":" + string.Join(",", dispatcher.Locals.Order().Select(l => Key(locals[l])));
            if (!_contexts.TryGetValue(name, out int context))
            {
                if (_contexts.Count > MaxContexts) throw new Stop($"the dispatcher sees more than {MaxContexts} states");
                _contexts[name] = context = _contexts.Count;
            }
            Flow(dispatcher.Switch, t, locals, stack, context);
        }
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
            case Code.Ldloca: case Code.Ldloca_S:
            {
                int i = ins.GetLocal(_body.Variables)?.Index ?? -1;
                Push(Tracks(i) ? new LocalAddress(i) : Unknown);
                return null;
            }
            case Code.Ldind_I1: case Code.Ldind_U1: case Code.Ldind_I2: case Code.Ldind_U2: case Code.Ldind_I4: case Code.Ldind_U4:
            case Code.Ldind_I8: case Code.Ldind_I: case Code.Ldind_R4: case Code.Ldind_R8: case Code.Ldind_Ref:
            {
                // Only an ldloca read at once pushes an address; it reads the local's own type.
                Push(Pop() is LocalAddress a ? locals[a.Index] : Unknown);
                return null;
            }
            case Code.Ldsfld:
            {
                var field = (IField)ins.Operand;
                var v = StaticValue(ins, field);
                Push(v);
                return null;
            }
            case Code.Ldfld:
            {
                var target = Pop();
                if (target is FieldPath path && ins.Operand is IField)
                    Push(PathValue(new FieldPath([.. path.Loads, ins])));
                else
                    // A field nothing writes holds its default on every object; the load stays (it throws on null).
                    Push(ins.Operand is FieldDef { FieldType: var type } field && Modelled(type) && _evaluator.NeverWritten(field) ? Initial(ValueType(type), true) : Unknown);
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
        IsConstant(a) && IsConstant(b) && (Numeric.IsNumber(a) && Numeric.IsNumber(b) || (a is null or string or FieldPath && b is null or string or FieldPath && (a == null || b == null)));

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
        if (field is not FieldDef { IsStatic: true } fd) return Unknown;
        if (!Modelled(fd.FieldType)) return fd.FieldType.IsValueType ? Unknown : PathValue(new FieldPath([ins]));
        if (!_fields.TryGetValue(field, out var value))
        {
            value = Evaluate([new Instruction(OpCodes.Ldsfld, field)]);
            _fields[field] = value;
        }
        if (IsConstant(value)) Evaluated.Add(ins);
        return value;
    }

    /// <summary>
    /// What a path of loads reads, as the evaluator computes it: a number or string, null, or (for an object the evaluator
    /// models) the path itself; unknown when the evaluator cannot read it.
    /// </summary>
    private object? PathValue(FieldPath path)
    {
        var key = path.Key;
        if (!_paths.TryGetValue(key, out var value))
        {
            try
            {
                value = _evaluator.EvaluateSlice(path.Loads.Select(l => new Instruction(l.OpCode, l.Operand)).ToList()) switch
                {
                    [var v] when v is null or string || Numeric.IsNumber(v) => v,
                    [InstanceObject or ArrayObject or ReflectionObject] => path,
                    _ => Unknown,
                };
            }
            catch (EvaluationBailout)
            {
                value = Unknown;
            }
            _paths[key] = value;
        }
        if (value is FieldPath) return path;
        if (IsConstant(value)) Evaluated.UnionWith(path.Loads);
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
        if (IsConstant(value))
        {
            Evaluated.Add(ins);
            foreach (var path in args.OfType<FieldPath>()) Evaluated.UnionWith(path.Loads);
        }
        return value;
    }

    private static string Key(object? v) => v switch
    {
        FieldPath path => "path:" + path.Key,
        _ => KeyOf(v),
    };

    private static string KeyOf(object? v) => v switch
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
        FieldPath path => path.Loads.Select(l => new Instruction(l.OpCode, l.Operand)).ToArray(),
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
