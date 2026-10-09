using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Text;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace NetDecompilerMcp.Services.Simplify;

/// <summary>Evaluation left the supported subset (see <see cref="SimplifyManifest"/>); the message says where.</summary>
internal sealed class EvaluationBailout(FallbackReason reason, string message) : Exception(message)
{
    public FallbackReason Reason { get; } = reason;

    /// <summary>"message [code]", as reports show it.</summary>
    public string Describe() => $"{Message} [{SimplifyManifest.CodeOf(Reason)}]";
}

/// <summary>
/// Limits of the evaluator: call depth (frames, the evaluated call itself included), instructions per evaluation (nested
/// calls and the static constructors they trigger included), instructions across all evaluations of one method,
/// simulated allocations per evaluation, and the time one method may take across all passes. A type initializer that
/// keeps committing new state may run past the budget up to the initializer ceiling and time limit, accounted apart
/// (the extended tier, see IlEvaluator.Progress.cs).
/// </summary>
public sealed record EvaluationLimits(
    int MaxDepth = 8,
    int InstructionBudget = 100_000,
    long MethodInstructionBudget = 5_000_000,
    long MemoryLimit = 16 * 1024 * 1024,
    int MethodTimeLimitMs = 5_000,
    long InitializerInstructionCeiling = 50_000_000,
    int InitializerTimeLimitMs = 30_000)
{
    public TimeSpan MethodTimeLimit => TimeSpan.FromMilliseconds(MethodTimeLimitMs);
    public TimeSpan InitializerTimeLimit => TimeSpan.FromMilliseconds(InitializerTimeLimitMs);
}

/// <summary>Resources of simplifying one method, shared by its passes and every evaluation they run.</summary>
internal sealed class MethodMeter(EvaluationLimits limits)
{
    private readonly long _start = Stopwatch.GetTimestamp();

    public long InstructionsLeft { get; set; } = limits.MethodInstructionBudget;

    public TimeSpan Elapsed => Stopwatch.GetElapsedTime(_start + _excluded);

    /// <summary>Time spent on module-wide analysis, which is not the method's own work.</summary>
    public IDisposable Exclude()
    {
        long start = Stopwatch.GetTimestamp();
        return new Resume(() => _excluded += Stopwatch.GetTimestamp() - start);
    }

    private long _excluded;

    /// <summary>Time already spent (timestamp ticks) that was not the method's own work.</summary>
    public void Exclude(long ticks) => _excluded += ticks;

    private sealed class Resume(Action done) : IDisposable
    {
        public void Dispose() => done();
    }

    /// <summary>Throws <see cref="MethodTimeout"/> once the method's time limit has passed.</summary>
    public void CheckTime()
    {
        if (Elapsed > limits.MethodTimeLimit)
            throw new MethodTimeout($"simplifying the method took longer than its time limit of {limits.MethodTimeLimit.TotalSeconds:0.###} s");
    }
}

/// <summary>The method's time limit passed: the method is left unchanged. Not an <see cref="EvaluationBailout"/>, so no pass absorbs it.</summary>
internal sealed class MethodTimeout(string message) : Exception(message);

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
    /// <summary>Per element, the extended tier's window that last counted a change to it (see IlEvaluator.Progress.cs), or null.</summary>
    public int[]? Stamps { get; set; }
}

internal sealed class BuilderObject : HeapObject
{
    public StringBuilder Text { get; } = new();
}

/// <summary>A struct of the module being simplified: a value, copied on every load and store.</summary>
internal sealed class StructValue(TypeDef type, object?[] fields)
{
    public TypeDef Type { get; } = type;
    public object?[] Fields { get; } = fields;

    public StructValue Clone() => new(Type, Fields.Select(f => f is StructValue s ? s.Clone() : f).ToArray());

    public bool HoldsObjects => Fields.Any(f => f is HeapObject || (f is StructValue s && s.HoldsObjects));
}

/// <summary>The result of ldtoken on a field (only consumed by RuntimeHelpers.InitializeArray).</summary>
internal sealed record FieldHandle(FieldDef Field);

/// <summary>A managed pointer to a local, an argument, an array element or a struct field. Reads return the stored value itself.</summary>
internal sealed class Pointer(Func<object?> get, Action<object?> set)
{
    public object? Get() => get();
    public void Set(object? value) => set(value);
}

/// <summary>
/// Memory from <c>localloc</c> (stackalloc) and an offset into it: an unmanaged pointer. Pointer arithmetic moves the offset;
/// ldind / stind read and write the bytes, little-endian.
/// </summary>
internal sealed class BufferPointer(byte[] memory, int offset)
{
    public byte[] Memory { get; } = memory;
    public int Offset { get; } = offset;

    public BufferPointer Move(long delta) => new(Memory, checked((int)(Offset + delta)));

    public Span<byte> Bytes(int size) => Offset >= 0 && Offset + size <= Memory.Length
        ? Memory.AsSpan(Offset, size)
        : throw new EvaluationBailout(FallbackReason.RuntimeError, "access outside stack-allocated memory");
}

/// <summary>The result of ldftn: a method, as passed to a delegate constructor.</summary>
internal sealed record FunctionPointer(IMethod Method);

/// <summary>Value of a slot whose type the evaluator does not model (structs of other modules, pointers); reading it bails out.</summary>
internal sealed class Opaque
{
    public static readonly Opaque Instance = new();
}

/// <summary>
/// Interprets the IL subset listed in <see cref="SimplifyManifest"/> to compute values at analysis time. Anything else
/// throws <see cref="EvaluationBailout"/> with a <see cref="FallbackReason"/>.
/// Stack values: int (int32), long (int64), nint (native int, int32 range), float / double (F), null, string, the heap
/// types above, structs, pointers and Encoding instances. Static state computed by static constructors is cached for
/// the evaluator's lifetime; failures caused by resource limits are not, so a later evaluation with budget left retries.
/// </summary>
internal sealed partial class IlEvaluator(ModuleDef module, EvaluationLimits limits)
{
    private const int MaxArrayLength = 1 << 20;
    private const int MaxStringLength = 1 << 20;
    private const int TimeCheckInterval = 4096;

    private readonly ModuleFacts _facts = new(module);
    private readonly Dictionary<FieldDef, object?> _statics = new();
    private readonly Dictionary<TypeDef, EvaluationBailout?> _initialized = new(); // null: initialized; otherwise why it failed
    private readonly List<TypeDef> _initializing = new();
    private readonly Dictionary<MethodDef, Dictionary<Instruction, int>> _indexes = new();
    private readonly Dictionary<TypeDef, StructLayout?> _layouts = new();
    private long _budget;
    private bool _methodBudgetBound; // the budget of this evaluation is what is left of the method's
    private int _depth;
    private int _cctorDepth;
    private long _allocated;
    private long _retained; // allocations of static constructors that completed: live static state
    private int _sinceTimeCheck;

    private static readonly object Void = new();

    public EvaluationLimits Limits => limits;

    /// <summary>The method being simplified: code reading static state must not run during that state's initialization.</summary>
    public MethodDef? CurrentMethod { get; set; }

    /// <summary>The resources of the method being simplified; evaluations draw on its instruction budget and time.</summary>
    public MethodMeter? Meter { get; set; }

    /// <summary>
    /// Runs a straight-line instruction sequence (no branches, arguments or locals) on an empty stack and returns the
    /// resulting stack, bottom first. <paramref name="at"/>: the instruction of the original body of
    /// <see cref="CurrentMethod"/> the slice starts at, when it maps to one; inside a static constructor, the slice may
    /// then read its own type's state as it stands there (<see cref="RunToSite"/>).
    /// </summary>
    public List<object?> EvaluateSlice(IList<Instruction> slice, Instruction? at = null)
    {
        long left = Meter?.InstructionsLeft ?? long.MaxValue;
        _methodBudgetBound = left < limits.InstructionBudget;
        long start = _budget = Math.Min(limits.InstructionBudget, left);
        _depth = 0;
        _allocated = _retained;
        _scratch.Clear();
        _site = at;
        try
        {
            try
            {
                return RunSlice(slice);
            }
            catch (OwnStateNeeded)
            {
                return RunToSite(at!, () => RunSlice(slice));
            }
        }
        catch (Exception ex) when (ex is InsufficientExecutionStackException)
        {
            throw Bail(FallbackReason.CallDepth, "nested calls exhaust the evaluator's stack");
        }
        catch (Exception ex) when (ex is not (EvaluationBailout or MethodTimeout or OperationCanceledException))
        {
            // Malformed operands or metadata in the evaluated code.
            throw Bail(FallbackReason.InvalidCode, $"evaluation failed ({ex.GetType().Name}: {ex.Message})");
        }
        finally
        {
            if (Meter != null) Meter.InstructionsLeft -= start - Math.Max(_budget, 0);
            _scratch.Clear();
            _site = null;
        }
    }

    private List<object?> RunSlice(IList<Instruction> slice)
    {
        var frame = new Frame(null, slice, [], [], [], []);
        _depth = 0;
        _scratch.Clear();
        Interpret(frame, sliceMode: true);
        if (_scratch.Count > 0)
        {
            // A static collection was used as a cache: the same call made again, on the state this one left, must
            // give the same result.
            var again = new Frame(null, slice, [], [], [], []);
            _depth = 0;
            Interpret(again, sliceMode: true);
            if (frame.Stack.Count != again.Stack.Count || frame.Stack.Zip(again.Stack).Any(p => !SameResult(p.First, p.Second)))
                throw Bail(FallbackReason.CacheDependent, "the result differs when the call is made again (it depends on what the cache holds)");
        }
        return frame.Stack;
    }

    // ---- a static constructor's own state at one of its instructions

    private Instruction? _site; // see EvaluateSlice
    private TypeDef? _ownType; // set while a slice runs on the state RunToSite computed
    private Instruction? _stopAt;
    private MethodDef? _stopIn;
    private HashSet<Instruction>? _passed; // instructions of _stopIn the run to the site executed
    /// <summary>
    /// Per static constructor: a run toward a site that failed (not for lack of budget), and the instructions it executed
    /// first. The run is deterministic: one toward any site it did not pass fails the same way.
    /// </summary>
    private readonly Dictionary<MethodDef, (HashSet<Instruction> Passed, EvaluationBailout Failure)> _failedRuns = new();

    /// <summary>A slice inside a static constructor reads the state of the constructor's own type.</summary>
    private sealed class OwnStateNeeded : Exception;

    private sealed class SiteReached : Exception;

    /// <summary>
    /// Runs <paramref name="evaluate"/> on the static state as it stands when the static constructor being simplified
    /// reaches <paramref name="site"/>. A static constructor runs once and the evaluator follows its one path, so that
    /// state is exact when the site is reached at most once: it is on no cycle of the constructor's flow graph (exception
    /// edges included) and in no handler. The constructor runs on what is known of the types that cannot depend on its
    /// state (<see cref="Independent"/>); the others start over, and may see its partial state, as at run time. That
    /// state is dropped afterwards. The slice may not write the type's statics or modify its objects: the rewrite drops
    /// the call, and with it any such effect.
    /// </summary>
    private List<object?> RunToSite(Instruction site, Func<List<object?>> evaluate)
    {
        var cctor = CurrentMethod!;
        var type = cctor.DeclaringType;
        using (Meter?.Exclude())
        {
            if (!ReachedAtMostOnce(cctor, site))
                throw Bail(FallbackReason.StaticInitializer, $"needs the static state of {type.FullName} inside its own static constructor, at IL_{site.Offset:X4}, which can run more than once there");
        }
        if (_failedRuns.TryGetValue(cctor, out var failed) && !failed.Passed.Contains(site)) throw failed.Failure;
        var statics = new Dictionary<FieldDef, object?>(_statics);
        var initialized = new Dictionary<TypeDef, EvaluationBailout?>(_initialized);
        long retained = _retained;
        // What is known of types whose initialization cannot have seen this type's state stands; the others start over.
        HashSet<TypeDef> independent;
        using (Meter?.Exclude())
        {
            var memo = new Dictionary<TypeDef, bool>();
            independent = initialized.Keys.Where(t => Independent(t, type, cctor, memo)).ToHashSet();
        }
        foreach (var t in initialized.Keys) if (!independent.Contains(t)) _initialized.Remove(t);
        foreach (var f in statics.Keys) if (!independent.Contains(f.DeclaringType)) _statics.Remove(f);
        _initializing.Add(type);
        try
        {
            bool outermost = _cctorDepth == 0, reached = false;
            if (outermost) BeginInitializerRun();
            _cctorDepth++;
            _stopAt = site;
            _stopIn = cctor;
            _passed = new HashSet<Instruction>();
            EvaluationBailout? failure = null;
            try
            {
                try
                {
                    Execute(cctor, []);
                    throw Bail(FallbackReason.StaticInitializer, $"the static constructor of {type.FullName} returns without reaching IL_{site.Offset:X4}");
                }
                catch (SiteReached)
                {
                }
                if (outermost) PassObservation();
                reached = true;
            }
            catch (EvaluationBailout bailout)
            {
                var ex = outermost ? InitializerFailure(bailout) : bailout;
                failure = Bail(ex.Reason is FallbackReason.CallDepth or FallbackReason.InstructionBudget or FallbackReason.MemoryLimit or FallbackReason.CacheDependent
                    ? ex.Reason
                    : FallbackReason.StaticInitializer, $"static constructor of {type.FullName} cannot be evaluated as far as the call: {ex.Message}");
                if (!SimplifyManifest.Info(failure.Reason).Transient) _failedRuns[cctor] = (_passed, failure);
                throw failure;
            }
            finally
            {
                var passed = _passed!;
                _stopAt = null;
                _stopIn = null;
                _passed = null;
                _cctorDepth--;
                if (outermost && EndInitializerRun(type, reached) && failure != null) _failedRuns[cctor] = (passed, failure);
            }
            _retained = _allocated;
            _ownType = type;
            return evaluate();
        }
        finally
        {
            _ownType = null;
            _initializing.Remove(type);
            _statics.Clear();
            foreach (var (k, v) in statics) _statics[k] = v;
            _initialized.Clear();
            foreach (var (k, v) in initialized) _initialized[k] = v;
            _retained = retained;
        }
    }

    /// <summary>
    /// Whether the initialization of <paramref name="other"/> cannot depend on the state of <paramref name="type"/>: it
    /// cannot run its static constructor, and every type whose statics it read or wrote as it ran (reflection included)
    /// is independent too.
    /// </summary>
    private bool Independent(TypeDef other, TypeDef type, MethodDef cctor, Dictionary<TypeDef, bool> memo)
    {
        if (other == type) return false;
        if (memo.TryGetValue(other, out bool known)) return known;
        memo[other] = false; // a cycle back here: not independent
        bool independent = !_facts.RunsDuringInitialization(other, cctor) &&
                           (!_touched.TryGetValue(other, out var touched) || touched.All(t => Independent(t, type, cctor, memo)));
        memo[other] = independent;
        return independent;
    }

    /// <summary>Per type: the other types whose statics its initialization read or wrote.</summary>
    private readonly Dictionary<TypeDef, HashSet<TypeDef>> _touched = new();

    private void Touch(TypeDef owner)
    {
        foreach (var outer in _initializing)
        {
            if (outer == owner) continue;
            if (!_touched.TryGetValue(outer, out var set)) _touched[outer] = set = new HashSet<TypeDef>();
            set.Add(owner);
        }
    }

    /// <summary>
    /// Whether <paramref name="site"/> is outside every handler and on no cycle of the method's flow graph, with an edge
    /// from every instruction of a protected region to its handler and from endfinally to every leave target.
    /// </summary>
    private static bool ReachedAtMostOnce(MethodDef method, Instruction site)
    {
        var code = method.Body.Instructions;
        var index = new Dictionary<Instruction, int>(code.Count);
        for (int i = 0; i < code.Count; i++) index[code[i]] = i;
        if (!index.TryGetValue(site, out int at)) return false;
        int End(Instruction? i) => i == null ? code.Count : index.TryGetValue(i, out int k) ? k : code.Count;
        foreach (var eh in method.Body.ExceptionHandlers)
        {
            if (at >= End(eh.HandlerStart) && at < End(eh.HandlerEnd)) return false;
            if (eh.FilterStart != null && at >= End(eh.FilterStart) && at < End(eh.HandlerStart)) return false;
        }
        var leaveTargets = code.Where(i => i.OpCode.Code is Code.Leave or Code.Leave_S && i.Operand is Instruction).Select(i => End((Instruction)i.Operand)).ToList();
        IEnumerable<int> Successors(int k)
        {
            var ins = code[k];
            switch (ins.OpCode.FlowControl)
            {
                case FlowControl.Branch:
                    if (ins.Operand is Instruction t) yield return End(t);
                    break;
                case FlowControl.Cond_Branch:
                    yield return k + 1;
                    if (ins.Operand is Instruction c) yield return End(c);
                    else if (ins.Operand is IList<Instruction> cases) foreach (var c2 in cases) yield return End(c2);
                    break;
                case FlowControl.Return or FlowControl.Throw:
                    if (ins.OpCode.Code is Code.Endfinally) foreach (var l in leaveTargets) yield return l;
                    break;
                default:
                    yield return k + 1;
                    break;
            }
            foreach (var eh in method.Body.ExceptionHandlers)
            {
                if (k < End(eh.TryStart) || k >= End(eh.TryEnd)) continue;
                yield return End(eh.FilterStart ?? eh.HandlerStart);
            }
        }
        var seen = new HashSet<int>();
        var work = new Stack<int>(Successors(at));
        while (work.Count > 0)
        {
            int k = work.Pop();
            if (k == at) return false;
            if (k >= code.Count || !seen.Add(k)) continue;
            foreach (var s in Successors(k)) work.Push(s);
        }
        return true;
    }

    private sealed class Frame(MethodDef? method, IList<Instruction> code, object?[] args, Slot[] argSlots, object?[] locals, Slot[] localSlots)
    {
        public MethodDef? Method { get; } = method;
        /// <summary>Whether ret returns a value (a dynamic method has no MethodDef to tell).</summary>
        public bool ReturnsValue { get; init; } = method != null && HasReturnValue(method);
        /// <summary>The slot ret stores its value through.</summary>
        public Slot? ReturnSlot { get; init; }
        public IList<ExceptionHandler> Handlers { get; init; } = method?.Body?.ExceptionHandlers ?? (IList<ExceptionHandler>)Array.Empty<ExceptionHandler>();
        public IList<Instruction> Code { get; } = code;
        public object?[] Args { get; } = args;
        public Slot[] ArgSlots { get; } = argSlots;
        public object?[] Locals { get; } = locals;
        public Slot[] LocalSlots { get; } = localSlots;
        public List<object?> Stack { get; } = new();
        /// <summary>The type arguments of a generic method instantiation the frame runs, or null.</summary>
        public IList<TypeSig>? GenericArgs { get; init; }
    }

    private static EvaluationBailout Bail(FallbackReason reason, string message) => new(reason, message);

    private object? Execute(MethodDef method, object?[] args, IList<TypeSig>? generic = null)
    {
        if (_depth + 1 > limits.MaxDepth)
            throw Bail(FallbackReason.CallDepth, $"call depth exceeds the limit of {limits.MaxDepth}");
        if (method.Module != module)
            throw Bail(FallbackReason.OtherModule, $"calls {Describe(method)} in another module");
        if (method.IsPinvokeImpl || method.IsInternalCall || method.IsRuntime || method.IsNative || method.IsAbstract || !method.HasBody)
            throw Bail(FallbackReason.NoBody, $"calls {Describe(method)}, which has no IL body (native or runtime code)");
        if (method.DeclaringType.HasGenericParameters || method.HasGenericParameters != (generic is { Count: > 0 }))
            throw Bail(FallbackReason.Generic, $"calls generic {Describe(method)}");
        if (generic != null && (generic.Count != method.GenericParameters.Count || generic.Any(Generics.IsOpen)))
            throw Bail(FallbackReason.Generic, $"calls {Describe(method)} with type arguments that are not closed types");
        var body = method.Body;
        if (body.ExceptionHandlers.Any(eh => eh.HandlerType is not (ExceptionHandlerType.Catch or ExceptionHandlerType.Finally or ExceptionHandlerType.Fault)))
            throw Bail(FallbackReason.ExceptionHandling, $"{Describe(method)} uses an exception filter");
        if (args.Length != method.Parameters.Count)
            throw Bail(FallbackReason.InvalidCode, $"calls {Describe(method)} with {args.Length} argument(s)");
        RuntimeHelpers.EnsureSufficientExecutionStack();

        var argSlots = method.Parameters.Select(p => SlotOf(Generics.Substitute(p.Type, generic))).ToArray();
        var actual = new object?[args.Length];
        for (int i = 0; i < args.Length; i++) actual[i] = argSlots[i].Kind == Kind.Opaque ? Opaque.Instance : Store(argSlots[i], args[i]);
        var localSlots = body.Variables.Select(v => SlotOf(Generics.Substitute(v.Type, generic))).ToArray();
        var locals = localSlots.Select(Default).ToArray();

        _depth++;
        try
        {
            var result = Interpret(new Frame(method, body.Instructions, actual, argSlots, locals, localSlots) { GenericArgs = generic }, sliceMode: false);
            return result == Void ? Void : Store(SlotOf(Generics.Substitute(method.MethodSig.RetType, generic)), result);
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

    private void Tick()
    {
        if (--_budget < 0 && !ExtendBudget())
            throw _tierStop != null ? TierExhausted() : BudgetExhausted();
        if (++_sinceTimeCheck >= TimeCheckInterval)
        {
            _sinceTimeCheck = 0;
            if (InTier) CheckTierTime();
            else Meter?.CheckTime();
        }
    }

    /// <summary>
    /// Runs a frame until ret (returns the value, or <see cref="Void"/>) or, in slice mode, the end of the code. In
    /// finally mode it runs a finally handler from <paramref name="start"/> to its endfinally. An exception is never
    /// caught: the code throwing stops evaluation, so catch and fault handlers never run.
    /// </summary>
    private object? Interpret(Frame f, bool sliceMode, int start = 0, bool finallyMode = false)
    {
        var code = f.Code;
        var stack = f.Stack;
        Dictionary<Instruction, int>? index = null;
        int Target(Instruction target) => (index ??= IndexOf(f)).TryGetValue(target, out int i) ? i : throw Bail(FallbackReason.InvalidCode, "branch target outside the method");
        object? Pop() => stack.Count > 0 ? Pop1(stack) : throw Bail(FallbackReason.InvalidCode, "stack underflow");
        void Push(object? v) => stack.Add(v);

        int pc = start;
        while (true)
        {
            if (pc >= code.Count)
            {
                if (sliceMode) return Void;
                throw Bail(FallbackReason.InvalidCode, $"execution runs past the end of {Describe(f.Method!)}");
            }
            if (_stopAt != null && f.Method == _stopIn)
            {
                if (ReferenceEquals(code[pc], _stopAt)) throw new SiteReached();
                _passed!.Add(code[pc]);
            }
            Tick();
            var ins = code[pc++];
            var op = ins.OpCode.Code;
            switch (op)
            {
                case Code.Nop: case Code.Tailcall: case Code.Volatile: case Code.Unaligned: case Code.Readonly:
                case Code.Constrained: // the callvirt that follows gets a managed pointer to the value as its receiver
                    break;

                case Code.Ldarg: case Code.Ldarg_S: case Code.Ldarg_0: case Code.Ldarg_1: case Code.Ldarg_2: case Code.Ldarg_3:
                {
                    int i = ArgIndex(f, ins);
                    Push(Load(f.ArgSlots[i], f.Args[i]));
                    break;
                }
                case Code.Starg: case Code.Starg_S:
                {
                    int i = ArgIndex(f, ins);
                    f.Args[i] = Store(f.ArgSlots[i], Pop());
                    break;
                }
                case Code.Ldarga: case Code.Ldarga_S:
                {
                    int i = ArgIndex(f, ins);
                    Push(SlotPointer(f.Args, i, f.ArgSlots[i]));
                    break;
                }
                case Code.Ldloc: case Code.Ldloc_S: case Code.Ldloc_0: case Code.Ldloc_1: case Code.Ldloc_2: case Code.Ldloc_3:
                {
                    int i = LocalIndex(f, ins);
                    Push(Load(f.LocalSlots[i], f.Locals[i]));
                    break;
                }
                case Code.Stloc: case Code.Stloc_S: case Code.Stloc_0: case Code.Stloc_1: case Code.Stloc_2: case Code.Stloc_3:
                {
                    int i = LocalIndex(f, ins);
                    f.Locals[i] = Store(f.LocalSlots[i], Pop());
                    break;
                }
                case Code.Ldloca: case Code.Ldloca_S:
                {
                    int i = LocalIndex(f, ins);
                    Push(SlotPointer(f.Locals, i, f.LocalSlots[i]));
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
                    Push((float)ins.Operand);
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
                    Push(v is StructValue s ? s.Clone() : v);
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
                    Push(a is BufferPointer || b is BufferPointer ? PointerArithmetic(op, a, b) : Numeric.Binary(op, a, b));
                    break;
                }
                case Code.Neg:
                    Push(Numeric.Negate(Pop()));
                    break;
                case Code.Not:
                    Push(Numeric.Not(Pop()));
                    break;
                case Code.Ckfinite:
                    Push(Numeric.CheckFinite(Pop()));
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
                {
                    var v = Pop();
                    Push(v is BufferPointer bp
                        ? op is Code.Conv_I or Code.Conv_U ? bp : throw Bail(FallbackReason.UnsupportedValue, "conversion of a pointer to a fixed-size integer")
                        : Numeric.Convert(op, v));
                    break;
                }

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
                    var value = Pop() as int? ?? throw Bail(FallbackReason.InvalidCode, "switch on a non-int32 value");
                    if ((uint)value < (uint)targets.Count) pc = Target(targets[value]);
                    break;
                }
                case Code.Ret:
                    if (sliceMode || finallyMode) throw Bail(FallbackReason.InvalidCode, "ret in a slice or a finally handler");
                    return f.ReturnsValue ? Pop() : Void;
                case Code.Leave: case Code.Leave_S:
                {
                    int target = Target((Instruction)ins.Operand);
                    stack.Clear();
                    RunFinallies(f, pc - 1, target);
                    pc = target;
                    break;
                }
                case Code.Endfinally:
                    if (!finallyMode) throw Bail(FallbackReason.InvalidCode, "endfinally outside a finally handler");
                    return Void;
                case Code.Localloc:
                {
                    var size = Numeric.Index(Pop());
                    if (size < 0 || size > MaxArrayLength) throw Bail(FallbackReason.MemoryLimit, $"stackalloc of {size:N0} bytes");
                    Allocate(size);
                    Push(new BufferPointer(new byte[size], 0));
                    break;
                }
                case Code.Ldftn:
                    Push(new FunctionPointer((IMethod)ins.Operand));
                    break;

                case Code.Newarr:
                {
                    var length = Numeric.Index(Pop());
                    if (length < 0) throw Bail(FallbackReason.RuntimeError, "negative array length");
                    if (length > MaxArrayLength) throw Bail(FallbackReason.MemoryLimit, $"array of {length:N0} elements is too large");
                    var type = ElementClrType(TypeOperand(f, ins));
                    Push(NewArray(Array.CreateInstance(type, (int)length)));
                    break;
                }
                case Code.Ldlen:
                    Push((nint)ArrayOf(Pop()).Data.Length);
                    break;
                case Code.Ldelem_I1: case Code.Ldelem_U1: case Code.Ldelem_I2: case Code.Ldelem_U2: case Code.Ldelem_I4: case Code.Ldelem_U4:
                case Code.Ldelem_I8: case Code.Ldelem_I: case Code.Ldelem_R4: case Code.Ldelem_R8: case Code.Ldelem_Ref: case Code.Ldelem:
                {
                    var i = Numeric.Index(Pop());
                    var array = ArrayOf(Pop());
                    CheckIndex(array, i);
                    var slot = op == Code.Ldelem ? SlotOf(TypeOperand(f, ins)) : ElementSlot(op);
                    Push(Store(slot, NaturalElement(array.Data, (int)i)));
                    break;
                }
                case Code.Ldelema:
                {
                    var at = Numeric.Index(Pop());
                    var array = ArrayOf(Pop());
                    CheckIndex(array, at);
                    int i = (int)at;
                    Push(new Pointer(() => NaturalElement(array.Data, i), v =>
                    {
                        RequireMutable(array);
                        var old = Tracking ? NaturalElement(array.Data, i) : null;
                        SetElement(array.Data, i, v);
                        Committed(array, i, old);
                    }));
                    break;
                }
                case Code.Stelem_I1: case Code.Stelem_I2: case Code.Stelem_I4: case Code.Stelem_I8: case Code.Stelem_I:
                case Code.Stelem_R4: case Code.Stelem_R8: case Code.Stelem_Ref: case Code.Stelem:
                {
                    var value = Pop();
                    var i = Numeric.Index(Pop());
                    var array = ArrayOf(Pop());
                    RequireMutable(array);
                    CheckIndex(array, i);
                    var old = Tracking ? NaturalElement(array.Data, (int)i) : null;
                    SetElement(array.Data, (int)i, value);
                    Committed(array, (int)i, old);
                    break;
                }

                case Code.Ldind_I1: case Code.Ldind_U1: case Code.Ldind_I2: case Code.Ldind_U2: case Code.Ldind_I4: case Code.Ldind_U4:
                case Code.Ldind_I8: case Code.Ldind_I: case Code.Ldind_R4: case Code.Ldind_R8: case Code.Ldind_Ref:
                {
                    var address = Pop();
                    Push(address is BufferPointer bp ? ReadBuffer(bp, op) : Store(IndirectSlot(op), Known(PointerOf(address).Get())));
                    break;
                }
                case Code.Stind_I1: case Code.Stind_I2: case Code.Stind_I4: case Code.Stind_I8: case Code.Stind_I:
                case Code.Stind_R4: case Code.Stind_R8: case Code.Stind_Ref:
                {
                    var value = Pop();
                    var address = Pop();
                    if (address is BufferPointer bp) WriteBuffer(bp, op, value);
                    else PointerOf(address).Set(Store(IndirectSlot(op), value));
                    break;
                }

                case Code.Ldobj:
                    Push(Store(SlotOf(TypeOperand(f, ins)), Known(PointerOf(Pop()).Get())));
                    break;
                case Code.Stobj:
                {
                    var value = Pop();
                    PointerOf(Pop()).Set(Store(SlotOf(TypeOperand(f, ins)), value));
                    break;
                }
                case Code.Initobj:
                    PointerOf(Pop()).Set(Default(SlotOf(TypeOperand(f, ins))));
                    break;
                case Code.Ldfld:
                {
                    var target = Pop();
                    if (target is InstanceObject obj)
                    {
                        var field = InstanceField(obj, ins.Operand);
                        Push(Load(SlotOf(field.FieldType), obj.Fields[field]));
                        break;
                    }
                    var (s, k, slot) = FieldOf(target, ins.Operand, viaPointerOnly: false);
                    Push(Load(slot, s.Fields[k]));
                    break;
                }
                case Code.Ldflda:
                {
                    var target = Pop();
                    if (target is InstanceObject obj)
                    {
                        var field = InstanceField(obj, ins.Operand);
                        var fieldSlot = SlotOf(field.FieldType);
                        Push(new Pointer(() => obj.Fields[field], v =>
                        {
                            RequireMutable(obj);
                            var old = obj.Fields.GetValueOrDefault(field);
                            obj.Fields[field] = Store(fieldSlot, v);
                            Committed(obj, field, old);
                        }));
                        break;
                    }
                    var (_, k, slot) = FieldOf(target, ins.Operand, viaPointerOnly: true);
                    var parent = (Pointer)target!;
                    Push(new Pointer(() => ((StructValue)parent.Get()!).Fields[k], v => ((StructValue)parent.Get()!).Fields[k] = Store(slot, v)));
                    break;
                }
                case Code.Stfld:
                {
                    var value = Pop();
                    var target = Pop();
                    if (target is InstanceObject obj)
                    {
                        var field = InstanceField(obj, ins.Operand);
                        RequireMutable(obj);
                        var old = obj.Fields.GetValueOrDefault(field);
                        obj.Fields[field] = Store(SlotOf(field.FieldType), value);
                        Committed(obj, field, old);
                        break;
                    }
                    var (s, k, slot) = FieldOf(target, ins.Operand, viaPointerOnly: true);
                    s.Fields[k] = Store(slot, value);
                    break;
                }

                case Code.Ldsfld:
                    Push(LoadStatic((IField)ins.Operand));
                    break;
                case Code.Ldsflda:
                {
                    var field = (IField)ins.Operand;
                    Push(new Pointer(() => LoadStatic(field), v => StoreStatic(field, v)));
                    break;
                }
                case Code.Stsfld:
                    StoreStatic((IField)ins.Operand, Pop());
                    break;
                case Code.Ldtoken:
                    Push(ins.Operand switch
                    {
                        FieldDef fd => new FieldHandle(fd),
                        MemberRef { IsFieldRef: true } => throw Bail(FallbackReason.OtherModule, "ldtoken of a field of another module"),
                        ITypeDefOrRef => TypeObjectOf(TypeOperand(f, ins)),
                        IMethod m => MethodObjectOf(m),
                        _ => throw Bail(FallbackReason.UnsupportedValue, "ldtoken of a member of another module"),
                    });
                    break;

                case Code.Isinst: case Code.Castclass:
                {
                    var v = Pop();
                    var type = TypeOperand(f, ins);
                    bool matches = v == null || IsInstance(v, type);
                    if (!matches && op == Code.Castclass) throw Bail(FallbackReason.RuntimeError, $"invalid cast to {type.FullName}");
                    Push(matches ? v : null);
                    break;
                }

                case Code.Call: case Code.Callvirt: case Code.Newobj:
                {
                    var method = Instantiated(f, (IMethod)ins.Operand);
                    var sig = method.MethodSig ?? throw Bail(FallbackReason.InvalidCode, "call without a signature");
                    int count = sig.Params.Count + (sig.HasThis && op != Code.Newobj ? 1 : 0);
                    if (sig.ExplicitThis || sig.CallingConvention == CallingConvention.VarArg) throw Bail(FallbackReason.UnsupportedCall, "vararg or explicit-this call");
                    if (stack.Count < count) throw Bail(FallbackReason.InvalidCode, "stack underflow");
                    var args = new object?[count];
                    for (int i = count - 1; i >= 0; i--) args[i] = Pop();
                    var result = Invoke(method, op, args);
                    if (result != Void) Push(result);
                    break;
                }

                case Code.Throw: case Code.Rethrow:
                    throw Bail(FallbackReason.ExceptionHandling, "the code throws an exception");
                case Code.Box:
                    Push(Box(TypeOperand(f, ins), Pop()));
                    break;
                case Code.Unbox_Any:
                {
                    var type = TypeOperand(f, ins);
                    var v = Pop();
                    if (!type.IsValueType)
                    {
                        // On a reference type, unbox.any is castclass.
                        if (v != null && !IsInstance(v, type)) throw Bail(FallbackReason.RuntimeError, $"invalid cast to {type.FullName}");
                        Push(v);
                        break;
                    }
                    Push(Load(SlotOf(type), Unbox(v, type)));
                    break;
                }
                case Code.Unbox:
                {
                    var type = TypeOperand(f, ins);
                    var value = Unbox(Pop(), type);
                    Push(new Pointer(() => value, _ => throw Bail(FallbackReason.UnsupportedValue, "writes into a boxed value")));
                    break;
                }
                case Code.Sizeof:
                    Push(SizeOf(TypeOperand(f, ins)));
                    break;

                default:
                    throw Bail(FallbackReason.UnsupportedInstruction, $"unsupported instruction {ins.OpCode.Name}");
            }
        }
    }

    /// <summary>Runs the finally handlers a leave from code[from] to code[to] exits, innermost first.</summary>
    private void RunFinallies(Frame f, int from, int to)
    {
        if (f.Handlers.Count == 0) return;
        var index = IndexOf(f);
        int Index(Instruction? i) => i == null ? f.Code.Count : index.TryGetValue(i, out int k) ? k : throw Bail(FallbackReason.InvalidCode, "handler boundary outside the method");
        foreach (var eh in f.Handlers)
        {
            int tryStart = Index(eh.TryStart), tryEnd = Index(eh.TryEnd);
            bool exits = from >= tryStart && from < tryEnd && !(to >= tryStart && to < tryEnd);
            if (!exits || eh.HandlerType != ExceptionHandlerType.Finally) continue;
            var handler = new Frame(f.Method, f.Code, f.Args, f.ArgSlots, f.Locals, f.LocalSlots) { Handlers = f.Handlers, ReturnsValue = f.ReturnsValue };
            Interpret(handler, sliceMode: false, start: Index(eh.HandlerStart), finallyMode: true);
        }
    }

    private static object PointerArithmetic(Code op, object? a, object? b) => (op, a, b) switch
    {
        (Code.Add, BufferPointer p, var n) when Numeric.IsNumber(n) && n is not (float or double) => p.Move(Numeric.Bits(n)),
        (Code.Add, var n, BufferPointer p) when Numeric.IsNumber(n) && n is not (float or double) => p.Move(Numeric.Bits(n)),
        (Code.Sub, BufferPointer p, var n) when Numeric.IsNumber(n) && n is not (float or double) => p.Move(-Numeric.Bits(n)),
        (Code.Sub, BufferPointer p, BufferPointer q) when p.Memory == q.Memory => (nint)(p.Offset - q.Offset),
        _ => throw Bail(FallbackReason.UnsupportedValue, $"{op.ToOpCode().Name} on a pointer"),
    };

    // Each arm is boxed as its own type (a switch expression would otherwise convert them all to double).
    private static object ReadBuffer(BufferPointer p, Code op) => op switch
    {
        Code.Ldind_I1 => (object)(int)(sbyte)p.Bytes(1)[0],
        Code.Ldind_U1 => (object)(int)p.Bytes(1)[0],
        Code.Ldind_I2 => (object)(int)System.Buffers.Binary.BinaryPrimitives.ReadInt16LittleEndian(p.Bytes(2)),
        Code.Ldind_U2 => (object)(int)System.Buffers.Binary.BinaryPrimitives.ReadUInt16LittleEndian(p.Bytes(2)),
        Code.Ldind_I4 or Code.Ldind_U4 => (object)System.Buffers.Binary.BinaryPrimitives.ReadInt32LittleEndian(p.Bytes(4)),
        Code.Ldind_I8 => (object)System.Buffers.Binary.BinaryPrimitives.ReadInt64LittleEndian(p.Bytes(8)),
        Code.Ldind_R4 => (object)System.Buffers.Binary.BinaryPrimitives.ReadSingleLittleEndian(p.Bytes(4)),
        Code.Ldind_R8 => (object)System.Buffers.Binary.BinaryPrimitives.ReadDoubleLittleEndian(p.Bytes(8)),
        _ => throw Bail(FallbackReason.UnsupportedValue, "native-size or reference read from stack-allocated memory"),
    };

    private static void WriteBuffer(BufferPointer p, Code op, object? value)
    {
        switch (op)
        {
            case Code.Stind_I1: p.Bytes(1)[0] = unchecked((byte)Numeric.Bits(value)); break;
            case Code.Stind_I2: System.Buffers.Binary.BinaryPrimitives.WriteInt16LittleEndian(p.Bytes(2), unchecked((short)Numeric.Bits(value))); break;
            case Code.Stind_I4: System.Buffers.Binary.BinaryPrimitives.WriteInt32LittleEndian(p.Bytes(4), unchecked((int)Numeric.Bits(value))); break;
            case Code.Stind_I8: System.Buffers.Binary.BinaryPrimitives.WriteInt64LittleEndian(p.Bytes(8), Numeric.Bits(value)); break;
            case Code.Stind_R4 when value is float f: System.Buffers.Binary.BinaryPrimitives.WriteSingleLittleEndian(p.Bytes(4), f); break;
            case Code.Stind_R8 when value is double d: System.Buffers.Binary.BinaryPrimitives.WriteDoubleLittleEndian(p.Bytes(8), d); break;
            default: throw Bail(FallbackReason.UnsupportedValue, "native-size, float or reference write to stack-allocated memory");
        }
    }

    private static object? Pop1(List<object?> stack)
    {
        var v = stack[^1];
        stack.RemoveAt(stack.Count - 1);
        return v;
    }

    private static int ArgIndex(Frame f, Instruction ins)
    {
        int i = ins.GetParameterIndex();
        return i >= 0 && i < f.Args.Length ? i : throw Bail(FallbackReason.InvalidCode, "argument access outside a method");
    }

    private static int LocalIndex(Frame f, Instruction ins)
    {
        if (f.Method == null) throw Bail(FallbackReason.InvalidCode, "local access outside a method");
        var local = ins.GetLocal(f.Method.Body.Variables);
        int i = local?.Index ?? -1;
        return i >= 0 && i < f.Locals.Length ? i : throw Bail(FallbackReason.InvalidCode, "local access outside a method");
    }

    private Pointer SlotPointer(object?[] slots, int i, Slot slot) => new(() => slots[i], v => slots[i] = Store(slot, v));

    private static bool HasReturnValue(IMethod m) => m.MethodSig.RetType.RemovePinnedAndModifiers().ElementType != ElementType.Void;

    internal static string Describe(IMethod m) => $"{m.DeclaringType?.FullName}::{m.Name}({Core.Format.ParameterTypes(m.MethodSig)})";

    // ---- type tests

    private bool IsInstance(object value, TypeSig type) => value is BoxedValue boxed ? boxed.Is(type)
        : value is ReflectionObject r ? r.Is(type.FullName)
        : value is InstanceObject o ? IsInstanceOf(o, type.FullName)
        : value is StreamObject { ModuleType: { } derived } && Chain(derived).Any(t => t.FullName == type.FullName) ? true
        : value is StreamObject { FromFile: true } ? type.FullName is "System.IO.Stream" or "System.IO.FileStream" or "System.IDisposable" or "System.Object"
        : value is StreamObject ? type.FullName is "System.IO.Stream" or "System.IO.MemoryStream" or "System.IO.UnmanagedMemoryStream" or "System.IDisposable" or "System.Object"
        : value is CipherObject ? IsAlgorithmType(type)
        : value is TransformObject ? type.FullName is "System.Security.Cryptography.ICryptoTransform" or "System.IDisposable" or "System.Object"
        : value is ArrayObject array && (type.FullName == "System.Array" || type is SZArraySig) ? IsArrayOf(array, type)
        : value is BinaryReaderObject ? type.FullName is "System.IO.BinaryReader" or "System.IDisposable" or "System.Object"
        : value is StreamReaderObject ? type.FullName is "System.IO.StreamReader" or "System.IO.TextReader" or "System.IDisposable" or "System.Object"
        : type.FullName switch
    {
        "System.Object" => value is not (StructValue or Pointer or Opaque) && !Numeric.IsNumber(value)
            ? true
            : throw Bail(FallbackReason.InvalidCode, "type test of a value that is not a reference"),
        "System.String" => value is string,
        "System.Text.StringBuilder" => value is BuilderObject,
        "System.Text.Encoding" => value is Encoding,
        _ => throw Bail(FallbackReason.UnsupportedValue, $"type test against {type.FullName}"),
    };

    // ---- static state

    private object? LoadStatic(IField field)
    {
        if (field.FullName == "System.String System.String::Empty") return "";
        if (field.FullName is "System.IntPtr System.IntPtr::Zero" or "System.UIntPtr System.UIntPtr::Zero") return (nint)0;
        if (field.DeclaringType?.FullName == "System.Reflection.Emit.OpCodes") return OpCodeOf(field.Name);
        var fd = field as FieldDef;
        if (fd == null || fd.Module != module)
            throw Bail(FallbackReason.OtherModule, $"reads static field {field.FullName} of another module");
        if (!fd.IsStatic) throw Bail(FallbackReason.InvalidCode, "ldsfld of an instance field");
        if (fd.IsLiteral) throw Bail(FallbackReason.InvalidCode, $"ldsfld of the constant {fd.Name}");
        var type = fd.DeclaringType;
        if (type.HasGenericParameters) throw Bail(FallbackReason.Generic, $"static state of generic type {type.FullName}");
        bool initializing = _initializing.Contains(type);
        if (_initializing.Count > 0) Touch(type);
        if (!initializing && !fd.IsInitOnly && !WrittenOnlyByInitialization(fd))
        {
            // Fields that only uncallable code writes hold their default; a lazily created ResourceManager is always an
            // equivalent manager.
            if (AlwaysDefault(fd)) return Default(SlotOf(fd.FieldType));
            if (LazyManager(fd) is { } manager) return manager;
            throw Bail(FallbackReason.MutableStatic, $"reads mutable static field {type.FullName}::{fd.Name}");
        }
        RequireSettledState(type);
        EnsureInitialized(type);
        var value = _statics.TryGetValue(fd, out var v) ? v : Default(SlotOf(fd.FieldType));
        if (!initializing && value is DictionaryObject or ListObject && !Frozen(fd))
            return Load(SlotOf(fd.FieldType), Scratch(fd, (HeapObject)value));
        if (!initializing && value is HeapObject or StructValue { HoldsObjects: true } or DynamicMethodObject or ILGeneratorObject && !Fieldless(value) && !Frozen(fd))
            throw Bail(FallbackReason.MutableStatic, $"the object in static field {type.FullName}::{fd.Name} may be modified by other code");
        return Load(SlotOf(fd.FieldType), value);
    }

    /// <summary>
    /// An instance with no fields (the singleton of a compiler-generated lambda class, <c>&lt;&gt;c.&lt;&gt;9</c>, or a
    /// <c>new object()</c> used as a lock): nothing in it can be modified, so any code may read it.
    /// </summary>
    private static bool Fieldless(object? value) => value is InstanceObject { Fields.Count: 0 };

    /// <summary>
    /// A static field of the module whose initialization left <paramref name="value"/> in it, and that only that
    /// initialization writes (readonly, or as <see cref="ModuleFacts"/> proves); null when there is none.
    /// </summary>
    public FieldDef? StaticHolding(object value)
    {
        foreach (var (field, held) in _statics)
            if (ReferenceEquals(held, value) && (field.IsInitOnly || WrittenOnlyByInitialization(field))) return field;
        return null;
    }

    private bool AlwaysDefault(FieldDef field)
    {
        using var analysis = Meter?.Exclude();
        return _facts.AlwaysDefault(field);
    }

    /// <summary>See <see cref="ModuleFacts.NeverWritten"/>.</summary>
    public bool NeverWritten(FieldDef field)
    {
        using var analysis = Meter?.Exclude();
        return _facts.NeverWritten(field);
    }

    /// <summary>
    /// Whether the static field's value cannot change while <paramref name="method"/> runs: only its type's
    /// initialization writes it (readonly, or as <see cref="ModuleFacts"/> proves), and that initialization cannot be
    /// running then.
    /// </summary>
    public bool StableStatic(FieldDef field, MethodDef method)
    {
        using var analysis = Meter?.Exclude();
        return field.Module == module && field.IsStatic && (field.IsInitOnly || _facts.WrittenOnlyByInitialization(field)) &&
               !_facts.RunsDuringInitialization(field.DeclaringType, method);
    }

    private bool WrittenOnlyByInitialization(FieldDef field)
    {
        using var analysis = Meter?.Exclude();
        return _facts.WrittenOnlyByInitialization(field);
    }

    private bool Frozen(FieldDef field)
    {
        using var analysis = Meter?.Exclude();
        return _facts.IsFrozen(field);
    }

    private void StoreStatic(IField field, object? value)
    {
        var fd = field as FieldDef;
        if (fd == null || fd.Module != module || !fd.IsStatic)
            throw Bail(FallbackReason.OtherModule, $"writes static field {field.FullName} of another module");
        if (!_initializing.Contains(fd.DeclaringType))
            throw Bail(FallbackReason.MutableStatic, $"writes static field {fd.DeclaringType.FullName}::{fd.Name} outside its static constructor");
        if (_initializing.Count > 0) Touch(fd.DeclaringType);
        if (fd.DeclaringType == _ownType)
            throw Bail(FallbackReason.MutableStatic, $"writes static field {fd.DeclaringType.FullName}::{fd.Name} of the type whose static constructor is running");
        var old = _statics.GetValueOrDefault(fd);
        _statics[fd] = Store(SlotOf(fd.FieldType), value);
        Committed(fd, old);
    }

    /// <summary>
    /// The state of <paramref name="type"/> is partial while its static constructor runs. Reading it is sound only when the
    /// code being evaluated cannot run then: neither the method being simplified nor a static constructor evaluated on its
    /// behalf may be reachable from that constructor (unless the evaluator is running that constructor itself).
    /// </summary>
    private void RequireSettledState(TypeDef type)
    {
        if (_initializing.Contains(type)) return;
        using var analysis = Meter?.Exclude();
        if (CurrentMethod != null && _facts.RunsDuringInitialization(type, CurrentMethod))
        {
            if (_site != null && _ownType == null && CurrentMethod.IsStaticConstructor && CurrentMethod.DeclaringType == type) throw new OwnStateNeeded();
            throw Bail(FallbackReason.StaticInitializer, CurrentMethod.IsStaticConstructor && CurrentMethod.DeclaringType == type
                ? $"needs the static state of {type.FullName} inside its own static constructor"
                : $"needs the static state of {type.FullName}, and {Describe(CurrentMethod)} can run during its static constructor");
        }
        foreach (var outer in _initializing)
            if (outer.FindStaticConstructor() is { } cctor && _facts.RunsDuringInitialization(type, cctor))
                throw Bail(FallbackReason.StaticInitializer, $"the static constructor of {outer.FullName} can run during that of {type.FullName}");
    }

    /// <summary>Calling a static method of a type without beforefieldinit (or any member of such a struct) runs its static constructor.</summary>
    private void TriggerTypeInitializer(MethodDef method)
    {
        // Reads of the type's state check RequireSettledState; the constructor's own run in the sandbox has no visible effect.
        if (!method.DeclaringType.IsBeforeFieldInit) EnsureInitialized(method.DeclaringType);
    }

    /// <summary>
    /// Runs a type's static constructor once, on the current evaluation's budget. If it cannot be evaluated, statics it
    /// wrote are rolled back and later accesses bail out with the same reason (unless a resource limit stopped it).
    /// </summary>
    private void EnsureInitialized(TypeDef type)
    {
        if (_initialized.TryGetValue(type, out var known))
        {
            if (known != null) throw known;
            return;
        }
        if (_initializing.Contains(type)) return; // recursive initialization sees the partially initialized type, as at run time
        var cctor = type.FindStaticConstructor();
        if (cctor == null)
        {
            _initialized[type] = null;
            return;
        }

        var snapshot = new Dictionary<FieldDef, object?>(_statics);
        var initializedBefore = new HashSet<TypeDef>(_initialized.Keys);
        long allocatedBefore = _allocated;
        _initializing.Add(type);
        bool outermost = _cctorDepth == 0;
        if (outermost) BeginInitializerRun();
        _cctorDepth++;
        bool completed = false;
        EvaluationBailout? failure = null;
        try
        {
            Execute(cctor, []);
            if (outermost) PassObservation();
            _initialized[type] = null;
            _retained += _allocated - allocatedBefore;
            completed = true;
        }
        catch (EvaluationBailout bailout)
        {
            var ex = outermost ? InitializerFailure(bailout) : bailout;
            failure = Bail(ex.Reason is FallbackReason.CallDepth or FallbackReason.InstructionBudget or FallbackReason.MemoryLimit or FallbackReason.CacheDependent
                    ? ex.Reason
                    : FallbackReason.StaticInitializer,
                $"static constructor of {type.FullName} cannot be evaluated: {ex.Message}");
            if (!SimplifyManifest.Info(ex.Reason).Transient) _initialized[type] = failure;
            throw failure;
        }
        finally
        {
            if (!completed)
            {
                // Types whose initialization ran within this one lose their state with it: they are initialized again
                // when next needed (only this type's own failure is remembered).
                _statics.Clear();
                foreach (var (k, v) in snapshot) _statics[k] = v;
                foreach (var t in _initialized.Keys.Where(t => t != type && !initializedBefore.Contains(t)).ToList()) _initialized.Remove(t);
            }
            _cctorDepth--;
            _initializing.Remove(type);
            // A run the extended tier stopped would stop the same way again.
            if (outermost && EndInitializerRun(type, completed) && failure != null) _initialized[type] = failure;
        }
    }

    private void RequireMutable(HeapObject obj)
    {
        if (obj.Shared && _cctorDepth == 0)
            throw Bail(FallbackReason.MutableStatic, "modifies an object held in a static field");
    }

    // ---- memory

    private void Allocate(long bytes)
    {
        _allocated += bytes;
        if (_allocated > limits.MemoryLimit)
            throw Bail(FallbackReason.MemoryLimit, $"simulated allocations exceed the memory limit of {limits.MemoryLimit / (1024 * 1024)} MB");
    }

    private ArrayObject NewArray(Array data)
    {
        if (data.Length > MaxArrayLength) throw Bail(FallbackReason.MemoryLimit, "array too large");
        Allocate(24 + (long)data.Length * (data is object?[] or nint[] ? 8 : Buffer.ByteLength(data) / Math.Max(data.Length, 1)));
        return new ArrayObject(data) { Shared = _cctorDepth > 0 };
    }

    private string NewString(string s)
    {
        if (s.Length > MaxStringLength) throw Bail(FallbackReason.MemoryLimit, "string result too long");
        Allocate(22 + 2L * s.Length);
        return s;
    }

    // ---- slots: how values are stored in typed locations

    private enum Kind { I1, U1, I2, U2, Bool, I4, I8, Native, R4, R8, Ref, Struct, Opaque, UnmanagedPointer }

    /// <summary>Framework structs that hold a reflection object: the evaluator keeps them as that object.</summary>
    private static readonly HashSet<string> ReflectionStructs = new(StringComparer.Ordinal)
    {
        "System.RuntimeTypeHandle", "System.RuntimeMethodHandle", "System.RuntimeFieldHandle", "System.ModuleHandle", "System.Reflection.Emit.OpCode",
    };

    private readonly record struct Slot(Kind Kind, StructLayout? Layout = null);

    /// <summary>The instance fields of a module struct, in declaration order.</summary>
    private sealed record StructLayout(TypeDef Type, List<FieldDef> Fields, Slot[] Slots);

    private Slot SlotOf(TypeSig? sig) => SlotOf(sig, 0);

    private Slot SlotOf(TypeSig? sig, int nesting)
    {
        sig = sig?.RemovePinnedAndModifiers();
        switch (sig?.ElementType)
        {
            case ElementType.I1: return new(Kind.I1);
            case ElementType.U1: return new(Kind.U1);
            case ElementType.Boolean: return new(Kind.Bool);
            case ElementType.I2: return new(Kind.I2);
            case ElementType.U2: case ElementType.Char: return new(Kind.U2);
            case ElementType.I4: case ElementType.U4: return new(Kind.I4);
            case ElementType.I8: case ElementType.U8: return new(Kind.I8);
            case ElementType.I: case ElementType.U: return new(Kind.Native);
            case ElementType.R4: return new(Kind.R4);
            case ElementType.R8: return new(Kind.R8);
            case ElementType.String: case ElementType.Object: case ElementType.Class: case ElementType.SZArray:
            case ElementType.Array: case ElementType.ByRef:
                return new(Kind.Ref);
            case ElementType.GenericInst:
                return !sig.IsValueType || IsCollectionStruct((GenericInstSig)sig) ? new(Kind.Ref) : new(Kind.Opaque);
            case ElementType.Ptr: case ElementType.FnPtr:
                return new(Kind.UnmanagedPointer);
            case ElementType.ValueType when ReflectionStructs.Contains(sig.FullName):
                return new(Kind.Ref);
            case ElementType.ValueType:
                var td = sig.ToTypeDefOrRef()?.ResolveTypeDef();
                if (td is { IsEnum: true }) return td.GetEnumUnderlyingType() is { } underlying ? SlotOf(underlying, nesting) : new(Kind.Opaque);
                return LayoutOf(td, nesting) is { } layout ? new(Kind.Struct, layout) : new(Kind.Opaque);
            default:
                return new(Kind.Opaque);
        }
    }

    /// <summary>The layout of a struct of this module the evaluator can model, or null.</summary>
    private StructLayout? LayoutOf(TypeDef? type, int nesting)
    {
        if (type == null || type.Module != module || !type.IsValueType || type.IsEnum || type.HasGenericParameters || type.IsExplicitLayout) return null;
        if (_layouts.TryGetValue(type, out var cached)) return cached;
        if (nesting > 8) return null;
        _layouts[type] = null; // a struct containing itself (malformed) stays unsupported
        var fields = type.Fields.Where(f => !f.IsStatic).ToList();
        var layout = new StructLayout(type, fields, fields.Select(f => SlotOf(f.FieldType, nesting + 1)).ToArray());
        _layouts[type] = layout;
        return layout;
    }

    private object? Default(Slot slot) => slot.Kind switch
    {
        Kind.I8 => 0L,
        Kind.Native => (nint)0,
        Kind.R4 => 0f,
        Kind.R8 => 0.0,
        Kind.Ref => null,
        Kind.Struct => NewStruct(slot.Layout!),
        Kind.Opaque => Opaque.Instance,
        Kind.UnmanagedPointer => (nint)0,
        _ => 0,
    };

    private StructValue NewStruct(StructLayout layout)
    {
        Allocate(16 + 8L * layout.Fields.Count);
        return new StructValue(layout.Type, layout.Slots.Select(Default).ToArray());
    }

    /// <summary>A slot's value as pushed by a load: structs are copied.</summary>
    private static object? Load(Slot slot, object? value) => Known(value) is StructValue s ? s.Clone() : value;

    private static object? Known(object? value) =>
        value is Opaque ? throw Bail(FallbackReason.UnsupportedValue, "reads a variable of a type the interpreter does not model") : value;

    /// <summary>The value as it reads back after being stored in a slot (small integers truncate, floats round, structs copy).</summary>
    private static object? Store(Slot slot, object? value) => slot.Kind switch
    {
        Kind.I1 => (int)unchecked((sbyte)Numeric.Bits(value)),
        Kind.U1 or Kind.Bool => (int)unchecked((byte)Numeric.Bits(value)),
        Kind.I2 => (int)unchecked((short)Numeric.Bits(value)),
        Kind.U2 => (int)unchecked((ushort)Numeric.Bits(value)),
        Kind.I4 => unchecked((int)Numeric.Bits(value)),
        Kind.I8 => Numeric.Bits(value),
        Kind.Native or Kind.UnmanagedPointer when value is BufferPointer => value,
        Kind.Native => Numeric.Native(Numeric.Bits(value)),
        Kind.UnmanagedPointer => Numeric.Native(Numeric.Bits(value)),
        Kind.R4 => value switch { float f => f, double d => (float)d, _ => throw Bail(FallbackReason.InvalidCode, "float slot holds a non-float") },
        Kind.R8 => value switch { double d => d, float f => (double)f, _ => throw Bail(FallbackReason.InvalidCode, "double slot holds a non-float") },
        Kind.Ref => Numeric.IsNumber(value) || value is StructValue
            ? throw Bail(FallbackReason.InvalidCode, "reference slot holds a value type")
            : value,
        Kind.Struct => value is StructValue s && s.Type == slot.Layout!.Type
            ? s.Clone()
            : throw Bail(FallbackReason.InvalidCode, $"{slot.Layout!.Type.FullName} slot holds another value"),
        _ => throw Bail(FallbackReason.UnsupportedValue, "stores a value of a type the interpreter does not model"),
    };

    private static Slot ElementSlot(Code op) => op switch
    {
        Code.Ldelem_I1 => new(Kind.I1),
        Code.Ldelem_U1 => new(Kind.U1),
        Code.Ldelem_I2 => new(Kind.I2),
        Code.Ldelem_U2 => new(Kind.U2),
        Code.Ldelem_I4 or Code.Ldelem_U4 => new(Kind.I4),
        Code.Ldelem_I8 => new(Kind.I8),
        Code.Ldelem_I => new(Kind.Native),
        Code.Ldelem_R4 => new(Kind.R4),
        Code.Ldelem_R8 => new(Kind.R8),
        _ => new(Kind.Ref),
    };

    private static Slot IndirectSlot(Code op) => op switch
    {
        Code.Ldind_I1 or Code.Stind_I1 => new(Kind.I1),
        Code.Ldind_U1 => new(Kind.U1),
        Code.Ldind_I2 or Code.Stind_I2 => new(Kind.I2),
        Code.Ldind_U2 => new(Kind.U2),
        Code.Ldind_I4 or Code.Ldind_U4 or Code.Stind_I4 => new(Kind.I4),
        Code.Ldind_I8 or Code.Stind_I8 => new(Kind.I8),
        Code.Ldind_I or Code.Stind_I => new(Kind.Native),
        Code.Ldind_R4 or Code.Stind_R4 => new(Kind.R4),
        Code.Ldind_R8 or Code.Stind_R8 => new(Kind.R8),
        _ => new(Kind.Ref),
    };

    // ---- struct fields

    /// <summary>The struct and field index an ldfld / ldflda / stfld addresses: a pointer to a module struct, or (ldfld) a struct value.</summary>
    private (StructValue Struct, int Index, Slot Slot) FieldOf(object? target, object operand, bool viaPointerOnly)
    {
        var field = operand as FieldDef ?? (operand as MemberRef)?.ResolveField();
        var s = target switch
        {
            Pointer p => p.Get() as StructValue,
            StructValue v when !viaPointerOnly => v,
            null => throw Bail(FallbackReason.RuntimeError, "null reference"),
            _ => null,
        };
        if (s == null) throw Bail(FallbackReason.InstanceObject, $"accesses field {field?.Name ?? "?"} of a class instance");
        if (field == null || field.IsStatic || field.DeclaringType != s.Type)
            throw Bail(FallbackReason.InvalidCode, "field access on a struct of another type");
        var layout = LayoutOf(s.Type, 0)!;
        int k = layout.Fields.IndexOf(field);
        return (s, k, layout.Slots[k]);
    }

    // ---- arrays

    private Type ElementClrType(TypeSig sig)
    {
        sig = sig.RemovePinnedAndModifiers();
        // An enum's elements are stored as its underlying integers.
        if (IsEnum(sig) && sig.ToTypeDefOrRef()?.ResolveTypeDef()?.GetEnumUnderlyingType() is { } underlying) sig = underlying.RemovePinnedAndModifiers();
        return sig.ElementType switch
        {
            ElementType.I1 => typeof(sbyte),
            ElementType.U1 => typeof(byte),
            ElementType.Boolean => typeof(byte), // a bool element holds the stored byte
            ElementType.I2 => typeof(short),
            ElementType.U2 => typeof(ushort),
            ElementType.Char => typeof(char),
            ElementType.I4 => typeof(int),
            ElementType.U4 => typeof(uint),
            ElementType.I8 => typeof(long),
            ElementType.U8 => typeof(ulong),
            ElementType.I or ElementType.U => typeof(nint),
            ElementType.R4 => typeof(float),
            ElementType.R8 => typeof(double),
            _ => SlotOf(sig).Kind == Kind.Ref ? typeof(object) : throw Bail(FallbackReason.UnsupportedValue, $"array of {sig.FullName}"),
        };
    }

    private static ArrayObject ArrayOf(object? value) => value switch
    {
        ArrayObject a => a,
        null => throw Bail(FallbackReason.RuntimeError, "null array access"),
        _ => throw Bail(FallbackReason.InvalidCode, "array access on a non-array"),
    };

    private static void CheckIndex(ArrayObject array, long i)
    {
        if ((ulong)i >= (ulong)array.Data.Length) throw Bail(FallbackReason.RuntimeError, "array index out of range");
    }

    private static Pointer PointerOf(object? value) => value switch
    {
        Pointer p => p,
        null => throw Bail(FallbackReason.RuntimeError, "null reference"),
        _ => throw Bail(FallbackReason.UnsupportedValue, "indirect access through something other than a managed pointer"),
    };

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
        nint[] a => a[i],
        float[] a => a[i],
        double[] a => a[i],
        object?[] a => a[i],
        _ => throw Bail(FallbackReason.UnsupportedValue, "unsupported array"),
    };

    private static void SetElement(Array data, int i, object? value)
    {
        switch (data)
        {
            case byte[] a: a[i] = unchecked((byte)Numeric.Bits(value)); break;
            case sbyte[] a: a[i] = unchecked((sbyte)Numeric.Bits(value)); break;
            case bool[] a: a[i] = (byte)Numeric.Bits(value) != 0; break;
            case short[] a: a[i] = unchecked((short)Numeric.Bits(value)); break;
            case ushort[] a: a[i] = unchecked((ushort)Numeric.Bits(value)); break;
            case char[] a: a[i] = unchecked((char)Numeric.Bits(value)); break;
            case int[] a: a[i] = unchecked((int)Numeric.Bits(value)); break;
            case uint[] a: a[i] = unchecked((uint)Numeric.Bits(value)); break;
            case long[] a: a[i] = Numeric.Bits(value); break;
            case ulong[] a: a[i] = unchecked((ulong)Numeric.Bits(value)); break;
            case nint[] a: a[i] = Numeric.Native(Numeric.Bits(value)); break;
            case float[] a: a[i] = value switch { float f => f, double d => (float)d, _ => throw Bail(FallbackReason.InvalidCode, "float element from a non-float") }; break;
            case double[] a: a[i] = value switch { double d => d, float f => f, _ => throw Bail(FallbackReason.InvalidCode, "double element from a non-float") }; break;
            case object?[] a:
                a[i] = Numeric.IsNumber(value) || value is StructValue ? throw Bail(FallbackReason.UnsupportedValue, "boxing is not modelled") : value;
                break;
            default: throw Bail(FallbackReason.UnsupportedValue, "unsupported array");
        }
    }

    // ---- calls

    private object? Invoke(IMethod method, Code op, object?[] args)
    {
        if (op == Code.Newobj && args is [var target, FunctionPointer pointer])
            return CreateDelegate(method.DeclaringType.ToTypeSig(), pointer.Method, target);
        if (method.Name == "Invoke" && op != Code.Newobj && args.Length > 0 && args[0] is DelegateObject d)
            return InvokeDelegate(d, args[1..]);
        if (op == Code.Newobj && IsObjectConstructor(method)) return NewPlainObject();
        if (op != Code.Newobj && args.Length > 0 && args[0] is InstanceObject instance && (method.MethodSig?.HasThis ?? false))
            return InvokeInstance(instance, method, op, args);
        if (op == Code.Newobj && method is MethodDef { DeclaringType.IsValueType: false, IsInstanceConstructor: true } streamCtor && streamCtor.Module == module && IsStreamClass(streamCtor.DeclaringType))
            return NewStream(streamCtor, args);
        if (op != Code.Newobj && args.Length > 0 && args[0] is StreamObject { ModuleType: { } streamType } && method is MethodDef { IsStatic: false } own && own.Module == module)
        {
            if (!Chain(streamType).Contains(own.DeclaringType)) throw Bail(FallbackReason.InvalidCode, $"calls {Describe(own)} on an instance of another class");
            var result = Execute(own, args);
            return HasReturnValue(own) ? result : Void;
        }
        if (op == Code.Newobj && method is MethodDef { DeclaringType.IsValueType: false, IsInstanceConstructor: true } classCtor && classCtor.Module == module)
            return NewInstance(classCtor, args);
        var environment = EnvironmentCall(method, op, args, out bool fromEnvironment);
        if (fromEnvironment) return environment;
        var resource = ResourceCall(method, op, args, out bool viaResources);
        if (viaResources) return resource;
        var sorted = SortedListCall(method, op, args, out bool viaSortedList);
        if (viaSortedList) return sorted;
        var collection = CollectionCall(method, op, args, out bool handled);
        if (handled) return collection;
        if (method.FullName == "System.Void System.IDisposable::Dispose()" && args.Length == 1 && (args[0] is Pointer p ? p.Get() : args[0]) is EnumeratorObject)
            return Void;
        if (method is MethodSpec spec)
        {
            // An instantiation of a static generic method of the module, with closed type arguments.
            if (spec.Method is not MethodDef { IsStatic: true } generic || generic.Module != module || op == Code.Newobj)
                throw Bail(FallbackReason.Generic, $"calls generic method {Describe(method)}");
            TriggerTypeInitializer(generic);
            var result = Execute(generic, args, Generics.Arguments(spec));
            return HasReturnValue(generic) ? result : Void;
        }
        if (Intrinsics.TryGetValue(method.FullName, out var intrinsic))
        {
            if (op == Code.Callvirt && args.Length > 0 && args[0] == null) throw Bail(FallbackReason.RuntimeError, "null reference");
            var result = intrinsic(this, args);
            if (result is string s) NewString(s);
            return HasReturnValue(method) || op == Code.Newobj ? result : Void;
        }
        if (method is MethodDef md && md.Module == module)
        {
            if (md.IsStatic)
            {
                if (op == Code.Newobj) throw Bail(FallbackReason.InvalidCode, "newobj of a static method");
                TriggerTypeInitializer(md);
                var result = Execute(md, args);
                return HasReturnValue(md) ? result : Void;
            }
            var layout = LayoutOf(md.DeclaringType, 0);
            if (layout == null)
                throw Bail(FallbackReason.InstanceObject, op == Code.Newobj
                    ? $"creates an instance of {md.DeclaringType.FullName}"
                    : $"calls instance method {Describe(md)}");
            TriggerTypeInitializer(md);
            if (op == Code.Newobj)
            {
                if (!md.IsInstanceConstructor) throw Bail(FallbackReason.InvalidCode, "newobj of a method that is not a constructor");
                var cell = new object?[] { NewStruct(layout) };
                Execute(md, [SlotPointer(cell, 0, new Slot(Kind.Struct, layout)), .. args]);
                return cell[0];
            }
            if (args[0] is not Pointer) throw Bail(FallbackReason.InvalidCode, "struct method called without a managed pointer");
            // callvirt on a struct method comes after constrained. (the receiver is a managed pointer, checked above).
            var value = Execute(md, args);
            return HasReturnValue(md) ? value : Void;
        }
        if (method is MethodDef other)
            throw Bail(FallbackReason.OtherModule, $"calls {Describe(other)} in another module");
        throw Bail(FallbackReason.UnsupportedCall, $"calls {Describe(method)}, which is not evaluable");
    }
}
