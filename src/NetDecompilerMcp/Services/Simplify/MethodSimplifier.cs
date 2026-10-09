using dnlib.DotNet;
using dnlib.DotNet.Emit;
using NetDecompilerMcp.Core;

namespace NetDecompilerMcp.Services.Simplify;

/// <summary>
/// Which passes run, the evaluator limits, and whether environment reads are pinned to fixed stand-ins
/// (<see cref="EnvironmentStandIns"/>; off unless asked for).
/// </summary>
public sealed record SimplifyOptions(bool Fold = true, bool ControlFlow = true, bool Forwarders = true, EvaluationLimits? Limits = null, bool DeterministicEnvironment = false)
{
    public EvaluationLimits EffectiveLimits => Limits ?? new EvaluationLimits();

    public static readonly IReadOnlyList<string> PassNames = ["fold", "cfg", "inline"];

    /// <summary>Parses a comma-separated pass list (fold, cfg, inline; "all" or empty for every pass).</summary>
    public static SimplifyOptions Parse(string? passes, int? maxDepth, int? budget, bool deterministicEnvironment = false)
    {
        var limits = new EvaluationLimits(Math.Clamp(maxDepth ?? 8, 1, 64), Math.Clamp(budget ?? 100_000, 100, 10_000_000));
        var names = (passes ?? "").Split([',', ' ', ';'], StringSplitOptions.RemoveEmptyEntries).Select(p => p.ToLowerInvariant()).ToList();
        if (names.Count == 0 || names.Contains("all")) return new SimplifyOptions(Limits: limits, DeterministicEnvironment: deterministicEnvironment);
        var unknown = names.Except(PassNames).ToList();
        if (unknown.Count > 0)
            throw new ToolError($"Unknown pass '{unknown[0]}'. Passes: fold (evaluate string-producing calls), cfg (control-flow cleanup), inline (forwarder inlining and calls through delegate fields), or all.");
        return new SimplifyOptions(names.Contains("fold"), names.Contains("cfg"), names.Contains("inline"), limits, deterministicEnvironment);
    }

    public string Describe() => string.Join(",", PassNames.Where((_, i) => new[] { Fold, ControlFlow, Forwarders }[i]));

    /// <summary>The passes, and the deterministic environment when it is on (report headers).</summary>
    public string Label() => Describe() + (DeterministicEnvironment ? "; deterministic environment" : "");
}

/// <summary>A fallback: what was left alone, and why.</summary>
public sealed record Fallback(FallbackReason Reason, string Detail)
{
    public override string ToString() => $"{Detail} [{SimplifyManifest.CodeOf(Reason)}]";
}

/// <summary>What the passes did to one method. <see cref="NewBody"/> is set when the method changed and the result verified.</summary>
public sealed class MethodChange(MethodDef method)
{
    public MethodDef Method { get; } = method;
    public List<string> Folded { get; } = new();
    public List<string> Inlined { get; } = new();
    /// <summary>Calls through delegate fields that now call the delegate's target directly.</summary>
    public List<string> Delegates { get; } = new();
    /// <summary>Calls of the module's own helpers that could not be evaluated (the call is kept).</summary>
    public List<Fallback> Bailouts { get; } = new();
    /// <summary>Rewrites refused for a piece of the method, which is kept as it is; the other passes still apply.</summary>
    public List<Fallback> Skipped { get; } = new();
    public int ConstantBranches { get; set; }
    public int CollapsedChains { get; set; }
    public int RemovedBlocks { get; set; }
    public int RemovedInstructions { get; set; }
    public int RemovedHandlers { get; set; }
    /// <summary>Stores to locals that the other passes left unread.</summary>
    public int RemovedStores { get; set; }
    /// <summary>Loads kept only for their effect (<c>_ = S.F;</c>) that repeat one that always ran before them, removed.</summary>
    public int RemovedLoads { get; set; }
    /// <summary>Reads of locals through their address (<c>ldloca; ldind</c>) that read a constant, replaced by it.</summary>
    public int ConstantReads { get; set; }
    /// <summary>Switch dispatchers of flattened control flow removed: each transition goes straight to its case.</summary>
    public int Dispatchers { get; set; }
    public int Transitions { get; set; }
    public int InstructionsBefore { get; set; }
    public int InstructionsAfter { get; set; }
    public CilBody? NewBody { get; set; }
    /// <summary>Why the method was left unchanged as a whole (it did not verify before or after, it took too long, or an error).</summary>
    public Fallback? Rejected { get; set; }

    public bool Changed => NewBody != null;

    public bool HasEffects => Folded.Count + Inlined.Count + Delegates.Count + ConstantBranches + CollapsedChains + RemovedBlocks + RemovedHandlers + Transitions + RemovedStores
                              + ConstantReads + RemovedLoads > 0;
}

/// <summary>
/// Compiler-style simplification of method bodies, on copies (the methods are not touched; callers assign
/// <see cref="MethodChange.NewBody"/>):
/// <list type="number">
/// <item>inline: call sites of forwarder methods (bodies that only pass their arguments on to another method) call the target directly;</item>
/// <item>fold: calls producing a string from constant inputs are evaluated with <see cref="IlEvaluator"/> and replaced by ldstr;</item>
/// <item>cfg: branches on constant conditions are folded (also conditions computed through locals and blocks:
/// <see cref="ConstantFlow"/>), stores to locals left unread removed, branch-to-branch chains collapsed, flattened switch dispatchers
/// (in the clean form, or analyzed per state: <see cref="PlanPerState"/>)
/// normalized, empty try regions and handlers removed, and unreachable code deleted.</item>
/// </list>
/// Every rewritten body must pass <see cref="BodyGraph.Verify"/>; otherwise the method is reported and left unchanged.
/// </summary>
public sealed class MethodSimplifier
{
    private readonly ModuleDef _module;
    private readonly SimplifyOptions _options;
    private readonly IlEvaluator _evaluator;
    private readonly Forwarders _forwarders;
    /// <summary>Calls and static reads of the method being simplified that the evaluator computed (they only produce their value).</summary>
    private readonly HashSet<Instruction> _evaluated = new();
    /// <summary>In a static constructor: each instruction of the working copy that stands at an instruction of the original body.</summary>
    private readonly Dictionary<Instruction, Instruction> _origin = new();

    /// <summary>Type initializer runs that used the extended tier (see IlEvaluator.Progress.cs).</summary>
    public IReadOnlyList<ExtendedInitializer> ExtendedInitializers => _evaluator.ExtendedInitializers;

    public MethodSimplifier(ModuleDef module, SimplifyOptions options)
    {
        _module = module;
        _options = options;
        _evaluator = new IlEvaluator(module, options.EffectiveLimits) { DeterministicEnvironment = options.DeterministicEnvironment, FollowsDelegateFields = true };
        _forwarders = new Forwarders(module);
    }

    /// <summary>Test hook: runs on the rewritten body before it is verified.</summary>
    internal Action<CilBody>? AfterPasses { get; set; }

    public List<MethodChange> Run(IEnumerable<MethodDef> methods, CancellationToken ct)
    {
        var changes = new List<MethodChange>();
        foreach (var m in methods)
        {
            ct.ThrowIfCancellationRequested();
            MethodChange? change;
            try
            {
                change = Simplify(m);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                change = new MethodChange(m) { Rejected = new(FallbackReason.Unexpected, $"{ex.GetType().Name}: {ex.Message}") };
            }
            if (change != null) changes.Add(change);
        }
        return changes;
    }

    /// <summary>Simplifies one method; null when it has no IL body.</summary>
    public MethodChange? Simplify(MethodDef method)
    {
        if (method.Module != _module) return null;
        var original = MetadataUtil.SafeBody(method);
        if (original == null || original.Instructions.Count == 0) return null;
        var change = new MethodChange(method) { InstructionsBefore = original.Instructions.Count };
        bool hasReturnValue = method.MethodSig.RetType.RemovePinnedAndModifiers().ElementType != ElementType.Void;

        if (new BodyGraph(original).Verify(hasReturnValue, out var originalError) == null)
        {
            change.Rejected = new(FallbackReason.OriginalUnverifiable, $"the original body does not verify ({originalError})");
            return change;
        }

        var meter = new MethodMeter(_options.EffectiveLimits);
        _evaluator.CurrentMethod = method;
        _evaluator.Meter = meter;
        try
        {
            return Rewrite(method, original, hasReturnValue, change, meter);
        }
        catch (MethodTimeout ex)
        {
            var timedOut = new MethodChange(method) { InstructionsBefore = change.InstructionsBefore, Rejected = new(FallbackReason.TimeLimit, ex.Message) };
            return timedOut;
        }
        finally
        {
            _evaluator.CurrentMethod = null;
            _evaluator.Meter = null;
        }
    }

    private MethodChange Rewrite(MethodDef method, CilBody original, bool hasReturnValue, MethodChange change, MethodMeter meter)
    {
        var body = BodyGraph.Clone(original);
        _evaluated.Clear();
        _origin.Clear();
        if (method.IsStaticConstructor)
            for (int i = 0; i < body.Instructions.Count; i++) _origin[body.Instructions[i]] = original.Instructions[i];
        var dead = new HashSet<Instruction>(); // instructions turned into nops by the passes; removed at the end
        var unclean = new List<Fallback>(); // flattened dispatchers not in the clean form, as of the last round
        var readOriginally = body.Instructions
            .Where(i => i.IsLdloc() || i.OpCode.Code is Code.Ldloca or Code.Ldloca_S).Select(i => i.GetLocal(body.Variables)).OfType<Local>().ToHashSet();
        if (_options.Forwarders)
        {
            ResolveDelegateCalls(method, body, dead, change);
            RemoveNops(body, dead);
            InlineForwarders(method, body, change);
        }
        if (_options.Fold) FoldStringCalls(body, dead, change);
        if (_options.ControlFlow)
        {
            for (int round = 0; round < 16; round++)
            {
                meter.CheckTime();
                bool changed = FoldBranches(body, dead, change);
                changed |= PropagateConstants(body, hasReturnValue, dead, change, meter);
                changed |= RemoveNops(body, dead);
                changed |= CollapseChains(body, change);
                changed |= Normalize(body, hasReturnValue, dead, change, unclean, meter);
                changed |= SimplifyTryRegions(body, dead, hasReturnValue, change);
                changed |= RemoveNops(body, dead);
                changed |= RemoveUnreachable(body, dead, change);
                changed |= RemoveDeadStores(body, readOriginally, dead, change);
                changed |= DropBranchesToNext(body, dead);
                changed |= RemovePurePops(body, dead);
                changed |= RemoveRepeatedLoads(method, body, dead, change);
                changed |= RemoveNops(body, dead);
                if (!changed) break;
            }
        }
        RemoveNops(body, dead);
        change.Skipped.AddRange(unclean);
        AfterPasses?.Invoke(body);

        if (!change.HasEffects) return change;
        if (new BodyGraph(body).Verify(hasReturnValue, out var error) == null)
        {
            change.Rejected = new(FallbackReason.ResultUnverifiable, $"the simplified body would not verify ({error}); left unchanged");
            return change;
        }
        body.SimplifyBranches();
        body.OptimizeBranches();
        body.UpdateInstructionOffsets();
        change.InstructionsAfter = body.Instructions.Count;
        change.NewBody = body;
        return change;
    }

    private static string At(Instruction ins) => $"IL_{ins.Offset:X4}";

    /// <summary>
    /// The instruction of the original body a slice starting at <paramref name="ins"/> stands at: the working copy's own
    /// instructions keep their place in the program's run (rewrites in place keep what runs before them); instructions
    /// the passes added map to none.
    /// </summary>
    private Instruction? Origin(Instruction ins) => _origin.GetValueOrDefault(ins);

    // ---- pass: forwarder inlining

    private void InlineForwarders(MethodDef caller, CilBody body, MethodChange change)
    {
        var code = body.Instructions;
        for (int i = 0; i < code.Count; i++)
        {
            var site = code[i];
            if (site.OpCode.Code is not (Code.Call or Code.Callvirt)) continue;
            if (i > 0 && code[i - 1].OpCode.OpCodeType == OpCodeType.Prefix) continue; // tail. / constrained. / readonly.
            var first = site.Operand as IMethod;
            for (int hop = 0; hop < 8 && site.Operand is MethodDef wrapper; hop++)
            {
                var rewrite = _forwarders.Rewrite(site.OpCode.Code, wrapper, caller.DeclaringType);
                if (rewrite == null) break;
                site.OpCode = rewrite.Value.OpCode;
                site.Operand = rewrite.Value.Target;
            }
            if (!ReferenceEquals(site.Operand, first))
                change.Inlined.Add($"{Describe(first!)} -> {Describe((IMethod)site.Operand)} at {At(site)}");
        }
    }

    // ---- pass: calls through delegate fields

    /// <summary>
    /// Call sites <c>ldsfld F; args; call(virt) D::Invoke</c> through a static delegate field of this module whose value
    /// the evaluator computes (the field's type initializer run in the sandbox, reflection-based initializers included)
    /// call the delegate's target directly: <c>args; call M</c> for a delegate of a static method, or the code of its
    /// dynamic method after it has loaded its arguments, in order (<c>ldarg.0 ... ldarg.n-1; [code]; ret</c>). The field
    /// must only be written while its type initializes (readonly, or proven by <see cref="ModuleFacts"/>); anything else is
    /// reported (delegate-target) and the call is kept.
    /// </summary>
    private void ResolveDelegateCalls(MethodDef caller, CilBody body, HashSet<Instruction> dead, MethodChange change)
    {
        var code = body.Instructions;
        BodyGraph? graph = null;
        for (int i = 0; i < code.Count; i++)
        {
            var site = code[i];
            if (site.OpCode.Code is not (Code.Call or Code.Callvirt) || site.Operand is not IMethod { Name.String: "Invoke" } invoke) continue;
            if (invoke.MethodSig is not { HasThis: true } sig || (i > 0 && code[i - 1].OpCode.OpCodeType == OpCodeType.Prefix)) continue;
            graph ??= new BodyGraph(body);
            int producer = Producer(code, graph.Targets, i, sig.Params.Count);
            if (producer < 0 || code[producer] is not { OpCode.Code: Code.Ldsfld, Operand: FieldDef { IsStatic: true } field } || field.Module != _module ||
                field.FieldType.FullName != invoke.DeclaringType.FullName)
                continue;

            string where = $"call through {field.DeclaringType.FullName}::{field.Name} at {At(site)}";
            object? value;
            try
            {
                value = _evaluator.EvaluateSlice([new Instruction(OpCodes.Ldsfld, field)], Origin(code[producer])) is [var v] ? v : null;
            }
            catch (EvaluationBailout ex)
            {
                change.Skipped.Add(new(FallbackReason.DelegateTarget, $"{where}: {ex.Message}"));
                continue;
            }
            if (value is not DelegateObject d)
            {
                change.Skipped.Add(new(FallbackReason.DelegateTarget, $"{where}: the field holds {(value == null ? "null" : "no delegate")} after its type's initialization"));
                continue;
            }
            if (DelegateCode(d, sig.Params.Count, out var target, out var why) is not { } replacement)
            {
                change.Skipped.Add(new(FallbackReason.DelegateTarget, $"{where}: {why}"));
                continue;
            }
            // A delegate bound to a field-less singleton loads the singleton where the delegate was loaded.
            if (d.Target != null)
            {
                if (_evaluator.StaticHolding(d.Target) is not { } holder || !Forwarders.IsAccessible(holder, caller.DeclaringType) ||
                    d.Method is not MethodDef { IsStatic: false } bound || !Forwarders.IsAccessible(bound, caller.DeclaringType))
                {
                    change.Skipped.Add(new(FallbackReason.DelegateTarget, $"{where}: the delegate is bound to an object that no static field accessible here holds"));
                    continue;
                }
                code[producer].Operand = holder;
            }
            else MakeDead(code[producer], dead);
            site.OpCode = replacement[0].OpCode;
            site.Operand = replacement[0].Operand;
            for (int k = 1; k < replacement.Count; k++)
            {
                replacement[k].Offset = site.Offset; // reported at the call they replace
                code.Insert(i + k, replacement[k]);
            }
            i += replacement.Count - 1;
            graph = null;
            change.Delegates.Add($"{field.DeclaringType.FullName}::{field.Name}.Invoke -> {target} at {At(site)}");
        }
    }

    /// <summary>
    /// Index of the instruction that pushes the stack slot <paramref name="depth"/> positions below the top before
    /// code[end] (0: the top), found in the straight-line code before it (no instruction after it is in
    /// <paramref name="targets"/>); -1 when it is not a single push there.
    /// </summary>
    internal static int Producer(IList<Instruction> code, ISet<Instruction> targets, int end, int depth)
    {
        for (int k = end - 1; k >= 0; k--)
        {
            if (targets.Contains(code[k + 1])) return -1;
            var ins = code[k];
            if (ins.OpCode.FlowControl is not (FlowControl.Next or FlowControl.Call) || ins.OpCode.OpCodeType == OpCodeType.Prefix) return -1;
            ins.CalculateStackUsage(false, out int pushes, out int pops);
            if (pops < 0) return -1;
            if (depth < pushes) return pushes == 1 ? k : -1;
            depth = depth - pushes + pops;
        }
        return -1;
    }

    /// <summary>The code that does what invoking the delegate with its arguments on the stack does, or null with <paramref name="why"/>.</summary>
    internal static List<Instruction>? DelegateCode(DelegateObject d, int arguments, out string target, out string? why)
    {
        why = null;
        target = "";
        if (d.Dynamic is { } dynamic)
        {
            var body = dynamic.Code;
            if (dynamic.Parameters.Length != arguments || body.Count < arguments + 1 || body[^1].OpCode.Code != Code.Ret)
            {
                why = "its dynamic method does not match the delegate's signature";
                return null;
            }
            for (int k = 0; k < arguments; k++)
            {
                if (!body[k].IsLdarg() || body[k].GetParameterIndex() != k)
                {
                    why = "its dynamic method does not load its arguments in order first";
                    return null;
                }
            }
            var tail = new List<Instruction>();
            for (int k = arguments; k < body.Count - 1; k++)
            {
                var ins = body[k];
                if (ins.OpCode.Code == Code.Tailcall) continue; // the call is followed by its ret
                if (ins.IsLdarg() || ins.IsStarg() || ins.OpCode.Code is Code.Ldarga or Code.Ldarga_S || ins.OpCode.FlowControl is not (FlowControl.Next or FlowControl.Call)
                    || ins.OpCode.OpCodeType == OpCodeType.Prefix)
                {
                    why = $"its dynamic method does more than pass its arguments on ({ins.OpCode.Name})";
                    return null;
                }
                tail.Add(new Instruction(ins.OpCode, ins.Operand));
            }
            if (tail.Count == 0)
            {
                why = "its dynamic method only returns its argument";
                return null;
            }
            var call = tail.LastOrDefault(i => i.Operand is IMethod);
            target = call?.Operand is IMethod m ? (tail.Count == 1 ? Describe(m) : $"{Describe(m)} (after {string.Join("; ", tail.Take(tail.Count - 1).Select(i => $"{i.OpCode.Name} {i.Operand}".Trim()))})") : "dynamic code";
            return tail;
        }
        if (d.Method is { } method && d.Target == null && !(method.MethodSig?.HasThis ?? true) && method.MethodSig!.Params.Count == arguments)
        {
            target = Describe(method);
            return [OpCodes.Call.ToInstruction(method)];
        }
        // Bound to a field-less singleton: the caller loads the singleton in the delegate's place.
        if (d.Method is { } bound && d.Target is InstanceObject { Fields.Count: 0 } && (bound.MethodSig?.HasThis ?? false) && bound.MethodSig!.Params.Count == arguments)
        {
            target = Describe(bound);
            return [OpCodes.Call.ToInstruction(bound)];
        }
        why = "the delegate is bound to an object or does not match its signature";
        return null;
    }

    // ---- pass: evaluation of string-producing calls

    private void FoldStringCalls(CilBody body, HashSet<Instruction> dead, MethodChange change)
    {
        var code = body.Instructions;
        var graph = new BodyGraph(body);
        for (int j = 0; j < code.Count; j++)
        {
            var call = code[j];
            if (call.OpCode.Code is not (Code.Call or Code.Callvirt or Code.Newobj) || call.Operand is not IMethod callee) continue;
            if (!ProducesString(call.OpCode.Code, callee)) continue;
            call.CalculateStackUsage(false, out _, out int pops);
            int? start = SliceStart(code, graph, j, pops);
            if (start == null) continue; // arguments are not compile-time constants

            object? value;
            try
            {
                var stack = _evaluator.EvaluateSlice(code.Skip(start.Value).Take(j - start.Value + 1).ToList(), Origin(code[start.Value]));
                if (stack.Count != 1 || stack[0] is not (string or null)) continue;
                value = stack[0];
            }
            catch (EvaluationBailout ex)
            {
                // Reported for the assembly's own helpers; framework calls that cannot be evaluated are expected.
                if (Generics.Definition(callee) is MethodDef def && def.Module == _module)
                    change.Bailouts.Add(new(ex.Reason, $"{At(call)} {Describe(callee)}: {ex.Message}"));
                continue;
            }

            var head = code[start.Value];
            head.OpCode = value == null ? OpCodes.Ldnull : OpCodes.Ldstr;
            head.Operand = value;
            for (int k = start.Value + 1; k <= j; k++) MakeDead(code[k], dead);
            change.Folded.Add($"{Describe(callee)} -> {Format.Clip(Format.Literal(value), 120)} at {At(call)}");
        }
    }

    private static bool ProducesString(Code op, IMethod callee) => op == Code.Newobj
        ? callee.DeclaringType?.FullName == "System.String"
        : Generics.ReturnType(callee)?.RemovePinnedAndModifiers().ElementType == ElementType.String;

    /// <summary>
    /// Start of the shortest run of instructions ending before <paramref name="end"/> that pushes the
    /// <paramref name="needed"/> operands of code[end] from an empty stack, without branches, arguments, locals or
    /// incoming branches in between; null when there is none.
    /// </summary>
    /// <remarks><paramref name="endMayBeTarget"/>: code[end] may be entered from elsewhere (the slice ends just before it).</remarks>
    private static int? SliceStart(IList<Instruction> code, BodyGraph graph, int end, int needed, bool endMayBeTarget = false)
    {
        int i = end;
        while (needed > 0)
        {
            if (--i < 0) return null;
            var ins = code[i];
            if (!Sliceable(ins)) return null;
            ins.CalculateStackUsage(false, out int pushes, out int pops);
            if (pops < 0) return null;
            needed -= pushes;
            if (needed < 0) return null;
            needed += pops;
        }
        for (int k = i + 1; k <= end; k++)
            if (graph.Targets.Contains(code[k]) && !(endMayBeTarget && k == end)) return null;
        return i;
    }

    private static bool Sliceable(Instruction ins)
    {
        if (ins.OpCode.FlowControl is not (FlowControl.Next or FlowControl.Call)) return false;
        if (ins.OpCode.OpCodeType == OpCodeType.Prefix) return false;
        if (ins.IsLdarg() || ins.IsStarg() || ins.IsLdloc() || ins.IsStloc()) return false;
        return ins.OpCode.Code is not (Code.Ldarga or Code.Ldarga_S or Code.Ldloca or Code.Ldloca_S or Code.Calli or Code.Jmp or Code.Pop);
    }

    // ---- pass: control flow

    private bool FoldBranches(CilBody body, HashSet<Instruction> dead, MethodChange change)
    {
        var code = body.Instructions;
        var graph = new BodyGraph(body);
        bool changed = false;
        for (int j = 0; j < code.Count; j++)
        {
            var branch = code[j];
            if (branch.OpCode.FlowControl != FlowControl.Cond_Branch || dead.Contains(branch)) continue;
            branch.CalculateStackUsage(false, out _, out int pops);
            int? start = SliceStart(code, graph, j, pops);
            if (start == null) continue;

            Instruction? target;
            try
            {
                var operands = _evaluator.EvaluateSlice(code.Skip(start.Value).Take(j - start.Value).ToList(), Origin(code[start.Value]));
                if (operands.Count != pops) continue;
                target = Decide(branch, operands);
            }
            catch (EvaluationBailout)
            {
                continue; // not constant after all
            }

            var head = code[start.Value];
            if (target != null)
            {
                head.OpCode = OpCodes.Br;
                head.Operand = target;
            }
            else
            {
                MakeDead(head, dead);
            }
            for (int k = start.Value + 1; k <= j; k++) MakeDead(code[k], dead);
            change.ConstantBranches++;
            changed = true;
        }
        return changed;
    }

    /// <summary>
    /// Branches and switches whose operands are the same on every run though computed across instructions, locals and
    /// blocks (<see cref="ConstantFlow"/>) go straight to the code they select. The instructions computing the operands are
    /// deleted when they only compute them (loads, arithmetic, evaluated calls and static reads right before the branch);
    /// otherwise the branch pops them. Stores whose local is no longer read are removed afterwards (<see cref="RemoveDeadStores"/>).
    /// </summary>
    private bool PropagateConstants(CilBody body, bool hasReturnValue, HashSet<Instruction> dead, MethodChange change, MethodMeter meter)
    {
        var all = body.Instructions;
        if (!all.Any(i => i.OpCode.FlowControl == FlowControl.Cond_Branch && !dead.Contains(i)) &&
            !all.Any(i => i.OpCode.Code is Code.Ldloca or Code.Ldloca_S)) return false;
        var graph = new BodyGraph(body);
        if (graph.Verify(hasReturnValue, out _) == null) return false;
        var flow = new ConstantFlow(body, graph, hasReturnValue, _evaluator);
        var decisions = flow.Decisions(meter);
        _evaluated.UnionWith(flow.Evaluated);
        var code = body.Instructions;

        // A constant hidden behind a local read through its address becomes the constant.
        bool replaced = false;
        foreach (var (read, value) in flow.AddressReads)
        {
            int at = graph.IndexOf(read);
            if (at < 1 || dead.Contains(read) || Constant(value) is not { } constant) continue;
            code[at - 1].OpCode = constant.OpCode;
            code[at - 1].Operand = constant.Operand;
            MakeDead(read, dead);
            change.ConstantReads++;
            replaced = true;
        }
        if (decisions.Count == 0) return replaced;

        var insertions = new List<(Instruction After, Instruction[] Code)>();
        foreach (var (branch, next) in decisions)
        {
            int j = graph.IndexOf(branch);
            branch.CalculateStackUsage(false, out _, out int pops);
            bool falls = j + 1 < code.Count && next == code[j + 1];
            if (OperandSlice(code, graph, j, pops, mayThrow: true) is { } start)
            {
                var head = code[start];
                if (falls) MakeDead(head, dead);
                else
                {
                    head.OpCode = OpCodes.Br;
                    head.Operand = next;
                }
                for (int k = start + 1; k <= j; k++) MakeDead(code[k], dead);
            }
            else
            {
                // The operands stay computed (they may have effects); the branch only drops them.
                branch.OpCode = OpCodes.Pop;
                branch.Operand = null;
                var after = Enumerable.Range(1, pops - 1).Select(_ => OpCodes.Pop.ToInstruction()).ToList();
                if (!falls) after.Add(OpCodes.Br.ToInstruction(next));
                if (after.Count > 0) insertions.Add((branch, after.ToArray()));
            }
            change.ConstantBranches++;
        }
        foreach (var (after, added) in insertions)
        {
            int at = code.IndexOf(after) + 1;
            for (int k = 0; k < added.Length; k++) code.Insert(at + k, added[k]);
        }
        return true;
    }

    /// <summary>
    /// Start of the run of instructions right before code[end] that pushes its <paramref name="needed"/> operands and
    /// does nothing else, so that it can be deleted with code[end]: constants, loads of locals and arguments, arithmetic,
    /// comparisons and conversions, and calls or static reads the evaluator computed; null when there is none.
    /// <paramref name="mayThrow"/>: operations that throw for some operands (division, checked arithmetic and
    /// conversions) are included, which is right only when their operands are known not to make them throw.
    /// </summary>
    private int? OperandSlice(IList<Instruction> code, BodyGraph graph, int end, int needed, bool mayThrow) =>
        graph.Targets.Contains(code[end]) ? null : RemovableRun(code, graph, end - 1, needed, mayThrow);

    /// <summary>
    /// Start of the run of instructions ending at code[last] that pushes <paramref name="needed"/> values and does nothing
    /// else (see <see cref="OperandSlice"/>; a local read through its address right away, <c>ldloca; ldind</c>, counts as a
    /// load); last + 1 when nothing is needed, null when there is no such run.
    /// </summary>
    private int? RemovableRun(IList<Instruction> code, BodyGraph graph, int last, int needed, bool mayThrow)
    {
        int i = last + 1;
        while (needed > 0)
        {
            if (--i < 0) return null;
            var ins = code[i];
            var op = ins.OpCode.Code;
            bool pure = ins.IsLdcI4() || ins.IsLdloc() || ins.IsLdarg() || op is Code.Ldc_I8 or Code.Ldc_R4 or Code.Ldc_R8
                or Code.Ldnull or Code.Ldstr or Code.Nop or Code.Dup || IsArithmetic(op) && (mayThrow || !Throws(op)) ||
                (op is Code.Call or Code.Callvirt or Code.Ldsfld && _evaluated.Contains(ins) && !(i > 0 && code[i - 1].OpCode.OpCodeType == OpCodeType.Prefix)) ||
                (op is >= Code.Ldind_I1 and <= Code.Ldind_Ref && i > 0 && code[i - 1].OpCode.Code is Code.Ldloca or Code.Ldloca_S) ||
                (op is Code.Ldloca or Code.Ldloca_S && i < last && code[i + 1].OpCode.Code is >= Code.Ldind_I1 and <= Code.Ldind_Ref);
            if (!pure) return null;
            ins.CalculateStackUsage(false, out int pushes, out int pops);
            needed -= pushes;
            if (needed < 0) return null;
            needed += pops;
        }
        for (int k = i + 1; k <= last; k++)
            if (graph.Targets.Contains(code[k])) return null;
        return i;
    }

    /// <summary>Arithmetic that throws for some operands: division and remainder, checked arithmetic and conversions, ckfinite.</summary>
    private static bool Throws(Code op) => op is Code.Div or Code.Div_Un or Code.Rem or Code.Rem_Un or Code.Ckfinite
        || op.ToOpCode().Name.Contains(".ovf", StringComparison.Ordinal);

    private static bool IsArithmetic(Code op) => op is Code.Add or Code.Sub or Code.Mul or Code.Div or Code.Div_Un or Code.Rem or Code.Rem_Un
        or Code.And or Code.Or or Code.Xor or Code.Shl or Code.Shr or Code.Shr_Un or Code.Add_Ovf or Code.Add_Ovf_Un or Code.Sub_Ovf
        or Code.Sub_Ovf_Un or Code.Mul_Ovf or Code.Mul_Ovf_Un or Code.Neg or Code.Not or Code.Ckfinite
        or Code.Ceq or Code.Cgt or Code.Cgt_Un or Code.Clt or Code.Clt_Un
        or Code.Conv_I1 or Code.Conv_I2 or Code.Conv_I4 or Code.Conv_I8 or Code.Conv_U1 or Code.Conv_U2 or Code.Conv_U4 or Code.Conv_U8
        or Code.Conv_I or Code.Conv_U or Code.Conv_R4 or Code.Conv_R8 or Code.Conv_R_Un
        or Code.Conv_Ovf_I1 or Code.Conv_Ovf_I2 or Code.Conv_Ovf_I4 or Code.Conv_Ovf_I8 or Code.Conv_Ovf_U1 or Code.Conv_Ovf_U2
        or Code.Conv_Ovf_U4 or Code.Conv_Ovf_U8 or Code.Conv_Ovf_I or Code.Conv_Ovf_U or Code.Conv_Ovf_I1_Un or Code.Conv_Ovf_I2_Un
        or Code.Conv_Ovf_I4_Un or Code.Conv_Ovf_I8_Un or Code.Conv_Ovf_U1_Un or Code.Conv_Ovf_U2_Un or Code.Conv_Ovf_U4_Un
        or Code.Conv_Ovf_U8_Un or Code.Conv_Ovf_I_Un or Code.Conv_Ovf_U_Un;

    /// <summary>
    /// Locals the passes left unread (the original body read them): their stores do nothing any more. A store whose value
    /// is computed right before it without effects (<see cref="OperandSlice"/>, nothing that may throw) is deleted with
    /// that computation; any other store pops its value instead.
    /// </summary>
    private bool RemoveDeadStores(CilBody body, HashSet<Local> readOriginally, HashSet<Instruction> dead, MethodChange change)
    {
        var code = body.Instructions;
        var read = new HashSet<Local>();
        foreach (var ins in code)
            if ((ins.IsLdloc() || ins.OpCode.Code is Code.Ldloca or Code.Ldloca_S) && ins.GetLocal(body.Variables) is { } l) read.Add(l);
        var unread = readOriginally.Where(l => !read.Contains(l)).ToHashSet();
        if (unread.Count == 0) return false;
        var graph = new BodyGraph(body);
        bool changed = false;
        for (int i = 0; i < code.Count; i++)
        {
            var store = code[i];
            if (!store.IsStloc() || dead.Contains(store) || store.GetLocal(body.Variables) is not { } local || !unread.Contains(local)) continue;
            if (OperandSlice(code, graph, i, 1, mayThrow: false) is { } start && !code.Skip(start).Take(i - start).Any(dead.Contains))
            {
                for (int k = start; k <= i; k++) MakeDead(code[k], dead);
            }
            else
            {
                store.OpCode = OpCodes.Pop;
                store.Operand = null;
            }
            change.RemovedStores++;
            changed = true;
        }
        return changed;
    }

    /// <summary>The branch target taken for the given operands, or null for fall-through.</summary>
    private static Instruction? Decide(Instruction branch, List<object?> operands)
    {
        var op = branch.OpCode.Code;
        if (op == Code.Switch)
        {
            var targets = (IList<Instruction>)branch.Operand;
            var index = operands[0] as int? ?? throw new EvaluationBailout(FallbackReason.InvalidCode, "switch on a non-int32");
            return (uint)index < (uint)targets.Count ? targets[index] : null;
        }
        bool taken = op switch
        {
            Code.Brtrue or Code.Brtrue_S => Numeric.IsTrue(operands[0]),
            Code.Brfalse or Code.Brfalse_S => !Numeric.IsTrue(operands[0]),
            _ => Numeric.Branch(op, operands[0], operands[1]),
        };
        return taken ? (Instruction)branch.Operand : null;
    }

    /// <summary>Branches to an unconditional br within the same protected regions go straight to its final target.</summary>
    private static bool CollapseChains(CilBody body, MethodChange change)
    {
        var graph = new BodyGraph(body);
        bool changed = false;
        Instruction Final(int from, Instruction target)
        {
            var seen = new HashSet<Instruction>();
            while (target.OpCode.Code is Code.Br or Code.Br_S && seen.Add(target))
            {
                var next = (Instruction)target.Operand;
                int t = graph.IndexOf(target), n = graph.IndexOf(next);
                if (t < 0 || n < 0 || !graph.SameRegions(from, t) || !graph.SameRegions(from, n)) break;
                target = next;
            }
            return target;
        }

        for (int i = 0; i < graph.Instructions.Count; i++)
        {
            var ins = graph.Instructions[i];
            if (ins.OpCode.FlowControl is not (FlowControl.Branch or FlowControl.Cond_Branch)) continue;
            if (ins.OpCode.Code is Code.Leave or Code.Leave_S) continue;
            switch (ins.Operand)
            {
                case Instruction t when Final(i, t) is var f && f != t:
                    ins.Operand = f;
                    change.CollapsedChains++;
                    changed = true;
                    break;
                case Instruction[] ts:
                    for (int k = 0; k < ts.Length; k++)
                    {
                        var f = Final(i, ts[k]);
                        if (f == ts[k]) continue;
                        ts[k] = f;
                        change.CollapsedChains++;
                        changed = true;
                    }
                    break;
            }
        }
        return changed;
    }

    // ---- pass: control flow, flattened switch dispatchers

    /// <summary>What normalizing one dispatcher does to the body.</summary>
    private sealed class NormalizePlan
    {
        /// <summary>The constants stored to the state local, and the stores.</summary>
        public List<Instruction> Dead { get; } = new();
        /// <summary>Branches into the dispatcher (or a shared tail) that now go straight to their case.</summary>
        public List<(Instruction Branch, Instruction Target)> Retarget { get; } = new();
        /// <summary>Transitions that fell into the dispatcher (or a shared tail): a br to their case is inserted before it.</summary>
        public List<(Instruction Before, Instruction Target)> Insert { get; } = new();
        public int Transitions => Retarget.Count + Insert.Count;
    }

    /// <summary>
    /// Flattened control flow: a loop whose body is a switch over a state local, each case storing the next state as a
    /// constant and branching back to the switch. Only the clean form (<see cref="PlanNormalize"/>) is rewritten: every
    /// transition goes straight to the case its state selects, the constant stores are deleted, and the dispatcher, no
    /// longer entered, is removed as unreachable code. A dispatcher in any other form is kept as it is and listed in
    /// <paramref name="unclean"/> (refilled on every call); the other passes still apply to the method.
    /// </summary>
    private bool Normalize(CilBody body, bool hasReturnValue, HashSet<Instruction> dead, MethodChange change, List<Fallback> unclean, MethodMeter meter)
    {
        unclean.Clear();
        bool changed = false;
        // The body's graph is rebuilt only after a dispatcher is rewritten.
        BodyGraph? graph = null;
        int[]? depth = null;
        foreach (var sw in body.Instructions.Where(i => i.OpCode.Code == Code.Switch).ToList())
        {
            if (graph == null)
            {
                graph = new BodyGraph(body);
                depth = graph.Verify(hasReturnValue, out _);
            }
            if (depth == null) break;
            int s = graph.IndexOf(sw);
            if (s < 0 || depth[s] < 0) continue;
            var plan = PlanNormalize(body, graph, depth, s, out var head, out var why);
            if (plan == null)
            {
                // Not the clean form: the dispatcher is analyzed per state.
                if (DispatcherStart(body, graph, depth, s) is not { } start)
                {
                    if (why != null)
                        unclean.Add(new(FallbackReason.FlattenedShape, $"switch dispatcher at {At(head!)}: {why}; the dispatcher is kept"));
                    continue;
                }
                var computed = PlanPerState(body, graph, depth, hasReturnValue, start, s, meter, out var reason);
                if (computed == null)
                {
                    unclean.Add(new(FallbackReason.FlattenedShape, $"switch dispatcher at {At(head ?? graph.Instructions[start])}: {reason}; the dispatcher is kept"));
                    continue;
                }
                ApplyPerState(body, computed, dead);
                change.Dispatchers++;
                change.Transitions += computed.Transitions;
                changed = true;
                graph = null;
                continue;
            }
            foreach (var ins in plan.Dead) MakeDead(ins, dead);
            foreach (var (branch, target) in plan.Retarget) branch.Operand = target;
            foreach (var (before, target) in plan.Insert)
                body.Instructions.Insert(body.Instructions.IndexOf(before), OpCodes.Br.ToInstruction(target));
            change.Dispatchers++;
            change.Transitions += plan.Transitions;
            changed = true;
            graph = null;
        }
        return changed;
    }

    /// <summary>
    /// Plans normalizing the switch at code[s]. Null with <paramref name="why"/> null: not flattened control flow, i.e. not
    /// <c>ldloc state; ...; switch</c> where code reachable from the switch stores the state and goes back to the ldloc
    /// (a plain <c>switch (local)</c> is not a candidate). Null with <paramref name="why"/> set: flattened, but not in the
    /// clean form, which is:
    /// <list type="bullet">
    /// <item>the dispatcher <c>ldloc state; key; switch</c> is entered only at the ldloc, with an empty stack, and the key
    /// only computes on the stack (e.g. <c>ldc.i4 k; xor</c>);</item>
    /// <item>the state is an int local whose address is never taken, read only by the dispatcher;</item>
    /// <item>every entry into the dispatcher is a transition: <c>constant; stloc state</c>, straight-line code that leaves
    /// the state alone, then <c>br dispatcher</c> or falling into it. A shared tail <c>stloc state; br dispatcher</c>
    /// (what <c>state = c ? 3 : 5;</c> compiles to) counts when every way into it is a br or fall-through after a constant;</item>
    /// <item>every store to the state belongs to a transition, and the constants are computed without calls.</item>
    /// </list>
    /// Unreachable code is ignored: it is removed with the dispatcher.
    /// </summary>
    private NormalizePlan? PlanNormalize(CilBody body, BodyGraph graph, int[] depth, int s, out Instruction? head, out string? why)
    {
        head = null;
        why = null;
        var code = graph.Instructions;
        int h = s - 1;
        while (h >= 0 && !code[h].IsLdloc() && code[h].OpCode.FlowControl is FlowControl.Next or FlowControl.Call) h--;
        if (h < 0 || !code[h].IsLdloc() || code[h].GetLocal(body.Variables) is not { } state) return null;
        var entry = code[h];
        // Flattened control flow loops: some case stores the state and goes back to the dispatcher.
        var loop = graph.ReachableFrom(s);
        bool IsEntry(int e) => BodyGraph.BranchTargets(code[e]).Contains(entry) || (e + 1 == h && BodyGraph.FallsThrough(code[e]));
        if (!Enumerable.Range(0, code.Count).Any(e => loop[e] && IsEntry(e) &&
                StateStore(code, graph, code[e].OpCode.FlowControl == FlowControl.Branch ? e - 1 : e, state, body) >= 0)) return null;
        head = entry;

        if (state.Type.RemovePinnedAndModifiers().ElementType is not (ElementType.I4 or ElementType.U4))
        {
            why = $"the state local V_{state.Index} is not an int";
            return null;
        }
        foreach (var ins in code)
        {
            if (ins.OpCode.Code is Code.Ldloca or Code.Ldloca_S && ins.GetLocal(body.Variables) == state)
            {
                why = $"the address of the state local is taken at {At(ins)}";
                return null;
            }
            if (ins.IsLdloc() && ins != entry && ins.GetLocal(body.Variables) == state)
            {
                why = $"the state local is read at {At(ins)}, outside the dispatcher";
                return null;
            }
        }
        if (depth[h] != 0)
        {
            why = "the dispatcher is entered with values on the stack";
            return null;
        }
        for (int k = h + 1; k <= s; k++)
        {
            bool pure = k == s || (Sliceable(code[k]) && code[k].OpCode.FlowControl == FlowControl.Next);
            if (!pure || graph.Targets.Contains(code[k]) || depth[k] < 1)
            {
                why = $"the switch value is not computed from the state alone (at {At(code[k])})";
                return null;
            }
        }
        if (RegionStartsAt(graph, entry))
        {
            why = "a protected region starts at the dispatcher";
            return null;
        }

        var key = code.Skip(h + 1).Take(s - h - 1).ToList();
        Instruction? Case(int start, int end)
        {
            if (ConstantState(code, start, end) is not { } value) return null;
            try
            {
                var operands = _evaluator.EvaluateSlice(key.Prepend(OpCodes.Ldc_I4.ToInstruction(value)).ToList());
                var target = operands.Count == 1 ? Decide(code[s], operands) ?? code[s + 1] : null;
                return target == entry ? null : target;
            }
            catch (EvaluationBailout)
            {
                return null;
            }
        }

        var plan = new NormalizePlan();
        var transitionStores = new HashSet<Instruction>();
        for (int e = 0; e < code.Count; e++)
        {
            bool jumps = BodyGraph.BranchTargets(code[e]).Contains(entry);
            bool falls = e + 1 == h && BodyGraph.FallsThrough(code[e]);
            if (!jumps && !falls || depth[e] < 0) continue;
            if (jumps ? code[e].OpCode.Code is not (Code.Br or Code.Br_S) : code[e].OpCode.FlowControl is not (FlowControl.Next or FlowControl.Call))
            {
                why = $"{At(code[e])} enters the dispatcher by a conditional branch, switch or leave";
                return null;
            }
            int store = jumps && graph.Targets.Contains(code[e]) ? -1 : StateStore(code, graph, jumps ? e - 1 : e, state, body);
            if (store < 0)
            {
                why = $"{At(code[e])} enters the dispatcher without storing a state";
                return null;
            }
            transitionStores.Add(code[store]);
            string notConstant = $"the state stored at {At(code[store])} is not a constant that selects a case";

            if (!graph.Targets.Contains(code[store]))
            {
                // constant; stloc state; ...; br dispatcher
                if (!graph.SameRegions(store, h) || SliceStart(code, graph, store, 1) is not { } start || Case(start, store - 1) is not { } target)
                {
                    why = notConstant;
                    return null;
                }
                plan.Dead.AddRange(code.Skip(start).Take(store - start + 1));
                if (jumps) plan.Retarget.Add((code[e], target));
                else plan.Insert.Add((entry, target));
                continue;
            }

            // Shared tail stloc state; br dispatcher: each way in pushes a constant and goes straight to its case instead.
            if (store != (jumps ? e - 1 : e) || depth[store] != 1 || !graph.SameRegions(store, h) || RegionStartsAt(graph, code[store]))
            {
                why = notConstant;
                return null;
            }
            for (int p = 0; p < code.Count; p++)
            {
                bool into = BodyGraph.BranchTargets(code[p]).Contains(code[store]);
                bool fallsInto = p + 1 == store && BodyGraph.FallsThrough(code[p]);
                if (!into && !fallsInto || depth[p] < 0) continue;
                int end = into ? p - 1 : p;
                int? start = into
                    ? code[p].OpCode.Code is Code.Br or Code.Br_S ? SliceStart(code, graph, p, 1) : null
                    : code[p].OpCode.FlowControl == FlowControl.Next ? SliceStart(code, graph, store, 1, endMayBeTarget: true) : null;
                if (start == null || !graph.SameRegions(start.Value, store) || Case(start.Value, end) is not { } target)
                {
                    why = notConstant;
                    return null;
                }
                plan.Dead.AddRange(code.Skip(start.Value).Take(end - start.Value + 1));
                if (into) plan.Retarget.Add((code[p], target));
                else plan.Insert.Add((code[store], target));
            }
        }

        for (int i = 0; i < code.Count; i++)
        {
            if (depth[i] < 0 || !IsStore(code[i], state, body) || transitionStores.Contains(code[i])) continue;
            why = $"the state local is written at {At(code[i])} outside a transition";
            return null;
        }
        return plan.Transitions > 0 ? plan : null;
    }

    /// <summary>What normalizing one dispatcher analyzed per state does to the body.</summary>
    private sealed class PerStatePlan
    {
        /// <summary>Instructions deleted (the values a transition pushed for the dispatcher).</summary>
        public List<Instruction> Dead { get; } = new();
        /// <summary>Branch operands that pointed into the dispatcher (From) and now point at the case (To).</summary>
        public List<(Instruction Branch, Instruction From, Instruction To)> Retarget { get; } = new();
        /// <summary>Code inserted before an instruction (a transition that fell into the dispatcher).</summary>
        public List<(Instruction Before, Instruction[] Code)> Insert { get; } = new();
        /// <summary>Instructions rewritten in place (reads of the state that are the same on every run become constants).</summary>
        public List<(Instruction Instruction, OpCode OpCode, object? Operand)> Replace { get; } = new();
        /// <summary>Code appended at the end of the body (stubs that drop the values a conditional branch passed to the dispatcher).</summary>
        public List<Instruction> Append { get; } = new();
        public int Transitions { get; set; }
    }

    /// <summary>
    /// The first instruction of the dispatcher that ends with the switch at code[s]: the straight-line code before the
    /// switch, from its earliest branch target on. Null unless it is flattened control flow: code reachable from the
    /// switch branches back into it (a loop over the switch), and that loop passes it a state, by storing a local the
    /// dispatcher reads or by values on the stack.
    /// </summary>
    private static int? DispatcherStart(CilBody body, BodyGraph graph, int[] depth, int s)
    {
        var code = graph.Instructions;
        int run = s;
        while (run > 0 && depth[run - 1] >= 0 && InDispatcher(code, run - 1) && graph.SameRegions(run - 1, s))
            run--;
        int start = Enumerable.Range(run, s - run + 1).FirstOrDefault(i => graph.BranchTargetSet.Contains(code[i]), -1);
        if (start < 0) return null;
        var loop = graph.ReachableFrom(s);
        var read = Enumerable.Range(start, s - start).Where(i => code[i].IsLdloc() || code[i].OpCode.Code is Code.Ldloca or Code.Ldloca_S)
            .Select(i => code[i].GetLocal(body.Variables)).ToHashSet();
        bool backEdge = false, state = false;
        for (int e = 0; e < code.Count; e++)
        {
            if (!loop[e] || depth[e] < 0) continue;
            if (code[e].IsStloc() && read.Contains(code[e].GetLocal(body.Variables)) && (e < start || e > s)) state = true;
            foreach (var t in BodyGraph.BranchTargets(code[e]))
            {
                int i = graph.IndexOf(t);
                if (i < start || i > s) continue;
                backEdge = true;
                if (depth[i] > 0) state = true;
            }
        }
        return backEdge && state ? start : null;
    }

    /// <summary>
    /// Whether code[i] may be part of a dispatcher that transitions bypass: it only computes (constants, loads and stores
    /// of locals, arithmetic, comparisons, conversions), so skipping it changes nothing but its locals. Division and
    /// remainder only by a constant that cannot make them throw.
    /// </summary>
    private static bool InDispatcher(IList<Instruction> code, int i)
    {
        var ins = code[i];
        var op = ins.OpCode.Code;
        if (op is Code.Div or Code.Div_Un or Code.Rem or Code.Rem_Un)
            return i > 0 && code[i - 1].IsLdcI4() && code[i - 1].GetLdcI4Value() is not (0 or -1);
        if (op is >= Code.Ldind_I1 and <= Code.Ldind_Ref) return i > 0 && code[i - 1].OpCode.Code is Code.Ldloca or Code.Ldloca_S;
        if (op is Code.Ldloca or Code.Ldloca_S) return i + 1 < code.Count && code[i + 1].OpCode.Code is >= Code.Ldind_I1 and <= Code.Ldind_Ref;
        return ins.IsLdcI4() || ins.IsLdloc() || ins.IsStloc() || ins.IsLdarg() || op is Code.Ldc_I8 or Code.Ldnull or Code.Nop or Code.Dup or Code.Pop
               || IsArithmetic(op) && !Throws(op);
    }

    /// <summary>
    /// Plans normalizing the dispatcher code[start..s] by analyzing it per state (<see cref="ConstantFlow.Dispatch"/>):
    /// its locals (the state, and what the dispatcher computes from it) must be tracked; every way into the dispatcher
    /// must select the same case on every run; and every read of those locals outside the dispatcher must read the same
    /// value on every run. Each way in then goes straight to its case (values passed on the stack are dropped), the reads
    /// become constants, and the dispatcher, no longer entered, is removed with the stores to its locals.
    /// </summary>
    private PerStatePlan? PlanPerState(CilBody body, BodyGraph graph, int[] depth, bool hasReturnValue, int start, int s, MethodMeter meter, out string? why)
    {
        why = null;
        var code = graph.Instructions;
        foreach (int k in DispatcherMembers(body, graph, depth, start, s))
        {
            if (RegionStartsAt(graph, code[k]))
            {
                why = "a protected region starts in the dispatcher";
                return null;
            }
        }
        var members = DispatcherMembers(body, graph, depth, start, s);
        // Ways in that no plan could rewrite are found before the (costly) analysis.
        for (int e = 0; e < code.Count; e++)
        {
            if (depth[e] < 0 || code[e].OpCode.FlowControl is not FlowControl.Cond_Branch and not FlowControl.Branch) continue;
            bool leave = code[e].OpCode.Code is Code.Leave or Code.Leave_S;
            foreach (var t in BodyGraph.BranchTargets(code[e]))
            {
                int to = graph.IndexOf(t);
                if (!members.Contains(to) || members.Contains(e) || depth[to] == 0) continue;
                if (leave)
                {
                    why = $"{At(code[e])} leaves into the dispatcher with values on the stack";
                    return null;
                }
                if (code[e].OpCode.FlowControl == FlowControl.Cond_Branch &&
                    (graph.Regions(e).Length > 0 || body.ExceptionHandlers.Any(h => h.HandlerEnd == null) || BodyGraph.FallsThrough(code[^1])))
                {
                    why = $"{At(code[e])} enters the dispatcher by a conditional branch with values on the stack inside a protected region";
                    return null;
                }
            }
        }
        var flow = new ConstantFlow(body, graph, hasReturnValue, _evaluator);
        var locals = new SortedSet<int>();
        foreach (int k in members)
        {
            var ins = code[k];
            var local = ins.IsLdloc() || ins.IsStloc() || ins.OpCode.Code is Code.Ldloca or Code.Ldloca_S ? ins.GetLocal(body.Variables) : null;
            if (local == null) continue;
            locals.Add(local.Index);
            if (flow.Tracks(local.Index)) continue;
            int taken = Enumerable.Range(0, code.Count).FirstOrDefault(i => code[i].OpCode.Code is Code.Ldloca or Code.Ldloca_S
                                                                             && code[i].GetLocal(body.Variables) == local && !flow.ReadAtOnce(i, local.Index), -1);
            why = taken >= 0 ? $"the address of the state local V_{local.Index} is taken at {At(code[taken])}"
                : IsIntegerLocal(local) ? $"the state local V_{local.Index} is written in a finally or fault handler"
                : $"the state local V_{local.Index} is not an integer";
            return null;
        }

        var result = flow.Dispatch(new ConstantFlow.Dispatcher(s, members, locals), meter);
        _evaluated.UnionWith(flow.Evaluated);
        if (result.Failure != null)
        {
            why = result.Failure;
            return null;
        }

        var plan = new PerStatePlan();
        foreach (var ((from, to), target) in result.Edges.OrderBy(e => e.Key))
        {
            int t = graph.IndexOf(target);
            int k = depth[to]; // values passed to the dispatcher on the stack
            var entered = code[to];
            if (from < 0)
            {
                // The method starts with the dispatcher.
                if (graph.Regions(to).Length > 0 || graph.Regions(t).Any(id => id % 3 != 0 || graph.Handlers[id / 3].TryStart != target))
                {
                    why = "the method starts with the dispatcher inside a protected region";
                    return null;
                }
                plan.Insert.Add((entered, [OpCodes.Br.ToInstruction(target)]));
                plan.Transitions++;
                continue;
            }
            var e = code[from];
            bool jumps = BodyGraph.BranchTargets(e).Contains(entered);
            bool falls = from + 1 == to && BodyGraph.FallsThrough(e);
            if (jumps && falls)
            {
                why = $"{At(e)} enters the dispatcher both by branching and by falling through";
                return null;
            }
            bool leave = e.OpCode.Code is Code.Leave or Code.Leave_S;
            if (!(leave ? graph.LeavesLegally(from, t) : graph.EntersLegally(from, t)))
            {
                why = $"the case that {At(e)} selects is in another protected region";
                return null;
            }

            if (falls || e.OpCode.Code is Code.Br or Code.Br_S)
            {
                // Values pushed for the dispatcher right before are deleted; otherwise popped.
                int last = falls ? from : from - 1;
                var drop = new List<Instruction>();
                if (RemovableRun(code, graph, last, k, mayThrow: false) is { } run)
                    plan.Dead.AddRange(code.Skip(run).Take(last - run + 1));
                else
                    drop.AddRange(Enumerable.Range(0, k).Select(_ => OpCodes.Pop.ToInstruction()));
                if (falls)
                {
                    drop.Add(OpCodes.Br.ToInstruction(target));
                    plan.Insert.Add((entered, drop.ToArray()));
                }
                else if (drop.Count == 0)
                {
                    plan.Retarget.Add((e, entered, target));
                }
                else
                {
                    // br dispatcher becomes pop...; br case.
                    plan.Replace.Add((e, OpCodes.Pop, null));
                    plan.Insert.Add((code[from + 1 < code.Count ? from + 1 : from], [.. drop.Skip(1), OpCodes.Br.ToInstruction(target)]));
                    if (from + 1 >= code.Count)
                    {
                        why = $"{At(e)} ends the body";
                        return null;
                    }
                }
            }
            else if (k == 0 || leave)
            {
                if (leave && k != 0)
                {
                    why = $"{At(e)} leaves into the dispatcher with values on the stack";
                    return null;
                }
                plan.Retarget.Add((e, entered, target));
            }
            else
            {
                // A conditional branch (or switch) that passes values: it branches to a stub that drops them.
                if (graph.Regions(from).Length > 0 || body.ExceptionHandlers.Any(h => h.HandlerEnd == null) ||
                    BodyGraph.FallsThrough(code[^1]))
                {
                    why = $"{At(e)} enters the dispatcher by a conditional branch with values on the stack inside a protected region";
                    return null;
                }
                var stub = Enumerable.Range(0, k).Select(_ => OpCodes.Pop.ToInstruction()).Append(OpCodes.Br.ToInstruction(target)).ToList();
                plan.Append.AddRange(stub);
                plan.Retarget.Add((e, entered, stub[0]));
            }
            plan.Transitions++;
        }

        foreach (var (index, value) in result.Reads)
        {
            if (Constant(value) is not { } constant)
            {
                why = $"the state read at {At(code[index])} is not a number";
                return null;
            }
            var read = code[index];
            if (read.IsLdloc()) plan.Replace.Add((read, constant.OpCode, constant.Operand));
            else
            {
                plan.Replace.Add((code[index - 1], constant.OpCode, constant.Operand)); // ldloca; ldind
                plan.Dead.Add(read);
            }
        }
        return plan.Transitions > 0 ? plan : null;
    }

    /// <summary>
    /// The dispatcher's code: code[start..s], and tails that only lead into it: straight-line code from a branch target
    /// on that only computes (<see cref="InDispatcher"/>) and ends with a br into the dispatcher, such as the
    /// <c>stloc state; br dispatcher</c> that <c>state = c ? a : b;</c> compiles to.
    /// </summary>
    private static HashSet<int> DispatcherMembers(CilBody body, BodyGraph graph, int[] depth, int start, int s)
    {
        var code = graph.Instructions;
        var members = Enumerable.Range(start, s - start + 1).ToHashSet();
        for (bool grew = true; grew;)
        {
            grew = false;
            for (int j = 0; j < code.Count; j++)
            {
                if (members.Contains(j) || depth[j] < 0 || code[j].OpCode.Code is not (Code.Br or Code.Br_S)) continue;
                if (!members.Contains(graph.IndexOf((Instruction)code[j].Operand)) || !graph.SameRegions(j, s)) continue;
                int run = j;
                while (run > 0 && depth[run - 1] >= 0 && InDispatcher(code, run - 1) && graph.SameRegions(run - 1, s) && !members.Contains(run - 1))
                    run--;
                int first = Enumerable.Range(run, j - run + 1).FirstOrDefault(i => graph.BranchTargetSet.Contains(code[i]), -1);
                if (first < 0 || first == j) continue; // entered only by falling through, or a plain br: an ordinary transition
                // A tail may only store the dispatcher's own locals: skipping it must not lose other stores.
                var own = members.Where(i => code[i].IsLdloc() || code[i].IsStloc()).Select(i => code[i].GetLocal(body.Variables)).ToHashSet();
                if (Enumerable.Range(first, j - first + 1).Any(i => code[i].IsStloc() && !own.Contains(code[i].GetLocal(body.Variables)))) continue;
                for (int i = first; i <= j; i++) members.Add(i);
                grew = true;
            }
        }
        return members;
    }

    private static bool IsIntegerLocal(Local local) => local.Type.RemovePinnedAndModifiers().ElementType is ElementType.I1 or ElementType.U1
        or ElementType.I2 or ElementType.U2 or ElementType.I4 or ElementType.U4 or ElementType.I8 or ElementType.U8 or ElementType.Boolean
        or ElementType.Char || local.Type.RemovePinnedAndModifiers().ToTypeDefOrRef()?.ResolveTypeDef() is { IsEnum: true };

    /// <summary>The instruction that pushes an int32 or int64 constant, or null for other values.</summary>
    private static Instruction? Constant(object? value) => value switch
    {
        int i => OpCodes.Ldc_I4.ToInstruction(i),
        long l => OpCodes.Ldc_I8.ToInstruction(l),
        _ => null,
    };

    private static void ApplyPerState(CilBody body, PerStatePlan plan, HashSet<Instruction> dead)
    {
        foreach (var (ins, op, operand) in plan.Replace)
        {
            ins.OpCode = op;
            ins.Operand = operand;
        }
        foreach (var ins in plan.Dead) MakeDead(ins, dead);
        foreach (var (branch, from, to) in plan.Retarget)
        {
            switch (branch.Operand)
            {
                case Instruction t when t == from:
                    branch.Operand = to;
                    break;
                case Instruction[] ts:
                    for (int k = 0; k < ts.Length; k++)
                        if (ts[k] == from) ts[k] = to;
                    break;
            }
        }
        foreach (var (before, code) in plan.Insert)
        {
            int at = body.Instructions.IndexOf(before);
            for (int k = 0; k < code.Length; k++) body.Instructions.Insert(at + k, code[k]);
        }
        foreach (var ins in plan.Append) body.Instructions.Add(ins);
    }

    private static bool RegionStartsAt(BodyGraph graph, Instruction ins) =>
        graph.Handlers.Any(eh => eh.TryStart == ins || eh.HandlerStart == ins || eh.FilterStart == ins);

    /// <summary>
    /// The store to the state local that code[last] is reached from by straight-line code that leaves the local alone
    /// (e.g. <c>state = 0; acc = x;</c> before the loop), or -1.
    /// </summary>
    private static int StateStore(IList<Instruction> code, BodyGraph graph, int last, Local state, CilBody body)
    {
        for (int k = last; k >= 0; k--)
        {
            if (IsStore(code[k], state, body)) return k;
            if (graph.Targets.Contains(code[k]) || code[k].OpCode.FlowControl is not (FlowControl.Next or FlowControl.Call)) return -1;
        }
        return -1;
    }

    private static bool IsStore(Instruction ins, Local local, CilBody body) => ins.IsStloc() && ins.GetLocal(body.Variables) == local;

    /// <summary>The int32 that code[start..end] pushes without calls, or null when it is not such a constant.</summary>
    private int? ConstantState(IList<Instruction> code, int start, int end)
    {
        for (int i = start; i <= end; i++)
            if (code[i].OpCode.FlowControl != FlowControl.Next) return null;
        try
        {
            return _evaluator.EvaluateSlice(code.Skip(start).Take(end - start + 1).ToList()) is [int value] ? value : null;
        }
        catch (EvaluationBailout)
        {
            return null;
        }
    }

    /// <summary>
    /// Removes handlers that can no longer run or do nothing: a finally that only ends; a catch, fault or filter whose
    /// try only leaves; a try that only leaves into its finally, whose body then runs inline. Leaves that no longer
    /// exit a region become plain branches.
    /// </summary>
    private static bool SimplifyTryRegions(CilBody body, HashSet<Instruction> dead, bool hasReturnValue, MethodChange change)
    {
        bool changed = false;
        for (int h = 0; h < body.ExceptionHandlers.Count; h++)
        {
            var graph = new BodyGraph(body);
            var depth = graph.Verify(hasReturnValue, out _);
            if (depth == null) return changed;
            var eh = body.ExceptionHandlers[h];
            var code = graph.Instructions;
            var tryCode = Range(graph, eh.TryStart, eh.TryEnd).Where(i => code[i].OpCode.Code != Code.Nop).ToList();
            var handlerCode = Range(graph, eh.HandlerStart, eh.HandlerEnd).Where(i => code[i].OpCode.Code != Code.Nop).ToList();

            bool emptyFinally = eh.HandlerType == ExceptionHandlerType.Finally &&
                                handlerCode.Count == 1 && code[handlerCode[0]].OpCode.Code == Code.Endfinally;
            bool onlyLeaves = tryCode.Count == 1 && code[tryCode[0]].OpCode.Code is Code.Leave or Code.Leave_S && depth[tryCode[0]] == 0;

            if (emptyFinally || (onlyLeaves && eh.HandlerType != ExceptionHandlerType.Finally))
            {
                body.ExceptionHandlers.RemoveAt(h--);
                change.RemovedHandlers++;
                changed = true;
                continue;
            }
            if (onlyLeaves && InlineFinally(graph, depth, h, tryCode[0], handlerCode, dead))
            {
                body.ExceptionHandlers.RemoveAt(h--);
                change.RemovedHandlers++;
                changed = true;
            }
        }

        // Leaves that do not exit any region (left over after removing handlers) are plain branches.
        var final = new BodyGraph(body);
        var depths = final.Verify(hasReturnValue, out _);
        if (depths == null) return changed;
        for (int i = 0; i < final.Instructions.Count; i++)
        {
            var ins = final.Instructions[i];
            if (ins.OpCode.Code is not (Code.Leave or Code.Leave_S) || depths[i] != 0) continue;
            if (!final.SameRegions(i, final.IndexOf((Instruction)ins.Operand))) continue;
            ins.OpCode = OpCodes.Br;
            changed = true;
        }
        return changed;
    }

    /// <summary>
    /// try { leave L } finally { F } with the finally right after the leave: the leave falls into F and F's own endfinally
    /// instructions branch to L.
    /// </summary>
    private static bool InlineFinally(BodyGraph graph, int[] depth, int h, int leave, List<int> handlerCode, HashSet<Instruction> dead)
    {
        var code = graph.Instructions;
        var eh = graph.Handlers[h];
        var target = (Instruction)code[leave].Operand;
        int handlerStart = graph.IndexOf(eh.HandlerStart);
        for (int k = leave + 1; k < handlerStart; k++)
            if (code[k].OpCode.Code != Code.Nop) return false;
        // L must be outside exactly this try: the leave's regions without the try.
        var expected = graph.Regions(leave).Where(id => id != h * 3).ToArray();
        if (!graph.Regions(graph.IndexOf(target)).AsSpan().SequenceEqual(expected)) return false;
        var ends = handlerCode.Where(i => code[i].OpCode.Code == Code.Endfinally && OwnEndfinally(graph, i, h)).ToList();
        if (ends.Any(i => depth[i] != 0)) return false;

        MakeDead(code[leave], dead);
        foreach (int i in ends)
        {
            code[i].OpCode = OpCodes.Br;
            code[i].Operand = target;
        }
        return true;
    }

    /// <summary>An endfinally inside handler h that does not belong to a finally nested in it.</summary>
    private static bool OwnEndfinally(BodyGraph graph, int index, int h)
    {
        int inner = graph.Regions(index).Count(id => id % 3 != 0);
        int own = graph.Regions(graph.IndexOf(graph.Handlers[h].HandlerStart)).Count(id => id % 3 != 0);
        return inner == own;
    }

    private static IEnumerable<int> Range(BodyGraph graph, Instruction? start, Instruction? end)
    {
        int from = start == null ? graph.Instructions.Count : graph.IndexOf(start);
        int to = graph.IndexOrEnd(end);
        for (int i = Math.Max(from, 0); i < to; i++) yield return i;
    }

    private static bool RemoveUnreachable(CilBody body, HashSet<Instruction> dead, MethodChange change)
    {
        var graph = new BodyGraph(body);
        var reached = graph.Reachable();
        if (reached.All(r => r)) return false;
        var code = body.Instructions;

        // Handlers whose try has no reachable code can never run.
        for (int h = body.ExceptionHandlers.Count - 1; h >= 0; h--)
        {
            var eh = body.ExceptionHandlers[h];
            if (!Range(graph, eh.TryStart, eh.TryEnd).Any(i => reached[i]))
            {
                body.ExceptionHandlers.RemoveAt(h);
                change.RemovedHandlers++;
            }
        }

        // Each removed instruction is replaced, as a branch target or boundary, by the next surviving one.
        var next = new Instruction?[code.Count];
        Instruction? following = null;
        for (int i = code.Count - 1; i >= 0; i--)
        {
            next[i] = following;
            if (reached[i]) following = code[i];
        }
        var replacement = new Dictionary<Instruction, Instruction?>();
        for (int i = 0; i < code.Count; i++)
            if (!reached[i]) replacement[code[i]] = next[i];
        Redirect(body, replacement);

        bool inBlock = false;
        for (int i = 0; i < code.Count; i++)
        {
            bool removed = !reached[i] && !dead.Contains(code[i]);
            if (removed) change.RemovedInstructions++;
            if (removed && !inBlock) change.RemovedBlocks++;
            inBlock = removed || (inBlock && !reached[i]);
        }
        var survivors = code.Where((_, i) => reached[i]).ToList();
        code.Clear();
        foreach (var ins in survivors) code.Add(ins);
        dead.IntersectWith(survivors);
        return true;
    }

    /// <summary>
    /// An unconditional branch to the next instruction does nothing; a conditional one only consumes its operands and
    /// becomes pops. (A conditional branch whose target is also its fall-through crashes the .NET 10 JIT when that
    /// instruction starts nested try regions, so it must not be left behind. The IL is valid: this is a runtime-level
    /// issue; minimal repro in docs/known-issues.md, fixture SimplifyRegressionTests.ConditionalBranchToNextBecomesPops.)
    /// </summary>
    private static bool DropBranchesToNext(CilBody body, HashSet<Instruction> dead)
    {
        var code = body.Instructions;
        bool changed = false;
        for (int i = 0; i + 1 < code.Count; i++)
        {
            var ins = code[i];
            if (ins.Operand != code[i + 1] || dead.Contains(ins)) continue;
            if (ins.OpCode.Code is Code.Br or Code.Br_S)
            {
                MakeDead(ins, dead);
                changed = true;
            }
            else if (ins.OpCode.FlowControl == FlowControl.Cond_Branch)
            {
                ins.CalculateStackUsage(false, out _, out int pops);
                ins.OpCode = OpCodes.Pop;
                ins.Operand = null;
                for (int k = 1; k < pops; k++) code.Insert(i + 1, OpCodes.Pop.ToInstruction());
                changed = true;
            }
        }
        return changed;
    }

    /// <summary>
    /// A pop of a value computed right before it without effects (what folding leaves behind, see
    /// <see cref="RemovableRun"/>; nothing that may throw) is deleted with that computation. So is a pop of a constant or
    /// a load of a local or argument pushed earlier in the same straight-line code, below values the code in between
    /// pushes and pops itself (<c>ldc.i4 N; ldsfld S; ldfld F; pop; pop</c>, around a load kept for its effect): the
    /// code in between does not see it.
    /// </summary>
    private bool RemovePurePops(CilBody body, HashSet<Instruction> dead)
    {
        var code = body.Instructions;
        BodyGraph? graph = null;
        bool changed = false;
        for (int i = 1; i < code.Count; i++)
        {
            var pop = code[i];
            if (pop.OpCode.Code != Code.Pop || dead.Contains(pop)) continue;
            graph ??= new BodyGraph(body);
            if (graph.Targets.Contains(pop)) continue;
            if (RemovableRun(code, graph, i - 1, 1, mayThrow: false) is { } start)
            {
                if (Enumerable.Range(start, i - start).Any(k => dead.Contains(code[k]))) continue;
                for (int k = start; k <= i; k++) MakeDead(code[k], dead);
                changed = true;
                continue;
            }
            int producer = Producer(code, graph.Targets, i, 0);
            if (producer < 0 || producer == i - 1 || dead.Contains(code[producer])) continue;
            var pushed = code[producer];
            if (!(pushed.IsLdcI4() || pushed.IsLdloc() || pushed.IsLdarg() || pushed.OpCode.Code is Code.Ldc_I8 or Code.Ldc_R4 or Code.Ldc_R8 or Code.Ldnull or Code.Ldstr)) continue;
            MakeDead(pushed, dead);
            MakeDead(pop, dead);
            changed = true;
        }
        return changed;
    }

    /// <summary>
    /// A load kept only for what it may do (<c>ldsfld S; ldfld F; pop</c>: run S's type initializer, throw on a null
    /// receiver) does nothing when the same load has run before it: its pop dominates this one (every path from the entry,
    /// exception edges included, passes it) and the receivers cannot have changed in between. The root is an argument
    /// never stored to nor taken the address of (not a struct's 'this'), or a static field that only its type's
    /// initialization writes, read outside that initialization (or with no field after it: then only the initializer
    /// matters, and it has run); the fields between root and the last one are readonly, outside constructors.
    /// </summary>
    private bool RemoveRepeatedLoads(MethodDef method, CilBody body, HashSet<Instruction> dead, MethodChange change)
    {
        var code = body.Instructions;
        BodyGraph? graph = null;
        var loads = new List<(int Start, int Pop, string Key)>();
        for (int i = 1; i < code.Count; i++)
        {
            if (code[i].OpCode.Code != Code.Pop || dead.Contains(code[i])) continue;
            int k = i - 1;
            while (k >= 0 && code[k].OpCode.Code == Code.Ldfld) k--;
            if (k < 0 || dead.Contains(code[k])) continue;
            var root = code[k];
            graph ??= new BodyGraph(body);
            if (Enumerable.Range(k + 1, i - k).Any(j => graph.Targets.Contains(code[j]))) continue;
            if (!StableRoot(method, body, root, hasFields: i - k > 1)) continue;
            bool stable = true;
            for (int j = k + 1; j < i - 1 && stable; j++)
                stable = MetadataUtil.AsField(code[j].Operand) is { } f && f.ResolveFieldDef() is { IsInitOnly: true } fd &&
                         !(method.IsConstructor && method.DeclaringType == fd.DeclaringType);
            if (!stable) continue;
            var key = string.Join(" ", code.Skip(k).Take(i - k).Select(x => x.OpCode.Code == Code.Ldfld || x.OpCode.Code == Code.Ldsfld
                ? $"{x.OpCode.Code} {MetadataUtil.AsField(x.Operand)?.FullName}"
                : $"arg {x.GetParameterIndex()}"));
            loads.Add((k, i, key));
        }
        bool changed = false;
        foreach (var group in loads.GroupBy(l => l.Key).Where(g => g.Count() > 1))
        {
            var members = group.ToList();
            var kept = new List<(int Start, int Pop, string Key)>();
            foreach (var load in members)
            {
                if (kept.Any(earlier => Dominates(body, code[earlier.Pop], code[load.Start])))
                {
                    for (int j = load.Start; j <= load.Pop; j++) MakeDead(code[j], dead);
                    change.RemovedLoads++;
                    changed = true;
                }
                else
                {
                    kept.Add(load);
                }
            }
        }
        return changed;
    }

    private bool StableRoot(MethodDef method, CilBody body, Instruction root, bool hasFields)
    {
        if (root.OpCode.Code == Code.Ldsfld)
        {
            if (root.Operand is not FieldDef field) return !hasFields && MetadataUtil.AsField(root.Operand) != null;
            return !hasFields || _evaluator.StableStatic(field, method);
        }
        if (!root.IsLdarg() || !hasFields) return false;
        int index = root.GetParameterIndex();
        if (index < 0 || index >= method.Parameters.Count) return false;
        var parameter = method.Parameters[index];
        if (parameter.IsHiddenThisParameter ? method.DeclaringType.IsValueType : parameter.Type.RemovePinnedAndModifiers().IsByRef) return false;
        return !body.Instructions.Any(ins => (ins.IsStarg() || ins.OpCode.Code is Code.Ldarga or Code.Ldarga_S) && ins.GetParameterIndex() == index);
    }

    /// <summary>
    /// Whether every path from the entry to <paramref name="to"/> passes <paramref name="from"/>: with it taken out,
    /// <paramref name="to"/> is unreachable. Edges: fall-through, branches, from each instruction of a protected region
    /// to its handler (or filter), from endfinally to every leave target.
    /// </summary>
    private static bool Dominates(CilBody body, Instruction from, Instruction to)
    {
        var code = body.Instructions;
        var index = new Dictionary<Instruction, int>(code.Count);
        for (int i = 0; i < code.Count; i++) index[code[i]] = i;
        int At(Instruction? i) => i == null ? code.Count : index.TryGetValue(i, out int k) ? k : code.Count;
        int blocked = At(from), target = At(to);
        if (blocked == target) return false;
        var leaveTargets = code.Where(i => i.OpCode.Code is Code.Leave or Code.Leave_S && i.Operand is Instruction).Select(i => At((Instruction)i.Operand)).ToList();
        var seen = new bool[code.Count];
        var work = new Stack<int>();
        work.Push(0);
        while (work.Count > 0)
        {
            int k = work.Pop();
            if (k >= code.Count || k == blocked || seen[k]) continue;
            if (k == target) return false;
            seen[k] = true;
            var ins = code[k];
            switch (ins.OpCode.FlowControl)
            {
                case FlowControl.Branch:
                    if (ins.Operand is Instruction t) work.Push(At(t));
                    break;
                case FlowControl.Cond_Branch:
                    work.Push(k + 1);
                    if (ins.Operand is Instruction c) work.Push(At(c));
                    else if (ins.Operand is IList<Instruction> cases) foreach (var c2 in cases) work.Push(At(c2));
                    break;
                case FlowControl.Return or FlowControl.Throw:
                    if (ins.OpCode.Code is Code.Endfinally) foreach (var l in leaveTargets) work.Push(l);
                    break;
                default:
                    work.Push(k + 1);
                    break;
            }
            foreach (var eh in body.ExceptionHandlers)
                if (k >= At(eh.TryStart) && k < At(eh.TryEnd)) work.Push(At(eh.FilterStart ?? eh.HandlerStart));
        }
        return true;
    }

    private static void MakeDead(Instruction ins, HashSet<Instruction> dead)
    {
        ins.OpCode = OpCodes.Nop;
        ins.Operand = null;
        dead.Add(ins);
    }

    /// <summary>Deletes the nops the passes created, moving branch targets and boundaries on them to the next instruction.</summary>
    private static bool RemoveNops(CilBody body, HashSet<Instruction> dead)
    {
        var code = body.Instructions;
        if (!code.Any(dead.Contains)) return false;
        var replacement = new Dictionary<Instruction, Instruction?>();
        Instruction? following = null;
        for (int i = code.Count - 1; i >= 0; i--)
        {
            if (dead.Contains(code[i])) replacement[code[i]] = following;
            else following = code[i];
        }
        // A nop at the very end that something branches to has no successor to stand for it.
        var branchTargets = code.SelectMany(BodyGraph.BranchTargets).ToHashSet();
        foreach (var (nop, next) in replacement.ToList())
            if (next == null && branchTargets.Contains(nop)) replacement.Remove(nop);
        if (replacement.Count == 0) return false;

        Redirect(body, replacement);
        var survivors = code.Where(i => !replacement.ContainsKey(i)).ToList();
        code.Clear();
        foreach (var ins in survivors) code.Add(ins);
        dead.ExceptWith(replacement.Keys);

        // A try that lost all its instructions is empty: drop the handler (its code becomes unreachable).
        for (int h = body.ExceptionHandlers.Count - 1; h >= 0; h--)
        {
            var eh = body.ExceptionHandlers[h];
            if (eh.TryStart == null || eh.TryStart == eh.TryEnd || eh.HandlerStart == null || eh.HandlerStart == eh.HandlerEnd)
                body.ExceptionHandlers.RemoveAt(h);
        }
        return true;
    }

    private static void Redirect(CilBody body, Dictionary<Instruction, Instruction?> replacement)
    {
        Instruction? Map(Instruction? i) => i != null && replacement.TryGetValue(i, out var r) ? r : i;
        foreach (var ins in body.Instructions)
        {
            if (replacement.ContainsKey(ins)) continue;
            switch (ins.Operand)
            {
                case Instruction t:
                    ins.Operand = Map(t);
                    break;
                case Instruction[] ts:
                    for (int k = 0; k < ts.Length; k++) ts[k] = Map(ts[k])!;
                    break;
            }
        }
        foreach (var eh in body.ExceptionHandlers)
        {
            eh.TryStart = Map(eh.TryStart);
            eh.TryEnd = Map(eh.TryEnd);
            eh.FilterStart = Map(eh.FilterStart);
            eh.HandlerStart = Map(eh.HandlerStart);
            eh.HandlerEnd = Map(eh.HandlerEnd);
        }
    }

    internal static string Describe(IMethod m) => IlEvaluator.Describe(m);
}
