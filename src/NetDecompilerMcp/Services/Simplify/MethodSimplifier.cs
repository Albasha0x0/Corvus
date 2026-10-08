using dnlib.DotNet;
using dnlib.DotNet.Emit;
using NetDecompilerMcp.Core;

namespace NetDecompilerMcp.Services.Simplify;

/// <summary>Which passes run, and the evaluator limits.</summary>
public sealed record SimplifyOptions(bool Fold = true, bool ControlFlow = true, bool Forwarders = true, EvaluationLimits? Limits = null)
{
    public EvaluationLimits EffectiveLimits => Limits ?? new EvaluationLimits();

    public static readonly IReadOnlyList<string> PassNames = ["fold", "cfg", "inline"];

    /// <summary>Parses a comma-separated pass list (fold, cfg, inline; "all" or empty for every pass).</summary>
    public static SimplifyOptions Parse(string? passes, int? maxDepth, int? budget)
    {
        var limits = new EvaluationLimits(Math.Clamp(maxDepth ?? 8, 1, 64), Math.Clamp(budget ?? 100_000, 100, 10_000_000));
        var names = (passes ?? "").Split([',', ' ', ';'], StringSplitOptions.RemoveEmptyEntries).Select(p => p.ToLowerInvariant()).ToList();
        if (names.Count == 0 || names.Contains("all")) return new SimplifyOptions(Limits: limits);
        var unknown = names.Except(PassNames).ToList();
        if (unknown.Count > 0)
            throw new ToolError($"Unknown pass '{unknown[0]}'. Passes: fold (evaluate string-producing calls), cfg (control-flow cleanup), inline (forwarder inlining), or all.");
        return new SimplifyOptions(names.Contains("fold"), names.Contains("cfg"), names.Contains("inline"), limits);
    }

    public string Describe() => string.Join(",", PassNames.Where((_, i) => new[] { Fold, ControlFlow, Forwarders }[i]));
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
    /// <summary>Calls of the module's own helpers that could not be evaluated (the call is kept).</summary>
    public List<Fallback> Bailouts { get; } = new();
    public int ConstantBranches { get; set; }
    public int CollapsedChains { get; set; }
    public int RemovedBlocks { get; set; }
    public int RemovedInstructions { get; set; }
    public int RemovedHandlers { get; set; }
    public int InstructionsBefore { get; set; }
    public int InstructionsAfter { get; set; }
    public CilBody? NewBody { get; set; }
    /// <summary>Why the method was left unchanged as a whole (it did not verify before or after, it took too long, or an error).</summary>
    public Fallback? Rejected { get; set; }

    public bool Changed => NewBody != null;

    public bool HasEffects => Folded.Count + Inlined.Count + ConstantBranches + CollapsedChains + RemovedBlocks + RemovedHandlers > 0;
}

/// <summary>
/// Compiler-style simplification of method bodies, on copies (the methods are not touched; callers assign
/// <see cref="MethodChange.NewBody"/>):
/// <list type="number">
/// <item>inline: call sites of forwarder methods (bodies that only pass their arguments on to another method) call the target directly;</item>
/// <item>fold: calls producing a string from constant inputs are evaluated with <see cref="IlEvaluator"/> and replaced by ldstr;</item>
/// <item>cfg: branches on constant conditions are folded, branch-to-branch chains collapsed, empty try regions and handlers
/// removed, and unreachable code deleted.</item>
/// </list>
/// Every rewritten body must pass <see cref="BodyGraph.Verify"/>; otherwise the method is reported and left unchanged.
/// </summary>
public sealed class MethodSimplifier
{
    private readonly ModuleDef _module;
    private readonly SimplifyOptions _options;
    private readonly IlEvaluator _evaluator;
    private readonly Forwarders _forwarders;

    public MethodSimplifier(ModuleDef module, SimplifyOptions options)
    {
        _module = module;
        _options = options;
        _evaluator = new IlEvaluator(module, options.EffectiveLimits);
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
        var dead = new HashSet<Instruction>(); // instructions turned into nops by the passes; removed at the end
        if (_options.Forwarders) InlineForwarders(method, body, change);
        if (_options.Fold) FoldStringCalls(body, dead, change);
        if (_options.ControlFlow)
        {
            for (int round = 0; round < 16; round++)
            {
                meter.CheckTime();
                bool changed = FoldBranches(body, dead, change);
                changed |= RemoveNops(body, dead);
                changed |= CollapseChains(body, change);
                changed |= SimplifyTryRegions(body, dead, hasReturnValue, change);
                changed |= RemoveNops(body, dead);
                changed |= RemoveUnreachable(body, dead, change);
                changed |= DropBranchesToNext(body, dead);
                changed |= RemoveNops(body, dead);
                if (!changed) break;
            }
        }
        RemoveNops(body, dead);
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
                var stack = _evaluator.EvaluateSlice(code.Skip(start.Value).Take(j - start.Value + 1).ToList());
                if (stack.Count != 1 || stack[0] is not (string or null)) continue;
                value = stack[0];
            }
            catch (EvaluationBailout ex)
            {
                // Reported for the assembly's own helpers; framework calls that cannot be evaluated are expected.
                if (callee is MethodDef def && def.Module == _module)
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
        : callee.MethodSig?.RetType.RemovePinnedAndModifiers().ElementType == ElementType.String;

    /// <summary>
    /// Start of the shortest run of instructions ending before <paramref name="end"/> that pushes the
    /// <paramref name="needed"/> operands of code[end] from an empty stack, without branches, arguments, locals or
    /// incoming branches in between; null when there is none.
    /// </summary>
    private static int? SliceStart(IList<Instruction> code, BodyGraph graph, int end, int needed)
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
            if (graph.Targets.Contains(code[k])) return null;
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
                var operands = _evaluator.EvaluateSlice(code.Skip(start.Value).Take(j - start.Value).ToList());
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

    /// <summary>An unconditional branch to the next instruction does nothing.</summary>
    private static bool DropBranchesToNext(CilBody body, HashSet<Instruction> dead)
    {
        var code = body.Instructions;
        bool changed = false;
        for (int i = 0; i + 1 < code.Count; i++)
        {
            var ins = code[i];
            if (ins.OpCode.Code is Code.Br or Code.Br_S && ins.Operand == code[i + 1] && !dead.Contains(ins))
            {
                MakeDead(ins, dead);
                changed = true;
            }
        }
        return changed;
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
