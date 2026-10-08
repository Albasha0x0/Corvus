using dnlib.DotNet.Emit;

namespace NetDecompilerMcp.Services.Simplify;

/// <summary>
/// Structural view of a method body: instruction indexes, branch targets, protected-region membership, reachability
/// and a stack verifier. A snapshot: rebuild it after the body changes.
/// </summary>
internal sealed class BodyGraph
{
    public IList<Instruction> Instructions { get; }
    public IList<ExceptionHandler> Handlers { get; }
    private readonly Dictionary<Instruction, int> _index;
    private readonly int[][] _regions;

    public BodyGraph(CilBody body)
    {
        Instructions = body.Instructions;
        Handlers = body.ExceptionHandlers;
        _index = new Dictionary<Instruction, int>(Instructions.Count);
        for (int i = 0; i < Instructions.Count; i++) _index[Instructions[i]] = i;

        Targets = new HashSet<Instruction>();
        foreach (var ins in Instructions)
            foreach (var t in BranchTargets(ins))
                Targets.Add(t);
        foreach (var eh in Handlers)
            foreach (var b in new[] { eh.TryStart, eh.TryEnd, eh.HandlerStart, eh.HandlerEnd, eh.FilterStart })
                if (b != null) Targets.Add(b);

        // Region ids: handler index * 3 + 0 (try), 1 (handler), 2 (filter).
        var regions = new List<int>[Instructions.Count];
        for (int i = 0; i < Instructions.Count; i++) regions[i] = new List<int>();
        for (int h = 0; h < Handlers.Count; h++)
        {
            var eh = Handlers[h];
            Mark(regions, eh.TryStart, eh.TryEnd, h * 3);
            Mark(regions, eh.HandlerStart, eh.HandlerEnd, h * 3 + 1);
            if (eh.FilterStart != null) Mark(regions, eh.FilterStart, eh.HandlerStart, h * 3 + 2);
        }
        _regions = regions.Select(r => r.ToArray()).ToArray();
    }

    private void Mark(List<int>[] regions, Instruction? start, Instruction? end, int id)
    {
        if (start == null || !_index.TryGetValue(start, out int from)) return;
        int to = IndexOrEnd(end);
        for (int i = from; i < to; i++) regions[i].Add(id);
    }

    /// <summary>Branch targets and protected-region boundaries.</summary>
    public HashSet<Instruction> Targets { get; }

    public int IndexOf(Instruction ins) => _index.TryGetValue(ins, out int i) ? i : -1;

    public int IndexOrEnd(Instruction? ins) => ins == null ? Instructions.Count : _index.TryGetValue(ins, out int i) ? i : Instructions.Count;

    /// <summary>Ids of the protected regions (try, handler, filter) containing the instruction, ascending.</summary>
    public int[] Regions(int index) => index < _regions.Length ? _regions[index] : [];

    public bool SameRegions(int a, int b) => Regions(a).AsSpan().SequenceEqual(Regions(b));

    /// <summary>Whether the instruction lies inside the handler (or filter) of handler <paramref name="h"/>.</summary>
    public bool InHandlerOf(int index, int h) => Regions(index).Contains(h * 3 + 1) || Regions(index).Contains(h * 3 + 2);

    public static IEnumerable<Instruction> BranchTargets(Instruction ins) => ins.Operand switch
    {
        Instruction t => [t],
        IList<Instruction> ts => ts,
        _ => [],
    };

    public static bool FallsThrough(Instruction ins) =>
        ins.OpCode.FlowControl is FlowControl.Next or FlowControl.Call or FlowControl.Cond_Branch or FlowControl.Meta or FlowControl.Break
        && ins.OpCode.Code != Code.Jmp;

    /// <summary>Instructions reachable from the entry, or from the handlers of a try with reachable code.</summary>
    public bool[] Reachable()
    {
        var reached = new bool[Instructions.Count];
        var work = new Stack<int>();
        void Visit(int i)
        {
            if (i >= 0 && i < reached.Length && !reached[i]) { reached[i] = true; work.Push(i); }
        }

        if (Instructions.Count > 0) Visit(0);
        var pending = Handlers.ToList();
        while (true)
        {
            while (work.Count > 0)
            {
                int i = work.Pop();
                var ins = Instructions[i];
                foreach (var t in BranchTargets(ins)) Visit(IndexOf(t));
                if (FallsThrough(ins)) Visit(i + 1);
            }
            var entered = pending.Where(eh => AnyReached(reached, eh.TryStart, eh.TryEnd)).ToList();
            if (entered.Count == 0) return reached;
            foreach (var eh in entered)
            {
                pending.Remove(eh);
                Visit(IndexOf(eh.HandlerStart));
                if (eh.FilterStart != null) Visit(IndexOf(eh.FilterStart));
            }
        }
    }

    /// <summary>Instructions reachable from code[start] by branches and fall-through (exceptions not followed).</summary>
    public bool[] ReachableFrom(int start)
    {
        var reached = new bool[Instructions.Count];
        var work = new Stack<int>();
        void Visit(int i)
        {
            if (i >= 0 && i < reached.Length && !reached[i]) { reached[i] = true; work.Push(i); }
        }

        Visit(start);
        while (work.Count > 0)
        {
            int i = work.Pop();
            foreach (var t in BranchTargets(Instructions[i])) Visit(IndexOf(t));
            if (FallsThrough(Instructions[i])) Visit(i + 1);
        }
        return reached;
    }

    private bool AnyReached(bool[] reached, Instruction start, Instruction? end)
    {
        int from = IndexOf(start), to = IndexOrEnd(end);
        for (int i = Math.Max(from, 0); i < to; i++)
            if (reached[i]) return true;
        return false;
    }

    /// <summary>
    /// Checks structural validity: operands and boundaries inside the body, consistent stack depths at every merge point,
    /// no underflow, ret on the right depth outside protected regions, no fall-through off the end or across region
    /// boundaries, and branches that stay within their regions (leave may exit them). Returns the stack depth before
    /// each instruction (-1: unreachable) or null with <paramref name="error"/> set.
    /// </summary>
    public int[]? Verify(bool hasReturnValue, out string? error)
    {
        (var depth, error) = Check(hasReturnValue);
        return depth;
    }

    private (int[]? Depth, string? Error) Check(bool hasReturnValue)
    {
        string? error = null;
        string Where(int i) => $"IL_{Instructions[i].Offset:X4}";
        foreach (var ins in Instructions)
            foreach (var t in BranchTargets(ins))
                if (IndexOf(t) < 0) { error = $"branch target outside the body ({ins})"; return (null, error); }
        foreach (var eh in Handlers)
        {
            if (eh.TryStart == null || eh.HandlerStart == null || IndexOf(eh.TryStart) < 0 || IndexOf(eh.HandlerStart) < 0 ||
                (eh.TryEnd != null && IndexOf(eh.TryEnd) < 0) || (eh.HandlerEnd != null && IndexOf(eh.HandlerEnd) < 0) ||
                (eh.HandlerType == ExceptionHandlerType.Filter && (eh.FilterStart == null || IndexOf(eh.FilterStart) < 0)))
            { error = "exception handler boundary outside the body"; return (null, error); }
            if (IndexOf(eh.TryStart) >= IndexOrEnd(eh.TryEnd) || IndexOf(eh.HandlerStart) >= IndexOrEnd(eh.HandlerEnd))
            { error = "empty protected region"; return (null, error); }
        }

        var depth = Enumerable.Repeat(-1, Instructions.Count).ToArray();
        var work = new Stack<int>();
        bool Flow(int to, int d, int from)
        {
            if (to >= Instructions.Count) { error = $"execution falls off the end after {Where(from)}"; return false; }
            if (depth[to] == -1) { depth[to] = d; work.Push(to); return true; }
            if (depth[to] == d) return true;
            error = $"inconsistent stack depth at {Where(to)} ({depth[to]} vs {d})";
            return false;
        }
        if (Instructions.Count == 0) { error = "empty body"; return (null, error); }
        if (!Flow(0, 0, 0)) return (null, error);
        foreach (var eh in Handlers)
        {
            int handlerDepth = eh.HandlerType is ExceptionHandlerType.Catch or ExceptionHandlerType.Filter ? 1 : 0;
            if (!Flow(IndexOf(eh.HandlerStart), handlerDepth, 0)) return (null, error);
            if (eh.FilterStart != null && !Flow(IndexOf(eh.FilterStart), 1, 0)) return (null, error);
        }

        while (work.Count > 0)
        {
            int i = work.Pop();
            var ins = Instructions[i];
            int d = depth[i];
            ins.CalculateStackUsage(hasReturnValue, out int pushes, out int pops);
            if (pops >= 0 && d < pops) { error = $"stack underflow at {Where(i)}"; return (null, error); }
            int after = pops < 0 ? 0 : d - pops + pushes;

            switch (ins.OpCode.Code)
            {
                case Code.Ret:
                    if (d != pops) { error = $"ret with stack depth {d} at {Where(i)}"; return (null, error); }
                    if (Regions(i).Length > 0) { error = $"ret inside a protected region at {Where(i)}"; return (null, error); }
                    continue;
                case Code.Leave: case Code.Leave_S:
                {
                    int t = IndexOf((Instruction)ins.Operand);
                    if (!Regions(t).All(Regions(i).Contains)) { error = $"leave enters a protected region at {Where(i)}"; return (null, error); }
                    if (!Flow(t, 0, i)) return (null, error);
                    continue;
                }
            }

            foreach (var target in BranchTargets(ins))
            {
                int t = IndexOf(target);
                if (!EntersLegally(i, t)) { error = $"branch crosses a protected region boundary at {Where(i)}"; return (null, error); }
                if (!Flow(t, after, i)) return (null, error);
            }
            if (FallsThrough(ins))
            {
                if (i + 1 < Instructions.Count && !EntersLegally(i, i + 1)) { error = $"execution falls across a protected region boundary after {Where(i)}"; return (null, error); }
                if (!Flow(i + 1, after, i)) return (null, error);
            }
        }
        return (depth, null);
    }

    /// <summary>Plain control transfer from one instruction to another: same regions, or entering trys at their first instruction.</summary>
    private bool EntersLegally(int from, int to)
    {
        if (SameRegions(from, to)) return true;
        var source = Regions(from);
        var target = Regions(to);
        if (!source.All(target.Contains)) return false;
        foreach (int id in target.Except(source))
        {
            if (id % 3 != 0) return false; // only try blocks may be entered
            if (Handlers[id / 3].TryStart != Instructions[to]) return false;
        }
        return true;
    }

    /// <summary>Deep copy: new instructions with remapped branch operands and handler boundaries; locals are shared.</summary>
    public static CilBody Clone(CilBody body)
    {
        var map = new Dictionary<Instruction, Instruction>(body.Instructions.Count);
        var instructions = new List<Instruction>(body.Instructions.Count);
        foreach (var ins in body.Instructions)
        {
            var copy = new Instruction(ins.OpCode, ins.Operand) { Offset = ins.Offset, SequencePoint = ins.SequencePoint };
            map[ins] = copy;
            instructions.Add(copy);
        }
        Instruction? Map(Instruction? i) => i == null ? null : map.TryGetValue(i, out var m) ? m : i;
        foreach (var ins in instructions)
        {
            ins.Operand = ins.Operand switch
            {
                Instruction t => Map(t),
                IList<Instruction> ts => ts.Select(t => Map(t)!).ToArray(),
                var other => other,
            };
        }
        var handlers = body.ExceptionHandlers.Select(eh => new ExceptionHandler(eh.HandlerType)
        {
            TryStart = Map(eh.TryStart),
            TryEnd = Map(eh.TryEnd),
            FilterStart = Map(eh.FilterStart),
            HandlerStart = Map(eh.HandlerStart),
            HandlerEnd = Map(eh.HandlerEnd),
            CatchType = eh.CatchType,
        }).ToList();
        return new CilBody(body.InitLocals, instructions, handlers, body.Variables.ToList())
        {
            MaxStack = body.MaxStack,
            LocalVarSigTok = body.LocalVarSigTok,
        };
    }
}
