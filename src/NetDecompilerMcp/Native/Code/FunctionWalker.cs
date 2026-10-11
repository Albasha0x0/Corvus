namespace NetDecompilerMcp.Native.Code;

/// <summary>What one walk of a function found: its code extents, cross-references and whether it can return.</summary>
internal sealed class WalkResult
{
    public uint[] RangeStarts = [];
    public uint[] RangeEnds = [];
    public CodeXref[] Xrefs = [];
    /// <summary>Functions it calls or tail-calls (local starts only).</summary>
    public uint[] Callees = [];
    /// <summary>Function starts the code runs into without a branch.</summary>
    public uint[] FallsInto = [];
    public bool Returns;
    public FunctionFlags Flags;
    public int Instructions;
    public int Blocks;
    public FunctionGraph? Graph;
}

/// <summary>
/// Recursive descent over one function given the known function starts: follows jumps, conditional jumps and
/// resolved switches, stops at returns, traps, noreturn calls, tail calls and other functions' starts. Optionally
/// builds the basic blocks and edges. One instance per thread; scratch collections are reused.
/// </summary>
internal sealed class FunctionWalker
{
    private enum RunEnd : byte { FallThrough, Jump, Return, Switch, IndirectJump, TailCall, NoReturnCall, Trap, Invalid, FunctionBoundary, EndOfCode, Truncated }

    private struct Run
    {
        public uint Start, End;
        public int FirstInsn, InsnCount;
        public RunEnd EndKind;
    }

    private readonly CodeContext _ctx;
    private readonly ICodeDecoder _dec;
    private readonly HashSet<uint> _visited = [];
    private readonly List<uint> _insns = [];
    private readonly List<byte> _lengths = [];
    private readonly List<Run> _runs = [];
    private readonly HashSet<uint> _leaders = [];
    private readonly Stack<(uint Rva, IndexBound Bound)> _work = new();
    private readonly List<CodeXref> _xrefs = [];
    private readonly HashSet<uint> _callees = [];
    private readonly List<(uint Insn, uint To, EdgeKind Kind)> _branches = [];
    private readonly HashSet<uint> _conditionals = [];
    private readonly List<SwitchTable> _switches = [];
    private readonly List<UnresolvedJump> _unresolved = [];
    private readonly List<uint> _tails = [];
    private readonly List<uint> _fallsInto = [];
    /// <summary>Unresolved indirect jumps that a later path with a known bound may still resolve, and their runs.</summary>
    private readonly SortedSet<uint> _pending = [];
    private readonly Dictionary<uint, int> _pendingRun = [];
    /// <summary>ARM32: some return is conditional (the run goes on after it).</summary>
    private bool _conditionalReturn;

    public FunctionWalker(CodeContext ctx)
    {
        _ctx = ctx;
        _dec = ctx.NewDecoder(computeAccess: true);
    }

    /// <param name="chunks">
    /// Further roots of the same function (exception funclets and handlers), walked after its body, each with its own
    /// .pdata ranges when it has them; code shared with the body is decoded once.
    /// </param>
    public WalkResult Walk(NativeFunction? function, uint start, bool buildGraph, CancellationToken ct, IReadOnlyList<uint>? chunks = null)
    {
        _visited.Clear(); _insns.Clear(); _lengths.Clear(); _runs.Clear(); _leaders.Clear(); _work.Clear(); _xrefs.Clear(); _callees.Clear();
        _branches.Clear(); _conditionals.Clear(); _switches.Clear(); _unresolved.Clear(); _tails.Clear(); _fallsInto.Clear(); _pending.Clear(); _pendingRun.Clear();
        var result = new WalkResult();
        _conditionalReturn = false;
        _dec.BeginFunction(start);
        // chained .pdata fragments only say which jumps stay inside the function: a fragment can begin with data
        // (a switch table), so fragments are reached by flow, never decoded from their begin
        var bodyOwn = _ctx.PdataRanges.GetValueOrDefault(start);
        var own = bodyOwn;
        uint root = start;
        int nextChunk = 0;
        Push(start, IndexBound.None);
        int cap = _ctx.Options.MaxInstructionsPerFunction;
        int checkCounter = 0;

        while (true)
        {
            if (_work.Count == 0)
            {
                if (chunks == null || nextChunk >= chunks.Count) break;
                root = chunks[nextChunk++];
                own = _ctx.PdataRanges.GetValueOrDefault(root) ?? bodyOwn;
                Push(root, IndexBound.None);
                continue;
            }
            var (a, bound) = _work.Pop();
            if (_visited.Contains(a))
            {
                if (bound.IsKnown && _pending.Count > 0) RetrySwitches(a, bound, own);
                continue;
            }
            if (++checkCounter % 256 == 0) ct.ThrowIfCancellationRequested();
            _dec.BeginRun(bound);
            var run = new Run { Start = a, FirstInsn = _insns.Count };
            while (true)
            {
                if (_insns.Count >= cap) { run.EndKind = RunEnd.Truncated; result.Flags |= FunctionFlags.Truncated; break; }
                if (!_dec.Decode(a, out var insn)) { run.EndKind = RunEnd.EndOfCode; break; }
                if (insn.Flow == FlowKind.Invalid) { run.EndKind = RunEnd.Invalid; result.Flags |= FunctionFlags.InvalidCode; break; }
                _visited.Add(a);
                _insns.Add(a);
                _lengths.Add((byte)insn.Length);
                RecordData(in insn);
                bool stop = Step(in insn, root, own, ref run, result);
                a = insn.Next;
                if (stop) break;
                bool conditional = insn.Flow == FlowKind.ConditionalJump || insn.Conditional;
                if (_visited.Contains(a))
                {
                    run.EndKind = RunEnd.FallThrough;
                    _leaders.Add(a);
                    if (!conditional) _branches.Add((insn.Rva, a, EdgeKind.FallThrough));
                    break;
                }
                if (a != start && a != root && _ctx.FunctionStarts.Contains(a))
                {
                    run.EndKind = RunEnd.FunctionBoundary;
                    _callees.Add(a);
                    _tails.Add(a);
                    _fallsInto.Add(a);
                    if (conditional) _branches.Remove((insn.Rva, a, EdgeKind.ConditionalFallThrough));
                    _branches.Add((insn.Rva, a, EdgeKind.TailCall));
                    break;
                }
                if (!_ctx.Code.IsCode(a)) { run.EndKind = RunEnd.EndOfCode; break; }
            }
            run.End = a;
            run.InsnCount = _insns.Count - run.FirstInsn;
            if (run.InsnCount == 0) { run.End = run.Start; }
            _runs.Add(run);
        }

        Summarize(result, start);
        if (buildGraph && function != null) result.Graph = BuildGraph(function, result);
        return result;
    }

    private void Push(uint rva, IndexBound bound)
    {
        _leaders.Add(rva);
        // already decoded: still queued when it carries a bound, for switches left unresolved on another path
        if (!_visited.Contains(rva) || (bound.IsKnown && _pending.Count > 0)) _work.Push((rva, bound));
    }

    /// <summary>
    /// A path with a known index bound reaches <paramref name="a"/>, which is already decoded: decodes again from
    /// there with the bound, and resolves unresolved indirect jumps that this path reaches.
    /// </summary>
    private void RetrySwitches(uint a, IndexBound bound, List<(uint Begin, uint End)>? own)
    {
        foreach (uint jump in _pending.GetViewBetween(a, a + RetryWindow).ToList())
        {
            if (SwitchDispatch.Redecode(_dec, _ctx, a, bound, jump, own) is not { } table) continue;
            _pending.Remove(jump);
            _unresolved.RemoveAll(u => u.Rva == jump);
            int runIndex = _pendingRun[jump];
            var run = _runs[runIndex];
            run.EndKind = RunEnd.Switch;
            _runs[runIndex] = run;
            AddSwitch(jump, table);
        }
    }

    private const uint RetryWindow = 512;

    private void AddSwitch(uint jump, SwitchTable table)
    {
        _switches.Add(table);
        _xrefs.Add(new CodeXref(jump, table.TableRva, XrefKind.JumpTable));
        if (table.IndexTableRva is { } it) _xrefs.Add(new CodeXref(jump, it, XrefKind.JumpTable));
        foreach (var t in table.Targets)
        {
            _xrefs.Add(new CodeXref(jump, t, XrefKind.SwitchCase));
            _branches.Add((jump, t, EdgeKind.Switch));
            Push(t, IndexBound.None);
        }
    }

    private bool IsTailTarget(uint target, uint start, List<(uint Begin, uint End)>? own)
    {
        if (target == start) return false;
        if (_ctx.FunctionStarts.Contains(target)) return true;
        if (own == null) return false;
        foreach (var (b, e) in own) if (target >= b && target < e) return false;
        // x64: leaving the function's .pdata ranges into another function's ranges
        return _ctx.PdataOwner(target) is { } owner && owner != start;
    }

    private bool IsNoReturnCall(uint target) => _ctx.NoReturn.Contains(target);

    /// <summary>Handles control flow of one instruction; true when the run ends here.</summary>
    private bool Step(in Insn insn, uint start, List<(uint Begin, uint End)>? own, ref Run run, WalkResult result)
    {
        switch (insn.Flow)
        {
            case FlowKind.Call:
                if (!insn.HasTarget) return false;
                _xrefs.Add(new CodeXref(insn.Rva, insn.Target, XrefKind.Call));
                if (insn.Target == insn.Next) return false;
                if (_ctx.LocalSubroutines.Contains(insn.Target))
                {
                    // called inside its own function (x86 __finally blocks): part of this function
                    Push(insn.Target, IndexBound.None);
                    return false;
                }
                _callees.Add(insn.Target);
                if (IsNoReturnCall(insn.Target)) { run.EndKind = RunEnd.NoReturnCall; return true; }
                return false;

            case FlowKind.IndirectCall:
                if (insn.HasMem && _ctx.ImportSlots.ContainsKey(insn.MemTarget) && _ctx.NoReturn.Contains(insn.MemTarget))
                {
                    run.EndKind = RunEnd.NoReturnCall;
                    return true;
                }
                return false;

            case FlowKind.Jump:
                if (!insn.HasTarget || !_ctx.Code.IsCode(insn.Target)) { run.EndKind = RunEnd.Jump; return true; }
                if (IsTailTarget(insn.Target, start, own))
                {
                    _xrefs.Add(new CodeXref(insn.Rva, insn.Target, XrefKind.TailCall));
                    _callees.Add(insn.Target);
                    _tails.Add(insn.Target);
                    _branches.Add((insn.Rva, insn.Target, EdgeKind.TailCall));
                    run.EndKind = RunEnd.TailCall;
                    return true;
                }
                _xrefs.Add(new CodeXref(insn.Rva, insn.Target, XrefKind.Jump));
                _branches.Add((insn.Rva, insn.Target, EdgeKind.Jump));
                Push(insn.Target, IndexBound.None);
                run.EndKind = RunEnd.Jump;
                return true;

            case FlowKind.ConditionalJump:
            {
                _dec.ConditionalBounds(out var taken, out _);
                _leaders.Add(insn.Next);
                _conditionals.Add(insn.Rva);
                _branches.Add((insn.Rva, insn.Next, EdgeKind.ConditionalFallThrough));
                if (!insn.HasTarget || !_ctx.Code.IsCode(insn.Target)) return false;
                if (IsTailTarget(insn.Target, start, own))
                {
                    _xrefs.Add(new CodeXref(insn.Rva, insn.Target, XrefKind.TailCall));
                    _callees.Add(insn.Target);
                    _tails.Add(insn.Target);
                    _branches.Add((insn.Rva, insn.Target, EdgeKind.TailCall));
                    return false;
                }
                _xrefs.Add(new CodeXref(insn.Rva, insn.Target, XrefKind.ConditionalJump));
                _branches.Add((insn.Rva, insn.Target, EdgeKind.ConditionalTaken));
                Push(insn.Target, taken);
                return false;
            }

            case FlowKind.IndirectJump:
            {
                if (insn.Conditional) ConditionalFallThrough(in insn);
                if (insn.HasMem && _ctx.ImportSlots.ContainsKey(insn.MemTarget))
                {
                    _callees.Add(insn.MemTarget);
                    run.EndKind = RunEnd.TailCall;
                    return !insn.Conditional;
                }
                var match = _dec.MatchSwitch(out var reason);
                var table = match != null ? _ctx.ReadSwitch(insn.Rva, match, own, out reason) : null;
                if (table == null)
                {
                    _unresolved.Add(new UnresolvedJump(insn.Rva, match == null && insn.HasMem && reason == SwitchMatch.NoDispatch ? $"jump through memory at rva 0x{insn.MemTarget:X}" : reason));
                    if (insn.Conditional) return false;
                    _pending.Add(insn.Rva);
                    _pendingRun[insn.Rva] = _runs.Count;
                    run.EndKind = RunEnd.IndirectJump;
                    return true;
                }
                AddSwitch(insn.Rva, table);
                run.EndKind = RunEnd.Switch;
                return !insn.Conditional;
            }

            case FlowKind.Return:
                if (insn.Conditional)
                {
                    _conditionalReturn = true;
                    ConditionalFallThrough(in insn);
                    return false;
                }
                run.EndKind = RunEnd.Return;
                return true;

            case FlowKind.Trap:
                run.EndKind = RunEnd.Trap;
                return true;
        }
        return false;
    }

    /// <summary>ARM32 conditional return or dispatch: the block ends there and the next instruction is its other successor.</summary>
    private void ConditionalFallThrough(in Insn insn)
    {
        _leaders.Add(insn.Next);
        _conditionals.Add(insn.Rva);
        _branches.Add((insn.Rva, insn.Next, EdgeKind.ConditionalFallThrough));
    }

    private void RecordData(in Insn insn)
    {
        if (insn.HasMem)
        {
            XrefKind kind;
            if (_ctx.ImportSlots.ContainsKey(insn.MemTarget) && insn.Flow is FlowKind.IndirectCall or FlowKind.IndirectJump)
                kind = insn.Flow == FlowKind.IndirectCall ? XrefKind.ImportCall : XrefKind.ImportJump;
            else
                kind = insn.MemAccess switch
                {
                    OperandAccess.Address => XrefKind.Address,
                    OperandAccess.Write or OperandAccess.ReadWrite => XrefKind.Write,
                    _ => XrefKind.Read,
                };
            _xrefs.Add(new CodeXref(insn.Rva, insn.MemTarget, kind));
        }
        if (insn.HasImm && !(insn.HasMem && insn.ImmTarget == insn.MemTarget))
            _xrefs.Add(new CodeXref(insn.Rva, insn.ImmTarget, XrefKind.Address));
    }

    private void Summarize(WalkResult result, uint start)
    {
        bool returns = _conditionalReturn;
        foreach (var r in _runs)
        {
            switch (r.EndKind)
            {
                case RunEnd.Return:
                case RunEnd.IndirectJump:
                case RunEnd.Invalid:
                case RunEnd.EndOfCode:
                case RunEnd.Truncated:
                    returns = true;
                    break;
            }
        }
        // a tail call (or falling into the next function) returns when its target does
        foreach (var t in _tails)
            if (!_ctx.NoReturn.Contains(t)) returns = true;
        foreach (var c in _callees)
            if (_ctx.ImportSlots.ContainsKey(c) && !_ctx.NoReturn.Contains(c)) returns = true; // jmp [import]
        result.Returns = returns;
        result.Instructions = _insns.Count;
        if (_unresolved.Count > 0) result.Flags |= FunctionFlags.UnresolvedJumps;

        // extents: runs merged into sorted, non-overlapping ranges
        var spans = new List<(uint S, uint E)>(_runs.Count);
        foreach (var r in _runs) if (r.End > r.Start) spans.Add((r.Start, r.End));
        spans.Sort((x, y) => x.S.CompareTo(y.S));
        var starts = new List<uint>();
        var ends = new List<uint>();
        foreach (var (s, e) in spans)
        {
            if (ends.Count > 0 && s <= ends[^1]) { if (e > ends[^1]) ends[^1] = e; continue; }
            starts.Add(s);
            ends.Add(e);
        }
        if (HasOverlappingInstructions()) result.Flags |= FunctionFlags.OverlappingCode;
        result.RangeStarts = starts.ToArray();
        result.RangeEnds = ends.ToArray();
        int blocks = 0;
        foreach (var l in _leaders) if (_visited.Contains(l)) blocks++;
        result.Blocks = Math.Max(blocks, _runs.Count(r => r.InsnCount > 0));
        result.Xrefs = _xrefs.ToArray();
        result.FallsInto = _fallsInto.ToArray();
        _callees.Remove(start);
        result.Callees = _callees.Where(c => !_ctx.ImportSlots.ContainsKey(c)).ToArray();
    }

    /// <summary>Some instruction starts inside another one (code decoded at two offsets).</summary>
    private bool HasOverlappingInstructions()
    {
        if (_runs.Count < 2) return false;
        var all = new (uint Start, uint End)[_insns.Count];
        for (int i = 0; i < all.Length; i++) all[i] = (_insns[i], _insns[i] + _lengths[i]);
        Array.Sort(all);
        for (int i = 1; i < all.Length; i++)
            if (all[i].Start < all[i - 1].End) return true;
        return false;
    }

    private FunctionGraph BuildGraph(NativeFunction function, WalkResult result)
    {
        var edgesByInsn = new Dictionary<uint, List<(uint To, EdgeKind Kind)>>();
        foreach (var (insn, to, kind) in _branches)
        {
            if (!edgesByInsn.TryGetValue(insn, out var list)) edgesByInsn[insn] = list = [];
            if (!list.Contains((to, kind))) list.Add((to, kind));
        }
        var blocks = new List<BasicBlock>();
        foreach (var run in _runs)
        {
            if (run.InsnCount == 0) continue;
            int first = run.FirstInsn, last = run.FirstInsn + run.InsnCount - 1;
            int blockFirst = first;
            for (int i = first; i <= last; i++)
            {
                bool endsHere = i == last || _leaders.Contains(_insns[i + 1]);
                if (!endsHere) continue;
                uint bStart = _insns[blockFirst];
                uint lastInsn = _insns[i];
                uint bEnd = i == last ? run.End : _insns[i + 1];
                edgesByInsn.TryGetValue(lastInsn, out var branchEdges);
                bool conditional = _conditionals.Contains(lastInsn);
                var endKind = i == last ? MapEnd(run.EndKind) : BlockEnd.FallThrough;
                if (conditional && endKind is BlockEnd.FallThrough or BlockEnd.FunctionBoundary) endKind = BlockEnd.ConditionalJump;
                var block = new BasicBlock { Start = bStart, End = bEnd, InstructionCount = i - blockFirst + 1, LastInstruction = lastInsn, EndKind = endKind };
                if (branchEdges != null)
                    foreach (var (to, kind) in branchEdges) block.Successors.Add(new CfgEdge(bStart, to, kind));
                if (i != last && !conditional)
                    block.Successors.Add(new CfgEdge(bStart, bEnd, EdgeKind.FallThrough));
                blocks.Add(block);
                blockFirst = i + 1;
            }
        }
        blocks.Sort((x, y) => x.Start.CompareTo(y.Start));
        var byStart = new Dictionary<uint, BasicBlock>();
        foreach (var b in blocks) byStart.TryAdd(b.Start, b);
        foreach (var b in blocks)
            foreach (var e in b.Successors)
                if (e.Kind != EdgeKind.TailCall && byStart.TryGetValue(e.To, out var succ))
                    succ.Predecessors.Add(e);
        return new FunctionGraph
        {
            Function = function,
            Blocks = blocks,
            Switches = _switches.ToList(),
            UnresolvedJumps = _unresolved.ToList(),
            TailCalls = _tails.Distinct().ToList(),
            Truncated = (result.Flags & FunctionFlags.Truncated) != 0,
        };
    }

    private static BlockEnd MapEnd(RunEnd e) => e switch
    {
        RunEnd.FallThrough => BlockEnd.FallThrough,
        RunEnd.Jump => BlockEnd.Jump,
        RunEnd.Return => BlockEnd.Return,
        RunEnd.Switch => BlockEnd.Switch,
        RunEnd.IndirectJump => BlockEnd.IndirectJump,
        RunEnd.TailCall => BlockEnd.TailCall,
        RunEnd.NoReturnCall => BlockEnd.NoReturnCall,
        RunEnd.Trap => BlockEnd.Trap,
        RunEnd.Invalid => BlockEnd.Invalid,
        RunEnd.FunctionBoundary => BlockEnd.FunctionBoundary,
        RunEnd.EndOfCode => BlockEnd.EndOfCode,
        _ => BlockEnd.Truncated,
    };
}
