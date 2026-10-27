namespace Corvus.Native.Code;

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
    /// <summary>(data address, byte length) pairs the code loads (<see cref="StringHints"/>).</summary>
    public (uint Target, int Length)[] StringLengths = [];
    /// <summary>Swift small strings in the code: the instruction that completes each, and its text.</summary>
    public (uint Rva, string Text)[] InlineStrings = [];
}

/// <summary>Walks one function by recursive descent over the known starts; optionally builds its blocks. One instance per thread.</summary>
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
    private readonly ScratchSet _visited = new();
    private readonly List<uint> _insns = [];
    private readonly List<Run> _runs = [];
    private readonly ScratchSet _leaders = new();
    private readonly Stack<(uint Rva, IndexBound Bound)> _work = new();
    private readonly List<CodeXref> _xrefs = [];
    private readonly ScratchSet _callees = new();
    private readonly List<(uint Insn, uint To, EdgeKind Kind)> _branches = [];
    private readonly ScratchSet _conditionals = new();
    private readonly List<SwitchTable> _switches = [];
    private readonly List<UnresolvedJump> _unresolved = [];
    private readonly List<uint> _tails = [];
    private readonly List<uint> _fallsInto = [];
    /// <summary>Unresolved indirect jumps that a later path with a known bound may still resolve, and their runs.</summary>
    private readonly SortedSet<uint> _pending = [];
    private readonly Dictionary<uint, int> _pendingRun = [];
    /// <summary>ARM32: some return is conditional (the run goes on after it).</summary>
    private bool _conditionalReturn;
    /// <summary>ARM32: halfwords of the literal pool entries the function loads; flow never runs into them.</summary>
    private readonly HashSet<uint> _ownLiterals = [];
    /// <summary>ARM32: runs holding a literal pool, extended once every load is known.</summary>
    private readonly List<int> _poolRuns = [];
    private readonly StringHints? _hints;

    public FunctionWalker(CodeContext ctx)
    {
        _ctx = ctx;
        _dec = ctx.NewDecoder(computeAccess: true);
        if (ctx.RustStrings || ctx.SwiftStrings) _hints = new StringHints(ctx.RustStrings, ctx.SwiftStrings, ctx.Image.Arch, ctx.Image.Format);
    }

    /// <param name="chunks">Further roots of the function (funclets, handlers), walked after its body with their own .pdata ranges.</param>
    public WalkResult Walk(NativeFunction? function, uint start, bool buildGraph, CancellationToken ct, IReadOnlyList<uint>? chunks = null)
    {
        var result = new WalkResult();
        Explore(start, chunks, result, ct);
        Summarize(result, start);
        if (buildGraph && function != null) result.Graph = BuildGraph(function, result);
        return result;
    }

    /// <summary>Walks like <see cref="Walk"/> and fills <paramref name="blocks"/> only, without result arrays or graph objects.</summary>
    public void WalkBlocks(uint start, IReadOnlyList<uint>? chunks, BlockList blocks, CancellationToken ct)
    {
        _scratchResult.Flags = 0;
        Explore(start, chunks, _scratchResult, ct);
        BuildBlocks(blocks);
    }

    private readonly WalkResult _scratchResult = new();

    private void Explore(uint start, IReadOnlyList<uint>? chunks, WalkResult result, CancellationToken ct)
    {
        _visited.Clear(); _insns.Clear(); _runs.Clear(); _leaders.Clear(); _work.Clear(); _xrefs.Clear(); _callees.Clear();
        _branches.Clear(); _conditionals.Clear(); _switches.Clear(); _unresolved.Clear(); _tails.Clear(); _fallsInto.Clear(); _pending.Clear(); _pendingRun.Clear();
        _conditionalReturn = false;
        _ownLiterals.Clear();
        _poolRuns.Clear();
        _hints?.Clear();
        _dec.BeginFunction(start);
        // Chained .pdata fragments are reached by flow only; a fragment can begin with data such as a switch table.
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
            _hints?.BeginRun();
            var run = new Run { Start = a, FirstInsn = _insns.Count };
            bool afterCall = false;
            bool pool = false;
            while (true)
            {
                if (_insns.Count >= cap) { run.EndKind = RunEnd.Truncated; result.Flags |= FunctionFlags.Truncated; break; }
                // ARM32: a literal the function loads ends the run as data; right after a direct call, that call does not return.
                if (_ownLiterals.Count > 0 && _ownLiterals.Contains(a & ~1u))
                {
                    run.EndKind = afterCall ? RunEnd.NoReturnCall : RunEnd.EndOfCode;
                    pool = true;
                    break;
                }
                if (!_dec.Decode(a, out var insn)) { run.EndKind = RunEnd.EndOfCode; break; }
                if (insn.Flow == FlowKind.Invalid) { run.EndKind = RunEnd.Invalid; result.Flags |= FunctionFlags.InvalidCode; break; }
                _visited.Add(a);
                _insns.Add(a);
                RecordData(in insn);
                _hints?.Observe(in insn, _dec);
                if (HybridDecoder.PrimaryOf(_dec) is Arm32Decoder arm)
                {
                    if (insn.HasMem && arm.LastLiteralSize is > 0 and var size)
                        for (uint l = insn.MemTarget & ~1u; l < insn.MemTarget + (uint)size; l += 2) _ownLiterals.Add(l);
                    if (!(afterCall && arm.Last.Mnemonic == "nop")) afterCall = insn.Flow == FlowKind.Call && insn.HasTarget;
                }
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
            if (pool && !_poolRuns.Exists(k => _runs[k].Start == a))
            {
                _poolRuns.Add(_runs.Count);
                _runs.Add(new Run { Start = a, End = a, FirstInsn = _insns.Count, EndKind = RunEnd.NoReturnCall });
            }
        }
        // Each literal pool stays in the extent as data, without instructions or blocks.
        foreach (int k in _poolRuns)
        {
            var r = _runs[k];
            while (_ownLiterals.Contains(r.End) && !_visited.Contains(r.End)) r.End += 2;
            _runs[k] = r;
        }
    }

    private void Push(uint rva, IndexBound bound)
    {
        _leaders.Add(rva);
        // Decoded code is queued again with a bound, for switches unresolved on another path.
        if (!_visited.Contains(rva) || (bound.IsKnown && _pending.Count > 0)) _work.Push((rva, bound));
    }

    /// <summary>Redecodes from decoded <paramref name="a"/> with a known index bound and resolves the pending jumps it reaches.</summary>
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
        // x64: leaving the function's .pdata ranges into another function's.
        return _ctx.PdataOwner(target) is { } owner && owner != start && !_ctx.PdataFragments.Contains(owner);
    }

    private bool IsNoReturnCall(uint target) => _ctx.NoReturn.Contains(target);

    private ICodeDecoder? _peek;

    /// <summary>A direct call to a no-return function comes next, so the code is still this function's.</summary>
    private bool AbortFollows(uint rva)
    {
        if (_ctx.FunctionStarts.Contains(rva)) return false;
        _peek ??= _ctx.NewDecoder(computeAccess: false);
        _peek.BeginRun(IndexBound.None);
        return _peek.Decode(rva, out var next) && next.Flow == FlowKind.Call && next.HasTarget && next.Target != next.Next && IsNoReturnCall(next.Target);
    }

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
                    // A local subroutine (x86 __finally block) is part of this function.
                    Push(insn.Target, IndexBound.None);
                    return false;
                }
                _callees.Add(insn.Target);
                if (IsNoReturnCall(insn.Target) && !AbortFollows(insn.Next)) { run.EndKind = RunEnd.NoReturnCall; return true; }
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
        // A tail call or fall-through returns when its target does.
        foreach (var t in _tails)
            if (!_ctx.NoReturn.Contains(t)) returns = true;
        // Jmp [import].
        foreach (var c in _callees.Items)
            if (_ctx.ImportSlots.ContainsKey(c) && !_ctx.NoReturn.Contains(c)) returns = true;
        result.Returns = returns;
        result.Instructions = _insns.Count;
        if (_unresolved.Count > 0) result.Flags |= FunctionFlags.UnresolvedJumps;

        // Merge runs into sorted, non-overlapping ranges.
        int count = 0;
        foreach (var r in _runs) if (r.End > r.Start) count++;
        if (_spans.Length < count) _spans = new ulong[Math.Max(count, _spans.Length * 2)];
        var spans = _spans;
        count = 0;
        foreach (var r in _runs) if (r.End > r.Start) spans[count++] = (ulong)r.Start << 32 | r.End;
        Array.Sort(spans, 0, count);
        var starts = _rangeStarts;
        var ends = _rangeEnds;
        starts.Clear();
        ends.Clear();
        // No address is decoded twice, so intersecting runs decode one byte range at two offsets.
        bool overlapping = false;
        for (int k = 0; k < count; k++)
        {
            ulong span = spans[k];
            uint s = (uint)(span >> 32), e = (uint)span;
            if (ends.Count > 0 && s <= ends[^1])
            {
                overlapping |= s < ends[^1];
                if (e > ends[^1]) ends[^1] = e;
                continue;
            }
            starts.Add(s);
            ends.Add(e);
        }
        if (overlapping) result.Flags |= FunctionFlags.OverlappingCode;
        result.RangeStarts = starts.ToArray();
        result.RangeEnds = ends.ToArray();
        int blocks = 0, nonEmpty = 0;
        foreach (var l in _leaders.Items) if (_visited.Contains(l)) blocks++;
        foreach (var r in _runs) if (r.InsnCount > 0) nonEmpty++;
        result.Blocks = Math.Max(blocks, nonEmpty);
        result.Xrefs = _xrefs.ToArray();
        result.FallsInto = _fallsInto.ToArray();
        _calleeScratch.Clear();
        foreach (uint c in _callees.Items) if (c != start && !_ctx.ImportSlots.ContainsKey(c)) _calleeScratch.Add(c);
        result.Callees = _calleeScratch.ToArray();
        if (_hints != null) (result.StringLengths, result.InlineStrings) = (_hints.Lengths.ToArray(), _hints.Inline.ToArray());
    }

    // Summarize scratch, reused across walks.
    private ulong[] _spans = new ulong[64];
    private readonly List<uint> _rangeStarts = [], _rangeEnds = [], _calleeScratch = [];

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

    // BuildBlocks scratch: edges by instruction then insertion, raw blocks, block order by start.
    private ulong[] _edgeOrder = new ulong[64];
    private uint[] _rawStart = new uint[64], _rawEnd = new uint[64], _rawLast = new uint[64];
    private bool[] _rawFalls = new bool[64];
    private ulong[] _rawOrder = new ulong[64];

    /// <summary>The blocks <see cref="BuildGraph"/> would build and their successors in the same order, into reused arrays.</summary>
    private void BuildBlocks(BlockList g)
    {
        int ne = _branches.Count;
        if (_edgeOrder.Length < ne) _edgeOrder = new ulong[Math.Max(ne, _edgeOrder.Length * 2)];
        for (int i = 0; i < ne; i++) _edgeOrder[i] = (ulong)_branches[i].Insn << 32 | (uint)i;
        Array.Sort(_edgeOrder, 0, ne);
        int n = 0;
        foreach (var run in _runs)
        {
            if (run.InsnCount == 0) continue;
            int first = run.FirstInsn, last = run.FirstInsn + run.InsnCount - 1;
            int blockFirst = first;
            for (int i = first; i <= last; i++)
            {
                if (i != last && !_leaders.Contains(_insns[i + 1])) continue;
                if (n == _rawStart.Length)
                {
                    Array.Resize(ref _rawStart, n * 2); Array.Resize(ref _rawEnd, n * 2); Array.Resize(ref _rawLast, n * 2);
                    Array.Resize(ref _rawFalls, n * 2); Array.Resize(ref _rawOrder, n * 2);
                }
                uint lastInsn = _insns[i];
                _rawStart[n] = _insns[blockFirst];
                _rawEnd[n] = i == last ? run.End : _insns[i + 1];
                _rawLast[n] = lastInsn;
                _rawFalls[n] = i != last && !_conditionals.Contains(lastInsn);
                _rawOrder[n] = (ulong)_rawStart[n] << 32 | (uint)n;
                n++;
                blockFirst = i + 1;
            }
        }
        Array.Sort(_rawOrder, 0, n);
        g.Reset(n);
        for (int k = 0; k < n; k++)
        {
            int raw = (int)(uint)_rawOrder[k];
            g.Starts[k] = _rawStart[raw];
            g.Ends[k] = _rawEnd[raw];
        }
        int s = 0;
        for (int k = 0; k < n; k++)
        {
            g.SuccStart[k] = s;
            int raw = (int)(uint)_rawOrder[k];
            uint lastInsn = _rawLast[raw];
            ulong key = (ulong)lastInsn << 32;
            int lo = 0, hi = ne;
            while (lo < hi) { int mid = (lo + hi) >>> 1; if (_edgeOrder[mid] < key) lo = mid + 1; else hi = mid; }
            for (int j = lo; j < ne && (uint)(_edgeOrder[j] >> 32) == lastInsn; j++)
            {
                var (_, to, kind) = _branches[(int)(uint)_edgeOrder[j]];
                if (kind != EdgeKind.TailCall) g.AddSuccessor(k, ref s, g.IndexOf(to));
            }
            if (_rawFalls[raw]) g.AddSuccessor(k, ref s, g.IndexOf(_rawEnd[raw]));
        }
        g.SuccStart[n] = s;
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

/// <summary>Basic blocks of one walk by start, with distinct successor block indexes in graph order; reused across walks.</summary>
internal sealed class BlockList
{
    public uint[] Starts = new uint[64];
    /// <summary>Exclusive ends.</summary>
    public uint[] Ends = new uint[64];
    /// <summary>Successors of block b: <see cref="Succs"/>[SuccStart[b] .. SuccStart[b + 1]).</summary>
    public int[] SuccStart = new int[65];
    public int[] Succs = new int[64];
    public int Count;

    public void Reset(int count)
    {
        Count = count;
        if (Starts.Length < count)
        {
            Starts = new uint[count * 2];
            Ends = new uint[count * 2];
            SuccStart = new int[count * 2 + 1];
        }
    }

    public ReadOnlySpan<int> Successors(int b) => Succs.AsSpan(SuccStart[b], SuccStart[b + 1] - SuccStart[b]);

    /// <summary>The block starting at <paramref name="start"/>, or -1.</summary>
    public int IndexOf(uint start)
    {
        int i = Array.BinarySearch(Starts, 0, Count, start);
        return i >= 0 ? i : -1;
    }

    internal void AddSuccessor(int b, ref int end, int target)
    {
        if (target < 0) return;
        for (int i = SuccStart[b]; i < end; i++) if (Succs[i] == target) return;
        if (end == Succs.Length) Array.Resize(ref Succs, end * 2);
        Succs[end++] = target;
    }
}
/// <summary>A set of 32-bit values that clears in constant time, unlike a hash set that zeroes its capacity; <see cref="Items"/> keeps insertion order.</summary>
internal sealed class ScratchSet
{
    private uint[] _keys = new uint[64];
    private int[] _stamps = new int[64];
    private int _stamp = 1;
    private int _shift = 64 - 6;

    public List<uint> Items { get; } = [];

    public int Count => Items.Count;

    public void Clear()
    {
        Items.Clear();
        if (++_stamp == int.MaxValue)
        {
            Array.Clear(_stamps);
            _stamp = 1;
        }
    }

    private int Slot(uint key) => (int)((key * 0x9E3779B97F4A7C15UL) >> _shift);

    public bool Contains(uint key)
    {
        int mask = _keys.Length - 1;
        for (int i = Slot(key); ; i = (i + 1) & mask)
        {
            if (_stamps[i] != _stamp) return false;
            if (_keys[i] == key) return true;
        }
    }

    public bool Add(uint key)
    {
        if (Items.Count * 2 >= _keys.Length) Grow();
        if (!Insert(key)) return false;
        Items.Add(key);
        return true;
    }

    private bool Insert(uint key)
    {
        int mask = _keys.Length - 1;
        for (int i = Slot(key); ; i = (i + 1) & mask)
        {
            if (_stamps[i] != _stamp)
            {
                _stamps[i] = _stamp;
                _keys[i] = key;
                return true;
            }
            if (_keys[i] == key) return false;
        }
    }

    private void Grow()
    {
        _keys = new uint[_keys.Length * 2];
        _stamps = new int[_keys.Length];
        _stamp = 1;
        _shift--;
        foreach (uint k in Items) Insert(k);
    }
}
