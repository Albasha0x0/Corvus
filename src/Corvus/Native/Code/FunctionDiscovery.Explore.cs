using System.Collections.Concurrent;
using System.Runtime.InteropServices;

namespace Corvus.Native.Code;

internal sealed partial class FunctionDiscovery
{
    /// <summary>Roots taken from the queue at once for parallel exploration; bounds the logs held.</summary>
    private const int ExploreBatch = 8192;

    private List<Explorer>? _workers;
    // pending switches added or removed while a batch commits: speculative runs that looked near them are not taken
    private readonly SortedSet<uint> _pendingChanged = [];
    private bool _trackPending;

    /// <summary>
    /// Parallel explorers, or null: one thread, or ARM32 (decoding reads the ARM / Thumb hints exploring writes).
    /// </summary>
    private List<Explorer>? Workers()
    {
        if (_workers != null) return _workers.Count > 0 ? _workers : null;
        int n = _ctx.Options.MaxParallelism > 0 ? _ctx.Options.MaxParallelism : Environment.ProcessorCount;
        _workers = n <= 1 ? [] : [.. Enumerable.Range(0, n).Select(_ => NewWorker())];
        return _workers.Count > 0 ? _workers : null;
    }

    private Explorer NewWorker() => new(this, _ctx.NewDecoder(computeAccess: false), _ctx.NewDecoder(computeAccess: false), _ctx.NewDecoder(computeAccess: false), speculative: true);

    /// <summary>The thunk slots of many starts found on several threads (a slot depends on the bytes alone), so adding them stays cheap.</summary>
    private void FindThunkSlots(IEnumerable<uint> starts)
    {
        // ARM32: a slot depends on the start's state, which exploring may still learn
        if (_ctx.ArmModes != null || Workers() is not { } workers) return;
        var list = starts.Where(s => !_thunkCache.ContainsKey(s)).Distinct().ToArray();
        if (list.Length < _ctx.Options.ParallelExploreMin) return;
        var slots = new uint?[list.Length];
        var free = new ConcurrentBag<Explorer>(workers);
        var po = new ParallelOptions { CancellationToken = _ct, MaxDegreeOfParallelism = workers.Count };
        Parallel.ForEach(Partitioner.Create(0, list.Length, 1024), po, () => free.TryTake(out var w) ? w : NewWorker(), (range, _, w) =>
        {
            for (int i = range.Item1; i < range.Item2; i++) slots[i] = w.FindThunkSlot(list[i]);
            return w;
        }, free.Add);
        for (int i = 0; i < list.Length; i++) _thunkCache[list[i]] = slots[i];
    }

    /// <summary>
    /// Explores queued roots on several threads against the state as it is, then commits them one by one in queue order: a
    /// run whose reads still hold is applied from its log, any other is explored again directly. The result is the serial
    /// one whatever the thread count or scheduling.
    /// </summary>
    private void ExploreInParallel(List<Explorer> workers)
    {
        int n = Math.Min(_roots.Count, ExploreBatch);
        var batch = new uint[n];
        for (int i = 0; i < n; i++) batch[i] = _roots.Dequeue();
        var runs = new (Explorer Worker, int Start, int Count)[n];
        foreach (var w in workers) w.BeginBatch();
        var free = new ConcurrentBag<Explorer>(workers);
        var po = new ParallelOptions { CancellationToken = _ct, MaxDegreeOfParallelism = workers.Count };
        Parallel.ForEach(Partitioner.Create(0, n, 16), po, () => free.TryTake(out var w) ? w : NewWorker(), (range, _, w) =>
        {
            for (int i = range.Item1; i < range.Item2; i++)
            {
                int start = w.Log.Count;
                w.Explore(batch[i]);
                runs[i] = (w, start, w.Log.Count - start);
            }
            return w;
        }, free.Add);
        // workers created when the bag ran dry stay for later batches
        foreach (var w in free) if (!workers.Contains(w)) workers.Add(w);
        _pendingChanged.Clear();
        _trackPending = true;
        for (int i = 0; i < n; i++)
        {
            if ((i & 255) == 0) Heartbeat();
            var (w, start, count) = runs[i];
            // ARM32: the start takes its neighbour's state first, as a direct run does
            if (_ctx.ArmModes != null) HintFromNeighbor(batch[i]);
            if (!Commit(CollectionsMarshal.AsSpan(w.Log).Slice(start, count), w)) _direct.Explore(batch[i]);
        }
        _trackPending = false;
    }

    /// <summary>Applies a speculative run when every read it made still gives the same answer; false when one does not.</summary>
    private bool Commit(ReadOnlySpan<Op> log, Explorer worker)
    {
        int adds = 0;
        (int From, int Count) modeOps = default;
        foreach (ref readonly var op in log)
        {
            bool stale = op.Kind switch
            {
                OpKind.Decoded => _starts[op.A] || _literals != null && LiteralIn(op.A, op.B),
                OpKind.Invalid => _starts[op.A],
                OpKind.NotFunction => _functions.ContainsKey((uint)op.A),
                OpKind.NoStartBetween => AnyStartBetween((uint)op.A, op.B),
                OpKind.NotLocalSubroutine => _ctx.LocalSubroutines.Contains((uint)op.A),
                OpKind.NotNoReturn => _ctx.NoReturn.Contains((uint)op.A),
                OpKind.PendingQuery => _pendingChanged.Count > 0 && _pendingChanged.GetViewBetween((uint)op.A, op.B).Count > 0,
                _ => false,
            };
            if (stale) return false;
            if (op.Kind == OpKind.AddFunction) adds++;
            else if (op.Kind == OpKind.ModeOps) modeOps = ((int)op.A, (int)op.B);
        }
        // near the function limit an add may be dropped, which the run did not foresee
        if (adds > 0 && _functions.Count + adds >= _ctx.Options.MaxFunctions) return false;
        // ARM32: the states the run read are the ones it would read now; its hints are then taken
        if (_ctx.ArmModes is { } modes && !modes.Commit(worker.Modes!, modeOps.From, modeOps.Count)) return false;
        foreach (ref readonly var op in log)
            switch (op.Kind)
            {
                case OpKind.Decoded: SetStart(op.A, (int)op.B); break;
                case OpKind.Covered: MarkData((uint)op.A, op.B); break;
                case OpKind.AddFunction:
                    // the run found the slot already (0: none, the image header is never an import slot)
                    _thunkCache.TryAdd((uint)op.A, (uint)(op.A >> 32) is var slot and not 0 ? slot : null);
                    Add((uint)op.A, (FunctionSource)op.B, strong: true);
                    break;
                case OpKind.AddressCandidate: _addressCandidates.Add((uint)op.A); break;
                case OpKind.DataInCode: _dataInCode.Add((uint)op.A); break;
                case OpKind.CodeTable: _codeTables.Add((uint)op.A); break;
                case OpKind.PendingAdd: AddPending((uint)op.A); break;
                case OpKind.PendingRemove: RemovePending((uint)op.A); break;
                case OpKind.FarJump: _farJumps.Add((uint)op.A); break;
                case OpKind.LocalSubroutine: _ctx.LocalSubroutines.Add((uint)op.A); break;
                case OpKind.Jump: _jumps.Add(((uint)(op.A >> 32), (uint)op.A, op.B)); break;
                case OpKind.ArmInsn: (_armInsns ??= new CodeBitmap(_ctx.Code.TotalBytes))[op.A] = true; break;
                case OpKind.Literal: (_literals ??= new CodeBitmap(_ctx.Code.TotalBytes))[op.A] = true; break;
            }
        return true;
    }

    /// <summary>A known literal pool entry covers a halfword of the instruction at code bit <paramref name="bit"/>.</summary>
    private bool LiteralIn(long bit, uint length)
    {
        for (uint k = 0; k < length; k += 2)
            if (_literals![bit + k]) return true;
        return false;
    }

    private void SetStart(long bit, int length)
    {
        _starts[bit] = true;
        _covered.SetRange(bit, length);
        if ((++_decoded & 0xFFFF) == 0)
        {
            _ct.ThrowIfCancellationRequested();
            _progress?.Invoke(_decoded);
        }
    }

    private void AddPending(uint jump)
    {
        if (_pendingSwitches.Add(jump) && _trackPending) _pendingChanged.Add(jump);
    }

    private void RemovePending(uint jump)
    {
        if (_pendingSwitches.Remove(jump) && _trackPending) _pendingChanged.Add(jump);
    }

    private bool AnyStartBetween(uint low, uint high) => low <= high && _sortedStarts!.GetViewBetween(low, high).Count > 0;

    private enum OpKind : byte
    {
        // reads that answered false (true answers stay true: what they read only grows)
        Decoded, Invalid, NotFunction, NoStartBetween, NotLocalSubroutine, NotNoReturn, PendingQuery,
        // writes, replayed in order
        Covered, AddFunction, AddressCandidate, DataInCode, CodeTable, PendingAdd, PendingRemove, FarJump, LocalSubroutine, Jump,
        // ARM32: an A32 instruction start and a literal pool halfword (code bit indexes); the run's state reads and hints (Modes)
        ArmInsn, Literal, ModeOps,
    }

    /// <summary>One read or write of a speculative run: an address or bit index (an added function's thunk slot above it) and a length, bound or source.</summary>
    private readonly record struct Op(OpKind Kind, long A, uint B);

    /// <summary>
    /// Recursive descent from one root. Direct: reads and writes the discovery state. Speculative: reads it as it was when the
    /// batch began plus the run's own writes, and logs both for <see cref="Commit"/>.
    /// </summary>
    private sealed class Explorer
    {
        private readonly FunctionDiscovery d;
        private readonly CodeContext _ctx;
        private readonly ICodeDecoder _dec;
        private readonly ICodeDecoder _peek;
        private readonly ICodeDecoder? _thunks;
        private readonly X86Decoder? _x86Dec;
        private readonly X86Decoder? _x86Peek;
        // jumps that may leave the function are recorded (FunctionDiscovery.TailTargets)
        private readonly bool _tailJumps;
        private readonly bool _speculative;
        private readonly Func<uint, uint, bool> _anyStartBetween;
        private readonly Func<uint, bool> _inNoReturn;
        private readonly Stack<(uint Rva, IndexBound Bound)> _work = new();
        public readonly List<Op> Log = [];
        // speculative: thunk slots found by this worker during the batch (the discovery's cache is read-only meanwhile)
        private readonly Dictionary<uint, uint?> _thunkSlots = [];
        // ARM32 speculative runs: the state reads and hints of the batch's runs
        public readonly Arm32Modes.Speculation? Modes;
        // the run's own writes, seen by its later reads
        private readonly ScratchSet _starts = new();
        private readonly ScratchSet _literals = new();
        private readonly ScratchSet _functions = new();
        private readonly HashSet<uint> _localSubroutines = [];
        private readonly HashSet<uint> _pendingAdded = [];
        private readonly HashSet<uint> _pendingRemoved = [];
        private long _decoded;
        // exploring a landing pad: part of another function, so neither a jump as its first instruction nor a far jump (into
        // the function's cold part) is a tail call
        private bool _chunk;

        /// <param name="thunks">Speculative runs find thunk slots with their own decoder (null: the discovery's).</param>
        public Explorer(FunctionDiscovery owner, ICodeDecoder dec, ICodeDecoder peek, ICodeDecoder? thunks, bool speculative)
        {
            d = owner;
            _ctx = owner._ctx;
            _dec = dec;
            _peek = peek;
            _thunks = thunks;
            _x86Dec = HybridDecoder.PrimaryOf(dec) as X86Decoder;
            _x86Peek = HybridDecoder.PrimaryOf(peek) as X86Decoder;
            _tailJumps = _x86Dec != null || HybridDecoder.PrimaryOf(dec) is Arm64Decoder or Arm32Decoder;
            _speculative = speculative;
            _anyStartBetween = AnyStartBetween;
            _inNoReturn = InNoReturn;
            if (speculative && _ctx.ArmModes != null) Modes = new Arm32Modes.Speculation(_ctx.ArmModes);
        }

        public uint? FindThunkSlot(uint rva) => _thunks!.ThunkSlot(rva, _ctx.ImportSlots.ContainsKey);

        public void BeginBatch()
        {
            Log.Clear();
            _thunkSlots.Clear();
            _thunkModes.Clear();
            Modes?.Clear();
        }

        /// <param name="chunk">Explores a landing pad: its callees become functions, it does not.</param>
        public void Explore(uint root, bool chunk = false)
        {
            if (Modes == null) { ExploreCore(root, chunk); return; }
            int from = Modes.Count;
            Modes.BeginRun();
            _ctx.ArmModes!.Speculate(Modes);
            try { ExploreCore(root, chunk); }
            finally { _ctx.ArmModes.Speculate(null); }
            Log.Add(new Op(OpKind.ModeOps, from, (uint)(Modes.Count - from)));
        }

        private void ExploreCore(uint root, bool chunk)
        {
            _chunk = chunk;
            if (_speculative)
            {
                _starts.Clear();
                _functions.Clear();
                _localSubroutines.Clear();
                _pendingAdded.Clear();
                _pendingRemoved.Clear();
                _literals.Clear();
            }
            List<(uint Begin, uint End)>? own = _ctx.PdataRanges.TryGetValue(root, out var r) ? r : null;
            // speculative: the neighbour's state is taken when the run commits
            if (_ctx.ArmModes != null && !_speculative) d.HintFromNeighbor(root);
            _ctx.ArmModes?.Fix(root);
            _dec.BeginFunction(root);
            _work.Clear();
            _work.Push((root, IndexBound.None));
            while (_work.Count > 0)
            {
                var (a, bound) = _work.Pop();
                var region = _ctx.Code.RegionAt(a);
                if (region == null) continue;
                if (IsStart(region.BitBase + (a - region.Rva)))
                {
                    if (bound.IsKnown) RetrySwitches(a, bound, own, root);
                    continue;
                }
                _dec.BeginRun(bound);
                while (true)
                {
                    if (a - region.Rva >= (uint)region.Bytes.Length)
                    {
                        region = _ctx.Code.RegionAt(a);
                        if (region == null) break;
                    }
                    long bit = region.BitBase + (a - region.Rva);
                    if (IsStart(bit)) break;
                    _dec.Decode(region, a, out var insn);
                    // ARM32: a literal pool known code loads ends the run (after a call that does not return)
                    if (insn.Flow == FlowKind.Invalid || IsLiteralAt(bit, a, (int)Math.Min(insn.Length, region.End - a)))
                    {
                        if (_speculative) Log.Add(new Op(OpKind.Invalid, bit, 0));
                        break;
                    }
                    SetStart(bit, (int)Math.Min(insn.Length, region.End - a));
                    if (insn.HasMem && _ctx.Code.IsCode(insn.MemTarget))
                    {
                        if (insn.MemAccess == OperandAccess.Address) Write(OpKind.AddressCandidate, insn.MemTarget);
                        else
                        {
                            Write(OpKind.DataInCode, insn.MemTarget);
                            // [index*4 + table] in code: an x86 switch table (or another pointer table), whatever the dispatch
                            if (_x86Dec is { } x86 && x86.Last.MemoryIndex != Iced.Intel.Register.None && x86.Last.MemoryIndexScale == 4) Write(OpKind.CodeTable, insn.MemTarget);
                        }
                    }
                    if (insn.HasImm && _ctx.Code.IsCode(insn.ImmTarget)) Write(OpKind.AddressCandidate, insn.ImmTarget);
                    if (_ctx.ArmModes != null) NoteArm32(in insn, bit);
                    if (!Follow(in insn, root, own)) break;
                    a = insn.Next;
                }
            }
        }

        private bool IsStart(long bit) => d._starts[bit] || (_speculative && _starts.Contains((uint)bit));

        private bool IsLiteralAt(long bit, uint rva, int length)
        {
            if (d.IsLiteralAt(bit, rva, length)) return true;
            if (!_speculative || _literals.Count == 0) return false;
            for (int k = 0; k < length; k += 2)
                if (_literals.Contains((uint)(bit + k))) return true;
            return false;
        }

        /// <summary>ARM32: the instruction's state and the literal it loads (<see cref="FunctionDiscovery.NoteArm32"/>), logged when speculative.</summary>
        private void NoteArm32(in Insn insn, long bit)
        {
            if (!_speculative) { d.NoteArm32(_dec, in insn, bit); return; }
            if (HybridDecoder.PrimaryOf(_dec) is not Arm32Decoder arm) return;
            if (!arm.Thumb) Log.Add(new Op(OpKind.ArmInsn, bit, 0));
            if (insn.HasMem && arm.LastLiteralSize is > 0 and var size)
                for (uint a = insn.MemTarget & ~1u; a < insn.MemTarget + (uint)size; a += 2)
                    if (_ctx.Code.BitIndex(a) is var b and >= 0)
                    {
                        _literals.Add((uint)b);
                        Log.Add(new Op(OpKind.Literal, b, 0));
                    }
        }

        private void SetStart(long bit, int length)
        {
            if (!_speculative) { d.SetStart(bit, length); return; }
            _starts.Add((uint)bit);
            Log.Add(new Op(OpKind.Decoded, bit, (uint)length));
            if ((++_decoded & 0xFFFF) == 0) d._ct.ThrowIfCancellationRequested();
        }

        private bool IsFunction(uint rva)
        {
            if (d._functions.ContainsKey(rva)) return true;
            if (!_speculative) return false;
            if (_functions.Contains(rva)) return true;
            Log.Add(new Op(OpKind.NotFunction, rva, 0));
            return false;
        }

        private void AddFunction(uint rva, FunctionSource source)
        {
            if (!_speculative) { d.Add(rva, source, strong: true); return; }
            if (!d._functions.ContainsKey(rva)) _functions.Add(rva);
            Log.Add(new Op(OpKind.AddFunction, rva | (long)(ThunkSlot(rva) ?? 0) << 32, (uint)source));
        }

        private bool AnyStartBetween(uint low, uint high)
        {
            if (d.AnyStartBetween(low, high)) return true;
            if (!_speculative) return false;
            foreach (uint f in _functions.Items) if (f >= low && f <= high) return true;
            Log.Add(new Op(OpKind.NoStartBetween, low, high));
            return false;
        }

        private bool IsLocalSubroutine(uint rva)
        {
            if (_ctx.LocalSubroutines.Contains(rva)) return true;
            if (!_speculative) return false;
            if (_localSubroutines.Contains(rva)) return true;
            Log.Add(new Op(OpKind.NotLocalSubroutine, rva, 0));
            return false;
        }

        private void AddLocalSubroutine(uint rva)
        {
            if (!_speculative) _ctx.LocalSubroutines.Add(rva);
            else if (_localSubroutines.Add(rva)) Log.Add(new Op(OpKind.LocalSubroutine, rva, 0));
        }

        /// <summary>A direct call target or memory operand known not to return (thunks to such imports join the set as they are found).</summary>
        private bool InNoReturn(uint rva)
        {
            if (_ctx.NoReturn.Contains(rva)) return true;
            if (_speculative && _ctx.Code.IsCode(rva)) Log.Add(new Op(OpKind.NotNoReturn, rva, 0));
            return false;
        }

        private void WriteJump(uint site, uint target, uint root)
        {
            if (_speculative) Log.Add(new Op(OpKind.Jump, (long)site << 32 | target, root));
            else d._jumps.Add((site, target, root));
        }

        private void Write(OpKind kind, uint rva)
        {
            if (_speculative) { Log.Add(new Op(kind, rva, 0)); return; }
            switch (kind)
            {
                case OpKind.AddressCandidate: d._addressCandidates.Add(rva); break;
                case OpKind.DataInCode: d._dataInCode.Add(rva); break;
                case OpKind.CodeTable: d._codeTables.Add(rva); break;
                case OpKind.FarJump: d._farJumps.Add(rva); break;
            }
        }

        private uint? ThunkSlot(uint rva)
        {
            if (!_speculative) return d.ThunkSlot(rva);
            if (d._thunkCache.TryGetValue(rva, out var slot)) return slot;
            // ARM32: a slot found in another state is found again (the read is logged either way)
            bool? thumb = _ctx.ArmModes?.StartMode(rva);
            if (_thunkSlots.TryGetValue(rva, out slot) && (thumb == null || _thunkModes[rva] == thumb)) return slot;
            if (thumb is { } t) _thunkModes[rva] = t;
            return _thunkSlots[rva] = _thunks!.ThunkSlot(rva, _ctx.ImportSlots.ContainsKey);
        }

        // ARM32: the state each slot in _thunkSlots was found in
        private readonly Dictionary<uint, bool> _thunkModes = [];

        private bool IsNoReturnTarget(uint target) =>
            _ctx.NoReturn.Contains(target) || (ThunkSlot(target) is { } slot && _ctx.NoReturn.Contains(slot));

        /// <summary>Queues the successors of one instruction; false when the linear run ends.</summary>
        private bool Follow(in Insn insn, uint root, List<(uint Begin, uint End)>? own)
        {
            switch (insn.Flow)
            {
                case FlowKind.Call:
                    if (insn.HasTarget && insn.Target != insn.Next && _ctx.Code.IsCode(insn.Target))
                    {
                        // whether the target is a function matters only for a call that may be a local subroutine
                        if (IsLocalSubroutine(insn.Target) || ((LocalFinallyCall(in insn) || UsesCallerFrame(insn.Target)) && !IsFunction(insn.Target)))
                        {
                            AddLocalSubroutine(insn.Target);
                            _work.Push((insn.Target, IndexBound.None));
                            return true;
                        }
                        AddFunction(insn.Target, FunctionSource.Call);
                        if (IsNoReturnTarget(insn.Target)) return false;
                    }
                    return true;
                case FlowKind.IndirectCall:
                    return !(insn.HasMem && InNoReturn(insn.MemTarget));
                case FlowKind.Jump:
                    if (!insn.HasTarget || !_ctx.Code.IsCode(insn.Target)) return false;
                    // a function that is only a jump (adjustor / ICF thunk), a jump to an import thunk, an x86 jump to a standard
                    // prologue, an ARM32 jump that changes state, is computed (a veneer) or reaches a bx pc stub: tail calls to functions
                    if (own == null && !_chunk && d.IsFarJump(in insn, root, _anyStartBetween) && !IsFunction(insn.Target))
                    {
                        Write(OpKind.FarJump, insn.Target);
                        return false;
                    }
                    if (insn.Rva == root && insn.Target != root && !_chunk || ThunkSlot(insn.Target) != null && !FallsInto(insn.Target) || (_x86Dec is { Is64: false } && d.StartsWithPrologue(insn.Target))
                        || _dec is Arm32Decoder arm && (arm.LastSwitchesState || arm.LastIsComputed || arm.IsStateSwitchStub(insn.Target)))
                        AddFunction(insn.Target, FunctionSource.TailJump);
                    else
                    {
                        // without unwind ranges: a jump that may leave the function (a tail call, decided after discovery)
                        if (own == null && !_chunk && _tailJumps && (insn.Target < root || insn.Target - insn.Rva > 16 || d.JumpOverBarrier(insn.Rva, insn.Target))) WriteJump(insn.Rva, insn.Target, root);
                        Branch(insn.Target, root, own, IndexBound.None);
                    }
                    return false;
                case FlowKind.ConditionalJump:
                    if (insn.HasTarget && _ctx.Code.IsCode(insn.Target))
                    {
                        // a conditional tail call to an import stub or a linker veneer (ARM32 bne.w): exploring it here would make the stub a
                        // block of this function; other far conditional targets stay blocks (functions larger than any distance rule)
                        if (own == null && (ThunkSlot(insn.Target) != null ? !IsFunction(insn.Target) && !FallsInto(insn.Target) : !IsFunction(insn.Target) && d.IsVeneer(insn.Target)))
                        {
                            AddFunction(insn.Target, FunctionSource.TailJump);
                            return true;
                        }
                        _dec.ConditionalBounds(out var taken, out _);
                        Branch(insn.Target, root, own, taken);
                    }
                    return true;
                case FlowKind.IndirectJump:
                    // a conditional dispatch (ARM32 ldrls pc / addls pc) falls through to its default
                    if (insn.HasMem && _ctx.ImportSlots.ContainsKey(insn.MemTarget)) return insn.Conditional;
                    if (_dec.MatchSwitch(out _) is { } m && _ctx.ReadSwitch(insn.Rva, m, own, out _) is { } table) FollowSwitch(table);
                    else if (!insn.Conditional) AddPending(insn.Rva);
                    return insn.Conditional;
                case FlowKind.Next:
                    return true;
                case FlowKind.Return:
                    return insn.Conditional;
                default:
                    return false;
            }
        }

        /// <summary>ARM64: the instruction before <paramref name=target/> runs on into it, so an import stub there is the function's own tail, not a thunk.</summary>
        private bool FallsInto(uint target) =>
            _ctx.Image.Arch == NativeArch.Arm64 && target >= 4 && _ctx.Code.RegionAt(target - 4) is { } region && !_peek.IsPadding(region, target - 4)
            && _peek.Decode(target - 4, out var prev) && prev.Flow is FlowKind.Next or FlowKind.ConditionalJump or FlowKind.Call or FlowKind.IndirectCall;

        private void Branch(uint target, uint root, List<(uint Begin, uint End)>? own, IndexBound bound)
        {
            if (target != root && IsFunction(target)) return;
            // x64: a jump out of a .pdata function into code no .pdata entry covers is a tail call to a leaf function,
            // unless it lands right after the function's own range (an epilogue the unwind data leaves out)
            if (own != null && !InRanges(own, target) && _ctx.PdataOwner(target) == null && !JustAfter(own, target))
            {
                AddFunction(target, FunctionSource.TailJump);
                return;
            }
            _work.Push((target, bound));
        }

        /// <summary>A path with a known index bound reaches decoded code: retries the unresolved switches it leads to.</summary>
        private void RetrySwitches(uint a, IndexBound bound, List<(uint Begin, uint End)>? own, uint root)
        {
            if (!_speculative && d._pendingSwitches.Count == 0) return;
            var jumps = PendingBetween(a, a + 512);
            if (jumps.Count == 0) return;
            _peek.BeginFunction(root);
            foreach (uint jump in jumps)
            {
                if (SwitchDispatch.Redecode(_peek, _ctx, a, bound, jump, own, _inNoReturn) is not { } table) continue;
                RemovePending(jump);
                FollowSwitch(table);
            }
        }

        private List<uint> PendingBetween(uint low, uint high)
        {
            var list = d._pendingSwitches.GetViewBetween(low, high).ToList();
            if (!_speculative) return list;
            Log.Add(new Op(OpKind.PendingQuery, low, high));
            if (_pendingRemoved.Count > 0) list.RemoveAll(_pendingRemoved.Contains);
            foreach (uint j in _pendingAdded) if (j >= low && j <= high && !list.Contains(j)) list.Add(j);
            if (_pendingAdded.Count > 0) list.Sort();
            return list;
        }

        private void AddPending(uint jump)
        {
            if (!_speculative) { d.AddPending(jump); return; }
            _pendingRemoved.Remove(jump);
            _pendingAdded.Add(jump);
            Log.Add(new Op(OpKind.PendingAdd, jump, 0));
        }

        private void RemovePending(uint jump)
        {
            if (!_speculative) { d.RemovePending(jump); return; }
            _pendingAdded.Remove(jump);
            _pendingRemoved.Add(jump);
            Log.Add(new Op(OpKind.PendingRemove, jump, 0));
        }

        /// <summary>Queues the cases; the tables are data inside code, marked covered so no gap scan decodes them.</summary>
        private void FollowSwitch(SwitchTable table)
        {
            MarkData(table.TableRva, (uint)(table.EntryCount * table.EntrySize));
            if (table.IndexTableRva is { } it) MarkData(it, (uint)table.IndexEntryCount);
            foreach (var t in table.Targets) _work.Push((t, IndexBound.None));
        }

        private void MarkData(uint rva, uint length)
        {
            if (_speculative) Log.Add(new Op(OpKind.Covered, rva, length));
            else d.MarkData(rva, length);
        }

        /// <summary>x86: a call just after leaving an SEH scope to a block shortly after it (the __finally block).</summary>
        private bool LocalFinallyCall(in Insn call) =>
            call.Target > call.Rva && call.Target - call.Rva < 0x400 && _x86Dec?.PreviousLeavesSehScope() == true;

        /// <summary>
        /// x86: the code at <paramref name="rva"/> reads or writes [ebp+x] before it sets ebp, so it runs in its
        /// caller's frame (a __finally block called by the function that owns it), not as a function of its own.
        /// </summary>
        private bool UsesCallerFrame(uint rva)
        {
            if (_x86Peek is not { Is64: false } peek) return false;
            for (int n = 0; n < 8; n++)
            {
                if (!peek.Decode(rva, out var insn) || insn.Flow == FlowKind.Invalid) return false;
                ref readonly var x = ref peek.Last;
                if (x.Op0Kind == Iced.Intel.OpKind.Register && x.Op0Register == Iced.Intel.Register.EBP && x.Mnemonic != Iced.Intel.Mnemonic.Push) return false;
                if (UsesEbpMemory(in x)) return true;
                if (insn.Flow != FlowKind.Next) return false;
                rva = insn.Next;
            }
            return false;
        }
    }
}
