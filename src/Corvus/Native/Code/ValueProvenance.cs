using Iced.Intel;

namespace Corvus.Native.Code;

/// <summary>
/// Where a value came from: a constant, an incoming argument, a load, an
/// address or a call result.
/// </summary>
internal abstract record Origin;

/// <summary>A known integer.</summary>
internal sealed record ConstOrigin(long Number) : Origin;

/// <summary>The n-th integer argument at function entry, counted from zero.</summary>
internal sealed record ArgOrigin(int Index) : Origin;

/// <summary>
/// The 64-bit value at <paramref name="Base"/> plus <paramref name="Disp"/>,
/// read at <paramref name="Epoch"/>: the last call or store before the load.
/// Loads of one address in different epochs are different values.
/// </summary>
internal sealed record LoadOrigin(Origin Base, long Disp, ulong Epoch = 0) : Origin;

/// <summary>An absolute address in the image, such as a static.</summary>
internal sealed record AddressOrigin(ulong Address) : Origin;

/// <summary>The return value of the call at <paramref name="Ip"/>.</summary>
internal sealed record ResultOrigin(ulong Ip) : Origin;

/// <summary>
/// Register and stack slot values at one point of a function; a missing entry
/// is unknown.
/// </summary>
internal sealed class ProvenanceState
{
    // Chains of loads deeper than this are unknown.
    private const int MaxDepth = 6;

    private const int ShadowSpace = 32;

    private readonly Dictionary<Register, Origin> _regs = [];
    // Keyed by offset from the stack pointer at function entry.
    private readonly Dictionary<long, Origin> _slots = [];
    private long? _sp = 0;
    private long? _bp;
    private bool _escaped;
    private ulong _epoch;

    /// <summary>False for a state made without a known path to the block.</summary>
    public bool Reached { get; private set; } = true;

    /// <summary>A state where nothing is known, not even the stack pointer.</summary>
    public static ProvenanceState Unknown() => new() { _sp = null, Reached = false };

    public ProvenanceState Clone()
    {
        var c = new ProvenanceState { _sp = _sp, _bp = _bp, _escaped = _escaped, _epoch = _epoch, Reached = Reached };
        foreach (var (k, v) in _regs) c._regs[k] = v;
        foreach (var (k, v) in _slots) c._slots[k] = v;
        return c;
    }

    /// <summary>The origin of a register, null when unknown.</summary>
    public Origin? Get(Register r) => _regs.GetValueOrDefault(r.GetFullRegister());

    internal void Set(Register r, Origin? value)
    {
        var full = r.GetFullRegister();
        if (value == null || Depth(value) > MaxDepth) _regs.Remove(full);
        else _regs[full] = value;
    }

    /// <summary>
    /// The origin of the 64-bit value a memory operand of
    /// <paramref name="ins"/> addresses, null when unknown.
    /// </summary>
    public Origin? Memory(in Instruction ins)
    {
        if (ins.SegmentPrefix != Register.None) return null;
        long scaled = 0;
        // A constant index folds into the displacement.
        if (ins.MemoryIndex != Register.None)
        {
            if (Get(ins.MemoryIndex) is not ConstOrigin index || IsFrame(ins.MemoryBase)) return null;
            scaled = index.Number * ins.MemoryIndexScale;
        }
        if (ins.MemoryBase == Register.RIP) return new LoadOrigin(new AddressOrigin(ins.IPRelativeMemoryAddress), 0, _epoch);
        if (IsFrame(ins.MemoryBase)) return SlotOf(ins) is { } slot ? _slots.GetValueOrDefault(slot) : null;
        if (!ins.MemoryBase.IsGPR64()) return null;
        return Get(ins.MemoryBase) is { } b ? new LoadOrigin(b, (long)ins.MemoryDisplacement64 + scaled, _epoch) : null;
    }

    private static bool IsFrame(Register r) => r is Register.RSP or Register.RBP;

    private static int Depth(Origin o) => o is LoadOrigin l ? 1 + Depth(l.Base) : 0;

    // The entry-relative offset of a stack operand, null when the frame is unknown.
    private long? SlotOf(in Instruction ins)
    {
        long? frame = ins.MemoryBase == Register.RSP ? _sp : ins.MemoryBase == Register.RBP ? _bp : null;
        return frame is { } f ? f + (long)ins.MemoryDisplacement64 : null;
    }

    private static bool TouchesFrame(in Instruction ins) =>
        IsFrame(ins.MemoryBase) || IsFrame(ins.MemoryIndex);

    private void Forget(long from, int size)
    {
        for (long k = from - 7; k < from + size; k++) _slots.Remove(k);
    }

    // Windows callees own the shadow space at and above the call-time stack pointer.
    private void ForgetShadowSpace()
    {
        if (_sp is not { } sp) return;
        foreach (var k in _slots.Keys.ToList())
            if (k < sp + ShadowSpace) _slots.Remove(k);
    }

    private void Lose()
    {
        _slots.Clear();
        _sp = null;
    }

    // Calls clobber the registers the convention names; RAX takes the result.
    internal void Call(in Instruction ins, Register[] clobbered, bool windows)
    {
        foreach (var r in clobbered) _regs.Remove(r);
        if (windows) ForgetShadowSpace();
        _epoch = ins.IP;
        _regs[Register.RAX] = new ResultOrigin(ins.IP);
    }

    private static bool Writes(OpAccess a) =>
        a is OpAccess.Write or OpAccess.ReadWrite or OpAccess.CondWrite or OpAccess.ReadCondWrite;

    private static bool IsImmediate(OpKind k) =>
        k is OpKind.Immediate8 or OpKind.Immediate8to32 or OpKind.Immediate8to64
            or OpKind.Immediate32 or OpKind.Immediate32to64;

    /// <summary>Applies one non-call instruction.</summary>
    internal void Apply(in Instruction ins, InstructionInfoFactory factory)
    {
        switch (ins.Mnemonic)
        {
            case Mnemonic.Push:
                if (_sp is { } sp)
                {
                    _sp = sp - 8;
                    Forget(sp - 8, 8);
                    if (ins.Op0Kind == OpKind.Register && ins.Op0Register.IsGPR64()
                        && Get(ins.Op0Register) is { } pushed && !_escaped)
                        _slots[sp - 8] = pushed;
                }
                return;
            case Mnemonic.Pop:
                if (ins.Op0Kind == OpKind.Register)
                    Set(ins.Op0Register, _sp is { } top && !_escaped ? _slots.GetValueOrDefault(top) : null);
                if (ins.Op0Register == Register.RBP) _bp = null;
                if (_sp is { } t) _sp = t + 8;
                return;
            case Mnemonic.Leave:
                _sp = _bp is { } b ? b + 8 : null;
                if (_sp == null) Lose();
                _bp = null;
                _regs.Remove(Register.RBP);
                return;
        }
        if (ins.Op0Kind == OpKind.Register && ins.Op0Register == Register.RSP)
        {
            // Arithmetic with an immediate keeps the frame; anything else loses it.
            bool imm = ins.OpCount == 2 && IsImmediate(ins.Op1Kind);
            if (ins.Mnemonic == Mnemonic.Sub && imm && _sp is { } s1) _sp = s1 - (long)ins.GetImmediate(1);
            else if (ins.Mnemonic == Mnemonic.Add && imm && _sp is { } s2) _sp = s2 + (long)ins.GetImmediate(1);
            else if (ins.Mnemonic == Mnemonic.Mov && ins.Op1Kind == OpKind.Register
                && ins.Op1Register == Register.RBP && _bp is { } rbp) _sp = rbp;
            else Lose();
            return;
        }
        if (ins.Mnemonic == Mnemonic.Mov && ins.Op0Kind == OpKind.Register && ins.Op0Register == Register.RBP
            && ins.Op1Kind == OpKind.Register && ins.Op1Register == Register.RSP)
        {
            _bp = _sp;
            _regs.Remove(Register.RBP);
            return;
        }
        if (ins.Mnemonic == Mnemonic.Lea && ins.Op0Register == Register.RBP && ins.MemoryBase == Register.RSP
            && ins.MemoryIndex == Register.None && _sp is { } ls)
        {
            _bp = ls + (long)ins.MemoryDisplacement64;
            _regs.Remove(Register.RBP);
            return;
        }
        // A frame address in another register or taken with lea can be written through.
        if (ins.Mnemonic == Mnemonic.Lea && TouchesFrame(ins)
            || ins.Mnemonic == Mnemonic.Mov && ins.Op0Kind == OpKind.Register
                && ins.Op1Kind == OpKind.Register && IsFrame(ins.Op1Register))
        {
            _escaped = true;
            _slots.Clear();
        }
        var info = factory.GetInfo(ins);
        foreach (var m in info.GetUsedMemory())
        {
            if (!Writes(m.Access)) continue;
            if (!IsFrame(m.Base) && !IsFrame(m.Index))
            {
                _epoch = ins.IP;
                continue;
            }
            // An indexed or unlocated frame write can land on any slot.
            long? frame = m.Base == Register.RSP ? _sp : m.Base == Register.RBP ? _bp : null;
            if (m.Index != Register.None || frame is not { } f)
            {
                _slots.Clear();
                continue;
            }
            long at = f + (long)m.Displacement;
            Forget(at, Math.Max(1, m.MemorySize.GetSize()));
            if (ins.Mnemonic != Mnemonic.Mov || _escaped || m.MemorySize != MemorySize.UInt64) continue;
            if (ins.Op1Kind == OpKind.Register && ins.Op1Register.IsGPR64() && Get(ins.Op1Register) is { } stored)
                _slots[at] = stored;
            else if (ins.Op1Kind is OpKind.Immediate32to64 or OpKind.Immediate64)
                _slots[at] = new ConstOrigin((long)ins.GetImmediate(1));
        }
        var loaded = Loaded(ins);
        foreach (var u in info.GetUsedRegisters())
            if (Writes(u.Access)) _regs.Remove(u.Register.GetFullRegister());
        if (ins.Op0Kind == OpKind.Register && ins.Op0Register == Register.RBP) _bp = null;
        if (loaded != null) Set(ins.Op0Register, loaded);
    }

    // The value a mov, xor, lea or load leaves in its destination; null for others.
    // A narrow destination keeps the old upper bits, so only constants survive it.
    private Origin? Loaded(in Instruction ins)
    {
        if (ins.OpCount == 0 || ins.Op0Kind != OpKind.Register) return null;
        var dest = ins.Op0Register;
        if (!dest.IsGPR32() && !dest.IsGPR64()) return null;
        if (ins.Mnemonic == Mnemonic.Xor && ins.Op1Kind == OpKind.Register
            && dest.GetFullRegister() == ins.Op1Register.GetFullRegister())
            return new ConstOrigin(0);
        if (ins.Mnemonic == Mnemonic.Lea && ins.MemoryBase == Register.RIP && dest.IsGPR64())
            return new AddressOrigin(ins.IPRelativeMemoryAddress);
        if (ins.Mnemonic is Mnemonic.Add or Mnemonic.Sub or Mnemonic.Imul or Mnemonic.Shl) return Folded(ins);
        if (ins.Mnemonic != Mnemonic.Mov) return null;
        switch (ins.Op1Kind)
        {
            case OpKind.Immediate8 or OpKind.Immediate16 or OpKind.Immediate32 or OpKind.Immediate64
                or OpKind.Immediate8to32 or OpKind.Immediate8to64 or OpKind.Immediate32to64:
                return new ConstOrigin((long)ins.GetImmediate(1));
            case OpKind.Register when dest.IsGPR64() == ins.Op1Register.IsGPR64()
                && (ins.Op1Register.IsGPR64() || ins.Op1Register.IsGPR32()):
                var copied = Get(ins.Op1Register);
                return copied is ConstOrigin || dest.IsGPR64() ? copied : null;
            case OpKind.Memory when dest.IsGPR64() && ins.MemorySize == MemorySize.UInt64:
                return Memory(ins);
            default:
                return null;
        }
    }

    // The constant an operand holds: an immediate or a register with a known number.
    private long? ConstantOf(in Instruction ins, int operand)
    {
        var kind = ins.GetOpKind(operand);
        if (kind == OpKind.Register) return Get(ins.GetOpRegister(operand)) is ConstOrigin c ? c.Number : null;
        return IsImmediate(kind) ? (long)ins.GetImmediate(operand) : null;
    }

    // The result of add, sub, imul or shl on constants; null when an operand is unknown.
    private Origin? Folded(in Instruction ins)
    {
        bool three = ins.Mnemonic == Mnemonic.Imul && ins.OpCount == 3;
        if ((three ? ConstantOf(ins, 1) : ConstantOf(ins, 0)) is not { } left
            || ConstantOf(ins, three ? 2 : 1) is not { } right) return null;
        long result = ins.Mnemonic switch
        {
            Mnemonic.Add => left + right,
            Mnemonic.Sub => left - right,
            Mnemonic.Shl => right is >= 0 and < 64 ? left << (int)right : 0,
            _ => left * right,
        };
        if (ins.Mnemonic == Mnemonic.Shl && right is < 0 or >= 64) return null;
        return new ConstOrigin(ins.Op0Register.IsGPR64() ? result : (long)(uint)result);
    }

    /// <summary>Keeps what both states agree on; true when this state lost anything.</summary>
    internal bool Meet(ProvenanceState other)
    {
        bool changed = false;
        foreach (var k in _regs.Keys.ToList())
            if (!other._regs.TryGetValue(k, out var v) || !v.Equals(_regs[k])) { _regs.Remove(k); changed = true; }
        foreach (var k in _slots.Keys.ToList())
            if (!other._slots.TryGetValue(k, out var v) || !v.Equals(_slots[k])) { _slots.Remove(k); changed = true; }
        if (_sp != other._sp) { changed |= _sp != null; _sp = null; _slots.Clear(); }
        if (_bp != other._bp) { changed |= _bp != null; _bp = null; }
        if (_epoch != other._epoch && _epoch != ulong.MaxValue) { _epoch = ulong.MaxValue; changed = true; }
        if (other._escaped && !_escaped) { _escaped = true; _slots.Clear(); changed = true; }
        return changed;
    }
}

/// <summary>
/// Forward value provenance over the blocks of an x64 function: for each
/// instruction, where each register and stack slot value came from. A value
/// reached from two different sources is unknown.
/// </summary>
internal static class ValueProvenance
{
    // Passes over the blocks before the states are given up as unconverged.
    private const int MaxPasses = 64;

    /// <summary>The integer argument registers of the convention, in order.</summary>
    internal static Register[] ArgumentRegisters(bool windows) => windows
        ? [Register.RCX, Register.RDX, Register.R8, Register.R9]
        : [Register.RDI, Register.RSI, Register.RDX, Register.RCX, Register.R8, Register.R9];

    /// <summary>The registers a call may change.</summary>
    internal static Register[] Clobbered(bool windows) => windows
        ? [Register.RAX, Register.RCX, Register.RDX, Register.R8, Register.R9, Register.R10, Register.R11]
        : [Register.RAX, Register.RCX, Register.RDX, Register.RSI, Register.RDI, Register.R8, Register.R9, Register.R10, Register.R11];

    /// <summary>
    /// Calls <paramref name="visit"/> for each instruction of
    /// <paramref name="code"/> in address order with the state before it. A
    /// block starts from the meet of its predecessors; a block no predecessor
    /// reaches, or any block when the passes do not converge within
    /// <paramref name="maxPasses"/>, starts with nothing known.
    /// </summary>
    internal static void Walk(IReadOnlyList<Instruction> code, FunctionGraph graph, ulong imageBase, bool windows,
        Action<Instruction, ProvenanceState> visit, CancellationToken ct = default, int maxPasses = MaxPasses)
    {
        var args = ArgumentRegisters(windows);
        var clobbered = Clobbered(windows);
        var entry = new ProvenanceState();
        for (int i = 0; i < args.Length; i++) entry.Set(args[i], new ArgOrigin(i));
        var factory = new InstructionInfoFactory();
        var blocks = graph.Blocks;
        var spans = new (int From, int To)[blocks.Count];
        var index = new Dictionary<uint, int>();
        int at = 0;
        for (int i = 0; i < blocks.Count; i++)
        {
            index[blocks[i].Start] = i;
            while (at < code.Count && code[at].IP - imageBase < blocks[i].Start) at++;
            int from = at;
            while (at < code.Count && code[at].IP - imageBase < blocks[i].End) at++;
            spans[i] = (from, at);
        }
        ProvenanceState Run(int block, ProvenanceState start, Action<Instruction, ProvenanceState>? each)
        {
            var s = start.Clone();
            for (int k = spans[block].From; k < spans[block].To; k++)
            {
                var ins = code[k];
                each?.Invoke(ins, s);
                if (ins.FlowControl is FlowControl.Call or FlowControl.IndirectCall) s.Call(ins, clobbered, windows);
                else s.Apply(ins, factory);
            }
            return s;
        }
        var inStates = new ProvenanceState?[blocks.Count];
        var outStates = new ProvenanceState?[blocks.Count];
        bool converged = false;
        for (int pass = 0; pass < maxPasses; pass++)
        {
            bool changed = false;
            for (int i = 0; i < blocks.Count; i++)
            {
                ct.ThrowIfCancellationRequested();
                var state = i == 0 ? entry.Clone() : null;
                foreach (var p in blocks[i].Predecessors)
                {
                    if (!index.TryGetValue(p.From, out var pi) || outStates[pi] is not { } po) continue;
                    if (state == null) state = po.Clone();
                    else state.Meet(po);
                }
                if (state == null) continue;
                if (inStates[i] is { } prev)
                {
                    if (!prev.Meet(state)) continue;
                }
                else inStates[i] = state;
                changed = true;
                outStates[i] = Run(i, inStates[i]!, null);
            }
            if (!changed) { converged = true; break; }
        }
        for (int i = 0; i < blocks.Count; i++)
            Run(i, converged ? inStates[i] ?? ProvenanceState.Unknown() : ProvenanceState.Unknown(), visit);
    }
}
