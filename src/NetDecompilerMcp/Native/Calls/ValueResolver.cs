using Iced.Intel;

namespace NetDecompilerMcp.Native.Calls;

internal enum VKind : byte
{
    Unknown,
    /// <summary>A number (immediates, xor reg,reg, constant arithmetic, read-only data).</summary>
    Const,
    /// <summary>An address in the image (lea of RIP-relative / relocated absolute data, push offset).</summary>
    Addr,
    /// <summary>The contents of writable memory or an import slot at <see cref="Val.Rva"/>.</summary>
    Load,
    /// <summary>The return value of the call at <see cref="Val.Site"/>.</summary>
    Result,
    /// <summary>The address of a local of the current frame.</summary>
    StackAddr,
    /// <summary>A local whose address is taken (written by calls it is passed to): <see cref="Val.Num"/> is the offset, <see cref="Val.Site"/> 0 for [rsp+n], 1 for [rbp+n].</summary>
    TakenLocal,
    /// <summary>Internal: the path loops back to a location already being resolved.</summary>
    Cycle,
    /// <summary>Slice mode: the value at function entry; <see cref="Val.Site"/> is the register, else <see cref="Val.Num"/> the stack offset at entry.</summary>
    Incoming,
    /// <summary>Slice mode: paths with different values in <see cref="Val.Alternatives"/>; <see cref="Val.Rva"/> 1 when more were cut.</summary>
    Merge,
    /// <summary>Slice mode: a load from [base + <see cref="Val.Num"/>] at <see cref="Val.Site"/>; Alternatives[0] is the base.</summary>
    Field,
}

/// <summary>
/// A resolved value and how it was derived (instructions from the use back to the definition). An Unknown from a merge
/// of different values keeps them in <see cref="Alternatives"/>.
/// </summary>
internal readonly record struct Val(VKind Kind, ulong Num, uint Rva, uint Site, string Why, Val[]? Alternatives = null)
{
    /// <summary>The instruction that defines the value (the innermost of the derivation), 0 when none.</summary>
    public uint At { get; init; }

    public static Val Unknown(string why) => new(VKind.Unknown, 0, 0, 0, why);
    public bool SameAs(in Val o) => Kind == o.Kind && Num == o.Num && Rva == o.Rva && Site == o.Site;
}

internal enum LocKind : byte
{
    Register,
    /// <summary>[stack pointer + offset] at the current point.</summary>
    Stack,
    /// <summary>[frame pointer (ebp / rbp) + offset].</summary>
    Frame,
}

/// <summary>A register, a stack slot (offset from the stack pointer at the current point) or a frame slot.</summary>
internal readonly record struct Loc(Register Reg, int Slot, LocKind Kind)
{
    public bool IsSlot => Kind == LocKind.Stack;
    public static Loc Of(Register r) => new(r.GetFullRegister(), 0, LocKind.Register);
    public static Loc Stack(int offset) => new(Register.None, offset, LocKind.Stack);
    public static Loc Frame(int offset) => new(Register.None, offset, LocKind.Frame);
}

/// <summary>
/// Backward constant propagation inside one function: the value a register, stack slot or frame slot holds before an
/// instruction, following copies, immediates, lea of data addresses, xor-zeroing and constant arithmetic back through the
/// block and its predecessors. Paths that merge with different values, loops and anything not modelled give Unknown with
/// the reason. Bounded by a step budget and a recursion depth.
/// </summary>
internal sealed class ValueResolver
{
    private const int MaxDepth = 40;
    private const int MaxPredecessors = 8;
    private const int MaxAlternatives = 4;
    /// <summary>Slice mode: paths kept per merge.</summary>
    public const int MaxSlicePaths = 8;
    private readonly CallAnalysis _owner;
    private readonly FunctionCode _code;
    private readonly bool _is64;
    private readonly Register _sp = Register.RSP;
    private static readonly ulong SpBit = 1UL << FunctionCode.Bit(Register.RSP);
    private static readonly ulong FpBit = 1UL << FunctionCode.Bit(Register.RBP);
    private readonly int _slot;
    private readonly HashSet<(int Block, Loc Loc)> _active = [];
    private int _steps;
    private int _depth;

    public ValueResolver(CallAnalysis owner, FunctionCode code)
    {
        _owner = owner;
        _code = code;
        _is64 = owner.Is64;
        _slot = _is64 ? 8 : 4;
    }

    public FunctionCode Code => _code;

    /// <summary>Instruction steps allowed per top-level query.</summary>
    public int Budget { get; set; } = 6000;

    /// <summary>
    /// Slice mode (value tracing): merges keep every path, loops are <see cref="VKind.Cycle"/>, the function entry gives
    /// <see cref="VKind.Incoming"/>, [reg+n] loads give <see cref="VKind.Field"/> and a frame slot continues as the stack
    /// slot the frame pointer was set from.
    /// </summary>
    public bool Slice { get; init; }

    /// <summary>Instruction steps the last query took.</summary>
    public int Steps => _steps;

    /// <summary>The value of <paramref name="loc"/> just before instruction <paramref name="index"/> of block <paramref name="block"/>.</summary>
    public Val ValueBefore(Loc loc, int block, int index)
    {
        _steps = 0;
        _depth = 0;
        _active.Clear();
        var v = Walk(loc, block, index);
        return v.Kind == VKind.Cycle && !Slice ? Val.Unknown("loop") : v;
    }

    /// <summary>The value the instruction at <paramref name="index"/> of <paramref name="block"/> stores into memory (a mov or push).</summary>
    public Val ValueStoredBy(int block, int index)
    {
        _steps = 0;
        _depth = 0;
        _active.Clear();
        ref readonly var d = ref _code.Blocks[block][index];
        var v = d.I.Mnemonic == Mnemonic.Push ? PushValue(in d, block, index)
            : d.I.Op0Kind == OpKind.Memory ? StoreValue(in d, block, index, Math.Max(1, d.I.MemorySize.GetSize()))
            : Val.Unknown($"{d.I.Mnemonic.ToString().ToLowerInvariant()} does not store to memory");
        v = Why(v, in d);
        return v.Kind == VKind.Cycle && !Slice ? Val.Unknown("loop") : v;
    }

    private Val Walk(Loc loc, int block, int index)
    {
        if (++_depth > MaxDepth) { _depth--; return Val.Unknown("too deep"); }
        var entered = new List<(int, Loc)>();
        try { return WalkCore(loc, block, index, entered); }
        finally
        {
            _depth--;
            foreach (var e in entered) _active.Remove(e);
        }
    }

    private static bool IsImmediateOrNothing(in Instruction x) => x.Mnemonic is Mnemonic.Cmp or Mnemonic.Test or Mnemonic.Push or Mnemonic.Bt
        or Mnemonic.Prefetchnta or Mnemonic.Prefetcht0 or Mnemonic.Prefetcht1 or Mnemonic.Prefetcht2 or Mnemonic.Prefetchw or Mnemonic.Nop;

    /// <summary>Walks back from <paramref name="index"/> in <paramref name="block"/>, continuing into single predecessors without recursion.</summary>
    private Val WalkCore(Loc loc, int block, int index, List<(int, Loc)> entered)
    {
        while (true)
        {
            var insns = _code.Blocks[block];
            for (int i = Math.Min(index, insns.Length) - 1; i >= 0; i--)
            {
                if (++_steps > Budget) return Val.Unknown("search budget exhausted");
                ref readonly var d = ref insns[i];
                ref readonly var x = ref d.I;

                if (x.FlowControl is FlowControl.Call or FlowControl.IndirectCall)
                {
                    if (_owner.IsTransparentCall(in d)) continue;
                    switch (loc.Kind)
                    {
                        case LocKind.Register:
                            if (IsVolatile(loc.Reg))
                                return loc.Reg == Register.RAX || _is64 && loc.Reg == Register.ZMM0
                                    ? new Val(VKind.Result, 0, 0, d.Rva, $"result of the call at {Va(d.Rva)}")
                                    : Val.Unknown($"{Name(loc.Reg)} is clobbered by the call at {Va(d.Rva)}");
                            continue;
                        case LocKind.Frame:
                            // x86 [ebp+8...] are the parameters: a callee cannot reach them unless their address is taken (checked)
                            if (!_is64 && loc.Slot >= 8) continue;
                            return Val.Unknown($"local may be changed by the call at {Va(d.Rva)}");
                    }
                    if (_is64)
                    {
                        if (_code.StackAddressTaken(loc.Slot)) return new Val(VKind.TakenLocal, (ulong)(long)loc.Slot, 0, 0, $"local may be changed by the call at {Va(d.Rva)}");
                        continue;
                    }
                    // x86: the callee may remove its stack arguments (stdcall)
                    var pops = _owner.CalleePops(_code, block, i);
                    if (pops == null) return Val.Unknown($"stack effect of the call at {Va(d.Rva)} is unknown");
                    loc = Loc.Stack(loc.Slot + pops.Value);
                    continue;
                }

                if (loc.Kind == LocKind.Frame)
                {
                    if ((d.Writes & FpBit) != 0)
                    {
                        if (Slice && FrameBase(in x) is { } fromSp) { loc = Loc.Stack(loc.Slot + fromSp); continue; }
                        return Val.Unknown($"frame pointer set at {Va(d.Rva)}");
                    }
                    if (x.Op0Kind != OpKind.Memory || IsImmediateOrNothing(in x)) continue;
                    if (x.MemoryBase.GetFullRegister() == Register.RBP && x.MemoryIndex == Register.None)
                    {
                        int at = (int)(long)x.MemoryDisplacement64;
                        int size = Math.Max(1, x.MemorySize.GetSize());
                        if (at == loc.Slot) return Why(StoreValue(in d, block, i, size), d);
                        if (at < loc.Slot + _slot && loc.Slot < at + size) return Val.Unknown($"partly overwritten at {Va(d.Rva)}");
                        continue;
                    }
                    if (x.Mnemonic is Mnemonic.Mov or Mnemonic.And or Mnemonic.Or or Mnemonic.Add or Mnemonic.Sub or Mnemonic.Inc or Mnemonic.Dec
                        or Mnemonic.Xchg or Mnemonic.Movss or Mnemonic.Movsd or Mnemonic.Movq or Mnemonic.Movups or Mnemonic.Movaps or Mnemonic.Movdqu)
                        return Val.Unknown($"local may be overwritten through a pointer at {Va(d.Rva)}");
                    continue;
                }

                if (loc.Kind == LocKind.Stack)
                {
                    // a write to the slot
                    if (x.Op0Kind == OpKind.Memory && x.MemoryBase.GetFullRegister() == _sp && x.MemoryIndex == Register.None && !IsImmediateOrNothing(in x))
                    {
                        int at = (int)(long)x.MemoryDisplacement64;
                        int size = Math.Max(1, x.MemorySize.GetSize());
                        if (at == loc.Slot) return Why(StoreValue(in d, block, i, size), d);
                        if (at < loc.Slot + _slot && loc.Slot < at + size) return Val.Unknown($"partly overwritten at {Va(d.Rva)}");
                    }
                    if (x.Mnemonic == Mnemonic.Push)
                    {
                        if (loc.Slot == 0) return Why(PushValue(in d, block, i), d);
                        loc = Loc.Stack(loc.Slot + x.StackPointerIncrement);
                        continue;
                    }
                    if (x.Mnemonic is Mnemonic.Pop or Mnemonic.Pushfd or Mnemonic.Pushfq or Mnemonic.Popfd or Mnemonic.Popfq && x.StackPointerIncrement != 0)
                    {
                        loc = Loc.Stack(loc.Slot + x.StackPointerIncrement);
                        continue;
                    }
                    if ((d.Writes & SpBit) == 0) continue;
                    if (x.Mnemonic is Mnemonic.Sub or Mnemonic.Add && x.Op0Kind == OpKind.Register && x.Op0Register.GetFullRegister() == _sp && IsImmediate(x.Op1Kind))
                    {
                        long imm = (long)x.GetImmediate(1);
                        int delta = (int)(x.Mnemonic == Mnemonic.Sub ? -imm : imm);
                        loc = Loc.Stack(loc.Slot + delta);
                        if (loc.Slot < 0) return Val.Unknown("stack slot below the allocated frame");
                        continue;
                    }
                    return Val.Unknown($"stack pointer changed at {Va(d.Rva)}");
                }

                int bit = FunctionCode.Bit(loc.Reg);
                if (bit < 0 || (d.Writes & (1UL << bit)) == 0) continue;
                return Why(RegisterValue(d, loc.Reg, block, i), d);
            }

            // start of the block: the predecessors
            var b = _code.Graph.Blocks[block];
            if (b.Start == _code.Function.Start && b.Predecessors.Count == 0)
            {
                if (Slice && loc.Kind != LocKind.Frame)
                    return loc.Kind == LocKind.Register
                        ? new Val(VKind.Incoming, 0, 0, (uint)loc.Reg, $"incoming {Name(loc.Reg)}")
                        : new Val(VKind.Incoming, (ulong)(long)loc.Slot, 0, 0, $"incoming stack argument [sp+{loc.Slot:X}h]");
                return Val.Unknown(loc.Kind switch
                {
                    LocKind.Register => $"incoming {Name(loc.Reg)} (parameter or caller state)",
                    _ => "incoming stack argument",
                });
            }
            if (b.Predecessors.Count == 0) return Val.Unknown("block has no known predecessor");
            if (b.Predecessors.Count > MaxPredecessors) return Val.Unknown("too many incoming paths");
            if (!_active.Add((block, loc))) return new Val(VKind.Cycle, 0, 0, 0, "loop");
            entered.Add((block, loc));
            if (b.Predecessors.Count == 1)
            {
                int p = _code.BlockIndexOf(b.Predecessors[0].From);
                if (p < 0) return Val.Unknown("predecessor not decoded");
                block = p;
                index = int.MaxValue;
                continue;
            }
            return Merge(loc, b);
        }
    }

    /// <summary>The stack offset the frame pointer is set from (mov rbp, rsp / lea rbp, [rsp+n]), or null.</summary>
    private static int? FrameBase(in Instruction x)
    {
        if (x.Op0Kind != OpKind.Register || x.Op0Register.GetFullRegister() != Register.RBP) return null;
        if (x.Mnemonic == Mnemonic.Mov && x.Op1Kind == OpKind.Register && x.Op1Register.GetFullRegister() == Register.RSP) return 0;
        if (x.Mnemonic == Mnemonic.Lea && x.MemoryBase.GetFullRegister() == Register.RSP && x.MemoryIndex == Register.None) return (int)(long)x.MemoryDisplacement64;
        return null;
    }

    private Val SliceMerge(Loc loc, Code.BasicBlock b)
    {
        var values = new List<Val>();
        bool loop = false, cut = false;
        foreach (var e in b.Predecessors)
        {
            int p = _code.BlockIndexOf(e.From);
            var v = p < 0 ? Val.Unknown("predecessor not decoded") : Walk(loc, p, int.MaxValue);
            if (v.Kind == VKind.Cycle) { loop = true; continue; }
            if (values.Any(o => o.SameAs(in v) && (v.Kind != VKind.Unknown || o.Why == v.Why))) continue;
            if (values.Count >= MaxSlicePaths) { cut = true; continue; }
            values.Add(v);
        }
        if (values.Count == 0) return new Val(VKind.Cycle, 0, 0, 0, "loop");
        if (values.Count == 1 && !loop) return values[0] with { Why = values[0].Why + $" (same on {b.Predecessors.Count} paths)" };
        // the join's block start locates the merge and the loop (a value of their own has no defining instruction)
        if (loop) values.Add(new Val(VKind.Cycle, 0, 0, 0, $"carried around the loop at {Va(b.Start)}") { At = b.Start });
        return new Val(VKind.Merge, (ulong)b.Predecessors.Count, cut ? 1u : 0, 0, $"{b.Predecessors.Count} paths join at {Va(b.Start)}", [.. values]) { At = b.Start };
    }

    private Val Merge(Loc loc, Code.BasicBlock b)
    {
        if (Slice) return SliceMerge(loc, b);
        var values = new List<Val>();
        foreach (var e in b.Predecessors)
        {
            int p = _code.BlockIndexOf(e.From);
            if (p < 0) return Val.Unknown("predecessor not decoded");
            var v = Walk(loc, p, int.MaxValue);
            if (v.Kind == VKind.Cycle) continue;
            // one unknown path decides (and keeps the search linear in the common case)
            if (v.Kind == VKind.Unknown) return v;
            if (!values.Any(o => o.SameAs(in v))) values.Add(v);
        }
        if (values.Count == 0) return new Val(VKind.Cycle, 0, 0, 0, "loop");
        if (values.Count == 1) return values[0] with { Why = values[0].Why + $" (same on {b.Predecessors.Count} paths)" };
        return new Val(VKind.Unknown, 0, 0, 0, $"differs between paths ({string.Join(" / ", values.Take(MaxAlternatives).Select(Short))})",
            [.. values.Take(MaxAlternatives)]);
    }

    private static string Short(Val v) => v.Kind switch
    {
        VKind.Const => $"0x{v.Num:X}",
        VKind.Addr => $"&{v.Rva:X}",
        VKind.Load => $"[{v.Rva:X}]",
        VKind.Result => $"result@{v.Site:X}",
        _ => v.Kind.ToString(),
    };

    private string Va(uint rva) => $"0x{_owner.Image.ImageBase + rva:X}";

    private static string Name(Register r) => r.ToString().ToLowerInvariant();

    private Val Why(Val v, in Decoded d)
    {
        var text = $"{d.I} @{Va(d.Rva)}";
        return v with { Why = string.IsNullOrEmpty(v.Why) ? text : text + " <- " + v.Why, At = v.At != 0 ? v.At : d.Rva };
    }


    private bool IsVolatile(Register full) => _is64
        ? _owner.Abi.IsVolatile(full)
        : full is Register.RAX or Register.RCX or Register.RDX || (full >= Register.ZMM0 && full <= Register.ZMM7);

    private static bool IsImmediate(OpKind k) => k is OpKind.Immediate8 or OpKind.Immediate8to16 or OpKind.Immediate8to32 or OpKind.Immediate8to64
        or OpKind.Immediate16 or OpKind.Immediate32 or OpKind.Immediate32to64 or OpKind.Immediate64;

    private ulong Mask(int bytes) => bytes >= 8 ? ulong.MaxValue : (1UL << (bytes * 8)) - 1;

    /// <summary>An immediate operand: an address when relocated / RIP-confirmed, else a number.</summary>
    private Val Immediate(in Decoded d, int operand, int destBytes)
    {
        if (d.HasImm) return new Val(VKind.Addr, 0, d.ImmRva, 0, "");
        ulong v = d.I.GetImmediate(operand) & Mask(destBytes);
        return new Val(VKind.Const, v, 0, 0, "");
    }

    /// <summary>A memory operand read: an import slot or writable data is a load; read-only data is a constant.</summary>
    private Val MemoryRead(in Decoded d, int bytes, int block, int index)
    {
        ref readonly var x = ref d.I;
        if (d.HasMem) return _owner.ReadMemory(d.MemRva, bytes);
        if (x.MemoryIndex == Register.None && x.MemoryBase.GetFullRegister() is var b && (b == _sp || (b == Register.RBP && _code.HasFramePointer)))
        {
            int disp = (int)(long)x.MemoryDisplacement64;
            if (b == _sp) return Walk(Loc.Stack(disp), block, index);
            if (_code.FrameAddressTaken(disp)) return new Val(VKind.TakenLocal, (ulong)(long)disp, 0, 1, $"local [rbp{disp:+0;-0}] has its address taken");
            return Walk(Loc.Frame(disp), block, index);
        }
        if (Slice && x.MemoryIndex == Register.None && x.MemoryBase != Register.None && x.MemoryBase != Register.RIP)
        {
            var baseValue = Walk(Loc.Of(x.MemoryBase), block, index);
            long disp = _is64 ? (long)x.MemoryDisplacement64 : (int)(uint)x.MemoryDisplacement64;
            return new Val(VKind.Field, (ulong)disp, 0, d.Rva, $"load from {MemText(in x)}", [baseValue]);
        }
        return Val.Unknown($"load from {MemText(in x)}");
    }

    private static string MemText(in Instruction x)
    {
        var s = x.ToString();
        int open = s.IndexOf('['), close = s.IndexOf(']');
        return open >= 0 && close > open ? s[open..(close + 1)] : "memory";
    }

    private Val PushValue(in Decoded d, int block, int index)
    {
        ref readonly var x = ref d.I;
        switch (x.Op0Kind)
        {
            case OpKind.Register:
                return Walk(Loc.Of(x.Op0Register), block, index);
            case OpKind.Memory:
                // push [esp+n] reads relative to the stack pointer before the push
                return MemoryRead(in d, _slot, block, index);
            default:
                return IsImmediate(x.Op0Kind) ? Immediate(in d, 0, _slot) : Val.Unknown("push");
        }
    }

    /// <summary>The value an instruction stores into a stack slot.</summary>
    private Val StoreValue(in Decoded d, int block, int index, int size)
    {
        ref readonly var x = ref d.I;
        switch (x.Mnemonic)
        {
            case Mnemonic.Mov:
            case Mnemonic.Movss or Mnemonic.Movsd or Mnemonic.Movq or Mnemonic.Movd or Mnemonic.Movaps or Mnemonic.Movups
                or Mnemonic.Movapd or Mnemonic.Movupd or Mnemonic.Movdqa or Mnemonic.Movdqu or Mnemonic.Vmovss or Mnemonic.Vmovsd:
                if (x.Op1Kind == OpKind.Register)
                {
                    var v = Walk(Loc.Of(x.Op1Register), block, index);
                    return v.Kind == VKind.Const ? v with { Num = v.Num & Mask(size) } : v;
                }
                return IsImmediate(x.Op1Kind) ? Immediate(in d, 1, size) : Val.Unknown($"stored by {x.Mnemonic}");
            case Mnemonic.And when IsImmediate(x.Op1Kind) && x.GetImmediate(1) == 0:
                return new Val(VKind.Const, 0, 0, 0, "");
            case Mnemonic.Or when IsImmediate(x.Op1Kind) && (x.GetImmediate(1) & Mask(size)) == Mask(size):
                return new Val(VKind.Const, Mask(size), 0, 0, "");
            default:
                return Val.Unknown($"stored by {x.Mnemonic.ToString().ToLowerInvariant()}");
        }
    }

    /// <summary>The value an instruction leaves in register <paramref name="full"/>, which it writes.</summary>
    private Val RegisterValue(Decoded d, Register full, int block, int index)
    {
        var x = d.I;
        bool explicitDest = x.Op0Kind == OpKind.Register && x.Op0Register.GetFullRegister() == full;
        if (!explicitDest)
        {
            if (x.Mnemonic == Mnemonic.Xchg && x.Op1Kind == OpKind.Register && x.Op1Register.GetFullRegister() == full && x.Op0Kind == OpKind.Register)
                return Walk(Loc.Of(x.Op0Register), block, index);
            if (x.Mnemonic == Mnemonic.Pop && x.Op0Kind == OpKind.Register) { }
            else return Val.Unknown($"set by {x.Mnemonic.ToString().ToLowerInvariant()}");
        }
        var dest = x.Op0Register;
        int bytes = dest.GetSize();
        bool vector = full >= Register.ZMM0 && full <= Register.ZMM31;
        // 8 / 16-bit writes keep the upper bits: not modelled (32-bit writes zero-extend on x64)
        if (!vector && bytes < 4 && x.Mnemonic is not (Mnemonic.Movzx or Mnemonic.Movsx))
            return Val.Unknown($"partial write by {x.Mnemonic.ToString().ToLowerInvariant()}");
        if (vector) return VectorValue(in d, block, index);

        Val Src(int operand)
        {
            var k = x.GetOpKind(operand);
            if (k == OpKind.Register) return Walk(Loc.Of(x.GetOpRegister(operand)), block, index);
            if (k == OpKind.Memory) return MemoryRead(in d, x.MemorySize.GetSize(), block, index);
            return IsImmediate(k) ? Immediate(in d, operand, bytes) : Val.Unknown("operand");
        }
        Val Fold(Val v, Func<ulong, ulong> f) =>
            v.Kind == VKind.Const ? v with { Num = f(v.Num) & Mask(bytes) }
            : v.Kind == VKind.Merge ? v with { Alternatives = [.. v.Alternatives!.Select(a => Fold(a, f))] }
            : v.Kind is VKind.Unknown or VKind.Cycle ? v : Val.Unknown($"{x.Mnemonic.ToString().ToLowerInvariant()} of a non-constant");
        bool SameRegs() => x.Op1Kind == OpKind.Register && x.Op1Register.GetFullRegister() == full;

        switch (x.Mnemonic)
        {
            case Mnemonic.Mov:
            {
                var v = Src(1);
                return v.Kind == VKind.Const ? v with { Num = v.Num & Mask(bytes) } : v;
            }
            case Mnemonic.Movzx:
            {
                var v = Src(1);
                int srcBytes = x.Op1Kind == OpKind.Register ? x.Op1Register.GetSize() : x.MemorySize.GetSize();
                return v.Kind == VKind.Const ? v with { Num = v.Num & Mask(srcBytes) } : v.Kind == VKind.Unknown ? v : Val.Unknown("zero-extended non-constant");
            }
            case Mnemonic.Movsx or Mnemonic.Movsxd:
            {
                var v = Src(1);
                int srcBytes = x.Op1Kind == OpKind.Register ? x.Op1Register.GetSize() : x.MemorySize.GetSize();
                if (v.Kind != VKind.Const) return v.Kind == VKind.Unknown ? v : Val.Unknown("sign-extended non-constant");
                ulong n = v.Num & Mask(srcBytes);
                if (srcBytes < 8 && (n >> (srcBytes * 8 - 1) & 1) != 0) n |= ~Mask(srcBytes);
                return v with { Num = n & Mask(bytes) };
            }
            case Mnemonic.Lea:
            {
                if (d.HasMem) return new Val(VKind.Addr, 0, d.MemRva, 0, "");
                var baseReg = x.MemoryBase.GetFullRegister();
                long disp = (long)x.MemoryDisplacement64;
                if (!_is64) disp = (int)(uint)disp;
                if ((baseReg == _sp || (baseReg == Register.RBP && _code.HasFramePointer)) && x.MemoryIndex == Register.None) return new Val(VKind.StackAddr, (ulong)disp, 0, baseReg == _sp ? 0u : 1u, "");
                if (x.MemoryIndex != Register.None || baseReg == Register.None || baseReg == Register.RIP)
                {
                    if (baseReg == Register.None && x.MemoryIndex == Register.None) return new Val(VKind.Const, (ulong)disp & Mask(bytes), 0, 0, "");
                    return Val.Unknown("indexed address");
                }
                var v = Walk(Loc.Of(baseReg), block, index);
                if (v.Kind == VKind.Const) return v with { Num = (v.Num + (ulong)disp) & Mask(bytes) };
                if (v.Kind == VKind.Addr) return v with { Rva = (uint)(v.Rva + disp) };
                if (v.Kind == VKind.StackAddr) return v with { Num = v.Num + (ulong)disp };
                return v.Kind == VKind.Unknown ? v : Val.Unknown("address computed from a non-constant");
            }
            case Mnemonic.Xor or Mnemonic.Sub when SameRegs():
                return new Val(VKind.Const, 0, 0, 0, "");
            case Mnemonic.Or when IsImmediate(x.Op1Kind) && (x.GetImmediate(1) & Mask(bytes)) == Mask(bytes):
                return new Val(VKind.Const, Mask(bytes), 0, 0, "");
            case Mnemonic.And when IsImmediate(x.Op1Kind) && x.GetImmediate(1) == 0:
                return new Val(VKind.Const, 0, 0, 0, "");
            case Mnemonic.Add or Mnemonic.Sub when IsImmediate(x.Op1Kind):
            {
                var v = Walk(Loc.Of(dest), block, index);
                long imm = (long)x.GetImmediate(1);
                if (x.Mnemonic == Mnemonic.Sub) imm = -imm;
                if (v.Kind == VKind.Addr) return v with { Rva = (uint)(v.Rva + imm) };
                return Fold(v, n => n + (ulong)imm);
            }
            case Mnemonic.Or or Mnemonic.And or Mnemonic.Xor or Mnemonic.Shl or Mnemonic.Shr or Mnemonic.Sar when IsImmediate(x.Op1Kind):
            {
                var v = Walk(Loc.Of(dest), block, index);
                ulong imm = x.GetImmediate(1);
                return x.Mnemonic switch
                {
                    Mnemonic.Or => Fold(v, n => n | imm),
                    Mnemonic.And => Fold(v, n => n & imm),
                    Mnemonic.Xor => Fold(v, n => n ^ imm),
                    Mnemonic.Shl => Fold(v, n => n << (int)(imm & 63)),
                    Mnemonic.Shr => Fold(v, n => (n & Mask(bytes)) >> (int)(imm & 63)),
                    _ => Fold(v, n => bytes == 8 ? (ulong)((long)n >> (int)(imm & 63)) : (ulong)((int)(uint)n >> (int)(imm & 31))),
                };
            }
            case Mnemonic.Inc: return Fold(Walk(Loc.Of(dest), block, index), n => n + 1);
            case Mnemonic.Dec: return Fold(Walk(Loc.Of(dest), block, index), n => n - 1);
            case Mnemonic.Neg: return Fold(Walk(Loc.Of(dest), block, index), n => (ulong)-(long)n);
            case Mnemonic.Not: return Fold(Walk(Loc.Of(dest), block, index), n => ~n);
            case Mnemonic.Pop:
                return Walk(Loc.Stack(0), block, index);
            case Mnemonic.Xchg when x.Op1Kind == OpKind.Register:
                return Walk(Loc.Of(x.Op1Register), block, index);
            case Mnemonic.Movd or Mnemonic.Movq when x.Op1Kind == OpKind.Register:
                return Walk(Loc.Of(x.Op1Register), block, index);
            default:
                return Val.Unknown($"computed by {x.Mnemonic.ToString().ToLowerInvariant()}");
        }
    }

    /// <summary>xmm values: zeroing, copies and constants loaded from read-only data.</summary>
    private Val VectorValue(in Decoded d, int block, int index)
    {
        ref readonly var x = ref d.I;
        if (x.Mnemonic is Mnemonic.Xorps or Mnemonic.Xorpd or Mnemonic.Pxor or Mnemonic.Vxorps or Mnemonic.Vxorpd or Mnemonic.Vpxor
            && x.OpCount >= 2 && x.GetOpKind(x.OpCount - 1) == OpKind.Register && x.GetOpRegister(x.OpCount - 1) == x.GetOpRegister(x.OpCount - 2))
            return new Val(VKind.Const, 0, 0, 0, "");
        if (x.Mnemonic is Mnemonic.Movss or Mnemonic.Movsd or Mnemonic.Movaps or Mnemonic.Movups or Mnemonic.Movapd or Mnemonic.Movupd
            or Mnemonic.Movq or Mnemonic.Movd or Mnemonic.Vmovss or Mnemonic.Vmovsd)
        {
            var k = x.GetOpKind(x.OpCount - 1);
            if (k == OpKind.Register) return Walk(Loc.Of(x.GetOpRegister(x.OpCount - 1)), block, index);
            if (k == OpKind.Memory)
            {
                int size = Math.Min(8, x.MemorySize.GetSize());
                return MemoryRead(in d, size, block, index);
            }
        }
        return Val.Unknown($"computed by {x.Mnemonic.ToString().ToLowerInvariant()}");
    }
}
