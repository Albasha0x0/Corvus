using System.Buffers.Binary;
using Corvus.Native.Code;

namespace Corvus.Native.Calls;

/// <summary>A value the ARM32 backward resolver found (the same kinds as on ARM64).</summary>
internal sealed record A32Val(A64Kind Kind, uint At, string Why)
{
    public ulong Num { get; init; }
    public uint Rva { get; init; }
    public A32Loc Loc { get; init; }
    public A32Val[]? Inputs { get; init; }
    public bool Truncated { get; init; }
    /// <summary>A floating-point constant's number; null for integers.</summary>
    public string? Text { get; init; }

    public static A32Val Unknown(string why, uint at = 0) => new(A64Kind.Unknown, at, why);

    public bool SameAs(A32Val o) => Kind == o.Kind && Num == o.Num && Rva == o.Rva && Loc == o.Loc && Kind is not (A64Kind.Merge or A64Kind.Field or A64Kind.Unknown);
}

/// <summary>
/// Backward data flow in a 32-bit ARM function: the value a register or stack slot holds before an instruction, through
/// copies, constants (mov, mvn, movw / movt), address forming (adr, ADD of PC and a literal-pool offset, relocated MOVW /
/// MOVT), loads (literal pools, globals, GOT slots, stack slots, fields), push / pop of saved registers, call results in
/// r0, conditional (IT or A32 condition) writes as merges with the prior value, and the merges of predecessor paths; loops
/// end in a cycle value. VFP registers (s0-s31, d0-d31): vmov of constants, core registers and other VFP registers, vldr of
/// literal pools, locals and globals, results in s0 / d0.
/// </summary>
internal sealed class Arm32Resolver(Arm32Trace host, A32Function code)
{
    public const int MaxPaths = 16;
    private const int Pc = A32Function.Pc, Sp = A32Function.Sp;
    private readonly Dictionary<(A32Loc, int), A32Val> _atStart = [];
    private readonly HashSet<A32Val> _acyclic = new(ReferenceEqualityComparer.Instance);
    private readonly HashSet<(A32Loc, int)> _open = [];
    public int Budget { get; init; } = 6000;
    public int Steps { get; private set; }

    private INativeImage Image => host.Index.Image;

    public A32Val Before(A32Loc loc, int block, int index, int depth = 0)
    {
        var steps = code.Blocks[block];
        for (int k = Math.Min(index, steps.Length) - 1; k >= 0; k--)
        {
            if (++Steps > Budget) return A32Val.Unknown($"stopped after {Budget} steps");
            var s = steps[k];
            if (A32Function.IsCall(s.I))
            {
                if (!loc.IsSlot && loc.Value is 0 or A32Function.VfpS or A32Function.VfpD) return new A32Val(A64Kind.Result, s.Rva, $"{s.Text} @{host.Va(s.Rva)}") { Rva = s.Rva };
                if (!loc.IsSlot && A32Function.IsVolatile(loc.Value)) return A32Val.Unknown($"clobbered by the call {s.Text} @{host.Va(s.Rva)}", s.Rva);
                continue;
            }
            if (Defined(loc, block, k, depth) is { } v) return v;
        }
        return AtStart(loc, block, depth);
    }

    /// <summary>The value a store at step <paramref name="k"/> writes (the register stored at <paramref name="target"/> for a pair).</summary>
    public A32Val Stored(int block, int k, uint? target = null)
    {
        var s = code.Blocks[block][k];
        if (!s.I.Stores || s.I.OperandCount == 0 || s.I.Op(0).Kind != ArmOperandKind.Register) return A32Val.Unknown($"not a store of a core register: {s.Text}", s.Rva);
        int reg = s.I.Op(0).Reg;
        if (s.I.Mnemonic == "strd" && target is { } t && s.Facts.HasMem && t == s.Facts.MemTarget + 4) reg = s.I.Op(1).Reg;
        return Before(A32Loc.Reg(reg), block, k);
    }

    /// <summary>The value a load into PC (or any word load) at step <paramref name="k"/> reads.</summary>
    public A32Val LoadedBy(int block, int k) => Load(code.Blocks[block][k], block, k, 0, 0, 4);

    private A32Val AtStart(A32Loc loc, int block, int depth)
    {
        var key = (loc, block);
        if (_atStart.TryGetValue(key, out var hit)) return hit;
        if (!_open.Add(key)) return new A32Val(A64Kind.Cycle, code.Blocks[block].FirstOrDefault()?.Rva ?? 0, "carried around a loop");
        var values = new List<A32Val>();
        if (code.Graph.Blocks[block].Start == code.Function.Start) values.Add(Incoming(loc));
        bool truncated = false;
        foreach (int p in code.Predecessors(block))
        {
            var v = Before(loc, p, code.Blocks[p].Length, depth + 1);
            if (values.Any(o => o.SameAs(v))) continue;
            if (values.Count >= MaxPaths) { truncated = true; break; }
            values.Add(v);
        }
        _open.Remove(key);
        A32Val result = values.Count switch
        {
            0 => A32Val.Unknown("no path reaches it"),
            1 => values[0],
            _ => new A32Val(A64Kind.Merge, code.Blocks[block].FirstOrDefault()?.Rva ?? 0, $"{values.Count} paths meet at {host.Va(code.Graph.Blocks[block].Start)}")
                { Inputs = [.. values], Truncated = truncated },
        };
        if (!ContainsCycle(result, _acyclic)) _atStart[key] = result;
        return result;
    }

    /// <summary>Whether a cycle value is among <paramref name="v"/>'s inputs, each shared merge input walked once (a plain walk is
    /// exponential in the merge depth).</summary>
    internal static bool ContainsCycle(A32Val v, HashSet<A32Val> acyclic)
    {
        if (v.Kind == A64Kind.Cycle) return true;
        if (v.Inputs == null || acyclic.Contains(v)) return false;
        foreach (var input in v.Inputs)
            if (ContainsCycle(input, acyclic)) return true;
        acyclic.Add(v);
        return false;
    }

    private A32Val Incoming(A32Loc loc)
    {
        if (loc.IsSlot && loc.Value < 0) return A32Val.Unknown($"local {A32Function.Name(loc, null)} not written on this path");
        if (!loc.IsSlot && loc.Value == 12) return A32Val.Unknown("r12 is not set in the function before here");
        return new A32Val(A64Kind.Incoming, code.Function.Start, "") { Loc = loc };
    }

    /// <summary>The value the instruction at step <paramref name="k"/> gives <paramref name="loc"/>, or null when it leaves it alone.</summary>
    private A32Val? Defined(A32Loc loc, int block, int k, int depth)
    {
        var s = code.Blocks[block][k];
        var v = Write(loc, s, block, k, depth);
        // a conditional write: either the new value or the one before
        if (v != null && s.I.IsConditional && v.Kind != A64Kind.Unknown)
        {
            var prior = Before(loc, block, k, depth);
            return v.SameAs(prior) ? v : new A32Val(A64Kind.Merge, s.Rva, $"conditionally set by {s.Text} @{host.Va(s.Rva)}") { Inputs = [v, prior] };
        }
        return v;
    }

    private A32Val? Write(A32Loc loc, A32Step s, int block, int k, int depth)
    {
        var i = s.I;
        string at = $"{s.Text} @{host.Va(s.Rva)}";
        if (loc.IsSlot) return SlotWrite(loc, s, block, k, depth, at);
        if (loc.IsVfp) return VfpWrite(loc, s, block, k, depth, at);

        int r = loc.Value;
        if ((i.Writes & (1 << r)) == 0) return null;
        // pop restores a register from its slot
        if (i.Mnemonic == "pop" && s.Sp is { } sp)
        {
            int rank = System.Numerics.BitOperations.PopCount((uint)(i.Op(0).Value & ((1 << r) - 1)));
            return Chain(Before(A32Loc.Slot(sp + 4 * rank), block, k, depth), at);
        }
        if (A32Function.Memory(i) is { } wb && wb.Reg == r && wb.Indexing != ArmIndexing.Offset)
            return A32Val.Unknown($"advanced by the writeback of {at}", s.Rva);
        if (A32Function.Dest(i) != r && !(i.Loads && i.Mnemonic is "ldrd" && i.Op(1).Reg == r))
            return A32Val.Unknown($"set by {at}", s.Rva);

        switch (i.Mnemonic)
        {
            case "mov" when i.OperandCount == 2 && i.Op(1).Kind == ArmOperandKind.Immediate:
                return new A32Val(A64Kind.Const, s.Rva, at) { Num = (uint)i.Op(1).Value };
            case "mvn" when i.OperandCount == 2 && i.Op(1).Kind == ArmOperandKind.Immediate:
                return new A32Val(A64Kind.Const, s.Rva, at) { Num = ~(uint)i.Op(1).Value };
            case "movw":
                return s.Facts.HasImm ? Address(Image.ImageBase + s.Facts.ImmTarget, s.Rva, at) : new A32Val(A64Kind.Const, s.Rva, at) { Num = (uint)i.Op(1).Value };
            case "movt":
            {
                var prior = Before(loc, block, k, depth);
                if (prior.Kind is not (A64Kind.Const or A64Kind.Addr)) return A32Val.Unknown($"movt over a value that is not a constant: {at}", s.Rva);
                ulong low = prior.Kind == A64Kind.Const ? prior.Num : Image.ImageBase + prior.Rva;
                ulong value = (low & 0xFFFF) | (ulong)i.Op(1).Value << 16;
                return s.Facts.HasImm ? Address(value, s.Rva, $"{prior.Why}; {at}") : new A32Val(A64Kind.Const, s.Rva, $"{prior.Why}; {at}") { Num = value };
            }
            case "mov" when i.OperandCount == 2 && i.Op(1).Kind == ArmOperandKind.Register:
                return Chain(Value(i.Op(1).Reg, s, block, k, depth), at);
            case "adr":
                return Address((uint)i.Op(1).Value, s.Rva, at);
            case "add" or "addw" or "sub" or "subw" when i.OperandCount is 2 or 3:
            {
                bool add = i.Mnemonic.StartsWith("add", StringComparison.Ordinal);
                var a = i.OperandCount == 2 ? Value(i.Op(0).Reg, s, block, k, depth) : Operand(i.Op(1), s, block, k, depth);
                var b = Operand(i.Op(i.OperandCount - 1), s, block, k, depth);
                return Combine(a, b, add, s.Rva, at);
            }
        }
        if (i.Loads)
        {
            int size = i.Mnemonic is "ldrd" ? 4 : i.AccessSize;
            int extra = i.Mnemonic is "ldrd" && i.Op(1).Reg == r ? 4 : 0;
            if (i.Mnemonic is "ldm" or "ldmdb" or "ldmda" or "ldmib" || A32Function.Memory(i) == null) return A32Val.Unknown($"set by {at}", s.Rva);
            return Load(s, block, k, depth, extra, size);
        }
        return A32Val.Unknown($"set by {at}", s.Rva);
    }

    /// <summary>The value a VFP instruction gives an S or D register, or null when it leaves it alone.</summary>
    private A32Val? VfpWrite(A32Loc loc, A32Step s, int block, int k, int depth, string at)
    {
        var i = s.I;
        if (A32Function.ListCovers(i, loc)) return A32Val.Unknown($"loaded by {at}", s.Rva);
        if (A32Function.VfpDest(i) is not { } dest) return null;
        if (dest != loc) return A32Function.Overlaps(dest, loc) ? A32Val.Unknown($"partly set by {at}", s.Rva) : null;
        bool dbl = loc.Value >= A32Function.VfpD;
        if (i.Mnemonic == "vmov" && i.OperandCount == 2)
        {
            var src = i.Op(1);
            if (src.Kind == ArmOperandKind.Text && src.Text is ['#', ..] imm
                && double.TryParse(imm[1..], System.Globalization.NumberStyles.Float, System.Globalization.CultureInfo.InvariantCulture, out double f))
                return Float(dbl ? (ulong)BitConverter.DoubleToInt64Bits(f) : (uint)BitConverter.SingleToInt32Bits((float)f), dbl, s.Rva, at);
            if (src.Kind == ArmOperandKind.Register && !dbl) return Chain(Value(src.Reg, s, block, k, depth), at);
            if (A32Function.Vfp(src) is { } from) return Chain(Before(from, block, k, depth), at);
        }
        if (i.Mnemonic == "vmov" && i.OperandCount == 3 && dbl && i.Op(1).Kind == ArmOperandKind.Register && i.Op(2).Kind == ArmOperandKind.Register)
        {
            var lo = Value(i.Op(1).Reg, s, block, k, depth);
            var hi = Value(i.Op(2).Reg, s, block, k, depth);
            return lo.Kind == A64Kind.Const && hi.Kind == A64Kind.Const ? Float((uint)lo.Num | (ulong)(uint)hi.Num << 32, true, s.Rva, at)
                : A32Val.Unknown($"set from {Describe(lo)} and {Describe(hi)}: {at}", s.Rva);
        }
        if (i.Mnemonic == "vldr" && A32Function.Memory(i) is { } m)
        {
            int size = dbl ? 8 : 4;
            if (m.Reg == Pc && s.Facts.HasMem || s.Facts.HasMem && !(Image.SectionAt(s.Facts.MemTarget) is { } sec && (sec.Access & SectionAccess.Write) != 0))
            {
                Span<byte> b = stackalloc byte[8];
                b.Clear();
                if (Image.Read(s.Facts.MemTarget, b[..size]) != size) return A32Val.Unknown($"reads 0x{Image.ImageBase + s.Facts.MemTarget:X}: {at}", s.Rva);
                return Float(BinaryPrimitives.ReadUInt64LittleEndian(b), dbl, s.Rva, $"{at} (contents of 0x{Image.ImageBase + s.Facts.MemTarget:X})");
            }
            if (s.Facts.HasMem) return new A32Val(A64Kind.Global, s.Rva, at) { Rva = s.Facts.MemTarget };
            if (code.Slot(s) is { } slot)
                return dbl ? A32Val.Unknown($"a double read from local {A32Function.Name(A32Loc.Slot(slot), null)}: {at}", s.Rva)
                    : Chain(Before(A32Loc.Slot(slot), block, k, depth), at);
            return new A32Val(A64Kind.Field, s.Rva, at) { Num = (ulong)(m.Subtract ? -m.Value : m.Value), Inputs = [Value(m.Reg, s, block, k, depth)] };
        }
        return A32Val.Unknown($"set by {at}", s.Rva);
    }

    private static A32Val Float(ulong bits, bool dbl, uint at, string why) => new(A64Kind.Const, at, why)
    {
        Num = bits,
        Text = (dbl ? BitConverter.Int64BitsToDouble((long)bits) : BitConverter.Int32BitsToSingle((int)(uint)bits)).ToString("R", System.Globalization.CultureInfo.InvariantCulture) +
               (dbl ? "" : "f"),
    };

    /// <summary>A store into a stack slot: str / strd / push of a register, a partial or vector store that overlaps it.</summary>
    private A32Val? SlotWrite(A32Loc loc, A32Step s, int block, int k, int depth, string at)
    {
        var i = s.I;
        if (!i.Stores) return null;
        if (i.Mnemonic is "push" or "vpush" && s.Sp is { } sp)
        {
            if (i.Mnemonic == "vpush")
            {
                var v = i.Op(0);
                int size = v.Count * (v.Vector == ArmVector.D ? 8 : 4);
                return loc.Value >= sp - size && loc.Value < sp ? A32Val.Unknown($"a vector register is stored there by {at}", s.Rva) : null;
            }
            long mask = i.Op(0).Value;
            int n = System.Numerics.BitOperations.PopCount((ulong)mask);
            int start = sp - 4 * n;
            if (loc.Value < start || loc.Value >= sp) return null;
            if ((loc.Value - start) % 4 != 0) return A32Val.Unknown($"partly overwritten by {at}", s.Rva);
            int rank = (loc.Value - start) / 4, reg = 0;
            for (int seen = -1; reg < 16; reg++)
                if ((mask & (1 << reg)) != 0 && ++seen == rank) break;
            return Chain(Before(A32Loc.Reg(reg), block, k, depth), at);
        }
        if (code.Slot(s) is not { } slot) return null;
        int bytes = i.Mnemonic is "strd" ? 8 : i.AccessSize;
        if (loc.Value < slot || loc.Value >= slot + bytes) return null;
        // vstr s: the single register's value; vstr d: its low and high words
        if (i.Mnemonic == "vstr" && A32Function.Vfp(i.Op(0)) is { } stored)
            return stored.Value < A32Function.VfpD && loc.Value == slot ? Chain(Before(stored, block, k, depth), at)
                : A32Val.Unknown($"part of {A32Function.Name(stored, null)} stored there by {at}", s.Rva);
        if (i.Op(0).Kind != ArmOperandKind.Register) return A32Val.Unknown($"a vector register is stored there by {at}", s.Rva);
        if (i.AccessSize < 4) return A32Val.Unknown($"partly overwritten by {at}", s.Rva);
        int reg2 = loc.Value == slot ? i.Op(0).Reg : i.Mnemonic == "strd" && loc.Value == slot + 4 ? i.Op(1).Reg : -1;
        return reg2 < 0 ? A32Val.Unknown($"partly overwritten by {at}", s.Rva) : Chain(Before(A32Loc.Reg(reg2), block, k, depth), at);
    }

    /// <summary>A load at step <paramref name="k"/>: a literal pool word, a global, an import slot, a stack slot or a field.</summary>
    private A32Val Load(A32Step s, int block, int k, int depth, int extra, int size)
    {
        string at = $"{s.Text} @{host.Va(s.Rva)}";
        if (A32Function.Memory(s.I) is not { } m) return A32Val.Unknown($"set by {at}", s.Rva);
        if (m.Reg == Pc && s.Facts.HasMem) return Loaded(s.Facts.MemTarget + (uint)extra, size, s.Rva, at, constant: true);
        if (code.Slot(s) is { } slot)
        {
            if (size != 4) return A32Val.Unknown($"a partial load of a local: {at}", s.Rva);
            return Chain(Before(A32Loc.Slot(slot + extra), block, k, depth), at);
        }
        if (s.Facts.HasMem) return Loaded(s.Facts.MemTarget + (uint)extra, size, s.Rva, at, constant: false);
        if (m.Index != ArmOperand.NoReg)
        {
            // base + index: a GOT base plus a slot offset, both known
            var b = Value(m.Reg, s, block, k, depth);
            var x = Value(m.Index, s, block, k, depth);
            if (m.Shift == ArmShift.None || m.Amount == 0)
            {
                var sum = Combine(b, x, !m.Subtract, s.Rva, at);
                if (sum.Kind == A64Kind.Addr) return Loaded(sum.Rva + (uint)extra, size, s.Rva, $"{sum.Why}; {at}", constant: false);
            }
            return A32Val.Unknown($"loaded through an indexed address: {at}", s.Rva);
        }
        long disp = (m.Indexing == ArmIndexing.PostIndex ? 0 : m.Subtract ? -m.Value : m.Value) + extra;
        var bv = Value(m.Reg, s, block, k, depth);
        switch (bv.Kind)
        {
            case A64Kind.Addr: return Loaded((uint)(bv.Rva + disp), size, s.Rva, $"{bv.Why}; {at}", constant: false);
            case A64Kind.StackAddr: return Chain(Before(A32Loc.Slot((int)((long)bv.Num + disp)), block, k, depth), at);
        }
        return new A32Val(A64Kind.Field, s.Rva, at) { Num = (ulong)disp, Inputs = [bv] };
    }

    /// <summary>A register as an operand at step <paramref name="k"/>: PC is the address it reads, SP a stack address.</summary>
    private A32Val Value(int reg, A32Step s, int block, int k, int depth)
    {
        if (reg == Pc) return Address(s.I.Address + (s.I.Thumb ? 4u : 8u), s.Rva, $"pc @{host.Va(s.Rva)}");
        if (reg == Sp) return s.Sp is { } sp ? new A32Val(A64Kind.StackAddr, s.Rva, $"sp @{host.Va(s.Rva)}") { Num = (ulong)(long)sp } : A32Val.Unknown($"sp unknown at {host.Va(s.Rva)}", s.Rva);
        if (reg == code.FpReg && s.Fp is { } fp) return new A32Val(A64Kind.StackAddr, s.Rva, $"frame pointer @{host.Va(s.Rva)}") { Num = (ulong)(long)fp };
        return Before(A32Loc.Reg(reg), block, k, depth);
    }

    private A32Val Operand(ArmOperand op, A32Step s, int block, int k, int depth) => op.Kind switch
    {
        ArmOperandKind.Immediate => new A32Val(A64Kind.Const, s.Rva, "") { Num = (uint)op.Value },
        ArmOperandKind.Register => Value(op.Reg, s, block, k, depth),
        _ => A32Val.Unknown($"a shifted operand of {s.Text} @{host.Va(s.Rva)}", s.Rva),
    };

    private A32Val Combine(A32Val a, A32Val b, bool add, uint at, string why)
    {
        string Why(A32Val x, A32Val y) => string.Join("; ", new[] { x.Why, y.Why, why }.Where(w => w.Length > 0).Distinct());
        long Signed(ulong n) => add ? (long)(uint)n : -(long)(uint)n;
        return (a.Kind, b.Kind) switch
        {
            (A64Kind.Addr, A64Kind.Const) => Address((ulong)((long)(Image.ImageBase + a.Rva) + Signed(b.Num)) & 0xFFFFFFFF, at, Why(a, b)),
            (A64Kind.Const, A64Kind.Addr) when add => Address((Image.ImageBase + b.Rva + a.Num) & 0xFFFFFFFF, at, Why(a, b)),
            (A64Kind.Const, A64Kind.Const) => new A32Val(A64Kind.Const, at, Why(a, b)) { Num = (ulong)((long)a.Num + Signed(b.Num)) & 0xFFFFFFFF },
            (A64Kind.StackAddr, A64Kind.Const) => new A32Val(A64Kind.StackAddr, at, Why(a, b)) { Num = (ulong)((long)a.Num + (add ? (int)(uint)b.Num : -(int)(uint)b.Num)) },
            _ => A32Val.Unknown($"computed from {Describe(a)} and {Describe(b)}: {why}", at),
        };
    }

    private static A32Val Chain(A32Val v, string at) => v.Kind is A64Kind.Cycle or A64Kind.Merge ? v : v with { Why = v.Why.Length == 0 ? at : $"{v.Why}; {at}" };

    private static string Describe(A32Val v) => v.Kind switch
    {
        A64Kind.Incoming => $"incoming {A32Function.Name(v.Loc, null)}",
        A64Kind.Result => "a call result",
        A64Kind.Field => $"a field +0x{v.Num:X}",
        _ => v.Kind.ToString().ToLowerInvariant(),
    };

    private A32Val Address(ulong va, uint at, string why)
    {
        if (va < Image.ImageBase || va - Image.ImageBase >= Image.SizeOfImage) return new A32Val(A64Kind.Const, at, why) { Num = va };
        uint rva = (uint)(va - Image.ImageBase);
        // a Thumb code pointer names its function
        if ((rva & 1) != 0 && Image.SectionAt(rva) is { IsExecutable: true }) rva &= ~1u;
        return new A32Val(A64Kind.Addr, at, why) { Rva = rva };
    }

    /// <summary>
    /// A load from a known address: an import slot, a GOT slot of a function this image exports, a writable global (its
    /// writers), or the image's contents (literal pools and read-only data: relocated pointers become addresses).
    /// </summary>
    private A32Val Loaded(uint rva, int size, uint at, string why, bool constant)
    {
        if (host.ImportAt(rva) != null) return new A32Val(A64Kind.Import, at, why) { Rva = rva };
        if (host.LocalSlot(rva) is { } fn) return new A32Val(A64Kind.Addr, at, $"{why} (GOT slot of {host.Index.NameAt(fn) ?? host.Va(fn)})") { Rva = fn };
        bool writable = Image.SectionAt(rva) is { } sec && (sec.Access & SectionAccess.Write) != 0 && (sec.Access & SectionAccess.Execute) == 0;
        if (writable && !constant && !host.IsRelocated(rva)) return new A32Val(A64Kind.Global, at, why) { Rva = rva };
        Span<byte> b = stackalloc byte[4];
        b.Clear();
        if (size is not (1 or 2 or 4) || Image.Read(rva, b[..size]) != size) return A32Val.Unknown($"reads 0x{Image.ImageBase + rva:X}: {why}", at);
        uint value = BinaryPrimitives.ReadUInt32LittleEndian(b);
        if (size == 4 && host.IsRelocated(rva) && value >= Image.ImageBase && value - Image.ImageBase < Image.SizeOfImage)
            return Address(value, at, $"{why} (pointer at 0x{Image.ImageBase + rva:X})");
        if (writable && !constant) return new A32Val(A64Kind.Global, at, why) { Rva = rva };
        return new A32Val(A64Kind.Const, at, $"{why} (contents of 0x{Image.ImageBase + rva:X})") { Num = value };
    }
}
