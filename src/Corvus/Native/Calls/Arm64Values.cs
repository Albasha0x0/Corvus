using System.Buffers.Binary;
using AsmArm64;
using Corvus.Native.Code;

namespace Corvus.Native.Calls;

internal enum A64Kind : byte { Const, Addr, StackAddr, Import, Global, Field, Result, Incoming, Merge, Cycle, Unknown }

/// <summary>A value the backward resolver found: a constant, an address, a load, a call result, an incoming location, or a merge of paths.</summary>
internal sealed record A64Val(A64Kind Kind, uint At, string Why)
{
    public ulong Num { get; init; }
    public uint Rva { get; init; }
    public A64Loc Loc { get; init; }
    public A64Val[]? Inputs { get; init; }
    public bool Truncated { get; init; }

    public static A64Val Unknown(string why, uint at = 0) => new(A64Kind.Unknown, at, why);

    public bool SameAs(A64Val o) => Kind == o.Kind && Num == o.Num && Rva == o.Rva && Loc == o.Loc && Kind is not (A64Kind.Merge or A64Kind.Field or A64Kind.Unknown);
}

/// <summary>
/// Backward data flow in an ARM64 function: the value a register or stack slot holds before an instruction, through
/// copies, constants (mov / movk), address forming (adr, adrp + add), loads (literal pools, globals, GOT slots, stack
/// slots, fields), call results in x0, csel and the merges of predecessor paths; loops end in a cycle value.
/// </summary>
internal sealed class Arm64Resolver(Arm64Trace host, A64Function code)
{
    public const int MaxPaths = 16;
    private readonly Dictionary<(A64Loc, int), A64Val> _atStart = [];
    private readonly HashSet<(A64Loc, int)> _open = [];
    private readonly HashSet<A64Val> _acyclic = new(ReferenceEqualityComparer.Instance);
    public int Budget { get; init; } = 6000;
    public int Steps { get; private set; }

    private INativeImage Image => host.Index.Image;

    public A64Val Before(A64Loc loc, int block, int index, int depth = 0)
    {
        var steps = code.Blocks[block];
        for (int k = Math.Min(index, steps.Length) - 1; k >= 0; k--)
        {
            if (++Steps > Budget) return A64Val.Unknown($"stopped after {Budget} steps") with { Truncated = true };
            var s = steps[k];
            if (A64Function.IsCall(s.I) && host.IsGuardCheck(code, block, k))
            {
                if (!loc.IsSlot && loc.Value is 16 or 17 or 30) return A64Val.Unknown($"clobbered by the CFG check {s.Text} @{host.Va(s.Rva)}", s.Rva);
                continue;
            }
            if (A64Function.IsCall(s.I))
            {
                if (!loc.IsSlot && loc.Value is 0 or A64Function.VBase) return new A64Val(A64Kind.Result, s.Rva, $"{s.Text} @{host.Va(s.Rva)}") { Rva = s.Rva };
                if (!loc.IsSlot && A64Function.IsVolatile(loc.Value)) return A64Val.Unknown($"clobbered by the call {s.Text} @{host.Va(s.Rva)}", s.Rva);
                continue;
            }
            if (Defined(loc, block, k, depth) is { } v) return v;
        }
        return AtStart(loc, block, depth);
    }

    /// <summary>The value an instruction stores to memory (the stored register; the one at the referenced address for a pair).</summary>
    public A64Val Stored(int block, int k, uint? target = null)
    {
        var s = code.Blocks[block][k];
        if (!IsStore(s.I)) return A64Val.Unknown($"not a store: {s.Text}", s.Rva);
        int reg = A64Function.Reg(s.I, 0);
        if (s.I.Mnemonic is Arm64Mnemonic.STP or Arm64Mnemonic.STNP && target is { } t && s.Facts.HasMem && t != s.Facts.MemTarget) reg = A64Function.Reg(s.I, 1);
        if (reg < 0) return A64Val.Unknown($"stores no register: {s.Text}", s.Rva);
        if (reg == 31) return new A64Val(A64Kind.Const, s.Rva, $"{s.Text} @{host.Va(s.Rva)}");
        return Before(A64Loc.Reg(reg), block, k);
    }

    private A64Val AtStart(A64Loc loc, int block, int depth)
    {
        var key = (loc, block);
        if (_atStart.TryGetValue(key, out var hit)) return hit;
        if (!_open.Add(key)) return new A64Val(A64Kind.Cycle, code.Blocks[block].FirstOrDefault()?.Rva ?? 0, "carried around a loop");
        var values = new List<A64Val>();
        bool entry = code.Graph.Blocks[block].Start == code.Function.Start;
        if (entry) values.Add(Incoming(loc));
        bool truncated = false;
        foreach (int p in code.Predecessors(block))
        {
            var v = Before(loc, p, code.Blocks[p].Length, depth + 1);
            if (values.Any(o => o.SameAs(v))) continue;
            if (values.Count >= MaxPaths) { truncated = true; break; }
            values.Add(v);
        }
        _open.Remove(key);
        A64Val result = values.Count switch
        {
            0 => A64Val.Unknown("no path reaches it"),
            1 => values[0],
            _ => new A64Val(A64Kind.Merge, code.Blocks[block].FirstOrDefault()?.Rva ?? 0, $"{values.Count} paths meet at {host.Va(code.Graph.Blocks[block].Start)}")
                { Inputs = [.. values], Truncated = truncated },
        };
        // a value that depends on an unfinished loop head is not final: do not keep it
        if (!ContainsCycle(result, _acyclic)) _atStart[key] = result;
        return result;
    }

    /// <summary>Whether a cycle value is among <paramref name="v"/>'s inputs. Merges share inputs, so each value is walked once
    /// (<paramref name="acyclic"/> holds the ones already found free of cycles); a plain walk is exponential in the merge depth.</summary>
    internal static bool ContainsCycle(A64Val v, HashSet<A64Val> acyclic)
    {
        if (v.Kind == A64Kind.Cycle) return true;
        if (v.Inputs == null || acyclic.Contains(v)) return false;
        foreach (var input in v.Inputs)
            if (ContainsCycle(input, acyclic)) return true;
        acyclic.Add(v);
        return false;
    }

    private A64Val Incoming(A64Loc loc)
    {
        if (loc.IsSlot && loc.Value < 0) return A64Val.Unknown($"local {A64Function.Name(loc, null)} not written on this path");
        if (!loc.IsSlot && loc.Value is >= 9 and <= 18 or >= A64Function.VBase + 16)
            return A64Val.Unknown($"{A64Function.Name(loc, null)} is not set in the function before here");
        return new A64Val(A64Kind.Incoming, code.Function.Start, "") { Loc = loc };
    }

    /// <summary>The value the instruction at step <paramref name="k"/> gives <paramref name="loc"/>, or null when it leaves it alone.</summary>
    private A64Val? Defined(A64Loc loc, int block, int k, int depth)
    {
        var s = code.Blocks[block][k];
        var i = s.I;
        // formatted only when a value is found: most steps leave the location alone
        string? atText = null;
        string At() => atText ??= $"{s.Text} @{host.Va(s.Rva)}";
        if (loc.IsSlot)
        {
            if (!IsStore(i) || A64Function.Memory(s) is not { Slot: { } slot }) return null;
            int size = Arm64Inspector.AccessSize(in i);
            bool pair = i.Mnemonic is Arm64Mnemonic.STP or Arm64Mnemonic.STNP;
            int each = pair ? size / 2 : size;
            int reg;
            if (loc.Value == slot) reg = A64Function.Reg(i, 0);
            else if (pair && loc.Value == slot + each) reg = A64Function.Reg(i, 1);
            else if (loc.Value >= slot && loc.Value < slot + size) return A64Val.Unknown($"partly overwritten by {At()}", s.Rva);
            else return null;
            if (reg < 0) return A64Val.Unknown($"set by {At()}", s.Rva);
            if (reg == 31) return new A64Val(A64Kind.Const, s.Rva, At());
            return Chain(Before(A64Loc.Reg(reg), block, k, depth), At());
        }

        int r = loc.Value;
        // writeback changes the base register
        if (A64Function.Memory(s) is { } mem && (mem.Accessor.IsPreIncrement || mem.Post)
            && mem.Accessor.BaseRegister is { Kind: Arm64RegisterKind.X } b && b.Index == r)
            return A64Val.Unknown($"advanced by the writeback of {At()}", s.Rva);
        bool writes = A64Function.Dest(in i) is { } d && A64Function.Number(d) == r
                      || IsLoad(i) && i.Mnemonic is Arm64Mnemonic.LDP or Arm64Mnemonic.LDPSW or Arm64Mnemonic.LDNP && A64Function.Reg(i, 1) == r;
        if (!writes) return null;
        bool w = A64Function.IsW(i, 0);
        ulong mask = w ? 0xFFFF_FFFFUL : ulong.MaxValue;
        if (r >= A64Function.VBase && Vector(loc, block, k, depth, At()) is { } vector) return vector;

        switch (i.Mnemonic)
        {
            case Arm64Mnemonic.MOV when A64Function.Imm(in i, 1) is { } imm:
                return new A64Val(A64Kind.Const, s.Rva, At()) { Num = (ulong)imm & mask };
            case Arm64Mnemonic.MOVZ when A64Function.Imm(in i, 1) is { } imm:
                return new A64Val(A64Kind.Const, s.Rva, At()) { Num = (ulong)imm & mask };
            case Arm64Mnemonic.MOVN when A64Function.Imm(in i, 1) is { } imm:
                return new A64Val(A64Kind.Const, s.Rva, At()) { Num = ~(ulong)imm & mask };
            case Arm64Mnemonic.MOVK when A64Function.Imm(in i, 1) is { } imm:
            {
                int shift = i.OperandCount > 2 && i.GetOperand(2).Kind == Arm64OperandKind.Shift ? ((Arm64ShiftOperand)i.GetOperand(2)).Amount : 0;
                var prior = Before(loc, block, k, depth);
                if (prior.Kind != A64Kind.Const) return A64Val.Unknown($"movk over a value that is not a constant: {At()}", s.Rva);
                ulong bits = 0xFFFFUL << shift;
                return new A64Val(A64Kind.Const, s.Rva, $"{prior.Why}; {At()}") { Num = ((prior.Num & ~bits) | ((ulong)imm & bits)) & mask };
            }
            case Arm64Mnemonic.MOV when i.OperandCount >= 2 && i.GetOperand(1).Kind == Arm64OperandKind.Register:
            {
                var src = ((Arm64RegisterOperand)i.GetOperand(1)).Value;
                if (src.Kind == Arm64RegisterKind.SP) return s.Sp is { } sp ? new A64Val(A64Kind.StackAddr, s.Rva, At()) { Num = (ulong)(long)sp } : A64Val.Unknown($"sp unknown at {At()}", s.Rva);
                if (((Arm64RegisterOperand)i.GetOperand(1)).IsZeroRegister) return new A64Val(A64Kind.Const, s.Rva, At());
                if (A64Function.Number(src) < 0) return A64Val.Unknown($"copied from {src}: {At()}", s.Rva);
                return Chain(Before(A64Loc.Reg(A64Function.Number(src)), block, k, depth), At());
            }
            case Arm64Mnemonic.FMOV or Arm64Mnemonic.UMOV when A64Function.Reg(in i, 1) is var bits and >= A64Function.VBase:
                return Chain(Before(A64Loc.Reg(bits), block, k, depth), At());
            case Arm64Mnemonic.ADRP or Arm64Mnemonic.ADR when s.I.Flags.HasFlag(Arm64InstructionFlags.HasLabel):
            {
                long off = ((Arm64LabelOperand)i.GetOperand(1)).Offset;
                ulong pc = Image.ImageBase + s.Rva;
                ulong va = (i.Mnemonic == Arm64Mnemonic.ADRP ? pc & ~0xFFFUL : pc) + (ulong)off;
                return Address(va, s.Rva, At());
            }
            case Arm64Mnemonic.ADD or Arm64Mnemonic.SUB when A64Function.Imm(in i, 2) is { } imm && i.GetOperand(1).Kind == Arm64OperandKind.Register:
            {
                long delta = i.Mnemonic == Arm64Mnemonic.SUB ? -imm : imm;
                var src = ((Arm64RegisterOperand)i.GetOperand(1)).Value;
                if (src.Kind == Arm64RegisterKind.SP)
                    return s.Sp is { } sp ? new A64Val(A64Kind.StackAddr, s.Rva, At()) { Num = (ulong)(sp + delta) } : A64Val.Unknown($"sp unknown at {At()}", s.Rva);
                var v = Before(A64Loc.Reg(src.Index), block, k, depth);
                return v.Kind switch
                {
                    A64Kind.Addr => Address(Image.ImageBase + v.Rva + (ulong)delta, s.Rva, $"{v.Why}; {At()}"),
                    A64Kind.Const => new A64Val(A64Kind.Const, s.Rva, $"{v.Why}; {At()}") { Num = (v.Num + (ulong)delta) & mask },
                    A64Kind.StackAddr => v with { Num = (ulong)((long)v.Num + delta), At = s.Rva, Why = $"{v.Why}; {At()}" },
                    _ => A64Val.Unknown($"computed from {Describe(v)}: {At()}", s.Rva),
                };
            }
            case Arm64Mnemonic.CSEL when i.OperandCount >= 3:
            {
                var a = Operand(i, 1, block, k, depth);
                var c = Operand(i, 2, block, k, depth);
                return a.SameAs(c) ? a : new A64Val(A64Kind.Merge, s.Rva, $"selected by {At()}") { Inputs = [a, c] };
            }
        }

        if (IsLoad(i))
        {
            if (s.I.Flags.HasFlag(Arm64InstructionFlags.HasLabel) && s.Facts.HasMem)
                return Loaded(s.Facts.MemTarget, Arm64Inspector.AccessSize(in i), s.Rva, At(), constant: true);
            if (A64Function.Memory(s) is not { } m) return A64Val.Unknown($"set by {At()}", s.Rva);
            int size = Arm64Inspector.AccessSize(in i);
            bool pair = i.Mnemonic is Arm64Mnemonic.LDP or Arm64Mnemonic.LDPSW or Arm64Mnemonic.LDNP;
            int each = pair ? size / 2 : size;
            int extra = pair && A64Function.Reg(i, 1) == r ? each : 0;
            if (m.Slot is { } slot)
            {
                if (each != 8 && each != 4) return A64Val.Unknown($"a partial load of a local: {At()}", s.Rva);
                return Chain(Before(A64Loc.Slot(slot + extra), block, k, depth), At());
            }
            if (m.Accessor.HasIndexRegister) return A64Val.Unknown($"loaded through an indexed address: {At()}", s.Rva);
            if (s.Facts.HasMem) return Loaded(s.Facts.MemTarget + (uint)extra, each, s.Rva, At(), constant: false);
            long disp = (m.Post ? 0 : m.Accessor.HasImmediate ? m.Accessor.Immediate : 0) + extra;
            if (m.Accessor.BaseRegister.Kind != Arm64RegisterKind.X) return A64Val.Unknown($"set by {At()}", s.Rva);
            var bv = Before(A64Loc.Reg(m.Accessor.BaseRegister.Index), block, k, depth);
            switch (bv.Kind)
            {
                case A64Kind.Addr: return Loaded(bv.Rva + (uint)disp, each, s.Rva, $"{bv.Why}; {At()}", constant: false);
                case A64Kind.StackAddr: return Chain(Before(A64Loc.Slot((int)((long)bv.Num + disp)), block, k, depth), At());
            }
            return new A64Val(A64Kind.Field, s.Rva, At()) { Num = (ulong)disp, Inputs = [bv] };
        }
        return A64Val.Unknown($"set by {At()}", s.Rva);
    }

    /// <summary>
    /// A v register written by step <paramref name="k"/>: fmov of an immediate (its bits) or of a register, movi #0, scvtf / ucvtf
    /// of a constant; null for loads and stores, which the general path reads.
    /// </summary>
    private A64Val? Vector(A64Loc loc, int block, int k, int depth, string at)
    {
        var s = code.Blocks[block][k];
        var i = s.I;
        if (IsLoad(i) || i.OperandCount < 2) return null;
        bool single = A64Function.Dest(in i) is { VKind: Arm64RegisterVKind.S };
        ulong Bits(double value) => single ? BitConverter.SingleToUInt32Bits((float)value) : BitConverter.DoubleToUInt64Bits(value);
        var src = i.GetOperand(1);
        switch (i.Mnemonic)
        {
            case Arm64Mnemonic.FMOV when src.Kind == Arm64OperandKind.Immediate && ((Arm64ImmediateOperand)src).IsFloat:
                return new A64Val(A64Kind.Const, s.Rva, at) { Num = Bits(((Arm64ImmediateOperand)src).ValueAsFloat) };
            case Arm64Mnemonic.MOVI when A64Function.Imm(in i, 1) == 0:
                return new A64Val(A64Kind.Const, s.Rva, at);
            case Arm64Mnemonic.FMOV or Arm64Mnemonic.MOV or Arm64Mnemonic.ORR or Arm64Mnemonic.DUP or Arm64Mnemonic.INS when src.Kind == Arm64OperandKind.Register:
            {
                if (((Arm64RegisterOperand)src).IsZeroRegister) return new A64Val(A64Kind.Const, s.Rva, at);
                int from = A64Function.Reg(in i, 1);
                return from < 0 ? A64Val.Unknown($"set by {at}", s.Rva) : Chain(Before(A64Loc.Reg(from), block, k, depth), at);
            }
            case Arm64Mnemonic.SCVTF or Arm64Mnemonic.UCVTF when src.Kind == Arm64OperandKind.Register && A64Function.Reg(in i, 1) is var g and >= 0 and < A64Function.VBase:
            {
                var v = g == 31 ? new A64Val(A64Kind.Const, s.Rva, "zero register") : Before(A64Loc.Reg(g), block, k, depth);
                if (v.Kind != A64Kind.Const) return A64Val.Unknown($"converted from {Describe(v)}: {at}", s.Rva);
                bool w = ((Arm64RegisterOperand)src).Value.Kind == Arm64RegisterKind.W;
                double converted = i.Mnemonic == Arm64Mnemonic.UCVTF ? w ? (uint)v.Num : (double)v.Num : w ? (int)(uint)v.Num : (long)v.Num;
                return new A64Val(A64Kind.Const, s.Rva, $"{v.Why}; {at}") { Num = Bits(converted) };
            }
        }
        return A64Val.Unknown($"computed by {at}", s.Rva);
    }

    private A64Val Operand(Arm64Instruction i, int k, int block, int step, int depth)
    {
        int reg = A64Function.Gpr(i, k);
        if (reg == 31) return new A64Val(A64Kind.Const, code.Blocks[block][step].Rva, "zero register");
        return reg < 0 ? A64Val.Unknown("not a general-purpose register") : Before(A64Loc.Reg(reg), block, step, depth);
    }

    private static A64Val Chain(A64Val v, string at) => v.Kind is A64Kind.Cycle or A64Kind.Merge ? v : v with { Why = v.Why.Length == 0 ? at : $"{v.Why}; {at}" };

    private static string Describe(A64Val v) => v.Kind switch
    {
        A64Kind.Incoming => $"incoming {A64Function.Name(v.Loc, null)}",
        A64Kind.Result => "a call result",
        A64Kind.Field => $"a field +0x{v.Num:X}",
        _ => v.Kind.ToString().ToLowerInvariant(),
    };

    private A64Val Address(ulong va, uint at, string why)
    {
        if (va < Image.ImageBase || va - Image.ImageBase >= Image.SizeOfImage) return new A64Val(A64Kind.Const, at, why) { Num = va };
        return new A64Val(A64Kind.Addr, at, why) { Rva = (uint)(va - Image.ImageBase) };
    }

    /// <summary>
    /// A load from a known address: an import slot, a GOT slot of a function this image exports, a writable global (its
    /// writers), or the image's contents (literal pools and read-only data: relocated pointers become addresses, other
    /// words constants).
    /// </summary>
    private A64Val Loaded(uint rva, int size, uint at, string why, bool constant)
    {
        if (host.ImportAt(rva) != null) return new A64Val(A64Kind.Import, at, why) { Rva = rva };
        if (host.LocalSlot(rva) is { } fn) return new A64Val(A64Kind.Addr, at, $"{why} (GOT slot of {host.Index.NameAt(fn) ?? host.Va(fn)})") { Rva = fn };
        bool writable = Image.SectionAt(rva) is { } sec && (sec.Access & SectionAccess.Write) != 0 && (sec.Access & SectionAccess.Execute) == 0;
        if (writable && !constant) return new A64Val(A64Kind.Global, at, why) { Rva = rva };
        Span<byte> b = stackalloc byte[8];
        b.Clear();
        if (size is not (1 or 2 or 4 or 8) || Image.Read(rva, b[..size]) != size) return A64Val.Unknown($"reads 0x{Image.ImageBase + rva:X}: {why}", at);
        ulong value = BinaryPrimitives.ReadUInt64LittleEndian(b);
        if (size == 8 && host.IsRelocated(rva) && value >= Image.ImageBase && value - Image.ImageBase < Image.SizeOfImage)
            return new A64Val(A64Kind.Addr, at, $"{why} (pointer at 0x{Image.ImageBase + rva:X})") { Rva = (uint)(value - Image.ImageBase) };
        // zero in a data section is filled at run time (read-only after load, e.g. CFG-protected pointers)
        if (value == 0 && !constant && Image.SectionAt(rva) is { IsExecutable: false }) return new A64Val(A64Kind.Global, at, why) { Rva = rva };
        return new A64Val(A64Kind.Const, at, $"{why} (contents of 0x{Image.ImageBase + rva:X})") { Num = value };
    }

    public static bool IsLoad(in Arm64Instruction i) =>
        i.Mnemonic.ToString() is var m && m.StartsWith("LD", StringComparison.Ordinal) && Arm64Inspector.MemoryAccess(in i) == "read";

    public static bool IsStore(in Arm64Instruction i) =>
        i.Mnemonic.ToString() is var m && m.StartsWith("ST", StringComparison.Ordinal) && Arm64Inspector.MemoryAccess(in i) == "write"
        && i.Mnemonic is not (Arm64Mnemonic.STXR or Arm64Mnemonic.STLXR or Arm64Mnemonic.STXP or Arm64Mnemonic.STLXP or Arm64Mnemonic.STXRB
            or Arm64Mnemonic.STXRH or Arm64Mnemonic.STLXRB or Arm64Mnemonic.STLXRH);
}
