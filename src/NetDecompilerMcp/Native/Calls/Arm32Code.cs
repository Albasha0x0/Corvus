using System.Globalization;
using NetDecompilerMcp.Native.Code;

namespace NetDecompilerMcp.Native.Calls;

/// <summary>A 32-bit ARM value location: a core register r0-r14, or a stack slot as an offset from the stack pointer at function entry.</summary>
internal readonly record struct A32Loc(bool IsSlot, int Value)
{
    public static A32Loc Reg(int index) => new(false, index);
    public static A32Loc Slot(int offset) => new(true, offset);
}

/// <summary>One decoded instruction of a function, with the stack and frame pointer offsets before it (from entry SP; null when unknown).</summary>
internal sealed record A32Step(uint Rva, ArmInstruction I, Insn Facts, int? Sp, int? Fp)
{
    public string Text => I.Format();
}

/// <summary>
/// A 32-bit ARM function decoded block by block, in its ARM or Thumb state, for value analysis: instructions with their
/// facts (literal pools, PC-relative pairs, import slots), IT conditions, predecessors, and the stack pointer tracked from
/// entry (push / pop, vpush / vpop, sub / add sp, writeback, the frame pointer r7 or r11) so stack slots read the same
/// through sp and the frame pointer.
/// </summary>
internal sealed class A32Function
{
    public const int Sp = 13, Lr = 14, Pc = 15;

    public NativeFunction Function { get; }
    public FunctionGraph Graph { get; }
    public A32Step[][] Blocks { get; }
    /// <summary>The frame pointer register (r7 in Thumb, r11 in ARM code).</summary>
    public int FpReg { get; }
    private readonly Dictionary<uint, int> _blockOf = [];
    private readonly Dictionary<uint, (int Block, int Index)> _position = [];

    public A32Function(NativeCodeIndex index, NativeFunction f, CancellationToken ct)
    {
        Function = f;
        Graph = index.GetGraph(f, ct);
        Blocks = new A32Step[Graph.Blocks.Count][];
        var dec = index.NewDecoder() as Arm32Decoder ?? throw new NotSupportedException("ARM32 decoder unavailable");
        dec.BeginFunction(f.Start);
        FpReg = dec.Thumb ? 7 : 11;
        for (int b = 0; b < Graph.Blocks.Count; b++)
        {
            var block = Graph.Blocks[b];
            _blockOf[block.Start] = b;
            var steps = new List<A32Step>();
            dec.BeginRun(IndexBound.None);
            for (uint a = block.Start; a < block.End;)
            {
                if (!dec.DecodeMapped(a, out var insn) || insn.Flow == FlowKind.Invalid) break;
                _position[a] = (b, steps.Count);
                steps.Add(new A32Step(a, dec.Last, insn, null, null));
                a += (uint)insn.Length;
            }
            Blocks[b] = [.. steps];
        }
        TrackStack();
    }

    public int BlockIndexOf(uint start) => _blockOf.TryGetValue(start, out int b) ? b : -1;

    /// <summary>The block and position of the instruction at <paramref name="rva"/>, or (-1, -1).</summary>
    public (int Block, int Index) Position(uint rva) => _position.TryGetValue(rva, out var p) ? p : (-1, -1);

    public IEnumerable<int> Predecessors(int b) =>
        Graph.Blocks[b].Predecessors.Where(e => e.Kind != EdgeKind.TailCall).Select(e => Graph.BlockAt(e.From) is { } p ? BlockIndexOf(p.Start) : -1).Where(p => p >= 0).Distinct();

    public IEnumerable<int> Successors(int b) =>
        Graph.Blocks[b].Successors.Where(e => e.Kind != EdgeKind.TailCall).Select(e => BlockIndexOf(e.To)).Where(s => s >= 0).Distinct();

    /// <summary>Forward pass over the blocks: SP and the frame pointer as offsets from SP at entry, first value seen per block.</summary>
    private void TrackStack()
    {
        int entry = BlockIndexOf(Function.Start);
        if (entry < 0) return;
        var inSp = new int?[Blocks.Length];
        var inFp = new int?[Blocks.Length];
        var seen = new bool[Blocks.Length];
        var work = new Queue<int>();
        inSp[entry] = 0;
        seen[entry] = true;
        work.Enqueue(entry);
        while (work.Count > 0)
        {
            int b = work.Dequeue();
            int? sp = inSp[b], fp = inFp[b];
            var steps = Blocks[b];
            for (int k = 0; k < steps.Length; k++)
            {
                steps[k] = steps[k] with { Sp = sp, Fp = fp };
                Advance(steps[k].I, ref sp, ref fp);
            }
            foreach (int s in Successors(b))
            {
                if (seen[s]) continue;
                seen[s] = true;
                inSp[s] = sp;
                inFp[s] = fp;
                work.Enqueue(s);
            }
        }
    }

    private void Advance(in ArmInstruction i, ref int? sp, ref int? fp)
    {
        if (i.IsConditional) { if ((i.Writes & (1 << Sp)) != 0) sp = null; if ((i.Writes & (1 << FpReg)) != 0) fp = null; return; }
        switch (i.Mnemonic)
        {
            case "push" or "pop":
                sp += (i.Mnemonic == "push" ? -4 : 4) * Count(i.Op(0).Value);
                if (i.Mnemonic == "pop" && (i.Op(0).Value & (1 << FpReg)) != 0) fp = null;
                return;
            case "vpush" or "vpop":
            {
                var v = i.Op(0);
                int size = v.Count * (v.Vector == ArmVector.D ? 8 : 4);
                sp += i.Mnemonic == "vpush" ? -size : size;
                return;
            }
        }
        // writeback through sp
        if (Memory(in i) is { } m && m.Reg == Sp && m.Indexing != ArmIndexing.Offset && m.Index == ArmOperand.NoReg)
            sp += (int)(m.Subtract ? -m.Value : m.Value);
        bool toSp = (i.Writes & (1 << Sp)) != 0 && i.Op(0) is { Kind: ArmOperandKind.Register, Reg: Sp };
        bool toFp = (i.Writes & (1 << FpReg)) != 0 && i.Op(0) is { Kind: ArmOperandKind.Register } d && d.Reg == FpReg && !i.Loads;
        if (!toSp && !toFp) return;
        int? value = null;
        int? curSp = sp, curFp = fp;
        int? Base(int r) => r == Sp ? curSp : r == FpReg ? curFp : null;
        if (i.Mnemonic == "mov" && i.OperandCount == 2 && i.Op(1).Kind == ArmOperandKind.Register) value = Base(i.Op(1).Reg);
        else if (i.Mnemonic is "add" or "sub" or "addw" or "subw" && i.Op(i.OperandCount - 1).Kind == ArmOperandKind.Immediate)
        {
            int src = i.OperandCount == 2 ? i.Op(0).Reg : i.Op(1).Kind == ArmOperandKind.Register ? i.Op(1).Reg : -1;
            long imm = i.Op(i.OperandCount - 1).Value;
            if (src >= 0 && Base(src) is { } from) value = from + (int)(i.Mnemonic.StartsWith("sub", StringComparison.Ordinal) ? -imm : imm);
        }
        if (toSp) sp = value;
        else fp = value;
    }

    private static int Count(long mask) => System.Numerics.BitOperations.PopCount((ulong)mask);

    /// <summary>The memory operand of an instruction, or null.</summary>
    public static ArmOperand? Memory(in ArmInstruction i)
    {
        for (int k = 0; k < i.OperandCount; k++)
            if (i.Operands[k].Kind == ArmOperandKind.Memory) return i.Operands[k];
        return null;
    }

    /// <summary>The entry-relative stack slot a memory operand addresses (sp or a known frame pointer base, no index), or null.</summary>
    public int? Slot(A32Step s)
    {
        if (Memory(s.I) is not { } m || m.Index != ArmOperand.NoReg) return null;
        int off = m.Indexing == ArmIndexing.PostIndex ? 0 : (int)(m.Subtract ? -m.Value : m.Value);
        if (m.Reg == Sp && s.Sp is { } sp) return sp + off;
        if (m.Reg == FpReg && s.Fp is { } fp) return fp + off;
        return null;
    }

    public static bool IsCall(in ArmInstruction i) => i.Flow is ArmFlow.Call or ArmFlow.IndirectCall;

    /// <summary>Caller-saved under the AAPCS: r0-r3, r12 and lr.</summary>
    public static bool IsVolatile(int reg) => reg is >= 0 and <= 3 or 12 or 14;

    /// <summary>The register operand 0 writes, when it is one.</summary>
    public static int Dest(in ArmInstruction i) =>
        i.OperandCount > 0 && i.Op(0).Kind == ArmOperandKind.Register && (i.Writes & (1 << i.Op(0).Reg)) != 0 && !i.Stores ? i.Op(0).Reg : -1;

    /// <summary>"r3", "fp", "ip", "lr", or a slot "[sp+10h]" / "[sp, #16]" / "[r7-8]" relative to sp or the frame pointer at <paramref name="at"/>; null when not one.</summary>
    public A32Loc? Parse(string? text, A32Step? at) => Parse(text, at, FpReg);

    public static A32Loc? Parse(string? text, A32Step? at, int fpReg)
    {
        if (string.IsNullOrWhiteSpace(text)) return null;
        var t = text.Trim().ToLowerInvariant().Replace(" ", "").Replace(",#", "+").Replace("+-", "-");
        if (t.StartsWith('[') && t.EndsWith(']'))
        {
            t = t[1..^1];
            int sign = t.IndexOfAny(['+', '-']);
            var reg = sign < 0 ? t : t[..sign];
            long off = 0;
            if (sign >= 0 && !Number(t[(sign + 1)..], out off)) return null;
            if (sign >= 0 && t[sign] == '-') off = -off;
            int? origin = reg == "sp" ? at == null ? 0 : at.Sp : Register(reg) == fpReg || reg == "fp" ? at?.Fp : null;
            return origin is { } o ? A32Loc.Slot(o + (int)off) : null;
        }
        int r = Register(t);
        return r is >= 0 and < Sp or Lr ? A32Loc.Reg(r) : null;
    }

    private static int Register(string t) => t switch
    {
        "fp" => 11, "ip" => 12, "sb" => 9, "sl" => 10, "lr" => 14, "sp" => 13, "pc" => 15,
        _ => t.Length >= 2 && t[0] == 'r' && int.TryParse(t.AsSpan(1), NumberStyles.None, CultureInfo.InvariantCulture, out int n) && n is >= 0 and <= 15 ? n : -1,
    };

    private static bool Number(string s, out long value)
    {
        value = 0;
        if (s.EndsWith('h')) return long.TryParse(s[..^1], NumberStyles.AllowHexSpecifier, CultureInfo.InvariantCulture, out value);
        if (s.StartsWith("0x", StringComparison.Ordinal)) return long.TryParse(s[2..], NumberStyles.AllowHexSpecifier, CultureInfo.InvariantCulture, out value);
        return long.TryParse(s, NumberStyles.Integer, CultureInfo.InvariantCulture, out value);
    }

    /// <summary>A location as text at <paramref name="at"/> (slots relative to sp there; at entry when null).</summary>
    public static string Name(A32Loc loc, A32Step? at)
    {
        if (!loc.IsSlot) return ArmInstruction.RegisterNames[loc.Value & 15];
        int origin = at == null ? 0 : at.Sp ?? 0;
        int off = loc.Value - origin;
        return off < 0 ? $"[sp-{-off:X}h]" : $"[sp+{off:X}h]";
    }

    /// <summary>The 0-based AAPCS parameter position of an entry location (r0-r3, then 4-byte stack slots from entry sp), or -1.</summary>
    public static int ParameterIndex(A32Loc entry) => entry.IsSlot
        ? entry.Value >= 0 && entry.Value % 4 == 0 && entry.Value < 4 * 24 ? 4 + entry.Value / 4 : -1
        : entry.Value is >= 0 and < 4 ? entry.Value : -1;

    public static A32Loc ParameterEntry(int index) => index < 4 ? A32Loc.Reg(index) : A32Loc.Slot(4 * (index - 4));
}
