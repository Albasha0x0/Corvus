using System.Globalization;
using AsmArm64;
using Corvus.Native.Code;

namespace Corvus.Native.Calls;

/// <summary>An ARM64 value location: an X register, a v register from <see cref="A64Function.VBase"/>, or an entry-relative stack slot.</summary>
internal readonly record struct A64Loc(bool IsSlot, int Value)
{
    public static A64Loc Reg(int index) => new(false, index);
    public static A64Loc Slot(int offset) => new(true, offset);
}

/// <summary>One decoded instruction of a function, with the stack and frame pointer offsets before it (from entry SP; null when unknown).</summary>
internal sealed record A64Step(uint Rva, Arm64Instruction I, Insn Facts, int? Sp, int? Fp)
{
    public string Text => I.ToString();
}

/// <summary>An ARM64 function decoded per block for value analysis, with sp and x29 tracked from entry.</summary>
internal sealed class A64Function
{
    public NativeFunction Function { get; }
    public FunctionGraph Graph { get; }
    public A64Step[][] Blocks { get; }
    private readonly Dictionary<uint, int> _blockOf = [];

    public A64Function(NativeCodeIndex index, NativeFunction f, CancellationToken ct)
    {
        Function = f;
        Graph = index.GetGraph(f, ct);
        Blocks = new A64Step[Graph.Blocks.Count][];
        var dec = HybridDecoder.PrimaryOf(index.NewDecoder()) as Arm64Decoder ?? throw new NotSupportedException("ARM64 decoder unavailable");
        dec.BeginFunction();
        for (int b = 0; b < Graph.Blocks.Count; b++)
        {
            var block = Graph.Blocks[b];
            _blockOf[block.Start] = b;
            var steps = new List<A64Step>();
            dec.BeginRun(IndexBound.None);
            for (uint a = block.Start; a < block.End; a += 4)
            {
                if (!dec.DecodeMapped(a, out var insn) || insn.Flow == FlowKind.Invalid) break;
                steps.Add(new A64Step(a, dec.Last, insn, null, null));
            }
            Blocks[b] = [.. steps];
        }
        TrackStack();
    }

    public int BlockIndexOf(uint start) => _blockOf.TryGetValue(start, out int b) ? b : -1;

    /// <summary>The block and position of the instruction at <paramref name="rva"/>, or (-1, -1).</summary>
    public (int Block, int Index) Position(uint rva)
    {
        for (int b = 0; b < Blocks.Length; b++)
        {
            var s = Blocks[b];
            if (s.Length == 0 || rva < s[0].Rva || rva > s[^1].Rva || (rva - s[0].Rva) % 4 != 0) continue;
            return (b, (int)((rva - s[0].Rva) / 4));
        }
        return (-1, -1);
    }

    public IEnumerable<int> Predecessors(int b) =>
        Graph.Blocks[b].Predecessors.Where(e => e.Kind != EdgeKind.TailCall).Select(e => Graph.BlockAt(e.From) is { } p ? BlockIndexOf(p.Start) : -1).Where(p => p >= 0).Distinct();

    public IEnumerable<int> Successors(int b) =>
        Graph.Blocks[b].Successors.Where(e => e.Kind != EdgeKind.TailCall).Select(e => BlockIndexOf(e.To)).Where(s => s >= 0).Distinct();

    /// <summary>Forward pass over the blocks: SP and x29 as offsets from SP at entry, first value seen per block.</summary>
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

    private static void Advance(in Arm64Instruction i, ref int? sp, ref int? fp)
    {
        for (int k = 0; k < i.OperandCount; k++)
        {
            if (i.GetOperand(k) is not { Kind: Arm64OperandKind.Memory } m) continue;
            var a = ((Arm64MemoryOperand)m).Accessor;
            if (a.BaseRegister.Kind != Arm64RegisterKind.SP) continue;
            bool post = a.OffsetKind == Arm64MemoryOffsetKind.None && k + 1 < i.OperandCount && i.GetOperand(k + 1).Kind == Arm64OperandKind.Immediate;
            if (a.IsPreIncrement) sp += a.Immediate;
            else if (post) sp += (int)((Arm64ImmediateOperand)i.GetOperand(k + 1)).Value;
        }
        if (Dest(in i) is not { } d) return;
        bool toSp = d.Kind == Arm64RegisterKind.SP, toFp = d.Kind == Arm64RegisterKind.X && d.Index == 29;
        if (!toSp && !toFp) return;
        int? value = null;
        if (i.OperandCount >= 2 && i.GetOperand(1) is { Kind: Arm64OperandKind.Register } so)
        {
            var src = ((Arm64RegisterOperand)so).Value;
            int? from = src.Kind == Arm64RegisterKind.SP ? sp : src.Kind == Arm64RegisterKind.X && src.Index == 29 ? fp : null;
            if (from != null)
            {
                if (i.Mnemonic == Arm64Mnemonic.MOV) value = from;
                else if (i.Mnemonic is Arm64Mnemonic.ADD or Arm64Mnemonic.SUB && Imm(in i, 2) is { } imm) value = from + (int)(i.Mnemonic == Arm64Mnemonic.SUB ? -imm : imm);
            }
        }
        if (toSp) sp = value;
        else fp = value;
    }

    /// <summary>The register operand 0 writes, when it is one.</summary>
    public static Arm64RegisterAny? Dest(in Arm64Instruction i) =>
        !Arm64Extensions.IsBranch(i.Id) && i.OperandCount > 0 && i.GetOperand(0) is { Kind: Arm64OperandKind.Register } op && (op.Flags & Arm64OperandFlags.Write) != 0
            ? ((Arm64RegisterOperand)op).Value : null;

    /// <summary>Immediate operand <paramref name="k"/> with its optional lsl shift applied.</summary>
    public static long? Imm(in Arm64Instruction i, int k)
    {
        if (k >= i.OperandCount || i.GetOperand(k) is not { Kind: Arm64OperandKind.Immediate } op || ((Arm64ImmediateOperand)op).IsFloat) return null;
        int shift = k + 1 < i.OperandCount && i.GetOperand(k + 1).Kind == Arm64OperandKind.Shift ? ((Arm64ShiftOperand)i.GetOperand(k + 1)).Amount : 0;
        return ((Arm64ImmediateOperand)op).Value << shift;
    }

    /// <summary>Location numbers of v0-v31 start here.</summary>
    public const int VBase = 32;

    public static bool IsVector(Arm64RegisterAny r) =>
        r.Kind is not (Arm64RegisterKind.Invalid or Arm64RegisterKind.X or Arm64RegisterKind.W or Arm64RegisterKind.SP or Arm64RegisterKind.WSP or Arm64RegisterKind.C);

    /// <summary>The location number of a register: X / W index (31 for the zero register), <see cref="VBase"/> + n for a v register view, else -1.</summary>
    public static int Number(Arm64RegisterAny r) => r.Kind is Arm64RegisterKind.X or Arm64RegisterKind.W ? r.Index : IsVector(r) ? VBase + r.Index : -1;

    /// <summary>The location number (<see cref="Number(Arm64RegisterAny)"/>) of register operand <paramref name="k"/>, else -1.</summary>
    public static int Reg(in Arm64Instruction i, int k) =>
        k < i.OperandCount && i.GetOperand(k) is { Kind: Arm64OperandKind.Register } op ? Number(((Arm64RegisterOperand)op).Value) : -1;

    /// <summary>X / W register index of register operand <paramref name="k"/> (31 for the zero register), else -1.</summary>
    public static int Gpr(in Arm64Instruction i, int k)
    {
        if (k >= i.OperandCount || i.GetOperand(k) is not { Kind: Arm64OperandKind.Register } op) return -1;
        var r = ((Arm64RegisterOperand)op).Value;
        return r.Kind is Arm64RegisterKind.X or Arm64RegisterKind.W ? r.Index : -1;
    }

    public static bool IsW(in Arm64Instruction i, int k) =>
        k < i.OperandCount && i.GetOperand(k) is { Kind: Arm64OperandKind.Register } op && ((Arm64RegisterOperand)op).Value.Kind == Arm64RegisterKind.W;

    public static bool IsCall(in Arm64Instruction i) =>
        i.Mnemonic is Arm64Mnemonic.BL or Arm64Mnemonic.BLR or Arm64Mnemonic.BLRAA or Arm64Mnemonic.BLRAAZ or Arm64Mnemonic.BLRAB or Arm64Mnemonic.BLRABZ;

    /// <summary>Caller-saved under the AAPCS64: x0-x18, x30, v0-v7 and v16-v31 (v8-v15 keep their low 64 bits).</summary>
    public static bool IsVolatile(int reg) => reg is >= 0 and <= 18 or 30 || reg >= VBase && (reg - VBase < 8 || reg - VBase >= 16);

    /// <summary>The memory operand: its index, the address mode and the stack slot it addresses (entry-relative), when based on sp or a known x29.</summary>
    public static (int Operand, Arm64MemoryAccessorAny Accessor, bool Post, int? Slot)? Memory(A64Step s)
    {
        var i = s.I;
        for (int k = 0; k < i.OperandCount; k++)
        {
            if (i.GetOperand(k) is not { Kind: Arm64OperandKind.Memory } m) continue;
            var a = ((Arm64MemoryOperand)m).Accessor;
            bool post = a.OffsetKind == Arm64MemoryOffsetKind.None && k + 1 < i.OperandCount && i.GetOperand(k + 1).Kind == Arm64OperandKind.Immediate;
            int? slot = null;
            if (!a.HasIndexRegister)
            {
                int off = post ? 0 : a.HasImmediate ? a.Immediate : 0;
                if (a.BaseRegister.Kind == Arm64RegisterKind.SP && s.Sp is { } sp) slot = sp + off;
                else if (a.BaseRegister is { Kind: Arm64RegisterKind.X, Index: 29 } && s.Fp is { } fp) slot = fp + off;
            }
            return (k, a, post, slot);
        }
        return null;
    }

    /// <summary>"x3", "w3", "fp", "lr", "d0" / "s1" / "v2" (b, h, q views too), or a slot "[sp+10h]" / "[sp, #16]" / "[x29-8]" relative to sp or x29 at <paramref name="at"/>; null when not one.</summary>
    public static A64Loc? Parse(string? text, A64Step? at)
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
            int? origin = reg switch
            {
                "sp" => at == null ? 0 : at.Sp,
                "x29" or "fp" => at?.Fp,
                _ => null,
            };
            return origin is { } o ? A64Loc.Slot(o + (int)off) : null;
        }
        if (t is "fp") return A64Loc.Reg(29);
        if (t is "lr") return A64Loc.Reg(30);
        if (t.Length >= 2 && t[0] is 'x' or 'w' && int.TryParse(t.AsSpan(1), NumberStyles.None, CultureInfo.InvariantCulture, out int n) && n is >= 0 and <= 30)
            return A64Loc.Reg(n);
        if (t.Length >= 2 && t[0] is 'b' or 'h' or 's' or 'd' or 'q' or 'v' && int.TryParse(t.AsSpan(1), NumberStyles.None, CultureInfo.InvariantCulture, out int v) && v is >= 0 and <= 31)
            return A64Loc.Reg(VBase + v);
        return null;
    }

    private static bool Number(string s, out long value)
    {
        value = 0;
        if (s.EndsWith('h')) return long.TryParse(s[..^1], NumberStyles.AllowHexSpecifier, CultureInfo.InvariantCulture, out value);
        if (s.StartsWith("0x", StringComparison.Ordinal)) return long.TryParse(s[2..], NumberStyles.AllowHexSpecifier, CultureInfo.InvariantCulture, out value);
        return long.TryParse(s, NumberStyles.Integer, CultureInfo.InvariantCulture, out value);
    }

    /// <summary>A location as text at <paramref name="at"/> (slots relative to sp there; at entry when null).</summary>
    public static string Name(A64Loc loc, A64Step? at)
    {
        if (!loc.IsSlot) return loc.Value >= VBase ? $"d{loc.Value - VBase}" : $"x{loc.Value}";
        int origin = at == null ? 0 : at.Sp ?? 0;
        int off = loc.Value - origin;
        return off < 0 ? $"[sp-{-off:X}h]" : $"[sp+{off:X}h]";
    }

    /// <summary>The 0-based AAPCS64 parameter position of an entry location (x0-x7, then 8-byte stack slots from entry sp), or -1.</summary>
    public static int ParameterIndex(A64Loc entry) => entry.IsSlot
        ? entry.Value >= 0 && entry.Value % 8 == 0 && entry.Value < 8 * 24 ? 8 + entry.Value / 8 : -1
        : entry.Value is >= 0 and < 8 ? entry.Value : -1;

    public static A64Loc ParameterEntry(int index) => index < 8 ? A64Loc.Reg(index) : A64Loc.Slot(8 * (index - 8));
}
