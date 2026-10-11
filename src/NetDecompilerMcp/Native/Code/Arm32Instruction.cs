using System.Runtime.CompilerServices;
using System.Text;

namespace NetDecompilerMcp.Native.Code;

internal enum ArmOperandKind : byte { None, Register, Immediate, Memory, Label, RegisterList, ShiftedRegister, VectorRegister, VectorList, Text }

internal enum ArmShift : byte { None, Lsl, Lsr, Asr, Ror, Rrx }

internal enum ArmIndexing : byte { Offset, PreIndex, PostIndex }

internal enum ArmVector : byte { None, S, D, Q }

/// <summary>How an ARM32 instruction transfers control.</summary>
internal enum ArmFlow : byte { Next, Jump, Call, IndirectJump, IndirectCall, Return, Trap, Invalid }

/// <summary>One operand of an A32 / T32 instruction.</summary>
internal struct ArmOperand
{
    public const byte NoReg = 0xFF;

    public ArmOperandKind Kind;
    /// <summary>Register; memory base; vector register number; first register of a vector list.</summary>
    public byte Reg;
    /// <summary>Memory index register, <see cref="NoReg"/> when none.</summary>
    public byte Index;
    /// <summary>Shift of a shifted register or of the memory index.</summary>
    public ArmShift Shift;
    public byte Amount;
    /// <summary>Register holding the shift amount, <see cref="NoReg"/> when the amount is immediate.</summary>
    public byte ShiftReg;
    public ArmIndexing Indexing;
    /// <summary>Memory: the offset or index is subtracted from the base.</summary>
    public bool Subtract;
    public ArmVector Vector;
    /// <summary>Vector list length; vector element index + 1 (0: none) for a single register.</summary>
    public byte Count;
    /// <summary>Immediate; memory offset magnitude; label address; register list mask.</summary>
    public long Value;
    public string? Text;
}

[InlineArray(6)]
internal struct ArmOperands
{
    private ArmOperand _element;
}

/// <summary>
/// A decoded A32 or T32 instruction: mnemonic parts, operands, the core registers it reads and writes (bit n = rn) and
/// its control flow. Addresses are 32-bit virtual addresses.
/// </summary>
internal struct ArmInstruction
{
    public const byte Always = 14, Unconditional = 15;

    public uint Address;
    public byte Length;
    public bool Thumb;
    /// <summary>The base mnemonic (no condition, flag-setting s or width), lower case; "(bad)" when invalid.</summary>
    public string Mnemonic;
    /// <summary>Condition code (<see cref="Always"/>; <see cref="Unconditional"/> for encodings without one).</summary>
    public byte Cond;
    public bool SetsFlags;
    /// <summary>A 32-bit Thumb encoding of an instruction that also has a 16-bit one (shown as .w).</summary>
    public bool Wide;
    /// <summary>Data type or size qualifier (.f32, .8, ...).</summary>
    public string? Suffix;
    public ArmFlow Flow;
    /// <summary>Direct branch or call target.</summary>
    public uint Target;
    public bool HasTarget;
    /// <summary>The target runs in Thumb state (BLX switches state).</summary>
    public bool TargetThumb;
    public ushort Reads, Writes;
    /// <summary>Reads or writes the NZCV flags.</summary>
    public bool ReadsFlags, WritesFlags;
    /// <summary>Bytes a load or store moves per register (0: no memory access).</summary>
    public byte AccessSize;
    public bool Loads, Stores;
    /// <summary>For IT: the first condition and the mask.</summary>
    public byte ItFirst, ItMask;
    public uint Raw;
    public int OperandCount;
    public ArmOperands Operands;

    public readonly bool IsValid => Flow != ArmFlow.Invalid;
    public readonly bool IsConditional => Cond < Always;
    public readonly bool WritesPc => (Writes & 0x8000) != 0;

    public readonly ArmOperand Op(int i) => Operands[i];

    public static readonly string[] RegisterNames = ["r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7", "r8", "r9", "r10", "r11", "r12", "sp", "lr", "pc"];
    public static readonly string[] ConditionNames = ["eq", "ne", "hs", "lo", "mi", "pl", "vs", "vc", "hi", "ls", "ge", "lt", "gt", "le", "", ""];

    // builders used by the decoder

    internal void Reg(int r, bool write = false)
    {
        ref var o = ref Operands[Next()];
        o.Kind = ArmOperandKind.Register;
        o.Reg = (byte)r;
        Use(r, write);
    }

    internal void Use(int r, bool write)
    {
        if (r is < 0 or > 15) return;
        if (write) Writes |= (ushort)(1 << r);
        else Reads |= (ushort)(1 << r);
    }

    internal void Imm(long value)
    {
        ref var o = ref Operands[Next()];
        o.Kind = ArmOperandKind.Immediate;
        o.Value = value;
    }

    /// <summary>A pc-relative address; <paramref name="branch"/>: the branch or call target.</summary>
    internal void Label(uint target, bool thumb, bool branch = true)
    {
        ref var o = ref Operands[Next()];
        o.Kind = ArmOperandKind.Label;
        o.Value = target;
        if (!branch) return;
        Target = target;
        HasTarget = true;
        TargetThumb = thumb;
    }

    internal void Text(string text)
    {
        ref var o = ref Operands[Next()];
        o.Kind = ArmOperandKind.Text;
        o.Text = text;
    }

    internal void Shifted(int r, ArmShift shift, int amount, int shiftReg = ArmOperand.NoReg)
    {
        if (shift == ArmShift.None || (shift == ArmShift.Lsl && amount == 0 && shiftReg == ArmOperand.NoReg)) { Reg(r); return; }
        ref var o = ref Operands[Next()];
        o.Kind = ArmOperandKind.ShiftedRegister;
        o.Reg = (byte)r;
        o.Shift = shift;
        o.Amount = (byte)amount;
        o.ShiftReg = (byte)shiftReg;
        Use(r, false);
        if (shiftReg != ArmOperand.NoReg) Use(shiftReg, false);
    }

    internal void List(int mask, bool load)
    {
        ref var o = ref Operands[Next()];
        o.Kind = ArmOperandKind.RegisterList;
        o.Value = mask;
        if (load) Writes |= (ushort)mask;
        else Reads |= (ushort)mask;
    }

    /// <summary>A memory operand [base, #offset] (pre / post indexing writes the base back).</summary>
    internal void MemImm(int baseReg, long offset, ArmIndexing indexing = ArmIndexing.Offset)
    {
        ref var o = ref Operands[Next()];
        o.Kind = ArmOperandKind.Memory;
        o.Reg = (byte)baseReg;
        o.Index = ArmOperand.NoReg;
        o.Subtract = offset < 0;
        o.Value = Math.Abs(offset);
        o.Indexing = indexing;
        Use(baseReg, false);
        if (indexing != ArmIndexing.Offset) Use(baseReg, true);
    }

    /// <summary>A memory operand [base, ±index, shift #n].</summary>
    internal void MemReg(int baseReg, int index, bool subtract = false, ArmShift shift = ArmShift.None, int amount = 0, ArmIndexing indexing = ArmIndexing.Offset)
    {
        ref var o = ref Operands[Next()];
        o.Kind = ArmOperandKind.Memory;
        o.Reg = (byte)baseReg;
        o.Index = (byte)index;
        o.Subtract = subtract;
        o.Shift = shift;
        o.Amount = (byte)amount;
        o.Indexing = indexing;
        Use(baseReg, false);
        Use(index, false);
        if (indexing != ArmIndexing.Offset) Use(baseReg, true);
    }

    internal void Vec(ArmVector kind, int n, int element = -1)
    {
        ref var o = ref Operands[Next()];
        o.Kind = ArmOperandKind.VectorRegister;
        o.Vector = kind;
        o.Reg = (byte)n;
        o.Count = (byte)(element + 1);
    }

    internal void VecList(ArmVector kind, int first, int count, string? lanes = null, int stride = 1)
    {
        ref var o = ref Operands[Next()];
        o.Kind = ArmOperandKind.VectorList;
        o.Vector = kind;
        o.Reg = (byte)first;
        o.Count = (byte)count;
        o.Amount = (byte)stride;
        o.Text = lanes;
    }

    private int Next()
    {
        int n = OperandCount++;
        Operands[n] = default;
        Operands[n].Index = Operands[n].ShiftReg = ArmOperand.NoReg;
        return n;
    }

    /// <summary>Clears the operands and register use (an encoding re-read as another instruction).</summary>
    internal void ResetOperands()
    {
        OperandCount = 0;
        Reads = Writes = 0;
    }

    /// <summary>
    /// Text in the style of the ARM disassemblers: mnemonic with flags, condition and width padded to 6 columns, then
    /// the operands. <paramref name="label"/> names branch targets and ADR / literal addresses (null: hex address).
    /// </summary>
    public readonly string Format(Func<uint, string?>? label = null)
    {
        if (Flow == ArmFlow.Invalid) return "(bad)";
        var sb = new StringBuilder(32);
        sb.Append(Mnemonic);
        if (SetsFlags && Mnemonic is not ("cmp" or "cmn" or "tst" or "teq")) sb.Append('s');
        if (Cond < Always && Mnemonic != "it") sb.Append(ConditionNames[Cond]);
        if (Wide) sb.Append(".w");
        if (Suffix != null) sb.Append(Suffix);
        if (OperandCount == 0) return sb.ToString();
        if (sb.Length < 6) sb.Append(' ', 6 - sb.Length);
        sb.Append(' ');
        for (int k = 0; k < OperandCount; k++)
        {
            if (k > 0) sb.Append(", ");
            FormatOperand(sb, in Operands[k], label);
        }
        return sb.ToString();
    }

    public readonly string OperandText(int k, Func<uint, string?>? label = null)
    {
        var sb = new StringBuilder();
        FormatOperand(sb, in Operands[k], label);
        return sb.ToString();
    }

    private static void FormatOperand(StringBuilder sb, in ArmOperand o, Func<uint, string?>? label)
    {
        switch (o.Kind)
        {
            case ArmOperandKind.Register:
                sb.Append(RegisterNames[o.Reg & 15]).Append(o.Text);
                break;
            case ArmOperandKind.Immediate:
                sb.Append('#');
                Hex(sb, o.Value);
                break;
            case ArmOperandKind.Label:
                sb.Append(label?.Invoke((uint)o.Value) ?? $"0x{o.Value:X}");
                break;
            case ArmOperandKind.Text:
                sb.Append(o.Text);
                break;
            case ArmOperandKind.ShiftedRegister:
                sb.Append(RegisterNames[o.Reg & 15]).Append(", ");
                Shift(sb, o.Shift, o.Amount, o.ShiftReg);
                break;
            case ArmOperandKind.RegisterList:
            {
                sb.Append('{');
                bool first = true;
                for (int r = 0; r < 16; r++)
                {
                    if ((o.Value & (1 << r)) == 0) continue;
                    if (!first) sb.Append(", ");
                    sb.Append(RegisterNames[r]);
                    first = false;
                }
                sb.Append('}').Append(o.Text);
                break;
            }
            case ArmOperandKind.VectorRegister:
                sb.Append(VectorName(o.Vector, o.Reg));
                if (o.Count > 0) sb.Append('[').Append(o.Count - 1).Append(']');
                break;
            case ArmOperandKind.VectorList:
                sb.Append('{');
                for (int k = 0; k < o.Count; k++)
                {
                    if (k > 0) sb.Append(", ");
                    sb.Append(VectorName(o.Vector, o.Reg + k * Math.Max(1, (int)o.Amount)));
                    if (o.Text != null) sb.Append(o.Text);
                }
                sb.Append('}');
                break;
            case ArmOperandKind.Memory:
                sb.Append('[').Append(RegisterNames[o.Reg & 15]).Append(o.Text);
                if (o.Indexing == ArmIndexing.PostIndex) sb.Append(']');
                if (o.Index != ArmOperand.NoReg)
                {
                    sb.Append(", ");
                    if (o.Subtract) sb.Append('-');
                    sb.Append(RegisterNames[o.Index & 15]);
                    if (o.Shift != ArmShift.None && !(o.Shift == ArmShift.Lsl && o.Amount == 0))
                    {
                        sb.Append(", ");
                        Shift(sb, o.Shift, o.Amount, ArmOperand.NoReg);
                    }
                }
                else if (o.Value != 0 || o.Subtract || o.Indexing == ArmIndexing.PostIndex)
                {
                    sb.Append(", #");
                    Hex(sb, o.Subtract ? -o.Value : o.Value);
                }
                if (o.Indexing != ArmIndexing.PostIndex) sb.Append(']');
                if (o.Indexing == ArmIndexing.PreIndex) sb.Append('!');
                break;
        }
    }

    private static void Shift(StringBuilder sb, ArmShift shift, int amount, int shiftReg)
    {
        sb.Append(shift switch { ArmShift.Lsl => "lsl", ArmShift.Lsr => "lsr", ArmShift.Asr => "asr", ArmShift.Ror => "ror", _ => "rrx" });
        if (shift == ArmShift.Rrx) return;
        if (shiftReg != ArmOperand.NoReg) sb.Append(' ').Append(RegisterNames[shiftReg & 15]);
        else sb.Append(" #").Append(amount);
    }

    private static void Hex(StringBuilder sb, long v)
    {
        if (v < 0) { sb.Append('-'); v = -v; }
        if (v < 10) sb.Append(v);
        else sb.Append("0x").Append(v.ToString("X"));
    }

    public static string VectorName(ArmVector kind, int n) => kind switch { ArmVector.S => $"s{n}", ArmVector.D => $"d{n}", _ => $"q{n}" };
}
