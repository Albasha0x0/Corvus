namespace Corvus.Native.Elf;

/// <summary>How a register's caller value is found from the CFA (DWARF register rules).</summary>
internal enum CfiRuleKind : byte { Undefined, SameValue, Offset, ValOffset, Register, Expression, ValExpression }

/// <summary>One register rule: an offset from the CFA, a register number for <see cref="CfiRuleKind.Register"/>, or the DWARF expression of the two expression kinds.</summary>
internal readonly record struct CfiRule(CfiRuleKind Kind, long Operand, byte[]? Expression = null);

/// <summary>One row of the CFI table: the CFA (a register plus an offset) and the rules of the registers it saves.</summary>
internal sealed class CfiRow
{
    public int CfaRegister = -1;
    public long CfaOffset;
    /// <summary>The CFA's DWARF expression (DW_CFA_def_cfa_expression), or null for a register plus an offset.</summary>
    public byte[]? CfaExpression;
    /// <summary>AArch64: the return address is signed (DW_CFA_AARCH64_negate_ra_state).</summary>
    public bool RaSigned;
    /// <summary>The CIE's return address column.</summary>
    public int ReturnColumn;
    public Dictionary<int, CfiRule> Rules = [];

    public CfiRow Clone() => new() { CfaRegister = CfaRegister, CfaOffset = CfaOffset, CfaExpression = CfaExpression, RaSigned = RaSigned, ReturnColumn = ReturnColumn, Rules = new(Rules) };
}

internal static partial class EhFrame
{
    private const int MaxCfiSteps = 1 << 16;
    private const int MaxRememberDepth = 64;

    /// <summary>The CFI row in effect at link-time address <paramref name="pc"/>; null with a reason when the instructions are malformed or unknown.</summary>
    public static CfiRow? Row(ByteView data, ulong dataVa, bool is64, CfiFde fde, ulong pc, out string? failure)
    {
        var initial = new CfiRow { ReturnColumn = fde.Cie.ReturnColumn };
        ulong loc = fde.Start;
        if (!Execute(data, dataVa, is64, fde.Cie, fde.Cie.Instructions, fde.Cie.InstructionsEnd, initial, null, ref loc, ulong.MaxValue, out failure)) return null;
        var row = initial.Clone();
        loc = fde.Start;
        return Execute(data, dataVa, is64, fde.Cie, fde.Instructions, fde.InstructionsEnd, row, initial, ref loc, pc, out failure) ? row : null;
    }

    private static bool Execute(ByteView data, ulong dataVa, bool is64, CfiCie cie, long start, long end, CfiRow row, CfiRow? initial, ref ulong loc, ulong pc, out string? failure)
    {
        failure = null;
        var span = data.Span(start, end - start);
        var r = new LebReader(span);
        var remembered = new Stack<CfiRow>();
        long daf = cie.DataAlign;
        int Reg(ref LebReader rd) => (int)Math.Min(rd.Uleb(), int.MaxValue);
        for (int steps = 0; !r.AtEnd; steps++)
        {
            if (steps >= MaxCfiSteps) { failure = "more CFI instructions than the walk allows"; return false; }
            byte op = r.Byte();
            ulong delta = 0;
            bool advance = false;
            switch (op >> 6)
            {
                case 1: delta = (ulong)(op & 0x3F); advance = true; break;
                case 2: row.Rules[op & 0x3F] = new(CfiRuleKind.Offset, (long)r.Uleb() * daf); break;
                case 3: Restore(row, initial, op & 0x3F); break;
                default:
                    switch (op)
                    {
                        case 0x00: break; // nop
                        case 0x01: // set_loc
                        {
                            long p = start + r.Position;
                            if (!TryReadPointer(data, ref p, cie.FdeEncoding, dataVa, 0, is64, out ulong to)) { failure = "DW_CFA_set_loc address is unreadable"; return false; }
                            r.Position = (int)(p - start);
                            if (pc < to) return true;
                            loc = to;
                            break;
                        }
                        case 0x02: delta = r.Byte(); advance = true; break;
                        case 0x03: delta = data.U16(start + r.Position); r.Position += 2; advance = true; break;
                        case 0x04: delta = data.U32(start + r.Position); r.Position += 4; advance = true; break;
                        case 0x05: { int reg = Reg(ref r); row.Rules[reg] = new(CfiRuleKind.Offset, (long)r.Uleb() * daf); break; }
                        case 0x06: Restore(row, initial, Reg(ref r)); break;
                        case 0x07: row.Rules[Reg(ref r)] = new(CfiRuleKind.Undefined, 0); break;
                        case 0x08: row.Rules[Reg(ref r)] = new(CfiRuleKind.SameValue, 0); break;
                        case 0x09: { int reg = Reg(ref r); row.Rules[reg] = new(CfiRuleKind.Register, Reg(ref r)); break; }
                        case 0x0A:
                            if (remembered.Count >= MaxRememberDepth) { failure = "DW_CFA_remember_state nests too deep"; return false; }
                            remembered.Push(row.Clone());
                            break;
                        case 0x0B:
                            if (remembered.Count == 0) { failure = "DW_CFA_restore_state without a remembered state"; return false; }
                            var saved = remembered.Pop();
                            (row.CfaRegister, row.CfaOffset, row.CfaExpression, row.RaSigned, row.Rules) = (saved.CfaRegister, saved.CfaOffset, saved.CfaExpression, saved.RaSigned, saved.Rules);
                            break;
                        case 0x0C: row.CfaRegister = Reg(ref r); row.CfaOffset = (long)r.Uleb(); row.CfaExpression = null; break;
                        case 0x0D: row.CfaRegister = Reg(ref r); row.CfaExpression = null; break;
                        case 0x0E: row.CfaOffset = (long)r.Uleb(); break;
                        case 0x0F: row.CfaExpression = Block(span, ref r); break;
                        case 0x10: { int reg = Reg(ref r); row.Rules[reg] = new(CfiRuleKind.Expression, 0, Block(span, ref r)); break; }
                        case 0x11: { int reg = Reg(ref r); row.Rules[reg] = new(CfiRuleKind.Offset, r.Sleb() * daf); break; }
                        case 0x12: row.CfaRegister = Reg(ref r); row.CfaOffset = r.Sleb() * daf; row.CfaExpression = null; break;
                        case 0x13: row.CfaOffset = r.Sleb() * daf; break;
                        case 0x14: { int reg = Reg(ref r); row.Rules[reg] = new(CfiRuleKind.ValOffset, (long)r.Uleb() * daf); break; }
                        case 0x15: { int reg = Reg(ref r); row.Rules[reg] = new(CfiRuleKind.ValOffset, r.Sleb() * daf); break; }
                        case 0x16: { int reg = Reg(ref r); row.Rules[reg] = new(CfiRuleKind.ValExpression, 0, Block(span, ref r)); break; }
                        case 0x2D: row.RaSigned = !row.RaSigned; break; // AArch64 negate_ra_state (SPARC window_save)
                        case 0x2E: r.Uleb(); break; // GNU_args_size
                        case 0x2F: { int reg = Reg(ref r); row.Rules[reg] = new(CfiRuleKind.Offset, -((long)r.Uleb() * daf)); break; }
                        default:
                            failure = $"unknown CFI instruction 0x{op:X2}";
                            return false;
                    }
                    break;
            }
            if (r.Failed || r.Position > span.Length) { failure = "CFI instructions end inside an instruction"; return false; }
            if (advance)
            {
                ulong next = loc + delta * cie.CodeAlign;
                if (pc < next) return true;
                loc = next;
            }
        }
        return true;
    }

    private static void Restore(CfiRow row, CfiRow? initial, int reg)
    {
        if (initial != null && initial.Rules.TryGetValue(reg, out var rule)) row.Rules[reg] = rule;
        else row.Rules.Remove(reg);
    }

    /// <summary>A ULEB128 length and that many bytes; a block past the end marks the reader failed.</summary>
    private static byte[] Block(ReadOnlySpan<byte> span, ref LebReader r)
    {
        ulong length = r.Uleb();
        if (r.Failed || length > (ulong)(span.Length - r.Position)) { r.Failed = true; return []; }
        var block = span.Slice(r.Position, (int)length).ToArray();
        r.Position += (int)length;
        return block;
    }
}
