using AsmArm64;
using Corvus.Native.Calls;

namespace Corvus.Native.Code;

internal sealed partial class ProvenanceState
{
    private const int Lr = 30;

    private const int FramePointer = 29;

    private const int ZeroRegister = 31;

    // Registers a call may change under the AAPCS64: x0-x18 and the link
    // register.
    private const int LastVolatile = 18;

    private static bool IsFrameBase(Arm64RegisterAny r) =>
        r.Kind == Arm64RegisterKind.SP || r is { Kind: Arm64RegisterKind.X, Index: FramePointer };

    /// <summary>
    /// Applies one AArch64 step, whose stack offsets are entry-relative;
    /// imageBase resolves adrp and adr results to addresses.
    /// </summary>
    internal void ApplyArm64(A64Step step, ulong imageBase)
    {
        var i = step.I;
        if (A64Function.IsCall(in i))
        {
            for (int r = 0; r <= LastVolatile; r++) _regs.Remove(r);
            _regs.Remove(Lr);
            _epoch = imageBase + step.Rva;
            _regs[0] = new ResultOrigin(imageBase + step.Rva);
            return;
        }
        if (Arm64Resolver.IsStore(in i)) { Store(step, imageBase); return; }
        if (Arm64Resolver.IsLoad(in i)) { Load(step); return; }
        if (A64Function.Dest(in i) is not { } dest) return;
        int d = A64Function.Number(dest);
        if (d < 0) return;
        var value = Compute(step, imageBase);
        _regs.Remove(d);
        if (d < ZeroRegister && value != null) SetReg(d, value);
    }

    // The value a move, address or add leaves in its destination; null for
    // others.
    private Origin? Compute(A64Step step, ulong imageBase)
    {
        var i = step.I;
        var dest = A64Function.Dest(in i)!.Value;
        bool wide = dest.Kind == Arm64RegisterKind.X;
        long Narrow(long v) => wide ? v : (long)(uint)v;
        var reg1 = i.OperandCount >= 2 && i.GetOperand(1) is { Kind: Arm64OperandKind.Register } o1 ? (Arm64RegisterOperand?)(Arm64RegisterOperand)o1 : null;
        switch (i.Mnemonic)
        {
            case Arm64Mnemonic.MOV or Arm64Mnemonic.MOVZ when A64Function.Imm(in i, 1) is { } imm:
                return new ConstOrigin(Narrow(imm));
            case Arm64Mnemonic.MOVN when A64Function.Imm(in i, 1) is { } imm:
                return new ConstOrigin(Narrow(~imm));
            case Arm64Mnemonic.MOVK when A64Function.Imm(in i, 1) is { } imm && GetReg(A64Function.Number(dest)) is ConstOrigin prior:
            {
                int shift = i.OperandCount > 2 && i.GetOperand(2).Kind == Arm64OperandKind.Shift ? ((Arm64ShiftOperand)i.GetOperand(2)).Amount : 0;
                long bits = 0xFFFFL << shift;
                return new ConstOrigin(Narrow((prior.Number & ~bits) | (imm & bits)));
            }
            case Arm64Mnemonic.MOV when reg1 is { } src:
                if (src.IsZeroRegister) return new ConstOrigin(0);
                if (IsFrameBase(src.Value)) { TakeFrameAddress(dest); return null; }
                // A 32-bit copy truncates, so only a constant survives it.
                if (wide && src.Value.Kind == Arm64RegisterKind.X
                    && A64Function.Number(src.Value) is var from and >= 0 and < ZeroRegister)
                    return GetReg(from);
                return GetReg(A64Function.Number(src.Value)) is ConstOrigin copied ? new ConstOrigin(Narrow(copied.Number)) : null;
            case Arm64Mnemonic.ADRP or Arm64Mnemonic.ADR when i.Flags.HasFlag(Arm64InstructionFlags.HasLabel):
            {
                long off = ((Arm64LabelOperand)i.GetOperand(1)).Offset;
                ulong pc = imageBase + step.Rva;
                return new AddressOrigin((i.Mnemonic == Arm64Mnemonic.ADRP ? pc & ~0xFFFUL : pc) + (ulong)off);
            }
            case Arm64Mnemonic.ADD or Arm64Mnemonic.SUB when A64Function.Imm(in i, 2) is { } imm && reg1 is { } src:
            {
                long delta = i.Mnemonic == Arm64Mnemonic.SUB ? -imm : imm;
                if (IsFrameBase(src.Value)) { TakeFrameAddress(dest); return null; }
                return GetReg(A64Function.Number(src.Value)) switch
                {
                    ConstOrigin c => new ConstOrigin(Narrow(c.Number + delta)),
                    AddressOrigin a when wide => new AddressOrigin(a.Address + (ulong)delta),
                    _ => null,
                };
            }
            default:
                return null;
        }
    }

    // The frame pointer is set in the prologue; any other frame address can
    // be written through.
    private void TakeFrameAddress(Arm64RegisterAny dest)
    {
        if (dest is { Kind: Arm64RegisterKind.X, Index: FramePointer } || dest.Kind == Arm64RegisterKind.SP) return;
        _escaped = true;
        _slots.Clear();
    }

    private void Store(A64Step step, ulong imageBase)
    {
        var i = step.I;
        if (A64Function.Memory(step) is not { } m) return;
        if (!IsFrameBase(m.Accessor.BaseRegister))
        {
            _epoch = imageBase + step.Rva;
            Writeback(m);
            return;
        }
        if (m.Slot is not { } slot || m.Accessor.HasIndexRegister)
        {
            _slots.Clear();
            Writeback(m);
            return;
        }
        int size = Arm64Inspector.AccessSize(in i);
        bool pair = i.Mnemonic is Arm64Mnemonic.STP or Arm64Mnemonic.STNP;
        int each = pair ? size / 2 : size;
        Forget(slot, size);
        if (each == 8 && !_escaped)
            for (int k = 0; k < (pair ? 2 : 1); k++)
            {
                if (A64Function.IsW(in i, k)) continue;
                int reg = A64Function.Reg(in i, k);
                Origin? stored = reg == ZeroRegister ? new ConstOrigin(0) : reg is >= 0 and < ZeroRegister ? GetReg(reg) : null;
                if (stored != null) _slots[slot + k * 8] = stored;
            }
        Writeback(m);
    }

    private void Load(A64Step step)
    {
        var i = step.I;
        var dests = new List<(int Reg, int Operand)>();
        bool pair = i.Mnemonic is Arm64Mnemonic.LDP or Arm64Mnemonic.LDPSW or Arm64Mnemonic.LDNP;
        for (int k = 0; k < (pair ? 2 : 1); k++)
            if (A64Function.Reg(in i, k) is var r and >= 0) dests.Add((r, k));
        var values = new Origin?[dests.Count];
        if (A64Function.Memory(step) is { } m)
        {
            int size = Arm64Inspector.AccessSize(in i);
            int each = pair ? size / 2 : size;
            bool plain = i.Mnemonic is Arm64Mnemonic.LDR or Arm64Mnemonic.LDUR or Arm64Mnemonic.LDP or Arm64Mnemonic.LDNP;
            for (int n = 0; n < dests.Count && plain && each == 8; n++)
            {
                if (dests[n].Reg >= ZeroRegister || A64Function.IsW(in i, dests[n].Operand)) continue;
                values[n] = LoadedValue(m, n * each);
            }
            Writeback(m);
        }
        foreach (var (reg, _) in dests) _regs.Remove(reg);
        for (int n = 0; n < dests.Count; n++)
            if (dests[n].Reg < ZeroRegister) SetReg(dests[n].Reg, values[n]);
    }

    // The 64-bit value at the memory operand plus an extra offset; null when
    // unknown.
    private Origin? LoadedValue((int Operand, Arm64MemoryAccessorAny Accessor, bool Post, int? Slot) m, int extra)
    {
        var a = m.Accessor;
        if (a.HasIndexRegister) return null;
        if (IsFrameBase(a.BaseRegister)) return m.Slot is { } s && !_escaped ? _slots.GetValueOrDefault(s + extra) : null;
        if (a.BaseRegister.Kind != Arm64RegisterKind.X) return null;
        long disp = (m.Post ? 0 : a.HasImmediate ? a.Immediate : 0) + extra;
        return GetReg(a.BaseRegister.Index) is { } b ? new LoadOrigin(b, disp, _epoch) : null;
    }

    // A pre- or post-indexed access changes its base register.
    private void Writeback((int Operand, Arm64MemoryAccessorAny Accessor, bool Post, int? Slot) m)
    {
        if ((m.Accessor.IsPreIncrement || m.Post) && m.Accessor.BaseRegister.Kind == Arm64RegisterKind.X)
            _regs.Remove(m.Accessor.BaseRegister.Index);
    }
}
