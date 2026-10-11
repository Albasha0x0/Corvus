using System.Buffers.Binary;
using AsmArm64;

namespace NetDecompilerMcp.Native.Code;

/// <summary>
/// ARM64 decoding (AsmArm64) over the code of an image. A register file per linear run tracks addresses formed by
/// ADRP / ADR / ADD and what loads from them produce, so ADRP pairs become data references and loads from import slots
/// (GOT entries, Mach-O pointer slots) make the following BR / BLR an import jump or call. One instance per thread.
/// </summary>
internal sealed class Arm64Decoder : ICodeDecoder
{
    private enum Known : byte { None, Address, ImportSlot }

    private const int Registers = 31;
    private const uint Nop = 0xD503201F;

    private readonly ImageCode? _code;
    private readonly INativeImage _image;
    private readonly ulong _imageBase;
    private readonly uint _sizeOfImage;
    private readonly uint[] _relocs;
    private readonly IReadOnlySet<uint> _importSlots;
    private readonly byte[] _scratch = new byte[8];
    private readonly Known[] _kind = new Known[Registers];
    private readonly ulong[] _value = new ulong[Registers];
    private Arm64Instruction _last;

    /// <param name="sortedRelocations">Every relocated pointer location: code words a relocation touches are data, and loads from them yield addresses.</param>
    public Arm64Decoder(INativeImage image, ImageCode? code, uint[] sortedRelocations, IReadOnlySet<uint>? importSlots = null)
    {
        _image = image;
        _code = code;
        _imageBase = image.ImageBase;
        _sizeOfImage = image.SizeOfImage;
        _relocs = sortedRelocations;
        _importSlots = importSlots ?? image.Imports.Select(i => i.SlotRva).ToHashSet();
    }

    public bool Is64 => true;

    /// <summary>The last decoded instruction.</summary>
    public Arm64Instruction Last => _last;

    public void BeginRun(IndexBound incoming) => Array.Clear(_kind);

    public bool Decode(uint rva, out Insn insn)
    {
        var region = _code?.RegionAt(rva);
        if (region == null) { insn = default; return false; }
        Decode(region, rva, out insn);
        return true;
    }

    public void Decode(ImageCode.Region region, uint rva, out Insn insn)
    {
        int at = (int)(rva - region.Rva);
        if ((rva & 3) != 0 || at + 4 > region.Bytes.Length)
        {
            insn = new Insn { Rva = rva, Length = Math.Max(1, Math.Min(4, region.Bytes.Length - at)), Flow = FlowKind.Invalid };
            Array.Clear(_kind);
            return;
        }
        DecodeWord(BinaryPrimitives.ReadUInt32LittleEndian(region.Bytes.AsSpan(at)), rva, out insn);
    }

    public bool DecodeMapped(uint rva, out Insn insn)
    {
        int n = _image.Read(rva, _scratch.AsSpan(0, 4));
        if (n == 0) { insn = default; return false; }
        if (n < 4 || (rva & 3) != 0)
        {
            insn = new Insn { Rva = rva, Length = Math.Max(1, n), Flow = FlowKind.Invalid };
            return true;
        }
        DecodeWord(BinaryPrimitives.ReadUInt32LittleEndian(_scratch), rva, out insn);
        return true;
    }

    /// <summary>Instructions are always little-endian on AArch64, whatever the data byte order.</summary>
    private void DecodeWord(uint word, uint rva, out Insn insn)
    {
        insn = new Insn { Rva = rva, Length = 4 };
        _last = Arm64Instruction.Decode(word);
        // zero fill, and words a relocation patches (literal pools, pointer tables), are data
        if (word == 0 || _last.Id == Arm64InstructionId.Invalid || TouchedByRelocation(rva))
        {
            insn.Flow = FlowKind.Invalid;
            Array.Clear(_kind);
            return;
        }
        var m = _last.Mnemonic;
        long? label = LabelOffset(in _last);
        if (Arm64Extensions.IsBranch(_last.Id))
        {
            switch (m)
            {
                case Arm64Mnemonic.B when _last.Id == Arm64InstructionId.B_only_branch_imm:
                    insn.Flow = FlowKind.Jump;
                    break;
                case Arm64Mnemonic.BL:
                    insn.Flow = FlowKind.Call;
                    break;
                case Arm64Mnemonic.BR or Arm64Mnemonic.BRAA or Arm64Mnemonic.BRAAZ or Arm64Mnemonic.BRAB or Arm64Mnemonic.BRABZ:
                    insn.Flow = FlowKind.IndirectJump;
                    ThroughRegister(ref insn);
                    break;
                case Arm64Mnemonic.BLR or Arm64Mnemonic.BLRAA or Arm64Mnemonic.BLRAAZ or Arm64Mnemonic.BLRAB or Arm64Mnemonic.BLRABZ:
                    insn.Flow = FlowKind.IndirectCall;
                    ThroughRegister(ref insn);
                    break;
                case Arm64Mnemonic.RET or Arm64Mnemonic.RETAA or Arm64Mnemonic.RETAB or Arm64Mnemonic.RETAASPPC or Arm64Mnemonic.RETABSPPC
                    or Arm64Mnemonic.RETAASPPCR or Arm64Mnemonic.RETABSPPCR or Arm64Mnemonic.ERET or Arm64Mnemonic.ERETAA or Arm64Mnemonic.ERETAB:
                    insn.Flow = FlowKind.Return;
                    break;
                default:
                    insn.Flow = label != null ? FlowKind.ConditionalJump : FlowKind.IndirectJump;
                    break;
            }
            if (label is { } off && insn.Flow is FlowKind.Jump or FlowKind.Call or FlowKind.ConditionalJump)
                insn.HasTarget = TryRva(_imageBase + rva + (ulong)off, out insn.Target);
            if (insn.Flow is FlowKind.Call or FlowKind.IndirectCall) ClearCallerSaved();
            return;
        }
        insn.Flow = m is Arm64Mnemonic.BRK or Arm64Mnemonic.HLT or Arm64Mnemonic.UDF ? FlowKind.Trap : FlowKind.Next;
        Track(ref insn, rva, label);
    }

    /// <summary>A register branch through a register loaded from an import slot reads as a jump or call through that slot.</summary>
    private void ThroughRegister(ref Insn insn)
    {
        if (_last.OperandCount == 0 || _last.GetOperand(0) is not { Kind: Arm64OperandKind.Register } op) return;
        int r = X((Arm64RegisterOperand)op);
        if (r < 0 || _kind[r] != Known.ImportSlot) return;
        insn.HasMem = true;
        insn.MemTarget = (uint)_value[r];
        insn.MemAccess = OperandAccess.Read;
    }

    /// <summary>Address forming, memory references and register writes of a non-branch instruction.</summary>
    private void Track(ref Insn insn, uint rva, long? label)
    {
        ref readonly var i = ref _last;
        ulong pc = _imageBase + rva;
        int dest = i.OperandCount > 0 && i.GetOperand(0) is { Kind: Arm64OperandKind.Register } d0 ? X((Arm64RegisterOperand)d0) : -1;
        switch (i.Id)
        {
            case Arm64InstructionId.ADRP_only_pcreladdr when label is { } page:
                Set(dest, Known.Address, (pc & ~0xFFFUL) + (ulong)page);
                return;
            case Arm64InstructionId.ADR_only_pcreladdr when label is { } off:
                Set(dest, Known.Address, pc + (ulong)off);
                Address(ref insn, pc + (ulong)off);
                return;
            case Arm64InstructionId.ADD_64_addsub_imm:
            {
                int src = Reg(1);
                if (src >= 0 && _kind[src] == Known.Address && i.GetOperand(2).Kind == Arm64OperandKind.Immediate)
                {
                    int shift = i.OperandCount > 3 && i.GetOperand(3).Kind == Arm64OperandKind.Shift ? ((Arm64ShiftOperand)i.GetOperand(3)).Amount : 0;
                    ulong value = _value[src] + ((ulong)((Arm64ImmediateOperand)i.GetOperand(2)).Value << shift);
                    Set(dest, Known.Address, value);
                    Address(ref insn, value);
                    return;
                }
                break;
            }
            case Arm64InstructionId.MOV_orr_64_log_shift:
            {
                int src = Reg(1);
                if (dest >= 0 && src >= 0) { _kind[dest] = _kind[src]; _value[dest] = _value[src]; return; }
                break;
            }
        }

        // literal loads: pc-relative data
        if (label is { } literal && i.Flags.HasFlag(Arm64InstructionFlags.HasLabel))
        {
            ulong at = pc + (ulong)literal;
            Memory(ref insn, at, OperandAccess.Read);
            Clobber();
            if (Is64BitLoad(i.Id)) Loaded(dest, at);
            return;
        }

        for (int k = 0; k < i.OperandCount; k++)
        {
            if (i.GetOperand(k) is not { Kind: Arm64OperandKind.Memory } op) continue;
            var mem = (Arm64MemoryOperand)op;
            var a = mem.Accessor;
            int b = a.BaseRegister.Kind == Arm64RegisterKind.X ? a.BaseRegister.Index : -1;
            bool post = a.OffsetKind == Arm64MemoryOffsetKind.None && k + 1 < i.OperandCount && i.GetOperand(k + 1).Kind == Arm64OperandKind.Immediate;
            if (b >= 0 && b < Registers && _kind[b] == Known.Address && !a.HasIndexRegister)
            {
                ulong at = _value[b] + (a.HasImmediate && !post ? (ulong)(long)a.Immediate : 0);
                Memory(ref insn, at, (mem.Flags & Arm64OperandFlags.ReadWrite) switch
                {
                    Arm64OperandFlags.Write => OperandAccess.Write,
                    Arm64OperandFlags.ReadWrite => OperandAccess.ReadWrite,
                    _ => OperandAccess.Read,
                });
                Clobber();
                if (a.IsPreIncrement || post) Set(b, Known.None, 0);
                if (Is64BitLoad(i.Id) && insn.HasMem) Loaded(dest, at);
                return;
            }
            if (b >= 0 && b < Registers && (a.IsPreIncrement || post)) _kind[b] = Known.None;
            break;
        }
        Clobber();
    }

    private static bool Is64BitLoad(Arm64InstructionId id) =>
        id is Arm64InstructionId.LDR_64_ldst_pos or Arm64InstructionId.LDR_64_loadlit or Arm64InstructionId.LDUR_64_ldst_unscaled
            or Arm64InstructionId.LDR_64_ldst_immpre or Arm64InstructionId.LDR_64_ldst_immpost;

    /// <summary>The destination of a 64-bit load from <paramref name="va"/>: an import slot, a relocated pointer into the image, or unknown.</summary>
    private void Loaded(int dest, ulong va)
    {
        if (dest < 0 || !TryRva(va, out uint slot)) return;
        if (_importSlots.Contains(slot)) { Set(dest, Known.ImportSlot, slot); return; }
        if (Array.BinarySearch(_relocs, slot) < 0 || _image.Read(slot, _scratch) < 8) return;
        ulong target = BinaryPrimitives.ReadUInt64LittleEndian(_scratch);
        if (target >= _imageBase && target - _imageBase < _sizeOfImage) Set(dest, Known.Address, target);
    }

    /// <summary>Registers the last instruction writes lose what they held (W writes clear the X register).</summary>
    private void Clobber()
    {
        ref readonly var i = ref _last;
        for (int k = 0; k < i.OperandCount; k++)
        {
            var op = i.GetOperand(k);
            if (op.Kind != Arm64OperandKind.Register || (op.Flags & Arm64OperandFlags.Write) == 0) continue;
            int r = XorW((Arm64RegisterOperand)op);
            if (r >= 0) _kind[r] = Known.None;
        }
    }

    private void ClearCallerSaved()
    {
        Array.Clear(_kind, 0, 19);
        _kind[30] = Known.None;
    }

    private void Set(int reg, Known kind, ulong value)
    {
        if (reg < 0) return;
        _kind[reg] = kind;
        _value[reg] = value;
    }

    private void Address(ref Insn insn, ulong va)
    {
        if (!TryRva(va, out uint rva)) return;
        insn.HasImm = true;
        insn.ImmTarget = rva;
    }

    private void Memory(ref Insn insn, ulong va, OperandAccess access)
    {
        if (!TryRva(va, out uint rva)) return;
        insn.HasMem = true;
        insn.MemTarget = rva;
        insn.MemAccess = access;
    }

    private int Reg(int operand) =>
        operand < _last.OperandCount && _last.GetOperand(operand) is { Kind: Arm64OperandKind.Register } op ? X((Arm64RegisterOperand)op) : -1;

    /// <summary>The index of an X register operand (not XZR or SP), else -1.</summary>
    private static int X(Arm64RegisterOperand op) =>
        op.Value.Kind == Arm64RegisterKind.X && op.Value.Index < Registers && !op.IsZeroRegister ? op.Value.Index : -1;

    private static int XorW(Arm64RegisterOperand op) =>
        op.Value.Kind is Arm64RegisterKind.X or Arm64RegisterKind.W && op.Value.Index < Registers && !op.IsZeroRegister ? op.Value.Index : -1;

    private static long? LabelOffset(in Arm64Instruction i)
    {
        if ((i.Flags & Arm64InstructionFlags.HasLabel) == 0) return null;
        for (int k = 0; k < i.OperandCount; k++)
            if (i.GetOperand(k) is { Kind: Arm64OperandKind.Label } op) return ((Arm64LabelOperand)op).Offset;
        return null;
    }

    private bool TouchedByRelocation(uint rva)
    {
        if (_relocs.Length == 0) return false;
        int i = Array.BinarySearch(_relocs, rva > 7 ? rva - 7 : 0);
        if (i < 0) i = ~i;
        return i < _relocs.Length && _relocs[i] < rva + 4;
    }

    public bool TryRva(ulong va, out uint rva)
    {
        rva = 0;
        if (va < _imageBase || va - _imageBase >= _sizeOfImage) return false;
        rva = (uint)(va - _imageBase);
        return true;
    }

    public void ConditionalBounds(out IndexBound taken, out IndexBound fallThrough) => taken = fallThrough = IndexBound.None;

    public SwitchMatch? MatchSwitch(out string reason)
    {
        reason = SwitchMatch.NoDispatch;
        return null;
    }

    /// <summary>Hypervisor, secure monitor and debug-state instructions: user code never contains them.</summary>
    public bool LastIsImplausible(bool strict = true) =>
        strict && _last.Mnemonic is Arm64Mnemonic.HVC or Arm64Mnemonic.SMC or Arm64Mnemonic.DCPS1 or Arm64Mnemonic.DCPS2 or Arm64Mnemonic.DCPS3
            or Arm64Mnemonic.DRPS or Arm64Mnemonic.ERET or Arm64Mnemonic.ERETAA or Arm64Mnemonic.ERETAB;

    public bool LastHasImplausibleDisplacement(uint rva) => false;

    /// <summary>
    /// A few address-forming instructions ending in BR through a register loaded from an import slot: ELF PLT entries
    /// (adrp x16; ldr x17, [x16, #o]; add x16, x16, #o; br x17), Mach-O stubs (adrp x16; ldr x16, [x16, #o]; br x16) and
    /// their arm64e forms (braa).
    /// </summary>
    public uint? ThunkSlot(uint rva, Func<uint, bool> isImportSlot)
    {
        BeginRun(IndexBound.None);
        for (int n = 0; n < 5; n++, rva += 4)
        {
            if (!Decode(rva, out var insn)) return null;
            if (insn.Flow == FlowKind.IndirectJump) return insn.HasMem && isImportSlot(insn.MemTarget) ? insn.MemTarget : null;
            if (insn.Flow != FlowKind.Next || _last.Mnemonic is not (Arm64Mnemonic.ADRP or Arm64Mnemonic.ADD or Arm64Mnemonic.LDR or Arm64Mnemonic.NOP)) return null;
        }
        return null;
    }

    /// <summary>Zero words, nop and udf between functions.</summary>
    public bool IsPadding(ImageCode.Region region, uint rva)
    {
        int at = (int)(rva - region.Rva);
        if (at + 4 > region.Bytes.Length) return true;
        uint word = BinaryPrimitives.ReadUInt32LittleEndian(region.Bytes.AsSpan(at));
        return word == 0 || word == Nop || (word & 0xFFFF0000) == 0;
    }
}
