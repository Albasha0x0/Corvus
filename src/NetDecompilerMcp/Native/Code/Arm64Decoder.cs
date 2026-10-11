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
    private readonly (uint Start, uint End)[] _data;
    private readonly byte[] _scratch = new byte[8];
    private readonly Known[] _kind = new Known[Registers];
    private readonly ulong[] _value = new ulong[Registers];
    private Arm64Instruction _last;

    // the current linear run, for switch dispatch and bound matching
    private const int RingSize = 32;
    private readonly Arm64Instruction[] _ring = new Arm64Instruction[RingSize];
    private readonly uint[] _ringRva = new uint[RingSize];
    private int _ringHead, _ringCount;
    private IndexBound _runBound;

    // registers given one address in the whole function (hoisted ADRP + ADD): callee-saved x19-x28 are seeded into every
    // run; any register serves as a jump table base, which the table read then verifies
    private const int FirstSaved = 19, LastSaved = 28;
    private readonly ulong[] _saved = new ulong[Registers];
    private readonly byte[] _savedState = new byte[Registers]; // 0 unknown, 1 one address, 2 several

    /// <param name="sortedRelocations">Every relocated pointer location: code words a relocation touches are data, and loads from them yield addresses.</param>
    /// <param name="dataInCode">Sorted ranges inside code that hold data (literal pools, jump tables): never decoded.</param>
    public Arm64Decoder(INativeImage image, ImageCode? code, uint[] sortedRelocations, IReadOnlySet<uint>? importSlots = null,
        (uint Start, uint End)[]? dataInCode = null)
    {
        _data = dataInCode ?? [];
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

    public void BeginFunction() => Array.Clear(_savedState);

    public void BeginRun(IndexBound incoming)
    {
        Array.Clear(_kind);
        for (int r = FirstSaved; r <= LastSaved; r++)
            if (_savedState[r] == 1) Set(r, Known.Address, _saved[r]);
        _ringCount = 0;
        _runBound = incoming;
    }

    /// <summary>An address written to a register: kept for the function while it is the only one seen.</summary>
    private void Remember(int reg, ulong value)
    {
        if (_savedState[reg] == 0) { _savedState[reg] = 1; _saved[reg] = value; }
        else if (_savedState[reg] == 1 && _saved[reg] != value) _savedState[reg] = 2;
    }

    /// <summary>Any other write makes the register's function-wide value unknown.</summary>
    private void Forget(int reg) => _savedState[reg] = 2;

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
        if (word == 0 || _last.Id == Arm64InstructionId.Invalid || TouchedByRelocation(rva) || InData(rva))
        {
            insn.Flow = FlowKind.Invalid;
            Array.Clear(_kind);
            _ringCount = 0;
            return;
        }
        _ring[_ringHead] = _last;
        _ringRva[_ringHead] = rva;
        _ringHead = (_ringHead + 1) % RingSize;
        if (_ringCount < RingSize) _ringCount++;
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
                SetAddress(dest, (pc & ~0xFFFUL) + (ulong)page);
                return;
            case Arm64InstructionId.ADR_only_pcreladdr when label is { } off:
                SetAddress(dest, pc + (ulong)off);
                Address(ref insn, pc + (ulong)off);
                return;
            case Arm64InstructionId.ADD_64_addsub_imm:
            {
                int src = Reg(1);
                if (src >= 0 && _kind[src] == Known.Address && i.GetOperand(2).Kind == Arm64OperandKind.Immediate)
                {
                    int shift = i.OperandCount > 3 && i.GetOperand(3).Kind == Arm64OperandKind.Shift ? ((Arm64ShiftOperand)i.GetOperand(3)).Amount : 0;
                    ulong value = _value[src] + ((ulong)((Arm64ImmediateOperand)i.GetOperand(2)).Value << shift);
                    // adrp x, page; add x, x, #lo12 completes one address, it is not a second one
                    if (dest == src && dest >= 0 && _savedState[dest] == 1 && _saved[dest] == _value[src]) _saved[dest] = value;
                    SetAddress(dest, value);
                    Address(ref insn, value);
                    return;
                }
                break;
            }
            case Arm64InstructionId.MOV_orr_64_log_shift:
            {
                int src = Reg(1);
                if (dest >= 0 && src >= 0)
                {
                    _kind[dest] = _kind[src];
                    _value[dest] = _value[src];
                    if (_kind[src] == Known.Address) Remember(dest, _value[src]); else Forget(dest);
                    return;
                }
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
                if (a.IsPreIncrement || post) { Set(b, Known.None, 0); Forget(b); }
                if (Is64BitLoad(i.Id) && insn.HasMem) Loaded(dest, at);
                return;
            }
            if (b >= 0 && b < Registers && (a.IsPreIncrement || post)) { _kind[b] = Known.None; Forget(b); }
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

    /// <summary>
    /// Registers the last instruction writes lose what they held (W writes clear the X register). Restores from the stack
    /// (epilogues) do not end a callee-saved register's function-wide value.
    /// </summary>
    private void Clobber()
    {
        ref readonly var i = ref _last;
        bool restore = false;
        for (int k = 0; k < i.OperandCount; k++)
            if (i.GetOperand(k) is { Kind: Arm64OperandKind.Memory } m && ((Arm64MemoryOperand)m).Accessor.BaseRegister.Kind == Arm64RegisterKind.SP) restore = true;
        for (int k = 0; k < i.OperandCount; k++)
        {
            var op = i.GetOperand(k);
            if (op.Kind != Arm64OperandKind.Register || (op.Flags & Arm64OperandFlags.Write) == 0) continue;
            int r = XorW((Arm64RegisterOperand)op);
            if (r < 0) continue;
            _kind[r] = Known.None;
            if (!restore) Forget(r);
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

    /// <summary>A write from address forming: also remembered for the function when the register is callee-saved.</summary>
    private void SetAddress(int reg, ulong value)
    {
        Set(reg, Known.Address, value);
        if (reg >= 0) Remember(reg, value);
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

    private bool InData(uint rva)
    {
        int lo = 0, hi = _data.Length - 1;
        while (lo <= hi)
        {
            int mid = (lo + hi) >>> 1;
            if (rva < _data[mid].Start) hi = mid - 1;
            else if (rva >= _data[mid].End) lo = mid + 1;
            else return true;
        }
        return false;
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

    /// <summary>Instruction <paramref name="k"/> steps back in the current run (0 = the last one).</summary>
    private ref Arm64Instruction Back(int k) => ref _ring[(_ringHead - 1 - k + RingSize * 2) % RingSize];

    private uint BackRva(int k) => _ringRva[(_ringHead - 1 - k + RingSize * 2) % RingSize];

    private static int Index(in Arm64Instruction i, int operand) =>
        operand < i.OperandCount && i.GetOperand(operand) is { Kind: Arm64OperandKind.Register } op ? XorW((Arm64RegisterOperand)op) : -1;

    /// <summary>Operand 0 of a non-branch instruction is a register it writes (X or W): its index, else -1.</summary>
    private static int Written(in Arm64Instruction i)
    {
        if (Arm64Extensions.IsBranch(i.Id) || i.OperandCount == 0 || i.GetOperand(0) is not { Kind: Arm64OperandKind.Register } op
            || (op.Flags & Arm64OperandFlags.Write) == 0) return -1;
        return XorW((Arm64RegisterOperand)op);
    }

    private static bool Writes(in Arm64Instruction i, int reg)
    {
        if (Written(in i) == reg) return true;
        // the second destination of a load pair
        return i.Mnemonic is Arm64Mnemonic.LDP or Arm64Mnemonic.LDPSW or Arm64Mnemonic.LDNP or Arm64Mnemonic.LDAXP or Arm64Mnemonic.LDXP && Index(in i, 1) == reg;
    }

    /// <summary>Step of the nearest instruction at or before step <paramref name="k"/> that writes <paramref name="reg"/>, or -1 (also at a call).</summary>
    private int Writer(int k, int reg)
    {
        for (; k < _ringCount; k++)
        {
            ref var x = ref Back(k);
            if (x.Mnemonic is Arm64Mnemonic.BL or Arm64Mnemonic.BLR or Arm64Mnemonic.BLRAA or Arm64Mnemonic.BLRAAZ or Arm64Mnemonic.BLRAB or Arm64Mnemonic.BLRABZ) return -1;
            if (Writes(in x, reg)) return k;
        }
        return -1;
    }

    /// <summary>The address <paramref name="reg"/> holds before step <paramref name="k"/>, formed by ADRP / ADD / ADR / MOV in the run.</summary>
    private ulong? Constant(int k, int reg, int depth = 0)
    {
        int w = Writer(k, reg);
        if (w < 0 && reg >= 0 && _savedState[reg] == 1) return _saved[reg];
        if (w < 0 || depth > 6) return null;
        ref var x = ref Back(w);
        ulong pc = _imageBase + BackRva(w);
        long? label = LabelOffset(in x);
        switch (x.Id)
        {
            case Arm64InstructionId.ADRP_only_pcreladdr when label is { } page: return (pc & ~0xFFFUL) + (ulong)page;
            case Arm64InstructionId.ADR_only_pcreladdr when label is { } off: return pc + (ulong)off;
            case Arm64InstructionId.ADD_64_addsub_imm when x.GetOperand(2).Kind == Arm64OperandKind.Immediate:
            {
                int shift = x.OperandCount > 3 && x.GetOperand(3).Kind == Arm64OperandKind.Shift ? ((Arm64ShiftOperand)x.GetOperand(3)).Amount : 0;
                return Constant(w + 1, Index(in x, 1), depth + 1) is { } v ? v + ((ulong)((Arm64ImmediateOperand)x.GetOperand(2)).Value << shift) : null;
            }
            case Arm64InstructionId.MOV_orr_64_log_shift:
                return Constant(w + 1, Index(in x, 1), depth + 1);
        }
        return null;
    }

    private static bool SetsFlags(in Arm64Instruction i) =>
        i.Mnemonic is Arm64Mnemonic.CMP or Arm64Mnemonic.CMN or Arm64Mnemonic.TST or Arm64Mnemonic.SUBS or Arm64Mnemonic.ADDS or Arm64Mnemonic.ANDS
            or Arm64Mnemonic.BICS or Arm64Mnemonic.ADCS or Arm64Mnemonic.SBCS or Arm64Mnemonic.NEGS or Arm64Mnemonic.NGCS or Arm64Mnemonic.CCMP
            or Arm64Mnemonic.CCMN or Arm64Mnemonic.FCMP or Arm64Mnemonic.FCMPE or Arm64Mnemonic.FCCMP or Arm64Mnemonic.FCCMPE;

    /// <summary>"cmp reg, #imm" (or against a register loaded with mov #imm) at step <paramref name="k"/>: the register and the value.</summary>
    private bool Compare(int k, out int reg, out ulong imm)
    {
        reg = -1;
        imm = 0;
        ref var x = ref Back(k);
        if (x.Mnemonic != Arm64Mnemonic.CMP || x.OperandCount < 2) return false;
        reg = Index(in x, 0);
        var second = x.GetOperand(1);
        if (second.Kind == Arm64OperandKind.Immediate)
        {
            int shift = x.OperandCount > 2 && x.GetOperand(2).Kind == Arm64OperandKind.Shift ? ((Arm64ShiftOperand)x.GetOperand(2)).Amount : 0;
            imm = (ulong)((Arm64ImmediateOperand)second).Value << shift;
            return reg >= 0;
        }
        if (second.Kind != Arm64OperandKind.Register || x.OperandCount > 2 && x.GetOperand(2).Kind != Arm64OperandKind.Shift) return false;
        int w = Writer(k + 1, Index(in x, 1));
        if (w < 0) return false;
        ref var set = ref Back(w);
        if (set.Mnemonic != Arm64Mnemonic.MOV || set.OperandCount < 2 || set.GetOperand(1).Kind != Arm64OperandKind.Immediate) return false;
        long v = ((Arm64ImmediateOperand)set.GetOperand(1)).Value;
        if (v < 0) return false;
        imm = (ulong)v;
        return reg >= 0;
    }

    /// <summary>
    /// "ccmp reg, #imm, #nzcv, cond" at step <paramref name="k"/> whose fallback flags also take the out-of-range branch
    /// <paramref name="branch"/> (b.hi / b.hs): falling through still means reg is in range.
    /// </summary>
    private bool ConditionalCompare(int k, uint branch, out int reg, out ulong imm)
    {
        reg = -1;
        imm = 0;
        ref var x = ref Back(k);
        if (x.Mnemonic != Arm64Mnemonic.CCMP || x.OperandCount < 3 || x.GetOperand(1).Kind != Arm64OperandKind.Immediate || x.GetOperand(2).Kind != Arm64OperandKind.Immediate)
            return false;
        long nzcv = ((Arm64ImmediateOperand)x.GetOperand(2)).Value;
        bool c = (nzcv & 2) != 0, z = (nzcv & 4) != 0;
        if (!(branch == Hi ? c && !z : c)) return false;
        reg = Index(in x, 0);
        imm = (ulong)((Arm64ImmediateOperand)x.GetOperand(1)).Value;
        return reg >= 0;
    }

    /// <summary>The constant <paramref name="reg"/> was reduced by just before step <paramref name="k"/> (sub / add #imm), following copies.</summary>
    private long BiasBefore(int k, int reg)
    {
        for (int n = 0; k < _ringCount && n < 8; k++, n++)
        {
            ref var x = ref Back(k);
            if (!Writes(in x, reg)) continue;
            switch (x.Mnemonic)
            {
                case Arm64Mnemonic.SUB or Arm64Mnemonic.ADD when x.OperandCount > 2 && x.GetOperand(2).Kind == Arm64OperandKind.Immediate:
                    int shift = x.OperandCount > 3 && x.GetOperand(3).Kind == Arm64OperandKind.Shift ? ((Arm64ShiftOperand)x.GetOperand(3)).Amount : 0;
                    long v = ((Arm64ImmediateOperand)x.GetOperand(2)).Value << shift;
                    return x.Mnemonic == Arm64Mnemonic.SUB ? v : -v;
                case Arm64Mnemonic.MOV or Arm64Mnemonic.SXTW when x.OperandCount >= 2 && x.GetOperand(1).Kind == Arm64OperandKind.Register:
                    reg = Index(in x, 1);
                    continue;
                default:
                    return 0;
            }
        }
        return 0;
    }

    private static uint? Condition(in Arm64Instruction i) =>
        i.Id is Arm64InstructionId.B_only_condbranch or Arm64InstructionId.BC_only_condbranch && i.GetOperand(0).Kind == Arm64OperandKind.Enum
            ? (uint)((Arm64EnumOperand)i.GetOperand(0)).Value : null;

    private const uint Hs = 2, Lo = 3, Hi = 8, Ls = 9;

    /// <summary>After a b.cond (the last instruction): the index bounds on its taken and fall-through paths, from the compare before it.</summary>
    public void ConditionalBounds(out IndexBound taken, out IndexBound fallThrough)
    {
        taken = fallThrough = IndexBound.None;
        if (_ringCount < 2 || Condition(in Back(0)) is not { } cc) return;
        int k = 1;
        while (k < _ringCount && !SetsFlags(in Back(k))) k++;
        if (k >= _ringCount || !Compare(k, out int reg, out ulong imm) || imm >= uint.MaxValue) return;
        for (int j = k - 1; j > 0; j--) if (Writes(in Back(j), reg)) return;
        uint rva = BackRva(0);
        uint? target = LabelOffset(in Back(0)) is { } off && TryRva(_imageBase + rva + (ulong)off, out uint t) ? t : null;
        uint? next = rva + 4;
        long bias = BiasBefore(k + 1, reg);
        // the flags travel with the taken edge: a b.hi in the target block still bounds the compared register
        taken = new(0, 0, Bias: bias, FlagsReg: reg + 1, FlagsImm: imm);
        switch (cc)
        {
            case Hi: fallThrough = new(reg + 1, (uint)imm + 1, Default: target, Bias: bias); break;
            case Hs: fallThrough = new(reg + 1, (uint)imm, Default: target, Bias: bias); break;
            case Ls: taken = taken with { Reg = reg + 1, Count = (uint)imm + 1, Default = next }; break;
            case Lo: taken = taken with { Reg = reg + 1, Count = (uint)imm, Default = next }; break;
        }
    }

    /// <summary>
    /// The jump table dispatch ending at the last instruction (br xT), in any order within the run:
    /// xT = base + (ext(load) &lt;&lt; s) with load = ldr{b,h,sb,sh,sw} / ldr w [xTab, xIdx{, lsl / uxtw / sxtw #k}] and base an
    /// adr / adrp+add address or the table itself; or xT = ldr x [xTab, xIdx, lsl #3] (absolute entries). The index is
    /// bounded by cmp + b.hi / b.hs on the path (with a sub bias), an and-mask, or a bound carried into the run.
    /// </summary>
    public SwitchMatch? MatchSwitch(out string reason)
    {
        reason = SwitchMatch.NoDispatch;
        if (_ringCount == 0) return null;
        ref var br = ref Back(0);
        if (br.Mnemonic is not (Arm64Mnemonic.BR or Arm64Mnemonic.BRAAZ or Arm64Mnemonic.BRABZ)) return null;
        int t = Index(in br, 0);
        int w = Writer(1, t);
        if (w < 0) { reason = "the target register is set before this block"; return null; }
        ref var x = ref Back(w);
        if (x.Mnemonic == Arm64Mnemonic.LDR && Load(w, out _) is { Size: 8 } a)
            return Bound(a, out reason) is { } absolute ? absolute with { Absolute = true } : null;
        if (x.Mnemonic is Arm64Mnemonic.LDR or Arm64Mnemonic.LDUR or Arm64Mnemonic.LDRAA or Arm64Mnemonic.LDRAB)
        {
            reason = "jump through a pointer loaded from memory (a function pointer or vtable slot)";
            return null;
        }
        if (x.Mnemonic != Arm64Mnemonic.ADD || x.OperandCount < 3 || x.GetOperand(2).Kind != Arm64OperandKind.Register) return null;
        int shift = 0;
        bool? signed = null;
        if (x.OperandCount > 3)
        {
            var mod = x.GetOperand(3);
            if (mod.Kind == Arm64OperandKind.Shift) shift = ((Arm64ShiftOperand)mod).Amount;
            else if (mod.Kind == Arm64OperandKind.Extend)
            {
                var ext = (Arm64ExtendOperand)mod;
                shift = ext.Amount;
                signed = ext.ExtendKind is Arm64ExtendKind.SXTB or Arm64ExtendKind.SXTH or Arm64ExtendKind.SXTW or Arm64ExtendKind.SXTX;
            }
        }
        // either operand may be the base; the other is the loaded entry
        foreach (var (baseReg, entryReg) in new[] { (Index(in x, 1), Index(in x, 2)), (Index(in x, 2), Index(in x, 1)) })
        {
            int lw = Writer(w + 1, entryReg);
            if (lw < 0 || Load(lw, out _) is not { } load || load.Size == 8) continue;
            ulong? b = Constant(w + 1, baseReg);
            if (b == null && baseReg == load.TableReg) b = load.Table;
            if (b is not { } baseVa || !TryRva(baseVa, out uint baseRva)) continue;
            var m = Bound(load, out reason);
            if (m == null) return null;
            return m with { Base = baseRva, Shift = shift, Signed = signed ?? load.Signed };
        }
        return null;
    }

    private readonly record struct TableLoad(int Step, uint Table, int TableReg, int IndexReg, int Size, bool Signed);

    /// <summary>The load at step <paramref name="k"/> reads [xTab, xIdx{, scaled}] with xTab a known address.</summary>
    private TableLoad? Load(int k, out bool scaled)
    {
        scaled = false;
        ref var x = ref Back(k);
        (int size, bool signed) = x.Mnemonic switch
        {
            Arm64Mnemonic.LDRB => (1, false),
            Arm64Mnemonic.LDRSB => (1, true),
            Arm64Mnemonic.LDRH => (2, false),
            Arm64Mnemonic.LDRSH => (2, true),
            Arm64Mnemonic.LDRSW => (4, true),
            Arm64Mnemonic.LDR when x.GetOperand(0) is { Kind: Arm64OperandKind.Register } d
                && ((Arm64RegisterOperand)d).Value.Kind is Arm64RegisterKind.W or Arm64RegisterKind.X => (((Arm64RegisterOperand)d).Value.Kind == Arm64RegisterKind.X ? 8 : 4, false),
            _ => (0, false),
        };
        if (size == 0 || x.OperandCount < 2 || x.GetOperand(1).Kind != Arm64OperandKind.Memory) return null;
        var a = ((Arm64MemoryOperand)x.GetOperand(1)).Accessor;
        if (!a.HasIndexRegister || a.BaseRegister.Kind != Arm64RegisterKind.X) return null;
        int amount = a.HasExtend ? a.Extend.Amount : 0;
        if (amount != 0 && 1 << amount != size) return null;
        scaled = amount != 0;
        if (Constant(k + 1, a.BaseRegister.Index) is not { } table || !TryRva(table, out uint tableRva)) return null;
        return new TableLoad(k, tableRva, a.BaseRegister.Index, a.IndexRegister.Index, size, signed);
    }

    /// <summary>The bound of the load's index register, searched back from the load: a SwitchMatch without base, or null with the reason.</summary>
    private SwitchMatch? Bound(TableLoad load, out string reason)
    {
        reason = "switch index bound not found";
        int current = load.IndexReg;
        uint? pending = null;
        int pendingStep = 0;
        for (int k = load.Step + 1; k < _ringCount; k++)
        {
            ref var x = ref Back(k);
            if (x.Mnemonic is Arm64Mnemonic.BL or Arm64Mnemonic.BLR) return null;
            if (Condition(in x) is { } cc)
            {
                // the branch nearest the dispatch bounds it; earlier ones on the same flags leave the run when taken
                if (pending == null) { pending = cc; pendingStep = k; }
                continue;
            }
            if (pending is { } p && SetsFlags(in x))
            {
                if (p is Hi or Hs && (Compare(k, out int reg, out ulong imm) || ConditionalCompare(k, p, out reg, out imm)) && reg == current && imm < uint.MaxValue)
                {
                    uint count = p == Hi ? (uint)imm + 1 : (uint)imm;
                    uint? dflt = LabelOffset(in Back(pendingStep)) is { } off && TryRva(_imageBase + BackRva(pendingStep) + (ulong)off, out uint d) ? d : null;
                    return Match(load, count) with { Default = dflt, Bias = BiasBefore(k + 1, current) };
                }
                pending = null;
            }
            if (!Writes(in x, current)) continue;
            if (x.Mnemonic == Arm64Mnemonic.AND && x.OperandCount > 2 && x.GetOperand(2).Kind == Arm64OperandKind.Immediate
                && ((Arm64ImmediateOperand)x.GetOperand(2)).Value is var mask and >= 0 and < 1 << 20 && (mask & (mask + 1)) == 0)
                return Match(load, (uint)mask + 1) with { BoundByMask = true };
            if (x.Mnemonic is Arm64Mnemonic.MOV or Arm64Mnemonic.SXTW && x.OperandCount >= 2 && x.GetOperand(1).Kind == Arm64OperandKind.Register)
            {
                current = Index(in x, 1);
                continue;
            }
            return null;
        }
        if (_runBound.Reg == current + 1)
            return Match(load, _runBound.Count) with { Default = _runBound.Default, Bias = _runBound.Bias };
        if (pending is Hi or Hs && _runBound.FlagsReg == current + 1 && _runBound.FlagsImm < uint.MaxValue)
        {
            uint? dflt = LabelOffset(in Back(pendingStep)) is { } off && TryRva(_imageBase + BackRva(pendingStep) + (ulong)off, out uint d) ? d : null;
            return Match(load, pending == Hi ? (uint)_runBound.FlagsImm + 1 : (uint)_runBound.FlagsImm) with { Default = dflt, Bias = _runBound.Bias };
        }
        return null;
    }

    private static SwitchMatch Match(TableLoad load, uint count) => new(load.Table, load.Size, false, false, count, null, 0, false);

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
