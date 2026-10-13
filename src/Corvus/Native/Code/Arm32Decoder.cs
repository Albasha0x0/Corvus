using System.Buffers.Binary;

namespace Corvus.Native.Code;

/// <summary>
/// A32 / T32 decoding over the code of a 32-bit ARM image, in the state <see cref="Arm32Modes"/> gives each function
/// (BLX targets switch it). IT blocks make the instructions they cover conditional. A register file per linear run
/// tracks constants (MOVW / MOVT, MOV, literal loads) and addresses (ADR, PC-relative ADD, relocated MOVW / MOVT pairs and
/// literals), so literal pools and PC-relative pairs become data references, loads from import slots make the
/// following BX / BLX an import jump or call, and branches through a register holding a code address become direct.
/// One instance per thread.
/// </summary>
internal sealed class Arm32Decoder : ICodeDecoder
{
    private enum Known : byte { None, Constant, Address, ImportSlot }

    private const int Pc = 15, Lr = 14, Sp = 13;

    private readonly INativeImage _image;
    private readonly ImageCode? _code;
    private readonly uint _imageBase;
    private readonly uint _sizeOfImage;
    private readonly uint[] _relocs;
    private readonly IReadOnlySet<uint> _importSlots;
    private readonly (uint Start, uint End)[] _data;
    private readonly byte[] _scratch = new byte[4];
    private readonly Known[] _kind = new Known[16];
    private readonly uint[] _value = new uint[16];
    // a MOVW whose relocation (PE THUMB_MOV32 / ARM_MOV32) makes the MOVT that completes it an address
    private readonly bool[] _relocatedLow = new bool[16];
    // an address read from an unrelocated literal of a fixed-address image: a PC-relative offset when added to the PC
    private readonly bool[] _literal = new bool[16];
    private ArmInstruction _last;
    private bool _thumb = true;
    private bool _pinned;
    private uint _expected = uint.MaxValue;
    private int _itFirst, _itMask, _itLeft, _itIndex;

    // the current linear run, for switch dispatch and bound matching
    private const int RingSize = 64;
    private readonly ArmInstruction[] _ring = new ArmInstruction[RingSize];
    private readonly uint[] _ringRva = new uint[RingSize];
    private int _ringHead, _ringCount;
    private IndexBound _runBound;

    // callee-saved r4-r11 holding one address in the whole function (hoisted PIC bases)
    private const int FirstSaved = 4, LastSaved = 11;
    private readonly uint[] _saved = new uint[16];
    private readonly byte[] _savedState = new byte[16]; // 0 unknown, 1 one address, 2 several

    public Arm32Decoder(INativeImage image, ImageCode? code, uint[] sortedRelocations, Arm32Modes modes, IReadOnlySet<uint>? importSlots = null,
        (uint Start, uint End)[]? dataInCode = null)
    {
        _image = image;
        _code = code;
        _imageBase = (uint)image.ImageBase;
        _sizeOfImage = image.SizeOfImage;
        _relocs = sortedRelocations;
        Modes = modes;
        _importSlots = importSlots ?? image.Imports.Select(i => i.SlotRva).ToHashSet();
        _data = dataInCode ?? [];
    }

    public Arm32Modes Modes { get; }

    public bool Is64 => false;

    /// <summary>The last decoded instruction.</summary>
    public ArmInstruction Last => _last;

    /// <summary>The state decoding uses: fixed by <see cref="BeginFunction(uint)"/> or <see cref="Pin"/>, else looked up per address.</summary>
    public bool Thumb => _thumb;

    public void BeginFunction() => Array.Clear(_savedState);

    public void BeginFunction(uint start)
    {
        BeginFunction();
        Pin(Modes.StartMode(start));
    }

    /// <summary>Decodes in <paramref name="thumb"/> state until the next <see cref="BeginFunction(uint)"/> or <see cref="Unpin"/>.</summary>
    public void Pin(bool thumb)
    {
        _thumb = thumb;
        _pinned = true;
    }

    /// <summary>Looks the state up per address again.</summary>
    public void Unpin() => _pinned = false;

    public void BeginRun(IndexBound incoming)
    {
        Array.Clear(_kind);
        for (int r = FirstSaved; r <= LastSaved; r++)
            if (_savedState[r] == 1) Set(r, Known.Address, _saved[r]);
        _ringCount = 0;
        _runBound = incoming;
        _itLeft = 0;
        _expected = uint.MaxValue;
    }

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
        DecodeBytes(region.Bytes.AsSpan(at, Math.Min(4, region.Bytes.Length - at)), rva, out insn);
    }

    public bool DecodeMapped(uint rva, out Insn insn)
    {
        int n = _image.Read(rva, _scratch);
        if (n == 0) { insn = default; return false; }
        DecodeBytes(_scratch.AsSpan(0, n), rva, out insn);
        return true;
    }

    /// <summary>Bytes a load moves: one register's access size times the registers it loads.</summary>
    private static int LoadSize(in ArmInstruction i)
    {
        for (int k = 0; k < i.OperandCount; k++)
            if (i.Operands[k].Kind == ArmOperandKind.VectorList) return i.AccessSize * Math.Max(1, (int)i.Operands[k].Count);
        return i.AccessSize * (i.Mnemonic == "ldrd" ? 2 : 1);
    }

    /// <summary>Bytes the last instruction loads from a known address inside code (a literal pool entry at its memory target); 0 for none.</summary>
    public int LastLiteralSize { get; private set; }

    private void DecodeBytes(ReadOnlySpan<byte> bytes, uint rva, out Insn insn)
    {
        LastLiteralSize = 0;
        if (!_pinned) _thumb = Modes.At(rva);
        if (rva != _expected) _itLeft = 0;
        uint va = _imageBase + rva;
        if (_thumb)
        {
            if ((rva & 1) != 0) { Invalid(rva, 1, out insn); return; }
            Arm32Decode.Thumb(bytes, va, _itLeft > 0, out _last);
        }
        else
        {
            if ((rva & 3) != 0 || bytes.Length < 4) { Invalid(rva, Math.Max(1, Math.Min(4, bytes.Length)), out insn); return; }
            Arm32Decode.Arm(BinaryPrimitives.ReadUInt32LittleEndian(bytes), va, out _last);
        }
        int length = _last.Length;
        _expected = rva + (uint)length;
        if (!_last.IsValid || InData(rva) || (TouchedByRelocation(rva, length) && _last.Mnemonic is not ("movw" or "movt"))
            || (_last.Raw == 0 && (!_thumb || bytes.Length >= 4 && bytes[2] == 0 && bytes[3] == 0)))
        {
            Invalid(rva, length, out insn);
            return;
        }
        if (_itLeft > 0)
        {
            if (_last.Mnemonic.StartsWith("it", StringComparison.Ordinal) && _last.ItMask != 0) { Invalid(rva, length, out insn); return; }
            _last.Cond = Arm32Decode.ItCondition(_itFirst, _itMask, _itIndex++);
            _last.ReadsFlags = true;
            _itLeft--;
        }
        else if (_last.ItMask != 0)
        {
            _itFirst = _last.ItFirst;
            _itMask = _last.ItMask;
            _itLeft = Arm32Decode.ItCount(_itMask);
            _itIndex = 0;
        }
        _ring[_ringHead] = _last;
        _ringRva[_ringHead] = rva;
        _ringHead = (_ringHead + 1) % RingSize;
        if (_ringCount < RingSize) _ringCount++;

        insn = new Insn { Rva = rva, Length = length };
        bool conditional = _last.IsConditional;
        // bx lr / mov pc, lr after the run computed lr (adr; add lr, lr, index, lsl #2): a jump table dispatch, not a return
        if (_last.Flow == ArmFlow.Return && _last.Mnemonic is "bx" or "mov" && ComputedLr()) _last.Flow = ArmFlow.IndirectJump;
        switch (_last.Flow)
        {
            case ArmFlow.Jump:
                insn.Flow = conditional || _last.Mnemonic is "cbz" or "cbnz" ? FlowKind.ConditionalJump : FlowKind.Jump;
                Branch(ref insn);
                return;
            case ArmFlow.Call:
                insn.Flow = FlowKind.Call;
                Branch(ref insn);
                ClearCallerSaved();
                return;
            case ArmFlow.IndirectCall:
                insn.Flow = FlowKind.IndirectCall;
                Through(ref insn, rva);
                ClearCallerSaved();
                return;
            case ArmFlow.IndirectJump:
                insn.Flow = FlowKind.IndirectJump;
                insn.Conditional = conditional;
                Through(ref insn, rva);
                if (insn.Flow == FlowKind.Jump && conditional) insn.Flow = FlowKind.ConditionalJump;
                Clobber();
                return;
            case ArmFlow.Return:
                insn.Flow = FlowKind.Return;
                insn.Conditional = conditional;
                Clobber();
                return;
            case ArmFlow.Trap:
                insn.Flow = FlowKind.Trap;
                return;
        }
        insn.Flow = FlowKind.Next;
        Track(ref insn, rva);
    }

    private void Invalid(uint rva, int length, out Insn insn)
    {
        insn = new Insn { Rva = rva, Length = length, Flow = FlowKind.Invalid };
        _last.Flow = ArmFlow.Invalid;
        Array.Clear(_kind);
        _ringCount = 0;
        _itLeft = 0;
    }

    private void Branch(ref Insn insn)
    {
        if (!_last.HasTarget || !TryRva(_last.Target, out uint target)) return;
        insn.HasTarget = true;
        insn.Target = target;
        LastSwitchesState = _last.TargetThumb != _thumb;
        LastIsComputed = false;
        if (insn.Flow is FlowKind.Call or FlowKind.Jump || LastSwitchesState) Modes.Hint(target, _last.TargetThumb);
    }

    /// <summary>The last direct branch or call lands in the other state (BLX, bx pc): its target is another function.</summary>
    public bool LastSwitchesState { get; private set; }

    /// <summary>The last branch target came from a register, a literal or a GOT slot (a veneer or stub): its target is another function.</summary>
    public bool LastIsComputed { get; private set; }

    /// <summary>The code at <paramref name="rva"/> is a Thumb-to-ARM stub ("bx pc"): a function of its own, never part of a caller.</summary>
    public bool IsStateSwitchStub(uint rva) =>
        _image.Read(rva, _scratch.AsSpan(0, 2)) == 2 && BinaryPrimitives.ReadUInt16LittleEndian(_scratch) == 0x4778 && Modes.At(rva);

    /// <summary>
    /// BX / BLX / a load into PC: through an import slot (an import call or jump), or to a code address a register or
    /// literal holds (a direct branch, the state from bit 0; "bx pc" switches to ARM at the next word).
    /// </summary>
    private void Through(ref Insn insn, uint rva)
    {
        var i = _last;
        uint? target = null;
        bool thumb = _thumb;
        if (i.Mnemonic is "bx" or "blx" && i.OperandCount == 1)
        {
            int r = i.Op(0).Reg;
            if (r == Pc && i.Thumb) { target = (_imageBase + rva + 4) & ~3u; thumb = false; }
            else if (_kind[r] == Known.ImportSlot) { Slot(ref insn, _value[r]); return; }
            else if (_kind[r] == Known.Address) { target = _value[r] & ~1u; thumb = (_value[r] & 1) != 0; }
        }
        else if (i.Mnemonic == "add" && i.OperandCount == 3 && i.Op(1).Kind == ArmOperandKind.Register && i.Op(2).Kind == ArmOperandKind.Register
                 && (i.Op(1).Reg == Pc) != (i.Op(2).Reg == Pc))
        {
            // add pc, rX, pc with a constant rX (a long-branch veneer): the state from bit 0
            int r = i.Op(1).Reg == Pc ? i.Op(2).Reg : i.Op(1).Reg;
            if (_kind[r] == Known.Constant)
            {
                uint value = _value[r] + PcValue(in i, literal: false);
                target = value & ~1u;
                thumb = (value & 1) != 0;
            }
        }
        else if (i.Loads && Memory(in i) is { } k && Effective(in i, k) is { } ea && TryRva(ea, out uint slot))
        {
            if (_importSlots.Contains(slot)) { Slot(ref insn, slot); return; }
            insn.HasMem = true;
            insn.MemTarget = slot;
            insn.MemAccess = OperandAccess.Read;
            if (Modes.LocalSlots.TryGetValue(slot, out uint local))
            {
                // a PLT stub of a function this image exports
                target = _imageBase + (local & ~1u);
                thumb = (local & 1) != 0;
            }
            // a veneer or literal branch: ldr pc, [pc, #x] with the target in the literal
            else if (i.Op(k).Reg == Pc && i.Op(k).Index == ArmOperand.NoReg && _image.Read(slot, _scratch) == 4)
            {
                uint value = BinaryPrimitives.ReadUInt32LittleEndian(_scratch);
                target = value & ~1u;
                thumb = (value & 1) != 0;
            }
        }
        if (target is not { } t || !TryRva(t, out uint to) || _code?.IsCode(to) == false) return;
        insn.Flow = insn.Flow == FlowKind.IndirectCall ? FlowKind.Call : FlowKind.Jump;
        insn.HasTarget = true;
        insn.Target = to;
        insn.HasMem = false;
        LastSwitchesState = thumb != _thumb;
        LastIsComputed = true;
        Modes.Hint(to, thumb);
    }

    private static void Slot(ref Insn insn, uint slot)
    {
        insn.HasMem = true;
        insn.MemTarget = slot;
        insn.MemAccess = OperandAccess.Read;
    }

    private static int? Memory(in ArmInstruction i)
    {
        for (int k = 0; k < i.OperandCount; k++)
            if (i.Operands[k].Kind == ArmOperandKind.Memory) return k;
        return null;
    }

    /// <summary>The value of the PC an instruction reads (<paramref name="literal"/>: word-aligned, as loads and ADR use it).</summary>
    private uint PcValue(in ArmInstruction i, bool literal) => i.Thumb ? (literal ? (i.Address + 4) & ~3u : i.Address + 4) : i.Address + 8;

    /// <summary>The address a memory operand reads or writes when its registers are known (base + offset, or base + index).</summary>
    private uint? Effective(in ArmInstruction i, int k)
    {
        var op = i.Operands[k];
        if (op.Reg != Pc && _kind[op.Reg] != Known.Address && op.Index == ArmOperand.NoReg) return null;
        if (RegisterValue(in i, op.Reg) is not { } b) return null;
        if (op.Indexing == ArmIndexing.PostIndex) return b;
        if (op.Index == ArmOperand.NoReg) return op.Subtract ? b - (uint)op.Value : b + (uint)op.Value;
        // base + index: one must be an address (a GOT base plus a slot offset, or a literal offset plus pc)
        if (op.Shift != ArmShift.None && op.Amount != 0 || op.Subtract || RegisterValue(in i, op.Index) is not { } x) return null;
        bool address = op.Reg == Pc || _kind[op.Reg] == Known.Address || _kind[op.Index] == Known.Address;
        return address ? b + x : null;
    }

    private uint? RegisterValue(in ArmInstruction i, int r) =>
        r == Pc ? PcValue(in i, literal: true) : _kind[r] is Known.Address or Known.Constant ? _value[r] : null;

    /// <summary>Address forming, memory references and register writes of a non-branch instruction.</summary>
    private void Track(ref Insn insn, uint rva)
    {
        var i = _last;
        bool conditional = i.IsConditional;
        if (Memory(in i) is { } k)
        {
            var op = i.Operands[k];
            uint? ea = Effective(in i, k);
            if (ea is { } a && TryRva(a, out uint at) && (i.Loads || i.Stores || i.Mnemonic.StartsWith("pl", StringComparison.Ordinal)))
            {
                insn.HasMem = true;
                insn.MemTarget = at;
                insn.MemAccess = i.Loads && i.Stores ? OperandAccess.ReadWrite : i.Stores ? OperandAccess.Write : OperandAccess.Read;
                if (i.Loads && !i.Stores && op.Index == ArmOperand.NoReg && _code?.IsCode(at) == true) LastLiteralSize = LoadSize(in i);
            }
            int dest = i.Loads && i.AccessSize == 4 && i.Mnemonic is "ldr" && i.Op(0).Kind == ArmOperandKind.Register ? i.Op(0).Reg : -1;
            Clobber();
            if (op.Indexing != ArmIndexing.Offset) Forget(op.Reg);
            if (dest >= 0 && !conditional && insn.HasMem) Loaded(ref insn, dest, insn.MemTarget);
            return;
        }
        int rd = i.OperandCount > 0 && i.Op(0).Kind == ArmOperandKind.Register && (i.Writes & (1 << i.Op(0).Reg)) != 0 ? i.Op(0).Reg : -1;
        Known kind = Known.None;
        uint value = 0;
        bool relocatedLow = false;
        switch (i.Mnemonic)
        {
            case "adr":
                kind = Known.Address;
                value = (uint)i.Op(1).Value;
                break;
            case "movw":
                kind = Known.Constant;
                value = (uint)i.Op(1).Value;
                relocatedLow = Modes.IsRelocatedMov32(rva) || TouchedByRelocation(rva, i.Length);
                break;
            case "movt" when rd >= 0 && _kind[rd] == Known.Constant:
                value = (_value[rd] & 0xFFFF) | (uint)i.Op(1).Value << 16;
                kind = _relocatedLow[rd] || FixedAddress && TryRva(value & ~1u, out _) ? Known.Address : Known.Constant;
                break;
            case "mov" when i.OperandCount == 2:
                (kind, value) = Operand(in i, 1);
                break;
            case "add" or "addw" or "sub" or "subw":
            {
                var (k1, v1) = i.OperandCount == 2 ? Operand(in i, 0) : Operand(in i, 1);
                var (k2, v2) = Operand(in i, i.OperandCount == 2 ? 1 : 2);
                bool add = i.Mnemonic.StartsWith("add", StringComparison.Ordinal);
                (kind, value) = (k1, k2) switch
                {
                    (Known.Address, Known.Constant) => (Known.Address, add ? v1 + v2 : v1 - v2),
                    (Known.Constant, Known.Address) when add => (Known.Address, v1 + v2),
                    (Known.Constant, Known.Constant) => (Known.Constant, add ? v1 + v2 : v1 - v2),
                    (Known.Address, Known.Address) when add && PcPlusLiteral(in i) => (Known.Address, v1 + v2),
                    _ => (Known.None, 0u),
                };
                break;
            }
        }
        Clobber();
        if (rd < 0 || rd == Pc || conditional) return;
        if (kind == Known.Address)
        {
            uint target = value;
            if (TryRva(value & ~1u, out uint code) && _code?.IsCode(code) == true)
            {
                if ((value & 1) != 0) HintThumb(code, confirmed: !FixedAddress);
                target = value & ~1u;
            }
            if (TryRva(target, out uint taken)) { insn.HasImm = true; insn.ImmTarget = taken; }
            SetAddress(rd, value);
        }
        else if (kind != Known.None) Set(rd, kind, value);
        _relocatedLow[rd] = relocatedLow;
    }

    /// <summary>An odd address names Thumb code; one no relocation confirms may be a constant that happens to be odd.</summary>
    private void HintThumb(uint code, bool confirmed)
    {
        if (confirmed) Modes.Hint(code, true);
        else Modes.HintUnconfirmed(code, true);
    }

    /// <summary>add rd, pc / add rd, rX, pc where the other register came from an unrelocated literal.</summary>
    private bool PcPlusLiteral(in ArmInstruction i)
    {
        int first = i.OperandCount == 2 ? 0 : 1;
        var a = i.Op(first);
        var b = i.Op(first + 1);
        return a.Kind == ArmOperandKind.Register && b.Kind == ArmOperandKind.Register
            && (a.Reg == Pc && _literal[b.Reg] || b.Reg == Pc && _literal[a.Reg]);
    }

    /// <summary>What operand <paramref name="k"/> holds: a constant, an address (the PC included) or nothing known.</summary>
    private (Known, uint) Operand(in ArmInstruction i, int k)
    {
        var op = i.Operands[k];
        return op.Kind switch
        {
            ArmOperandKind.Immediate => (Known.Constant, (uint)op.Value),
            ArmOperandKind.Register when op.Reg == Pc => (Known.Address, PcValue(in i, literal: false)),
            ArmOperandKind.Register when _kind[op.Reg] is Known.Address or Known.Constant => (_kind[op.Reg], _value[op.Reg]),
            _ => (Known.None, 0),
        };
    }

    /// <summary>
    /// The destination of a word load from <paramref name="slot"/>: an import slot; a relocated pointer (an address, also
    /// recorded as taken); a literal in code (a constant); otherwise unknown.
    /// </summary>
    private void Loaded(ref Insn insn, int dest, uint slot)
    {
        if (_importSlots.Contains(slot)) { Set(dest, Known.ImportSlot, slot); return; }
        if (Modes.LocalSlots.TryGetValue(slot, out uint local)) { Set(dest, Known.Address, _imageBase + local); return; }
        if (_image.Read(slot, _scratch) < 4) return;
        uint value = BinaryPrimitives.ReadUInt32LittleEndian(_scratch);
        if (Array.BinarySearch(_relocs, slot) >= 0 || FixedAddress && _code?.IsCode(slot) == true && TryRva(value & ~1u, out _))
        {
            if (!TryRva(value & ~1u, out uint target)) return;
            if (_code?.IsCode(target) == true && (value & 1) != 0) HintThumb(target, confirmed: Array.BinarySearch(_relocs, slot) >= 0);
            if (!insn.HasImm) { insn.HasImm = true; insn.ImmTarget = _code?.IsCode(target) == true ? target : value - _imageBase; }
            Set(dest, Known.Address, value);
            _literal[dest] = Array.BinarySearch(_relocs, slot) < 0;
            return;
        }
        if (_code?.IsCode(slot) == true) Set(dest, Known.Constant, value);
    }

    /// <summary>Registers the last instruction writes lose what they held; restores from the stack keep function-wide values.</summary>
    private void Clobber()
    {
        ushort writes = _last.Writes;
        bool restore = _last.Loads && (_last.Mnemonic is "pop" || Memory(in _last) is { } k && _last.Operands[k].Reg == Sp);
        for (int r = 0; r < 16; r++)
        {
            if ((writes & (1 << r)) == 0) continue;
            _kind[r] = Known.None;
            if (!restore && r != Sp) Forget(r);
        }
    }

    private void ClearCallerSaved()
    {
        for (int r = 0; r <= 3; r++) _kind[r] = Known.None;
        _kind[12] = _kind[Lr] = Known.None;
    }

    private void Set(int reg, Known kind, uint value)
    {
        if (reg is < 0 or >= Pc) return;
        _kind[reg] = kind;
        _value[reg] = value;
        _relocatedLow[reg] = false;
        _literal[reg] = false;
    }

    private void SetAddress(int reg, uint value)
    {
        Set(reg, Known.Address, value);
        if (reg is >= FirstSaved and <= LastSaved) Remember(reg, value);
    }

    private void Remember(int reg, uint value)
    {
        if (_savedState[reg] == 0) { _savedState[reg] = 1; _saved[reg] = value; }
        else if (_savedState[reg] == 1 && _saved[reg] != value) _savedState[reg] = 2;
    }

    private void Forget(int reg) => _savedState[reg] = 2;

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

    private bool TouchedByRelocation(uint rva, int length)
    {
        if (_relocs.Length == 0) return false;
        int i = Array.BinarySearch(_relocs, rva > 3 ? rva - 3 : 0);
        if (i < 0) i = ~i;
        return i < _relocs.Length && _relocs[i] < rva + (uint)length;
    }

    /// <summary>A fixed-address image (an ELF executable, or one without relocations) (a static executable): literal and MOVW / MOVT values inside it are addresses.</summary>
    private bool FixedAddress => _fixed ??= _image is Elf.ElfFile { Type: 2 } || _relocs.Length == 0 && _imageBase >= 0x1000 && _image.Format != ImageFormat.Pe;
    private bool? _fixed;

    public bool TryRva(uint va, out uint rva)
    {
        rva = va - _imageBase;
        return va >= _imageBase && rva < _sizeOfImage;
    }

    // ---------------------------------------------------------------- switches

    /// <summary>Instruction <paramref name="k"/> steps back in the current run (0 = the last one).</summary>
    private ref ArmInstruction Back(int k) => ref _ring[(_ringHead - 1 - k + RingSize * 2) % RingSize];

    private uint BackRva(int k) => _ringRva[(_ringHead - 1 - k + RingSize * 2) % RingSize];

    private static bool IsCall(in ArmInstruction i) => i.Flow is ArmFlow.Call or ArmFlow.IndirectCall;

    /// <summary>Step of the nearest instruction at or before step <paramref name="k"/> that writes <paramref name="reg"/>, or -1 (also at a call).</summary>
    private int Writer(int k, int reg)
    {
        for (; k < _ringCount; k++)
        {
            ref var x = ref Back(k);
            if (IsCall(in x)) return -1;
            if ((x.Writes & (1 << reg)) != 0) return k;
        }
        return -1;
    }

    /// <summary>The address <paramref name="reg"/> holds before step <paramref name="k"/>, formed in the run (ADR, ADD / SUB, MOV, MOVW / MOVT, PC-relative ADD of a literal).</summary>
    private uint? Constant(int k, int reg, int depth = 0)
    {
        if (reg == Pc) return null;
        int w = Writer(k, reg);
        if (w < 0) return reg is >= FirstSaved and <= LastSaved && _savedState[reg] == 1 ? _saved[reg] : null;
        if (depth > 6) return null;
        var x = Back(w);
        uint? Value(int operand)
        {
            var op = x.Operands[operand];
            return op.Kind switch
            {
                ArmOperandKind.Immediate => (uint)op.Value,
                ArmOperandKind.Register when op.Reg == Pc => PcValue(in x, literal: false),
                ArmOperandKind.Register => Constant(w + 1, op.Reg, depth + 1),
                _ => null,
            };
        }
        switch (x.Mnemonic)
        {
            case "adr": return (uint)x.Op(1).Value;
            case "mov" when x.OperandCount == 2: return Value(1);
            case "movw": return (uint)x.Op(1).Value;
            case "movt": return Constant(w + 1, reg, depth + 1) is { } low ? (low & 0xFFFF) | (uint)x.Op(1).Value << 16 : null;
            case "add" or "addw" or "sub" or "subw":
            {
                uint? a = x.OperandCount == 2 ? Constant(w + 1, x.Op(0).Reg, depth + 1) : Value(1);
                uint? b = Value(x.OperandCount == 2 ? 1 : 2);
                if (a == null || b == null) return null;
                return x.Mnemonic.StartsWith("add", StringComparison.Ordinal) ? a + b : a - b;
            }
            case "ldr" when Memory(in x) is { } m && x.Operands[m].Reg == Pc && x.Operands[m].Index == ArmOperand.NoReg:
            {
                uint at = x.Operands[m].Subtract ? PcValue(in x, true) - (uint)x.Operands[m].Value : PcValue(in x, true) + (uint)x.Operands[m].Value;
                return TryRva(at, out uint rva) && _image.Read(rva, _scratch) == 4 ? BinaryPrimitives.ReadUInt32LittleEndian(_scratch) : null;
            }
        }
        return null;
    }

    /// <summary>The shift n when <paramref name="reg"/> was set by lsr(s) reg, <paramref name="index"/>, #n at or before step <paramref name="k"/>, the index unchanged since; else null.</summary>
    private int? ShiftedFrom(int k, int reg, int index)
    {
        int w = Writer(k, reg);
        if (w < 0) return null;
        ref var x = ref Back(w);
        if (x.Mnemonic != "lsr" || x.OperandCount != 3 || x.Op(1).Kind != ArmOperandKind.Register || x.Op(1).Reg != index || x.Op(2).Kind != ArmOperandKind.Immediate) return null;
        for (int j = k; j < w; j++) if ((Back(j).Writes & (1 << index)) != 0) return null;
        return (int)x.Op(2).Value;
    }

    /// <summary>The instruction writing lr last in the run (the current one excluded) adds to an address: lr holds a computed target.</summary>
    private bool ComputedLr()
    {
        int w = Writer(1, Lr);
        if (w < 0) return false;
        ref var x = ref Back(w);
        return x.Mnemonic is "add" or "addw" && x.OperandCount == 3 && x.Op(1).Kind == ArmOperandKind.Register && Constant(w + 1, x.Op(1).Reg) is { } a && TryRva(a & ~1u, out uint rva) && _code?.IsCode(rva) == true;
    }

    private static bool IsCompare(in ArmInstruction i) => i.Mnemonic is "cmp" or "cmn" or "tst" or "teq" || i.WritesFlags;

    /// <summary>"cmp reg, #imm" (or against a register set by mov #imm) at step <paramref name="k"/>.</summary>
    private bool Compare(int k, out int reg, out ulong imm)
    {
        reg = -1;
        imm = 0;
        ref var x = ref Back(k);
        if (x.Mnemonic != "cmp" || x.OperandCount != 2 || x.Op(0).Kind != ArmOperandKind.Register) return false;
        reg = x.Op(0).Reg;
        var second = x.Op(1);
        if (second.Kind == ArmOperandKind.Immediate) { imm = (ulong)second.Value; return true; }
        if (second.Kind != ArmOperandKind.Register) return false;
        int w = Writer(k + 1, second.Reg);
        if (w < 0) return false;
        ref var set = ref Back(w);
        if (set.Mnemonic is not ("mov" or "movw") || set.OperandCount != 2 || set.Op(1).Kind != ArmOperandKind.Immediate) return false;
        imm = (ulong)set.Op(1).Value;
        return true;
    }

    /// <summary>The constant <paramref name="reg"/> was reduced by just before step <paramref name="k"/> (sub / add #imm), following copies.</summary>
    private long BiasBefore(int k, int reg)
    {
        for (int n = 0; k < _ringCount && n < 8; k++, n++)
        {
            ref var x = ref Back(k);
            if ((x.Writes & (1 << reg)) == 0) continue;
            int last = x.OperandCount - 1;
            if (x.Mnemonic is "sub" or "subw" or "add" or "addw" && last >= 1 && x.Op(last).Kind == ArmOperandKind.Immediate)
                return x.Mnemonic.StartsWith("sub", StringComparison.Ordinal) ? x.Op(last).Value : -x.Op(last).Value;
            if (x.Mnemonic == "mov" && x.OperandCount == 2 && x.Op(1).Kind == ArmOperandKind.Register) { reg = x.Op(1).Reg; continue; }
            return 0;
        }
        return 0;
    }

    private const uint Hs = 2, Lo = 3, Hi = 8, Ls = 9;

    private static uint? Condition(in ArmInstruction i) =>
        i.Flow == ArmFlow.Jump && i.Mnemonic == "b" && i.IsConditional ? i.Cond : null;

    public void ConditionalBounds(out IndexBound taken, out IndexBound fallThrough)
    {
        taken = fallThrough = IndexBound.None;
        if (_ringCount < 2 || Condition(in Back(0)) is not { } cc) return;
        int k = 1;
        while (k < _ringCount && !IsCompare(in Back(k))) k++;
        if (k >= _ringCount || !Compare(k, out int reg, out ulong imm) || imm >= uint.MaxValue) return;
        for (int j = k - 1; j > 0; j--) if ((Back(j).Writes & (1 << reg)) != 0) return;
        uint? target = Back(0).HasTarget && TryRva(Back(0).Target, out uint t) ? t : null;
        uint next = BackRva(0) + Back(0).Length;
        long bias = BiasBefore(k + 1, reg);
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
    /// The jump table dispatch ending at the last instruction: TBB / TBH [rn, rm] (targets pc + 2 × entry); a load into
    /// PC from [table, index, lsl #2] (absolute entries); ADD PC of a base and an entry loaded from such a table
    /// (base-relative entries); ADD PC, PC, index, lsl #2 (a run of branches); BX / MOV PC of a loaded entry. The index is
    /// bounded by cmp + b.hi / b.hs on the path, by the dispatch's own LS / LO condition, an and-mask or a bound carried
    /// into the run.
    /// </summary>
    public SwitchMatch? MatchSwitch(out string reason)
    {
        reason = SwitchMatch.NoDispatch;
        if (_ringCount == 0) return null;
        ref var j = ref Back(0);
        uint jumpRva = BackRva(0);
        if (j.Mnemonic is "tbb" or "tbh")
        {
            var op = j.Op(0);
            uint? table = op.Reg == Pc ? j.Address + 4 : Constant(1, op.Reg);
            if (table is not { } tv || !TryRva(tv, out uint tableRva)) { reason = "table base register is not known"; return null; }
            var m = Bound(0, op.Index, j.Mnemonic == "tbb" ? 1 : 2, tableRva, out reason);
            return m == null ? null : m with { Base = jumpRva + 4, Shift = 1, Signed = false };
        }
        if (j.Loads && j.WritesPc && j.Mnemonic == "ldr")
        {
            if (TableLoad(0, out uint table, out int index) is not true) { reason = "jump through a pointer loaded from memory (a function pointer or vtable slot)"; return null; }
            var m = Bound(0, index, 4, table, out reason);
            return m == null ? null : m with { Absolute = true };
        }
        if (j.Mnemonic == "add" && j.WritesPc)
        {
            // add pc, pc, index, lsl #2: a run of branches right after the dispatch
            if (j.OperandCount == 3 && j.Op(1).Kind == ArmOperandKind.Register && j.Op(1).Reg == Pc && j.Op(2).Kind == ArmOperandKind.ShiftedRegister
                && j.Op(2).Shift == ArmShift.Lsl && j.Op(2).Amount == 2 && j.Op(2).ShiftReg == ArmOperand.NoReg)
            {
                uint first = PcValue(in j, literal: false) - _imageBase;
                var m = Bound(0, j.Op(2).Reg, 4, first, out reason);
                return m == null ? null : m with { Base = first, Shift = 2, Direct = true };
            }
            int a = j.OperandCount == 2 ? Pc : j.Op(1).Kind == ArmOperandKind.Register ? j.Op(1).Reg : -1;
            int b = j.Op(j.OperandCount == 2 ? 1 : 2) is { Kind: ArmOperandKind.Register } rb ? rb.Reg : -1;
            if (a < 0 || b < 0) return null;
            foreach (var (baseReg, entryReg) in new[] { (a, b), (b, a) })
            {
                if (entryReg == Pc) continue;
                int lw = Writer(1, entryReg);
                if (lw < 0 || TableLoad(lw, out uint table, out int index) is not true) continue;
                uint? baseVa = baseReg == Pc ? PcValue(in j, literal: false) : Constant(1, baseReg);
                if (baseVa is not { } bv || !TryRva(bv, out uint baseRva)) continue;
                var m = Bound(lw, index, 4, table, out reason);
                return m == null ? null : m with { Base = baseRva, Shift = 0, Signed = true };
            }
            return null;
        }
        if (j.Mnemonic is "bx" or "mov" && j.OperandCount is 1 or 2)
        {
            int r = j.Op(j.OperandCount - 1).Reg;
            int lw = Writer(1, r);
            if (lw < 0) return null;
            if (TableLoad(lw, out uint table, out int index) is true)
            {
                var m = Bound(lw, index, 4, table, out reason);
                return m == null ? null : m with { Absolute = true };
            }
            var x = Back(lw);
            // adr rB, table; ldr rE, [rB, index, lsl #2]; add rT, rB, rE; bx rT: entries relative to a base
            if (x.Mnemonic == "add" && x.OperandCount is 2 or 3 && x.Op(x.OperandCount - 1).Kind == ArmOperandKind.Register && x.Op(x.OperandCount - 2).Kind == ArmOperandKind.Register)
            {
                int ra = x.Op(x.OperandCount - 2).Reg, rb = x.Op(x.OperandCount - 1).Reg;
                foreach (var (baseReg, entryReg) in new[] { (ra, rb), (rb, ra) })
                {
                    int ew = Writer(lw + 1, entryReg);
                    if (ew < 0 || TableLoad(ew, out uint rel, out int relIndex) is not true) continue;
                    if (Constant(lw + 1, baseReg) is not { } bv || !TryRva(bv & ~1u, out uint baseRva)) continue;
                    var m = Bound(ew, relIndex, 4, rel, out reason);
                    return m == null ? null : m with { Base = baseRva, Shift = 0, Signed = true };
                }
            }
            // adr rB, run; add rT, rB, index, lsl #2; mov pc, rT: a run of branches
            if (x.Mnemonic != "add" || x.OperandCount != 3 || x.Op(1).Kind != ArmOperandKind.Register || x.Op(2).Kind != ArmOperandKind.ShiftedRegister
                || x.Op(2).Shift != ArmShift.Lsl || x.Op(2).Amount != 2 || x.Op(2).ShiftReg != ArmOperand.NoReg) return null;
            uint? runVa = x.Op(1).Reg == Pc ? PcValue(in x, literal: false) : Constant(lw + 1, x.Op(1).Reg);
            if (runVa is not { } rv || !TryRva(rv & ~1u, out uint first)) return null;
            var direct = Bound(lw, x.Op(2).Reg, 4, first, out reason);
            return direct == null ? null : direct with { Base = first, Shift = 2, Direct = true };
        }
        return null;
    }

    /// <summary>The word load at step <paramref name="k"/> reads [table, index, lsl #2] with the table address known.</summary>
    private bool? TableLoad(int k, out uint tableRva, out int index)
    {
        tableRva = 0;
        index = -1;
        ref var x = ref Back(k);
        if (x.Mnemonic != "ldr" || Memory(in x) is not { } m) return null;
        var op = x.Operands[m];
        if (op.Index == ArmOperand.NoReg || op.Subtract || op.Indexing != ArmIndexing.Offset || !(op.Shift == ArmShift.Lsl && op.Amount == 2)) return false;
        uint? table = op.Reg == Pc ? PcValue(in x, literal: false) : Constant(k + 1, op.Reg);
        if (table is not { } t || !TryRva(t, out tableRva)) return false;
        index = op.Index;
        return true;
    }

    /// <summary>
    /// The bound of <paramref name="index"/> searched back from step <paramref name="from"/> (the dispatch's own condition
    /// first): a SwitchMatch for the table, or null with the reason.
    /// </summary>
    private SwitchMatch? Bound(int from, int index, int entrySize, uint tableRva, out string reason)
    {
        reason = "switch index bound not found";
        SwitchMatch Match(uint count) => new(tableRva, entrySize, false, false, count, null, 0, false);
        ref var dispatch = ref Back(0);
        uint? pending = dispatch.IsConditional && (uint)dispatch.Cond is Ls or Lo ? dispatch.Cond : null;
        uint? pendingDefault = pending != null ? BackRva(0) + dispatch.Length : null;
        bool own = pending != null;
        int current = index;
        for (int k = from + 1; k < _ringCount; k++)
        {
            ref var x = ref Back(k);
            if (IsCall(in x)) return null;
            if (!own && Condition(in x) is { } cc)
            {
                if (pending == null)
                {
                    pending = cc;
                    pendingDefault = x.HasTarget && TryRva(x.Target, out uint d) ? d : null;
                }
                continue;
            }
            if (pending is { } p && IsCompare(in x))
            {
                if (Compare(k, out int reg, out ulong imm) && reg == current && imm < uint.MaxValue)
                {
                    uint? count = p switch { Hi or Ls => (uint)imm + 1, Hs or Lo => (uint)imm, _ => null };
                    if (count != null) return Match(count.Value) with { Default = pendingDefault, Bias = BiasBefore(k + 1, current) };
                }
                // cmp of the index shifted right (lsrs rC, index, #n; cmp rC, #imm): the bound scales by 2^n
                else if (reg >= 0 && imm < 0x10000 && ShiftedFrom(k + 1, reg, current) is { } shift and > 0 and < 16)
                {
                    uint? count = p switch { Hi or Ls => (uint)(imm + 1) << shift, Hs or Lo => (uint)imm << shift, _ => null };
                    if (count != null) return Match(count.Value) with { Default = pendingDefault, Bias = BiasBefore(k + 1, current) };
                }
                pending = null;
                own = false;
            }
            if ((x.Writes & (1 << current)) == 0) continue;
            if (x.Mnemonic == "and" && x.OperandCount == 3 && x.Op(2).Kind == ArmOperandKind.Immediate && x.Op(2).Value is var mask and >= 0 and < 1 << 20 && (mask & (mask + 1)) == 0)
                return Match((uint)mask + 1) with { BoundByMask = true };
            if (x.Mnemonic is "uxtb" && x.OperandCount == 2) return Match(256) with { BoundByMask = true };
            if (x.Mnemonic == "mov" && x.OperandCount == 2 && x.Op(1).Kind == ArmOperandKind.Register) { current = x.Op(1).Reg; continue; }
            return null;
        }
        if (_runBound.Reg == current + 1)
            return Match(_runBound.Count) with { Default = _runBound.Default, Bias = _runBound.Bias };
        if (pending is Hi or Hs && _runBound.FlagsReg == current + 1 && _runBound.FlagsImm < uint.MaxValue)
            return Match(pending == Hi ? (uint)_runBound.FlagsImm + 1 : (uint)_runBound.FlagsImm) with { Default = pendingDefault, Bias = _runBound.Bias };
        return null;
    }

    // ---------------------------------------------------------------- heuristics

    /// <summary>System and coprocessor instructions user code does not contain (TLS reads through p15 excepted).</summary>
    public bool LastIsImplausible(bool strict = true) =>
        strict && (_last.Mnemonic is "smc" or "hvc" or "eret" or "rfedb" or "rfeia" or "srsdb" or "srsia" or "cps" or "cpsid" or "cpsie" or "setend"
            or "bxj" or "cdp" or "ldc" or "stc" or "mcrr" or "mrrc" or "subs" && _last.WritesPc
            || _last.Mnemonic is "mcr" or "mrc" && _last.Op(0).Text != "p15"
            || _last.Mnemonic is "msr" or "mrs" && _last.Op(_last.Mnemonic == "msr" ? 0 : 1).Text == "spsr");

    public bool LastHasImplausibleDisplacement(uint rva) => false;

    /// <summary>
    /// A few address-forming instructions ending in a jump through an import slot: ELF PLT entries (add ip, pc, #..;
    /// add ip, ip, #..; ldr pc, [ip, #..]!), their Thumb entry (bx pc; nop), long PLT entries (movw / movt / add pc),
    /// Windows import thunks (movw / movt r12; ldr.w pc, [r12]).
    /// </summary>
    public uint? ThunkSlot(uint rva, Func<uint, bool> isImportSlot)
    {
        bool pinned = _pinned, thumb = _thumb;
        try
        {
            BeginRun(IndexBound.None);
            Pin(Modes.StartMode(rva));
            for (int n = 0; n < 6; n++)
            {
                if (!Decode(rva, out var insn)) return null;
                if (n == 0 && _thumb && _last.Raw == 0x4778)
                {
                    // bx pc; nop: the ARM entry follows
                    rva = (rva + 4) & ~3u;
                    Pin(false);
                    continue;
                }
                if (insn.Flow is FlowKind.IndirectJump or FlowKind.Jump) return insn.HasMem && isImportSlot(insn.MemTarget) ? insn.MemTarget : null;
                if (insn.Flow != FlowKind.Next || _last.Mnemonic is not ("add" or "adr" or "ldr" or "mov" or "movw" or "movt" or "nop" or "addw")) return null;
                rva = insn.Next;
            }
            return null;
        }
        finally
        {
            _pinned = pinned;
            _thumb = thumb;
        }
    }

    /// <summary>Zero fill, nop, mov r8, r8 and ARM nop encodings between functions.</summary>
    public bool IsPadding(ImageCode.Region region, uint rva)
    {
        int at = (int)(rva - region.Rva);
        if (at + 2 > region.Bytes.Length) return true;
        ushort h = BinaryPrimitives.ReadUInt16LittleEndian(region.Bytes.AsSpan(at));
        if (h == 0 && (at + 4 > region.Bytes.Length || BinaryPrimitives.ReadUInt16LittleEndian(region.Bytes.AsSpan(at + 2)) == 0)) return true;
        if (Modes.At(rva)) return h is 0xBF00 or 0x46C0;
        if (at + 4 > region.Bytes.Length) return true;
        uint w = BinaryPrimitives.ReadUInt32LittleEndian(region.Bytes.AsSpan(at));
        return w is 0 or 0xE1A00000 or 0xE320F000;
    }
}
