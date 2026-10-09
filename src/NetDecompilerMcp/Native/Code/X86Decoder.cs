using Iced.Intel;

namespace NetDecompilerMcp.Native.Code;

/// <summary>
/// An index known to be below <see cref="Count"/> (unsigned) on some path: a register, or with
/// <see cref="SlotBase"/> set the frame slot [SlotBase + SlotDisp].
/// </summary>
internal readonly record struct IndexBound(Register Reg, uint Count, Register SlotBase = Register.None, ulong SlotDisp = 0)
{
    public static readonly IndexBound None = new(Register.None, 0);
    public bool IsKnown => Reg != Register.None || SlotBase != Register.None;
}

/// <summary>Facts of one decoded instruction, in the form the analysis loops use. Addresses are RVAs.</summary>
internal struct Insn
{
    public uint Rva;
    public int Length;
    public FlowKind Flow;
    public bool HasTarget;
    /// <summary>Direct branch / call target.</summary>
    public uint Target;
    public bool HasMem;
    public uint MemTarget;
    public bool MemRip;
    public OperandAccess MemAccess;
    public bool HasImm;
    public uint ImmTarget;
    public uint Next => Rva + (uint)Length;
}

/// <summary>
/// x86 / x64 decoding over the code of an image (Iced). Keeps the last instructions of the current linear run so
/// switch dispatch sequences can be matched. One instance per thread.
/// </summary>
internal sealed class X86Decoder
{
    private sealed class Reader : CodeReader
    {
        public byte[] Data = [];
        public int Pos, End;
        public override int ReadByte() => Pos < End ? Data[Pos++] : -1;
    }

    private const int RingSize = 32;

    private readonly ImageCode? _code;
    private readonly INativeImage _image;
    private readonly byte[] _scratch = new byte[16];
    private readonly ulong _imageBase;
    private readonly uint _sizeOfImage;
    private readonly uint[] _relocs;
    private readonly bool _is64;
    private readonly Reader _reader = new();
    private readonly Decoder _decoder;
    private readonly InstructionInfoFactory _info = new();
    private readonly Instruction[] _ring = new Instruction[RingSize];
    private int _ringHead, _ringCount;
    private IndexBound _runBound;
    private Instruction _last;

    public X86Decoder(ImageCode code, uint[] sortedRelocations) : this(code.Image, code, sortedRelocations) { }

    /// <param name="code">Executable code for <see cref="Decode"/>; null when only <see cref="DecodeMapped"/> is used.</param>
    public X86Decoder(INativeImage image, ImageCode? code, uint[] sortedRelocations)
    {
        _image = image;
        _code = code;
        _imageBase = image.ImageBase;
        _sizeOfImage = image.SizeOfImage;
        _relocs = sortedRelocations;
        _is64 = image.Arch == NativeArch.X64;
        _decoder = Decoder.Create(_is64 ? 64 : 32, _reader, _imageBase, DecoderOptions.None);
    }

    public bool Is64 => _is64;
    /// <summary>Tell reads from writes of memory operands (costs an instruction info lookup); otherwise only lea is told apart.</summary>
    public bool ComputeAccess { get; set; } = true;
    /// <summary>Treat instructions user-mode compiled code never contains (<see cref="LastIsImplausible"/>) as invalid.</summary>
    public bool RejectImplausible { get; set; }
    /// <summary>
    /// Treat an instruction as invalid when a base relocation touches it anywhere but its displacement or immediate:
    /// the loader patches only pointer-sized operands, so such bytes are data (pointer tables), not code.
    /// </summary>
    public bool CheckRelocations { get; set; }

    private bool RelocationsFit(uint rva, int length)
    {
        if (_relocs.Length == 0) return true;
        int size = _is64 ? 8 : 4;
        int i = Array.BinarySearch(_relocs, rva);
        if (i < 0) i = ~i;
        if (i > 0 && _relocs[i - 1] + (uint)size > rva) return false; // a pointer that overlaps the first bytes
        if (i >= _relocs.Length || _relocs[i] >= rva + (uint)length) return true;
        var o = _decoder.GetConstantOffsets(in _last);
        for (; i < _relocs.Length && _relocs[i] < rva + (uint)length; i++)
        {
            uint at = _relocs[i] - rva;
            bool fits = (o.HasDisplacement && o.DisplacementOffset == at && o.DisplacementSize == size)
                || (o.HasImmediate && o.ImmediateOffset == at && o.ImmediateSize == size);
            if (!fits) return false;
        }
        return true;
    }
    public bool HasRelocations => _relocs.Length > 0;
    /// <summary>The last decoded instruction.</summary>
    public ref readonly Instruction Last => ref _last;

    /// <summary>Starts a new linear run; <paramref name="incoming"/> is a bound known on entry.</summary>
    public void BeginRun(IndexBound incoming)
    {
        _ringCount = 0;
        _runBound = incoming;
    }

    /// <summary>Decodes the instruction at <paramref name="rva"/>; false when the address is not in executable code.</summary>
    public bool Decode(uint rva, out Insn insn)
    {
        var region = _code?.RegionAt(rva);
        if (region == null) { insn = default; return false; }
        DecodeFrom(region.Bytes, (int)(rva - region.Rva), region.Bytes.Length, rva, out insn);
        return true;
    }

    /// <summary>Decodes at <paramref name="rva"/>, which the caller knows is inside <paramref name="region"/>.</summary>
    public void Decode(ImageCode.Region region, uint rva, out Insn insn) =>
        DecodeFrom(region.Bytes, (int)(rva - region.Rva), region.Bytes.Length, rva, out insn);

    /// <summary>Decodes at any mapped address (data included); false when nothing is mapped there.</summary>
    public bool DecodeMapped(uint rva, out Insn insn)
    {
        int n = _image.Read(rva, _scratch);
        if (n == 0) { insn = default; return false; }
        DecodeFrom(_scratch, 0, n, rva, out insn);
        return true;
    }

    private void DecodeFrom(byte[] data, int pos, int end, uint rva, out Insn insn)
    {
        insn = default;
        _reader.Data = data;
        _reader.Pos = pos;
        _reader.End = end;
        _decoder.IP = _imageBase + rva;
        _decoder.Decode(out _last);
        insn.Rva = rva;
        insn.Length = _last.Length;
        ref readonly var i = ref _last;
        if (i.IsInvalid || IsZeroPadding(data, pos, end, i.Length) || (RejectImplausible && LastIsImplausible(strict: false))
            || (CheckRelocations && !RelocationsFit(rva, i.Length)))
        {
            insn.Flow = FlowKind.Invalid;
            insn.Length = Math.Max(1, i.Length);
            _ringCount = 0;
            return;
        }
        _ring[_ringHead] = i;
        _ringHead = (_ringHead + 1) % RingSize;
        if (_ringCount < RingSize) _ringCount++;

        switch (i.FlowControl)
        {
            case FlowControl.UnconditionalBranch:
                insn.Flow = IsNear(i.Op0Kind) ? FlowKind.Jump : FlowKind.IndirectJump;
                break;
            case FlowControl.IndirectBranch:
                insn.Flow = FlowKind.IndirectJump;
                break;
            case FlowControl.ConditionalBranch:
                insn.Flow = FlowKind.ConditionalJump;
                break;
            case FlowControl.Call:
                insn.Flow = IsNear(i.Op0Kind) ? FlowKind.Call : FlowKind.IndirectCall;
                break;
            case FlowControl.IndirectCall:
                insn.Flow = FlowKind.IndirectCall;
                break;
            case FlowControl.Return:
                insn.Flow = FlowKind.Return;
                break;
            case FlowControl.Exception:
                insn.Flow = FlowKind.Trap;
                break;
            case FlowControl.Interrupt:
                insn.Flow = i.Mnemonic == Mnemonic.Int3 || (i.Mnemonic == Mnemonic.Int && i.Immediate8 == 0x29) ? FlowKind.Trap : FlowKind.Next;
                break;
            default:
                insn.Flow = i.Mnemonic is Mnemonic.Hlt or Mnemonic.Ud0 or Mnemonic.Ud1 or Mnemonic.Ud2 ? FlowKind.Trap : FlowKind.Next;
                break;
        }
        if (insn.Flow is FlowKind.Jump or FlowKind.Call or FlowKind.ConditionalJump && IsNear(i.Op0Kind))
            insn.HasTarget = TryRva(i.NearBranchTarget, out insn.Target);

        bool hasMemory = false, hasImmediate = false;
        for (int k = 0; k < i.OpCount; k++)
        {
            var kind = i.GetOpKind(k);
            if (kind == OpKind.Memory) hasMemory = true;
            else if (kind is OpKind.Immediate32 or OpKind.Immediate64) hasImmediate = true;
        }
        if (hasMemory) ResolveMemory(in i, ref insn);
        if (hasImmediate) ResolveImmediate(in i, ref insn);
    }

    /// <summary>
    /// The last instruction is one compilers do not emit in user-mode code (port I/O, BCD arithmetic, segment
    /// loads, privileged state, ds/es/ss/cs overrides; with <paramref name="strict"/> also far transfers and iret,
    /// which system code such as WoW64 transitions and context restore does use): decoding it means the bytes are data.
    /// </summary>
    public bool LastIsImplausible(bool strict = true)
    {
        ref readonly var i = ref _last;
        // segment overrides on data accesses (not on nops, which pad with cs:, nor on branches, where 3E is notrack)
        if (i.SegmentPrefix is Register.ES or Register.CS or Register.SS or Register.DS
            && i.Mnemonic != Mnemonic.Nop && i.FlowControl == FlowControl.Next) return true;
        if (strict)
        {
            for (int k = 0; k < i.OpCount; k++)
                if (i.GetOpKind(k) is OpKind.FarBranch16 or OpKind.FarBranch32) return true;
            if (i.MemorySize is MemorySize.SegPtr16 or MemorySize.SegPtr32 or MemorySize.SegPtr64) return true;
            if (i.Mnemonic is Mnemonic.Iret or Mnemonic.Iretd or Mnemonic.Iretq or Mnemonic.Retf) return true;
        }
        // "00 00": add [eax], al
        if (i.Code == Iced.Intel.Code.Add_rm8_r8 && i.Op0Kind == OpKind.Memory && i.MemoryBase is Register.EAX or Register.RAX
            && i.MemoryIndex == Register.None && i.MemoryDisplacement64 == 0 && i.Op1Register == Register.AL) return true;
        return i.Mnemonic is Mnemonic.In or Mnemonic.Out or Mnemonic.Insb or Mnemonic.Insw or Mnemonic.Insd
            or Mnemonic.Outsb or Mnemonic.Outsw or Mnemonic.Outsd or Mnemonic.Hlt or Mnemonic.Cli or Mnemonic.Sti
            or Mnemonic.Arpl or Mnemonic.Bound or Mnemonic.Les
            or Mnemonic.Lds or Mnemonic.Lss or Mnemonic.Lfs or Mnemonic.Lgs or Mnemonic.Into or Mnemonic.Aaa
            or Mnemonic.Aas or Mnemonic.Daa or Mnemonic.Das or Mnemonic.Aam or Mnemonic.Aad or Mnemonic.Salc
            or Mnemonic.Xlatb or Mnemonic.Int1 or Mnemonic.Sldt or Mnemonic.Lldt or Mnemonic.Lgdt
            or Mnemonic.Lidt or Mnemonic.Ltr or Mnemonic.Clts or Mnemonic.Invd or Mnemonic.Wbinvd or Mnemonic.Rdmsr
            or Mnemonic.Wrmsr or Mnemonic.Sysexit or Mnemonic.Sysret;
    }

    /// <summary>
    /// The last instruction has a 32-bit displacement compiled code would not produce: large, not covered by a
    /// relocation, not an RVA (x64 __ImageBase-relative tables) and not the fixed shared user data page.
    /// </summary>
    public bool LastHasImplausibleDisplacement(uint rva)
    {
        ref readonly var i = ref _last;
        if (i.MemoryDisplSize < 4 || i.IsIPRelativeMemoryOperand) return false;
        bool memory = false;
        for (int k = 0; k < i.OpCount; k++) memory |= i.GetOpKind(k) == OpKind.Memory;
        if (!memory) return false;
        long disp = (int)(uint)i.MemoryDisplacement64;
        if (disp is > -0x10000 and < 0x10000) return false;
        if (disp is >= 0x7FFE0000 and < 0x7FFF0000) return false;
        if (_is64 && disp >= 0 && disp < _sizeOfImage) return false;
        var offsets = _decoder.GetConstantOffsets(in i);
        return !(offsets.HasDisplacement && IsRelocated(rva + offsets.DisplacementOffset));
    }

    /// <summary>
    /// The instruction before the last one sets the x86 SEH state [ebp-4] to -1 / -2 (leaving the guarded
    /// block): the call that follows runs the __finally block.
    /// </summary>
    public bool PreviousLeavesSehScope()
    {
        if (_is64 || _ringCount < 2) return false;
        ref var x = ref Back(1);
        return x.Mnemonic == Mnemonic.Mov && x.Op0Kind == OpKind.Memory && x.MemoryBase == Register.EBP && x.MemoryIndex == Register.None
            && (int)(uint)x.MemoryDisplacement64 == -4 && x.Op1Kind is OpKind.Immediate32 or OpKind.Immediate8to32
            && (int)x.GetImmediate(1) is -1 or -2;
    }

    private static bool IsNear(OpKind kind) => kind is OpKind.NearBranch16 or OpKind.NearBranch32 or OpKind.NearBranch64;

    /// <summary>"00 00 00 00": zero fill decodes as add [rax], al twice; never treated as code.</summary>
    private static bool IsZeroPadding(byte[] data, int pos, int end, int length) =>
        length == 2 && pos + 4 <= end && BitConverter.ToUInt32(data, pos) == 0;

    public bool TryRva(ulong va, out uint rva)
    {
        rva = 0;
        if (!_is64) va &= 0xFFFFFFFF;
        if (va < _imageBase || va - _imageBase >= _sizeOfImage) return false;
        rva = (uint)(va - _imageBase);
        return true;
    }

    public bool IsRelocated(uint rva) => Array.BinarySearch(_relocs, rva) >= 0;

    private void ResolveMemory(in Instruction i, ref Insn insn)
    {
        uint target;
        if (i.IsIPRelativeMemoryOperand)
        {
            if (!TryRva(i.IPRelativeMemoryAddress, out target)) return;
            insn.MemRip = true;
        }
        else
        {
            if (i.MemoryDisplSize < 4) return;
            if (!TryRva(i.MemoryDisplacement64, out target)) return;
            if (HasRelocations)
            {
                var offsets = _decoder.GetConstantOffsets(in i);
                if (!offsets.HasDisplacement || !IsRelocated(insn.Rva + offsets.DisplacementOffset)) return;
            }
            else if (_is64 || i.MemoryBase != Register.None || _image.SectionAt(target) == null)
                return;
        }
        insn.HasMem = true;
        insn.MemTarget = target;
        insn.MemAccess = i.Mnemonic == Mnemonic.Lea ? OperandAccess.Address : ComputeAccess ? MemoryAccess(in i) : OperandAccess.Read;
    }

    private OperandAccess MemoryAccess(in Instruction i)
    {
        var info = _info.GetInfo(in i, InstructionInfoOptions.NoRegisterUsage);
        foreach (var m in info.GetUsedMemory())
        {
            // skip the implicit stack access of push [mem] / pop [mem]
            if (m.Base is Register.RSP or Register.ESP && i.MemoryBase is not (Register.RSP or Register.ESP)) continue;
            return m.Access switch
            {
                OpAccess.Read or OpAccess.CondRead => OperandAccess.Read,
                OpAccess.Write or OpAccess.CondWrite => OperandAccess.Write,
                OpAccess.ReadWrite or OpAccess.ReadCondWrite => OperandAccess.ReadWrite,
                OpAccess.NoMemAccess => OperandAccess.Address,
                _ => OperandAccess.Read,
            };
        }
        return OperandAccess.Read;
    }

    private void ResolveImmediate(in Instruction i, ref Insn insn)
    {
        for (int k = 0; k < i.OpCount; k++)
        {
            var kind = i.GetOpKind(k);
            if (kind is not (OpKind.Immediate32 or OpKind.Immediate64)) continue;
            if (kind == OpKind.Immediate32 && _is64) continue;
            if (!TryRva(i.GetImmediate(k), out uint target)) return;
            if (HasRelocations)
            {
                var offsets = _decoder.GetConstantOffsets(in i);
                if (!offsets.HasImmediate || !IsRelocated(insn.Rva + offsets.ImmediateOffset)) return;
            }
            else if (_is64 || i.Mnemonic is not (Mnemonic.Push or Mnemonic.Mov) || _image.SectionAt(target) == null)
                return;
            insn.HasImm = true;
            insn.ImmTarget = target;
            return;
        }
    }

    /// <summary>Instruction <paramref name="k"/> steps back in the current run (0 = the last one).</summary>
    private ref Instruction Back(int k) => ref _ring[(_ringHead - 1 - k + RingSize * 2) % RingSize];

    /// <summary>
    /// After a conditional jump (the last instruction): the bounds that hold on its taken and fall-through paths,
    /// from a preceding "cmp reg, imm".
    /// </summary>
    public void ConditionalBounds(out IndexBound taken, out IndexBound fallThrough)
    {
        taken = fallThrough = IndexBound.None;
        if (_ringCount < 2) return;
        var cc = Back(0).ConditionCode;
        if (cc is not (ConditionCode.a or ConditionCode.ae or ConditionCode.be or ConditionCode.b)) return;
        ulong imm;
        IndexBound Make(uint n)
        {
            if (TryCompare(1, 0, out var reg, out _)) return new(reg, n);
            ref var c = ref Back(1);
            return new(Register.None, n, c.MemoryBase.GetFullRegister(), c.MemoryDisplacement64);
        }
        if (TryCompare(1, 0, out _, out imm)) { }
        else if (Back(1) is { Mnemonic: Mnemonic.Cmp, Op0Kind: OpKind.Memory, MemoryIndex: Register.None } c
                 && c.MemoryBase is Register.EBP or Register.RBP && CompareImmediate(in c, out imm)) { }
        else return;
        if (imm >= uint.MaxValue) return;
        switch (cc)
        {
            case ConditionCode.a: fallThrough = Make((uint)imm + 1); break;
            case ConditionCode.ae: fallThrough = Make((uint)imm); break;
            case ConditionCode.be: taken = Make((uint)imm + 1); break;
            case ConditionCode.b: taken = Make((uint)imm); break;
        }
    }

    /// <summary>
    /// The flags-setting instruction at or before step <paramref name="k"/> is "cmp reg, imm", and reg is unchanged up to
    /// the conditional jump at step <paramref name="jcc"/>.
    /// </summary>
    private bool TryCompare(int k, int jcc, out Register reg, out ulong imm)
    {
        reg = Register.None;
        imm = 0;
        for (; k < _ringCount; k++)
        {
            ref var x = ref Back(k);
            if (x.RflagsModified == RflagsBits.None) continue;
            if (x.Mnemonic != Mnemonic.Cmp || x.Op0Kind != OpKind.Register) return false;
            if (x.Op1Kind == OpKind.Register)
            {
                // cmp reg, reg2 with reg2 loaded by "mov reg2, imm" or "push imm; pop reg2"
                int w = FindWriter(k + 1, x.Op1Register.GetFullRegister());
                if (w < 0) return false;
                ref var set = ref Back(w);
                if (set.Mnemonic == Mnemonic.Mov && set.Op1Kind is OpKind.Immediate32 or OpKind.Immediate32to64 or OpKind.Immediate64)
                    imm = set.GetImmediate(1);
                else if (set.Mnemonic == Mnemonic.Pop && PushedImmediate(w + 1) is { } pushed)
                    imm = pushed;
                else return false;
                if ((long)imm < 0) return false;
            }
            else if (!CompareImmediate(in x, out imm)) return false;
            reg = x.Op0Register.GetFullRegister();
            for (int j = k - 1; j > jcc; j--)
                if (WritesRegister(in Back(j), reg)) return false;
            return true;
        }
        return false;
    }

    /// <summary>Operand 0 is the frame slot [base + disp] (no index).</summary>
    private static bool IsSlot(in Instruction x, Register slotBase, ulong slotDisp) =>
        x.Op0Kind == OpKind.Memory && x.MemoryBase.GetFullRegister() == slotBase && x.MemoryIndex == Register.None && x.MemoryDisplacement64 == slotDisp;

    /// <summary>Operand 1 of a compare is a non-negative immediate.</summary>
    private static bool CompareImmediate(in Instruction x, out ulong imm)
    {
        imm = 0;
        if (x.Op1Kind is not (OpKind.Immediate8 or OpKind.Immediate8to16 or OpKind.Immediate8to32 or OpKind.Immediate8to64
            or OpKind.Immediate16 or OpKind.Immediate32 or OpKind.Immediate32to64)) return false;
        imm = x.GetImmediate(1);
        return !(x.Op1Kind is OpKind.Immediate8to32 or OpKind.Immediate8to64 or OpKind.Immediate32to64 && (long)imm < 0);
    }

    /// <summary>The immediate of the "push imm" matching a pop just after step <paramref name="k"/>, with no other stack change between.</summary>
    private ulong? PushedImmediate(int k)
    {
        for (int n = 0; k < _ringCount && n < 8; k++, n++)
        {
            ref var x = ref Back(k);
            if (x.Mnemonic == Mnemonic.Push)
                return x.Op0Kind is OpKind.Immediate8to32 or OpKind.Immediate32 or OpKind.Immediate8to64 or OpKind.Immediate32to64 ? x.GetImmediate(0) : null;
            if (x.Mnemonic == Mnemonic.Pop || x.FlowControl != FlowControl.Next || x.StackPointerIncrement != 0
                || (x.Op0Kind == OpKind.Register && x.Op0Register.GetFullRegister() == Register.RSP))
                return null;
        }
        return null;
    }

    private static bool WritesRegister(in Instruction x, Register full) =>
        x.Op0Kind == OpKind.Register && x.Op0Register.GetFullRegister() == full
        && x.Mnemonic is not (Mnemonic.Cmp or Mnemonic.Test or Mnemonic.Push or Mnemonic.Bt);

    /// <summary>
    /// A switch dispatch matched at the last instruction (an indirect jump). <see cref="BaseAssumed"/>: a register
    /// used as __ImageBase is set outside the run (hoisted by the compiler); the caller must confirm the table by
    /// requiring every target inside the function's own .pdata ranges.
    /// </summary>
    internal sealed record SwitchMatch(uint TableRva, int EntrySize, bool Absolute, bool RelativeToTable, uint Count, uint? IndexTableRva, uint IndexTableCount, bool BaseAssumed);

    /// <summary>
    /// Matches the instructions before the last one (an indirect jump) against the switch dispatch sequences:
    /// x64 MSVC "lea rB, __ImageBase; mov eT, [rB + rI*4 + table]; add rT, rB; jmp rT",
    /// x64 relative "lea rB, table; movsxd rT, [rB + rI*4]; add rT, rB; jmp rT",
    /// x86 "jmp [rI*4 + table]" / "mov rT, [rI*4 + table]; jmp rT",
    /// each bounded by "cmp rI, n; ja" on the path (optionally through a byte index table).
    /// Returns null (with a reason) when the dispatch or its bound is not recognized.
    /// </summary>
    public SwitchMatch? MatchSwitch(out string reason)
    {
        reason = "no recognized table dispatch";
        if (_ringCount == 0) return null;
        ref var jmp = ref Back(0);
        Register index;
        uint table;
        bool absolute = false, relative = false, baseAssumed = false;
        int k;
        if (jmp.Op0Kind == OpKind.Memory)
        {
            if (_is64 || jmp.MemoryBase != Register.None || jmp.MemoryIndex == Register.None || jmp.MemoryIndexScale != 4) return null;
            if (!TryRva(jmp.MemoryDisplacement64, out table)) return null;
            index = jmp.MemoryIndex.GetFullRegister();
            absolute = true;
            k = 1;
        }
        else if (jmp.Op0Kind == OpKind.Register)
        {
            var t = jmp.Op0Register.GetFullRegister();
            k = FindWriter(1, t);
            if (k < 0) return null;
            ref var w = ref Back(k);
            if (_is64 && w.Mnemonic == Mnemonic.Add && w.Op1Kind == OpKind.Register)
            {
                var b = w.Op1Register.GetFullRegister();
                int l = FindWriter(k + 1, t);
                if (l < 0) return null;
                ref var load = ref Back(l);
                if (load.Mnemonic is not (Mnemonic.Mov or Mnemonic.Movsxd) || load.Op1Kind != OpKind.Memory) return null;
                if (load.MemoryIndex == Register.None || load.MemoryIndexScale != 4 || load.MemoryBase == Register.None) return null;
                var loadBase = load.MemoryBase.GetFullRegister();
                var addBase = BaseOf(k + 1, b, out uint addRva);
                if (addBase == BaseKind.Table && load.MemoryDisplacement64 == 0 && load.Mnemonic == Mnemonic.Movsxd
                    && loadBase == b && FindWriter(k + 1, b) > l)
                {
                    // entries are offsets from the table itself
                    table = addRva;
                    relative = true;
                }
                else if (addBase is BaseKind.ImageBase or BaseKind.Unknown && load.MemoryDisplacement64 is > 0 and < uint.MaxValue)
                {
                    // entries are RVAs: [__ImageBase + index*4 + table RVA]
                    var lb = BaseOf(l + 1, loadBase, out _);
                    if (lb is not (BaseKind.ImageBase or BaseKind.Unknown)) return null;
                    table = (uint)load.MemoryDisplacement64;
                    baseAssumed = addBase == BaseKind.Unknown || lb == BaseKind.Unknown;
                }
                else return null;
                index = load.MemoryIndex.GetFullRegister();
                k = l + 1;
            }
            else if (!_is64 && w.Mnemonic == Mnemonic.Mov && w.Op1Kind == OpKind.Memory && w.MemoryBase == Register.None
                     && w.MemoryIndex != Register.None && w.MemoryIndexScale == 4 && TryRva(w.MemoryDisplacement64, out table))
            {
                index = w.MemoryIndex.GetFullRegister();
                absolute = true;
                k++;
            }
            else return null;
        }
        else return null;

        if (!TryFindBound(k, index, ref baseAssumed, out uint count, out uint? indexTable, out reason)) return null;
        if (indexTable is { } it)
            return new SwitchMatch(table, 4, absolute, relative, 0, it, count, baseAssumed);
        return new SwitchMatch(table, 4, absolute, relative, count, null, 0, baseAssumed);
    }

    private enum BaseKind { ImageBase, Table, Unknown, Other }

    /// <summary>
    /// What <paramref name="reg"/> holds at step <paramref name="k"/>: __ImageBase or a table (set by "lea reg, [rip+x]"
    /// in the run), unknown (no write in the run), or something else.
    /// </summary>
    private BaseKind BaseOf(int k, Register reg, out uint rva)
    {
        rva = 0;
        for (; k < _ringCount; k++)
        {
            ref var x = ref Back(k);
            if (!WritesRegister(in x, reg)) continue;
            if (x.Mnemonic != Mnemonic.Lea || !x.IsIPRelativeMemoryOperand) return BaseKind.Other;
            ulong va = x.IPRelativeMemoryAddress;
            if (va == _imageBase) return BaseKind.ImageBase;
            return TryRva(va, out rva) ? BaseKind.Table : BaseKind.Other;
        }
        return BaseKind.Unknown;
    }

    /// <summary>Step of the nearest instruction at or before step <paramref name="k"/> that writes <paramref name="reg"/>, or -1.</summary>
    private int FindWriter(int k, Register reg)
    {
        for (; k < _ringCount; k++)
        {
            ref var x = ref Back(k);
            if (x.FlowControl is FlowControl.Call or FlowControl.IndirectCall) return -1;
            if (WritesRegister(in x, reg)) return k;
        }
        return -1;
    }

    /// <summary>
    /// Walks back from step <paramref name="k"/> to the compare bounding <paramref name="index"/>, following register
    /// copies and at most one byte index table ("movzx rI, byte [rJ + table]").
    /// </summary>
    private bool TryFindBound(int k, Register index, ref bool baseAssumed, out uint count, out uint? indexTable, out string reason)
    {
        count = 0;
        indexTable = null;
        reason = "switch index bound not found";
        var current = index;
        var pending = ConditionCode.None;
        int pendingStep = 0;
        // the index was loaded from a frame slot [ebp/rbp + disp]: follow the slot instead of a register
        bool inSlot = false;
        var slotBase = Register.None;
        ulong slotDisp = 0;
        for (; k < _ringCount; k++)
        {
            ref var x = ref Back(k);
            if (x.FlowControl is FlowControl.Call or FlowControl.IndirectCall) return false;
            if (x.FlowControl == FlowControl.ConditionalBranch)
            {
                pending = x.ConditionCode;
                pendingStep = k;
                continue;
            }
            if (pending != ConditionCode.None && x.RflagsModified != RflagsBits.None)
            {
                // the run continues on the fall-through side of the pending jump: ja / jae bound the index
                ulong imm = 0;
                bool bounded = x.Mnemonic == Mnemonic.Cmp && (inSlot
                    ? IsSlot(in x, slotBase, slotDisp) && CompareImmediate(in x, out imm)
                    : TryCompare(k, pendingStep, out var reg, out imm) && reg == current);
                if (bounded && imm < uint.MaxValue)
                {
                    if (pending == ConditionCode.a) { count = (uint)imm + 1; return true; }
                    if (pending == ConditionCode.ae) { count = (uint)imm; return true; }
                }
                pending = ConditionCode.None;
            }
            if (inSlot)
            {
                if (WritesRegister(in x, slotBase)) return false;
                if (!IsSlot(in x, slotBase, slotDisp) || x.Mnemonic is Mnemonic.Cmp or Mnemonic.Test) continue;
                if (x.Mnemonic != Mnemonic.Mov || x.Op1Kind != OpKind.Register) return false;
                current = x.Op1Register.GetFullRegister();
                inSlot = false;
                continue;
            }
            if (!WritesRegister(in x, current)) continue;
            if (x.Mnemonic == Mnemonic.And && CompareImmediate(in x, out ulong mask) && mask < uint.MaxValue)
            {
                // "and rI, mask" bounds the index by itself
                count = (uint)mask + 1;
                return true;
            }
            if (x.Mnemonic is Mnemonic.Mov or Mnemonic.Movsxd && x.Op1Kind == OpKind.Memory && x.MemoryIndex == Register.None
                && x.MemoryBase is Register.EBP or Register.RBP && x.MemorySize is MemorySize.UInt32 or MemorySize.Int32 or MemorySize.UInt64 or MemorySize.Int64)
            {
                inSlot = true;
                slotBase = x.MemoryBase.GetFullRegister();
                slotDisp = x.MemoryDisplacement64;
                pending = ConditionCode.None;
                continue;
            }
            if (x.Mnemonic is Mnemonic.Mov or Mnemonic.Movsxd or Mnemonic.Movzx && x.Op1Kind == OpKind.Register)
            {
                current = x.Op1Register.GetFullRegister();
                continue;
            }
            if (indexTable == null && x.Mnemonic == Mnemonic.Movzx && x.Op1Kind == OpKind.Memory && x.MemorySize == MemorySize.UInt8)
            {
                Register other;
                uint tableRva;
                if (_is64)
                {
                    // movzx eI, byte [rB + rJ + table] with rB = __ImageBase
                    if (x.MemoryIndexScale != 1 || x.MemoryIndex == Register.None) return false;
                    var b = x.MemoryBase.GetFullRegister();
                    var j = x.MemoryIndex.GetFullRegister();
                    var bk = BaseOf(k + 1, b, out _);
                    if (bk == BaseKind.ImageBase) other = j;
                    else if (BaseOf(k + 1, j, out _) == BaseKind.ImageBase) other = b;
                    else if (bk == BaseKind.Unknown) { other = j; baseAssumed = true; }
                    else return false;
                    if (x.MemoryDisplacement64 is 0 or >= uint.MaxValue) return false;
                    tableRva = (uint)x.MemoryDisplacement64;
                }
                else
                {
                    // movzx eI, byte [rJ + table]
                    if (x.MemoryIndex != Register.None && x.MemoryBase != Register.None) return false;
                    other = (x.MemoryBase != Register.None ? x.MemoryBase : x.MemoryIndex).GetFullRegister();
                    if (other == Register.None || !TryRva(x.MemoryDisplacement64, out tableRva)) return false;
                }
                indexTable = tableRva;
                current = other;
                pending = ConditionCode.None;
                continue;
            }
            return false;
        }
        if (k >= _ringCount && _runBound.IsKnown && (inSlot
                ? _runBound.SlotBase == slotBase && _runBound.SlotDisp == slotDisp
                : _runBound.Reg == current))
        {
            count = _runBound.Count;
            return true;
        }
        return false;
    }
}
