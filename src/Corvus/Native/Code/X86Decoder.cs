using Iced.Intel;

namespace Corvus.Native.Code;

/// <summary>x86 / x64 decoder over an image's code that keeps the current run's last instructions; one instance per thread.</summary>
internal sealed class X86Decoder : ICodeDecoder
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
    // Outside PE, hlt ends crash paths (musl a_crash, glibc _start) and i386 code is position independent.
    private readonly bool _hltEnds;
    private readonly Reader _reader = new();
    private readonly Decoder _decoder;
    private readonly InstructionInfoFactory _info = new();
    private readonly Instruction[] _ring = new Instruction[RingSize];
    private int _ringHead, _ringCount;
    private IndexBound _runBound;
    private Instruction _last;

    public X86Decoder(ImageCode code, uint[] sortedRelocations) : this(code.Image, code, sortedRelocations) { }

    /// <param name="code">Executable code for <see cref="Decode"/>; null when only <see cref="DecodeMapped"/> is used.</param>
    /// <param name="is64">64-bit code in an image of another architecture (ARM64X x64 ranges); default from the image.</param>
    public X86Decoder(INativeImage image, ImageCode? code, uint[] sortedRelocations, bool? is64 = null)
    {
        _image = image;
        _code = code;
        _imageBase = image.ImageBase;
        _sizeOfImage = image.SizeOfImage;
        _relocs = sortedRelocations;
        _is64 = is64 ?? image.Arch == NativeArch.X64;
        _hltEnds = image.Format != ImageFormat.Pe;
        if (_hltEnds || _is64) _known = new uint[16];
        _decoder = Decoder.Create(_is64 ? 64 : 32, _reader, _imageBase, DecoderOptions.None);
    }

    public bool Is64 => _is64;
    /// <summary>Distinguish memory reads from writes at the cost of an instruction info lookup; otherwise only lea is distinguished.</summary>
    public bool ComputeAccess { get; set; } = true;
    /// <summary>Treat instructions user-mode compiled code never contains (<see cref="LastIsImplausible"/>) as invalid.</summary>
    public bool RejectImplausible { get; set; }
    /// <summary>Treat an instruction as invalid when a base relocation touches it outside its displacement or immediate: the loader patches only pointer-sized operands, so such bytes are data.</summary>
    public bool CheckRelocations { get; set; }

    private bool RelocationsFit(uint rva, int length)
    {
        if (_relocs.Length == 0) return true;
        int size = _is64 ? 8 : 4;
        int i = Array.BinarySearch(_relocs, rva);
        if (i < 0) i = ~i;
        // A pointer overlaps the first bytes.
        if (i > 0 && _relocs[i - 1] + (uint)size > rva) return false;
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
    /// <summary>The image has base relocations; the decoder may hold only those inside code.</summary>
    public bool HasRelocations => _relocs.Length > 0 || ImageHasRelocations;
    public bool ImageHasRelocations { get; set; }
    /// <summary>The last decoded instruction.</summary>
    public ref readonly Instruction Last => ref _last;

    /// <summary>Starts a new linear run; <paramref name="incoming"/> is a bound known on entry.</summary>
    public void BeginRun(IndexBound incoming)
    {
        _ringCount = 0;
        _runBound = incoming;
        _runStart = true;
        _padAfterCall = 0;
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
        if (insn.Flow == FlowKind.Call && i.Code is Iced.Intel.Code.Call_rel32_32 or Iced.Intel.Code.Call_rel32_64 && Retpoline(data, pos, end) is { } thunk)
        {
            insn.Flow = thunk.Flow;
            insn.Length = thunk.Length;
            insn.HasTarget = false;
        }

        bool hasMemory = false, hasImmediate = false;
        for (int k = 0; k < i.OpCount; k++)
        {
            var kind = i.GetOpKind(k);
            if (kind == OpKind.Memory) hasMemory = true;
            else if (kind is OpKind.Immediate32 or OpKind.Immediate64 or OpKind.Immediate32to64) hasImmediate = true;
        }
        if (_walking)
        {
            // Padding after a call means the call does not return, so a branch target there takes the branch's state.
            if (_runStart || (_padAfterCall == 2 && _stateAt.ContainsKey(rva))) RestoreState(rva);
            _padAfterCall = insn.Flow is FlowKind.Call or FlowKind.IndirectCall ? 1 : _padAfterCall > 0 && IsFill(in i) ? 2 : 0;
        }
        if (hasMemory) ResolveMemory(in i, ref insn);
        if (hasImmediate) ResolveImmediate(in i, ref insn);
        if (_walking) TrackKnown(in i, in insn);
    }

    /// <summary>An inline retpoline (indirect jump) or return thunk at the call at <paramref name="pos"/>, decoded as one instruction; null otherwise.</summary>
    private (FlowKind Flow, int Length)? Retpoline(byte[] data, int pos, int end)
    {
        int gap = BitConverter.ToInt32(data, pos + 1);
        int at = pos + 5 + gap;
        if (gap is < 2 or > 32 || at + 7 > end) return null;
        ReadOnlySpan<byte> loop = data.AsSpan(pos + 5, 3), l = data.AsSpan(at);
        if (!(loop[0] == 0xCC || loop.StartsWith((ReadOnlySpan<byte>)[0xF3, 0x90]) || loop.StartsWith((ReadOnlySpan<byte>)[0x0F, 0xAE, 0xE8]))) return null;
        int rex = 0;
        if (_is64)
        {
            if (l[0] is 0x48 or 0x4C && l[1] == 0x89 && (l[2] & 0xC7) == 0x04 && l[3] == 0x24 && l[4] == 0xC3) return (FlowKind.IndirectJump, at + 5 - pos);
            if (l[0] != 0x48) return null;
            l = l[1..];
            rex = 1;
        }
        else if (l[0] == 0x89 && (l[1] & 0xC7) == 0x04 && l[2] == 0x24 && l[3] == 0xC3) return (FlowKind.IndirectJump, at + 4 - pos);
        byte size = _is64 ? (byte)8 : (byte)4;
        if (l.StartsWith((ReadOnlySpan<byte>)[0x8D, 0x64, 0x24, size, 0xC3])) return (FlowKind.Return, at + rex + 5 - pos);
        if (l.StartsWith((ReadOnlySpan<byte>)[0x83, 0xC4, size, 0xC3])) return (FlowKind.Return, at + rex + 4 - pos);
        return null;
    }

    // RVA each of rax..r15 holds in the walked function, 0 when unknown: the i386 GOT pointer or an x64 lea [rip+x].
    private readonly uint[]? _known;
    private readonly Dictionary<uint, int> _pcThunks = [];
    // After "call $+5": the address a "pop reg" there loads.
    private uint _popPc;
    // Per ring slot: the values of operand 0, operand 1, memory base and index before the instruction.
    private readonly uint[] _ringOp0 = new uint[RingSize], _ringOp1 = new uint[RingSize], _ringBase = new uint[RingSize], _ringIndex = new uint[RingSize];

    // Register values are tracked from BeginFunction to the next single-instruction query (ThunkSlot).
    private bool _walking;

    /// <summary>Starts a function: register values known from its own code only.</summary>
    public void BeginFunction()
    {
        _walking = _known != null;
        if (_known != null) Array.Clear(_known);
        _popPc = 0;
        _spills = 0;
        _esp = 0;
        _espKnown = true;
        // Clear keeps the capacity a large function left, so shrink it back.
        if (_stateAt.Count > 0) { _stateAt.Clear(); if (_stateAt.EnsureCapacity(0) > 4096) _stateAt.TrimExcess(256); }
        _states = 0;
        _dispatchState = -1;
        _scaledSlots.Clear();
        _maskedSlots.Clear();
    }

    // Frame slots [ebp + d] holding another slot's value times four (a kept switch index), by displacement.
    private readonly Dictionary<ulong, ulong> _scaledSlots = [];

    /// <summary>Records "mov [ebp + d2], r" after "mov r, [ebp + d1]; shl r, 2" as d1 scaled; other stores forget the slot.</summary>
    private void TrackScaledSlot(in Instruction i)
    {
        var frame = _is64 ? Register.RBP : Register.EBP;
        if (i.Op0Kind != OpKind.Memory || i.MemoryBase != frame || i.MemoryIndex != Register.None
            || i.Mnemonic is Mnemonic.Cmp or Mnemonic.Test or Mnemonic.Push or Mnemonic.Bt or Mnemonic.Call or Mnemonic.Jmp) return;
        ulong d2 = i.MemoryDisplacement64;
        if (i.Mnemonic == Mnemonic.Mov && i.Op1Kind == OpKind.Register && IsFull(i.Op1Register))
        {
            var r = i.Op1Register.GetFullRegister();
            int w = FindWriter(1, r);
            if (w >= 0)
            {
                ref var x = ref Back(w);
                int load = -1;
                if (x.Mnemonic == Mnemonic.Shl && x.Op1Kind == OpKind.Immediate8 && x.Immediate8 == 2) load = FindWriter(w + 1, r);
                else if (x.Mnemonic == Mnemonic.Lea && x.MemoryBase == Register.None && x.MemoryIndexScale == 4 && x.MemoryDisplacement64 == 0)
                    load = FindWriter(w + 1, x.MemoryIndex.GetFullRegister());
                if (load >= 0 && Back(load) is { Mnemonic: Mnemonic.Mov, Op1Kind: OpKind.Memory, MemoryIndex: Register.None } l && l.MemoryBase == frame
                    && l.MemorySize is MemorySize.UInt32 or MemorySize.Int32)
                {
                    _scaledSlots[d2] = l.MemoryDisplacement64;
                    return;
                }
            }
        }
        _scaledSlots.Remove(d2);
    }

    // i386 frame slots holding an and-masked value, by entry esp offset: the count, 0 after any other store.
    private readonly Dictionary<int, uint> _maskedSlots = [];
    private readonly uint[] _ringSlotCount = new uint[RingSize];

    /// <summary>A store to the frame slot at <paramref name="at"/>: "mov [esp+d], r" right after "and r, mask" records the mask.</summary>
    private void TrackMaskedSlot(int at, in Instruction i)
    {
        uint count = 0;
        if (i.Mnemonic == Mnemonic.Mov && i.Op1Kind == OpKind.Register && i.Op1Register.GetSize() == 4
            && FindWriter(1, i.Op1Register.GetFullRegister()) is var w and >= 0 && Back(w) is { Mnemonic: Mnemonic.And } and && CompareImmediate(in and, out ulong mask)
            && mask < MaxRelocatedEntries)
            count = (uint)mask + 1;
        if (_maskedSlots.TryGetValue(at, out uint old) && old != count) count = 0;
        _maskedSlots[at] = count;
    }

    private static int Gpr(Register r)
    {
        var full = r.GetFullRegister();
        return full >= Register.RAX && full <= Register.R15 ? full - Register.RAX : -1;
    }

    private bool IsFull(Register r) => r == (_is64 ? r.GetFullRegister() : r.GetFullRegister32());

    private uint Known(Register r) => _known != null && Gpr(r) is var g and >= 0 ? _known[g] : 0;

    private void TrackKnown(in Instruction i, in Insn insn)
    {
        var known = _known!;
        int slot = (_ringHead - 1 + RingSize) % RingSize;
        _ringOp0[slot] = i.Op0Kind == OpKind.Register ? Known(i.Op0Register) : 0;
        _ringOp1[slot] = i.OpCount > 1 && i.Op1Kind == OpKind.Register ? Known(i.Op1Register) : 0;
        _ringBase[slot] = Known(i.MemoryBase);
        _ringIndex[slot] = Known(i.MemoryIndex);
        _ringSlotCount[slot] = 0;
        uint popPc = _popPc;
        _popPc = 0;
        int frame = _espKnown ? _esp : int.MinValue;
        TrackEsp(in i, in insn);
        if (i.Op0Kind == OpKind.Memory) TrackScaledSlot(in i);
        if (insn.Flow is FlowKind.Jump or FlowKind.ConditionalJump && insn.HasTarget && !_stateAt.ContainsKey(insn.Target)) _stateAt[insn.Target] = SaveState();
        else if (insn.Flow == FlowKind.IndirectJump) _dispatchState = SaveState();
        if (insn.Flow is FlowKind.Call or FlowKind.IndirectCall)
        {
            // eax, ecx, edx do not survive a call.
            known[0] = known[1] = known[2] = 0;
            if (_is64)
            {
                // Nor rsi, rdi (System V) and r8-r11.
                known[6] = known[7] = 0;
                Array.Clear(known, 8, 4);
            }
            else if (insn.Flow == FlowKind.Call && insn.HasTarget && PcThunkRegister(insn.Target) is var r and >= 0) known[r] = insn.Next;
            else if (i.Code == Iced.Intel.Code.Call_rel32_32 && i.NearBranchTarget == i.NextIP) _popPc = insn.Next;
            return;
        }
        if (i.Op0Kind == OpKind.Memory && IsStackSlot(in i) && i.Mnemonic is not (Mnemonic.Cmp or Mnemonic.Test or Mnemonic.Push or Mnemonic.Bt))
        {
            if (frame == int.MinValue) return;
            SetSpill(frame + (int)i.MemoryDisplacement64, i.Mnemonic == Mnemonic.Mov && i.Op1Kind == OpKind.Register && IsFull(i.Op1Register) ? Known(i.Op1Register) : 0);
            TrackMaskedSlot(frame + (int)i.MemoryDisplacement64, in i);
            return;
        }
        if (i.Op0Kind != OpKind.Register || Gpr(i.Op0Register) is not (var reg and >= 0)) return;
        switch (i.Mnemonic)
        {
            case Mnemonic.Mov when i.Op1Kind == OpKind.Memory && IsStackSlot(in i) && IsFull(i.Op0Register):
                known[reg] = frame != int.MinValue ? Spill(frame + (int)i.MemoryDisplacement64) : 0;
                if (frame != int.MinValue && _maskedSlots.TryGetValue(frame + (int)i.MemoryDisplacement64, out uint masked)) _ringSlotCount[slot] = masked;
                return;
            case Mnemonic.Pop:
                // An epilogue pop restores the caller's value on one path; other paths keep the known one.
                if (insn.Rva == popPc) known[reg] = popPc;
                return;
            case Mnemonic.Add when i.Op1Kind is OpKind.Immediate32 or OpKind.Immediate8to32:
                if (known[reg] != 0) known[reg] += (uint)i.GetImmediate(1);
                return;
            case Mnemonic.Lea when _is64 && i.IsIPRelativeMemoryOperand && IsFull(i.Op0Register):
                known[reg] = TryRva(i.IPRelativeMemoryAddress, out uint address) ? address : 0;
                return;
            case Mnemonic.Mov when i.Op1Kind == OpKind.Register && IsFull(i.Op0Register) && IsFull(i.Op1Register):
                known[reg] = Known(i.Op1Register);
                return;
            case Mnemonic.Xchg when i.Op1Kind == OpKind.Register && IsFull(i.Op0Register) && IsFull(i.Op1Register) && Gpr(i.Op1Register) is var other and >= 0:
                (known[reg], known[other]) = (known[other], known[reg]);
                return;
        }
        if (WritesRegister(in i, i.Op0Register)) known[reg] = 0;
    }

    // Esp offset from entry, tracked through push, pop, add and sub; i386 spills the GOT pointer by this offset.
    private int _esp;
    private bool _espKnown, _runStart;
    // Registers, esp and i386 spills at each block start, from the first branch there; case labels take the last dispatch.
    private readonly Dictionary<uint, int> _stateAt = [];
    private uint[] _statePool = new uint[I386StateSize * 64];
    private int _states, _dispatchState = -1;
    private int StateSize => _is64 ? 18 : I386StateSize;
    private const int I386StateSize = 19 + 2 * SpillSlots;

    private int SaveState()
    {
        if ((_states + 1) * StateSize > _statePool.Length) Array.Resize(ref _statePool, _statePool.Length * 2);
        int at = _states * StateSize;
        _known!.CopyTo(_statePool, at);
        _statePool[at + 16] = (uint)_esp;
        _statePool[at + 17] = _espKnown ? 1u : 0;
        if (!_is64)
        {
            _statePool[at + 18] = (uint)_spills;
            for (int n = 0; n < _spills; n++)
            {
                _statePool[at + 19 + n] = (uint)_spillDisp[n];
                _statePool[at + 19 + SpillSlots + n] = _spillValue[n];
            }
        }
        return _states++;
    }

    // 1 right after a call, 2 after a call and alignment fill, else 0.
    private int _padAfterCall;

    /// <summary>A nop form compilers pad with: nop, xchg ax, ax, mov / lea of a register to itself.</summary>
    private static bool IsFill(in Instruction i) =>
        i.Mnemonic == Mnemonic.Nop
        || i.Mnemonic is Mnemonic.Xchg or Mnemonic.Mov && i.Op0Kind == OpKind.Register && i.Op1Kind == OpKind.Register && i.Op0Register == i.Op1Register
        || i.Mnemonic == Mnemonic.Lea && i.MemoryBase == i.Op0Register && i.MemoryIndex == Register.None && i.MemoryDisplacement64 == 0;

    /// <summary>At the first instruction of a run: the state the branch to it saw.</summary>
    private void RestoreState(uint rva)
    {
        _runStart = false;
        int state = _stateAt.TryGetValue(rva, out int s) ? s : _dispatchState;
        if (state < 0) return;
        int at = state * StateSize;
        Array.Copy(_statePool, at, _known!, 0, 16);
        _esp = (int)_statePool[at + 16];
        _espKnown = _statePool[at + 17] != 0;
        if (_is64) return;
        _spills = (int)_statePool[at + 18];
        for (int n = 0; n < _spills; n++)
        {
            _spillDisp[n] = (int)_statePool[at + 19 + n];
            _spillValue[n] = _statePool[at + 19 + SpillSlots + n];
        }
    }

    private const int SpillSlots = 8;
    private readonly int[] _spillDisp = new int[SpillSlots];
    private readonly uint[] _spillValue = new uint[SpillSlots];
    private int _spills;

    private void TrackEsp(in Instruction i, in Insn insn)
    {
        if (insn.Flow is FlowKind.Call or FlowKind.IndirectCall or FlowKind.Return) return;
        if (i.Op0Kind == OpKind.Register && i.Op0Register == Register.ESP)
        {
            if (i.Mnemonic is Mnemonic.Add or Mnemonic.Sub && i.Op1Kind is OpKind.Immediate32 or OpKind.Immediate8to32)
                _esp += i.Mnemonic == Mnemonic.Add ? (int)i.GetImmediate(1) : -(int)i.GetImmediate(1);
            else if (i.Mnemonic == Mnemonic.Lea && i.MemoryBase == Register.ESP && i.MemoryIndex == Register.None) _esp += (int)i.MemoryDisplacement64;
            else _espKnown = false;
            return;
        }
        if (i.Mnemonic is Mnemonic.Leave or Mnemonic.Enter) _espKnown = false;
        else _esp += i.StackPointerIncrement;
    }

    private bool IsStackSlot(in Instruction i) => !_is64 && i.MemoryBase == Register.ESP && i.MemoryIndex == Register.None;

    private uint Spill(int disp)
    {
        for (int n = 0; n < _spills; n++) if (_spillDisp[n] == disp) return _spillValue[n];
        return 0;
    }

    private void SetSpill(int disp, uint value)
    {
        for (int n = 0; n < _spills; n++)
            if (_spillDisp[n] == disp) { _spillValue[n] = value; return; }
        if (value == 0) return;
        int at = _spills < _spillDisp.Length ? _spills++ : disp & (_spillDisp.Length - 1);
        _spillDisp[at] = disp;
        _spillValue[at] = value;
    }

    /// <summary>The register a get_pc_thunk at <paramref name="rva"/> loads ("mov reg, [esp]; ret"), or -1.</summary>
    private int PcThunkRegister(uint rva)
    {
        if (_pcThunks.TryGetValue(rva, out int r)) return r;
        r = -1;
        if (_code?.RegionAt(rva) is { } region && rva - region.Rva + 4 <= region.Bytes.Length)
        {
            var b = region.Bytes.AsSpan((int)(rva - region.Rva), 4);
            if (b[0] == 0x8B && (b[1] & 0xC7) == 0x04 && b[2] == 0x24 && b[3] == 0xC3) r = (b[1] >> 3) & 7;
        }
        return _pcThunks[rva] = r;
    }

    /// <summary>True when the last instruction is one user-mode compilers never emit; <paramref name="strict"/> adds far transfers and iret, which system code uses.</summary>
    public bool LastIsImplausible(bool strict = true)
    {
        ref readonly var i = ref _last;
        // Segment overrides on data accesses; nops pad with cs: and 3E on branches is notrack.
        if (i.SegmentPrefix is Register.ES or Register.CS or Register.SS or Register.DS
            && i.Mnemonic != Mnemonic.Nop && i.FlowControl == FlowControl.Next) return true;
        if (strict)
        {
            for (int k = 0; k < i.OpCount; k++)
                if (i.GetOpKind(k) is OpKind.FarBranch16 or OpKind.FarBranch32) return true;
            if (i.MemorySize is MemorySize.SegPtr16 or MemorySize.SegPtr32 or MemorySize.SegPtr64) return true;
            if (i.Mnemonic is Mnemonic.Iret or Mnemonic.Iretd or Mnemonic.Iretq or Mnemonic.Retf) return true;
        }
        // "00 00": add [eax], al.
        if (i.Code == Iced.Intel.Code.Add_rm8_r8 && i.Op0Kind == OpKind.Memory && i.MemoryBase is Register.EAX or Register.RAX
            && i.MemoryIndex == Register.None && i.MemoryDisplacement64 == 0 && i.Op1Register == Register.AL) return true;
        if (i.Mnemonic == Mnemonic.Hlt) return !_hltEnds;
        return i.Mnemonic is Mnemonic.In or Mnemonic.Out or Mnemonic.Insb or Mnemonic.Insw or Mnemonic.Insd
            or Mnemonic.Outsb or Mnemonic.Outsw or Mnemonic.Outsd or Mnemonic.Cli or Mnemonic.Sti
            or Mnemonic.Arpl or Mnemonic.Bound or Mnemonic.Les
            or Mnemonic.Lds or Mnemonic.Lss or Mnemonic.Lfs or Mnemonic.Lgs or Mnemonic.Into or Mnemonic.Aaa
            or Mnemonic.Aas or Mnemonic.Daa or Mnemonic.Das or Mnemonic.Aam or Mnemonic.Aad or Mnemonic.Salc
            or Mnemonic.Xlatb or Mnemonic.Int1 or Mnemonic.Sldt or Mnemonic.Lldt or Mnemonic.Lgdt
            or Mnemonic.Lidt or Mnemonic.Ltr or Mnemonic.Clts or Mnemonic.Invd or Mnemonic.Wbinvd or Mnemonic.Rdmsr
            or Mnemonic.Wrmsr or Mnemonic.Sysexit or Mnemonic.Sysret;
    }

    /// <summary>True when the last instruction has a large unrelocated 32-bit displacement that is neither an RVA nor the shared user data page.</summary>
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
        // i386 position-independent code addresses the image from the GOT pointer.
        if (_hltEnds && !_is64 && i.MemoryBase != Register.None && Math.Abs(disp) < _sizeOfImage) return false;
        // An array inside a large structure, or its offset formed by lea.
        if (i.MemoryIndex != Register.None && (i.MemoryBase != Register.None || i.Mnemonic == Mnemonic.Lea) && disp is > -0x100000 and < 0x100000) return false;
        var offsets = _decoder.GetConstantOffsets(in i);
        return !(offsets.HasDisplacement && IsRelocated(rva + offsets.DisplacementOffset));
    }

    /// <summary>True when the previous instruction sets the x86 SEH state [ebp-4] to -1 / -2, so the next call runs a __finally block.</summary>
    public bool PreviousLeavesSehScope()
    {
        if (_is64 || _ringCount < 2) return false;
        ref var x = ref Back(1);
        return x.Mnemonic == Mnemonic.Mov && x.Op0Kind == OpKind.Memory && x.MemoryBase == Register.EBP && x.MemoryIndex == Register.None
            && (int)(uint)x.MemoryDisplacement64 == -4 && x.Op1Kind is OpKind.Immediate32 or OpKind.Immediate8to32
            && (int)x.GetImmediate(1) is -1 or -2;
    }

    private static bool IsNear(OpKind kind) => kind is OpKind.NearBranch16 or OpKind.NearBranch32 or OpKind.NearBranch64;

    public uint? ThunkSlot(uint rva, Func<uint, bool> isImportSlot)
    {
        // A lone instruction takes no register values from earlier queries.
        if (_known != null) Array.Clear(_known);
        _walking = false;
        return Decode(rva, out var insn) && insn.Flow == FlowKind.IndirectJump && insn.HasMem && isImportSlot(insn.MemTarget) ? insn.MemTarget : null;
    }

    /// <summary>int3, nop and zero fill between functions.</summary>
    public bool IsPadding(ImageCode.Region region, uint rva) => region.Bytes[rva - region.Rva] is 0xCC or 0x90 or 0x00;

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
        else if (i.FlowControl == FlowControl.IndirectBranch && PltSlots.TryGetValue(insn.Rva, out target)) { }
        else if (!_is64 && i.MemoryIndex == Register.None && Known(i.MemoryBase) is var b and not 0)
        {
            target = b + (uint)i.MemoryDisplacement64;
            if (target >= _sizeOfImage) return;
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

    private Dictionary<uint, uint>? _pltSlots;

    /// <summary>i386 ELF PLT stub ("jmp [ebx + slot]") to its GOT slot, as the ELF reader matched them.</summary>
    private Dictionary<uint, uint> PltSlots => _pltSlots ??= !_is64 && _image is Elf.ElfFile elf
        ? elf.PltEntries.GroupBy(e => e.StubRva).ToDictionary(g => g.Key, g => g.First().SlotRva) : [];

    private OperandAccess MemoryAccess(in Instruction i)
    {
        var info = _info.GetInfo(in i, InstructionInfoOptions.NoRegisterUsage);
        foreach (var m in info.GetUsedMemory())
        {
            // Skip the implicit stack access of push [mem] / pop [mem].
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
            if (kind is not (OpKind.Immediate32 or OpKind.Immediate64 or OpKind.Immediate32to64)) continue;
            if (kind == OpKind.Immediate32 && _is64 && (HasRelocations || i.Mnemonic != Mnemonic.Mov)) continue;
            if (!TryRva(i.GetImmediate(k), out uint target)) return;
            if (HasRelocations)
            {
                var offsets = _decoder.GetConstantOffsets(in i);
                if (!offsets.HasImmediate || !IsRelocated(insn.Rva + offsets.ImmediateOffset)) return;
            }
            // Without relocations the image loads at its base, so push / mov of a section address is a pointer.
            else if (i.Mnemonic is not (Mnemonic.Push or Mnemonic.Mov) || (_is64 && i.Mnemonic != Mnemonic.Mov) || _image.SectionAt(target) == null)
                return;
            insn.HasImm = true;
            insn.ImmTarget = target;
            return;
        }
    }

    /// <summary>Instruction <paramref name="k"/> steps back in the current run (0 = the last one).</summary>
    private ref Instruction Back(int k) => ref _ring[(_ringHead - 1 - k + RingSize * 2) % RingSize];

    /// <summary>The bounds a "cmp reg, imm" before the last conditional jump sets on its taken and fall-through paths.</summary>
    public void ConditionalBounds(out IndexBound taken, out IndexBound fallThrough)
    {
        taken = fallThrough = IndexBound.None;
        if (_ringCount < 2) return;
        var cc = Back(0).ConditionCode;
        if (cc is not (ConditionCode.a or ConditionCode.ae or ConditionCode.be or ConditionCode.b)) return;
        ulong imm;
        ref var jcc = ref Back(0);
        // Out of range is the taken path of ja / jae and the fall-through of jbe / jb.
        uint? dflt = TryRva(cc is ConditionCode.a or ConditionCode.ae ? jcc.NearBranchTarget : jcc.NextIP, out uint d) ? d : null;
        IndexBound Make(uint n)
        {
            if (TryCompare(1, 0, out var reg, out _, out int step)) return new((int)reg, n, Default: dflt, Bias: BiasBefore(step + 1, reg));
            ref var c = ref Back(1);
            return new(0, n, (int)c.MemoryBase.GetFullRegister(), c.MemoryDisplacement64, dflt);
        }
        if (TryCompare(1, 0, out _, out imm)) { }
        else if (Back(1) is { Mnemonic: Mnemonic.Cmp, Op0Kind: OpKind.Memory, MemoryIndex: Register.None } c
                 && c.MemoryBase != Register.None && CompareImmediate(in c, out imm)) { }
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

    private bool TryCompare(int k, int jcc, out Register reg, out ulong imm) => TryCompare(k, jcc, out reg, out imm, out _);

    /// <summary>True when the flags setter at or before step <paramref name="k"/> is "cmp reg, imm" and reg holds up to step <paramref name="jcc"/>.</summary>
    private bool TryCompare(int k, int jcc, out Register reg, out ulong imm, out int step)
    {
        reg = Register.None;
        imm = 0;
        step = -1;
        for (; k < _ringCount; k++)
        {
            ref var x = ref Back(k);
            if (x.RflagsModified == RflagsBits.None) continue;
            if (x.Mnemonic != Mnemonic.Cmp || x.Op0Kind != OpKind.Register) return false;
            if (x.Op1Kind == OpKind.Register)
            {
                // cmp reg, reg2 with reg2 from "mov reg2, imm" or "push imm; pop reg2".
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
            step = k;
            return true;
        }
        return false;
    }

    /// <summary>The one constant adjustment to <paramref name="reg"/> within 8 steps before <paramref name="k"/>, through copies; 0 when none.</summary>
    private long BiasBefore(int k, Register reg)
    {
        for (int n = 0; k < _ringCount && n < 8; k++, n++)
        {
            ref var x = ref Back(k);
            if (IsCall(in x)) return 0;
            if (!WritesRegister(in x, reg)) continue;
            bool wide = x.Op0Register.GetSize() == 8;
            switch (x.Mnemonic)
            {
                case Mnemonic.Sub or Mnemonic.Add when x.Op1Kind is not (OpKind.Register or OpKind.Memory):
                    long v = wide ? (long)x.GetImmediate(1) : (int)(uint)x.GetImmediate(1);
                    return x.Mnemonic == Mnemonic.Sub ? v : -v;
                case Mnemonic.Dec: return 1;
                case Mnemonic.Inc: return -1;
                case Mnemonic.Lea when x.MemoryIndex == Register.None && x.MemoryBase != Register.None && !x.IsIPRelativeMemoryOperand:
                    return -(_is64 ? (long)x.MemoryDisplacement64 : (int)(uint)x.MemoryDisplacement64);
                case Mnemonic.Mov or Mnemonic.Movsxd or Mnemonic.Movzx when x.Op1Kind == OpKind.Register:
                    reg = x.Op1Register.GetFullRegister();
                    continue;
                default:
                    return 0;
            }
        }
        return 0;
    }

    /// <summary>A switch index load from memory whose bound may compare the memory itself; not an x86 byte index table.</summary>
    private bool IsSlotLoad(in Instruction x) =>
        x.Mnemonic is Mnemonic.Mov or Mnemonic.Movsxd or Mnemonic.Movzx && x.Op1Kind == OpKind.Memory && x.MemoryBase != Register.None
        // With an index register, a small displacement is an element, not a byte index table.
        && (x.MemoryIndex == Register.None || (long)x.MemoryDisplacement64 is > -0x1000 and < 0x1000)
        && x.MemorySize is MemorySize.UInt8 or MemorySize.UInt16 or MemorySize.UInt32 or MemorySize.Int32 or MemorySize.UInt64 or MemorySize.Int64
        && !(x.Mnemonic == Mnemonic.Movzx && !_is64 && TryRva(x.MemoryDisplacement64, out uint table) && _image.SectionAt(table) != null);

    /// <summary>True when a "cmp [same], imm; ja / jae" just before the load at step <paramref name="k"/> bounds the loaded index.</summary>
    private bool ComparedBefore(int k, in Instruction x, out uint count, out uint? dflt)
    {
        count = 0;
        dflt = null;
        if (x.Mnemonic is not (Mnemonic.Mov or Mnemonic.Movzx) || x.Op1Kind != OpKind.Memory || x.MemoryBase == Register.None) return false;
        Register b = x.MemoryBase.GetFullRegister(), i = x.MemoryIndex.GetFullRegister();
        uint baseValue = RingValue(_ringBase, k);
        bool baseWritten = false;
        int branch = -1;
        for (int j = k + 1, n = 0; j < _ringCount && n < 6; j++, n++)
        {
            ref var c = ref Back(j);
            if (c.FlowControl == FlowControl.ConditionalBranch) { branch = c.ConditionCode is ConditionCode.a or ConditionCode.ae ? j : -1; continue; }
            if (i != Register.None && WritesRegister(in c, i)) return false;
            baseWritten |= WritesRegister(in c, b);
            if (c.RflagsModified == RflagsBits.None) continue;
            bool same = !baseWritten && IsSlot(in c, b, x.MemoryDisplacement64, i, x.MemoryIndexScale)
                || baseValue != 0 && c.Op0Kind == OpKind.Memory && RingValue(_ringBase, j) == baseValue && c.MemoryIndex.GetFullRegister() == i
                   && (i == Register.None || c.MemoryIndexScale == x.MemoryIndexScale) && c.MemoryDisplacement64 == x.MemoryDisplacement64;
            if (branch < 0 || c.Mnemonic != Mnemonic.Cmp || c.MemorySize != x.MemorySize || !same || !CompareImmediate(in c, out ulong imm) || imm >= uint.MaxValue) return false;
            ref var jcc = ref Back(branch);
            count = jcc.ConditionCode == ConditionCode.a ? (uint)imm + 1 : (uint)imm;
            dflt = TryRva(jcc.NearBranchTarget, out uint d) ? d : null;
            return true;
        }
        return false;
    }

    /// <summary>Operand 0 is the memory slot [base + index*scale + disp].</summary>
    private static bool IsSlot(in Instruction x, Register slotBase, ulong slotDisp, Register slotIndex = Register.None, int slotScale = 1) =>
        x.Op0Kind == OpKind.Memory && x.MemoryBase.GetFullRegister() == slotBase && x.MemoryIndex.GetFullRegister() == slotIndex
        && (slotIndex == Register.None || x.MemoryIndexScale == slotScale) && x.MemoryDisplacement64 == slotDisp;

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

    /// <summary>A call that may change registers: not "call $+5", which only pushes its own address.</summary>
    private static bool IsCall(in Instruction x) =>
        x.FlowControl is FlowControl.Call or FlowControl.IndirectCall && !(x.Code == Iced.Intel.Code.Call_rel32_32 && x.NearBranchTarget == x.NextIP);

    /// <summary>A call that may change <paramref name="reg"/>: not "call $+5", nor a get_pc_thunk loading another register.</summary>
    private bool CallChanges(in Instruction x, Register reg) =>
        IsCall(in x) && !(x.Code == Iced.Intel.Code.Call_rel32_32 && TryRva(x.NearBranchTarget, out uint t) && PcThunkRegister(t) is var r and >= 0
            && Register.RAX + r != reg);

    private static bool WritesRegister(in Instruction x, Register full) =>
        (x.Op0Kind == OpKind.Register && x.Op0Register.GetFullRegister() == full && x.Mnemonic is not (Mnemonic.Cmp or Mnemonic.Test or Mnemonic.Push or Mnemonic.Bt))
        || (x.Mnemonic == Mnemonic.Xchg && x.Op1Kind == OpKind.Register && x.Op1Register.GetFullRegister() == full);

    /// <summary>Matches the run before the last indirect jump against bounded switch dispatch sequences; null with a reason when none matches.</summary>
    public SwitchMatch? MatchSwitch(out string reason)
    {
        reason = SwitchMatch.NoDispatch;
        if (_ringCount == 0) return null;
        ref var jmp = ref Back(0);
        Register index;
        uint table;
        bool absolute = false, relative = false, baseAssumed = false;
        int entrySize = _is64 ? 8 : 4;
        int k;
        if (jmp.Op0Kind == OpKind.Memory)
        {
            // "jmp [table + index*4]"; x64 also "jmp [table + index*8]" and Go's "jmp [rB + index*8]".
            if (jmp.MemoryIndex == Register.None || jmp.MemoryIndexScale != entrySize) return null;
            if (jmp.MemoryBase == Register.None ? !TryRva(jmp.MemoryDisplacement64, out table)
                : !_is64 || jmp.MemoryDisplacement64 != 0 || BaseOf(1, jmp.MemoryBase.GetFullRegister(), out table) != BaseKind.Table) return null;
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
                if (l < 0) return MatchKnownBase(k, t, out reason);
                ref var load = ref Back(l);
                if (load.Mnemonic is not (Mnemonic.Mov or Mnemonic.Movsxd) || load.Op1Kind != OpKind.Memory) return MatchKnownBase(k, t, out reason);
                if (load.MemoryIndex == Register.None || load.MemoryIndexScale != 4 || load.MemoryBase == Register.None) return MatchKnownBase(k, t, out reason);
                var loadBase = load.MemoryBase.GetFullRegister();
                var addBase = BaseOf(k + 1, b, out uint addRva);
                if (addBase == BaseKind.Table && load.MemoryDisplacement64 == 0 && load.Mnemonic == Mnemonic.Movsxd
                    && loadBase == b && FindWriter(k + 1, b) > l)
                {
                    // Entries are offsets from the table itself.
                    table = addRva;
                    relative = true;
                }
                else if (addBase is BaseKind.ImageBase or BaseKind.Unknown && load.MemoryDisplacement64 is > 0 and < uint.MaxValue)
                {
                    // Entries are RVAs: [__ImageBase + index*4 + table RVA].
                    var lb = BaseOf(l + 1, loadBase, out _);
                    if (lb is not (BaseKind.ImageBase or BaseKind.Unknown)) return MatchKnownBase(k, t, out reason);
                    table = (uint)load.MemoryDisplacement64;
                    baseAssumed = addBase == BaseKind.Unknown || lb == BaseKind.Unknown;
                }
                else return MatchKnownBase(k, t, out reason);
                index = load.MemoryIndex.GetFullRegister();
                k = l + 1;
            }
            else if (w.Mnemonic == Mnemonic.Mov && w.Op1Kind == OpKind.Memory && w.MemoryBase == Register.None
                     && w.MemoryIndex != Register.None && w.MemoryIndexScale == entrySize && TryRva(w.MemoryDisplacement64, out table))
            {
                index = w.MemoryIndex.GetFullRegister();
                absolute = true;
                k++;
            }
            else if (_is64 && w.Mnemonic == Mnemonic.Mov && w.Op1Kind == OpKind.Memory && w.MemoryBase != Register.None && w.MemoryDisplacement64 == 0
                     && w.MemoryIndex != Register.None && w.MemoryIndexScale == 8 && BaseOf(k + 1, w.MemoryBase.GetFullRegister(), out table) == BaseKind.Table)
            {
                // Go: lea rB, [rip+table]; mov rT, [rB + index*8]; jmp rT.
                index = w.MemoryIndex.GetFullRegister();
                absolute = true;
                k++;
            }
            else return MatchKnownBase(k, t, out reason);
        }
        else return null;

        if (!TryFindBound(k, index, ref baseAssumed, out uint count, out uint? indexTable, out reason, out var bound))
        {
            // PE: each absolute entry carries a base relocation, so the relocated run bounds the table.
            if (!absolute || entrySize != 4 || _image.Format != ImageFormat.Pe || !TryRva(jmp.IP, out uint at) || (count = RelocatedEntries(table, at)) == 0) return null;
            return new SwitchMatch(table, 4, true, false, count, null, 0, false) { BoundByRelocations = true, Window = KnownBaseWindow };
        }
        var match = indexTable is { } it
            ? new SwitchMatch(table, absolute ? entrySize : 4, absolute, relative, 0, it, count, baseAssumed)
            : new SwitchMatch(table, absolute ? entrySize : 4, absolute, relative, count, null, 0, baseAssumed);
        return match with { Default = bound.Default, Bias = bound.Bias, BoundByMask = bound.Mask };
    }

    /// <summary>Targets of a table matched through tracked register values lie this close to the dispatch.</summary>
    private const uint KnownBaseWindow = 0x100000;

    private const uint MaxRelocatedEntries = 1024;

    /// <summary>Entries of the absolute table up to the first without a relocation or a code target near <paramref name="jump"/>.</summary>
    private uint RelocatedEntries(uint table, uint jump)
    {
        Span<byte> b = stackalloc byte[4];
        uint n = 0;
        for (uint p = table; n < MaxRelocatedEntries; p += 4, n++)
        {
            if (Array.BinarySearch(_relocs, p) < 0 || _image.Read(p, b) < 4) break;
            if (!TryRva(System.Buffers.Binary.BinaryPrimitives.ReadUInt32LittleEndian(b), out uint t) || _code?.IsCode(t) != true
                || (t > jump ? t - jump : jump - t) > KnownBaseWindow || (t >= table && t < p + 4)) break;
        }
        return n;
    }

    /// <summary>A dispatch whose table and entry base registers hold values in <see cref="_known"/>; <paramref name="k"/> writes jump register <paramref name="t"/>.</summary>
    private SwitchMatch? MatchKnownBase(int k, Register t, out string reason)
    {
        reason = SwitchMatch.NoDispatch;
        if (_known == null) return null;
        // "xchg rT, rX; jmp rT": the target was computed in rX.
        for (int n = 0; n < 2 && Back(k) is { Mnemonic: Mnemonic.Xchg, Op0Kind: OpKind.Register, Op1Kind: OpKind.Register } xchg; n++)
        {
            t = xchg.Op0Register.GetFullRegister() == t ? xchg.Op1Register.GetFullRegister() : xchg.Op0Register.GetFullRegister();
            k = FindWriter(k + 1, t);
            if (k < 0) return null;
        }
        ref var w = ref Back(k);
        int load;
        uint entryBase;
        if (w.Mnemonic == Mnemonic.Add && w.Op1Kind == OpKind.Memory)
        {
            load = k;
            entryBase = RingValue(_ringOp0, k);
        }
        else
        {
            // The two summands and their values before the combining instruction.
            Register x, y;
            uint xv, yv;
            if (w.Mnemonic == Mnemonic.Add && w.Op1Kind == OpKind.Register)
                (x, xv, y, yv) = (t, RingValue(_ringOp0, k), w.Op1Register.GetFullRegister(), RingValue(_ringOp1, k));
            else if (w.Mnemonic == Mnemonic.Lea && w.MemoryBase != Register.None && w.MemoryIndex != Register.None && w.MemoryIndexScale == 1 && w.MemoryDisplacement64 == 0)
                (x, xv, y, yv) = (w.MemoryBase.GetFullRegister(), RingValue(_ringBase, k), w.MemoryIndex.GetFullRegister(), RingValue(_ringIndex, k));
            else return null;
            int lx = EntryLoad(k + 1, x), ly = EntryLoad(k + 1, y);
            if (lx >= 0 && yv != 0) (load, entryBase) = (lx, yv);
            else if (ly >= 0 && xv != 0) (load, entryBase) = (ly, xv);
            else return null;
        }
        if (entryBase == 0) return null;
        ref var l = ref Back(load);
        if (l.MemorySize is not (MemorySize.Int32 or MemorySize.UInt32) || l.MemoryBase == Register.None || l.MemoryIndex == Register.None) return null;
        uint tableBase = RingValue(_ringBase, load);
        if (tableBase == 0) return null;
        uint table = tableBase + (uint)l.MemoryDisplacement64;
        var index = l.MemoryIndex.GetFullRegister();
        int next = load + 1;
        uint count;
        uint? indexTable = null;
        (uint? Default, long Bias, bool Mask) bound;
        int s = l.MemoryIndexScale == 1 ? FindWriter(next, index) : -1;
        if (s >= 0 && Back(s) is { Mnemonic: Mnemonic.And } masked && CompareImmediate(in masked, out ulong mask) && (mask & 3) == 0 && mask < uint.MaxValue)
        {
            // A pre-scaled masked index: "and rI, 0xfc" bounds it to 64 entries.
            count = (uint)(mask >> 2) + 1;
            bound = (null, 0, true);
        }
        else
        {
            ulong? slot = null;
            if (l.MemoryIndexScale == 1)
            {
                // A pre-scaled index: lea rI, [rJ*4], shl rI, 2, or a scaled frame slot.
                if (s < 0) return null;
                ref var x = ref Back(s);
                if (x.Mnemonic == Mnemonic.Lea && x.MemoryBase == Register.None && x.MemoryIndexScale == 4 && x.MemoryDisplacement64 == 0) index = x.MemoryIndex.GetFullRegister();
                else if (x.Mnemonic == Mnemonic.Mov && x.Op1Kind == OpKind.Memory && x.MemoryIndex == Register.None && x.MemoryBase == (_is64 ? Register.RBP : Register.EBP)
                         && _scaledSlots.TryGetValue(x.MemoryDisplacement64, out ulong source)) slot = source;
                else if (!(x.Mnemonic == Mnemonic.Shl && x.Op1Kind == OpKind.Immediate8 && x.Immediate8 == 2)) return null;
                next = s + 1;
            }
            else if (l.MemoryIndexScale != 4) return null;
            bool assumed = false;
            if (!TryFindBound(next, index, ref assumed, out count, out indexTable, out reason, out bound, slot)) return null;
        }
        var match = indexTable is { } it
            ? new SwitchMatch(table, 4, false, entryBase == table, 0, it, count, false)
            : new SwitchMatch(table, 4, false, entryBase == table, count, null, 0, false);
        return match with
        {
            Base = entryBase == table ? null : entryBase, Signed = true, Window = KnownBaseWindow,
            Default = bound.Default, Bias = bound.Bias, BoundByMask = bound.Mask,
        };
    }

    private uint RingValue(uint[] values, int k) => values[(_ringHead - 1 - k + RingSize * 2) % RingSize];

    /// <summary>Step of the 32-bit table entry load into <paramref name="reg"/> at or before step <paramref name="k"/>, or -1.</summary>
    private int EntryLoad(int k, Register reg)
    {
        int s = FindWriter(k, reg);
        if (s < 0) return -1;
        ref var x = ref Back(s);
        return x.Mnemonic is Mnemonic.Mov or Mnemonic.Movsxd && x.Op1Kind == OpKind.Memory && x.MemoryIndex != Register.None ? s : -1;
    }

    private enum BaseKind { ImageBase, Table, Unknown, Other }

    /// <summary>What <paramref name="reg"/> holds at step <paramref name="k"/>: __ImageBase or a table from "lea reg, [rip+x]", unknown, or other.</summary>
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
            if (CallChanges(in x, reg)) return -1;
            if (WritesRegister(in x, reg)) return k;
        }
        return -1;
    }

    /// <summary>Walks back from step <paramref name="k"/> to the compare bounding <paramref name="index"/>, through copies and one byte index table.</summary>
    /// <param name="frameSlot">Displacement of the frame slot [ebp + d] holding the index instead.</param>
    private bool TryFindBound(int k, Register index, ref bool baseAssumed, out uint count, out uint? indexTable, out string reason,
        out (uint? Default, long Bias, bool Mask) bound, ulong? frameSlot = null)
    {
        count = 0;
        indexTable = null;
        bound = default;
        reason = "switch index bound not found";
        var current = index;
        var pending = ConditionCode.None;
        int pendingStep = 0;
        // An index loaded from memory is followed through its slot instead of a register.
        bool inSlot = frameSlot != null;
        Register slotBase = inSlot ? Register.RBP : Register.None, slotIndex = Register.None;
        int slotScale = 1;
        ulong slotDisp = frameSlot ?? 0;
        // "cmp byte [esp+d], n; ja" bounds the index when the slot was stored from the register it copies (clang).
        Register cmpBase = Register.None, storedFrom = Register.None;
        ulong cmpDisp = 0;
        var cmpSize = MemorySize.Unknown;
        uint cmpCount = 0;
        uint? cmpDefault = null;
        for (; k < _ringCount; k++)
        {
            ref var x = ref Back(k);
            if (CallChanges(in x, current) || (inSlot && (CallChanges(in x, slotBase) || CallChanges(in x, slotIndex)))) return false;
            if (IsFill(in x)) continue;
            if (cmpBase != Register.None && !inSlot)
            {
                if (storedFrom != Register.None && WritesRegister(in x, current) && x.Mnemonic is Mnemonic.Mov or Mnemonic.Movzx && x.Op1Kind == OpKind.Register
                    && x.Op1Register == storedFrom && (x.Mnemonic == Mnemonic.Movzx || storedFrom.GetSize() == 4))
                {
                    count = cmpCount;
                    bound = (cmpDefault, 0, false);
                    return true;
                }
                if (IsCall(in x) || WritesRegister(in x, cmpBase) || (cmpBase == Register.RSP && x.StackPointerIncrement != 0)
                    || (storedFrom != Register.None && WritesRegister(in x, storedFrom.GetFullRegister())))
                    cmpBase = storedFrom = Register.None;
                else if (storedFrom == Register.None && IsSlot(in x, cmpBase, cmpDisp) && x.Mnemonic is not (Mnemonic.Cmp or Mnemonic.Test))
                {
                    if (x.Mnemonic != Mnemonic.Mov || x.Op1Kind != OpKind.Register || x.MemorySize != cmpSize) cmpBase = Register.None;
                    else if (x.Op1Register == current && cmpSize is MemorySize.UInt32 or MemorySize.Int32)
                    {
                        count = cmpCount;
                        bound = (cmpDefault, 0, false);
                        return true;
                    }
                    else storedFrom = x.Op1Register;
                }
            }
            if (x.FlowControl == FlowControl.ConditionalBranch)
            {
                pending = x.ConditionCode;
                pendingStep = k;
                continue;
            }
            if (pending != ConditionCode.None && x.RflagsModified != RflagsBits.None)
            {
                // The run continues on the fall-through side, so ja / jae bound the index.
                ulong imm = 0;
                bool bounded = x.Mnemonic == Mnemonic.Cmp && (inSlot
                    ? IsSlot(in x, slotBase, slotDisp, slotIndex, slotScale) && CompareImmediate(in x, out imm)
                    : TryCompare(k, pendingStep, out var reg, out imm) && reg == current);
                if (bounded && imm < uint.MaxValue && pending is ConditionCode.a or ConditionCode.ae)
                {
                    count = pending == ConditionCode.a ? (uint)imm + 1 : (uint)imm;
                    bound = (TryRva(Back(pendingStep).NearBranchTarget, out uint d) ? d : null, inSlot ? 0 : BiasBefore(k + 1, current), false);
                    return true;
                }
                if (!inSlot && cmpBase == Register.None && pending is ConditionCode.a or ConditionCode.ae && x.Mnemonic == Mnemonic.Cmp
                    && x.Op0Kind == OpKind.Memory && x.MemoryBase is Register.ESP or Register.EBP or Register.RSP or Register.RBP && x.MemoryIndex == Register.None
                    && CompareImmediate(in x, out ulong slotImm) && slotImm < uint.MaxValue)
                {
                    (cmpBase, cmpDisp, cmpSize) = (x.MemoryBase.GetFullRegister(), x.MemoryDisplacement64, x.MemorySize);
                    cmpCount = pending == ConditionCode.a ? (uint)slotImm + 1 : (uint)slotImm;
                    cmpDefault = TryRva(Back(pendingStep).NearBranchTarget, out uint d) ? d : null;
                }
                pending = ConditionCode.None;
            }
            if (inSlot)
            {
                if (WritesRegister(in x, slotBase) || (slotIndex != Register.None && WritesRegister(in x, slotIndex))
                    || (slotBase == Register.RSP && x.StackPointerIncrement != 0)) return false;
                if (!IsSlot(in x, slotBase, slotDisp, slotIndex, slotScale) || x.Mnemonic is Mnemonic.Cmp or Mnemonic.Test) continue;
                if (x.Mnemonic != Mnemonic.Mov || x.Op1Kind != OpKind.Register) return false;
                current = x.Op1Register.GetFullRegister();
                inSlot = false;
                continue;
            }
            if (!WritesRegister(in x, current)) continue;
            if (x.Mnemonic == Mnemonic.And && CompareImmediate(in x, out ulong mask) && mask < uint.MaxValue)
            {
                // "and rI, mask" bounds the index by itself.
                count = (uint)mask + 1;
                bound = (null, 0, true);
                return true;
            }
            if (ComparedBefore(k, in x, out count, out var compareDefault))
            {
                bound = (compareDefault, 0, false);
                return true;
            }
            if (IsSlotLoad(in x))
            {
                if (_walking && RingValue(_ringSlotCount, k) is var masked and > 0)
                {
                    // A frame slot stored right after an and-mask in another block.
                    count = masked;
                    bound = (null, 0, true);
                    return true;
                }
                inSlot = true;
                slotBase = x.MemoryBase.GetFullRegister();
                slotIndex = x.MemoryIndex.GetFullRegister();
                slotScale = x.MemoryIndexScale;
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
                ? slotIndex == Register.None && _runBound.SlotBase == (int)slotBase && _runBound.SlotDisp == slotDisp
                : _runBound.Reg == (int)current))
        {
            count = _runBound.Count;
            bound = (_runBound.Default, _runBound.Bias, false);
            return true;
        }
        return false;
    }
}
