using System.Numerics;
using Iced.Intel;
using static Iced.Intel.Register;

namespace Corvus.Native.Emulation;

/// <summary>x86 and x64 integer execution on Iced; floating point, FS/GS bases, system instructions and wider vectors are refused by name.</summary>
public sealed class X86Cpu : IEmulatorCpu
{
    private readonly bool _is64;
    private readonly bool _windows;
    private readonly ulong[] _r = new ulong[16];
    private readonly (ulong Lo, ulong Hi)[] _xmm = new (ulong, ulong)[16];
    private bool _cf, _pf, _af, _zf, _sf, _of, _df;
    private readonly byte[] _fetch = new byte[15];
    private readonly MasmFormatter _formatter = new();
    private Instruction _last;

    /// <param name="windows">The Microsoft x64 convention (RCX, RDX, R8, R9, 32 bytes of shadow space) rather than System V's.</param>
    public X86Cpu(bool is64, bool windows)
    {
        _is64 = is64;
        _windows = windows;
        _formatter.Options.UppercaseHex = true;
        _formatter.Options.SpaceAfterOperandSeparator = true;
        _formatter.Options.RipRelativeAddresses = false;
        _formatter.Options.ShowBranchSize = false;
        _formatter.Options.BranchLeadingZeros = false;
        _formatter.Options.LeadingZeros = false;
    }

    public string Language => _is64 ? "x86-64" : "x86";

    public int PointerSize => _is64 ? 8 : 4;

    public ulong Pc { get; set; }

    public ulong Sp { get => _r[4] & Mask(PointerSize); set => _r[4] = value & Mask(PointerSize); }

    public string LastText
    {
        get
        {
            var o = new StringOutput();
            _formatter.Format(_last, o);
            return o.ToStringAndReset();
        }
    }


    public IReadOnlyList<string> MainRegisters => _is64
        ? ["RAX", "RBX", "RCX", "RDX", "RSI", "RDI", "RBP", "RSP", "R8", "R9", "R10", "R11", "R12", "R13", "R14", "R15", "RIP"]
        : ["EAX", "EBX", "ECX", "EDX", "ESI", "EDI", "EBP", "ESP", "EIP"];

    public string ReturnRegister => _is64 ? "RAX" : "EAX";

    public bool TryGet(string name, out ulong value)
    {
        value = 0;
        var n = name.Trim().ToUpperInvariant();
        if (n is "RIP" or "EIP" or "PC") { value = Pc; return true; }
        if (!Enum.TryParse<Register>(n, true, out var reg) || reg == None) return false;
        if (reg.IsGPR() && (_is64 || reg.GetSize() <= 4) && Index(reg) < (_is64 ? 16 : 8)) { value = Get(reg); return true; }
        return false;
    }

    public bool TrySet(string name, ulong value)
    {
        var n = name.Trim().ToUpperInvariant();
        if (n is "RIP" or "EIP" or "PC") { Pc = value; return true; }
        if (!Enum.TryParse<Register>(n, true, out var reg) || reg == None) return false;
        if (!reg.IsGPR() || !_is64 && reg.GetSize() > 4 || Index(reg) >= (_is64 ? 16 : 8)) return false;
        Set(reg, value);
        return true;
    }

    public void SetReturnAddress(EmulatorMemory memory, ulong sentinel)
    {
        Sp -= (ulong)PointerSize;
        memory.WriteUInt(Sp, sentinel, PointerSize);
    }

    public void ReturnFromCall(EmulatorMemory memory, ulong value, int purge)
    {
        _r[0] = _is64 ? value : value & 0xFFFFFFFF;
        Pc = memory.ReadUInt(Sp, PointerSize);
        Sp += (ulong)(PointerSize + purge);
    }

    public IReadOnlyList<ArgumentSlot> Arguments(int count)
    {
        string[] regs = !_is64 ? [] : _windows ? ["RCX", "RDX", "R8", "R9"] : ["RDI", "RSI", "RDX", "RCX", "R8", "R9"];
        // Stack arguments follow the return address, and on Windows x64 the 32 bytes of shadow space.
        int first = PointerSize + (_is64 && _windows ? 32 : 0);
        var slots = new List<ArgumentSlot>();
        for (int i = 0; i < count; i++)
            slots.Add(i < regs.Length ? new(regs[i], 0) : new(null, first + (i - regs.Length) * PointerSize));
        return slots;
    }

    // ---- registers ----

    private static ulong Mask(int size) => size >= 8 ? ulong.MaxValue : (1UL << (size * 8)) - 1;

    private static int Index(Register reg) => reg.GetFullRegister() - RAX;

    private static bool HighByte(Register reg) => reg is AH or CH or DH or BH;

    private ulong Get(Register reg)
    {
        if (HighByte(reg)) return _r[reg - AH] >> 8 & 0xFF;
        if (reg is RIP or EIP) return Pc;
        if (!reg.IsGPR()) throw new EmulatorUnsupportedException($"register {reg} is not modelled");
        return _r[Index(reg)] & Mask(reg.GetSize());
    }

    private void Set(Register reg, ulong value)
    {
        if (HighByte(reg))
        {
            int i = reg - AH;
            _r[i] = _r[i] & ~0xFF00UL | (value & 0xFF) << 8;
            return;
        }
        if (!reg.IsGPR()) throw new EmulatorUnsupportedException($"register {reg} is not modelled");
        int idx = Index(reg), size = reg.GetSize();
        // A 32-bit write zero-extends to 64 bits; 8- and 16-bit writes keep the rest.
        _r[idx] = size >= 4 ? value & Mask(size) : _r[idx] & ~Mask(size) | value & Mask(size);
    }

    // ---- operands ----

    private ulong Address(in Instruction i)
    {
        if (i.MemorySegment is FS or GS)
            throw new EmulatorUnsupportedException($"{i.MemorySegment.ToString().ToLowerInvariant()}: segment base (thread data) is not modelled");
        if (i.IsIPRelativeMemoryOperand) return i.IPRelativeMemoryAddress;
        ulong a = i.MemoryDisplacement64;
        if (i.MemoryBase != None) a += Get(i.MemoryBase);
        if (i.MemoryIndex != None)
        {
            if (!i.MemoryIndex.IsGPR()) throw new EmulatorUnsupportedException("a vector index (gather) is not modelled");
            a += Get(i.MemoryIndex) * (ulong)i.MemoryIndexScale;
        }
        bool narrow = !_is64 || i.MemoryBase.GetSize() == 4 || i.MemoryBase == None && i.MemoryIndex.GetSize() == 4;
        return narrow ? a & 0xFFFFFFFF : a;
    }

    private int Size(in Instruction i, int op) => i.GetOpKind(op) switch
    {
        OpKind.Register => i.GetOpRegister(op).GetSize(),
        OpKind.Memory => i.MemorySize.GetSize(),
        OpKind.Immediate8 or OpKind.Immediate8_2nd => 1,
        OpKind.Immediate16 or OpKind.Immediate8to16 => 2,
        OpKind.Immediate32 or OpKind.Immediate8to32 => 4,
        _ => 8,
    };

    private ulong Read(EmulatorMemory m, in Instruction i, int op)
    {
        switch (i.GetOpKind(op))
        {
            case OpKind.Register: return Get(i.GetOpRegister(op));
            case OpKind.Memory: return m.ReadUInt(Address(i), i.MemorySize.GetSize());
            case OpKind.NearBranch16 or OpKind.NearBranch32 or OpKind.NearBranch64: return i.NearBranchTarget;
            case OpKind.Immediate8 or OpKind.Immediate8_2nd or OpKind.Immediate16 or OpKind.Immediate32 or OpKind.Immediate64 or OpKind.Immediate8to16
                or OpKind.Immediate8to32 or OpKind.Immediate8to64 or OpKind.Immediate32to64:
                return i.GetImmediate(op);
            default: throw new EmulatorUnsupportedException($"operand kind {i.GetOpKind(op)} is not modelled");
        }
    }

    private void Write(EmulatorMemory m, in Instruction i, int op, ulong value)
    {
        switch (i.GetOpKind(op))
        {
            case OpKind.Register: Set(i.GetOpRegister(op), value); break;
            case OpKind.Memory: m.WriteUInt(Address(i), value, i.MemorySize.GetSize()); break;
            default: throw new EmulatorUnsupportedException($"a write to operand kind {i.GetOpKind(op)} is not modelled");
        }
    }

    // ---- flags ----

    private static bool Sign(ulong v, int size) => (v >> (size * 8 - 1) & 1) != 0;

    private static bool Parity(ulong v) => (BitOperations.PopCount(v & 0xFF) & 1) == 0;

    private void Result(ulong r, int size)
    {
        r &= Mask(size);
        _zf = r == 0;
        _sf = Sign(r, size);
        _pf = Parity(r);
    }

    private ulong Add(ulong a, ulong b, ulong carry, int size)
    {
        ulong mask = Mask(size);
        a &= mask;
        b &= mask;
        UInt128 wide = (UInt128)a + b + carry;
        ulong r = (ulong)wide & mask;
        _cf = size == 8 ? wide > ulong.MaxValue : (ulong)wide > mask;
        _of = Sign(~(a ^ b) & (a ^ r), size);
        _af = ((a ^ b ^ r) & 0x10) != 0;
        Result(r, size);
        return r;
    }

    private ulong Sub(ulong a, ulong b, ulong borrow, int size)
    {
        ulong mask = Mask(size);
        a &= mask;
        b &= mask;
        ulong r = a - b - borrow & mask;
        _cf = (UInt128)b + borrow > a;
        _of = Sign((a ^ b) & (a ^ r), size);
        _af = ((a ^ b ^ r) & 0x10) != 0;
        Result(r, size);
        return r;
    }

    private ulong Logic(ulong r, int size)
    {
        _cf = _of = _af = false;
        Result(r, size);
        return r & Mask(size);
    }

    private bool Condition(ConditionCode c) => c switch
    {
        ConditionCode.o => _of, ConditionCode.no => !_of,
        ConditionCode.b => _cf, ConditionCode.ae => !_cf,
        ConditionCode.e => _zf, ConditionCode.ne => !_zf,
        ConditionCode.be => _cf || _zf, ConditionCode.a => !_cf && !_zf,
        ConditionCode.s => _sf, ConditionCode.ns => !_sf,
        ConditionCode.p => _pf, ConditionCode.np => !_pf,
        ConditionCode.l => _sf != _of, ConditionCode.ge => _sf == _of,
        ConditionCode.le => _zf || _sf != _of, ConditionCode.g => !_zf && _sf == _of,
        _ => throw new EmulatorUnsupportedException($"condition {c} is not modelled"),
    };

    private ulong Flags() =>
        (_cf ? 1UL : 0) | 2 | (_pf ? 4UL : 0) | (_af ? 0x10UL : 0) | (_zf ? 0x40UL : 0) | (_sf ? 0x80UL : 0) | 0x200 | (_df ? 0x400UL : 0) | (_of ? 0x800UL : 0);

    private void SetFlags(ulong f)
    {
        _cf = (f & 1) != 0; _pf = (f & 4) != 0; _af = (f & 0x10) != 0; _zf = (f & 0x40) != 0; _sf = (f & 0x80) != 0;
        _df = (f & 0x400) != 0; _of = (f & 0x800) != 0;
    }

    private static long Signed(ulong v, int size) => size switch { 1 => (sbyte)v, 2 => (short)v, 4 => (int)v, _ => (long)v };

    // ---- stack ----

    private void Push(EmulatorMemory m, ulong v, int size)
    {
        Sp -= (ulong)size;
        m.WriteUInt(Sp, v, size);
    }

    private ulong Pop(EmulatorMemory m, int size)
    {
        ulong v = m.ReadUInt(Sp, size);
        Sp += (ulong)size;
        return v;
    }

    // ---- execution ----

    public EmulatorStep Step(EmulatorMemory m)
    {
        int n = 0;
        for (; n < _fetch.Length; n++)
        {
            if (!m.Mapped(Pc + (ulong)n)) break;
            m.Read(Pc + (ulong)n, _fetch.AsSpan(n, 1));
        }
        if (n == 0) throw new EmulatorFaultException(Pc, $"execution reached unmapped address 0x{Pc:x}");
        var decoder = Decoder.Create(_is64 ? 64 : 32, new ByteArrayCodeReader(_fetch, 0, n), Pc);
        decoder.Decode(out _last);
        ref readonly var i = ref _last;
        if (i.IsInvalid) throw new EmulatorUnsupportedException($"no valid instruction at 0x{Pc:x}");
        ulong next = i.NextIP;
        Pc = next;
        switch (i.Mnemonic)
        {
            case Mnemonic.Nop or Mnemonic.Endbr64 or Mnemonic.Endbr32 or Mnemonic.Pause or Mnemonic.Lfence or Mnemonic.Mfence or Mnemonic.Sfence
                or Mnemonic.Prefetchnta or Mnemonic.Prefetcht0 or Mnemonic.Prefetcht1 or Mnemonic.Prefetcht2 or Mnemonic.Prefetchw or Mnemonic.Vzeroupper:
                break;
            case Mnemonic.Mov:
                Write(m, i, 0, Read(m, i, 1));
                break;
            case Mnemonic.Movzx:
                Write(m, i, 0, Read(m, i, 1));
                break;
            case Mnemonic.Movsx or Mnemonic.Movsxd:
                Write(m, i, 0, (ulong)Signed(Read(m, i, 1), Size(i, 1)));
                break;
            case Mnemonic.Lea:
            {
                // The address computation ignores segments; Address refuses FS/GS only for real accesses.
                ulong a = i.IsIPRelativeMemoryOperand ? i.IPRelativeMemoryAddress
                    : i.MemoryDisplacement64 + (i.MemoryBase != None ? Get(i.MemoryBase) : 0) + (i.MemoryIndex != None ? Get(i.MemoryIndex) * (ulong)i.MemoryIndexScale : 0);
                Write(m, i, 0, a);
                break;
            }
            case Mnemonic.Xchg:
            {
                ulong a = Read(m, i, 0), b = Read(m, i, 1);
                Write(m, i, 0, b);
                Write(m, i, 1, a);
                break;
            }
            case Mnemonic.Push:
                Push(m, Read(m, i, 0), -i.StackPointerIncrement);
                break;
            case Mnemonic.Pop:
            {
                int size = i.StackPointerIncrement;
                ulong v = Pop(m, size);
                Write(m, i, 0, v);
                break;
            }
            case Mnemonic.Pushfq or Mnemonic.Pushfd or Mnemonic.Pushf:
                Push(m, Flags(), -i.StackPointerIncrement);
                break;
            case Mnemonic.Popfq or Mnemonic.Popfd or Mnemonic.Popf:
                SetFlags(Pop(m, i.StackPointerIncrement));
                break;
            case Mnemonic.Leave:
                Sp = _r[5];
                _r[5] = _is64 ? Pop(m, 8) : Pop(m, 4) | _r[5] & ~0xFFFFFFFFUL;
                break;
            case Mnemonic.Add or Mnemonic.Adc or Mnemonic.Sub or Mnemonic.Sbb or Mnemonic.Cmp:
            {
                int size = Size(i, 0);
                ulong a = Read(m, i, 0), b = Read(m, i, 1);
                ulong c = i.Mnemonic is Mnemonic.Adc or Mnemonic.Sbb && _cf ? 1UL : 0;
                ulong r = i.Mnemonic is Mnemonic.Add or Mnemonic.Adc ? Add(a, b, c, size) : Sub(a, b, c, size);
                if (i.Mnemonic != Mnemonic.Cmp) Write(m, i, 0, r);
                break;
            }
            case Mnemonic.Inc or Mnemonic.Dec:
            {
                int size = Size(i, 0);
                bool cf = _cf;
                ulong r = i.Mnemonic == Mnemonic.Inc ? Add(Read(m, i, 0), 1, 0, size) : Sub(Read(m, i, 0), 1, 0, size);
                _cf = cf;
                Write(m, i, 0, r);
                break;
            }
            case Mnemonic.Neg:
            {
                int size = Size(i, 0);
                ulong a = Read(m, i, 0);
                Write(m, i, 0, Sub(0, a, 0, size));
                _cf = (a & Mask(size)) != 0;
                break;
            }
            case Mnemonic.And or Mnemonic.Or or Mnemonic.Xor or Mnemonic.Test:
            {
                int size = Size(i, 0);
                ulong a = Read(m, i, 0), b = Read(m, i, 1);
                ulong r = Logic(i.Mnemonic switch { Mnemonic.Or => a | b, Mnemonic.Xor => a ^ b, _ => a & b }, size);
                if (i.Mnemonic != Mnemonic.Test) Write(m, i, 0, r);
                break;
            }
            case Mnemonic.Not:
                Write(m, i, 0, ~Read(m, i, 0));
                break;
            case Mnemonic.Shl or Mnemonic.Sal or Mnemonic.Shr or Mnemonic.Sar or Mnemonic.Rol or Mnemonic.Ror or Mnemonic.Rcl or Mnemonic.Rcr:
                Shift(m, i);
                break;
            case Mnemonic.Shld or Mnemonic.Shrd:
            {
                int size = Size(i, 0), bits = size * 8;
                int count = (int)(Read(m, i, 2) & (size == 8 ? 0x3FUL : 0x1FUL));
                if (count == 0) break;
                UInt128 dst = Read(m, i, 0) & Mask(size), src = Read(m, i, 1) & Mask(size);
                ulong r;
                if (i.Mnemonic == Mnemonic.Shld)
                {
                    UInt128 joined = dst << bits | src;
                    r = (ulong)(joined << count >> bits) & Mask(size);
                    _cf = (dst >> (bits - count) & 1) != 0;
                }
                else
                {
                    UInt128 joined = src << bits | dst;
                    r = (ulong)(joined >> count) & Mask(size);
                    _cf = (dst >> (count - 1) & 1) != 0;
                }
                _of = Sign(r ^ (ulong)dst, size);
                Result(r, size);
                Write(m, i, 0, r);
                break;
            }
            case Mnemonic.Mul or Mnemonic.Imul when i.OpCount == 1:
                MulWide(m, i);
                break;
            case Mnemonic.Imul:
            {
                int size = Size(i, 0);
                long a = Signed(i.OpCount == 3 ? Read(m, i, 1) : Read(m, i, 0), size);
                long b = Signed(i.OpCount == 3 ? Read(m, i, 2) : Read(m, i, 1), size);
                Int128 full = (Int128)a * b;
                ulong r = (ulong)(long)full & Mask(size);
                _cf = _of = full != Signed(r, size);
                Result(r, size);
                Write(m, i, 0, r);
                break;
            }
            case Mnemonic.Div or Mnemonic.Idiv:
                Divide(m, i);
                break;
            case Mnemonic.Cbw: Set(AX, (ulong)(sbyte)Get(AL)); break;
            case Mnemonic.Cwde: Set(EAX, (ulong)(short)Get(AX)); break;
            case Mnemonic.Cdqe: Set(RAX, (ulong)(int)Get(EAX)); break;
            case Mnemonic.Cwd: Set(DX, (short)Get(AX) < 0 ? 0xFFFFUL : 0); break;
            case Mnemonic.Cdq: Set(EDX, (int)Get(EAX) < 0 ? 0xFFFFFFFFUL : 0); break;
            case Mnemonic.Cqo: Set(RDX, (long)Get(RAX) < 0 ? ulong.MaxValue : 0); break;
            case Mnemonic.Bswap:
            {
                ulong v = Read(m, i, 0);
                Write(m, i, 0, Size(i, 0) == 8 ? System.Buffers.Binary.BinaryPrimitives.ReverseEndianness(v)
                    : System.Buffers.Binary.BinaryPrimitives.ReverseEndianness((uint)v));
                break;
            }
            case Mnemonic.Bt or Mnemonic.Bts or Mnemonic.Btr or Mnemonic.Btc:
            {
                int size = Size(i, 0);
                ulong offset = Read(m, i, 1);
                ulong value;
                ulong at = 0;
                int bit;
                bool memory = i.GetOpKind(0) == OpKind.Memory;
                if (memory && i.GetOpKind(1) == OpKind.Register)
                {
                    // A register bit offset reaches outside the operand: whole units before or after it.
                    long signedOffset = Signed(offset, Size(i, 1));
                    at = (ulong)((long)Address(i) + (signedOffset >> 3 & ~((long)size - 1)));
                    bit = (int)(signedOffset & (size * 8 - 1));
                    value = m.ReadUInt(at, size);
                }
                else
                {
                    bit = (int)(offset & (ulong)(size * 8 - 1));
                    value = Read(m, i, 0);
                }
                _cf = (value >> bit & 1) != 0;
                ulong r = i.Mnemonic switch { Mnemonic.Bts => value | 1UL << bit, Mnemonic.Btr => value & ~(1UL << bit), Mnemonic.Btc => value ^ 1UL << bit, _ => value };
                if (i.Mnemonic == Mnemonic.Bt) break;
                if (memory && i.GetOpKind(1) == OpKind.Register) m.WriteUInt(at, r, size); else Write(m, i, 0, r);
                break;
            }
            case Mnemonic.Bsf or Mnemonic.Bsr or Mnemonic.Tzcnt or Mnemonic.Lzcnt or Mnemonic.Popcnt:
            {
                int size = Size(i, 0);
                ulong v = Read(m, i, 1) & Mask(size);
                switch (i.Mnemonic)
                {
                    case Mnemonic.Popcnt:
                        _cf = _of = _sf = _af = _pf = false;
                        _zf = v == 0;
                        Write(m, i, 0, (ulong)BitOperations.PopCount(v));
                        break;
                    case Mnemonic.Tzcnt or Mnemonic.Lzcnt:
                    {
                        int count = v == 0 ? size * 8 : i.Mnemonic == Mnemonic.Tzcnt ? BitOperations.TrailingZeroCount(v) : BitOperations.LeadingZeroCount(v) - (64 - size * 8);
                        _cf = v == 0;
                        _zf = count == 0;
                        Write(m, i, 0, (ulong)count);
                        break;
                    }
                    default:
                        _zf = v == 0;
                        if (v != 0) Write(m, i, 0, (ulong)(i.Mnemonic == Mnemonic.Bsf ? BitOperations.TrailingZeroCount(v) : 63 - BitOperations.LeadingZeroCount(v)));
                        break;
                }
                break;
            }
            case Mnemonic.Xadd:
            {
                int size = Size(i, 0);
                ulong a = Read(m, i, 0), b = Read(m, i, 1);
                ulong r = Add(a, b, 0, size);
                Write(m, i, 1, a);
                Write(m, i, 0, r);
                break;
            }
            case Mnemonic.Cmpxchg:
            {
                int size = Size(i, 0);
                var acc = size switch { 1 => AL, 2 => AX, 4 => EAX, _ => RAX };
                ulong dst = Read(m, i, 0);
                Sub(Get(acc), dst, 0, size);
                if (_zf) Write(m, i, 0, Read(m, i, 1)); else Set(acc, dst);
                break;
            }
            case Mnemonic.Lahf: Set(AH, Flags() & 0xD5); break;
            case Mnemonic.Sahf: SetFlags(Flags() & ~0xD5UL | Get(AH) & 0xD5); break;
            case Mnemonic.Clc: _cf = false; break;
            case Mnemonic.Stc: _cf = true; break;
            case Mnemonic.Cmc: _cf = !_cf; break;
            case Mnemonic.Cld: _df = false; break;
            case Mnemonic.Std: _df = true; break;
            case Mnemonic.Jmp:
                Pc = Target(m, i);
                break;
            case Mnemonic.Call:
            {
                ulong target = Target(m, i);
                Push(m, next, PointerSize);
                Pc = target;
                return new EmulatorStep(true, i.IP, next);
            }
            case Mnemonic.Ret:
                Pc = Pop(m, PointerSize);
                if (i.OpCount == 1) Sp += i.Immediate16;
                break;
            case Mnemonic.Jrcxz or Mnemonic.Jecxz or Mnemonic.Jcxz:
                if ((i.Mnemonic == Mnemonic.Jrcxz ? _r[1] : i.Mnemonic == Mnemonic.Jecxz ? _r[1] & 0xFFFFFFFF : _r[1] & 0xFFFF) == 0) Pc = i.NearBranchTarget;
                break;
            case Mnemonic.Loop or Mnemonic.Loope or Mnemonic.Loopne:
            {
                ulong c = (_r[1] - 1) & Mask(_is64 ? 8 : 4);
                _r[1] = _is64 ? c : _r[1] & ~0xFFFFFFFFUL | c;
                if (c != 0 && (i.Mnemonic == Mnemonic.Loop || i.Mnemonic == Mnemonic.Loope == _zf)) Pc = i.NearBranchTarget;
                break;
            }
            case Mnemonic.Movsb or Mnemonic.Movsw or Mnemonic.Movsq or Mnemonic.Stosb or Mnemonic.Stosw or Mnemonic.Stosd or Mnemonic.Stosq
                or Mnemonic.Lodsb or Mnemonic.Lodsw or Mnemonic.Lodsd or Mnemonic.Lodsq or Mnemonic.Cmpsb or Mnemonic.Cmpsw or Mnemonic.Cmpsq
                or Mnemonic.Scasb or Mnemonic.Scasw or Mnemonic.Scasd or Mnemonic.Scasq:
                Strings(m, i);
                break;
            case Mnemonic.Movsd or Mnemonic.Cmpsd when i.GetOpKind(0) is OpKind.MemoryESRDI or OpKind.MemoryESEDI or OpKind.MemorySegRSI or OpKind.MemorySegESI:
                Strings(m, i);
                break;
            case Mnemonic.Movaps or Mnemonic.Movups or Mnemonic.Movdqa or Mnemonic.Movdqu or Mnemonic.Movapd or Mnemonic.Movupd or Mnemonic.Lddqu
                or Mnemonic.Vmovaps or Mnemonic.Vmovups or Mnemonic.Vmovdqa or Mnemonic.Vmovdqu when Width(i) == 16:
                WriteVector(m, i, 0, ReadVector(m, i, 1));
                break;
            case Mnemonic.Xorps or Mnemonic.Xorpd or Mnemonic.Pxor or Mnemonic.Orps or Mnemonic.Orpd or Mnemonic.Por or Mnemonic.Andps or Mnemonic.Andpd
                or Mnemonic.Pand or Mnemonic.Andnps or Mnemonic.Pandn when Width(i) == 16:
            {
                var (al, ah) = ReadVector(m, i, 0);
                var (bl, bh) = ReadVector(m, i, 1);
                (ulong, ulong) r = i.Mnemonic switch
                {
                    Mnemonic.Orps or Mnemonic.Orpd or Mnemonic.Por => (al | bl, ah | bh),
                    Mnemonic.Andps or Mnemonic.Andpd or Mnemonic.Pand => (al & bl, ah & bh),
                    Mnemonic.Andnps or Mnemonic.Pandn => (~al & bl, ~ah & bh),
                    _ => (al ^ bl, ah ^ bh),
                };
                WriteVector(m, i, 0, r);
                break;
            }
            case Mnemonic.Vpxor or Mnemonic.Vxorps or Mnemonic.Vpor or Mnemonic.Vpand when Width(i) == 16:
            {
                var (al, ah) = ReadVector(m, i, 1);
                var (bl, bh) = ReadVector(m, i, 2);
                WriteVector(m, i, 0, i.Mnemonic switch { Mnemonic.Vpor => (al | bl, ah | bh), Mnemonic.Vpand => (al & bl, ah & bh), _ => (al ^ bl, ah ^ bh) });
                break;
            }
            case Mnemonic.Movd or Mnemonic.Movq or Mnemonic.Vmovd or Mnemonic.Vmovq:
                MoveScalar(m, i);
                break;
            case Mnemonic.Punpcklqdq when Width(i) == 16:
                WriteVector(m, i, 0, (ReadVector(m, i, 0).Lo, ReadVector(m, i, 1).Lo));
                break;
            default:
                if (i.Mnemonic is >= Mnemonic.Cmova and <= Mnemonic.Cmovs || i.ConditionCode != ConditionCode.None && i.Mnemonic.ToString().StartsWith("Cmov", StringComparison.Ordinal))
                {
                    ulong v = Read(m, i, 1);
                    // A 32-bit CMOV zero-extends its destination even when the condition is false.
                    if (Condition(i.ConditionCode)) Write(m, i, 0, v); else if (Size(i, 0) == 4) Write(m, i, 0, Read(m, i, 0));
                    break;
                }
                if (i.ConditionCode != ConditionCode.None && i.Mnemonic.ToString().StartsWith("Set", StringComparison.Ordinal))
                {
                    Write(m, i, 0, Condition(i.ConditionCode) ? 1UL : 0);
                    break;
                }
                if (i.ConditionCode != ConditionCode.None && i.FlowControl == FlowControl.ConditionalBranch)
                {
                    if (Condition(i.ConditionCode)) Pc = i.NearBranchTarget;
                    break;
                }
                throw new EmulatorUnsupportedException($"{LastText}: {i.Mnemonic.ToString().ToLowerInvariant()} is not modelled");
        }
        return new EmulatorStep(false, i.IP, next);
    }

    private ulong Target(EmulatorMemory m, in Instruction i)
    {
        ulong t = Read(m, i, 0);
        return _is64 ? t : t & 0xFFFFFFFF;
    }

    private void Shift(EmulatorMemory m, in Instruction i)
    {
        int size = Size(i, 0), bits = size * 8;
        ulong v = Read(m, i, 0) & Mask(size);
        int count = (int)((i.OpCount > 1 ? Read(m, i, 1) : 1) & (size == 8 ? 0x3FUL : 0x1FUL));
        if (count == 0) return;
        ulong r;
        switch (i.Mnemonic)
        {
            case Mnemonic.Shl or Mnemonic.Sal:
                r = count >= 64 ? 0 : v << count & Mask(size);
                _cf = count <= bits && (v >> (bits - count) & 1) != 0;
                _of = Sign(r, size) != _cf;
                Result(r, size);
                break;
            case Mnemonic.Shr:
                r = count >= 64 ? 0 : v >> count;
                _cf = (v >> (count - 1) & 1) != 0;
                _of = Sign(v, size);
                Result(r, size);
                break;
            case Mnemonic.Sar:
                r = (ulong)(Signed(v, size) >> Math.Min(count, 63)) & Mask(size);
                _cf = (ulong)(Signed(v, size) >> Math.Min(count - 1, 63) & 1) != 0;
                _of = false;
                Result(r, size);
                break;
            case Mnemonic.Rol:
            {
                int c = count % bits;
                r = c == 0 ? v : (v << c | v >> (bits - c)) & Mask(size);
                _cf = (r & 1) != 0;
                _of = Sign(r, size) != _cf;
                break;
            }
            case Mnemonic.Ror:
            {
                int c = count % bits;
                r = c == 0 ? v : (v >> c | v << (bits - c)) & Mask(size);
                _cf = Sign(r, size);
                _of = Sign(r, size) != (r >> (bits - 2) & 1) is 1;
                break;
            }
            default:
            {
                // RCL and RCR rotate through the carry: a (bits + 1)-bit value.
                int c = count % (bits + 1);
                UInt128 wide = (UInt128)v | (UInt128)(_cf ? 1UL : 0) << bits;
                UInt128 all = ((UInt128)1 << (bits + 1)) - 1;
                if (i.Mnemonic == Mnemonic.Rcl) wide = (wide << c | wide >> (bits + 1 - c)) & all;
                else wide = (wide >> c | wide << (bits + 1 - c)) & all;
                r = (ulong)wide & Mask(size);
                _cf = (wide >> bits & 1) != 0;
                _of = i.Mnemonic == Mnemonic.Rcl ? Sign(r, size) != _cf : Sign(r, size) != (r >> (bits - 2) & 1) is 1;
                break;
            }
        }
        Write(m, i, 0, r);
    }

    private void MulWide(EmulatorMemory m, in Instruction i)
    {
        int size = Size(i, 0);
        ulong src = Read(m, i, 0) & Mask(size);
        bool signed = i.Mnemonic == Mnemonic.Imul;
        var (acc, high) = size switch { 1 => (AL, AH), 2 => (AX, DX), 4 => (EAX, EDX), _ => (RAX, RDX) };
        ulong a = Get(acc);
        UInt128 product = signed ? (UInt128)((Int128)Signed(a, size) * Signed(src, size)) : (UInt128)a * src;
        int bits = size * 8;
        ulong lo = (ulong)product & Mask(size), hi = (ulong)(product >> bits) & Mask(size);
        if (size == 1) Set(AX, lo | hi << 8);
        else { Set(acc, lo); Set(high, hi); }
        _cf = _of = signed ? (Int128)product != Signed(lo, size) : hi != 0;
    }

    private void Divide(EmulatorMemory m, in Instruction i)
    {
        int size = Size(i, 0), bits = size * 8;
        ulong d = Read(m, i, 0) & Mask(size);
        if (d == 0) throw new EmulatorUnsupportedException($"{LastText}: division by zero (#DE)");
        var (acc, high) = size switch { 1 => (AL, AH), 2 => (AX, DX), 4 => (EAX, EDX), _ => (RAX, RDX) };
        UInt128 n = size == 1 ? Get(AX) : (UInt128)Get(high) << bits | Get(acc);
        ulong q, rem;
        if (i.Mnemonic == Mnemonic.Div)
        {
            UInt128 uq = n / d;
            if (uq > Mask(size)) throw new EmulatorUnsupportedException($"{LastText}: quotient overflow (#DE)");
            q = (ulong)uq;
            rem = (ulong)(n % d);
        }
        else
        {
            // The dividend is 2 * size bits, sign-extended from its top bit.
            Int128 sn = (Int128)(n << (128 - 2 * bits)) >> (128 - 2 * bits);
            long sd = Signed(d, size);
            Int128 sq = sn / sd;
            if (sq > (Int128)Signed(Mask(size) >> 1, 8) || sq < -(Int128)Signed(Mask(size) >> 1, 8) - 1)
                throw new EmulatorUnsupportedException($"{LastText}: quotient overflow (#DE)");
            q = (ulong)(long)sq & Mask(size);
            rem = (ulong)(long)(sn % sd) & Mask(size);
        }
        if (size == 1) Set(AX, q | rem << 8);
        else { Set(acc, q); Set(high, rem); }
    }

    private void Strings(EmulatorMemory m, in Instruction i)
    {
        string name = i.Mnemonic.ToString();
        int size = name[^1] switch { 'b' => 1, 'w' => 2, 'd' => 4, _ => 8 };
        string op = name[..^1];
        bool rep = i.HasRepPrefix || i.HasRepePrefix || i.HasRepnePrefix;
        ulong addrMask = Mask(_is64 ? 8 : 4);
        long step = _df ? -size : size;
        var acc = size switch { 1 => AL, 2 => AX, 4 => EAX, _ => RAX };
        // One REP instruction runs to completion within a step, bounded so a runaway count still ends.
        for (long n = 0; ; n++)
        {
            if (rep && (_r[1] & addrMask) == 0) break;
            if (n >= 1 << 24) throw new EmulatorUnsupportedException($"{LastText}: more than 16,777,216 repetitions");
            ulong si = _r[6] & addrMask, di = _r[7] & addrMask;
            switch (op)
            {
                case "Movs": m.WriteUInt(di, m.ReadUInt(si, size), size); _r[6] = si + (ulong)step & addrMask; _r[7] = di + (ulong)step & addrMask; break;
                case "Stos": m.WriteUInt(di, Get(acc), size); _r[7] = di + (ulong)step & addrMask; break;
                case "Lods": Set(acc, m.ReadUInt(si, size)); _r[6] = si + (ulong)step & addrMask; break;
                case "Cmps": Sub(m.ReadUInt(si, size), m.ReadUInt(di, size), 0, size); _r[6] = si + (ulong)step & addrMask; _r[7] = di + (ulong)step & addrMask; break;
                default: Sub(Get(acc), m.ReadUInt(di, size), 0, size); _r[7] = di + (ulong)step & addrMask; break;
            }
            if (!rep) break;
            _r[1] = (_r[1] & ~addrMask) | ((_r[1] - 1) & addrMask);
            if (op is "Cmps" or "Scas" && (i.HasRepePrefix ? !_zf : i.HasRepnePrefix && _zf)) break;
        }
    }

    private static int Width(in Instruction i)
    {
        for (int op = 0; op < i.OpCount; op++)
        {
            if (i.GetOpKind(op) == OpKind.Register && i.GetOpRegister(op).IsYMM()) return 32;
            if (i.GetOpKind(op) == OpKind.Register && i.GetOpRegister(op).IsXMM()) return 16;
        }
        return 0;
    }

    private (ulong Lo, ulong Hi) ReadVector(EmulatorMemory m, in Instruction i, int op)
    {
        if (i.GetOpKind(op) == OpKind.Register) return _xmm[i.GetOpRegister(op) - XMM0];
        ulong a = Address(i);
        return (m.ReadUInt(a, 8), m.ReadUInt(a + 8, 8));
    }

    private void WriteVector(EmulatorMemory m, in Instruction i, int op, (ulong Lo, ulong Hi) v)
    {
        if (i.GetOpKind(op) == OpKind.Register) { _xmm[i.GetOpRegister(op) - XMM0] = v; return; }
        ulong a = Address(i);
        m.WriteUInt(a, v.Lo, 8);
        m.WriteUInt(a + 8, v.Hi, 8);
    }

    // MOVD and MOVQ between XMM registers, general registers and memory; a load into XMM clears the rest.
    private void MoveScalar(EmulatorMemory m, in Instruction i)
    {
        int size = i.Mnemonic is Mnemonic.Movd or Mnemonic.Vmovd ? 4 : 8;
        bool toXmm = i.GetOpKind(0) == OpKind.Register && i.GetOpRegister(0).IsXMM();
        bool fromXmm = i.GetOpKind(1) == OpKind.Register && i.GetOpRegister(1).IsXMM();
        if (i.GetOpKind(0) == OpKind.Register && i.GetOpRegister(0).IsMM() || i.GetOpKind(1) == OpKind.Register && i.GetOpRegister(1).IsMM())
            throw new EmulatorUnsupportedException($"{LastText}: MMX registers are not modelled");
        ulong v = fromXmm ? _xmm[i.GetOpRegister(1) - XMM0].Lo & Mask(size) : Read(m, i, 1) & Mask(size);
        if (toXmm) _xmm[i.GetOpRegister(0) - XMM0] = (v, 0);
        else if (i.GetOpKind(0) == OpKind.Memory) m.WriteUInt(Address(i), v, size);
        else Set(i.GetOpRegister(0), v);
    }
}
