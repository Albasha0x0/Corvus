using System.Numerics;

namespace Corvus.Native.Emulation;

/// <summary>ARM64 integer execution of A64 encodings; floating point, vector arithmetic and system registers are refused by name.</summary>
public sealed class Arm64Cpu : IEmulatorCpu
{
    private readonly ulong[] _x = new ulong[31];
    private readonly (ulong Lo, ulong Hi)[] _v = new (ulong, ulong)[32];
    private ulong _sp;
    private bool _n, _z, _c, _vf;
    private uint _word;
    private ulong _at;

    public string Language => "AArch64";

    public int PointerSize => 8;

    public ulong Pc { get; set; }

    public ulong Sp { get => _sp; set => _sp = value; }

    public string LastText => AsmArm64.Arm64Instruction.Decode(_word).ToString() ?? $".word 0x{_word:x8}";

    public IReadOnlyList<string> MainRegisters { get; } = [.. Enumerable.Range(0, 31).Select(i => $"x{i}"), "sp", "pc"];

    public string ReturnRegister => "x0";

    public bool TryGet(string name, out ulong value)
    {
        value = 0;
        var n = name.Trim().ToLowerInvariant();
        switch (n)
        {
            case "sp": value = _sp; return true;
            case "pc": value = Pc; return true;
            case "lr": value = _x[30]; return true;
            case "fp": value = _x[29]; return true;
            case "xzr" or "wzr": return true;
        }
        if (n.Length > 1 && n[0] is 'x' or 'w' && int.TryParse(n[1..], out int r) && r is >= 0 and <= 30)
        {
            value = n[0] == 'w' ? _x[r] & 0xFFFFFFFF : _x[r];
            return true;
        }
        return false;
    }

    public bool TrySet(string name, ulong value)
    {
        var n = name.Trim().ToLowerInvariant();
        switch (n)
        {
            case "sp": _sp = value; return true;
            case "pc": Pc = value; return true;
            case "lr": _x[30] = value; return true;
            case "fp": _x[29] = value; return true;
        }
        if (n.Length > 1 && n[0] is 'x' or 'w' && int.TryParse(n[1..], out int r) && r is >= 0 and <= 30)
        {
            _x[r] = n[0] == 'w' ? value & 0xFFFFFFFF : value;
            return true;
        }
        return false;
    }

    public void SetReturnAddress(EmulatorMemory memory, ulong sentinel) => _x[30] = sentinel;

    public void ReturnFromCall(EmulatorMemory memory, ulong value, int purge)
    {
        _x[0] = value;
        Pc = _x[30];
    }

    public IReadOnlyList<ArgumentSlot> Arguments(int count) =>
        [.. Enumerable.Range(0, count).Select(i => i < 8 ? new ArgumentSlot($"x{i}", 0) : new ArgumentSlot(null, (i - 8) * 8))];

    // ---- registers ----

    // Register 31 is the zero register in data operands and the stack pointer in address and some arithmetic operands.
    private ulong X(int r, bool sf) => r == 31 ? 0 : sf ? _x[r] : _x[r] & 0xFFFFFFFF;

    private ulong XSp(int r, bool sf) => r == 31 ? sf ? _sp : _sp & 0xFFFFFFFF : X(r, sf);

    private void SetX(int r, ulong v, bool sf)
    {
        if (r != 31) _x[r] = sf ? v : v & 0xFFFFFFFF;
    }

    private void SetXSp(int r, ulong v, bool sf)
    {
        if (r == 31) _sp = sf ? v : v & 0xFFFFFFFF; else SetX(r, v, sf);
    }

    private static ulong Mask(bool sf) => sf ? ulong.MaxValue : 0xFFFFFFFF;

    private static uint Bits(uint w, int lo, int n) => w >> lo & (uint)((1UL << n) - 1);

    private static long SignExtend(ulong v, int bits) => (long)(v << (64 - bits)) >> (64 - bits);

    // ---- flags ----

    private ulong AddWithCarry(ulong a, ulong b, bool carry, bool sf, bool setFlags)
    {
        ulong mask = Mask(sf);
        a &= mask;
        b &= mask;
        UInt128 wide = (UInt128)a + b + (carry ? 1UL : 0);
        ulong r = (ulong)wide & mask;
        if (setFlags)
        {
            int top = sf ? 63 : 31;
            _n = (r >> top & 1) != 0;
            _z = r == 0;
            _c = sf ? wide > ulong.MaxValue : (ulong)wide > mask;
            _vf = ((~(a ^ b) & (a ^ r)) >> top & 1) != 0;
        }
        return r;
    }

    private void LogicFlags(ulong r, bool sf)
    {
        _n = (r >> (sf ? 63 : 31) & 1) != 0;
        _z = (r & Mask(sf)) == 0;
        _c = _vf = false;
    }

    private bool Condition(uint cond)
    {
        bool r = (cond >> 1) switch
        {
            0 => _z,
            1 => _c,
            2 => _n,
            3 => _vf,
            4 => _c && !_z,
            5 => _n == _vf,
            6 => _n == _vf && !_z,
            _ => true,
        };
        return (cond & 1) != 0 && cond != 15 ? !r : r;
    }

    private static ulong Shift(ulong v, uint type, int amount, bool sf)
    {
        int bits = sf ? 64 : 32;
        v &= Mask(sf);
        amount %= bits;
        return type switch
        {
            0 => v << amount & Mask(sf),
            1 => v >> amount,
            2 => (ulong)((sf ? (long)v : (int)v) >> amount) & Mask(sf),
            _ => amount == 0 ? v : (v >> amount | v << (bits - amount)) & Mask(sf),
        };
    }

    private static ulong Extend(ulong v, uint option, int shift)
    {
        ulong e = option switch
        {
            0 => v & 0xFF,
            1 => v & 0xFFFF,
            2 => v & 0xFFFFFFFF,
            3 => v,
            4 => (ulong)(sbyte)v,
            5 => (ulong)(short)v,
            6 => (ulong)(int)v,
            _ => v,
        };
        return e << shift;
    }

    /// <summary>The bitmask immediate of a logical instruction (the architecture's DecodeBitMasks); null for a reserved encoding.</summary>
    private static (ulong WMask, ulong TMask)? BitMasks(uint n, uint imms, uint immr, bool logical, int width)
    {
        int len = 31 - BitOperations.LeadingZeroCount(n << 6 | (~imms & 0x3F));
        if (len < 1) return null;
        int levels = (1 << len) - 1;
        if (logical && (imms & levels) == levels) return null;
        int s = (int)(imms & levels), r = (int)(immr & levels), d = (s - r) & levels, esize = 1 << len;
        ulong welem = s + 1 >= 64 ? ulong.MaxValue : (1UL << (s + 1)) - 1, telem = d + 1 >= 64 ? ulong.MaxValue : (1UL << (d + 1)) - 1;
        ulong emask = esize == 64 ? ulong.MaxValue : (1UL << esize) - 1;
        ulong ror = r == 0 ? welem : ((welem >> r) | (welem << (esize - r))) & emask;
        ulong w = 0, t = 0;
        for (int i = 0; i < width; i += esize)
        {
            w |= ror << i;
            t |= telem << i;
        }
        ulong wm = width == 64 ? ulong.MaxValue : (1UL << width) - 1;
        return (w & wm, t & wm);
    }

    // ---- execution ----

    public EmulatorStep Step(EmulatorMemory m)
    {
        _at = Pc;
        if ((Pc & 3) != 0) throw new EmulatorUnsupportedException($"execution at 0x{Pc:x}, which is not 4-byte aligned");
        _word = (uint)m.ReadUInt(Pc, 4);
        uint w = _word;
        ulong next = Pc + 4;
        Pc = next;
        bool sf = (w >> 31) != 0;
        int rd = (int)(w & 31), rn = (int)Bits(w, 5, 5), rm = (int)Bits(w, 16, 5);

        // Hints (NOP, YIELD, PACIASP, AUTIASP, BTI) and barriers have no effect on one emulated thread.
        if ((w & 0xFFFFF01F) == 0xD503201F || (w & 0xFFFFF01F) == 0xD503301F) return new(false, _at, next);
        // Branches.
        if ((w & 0x7C000000) == 0x14000000)
        {
            ulong target = (ulong)((long)_at + SignExtend(w & 0x3FFFFFF, 26) * 4);
            bool link = (w >> 31) != 0;
            if (link) _x[30] = next;
            Pc = target;
            return new(link, _at, next);
        }
        if ((w & 0xFF000010) == 0x54000000)
        {
            if (Condition(w & 15)) Pc = (ulong)((long)_at + SignExtend(Bits(w, 5, 19), 19) * 4);
            return new(false, _at, next);
        }
        if ((w & 0x7E000000) == 0x34000000)
        {
            bool nonZero = (w >> 24 & 1) != 0;
            if (X(rd, sf) == 0 != nonZero) Pc = (ulong)((long)_at + SignExtend(Bits(w, 5, 19), 19) * 4);
            return new(false, _at, next);
        }
        if ((w & 0x7E000000) == 0x36000000)
        {
            int bit = (int)((w >> 31) << 5 | Bits(w, 19, 5));
            bool set = (X(rd, true) >> bit & 1) != 0, nonZero = (w >> 24 & 1) != 0;
            if (set == nonZero) Pc = (ulong)((long)_at + SignExtend(Bits(w, 5, 14), 14) * 4);
            return new(false, _at, next);
        }
        if ((w & 0xFE000000) == 0xD6000000)
        {
            // BR, BLR, RET and their pointer-authenticated forms (the authentication is not modelled; the target is used as is).
            uint opc = Bits(w, 21, 4);
            ulong target = X(rn, true);
            if (opc == 0 || opc == 8) { Pc = target; return new(false, _at, next); }
            if (opc == 1 || opc == 9) { _x[30] = next; Pc = target; return new(true, _at, next); }
            if (opc == 2) { Pc = (w & 0xFFFFFBFF) == 0xD65F0BFF ? _x[30] : target; return new(false, _at, next); }
            throw Unsupported();
        }

        // MOVI Vd, #0 (bytes or doublewords), as compilers emit before vector stores of zero.
        if ((w & 0x9FF8FC00) == 0x0F00E400 && Bits(w, 5, 5) == 0 && Bits(w, 16, 3) == 0)
        {
            _v[rd] = (0, 0);
            return new(false, _at, next);
        }
        uint op0 = Bits(w, 25, 4);
        if ((op0 & 0b1110) == 0b1000) DataImmediate(w, sf, rd, rn);
        else if ((op0 & 0b0111) == 0b0101) DataRegister(w, sf, rd, rn, rm);
        else if ((op0 & 0b0101) == 0b0100) LoadStore(m, w, rd, rn, rm);
        else if ((op0 & 0b0111) == 0b0111) VectorInteger(w, rd, rn);
        else throw Unsupported();
        return new(false, _at, next);
    }

    private EmulatorUnsupportedException Unsupported() =>
        new($"{LastText} (0x{_word:x8}) at 0x{_at:x}: the instruction is not modelled");

    private void DataImmediate(uint w, bool sf, int rd, int rn)
    {
        switch (Bits(w, 23, 6) & 0b111111)
        {
            case 0b100000 or 0b100001:
            {
                // ADR, ADRP.
                long imm = SignExtend(Bits(w, 5, 19) << 2 | Bits(w, 29, 2), 21);
                SetX(rd, (w >> 31) != 0 ? (ulong)((long)(_at & ~0xFFFUL) + (imm << 12)) : (ulong)((long)_at + imm), true);
                return;
            }
            case 0b100010:
            {
                bool sub = (w >> 30 & 1) != 0, flags = (w >> 29 & 1) != 0;
                ulong imm = (ulong)Bits(w, 10, 12) << (Bits(w, 22, 1) != 0 ? 12 : 0);
                ulong a = XSp(rn, sf);
                ulong r = sub ? AddWithCarry(a, ~imm, true, sf, flags) : AddWithCarry(a, imm, false, sf, flags);
                if (flags) SetX(rd, r, sf); else SetXSp(rd, r, sf);
                return;
            }
            case 0b100100:
            {
                uint opc = Bits(w, 29, 2);
                if (!sf && Bits(w, 22, 1) != 0) throw Unsupported();
                var masks = BitMasks(Bits(w, 22, 1), Bits(w, 10, 6), Bits(w, 16, 6), true, sf ? 64 : 32) ?? throw Unsupported();
                ulong a = X(rn, sf);
                ulong r = opc switch { 0 or 3 => a & masks.WMask, 1 => a | masks.WMask, _ => a ^ masks.WMask };
                if (opc == 3) { LogicFlags(r, sf); SetX(rd, r, sf); }
                else SetXSp(rd, r, sf);
                return;
            }
            case 0b100101:
            {
                uint opc = Bits(w, 29, 2);
                int hw = (int)Bits(w, 21, 2) * 16;
                ulong imm = (ulong)Bits(w, 5, 16) << hw;
                switch (opc)
                {
                    case 0: SetX(rd, ~imm, sf); return;
                    case 2: SetX(rd, imm, sf); return;
                    case 3: SetX(rd, X(rd, sf) & ~(0xFFFFUL << hw) | imm, sf); return;
                    default: throw Unsupported();
                }
            }
            case 0b100110:
            {
                uint opc = Bits(w, 29, 2);
                int width = sf ? 64 : 32;
                int r = (int)Bits(w, 16, 6), s = (int)Bits(w, 10, 6);
                var masks = BitMasks(Bits(w, 22, 1), (uint)s, (uint)r, false, width) ?? throw Unsupported();
                ulong src = X(rn, sf);
                ulong rot = Shift(src, 3, r, sf);
                ulong dst = opc == 1 ? X(rd, sf) : 0;
                ulong bot = (dst & ~masks.WMask) | (rot & masks.WMask);
                ulong top = opc == 0 ? ((src >> s & 1) != 0 ? Mask(sf) : 0) : dst;
                if (opc == 2) top = 0;
                if (opc == 3) throw Unsupported();
                SetX(rd, ((top & ~masks.TMask) | (bot & masks.TMask)) & Mask(sf), sf);
                return;
            }
            case 0b100111:
            {
                // EXTR (ROR by an immediate when both sources are one register).
                int lsb = (int)Bits(w, 10, 6), rm = (int)Bits(w, 16, 5);
                int width = sf ? 64 : 32;
                UInt128 joined = (UInt128)X(rn, sf) << width | X(rm, sf);
                SetX(rd, (ulong)(joined >> lsb) & Mask(sf), sf);
                return;
            }
            default: throw Unsupported();
        }
    }

    private void DataRegister(uint w, bool sf, int rd, int rn, int rm)
    {
        if ((w & 0x1F000000) == 0x0A000000)
        {
            // Logical, shifted register.
            uint opc = Bits(w, 29, 2);
            bool invert = (w >> 21 & 1) != 0;
            int amount = (int)Bits(w, 10, 6);
            if (!sf && amount > 31) throw Unsupported();
            ulong b = Shift(X(rm, sf), Bits(w, 22, 2), amount, sf);
            if (invert) b = ~b & Mask(sf);
            ulong a = X(rn, sf);
            ulong r = opc switch { 0 or 3 => a & b, 1 => a | b, _ => a ^ b };
            if (opc == 3) LogicFlags(r, sf);
            SetX(rd, r, sf);
            return;
        }
        if ((w & 0x1F000000) == 0x0B000000)
        {
            bool sub = (w >> 30 & 1) != 0, flags = (w >> 29 & 1) != 0;
            ulong a, b;
            if ((w >> 21 & 1) == 0)
            {
                // Shifted register: register 31 is the zero register.
                if (Bits(w, 22, 2) == 3) throw Unsupported();
                a = X(rn, sf);
                b = Shift(X(rm, sf), Bits(w, 22, 2), (int)Bits(w, 10, 6), sf);
            }
            else
            {
                // Extended register: Rn and a non-flag-setting Rd may be the stack pointer.
                a = XSp(rn, sf);
                b = Extend(X(rm, true), Bits(w, 13, 3), (int)Bits(w, 10, 3)) & Mask(sf);
            }
            ulong r = sub ? AddWithCarry(a, ~b, true, sf, flags) : AddWithCarry(a, b, false, sf, flags);
            if ((w >> 21 & 1) != 0 && !flags) SetXSp(rd, r, sf); else SetX(rd, r, sf);
            return;
        }
        switch (Bits(w, 21, 8))
        {
            case 0b11010000:
            {
                // ADC, ADCS, SBC, SBCS.
                bool sub = (w >> 30 & 1) != 0, flags = (w >> 29 & 1) != 0;
                ulong b = X(rm, sf);
                SetX(rd, AddWithCarry(X(rn, sf), sub ? ~b : b, _c, sf, flags), sf);
                return;
            }
            case 0b11010010:
            {
                // CCMN, CCMP (register or immediate).
                bool sub = (w >> 30 & 1) != 0;
                ulong b = (w >> 11 & 1) != 0 ? (ulong)rm : X(rm, sf);
                if (Condition(Bits(w, 12, 4))) AddWithCarry(X(rn, sf), sub ? ~b : b, sub, sf, true);
                else
                {
                    uint nzcv = w & 15;
                    _n = (nzcv & 8) != 0; _z = (nzcv & 4) != 0; _c = (nzcv & 2) != 0; _vf = (nzcv & 1) != 0;
                }
                return;
            }
            case 0b11010100:
            {
                // CSEL, CSINC, CSINV, CSNEG.
                uint op = Bits(w, 30, 1) << 1 | Bits(w, 10, 2);
                ulong r = Condition(Bits(w, 12, 4)) ? X(rn, sf) : op switch
                {
                    0 => X(rm, sf),
                    1 => X(rm, sf) + 1,
                    2 => ~X(rm, sf),
                    3 => (ulong)-(long)X(rm, sf),
                    _ => throw Unsupported(),
                };
                SetX(rd, r & Mask(sf), sf);
                return;
            }
            case 0b11010110:
                if ((w >> 30 & 1) == 0) TwoSource(w, sf, rd, rn, rm); else OneSource(w, sf, rd, rn);
                return;
        }
        if ((w & 0x1F000000) == 0x1B000000) { ThreeSource(w, sf, rd, rn, rm); return; }
        throw Unsupported();
    }

    private void TwoSource(uint w, bool sf, int rd, int rn, int rm)
    {
        ulong a = X(rn, sf), b = X(rm, sf);
        int bits = sf ? 64 : 32;
        ulong r = Bits(w, 10, 6) switch
        {
            // Division by zero gives zero on ARM64.
            2 => b == 0 ? 0 : a / b,
            3 => b == 0 ? 0 : sf ? (ulong)((long)a == long.MinValue && (long)b == -1 ? long.MinValue : (long)a / (long)b)
                : (ulong)(uint)((int)a == int.MinValue && (int)b == -1 ? int.MinValue : (int)a / (int)b),
            8 => Shift(a, 0, (int)(b % (ulong)bits), sf),
            9 => Shift(a, 1, (int)(b % (ulong)bits), sf),
            10 => Shift(a, 2, (int)(b % (ulong)bits), sf),
            11 => Shift(a, 3, (int)(b % (ulong)bits), sf),
            _ => throw Unsupported(),
        };
        SetX(rd, r, sf);
    }

    private void OneSource(uint w, bool sf, int rd, int rn)
    {
        ulong a = X(rn, sf);
        ulong r = Bits(w, 10, 6) switch
        {
            0 => sf ? ReverseBits(a) : ReverseBits(a) >> 32,
            1 => sf ? Swap16(a) : Swap16(a) & 0xFFFFFFFF,
            2 => sf ? Swap32(a) : System.Buffers.Binary.BinaryPrimitives.ReverseEndianness((uint)a),
            3 when sf => System.Buffers.Binary.BinaryPrimitives.ReverseEndianness(a),
            4 => (ulong)(sf ? BitOperations.LeadingZeroCount(a) : BitOperations.LeadingZeroCount((uint)a)),
            5 => (ulong)(sf ? Math.Max(0, BitOperations.LeadingZeroCount(a ^ (ulong)((long)a >> 63)) - 1)
                : Math.Max(0, BitOperations.LeadingZeroCount((uint)(a ^ (ulong)((int)a >> 31))) - 1)),
            _ => throw Unsupported(),
        };
        SetX(rd, r, sf);

        static ulong ReverseBits(ulong v)
        {
            ulong r = 0;
            for (int i = 0; i < 64; i++) r |= (v >> i & 1) << (63 - i);
            return r;
        }
        static ulong Swap16(ulong v) => (v & 0x00FF00FF00FF00FF) << 8 | (v >> 8 & 0x00FF00FF00FF00FF);
        static ulong Swap32(ulong v) =>
            (ulong)System.Buffers.Binary.BinaryPrimitives.ReverseEndianness((uint)v) | (ulong)System.Buffers.Binary.BinaryPrimitives.ReverseEndianness((uint)(v >> 32)) << 32;
    }

    private void ThreeSource(uint w, bool sf, int rd, int rn, int rm)
    {
        int ra = (int)Bits(w, 10, 5);
        bool o0 = (w >> 15 & 1) != 0;
        ulong a = X(rn, true), b = X(rm, true), acc = X(ra, true);
        ulong r = Bits(w, 21, 3) switch
        {
            0 => o0 ? acc - a * b : acc + a * b,
            1 => o0 ? acc - (ulong)((long)(int)a * (int)b) : acc + (ulong)((long)(int)a * (int)b),
            2 => (ulong)((Int128)(long)a * (long)b >> 64),
            5 => o0 ? acc - (a & 0xFFFFFFFF) * (b & 0xFFFFFFFF) : acc + (a & 0xFFFFFFFF) * (b & 0xFFFFFFFF),
            6 => (ulong)((UInt128)a * b >> 64),
            _ => throw Unsupported(),
        };
        SetX(rd, r, sf || Bits(w, 21, 3) != 0);
    }

    private void LoadStore(EmulatorMemory m, uint w, int rt, int rn, int rm)
    {
        bool vector = (w >> 26 & 1) != 0;
        // Load register (literal).
        if ((w & 0x3B000000) == 0x18000000)
        {
            ulong at = (ulong)((long)_at + SignExtend(Bits(w, 5, 19), 19) * 4);
            uint opc = w >> 30;
            if (vector) { LoadVector(m, at, opc switch { 0 => 4, 1 => 8, 2 => 16, _ => throw Unsupported() }, rt); return; }
            switch (opc)
            {
                case 0: SetX(rt, m.ReadUInt(at, 4), true); return;
                case 1: SetX(rt, m.ReadUInt(at, 8), true); return;
                case 2: SetX(rt, (ulong)(int)m.ReadUInt(at, 4), true); return;
                default: return; // PRFM
            }
        }
        // Load/store pair.
        if ((w & 0x3A000000) == 0x28000000)
        {
            uint opc = w >> 30, mode = Bits(w, 23, 2);
            bool load = (w >> 22 & 1) != 0;
            int size = vector ? 4 << (int)opc : opc == 2 ? 8 : 4;
            if (!vector && opc == 3) throw Unsupported();
            int rt2 = (int)Bits(w, 10, 5);
            long offset = SignExtend(Bits(w, 15, 7), 7) * size;
            ulong baseAddr = XSp(rn, true);
            ulong at = mode == 1 ? baseAddr : (ulong)((long)baseAddr + offset);
            if (vector)
            {
                if (load) { LoadVector(m, at, size, rt); LoadVector(m, at + (ulong)size, size, rt2); }
                else { StoreVector(m, at, size, rt); StoreVector(m, at + (ulong)size, size, rt2); }
            }
            else if (load)
            {
                bool signed = opc == 1;
                ulong a = m.ReadUInt(at, size), b = m.ReadUInt(at + (ulong)size, size);
                SetX(rt, signed ? (ulong)(int)a : a, true);
                SetX(rt2, signed ? (ulong)(int)b : b, true);
            }
            else
            {
                m.WriteUInt(at, X(rt, true), size);
                m.WriteUInt(at + (ulong)size, X(rt2, true), size);
            }
            if (mode is 1 or 3) SetXSp(rn, (ulong)((long)baseAddr + offset), true);
            return;
        }
        // Load/store exclusive and acquire/release: one thread, so an exclusive store always succeeds.
        if ((w & 0x3F000000) == 0x08000000 && !vector)
        {
            int size = 1 << (int)(w >> 30);
            bool load = (w >> 22 & 1) != 0, pair = (w >> 21 & 1) != 0, exclusive = (w >> 23 & 1) == 0;
            if (pair) throw Unsupported();
            ulong at = XSp(rn, true);
            if (load) SetX(rt, m.ReadUInt(at, size), true);
            else
            {
                m.WriteUInt(at, X(rt, true), size);
                if (exclusive) SetX(rm, 0, false);
            }
            return;
        }
        // Load/store register: unsigned offset, register offset, immediate pre/post-index and unscaled.
        if ((w & 0x3B000000) == 0x39000000 || (w & 0x3B200000) == 0x38000000 || (w & 0x3B200C00) == 0x38200800)
        {
            uint size = w >> 30, opc = Bits(w, 22, 2);
            int bytes = vector ? (opc >= 2 && size == 0 ? 16 : 1 << (int)size) : 1 << (int)size;
            ulong baseAddr = XSp(rn, true), at;
            bool writeBack = false;
            long wbValue = 0;
            if ((w & 0x3B000000) == 0x39000000) at = baseAddr + Bits(w, 10, 12) * (ulong)bytes;
            else if ((w & 0x00200000) != 0)
            {
                uint option = Bits(w, 13, 3);
                bool scaled = (w >> 12 & 1) != 0;
                at = baseAddr + Extend(X(rm, true), option, scaled ? BitOperations.Log2((uint)bytes) : 0);
            }
            else
            {
                long imm = SignExtend(Bits(w, 12, 9), 9);
                uint mode = Bits(w, 10, 2);
                at = mode == 1 ? baseAddr : (ulong)((long)baseAddr + imm);
                if (mode is 1 or 3) { writeBack = true; wbValue = (long)baseAddr + imm; }
            }
            if (vector)
            {
                if ((opc & 1) != 0) LoadVector(m, at, bytes, rt); else StoreVector(m, at, bytes, rt);
            }
            else
            {
                switch (opc)
                {
                    case 0: m.WriteUInt(at, X(rt, true), bytes); break;
                    case 1: SetX(rt, m.ReadUInt(at, bytes), true); break;
                    case 2 when size == 3: break; // PRFM
                    case 2: SetX(rt, (ulong)SignExtend(m.ReadUInt(at, bytes), bytes * 8), true); break;
                    default:
                        if (size >= 2) throw Unsupported();
                        SetX(rt, (ulong)SignExtend(m.ReadUInt(at, bytes), bytes * 8) & 0xFFFFFFFF, true);
                        break;
                }
            }
            if (writeBack) SetXSp(rn, (ulong)wbValue, true);
            return;
        }
        throw Unsupported();
    }

    // FMOV between general and vector registers, and CNT, ADDV and UADDLV: the population count compilers emit.
    private void VectorInteger(uint w, int rd, int rn)
    {
        switch (w & 0xFFFFFC00)
        {
            case 0x1E270000: _v[rd] = (X(rn, false), 0); return;
            case 0x9E670000: _v[rd] = (X(rn, true), 0); return;
            case 0x1E260000: SetX(rd, _v[rn].Lo & 0xFFFFFFFF, false); return;
            case 0x9E660000: SetX(rd, _v[rn].Lo, true); return;
        }
        int bytes = (w >> 30 & 1) != 0 ? 16 : 8;
        Span<byte> v = stackalloc byte[16];
        System.Buffers.Binary.BinaryPrimitives.WriteUInt64LittleEndian(v, _v[rn].Lo);
        System.Buffers.Binary.BinaryPrimitives.WriteUInt64LittleEndian(v[8..], _v[rn].Hi);
        if ((w & 0xBFFFFC00) == 0x0E205800)
        {
            for (int i = 0; i < 16; i++) v[i] = i < bytes ? (byte)BitOperations.PopCount(v[i]) : (byte)0;
            _v[rd] = (System.Buffers.Binary.BinaryPrimitives.ReadUInt64LittleEndian(v), System.Buffers.Binary.BinaryPrimitives.ReadUInt64LittleEndian(v[8..]));
            return;
        }
        bool widen = (w & 0xBF3FFC00) == 0x2E303800;
        if (!widen && (w & 0xBF3FFC00) != 0x0E31B800) throw Unsupported();
        int esize = 1 << (int)Bits(w, 22, 2);
        if (esize == 8) throw Unsupported();
        ulong sum = 0;
        for (int i = 0; i < bytes; i += esize)
        {
            ulong e = 0;
            for (int k = esize - 1; k >= 0; k--) e = e << 8 | v[i + k];
            sum += e;
        }
        int resultBits = esize * 8 * (widen ? 2 : 1);
        _v[rd] = (resultBits == 64 ? sum : sum & ((1UL << resultBits) - 1), 0);
    }

    private void LoadVector(EmulatorMemory m, ulong at, int size, int v)
    {
        if (size == 16) _v[v] = (m.ReadUInt(at, 8), m.ReadUInt(at + 8, 8));
        else _v[v] = (m.ReadUInt(at, size), 0);
    }

    private void StoreVector(EmulatorMemory m, ulong at, int size, int v)
    {
        if (size == 16)
        {
            m.WriteUInt(at, _v[v].Lo, 8);
            m.WriteUInt(at + 8, _v[v].Hi, 8);
        }
        else m.WriteUInt(at, _v[v].Lo, size);
    }
}
