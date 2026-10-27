namespace Corvus.Services.Simplify;

// Caller registers other than esp and unwritten stack memory are unknown; a result that depends on one declines.
/// <summary>Runs 32-bit x86 native method bodies limited to <see cref="Subset"/> on concrete arguments; returns eax or throws <see cref="Declined"/>.</summary>
internal sealed class NativeRoutine
{
    /// <summary>Why the code is outside the subset; the message names the offset and the instruction.</summary>
    public sealed class Declined(string message) : Exception(message);

    /// <summary>The instructions run, for the manifest.</summary>
    public const string Subset =
        "mov, lea, add, adc, sub, sbb, and, or, xor, cmp, test, inc, dec, neg, not, imul (two and three operands), shl, shr, sar, rol, ror, " +
        "cdq, push, pop, nop, jmp, jcc (all but the parity conditions) and ret, with 32-bit register, immediate and [base + index * scale + disp] " +
        "operands; no operand-size or segment prefixes, no 8- or 16-bit forms, no mul / div, no calls";

    public const int MaxCodeBytes = 4096;
    private const int FrameBytes = 4096;
    // Esp at entry, pointing at the return address.
    private const uint Top = 0x0010_0000;

    private const int Eax = 0, Ecx = 1, Edx = 2, Esp = 4;

    private readonly byte[] _code;
    private readonly int _arguments;
    private readonly Action _tick;
    private readonly uint?[] _r = new uint?[8];
    private readonly Dictionary<uint, byte> _memory = new();
    private bool? _cf, _zf, _sf, _of;
    private int _pc, _start;

    private NativeRoutine(byte[] code, int arguments, Action tick)
    {
        _code = code;
        _arguments = arguments;
        _tick = tick;
    }

    /// <summary>Runs the routine from its first byte, calling <paramref name="tick"/> once per instruction.</summary>
    public static int Run(byte[] code, int[] args, Action tick)
    {
        var routine = new NativeRoutine(code, args.Length, tick);
        routine._r[Esp] = Top;
        for (int i = 0; i < args.Length; i++) routine.Write(Top + 4 + 4 * (uint)i, (uint)args[i]);
        return routine.Execute();
    }

    private int Execute()
    {
        while (true)
        {
            _tick();
            _start = _pc;
            byte op = Fetch();
            switch (op)
            {
                case 0x90: break;
                case >= 0x00 and <= 0x3F when (op & 7) < 6 && op is not (0x26 or 0x2E or 0x36 or 0x3E or 0x27 or 0x2F or 0x37 or 0x3F):
                    Arithmetic(op);
                    break;
                case >= 0x40 and <= 0x47: Set(op & 7, Inc(Get(op & 7), +1)); break;
                case >= 0x48 and <= 0x4F: Set(op & 7, Inc(Get(op & 7), -1)); break;
                case >= 0x50 and <= 0x57: Push(Get(op & 7)); break;
                case >= 0x58 and <= 0x5F: Set(op & 7, Pop()); break;
                case 0x68: Push(Imm32()); break;
                case 0x6A: Push((uint)(sbyte)Fetch()); break;
                case 0x69 or 0x6B:
                {
                    var m = ModRm();
                    uint? a = Load(m);
                    uint b = op == 0x69 ? Imm32() : (uint)(sbyte)Fetch();
                    Set(m.Reg, Imul(a, b));
                    break;
                }
                case >= 0x70 and <= 0x7F:
                {
                    int rel = (sbyte)Fetch();
                    if (Condition(op & 0xF)) Jump(rel);
                    break;
                }
                case 0x81 or 0x83:
                {
                    var m = ModRm();
                    uint b = op == 0x81 ? Imm32() : (uint)(sbyte)Fetch();
                    var r = Alu(m.Reg, Load(m), b);
                    if (m.Reg != 7) Store(m, r);
                    break;
                }
                case 0x85:
                {
                    var m = ModRm();
                    Logic(And(Load(m), Get(m.Reg)));
                    break;
                }
                case 0x89: { var m = ModRm(); Store(m, Get(m.Reg)); break; }
                case 0x8B: { var m = ModRm(); Set(m.Reg, Load(m)); break; }
                case 0x8D:
                {
                    var m = ModRm();
                    if (m.Register) throw Decline("lea with a register operand");
                    Set(m.Reg, m.Address);
                    break;
                }
                case 0x99: Set(Edx, Get(Eax) is { } eax ? ((int)eax < 0 ? uint.MaxValue : 0) : null); break;
                case 0xA9: Logic(And(Get(Eax), Imm32())); break;
                case >= 0xB8 and <= 0xBF: Set(op & 7, Imm32()); break;
                case 0xC1 or 0xD1 or 0xD3:
                {
                    var m = ModRm();
                    uint? count = op == 0xC1 ? Fetch() : op == 0xD1 ? 1 : Get(Ecx);
                    Store(m, Shift(m.Reg, Load(m), count));
                    break;
                }
                case 0xC2 or 0xC3:
                    if (op == 0xC2) { Fetch(); Fetch(); }
                    if (_r[Esp] != Top) throw Decline("returns with esp not at the return address");
                    return Get(Eax) is { } result ? (int)result : throw Decline("returns a value that depends on registers or memory the caller left");
                case 0xC7:
                {
                    var m = ModRm();
                    if (m.Reg != 0) throw Unsupported(op);
                    Store(m, Imm32());
                    break;
                }
                case 0xE9: Jump((int)Imm32()); break;
                case 0xEB: Jump((sbyte)Fetch()); break;
                case 0xF7:
                {
                    var m = ModRm();
                    switch (m.Reg)
                    {
                        case 0: Logic(And(Load(m), Imm32())); break;
                        case 2: Store(m, Load(m) is { } v ? ~v : null); break;
                        case 3: Store(m, Sub(0, Load(m), carry: false)); _cf = Load(m) is { } n ? n != 0 : null; break;
                        default: throw Unsupported(op, m.Reg);
                    }
                    break;
                }
                case 0xFF:
                {
                    var m = ModRm();
                    switch (m.Reg)
                    {
                        case 0: Store(m, Inc(Load(m), +1)); break;
                        case 1: Store(m, Inc(Load(m), -1)); break;
                        case 6: Push(Load(m)); break;
                        default: throw Unsupported(op, m.Reg);
                    }
                    break;
                }
                case 0x0F:
                {
                    byte op2 = Fetch();
                    if (op2 == 0xAF)
                    {
                        var m = ModRm();
                        Set(m.Reg, Imul(Get(m.Reg), Load(m)));
                    }
                    else if (op2 is >= 0x80 and <= 0x8F)
                    {
                        int rel = (int)Imm32();
                        if (Condition(op2 & 0xF)) Jump(rel);
                    }
                    else throw Decline($"unsupported instruction 0F {op2:X2}");
                    break;
                }
                default: throw Unsupported(op);
            }
        }
    }

    /// <summary>Decodes the two-operand ALU forms op r/m, r; op r, r/m; and op eax, imm32.</summary>
    private void Arithmetic(byte op)
    {
        int kind = op >> 3;
        switch (op & 7)
        {
            case 1:
            {
                var m = ModRm();
                var r = Alu(kind, Load(m), Get(m.Reg), same: m.Register && m.Rm == m.Reg);
                if (kind != 7) Store(m, r);
                break;
            }
            case 3:
            {
                var m = ModRm();
                var r = Alu(kind, Get(m.Reg), Load(m), same: m.Register && m.Rm == m.Reg);
                if (kind != 7) Set(m.Reg, r);
                break;
            }
            case 5:
            {
                var r = Alu(kind, Get(Eax), Imm32());
                if (kind != 7) Set(Eax, r);
                break;
            }
            default: throw Unsupported(op);
        }
    }

    /// <summary>Runs ALU operation <paramref name="kind"/> (the 81 / 83 reg field) and sets the flags.</summary>
    private uint? Alu(int kind, uint? a, uint? b, bool same = false)
    {
        // xor r, r and sub r, r give 0 whatever the register held.
        if (same && kind is 5 or 6) { a = 0; b = 0; }
        switch (kind)
        {
            case 0: return Add(a, b, carry: false);
            case 2: return Add(a, b, carry: true);
            case 3: return Sub(a, b, carry: true);
            case 5 or 7: return Sub(a, b, carry: false);
            case 1: return Logic(a is { } x && b is { } y ? x | y : null);
            case 4: return Logic(And(a, b));
            case 6: return Logic(a is { } p && b is { } q ? p ^ q : null);
            default: throw Decline($"unsupported ALU operation {kind}");
        }
    }

    private static uint? And(uint? a, uint? b) => a is { } x && b is { } y ? x & y : a == 0 || b == 0 ? 0 : null;

    private uint? Add(uint? a, uint? b, bool carry)
    {
        bool? cin = carry ? _cf : false;
        if (a is not { } x || b is not { } y || cin is not { } c) return Unknown();
        ulong wide = (ulong)x + y + (c ? 1u : 0u);
        uint r = (uint)wide;
        _cf = wide > uint.MaxValue;
        _of = ((x ^ r) & (y ^ r) & 0x8000_0000) != 0;
        return Result(r);
    }

    private uint? Sub(uint? a, uint? b, bool carry)
    {
        bool? bin = carry ? _cf : false;
        if (a is not { } x || b is not { } y || bin is not { } c) return Unknown();
        ulong subtrahend = (ulong)y + (c ? 1u : 0u);
        uint r = (uint)(x - subtrahend);
        _cf = x < subtrahend;
        _of = ((x ^ y) & (x ^ r) & 0x8000_0000) != 0;
        return Result(r);
    }

    private uint? Logic(uint? r)
    {
        if (r is not { } v) return Unknown();
        _cf = false;
        _of = false;
        return Result(v);
    }

    /// <summary>Runs inc or dec: add or sub 1 with carry unchanged.</summary>
    private uint? Inc(uint? a, int delta)
    {
        bool? cf = _cf;
        var r = delta > 0 ? Add(a, 1, carry: false) : Sub(a, 1, carry: false);
        _cf = cf;
        return r;
    }

    /// <summary>Returns the low 32 bits of the signed product; carry and overflow report truncation.</summary>
    private uint? Imul(uint? a, uint? b)
    {
        if (a is not { } x || b is not { } y) return Unknown();
        long wide = (long)(int)x * (int)y;
        _cf = _of = wide != (int)wide;
        // Zero and sign are undefined after imul.
        _zf = _sf = null;
        return (uint)wide;
    }

    private uint? Shift(int kind, uint? a, uint? count)
    {
        if (count is not { } c) return Unknown();
        int n = (int)(c & 31);
        // A zero count leaves the flags unchanged.
        if (n == 0) return a;
        if (a is not { } x) return Unknown();
        uint r;
        switch (kind)
        {
            case 0: r = (x << n) | (x >> (32 - n)); _cf = (r & 1) != 0; break;
            case 1: r = (x >> n) | (x << (32 - n)); _cf = (r & 0x8000_0000) != 0; break;
            case 4 or 6: r = x << n; _cf = ((x >> (32 - n)) & 1) != 0; break;
            case 5: r = x >> n; _cf = ((x >> (n - 1)) & 1) != 0; break;
            case 7: r = (uint)((int)x >> n); _cf = (((int)x >> (n - 1)) & 1) != 0; break;
            default: throw Decline($"unsupported shift or rotate {kind}");
        }
        // Overflow is defined for single-bit shifts only; the subset never reads it after one.
        _of = null;
        // Rotates leave zero and sign alone.
        if (kind is 0 or 1) return r;
        return Result(r);
    }

    private uint Result(uint r)
    {
        _zf = r == 0;
        _sf = (r & 0x8000_0000) != 0;
        return r;
    }

    private uint? Unknown()
    {
        _cf = _zf = _sf = _of = null;
        return null;
    }

    private bool Condition(int cc)
    {
        bool? taken = (cc >> 1) switch
        {
            0 => _of,
            1 => _cf,
            2 => _zf,
            3 => _cf == true || _zf == true ? true : _cf is null || _zf is null ? null : false,
            4 => _sf,
            5 => throw Decline("branches on the parity flag"),
            6 => _sf is { } s && _of is { } o ? s != o : null,
            _ => _zf == true ? true : _zf is null || _sf is null || _of is null ? null : _sf != _of,
        };
        if (taken is not { } t) throw Decline("branches on a flag that depends on registers or memory the caller left");
        return (cc & 1) == 0 ? t : !t;
    }

    private void Jump(int rel)
    {
        long target = (long)_pc + rel;
        if (target < 0 || target >= _code.Length) throw Decline($"jumps outside the code read ({target})");
        _pc = (int)target;
    }

    private void Push(uint? value)
    {
        uint sp = (_r[Esp] ?? throw Decline("esp unknown")) - 4;
        _r[Esp] = sp;
        Write(sp, value);
    }

    private uint? Pop()
    {
        uint sp = _r[Esp] ?? throw Decline("esp unknown");
        var value = Read(sp);
        _r[Esp] = sp + 4;
        return value;
    }

    private uint? Get(int reg) => _r[reg];

    private void Set(int reg, uint? value)
    {
        if (reg == Esp && value is null) throw Decline("esp becomes unknown");
        _r[reg] = value;
    }

    /// <summary>A decoded ModR/M operand: a register, or a memory address within the frame.</summary>
    private readonly record struct Operand(int Reg, bool Register, int Rm, uint Address);

    private Operand ModRm()
    {
        byte b = Fetch();
        int mod = b >> 6, reg = (b >> 3) & 7, rm = b & 7;
        if (mod == 3) return new Operand(reg, true, rm, 0);
        uint? address;
        if (rm == 4)
        {
            byte sib = Fetch();
            int scale = sib >> 6, index = (sib >> 3) & 7, @base = sib & 7;
            if (@base == 5 && mod == 0) throw Decline("reads or writes an absolute address");
            address = Get(@base);
            if (index != 4) address = address is { } a && Get(index) is { } i ? a + (i << scale) : null;
        }
        else if (rm == 5 && mod == 0) throw Decline("reads or writes an absolute address");
        else address = Get(rm);
        uint disp = mod switch { 1 => (uint)(sbyte)Fetch(), 2 => Imm32(), _ => 0 };
        if (address is not { } at) throw Decline("reads or writes memory at an address that depends on registers the caller left");
        return new Operand(reg, false, rm, at + disp);
    }

    private uint? Load(Operand m) => m.Register ? Get(m.Rm) : Read(m.Address);

    private void Store(Operand m, uint? value)
    {
        if (m.Register) Set(m.Rm, value);
        else Write(m.Address, value);
    }

    /// <summary>Declines an access outside the frame, the return address and the arguments.</summary>
    private void CheckFrame(uint address, bool write)
    {
        uint low = Top - FrameBytes, high = Top + 4 + 4 * (uint)_arguments;
        if (address < low || address > high - 4)
            throw Decline($"{(write ? "writes" : "reads")} memory outside its stack frame and arguments (esp{(long)address - Top:+0;-0})");
    }

    private uint? Read(uint address)
    {
        CheckFrame(address, write: false);
        uint value = 0;
        for (uint i = 0; i < 4; i++)
        {
            if (!_memory.TryGetValue(address + i, out byte b)) return null;
            value |= (uint)b << (int)(8 * i);
        }
        return value;
    }

    private void Write(uint address, uint? value)
    {
        CheckFrame(address, write: true);
        for (uint i = 0; i < 4; i++)
        {
            if (value is { } v) _memory[address + i] = (byte)(v >> (int)(8 * i));
            else _memory.Remove(address + i);
        }
    }

    private byte Fetch() => _pc < _code.Length ? _code[_pc++] : throw Decline("runs past the code read");

    private uint Imm32()
    {
        uint v = 0;
        for (int i = 0; i < 4; i++) v |= (uint)Fetch() << (8 * i);
        return v;
    }

    private Declined Unsupported(byte op, int? ext = null) =>
        Decline(ext is { } e ? $"unsupported instruction {op:X2} /{e}" : $"unsupported instruction {op:X2}");

    private Declined Decline(string message) => new($"{message} at +0x{_start:X}");
}
