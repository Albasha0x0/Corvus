using System.Runtime.InteropServices;
using Corvus.Native;
using Corvus.Native.Emulation;
using Iced.Intel;
using Xunit.Abstractions;
using static Iced.Intel.AssemblerRegisters;

namespace Corvus.Tests;

/// <summary>
/// Random x86-64 integer sequences run on the host processor and in <see cref="X86Cpu"/>: the six data registers and
/// every arithmetic flag the architecture defines after the sequence must agree.
/// </summary>
public sealed class X86CpuDifferentialTests(ITestOutputHelper output)
{
    private const ulong Base = 0x10000000;
    private const int Registers = 6;
    // CF, PF, AF, ZF, SF, OF.
    private const ulong Cf = 1, Pf = 4, Af = 0x10, Zf = 0x40, Sf = 0x80, Of = 0x800, AllFlags = Cf | Pf | Af | Zf | Sf | Of;

    private static readonly AssemblerRegister64[] R64 = [rax, rdx, r8, r9, r10, r11];
    private static readonly AssemblerRegister32[] R32 = [eax, edx, r8d, r9d, r10d, r11d];
    private static readonly AssemblerRegister16[] R16 = [ax, dx, r8w, r9w, r10w, r11w];
    private static readonly AssemblerRegister8[] R8 = [al, dl, r8b, r9b, r10b, r11b];

    private delegate void Sequence(IntPtr state);

    private static class Kernel32
    {
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr VirtualAlloc(IntPtr address, nuint size, uint type, uint protect);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool VirtualFree(IntPtr address, nuint size, uint type);
    }

    /// <summary>One random sequence: loads the registers from [rcx], runs the operations, stores them and the flags back.</summary>
    private static (byte[] Code, ulong Undefined, List<string> Ops) Generate(Random rng, int count)
    {
        var a = new Assembler(64);
        for (int i = 0; i < Registers; i++) a.mov(R64[i], __qword_ptr[rcx + i * 8]);
        // Flags the last operations left undefined; the start state differs between the two runs.
        ulong undefined = AllFlags;
        var ops = new List<string>();
        int R() => rng.Next(Registers);
        void Define(ulong written, ulong leftUndefined = 0) => undefined = (undefined & ~written) | leftUndefined;
        void Reads(ulong flags)
        {
            if ((undefined & flags) == 0) return;
            a.cmp(R64[R()], R64[R()]);
            Define(AllFlags);
        }
        int Count(int bits) => rng.Next(3) == 0 ? 1 : rng.Next(1, bits);
        for (int n = 0; n < count; n++)
        {
            int d = R(), s = R(), kind = rng.Next(24);
            int imm = rng.Next(4) == 0 ? rng.Next(-2, 3) : rng.Next();
            int width = rng.Next(4) switch { 0 => 8, 1 => 16, 2 => 32, _ => 64 };
            ops.Add($"{kind}/{width}");
            switch (kind)
            {
                case 0: Op(width, d, s, imm, rng.Next(2) == 0, (x, y) => a.add(x, y), (x, y) => a.add(x, y), (x, y) => a.add(x, y), (x, y) => a.add(x, y), (x, i) => a.add(x, i), (x, i) => a.add(x, i), (x, i) => a.add(x, i), (x, i) => a.add(x, i)); Define(AllFlags); break;
                case 1: Op(width, d, s, imm, rng.Next(2) == 0, (x, y) => a.sub(x, y), (x, y) => a.sub(x, y), (x, y) => a.sub(x, y), (x, y) => a.sub(x, y), (x, i) => a.sub(x, i), (x, i) => a.sub(x, i), (x, i) => a.sub(x, i), (x, i) => a.sub(x, i)); Define(AllFlags); break;
                case 2: Reads(Cf); Op(width, d, s, imm, rng.Next(2) == 0, (x, y) => a.adc(x, y), (x, y) => a.adc(x, y), (x, y) => a.adc(x, y), (x, y) => a.adc(x, y), (x, i) => a.adc(x, i), (x, i) => a.adc(x, i), (x, i) => a.adc(x, i), (x, i) => a.adc(x, i)); Define(AllFlags); break;
                case 3: Reads(Cf); Op(width, d, s, imm, rng.Next(2) == 0, (x, y) => a.sbb(x, y), (x, y) => a.sbb(x, y), (x, y) => a.sbb(x, y), (x, y) => a.sbb(x, y), (x, i) => a.sbb(x, i), (x, i) => a.sbb(x, i), (x, i) => a.sbb(x, i), (x, i) => a.sbb(x, i)); Define(AllFlags); break;
                case 4: Op(width, d, s, imm, rng.Next(2) == 0, (x, y) => a.and(x, y), (x, y) => a.and(x, y), (x, y) => a.and(x, y), (x, y) => a.and(x, y), (x, i) => a.and(x, i), (x, i) => a.and(x, i), (x, i) => a.and(x, i), (x, i) => a.and(x, i)); Define(AllFlags, Af); break;
                case 5: Op(width, d, s, imm, rng.Next(2) == 0, (x, y) => a.or(x, y), (x, y) => a.or(x, y), (x, y) => a.or(x, y), (x, y) => a.or(x, y), (x, i) => a.or(x, i), (x, i) => a.or(x, i), (x, i) => a.or(x, i), (x, i) => a.or(x, i)); Define(AllFlags, Af); break;
                case 6: Op(width, d, s, imm, rng.Next(2) == 0, (x, y) => a.xor(x, y), (x, y) => a.xor(x, y), (x, y) => a.xor(x, y), (x, y) => a.xor(x, y), (x, i) => a.xor(x, i), (x, i) => a.xor(x, i), (x, i) => a.xor(x, i), (x, i) => a.xor(x, i)); Define(AllFlags, Af); break;
                case 7: Op(width, d, s, imm, rng.Next(2) == 0, (x, y) => a.cmp(x, y), (x, y) => a.cmp(x, y), (x, y) => a.cmp(x, y), (x, y) => a.cmp(x, y), (x, i) => a.cmp(x, i), (x, i) => a.cmp(x, i), (x, i) => a.cmp(x, i), (x, i) => a.cmp(x, i)); Define(AllFlags); break;
                case 8: Unary(width, d, x => a.inc(x), x => a.inc(x), x => a.inc(x), x => a.inc(x)); Define(AllFlags & ~Cf); break;
                case 9: Unary(width, d, x => a.dec(x), x => a.dec(x), x => a.dec(x), x => a.dec(x)); Define(AllFlags & ~Cf); break;
                case 10: Unary(width, d, x => a.neg(x), x => a.neg(x), x => a.neg(x), x => a.neg(x)); Define(AllFlags); break;
                case 11: Unary(width, d, x => a.not(x), x => a.not(x), x => a.not(x), x => a.not(x)); break;
                case 12 or 13 or 14:
                {
                    // shl, shr, sar by an immediate: AF is undefined; OF too for counts above 1.
                    int c = Count(width);
                    var sh = kind switch { 12 => 4, 13 => 5, _ => 7 };
                    Shift(width, d, c, sh);
                    Define(AllFlags, Af | (c > 1 ? Of : 0));
                    break;
                }
                case 15 or 16:
                {
                    // rol, ror: CF and OF only; OF is undefined for counts above 1.
                    int c = Count(width);
                    Shift(width, d, c, kind == 15 ? 0 : 1);
                    Define(Cf | Of, c > 1 ? Of : 0);
                    break;
                }
                case 17 or 18:
                {
                    // rcl, rcr read CF.
                    Reads(Cf);
                    int c = Count(width);
                    Shift(width, d, c, kind == 17 ? 2 : 3);
                    Define(Cf | Of, c > 1 ? Of : 0);
                    break;
                }
                case 19:
                    // imul: CF and OF defined, the rest undefined.
                    if (width == 8) { a.imul(R8[s]); Define(AllFlags, Sf | Zf | Af | Pf); break; }
                    if (rng.Next(2) == 0) { if (width == 16) a.imul(R16[d], R16[s]); else if (width == 32) a.imul(R32[d], R32[s]); else a.imul(R64[d], R64[s]); }
                    else if (width == 16) a.imul(R16[d], R16[s], (short)imm); else if (width == 32) a.imul(R32[d], R32[s], imm); else a.imul(R64[d], R64[s], imm);
                    Define(AllFlags, Sf | Zf | Af | Pf);
                    break;
                case 20:
                {
                    var cc = rng.Next(16);
                    Reads(Cc(cc));
                    if (width is 8) Setcc(cc, R8[d]); else Cmov(cc, width == 16 ? null : width, d, s);
                    break;
                }
                case 21:
                    if (width == 8) a.movzx(R32[d], R8[s]); else if (width == 16) a.movsx(R64[d], R16[s]); else if (width == 32) a.movsxd(R64[d], R32[s]); else a.bswap(R64[d]);
                    break;
                case 22:
                {
                    int c = Count(width == 8 ? 16 : width);
                    if (width is 8 or 16) { if (rng.Next(2) == 0) a.shld(R16[d], R16[s], (byte)c); else a.shrd(R16[d], R16[s], (byte)c); }
                    else if (width == 32) { if (rng.Next(2) == 0) a.shld(R32[d], R32[s], (byte)c); else a.shrd(R32[d], R32[s], (byte)c); }
                    else if (rng.Next(2) == 0) a.shld(R64[d], R64[s], (byte)c); else a.shrd(R64[d], R64[s], (byte)c);
                    Define(AllFlags, Af | (c > 1 ? Of : 0));
                    break;
                }
                default:
                    if (width == 64) a.lea(R64[d], __[R64[s] + R64[d] * 4 + imm]);
                    else if (width == 32) a.xadd(R32[d], R32[s]);
                    else a.test(R64[d], R64[s]);
                    if (width == 32) Define(AllFlags); else if (width != 64) Define(AllFlags, Af);
                    break;
            }
        }
        for (int i = 0; i < Registers; i++) a.mov(__qword_ptr[rcx + i * 8], R64[i]);
        a.pushfq();
        a.pop(rax);
        a.mov(__qword_ptr[rcx + Registers * 8], rax);
        a.ret();
        var stream = new MemoryStream();
        a.Assemble(new StreamCodeWriter(stream), Base);
        return (stream.ToArray(), undefined, ops);

        void Op(int w, int x, int y, int i, bool immediate,
            Action<AssemblerRegister8, AssemblerRegister8> r8, Action<AssemblerRegister16, AssemblerRegister16> r16,
            Action<AssemblerRegister32, AssemblerRegister32> r32, Action<AssemblerRegister64, AssemblerRegister64> r64,
            Action<AssemblerRegister8, sbyte> i8, Action<AssemblerRegister16, short> i16, Action<AssemblerRegister32, int> i32, Action<AssemblerRegister64, int> i64)
        {
            if (immediate)
            {
                switch (w) { case 8: i8(R8[x], (sbyte)i); break; case 16: i16(R16[x], (short)i); break; case 32: i32(R32[x], i); break; default: i64(R64[x], i); break; }
            }
            else
            {
                switch (w) { case 8: r8(R8[x], R8[y]); break; case 16: r16(R16[x], R16[y]); break; case 32: r32(R32[x], R32[y]); break; default: r64(R64[x], R64[y]); break; }
            }
        }

        void Unary(int w, int x, Action<AssemblerRegister8> u8, Action<AssemblerRegister16> u16, Action<AssemblerRegister32> u32, Action<AssemblerRegister64> u64)
        {
            switch (w) { case 8: u8(R8[x]); break; case 16: u16(R16[x]); break; case 32: u32(R32[x]); break; default: u64(R64[x]); break; }
        }

        void Shift(int w, int x, int c, int op)
        {
            byte b = (byte)c;
            switch (w)
            {
                case 8: (op switch { 0 => (Action)(() => a.rol(R8[x], b)), 1 => () => a.ror(R8[x], b), 2 => () => a.rcl(R8[x], b), 3 => () => a.rcr(R8[x], b), 4 => () => a.shl(R8[x], b), 5 => () => a.shr(R8[x], b), _ => () => a.sar(R8[x], b) })(); break;
                case 16: (op switch { 0 => (Action)(() => a.rol(R16[x], b)), 1 => () => a.ror(R16[x], b), 2 => () => a.rcl(R16[x], b), 3 => () => a.rcr(R16[x], b), 4 => () => a.shl(R16[x], b), 5 => () => a.shr(R16[x], b), _ => () => a.sar(R16[x], b) })(); break;
                case 32: (op switch { 0 => (Action)(() => a.rol(R32[x], b)), 1 => () => a.ror(R32[x], b), 2 => () => a.rcl(R32[x], b), 3 => () => a.rcr(R32[x], b), 4 => () => a.shl(R32[x], b), 5 => () => a.shr(R32[x], b), _ => () => a.sar(R32[x], b) })(); break;
                default: (op switch { 0 => (Action)(() => a.rol(R64[x], b)), 1 => () => a.ror(R64[x], b), 2 => () => a.rcl(R64[x], b), 3 => () => a.rcr(R64[x], b), 4 => () => a.shl(R64[x], b), 5 => () => a.shr(R64[x], b), _ => () => a.sar(R64[x], b) })(); break;
            }
        }

        void Setcc(int cc, AssemblerRegister8 r)
        {
            Action<AssemblerRegister8>[] set = [a.seto, a.setno, a.setb, a.setae, a.sete, a.setne, a.setbe, a.seta, a.sets, a.setns, a.setp, a.setnp, a.setl, a.setge, a.setle, a.setg];
            set[cc](r);
        }

        void Cmov(int cc, int? w, int x, int y)
        {
            Action<AssemblerRegister32, AssemblerRegister32>[] c32 = [a.cmovo, a.cmovno, a.cmovb, a.cmovae, a.cmove, a.cmovne, a.cmovbe, a.cmova, a.cmovs, a.cmovns, a.cmovp, a.cmovnp, a.cmovl, a.cmovge, a.cmovle, a.cmovg];
            Action<AssemblerRegister64, AssemblerRegister64>[] c64 = [a.cmovo, a.cmovno, a.cmovb, a.cmovae, a.cmove, a.cmovne, a.cmovbe, a.cmova, a.cmovs, a.cmovns, a.cmovp, a.cmovnp, a.cmovl, a.cmovge, a.cmovle, a.cmovg];
            Action<AssemblerRegister16, AssemblerRegister16>[] c16 = [a.cmovo, a.cmovno, a.cmovb, a.cmovae, a.cmove, a.cmovne, a.cmovbe, a.cmova, a.cmovs, a.cmovns, a.cmovp, a.cmovnp, a.cmovl, a.cmovge, a.cmovle, a.cmovg];
            if (w == null) c16[cc](R16[x], R16[y]); else if (w == 32) c32[cc](R32[x], R32[y]); else c64[cc](R64[x], R64[y]);
        }
    }

    // The flags condition code cc reads, in the order o, no, b, ae, e, ne, be, a, s, ns, p, np, l, ge, le, g.
    private static ulong Cc(int cc) => (cc >> 1) switch { 0 => Of, 1 => Cf, 2 => Zf, 3 => Cf | Zf, 4 => Sf, 5 => Pf, 6 => Sf | Of, _ => Sf | Of | Zf };

    private static ulong[] OnHost(byte[] code, ulong[] input)
    {
        // MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE; MEM_RELEASE.
        var page = Kernel32.VirtualAlloc(IntPtr.Zero, (nuint)code.Length, 0x3000, 0x40);
        Assert.NotEqual(IntPtr.Zero, page);
        var state = Marshal.AllocHGlobal((Registers + 1) * 8);
        try
        {
            Marshal.Copy(code, 0, page, code.Length);
            for (int i = 0; i < Registers; i++) Marshal.WriteInt64(state, i * 8, (long)input[i]);
            Marshal.GetDelegateForFunctionPointer<Sequence>(page)(state);
            return [.. Enumerable.Range(0, Registers + 1).Select(i => (ulong)Marshal.ReadInt64(state, i * 8))];
        }
        finally
        {
            Marshal.FreeHGlobal(state);
            Kernel32.VirtualFree(page, 0, 0x8000);
        }
    }

    private static ulong[] InEmulator(byte[] code, ulong[] input)
    {
        var image = new RawCodeImage(code, "sequence.bin", RawLayout.Parse("x64", $"0x{Base:x}", null, code.Length));
        const ulong region = 0x7ffe00000000, state = region + 0x100000, sentinel = region + 0x1F0000;
        var memory = new EmulatorMemory(image, Base, region, 0x200000);
        var cpu = new X86Cpu(true, true) { Pc = Base, Sp = region + 0xFF000 };
        for (int i = 0; i < Registers; i++) memory.WriteUInt(state + (ulong)i * 8, input[i], 8);
        cpu.TrySet("rcx", state);
        cpu.SetReturnAddress(memory, sentinel);
        for (int steps = 0; cpu.Pc != sentinel; steps++)
        {
            Assert.True(steps < 10_000, "the sequence did not return");
            cpu.Step(memory);
        }
        return [.. Enumerable.Range(0, Registers + 1).Select(i => memory.ReadUInt(state + (ulong)i * 8, 8))];
    }

    [Fact]
    public void Random_integer_sequences_match_the_host_processor()
    {
        // The sequences call through the Microsoft x64 convention on the host.
        if (!OperatingSystem.IsWindows() || RuntimeInformation.ProcessArchitecture != Architecture.X64)
        {
            output.WriteLine("not a Windows x64 host");
            return;
        }
        var rng = new Random(20261026);
        int sequences = 0, operations = 0;
        for (int round = 0; round < 400; round++)
        {
            var (code, undefined, ops) = Generate(rng, rng.Next(1, 40));
            ulong[] input = [.. Enumerable.Range(0, Registers).Select(_ => rng.Next(5) switch
            {
                0 => 0UL,
                1 => ulong.MaxValue,
                2 => 0x8000000000000000UL >> rng.Next(64),
                _ => (ulong)rng.NextInt64() ^ ((ulong)rng.Next(2) << 63),
            })];
            var host = OnHost(code, input);
            var emulated = InEmulator(code, input);
            ulong mask = AllFlags & ~undefined;
            for (int i = 0; i < Registers; i++)
                Assert.True(host[i] == emulated[i], $"round {round}, register {R64[i]}: host 0x{host[i]:x}, emulator 0x{emulated[i]:x}; ops {string.Join(" ", ops)}");
            Assert.True((host[Registers] & mask) == (emulated[Registers] & mask),
                $"round {round}: flags host 0x{host[Registers] & mask:x}, emulator 0x{emulated[Registers] & mask:x} (compared 0x{mask:x}); ops {string.Join(" ", ops)}");
            sequences++;
            operations += ops.Count;
        }
        output.WriteLine($"{sequences} sequences, {operations} operations agree");
    }
}
