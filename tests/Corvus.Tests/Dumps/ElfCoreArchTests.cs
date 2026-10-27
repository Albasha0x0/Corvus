using Corvus.Native.Dump;
using Corvus.Native.Dwarf;
using Corvus.Services;
using Corvus.Tests.NativeFormats;

namespace Corvus.Tests;

/// <summary>A synthetic 64-bit core for any machine: libarch.so with .eh_frame FDEs and one thread the test fills.</summary>
internal static class ArchCore
{
    public const ulong Base = 0x4000_0000, Stack = 0x7FF0_0000, S0 = Stack + 0x1000;
    public const uint A = 0x1000, B = 0x1040, C = 0x1080, M = 0x10C0;
    private const int HdrRva = 0x1400, EhRva = 0x1480;
    public const string ModulePath = "/usr/lib/libarch.so";

    public sealed record Cie(ulong CodeAlign, long DataAlign, int ReturnColumn, byte[] Initial);

    public static byte[] Module(ushort machine, bool bigEndian, Cie cie, params (uint Start, byte[] Instructions)[] fdes)
    {
        var w = new ByteWriter(bigEndian);
        w.Bytes([0x7F, (byte)'E', (byte)'L', (byte)'F', 2, (byte)(bigEndian ? 2 : 1), 1, 0]);
        w.PadTo(16);
        w.U16(3); w.U16(machine); w.U32(1); w.U64(M); w.U64(0x40); w.U64(0); w.U32(0);
        w.U16(64); w.U16(56); w.U16(2); w.U16(64); w.U16(0); w.U16(0);
        void Phdr(uint type, uint flags, ulong at, ulong size, ulong align) { w.U32(type); w.U32(flags); w.U64(at); w.U64(at); w.U64(at); w.U64(size); w.U64(size); w.U64(align); }
        Phdr(1, 5, 0, 0x2000, 0x1000);
        Phdr(0x6474E550, 4, HdrRva, 8, 4);

        w.PadTo(EhRva);
        int cieAt = w.Length;
        var c = new ByteWriter(bigEndian);
        c.U32(0); c.U8(1); c.CString("zR"); c.Uleb(cie.CodeAlign); c.Sleb(cie.DataAlign); c.U8((byte)cie.ReturnColumn); c.Uleb(1); c.U8(0x1B); c.Bytes(cie.Initial);
        while ((c.Length + 4) % 8 != 0) c.U8(0);
        w.U32((uint)c.Length);
        w.Bytes(c.ToArray());
        foreach (var (start, insns) in fdes)
        {
            int at = w.Length;
            var f = new ByteWriter(bigEndian);
            f.U32((uint)(at + 4 - cieAt));
            f.U32(unchecked((uint)(start - (at + 8))));
            f.U32(0x40);
            f.Uleb(0);
            f.Bytes(insns);
            while ((f.Length + 4) % 8 != 0) f.U8(0);
            w.U32((uint)f.Length);
            w.Bytes(f.ToArray());
        }
        w.U32(0);
        // .eh_frame_hdr: pcrel sdata4 eh_frame pointer, no search table (the FDEs are walked).
        w.BytesAt(HdrRva, [1, 0x1B, 0xFF, 0xFF]);
        w.U32At(HdrRva + 4, EhRva - (HdrRva + 4));
        w.PadTo(0x2000);
        return w.ToArray();
    }

    /// <summary>The core: one thread (SIGSEGV) with <paramref name="greg"/> as pr_reg, the module at <see cref="Base"/> and the stack words.</summary>
    public static byte[] Core(ushort machine, bool bigEndian, byte[] module, ulong[] greg, params (ulong At, ulong Value)[] stackWords)
    {
        ulong moduleSize = (ulong)(module.Length + 0xFFF) & ~0xFFFUL;
        module = [.. module, .. new byte[moduleSize - (ulong)module.Length]];
        var stack = new ByteWriter(bigEndian);
        stack.PadTo(0x2000);
        foreach (var (at, value) in stackWords) stack.U64At((int)(at - Stack), value);

        var notes = new ByteWriter(bigEndian);
        void Note(uint type, byte[] desc) { notes.U32(5); notes.U32((uint)desc.Length); notes.U32(type); notes.Bytes("CORE\0\0\0\0"u8); notes.Bytes(desc); notes.Align(4); }
        var d = new ByteWriter(bigEndian);
        d.U32(11); d.U32(0); d.U32(0); d.U16(11); d.U16(0);
        d.PadTo(32); d.U32(7001); d.U32(1); d.U32(7001); d.U32(7001);
        d.PadTo(112);
        foreach (var r in greg) d.U64(r);
        Note(1, d.ToArray());
        var nf = new ByteWriter(bigEndian);
        nf.U64(1); nf.U64(0x1000);
        nf.U64(Base); nf.U64(Base + moduleSize); nf.U64(0);
        nf.CString(ModulePath);
        Note(0x46494C45, nf.ToArray());
        var noteBytes = notes.ToArray();

        var w = new ByteWriter(bigEndian);
        w.Bytes([0x7F, (byte)'E', (byte)'L', (byte)'F', 2, (byte)(bigEndian ? 2 : 1), 1, 0]);
        w.PadTo(16);
        w.U16(4); w.U16(machine); w.U32(1); w.U64(0); w.U64(0x40); w.U64(0); w.U32(0);
        w.U16(64); w.U16(56); w.U16(3); w.U16(64); w.U16(0); w.U16(0);
        const int notesAt = 0x200;
        int data = 0x1000 * ((notesAt + noteBytes.Length + 0xFFF) / 0x1000);
        void Phdr(uint type, uint flags, ulong offset, ulong va, ulong size) { w.U32(type); w.U32(flags); w.U64(offset); w.U64(va); w.U64(0); w.U64(size); w.U64(size); w.U64(type == 4 ? 4u : 0x1000u); }
        Phdr(4, 0, notesAt, 0, (ulong)noteBytes.Length);
        Phdr(1, 5, (ulong)data, Base, moduleSize);
        Phdr(1, 6, (ulong)data + moduleSize, Stack, 0x2000);
        w.PadTo(notesAt);
        w.Bytes(noteBytes);
        w.PadTo(data);
        w.Bytes(module);
        w.Bytes(stack.ToArray());
        return w.ToArray();
    }

    /// <summary>A 64-bit shared object as the loader maps it at link addresses: each PT_LOAD's file bytes at its address.</summary>
    public static byte[] Mapped(byte[] file)
    {
        var v = new Corvus.Native.ByteView(file, file[5] == 2);
        long phoff = (long)v.U64(32);
        int count = v.U16(56);
        var loads = Enumerable.Range(0, count).Select(i => phoff + i * 56L).Where(at => v.U32(at) == 1)
            .Select(at => (Offset: (long)v.U64(at + 8), Va: (long)v.U64(at + 16), FileSize: (long)v.U64(at + 32), MemSize: (long)v.U64(at + 40))).ToList();
        var image = new byte[loads.Max(l => l.Va + l.MemSize)];
        foreach (var l in loads) file.AsSpan((int)l.Offset, (int)l.FileSize).CopyTo(image.AsSpan((int)l.Va));
        return image;
    }
}

public sealed class ElfCoreArchTests
{
    private static async Task<MinidumpService.StackReport> Walk(byte[] core)
    {
        using var dir = new TempDir();
        var path = dir.File("arch.core");
        File.WriteAllBytes(path, core);
        using var service = new MinidumpService();
        return await service.Stack(path, null, true, 64, 0, 64, null, CancellationToken.None);
    }

    private static void Frames(MinidumpService.StackReport r, string stop, params (uint Rva, ulong Sp, string Method)[] expected)
    {
        Assert.Equal(stop, r.Stop);
        Assert.Equal(expected.Select(e => ($"0x{ArchCore.Base + e.Rva:X}", $"0x{e.Sp:X}", e.Method)), r.Items.Select(f => (f.Address, f.StackPointer, f.Method)));
    }

    /// <summary>RISC-V: CFI saves ra and s0 below the CFA; A and M are walked by the frame record below s0.</summary>
    [Fact]
    public async Task Riscv64_core_unwinds_by_cfi_then_frame_pointer()
    {
        const ulong fa = ArchCore.S0 + 0x60, fm = ArchCore.S0 + 0x80;
        byte[] fde = [0x44, 0x0E, 32, 0x81, 1, 0x88, 2];
        var module = ArchCore.Module(243, false, new(1, -8, 1, [0x0C, 2, 0]), (ArchCore.B, fde), (ArchCore.C, fde));
        var greg = new ulong[32];
        greg[0] = ArchCore.Base + ArchCore.C + 8;
        greg[1] = ArchCore.Base + ArchCore.B + 0x10;
        greg[2] = ArchCore.S0;
        greg[8] = 0xBAD;
        var core = ArchCore.Core(243, false, module, greg,
            (ArchCore.S0 + 24, ArchCore.Base + ArchCore.B + 0x10), (ArchCore.S0 + 16, 0x1111),
            (ArchCore.S0 + 56, ArchCore.Base + ArchCore.A + 0x10), (ArchCore.S0 + 48, fa),
            (fa - 8, ArchCore.Base + ArchCore.M + 0x10), (fa - 16, fm), (fm - 8, 0));
        var r = await Walk(core);
        Assert.Equal("riscv64", r.Architecture);
        Frames(r, "end_of_stack", (ArchCore.C + 8, ArchCore.S0, FrameMethod.Context), (ArchCore.B + 0x10, ArchCore.S0 + 32, FrameMethod.UnwindInfo),
            (ArchCore.A + 0x10, ArchCore.S0 + 64, FrameMethod.UnwindInfo), (ArchCore.M + 0x10, fa, FrameMethod.FramePointer));
    }

    /// <summary>ppc64le: the link register (DWARF 65) saved 16 bytes above the CFA; A and M are walked by the back chain.</summary>
    [Fact]
    public async Task Ppc64_core_unwinds_by_cfi_then_back_chain()
    {
        const ulong spA = ArchCore.S0 + 80, spM = ArchCore.S0 + 128, spTop = ArchCore.S0 + 176;
        var module = ArchCore.Module(21, false, new(4, -8, 65, [0x0C, 1, 0]),
            (ArchCore.B, [0x41, 0x0E, 48, 0x11, 65, 0x7E]), (ArchCore.C, [0x41, 0x0E, 32, 0x11, 65, 0x7E]));
        var greg = new ulong[37];
        greg[1] = ArchCore.S0;
        greg[32] = ArchCore.Base + ArchCore.C + 8;
        greg[36] = ArchCore.Base + ArchCore.B + 0x10;
        var core = ArchCore.Core(21, false, module, greg,
            (ArchCore.S0 + 48, ArchCore.Base + ArchCore.B + 0x10), (ArchCore.S0 + 96, ArchCore.Base + ArchCore.A + 0x10),
            (spA, spM), (spM + 16, ArchCore.Base + ArchCore.M + 0x10), (spM, spTop), (spTop + 16, 0));
        var r = await Walk(core);
        Assert.Equal("ppc64le", r.Architecture);
        Frames(r, "end_of_stack", (ArchCore.C + 8, ArchCore.S0, FrameMethod.Context), (ArchCore.B + 0x10, ArchCore.S0 + 32, FrameMethod.UnwindInfo),
            (ArchCore.A + 0x10, spA, FrameMethod.UnwindInfo), (ArchCore.M + 0x10, spM, FrameMethod.FramePointer));
    }

    /// <summary>s390x (big-endian): CFA r15+160, r14 and r15 saved by the prologue; A has no FDE and the ABI keeps no back chain.</summary>
    [Fact]
    public async Task S390x_core_unwinds_by_cfi()
    {
        byte[] fde = [0x43, 0x8E, 6, 0x8F, 5, 0x42, 0x0E, 0xC0, 0x02];
        var module = ArchCore.Module(22, true, new(2, -8, 14, [0x0C, 15, 0xA0, 0x01]), (ArchCore.B, fde), (ArchCore.C, fde));
        var greg = new ulong[18];
        greg[1] = ArchCore.Base + ArchCore.C + 0x10;
        greg[2 + 14] = ArchCore.Base + ArchCore.B + 0x10;
        greg[2 + 15] = ArchCore.S0;
        var core = ArchCore.Core(22, true, module, greg,
            (ArchCore.S0 + 272, ArchCore.Base + ArchCore.B + 0x10), (ArchCore.S0 + 280, ArchCore.S0 + 160),
            (ArchCore.S0 + 432, ArchCore.Base + ArchCore.A + 0x10), (ArchCore.S0 + 440, ArchCore.S0 + 320));
        var r = await Walk(core);
        Assert.Equal("s390x", r.Architecture);
        Frames(r, "no_unwind_data", (ArchCore.C + 0x10, ArchCore.S0, FrameMethod.Context), (ArchCore.B + 0x10, ArchCore.S0 + 160, FrameMethod.UnwindInfo),
            (ArchCore.A + 0x10, ArchCore.S0 + 320, FrameMethod.UnwindInfo));
        Assert.Contains(r.Notes, n => n.Contains("no FDE covers libarch.so+0x100F") && n.Contains("no usable frame pointer"));
    }

    /// <summary>
    /// x64 CFI written as DWARF expressions: C's CFA (DW_CFA_def_cfa_expression) and saved rbp (DW_CFA_expression), B's
    /// CFA as GNU ld writes it for .plt entries (rsp + 8, plus 8 past the push) and rbp as a DW_CFA_val_expression. A is
    /// walked by rbp, which only the evaluated rules carry through.
    /// </summary>
    [Fact]
    public async Task X64_core_evaluates_cfi_expressions()
    {
        byte[] c = [0x42, 0x0F, 2, 0x77, 16, 0x10, 6, 3, 0x08, 16, 0x1C];
        byte[] b = [0x0F, 11, 0x77, 0x08, 0x80, 0x00, 0x3F, 0x1A, 0x3B, 0x2A, 0x33, 0x24, 0x22, 0x16, 6, 2, 0x76, 0x00];
        var module = ArchCore.Module(62, false, new(1, -8, 16, [0x0C, 7, 8, 0x90, 1]), (ArchCore.B, b), (ArchCore.C, c));
        var greg = new ulong[27];
        greg[4] = 0xBAD;
        greg[16] = ArchCore.Base + ArchCore.C + 2;
        greg[19] = ArchCore.S0;
        var core = ArchCore.Core(62, false, module, greg,
            (ArchCore.S0, ArchCore.S0 + 48), (ArchCore.S0 + 8, ArchCore.Base + ArchCore.B + 0x1B), (ArchCore.S0 + 24, ArchCore.Base + ArchCore.A + 9),
            (ArchCore.S0 + 48, ArchCore.S0 + 64), (ArchCore.S0 + 56, ArchCore.Base + ArchCore.M + 9), (ArchCore.S0 + 72, 0));
        var r = await Walk(core);
        Frames(r, "end_of_stack", (ArchCore.C + 2, ArchCore.S0, FrameMethod.Context), (ArchCore.B + 0x1B, ArchCore.S0 + 16, FrameMethod.UnwindInfo),
            (ArchCore.A + 9, ArchCore.S0 + 32, FrameMethod.UnwindInfo), (ArchCore.M + 9, ArchCore.S0 + 64, FrameMethod.FramePointer));
    }

    /// <summary>
    /// Real compiler CFI (CfiFixtures/frames.rs built by rustc and ld.lld): a thread stopped inside frame(), called from
    /// outer(). The stack is laid out from llvm-readobj --unwind's rows and llvm-nm's addresses: the CFA offset of each
    /// function, the return address slot, and on s390x the caller's r15 saved beside it.
    /// </summary>
    [Theory]
    [InlineData("ppc64le.so", 21, false, 37, 32, 1, 0x10430u, 0x104F0u, 336, -1, 320)]
    [InlineData("ppc64.so", 21, true, 37, 32, 1, 0x10424u, 0x104D8u, 336, -1, 320)]
    [InlineData("s390x.so", 22, true, 18, 1, 17, 0x13F0u, 0x1450u, 528, 536, 416)]
    [InlineData("riscv64.so", 243, false, 32, 0, 2, 0x1464u, 0x14B6u, 280, -1, 288)]
    public async Task Compiled_cfi_unwinds_on_each_architecture(string file, int machine, bool bigEndian, int words, int pcWord, int spWord,
        uint frame, uint outer, int raAt, int spAt, int outerSp)
    {
        var module = ArchCore.Mapped(File.ReadAllBytes(Path.Combine(AppContext.BaseDirectory, "Dumps", "CfiFixtures", file)));
        var greg = new ulong[words];
        greg[pcWord] = ArchCore.Base + frame + 0x30;
        greg[spWord] = ArchCore.S0;
        var stackWords = new List<(ulong, ulong)> { (ArchCore.S0 + (ulong)raAt, ArchCore.Base + outer + 0x20) };
        if (spAt >= 0) stackWords.Add((ArchCore.S0 + (ulong)spAt, ArchCore.S0 + (ulong)outerSp));
        var r = await Walk(ArchCore.Core((ushort)machine, bigEndian, module, greg, [.. stackWords]));
        Assert.Equal("end_of_stack", r.Stop);
        Assert.Equal([("frame", FrameMethod.Context), ("outer", FrameMethod.UnwindInfo)], r.Items.Select(f => (f.Function, f.Method)));
        Assert.Equal($"0x{ArchCore.S0 + (ulong)outerSp:X}", r.Items[1].StackPointer);
    }

    [Theory]
    [InlineData(new byte[] { 0x31, 0x32, 0x22 }, 3UL)] // lit1 lit2 plus
    [InlineData(new byte[] { 0x35, 0x37, 0x1C, 0x1F }, 2UL)] // 5 - 7, neg
    [InlineData(new byte[] { 0x33, 0x34, 0x16, 0x1C }, 1UL)] // swap: 4 - 3
    [InlineData(new byte[] { 0x31, 0x32, 0x33, 0x17, 0x13, 0x13 }, 3UL)] // rot leaves 3 on the bottom
    [InlineData(new byte[] { 0x38, 0x39, 0x15, 1, 0x1E }, 72UL)] // pick 1: 9 * 8
    [InlineData(new byte[] { 0x09, 0xF0, 0x34, 0x26 }, ulong.MaxValue)] // const1s -16 >> 4 (arithmetic)
    [InlineData(new byte[] { 0x35, 0x31, 0x28, 1, 0, 0x3A, 0x2F, 1, 0, 0x3B, 0x3C, 0x22 }, 17UL)] // bra over lit10, skip over lit11: 5 + 12
    [InlineData(new byte[] { 0x70, 0x10, 0x06 }, 0x1122334455667788UL)] // breg0 16, deref
    [InlineData(new byte[] { 0x70, 0x10, 0x94, 2 }, 0x7788UL)] // breg0 16, deref_size 2
    [InlineData(new byte[] { 0x10, 0x80, 0x01, 0x23, 0x7F, 0x9F }, 255UL)] // constu 128, plus_uconst 127, stack_value
    public void Dwarf_expressions_evaluate(byte[] expr, ulong expected)
    {
        bool ok = DwarfExpression.TryEvaluate(expr, 8, false, (int reg, out ulong v) => { v = reg == 0 ? 0x1000UL : 0; return reg == 0; },
            (ulong address, int size, out ulong v) => { v = address == 0x1010 ? 0x1122334455667788UL & (size == 8 ? ulong.MaxValue : (1UL << (size * 8)) - 1) : 0; return address == 0x1010; },
            null, out ulong value, out string? failure);
        Assert.True(ok, failure);
        Assert.Equal(expected, value);
    }

    [Theory]
    [InlineData(new byte[] { 0x50 }, "register")] // reg0: a location
    [InlineData(new byte[] { 0x91, 0x08 }, "frame base")]
    [InlineData(new byte[] { 0x22 }, "needs 2")]
    [InlineData(new byte[] { 0x30, 0x30, 0x1B }, "division by zero")]
    [InlineData(new byte[] { 0x2F, 0x00, 0x10 }, "leaves the expression")]
    [InlineData(new byte[] { 0x2F, 0xFD, 0xFF }, "runs longer")]
    [InlineData(new byte[] { 0x71, 0x00 }, "register 1")]
    public void Dwarf_expressions_fail_with_a_reason(byte[] expr, string reason)
    {
        bool ok = DwarfExpression.TryEvaluate(expr, 8, false, (int reg, out ulong v) => { v = 0; return reg == 0; }, (ulong a, int s, out ulong v) => { v = 0; return false; },
            null, out _, out string? failure);
        Assert.False(ok);
        Assert.Contains(reason, failure);
    }
}
