using System.Buffers.Binary;
using System.Text;
using NetDecompilerMcp.Native;
using NetDecompilerMcp.Native.Code;
using NetDecompilerMcp.Native.Elf;
using NetDecompilerMcp.Tests.NativeFormats;

namespace NetDecompilerMcp.Tests;

/// <summary>T32 and A32 encodings for synthetic code; addresses are RVAs of an image based at 0.</summary>
internal sealed class A32Code(uint origin)
{
    private readonly List<byte> _bytes = [];
    private readonly List<(int At, int Size, Func<uint> Value)> _fixups = [];

    public uint Here => origin + (uint)_bytes.Count;

    public A32Code H(ushort h) { _bytes.Add((byte)h); _bytes.Add((byte)(h >> 8)); return this; }

    public A32Code T(uint wide) => H((ushort)(wide >> 16)).H((ushort)wide);

    public A32Code W(uint word) { foreach (var b in BitConverter.GetBytes(word)) _bytes.Add(b); return this; }

    /// <summary>A halfword (2), Thumb-2 pair (-4: first halfword high) or word (4) computed once every label is known.</summary>
    public A32Code Later(int size, Func<uint, uint> value)
    {
        uint at = Here;
        _fixups.Add((_bytes.Count, size, () => value(at)));
        for (int k = 0; k < Math.Abs(size); k++) _bytes.Add(0);
        return this;
    }

    public A32Code Align4() { while ((Here & 3) != 0) H(0xBF00); return this; }

    public byte[] Bytes()
    {
        var b = _bytes.ToArray();
        foreach (var (at, size, value) in _fixups)
        {
            uint v = value();
            if (size == 2) BinaryPrimitives.WriteUInt16LittleEndian(b.AsSpan(at), (ushort)v);
            else if (size == 4) BinaryPrimitives.WriteUInt32LittleEndian(b.AsSpan(at), v);
            else { BinaryPrimitives.WriteUInt16LittleEndian(b.AsSpan(at), (ushort)(v >> 16)); BinaryPrimitives.WriteUInt16LittleEndian(b.AsSpan(at + 2), (ushort)v); }
        }
        return b;
    }

    // T32
    public static ushort PushLr(int mask) => (ushort)(0xB500 | mask);
    public static ushort PopPc(int mask) => (ushort)(0xBD00 | mask);
    public const ushort BxLr = 0x4770, Nop = 0xBF00;
    public static ushort BlxReg(int rm) => (ushort)(0x4780 | rm << 3);
    public static ushort AddPc(int rd) => (ushort)(0x4478 | rd);
    public static ushort LdrImm(int rt, int rn, int offset) => (ushort)(0x6800 | (offset / 4) << 6 | rn << 3 | rt);
    public static ushort MovImm(int rd, int imm) => (ushort)(0x2000 | rd << 8 | imm);
    public static ushort CmpImm(int rn, int imm) => (ushort)(0x2800 | rn << 8 | imm);
    public static ushort It(int cond) => (ushort)(0xBF08 | cond << 4);
    public static ushort LdrLit(int rt, uint from, uint literal) => (ushort)(0x4800 | rt << 8 | (int)(literal - ((from + 4) & ~3u)) / 4);
    public static ushort B(uint from, uint to) => (ushort)(0xE000 | ((to - from - 4) >> 1) & 0x7FF);
    public static ushort BCond(uint from, uint to, int cond) => (ushort)(0xD000 | cond << 8 | (int)((to - from - 4) >> 1) & 0xFF);
    public static ushort Cbz(uint from, uint to, int rn)
    {
        uint off = to - from - 4;
        return (ushort)(0xB100 | (off >> 6 & 1) << 9 | (off >> 1 & 31) << 3 | (uint)rn);
    }
    public static uint Tbb(int rm) => 0xE8DFF000 | (uint)rm;
    public static uint Tbh(int rm) => 0xE8DFF010 | (uint)rm;
    public static uint Movw(int rd, uint imm) => 0xF2400000 | (imm >> 11 & 1) << 26 | (imm >> 12) << 16 | (imm >> 8 & 7) << 12 | (uint)rd << 8 | imm & 0xFF;
    public static uint Movt(int rd, uint imm) => Movw(rd, imm) | 0x00800000;
    public static uint LdrW(int rt, int rn, uint imm12) => 0xF8D00000 | (uint)rn << 16 | (uint)rt << 12 | imm12;

    /// <summary>BL (<paramref name="exchange"/>: BLX to ARM code) from Thumb.</summary>
    public static uint Bl(uint from, uint to, bool exchange = false)
    {
        int off = exchange ? (int)(to - ((from + 4) & ~3u)) : (int)(to - from - 4);
        uint s = (uint)(off >> 24) & 1, i1 = (uint)(off >> 23) & 1, i2 = (uint)(off >> 22) & 1;
        uint j1 = (i1 ^ 1) ^ s, j2 = (i2 ^ 1) ^ s;
        uint hw1 = 0xF000 | s << 10 | (uint)(off >> 12) & 0x3FF;
        uint hw2 = (exchange ? 0xC000u : 0xD000u) | j1 << 13 | j2 << 11 | (uint)(off >> 1) & 0x7FF;
        if (exchange) hw2 &= ~1u;
        return hw1 << 16 | hw2;
    }

    // A32
    public const uint ArmBxLr = 0xE12FFF1E, ArmBxNeLr = 0x112FFF1E;
    public static uint ArmCmp(int rn, uint imm) => 0xE3500000 | (uint)rn << 16 | imm;
    public static uint ArmBl(uint from, uint to) => 0xEB000000 | ((to - from - 8) >> 2) & 0xFFFFFF;
    public static uint ArmB(uint from, uint to, uint cond = 14) => cond << 28 | 0x0A000000 | ((to - from - 8) >> 2) & 0xFFFFFF;

    /// <summary>An ELF PLT entry: add ip, pc, #hi; add ip, ip, #mid; ldr pc, [ip, #lo]!.</summary>
    public A32Code PltEntry(uint slot)
    {
        uint off = slot - (Here + 8);
        return W(0xE28FC600 | off >> 20 & 0xFF).W(0xE28CCA00 | off >> 12 & 0xFF).W(0xE5BCF000 | off & 0xFFF);
    }
}

/// <summary>
/// 32-bit ARM code analysis on synthetic ELF and PE images: Thumb and ARM functions with interworking, literal pools and
/// PC-relative addresses, PLT and GOT import calls, IT blocks and conditional returns, MOVW / MOVT import thunks,
/// disassembly and a saved index.
/// </summary>
public class NativeArm32Tests
{
    private const uint Text = ElfWriter.TextRva;
    private const uint Data = ElfWriter.DataRva;
    private const uint Got = ElfWriter.GotRva;

    private static ElfFile Elf(byte[] code, Action<ElfWriter>? configure = null) => ElfFile.FromBytes(ElfBytes(code, configure), "sample.so");

    private static byte[] ElfBytes(byte[] code, Action<ElfWriter>? configure = null)
    {
        var w = new ElfWriter { Is64 = false, Machine = ElfWriter.EmArm, UseRel = true, Text = code };
        var data = new byte[0x100];
        Encoding.ASCII.GetBytes("Hello, thumb\0").CopyTo(data, 0);
        w.Data = data;
        configure?.Invoke(w);
        return w.Build();
    }

    /// <summary>
    /// main (Thumb, exported): a string by literal + add pc, BL to a Thumb helper, CBZ, BLX to an ARM function, BLX to an
    /// ARM PLT stub of abort (noreturn), then free through its GOT slot. helper: it eq; bxeq lr. ARM function: bxne lr.
    /// </summary>
    internal static (ElfFile Image, uint Helper, uint ArmFn, uint Plt) Sample()
    {
        var (bytes, helper, armFn, plt) = SampleFile();
        return (ElfFile.FromBytes(bytes, "sample.so"), helper, armFn, plt);
    }

    /// <summary>The bytes of the <see cref="Sample"/> shared object.</summary>
    internal static (byte[] Bytes, uint Helper, uint ArmFn, uint Plt) SampleFile()
    {
        var a = new A32Code(Text);
        uint helper = 0, armFn = 0, plt = 0, after = 0, lit1 = 0, lit2 = 0, addStr = 0, addGot = 0;
        a.H(A32Code.PushLr(0x10));
        a.Later(2, at => A32Code.LdrLit(0, at, lit1));
        addStr = a.Here;
        a.H(A32Code.AddPc(0));
        a.Later(-4, at => A32Code.Bl(at, helper));
        a.Later(2, at => A32Code.Cbz(at, after, 0));
        a.Later(-4, at => A32Code.Bl(at, armFn, exchange: true));
        a.Later(-4, at => A32Code.Bl(at, plt, exchange: true));
        after = a.Here;
        a.Later(2, at => A32Code.LdrLit(3, at, lit2));
        addGot = a.Here;
        a.H(A32Code.AddPc(3)).H(A32Code.LdrImm(3, 3, 0)).H(A32Code.BlxReg(3)).H(A32Code.PopPc(0x10));
        a.Align4();
        lit1 = a.Here;
        a.Later(4, _ => Data - (addStr + 4));
        lit2 = a.Here;
        a.Later(4, _ => Got + 4 - (addGot + 4));
        helper = a.Here;
        a.H(A32Code.CmpImm(0, 0)).H(A32Code.It(0)).H(A32Code.BxLr).H(A32Code.MovImm(0, 1)).H(A32Code.BxLr);
        a.Align4();
        armFn = a.Here;
        a.W(A32Code.ArmCmp(0, 1)).W(A32Code.ArmBxNeLr).W(A32Code.ArmBxLr);
        plt = a.Here;
        a.PltEntry(Got);
        var bytes = ElfBytes(a.Bytes(), w =>
        {
            w.Symbols.Add(new ElfWriter.Symbol("main", Text | 1, Type: 2));
            w.Symbols.Add(new ElfWriter.Symbol("abort", Defined: false));
            w.Symbols.Add(new ElfWriter.Symbol("free", Defined: false));
            w.Relocations.Add(new ElfWriter.Reloc(Got, 22, "abort"));
            w.Relocations.Add(new ElfWriter.Reloc(Got + 4, 21, "free"));
        });
        return (bytes, helper, armFn, plt);
    }

    [Fact]
    public void Thumb_and_arm_functions_with_interworking_literals_and_imports()
    {
        var (image, helper, armFn, plt) = Sample();
        var index = NativeCodeIndex.Build(image);

        Assert.Equal(CodeSupport.Full, index.Support);
        Assert.Equal([Text, helper, armFn, plt], index.Functions.Select(f => f.Start));
        var dis = index.CreateDisassembler();
        Assert.Equal([true, true, false, false], index.Functions.Select(f => dis.ThumbAt(f.Start) == true));
        Assert.All(index.Functions, f => Assert.Equal(0, (int)(f.Flags & FunctionFlags.InvalidCode)));

        var main = index.FunctionByStart(Text)!;
        Assert.Equal("main", main.Name);
        var stub = index.FunctionByStart(plt)!;
        Assert.True((stub.Flags & FunctionFlags.Thunk) != 0);
        Assert.Equal("abort", stub.ThunkImport?.Name);
        Assert.True((stub.Flags & FunctionFlags.NoReturn) != 0);

        // the string formed by ldr r0, [pc, #x]; add r0, pc
        Assert.Contains(index.RefsTo(Data), x => x.Kind == XrefKind.Address && x.From == Text + 4);
        Assert.Equal("Hello, thumb", index.ReadString(index.StringAt(Data)!.Value));
        // free called through its GOT slot: ldr r3, [pc]; add r3, pc; ldr r3, [r3]; blx r3
        var free = image.Imports.Single(i => i.Name == "free");
        Assert.Contains(index.Callers(free), c => c.Kind == XrefKind.ImportCall && c.Caller == main);
        Assert.Contains(index.Callees(main), c => c.Function?.Start == armFn);
        Assert.Contains(index.Callees(main), c => c.Function?.Start == helper);

        // conditional returns keep the fall-through: two blocks each, and both functions return
        foreach (var f in new[] { helper, armFn })
        {
            var fn = index.FunctionByStart(f)!;
            Assert.Equal(0, (int)(fn.Flags & FunctionFlags.NoReturn));
            var g = index.GetGraph(fn);
            Assert.Equal(2, g.Blocks.Count);
            Assert.Contains(g.Blocks[0].Successors, e => e.Kind == EdgeKind.ConditionalFallThrough);
        }

        var text = string.Join("\n", index.DisassembleFunction(main, 100, out _).Select(l => l.Label ?? $"{l.Line!.Text} ; {l.Line.Comment}"));
        Assert.Contains($"bl     sub_{helper:X}", text);
        Assert.Contains($"blx    sub_{armFn:X}", text);
        Assert.Contains("j_abort", text);
        Assert.Contains("\"Hello, thumb\"", text);
        Assert.DoesNotContain("(bad)", text);
        var arm = string.Join("\n", index.Disassemble(armFn, 3).Select(l => l.Text));
        Assert.Equal("cmp    r0, #1\nbxne   lr\nbx     lr", arm);
    }

    [Fact]
    public void Odd_addresses_are_thumb_and_code_pointers_name_their_state()
    {
        // an ARM function and a Thumb function reached only through relocated pointers in data (the Thumb one odd)
        var a = new A32Code(Text);
        a.W(A32Code.ArmCmp(0, 0)).W(A32Code.ArmBxLr);
        uint thumb = a.Here;
        a.H(A32Code.MovImm(0, 2)).H(A32Code.BxLr);
        var image = Elf(a.Bytes(), w =>
        {
            w.Relocations.Add(new ElfWriter.Reloc(Data + 0x40, 23, Addend: Text));
            w.Relocations.Add(new ElfWriter.Reloc(Data + 0x44, 23, Addend: thumb | 1));
        });
        var index = NativeCodeIndex.Build(image);
        Assert.Equal([Text, thumb], index.Functions.Select(f => f.Start));
        var dis = index.CreateDisassembler();
        Assert.Equal((false, true), (dis.ThumbAt(Text), dis.ThumbAt(thumb)));
        Assert.Equal("movs   r0, #2", dis.DecodeOne(thumb)!.Text);
        // an odd address asks for Thumb decoding at the address below it
        Assert.Equal("movs   r0, #2", index.Disassemble(thumb | 1, 1)[0].Text);
        Assert.Contains(index.RefsTo(thumb), x => x.Kind == XrefKind.Pointer);
    }

    [Fact]
    public void Fixed_address_executables_take_literals_as_addresses()
    {
        // ET_EXEC at 0x10000 without relocations: main passes helper (a Thumb pointer) and a string through literal pools
        const uint baseVa = 0x10000;
        var a = new A32Code(Text);
        uint helper = 0, sink = 0, litFn = 0, litStr = 0;
        a.H(A32Code.PushLr(0x80));
        a.Later(2, at => A32Code.LdrLit(0, at, litFn)).Later(2, at => A32Code.LdrLit(1, at, litStr));
        a.Later(-4, at => A32Code.Bl(at, sink));
        a.H(A32Code.PopPc(0x80)).Align4();
        litFn = a.Here; a.Later(4, _ => baseVa + helper + 1);
        litStr = a.Here; a.Later(4, _ => baseVa + Data);
        helper = a.Here; a.H(A32Code.MovImm(0, 1)).H(A32Code.BxLr);
        sink = a.Here; a.H(A32Code.BxLr).H(A32Code.Nop);
        var image = Elf(a.Bytes(), w =>
        {
            w.Type = 2;
            w.Base = baseVa;
            w.Entry = Text | 1;
        });
        var index = NativeCodeIndex.Build(image);
        Assert.Contains(index.Functions, f => f.Start == helper && (f.Sources & FunctionSource.CodeAddress) != 0);
        Assert.True(index.CreateDisassembler().ThumbAt(helper));
        Assert.Contains(index.RefsTo(Data), x => x.Kind == XrefKind.Address && x.From == Text + 4);
        Assert.Equal("Hello, thumb", index.ReadString(index.StringAt(Data)!.Value));
    }

    [Fact]
    public void Veneers_and_unwind_starts_get_their_state()
    {
        // main (Thumb) tail-jumps to a bx pc veneer whose ARM half jumps on with add pc, ip, pc to an ARM function that
        // only an unwind entry and an even data pointer name, and that starts with conditional instructions
        var a = new A32Code(Text);
        uint veneer = 0, target = 0, other = 0;
        a.Later(-4, at => A32Code.Bl(at, veneer) & 0xFFFFBFFF | 0x1000); // b.w veneer
        a.Align4();
        veneer = a.Here;
        a.H(0x4778).H(0x46C0);                                              // bx pc; nop
        uint add = a.Here + 4;
        a.W(0xE59FC000).W(0xE08FF00C).Later(4, _ => target - (add + 8));    // ldr ip, [pc]; add pc, ip, pc; .word
        target = a.Here;
        a.W(A32Code.ArmBxLr);
        other = a.Here;
        a.W(A32Code.ArmCmp(0, 0)).W(0x03A00000).W(0x012FFF1E).W(0xE3A00001).W(A32Code.ArmBxLr); // cmp; moveq r0, #0; bxeq lr; mov r0, #1; bx lr
        var image = Elf(a.Bytes(), w =>
        {
            w.Symbols.Add(new ElfWriter.Symbol("main", Text | 1, Type: 2));
            w.Exidx.Add((other, true));
            w.Relocations.Add(new ElfWriter.Reloc(Data + 0x40, 23, Addend: other));
        });
        var index = NativeCodeIndex.Build(image);
        var dis = index.CreateDisassembler();
        Assert.Equal([Text, veneer, veneer + 4, target, other], index.Functions.Select(f => f.Start));
        Assert.Equal([true, true, false, false, false], index.Functions.Select(f => dis.ThumbAt(f.Start) == true));
        Assert.All(index.Functions, f => Assert.Equal(0, (int)(f.Flags & FunctionFlags.InvalidCode)));
        Assert.Contains(index.RefsFrom(veneer + 4, veneer + 12), x => x.Kind == XrefKind.TailCall && x.To == target);
    }

    [Fact]
    public void Windows_thumb_import_thunk_and_relocated_movw_movt()
    {
        // Windows on ARM: every function is Thumb; movw / movt r12 (THUMB_MOV32 relocation); ldr.w pc, [r12]
        uint slot = CodeTestImage.SyntheticDataRva + 0x10;
        ulong imageBase = 0x10000000;
        uint va = (uint)(imageBase + slot);
        var a = new A32Code(CodeTestImage.SyntheticCodeRva);
        uint thunk = 0;
        a.H(A32Code.PushLr(0)).Later(-4, at => A32Code.Bl(at, thunk)).H(A32Code.PopPc(0));
        thunk = a.Here;
        a.T(A32Code.Movw(12, va & 0xFFFF)).T(A32Code.Movt(12, va >> 16)).T(A32Code.LdrW(15, 12, 0));
        // the base relocation of the pair sits at the movw
        var image = CodeTestImage.Synthetic(NativeArch.Arm, a.Bytes(), imports: [new NativeImport("kernel32.dll", "Sleep", null, 0, slot, false)],
            entry: CodeTestImage.SyntheticCodeRva, relocations: [thunk]);
        var index = NativeCodeIndex.Build(image);
        var t = index.FunctionByStart(thunk)!;
        Assert.True((t.Flags & FunctionFlags.Thunk) != 0);
        Assert.Equal("Sleep", t.ThunkImport?.Name);
        Assert.Single(index.Callers(image.Imports[0]));
        var lines = index.Disassemble(thunk, 3);
        Assert.Equal("kernel32!Sleep", lines[2].Comment);
    }

    [Fact]
    public void Saved_index_keeps_the_instruction_states()
    {
        var (image, _, armFn, _) = Sample();
        using var dir = new TempDir();
        var cache = new NetDecompilerMcp.Native.Code.CodeIndexCache(new CodeIndexCacheOptions(dir.File("cache"), 1L << 30, TimeSpan.FromDays(1), TimeSpan.Zero));
        var built = NativeCodeIndex.Build(image);
        Assert.True(cache.Save(built, null));
        var loaded = cache.TryLoad(Sample().Image, null)!;
        Assert.True(loaded.LoadedFromCache);
        Assert.Equal(built.Functions.Select(f => f.Start), loaded.Functions.Select(f => f.Start));
        Assert.Equal(false, loaded.CreateDisassembler().ThumbAt(armFn));
        Assert.Equal(built.Disassemble(armFn, 3).Select(l => l.Text), loaded.Disassemble(armFn, 3).Select(l => l.Text));
        var g = loaded.GetGraph(loaded.FunctionByStart(armFn)!);
        Assert.Equal(2, g.Blocks.Count);
    }

    /// <summary>Thumb b&lt;cond&gt;.w (T3).</summary>
    private static uint BCondW(uint from, uint to, int cond)
    {
        uint off = to - from - 4;
        return 0xF0008000 | (off >> 20 & 1) << 26 | (uint)cond << 22 | (off >> 12 & 0x3F) << 16 | (off >> 18 & 1) << 13 | (off >> 19 & 1) << 11 | (off >> 1 & 0x7FF);
    }

    /// <summary>
    /// A conditional b.w to a linker veneer (movw ip / movt ip / add ip, pc / bx ip) past other functions, and a b.w thunk to it:
    /// the veneer is a function of its own named j_dst (not a block of the first jumper), the thunk j_j_dst.
    /// </summary>
    [Fact]
    public async Task Conditional_tail_jumps_to_a_veneer_make_it_a_named_function()
    {
        var a = new A32Code(Text);
        uint veneer = 0, dst = 0, add = 0;
        a.H(A32Code.CmpImm(0, 0));
        a.Later(-4, at => BCondW(at, veneer, 1));
        a.H(A32Code.BxLr);
        uint thunk = a.Here;
        a.Later(-4, at => A32Code.Bl(at, veneer) & ~0x4000u); // b.w
        a.Align4();
        uint other = a.Here;
        a.H(A32Code.MovImm(0, 1)).H(A32Code.BxLr);
        veneer = a.Here;
        a.Later(-4, _ => A32Code.Movw(12, (dst | 1) - (add + 4) & 0xFFFF));
        a.Later(-4, _ => A32Code.Movt(12, (dst | 1) - (add + 4) >> 16));
        add = a.Here;
        a.H(0x44FC).H(0x4760);
        dst = a.Here;
        a.H(A32Code.MovImm(0, 2)).H(A32Code.BxLr);
        var image = Elf(a.Bytes(), w =>
        {
            w.Symbols.Add(new ElfWriter.Symbol("dst", dst | 1, Type: 2));
            w.Relocations.Add(new ElfWriter.Reloc(Data + 0x40, 23, Addend: Text | 1));
            w.Relocations.Add(new ElfWriter.Reloc(Data + 0x44, 23, Addend: thunk | 1));
            w.Relocations.Add(new ElfWriter.Reloc(Data + 0x48, 23, Addend: other | 1));
        });
        var index = NativeCodeIndex.Build(image);
        Assert.Equal(veneer, index.FunctionAt(veneer)?.Start);
        Assert.Equal("j_dst", index.FunctionByStart(veneer)!.Name);
        Assert.Equal("j_j_dst", index.FunctionByStart(thunk)!.Name);
        Assert.Equal(Text, index.FunctionAt(Text + 2)?.Start);

        // a mnemonic search ignores the width qualifier: ^b$ finds b.w
        using var dir = new TempDir();
        var path = dir.File("veneer.so");
        File.WriteAllBytes(path, ElfBytes(a.Bytes(), w =>
        {
            w.Symbols.Add(new ElfWriter.Symbol("dst", dst | 1, Type: 2));
            w.Relocations.Add(new ElfWriter.Reloc(Data + 0x40, 23, Addend: Text | 1));
            w.Relocations.Add(new ElfWriter.Reloc(Data + 0x44, 23, Addend: thunk | 1));
            w.Relocations.Add(new ElfWriter.Reloc(Data + 0x48, 23, Addend: other | 1));
        }));
        using var h = new NativeToolHarness(backgroundIndexing: false);
        var found = await h.CodeTools.SearchInstructions(path, mnemonic: "^b$");
        Assert.Contains("1 match(es)", found);
        Assert.Contains("b.w", found);
    }

    /// <summary>A vtable slot (Thumb pointer) to ldr; str; bx lr, whose bytes read "IjAbpG" with a NUL after: code, not a string.</summary>
    [Fact]
    public void Thumb_pointer_targets_are_code_even_where_the_bytes_read_as_text()
    {
        var a = new A32Code(Text);
        a.H(A32Code.MovImm(0, 1)).H(A32Code.BxLr);
        uint setter = a.Here;
        a.H(0x6A49).H(0x6241).H(A32Code.BxLr).H(0x0000);
        var image = Elf(a.Bytes(), w =>
        {
            w.Relocations.Add(new ElfWriter.Reloc(Data + 0x40, 23, Addend: Text | 1));
            w.Relocations.Add(new ElfWriter.Reloc(Data + 0x44, 23, Addend: setter | 1));
        });
        var index = NativeCodeIndex.Build(image);
        Assert.Equal(setter, index.FunctionByStart(setter)?.Start);
        Assert.Equal(3, index.FunctionByStart(setter)!.InstructionCount);
    }
}
