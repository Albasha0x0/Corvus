using System.Buffers.Binary;
using System.Text;
using NetDecompilerMcp.Native;
using NetDecompilerMcp.Native.Code;
using NetDecompilerMcp.Tests.NativeFormats;

namespace NetDecompilerMcp.Tests;

/// <summary>A64 encodings for synthetic code; labels are RVAs, resolved when the word is emitted.</summary>
internal sealed class A64(uint origin)
{
    private readonly List<uint> _words = [];
    private readonly List<(int At, Func<uint> Word)> _fixups = [];

    public uint Here => origin + (uint)_words.Count * 4;

    public A64 Word(uint w) { _words.Add(w); return this; }

    /// <summary>A word computed once every label is known (forward branches).</summary>
    public A64 Later(Func<uint, uint> word)
    {
        uint at = Here;
        _fixups.Add((_words.Count, () => word(at)));
        _words.Add(0);
        return this;
    }

    public byte[] Bytes()
    {
        foreach (var (at, word) in _fixups) _words[at] = word();
        var bytes = new byte[_words.Count * 4];
        for (int i = 0; i < _words.Count; i++) BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(i * 4), _words[i]);
        return bytes;
    }

    private static uint Imm(long value, int bits) => (uint)value & ((1u << bits) - 1);

    public static uint B(uint from, uint to) => 0x14000000 | Imm(((long)to - from) / 4, 26);
    public static uint Bl(uint from, uint to) => 0x94000000 | Imm(((long)to - from) / 4, 26);
    public static uint BCond(uint from, uint to, uint cond) => 0x54000000 | Imm(((long)to - from) / 4, 19) << 5 | cond;
    public static uint Cbz(uint from, uint to, int rt) => 0xB4000000 | Imm(((long)to - from) / 4, 19) << 5 | (uint)rt;
    public static uint Adrp(uint from, uint to, int rd, ulong imageBase)
    {
        long pages = (long)(((imageBase + to) & ~0xFFFUL) - ((imageBase + from) & ~0xFFFUL)) >> 12;
        return 0x90000000 | (Imm(pages, 2) << 29) | (Imm(pages >> 2, 19) << 5) | (uint)rd;
    }
    public static uint Adr(uint from, uint to, int rd)
    {
        long d = (long)to - from;
        return 0x10000000 | (Imm(d, 2) << 29) | (Imm(d >> 2, 19) << 5) | (uint)rd;
    }
    public static uint AddImm(int rd, int rn, uint imm) => 0x91000000 | (imm & 0xFFF) << 10 | (uint)rn << 5 | (uint)rd;
    public static uint LdrX(int rt, int rn, uint offset) => 0xF9400000 | (offset / 8) << 10 | (uint)rn << 5 | (uint)rt;
    public static uint Br(int rn) => 0xD61F0000 | (uint)rn << 5;
    public static uint Blr(int rn) => 0xD63F0000 | (uint)rn << 5;
    public static uint MovW(int rd, uint imm) => 0x52800000 | (imm & 0xFFFF) << 5 | (uint)rd;
    public const uint Ret = 0xD65F03C0, Nop = 0xD503201F, PacIaSp = 0xD503233F, AutIaSp = 0xD50323BF;
    public const uint StpFpLrPre = 0xA9BF7BFD, LdpFpLrPost = 0xA8C17BFD, MovFpSp = 0x910003FD, Brk1 = 0xD4200020;
}

/// <summary>The ARM64 decoder: flow, ADRP pairs, import calls through slots, PLT thunks, disassembly; ARM64 PE end to end.</summary>
public class NativeArm64Tests
{
    private const uint Code = CodeTestImage.SyntheticCodeRva;
    private const uint Data = CodeTestImage.SyntheticDataRva;
    private const ulong Base = 0x10000000UL;

    private static NativeImport Import(string name, uint slot) => new("libc.so", name, null, 0, slot, false);

    [Fact]
    public void Functions_calls_adrp_pairs_and_strings()
    {
        var a = new A64(Code);
        uint helper = 0, after = 0;
        a.Word(A64.PacIaSp).Word(A64.StpFpLrPre).Word(A64.MovFpSp);
        a.Word(A64.Adrp(a.Here, Data + 0x100, 0, Base));
        a.Word(A64.AddImm(0, 0, (Data + 0x100) & 0xFFF));
        a.Later(at => A64.Bl(at, helper));
        a.Later(at => A64.Cbz(at, after, 0));
        a.Word(A64.MovW(0, 1));
        after = a.Here;
        a.Word(A64.LdpFpLrPost).Word(A64.AutIaSp).Word(A64.Ret);
        helper = a.Here;
        a.Word(A64.Ret);
        var data = new byte[0x200];
        Encoding.ASCII.GetBytes("Hello, arm\0").CopyTo(data, 0x100);
        var image = CodeTestImage.Synthetic(NativeArch.Arm64, a.Bytes(), data, entry: Code);
        var index = NativeCodeIndex.Build(image);

        Assert.Equal(CodeSupport.Full, index.Support);
        Assert.Equal([Code, helper], index.Functions.Select(f => f.Start));
        var f = index.FunctionByStart(Code)!;
        Assert.Equal(0, (int)(f.Flags & FunctionFlags.InvalidCode));
        Assert.Equal(11 * 4u, f.Size);
        Assert.Contains(index.RefsTo(helper), x => x.Kind == XrefKind.Call && x.From == Code + 5 * 4);
        Assert.Contains(index.RefsTo(Data + 0x100), x => x.Kind == XrefKind.Address && x.From == Code + 4 * 4);
        Assert.Equal("Hello, arm", index.ReadString(index.StringAt(Data + 0x100)!.Value));

        var graph = index.GetGraph(f);
        Assert.Equal(3, graph.Blocks.Count);
        Assert.Contains(graph.Blocks[0].Successors, e => e.Kind == EdgeKind.ConditionalTaken && e.To == after);

        var text = string.Join("\n", index.DisassembleFunction(f, 100, out _).Select(l => l.Label ?? $"{l.Line!.Text} ; {l.Line.Comment}"));
        Assert.Contains($"bl     sub_{helper:X}", text);
        Assert.Contains("paciasp", text);
        Assert.Contains("\"Hello, arm\"", text);
        Assert.DoesNotContain("(bad)", text);
    }

    [Fact]
    public void Calls_through_got_slots_and_plt_stubs_are_import_calls()
    {
        uint slotFree = Data + 0x10, slotAbort = Data + 0x18;
        var a = new A64(Code);
        uint plt = 0, tail = 0;
        // main: adrp x16, slot; ldr x17, [x16, #slot]; blr x17 (free through the GOT); bl abort@plt; garbage
        a.Word(A64.StpFpLrPre);
        a.Word(A64.Adrp(a.Here, slotFree, 16, Base)).Word(A64.LdrX(17, 16, slotFree & 0xFFF)).Word(A64.Blr(17));
        a.Later(at => A64.Bl(at, plt));
        a.Word(0xFFFFFFFF);
        // second: tail call through the PLT
        tail = a.Here;
        a.Later(at => A64.B(at, plt));
        plt = a.Here;
        a.Word(A64.Adrp(a.Here, slotAbort, 16, Base)).Word(A64.LdrX(17, 16, slotAbort & 0xFFF)).Word(A64.AddImm(16, 16, slotAbort & 0xFFF)).Word(A64.Br(17));
        var image = CodeTestImage.Synthetic(NativeArch.Arm64, a.Bytes(), imports: [Import("free", slotFree), Import("abort", slotAbort)], entry: Code,
            exports: [new NativeExport("second", 1, tail, null)]);
        var index = NativeCodeIndex.Build(image);

        var stub = index.FunctionByStart(plt)!;
        Assert.NotEqual(0, (int)(stub.Flags & FunctionFlags.Thunk));
        Assert.Equal("abort", stub.ThunkImport!.Name);
        Assert.NotEqual(0, (int)(stub.Flags & FunctionFlags.NoReturn));
        Assert.Contains(index.RefsTo(slotFree), x => x.Kind == XrefKind.ImportCall && x.From == Code + 3 * 4);
        var main = index.FunctionByStart(Code)!;
        Assert.Equal(0, (int)(main.Flags & FunctionFlags.InvalidCode)); // stops at the noreturn call
        Assert.Contains(index.Callers(image.Imports[1]), c => c.Caller == main);
        Assert.Contains(index.Callees(main), c => c.Import?.Name == "free");
        Assert.Contains("libc.so!free", index.Disassemble(Code, 4)[3].Comment);
    }

    [Fact]
    public void Call_arguments_follow_the_arm64_convention()
    {
        uint slotFopen = Data + 0x10, slotMalloc = Data + 0x18;
        var a = new A64(Code);
        uint plt = 0;
        a.Word(A64.StpFpLrPre).Word(A64.MovFpSp);
        // fopen("log.txt", "rb") through the GOT; malloc(0x12345) through a PLT stub; then an unknown callee with x0 = the result
        a.Word(A64.Adrp(a.Here, Data + 0x100, 0, Base)).Word(A64.AddImm(0, 0, (Data + 0x100) & 0xFFF));
        a.Word(A64.Adr(a.Here, Data + 0x108, 1)); // adr reaches the data section in this synthetic layout? keep it in range below
        a.Word(A64.Adrp(a.Here, slotFopen, 16, Base)).Word(A64.LdrX(17, 16, slotFopen & 0xFFF)).Word(A64.Blr(17));
        a.Word(0x52846AA0 /* mov w0, #0x2355 */).Word(0x72A00020 /* movk w0, #1, lsl #16 */);
        a.Later(at => A64.Bl(at, plt));
        a.Word(A64.LdpFpLrPost).Word(A64.Ret);
        plt = a.Here;
        a.Word(A64.Adrp(a.Here, slotMalloc, 16, Base)).Word(A64.LdrX(17, 16, slotMalloc & 0xFFF)).Word(A64.AddImm(16, 16, slotMalloc & 0xFFF)).Word(A64.Br(17));
        var data = new byte[0x200];
        Encoding.ASCII.GetBytes("log.txt\0rb\0").CopyTo(data, 0x100);
        var image = CodeTestImage.Synthetic(NativeArch.Arm64, a.Bytes(), data, entry: Code,
            imports: [Import("fopen", slotFopen), Import("malloc", slotMalloc)]);
        var index = NativeCodeIndex.Build(image);
        var sites = Native.Calls.Arm64CallSites.For(index).CallsIn(index.FunctionByStart(Code)!);
        Assert.Equal(2, sites.Count);
        Assert.Equal("fopen(\"log.txt\", \"rb\")", sites[0].Display);
        Assert.Equal(["filename", "mode"], sites[0].Arguments.Select(x => x.Name!));
        Assert.Equal("malloc(0x12355)", sites[1].Display);
        Assert.Equal(Native.Calls.CalleeKind.Import, sites[1].Kind);
    }

    [Fact]
    public void Relocated_words_and_zero_fill_are_not_code()
    {
        var a = new A64(Code);
        a.Word(A64.MovW(0, 7)).Word(A64.Ret).Word(0).Word(0);
        var code = a.Bytes();
        var index = NativeCodeIndex.Build(CodeTestImage.Synthetic(NativeArch.Arm64, code, relocations: [Code + 4], entry: Code));
        Assert.Equal(FlowKind.Invalid, index.Decode(Code + 4)!.Flow);
        Assert.Equal(FlowKind.Invalid, index.Decode(Code + 8)!.Flow);
        Assert.Equal(FlowKind.Invalid, index.Decode(Code + 2)!.Flow);
        Assert.Equal(FlowKind.Next, index.Decode(Code)!.Flow);
    }

    [Fact]
    public async Task Arm64_pe_is_decoded_end_to_end()
    {
        var pe = Native.Pe.PeFile.Open(NativeFixtures.WinArm64DbgShim);
        var index = NativeCodeIndex.Build(pe);
        Assert.Equal(CodeSupport.Full, index.Support);
        var starts = index.Functions.Select(f => f.Start).ToHashSet();
        Assert.All(pe.RuntimeFunctions, rf => Assert.Contains(rf.BeginRva, starts));
        Assert.True(index.Functions.Count > pe.RuntimeFunctions.Count / 2);
        Assert.True(index.Stats.Instructions > 20_000, $"{index.Stats.Instructions} instructions");
        var invalid = index.Functions.Count(f => (f.Flags & FunctionFlags.InvalidCode) != 0);
        Assert.True(invalid * 50 < index.Functions.Count, $"{invalid} of {index.Functions.Count} functions run into invalid code");
        Assert.Contains(index.Functions, f => (f.Flags & FunctionFlags.Thunk) != 0 || index.Callees(f).Any(c => c.Import != null));
        Assert.NotEmpty(index.Strings);
        var export = pe.Exports.First(e => e.Name == "RegisterForRuntimeStartup");
        Assert.Contains(index.Functions, f => f.Start == export.Rva && f.KnownName == export.Name);

        using var h = new NativeToolHarness(backgroundIndexing: false);
        await h.Exercise(NativeFixtures.WinArm64DbgShim);
        var failed = h.Calls.Where(c => c.Failed).ToList();
        Assert.True(failed.Count == 0, string.Join("\n", failed.Take(10)));
        var asm = await h.CodeTools.Disassemble(NativeFixtures.WinArm64DbgShim, "RegisterForRuntimeStartup");
        Assert.Contains("Engine: ours", asm);
        Assert.Matches(@"(?m)^\s+[0-9A-F]+\s+[0-9A-F]{8}\s+(stp|pacibsp|paciasp|sub|mov)\b", asm);
    }
}
