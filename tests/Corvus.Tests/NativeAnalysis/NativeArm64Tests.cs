using System.Buffers.Binary;
using System.Text;
using Corvus.Native;
using Corvus.Native.Code;
using Corvus.Tests.NativeFormats;

namespace Corvus.Tests;

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
    public void A_plt_stub_of_an_own_export_jumps_to_the_export()
    {
        // main: bl exported@plt; ret. exported: mov w0, #1; ret, exported and bound through its GOT slot (no -Bsymbolic)
        const uint text = ElfWriter.TextRva;
        ElfWriter Writer(uint bl) => new()
        {
            Entry = text, PltImports = ["exported"], Symbols = [new ElfWriter.Symbol("exported", text + 8, 8)],
            Text = [.. BitConverter.GetBytes(bl), .. BitConverter.GetBytes(A64.Ret), .. BitConverter.GetBytes(A64.MovW(0, 1)), .. BitConverter.GetBytes(A64.Ret)],
        };
        var probe = Writer(A64.Bl(text, text));
        probe.Build();
        uint stubRva = probe.PltRva + 32;
        var index = NativeCodeIndex.Build(Native.Elf.ElfFile.FromBytes(Writer(A64.Bl(text, stubRva)).Build(), "own.so"));
        var stub = index.FunctionByStart(stubRva)!;
        var exported = index.FunctionByStart(text + 8)!;
        Assert.Equal("j_exported", index.NameAt(stubRva));
        Assert.Contains(index.Callees(stub), c => c.Function == exported && c.Kind == XrefKind.TailCall);
        Assert.Contains(index.Callers(exported), c => c.Caller == stub);
        Assert.Equal(0, (int)(stub.Flags & FunctionFlags.UnresolvedJumps));
        var site = Native.Calls.Arm64CallSites.For(index).CallsIn(index.FunctionByStart(text)!).Single();
        Assert.Equal(stubRva, site.Target);
    }

    [Trait("Speed", "Slow")]
    [Theory]
    [InlineData("linux-arm64", 5)]
    [InlineData("android-arm", 5)]
    public void Real_plt_stubs_of_own_exports_reach_the_export(string rid, int expected)
    {
        string path = rid == "linux-arm64"
            ? RealPackages.File("Microsoft.NETCore.App.Runtime.linux-arm64", "10.0.11", "runtimes/linux-arm64/native/libSystem.Native.so")
            : RealPackages.File("Microsoft.Android.Runtime.35.android-arm", "35.0.105", "runtimes/android-arm/native/libmono-android.release.so");
        var elf = (Native.Elf.ElfFile)NativeImageLoader.Open(path);
        var local = ElfLocalSlots.Of(elf);
        var stubs = elf.PltEntries.Where(e => local.ContainsKey(e.SlotRva)).ToList();
        Assert.Equal(expected, stubs.Count);
        var index = NativeCodeIndex.Build(elf);
        foreach (var e in stubs)
        {
            Assert.Equal("j_" + e.Symbol, index.NameAt(e.StubRva));
            Assert.Contains(index.Callees(index.FunctionByStart(e.StubRva)!), c => c.Function?.Start == (local[e.SlotRva] & ~1u));
        }
    }

    /// <summary>
    /// A native method calls (*env)->FindClass(env, "com/example/Native"); JNI_OnLoad gets env through (*vm)->GetEnv(vm,
    /// &amp;env, JNI_VERSION_1_6) and calls (*env)->RegisterNatives(env, clazz, methods, 1).
    /// </summary>
    [Fact]
    public void Jni_function_table_calls_are_named()
    {
        uint name = Data + 0x100;
        var a = new A64(Code);
        uint native = a.Here;
        a.Word(A64.StpFpLrPre).Word(A64.MovFpSp);
        a.Word(A64.LdrX(8, 0, 0)).Word(A64.Adrp(a.Here, name, 1, Base)).Word(A64.AddImm(1, 1, name & 0xFFF)).Word(A64.LdrX(8, 8, 6 * 8)).Word(A64.Blr(8));
        a.Word(A64.LdpFpLrPost).Word(A64.Ret);
        uint onLoad = a.Here;
        a.Word(0xA9BE7BFD /* stp x29, x30, [sp, #-32]! */).Word(A64.MovFpSp);
        a.Word(A64.LdrX(8, 0, 0)).Word(A64.AddImm(1, 31, 16)).Word(A64.MovW(2, 6)).Word(0x72A00022 /* movk w2, #1, lsl #16 */).Word(A64.LdrX(8, 8, 6 * 8)).Word(A64.Blr(8));
        a.Word(A64.LdrX(0, 31, 16)).Word(A64.LdrX(8, 0, 0)).Word(A64.MovW(3, 1)).Word(A64.LdrX(8, 8, 215 * 8)).Word(A64.Blr(8));
        a.Word(A64.MovW(0, 6)).Word(0x72A00020 /* movk w0, #1, lsl #16 */).Word(0xA8C27BFD /* ldp x29, x30, [sp], #32 */).Word(A64.Ret);
        var data = new byte[0x200];
        Encoding.ASCII.GetBytes("com/example/Native ").CopyTo(data, 0x100);
        var image = CodeTestImage.Synthetic(NativeArch.Arm64, a.Bytes(), data, entry: native,
            exports: [new NativeExport("Java_com_example_Native_init", 1, native, null), new NativeExport("JNI_OnLoad", 2, onLoad, null)]);
        var index = NativeCodeIndex.Build(image);
        var sites = Native.Calls.Arm64CallSites.For(index);
        var find = Assert.Single(sites.CallsIn(index.FunctionByStart(native)!));
        Assert.Equal("JNIEnv::FindClass(?, \"com/example/Native\")", find.Display);
        var load = sites.CallsIn(index.FunctionByStart(onLoad)!);
        Assert.Equal(["JavaVM::GetEnv", "JNIEnv::RegisterNatives"], load.Select(s => s.Callee));
        Assert.Equal(["vm", "penv", "version"], load[0].Arguments.Select(x => x.Name!));
        Assert.Equal("0x10006", load[0].Arguments[2].Text);
        Assert.Equal("1", load[1].Arguments[3].Text);
        Assert.Equal(["JNIEnv::GetMethodID", "JNIEnv::GetFieldID", "JNIEnv::GetStaticMethodID", "JNIEnv::GetStaticFieldID", "JNIEnv::NewStringUTF",
            "JNIEnv::GetStringUTFChars", "JNIEnv::ExceptionCheck", "JNIEnv::GetModule"],
            new[] { 33, 94, 113, 144, 167, 169, 228, 233 }.Select(n => Native.Calls.JniInterface.Name(Native.Calls.JniInterface.Table.Env, n)));
        Assert.Null(Native.Calls.JniInterface.Name(Native.Calls.JniInterface.Table.Env, 234));
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

    /// <summary>
    /// malloc(0x40) with x0 set before a branch; pow(1.5, 2.0) and powf(1.0f, 3.0f) in d / s registers (fmov immediates and
    /// fmov from a general register); dlsym(dlopen("libm.so.6", 2), "cos") called through x8.
    /// </summary>
    [Fact]
    public void Arm64_arguments_cross_blocks_floating_point_and_late_bound_targets()
    {
        uint malloc = Data + 0x10, pow = Data + 0x18, powf = Data + 0x20, dlopen = Data + 0x28, dlsym = Data + 0x30, lib = Data + 0x100, cos = Data + 0x110,
            sin = Data + 0x118;
        var a = new A64(Code);
        uint skip = 0, resolve = 0;
        A64 Got(uint slot) => a.Word(A64.Adrp(a.Here, slot, 16, Base)).Word(A64.LdrX(17, 16, slot & 0xFFF)).Word(A64.Blr(17));
        a.Word(A64.StpFpLrPre).Word(A64.MovFpSp);
        a.Word(A64.MovW(0, 0x40)).Later(at => A64.Cbz(at, skip, 1)).Word(A64.Nop);
        skip = a.Here;
        Got(malloc);
        a.Word(0x1E6F1000 /* fmov d0, #1.5 */).Word(0x1E601001 /* fmov d1, #2.0 */);
        Got(pow);
        a.Word(0x1E2E1000 /* fmov s0, #1.0 */).Word(0x52A80808 /* mov w8, #0x40400000 */).Word(0x1E270101 /* fmov s1, w8 */);
        Got(powf);
        a.Word(A64.Adrp(a.Here, lib, 0, Base)).Word(A64.AddImm(0, 0, lib & 0xFFF)).Word(A64.MovW(1, 2));
        Got(dlopen);
        a.Word(A64.Adrp(a.Here, cos, 1, Base)).Word(A64.AddImm(1, 1, cos & 0xFFF));
        Got(dlsym);
        a.Word(0xAA0003E8 /* mov x8, x0 */).Word(0x1E6E1000 /* fmov d0, #1.0 */);
        uint late = a.Here;
        a.Word(A64.Blr(8));
        // resolve("sin")(): the name reaches dlsym through the wrapper's parameter
        a.Word(A64.Adrp(a.Here, sin, 0, Base)).Word(A64.AddImm(0, 0, sin & 0xFFF)).Later(at => A64.Bl(at, resolve));
        uint wrapped = a.Here;
        a.Word(A64.Blr(0));
        a.Word(A64.LdpFpLrPost).Word(A64.Ret);
        resolve = a.Here;
        a.Word(A64.StpFpLrPre).Word(A64.MovFpSp).Word(0xAA0003E1 /* mov x1, x0 */).Word(A64.MovW(0, 0));
        Got(dlsym);
        a.Word(A64.LdpFpLrPost).Word(A64.Ret);
        var data = new byte[0x200];
        Encoding.ASCII.GetBytes("libm.so.6\0").CopyTo(data, lib - Data);
        Encoding.ASCII.GetBytes("cos\0").CopyTo(data, cos - Data);
        Encoding.ASCII.GetBytes("sin\0").CopyTo(data, sin - Data);
        var image = CodeTestImage.Synthetic(NativeArch.Arm64, a.Bytes(), data, entry: Code,
            imports: [Import("malloc", malloc), Import("pow", pow), Import("powf", powf), Import("dlopen", dlopen), Import("dlsym", dlsym)]);
        var index = NativeCodeIndex.Build(image);
        var sites = Native.Calls.Arm64CallSites.For(index).CallsIn(index.FunctionByStart(Code)!);
        Assert.Equal("malloc(64)", sites[0].Display);
        Assert.Equal(0x40UL, sites[0].Arguments[0].Value);
        Assert.Equal("pow(1.5, 2)", sites[1].Display);
        Assert.Equal(["d0", "d1"], sites[1].Arguments.Select(x => x.Location));
        Assert.Equal("powf(1f, 3f)", sites[2].Display);
        Assert.Equal(["s0", "s1"], sites[2].Arguments.Select(x => x.Location));
        var call = sites.Single(s => s.Rva == late);
        Assert.Equal(("libm.so.6!cos", Native.Calls.CalleeKind.Dynamic), (call.Callee, call.Kind));
        Assert.Equal("cos(1)", call.Display);
        var target = Native.Calls.Arm64CallTargets.At(Native.Calls.Arm64Trace.For(index), late, deep: false)!;
        Assert.Equal(("resolved", "libm.so.6!cos", "getprocaddress"), (target.Status, target.Targets.Single().Name, target.Targets.Single().Basis));
        var viaWrapper = sites.Single(s => s.Rva == wrapped);
        Assert.Equal(("?!sin", Native.Calls.CalleeKind.Dynamic), (viaWrapper.Callee, viaWrapper.Kind));
    }

    /// <summary>
    /// The call sites the late-bound search analyzed are kept after it when none could name a late-bound import (a helper
    /// that only calls dlsym), and analyzed again when one could (a call through dlsym's result).
    /// </summary>
    [Fact]
    public void Arm64_call_sites_of_the_late_bound_search_are_kept_unless_a_site_waits_for_it()
    {
        uint dlsym = Data + 0x10, cos = Data + 0x100;
        var a = new A64(Code);
        uint helper = 0;
        A64 Got(uint slot) => a.Word(A64.Adrp(a.Here, slot, 16, Base)).Word(A64.LdrX(17, 16, slot & 0xFFF)).Word(A64.Blr(17));
        a.Word(A64.StpFpLrPre).Word(A64.MovFpSp).Word(A64.MovW(0, 0));
        a.Word(A64.Adrp(a.Here, cos, 1, Base)).Word(A64.AddImm(1, 1, cos & 0xFFF));
        Got(dlsym);
        a.Word(0xAA0003E8 /* mov x8, x0 */);
        uint late = a.Here;
        a.Word(A64.Blr(8)).Later(at => A64.Bl(at, helper));
        a.Word(A64.LdpFpLrPost).Word(A64.Ret);
        helper = a.Here;
        a.Word(A64.StpFpLrPre).Word(A64.MovFpSp).Word(A64.MovW(0, 0)).Word(A64.Adrp(a.Here, cos, 1, Base)).Word(A64.AddImm(1, 1, cos & 0xFFF));
        Got(dlsym);
        a.Word(A64.LdpFpLrPost).Word(A64.Ret);
        var data = new byte[0x200];
        Encoding.ASCII.GetBytes("cos ").CopyTo(data, cos - Data);
        var index = NativeCodeIndex.Build(CodeTestImage.Synthetic(NativeArch.Arm64, a.Bytes(), data, entry: Code, imports: [Import("dlsym", dlsym)]));
        var calls = Native.Calls.Arm64CallSites.For(index);
        Assert.Equal(2, calls.DynamicImports().GetProcAddressSites);
        var kept = (System.Collections.IDictionary)typeof(Native.Calls.Arm64CallSites).GetField("_sites", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance)!.GetValue(calls)!;
        Assert.Equal([helper], kept.Keys.Cast<uint>());
        var call = calls.CallsIn(index.FunctionByStart(Code)!).Single(s => s.Rva == late);
        Assert.Equal(("?!cos", Native.Calls.CalleeKind.Dynamic), (call.Callee, call.Kind));
    }

    /// <summary>open(path, 0x601, 0644) in a Mach-O image: Darwin's O_CREAT is 0x200 and O_TRUNC 0x400 (Linux would read O_TRUNC|O_APPEND).</summary>
    [Fact]
    public void Open_flags_use_the_images_operating_system()
    {
        uint open = Data + 0x10;
        var a = new A64(Code);
        a.Word(A64.StpFpLrPre).Word(A64.MovFpSp).Word(A64.MovW(1, 0x601)).Word(A64.MovW(2, 0x1A4));
        a.Word(A64.Adrp(a.Here, open, 16, Base)).Word(A64.LdrX(17, 16, open & 0xFFF)).Word(A64.Blr(17));
        a.Word(A64.LdpFpLrPost).Word(A64.Ret);
        string Flags(ImageFormat format)
        {
            var image = CodeTestImage.Synthetic(NativeArch.Arm64, a.Bytes(), new byte[0x200], entry: Code, imports: [Import("open", open)], format: format);
            var index = NativeCodeIndex.Build(image);
            return Native.Calls.Arm64CallSites.For(index).CallsIn(index.FunctionByStart(Code)!).Single().Arguments[1].Text;
        }
        Assert.Equal("O_WRONLY|O_CREAT|O_TRUNC", Flags(ImageFormat.MachO));
        Assert.Equal("_O_WRONLY|_O_TRUNC|_O_EXCL", Flags(ImageFormat.Pe));
    }

    /// <summary>
    /// d0 set before a branch reaches pow(d0, d1); s0 set before an unconditional branch reaches a callee without a
    /// signature; d0 that differs between the paths stays unknown.
    /// </summary>
    [Fact]
    public void Arm64_floating_point_arguments_set_in_predecessor_blocks()
    {
        uint pow = Data + 0x18;
        var a = new A64(Code);
        uint skip = 0, next = 0, helper = 0, other = 0, join = 0;
        A64 Got(uint slot) => a.Word(A64.Adrp(a.Here, slot, 16, Base)).Word(A64.LdrX(17, 16, slot & 0xFFF)).Word(A64.Blr(17));
        a.Word(A64.StpFpLrPre).Word(A64.MovFpSp);
        a.Word(0x1E6F1000 /* fmov d0, #1.5 */).Later(at => A64.Cbz(at, skip, 1)).Word(A64.Nop);
        skip = a.Here;
        a.Word(0x1E601001 /* fmov d1, #2.0 */);
        uint powCall = a.Here + 8;
        Got(pow);
        a.Word(0x1E2E1000 /* fmov s0, #1.0 */).Later(at => A64.B(at, next));
        next = a.Here;
        uint helperCall = a.Here;
        a.Later(at => A64.Bl(at, helper));
        a.Word(0x1E6F1000 /* fmov d0, #1.5 */).Later(at => A64.Cbz(at, other, 2)).Word(0x1E601000 /* fmov d0, #2.0 */).Later(at => A64.B(at, join));
        other = a.Here;
        a.Word(A64.Nop);
        join = a.Here;
        a.Word(0x1E601001 /* fmov d1, #2.0 */);
        uint mixedCall = a.Here + 8;
        Got(pow);
        a.Word(A64.LdpFpLrPost).Word(A64.Ret);
        helper = a.Here;
        a.Word(A64.Ret);
        var image = CodeTestImage.Synthetic(NativeArch.Arm64, a.Bytes(), entry: Code, imports: [Import("pow", pow)]);
        var index = NativeCodeIndex.Build(image);
        var sites = Native.Calls.Arm64CallSites.For(index).CallsIn(index.FunctionByStart(Code)!);
        Assert.Equal("pow(1.5, 2)", sites.Single(s => s.Rva == powCall).Display);
        var guessed = sites.Single(s => s.Rva == helperCall);
        Assert.Equal(["s0"], guessed.Arguments.Select(x => x.Location));
        Assert.Equal("1f", guessed.Arguments[0].Text);
        var mixed = sites.Single(s => s.Rva == mixedCall);
        Assert.Equal(("?", "2"), (mixed.Arguments[0].Text, mixed.Arguments[1].Text));
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

    [Trait("Speed", "Slow")]
    [Fact]
    public async Task Arm64_pe_is_decoded_end_to_end()
    {
        var pe = Native.Pe.PeFile.Open(NativeFixtures.WinArm64DbgShim);
        var index = NativeCodeIndex.Build(pe);
        Assert.Equal(CodeSupport.Full, index.Support);
        var starts = index.Functions.Select(f => f.Start).ToHashSet();
        // every entry starts a function, but a fragment without prologue the flow of another reaches, and an SEH handler
        // (__finally, __except, filter), which join their function as chunks
        Assert.All(pe.RuntimeFunctions, rf => Assert.True(starts.Contains(rf.BeginRva) || index.FunctionAt(rf.BeginRva) is { } f && (rf.Fragment || f.Chunks.Any(c => c.Start == rf.BeginRva)), $"0x{rf.BeginRva:X}"));
        Assert.Contains(pe.RuntimeFunctions, rf => rf.Fragment && !starts.Contains(rf.BeginRva));
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
