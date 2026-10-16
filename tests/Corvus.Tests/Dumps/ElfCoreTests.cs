using Corvus.Core;
using Corvus.Native;
using Corvus.Native.Dump;
using Corvus.Native.Elf;
using Corvus.Services;
using Corvus.Tests.NativeFormats;

namespace Corvus.Tests;

/// <summary>
/// A synthetic Linux crash as an ELF core (x64 or AArch64): libcrash.so (ELF header, build id note, PT_DYNAMIC with
/// .dynsym, .eh_frame_hdr and .eh_frame) where M calls A (frame pointer, no FDE), A calls B (FDE with
/// remember/restore_state) and B calls crash::null() (FDE), which faults reading 0x10. Two threads, NT_SIGINFO,
/// NT_FILE, NT_AUXV and NT_PRPSINFO; the stack holds the saved registers and return addresses.
/// </summary>
internal static class SyntheticCore
{
    public const ulong Base = 0x7F00_0000_0000, Stack = 0x7FFD_0000_0000;
    public const ulong X = Stack + 0x1000, Y = X + 0x100;
    public const uint A = 0x1000, B = 0x1020, C = 0x1040, M = 0x1060;
    public const uint HdrRva = 0x1400, EhRva = 0x1480, HashRva = 0x1580, SymRva = 0x1600, StrRva = 0x1700, DynRva = 0x1800;
    public const string ModulePath = "/usr/lib/libcrash.so";
    public static readonly byte[] BuildId = [.. Enumerable.Range(0, 20).Select(i => (byte)(0xA0 + i))];

    /// <summary>The return address into the caller of each function and the crash point, as RVAs.</summary>
    public static (uint Crash, uint IntoB, uint IntoA, uint IntoM) Points(bool arm64) => arm64 ? (C + 8, B + 0x10, A + 0xC, M + 0xC) : (C + 2, B + 0xA, A + 9, M + 9);

    public static byte[] Module(bool arm64, byte[]? buildId = null)
    {
        var w = new ByteWriter();
        buildId ??= BuildId;
        // ELF header
        w.Bytes([0x7F, (byte)'E', (byte)'L', (byte)'F', 2, 1, 1, 0]);
        w.PadTo(16);
        w.U16(3); w.U16(arm64 ? ElfWriter.EmAarch64 : ElfWriter.EmX64); w.U32(1); w.U64(M); w.U64(0x40); w.U64(0); w.U32(0);
        w.U16(64); w.U16(56); w.U16(4); w.U16(64); w.U16(0); w.U16(0);
        void Phdr(uint type, uint flags, ulong at, ulong size, ulong align) { w.U32(type); w.U32(flags); w.U64(at); w.U64(at); w.U64(at); w.U64(size); w.U64(size); w.U64(align); }
        Phdr(1, 5, 0, 0x2000, 0x1000);
        Phdr(2, 6, DynRva, 0x60, 8);
        Phdr(0x6474E550, 4, HdrRva, 0x1C, 4);
        Phdr(4, 4, 0x200, 36, 4);
        w.PadTo(0x200);
        w.U32(4); w.U32((uint)buildId.Length); w.U32(3); w.Bytes("GNU\0"u8); w.Bytes(buildId);

        // code: only the x64 crash instruction is decoded (mov dword ptr [rax], ecx)
        w.PadTo((int)A);
        if (!arm64)
        {
            w.BytesAt((int)A, [0x55, 0x48, 0x89, 0xE5, 0xE8]);
            w.BytesAt((int)B, [0x53, 0x48, 0x83, 0xEC, 0x10, 0xE8]);
            w.BytesAt((int)C, [0x41, 0x54, 0x89, 0x08]);
            w.BytesAt((int)M, [0x55, 0x48, 0x89, 0xE5, 0xE8]);
        }
        w.PadTo((int)M + 0x20);

        // .eh_frame: a CIE, then FDEs for B and C
        w.PadTo((int)EhRva);
        int cie = w.Length;
        var c = new ByteWriter();
        c.U32(0); c.U8(1); c.CString("zR");
        if (arm64) { c.Uleb(4); c.Sleb(-8); c.U8(30); c.Uleb(1); c.U8(0x1B); c.Bytes([0x0C, 31, 0]); }
        else { c.Uleb(1); c.Sleb(-8); c.U8(16); c.Uleb(1); c.U8(0x1B); c.Bytes([0x0C, 7, 8, 0x90, 1]); }
        while ((c.Length + 4) % 8 != 0) c.U8(0);
        w.U32((uint)c.Length);
        w.Bytes(c.ToArray());
        int Fde(uint start, uint size, byte[] insns)
        {
            int at = w.Length;
            var f = new ByteWriter();
            f.U32((uint)(at + 4 - cie));
            f.U32((uint)(start - (at + 8)));
            f.U32(size);
            f.Uleb(0);
            f.Bytes(insns);
            while ((f.Length + 4) % 8 != 0) f.U8(0);
            w.U32((uint)f.Length);
            w.Bytes(f.ToArray());
            return at;
        }
        // B: CFA moves with the prologue; remember_state, a bogus offset, restore_state at the call
        int fdeB = Fde(B, 0x20, arm64
            ? [0x41, 0x0E, 0x20, 0x41, 0x9D, 0x02, 0x9E, 0x01, 0x41, 0x0C, 29, 0x10, 0x0A, 0x0E, 0x63, 0x0B]
            : [0x41, 0x0E, 0x10, 0x83, 0x02, 0x44, 0x0E, 0x20, 0x0A, 0x0E, 0x63, 0x0B]);
        int fdeC = Fde(C, 0x20, arm64 ? [0x41, 0x0E, 0x10, 0x9D, 0x02, 0x9E, 0x01] : [0x42, 0x0E, 0x10, 0x8C, 0x02]);
        w.U32(0);

        // .eh_frame_hdr: pcrel eh_frame pointer, udata4 count, datarel sdata4 table
        w.BytesAt((int)HdrRva, [1, 0x1B, 0x03, 0x3B]);
        w.U32At((int)HdrRva + 4, EhRva - (HdrRva + 4));
        w.U32At((int)HdrRva + 8, 2);
        static uint Rel(long to) => unchecked((uint)(to - HdrRva));
        w.U32At((int)HdrRva + 12, Rel(B)); w.U32At((int)HdrRva + 16, Rel(fdeB));
        w.U32At((int)HdrRva + 20, Rel(C)); w.U32At((int)HdrRva + 24, Rel(fdeC));

        // .hash, .dynsym, .dynstr, .dynamic
        string[] names = ["A", "B", "_ZN5crash4nullEv", "M"];
        uint[] values = [A, B, C, M];
        w.PadTo((int)HashRva);
        w.U32(1); w.U32(5); w.U32(4); w.U32(0); w.U32(0); w.U32(1); w.U32(2); w.U32(3);
        w.PadTo((int)SymRva + 24);
        uint nameAt = 1;
        for (int i = 0; i < 4; i++)
        {
            w.U32(nameAt); w.U8(0x12); w.U8(0); w.U16(1); w.U64(values[i]); w.U64(0x20);
            nameAt += (uint)names[i].Length + 1;
        }
        w.PadTo((int)StrRva);
        w.U8(0);
        foreach (var n in names) w.CString(n);
        w.PadTo((int)DynRva);
        foreach (var (tag, value) in new (ulong, ulong)[] { (4, HashRva), (5, StrRva), (6, SymRva), (10, nameAt), (11, 24), (0, 0) }) { w.U64(tag); w.U64(value); }
        w.PadTo(0x2000);
        return w.ToArray();
    }

    /// <summary>The core; <paramref name="moduleCode"/> false keeps only the module's first page, as a default Linux core does.</summary>
    public static byte[] Core(bool arm64, bool moduleCode = true)
    {
        var module = Module(arm64);
        var p = Points(arm64);
        var stack = new byte[0x2000];
        void Put(ulong va, ulong v) => BitConverter.GetBytes(v).CopyTo(stack, (int)(va - Stack));
        if (arm64)
        {
            Put(X, X + 32); Put(X + 8, Base + p.IntoB);
            Put(X + 32, X + 48); Put(X + 40, Base + p.IntoA);
        }
        else
        {
            Put(X, 0x1212); Put(X + 8, Base + p.IntoB);
            Put(X + 32, 0x3333); Put(X + 40, Base + p.IntoA);
        }
        Put(X + 48, Y); Put(X + 56, Base + p.IntoM);
        "/usr/bin/crasher\0"u8.CopyTo(stack.AsSpan(0x1F00));

        var notes = new ByteWriter();
        void Note(uint type, byte[] desc) { notes.U32(5); notes.U32((uint)desc.Length); notes.U32(type); notes.Bytes("CORE\0\0\0\0"u8); notes.Bytes(desc); notes.Align(4); }
        byte[] Prstatus(uint tid, ushort signal, ulong pc, ulong sp, ulong fp, ulong lr)
        {
            var regs = new ulong[arm64 ? 34 : 27];
            if (arm64) { regs[32] = pc; regs[31] = sp; regs[29] = fp; regs[30] = lr; }
            else { regs[16] = pc; regs[19] = sp; regs[4] = fp; regs[5] = 0xBBBB; regs[3] = 0xC12; }
            var d = new ByteWriter();
            d.U32(signal); d.U32(0); d.U32(0); d.U16(signal); d.U16(0);
            d.PadTo(32); d.U32(tid); d.U32(1); d.U32(tid); d.U32(tid);
            d.PadTo(112);
            foreach (var r in regs) d.U64(r);
            d.U32(1);
            d.Align(8);
            return d.ToArray();
        }
        Note(1, Prstatus(1001, 11, Base + p.Crash, X, arm64 ? X : X + 48, Base + B + 0x10));
        Note(1, Prstatus(1002, 0, Base + p.IntoM, Y - 16, Y, 0));
        var ps = new ByteWriter();
        ps.U8(0); ps.U8((byte)'R'); ps.U8(0); ps.U8(0); ps.U32(0); ps.U64(0); ps.U32(1000); ps.U32(1000); ps.U32(4242); ps.U32(1); ps.U32(4242); ps.U32(4242);
        ps.FixedString("crasher", 16); ps.FixedString("./crasher --now", 80);
        Note(3, ps.ToArray());
        var si = new ByteWriter();
        si.U32(11); si.U32(0); si.U32(1); si.U32(0); si.U64(0x10); si.PadTo(128);
        Note(0x53494749, si.ToArray());
        var aux = new ByteWriter();
        foreach (var (t, v) in new (ulong, ulong)[] { (3, Base + 0x40), (6, 0x1000), (9, Base + M), (31, Stack + 0x1F00), (0, 0) }) { aux.U64(t); aux.U64(v); }
        Note(6, aux.ToArray());
        var nf = new ByteWriter();
        nf.U64(2); nf.U64(0x1000);
        nf.U64(Base); nf.U64(Base + 0x1000); nf.U64(0);
        nf.U64(Base + 0x1000); nf.U64(Base + 0x2000); nf.U64(1);
        nf.CString(ModulePath); nf.CString(ModulePath);
        Note(0x46494C45, nf.ToArray());
        var noteBytes = notes.ToArray();

        var w = new ByteWriter();
        w.Bytes([0x7F, (byte)'E', (byte)'L', (byte)'F', 2, 1, 1, 0]);
        w.PadTo(16);
        w.U16(4); w.U16(arm64 ? ElfWriter.EmAarch64 : ElfWriter.EmX64); w.U32(1); w.U64(0); w.U64(0x40); w.U64(0); w.U32(0);
        w.U16(64); w.U16(56); w.U16(4); w.U16(64); w.U16(0); w.U16(0);
        int notesAt = 0x200, data = 0x1000 * ((notesAt + noteBytes.Length + 0xFFF) / 0x1000);
        void Phdr(uint type, uint flags, ulong offset, ulong va, ulong filesz, ulong memsz) { w.U32(type); w.U32(flags); w.U64(offset); w.U64(va); w.U64(0); w.U64(filesz); w.U64(memsz); w.U64(type == 4 ? 4u : 0x1000u); }
        Phdr(4, 0, (ulong)notesAt, 0, (ulong)noteBytes.Length, 0);
        Phdr(1, 5, (ulong)data, Base, 0x1000, 0x1000);
        Phdr(1, 5, (ulong)data + 0x1000, Base + 0x1000, moduleCode ? 0x1000u : 0, 0x1000);
        Phdr(1, 6, (ulong)data + (moduleCode ? 0x2000u : 0x1000u), Stack, 0x2000, 0x2000);
        w.PadTo(notesAt);
        w.Bytes(noteBytes);
        w.PadTo(data);
        w.Bytes(module.AsSpan(0, moduleCode ? 0x2000 : 0x1000));
        w.Bytes(stack);
        return w.ToArray();
    }
}

public sealed class ElfCoreTests
{
    private static string Write(TempDir dir, byte[] bytes, string name = "app.core")
    {
        var path = dir.File(name);
        File.WriteAllBytes(path, bytes);
        return path;
    }

    [Fact]
    public void Core_notes_give_threads_signal_files_auxv_and_process()
    {
        using var core = ElfCoreFile.FromBytes(SyntheticCore.Core(arm64: false), "app.core");
        Assert.Empty(core.Issues);
        Assert.Equal(NativeArch.X64, core.Arch);
        Assert.Equal([1001u, 1002u], core.Threads.Select(t => t.Id));
        Assert.Equal(11, core.FaultingThread!.Signal);
        Assert.Equal(SyntheticCore.Base + SyntheticCore.C + 2, core.Threads[0].Registers!.Pc);
        Assert.Equal(new ElfCoreSignal(11, 1, 0, 0x10, null), core.Signal);
        Assert.Equal(2, core.Files.Count);
        var module = Assert.Single(core.CoreModules);
        Assert.Equal(SyntheticCore.Base, module.Module.Base);
        Assert.Equal(0x2000u, module.Module.Size);
        Assert.Equal(Convert.ToHexStringLower(SyntheticCore.BuildId), module.BuildId);
        Assert.Same(module, core.MainModule);
        Assert.Equal("crasher", core.Process!.Name);
        Assert.Equal("./crasher --now", core.Process.Arguments);
        Assert.Equal(4242u, core.Process.Pid);
        Assert.Equal("/usr/bin/crasher", core.ReadString(core.Aux(31)!.Value));
        Assert.Equal(3, core.Segments.Count);
    }

    [Fact]
    public async Task Open_minidump_summarizes_an_x64_core()
    {
        using var dir = new TempDir();
        var path = Write(dir, SyntheticCore.Core(arm64: false));
        using var service = new MinidumpService();
        var r = await service.Summarize(path, null, CancellationToken.None);
        Assert.Equal("app.core", r.Id);
        Assert.Equal("x64", r.System!.Architecture);
        Assert.Equal("Linux", r.System.Os);
        Assert.Equal(4242u, r.Process!.ProcessId);
        Assert.Equal("/usr/bin/crasher", r.Process.MainModule);
        var e = r.Exception!;
        Assert.Equal("SIGSEGV", e.Name);
        Assert.Contains("SEGV_MAPERR", e.Description);
        Assert.Contains("0x10 (a null or near-null pointer)", e.Description);
        Assert.Equal(1001u, e.ThreadId);
        Assert.Equal("libcrash.so!crash::null()+0x2", e.Symbol);
        Assert.Equal("export", e.SymbolSource);
        Assert.StartsWith("mov", e.Instruction);
        Assert.Contains("rip=00007f0000001042", e.Registers);
        Assert.Equal(Convert.ToHexStringLower(SyntheticCore.BuildId), r.FaultingModule!.BuildId);
        Assert.Equal("missing", r.FaultingModule.LocalImage);
        Assert.True(r.FaultingThread!.Faulting);
        Assert.Equal(2, r.Counts!.Threads);
        Assert.Contains(r.Notes!, n => n.Contains("crasher (pid 4242") && n.Contains("./crasher --now"));
        Assert.Contains(r.Notes!, n => n.Contains("AT_EXECFN=/usr/bin/crasher") && n.Contains("AT_ENTRY=0x7F0000001060"));

        var (_, threads, total) = await service.Threads(path, null, 0, 10, CancellationToken.None);
        Assert.Equal(2, total);
        Assert.Equal("libcrash.so!M+0x9", threads[1].Location);
        var (_, memory, regions) = service.Memory(path, 0, 10);
        Assert.Equal(3, regions);
        Assert.Contains(memory, m => m.Protection == "rw-" && m.Type == "private");
        Assert.Equal("image", memory[0].Type);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Dump_stack_unwinds_by_cfi_then_frame_pointer(bool arm64)
    {
        using var dir = new TempDir();
        var path = Write(dir, SyntheticCore.Core(arm64));
        using var service = new MinidumpService();
        var r = await service.Stack(path, null, true, 64, 0, 64, null, CancellationToken.None);
        Assert.Equal(arm64 ? "ARM64" : "x64", r.Architecture);
        Assert.Equal("end_of_stack", r.Stop);
        Assert.Equal(["crash::null()", "B", "A", "M"], r.Items.Select(f => f.Function));
        Assert.Equal([FrameMethod.Context, FrameMethod.UnwindInfo, FrameMethod.UnwindInfo, FrameMethod.FramePointer], r.Items.Select(f => f.Method));
        var p = SyntheticCore.Points(arm64);
        Assert.Equal($"0x{SyntheticCore.Base + p.IntoM:X}", r.Items[3].Address);
        Assert.Equal($"0x{SyntheticCore.X + 64:X}", r.Items[3].StackPointer);
        Assert.Contains(r.Notes, n => n.StartsWith("libcrash.so: image core_memory") && n.Contains(".eh_frame") && n.Contains("4 function symbols"));

        var second = await service.Stack(path, "1002", true, 64, 0, 64, null, CancellationToken.None);
        Assert.Equal(1002u, second.ThreadId);
        Assert.Equal("M", second.Items[0].Function);
    }

    [Fact]
    public async Task Module_code_comes_from_the_file_matched_by_build_id()
    {
        using var dir = new TempDir();
        var path = Write(dir, SyntheticCore.Core(arm64: false, moduleCode: false));
        File.WriteAllBytes(dir.File("libcrash.so"), SyntheticCore.Module(arm64: false));
        using var service = new MinidumpService();
        var (_, modules, _) = service.Modules(path, null, 0, 10);
        Assert.Equal("matches", modules[0].LocalImage);
        Assert.Contains("build id", modules[0].LocalDetail);

        var r = await service.Stack(path, null, true, 64, 0, 64, null, CancellationToken.None);
        Assert.Equal(["crash::null()", "B", "A", "M"], r.Items.Select(f => f.Function));
        Assert.Contains(r.Notes, n => n.StartsWith("libcrash.so: image disk"));

        var read = await service.ReadMemory(path, "libcrash.so+0x1040", 4, true, CancellationToken.None);
        Assert.Equal("41548908", read.Code);
        Assert.Equal("module_image (disk)", read.Source);
        var dumpOnly = await service.ReadMemory(path, "libcrash.so+0x1040", 4, false, CancellationToken.None);
        Assert.Equal(0, dumpOnly.Length);

        using var other = new TempDir();
        var moved = Write(other, File.ReadAllBytes(path));
        File.WriteAllBytes(other.File("libcrash.so"), SyntheticCore.Module(arm64: false, buildId: new byte[20]));
        using var fresh = new MinidumpService();
        Assert.Equal("mismatch", fresh.Modules(moved, null, 0, 10).Rows[0].LocalImage);
    }

    [Fact]
    public async Task Read_dump_memory_reads_core_segments()
    {
        using var dir = new TempDir();
        var path = Write(dir, SyntheticCore.Core(arm64: false));
        using var service = new MinidumpService();
        var read = await service.ReadMemory(path, $"0x{SyntheticCore.Stack + 0x1F00:X}", 16, false, CancellationToken.None);
        Assert.Equal("dump_memory", read.Source);
        Assert.Equal("rw-", read.Protection);
        Assert.Equal(Convert.ToHexString("/usr/bin/crasher"u8), read.Code);
    }

    [Fact]
    public async Task Managed_heap_of_a_core_is_unsupported()
    {
        using var dir = new TempDir();
        var path = Write(dir, SyntheticCore.Core(arm64: false));
        using var service = new MinidumpService();
        var heap = await Assert.ThrowsAsync<ToolError>(() => service.Heap(path, "stats", null, 0, 0, 10, 1000, CancellationToken.None));
        Assert.Equal(ErrorCode.Unsupported, heap.Code);
        Assert.Contains("Linux DAC", heap.Remediation);
        var obj = await Assert.ThrowsAsync<ToolError>(() => service.Object(path, "0x1000", 1, 10, 10, CancellationToken.None));
        Assert.Equal(ErrorCode.Unsupported, obj.Code);
    }

    [Fact]
    public async Task Bucket_minidumps_groups_cores_by_signal_and_frames()
    {
        using var dir = new TempDir();
        var bytes = SyntheticCore.Core(arm64: false);
        Write(dir, bytes, "app.core");
        Write(dir, bytes, "core.4242");
        File.WriteAllText(dir.File("core.c"), "int main() { return 0; }");
        using var service = new MinidumpService { BucketCache = dir.File("cache") };
        var r = await service.Bucket(dir.Path, false, null, 3, null, false, true, 100, null, 0, 10, null, CancellationToken.None);
        Assert.Empty(r.Failed);
        var bucket = Assert.Single(r.Items);
        Assert.Equal(2, bucket.Count);
        Assert.Equal("SIGSEGV | libcrash.so!crash::null() | libcrash.so!B > libcrash.so!A > libcrash.so!M", bucket.Signature);
        Assert.Equal("exception", bucket.Kind);
    }

    [Fact]
    public async Task Get_pe_info_points_a_core_to_open_minidump()
    {
        using var dir = new TempDir();
        var path = Write(dir, SyntheticCore.Core(arm64: true));
        using var h = new NativeToolHarness(backgroundIndexing: false);
        Assert.Contains("a core dump: open_minidump", await h.Native.GetPeInfo(path));
    }

    [Fact]
    [FuzzEntry(typeof(ElfCoreFile), typeof(ElfMemoryHeader))]
    public void Fuzzed_cores_never_throw()
    {
        var failures = FormatFuzz.Run(SyntheticCore.Core(arm64: false), b =>
        {
            try
            {
                using var core = ElfCoreFile.FromBytes(b);
                foreach (var t in core.Threads)
                {
                    if (t.Registers == null || !t.Registers.Arch.Unwinds) continue;
                    var images = new Dictionary<DumpModule, ElfCoreImage?>();
                    ElfCoreImage? Image(ulong a) => core.ModuleAt(a) is { } m ? images.TryGetValue(m, out var i) ? i : images[m] = ElfCoreImage.FromMemory(core, m, "") : null;
                    var walk = new ElfCoreUnwinder(core, t.Registers.Arch, Image).Walk(t.Registers, 0, 0, 64);
                    foreach (var f in walk.Frames) _ = Image(f.LookupAddress)?.SymbolAt(f.LookupAddress);
                }
            }
            catch (ToolError) { }
        }, 1500);
        Assert.Empty(failures);
    }

    [Fact]
    public void Fuzzed_cfi_never_throws()
    {
        var module = SyntheticCore.Module(arm64: true);
        var seed = module.AsSpan((int)SyntheticCore.EhRva, 0x100).ToArray();
        var failures = FormatFuzz.Run(seed, b =>
        {
            var view = new ByteView(b, false);
            foreach (var fde in EhFrame.WalkFull(view, SyntheticCore.EhRva, true, 64))
                for (ulong pc = fde.Start; pc < fde.Start + Math.Min(fde.Range, 0x40); pc += 4)
                    _ = EhFrame.Row(view, SyntheticCore.EhRva, true, fde, pc, out _);
        }, 3000);
        Assert.Empty(failures);
    }

    [RequiresRealDataFact(RealData.ElfCores)]
    public async Task Real_cores_open_and_walk()
    {
        var root = RealData.Path(RealData.ElfCores);
        using var service = new MinidumpService();
        int seen = 0;
        foreach (var path in Directory.EnumerateFiles(root, "*", SearchOption.AllDirectories).Where(ElfCoreFile.IsCore))
        {
            seen++;
            var summary = await service.Summarize(path, Path.GetDirectoryName(path), CancellationToken.None);
            Assert.NotNull(summary.System);
            var stack = await service.Stack(path, null, true, 64, 0, 64, null, CancellationToken.None);
            Assert.NotEmpty(stack.Items);
        }
        Assert.True(seen > 0, $"no ELF core under {root}");
    }
}
