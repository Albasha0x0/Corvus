using System.Buffers.Binary;
using NetDecompilerMcp.Core;
using NetDecompilerMcp.Native.Dump;
using NetDecompilerMcp.Native.Pe;
using NetDecompilerMcp.Services;

namespace NetDecompilerMcp.Tests;

/// <summary>
/// A synthetic x64 crash: a module (only in dump memory) with three exported functions whose .pdata / UNWIND_INFO use
/// push nonvol, alloc small / large, set frame register, save nonvol and a chained fragment, and a stack where
/// Big calls Outer (from its chained fragment) which calls Crash, which writes through a null pointer.
/// </summary>
internal static class SyntheticCrash
{
    public const ulong Base = 0x7FF6_1000_0000;
    public const ulong Stack = 0xE0_0001_0000;
    public const uint CrashRva = 0x1000, OuterRva = 0x1020, FragmentRva = 0x1050, BigRva = 0x1080;
    public const ulong JitCode = 0x0000_0200_0000_0000;

    /// <summary>The module as mapped in memory.</summary>
    public static byte[] Image()
    {
        var pe = PeFile.FromBytes(FileImage());
        var mapped = new byte[pe.SizeOfImage];
        for (uint page = 0; page < mapped.Length; page += 0x1000) pe.Read(page, mapped.AsSpan((int)page, 0x1000));
        return mapped;
    }

    /// <summary>The module's file (synth.dll).</summary>
    public static byte[] FileImage()
    {
        var b = new PeBuilder { ImageBase = Base, Characteristics = 0x2022 };
        var text = new byte[0x100];
        // Crash: push rbx; sub rsp, 20h; mov [rax], ecx; add rsp, 20h; pop rbx; ret
        new byte[] { 0x53, 0x48, 0x83, 0xEC, 0x20, 0x89, 0x08, 0x48, 0x83, 0xC4, 0x20, 0x5B, 0xC3 }.CopyTo(text, 0x00);
        // Outer: push rbp; push rsi; sub rsp, 30h; lea rbp, [rsp+20h]; jmp fragment
        new byte[] { 0x55, 0x56, 0x48, 0x83, 0xEC, 0x30, 0x48, 0x8D, 0x6C, 0x24, 0x20, 0xE9, 0x20, 0x00, 0x00, 0x00 }.CopyTo(text, 0x20);
        // fragment: call Crash; lea rsp, [rbp+10h]; pop rsi; pop rbp; ret
        text[0x50] = 0xE8;
        BinaryPrimitives.WriteInt32LittleEndian(text.AsSpan(0x51), (int)CrashRva - (int)(FragmentRva + 5));
        new byte[] { 0x48, 0x8D, 0x65, 0x10, 0x5E, 0x5D, 0xC3 }.CopyTo(text, 0x55);
        // Big: sub rsp, 1000h; mov [rsp+1010h], rdi; call Outer; ...; ret
        new byte[] { 0x48, 0x81, 0xEC, 0x00, 0x10, 0x00, 0x00, 0x48, 0x89, 0xBC, 0x24, 0x10, 0x10, 0x00, 0x00, 0xE8 }.CopyTo(text, 0x80);
        BinaryPrimitives.WriteInt32LittleEndian(text.AsSpan(0x90), (int)OuterRva - (int)(BigRva + 20));
        new byte[] { 0x48, 0x8B, 0xBC, 0x24, 0x10, 0x10, 0x00, 0x00, 0x48, 0x81, 0xC4, 0x00, 0x10, 0x00, 0x00, 0xC3 }.CopyTo(text, 0x94);
        b.Add(".text", text, 0x60000020);

        uint uCrash = 0, uOuter = 0, uFragment = 0, uBig = 0, exports = 0, exportSize = 0;
        b.Add(".rdata", rva =>
        {
            var blob = new PeBlob(rva);
            uCrash = blob.Bytes([0x01, 5, 2, 0x00, 0x05, 0x32, 0x01, 0x30]); // alloc small 20h @5, push rbx @1
            uOuter = blob.Bytes([0x01, 11, 4, 0x25, 0x0B, 0x03, 0x06, 0x52, 0x02, 0x60, 0x01, 0x50]); // set fpreg rbp-20h @11, alloc 30h @6, push rsi @2, push rbp @1
            uFragment = blob.Bytes([0x21, 0, 0, 0x00]); // chained, no codes
            blob.U32(OuterRva);
            blob.U32(OuterRva + 0x10);
            uint chainedUnwind = blob.U32(0);
            uBig = blob.Bytes([0x01, 15, 4, 0x00, 0x0F, 0x74, 0x02, 0x02, 0x07, 0x01, 0x00, 0x02]); // save rdi @15 (slot 202h), alloc large 1000h @7
            blob.Patch32(chainedUnwind, uOuter);
            blob.Align(4);
            exports = blob.Zero(40);
            uint dll = blob.Ascii("synth.dll");
            blob.Align(4);
            uint eat = blob.U32(BigRva);
            blob.U32(CrashRva);
            blob.U32(OuterRva);
            uint n1 = blob.Ascii("Big"), n2 = blob.Ascii("Crash"), n3 = blob.Ascii("Outer");
            blob.Align(4);
            uint names = blob.U32(n1);
            blob.U32(n2);
            blob.U32(n3);
            uint ordinals = blob.U16(0);
            blob.U16(1);
            blob.U16(2);
            blob.Patch32(exports + 12, dll);
            blob.Patch32(exports + 16, 1);
            blob.Patch32(exports + 20, 3);
            blob.Patch32(exports + 24, 3);
            blob.Patch32(exports + 28, eat);
            blob.Patch32(exports + 32, names);
            blob.Patch32(exports + 36, ordinals);
            exportSize = blob.Here - exports;
            return blob.ToArray();
        });
        b.Directories[PeDirectory.Export] = (exports, exportSize);
        var pdata = b.Add(".pdata", rva =>
        {
            var blob = new PeBlob(rva);
            foreach (var (begin, end, unwind) in new[] { (CrashRva, CrashRva + 13, uCrash), (OuterRva, OuterRva + 0x10, uOuter), (FragmentRva, FragmentRva + 0xC, uFragment), (BigRva, BigRva + 0x24, uBig) })
            {
                blob.U32(begin);
                blob.U32(end);
                blob.U32(unwind);
            }
            return blob.ToArray();
        });
        b.Directories[PeDirectory.Exception] = (pdata.Rva, 48);
        return b.Build();
    }

    /// <summary>The crash; <paramref name="moduleBase"/> moves the module (ASLR), <paramref name="faultOffset"/> the faulting instruction inside Crash.</summary>
    public static MinidumpBuilder Builder(ulong moduleBase = Base, uint faultOffset = 5, uint code = 0xC0000005, bool exception = true, uint versionLs = 0x00030004)
    {
        var image = Image();
        var stack = new byte[0x1100];
        void Put(int at, ulong v) => BinaryPrimitives.WriteUInt64LittleEndian(stack.AsSpan(at), v);
        Put(0x20, 0x1111); // rbx saved by Crash
        Put(0x28, moduleBase + FragmentRva + 5);
        Put(0x60, 0x6666); // rsi saved by Outer
        Put(0x68, 0x5555); // caller's rbp
        Put(0x70, moduleBase + BigRva + 20);
        Put(0x1078, 0); // Big's return address: end of the stack
        Put(0x1088, 0x7777); // rdi saved by Big
        var d = new MinidumpBuilder { FullMemory = true };
        d.Modules.Add(new MinidumpBuilder.Module(moduleBase, (uint)image.Length, 0, @"Z:\nowhere\synth.dll", VersionLs: versionLs));
        d.Memory.Add((moduleBase, image));
        d.Memory.Add((Stack, stack));
        d.Memory.Add((JitCode - 0x10, Enumerable.Repeat((byte)0xCC, 0x40).ToArray()));
        d.Regions.Add(new MinidumpBuilder.Region(moduleBase, (ulong)image.Length, 0x20));
        d.Regions.Add(new MinidumpBuilder.Region(JitCode - 0x1000, 0x2000, 0x20));
        d.Regions.Add(new MinidumpBuilder.Region(Stack, 0x1100, 0x04));
        var crash = MinidumpBuilder.ContextX64(moduleBase + CrashRva + faultOffset, Stack, rbp: Stack + 0x50, rcx: 0x2A);
        d.Threads.Add(new MinidumpBuilder.Thread(100, Stack, crash, "main"));
        // inside Crash's epilog: after add rsp, before pop rbx
        d.Threads.Add(new MinidumpBuilder.Thread(101, Stack, MinidumpBuilder.ContextX64(moduleBase + CrashRva + 11, Stack + 0x20, rbp: Stack + 0x50)));
        // inside Crash's prolog: after push rbx, before sub rsp
        d.Threads.Add(new MinidumpBuilder.Thread(102, Stack, MinidumpBuilder.ContextX64(moduleBase + CrashRva + 1, Stack + 0x20, rbp: Stack + 0x50)));
        // in code outside any module (JIT): only a scan finds the caller
        d.Threads.Add(new MinidumpBuilder.Thread(103, Stack, MinidumpBuilder.ContextX64(JitCode, Stack, rbp: Stack + 0x50)));
        if (exception) d.Exception = (100, code, moduleBase + CrashRva + faultOffset, [1, 0], crash);
        return d;
    }

    public static string Write(TempDir dir, string name = "synth.dmp")
    {
        var path = dir.File(name);
        if (!File.Exists(path)) File.WriteAllBytes(path, Builder().Build());
        return path;
    }
}

public sealed class MinidumpTests
{
    [Fact]
    public async Task SyntheticCrashIsSummarizedAndUnwound()
    {
        using var dir = new TempDir();
        var path = SyntheticCrash.Write(dir);
        var service = new MinidumpService();
        var summary = await service.Summarize(path, null, 0, 50, 0, 50, default);
        Assert.Equal("synth.dmp", summary.Id);
        Assert.Equal("x64", summary.System!.Architecture);
        Assert.Equal(4242u, summary.Process.ProcessId);
        var e = summary.Exception!;
        Assert.Equal("EXCEPTION_ACCESS_VIOLATION", e.Name);
        Assert.Equal("access violation writing 0x0000000000000000 (a null or near-null pointer)", e.Description);
        Assert.Equal("synth!Crash+0x5", e.Symbol);
        Assert.Equal("export", e.SymbolSource);
        Assert.Equal("mov    dword ptr [rax], ecx", e.Instruction);
        Assert.Equal("dump_memory", e.InstructionSource);
        Assert.Equal("main", e.ThreadName);
        var module = Assert.Single(summary.Modules);
        Assert.Equal("missing", module.LocalImage);
        Assert.Empty(summary.Issues);

        var stack = await service.Stack(summary.Id, null, true, 64, 0, 64, null, default);
        Assert.Equal("exception", stack.Context);
        Assert.Equal(["synth!Crash+0x5", "synth!Outer+0x35", "synth!Big+0x14"], stack.Frames.Select(f => f.Symbol));
        Assert.Equal(["context", "unwind_info", "unwind_info"], stack.Frames.Select(f => f.Method));
        Assert.Equal("end_of_stack", stack.Stop);
        Assert.Equal(0, stack.HeuristicFrames);
        Assert.Contains(stack.Notes, n => n.StartsWith("synth.dll: image dump_memory", StringComparison.Ordinal));

        // epilog, prolog and a scan from code outside any module
        var epilog = await service.Stack(path, "101", true, 64, 0, 64, null, default);
        Assert.Equal(["synth!Crash+0xB", "synth!Outer+0x35", "synth!Big+0x14"], epilog.Frames.Select(f => f.Symbol));
        Assert.Equal("epilog", epilog.Frames[1].Method);
        var prolog = await service.Stack(path, "0x66", true, 64, 0, 64, null, default);
        Assert.Equal(["synth!Crash+0x1", "synth!Outer+0x35", "synth!Big+0x14"], prolog.Frames.Select(f => f.Symbol));
        var jit = await service.Stack(path, "#3", true, 64, 0, 64, null, default);
        Assert.Equal("unknown", jit.Frames[0].Kind);
        Assert.Equal("scan", jit.Frames[1].Method);
        Assert.True(jit.Frames[1].Heuristic);
        Assert.Equal(["synth!Outer+0x35", "synth!Big+0x14"], jit.Frames.Skip(1).Select(f => f.Symbol));

        var memory = await service.ReadMemory(path, "synth+0x1000", 16, true, default);
        Assert.Equal("dump_memory", memory.Source);
        Assert.StartsWith("00007FF6`10001000  53 48 83 EC 20 89 08 48-83 C4 20 5B C3", memory.Hex);
        Assert.Equal("synth!Crash", memory.Location);
        var missing = await service.ReadMemory(path, "0x10", 8, true, default);
        Assert.Equal(0, missing.Length);
        Assert.Equal("none", missing.Source);

        var error = await Assert.ThrowsAsync<ToolError>(() => service.Stack(path, "999", true, 64, 0, 64, null, default));
        Assert.Equal(ErrorCode.NotFound, error.Code);
    }

    [Fact]
    public void NotADumpIsRejectedAndMalformedDumpsNeverThrow()
    {
        var error = Assert.Throws<ToolError>(() => MinidumpFile.FromBytes(new byte[64]));
        Assert.Equal(ErrorCode.MalformedInput, error.Code);
        var good = SyntheticCrash.Builder().Build();

        // truncated anywhere after the header
        foreach (int cut in new[] { 32, 40, 100, 200, 400, 1000, good.Length / 2, good.Length - 100 })
        {
            using var dump = MinidumpFile.FromBytes(good[..cut]);
            Exercise(dump);
            if (cut < good.Length / 2) Assert.NotEmpty(dump.Issues);
        }

        // a stream directory past the end of the file
        var bad = (byte[])good.Clone();
        BinaryPrimitives.WriteUInt32LittleEndian(bad.AsSpan(12), 0x7FFFFFF0);
        using (var dump = MinidumpFile.FromBytes(bad))
        {
            Assert.Contains(dump.Issues, i => i.Message.Contains("runs past the end"));
            Assert.Empty(dump.Threads);
        }

        // two directory entries on the same data; a stream past the end
        bad = (byte[])good.Clone();
        Array.Copy(bad, 32 + 8, bad, 32 + 12 + 8, 4); // second stream's RVA = first stream's
        BinaryPrimitives.WriteUInt32LittleEndian(bad.AsSpan(32 + 2 * 12 + 8), (uint)good.Length - 4);
        using (var dump = MinidumpFile.FromBytes(bad))
        {
            Assert.Contains(dump.Issues, i => i.Message.Contains("overlaps"));
            Assert.Contains(dump.Issues, i => i.Message.Contains("runs past the end"));
            Exercise(dump);
        }

        // huge counts: thread list, memory list, stream count
        bad = (byte[])good.Clone();
        using (var probe = MinidumpFile.FromBytes(good))
        {
            foreach (var s in probe.Streams.Where(s => s.Type is MinidumpFile.ThreadListStream or MinidumpFile.ModuleListStream))
                BinaryPrimitives.WriteUInt32LittleEndian(bad.AsSpan((int)s.Rva), 0xFFFFFFFF);
            var mem = probe.Streams.Single(s => s.Type == MinidumpFile.Memory64ListStream);
            BinaryPrimitives.WriteUInt64LittleEndian(bad.AsSpan((int)mem.Rva), ulong.MaxValue);
        }
        BinaryPrimitives.WriteUInt32LittleEndian(bad.AsSpan(8), 0xFFFFFFFF);
        using (var dump = MinidumpFile.FromBytes(bad))
        {
            Assert.Contains(dump.Issues, i => i.Message.Contains("entries declared"));
            Assert.Contains(dump.Issues, i => i.Message.Contains("streams declared"));
            Exercise(dump);
        }

        // random byte mutations
        var random = new Random(11);
        for (int round = 0; round < 150; round++)
        {
            var m = (byte[])good.Clone();
            int flips = 1 + random.Next(16);
            for (int i = 0; i < flips; i++)
            {
                int at = random.Next(random.Next(4) == 0 ? m.Length : Math.Min(m.Length, 2048));
                m[at] = random.Next(3) == 0 ? (byte)0xFF : (byte)random.Next(256);
            }
            BinaryPrimitives.WriteUInt32LittleEndian(m, MinidumpFile.Signature);
            using var dump = MinidumpFile.FromBytes(m);
            Exercise(dump);
        }
    }

    /// <summary>Everything the tools do with a dump: contexts, memory, images, names and a stack walk of every thread.</summary>
    private static void Exercise(MinidumpFile dump)
    {
        var images = new Dictionary<DumpModule, PeFile?>();
        PeFile? Image(DumpModule m) => images.TryGetValue(m, out var i) ? i : images[m] = DumpImages.FromMemory(dump, m, out _);
        foreach (var m in dump.Modules.Take(8))
            if (Image(m) is { } image) new ModuleNames(image, null, null).Lookup(SyntheticCrash.CrashRva + 5);
        var walker = new StackWalker(dump, Image);
        foreach (var t in dump.Threads.Take(8))
        {
            var ctx = dump.ReadContext(t.Context);
            if (ctx == null) continue;
            var walk = walker.Walk(ctx, t.StackStart, t.StackStart + t.StackSize, 64);
            Assert.NotEmpty(walk.Frames);
        }
        if (dump.Exception is { } e)
        {
            dump.ReadContext(e.Context);
            ExceptionCodes.Describe(e.Code, e.Parameters, dump.Is64Bit);
        }
        var buffer = new byte[64];
        dump.ReadMemory(SyntheticCrash.Base, buffer);
        dump.ReadMemory(ulong.MaxValue - 8, buffer);
        _ = (dump.FlagNames, dump.Comments, dump.Handles, dump.UnloadedModules, dump.MemoryRegions, dump.MiscInfo, dump.SystemInfo);
    }
}
