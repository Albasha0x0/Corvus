using System.Buffers.Binary;
using Corvus.Core;
using Corvus.Native.Dump;
using Corvus.Native.Pe;
using Corvus.Services;

namespace Corvus.Tests;

/// <summary>A synthetic x64 crash whose stack unwinds through every UNWIND_INFO form and a chained fragment.</summary>
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
        // Crash: push rbx; sub rsp, 20h; mov [rax], ecx; add rsp, 20h; pop rbx; ret.
        new byte[] { 0x53, 0x48, 0x83, 0xEC, 0x20, 0x89, 0x08, 0x48, 0x83, 0xC4, 0x20, 0x5B, 0xC3 }.CopyTo(text, 0x00);
        // Outer: push rbp; push rsi; sub rsp, 30h; lea rbp, [rsp+20h]; jmp fragment.
        new byte[] { 0x55, 0x56, 0x48, 0x83, 0xEC, 0x30, 0x48, 0x8D, 0x6C, 0x24, 0x20, 0xE9, 0x20, 0x00, 0x00, 0x00 }.CopyTo(text, 0x20);
        // Fragment: call Crash; lea rsp, [rbp+10h]; pop rsi; pop rbp; ret.
        text[0x50] = 0xE8;
        BinaryPrimitives.WriteInt32LittleEndian(text.AsSpan(0x51), (int)CrashRva - (int)(FragmentRva + 5));
        new byte[] { 0x48, 0x8D, 0x65, 0x10, 0x5E, 0x5D, 0xC3 }.CopyTo(text, 0x55);
        // Big: sub rsp, 1000h; mov [rsp+1010h], rdi; call Outer; ...; ret.
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
        // Inside Crash's epilog: after add rsp, before pop rbx.
        d.Threads.Add(new MinidumpBuilder.Thread(101, Stack, MinidumpBuilder.ContextX64(moduleBase + CrashRva + 11, Stack + 0x20, rbp: Stack + 0x50)));
        // Inside Crash's prolog: after push rbx, before sub rsp.
        d.Threads.Add(new MinidumpBuilder.Thread(102, Stack, MinidumpBuilder.ContextX64(moduleBase + CrashRva + 1, Stack + 0x20, rbp: Stack + 0x50)));
        // In code outside any module (JIT): only a scan finds the caller.
        d.Threads.Add(new MinidumpBuilder.Thread(103, Stack, MinidumpBuilder.ContextX64(JitCode, Stack, rbp: Stack + 0x50)));
        // A call to a bad address from Outer's fragment: the return address is at the stack pointer.
        d.Threads.Add(new MinidumpBuilder.Thread(104, Stack, MinidumpBuilder.ContextX64(0x1234, Stack + 0x28, rbp: Stack + 0x50)));
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

/// <summary>Synthetic x86 crashes: frame-pointer-less frames, a bad call target and a call through an import slot.</summary>
internal static class SyntheticCrashX86
{
    public const uint Base = 0x1000_0000, HaltBase = 0x2000_0000, Stack = 0x00E0_0000;
    public const uint LeafRva = 0x1000, MidRva = 0x1020, TopRva = 0x1040, JumpRva = 0x1060, TrapRva = 0x1070, TailRva = 0x1080, OuterRva = 0x10A0;

    /// <summary>
    /// A PE32 with .text at 0x1000 and .rdata at 0x2000: exports, one import whose IAT slot VA the code gets, and a
    /// CodeView record naming a PDB.
    /// </summary>
    internal static byte[] Pe32(string dll, uint imageBase, Func<uint, byte[]> text, (string Name, uint Rva)[] exports, (string Module, string Name)? import,
        (Guid Guid, uint Age, string Pdb)? codeView = null)
    {
        var blob = new PeBlob(0x2000);
        uint descriptors = 0, slot = 0;
        if (import is { } imp)
        {
            descriptors = blob.Zero(40);
            uint module = blob.Ascii(imp.Module);
            blob.Align(2);
            uint hint = blob.U16(0);
            blob.Ascii(imp.Name);
            blob.Align(4);
            uint ilt = blob.U32(hint);
            blob.U32(0);
            slot = blob.U32(hint);
            blob.U32(0);
            blob.Patch32(descriptors, ilt);
            blob.Patch32(descriptors + 12, module);
            blob.Patch32(descriptors + 16, slot);
        }
        blob.Align(4);
        uint dir = blob.Zero(40);
        uint name = blob.Ascii(dll);
        blob.Align(4);
        uint eat = blob.Here;
        foreach (var e in exports) blob.U32(e.Rva);
        var nameRvas = exports.Select(e => blob.Ascii(e.Name)).ToList();
        blob.Align(4);
        uint names = blob.Here;
        foreach (var n in nameRvas) blob.U32(n);
        uint ordinals = blob.Here;
        for (int i = 0; i < exports.Length; i++) blob.U16((ushort)i);
        blob.Patch32(dir + 12, name);
        blob.Patch32(dir + 16, 1);
        blob.Patch32(dir + 20, (uint)exports.Length);
        blob.Patch32(dir + 24, (uint)exports.Length);
        blob.Patch32(dir + 28, eat);
        blob.Patch32(dir + 32, names);
        blob.Patch32(dir + 36, ordinals);
        uint debug = 0;
        if (codeView is { } cv)
        {
            blob.Align(4);
            debug = blob.Zero(28);
            uint record = blob.Here;
            blob.Bytes("RSDS"u8);
            blob.Bytes(cv.Guid.ToByteArray());
            blob.U32(cv.Age);
            blob.Ascii(cv.Pdb);
            blob.Patch32(debug + 12, 2);
            blob.Patch32(debug + 16, blob.Here - record);
            blob.Patch32(debug + 20, record);
        }
        var b = new PeBuilder { Is64 = false, Machine = 0x14C, ImageBase = imageBase, Characteristics = 0x2102 };
        b.Add(".text", text(imageBase + slot), 0x60000020);
        b.Add(".rdata", blob.ToArray());
        b.Directories[PeDirectory.Export] = (dir, blob.Here - dir);
        if (import != null) b.Directories[PeDirectory.Import] = (descriptors, 40);
        if (debug != 0) b.Directories[6] = (debug, 28);
        return b.Build();
    }

    public static byte[] FileImage() => Pe32("synth32.dll", Base, slotVa =>
    {
        var text = new byte[0xC0];
        new byte[] { 0x89, 0x08, 0xC3 }.CopyTo(text, 0x00); // Leaf: mov [eax], ecx; ret
        text[0x20] = 0x56; // Mid: push esi; call Leaf; pop esi; ret
        text[0x21] = 0xE8;
        BinaryPrimitives.WriteInt32LittleEndian(text.AsSpan(0x22), (int)LeafRva - (int)(MidRva + 6));
        new byte[] { 0x5E, 0xC3 }.CopyTo(text, 0x26);
        new byte[] { 0x55, 0x8B, 0xEC, 0xE8 }.CopyTo(text, 0x40); // Top: push ebp; mov ebp, esp; call Mid; pop ebp; ret
        BinaryPrimitives.WriteInt32LittleEndian(text.AsSpan(0x44), (int)MidRva - (int)(TopRva + 8));
        new byte[] { 0x5D, 0xC3 }.CopyTo(text, 0x48);
        new byte[] { 0xFF, 0xD0, 0xC3 }.CopyTo(text, 0x60); // Jump: call eax; ret
        new byte[] { 0xFF, 0x15 }.CopyTo(text, 0x70); // Trap: call [halt.dll!Halt]; ret
        BinaryPrimitives.WriteUInt32LittleEndian(text.AsSpan(0x72), slotVa);
        text[0x76] = 0xC3;
        new byte[] { 0x89, 0xC8, 0xE9 }.CopyTo(text, 0x80); // Tail: mov eax, ecx; jmp Leaf (a tail call)
        BinaryPrimitives.WriteInt32LittleEndian(text.AsSpan(0x83), (int)LeafRva - (int)(TailRva + 7));
        new byte[] { 0x55, 0x8B, 0xEC, 0xE8 }.CopyTo(text, 0xA0); // Outer: push ebp; mov ebp, esp; call Tail; pop ebp; ret
        BinaryPrimitives.WriteInt32LittleEndian(text.AsSpan(0xA4), (int)TailRva - (int)(OuterRva + 8));
        new byte[] { 0x5D, 0xC3 }.CopyTo(text, 0xA8);
        return text;
    }, [("Leaf", LeafRva), ("Mid", MidRva), ("Top", TopRva), ("Jump", JumpRva), ("Trap", TrapRva), ("Tail", TailRva), ("Outer", OuterRva)], ("halt.dll", "Halt"));

    public static byte[] HaltImage() => Pe32("halt.dll", HaltBase, _ => [0x8B, 0xFF, 0xCC, 0xC3], [("Halt", 0x1000)], null); // mov edi, edi; int3; ret

    internal static byte[] Mapped(byte[] file)
    {
        var pe = PeFile.FromBytes(file);
        var image = new byte[pe.SizeOfImage];
        for (uint page = 0; page < image.Length; page += 0x1000) pe.Read(page, image.AsSpan((int)page, 0x1000));
        return image;
    }

    public const uint Jit = 0x0300_0000;

    /// <summary>The 32-bit stack at <see cref="Stack"/>: Leaf's frame up to Top's at 0x00, a bad call's return at 0x100, Halt's at 0x200.</summary>
    internal static byte[] StackBytes(bool jit = false)
    {
        var stack = new byte[0x300];
        void Put(int at, uint v) => BinaryPrimitives.WriteUInt32LittleEndian(stack.AsSpan(at), v);
        Put(0x00, Base + MidRva + 6); // Leaf's return into Mid
        Put(0x04, 0x6666); // esi saved by Mid
        Put(0x08, Base + TopRva + 8); // Mid's return into Top
        Put(0x0C, 0); // Top's saved ebp; EBP points here
        Put(0x10, jit ? Jit + 5 : 0); // Top's return: into JIT code, or the end
        Put(0x100, Base + JumpRva + 2); // the bad call's return into Jump
        Put(0x200, Base + TrapRva + 6); // Halt's return into Trap
        Put(0x280, Base + OuterRva + 8); // Leaf's return into Outer, which called Tail (Tail tail-jumped to Leaf); EBP at 0x284
        return stack;
    }

    /// <summary>The dump; <paramref name="jit"/> puts JIT code (an executable region outside any module) below Top on the stack.</summary>
    public static string Write(TempDir dir, string name = "synth32.dmp", bool jit = false)
    {
        var image = Mapped(FileImage());
        var halt = Mapped(HaltImage());
        var stack = StackBytes(jit);
        var d = new MinidumpBuilder { FullMemory = true, ProcessorArchitecture = 0 };
        d.Modules.Add(new MinidumpBuilder.Module(Base, (uint)image.Length, 0, @"Z:\nowhere\synth32.dll"));
        d.Modules.Add(new MinidumpBuilder.Module(HaltBase, (uint)halt.Length, 0, @"Z:\nowhere\halt.dll"));
        d.Memory.Add((Base, image));
        d.Memory.Add((HaltBase, halt));
        d.Memory.Add((Stack, stack));
        d.Regions.Add(new MinidumpBuilder.Region(Base, (ulong)image.Length, 0x20));
        d.Regions.Add(new MinidumpBuilder.Region(HaltBase, (ulong)halt.Length, 0x20));
        d.Regions.Add(new MinidumpBuilder.Region(Stack, 0x300, 0x04));
        if (jit)
        {
            d.Memory.Add((Jit, [0xE8, 0, 0, 0, 0, 0xC3, 0, 0])); // call; ret
            d.Regions.Add(new MinidumpBuilder.Region(Jit, 0x1000, 0x20));
        }
        var crash = MinidumpBuilder.ContextX86(Base + LeafRva, Stack, ebp: Stack + 0xC, ecx: 0x2A);
        d.Threads.Add(new MinidumpBuilder.Thread(100, Stack, crash, "main"));
        d.Threads.Add(new MinidumpBuilder.Thread(101, Stack, MinidumpBuilder.ContextX86(0x1234, Stack + 0x100)));
        d.Threads.Add(new MinidumpBuilder.Thread(102, Stack, MinidumpBuilder.ContextX86(HaltBase + 0x1002, Stack + 0x200)));
        d.Threads.Add(new MinidumpBuilder.Thread(103, Stack, MinidumpBuilder.ContextX86(Base + LeafRva, Stack + 0x280, ebp: Stack + 0x284)));
        d.Exception = (100, 0xC0000005, Base + LeafRva, [1, 0], crash);
        var path = dir.File(name);
        File.WriteAllBytes(path, d.Build());
        return path;
    }
}

public sealed class MinidumpTests
{
    /// <summary>A 32-bit program dumped by a 64-bit writer lists its image twice, once per module list: one module, no issue.</summary>
    [Fact]
    public void A_module_listed_twice_reads_once()
    {
        var d = new MinidumpBuilder();
        d.Modules.Add(new MinidumpBuilder.Module(0xCA0000, 0x169000, 0x66036A1C, @"C:\app\app.exe"));
        d.Modules.Add(new MinidumpBuilder.Module(0x7FF9_2066_0000, 0x200000, 0, @"C:\Windows\System32\ntdll.dll"));
        d.Modules.Add(new MinidumpBuilder.Module(0xCA0000, 0x169000, 0x66036A1C, @"C:\app\app.exe"));
        d.Modules.Add(new MinidumpBuilder.Module(0xCA1000, 0x1000, 0, @"C:\app\inside.dll"));
        using var dump = MinidumpFile.FromBytes(d.Build());
        Assert.Equal(["app.exe", "inside.dll", "ntdll.dll"], dump.Modules.Select(m => m.FileName));
        Assert.Equal("app.exe", dump.MainModule!.FileName);
        Assert.Single(dump.Issues, i => i.Message.Contains("overlaps"));
        Assert.Contains(dump.Issues, i => i.Message.Contains("inside.dll"));
    }

    /// <summary>
    /// An ARM64 thread stopped at a function's first instruction returns through the link register, then follows the frame
    /// chain; stopped past the start, the chain names the caller and the stale link register is not used.
    /// </summary>
    [Fact]
    public void Arm64_stacks_use_the_link_register_at_a_function_start_then_the_frame_chain()
    {
        const ulong Base = 0x7FF6_0000_0000, Stack = 0x1000_0000;
        var pe = new PeBuilder { Machine = 0xAA64, ImageBase = Base };
        pe.Add(".text", new byte[0x1000], 0x60000020);
        var pdata = new byte[8];
        // Work spans 0x1000-0x1040, with packed unwind data.
        BinaryPrimitives.WriteUInt32LittleEndian(pdata, 0x1000);
        BinaryPrimitives.WriteUInt32LittleEndian(pdata.AsSpan(4), 1 | (0x40 >> 2) << 2);
        var section = pe.Add(".pdata", pdata);
        pe.Directories[3] = (section.Rva, 8);
        var image = PeFile.FromBytes(pe.Build());
        // Work's caller main returns to start; start's record ends the chain.
        var stack = new byte[0x100];
        BinaryPrimitives.WriteUInt64LittleEndian(stack.AsSpan(0x20), Stack + 0x40);
        BinaryPrimitives.WriteUInt64LittleEndian(stack.AsSpan(0x28), Base + 0x1208);
        BinaryPrimitives.WriteUInt64LittleEndian(stack.AsSpan(0x10), Stack + 0x20);
        BinaryPrimitives.WriteUInt64LittleEndian(stack.AsSpan(0x18), Base + 0x1104);

        ulong[] Walk(ulong pc, ulong fp, ulong lr)
        {
            var d = new MinidumpBuilder { ProcessorArchitecture = 12 };
            d.Modules.Add(new MinidumpBuilder.Module(Base, 0x3000, 0, @"C:\app\app.exe"));
            d.Memory.Add((Stack, stack));
            var context = Corvus.Native.Diagnostics.ProcessSnapshot.ContextArm64(new Dictionary<string, ulong> { ["pc"] = pc, ["sp"] = Stack, ["fp"] = fp, ["lr"] = lr });
            d.Threads.Add(new MinidumpBuilder.Thread(1, Stack, context));
            using var dump = MinidumpFile.FromBytes(d.Build());
            var walk = new StackWalker(dump, _ => image).Walk(dump.ReadContext(dump.Threads[0].Context)!, Stack, Stack + 0x100, 16);
            Assert.Equal("end_of_stack", walk.Stop);
            return [.. walk.Frames.Select(f => f.Ip)];
        }

        Assert.Equal([Base + 0x1000, Base + 0x1104, Base + 0x1208], Walk(Base + 0x1000, Stack + 0x20, Base + 0x1104));
        Assert.Equal([Base + 0x1010, Base + 0x1104, Base + 0x1208], Walk(Base + 0x1010, Stack + 0x10, Base + 0x1F00));
    }

    /// <summary>x86 frames without a frame pointer are found by the return address whose call targets the function, not lost to the EBP chain.</summary>
    [Fact]
    public async Task X86_frame_pointer_omitted_frames_are_walked()
    {
        using var dir = new TempDir();
        var path = SyntheticCrashX86.Write(dir);
        using var service = new MinidumpService();
        var stack = await service.Stack(path, null, true, 64, 0, 64, null, default);
        Assert.Equal("x86", stack.Architecture);
        Assert.Equal(["synth32!Leaf", "synth32!Mid+0x6", "synth32!Top+0x8"], stack.Items.Select(f => f.Symbol));
        Assert.Equal(["context", "call_target", "call_target"], stack.Items.Select(f => f.Method));
        Assert.Equal(0, stack.ScannedFrames);
        Assert.Equal("end_of_stack", stack.Stop);
        // A call to a bad address: the return address is at the stack pointer.
        var bad = await service.Stack(path, "101", true, 64, 0, 64, null, default);
        Assert.Equal(("leaf", "synth32!Jump+0x2"), (bad.Items[1].Method, bad.Items[1].Symbol));
        // A call through an import slot the dump holds unbound: matched by the import's name.
        var trap = await service.Stack(path, "102", true, 64, 0, 64, null, default);
        Assert.Equal(["halt!Halt+0x2", "synth32!Trap+0x6"], trap.Items.Take(2).Select(f => f.Symbol));
        // The name of the nearest export.
        Assert.Equal(("call_target", "inferred"), (trap.Items[1].Method, trap.Items[1].Basis));
        Assert.Equal("derived", MinidumpService.FrameBasis("call_target", false, "export"));
        Assert.Null(MinidumpService.FrameBasis("unwind_info", false, "pdb"));
        // Leaf reached by a tail jump from Tail: the return address is Outer's call to Tail; the EBP chain would skip Outer.
        var tail = await service.Stack(path, "103", true, 64, 0, 64, null, default);
        Assert.Equal(["synth32!Leaf", "synth32!Outer+0x8"], tail.Items.Select(f => f.Symbol));
        Assert.Equal("call_target", tail.Items[1].Method);

        using var bucketing = new MinidumpService { BucketCache = dir.File("cache") };
        var buckets = await bucketing.Bucket(dir.Path, false, null, 3, null, false, true, 10, null, 0, 10, null, default);
        Assert.Equal("0xC0000005 | synth32!Leaf | synth32!Mid > synth32!Top", Assert.Single(buckets.Items).Signature);
    }

    /// <summary>
    /// A small dump of a module loaded away from its preferred base: the call through its import slot is read from the file,
    /// whose operand holds the slot at the preferred base; relocated, it names the callee, so the caller is a call target.
    /// </summary>
    [Fact]
    public async Task X86_import_call_read_from_a_rebased_file_finds_the_caller()
    {
        const uint Rebased = 0x1100_0000;
        using var dir = new TempDir();
        File.WriteAllBytes(dir.File("synth32.dll"), SyntheticCrashX86.FileImage());
        var halt = SyntheticCrashX86.Mapped(SyntheticCrashX86.HaltImage());
        var stack = new byte[0x100];
        // The stack holds Halt's return into Trap.
        BinaryPrimitives.WriteUInt32LittleEndian(stack, Rebased + SyntheticCrashX86.TrapRva + 6);
        var d = new MinidumpBuilder { ProcessorArchitecture = 0 };
        d.Modules.Add(new MinidumpBuilder.Module(Rebased, 0x3000, 0, Path.Combine(dir.Path, "synth32.dll")));
        d.Modules.Add(new MinidumpBuilder.Module(SyntheticCrashX86.HaltBase, (uint)halt.Length, 0, @"Z:\nowhere\halt.dll"));
        d.Memory.Add((SyntheticCrashX86.HaltBase, halt));
        d.Memory.Add((SyntheticCrashX86.Stack, stack));
        d.Threads.Add(new MinidumpBuilder.Thread(102, SyntheticCrashX86.Stack, MinidumpBuilder.ContextX86(SyntheticCrashX86.HaltBase + 0x1002, SyntheticCrashX86.Stack)));
        var path = dir.File("rebased32.dmp");
        File.WriteAllBytes(path, d.Build());
        using var service = new MinidumpService();
        var walk = await service.Stack(path, "102", true, 64, 0, 64, dir.Path, default);
        Assert.Equal(["halt!Halt+0x2", "synth32!Trap+0x6"], walk.Items.Take(2).Select(f => f.Symbol));
        Assert.Equal("call_target", walk.Items[1].Method);
    }

    /// <summary>
    /// filt32.dll: Outer (an EBP frame) calls Caller, which calls Block; Block calls halt.dll!Halt through esi, so no
    /// call instruction names Halt, and EBP still holds Outer's frame. Only Outer is exported.
    /// </summary>
    [Fact]
    public async Task X86_frame_data_from_the_module_pdb_finds_the_frames_the_ebp_chain_skips()
    {
        const uint Base = 0x1300_0000;
        var guid = new Guid("5a5a5a5a-1111-2222-3333-444455556666");
        using var dir = new TempDir();
        File.WriteAllBytes(Path.Combine(dir.Path, "filt32.dll"), SyntheticCrashX86.Pe32("filt32.dll", Base, _ =>
        {
            var text = new byte[0x30];
            new byte[] { 0x55, 0x8B, 0xEC, 0xE8 }.CopyTo(text, 0); // Outer: push ebp; mov ebp, esp; call Caller; pop ebp; ret
            BinaryPrimitives.WriteInt32LittleEndian(text.AsSpan(4), 0x10 - 8);
            new byte[] { 0x5D, 0xC3 }.CopyTo(text, 8);
            text[0x10] = 0xE8; // Caller: call Block; ret
            BinaryPrimitives.WriteInt32LittleEndian(text.AsSpan(0x11), 0x20 - 0x15);
            text[0x15] = 0xC3;
            new byte[] { 0xFF, 0xD6, 0xC3 }.CopyTo(text, 0x20); // Block: call esi; ret
            return text;
        }, [("Outer", 0x1000)], null, (guid, 1, @"C:\build\filt32.pdb")));
        var pdb = new PdbBuilder { Guid = guid, Age = 1 };
        pdb.FrameData.Add((0x1020, 3, 0, 0, 0, "$T0 .raSearch = $eip $T0 ^ = $esp $T0 4 + ="));
        File.WriteAllBytes(Path.Combine(dir.Path, "filt32.pdb"), pdb.Build());
        var halt = SyntheticCrashX86.Mapped(SyntheticCrashX86.HaltImage());
        var stack = new byte[0x100];
        void Put(int at, uint v) => BinaryPrimitives.WriteUInt32LittleEndian(stack.AsSpan(at), v);
        Put(0x00, Base + 0x1022);
        Put(0x04, Base + 0x1015);
        Put(0x44, Base + 0x1008);
        var d = new MinidumpBuilder { FullMemory = true, ProcessorArchitecture = 0 };
        d.Modules.Add(new MinidumpBuilder.Module(Base, 0x3000, 0, @"Z:\nowhere\filt32.dll"));
        d.Modules.Add(new MinidumpBuilder.Module(SyntheticCrashX86.HaltBase, (uint)halt.Length, 0, @"Z:\nowhere\halt.dll"));
        d.Memory.Add((SyntheticCrashX86.HaltBase, halt));
        d.Memory.Add((SyntheticCrashX86.Stack, stack));
        d.Regions.Add(new MinidumpBuilder.Region(SyntheticCrashX86.HaltBase, (ulong)halt.Length, 0x20));
        d.Regions.Add(new MinidumpBuilder.Region(SyntheticCrashX86.Stack, 0x100, 0x04));
        d.Threads.Add(new MinidumpBuilder.Thread(107, SyntheticCrashX86.Stack,
            MinidumpBuilder.ContextX86(SyntheticCrashX86.HaltBase + 0x1000, SyntheticCrashX86.Stack, ebp: SyntheticCrashX86.Stack + 0x40)));
        var path = dir.File("filt32.dmp");
        File.WriteAllBytes(path, d.Build());
        using var service = new MinidumpService();
        var walk = await service.Stack(path, "107", true, 64, 0, 64, dir.Path, default);
        Assert.Equal(["halt!Halt", "filt32!Outer+0x22", "filt32!Outer+0x15", "filt32!Outer+0x8"], walk.Items.Take(4).Select(f => f.Symbol));
        Assert.Equal("frame_data", walk.Items[2].Method);
    }

    /// <summary>
    /// entry32.dll: Top calls Outer (an EBP frame), which calls Inner; the thread is stopped at Inner's first instruction,
    /// a push esi, and Inner's frame data describes an EBP frame it has not built yet.
    /// </summary>
    [Fact]
    public async Task X86_stop_at_a_function_entry_finds_its_caller_despite_frame_data()
    {
        var walk = await EntryWalk(returnSlot: true);
        Assert.Equal(["entry32!Inner", "entry32!Outer+0x8", "entry32!Top+0x5"], walk.Items.Take(3).Select(f => f.Symbol));
    }

    /// <summary>The same thread with a zero return slot: a thread that has not started yet.</summary>
    [Fact]
    public async Task X86_thread_at_an_entry_with_a_zero_return_slot_ends_the_stack()
    {
        var walk = await EntryWalk(returnSlot: false);
        Assert.Equal(["entry32!Inner"], walk.Items.Select(f => f.Symbol));
        Assert.Equal("end_of_stack", walk.Stop);
    }

    private static async Task<MinidumpService.StackReport> EntryWalk(bool returnSlot)
    {
        const uint Base = 0x1400_0000;
        var guid = new Guid("6b6b6b6b-1111-2222-3333-444455556666");
        using var dir = new TempDir();
        File.WriteAllBytes(Path.Combine(dir.Path, "entry32.dll"), SyntheticCrashX86.Pe32("entry32.dll", Base, _ =>
        {
            var text = new byte[0x30];
            new byte[] { 0x55, 0x8B, 0xEC, 0xE8 }.CopyTo(text, 0); // Outer: push ebp; mov ebp, esp; call Inner; pop ebp; ret
            BinaryPrimitives.WriteInt32LittleEndian(text.AsSpan(4), 0x10 - 8);
            new byte[] { 0x5D, 0xC3 }.CopyTo(text, 8);
            new byte[] { 0x56, 0x55, 0x8B, 0xEC, 0x5D, 0x5E, 0xC3 }.CopyTo(text, 0x10); // Inner: push esi; push ebp; mov ebp, esp; pop ebp; pop esi; ret
            text[0x20] = 0xE8; // Top: call Outer; ret
            BinaryPrimitives.WriteInt32LittleEndian(text.AsSpan(0x21), 0 - 0x25);
            text[0x25] = 0xC3;
            return text;
        }, [("Outer", 0x1000), ("Inner", 0x1010), ("Top", 0x1020)], null, (guid, 1, @"C:\build\entry32.pdb")));
        var pdb = new PdbBuilder { Guid = guid, Age = 1 };
        pdb.FrameData.Add((0x1010, 7, 0, 0, 4, "$T0 $ebp = $eip $T0 4 + ^ = $ebp $T0 ^ = $esp $T0 8 + ="));
        File.WriteAllBytes(Path.Combine(dir.Path, "entry32.pdb"), pdb.Build());
        var stack = new byte[0x100];
        void Put(int at, uint v) => BinaryPrimitives.WriteUInt32LittleEndian(stack.AsSpan(at), v);
        if (returnSlot) Put(0x00, Base + 0x1008);
        Put(0x44, Base + 0x1025);
        var d = new MinidumpBuilder { FullMemory = true, ProcessorArchitecture = 0 };
        d.Modules.Add(new MinidumpBuilder.Module(Base, 0x3000, 0, @"Z:\nowhere\entry32.dll"));
        d.Memory.Add((SyntheticCrashX86.Stack, stack));
        d.Regions.Add(new MinidumpBuilder.Region(SyntheticCrashX86.Stack, 0x100, 0x04));
        d.Threads.Add(new MinidumpBuilder.Thread(109, SyntheticCrashX86.Stack,
            MinidumpBuilder.ContextX86(Base + 0x1010, SyntheticCrashX86.Stack, ebp: SyntheticCrashX86.Stack + 0x40)));
        var path = dir.File("entry32.dmp");
        File.WriteAllBytes(path, d.Build());
        using var service = new MinidumpService();
        return await service.Stack(path, "109", true, 64, 0, 64, dir.Path, default);
    }

    /// <summary>
    /// ntdll.dll: KiUserExceptionDispatcher calls RtlDispatchException, stopped in its prolog; the kernel copied the
    /// EXCEPTION_RECORD and CONTEXT above the dispatcher's two arguments.
    /// </summary>
    [Fact]
    public async Task X86_exception_dispatcher_frame_continues_at_the_faulting_context()
    {
        const uint Ntdll = 0x7700_0000, S = SyntheticCrashX86.Stack;
        var ntdll = SyntheticCrashX86.Mapped(SyntheticCrashX86.Pe32("ntdll.dll", Ntdll, _ =>
        {
            var text = new byte[0x30];
            // KiUserExceptionDispatcher: cld; mov ecx, [esp+4]; mov ebx, [esp]; push ecx; push ebx; call RtlDispatchException.
            new byte[] { 0xFC, 0x8B, 0x4C, 0x24, 0x04, 0x8B, 0x1C, 0x24, 0x51, 0x53, 0xE8 }.CopyTo(text, 0);
            BinaryPrimitives.WriteInt32LittleEndian(text.AsSpan(11), 0x20 - 0x0F);
            new byte[] { 0x8B, 0xFF, 0xCC, 0xC3 }.CopyTo(text, 0x20); // RtlDispatchException: mov edi, edi; int3; ret
            return text;
        }, [("KiUserExceptionDispatcher", 0x1000), ("RtlDispatchException", 0x1020)], null));
        var synth = SyntheticCrashX86.Mapped(SyntheticCrashX86.FileImage());
        var stack = new byte[0x200];
        void Put(int at, uint v) => BinaryPrimitives.WriteUInt32LittleEndian(stack.AsSpan(at), v);
        Put(0x00, Ntdll + 0x100F);
        Put(0x04, S + 0x14);
        Put(0x08, S + 0x64);
        Put(0x0C, S + 0x14);
        Put(0x10, S + 0x64);
        MinidumpBuilder.ContextX86(SyntheticCrashX86.Base + SyntheticCrashX86.LeafRva, S + 0x180).CopyTo(stack, 0x64);
        var d = new MinidumpBuilder { FullMemory = true, ProcessorArchitecture = 0 };
        d.Modules.Add(new MinidumpBuilder.Module(Ntdll, (uint)ntdll.Length, 0, @"Z:\nowhere\ntdll.dll"));
        d.Modules.Add(new MinidumpBuilder.Module(SyntheticCrashX86.Base, (uint)synth.Length, 0, @"Z:\nowhere\synth32.dll"));
        d.Memory.Add((Ntdll, ntdll));
        d.Memory.Add((SyntheticCrashX86.Base, synth));
        d.Memory.Add((S, stack));
        d.Regions.Add(new MinidumpBuilder.Region(Ntdll, (ulong)ntdll.Length, 0x20));
        d.Regions.Add(new MinidumpBuilder.Region(SyntheticCrashX86.Base, (ulong)synth.Length, 0x20));
        d.Regions.Add(new MinidumpBuilder.Region(S, 0x200, 0x04));
        d.Threads.Add(new MinidumpBuilder.Thread(108, S, MinidumpBuilder.ContextX86(Ntdll + 0x1020, S)));
        using var dir = new TempDir();
        var path = dir.File("dispatch32.dmp");
        File.WriteAllBytes(path, d.Build());
        using var service = new MinidumpService();
        var walk = await service.Stack(path, "108", true, 64, 0, 64, null, default);
        Assert.Equal(["ntdll!RtlDispatchException", "ntdll!KiUserExceptionDispatcher+0xF", "synth32!Leaf"], walk.Items.Take(3).Select(f => f.Symbol));
        Assert.Equal("machine_frame", walk.Items[2].Method);
    }

    /// <summary>A function that tail-jumps through an import slot (jmp [slot]) leaves its caller's return address on top: the caller is a call target.</summary>
    [Fact]
    public async Task X86_tail_jump_through_an_import_slot_finds_the_caller()
    {
        const uint Base = 0x1200_0000, CallerRva = 0x1000, WrapperRva = 0x1010;
        using var dir = new TempDir();
        var image = SyntheticCrashX86.Mapped(SyntheticCrashX86.Pe32("wrap32.dll", Base, slotVa =>
        {
            var text = new byte[0x20];
            // Caller: call Wrapper; ret.
            text[0] = 0xE8;
            BinaryPrimitives.WriteInt32LittleEndian(text.AsSpan(1), (int)WrapperRva - (int)(CallerRva + 5));
            text[5] = 0xC3;
            // Wrapper: jmp [halt.dll!Halt].
            new byte[] { 0xFF, 0x25 }.CopyTo(text, 0x10);
            BinaryPrimitives.WriteUInt32LittleEndian(text.AsSpan(0x12), slotVa);
            return text;
        }, [("Caller", CallerRva), ("Wrapper", WrapperRva)], ("halt.dll", "Halt")));
        var halt = SyntheticCrashX86.Mapped(SyntheticCrashX86.HaltImage());
        var stack = new byte[0x100];
        BinaryPrimitives.WriteUInt32LittleEndian(stack, Base + CallerRva + 5);
        var d = new MinidumpBuilder { FullMemory = true, ProcessorArchitecture = 0 };
        d.Modules.Add(new MinidumpBuilder.Module(Base, (uint)image.Length, 0, @"Z:\nowhere\wrap32.dll"));
        d.Modules.Add(new MinidumpBuilder.Module(SyntheticCrashX86.HaltBase, (uint)halt.Length, 0, @"Z:\nowhere\halt.dll"));
        d.Memory.Add((Base, image));
        d.Memory.Add((SyntheticCrashX86.HaltBase, halt));
        d.Memory.Add((SyntheticCrashX86.Stack, stack));
        d.Regions.Add(new MinidumpBuilder.Region(Base, (ulong)image.Length, 0x20));
        d.Regions.Add(new MinidumpBuilder.Region(SyntheticCrashX86.HaltBase, (ulong)halt.Length, 0x20));
        d.Regions.Add(new MinidumpBuilder.Region(SyntheticCrashX86.Stack, 0x100, 0x04));
        d.Threads.Add(new MinidumpBuilder.Thread(106, SyntheticCrashX86.Stack, MinidumpBuilder.ContextX86(SyntheticCrashX86.HaltBase + 0x1002, SyntheticCrashX86.Stack)));
        var path = dir.File("wrap32.dmp");
        File.WriteAllBytes(path, d.Build());
        using var service = new MinidumpService();
        var walk = await service.Stack(path, "106", true, 64, 0, 64, null, default);
        Assert.Equal(["halt!Halt+0x2", "wrap32!Caller+0x5"], walk.Items.Take(2).Select(f => f.Symbol));
        Assert.Equal("call_target", walk.Items[1].Method);
    }

    /// <summary>
    /// A thread held in a hook: its EBP points off the stack (not a frame), the scan's guessed frame pointer reads a zero
    /// return address (not the end of the stack), and the scan above reaches the program's frame.
    /// </summary>
    [Fact]
    public async Task X86_guessed_frame_pointers_do_not_end_the_walk()
    {
        // The heap block lies above the stack, where a chain could follow it.
        const uint Stack2 = 0x00E1_0000, Heap = 0x0100_0000;
        using var dir = new TempDir();
        var image = SyntheticCrashX86.Mapped(SyntheticCrashX86.FileImage());
        var stack = new byte[0x100];
        void Put(byte[] to, int at, uint v) => BinaryPrimitives.WriteUInt32LittleEndian(to.AsSpan(at), v);
        Put(stack, 0x04, Stack2 + 0x20); // below the return address: the scan's guessed frame pointer
        Put(stack, 0x08, SyntheticCrashX86.Base + SyntheticCrashX86.MidRva + 6); // found by the scan
        // 0x20: the guessed frame holds zeros (saved ebp, return address).
        Put(stack, 0x30, SyntheticCrashX86.Base + SyntheticCrashX86.OuterRva + 8); // found by the scan above it
        var heap = new byte[0x10];
        Put(heap, 0x00, Stack2 + 0x40);
        Put(heap, 0x04, SyntheticCrashX86.Base + SyntheticCrashX86.TopRva + 8); // a plausible return, but off the stack
        var d = new MinidumpBuilder { FullMemory = true, ProcessorArchitecture = 0 };
        d.Modules.Add(new MinidumpBuilder.Module(SyntheticCrashX86.Base, (uint)image.Length, 0, @"Z:\nowhere\synth32.dll"));
        d.Memory.Add((SyntheticCrashX86.Base, image));
        d.Memory.Add((Stack2, stack));
        d.Memory.Add((Heap, heap));
        d.Regions.Add(new MinidumpBuilder.Region(SyntheticCrashX86.Base, (ulong)image.Length, 0x20));
        d.Regions.Add(new MinidumpBuilder.Region(Stack2, 0x100, 0x04));
        d.Regions.Add(new MinidumpBuilder.Region(Heap, 0x1000, 0x04));
        d.Threads.Add(new MinidumpBuilder.Thread(104, Stack2, MinidumpBuilder.ContextX86(SyntheticCrashX86.Base + 0x10B8, Stack2, ebp: Heap)));
        var path = dir.File("hooked32.dmp");
        File.WriteAllBytes(path, d.Build());
        using var service = new MinidumpService();
        var walk = await service.Stack(path, "104", true, 64, 0, 64, null, default);
        Assert.Equal(["synth32!Mid+0x6", "synth32!Outer+0x8"], walk.Items.Skip(1).Select(f => f.Symbol));
        Assert.Equal(["scan", "scan"], walk.Items.Skip(1).Select(f => f.Method));
        Assert.DoesNotContain(walk.Items, f => f.Symbol == "synth32!Top+0x8");
    }

    /// <summary>A frame chained from the scan's guessed frame pointer is a guess too, marked inferred: the zero return address after it does not end the walk.</summary>
    [Fact]
    public async Task X86_frames_chained_from_a_guess_do_not_end_the_walk()
    {
        const uint Stack2 = 0x00E1_0000;
        using var dir = new TempDir();
        var image = SyntheticCrashX86.Mapped(SyntheticCrashX86.FileImage());
        var stack = new byte[0x100];
        void Put(int at, uint v) => BinaryPrimitives.WriteUInt32LittleEndian(stack.AsSpan(at), v);
        Put(0x04, Stack2 + 0x20); // the scan's guessed frame pointer
        Put(0x08, SyntheticCrashX86.Base + SyntheticCrashX86.MidRva + 6); // found by the scan
        Put(0x20, Stack2 + 0x40); // the guessed frame chains on
        Put(0x24, SyntheticCrashX86.Base + SyntheticCrashX86.OuterRva + 8);
        // 0x40: zeros (saved ebp, return address).
        Put(0x50, SyntheticCrashX86.Base + SyntheticCrashX86.TopRva + 8); // found by the scan above it
        var d = new MinidumpBuilder { FullMemory = true, ProcessorArchitecture = 0 };
        d.Modules.Add(new MinidumpBuilder.Module(SyntheticCrashX86.Base, (uint)image.Length, 0, @"Z:\nowhere\synth32.dll"));
        d.Memory.Add((SyntheticCrashX86.Base, image));
        d.Memory.Add((Stack2, stack));
        d.Regions.Add(new MinidumpBuilder.Region(SyntheticCrashX86.Base, (ulong)image.Length, 0x20));
        d.Regions.Add(new MinidumpBuilder.Region(Stack2, 0x100, 0x04));
        d.Threads.Add(new MinidumpBuilder.Thread(105, Stack2, MinidumpBuilder.ContextX86(SyntheticCrashX86.Base + 0x10B8, Stack2, ebp: 0)));
        var path = dir.File("chained32.dmp");
        File.WriteAllBytes(path, d.Build());
        using var service = new MinidumpService();
        var walk = await service.Stack(path, "105", true, 64, 0, 64, null, default);
        Assert.Equal(["synth32!Mid+0x6", "synth32!Outer+0x8", "synth32!Top+0x8"], walk.Items.Skip(1).Select(f => f.Symbol));
        Assert.Equal(["scan", "frame_pointer", "scan"], walk.Items.Skip(1).Select(f => f.Method));
        Assert.Equal(["inferred", "inferred", "inferred"], walk.Items.Skip(1).Select(f => f.Basis));
        Assert.Equal(3, walk.ScannedFrames);
    }

    /// <summary>Caller searches that find nothing over many frames without a frame pointer leave the scan its own budget (fails without 7fba2d2e).</summary>
    [Fact]
    public async Task X86_caller_searches_do_not_spend_the_scan_budget()
    {
        const uint Stack2 = 0x00E2_0000;
        const int Frames = 10;
        using var dir = new TempDir();
        var image = SyntheticCrashX86.Mapped(SyntheticCrashX86.FileImage());
        // Each search for Mid's caller (Top+8) reads 0x4000 slots of the stack and finds none.
        var stack = new byte[0x11000];
        for (int i = 0; i < Frames; i++) BinaryPrimitives.WriteUInt32LittleEndian(stack.AsSpan(4 * i), SyntheticCrashX86.Base + SyntheticCrashX86.MidRva + 6);
        var d = new MinidumpBuilder { FullMemory = true, ProcessorArchitecture = 0 };
        d.Modules.Add(new MinidumpBuilder.Module(SyntheticCrashX86.Base, (uint)image.Length, 0, @"Z:\nowhere\synth32.dll"));
        d.Memory.Add((SyntheticCrashX86.Base, image));
        d.Memory.Add((Stack2, stack));
        d.Regions.Add(new MinidumpBuilder.Region(SyntheticCrashX86.Base, (ulong)image.Length, 0x20));
        d.Regions.Add(new MinidumpBuilder.Region(Stack2, (ulong)stack.Length, 0x04));
        d.Threads.Add(new MinidumpBuilder.Thread(107, Stack2, MinidumpBuilder.ContextX86(SyntheticCrashX86.Base + SyntheticCrashX86.MidRva + 6, Stack2, ebp: 0)));
        var path = dir.File("budget32.dmp");
        File.WriteAllBytes(path, d.Build());
        using var service = new MinidumpService();
        var walk = await service.Stack(path, "107", true, 64, 0, 64, null, default);
        Assert.Equal(Frames, walk.Items.Skip(1).Count(f => f.Symbol == "synth32!Mid+0x6"));
    }

    /// <summary>An unwind that reads something other than code as the return address (a stale slot) scans on instead of reporting it.</summary>
    [Fact]
    public async Task An_unwound_return_address_that_is_not_code_scans_on()
    {
        const ulong Stack2 = 0xE0_0002_0000;
        using var dir = new TempDir();
        var stack = new byte[0x100];
        void Put(int at, ulong v) => BinaryPrimitives.WriteUInt64LittleEndian(stack.AsSpan(at), v);
        // Where Crash's unwind finds its return address.
        Put(0x28, 0x43BF_8000_443E_C000);
        Put(0x40, SyntheticCrash.Base + SyntheticCrash.BigRva + 20);
        var d = SyntheticCrash.Builder(exception: false);
        d.Memory.Add((Stack2, stack));
        d.Regions.Add(new MinidumpBuilder.Region(Stack2, 0x100, 0x04));
        d.Threads.Add(new MinidumpBuilder.Thread(106, Stack2, MinidumpBuilder.ContextX64(SyntheticCrash.Base + SyntheticCrash.CrashRva + 5, Stack2)));
        var path = dir.File("stale.dmp");
        File.WriteAllBytes(path, d.Build());
        using var service = new MinidumpService();
        var walk = await service.Stack(path, "106", true, 64, 0, 64, null, default);
        Assert.Equal("synth!Big+0x14", walk.Items[1].Symbol);
        Assert.Equal("scan", walk.Items[1].Method);
    }

    /// <summary>
    /// A WoW64 process dumped by a 64-bit tool: each thread's 32-bit side comes from the x86 context WoW64 keeps in the
    /// CPU area that TEB64 TLS slot 1 points to, with the 32-bit stack bounds from the TEB32 at TEB64 + 0x2000.
    /// </summary>
    [Fact]
    public async Task WOW64_threads_show_their_32_bit_side()
    {
        using var dir = new TempDir();
        const uint id = 7;
        ulong teb = 0x7FF000000000UL + id * 0x2000UL, cpu = 0x7FF0_1000_0000, wow64cpu = 0x7FFA_0000_0000;
        var image = SyntheticCrashX86.Mapped(SyntheticCrashX86.FileImage());
        var d = new MinidumpBuilder { FullMemory = true };
        d.Modules.Add(new MinidumpBuilder.Module(SyntheticCrashX86.Base, (uint)image.Length, 0, @"Z:\nowhere\synth32.dll"));
        d.Modules.Add(new MinidumpBuilder.Module(wow64cpu, 0x10000, 0, @"C:\Windows\System32\wow64cpu.dll"));
        d.Memory.Add((SyntheticCrashX86.Base, image));
        d.Memory.Add((SyntheticCrashX86.Stack, SyntheticCrashX86.StackBytes()));
        var teb64 = new byte[0x1500];
        BinaryPrimitives.WriteUInt64LittleEndian(teb64.AsSpan(0x1488), cpu);
        d.Memory.Add((teb, teb64));
        var teb32 = new byte[0x10];
        BinaryPrimitives.WriteUInt32LittleEndian(teb32.AsSpan(4), SyntheticCrashX86.Stack + 0x300);
        BinaryPrimitives.WriteUInt32LittleEndian(teb32.AsSpan(8), SyntheticCrashX86.Stack);
        d.Memory.Add((teb + 0x2000, teb32));
        d.Memory.Add((cpu, [0, 0, 0x4C, 0x01, .. MinidumpBuilder.ContextX86(SyntheticCrashX86.Base + SyntheticCrashX86.LeafRva, SyntheticCrashX86.Stack, ebp: SyntheticCrashX86.Stack + 0xC)]));
        d.Regions.Add(new MinidumpBuilder.Region(SyntheticCrashX86.Base, (ulong)image.Length, 0x20));
        d.Regions.Add(new MinidumpBuilder.Region(SyntheticCrashX86.Stack, 0x300, 0x04));
        d.Threads.Add(new MinidumpBuilder.Thread(id, 0x7FF0_2000_0000, MinidumpBuilder.ContextX64(wow64cpu + 0x1000, 0x7FF0_2000_0000)));
        var path = dir.File("wow64.dmp");
        File.WriteAllBytes(path, d.Build());

        using var service = new MinidumpService { BucketCache = dir.File("cache") };
        var stack = await service.Stack(path, null, true, 64, 0, 64, null, default);
        Assert.Equal("x86 (WoW64)", stack.Architecture);
        Assert.Equal(["synth32!Leaf", "synth32!Mid+0x6", "synth32!Top+0x8"], stack.Items.Take(3).Select(f => f.Symbol));
        Assert.Contains(stack.Notes, n => n.StartsWith("WoW64 thread: frames 0-2 are its 32-bit side", StringComparison.Ordinal));
        var summary = await service.Summarize(path, null, default);
        Assert.Equal("synth32!Leaf", (await service.Threads(path, null, 0, 50, default)).Rows.Single().Location);
        Assert.True(summary.Process!.Wow64);
        Assert.Equal("hang | synth32!Leaf > synth32!Mid > synth32!Top", Assert.Single((await service.Bucket(dir.Path, false, null, 3, null, false, true, 10, null, 0, 10, null, default)).Items).Signature);
    }

    /// <summary>A module name two modules share (a WoW64 process's two ntdll.dll) is ambiguous alone and with an offset alike.</summary>
    [Fact]
    public async Task Module_names_shared_by_two_modules_are_ambiguous_in_every_form()
    {
        using var dir = new TempDir();
        var d = new MinidumpBuilder();
        d.Modules.Add(new MinidumpBuilder.Module(0x7700_0000, 0x10000, 0, @"C:\Windows\SysWOW64\ntdll.dll"));
        d.Modules.Add(new MinidumpBuilder.Module(0x7FFE_0000_0000, 0x10000, 0, @"C:\Windows\System32\ntdll.dll"));
        d.Threads.Add(new MinidumpBuilder.Thread(1, 0x1000, MinidumpBuilder.ContextX64(0x7FFE_0000_1000, 0x1000)));
        var path = dir.File("two.dmp");
        File.WriteAllBytes(path, d.Build());
        using var service = new MinidumpService();
        foreach (var address in new[] { "ntdll", "ntdll.dll", "ntdll+0x10" })
        {
            var error = await Assert.ThrowsAsync<ToolError>(() => service.ReadMemory(path, address, 8, true, default));
            Assert.Equal(ErrorCode.Ambiguous, error.Code);
            Assert.Contains("0x77000000", error.Message);
            Assert.Contains("0x7FFE00000000", error.Message);
        }
    }

    /// <summary>Frames without a name (JIT code, unknown places) are left out of a signature, so a dump that holds less memory lands in the same bucket.</summary>
    [Fact]
    public async Task Unnamed_frames_do_not_split_a_bucket()
    {
        using var dir = new TempDir();
        SyntheticCrashX86.Write(dir, "with-jit.dmp", jit: true);
        SyntheticCrashX86.Write(dir, "without.dmp");
        using var service = new MinidumpService { BucketCache = dir.File("cache") };
        var bucket = Assert.Single((await service.Bucket(dir.Path, false, null, 4, null, false, true, 10, null, 0, 10, null, default)).Items);
        Assert.Equal((2, "0xC0000005 | synth32!Leaf | synth32!Mid > synth32!Top"), (bucket.Count, bucket.Signature));
    }

    /// <summary>read_dump_memory pages by bytes within the budget: the pages' hex, walked by nextOffset, is the whole read.</summary>
    /// <summary>dump_stack starts the faulting thread at the exception context unless dumpTimeContext.</summary>
    [Fact]
    public async Task Dump_stack_starts_at_the_exception_context_unless_dump_time_context()
    {
        using var dir = new TempDir();
        var path = SyntheticCrash.Write(dir);
        using var service = new MinidumpService();
        var tools = new Corvus.Tools.MinidumpTools(service);
        Assert.Contains("from the exception context", await tools.DumpStack(path));
        Assert.Contains("from the thread context", await tools.DumpStack(path, dumpTimeContext: true));
    }

    [Fact]
    public async Task Read_dump_memory_pages_walk_the_whole_range()
    {
        using var dir = new TempDir();
        var path = SyntheticCrash.Write(dir);
        using var service = new MinidumpService();
        var tools = new Corvus.Tools.MinidumpTools(service);
        var whole = await service.ReadMemory(path, "synth", 0x1000, true, default);
        Assert.Equal(0x1000, whole.Length);
        var hex = new System.Text.StringBuilder();
        int? offset = 0, pages = 0;
        while (offset is { } at)
        {
            var call = OutputCall.Begin(new OutputCall("read_dump_memory", 1200, null));
            var text = await tools.ReadDumpMemory(path, "synth", 0x1000, offset: at);
            var page = Assert.IsType<MinidumpService.MemoryRead>(call.Record);
            Assert.True(TokenEstimate.Of(text) <= 1200, text);
            Assert.Equal(at, page.Offset);
            hex.Append(page.Code);
            if (page.NextOffset is { } next) Assert.Equal($"0x{SyntheticCrash.Base + (ulong)next:X}", page.NextAddress);
            offset = page.NextOffset;
            pages++;
        }
        OutputCall.Begin(null!);
        Assert.InRange(pages ?? 0, 3, 16);
        Assert.Equal(whole.Code, hex.ToString());
    }

    /// <summary>open_minidump: the summary names the faulting module and thread; each list view pages its rows with one offset.</summary>
    [Fact]
    public async Task Open_minidump_views_page_their_rows()
    {
        using var dir = new TempDir();
        var path = SyntheticCrash.Write(dir);
        using var service = new MinidumpService();
        var tools = new Corvus.Tools.MinidumpTools(service);

        var collector = Corvus.Mcp.ToolOutput.Collect();
        var text = await tools.OpenMinidump(path);
        var summary = Assert.IsType<MinidumpService.DumpReport>(collector.Value);
        Assert.Equal(("summary", "synth.dll", 1), (summary.View, summary.FaultingModule!.Name, summary.Counts!.Modules));
        Assert.True(summary.FaultingThread!.Faulting);
        Assert.Null(summary.Items);
        Assert.Contains("Exception 0xC0000005 (EXCEPTION_ACCESS_VIOLATION)", text);
        Assert.Contains("Faulting module: 0x7FF610000000 synth.dll", text);

        foreach (var (view, noun) in new[] { ("modules", "module"), ("threads", "thread"), ("memory", "region") })
        {
            collector = Corvus.Mcp.ToolOutput.Collect();
            text = await tools.OpenMinidump(path, view: view);
            var list = Assert.IsType<MinidumpService.DumpReport>(collector.Value);
            Assert.Equal((view, 0), (list.View, list.Offset));
            Assert.Equal(list.Total, list.Items!.Count);
            Assert.Null(list.Exception);
            Assert.Contains($" {noun}", text);
        }
        collector = Corvus.Mcp.ToolOutput.Collect();
        await tools.OpenMinidump(path, view: "threads", offset: summary.Counts.Threads);
        Assert.Empty(Assert.IsType<MinidumpService.DumpReport>(collector.Value).Items!);
        Assert.Equal(ErrorCode.InvalidArgument, (await Assert.ThrowsAsync<ToolError>(() => tools.OpenMinidump(path, view: "stacks"))).Code);
    }

    /// <summary>unload_assembly closes an open dump id and leaves the file.</summary>
    [Fact]
    public async Task Unload_closes_an_open_dump_id()
    {
        using var dir = new TempDir();
        var path = SyntheticCrash.Write(dir);
        using var service = new MinidumpService();
        using var ws = new AssemblyWorkspace();
        await new Corvus.Tools.MinidumpTools(service).OpenMinidump(path);
        var id = Assert.Single(service.OpenIds);
        var tools = new Corvus.Tools.WorkspaceTools(ws, new AotMetadataService(ws), new IndexingService(ws, new CallGraphService(ws), new ServerOptions()), new Corvus.Services.Analysis.UnpackService(ws), dumps: service);
        Assert.StartsWith($"Closed dump {id}", await tools.UnloadAssembly(id));
        Assert.Empty(service.OpenIds);
        Assert.True(File.Exists(path));
        Assert.Equal(ErrorCode.NotLoaded, (await Assert.ThrowsAsync<ToolError>(() => tools.UnloadAssembly(id))).Code);
    }

    [Fact]
    public async Task Synthetic_crash_is_summarized_and_unwound()
    {
        using var dir = new TempDir();
        var path = SyntheticCrash.Write(dir);
        using var service = new MinidumpService();
        var summary = await service.Summarize(path, null, default);
        Assert.Equal("synth.dmp", summary.Id);
        Assert.Equal("x64", summary.System!.Architecture);
        Assert.Equal(4242u, summary.Process!.ProcessId);
        var e = summary.Exception!;
        Assert.Equal("EXCEPTION_ACCESS_VIOLATION", e.Name);
        Assert.Equal("access violation writing 0x0000000000000000 (a null or near-null pointer)", e.Description);
        Assert.Equal("synth!Crash+0x5", e.Symbol);
        Assert.Equal("export", e.SymbolSource);
        Assert.Equal("mov    dword ptr [rax], ecx (8908)", e.Instruction);
        Assert.Equal("dump_memory", e.InstructionSource);
        Assert.Equal("main", summary.FaultingThread!.Name);
        var module = Assert.Single(service.Modules(path, null, 0, 50).Rows);
        Assert.Equal("missing", module.LocalImage);
        Assert.Empty(summary.Issues!);

        var stack = await service.Stack(summary.Id, null, true, 64, 0, 64, null, default);
        Assert.Equal("exception", stack.Context);
        Assert.Equal(["synth!Crash+0x5", "synth!Outer+0x35", "synth!Big+0x14"], stack.Items.Select(f => f.Symbol));
        Assert.Equal(["context", "unwind_info", "unwind_info"], stack.Items.Select(f => f.Method));
        Assert.Equal("end_of_stack", stack.Stop);
        Assert.Equal(0, stack.ScannedFrames);
        Assert.Contains(stack.Notes, n => n.StartsWith("synth.dll: image dump_memory", StringComparison.Ordinal));

        // Epilog, prolog and a scan from code outside any module.
        var epilog = await service.Stack(path, "101", true, 64, 0, 64, null, default);
        Assert.Equal(["synth!Crash+0xB", "synth!Outer+0x35", "synth!Big+0x14"], epilog.Items.Select(f => f.Symbol));
        Assert.Equal("epilog", epilog.Items[1].Method);
        var prolog = await service.Stack(path, "0x66", true, 64, 0, 64, null, default);
        Assert.Equal(["synth!Crash+0x1", "synth!Outer+0x35", "synth!Big+0x14"], prolog.Items.Select(f => f.Symbol));
        var jit = await service.Stack(path, "#3", true, 64, 0, 64, null, default);
        Assert.Equal("unknown", jit.Items[0].Kind);
        Assert.Equal("scan", jit.Items[1].Method);
        Assert.Equal("inferred", jit.Items[1].Basis);
        Assert.Equal(["synth!Outer+0x35", "synth!Big+0x14"], jit.Items.Skip(1).Select(f => f.Symbol));
        var bad = await service.Stack(path, "104", true, 64, 0, 64, null, default);
        Assert.Equal(["leaf", "unwind_info"], bad.Items.Skip(1).Select(f => f.Method));
        Assert.Equal(["synth!Outer+0x35", "synth!Big+0x14"], bad.Items.Skip(1).Select(f => f.Symbol));

        var memory = await service.ReadMemory(path, "synth+0x1000", 16, true, default);
        Assert.Equal("dump_memory", memory.Source);
        Assert.StartsWith("534883EC20890848", memory.Code);
        Assert.Equal("synth!Crash", memory.Location);
        var missing = await service.ReadMemory(path, "0x10", 8, true, default);
        Assert.Equal(0, missing.Length);
        Assert.Equal("none", missing.Source);

        var error = await Assert.ThrowsAsync<ToolError>(() => service.Stack(path, "999", true, 64, 0, 64, null, default));
        Assert.Equal(ErrorCode.NotFound, error.Code);
    }

    [Fact]
    [FuzzEntry(typeof(MinidumpFile))]
    public void Not_a_dump_is_rejected_and_malformed_dumps_never_throw()
    {
        var error = Assert.Throws<ToolError>(() => MinidumpFile.FromBytes(new byte[64]));
        Assert.Equal(ErrorCode.MalformedInput, error.Code);
        var good = SyntheticCrash.Builder().Build();

        // Truncated anywhere after the header.
        foreach (int cut in new[] { 32, 40, 100, 200, 400, 1000, good.Length / 2, good.Length - 100 })
        {
            using var dump = MinidumpFile.FromBytes(good[..cut]);
            Exercise(dump);
            if (cut < good.Length / 2) Assert.NotEmpty(dump.Issues);
        }

        // A stream directory past the end of the file.
        var bad = (byte[])good.Clone();
        BinaryPrimitives.WriteUInt32LittleEndian(bad.AsSpan(12), 0x7FFFFFF0);
        using (var dump = MinidumpFile.FromBytes(bad))
        {
            Assert.Contains(dump.Issues, i => i.Message.Contains("runs past the end"));
            Assert.Empty(dump.Threads);
        }

        // Two directory entries on the same data; a stream past the end.
        bad = (byte[])good.Clone();
        // Second stream's RVA = first stream's.
        Array.Copy(bad, 32 + 8, bad, 32 + 12 + 8, 4);
        BinaryPrimitives.WriteUInt32LittleEndian(bad.AsSpan(32 + 2 * 12 + 8), (uint)good.Length - 4);
        using (var dump = MinidumpFile.FromBytes(bad))
        {
            Assert.Contains(dump.Issues, i => i.Message.Contains("overlaps"));
            Assert.Contains(dump.Issues, i => i.Message.Contains("runs past the end"));
            Exercise(dump);
        }

        // Huge counts: thread list, memory list, stream count.
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

        // Random byte mutations.
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
