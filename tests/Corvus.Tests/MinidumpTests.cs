using System.Buffers.Binary;
using Corvus.Core;
using Corvus.Native.Dump;
using Corvus.Native.Pe;
using Corvus.Services;

namespace Corvus.Tests;

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
        // a call to a bad address from Outer's fragment: the return address is at the stack pointer
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

/// <summary>
/// Synthetic x86 crashes. synth32.dll: Top (an EBP frame) calls Mid, which calls Leaf; Mid and Leaf keep no frame pointer,
/// so EBP still holds Top's frame when Leaf faults. Jump calls through eax to a bad address; Trap calls halt.dll!Halt
/// through its import slot.
/// </summary>
internal static class SyntheticCrashX86
{
    public const uint Base = 0x1000_0000, HaltBase = 0x2000_0000, Stack = 0x00E0_0000;
    public const uint LeafRva = 0x1000, MidRva = 0x1020, TopRva = 0x1040, JumpRva = 0x1060, TrapRva = 0x1070, TailRva = 0x1080, OuterRva = 0x10A0;

    /// <summary>A PE32 with .text at 0x1000 and .rdata at 0x2000: exports, and one import whose IAT slot VA the code gets.</summary>
    internal static byte[] Pe32(string dll, uint imageBase, Func<uint, byte[]> text, (string Name, uint Rva)[] exports, (string Module, string Name)? import)
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
        var b = new PeBuilder { Is64 = false, Machine = 0x14C, ImageBase = imageBase, Characteristics = 0x2102 };
        b.Add(".text", text(imageBase + slot), 0x60000020);
        b.Add(".rdata", blob.ToArray());
        b.Directories[PeDirectory.Export] = (dir, blob.Here - dir);
        if (import != null) b.Directories[PeDirectory.Import] = (descriptors, 40);
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
    /// <summary>x86 frames without a frame pointer are found by the return address whose call targets the function, not lost to the EBP chain.</summary>
    [Fact]
    public async Task X86FramePointerOmittedFramesAreWalked()
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
        // a call to a bad address: the return address is at the stack pointer
        var bad = await service.Stack(path, "101", true, 64, 0, 64, null, default);
        Assert.Equal(("leaf", "synth32!Jump+0x2"), (bad.Items[1].Method, bad.Items[1].Symbol));
        // a call through an import slot the dump holds unbound: matched by the import's name
        var trap = await service.Stack(path, "102", true, 64, 0, 64, null, default);
        Assert.Equal(["halt!Halt+0x2", "synth32!Trap+0x6"], trap.Items.Take(2).Select(f => f.Symbol));
        Assert.Equal(("call_target", "inferred"), (trap.Items[1].Method, trap.Items[1].Basis)); // a nearest-export name
        Assert.Equal("derived", MinidumpService.FrameBasis("call_target", false, "export"));
        Assert.Null(MinidumpService.FrameBasis("unwind_info", false, "pdb"));
        // Leaf reached by a tail jump from Tail: the return address is Outer's call to Tail; the EBP chain would skip Outer
        var tail = await service.Stack(path, "103", true, 64, 0, 64, null, default);
        Assert.Equal(["synth32!Leaf", "synth32!Outer+0x8"], tail.Items.Select(f => f.Symbol));
        Assert.Equal("call_target", tail.Items[1].Method);

        using var bucketing = new MinidumpService { BucketCache = dir.File("cache") };
        var buckets = await bucketing.Bucket(dir.Path, false, null, 3, null, false, true, 10, null, 0, 10, null, default);
        Assert.Equal("0xC0000005 | synth32!Leaf | synth32!Mid > synth32!Top", Assert.Single(buckets.Items).Signature);
    }

    /// <summary>
    /// A WoW64 process dumped by a 64-bit tool: each thread's 32-bit side comes from the x86 context WoW64 keeps in the
    /// CPU area that TEB64 TLS slot 1 points to, with the 32-bit stack bounds from the TEB32 at TEB64 + 0x2000.
    /// </summary>
    [Fact]
    public async Task Wow64ThreadsShowTheir32BitSide()
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
    public async Task ModuleNamesSharedByTwoModulesAreAmbiguousInEveryForm()
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
    public async Task UnnamedFramesDoNotSplitABucket()
    {
        using var dir = new TempDir();
        SyntheticCrashX86.Write(dir, "with-jit.dmp", jit: true);
        SyntheticCrashX86.Write(dir, "without.dmp");
        using var service = new MinidumpService { BucketCache = dir.File("cache") };
        var bucket = Assert.Single((await service.Bucket(dir.Path, false, null, 4, null, false, true, 10, null, 0, 10, null, default)).Items);
        Assert.Equal((2, "0xC0000005 | synth32!Leaf | synth32!Mid > synth32!Top"), (bucket.Count, bucket.Signature));
    }

    /// <summary>read_dump_memory pages by bytes within the budget: the pages' hex, walked by nextOffset, is the whole read.</summary>
    [Fact]
    public async Task ReadDumpMemoryPagesWalkTheWholeRange()
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
    public async Task OpenMinidumpViewsPageTheirRows()
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

    [Fact]
    public async Task SyntheticCrashIsSummarizedAndUnwound()
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

        // epilog, prolog and a scan from code outside any module
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
