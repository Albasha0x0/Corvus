using System.Buffers.Binary;
using System.Text;
using Corvus.Core;
using Corvus.Native;
using Corvus.Native.Dump;
using Corvus.Services;

namespace Corvus.Tests;

/// <summary>A synthetic Mach-O core (ARM64 or x86_64) with a three-frame stack and optional lldb notes.</summary>
internal static class SyntheticMachOCore
{
    public const ulong Base = 0x1_0000_0000, Dyld = 0x2_0000_0000, Stack = 0x1_6F00_0000;
    public const uint Leaf = 0x1000, Work = 0x1100, Main = 0x1200, ImageSize = 0x5000;
    public const string ImagePath = "/Users/dev/app";
    public static readonly byte[] Uuid = [.. Enumerable.Range(0x10, 16).Select(i => (byte)i)];

    private static void U32(byte[] b, long at, uint v) => BinaryPrimitives.WriteUInt32LittleEndian(b.AsSpan((int)at), v);
    private static void U64(byte[] b, long at, ulong v) => BinaryPrimitives.WriteUInt64LittleEndian(b.AsSpan((int)at), v);
    private static void Text(byte[] b, long at, string s) => Encoding.ASCII.GetBytes(s).CopyTo(b, at);
    private static uint Cpu(bool x64) => x64 ? 0x01000007u : 0x0100000Cu;

    /// <summary>The executable as a file, laid out as it is mapped (file offset = address - Base).</summary>
    public static byte[] Image(bool x64)
    {
        var b = new byte[ImageSize];
        U32(b, 0, 0xFEEDFACF); U32(b, 4, Cpu(x64)); U32(b, 8, x64 ? 3u : 0u); U32(b, 12, 2); U32(b, 16, 4); U32(b, 20, 152 + 72 + 24 + 24);
        long at = 32;
        U32(b, at, 0x19); U32(b, at + 4, 152); Text(b, at + 8, "__TEXT"); U64(b, at + 24, Base); U64(b, at + 32, 0x4000); U64(b, at + 48, 0x4000);
        U32(b, at + 56, 5); U32(b, at + 60, 5); U32(b, at + 64, 1);
        Text(b, at + 72, "__text"); Text(b, at + 88, "__TEXT"); U64(b, at + 104, Base + 0x1000); U64(b, at + 112, 0x1000); U32(b, at + 120, 0x1000); U32(b, at + 124, 2);
        // The section flags are S_ATTR_PURE_INSTRUCTIONS |
        // S_ATTR_SOME_INSTRUCTIONS.
        U32(b, at + 136, 0x80000400);
        at += 152;
        U32(b, at, 0x19); U32(b, at + 4, 72); Text(b, at + 8, "__LINKEDIT"); U64(b, at + 24, Base + 0x4000); U64(b, at + 32, 0x1000); U64(b, at + 40, 0x4000); U64(b, at + 48, 0x1000);
        U32(b, at + 56, 1); U32(b, at + 60, 1);
        at += 72;
        U32(b, at, 0x2); U32(b, at + 4, 24); U32(b, at + 8, 0x4000); U32(b, at + 12, 3); U32(b, at + 16, 0x4100); U32(b, at + 20, 0x40);
        at += 24;
        U32(b, at, 0x1B); U32(b, at + 4, 24); Uuid.CopyTo(b, at + 8);
        Text(b, 0x4100, "\0_leaf\0_work\0_main\0");
        (uint Name, uint Rva)[] symbols = [(1, Leaf), (7, Work), (13, Main)];
        for (int i = 0; i < symbols.Length; i++)
        {
            long e = 0x4000 + i * 16;
            U32(b, e, symbols[i].Name); b[e + 4] = 0x0F; b[e + 5] = 1; U64(b, e + 8, Base + symbols[i].Rva);
        }
        return b;
    }

    public static byte[] Core(bool x64 = false, bool imageInCore = true, bool notes = false)
    {
        int stateWords = x64 ? 42 : 68, threadSize = 16 + stateWords * 4;
        int sizeofcmds = 3 * 72 + 2 * threadSize + (notes ? 2 * 40 : 0);
        long payload = 32 + sizeofcmds;
        var infos = notes ? new byte[24 + 48 + 2 * 32 + 32] : [];
        var metadata = notes ? Encoding.ASCII.GetBytes("{\"threads\":[{\"thread_id\":7937},{\"thread_id\":7938}]}") : [];
        long data = (payload + infos.Length + metadata.Length + 0xFFF) & ~0xFFFL;
        long imageAt = data, dyldAt = data + (imageInCore ? ImageSize : 0), stackAt = dyldAt + 0x1000;
        var b = new byte[stackAt + 0x1000];
        U32(b, 0, 0xFEEDFACF); U32(b, 4, Cpu(x64)); U32(b, 12, 4); U32(b, 16, (uint)(3 + 2 + (notes ? 2 : 0))); U32(b, 20, (uint)sizeofcmds);
        long at = 32;
        void Segment(ulong vm, ulong size, long fileOffset, ulong fileSize, uint prot)
        {
            U32(b, at, 0x19); U32(b, at + 4, 72); U64(b, at + 24, vm); U64(b, at + 32, size); U64(b, at + 40, (ulong)fileOffset); U64(b, at + 48, fileSize);
            U32(b, at + 56, prot); U32(b, at + 60, prot);
            at += 72;
        }
        Segment(Base, ImageSize, imageAt, imageInCore ? ImageSize : 0, 5);
        Segment(Dyld, 0x1000, dyldAt, 0x1000, 3);
        Segment(Stack, 0x1000, stackAt, 0x1000, 3);
        void Thread(ulong pc, ulong sp, ulong fp, ulong lr)
        {
            U32(b, at, 0x4); U32(b, at + 4, (uint)threadSize); U32(b, at + 8, x64 ? 4u : 6u); U32(b, at + 12, (uint)stateWords);
            long s = at + 16;
            if (x64) { U64(b, s + 6 * 8, fp); U64(b, s + 7 * 8, sp); U64(b, s + 16 * 8, pc); }
            else { U64(b, s + 29 * 8, fp); U64(b, s + 30 * 8, lr); U64(b, s + 31 * 8, sp); U64(b, s + 32 * 8, pc); U32(b, s + 264, 0x60000000); }
            at += threadSize;
        }
        // ARM64 stops at leaf's entry (the return address in lr, fp still
        // work's); x86_64 stops inside leaf, its frame at Stack+0xF0.
        if (x64) Thread(Base + Leaf + 4, Stack + 0x80, Stack + 0xF0, 0);
        else Thread(Base + Leaf, Stack + 0x80, Stack + 0x100, Base + Work + 0x10);
        Thread(Base + Main + 0x20, Stack + 0x400, 0, 0);
        if (notes)
        {
            void Note(string owner, long offset, int size)
            {
                U32(b, at, 0x31); U32(b, at + 4, 40); Text(b, at + 8, owner); U64(b, at + 24, (ulong)offset); U64(b, at + 32, (ulong)size);
                at += 40;
            }
            long entry = payload + 24, segs = entry + 48, path = segs + 64;
            U32(infos, 0, 1); U32(infos, 4, 1); U64(infos, 8, (ulong)entry); U32(infos, 16, 48);
            U64(infos, 24, (ulong)path); Uuid.CopyTo(infos, 32); U64(infos, 48, Base); U64(infos, 56, (ulong)segs); U32(infos, 64, 2);
            Text(infos, 72, "__TEXT"); U64(infos, 88, Base); Text(infos, 104, "__LINKEDIT"); U64(infos, 120, Base + 0x4000);
            Text(infos, 136, ImagePath);
            infos.CopyTo(b, payload);
            metadata.CopyTo(b, payload + infos.Length);
            Note("all image infos", payload, infos.Length);
            Note("process metadata", payload + infos.Length, metadata.Length);
        }
        if (imageInCore) Image(x64).CopyTo(b, imageAt);
        // dyld_all_image_infos at +0x100 holds version, infoArrayCount,
        // infoArray, ... uuidArrayCount, uuidArray and its own address.
        long d = dyldAt + 0x100;
        U32(b, d, 17); U32(b, d + 4, 1); U64(b, d + 8, Dyld + 0x200); U64(b, d + 88, 1); U64(b, d + 96, Dyld + 0x400); U64(b, d + 104, Dyld + 0x100);
        U64(b, dyldAt + 0x200, Base); U64(b, dyldAt + 0x208, Dyld + 0x300);
        Text(b, dyldAt + 0x300, ImagePath);
        U64(b, dyldAt + 0x400, Base); Uuid.CopyTo(b, dyldAt + 0x408);
        // The frame records run leaf's (x86_64), work's, then main's, whose
        // saved frame pointer and return address are 0.
        U64(b, stackAt + 0xF0, Stack + 0x100); U64(b, stackAt + 0xF8, Base + Work + 0x10);
        U64(b, stackAt + 0x100, Stack + 0x200); U64(b, stackAt + 0x108, Base + Main + 0x10);
        return b;
    }
}

public sealed class MachOCoreTests
{
    private static string Write(TempDir dir, byte[] bytes, string name = "app.core")
    {
        var path = dir.File(name);
        File.WriteAllBytes(path, bytes);
        return path;
    }

    [Fact]
    public void Segments_threads_and_images_come_from_load_commands_and_dyld_all_image_infos()
    {
        var bytes = SyntheticMachOCore.Core();
        Assert.True(CoreFile.IsCore(bytes));
        using var core = CoreFile.FromBytes(bytes, "app.core");
        Assert.Empty(core.Issues);
        Assert.True(core.IsMachO);
        Assert.Equal(NativeArch.Arm64, core.Arch);
        Assert.Equal("dyld_all_image_infos", core.ImageList);
        Assert.Equal(["r-x", "rw-", "rw-"], core.Segments.Select(s => s.Protection));
        Assert.Equal([0u, 1u], core.Threads.Select(t => t.Id));
        var regs = core.Threads[0].Registers!;
        Assert.Equal(SyntheticMachOCore.Base + SyntheticMachOCore.Leaf, regs.Pc);
        Assert.Contains("lr=0000000100001110", regs.Format());
        Assert.Contains("pstate=0000000060000000", regs.Format());
        var module = Assert.Single(core.CoreModules);
        Assert.Equal((SyntheticMachOCore.Base, SyntheticMachOCore.ImageSize), (module.Module.Base, module.Module.Size));
        Assert.Equal(SyntheticMachOCore.ImagePath, module.Module.Path);
        Assert.Equal(Convert.ToHexStringLower(SyntheticMachOCore.Uuid), module.BuildId);
        Assert.Same(module, core.MainModule);
    }

    [Fact]
    public void Lldb_notes_give_the_image_list_and_thread_ids()
    {
        using var core = CoreFile.FromBytes(SyntheticMachOCore.Core(x64: true, imageInCore: false, notes: true), "app.core");
        Assert.Empty(core.Issues);
        Assert.Equal("lldb's all image infos note", core.ImageList);
        Assert.Equal([7937u, 7938u], core.Threads.Select(t => t.Id));
        Assert.Contains("rbp=000000016f0000f0", core.Threads[0].Registers!.Format());
        var module = Assert.Single(core.CoreModules);
        // Without the header in the core, __TEXT reaches the next segment the
        // note lists.
        Assert.Equal(0x4000u, module.Module.Size);
        Assert.Equal(Convert.ToHexStringLower(SyntheticMachOCore.Uuid), module.BuildId);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Dump_stack_walks_the_frame_chain_and_names_frames_from_the_symbols_in_the_core(bool x64)
    {
        using var dir = new TempDir();
        var path = Write(dir, SyntheticMachOCore.Core(x64));
        using var service = new MinidumpService();
        var summary = await service.Summarize(path, null, CancellationToken.None);
        Assert.Equal("macOS", summary.System!.Os);
        Assert.Null(summary.Process!.ProcessId);
        Assert.Contains(summary.Notes!, n => n.StartsWith("Mach-O core dump (macOS, " + (x64 ? "x64" : "ARM64")) && n.Contains("dyld_all_image_infos"));

        var r = await service.Stack(path, null, true, 64, 0, 64, null, CancellationToken.None);
        Assert.Equal(["leaf", "work", "main"], r.Items.Select(f => f.Function));
        Assert.Equal(x64 ? FrameMethod.FramePointer : FrameMethod.Leaf, r.Items[1].Method);
        Assert.Equal($"0x{SyntheticMachOCore.Base + SyntheticMachOCore.Main + 0x10:X}", r.Items[2].Address);
        Assert.Contains(r.Notes, n => n.StartsWith("app: image core_memory") && n.Contains("3 function symbols"));
    }

    [Fact]
    public async Task Module_symbols_come_from_the_file_matched_by_uuid()
    {
        using var dir = new TempDir();
        var path = Write(dir, SyntheticMachOCore.Core(imageInCore: false, notes: true));
        File.WriteAllBytes(dir.File("app"), SyntheticMachOCore.Image(x64: false));
        using var service = new MinidumpService();
        var (_, modules, _) = service.Modules(path, null, 0, 10);
        Assert.Equal("matches", modules[0].LocalImage);
        Assert.Contains($"UUID {Convert.ToHexStringLower(SyntheticMachOCore.Uuid)} matches", modules[0].LocalDetail);

        var r = await service.Stack(path, "7937", true, 64, 0, 64, null, CancellationToken.None);
        Assert.Equal(["leaf", "work", "main"], r.Items.Select(f => f.Function));
        Assert.Contains(r.Notes, n => n.StartsWith("app: image disk"));
    }

    [Fact]
    [FuzzEntry(typeof(CoreFile))]
    public void Fuzzed_mach_o_cores_never_throw()
    {
        foreach (var seed in new[] { SyntheticMachOCore.Core(), SyntheticMachOCore.Core(x64: true, notes: true) })
        {
            var failures = FormatFuzz.Run(seed, b =>
            {
                try
                {
                    using var core = CoreFile.FromBytes(b);
                    foreach (var t in core.Threads)
                    {
                        if (t.Registers == null) continue;
                        CoreImage? Image(ulong a) => core.ModuleAt(a) is { } m ? MachOCoreImage.FromMemory(core, m, "") : null;
                        var walk = new CoreUnwinder(core, t.Registers.Arch, Image).Walk(t.Registers, 0, 0, 64);
                        foreach (var f in walk.Frames) _ = Image(f.LookupAddress)?.SymbolAt(f.LookupAddress);
                    }
                }
                catch (ToolError) { }
            }, 750);
            Assert.Empty(failures);
        }
    }
}
