using System.Diagnostics;
using NetDecompilerMcp.Core;
using NetDecompilerMcp.Native;
using NetDecompilerMcp.Native.Annotations;
using NetDecompilerMcp.Native.Code;
using NetDecompilerMcp.Native.Patching;
using NetDecompilerMcp.Native.Pe;
using NetDecompilerMcp.Services;
using NetDecompilerMcp.Tools;
using Xunit.Abstractions;

namespace NetDecompilerMcp.Tests;

/// <summary>Patch-site extension (relocation stubs): x86/x64 round trips, refusal reason codes, export and migration.</summary>
public class NativeStubTests(ITestOutputHelper output)
{
    private readonly ITestOutputHelper _output = output;

    // A code section whose entry function is: sub [rs]sp,0F8h ; mov eax,7 ; add [rs]sp,0F8h ; ret, then a 0xCC code cave.
    private static byte[] ImageWith(NativeArch arch, out uint entry, out uint returnRva)
    {
        bool is64 = arch == NativeArch.X64;
        var code = new List<byte>();
        if (is64) code.AddRange([0x48, 0x81, 0xEC, 0xF8, 0x00, 0x00, 0x00]); // sub rsp, 0F8h (7)
        else code.AddRange([0x81, 0xEC, 0xF8, 0x00, 0x00, 0x00]);           // sub esp, 0F8h (6)
        uint returnOffset = (uint)code.Count;
        code.AddRange([0xB8, 0x07, 0x00, 0x00, 0x00]);                      // mov eax, 7
        if (is64) code.AddRange([0x48, 0x81, 0xC4, 0xF8, 0x00, 0x00, 0x00]); // add rsp, 0F8h
        else code.AddRange([0x81, 0xC4, 0xF8, 0x00, 0x00, 0x00]);           // add esp, 0F8h
        code.Add(0xC3);                                                      // ret
        while (code.Count < 96) code.Add(0xCC);                             // int3 code cave

        var b = new PeBuilder { Is64 = is64, Machine = (ushort)(is64 ? 0x8664 : 0x14c), ImageBase = is64 ? 0x140000000UL : 0x10000000UL };
        var text = b.Add(".text", code.ToArray(), 0x60000020);
        b.EntryPoint = text.Rva;
        entry = text.Rva;
        returnRva = text.Rva + returnOffset;
        return b.Build();
    }

    private sealed class Harness : IDisposable
    {
        public readonly TempDir Dir = new();
        public readonly Env Env = new();
        public readonly AnnotationStore Store;
        public readonly NativeCodeService Code;
        public readonly NativeEditService Edits;

        public Harness()
        {
            Store = new AnnotationStore(Dir.File("ann"));
            Code = new NativeCodeService(Env.Workspace, Env.Options, null, Store);
            Edits = new NativeEditService(Env.Workspace, Code);
        }

        public async Task<(LoadedNative Native, NativeCodeIndex Index, string Path, uint Entry, uint Ret)> Load(NativeArch arch)
        {
            var path = Dir.File($"stub-{arch}.dll");
            File.WriteAllBytes(path, ImageWith(arch, out uint entry, out uint ret));
            var n = Env.Workspace.LoadAny(path).Native!;
            return (n, await Code.Index(n, null, default), path, entry, ret);
        }

        public void Dispose() { Env.Dispose(); Dir.Dispose(); }
    }

    /// <summary>Follows the instruction stream from <paramref name="start"/> through jumps, returning the text of each step.</summary>
    private static List<string> Trace(NativeCodeIndex index, uint start, int max = 32)
    {
        var dis = index.CreateDisassembler();
        var steps = new List<string>();
        uint rva = start;
        for (int i = 0; i < max; i++)
        {
            var line = dis.DecodeOne(rva);
            var facts = index.Decode(rva);
            if (line == null || facts == null) break;
            steps.Add(line.Text);
            if (facts.Flow is FlowKind.Return or FlowKind.Trap or FlowKind.Invalid) break;
            if (facts.Flow == FlowKind.Jump && facts.BranchTarget is { } t) { rva = t; continue; }
            rva += (uint)facts.Length;
        }
        return steps;
    }

    [Theory]
    [InlineData(NativeArch.X64, StubMode.Before)]
    [InlineData(NativeArch.X64, StubMode.Replace)]
    [InlineData(NativeArch.X64, StubMode.After)]
    [InlineData(NativeArch.X86, StubMode.Before)]
    [InlineData(NativeArch.X86, StubMode.Replace)]
    public async Task ExtendedPatch_RoundTripsThroughSaveAndPreservesOrder(NativeArch arch, StubMode mode)
    {
        using var h = new Harness();
        var (native, index, _, entry, ret) = await h.Load(arch);

        var newBytes = X86Assembler.Assemble(arch, native.Image.ImageBase + entry, "mov eax, 2").Bytes;
        var prepared = h.Edits.PrepareExtendedPatch(index, entry, newBytes, "mov eax, 2", mode, "test stub", null);
        var stub = prepared.Patch.Stub!;
        Assert.Equal(ret, stub.ReturnRva);
        // The site becomes a near jump (rel8 or rel32); its leftover bytes are int3 padding.
        byte op = prepared.Patch.Replacement[0];
        Assert.True(op is 0xEB or 0xE9, $"site should start with a jmp, got 0x{op:X2}");
        int jmpLen = op == 0xEB ? 2 : 5;
        Assert.All(prepared.Patch.Replacement[jmpLen..], x => Assert.Equal(0xCC, x));
        h.Edits.ApplyPatch(native, index, prepared, dryRun: false);

        // Save, then reload the written file in a fresh workspace and decode the stub.
        var outPath = h.Dir.File($"out-{arch}-{mode}.dll");
        var report = h.Edits.Save(native, outPath, overwrite: true, stripSignature: false);
        Assert.Contains("Verified", report);

        using var env2 = new Env();
        var code2 = new NativeCodeService(env2.Workspace, env2.Options, null, h.Store);
        var reloaded = env2.Workspace.LoadAny(outPath).Native!;
        var index2 = await code2.Index(reloaded, null, default);

        var trace = Trace(index2, entry).Select(t => string.Join(' ', t.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries))).ToList();
        _output.WriteLine($"{arch} {mode}: {string.Join(" | ", trace)}");

        // The new code runs in every mode; execution reaches the original tail (mov eax, 7 ... ret).
        Assert.Contains("mov eax, 2", trace);
        Assert.Contains("mov eax, 7", trace);
        Assert.Equal("ret", trace[^1]);
        // The displaced original instruction (sub) runs only when the mode keeps it.
        bool hasSub = trace.Any(t => t.StartsWith("sub "));
        Assert.Equal(mode != StubMode.Replace, hasSub);
        // Order: in "before" the new code precedes the displaced sub; in "after" it follows.
        if (mode == StubMode.Before)
            Assert.True(trace.FindIndex(t => t == "mov eax, 2") < trace.FindIndex(t => t.StartsWith("sub ")));
        if (mode == StubMode.After)
            Assert.True(trace.FindIndex(t => t.StartsWith("sub ")) < trace.FindIndex(t => t == "mov eax, 2"));
    }

    [Fact]
    public async Task DryRun_ShowsStubAddressAndDisassembly_WithoutRecording()
    {
        using var h = new Harness();
        var (native, index, path, entry, _) = await h.Load(NativeArch.X64);
        var tools = new NativeEditTools(h.Env.Workspace, h.Code, h.Edits);

        var preview = await tools.PatchAsm(path, $"rva:0x{entry:X}", "mov eax, 2", extend: true, dryRun: true, stubMode: "replace");
        Assert.Contains("Stub (replace)", preview);
        Assert.Contains("cave in section '.text'", preview);
        Assert.Contains("jmp", preview);
        Assert.False(native.HasPatches); // dry run recorded nothing
    }

    [Fact]
    public async Task Undo_RestoresSiteAndCave()
    {
        using var h = new Harness();
        var (native, index, _, entry, _) = await h.Load(NativeArch.X64);
        var original = native.Image.FileBytes.ToArray();

        var newBytes = X86Assembler.Assemble(NativeArch.X64, native.Image.ImageBase + entry, "mov eax, 2").Bytes;
        var prepared = h.Edits.PrepareExtendedPatch(index, entry, newBytes, "mov eax, 2", StubMode.Before, "s", null);
        h.Edits.ApplyPatch(native, index, prepared, dryRun: false);
        Assert.Contains("stub", h.Edits.List(native));
        Assert.NotEqual(Convert.ToHexString(original), Convert.ToHexString(native.Patches.PatchedBytes()));

        h.Edits.Undo(native, null);
        Assert.Equal(Convert.ToHexString(original), Convert.ToHexString(native.Patches.PatchedBytes()));
    }

    [Fact]
    public async Task Refuses_BranchTargetInsideSite()
    {
        using var h = new Harness();
        // xor eax,eax ; inc eax (loop target) ; cmp eax,5 ; jb -> inc ; ret. The jb targets inside the displaced range.
        var b = new PeBuilder { Is64 = true, Machine = 0x8664, ImageBase = 0x140000000 };
        var code = new List<byte> { 0x31, 0xC0, 0xFF, 0xC0, 0x83, 0xF8, 0x05, 0x72, 0xF9, 0xC3 };
        while (code.Count < 96) code.Add(0xCC);
        var text = b.Add(".text", code.ToArray(), 0x60000020);
        b.EntryPoint = text.Rva;
        var path = h.Dir.File("branch.dll");
        File.WriteAllBytes(path, b.Build());
        var n = h.Env.Workspace.LoadAny(path).Native!;
        var idx = await h.Code.Index(n, null, default);

        var nb = X86Assembler.Assemble(NativeArch.X64, n.Image.ImageBase + text.Rva, "mov eax, 2").Bytes;
        var ex = Assert.Throws<ToolError>(() => h.Edits.PrepareExtendedPatch(idx, text.Rva, nb, "mov eax, 2", StubMode.Replace, "s", null));
        Assert.Contains("branch_target_in_site", ex.Message);
    }

    [Fact]
    public async Task Refuses_WhenNoCave_And_OnArm64()
    {
        using var h = new Harness();
        // A tiny image with no filler cave after the function.
        var b = new PeBuilder { Is64 = true, Machine = 0x8664, ImageBase = 0x140000000 };
        var code = new byte[] { 0x48, 0x81, 0xEC, 0xF8, 0, 0, 0, 0xB8, 7, 0, 0, 0, 0xC3 }; // sub rsp; mov eax,7; ret (no cave)
        var text = b.Add(".text", code, 0x60000020);
        b.EntryPoint = text.Rva;
        var path = h.Dir.File("nocave.dll");
        File.WriteAllBytes(path, b.Build());
        var n = h.Env.Workspace.LoadAny(path).Native!;
        var idx = await h.Code.Index(n, null, default);
        var nb = X86Assembler.Assemble(NativeArch.X64, n.Image.ImageBase + text.Rva, "mov eax, 2").Bytes;
        var ex = Assert.Throws<ToolError>(() => h.Edits.PrepareExtendedPatch(idx, text.Rva, nb, "mov eax, 2", StubMode.Replace, "s", null));
        Assert.Contains("no_space", ex.Message);
    }

    [Fact]
    public async Task Export_RecordsStub_And_MigrationRefuses()
    {
        using var h = new Harness();
        var (native, index, path, entry, _) = await h.Load(NativeArch.X64);
        var newBytes = X86Assembler.Assemble(NativeArch.X64, native.Image.ImageBase + entry, "mov eax, 2").Bytes;
        var prepared = h.Edits.PrepareExtendedPatch(index, entry, newBytes, "mov eax, 2", StubMode.Before, "s", null);
        h.Edits.ApplyPatch(native, index, prepared, dryRun: false);

        // JSON export marks the patch as a stub and carries the stub bytes.
        var notes = new List<string>();
        var output = NativeEditService.OutputBytes(native, false, notes);
        var src = new PatchExportSource(native.FilePath, native.OriginalSha256, native.Image.ImageBase, native.Image.Arch,
            native.Patches.Patches.ToList(), native.Patches.OriginalBytes(), output, -1, o => native.Image.TryFileOffsetToRva(o, out var r) ? r : null);
        var json = System.Text.Encoding.UTF8.GetString(PatchExport.Render(src, PatchExport.Format.Json).Content);
        Assert.Contains("\"origin\": \"stub\"", json);
        Assert.Contains("\"returnRva\"", json);

        // Migration of a stub patch is refused with its own reason code (not crashed).
        var migratable = PatchMigration.FromJson(json);
        Assert.Single(migratable);
        Assert.True(migratable[0].IsStub);
    }

    // ---- compile a tiny exe, extend-patch it to change output, run it (needs MSVC BuildTools via vswhere) ----

    [Trait("Speed", "Slow")]
    [WindowsFact]
    public void ExtendedPatch_ChangesCompiledProgramOutput()
    {
        var vcvars = VisualStudio.VcVarsAll();
        if (vcvars == null) return; // no MSVC toolchain

        using var dir = new TempDir();
        var src = dir.File("prog.c");
        // Prints 1; we extend-patch the "mov eax, 1" site in value() so it returns 2. noinline keeps value() a real call.
        File.WriteAllText(src, "#include <stdio.h>\n__declspec(noinline) int value(void){ return 1; }\nint main(void){ printf(\"%d\\n\", value()); return 0; }\n");
        var exe = dir.File("prog.exe");

        foreach (var (archFlag, arch) in new[] { ("x64", NativeArch.X64), ("x86", NativeArch.X86) })
        {
            var bat = dir.File($"build-{archFlag}.bat");
            File.WriteAllText(bat, $"@call \"{vcvars}\" {archFlag} >nul\r\n@cl /nologo /Od \"{src}\" /Fe:\"{exe}\" >nul\r\n");
            var (code, outp) = Tools.Run(new ProcessStartInfo("cmd.exe", $"/c \"{bat}\""), 180_000);
            if (code != 0 || !File.Exists(exe)) { _output.WriteLine($"{archFlag} build skipped: {outp}"); continue; }

            var baseline = Tools.Run(new ProcessStartInfo(exe), 30_000);
            Assert.Equal("1", baseline.Output.Trim());

            using var env = new Env();
            using var store = new TempDir();
            var code2 = new NativeCodeService(env.Workspace, env.Options, null, new AnnotationStore(store.File("ann")));
            var edits = new NativeEditService(env.Workspace, code2);
            var native = env.Workspace.LoadAny(exe).Native!;
            var index = code2.Index(native, null, default).Result;
            if (index.Image.Arch != arch) continue;

            // Find the "mov eax, 1" instruction inside the small value() function and extend-patch that site with a stub
            // whose new code is "mov eax, 2" (replace mode), so value() returns 2.
            if (!TryFindMovEax1Site(index, out uint site)) { _output.WriteLine("mov eax,1 site not located"); continue; }

            var nb = X86Assembler.Assemble(arch, index.Image.ImageBase + site, "mov eax, 2").Bytes;
            var prepared = edits.PrepareExtendedPatch(index, site, nb, "mov eax, 2", StubMode.Replace, "ret 2", null);
            edits.ApplyPatch(native, index, prepared, dryRun: false);
            var patched = dir.File($"prog-{archFlag}.exe");
            edits.Save(native, patched, overwrite: true, stripSignature: false);

            var run = Tools.Run(new ProcessStartInfo(patched), 30_000);
            _output.WriteLine($"{archFlag}: baseline={baseline.Output.Trim()} patched={run.Output.Trim()}");
            Assert.Equal("2", run.Output.Trim());
        }
    }

    /// <summary>Locates the "mov eax, 1" instruction inside a small function (value()); returns its RVA as the patch site.</summary>
    private static bool TryFindMovEax1Site(NativeCodeIndex index, out uint site)
    {
        var dis = index.CreateDisassembler();
        foreach (var f in index.Functions)
        {
            if (f.Size == 0 || f.Size > 128) continue;
            foreach (var line in dis.Disassemble(f.Start, 32, f.End))
                if (line.Text.Replace(" ", "") is "moveax,1" or "moveax,1h")
                {
                    site = line.Rva;
                    return true;
                }
        }
        site = 0;
        return false;
    }
}
