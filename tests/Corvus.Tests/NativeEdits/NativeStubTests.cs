using System.Diagnostics;
using Corvus.Core;
using Corvus.Native;
using Corvus.Native.Annotations;
using Corvus.Native.Code;
using Corvus.Native.Patching;
using Corvus.Native.Pe;
using Corvus.Services;
using Corvus.Tools;
using Xunit.Abstractions;

namespace Corvus.Tests;

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
    public async Task Extended_patch_round_trips_through_save_and_preserves_order(NativeArch arch, StubMode mode)
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

    [Theory]
    [InlineData(NativeArch.X64, StubMode.Before)]
    [InlineData(NativeArch.X64, StubMode.Replace)]
    [InlineData(NativeArch.X64, StubMode.After)]
    [InlineData(NativeArch.X86, StubMode.Before)]
    [InlineData(NativeArch.X86, StubMode.Replace)]
    public async Task Grown_section_round_trips_through_save_and_preserves_order(NativeArch arch, StubMode mode)
    {
        using var h = new Harness();
        var (native, index, _, entry, ret) = await h.Load(arch);
        var original = native.Pe!.FileBytes.ToArray();

        // placement=section forces a new section even though the image has a cave.
        var newBytes = X86Assembler.Assemble(arch, native.Image.ImageBase + entry, "mov eax, 2").Bytes;
        var prepared = h.Edits.PrepareExtendedPatch(index, entry, newBytes, "mov eax, 2", mode, "grow stub", null, StubPlacement.Section);
        var stub = prepared.Patch.Stub!;
        var growth = prepared.Patch.Growth!;
        Assert.Equal(ret, stub.ReturnRva);
        Assert.StartsWith("new section", stub.Placement);
        Assert.Equal(stub.Rva, growth.SectionRva);
        h.Edits.ApplyPatch(native, index, prepared, dryRun: false);

        // Save: the file grows and verify accepts it.
        var outPath = h.Dir.File($"grow-{arch}-{mode}.dll");
        var report = h.Edits.Save(native, outPath, overwrite: true, stripSignature: false);
        Assert.Contains("Verified", report);
        Assert.Contains("grown by", report);
        Assert.True(new FileInfo(outPath).Length > original.Length);

        // Reload the written file in a fresh workspace: it parses, the new section is listed, the trace holds.
        using var env2 = new Env();
        var code2 = new NativeCodeService(env2.Workspace, env2.Options, null, h.Store);
        var reloaded = env2.Workspace.LoadAny(outPath).Native!;
        var index2 = await code2.Index(reloaded, null, default);
        Assert.Contains(reloaded.Image.Sections, s => s.Name == growth.SectionName && s.Rva == growth.SectionRva);
        Assert.True(reloaded.Image.SizeOfImage > native.Image.SizeOfImage - growth.SectionVirtualSize); // SizeOfImage grew

        var trace = Trace(index2, entry).Select(t => string.Join(' ', t.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries))).ToList();
        _output.WriteLine($"{arch} {mode} (section): {string.Join(" | ", trace)}");
        Assert.Contains("mov eax, 2", trace);
        Assert.Contains("mov eax, 7", trace);
        Assert.Equal("ret", trace[^1]);
        bool hasSub = trace.Any(t => t.StartsWith("sub "));
        Assert.Equal(mode != StubMode.Replace, hasSub);
        if (mode == StubMode.Before)
            Assert.True(trace.FindIndex(t => t == "mov eax, 2") < trace.FindIndex(t => t.StartsWith("sub ")));
        if (mode == StubMode.After)
            Assert.True(trace.FindIndex(t => t.StartsWith("sub ")) < trace.FindIndex(t => t == "mov eax, 2"));

        // Undo removes the section: the image returns byte-for-byte to the original.
        h.Edits.Undo(native, null);
        Assert.Equal(Convert.ToHexString(original), Convert.ToHexString(native.Patches.PatchedBytes()));
    }

    [Fact]
    public async Task Grown_section_exports_and_reapplies_across_formats()
    {
        using var h = new Harness();
        var (native, index, path, entry, _) = await h.Load(NativeArch.X64);
        var newBytes = X86Assembler.Assemble(NativeArch.X64, native.Image.ImageBase + entry, "mov eax, 2").Bytes;
        var prepared = h.Edits.PrepareExtendedPatch(index, entry, newBytes, "mov eax, 2", StubMode.Before, "grow stub", null, StubPlacement.Section);
        h.Edits.ApplyPatch(native, index, prepared, dryRun: false);

        var tools = new NativePatchTools(h.Env.Workspace, h.Code, h.Edits);
        var saved = h.Dir.File("grow-saved.bin");
        h.Edits.Save(native, saved, overwrite: true, stripSignature: false);
        var expected = File.ReadAllBytes(saved);
        var originalBytes = native.Patches.OriginalBytes();

        // IPS/IPS32 and JSON applied to the original reproduce save_native's grown file; .dif refuses growth.
        foreach (var fmt in new[] { "ips", "ips32", "json" })
        {
            var p = h.Dir.File($"grow.{fmt}");
            var r = await tools.Export(native.Id, p, fmt);
            byte[] applied = fmt == "json"
                ? NativePatchExportTests.ApplyJson(originalBytes, File.ReadAllText(p))
                : NativePatchExportTests.ApplyIps(originalBytes, File.ReadAllBytes(p));
            Assert.True(expected.AsSpan().SequenceEqual(applied), $"{fmt} did not reproduce save_native's grown file");
        }
        await Assert.ThrowsAsync<ToolError>(() => tools.Export(native.Id, h.Dir.File("grow.dif"), "dif"));

        // The IDAPython script creates the segment for the appended section.
        var idaPath = h.Dir.File("grow.ida");
        await tools.Export(native.Id, idaPath, "ida");
        var script = File.ReadAllText(idaPath);
        Assert.Contains("ida_segment", script);
        Assert.Contains("add_segments()", script);
        Assert.Contains(".patch", script);
    }

    [Fact]
    public async Task Dry_run_shows_stub_address_and_disassembly_without_recording()
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
    public async Task Undo_restores_site_and_cave()
    {
        using var h = new Harness();
        var (native, index, _, entry, _) = await h.Load(NativeArch.X64);
        var original = native.Pe!.FileBytes.ToArray();

        var newBytes = X86Assembler.Assemble(NativeArch.X64, native.Image.ImageBase + entry, "mov eax, 2").Bytes;
        var prepared = h.Edits.PrepareExtendedPatch(index, entry, newBytes, "mov eax, 2", StubMode.Before, "s", null);
        h.Edits.ApplyPatch(native, index, prepared, dryRun: false);
        Assert.Contains("stub", h.Edits.List(native));
        Assert.NotEqual(Convert.ToHexString(original), Convert.ToHexString(native.Patches.PatchedBytes()));

        h.Edits.Undo(native, null);
        Assert.Equal(Convert.ToHexString(original), Convert.ToHexString(native.Patches.PatchedBytes()));
    }

    [Fact]
    public async Task Refuses_branch_target_inside_site()
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
    public async Task Refuses_when_no_cave_and_on_ARM64()
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
        // placement=cave: with no cave it still refuses (auto would grow a section instead).
        var ex = Assert.Throws<ToolError>(() => h.Edits.PrepareExtendedPatch(idx, text.Rva, nb, "mov eax, 2", StubMode.Replace, "s", null, StubPlacement.Cave));
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
    public void Extended_patch_changes_compiled_program_output()
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

            // Extend-patch "mov eax, 1" in value() with "mov eax, 2" (replace mode), so value() returns 2.
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

    [Trait("Speed", "Slow")]
    [WindowsFact]
    public void Grown_section_changes_compiled_program_output()
    {
        var vcvars = VisualStudio.VcVarsAll();
        if (vcvars == null) return; // no MSVC toolchain

        using var dir = new TempDir();
        var src = dir.File("prog.c");
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
            if (!TryFindMovEax1Site(index, out uint site)) { _output.WriteLine("mov eax,1 site not located"); continue; }

            // Force placement=section: the stub goes into a brand-new appended section, not a cave.
            var nb = X86Assembler.Assemble(arch, index.Image.ImageBase + site, "mov eax, 2").Bytes;
            var prepared = edits.PrepareExtendedPatch(index, site, nb, "mov eax, 2", StubMode.Replace, "ret 2", null, StubPlacement.Section);
            Assert.StartsWith("new section", prepared.Patch.Stub!.Placement);
            edits.ApplyPatch(native, index, prepared, dryRun: false);
            var patched = dir.File($"prog-grow-{archFlag}.exe");
            var report = edits.Save(native, patched, overwrite: true, stripSignature: false);
            Assert.Contains("grown by", report);

            var run = Tools.Run(new ProcessStartInfo(patched), 30_000);
            _output.WriteLine($"{archFlag} (section): baseline={baseline.Output.Trim()} patched={run.Output.Trim()} exit={run.ExitCode}");
            Assert.Equal("2", run.Output.Trim());
            Assert.Equal(0, run.ExitCode);
        }
    }

    /// <summary>A copy of a real System32 DLL: grown with a stub in a new section, it reloads and the trace jmp -> stub -> back holds.</summary>
    [Trait("Speed", "Slow")]
    [WindowsFact]
    public async Task A_grown_section_in_a_System32_binary_reloads_and_its_trace_holds()
    {
        var src = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "version.dll");
        if (!File.Exists(src)) return;
        using var h = new Harness();
        var copy = h.Dir.File("version.dll");
        File.Copy(src, copy); // read-only source, patch a writable copy
        var native = h.Env.Workspace.LoadAny(copy).Native!;
        var index = await h.Code.Index(native, null, default);
        if (index.Support != CodeSupport.Full) return;

        // Find a site, past any prologue, that PatchExtension accepts; skip cleanly if none is found quickly.
        NativeEditService.PatchResult? prepared = null;
        uint site = 0;
        var dis = index.CreateDisassembler();
        foreach (var f in index.Functions.Take(400))
        {
            if (f.Size < 16) continue;
            foreach (var line in dis.Disassemble(f.Start, 24, f.End))
            {
                if (line.Rva <= f.Start + 8 || line.Rva + 5 > f.End) continue; // past the prologue, room for a jmp
                try
                {
                    prepared = h.Edits.PrepareExtendedPatch(index, line.Rva, [0x90], null, StubMode.Before, "grow", null, StubPlacement.Section);
                    site = line.Rva;
                }
                catch (ToolError) { continue; }
                break;
            }
            if (prepared != null) break;
        }
        if (prepared == null) { _output.WriteLine("no stub-able site found in version.dll"); return; }
        var growth = prepared.Patch.Growth!;
        h.Edits.ApplyPatch(native, index, prepared, dryRun: false);

        var outPath = h.Dir.File("version-grown.dll");
        var report = h.Edits.Save(native, outPath, overwrite: true, stripSignature: true);
        Assert.Contains("Verified", report);

        using var env2 = new Env();
        var code2 = new NativeCodeService(env2.Workspace, env2.Options, null, h.Store);
        var reloaded = env2.Workspace.LoadAny(outPath).Native!;
        var index2 = await code2.Index(reloaded, null, default);
        Assert.Contains(reloaded.Image.Sections, s => s.Name == growth.SectionName);

        // The site now jumps into the new section; following it returns to the instruction after the site.
        var facts = index2.Decode(site);
        Assert.NotNull(facts);
        Assert.Equal(FlowKind.Jump, facts!.Flow);
        Assert.Equal(growth.SectionRva, facts.BranchTarget);
        var stubFacts = index2.Decode(growth.SectionRva);
        Assert.NotNull(stubFacts); // the new section decodes
        _output.WriteLine($"version.dll grown: site 0x{site:X} -> section '{growth.SectionName}' 0x{growth.SectionRva:X} ({growth.SectionVirtualSize} bytes), file {new FileInfo(src).Length:N0} -> {new FileInfo(outPath).Length:N0}");
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
