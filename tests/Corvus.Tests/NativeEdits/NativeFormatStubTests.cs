using Corvus.Core;
using Corvus.Native;
using Corvus.Native.Annotations;
using Corvus.Native.Code;
using Corvus.Native.MachO;
using Corvus.Native.Patching;
using Corvus.Services;
using Corvus.Tests.NativeFormats;
using Xunit.Abstractions;

namespace Corvus.Tests;

/// <summary>Patch-site extension (relocation stubs) on x64 ELF and Mach-O: code caves, appended segments, round trip, undo and export.</summary>
public sealed class NativeFormatStubTests(ITestOutputHelper output) : IDisposable
{
    private readonly TempDir _dir = new();
    private readonly Env _env = new();
    private readonly AnnotationStore _store = new(Path.Combine(Path.GetTempPath(), "corvus-stub-" + Guid.NewGuid().ToString("N")));

    public void Dispose() { _env.Dispose(); _dir.Dispose(); }

    /// <summary>x64: sub rsp,0F8h ; mov eax,7 ; add rsp,0F8h ; ret, then an int3 code cave, as a code section's bytes.</summary>
    private static byte[] CodeBytes(out uint returnOffset)
    {
        var code = new List<byte> { 0x48, 0x81, 0xEC, 0xF8, 0x00, 0x00, 0x00 }; // sub rsp, 0F8h (7)
        returnOffset = (uint)code.Count;
        code.AddRange([0xB8, 0x07, 0x00, 0x00, 0x00]);                          // mov eax, 7
        code.AddRange([0x48, 0x81, 0xC4, 0xF8, 0x00, 0x00, 0x00]);              // add rsp, 0F8h
        code.Add(0xC3);                                                          // ret
        while (code.Count < 96) code.Add(0xCC);                                 // int3 cave
        return [.. code];
    }

    private static byte[] Elf(out uint returnOffset) => new ElfWriter
    {
        Machine = ElfWriter.EmX64, Type = 3, Base = 0, Entry = ElfWriter.TextRva, Text = CodeBytes(out returnOffset),
    }.Build();

    private static byte[] MachO(out uint returnOffset, MachOWriter.Signature? signature = null) => new MachOWriter
    {
        CpuType = MachOWriter.CpuX64, FileType = 6, Text = CodeBytes(out returnOffset), CodeSignature = signature,
    }.Build();

    private NativeCodeService Code() => new(_env.Workspace, _env.Options, null, _store);

    private async Task<(LoadedNative Native, NativeCodeIndex Index, NativeEditService Edits, NativeCodeService Code, uint Entry, uint Ret)> Load(string name, byte[] bytes, uint returnOffset)
    {
        var path = _dir.File(name);
        File.WriteAllBytes(path, bytes);
        var code = Code();
        var edits = new NativeEditService(_env.Workspace, code);
        var native = _env.Workspace.LoadAny(path).Native!;
        var index = await code.Index(native, null, default);
        return (native, index, edits, code, ElfWriter.TextRva, ElfWriter.TextRva + returnOffset);
    }

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
            steps.Add(string.Join(' ', line.Text.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries)));
            if (facts.Flow is FlowKind.Return or FlowKind.Trap or FlowKind.Invalid) break;
            if (facts.Flow == FlowKind.Jump && facts.BranchTarget is { } t) { rva = t; continue; }
            rva += (uint)facts.Length;
        }
        return steps;
    }

    public static IEnumerable<object[]> Cases() =>
        from fmt in new[] { "elf", "macho" }
        from placement in new[] { StubPlacement.Cave, StubPlacement.Section }
        select new object[] { fmt, placement };

    [Theory]
    [MemberData(nameof(Cases))]
    public async Task Extended_patch_round_trips_and_undoes(string fmt, StubPlacement placement)
    {
        var bytes = fmt == "elf" ? Elf(out var ro) : MachO(out ro);
        var ext = fmt == "elf" ? ".so" : ".dylib";
        var (native, index, edits, _, entry, ret) = await Load($"{fmt}-{placement}{ext}", bytes, ro);
        var original = native.Patches.OriginalBytes();

        var newBytes = X86Assembler.Assemble(NativeArch.X64, native.Image.ImageBase + entry, "mov eax, 2").Bytes;
        var prepared = edits.PrepareExtendedPatch(index, entry, newBytes, "mov eax, 2", StubMode.Before, "grow stub", null, placement);
        var stub = prepared.Patch.Stub!;
        Assert.Equal(ret, stub.ReturnRva);
        if (placement == StubPlacement.Section)
        {
            Assert.NotNull(prepared.Patch.Growth);
            Assert.StartsWith("new segment", stub.Placement);
        }
        else
        {
            Assert.Null(prepared.Patch.Growth);
            Assert.StartsWith("cave", stub.Placement);
        }
        edits.ApplyPatch(native, index, prepared, dryRun: false);

        var outPath = _dir.File($"out-{fmt}-{placement}{ext}");
        var report = edits.Save(native, outPath, overwrite: true, stripSignature: false);
        Assert.Contains("Verified", report);
        if (placement == StubPlacement.Section) Assert.Contains("grown by", report);

        // Reload the written file fresh and follow the stub: jmp -> new code -> displaced sub -> original tail -> ret.
        using var env2 = new Env();
        var code2 = new NativeCodeService(env2.Workspace, env2.Options, null, _store);
        var reloaded = env2.Workspace.LoadAny(outPath).Native!;
        var index2 = await code2.Index(reloaded, null, default);
        var trace = Trace(index2, entry);
        output.WriteLine($"{fmt} {placement}: {string.Join(" | ", trace)}");
        Assert.Contains("mov eax, 2", trace);
        Assert.Contains("mov eax, 7", trace);
        Assert.Equal("ret", trace[^1]);
        Assert.True(trace.FindIndex(t => t == "mov eax, 2") < trace.FindIndex(t => t.StartsWith("sub ")));

        if (placement == StubPlacement.Section)
        {
            // The appended region maps and reads back the stub bytes (ELF lists no section for it when section headers exist).
            var g = prepared.Patch.Growth!;
            Assert.True(reloaded.Image.SizeOfImage >= g.SectionRva + g.SectionVirtualSize);
            var head = new byte[4];
            Assert.Equal(4, reloaded.Image.Read(g.SectionRva, head));
            Assert.Equal(stub.Replacement.AsSpan(0, 4).ToArray(), head);
        }

        // Undo restores the original bytes exactly (the appended segment and its header edits are removed).
        edits.Undo(native, null);
        Assert.Equal(Convert.ToHexString(original), Convert.ToHexString(native.Patches.PatchedBytes()));
    }

    [Fact]
    public async Task Grown_segment_exports_segment_in_IDA_and_JSON()
    {
        var (native, index, edits, _, entry, _) = await Load("export.so", Elf(out var ro), ro);
        var newBytes = X86Assembler.Assemble(NativeArch.X64, native.Image.ImageBase + entry, "mov eax, 2").Bytes;
        var prepared = edits.PrepareExtendedPatch(index, entry, newBytes, "mov eax, 2", StubMode.Replace, "grow stub", null, StubPlacement.Section);
        edits.ApplyPatch(native, index, prepared, dryRun: false);

        var ida = _env.Workspace.Read(() => NativeEditService.RenderPatches(native, PatchExport.Format.Ida));
        var idaText = System.Text.Encoding.UTF8.GetString(ida.Content);
        Assert.Contains("ida_segment.add_segm", idaText);
        Assert.Contains($"0x{prepared.Patch.Growth!.SectionRva:X}", idaText);

        var json = _env.Workspace.Read(() => NativeEditService.RenderPatches(native, PatchExport.Format.Json));
        var jsonText = System.Text.Encoding.UTF8.GetString(json.Content);
        Assert.Contains("appendedSections", jsonText);
        Assert.Contains(prepared.Patch.Growth!.SectionName, jsonText);

        // .dif cannot grow a file: it refuses with the grown_file code.
        var ex = Assert.Throws<ToolError>(() => _env.Workspace.Read(() => NativeEditService.RenderPatches(native, PatchExport.Format.Dif)));
        Assert.Contains("grown_file", ex.Message);
    }

    [Fact]
    public async Task Signed_MachO_patch_reports_the_signature_no_longer_matches()
    {
        var (native, index, edits, _, entry, _) = await Load("signed.dylib",
            MachO(out _, new MachOWriter.Signature("com.example.test")), 0);
        var newBytes = X86Assembler.Assemble(NativeArch.X64, native.Image.ImageBase + entry, "mov eax, 2").Bytes;
        var prepared = edits.PrepareExtendedPatch(index, entry, newBytes, "mov eax, 2", StubMode.Replace, "s", null, StubPlacement.Cave);
        var report = edits.ApplyPatch(native, index, prepared, dryRun: true);
        Assert.Contains("code signature no longer matches", report);
    }

    [Fact]
    public async Task MachO_chained_fixup_under_a_patch_is_refused()
    {
        // __data holds a chained-fixup rebase; an in-place patch over it refuses with fixup_chain.
        var writer = new MachOWriter
        {
            CpuType = MachOWriter.CpuX64, FileType = 6, Text = CodeBytes(out _), ChainedFormat = 2,
            Fixups = [new MachOWriter.Fixup(MachOWriter.DataOffset, Target: MachOWriter.TextOffset)],
        };
        var path = _dir.File("chain.dylib");
        File.WriteAllBytes(path, writer.Build());
        var code = Code();
        var edits = new NativeEditService(_env.Workspace, code);
        var native = _env.Workspace.LoadAny(path).Native!;
        var index = await code.Index(native, null, default);
        var macho = (MachOFile)native.Image;
        Assert.True(macho.HasChainedFixups);
        var dataRva = macho.Section("__DATA", "__data")!.Address - macho.ImageBase;
        var ex = Assert.Throws<ToolError>(() => edits.PreparePatch(index, (uint)dataRva, new byte[8], false, "over a fixup"));
        Assert.Contains("fixup_chain", ex.Message);
    }
}
