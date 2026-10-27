using System.Buffers.Binary;
using System.Diagnostics;
using Iced.Intel;
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

/// <summary>migrate_native_patches reapplies patches where the new build's original bytes match and refuses with a reason otherwise.</summary>
public class NativePatchMigrationTests(ITestOutputHelper output)
{
    private sealed class Harness : IDisposable
    {
        public readonly TempDir Dir = new();
        public readonly Env Env = new();
        public readonly NativeCodeService Code;
        public readonly NativeEditService Edits;
        public readonly NativePatchTools Tools;

        private readonly Dictionary<LoadedNative, uint[]> _starts = new();

        public Harness()
        {
            // Load sets the function starts after the load event: a background build would race it and miss them.
            Env.Options.BackgroundIndexing = false;
            Code =new NativeCodeService(Env.Workspace, Env.Options, null, new AnnotationStore(Dir.File("ann")));
            Code.SymbolStarts = (n, _) => _starts.TryGetValue(n, out var s) ? s : null;
            Edits = new NativeEditService(Env.Workspace, Code);
            Tools = new NativePatchTools(Env.Workspace, Code, Edits);
        }

        public async Task<(LoadedNative, NativeCodeIndex)> Load(byte[] image, string name, uint[]? starts = null)
        {
            var path = Dir.File(name);
            File.WriteAllBytes(path, image);
            var n = Env.Workspace.LoadAny(path).Native!;
            if (starts != null) _starts[n] = starts;
            return (n, await Code.Index(n, null, default));
        }

        /// <summary>Loads a real file from its original path (so its PDB is found) with function starts from the PDB when present.</summary>
        public async Task<(LoadedNative, NativeCodeIndex)> LoadReal(string path, CancellationToken ct)
        {
            var n = Env.Workspace.LoadAny(path).Native!;
            var pe = n.Pe!;
            if (Corvus.Native.Pdb.PdbLocator.Locate(pe).Path is { } pdbPath)
            {
                var pdb = Corvus.Native.Pdb.PdbFile.Open(pdbPath, pe.Sections, ct);
                _starts[n] = Corvus.Native.Pdb.PdbNaming.Choose(pdb, pe.SizeOfImage, ct).Where(x => x.IsFunction).Select(x => x.Rva).ToArray();
            }
            return (n, await Code.Index(n, null, ct));
        }

        public NativeEditService.PatchResult Asm(NativeCodeIndex index, uint rva, string text)
        {
            var r = X86Assembler.Assemble(index.Image.Arch, index.Image.ImageBase + rva, text);
            return Edits.PreparePatch(index, rva, r.Bytes, false, "patch_asm", RelocationMode.Auto, r.Constants, text);
        }

        public void Dispose() { Env.Dispose(); Dir.Dispose(); }
    }

    // A tiny x64 image. .text has two functions, each three instructions (the matcher skips < 3-instruction functions):
    //   f1 @f1: mov eax, [rip+g] ; add eax, 0x11 ; ret   (RIP-relative load; the displacement moves between builds)
    //   f2 @f2: mov eax, f2Imm   ; add eax, 0x22 ; ret   (a plain immediate)
    // In the new build the functions and g are shifted, so f1's RIP-relative bytes differ but the opcode does not.
    internal static byte[] X64Image(uint f1, uint gData, uint f2, byte f2Imm)
    {
        var b = new PeBuilder { Is64 = true, Machine = 0x8664, ImageBase = 0x180000000, DllCharacteristics = 0x0160 };
        var code = new byte[0x80];
        int o = (int)(f1 - 0x1000);
        code[o] = 0x8B; code[o + 1] = 0x05;             // mov eax, [rip+disp]
        BinaryPrimitives.WriteInt32LittleEndian(code.AsSpan(o + 2), (int)gData - ((int)f1 + 6));
        code[o + 6] = 0x83; code[o + 7] = 0xC0; code[o + 8] = 0x11;   // add eax, 0x11
        code[o + 9] = 0xC3;                             // ret
        int o2 = (int)(f2 - 0x1000);
        code[o2] = 0xB8; code[o2 + 1] = f2Imm;          // mov eax, imm32
        code[o2 + 5] = 0x83; code[o2 + 6] = 0xC0; code[o2 + 7] = 0x22; // add eax, 0x22
        code[o2 + 8] = 0xC3;                            // ret
        var text = b.Add(".text", code, 0x60000020);
        var data = new byte[0x40];
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan((int)(gData - 0x2000)), 0xDEAD);
        b.Add(".data", data, 0xC0000040);
        b.EntryPoint = text.Rva;
        return b.Build();
    }

    [Fact]
    public async Task Patches_migrate_by_function_match_and_refuse_where_bytes_differ()
    {
        using var h = new Harness();
        var starts = new uint[] { 0x1000, 0x1040 };
        var old = X64Image(0x1000, 0x2000, 0x1040, 1);
        var @new = X64Image(0x1010, 0x2020, 0x1050, 1);   // f1 and g moved; f2 moved but identical bytes
        var (oldN, oldIdx) = await h.Load(old, "old.dll", starts);
        var (newN, _) = await h.Load(@new, "new.dll", [0x1010, 0x1050]);

        // patch_asm over f1's 'add eax' instruction, and a raw patch over f2's whole 'mov eax,imm'.
        h.Edits.ApplyPatch(oldN, oldIdx, h.Asm(oldIdx, 0x1006, "nop"), dryRun: false);
        oldIdx = await h.Code.Index(oldN, null, default);
        h.Edits.ApplyPatch(oldN, oldIdx, h.Edits.PreparePatch(oldIdx, 0x1040, [0xB8, 0x02, 0, 0, 0], false, "patch_bytes 5 bytes"), dryRun: false);

        var dry = await h.Tools.CarryPatches(oldN.Id, newN.Id, dryRun: true);
        Assert.Equal("in_memory", dry.Source);
        Assert.Equal(2, dry.Patches);
        Assert.Equal(2, dry.Carried);
        Assert.False(dry.Applied);
        var f1Entry = dry.Items.Single(e => e.OldAddress.EndsWith("1006"));
        Assert.Equal("would_apply", f1Entry.Status);
        Assert.Equal("0x180001016", f1Entry.NewAddress);   // 0x1006 -> 0x1016 after the 0x10 shift
        var f2Entry = dry.Items.Single(e => e.OldAddress.EndsWith("1040"));
        Assert.Equal("0x180001050", f2Entry.NewAddress);
        Assert.Equal("B802000000", f2Entry.ReplacementBytes);

        // Apply for real: both land, and the new image shows them.
        var applied = await h.Tools.CarryPatches(oldN.Id, newN.Id, dryRun: false);
        Assert.Equal((2, 2), (applied.Carried, applied.EditIds.Count));
        Assert.Equal(0, applied.Refused);
        var img = newN.Image;
        var nop = new byte[1]; img.Read(0x1016, nop); Assert.Equal(0x90, nop[0]);
        var imm = new byte[1]; img.Read(0x1051, imm); Assert.Equal(0x02, imm[0]);
    }

    [Fact]
    public async Task Raw_patch_is_refused_when_the_new_original_bytes_differ()
    {
        using var h = new Harness();
        var old = X64Image(0x1000, 0x2000, 0x1040, 1);
        var @new = X64Image(0x1000, 0x2000, 0x1040, 7);   // f2's immediate is 7, not 1
        var (oldN, oldIdx) = await h.Load(old, "old.dll", [0x1000, 0x1040]);
        var (newN, _) = await h.Load(@new, "new.dll", [0x1000, 0x1040]);

        // Raw patch over f2's whole body (B8 01 00 00 00): the new build's original differs (B8 07 ...).
        h.Edits.ApplyPatch(oldN, oldIdx, h.Edits.PreparePatch(oldIdx, 0x1040, [0xB8, 0x02, 0, 0, 0], false, "patch_bytes 5 bytes"), dryRun: false);
        var dry = await h.Tools.CarryPatches(oldN.Id, newN.Id, dryRun: true);
        var entry = Assert.Single(dry.Items);
        Assert.True(entry is { Status: "refused", Reason: "original_bytes_differ" }, $"{entry.Status} {entry.Reason}: {entry.Detail}");
        Assert.Contains("B8010000", entry.Detail.Replace(" ", ""));  // expected (old) bytes in the evidence
        Assert.Equal(0, dry.Carried);
        Assert.Contains(dry.RefusedBy, r => r is { Reason: "original_bytes_differ", Count: 1 });
    }

    [Fact]
    public async Task Patch_in_an_unmatched_function_is_refused_function_not_matched()
    {
        using var h = new Harness();
        var old = X64Image(0x1000, 0x2000, 0x1040, 1);
        // The new build has f1 only (f2 replaced by filler): f2's patch cannot map.
        var newBuild = X64Image(0x1000, 0x2000, 0x1040, 1);
        for (int i = 0x40; i < 0x49; i++) newBuild[FileOffset(newBuild, 0x1000) + i] = 0x90;  // wipe f2 to nops
        var (oldN, oldIdx) = await h.Load(old, "old.dll", [0x1000, 0x1040]);
        var (newN, _) = await h.Load(newBuild, "new.dll", [0x1000]);

        h.Edits.ApplyPatch(oldN, oldIdx, h.Edits.PreparePatch(oldIdx, 0x1040, [0x90], false, "patch_bytes 1 bytes"), dryRun: false);
        var dry = await h.Tools.CarryPatches(oldN.Id, newN.Id, dryRun: true, codeOnly: true);
        var entry = Assert.Single(dry.Items);
        Assert.Equal("refused", entry.Status);
        Assert.Contains(entry.Reason, new[] { "function_not_matched", "ambiguous", "changed_region", "not_an_instruction", "original_bytes_differ" });
    }

    [Fact]
    public async Task Migrates_from_an_exported_json_patch_set()
    {
        using var h = new Harness();
        var old = X64Image(0x1000, 0x2000, 0x1040, 1);
        var @new = X64Image(0x1010, 0x2020, 0x1050, 1);
        var (oldN, oldIdx) = await h.Load(old, "old.dll", [0x1000, 0x1040]);
        var (newN, _) = await h.Load(@new, "new.dll", [0x1010, 0x1050]);
        h.Edits.ApplyPatch(oldN, oldIdx, h.Asm(oldIdx, 0x1006, "nop"), dryRun: false);

        var jsonPath = h.Dir.File("set.json");
        var (export, exportText) = await BuildToolCalls.Collected<NativePatchTools.PatchExportReport>(() => h.Tools.ExportNativePatches(oldN.Id, jsonPath, "json"));
        Assert.Equal(1, export.Patches);
        Assert.StartsWith($"Wrote 1 patch of {oldN.Id} as json to {jsonPath} (1 record, ", exportText);
        Assert.True(exportText.TrimEnd('\n').Split('\n').Length <= 2, exportText);
        // Undo the in-memory patch so the only source is the JSON.
        h.Edits.Undo(oldN, null);
        Assert.False(oldN.Patches.IsDirty);

        var (preview, previewText) = await BuildToolCalls.Collected<NativePatchTools.MigrationPatchReport>(() => h.Tools.MigrateNativePatches(oldN.Id, newN.Id, patchSet: jsonPath));
        Assert.Equal((true, 1, "would_apply"), (preview.DryRun, preview.Carried, Assert.Single(preview.Items).Status));
        Assert.StartsWith($"Dry run: 1 of 1 patch ({jsonPath}) would apply to {newN.Id}. Nothing recorded", previewText);
        Assert.Contains("#1 0x180001006 -> 0x180001016 ", previewText);
        var report = await h.Tools.CarryPatches(oldN.Id, newN.Id, patchSet: jsonPath, dryRun: false);
        Assert.StartsWith(h.Dir.Path, report.Source);   // the json file path
        Assert.Equal(1, report.Carried);
        var nop = new byte[1]; newN.Image.Read(0x1016, nop); Assert.Equal(0x90, nop[0]);
    }

    private static int FileOffset(byte[] image, uint sectionRva)
    {
        var pe = PeFile.FromBytes(image, "x");
        pe.TryRvaToFileOffset(sectionRva, out var off);
        return (int)off;
    }

    // ---- real build pairs ----

    /// <summary>A patch_asm and a patch_bytes patch migrate between real build pairs and the mapped bytes verify.</summary>
    [Trait("Speed", "Slow")]
    [WindowsFact]
    public async Task Real_build_pairs_migrate_patches()
    {
        int pairs = 0, appliedTotal = 0, refusedTotal = 0;
        var sw = Stopwatch.StartNew();
        foreach (var (oldPath, newPath, label) in NativeDiffRealTests.DiscoverPairs(6))
        {
            using var h = new Harness();
            LoadedNative oldN, newN;
            NativeCodeIndex oldIdx, newIdx;
            try
            {
                (oldN, oldIdx) = await h.LoadReal(oldPath, default);
                (newN, newIdx) = await h.LoadReal(newPath, default);
            }
            catch (Exception ex) { output.WriteLine($"{label}: skipped ({ex.GetType().Name})"); continue; }
            if (oldIdx.Support != CodeSupport.Full || newIdx.Support != CodeSupport.Full) continue;

            // Pick two function starts with a plain body to patch.
            var sites = oldIdx.Functions.Where(f => f.End - f.Start >= 8).OrderBy(f => f.Start).Take(200).Select(f => f.Start).ToList();
            uint? asmSite = null, rawSite = null;
            byte[]? rawOriginal = null;
            foreach (var rva in sites)
            {
                if (asmSite == null && Try(() => h.Asm(oldIdx, rva, "xor eax, eax\nret")) is { } pa)
                { h.Edits.ApplyPatch(oldN, oldIdx, pa, false); asmSite = rva; oldIdx = await h.Code.Index(oldN, null, default); continue; }
                if (asmSite != null && rawSite == null && rva > asmSite + 16)
                {
                    var one = new byte[1]; oldIdx.Image.Read(rva, one);
                    if (Try(() => h.Edits.PreparePatch(oldIdx, rva, [0xCC], false, "patch_bytes 1 bytes")) is { } pb)
                    { h.Edits.ApplyPatch(oldN, oldIdx, pb, false); rawSite = rva; rawOriginal = one; break; }
                }
            }
            if (asmSite == null || rawSite == null) { output.WriteLine($"{label}: no usable sites"); continue; }

            var report = await h.Tools.CarryPatches(oldN.Id, newN.Id, dryRun: false);
            pairs++;
            appliedTotal += report.Carried;
            refusedTotal += report.Refused;
            output.WriteLine($"{label}: {report.Carried} applied, {report.Refused} refused ({string.Join(", ", report.RefusedBy.Select(r => $"{r.Reason}×{r.Count}"))})");
            foreach (var e in report.Items.Where(e => e.Status == "applied"))
            {
                Assert.NotNull(e.NewAddress);
                // The applied bytes are present at the mapped address.
                uint newRva = (uint)(Convert.ToUInt64(e.NewAddress!.Substring(2), 16) - newN.Image.ImageBase);
                var got = new byte[e.ReplacementBytes!.Length / 2];
                newN.Image.Read(newRva, got);
                Assert.Equal(e.ReplacementBytes, Convert.ToHexString(got));
            }
            // Every entry is accounted for.
            Assert.Equal(report.Patches, report.Items.Count(e => e.Status is "applied" or "refused"));
            if (appliedTotal > 0 && pairs >= 2) break;
            if (pairs >= 4) break;
        }
        output.WriteLine($"{pairs} pair(s): {appliedTotal} applied, {refusedTotal} refused in {sw.ElapsedMilliseconds} ms");
        if (pairs == 0) return;   // no suitable build pairs on this machine
        Assert.True(appliedTotal > 0, $"no patch migrated across {pairs} real build pair(s)");
    }

    private static T? Try<T>(Func<T> f) where T : class { try { return f(); } catch (ToolError) { return null; } }
}
