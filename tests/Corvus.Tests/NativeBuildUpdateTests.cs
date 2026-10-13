using System.Buffers.Binary;
using System.Diagnostics;
using dnlib.DotNet;
using Corvus.Core;
using Corvus.Native;
using Corvus.Native.Annotations;
using Corvus.Native.Code;
using Corvus.Native.Patching;
using Corvus.Services;
using Corvus.Tools;
using Xunit.Abstractions;

namespace Corvus.Tests;

/// <summary>
/// update_to_new_build: names, imported layers, patches (stub extensions re-created), code patterns and the Il2Cpp method
/// mapping carried from an old build to a new one in one call. Two synthetic builds cover every category and a refusal per
/// reason; a Slow test runs it on real build pairs.
/// </summary>
public class NativeBuildUpdateTests(ITestOutputHelper output)
{
    internal sealed class Harness : IDisposable
    {
        public readonly TempDir Dir = new();
        public readonly Env Env = new();
        public readonly NativeCodeService Code;
        public readonly NativeEditService Edits;
        public readonly BuildUpdateTools Tools;
        public readonly NotesService Notes;
        private readonly Dictionary<LoadedNative, uint[]> _starts = new();

        public Harness()
        {
            // Load sets the function starts after the load event: a background build would race it and miss them.
            Env.Options.BackgroundIndexing = false;
            var store = new AnnotationStore(Dir.File("ann"));
            Code = new NativeCodeService(Env.Workspace, Env.Options, null, store);
            var pdb = new PdbService(Code);
            Code.SymbolStarts = (n, _) => _starts.TryGetValue(n, out var s) ? s : null;
            Edits = new NativeEditService(Env.Workspace, Code);
            Notes = new NotesService(store);
            Tools = new BuildUpdateTools(Env.Workspace, Code, Edits, pdb, Env.Il2Cpp, Env.Il2CppNavigator, new Il2CppNativeNames(Env.Il2Cpp, Env.Il2CppNavigator, Code),
                noteStore: Notes, comparer: new AssemblyComparer(Env.Workspace));
        }

        public async Task<(LoadedNative, NativeCodeIndex)> Load(byte[] image, string name, uint[]? starts)
        {
            var path = Dir.File(name);
            File.WriteAllBytes(path, image);
            var n = Env.Workspace.LoadAny(path).Native!;
            if (starts != null) _starts[n] = starts;
            return (n, await Code.Index(n, null, default));
        }

        public async Task<(LoadedNative, NativeCodeIndex)> LoadReal(string path)
        {
            var n = Env.Workspace.LoadAny(path).Native!;
            var pe = n.Pe!;
            if (Corvus.Native.Pdb.PdbLocator.Locate(pe).Path is { } pdbPath)
            {
                var pdb = Corvus.Native.Pdb.PdbFile.Open(pdbPath, pe.Sections, default);
                _starts[n] = Corvus.Native.Pdb.PdbNaming.Choose(pdb, pe.SizeOfImage, default).Where(x => x.IsFunction).Select(x => x.Rva).ToArray();
            }
            return (n, await Code.Index(n, null, default));
        }

        public void Dispose() { Env.Dispose(); Dir.Dispose(); }
    }

    // Two builds of one x64 image; the new build moves everything by `shift` and:
    //   f1 ReadGlobal: mov eax,[rip+g] ; add eax,0x11 ; ret                         same (g moves too)
    //   f2:            mov eax,1 ; add eax,0x22 ; ret                                 same
    //   f3:            sub rsp,0F8h ; mov eax,7 ; add rsp,0F8h ; ret                   same (a stub site)
    //   f4:            sub rsp,X ; xor edx,edx ; mov ecx,Y ; add rsp,X ; ret           X and Y change
    //   f5 Removed:    xor eax,eax ; L: inc eax ; cmp eax,10 ; jl L ; ret                gone
    //   f6 Duplicated: mov eax,6666h ; xor eax,77h ; ret                               two copies
    // The rest of .text is int3 (a code cave).
    internal const uint F1 = 0x1000, F2 = 0x1020, F3 = 0x1040, F4 = 0x1060, F5 = 0x1090, F6 = 0x10A0, F6b = 0x10C0;
    internal static readonly uint[] OldStarts = [F1, F2, F3, F4, F5, F6];
    internal static uint[] NewStarts(uint s) => [F1 + s, F2 + s, F3 + s, F4 + s, F6 + s, F6b + s];

    internal static byte[] Image(bool newer, uint s)
    {
        var b = new PeBuilder { Is64 = true, Machine = 0x8664, ImageBase = 0x180000000, DllCharacteristics = 0x0160 };
        var code = Enumerable.Repeat((byte)0xCC, 0x200).ToArray();
        void Put(uint rva, params byte[] bytes) => bytes.CopyTo(code, (int)(rva + s - 0x1000));
        uint g = 0x2000 + s;
        Put(F1, [0x8B, 0x05, .. BitConverter.GetBytes((int)g - (int)(F1 + s + 6)), 0x83, 0xC0, 0x11, 0xC3]);
        Put(F2, [0xB8, 0x01, 0, 0, 0, 0x83, 0xC0, 0x22, 0xC3]);
        Put(F3, [0x48, 0x81, 0xEC, 0xF8, 0, 0, 0, 0xB8, 0x07, 0, 0, 0, 0x48, 0x81, 0xC4, 0xF8, 0, 0, 0, 0xC3]);
        byte x = newer ? (byte)0xD8 : (byte)0xE8, y = newer ? (byte)4 : (byte)3;
        Put(F4, [0x48, 0x81, 0xEC, x, 0, 0, 0, 0x31, 0xD2, 0xB9, y, 0, 0, 0, 0x48, 0x81, 0xC4, x, 0, 0, 0, 0xC3]);
        if (!newer) Put(F5, [0x31, 0xC0, 0xFF, 0xC0, 0x83, 0xF8, 0x0A, 0x7C, 0xF9, 0xC3]);
        Put(F6, [0xB8, 0x66, 0x66, 0, 0, 0x83, 0xF0, 0x77, 0xC3]);
        if (newer) Put(F6b, [0xB8, 0x66, 0x66, 0, 0, 0x83, 0xF0, 0x77, 0xC3]);
        var text = b.Add(".text", code, 0x60000020);
        var data = new byte[0x80];
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan((int)(g - 0x2000)), 0xDEAD);
        b.Add(".data", data, 0xC0000040);
        b.EntryPoint = text.Rva;
        return b.Build();
    }

    internal const uint Shift = 0x10;
    internal static string Va(uint rva) => $"0x{0x180000000UL + rva:X}";

    /// <summary>The old build with user names, a comment, a PDB and an Il2Cpp layer, and five patches (two of which cannot carry).</summary>
    private static async Task<(LoadedNative Old, LoadedNative New)> Prepare(Harness h)
    {
        var (oldN, oldIdx) = await h.Load(Image(false, 0), "old.dll", OldStarts);
        var (newN, _) = await h.Load(Image(true, Shift), "new.dll", NewStarts(Shift));
        var ann = h.Code.Annotations(oldN);
        ann.SetMany([(F1, "ReadGlobal"), (F5, "Removed"), (F6, "Duplicated")], [(F1 + 6, "adds the bias")]);
        foreach (var (rva, name) in ann.Names()) oldIdx.SetUserName(rva, name);
        NativeNameLayers.Of(oldN).Set(new NativeNameLayers.Layer(NativeNameSource.Pdb, new Dictionary<uint, string> { [F2] = "pdb_f2" }, new Dictionary<uint, string>(), "old.pdb"), oldIdx);
        NativeNameLayers.Of(oldN).Set(new NativeNameLayers.Layer(NativeNameSource.Il2Cpp, new Dictionary<uint, string> { [F3] = "Game_Thing__Update" },
            new Dictionary<uint, string> { [F3] = "Game.Thing::Update()" }, "Il2Cpp metadata (test)"), oldIdx);

        async Task Apply(Func<NativeCodeIndex, NativeEditService.PatchResult> make)
        {
            var index = await h.Code.Index(oldN, null, default);
            h.Edits.ApplyPatch(oldN, index, make(index), dryRun: false);
        }
        await Apply(i => { var r = X86Assembler.Assemble(NativeArch.X64, 0x180000000UL + F1 + 6, "nop"); return h.Edits.PreparePatch(i, F1 + 6, r.Bytes, false, "patch_asm", RelocationMode.Auto, r.Constants, "nop"); });
        await Apply(i => h.Edits.PreparePatch(i, F2, [0xB8, 0x02, 0, 0, 0], false, "patch_bytes 5 bytes"));
        await Apply(i => h.Edits.PrepareExtendedPatch(i, F3, X86Assembler.Assemble(NativeArch.X64, 0x180000000UL + F3, "mov eax, 2").Bytes, "mov eax, 2", StubMode.Before, "patch_asm (stub)", null));
        await Apply(i => h.Edits.PreparePatch(i, F4 + 9, [0xB9, 0x09, 0, 0, 0], false, "patch_bytes 5 bytes"));
        await Apply(i => h.Edits.PrepareExtendedPatch(i, F4, [0x90], null, StubMode.Before, "patch_bytes 1 bytes (stub)", null));
        return (oldN, newN);
    }

    private static BuildUpdateTools.UpdateItem One(BuildUpdateTools.UpdateReport r, string category, Func<BuildUpdateTools.UpdateItem, bool> where)
    {
        var found = r.Items.Where(i => i.Category == category && where(i)).ToList();
        Assert.True(found.Count == 1, $"{category}: {found.Count} matching items among\n" + string.Join("\n", r.Items.Where(i => i.Category == category)
            .Select(i => $"  {i.Kind} {i.OldAddress} -> {i.NewAddress} {i.Value}: {i.Outcome} {i.Reason} ({i.Detail})")));
        return found[0];
    }

    [Fact]
    public async Task Elf_builds_carry_names_and_patches()
    {
        using var h = new Harness();
        byte[] Elf(byte extra) => new NativeFormats.ElfWriter
        {
            Machine = NativeFormats.ElfWriter.EmX64, Entry = NativeFormats.ElfWriter.TextRva,
            Text = [0xB8, 0x01, 0x00, 0x00, 0x00, 0x83, 0xC0, extra, 0xC3, 0xCC, 0xB8, 0x02, 0x00, 0x00, 0x00, 0xC3],
        }.Build();
        var (oldN, _) = await h.Load(Elf(5), "old.so", null);
        var (newN, _) = await h.Load(Elf(6), "new.so", null);
        h.Code.Annotations(oldN).SetName(NativeFormats.ElfWriter.TextRva, "entry_renamed");
        var index = await h.Code.Index(oldN, null, default);
        h.Edits.ApplyPatch(oldN, index, h.Edits.PreparePatch(index, NativeFormats.ElfWriter.TextRva + 10, [0xB8, 0x03, 0, 0, 0], false, "patch_bytes 5 bytes"), dryRun: false);
        var report = await h.Tools.UpdateToNewBuild(oldN.Id, newN.Id);
        Assert.Contains(report.Items, i => i is { Category: "names", Value: "entry_renamed", Outcome: "would_carry" });
        Assert.Contains(report.Items, i => i is { Category: "patches", Outcome: "would_carry" });
    }

    [Fact]
    public async Task Notes_follow_their_address_to_the_new_build()
    {
        using var h = new Harness();
        var (oldN, _) = await h.Load(Image(false, 0), "old.dll", OldStarts);
        var (newN, _) = await h.Load(Image(true, Shift), "new.dll", NewStarts(Shift));
        NoteAnchor At(uint rva) => new(NoteAnchor.Native, Sha256: oldN.OriginalSha256, Rva: rva, Label: "old.dll@" + Va(rva));
        h.Notes.Record("bias added here", null, null, At(F1 + 6), ["bias"], null, null);
        h.Notes.Record("loop removed later", "question", null, At(F5 + 2), null, null, null);
        h.Notes.Record("whole file packed?", "question", null, new NoteAnchor(NoteAnchor.File, Sha256: oldN.OriginalSha256, Label: "old.dll"), null, null, null);

        var dry = await h.Tools.UpdateToNewBuild(oldN.Id, newN.Id, include: "notes");
        Assert.Equal(("would_carry", Va(F1 + Shift + 6)), One(dry, "notes", i => i.Value == "bias added here") is var b ? (b.Outcome, b.NewAddress) : default);
        Assert.Equal("refused", One(dry, "notes", i => i.Value == "loop removed later").Outcome);
        Assert.Equal(("would_carry", "file"), One(dry, "notes", i => i.Value == "whole file packed?") is var f ? (f.Outcome, f.Reason) : default);
        Assert.Empty(h.Notes.Read(newN.OriginalSha256));

        var run = await h.Tools.UpdateToNewBuild(oldN.Id, newN.Id, dryRun: false, include: "notes");
        Assert.Equal(2, run.Categories.Single(c => c.Category == "notes").Carried);
        var carried = h.Notes.Read(newN.OriginalSha256).Single(n => n.Text == "bias added here");
        Assert.Equal((F1 + Shift + 6, "new.dll@" + Va(F1 + Shift + 6)), (carried.Anchor.Rva!.Value, carried.Anchor.Label));
        Assert.Equal(["bias"], carried.Tags);
        Assert.StartsWith("carried from old.dll@" + Va(F1 + 6), carried.Evidence[^1].Text);

        var again = await h.Tools.UpdateToNewBuild(oldN.Id, newN.Id, dryRun: false, include: "notes");
        Assert.Equal(2, again.Items.Count(i => i is { Category: "notes", Outcome: "already_present" }));
        Assert.Equal(2, h.Notes.Read(newN.OriginalSha256).Count);
    }

    [Fact]
    public async Task DotNet_notes_follow_find_counterpart_to_the_new_build()
    {
        using var h = new Harness();
        LoadedAssembly Build(string folder, string source)
        {
            var path = h.Dir.File(Path.Combine(folder, "Lib.dll"));
            Directory.CreateDirectory(Path.GetDirectoryName(path)!);
            File.WriteAllBytes(path, Roslyn.Release("Lib", source));
            return h.Env.Workspace.Load(path);
        }
        var oldAsm = Build("v1", "namespace N { public class Shop { public int Describe(int x) { return x * 37 + 11; } public int Gone(int y) { return y ^ 0x5A5A; } } }");
        var newAsm = Build("v2", "namespace N { public class Shop { public int Summary(int x) { return x * 37 + 11; } } }");
        NoteAnchor On(string name)
        {
            var m = h.Env.Workspace.Read(() => oldAsm.Module.Find("N.Shop", false).Methods.Single(x => x.Name == name));
            return new NoteAnchor(NoteAnchor.DotNet, Sha256: oldAsm.OriginalSha256, Mvid: oldAsm.Module.Mvid.ToString(), Token: m.MDToken.Raw, Label: $"{oldAsm.Id}:N.Shop::{name}");
        }
        h.Notes.Record("checks the license", null, null, On("Describe"), ["license"], null, null);
        h.Notes.Record("dead code?", "question", null, On("Gone"), null, null, null);
        h.Notes.Record("obfuscated build", null, null, new NoteAnchor(NoteAnchor.File, Sha256: oldAsm.OriginalSha256, Label: oldAsm.Id), null, null, null);

        var dry = await h.Tools.UpdateToNewBuild(oldAsm.Id, newAsm.Id, include: "notes");
        var summaryToken = h.Env.Workspace.Read(() => newAsm.Module.Find("N.Shop", false).Methods.Single(x => x.Name == "Summary").MDToken.Raw);
        Assert.Equal(("would_carry", $"0x{summaryToken:X8}"), One(dry, "notes", i => i.Value == "checks the license") is var d ? (d.Outcome, d.NewAddress) : default);
        Assert.Equal(("refused", "no_counterpart"), One(dry, "notes", i => i.Value == "dead code?") is var g ? (g.Outcome, g.Reason) : default);
        Assert.Equal(("would_carry", "file"), One(dry, "notes", i => i.Value == "obfuscated build") is var f ? (f.Outcome, f.Reason) : default);
        Assert.Equal("reported", dry.Categories.Single(c => c.Category == "dotnet").Status);
        Assert.Equal("not_applicable", (await h.Tools.UpdateToNewBuild(oldAsm.Id, newAsm.Id)).Categories.Single(c => c.Category == "names").Status);

        await h.Tools.UpdateToNewBuild(oldAsm.Id, newAsm.Id, dryRun: false, include: "notes");
        var carried = h.Notes.Read(new NoteAnchor(NoteAnchor.DotNet, Mvid: newAsm.Module.Mvid.ToString()).StoreKey).Single();
        Assert.Equal((summaryToken, $"{newAsm.Id}:N.Shop::Summary(int)"), (carried.Anchor.Token!.Value, carried.Anchor.Label));
        Assert.Equal(["license"], carried.Tags);
        Assert.Single(h.Notes.Read(newAsm.OriginalSha256.ToLowerInvariant()));

        var again = await h.Tools.UpdateToNewBuild(oldAsm.Id, newAsm.Id, dryRun: false, include: "notes");
        Assert.Equal(2, again.Items.Count(i => i.Outcome == "already_present"));
    }

    [Fact]
    public async Task Carries_each_category_previews_then_applies_and_a_rerun_is_idempotent()
    {
        using var h = new Harness();
        var (oldN, newN) = await Prepare(h);

        // ---- dry run: everything reported, nothing changed ----
        var dry = await h.Tools.UpdateToNewBuild(oldN.Id, newN.Id, dryRun: true, limit: 2000);
        output.WriteLine(dry.Summary);
        Assert.True(dry.DryRun);
        Assert.StartsWith("Dry run", dry.Summary);
        Assert.Equal("would_carry", One(dry, "names", i => i.Value == "ReadGlobal").Outcome);
        Assert.Equal(Va(F1 + Shift), One(dry, "names", i => i.Value == "ReadGlobal").NewAddress);
        Assert.Equal("would_carry", One(dry, "names", i => i.Kind == "comment").Outcome);
        Assert.Equal(("refused", "function_not_matched"), One(dry, "names", i => i.Value == "Removed") is var removed ? (removed.Outcome, removed.Reason) : default);
        Assert.Equal("ambiguous", One(dry, "names", i => i.Value == "Duplicated").Outcome);
        Assert.Equal(("not_applicable", "pdb_mismatch"), One(dry, "pdb", _ => true) is var p ? (p.Outcome, p.Reason) : default);
        var il2 = One(dry, "il2cpp_names", i => i.Value == "Game_Thing__Update");
        Assert.Equal(("would_carry", Va(F3 + Shift)), (il2.Outcome, il2.NewAddress));

        Assert.Equal(Va(F1 + Shift + 6), One(dry, "patches", i => i.OldAddress == Va(F1 + 6)).NewAddress);
        Assert.Equal("would_carry", One(dry, "patches", i => i.OldAddress == Va(F2)).Outcome);
        var stub = One(dry, "patches", i => i.OldAddress == Va(F3));
        Assert.True(stub.Outcome == "would_carry", stub.Detail);
        Assert.Contains("stub placed: cave", stub.Detail);
        Assert.Equal(("refused", "displaced_bytes_differ"), One(dry, "patches", i => i.OldAddress == Va(F4)) is var d ? (d.Outcome, d.Reason) : default);
        Assert.Equal(("refused", "original_bytes_differ"), One(dry, "patches", i => i.OldAddress == Va(F4 + 9)) is var o ? (o.Outcome, o.Reason) : default);

        Assert.Equal("still_unique", One(dry, "patterns", i => i.OldAddress == Va(F1)).Reason);
        Assert.Equal("carried", One(dry, "patterns", i => i.OldAddress == Va(F1)).Outcome);
        Assert.Equal("not_found", One(dry, "patterns", i => i.OldAddress == Va(F5)).Reason);
        Assert.Equal("now_ambiguous", One(dry, "patterns", i => i.OldAddress == Va(F6)).Reason);
        Assert.Equal("not_applicable", dry.Categories.Single(c => c.Category == "il2cpp_mapping").Status);
        Assert.Equal("out_of_scope", dry.Categories.Single(c => c.Category == "dotnet").Status);
        var patches = dry.Categories.Single(c => c.Category == "patches");
        Assert.Equal((3, 2), (patches.Carried, patches.Refused));
        Assert.Contains(patches.Reasons, r => r.Reason == "displaced_bytes_differ");
        Assert.False(newN.HasPatches);
        Assert.Equal(0, h.Code.Annotations(newN).NameCount);
        Assert.Null(NativeNameLayers.OfOrNull(newN)?.Get(NativeNameSource.Il2Cpp));

        // paging and filters
        var page = await h.Tools.UpdateToNewBuild(oldN.Id, newN.Id, include: "patches", outcome: "refused", limit: 1);
        Assert.Equal((2, 1, true), (page.Total, page.Items.Count, page.Truncated));
        Assert.Equal("not_included", page.Categories.Single(c => c.Category == "names").Status);

        // ---- apply ----
        var applied = await h.Tools.UpdateToNewBuild(oldN.Id, newN.Id, dryRun: false, limit: 2000);
        output.WriteLine(applied.Summary);
        Assert.Equal(3, applied.Categories.Single(c => c.Category == "patches").Carried);
        Assert.Equal(3, newN.Patches.Patches.Count);
        var img = newN.Image;
        var b = new byte[1];
        img.Read(F1 + Shift + 6, b); Assert.Equal(0x90, b[0]);
        img.Read(F2 + Shift + 1, b); Assert.Equal(0x02, b[0]);
        img.Read(F3 + Shift, b); Assert.True(b[0] is 0xE9 or 0xEB, $"stub site starts with 0x{b[0]:X2}");
        Assert.NotNull(newN.Patches.Patches.Single(x => x.Rva == F3 + Shift).Stub?.NewAssembly);
        Assert.Equal("ReadGlobal", h.Code.Annotations(newN).NameAt(F1 + Shift));
        var carried = NativeNameLayers.Of(newN).Get(NativeNameSource.Il2Cpp);
        Assert.StartsWith("carried by match from", carried!.Origin);
        Assert.Equal("Game_Thing__Update", carried.Names[F3 + Shift]);
        Assert.Contains("confidence", carried.Comments[F3 + Shift]);

        // ---- re-run: nothing applied twice ----
        var again = await h.Tools.UpdateToNewBuild(oldN.Id, newN.Id, dryRun: false, limit: 2000);
        Assert.Equal(3, newN.Patches.Patches.Count);
        Assert.Equal(3, again.Categories.Single(c => c.Category == "patches").AlreadyPresent);
        Assert.Equal("already_present", One(again, "names", i => i.Value == "ReadGlobal").Outcome);
        Assert.Equal("already_present", One(again, "il2cpp_names", i => i.Value == "Game_Thing__Update").Outcome);
    }

    [Fact]
    public async Task Stub_patch_without_its_new_code_and_bad_arguments_are_refused()
    {
        using var h = new Harness();
        var (oldN, oldIdx) = await h.Load(Image(false, 0), "old.dll", OldStarts);
        var (newN, _) = await h.Load(Image(true, Shift), "new.dll", NewStarts(Shift));
        h.Edits.ApplyPatch(oldN, oldIdx, h.Edits.PrepareExtendedPatch(oldIdx, F3, [0x90], null, StubMode.Before, "stub", null), dryRun: false);
        var json = h.Dir.File("set.json");
        await new NativePatchTools(h.Env.Workspace, h.Code, h.Edits).Export(oldN.Id, json, "json");
        // a patch set exported before the stub's new code was recorded
        File.WriteAllText(json, System.Text.RegularExpressions.Regex.Replace(File.ReadAllText(json), "\"newCode\":\\s*\"[0-9A-F]*\"", "\"newCode\": null"));
        var r = await h.Tools.UpdateToNewBuild(oldN.Id, newN.Id, include: "patches", patchSet: json);
        Assert.Equal(("refused", "stub_code_unknown"), One(r, "patches", _ => true) is var e ? (e.Outcome, e.Reason) : default);

        await Assert.ThrowsAsync<ToolError>(() => h.Tools.UpdateToNewBuild(oldN.Id, newN.Id, include: "names,bogus"));
        await Assert.ThrowsAsync<ToolError>(() => h.Tools.UpdateToNewBuild(oldN.Id, oldN.Id));
        await Assert.ThrowsAsync<ToolError>(() => h.Tools.UpdateToNewBuild(oldN.Id, newN.Id, stubPlacement: "heap"));
    }

    [Fact]
    public async Task Il2Cpp_methods_map_by_metadata_identity_and_are_cross_checked()
    {
        using var h = new Harness();
        var (oldN, _) = await h.Load(Image(false, 0), "old.dll", OldStarts);
        var (newN, _) = await h.Load(Image(true, Shift), "new.dll", NewStarts(Shift));
        // the new build's dummy assembly: the fixture with NativeThing.First at F1+Shift (the matched function) and Second at 0x1150
        var module = ModuleDefMD.Load(File.ReadAllBytes(Env.FixturePath));
        var thing = module.Find("Fixture.Native.NativeThing", false);
        void Move(string method, string rva)
        {
            var ca = thing.FindMethod(method).CustomAttributes.First(a => a.AttributeType.Name == "AddressAttribute");
            var i = ca.NamedArguments.ToList().FindIndex(n => n.Name == "RVA");
            ca.NamedArguments[i] =new CANamedArgument(true, module.CorLibTypes.String, "RVA", new CAArgument(module.CorLibTypes.String, new UTF8String(rva)));
        }
        Move("First", $"0x{F1 + Shift:X}");
        Move("Second", "0x1150");
        Directory.CreateDirectory(h.Dir.File("v2"));
        var path = h.Dir.File(Path.Combine("v2", Path.GetFileName(Env.FixturePath)));
        module.Write(path);
        var v2 = h.Env.Workspace.LoadAny(path).Assembly!;

        var r = await h.Tools.UpdateToNewBuild(oldN.Id, newN.Id, include: "il2cpp", oldIl2Cpp: h.Env.Fixture.Id, newIl2Cpp: v2.Id, limit: 2000);
        var map = r.Il2CppMapping!;
        output.WriteLine(r.Summary);
        Assert.True(map.Agree >= 1, r.Summary);
        var first = One(r, "il2cpp_mapping", i => i.Value.Contains("NativeThing::First"));
        Assert.Equal(("carried", "agree", Va(F1 + Shift)), (first.Outcome, first.Reason, first.NewAddress));
        var second = One(r, "il2cpp_mapping", i => i.Value.Contains("NativeThing::Second"));
        Assert.Equal(Va(0x1150), second.NewAddress);
        Assert.Contains(second.Reason, new[] { "metadata_only", "disagree" });
        // the new build has its own metadata: its names are re-applied from it, not carried
        Assert.Equal("reapply_from_metadata", One(r, "il2cpp_names", _ => true).Reason);
    }

    /// <summary>compare_native_images: one view's rows as items, by old address, in both parts and paged by rows.</summary>
    [Fact]
    public async Task Comparison_pages_one_views_rows()
    {
        using var h = new Harness();
        var (oldN, _) = await h.Load(Image(false, 0), "old.dll", OldStarts);
        var (newN, _) = await h.Load(Image(true, Shift), "new.dll", NewStarts(Shift));
        var tools = new NativeDiffTools(h.Env.Workspace, h.Code);
        async Task<(NativeDiffTools.NativeComparison, string)> Compare(string view = "pairs", int offset = 0, int limit = 40) =>
            await BuildToolCalls.Collected<NativeDiffTools.NativeComparison>(() => tools.CompareNativeImages(oldN.Id, newN.Id, view, offset: offset, limit: limit));

        var (pairs, text) = await Compare();
        Assert.Equal("pairs", pairs.View);
        Assert.All(pairs.Items, r => Assert.NotNull(r.Tier));
        Assert.Equal(pairs.Items.Select(r => r.Old).Order(StringComparer.Ordinal), pairs.Items.Select(r => r.Old));
        var f1 = pairs.Items.Single(r => r.Old == Va(F1));
        Assert.Equal((Va(F1 + Shift), true), (f1.New, f1.Identical));
        Assert.Contains($"{Va(F1)} -> {Va(F1 + Shift)} ", text);
        Assert.Contains("identical, moved", text);
        Assert.Contains($"{pairs.Matched} of {pairs.OldFunctions} old functions matched", text);

        var (page, pageText) = await Compare(offset: 1, limit: 1);
        Assert.Equal(pairs.Items[1], Assert.Single(page.Items));
        Assert.Contains("(showing 2-2)", pageText);

        var (unmatched, unmatchedText) = await Compare("unmatched");
        var removed = unmatched.Items.Single(r => r.Old == Va(F5));
        Assert.Equal((null, "below_min_score"), (removed.New, removed.Reason));
        Assert.Contains($"old {Va(F5)} ", unmatchedText);
        Assert.Contains("below_min_score (best ", unmatchedText);
        var (ambiguous, _) = await Compare("ambiguous");
        Assert.All(ambiguous.Items, r => Assert.NotEmpty(r.Candidates!));
    }

    /// <summary>map_address_between_builds: a batch with a bad address succeeds with failed=1; every address bad is an error.</summary>
    [Fact]
    public async Task Address_batch_reports_a_bad_address_per_item()
    {
        using var h = new Harness();
        var (oldN, _) = await h.Load(Image(false, 0), "old.dll", OldStarts);
        var (newN, _) = await h.Load(Image(true, Shift), "new.dll", NewStarts(Shift));
        var tools = new NativeDiffTools(h.Env.Workspace, h.Code);
        var (r, text) = await BuildToolCalls.Collected<NativeDiffTools.AddressMappings>(() =>
            tools.MapAddressBetweenBuilds(oldN.Id, newN.Id, addresses: [Va(F1), "no_such_name", Va(F5)]));
        Assert.Equal(1, r.Failed);
        Assert.Equal([Va(F1), "no_such_name", Va(F5)], r.Results.Select(x => x.Target));
        Assert.Equal((Va(F1 + Shift), "function_start"), (r.Results[0].NewAddress, r.Results[0].Reason));
        Assert.Equal("not_found", r.Results[1].Error!.Code);
        Assert.Null(r.Results[2].NewAddress);
        Assert.StartsWith("3 addresses, 1 failed.", text);
        Assert.Contains("no_such_name: error not_found", text);
        var all = await Assert.ThrowsAsync<ToolError>(() => tools.MapAddressBetweenBuilds(oldN.Id, newN.Id, addresses: ["nope1", "nope2"]));
        Assert.Equal(ErrorCode.NotFound, all.Code);
        await Assert.ThrowsAsync<ToolError>(() => tools.MapAddressBetweenBuilds(oldN.Id, newN.Id, Va(F1), [Va(F2)]));
        Assert.Equal(ErrorCode.InvalidArgument, (await Assert.ThrowsAsync<ToolError>(() =>
            tools.MapAddressBetweenBuilds(oldN.Id, newN.Id, addresses: [.. Enumerable.Repeat(Va(F1), 101)]))).Code);
    }

    /// <summary>diff_function: rows paged as items in both parts; addresses[] gives one summary per function with a per-item error.</summary>
    [Fact]
    public async Task Function_diff_pages_rows_and_batches_summaries()
    {
        using var h = new Harness();
        var (oldN, _) = await h.Load(Image(false, 0), "old.dll", OldStarts);
        var (newN, _) = await h.Load(Image(true, Shift), "new.dll", NewStarts(Shift));
        var tools = new NativeDiffTools(h.Env.Workspace, h.Code);
        var (all, text) = await BuildToolCalls.Collected<NativeDiffTools.FunctionDiffReport>(() => tools.DiffFunction(oldN.Id, newN.Id, Va(F4)));
        Assert.Equal(("asm", 3), (all.View, all.Changed));
        Assert.Equal(all.Total, all.Items.Count);
        Assert.Contains($"~ {Va(F4)} {Va(F4 + Shift)}", text);
        var (page, pageText) = await BuildToolCalls.Collected<NativeDiffTools.FunctionDiffReport>(() => tools.DiffFunction(oldN.Id, newN.Id, Va(F4), offset: 1, limit: 2));
        Assert.Equal(all.Items.Skip(1).Take(2), page.Items);
        Assert.Contains("[More: offset=3]", pageText);

        var (batch, batchText) = await BuildToolCalls.Collected<NativeDiffTools.FunctionDiffReport>(() =>
            tools.DiffFunction(oldN.Id, newN.Id, addresses: [Va(F4), "nope", Va(F5)]));
        Assert.Empty(batch.Items);
        Assert.Equal(3, batch.Functions!.Count);
        Assert.Equal(all.Summary, batch.Functions[0].Summary);
        Assert.Equal("not_found", batch.Functions[1].Error!.Code);
        Assert.StartsWith("function_not_matched", batch.Functions[2].Summary);
        Assert.StartsWith("3 functions, 1 failed (asm):", batchText);
    }

    [Fact]
    public async Task User_types_carry_by_function_match_and_never_replace_the_new_builds()
    {
        using var h = new Harness();
        var (oldN, _) = await h.Load(Image(false, 0), "old.dll", OldStarts);
        var (newN, _) = await h.Load(Image(true, Shift), "new.dll", NewStarts(Shift));
        h.Code.Annotations(oldN).ChangeUserTypes(l => l.WithDeclarations("struct Cfg { int a; };")
            .WithType(F1, "int __fastcall ReadGlobal(void)").WithType(F5, "void Removed(void)").WithType(F2, "int f2(void)")
            .WithLocal(new(F2, "v1", null, "count", "int")).WithStackVar(new(F3, 0x20, "buffer", "char[16]"))
            .WithAnalysis(new(F1, "function", F1 + 0x10, null)).WithOperand(new(F1, 1, "dec", null)).WithEnumMember(new("Mode", "Fast", 2))
            .WithTypeEdit(new("OldCfg", null)).WithTypeEdit(new("Theirs", null)).WithField(new("Cfg", "b", null, "int")));
        h.Code.Annotations(newN).ChangeUserTypes(l => l.WithType(F2 + Shift, "int mine(void)").WithTypeEdit(new("Theirs", "Kept")));
        var tools = new NativeDiffTools(h.Env.Workspace, h.Code);

        var dry = await tools.CarryNames(oldN.Id, newN.Id, true, 5, 0, null, false, false, default, default);
        NativeDiffTools.MigrationEntry Entry(string kind, string? old) => Assert.Single(dry.Items, e => e.Kind == kind && e.OldAddress == old);
        Assert.Equal(("would_set", "copied"), (Entry("declarations", null).Action, Entry("declarations", null).Reason));
        Assert.Equal(("would_set", Va(F1 + Shift)), (Entry("type", Va(F1)).Action, Entry("type", Va(F1)).NewAddress));
        Assert.Equal(("skipped", "function_not_matched"), (Entry("type", Va(F5)).Action, Entry("type", Va(F5)).Reason));
        Assert.Equal(("skipped", "user_type_exists"), (Entry("type", Va(F2)).Action, Entry("type", Va(F2)).Reason));
        Assert.Equal(("would_set", Va(F2 + Shift)), (Entry("local", Va(F2)).Action, Entry("local", Va(F2)).NewAddress));
        Assert.Equal(("would_set", Va(F3 + Shift)), (Entry("stack_var", Va(F3)).Action, Entry("stack_var", Va(F3)).NewAddress));
        Assert.Equal(("would_set", Va(F1 + Shift)), (Entry("analysis", Va(F1)).Action, Entry("analysis", Va(F1)).NewAddress));
        Assert.Equal(("would_set", "copied"), (Entry("enum_member", null).Action, Entry("enum_member", null).Reason));
        Assert.Equal(["copied", "user_type_edit_exists"], dry.Items.Where(e => e.Kind == "type_edit").Select(e => e.Reason));
        Assert.Equal(("would_set", "copied"), (Entry("field", null).Action, Entry("field", null).Reason));
        Assert.Equal("int mine(void)", Assert.Single(h.Code.Annotations(newN).UserTypes.Types).Value);

        var preview = await h.Tools.UpdateToNewBuild(oldN.Id, newN.Id, include: "names", limit: 500);
        Assert.Equal("would_carry", One(preview, "names", i => i.Kind == "local").Outcome);
        Assert.Equal("refused", One(preview, "names", i => i.Kind == "type" && i.OldAddress == Va(F2)).Outcome);

        await tools.CarryNames(oldN.Id, newN.Id, false, 5, 0, null, false, false, default, default);
        var carried = h.Code.Annotations(newN).UserTypes;
        Assert.Equal(["struct Cfg { int a; };"], carried.Declarations);
        Assert.Equal("int __fastcall ReadGlobal(void)", carried.Types[F1 + Shift]);
        Assert.Equal("int mine(void)", carried.Types[F2 + Shift]);
        Assert.Equal(new Corvus.Native.Providers.NativeLocalEdit(F2 + Shift, "v1", null, "count", "int"), Assert.Single(carried.Locals[F2 + Shift]));
        Assert.Equal(new Corvus.Native.Providers.NativeStackVarEdit(F3 + Shift, 0x20, "buffer", "char[16]"), Assert.Single(carried.StackVars[F3 + Shift]));
        // the edit keeps its length at the mapped start
        Assert.Equal(new Corvus.Native.Providers.NativeAnalysisEdit(F1 + Shift, "function", F1 + Shift + 0x10, null), Assert.Single(carried.Analysis));
        Assert.Equal(new Corvus.Native.Providers.NativeOperandEdit(F1 + Shift, 1, "dec", null), Assert.Single(carried.Operands).Value);
        Assert.Equal(2, Assert.Single(carried.EnumMembers).Value.Value);
        Assert.Equal([new("Theirs", "Kept"), new Corvus.Native.Providers.NativeTypeEdit("OldCfg", null)], carried.TypeEdits);
        Assert.Equal(new Corvus.Native.Providers.NativeFieldEdit("Cfg", "b", null, "int"), Assert.Single(carried.Fields));

        var again = await h.Tools.UpdateToNewBuild(oldN.Id, newN.Id, include: "names", dryRun: false, limit: 500);
        Assert.Equal("already_present", One(again, "names", i => i.Kind == "local").Outcome);
        Assert.Equal("already_present", One(again, "names", i => i.Kind == "declarations").Outcome);
    }

    [Fact]
    public void Il2Cpp_build_map_statuses()
    {
        var old = new List<Il2CppBuildMap.Method> { new("a|A", 0x10), new("a|B", 0x20), new("a|C", 0x30), new("a|D", 0x40), new("a|E", 0x50), new("a|E", 0x58) };
        var @new = new List<Il2CppBuildMap.Method> { new("a|A", 0x110), new("a|B", 0x120), new("a|C", 0x130), new("a|E", 0x150), new("a|F", 0x160) };
        var r = Il2CppBuildMap.Map(old, @new, rva => rva switch
        {
            0x10 => new(0x110, 1, "identical_bytes", 1, "function_start"),
            0x20 => new(0x199, 5, "fuzzy", 0.6, "function_start"),
            _ => new(null, null, null, 0, "function_not_matched"),
        }, default);
        Assert.Equal(["agree", "disagree", "metadata_only", "removed", "ambiguous"], r.Entries.Select(e => e.Status));
        Assert.Equal((5, 5, 1), (r.OldMethods, r.NewMethods, r.Added));
    }

}

/// <summary>update_to_new_build on real build pairs (the pairs the native-diff tests discover), with counts and timings.</summary>
[Trait("Speed", "Slow")]
[Collection(SweepCollection.Name)]
public class NativeBuildUpdateRealTests(ITestOutputHelper output)
{
    [WindowsFact]
    public async Task Real_build_pairs_update()
    {
        int pairs = 0;
        foreach (var (oldPath, newPath, label) in NativeDiffRealTests.DiscoverPairs(6))
        {
            using var h = new NativeBuildUpdateTests.Harness();
            LoadedNative oldN, newN;
            NativeCodeIndex oldIdx, newIdx;
            var load = Stopwatch.StartNew();
            try
            {
                (oldN, oldIdx) = await h.LoadReal(oldPath);
                (newN, newIdx) = await h.LoadReal(newPath);
            }
            catch (Exception ex) { output.WriteLine($"{label}: skipped ({ex.GetType().Name})"); continue; }
            if (oldIdx.Support != CodeSupport.Full || newIdx.Support != CodeSupport.Full) continue;
            load.Stop();

            // work on the old build: names on 50 functions, a comment, and two patches
            var funcs = oldIdx.Functions.Where(f => f.End - f.Start >= 16).OrderBy(f => f.Start).ToList();
            var named = funcs.Where((_, i) => i % Math.Max(1, funcs.Count / 50) == 0).Take(50).ToList();
            var ann = h.Code.Annotations(oldN);
            ann.SetMany(named.Select((f, i) => (f.Start, $"user_fn_{i}")), [(named[0].Start, "first named")]);
            foreach (var (rva, name) in ann.Names()) oldIdx.SetUserName(rva, name);
            int patchesMade = 0;
            foreach (var f in named.Skip(1))
            {
                try
                {
                    var asm = X86Assembler.Assemble(oldIdx.Image.Arch, oldIdx.Image.ImageBase + f.Start, "xor eax, eax\nret");
                    h.Edits.ApplyPatch(oldN, oldIdx, h.Edits.PreparePatch(oldIdx, f.Start, asm.Bytes, false, "patch_asm", RelocationMode.Auto, asm.Constants, "xor eax, eax\nret"), false);
                    oldIdx = await h.Code.Index(oldN, null, default);
                    if (++patchesMade == 2) break;
                }
                catch (ToolError) { }
            }

            var sw = Stopwatch.StartNew();
            var dry = await h.Tools.UpdateToNewBuild(oldN.Id, newN.Id, dryRun: true, maxPatterns: 30, limit: 1);
            var dryTime = sw.Elapsed;
            sw.Restart();
            var applied = await h.Tools.UpdateToNewBuild(oldN.Id, newN.Id, dryRun: false, maxPatterns: 30, limit: 1);
            var applyTime = sw.Elapsed;
            sw.Restart();
            var again = await h.Tools.UpdateToNewBuild(oldN.Id, newN.Id, dryRun: false, include: "names,patches", limit: 1);
            var rerunTime = sw.Elapsed;
            pairs++;
            output.WriteLine($"{label}: {dry.FunctionsMatched}/{dry.OldFunctions} matched; load {load.ElapsedMilliseconds} ms, dry run {dryTime.TotalMilliseconds:0} ms, " +
                             $"apply {applyTime.TotalMilliseconds:0} ms, re-run {rerunTime.TotalMilliseconds:0} ms");
            foreach (var c in applied.Categories.Where(c => c.Status is not ("not_included" or "out_of_scope")))
                output.WriteLine($"  {c.Category,-15} {c.Status,-14} considered {c.Considered}, carried {c.Carried}, already {c.AlreadyPresent}, refused {c.Refused}, " +
                                 $"n/a {c.NotApplicable}, ambiguous {c.Ambiguous}; {string.Join(", ", c.Reasons.Take(5).Select(r => $"{r.Reason} {r.Count}"))}");
            output.WriteLine("  " + applied.Summary);

            var names = applied.Categories.Single(c => c.Category == "names");
            Assert.True(names.Considered == 51, $"{names.Considered} name items");
            Assert.Equal(dry.Categories.Single(c => c.Category == "names").Carried, names.Carried);
            var rerunNames = again.Categories.Single(c => c.Category == "names");
            Assert.Equal(names.Carried, rerunNames.AlreadyPresent);
            Assert.Equal(applied.Categories.Single(c => c.Category == "patches").Carried, again.Categories.Single(c => c.Category == "patches").AlreadyPresent);
            if (pairs >= 3) break;
        }
        output.WriteLine($"{pairs} pair(s)");
    }
}
