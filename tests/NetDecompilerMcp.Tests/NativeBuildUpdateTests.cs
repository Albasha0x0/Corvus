using System.Buffers.Binary;
using System.Diagnostics;
using dnlib.DotNet;
using NetDecompilerMcp.Core;
using NetDecompilerMcp.Native;
using NetDecompilerMcp.Native.Annotations;
using NetDecompilerMcp.Native.Code;
using NetDecompilerMcp.Native.Patching;
using NetDecompilerMcp.Services;
using NetDecompilerMcp.Tools;
using Xunit.Abstractions;

namespace NetDecompilerMcp.Tests;

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
            var store = new AnnotationStore(Dir.File("ann"));
            Code = new NativeCodeService(Env.Workspace, Env.Options, null, store);
            var pdb = new PdbService(Code);
            Code.SymbolStarts = (n, _) => _starts.TryGetValue(n, out var s) ? s : null;
            Edits = new NativeEditService(Env.Workspace, Code);
            Notes = new NotesService(store);
            Tools = new BuildUpdateTools(Env.Workspace, Code, Edits, pdb, Env.Il2Cpp, Env.Il2CppNavigator, new Il2CppNativeNames(Env.Il2Cpp, Env.Il2CppNavigator, Code),
                noteStore: Notes);
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
            if (NetDecompilerMcp.Native.Pdb.PdbLocator.Locate(pe).Path is { } pdbPath)
            {
                var pdb = NetDecompilerMcp.Native.Pdb.PdbFile.Open(pdbPath, pe.Sections, default);
                _starts[n] = NetDecompilerMcp.Native.Pdb.PdbNaming.Choose(pdb, pe.SizeOfImage, default).Where(x => x.IsFunction).Select(x => x.Rva).ToArray();
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
    private const uint F1 = 0x1000, F2 = 0x1020, F3 = 0x1040, F4 = 0x1060, F5 = 0x1090, F6 = 0x10A0, F6b = 0x10C0;
    private static readonly uint[] OldStarts = [F1, F2, F3, F4, F5, F6];
    private static uint[] NewStarts(uint s) => [F1 + s, F2 + s, F3 + s, F4 + s, F6 + s, F6b + s];

    private static byte[] Image(bool newer, uint s)
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

    private const uint Shift = 0x10;
    private static string Va(uint rva) => $"0x{0x180000000UL + rva:X}";

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
        Assert.StartsWith("carried from old.dll@" + Va(F1 + 6), carried.Evidence[^1]);

        var again = await h.Tools.UpdateToNewBuild(oldN.Id, newN.Id, dryRun: false, include: "notes");
        Assert.Equal(2, again.Items.Count(i => i is { Category: "notes", Outcome: "already_present" }));
        Assert.Equal(2, h.Notes.Read(newN.OriginalSha256).Count);
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
        await new NativePatchTools(h.Env.Workspace, h.Code, h.Edits).ExportNativePatches(oldN.Id, json, "json");
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

    [Fact]
    public async Task User_types_carry_by_function_match_and_never_replace_the_new_builds()
    {
        using var h = new Harness();
        var (oldN, _) = await h.Load(Image(false, 0), "old.dll", OldStarts);
        var (newN, _) = await h.Load(Image(true, Shift), "new.dll", NewStarts(Shift));
        h.Code.Annotations(oldN).ChangeUserTypes(l => l.WithDeclarations("struct Cfg { int a; };")
            .WithType(F1, "int __fastcall ReadGlobal(void)").WithType(F5, "void Removed(void)").WithType(F2, "int f2(void)")
            .WithLocal(new(F2, "v1", null, "count", "int")).WithStackVar(new(F3, 0x20, "buffer", "char[16]"))
            .WithAnalysis(new(F1, "function", F1 + 0x10, null)));
        h.Code.Annotations(newN).ChangeUserTypes(l => l.WithType(F2 + Shift, "int mine(void)"));
        var tools = new NativeDiffTools(h.Env.Workspace, h.Code);

        var dry = await tools.MigrateNativeNames(oldN.Id, newN.Id, dryRun: true, limit: 500);
        NativeDiffTools.MigrationEntry Entry(string kind, string? old) => Assert.Single(dry.Entries, e => e.Kind == kind && e.OldAddress == old);
        Assert.Equal(("would_set", "copied"), (Entry("declarations", null).Action, Entry("declarations", null).Reason));
        Assert.Equal(("would_set", Va(F1 + Shift)), (Entry("type", Va(F1)).Action, Entry("type", Va(F1)).NewAddress));
        Assert.Equal(("skipped", "function_not_matched"), (Entry("type", Va(F5)).Action, Entry("type", Va(F5)).Reason));
        Assert.Equal(("skipped", "user_type_exists"), (Entry("type", Va(F2)).Action, Entry("type", Va(F2)).Reason));
        Assert.Equal(("would_set", Va(F2 + Shift)), (Entry("local", Va(F2)).Action, Entry("local", Va(F2)).NewAddress));
        Assert.Equal(("would_set", Va(F3 + Shift)), (Entry("stack_var", Va(F3)).Action, Entry("stack_var", Va(F3)).NewAddress));
        Assert.Equal(("would_set", Va(F1 + Shift)), (Entry("analysis", Va(F1)).Action, Entry("analysis", Va(F1)).NewAddress));
        Assert.Equal("int mine(void)", Assert.Single(h.Code.Annotations(newN).UserTypes.Types).Value);

        var preview = await h.Tools.UpdateToNewBuild(oldN.Id, newN.Id, include: "names", limit: 500);
        Assert.Equal("would_carry", One(preview, "names", i => i.Kind == "local").Outcome);
        Assert.Equal("refused", One(preview, "names", i => i.Kind == "type" && i.OldAddress == Va(F2)).Outcome);

        await tools.MigrateNativeNames(oldN.Id, newN.Id, dryRun: false);
        var carried = h.Code.Annotations(newN).UserTypes;
        Assert.Equal(["struct Cfg { int a; };"], carried.Declarations);
        Assert.Equal("int __fastcall ReadGlobal(void)", carried.Types[F1 + Shift]);
        Assert.Equal("int mine(void)", carried.Types[F2 + Shift]);
        Assert.Equal(new NetDecompilerMcp.Native.Providers.NativeLocalEdit(F2 + Shift, "v1", null, "count", "int"), Assert.Single(carried.Locals[F2 + Shift]));
        Assert.Equal(new NetDecompilerMcp.Native.Providers.NativeStackVarEdit(F3 + Shift, 0x20, "buffer", "char[16]"), Assert.Single(carried.StackVars[F3 + Shift]));
        // the edit keeps its length at the mapped start
        Assert.Equal(new NetDecompilerMcp.Native.Providers.NativeAnalysisEdit(F1 + Shift, "function", F1 + Shift + 0x10, null), Assert.Single(carried.Analysis));

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
