using System.Diagnostics;
using System.Text.RegularExpressions;
using Corvus.Core;
using Corvus.Native;
using Corvus.Native.Code;
using Corvus.Native.Pdb;
using Corvus.Native.Pe;
using Corvus.Native.Providers;
using Corvus.Native.Providers.Ghidra;
using Corvus.Native.Providers.Ida;
using Corvus.Services;
using Corvus.Tools;
using Xunit.Abstractions;

namespace Corvus.Tests;

/// <summary>
/// The native tools through a real Ghidra (CORVUS_GHIDRA_DIR): engine=ghidra on the code tools and decompile_native, our
/// names and patches pushed into the project, PDB types through Ghidra's loader, and agreement with IDA where both run.
/// </summary>
[Trait("Speed", "Slow")]
public sealed class NativeGhidraEngineTests(ITestOutputHelper output) : IDisposable
{
    private const string Export = "CheckSumMappedFile";
    private readonly TempDir _dir = new();
    private readonly List<IDisposable> _owned = [];

    public void Dispose()
    {
        foreach (var d in _owned) d.Dispose();
        _dir.Dispose();
    }

    private sealed record Rig(AssemblyWorkspace Workspace, NativeCodeService Code, NativeCodeTools Tools, NativeAnalysisTools Analysis, NativeEngineService Engines,
        PdbService Pdbs);

    private Rig Setup(string cache, EngineMode mode = EngineMode.Auto)
    {
        var options = new ServerOptions { TimeoutSeconds = 600, BackgroundIndexing = false, Engine = mode };
        var workspace = new AssemblyWorkspace(options);
        var code = new NativeCodeService(workspace, options, null, new Native.Annotations.AnnotationStore(_dir.File("annotations")));
        var engines = new NativeEngineService(new IdaProviderOptions { CacheRoot = cache }, code, workspace, options);
        _owned.Add(engines);
        _owned.Add(workspace);
        var pager = new OutputPager(options);
        var names = new NativeNamePush(code);
        return new Rig(workspace, code, new NativeCodeTools(workspace, code, pager, null, engines, names),
            new NativeAnalysisTools(workspace, engines, pager, names, code, new NativeTypePush(), new NativeUserTypePush(code)), engines, new PdbService(code));
    }

    private string Sample()
    {
        var dir = Directory.CreateDirectory(_dir.File("input")).FullName;
        var copy = Path.Combine(dir, Path.GetFileName(NativeIdaProviderTests.System64));
        if (!File.Exists(copy)) File.Copy(NativeIdaProviderTests.System64, copy);
        return copy;
    }

    [GhidraFact]
    public async Task Code_tools_and_decompile_native_answer_through_Ghidra_with_our_names_and_patches()
    {
        var rig = Setup(_dir.File("cache"));
        var path = Sample();
        var clock = Stopwatch.StartNew();
        var list = await rig.Tools.ListFunctions(path, limit: 5000, engine: "ghidra");
        output.WriteLine($"list_functions engine=ghidra {clock.Elapsed.TotalSeconds:0.0} s (includes the analysis)\n{string.Join('\n', list.Split('\n').Take(4))}");
        Assert.Contains("Engine: ghidra (engine=ghidra: Ghidra's analysis)", list);
        Assert.Contains(NativeEngineCode.Via("ghidra"), list);
        Assert.Contains($"  {Export}", list); // the export's name in effect wins over Ghidra's
        Assert.Contains("(ghidra", list);
        var native = rig.Workspace.Read(() => rig.Workspace.Natives[0]);

        // auto now takes Ghidra's complete analysis without a request
        var cfg = await rig.Tools.GetCfg(native.Id, Export);
        Assert.Contains("Engine: ghidra (server default auto: Ghidra has analyzed these bytes)", cfg);
        Assert.Contains(NativeEngineCode.Via("ghidra"), cfg);
        var xrefs = await rig.Tools.FindXrefs(native.Id, Export);
        Assert.Contains("Engine: ghidra", xrefs);
        var tree = await rig.Tools.NativeCallTree(native.Id, Export, depth: 1);
        Assert.Contains(NativeEngineCode.Via("ghidra"), tree);

        // a user name reaches Ghidra's listing and pseudocode
        var index = await rig.Code.Index(native, null, default);
        var callee = Regex.Match(tree, @"\n  (\S+)  0x([0-9A-F]+)").Groups[2].Value;
        var calleeRva = (uint)(Convert.ToUInt64(callee, 16) - native.Image.ImageBase);
        new NativeEditService(rig.Workspace, rig.Code).Rename(native, index, calleeRva, "SampleRenamedHelper", false);
        var decompiled = await rig.Analysis.DecompileNative(native.Id, Export, engine: "ghidra");
        output.WriteLine(decompiled);
        Assert.Contains("(ghidra", decompiled.Split('\n').First(l => l.StartsWith("// " + Export, StringComparison.Ordinal)));
        Assert.Contains("SampleRenamedHelper", decompiled);
        Assert.Contains("SampleRenamedHelper", await rig.Tools.NativeCallTree(native.Id, Export, depth: 1));

        // a patch goes into the project; undo reverts it
        var edits = new NativeEditService(rig.Workspace, rig.Code);
        var rva = native.Image.Exports.First(e => e.Name == Export).Rva;
        edits.ApplyPatch(native, index, edits.PreparePatch(index, rva, [0xB8, 0x17, 0x5A, 0x00, 0x00, 0xC3], false, "return 0x5A17"), dryRun: false);
        var patched = await rig.Analysis.DecompileNative(native.Id, Export, engine: "ghidra");
        output.WriteLine(patched);
        Assert.Contains("applied in the database", patched);
        Assert.Contains("0x5a17;", patched);
        Assert.True(rig.Engines.LastPatchSync(native, "ghidra")!.Complete);
        edits.Undo(native, null);
        var session = await rig.Engines.Session(native, "ghidra", null, default);
        Assert.DoesNotContain("0x5a17", (await session.DecompileAsync(rva)).Text);
        Assert.True(rig.Engines.LastPatchSync(native, "ghidra")!.Reverted > 0);
    }

    [GhidraFact]
    public async Task Ghidra_names_form_a_layer_and_its_default_names_are_addresses()
    {
        var rig = Setup(_dir.File("cache"));
        rig.Workspace.LoadAny(Sample());
        var native = rig.Workspace.Read(() => rig.Workspace.Natives[0]);
        var index = await rig.Code.Index(native, null, default);
        var session = (GhidraSession)await rig.Engines.Session(native, "ghidra", null, default);
        Assert.True(await rig.Engines.GhidraNameLayer(native)! > 0);
        var names = await session.ListNamesAsync();
        output.WriteLine($"{names.Count} Ghidra names, e.g. {string.Join(", ", names.Where(n => n.Function).Take(8).Select(n => $"{n.Name} ({(n.Imported ? "imported" : "analysis")})"))}");
        // the ghidra layer holds Ghidra's names below the others; without the PDB layer a name only Ghidra has left resolves through it
        var exports = native.Image.Exports.Select(e => e.Rva).ToHashSet();
        var only = names.First(n => n.Function && !exports.Contains(n.Rva) && index.FunctionAt(n.Rva)?.Start == n.Rva);
        Assert.Equal(only.Name, index.Sourced.NameAt(only.Rva, NativeNameSource.Ghidra));
        NativeNameLayers.Of(native).Remove(NativeNameSource.Pdb, index);
        Assert.Equal((only.Name, NativeNameSource.Ghidra), index.Sourced.NameAt(only.Rva));
        Assert.Equal(only.Rva, index.AddressOfName(only.Name));
        Assert.Contains(only.Name, await rig.Analysis.DecompileNative(native.Id, only.Name, engine: "ghidra"));
        // Ghidra's default names (FUN_<va>, thunk_FUN_<va>) are addresses
        var other = (await session.ListFunctionsAsync()).First(f => f.StartRva != only.Rva && !exports.Contains(f.StartRva) && f.EndRva - f.StartRva > 16);
        var va = native.Image.ImageBase + other.StartRva;
        foreach (var form in new[] { $"FUN_{va:x}", $"thunk_FUN_{va:x}" })
            Assert.Contains($"at {NativeAddress.Va(native.Image, other.StartRva)}", await rig.Analysis.DecompileNative(native.Id, form, engine: "ghidra"));
    }

    [GhidraFact]
    public async Task Pdb_types_reach_the_pseudocode_through_Ghidras_loader()
    {
        if (PdbIdaTypesTests.Build(_dir) is not { } built) { output.WriteLine("no MSVC build tools"); return; }
        // the PDB away from the image: the first analysis has no symbols
        var pdbPath = Path.Combine(Directory.CreateDirectory(_dir.File("symbols")).FullName, "fixture.pdb");
        File.Move(built.Pdb, pdbPath);
        var rig = Setup(_dir.File("cache"), EngineMode.Ghidra);
        var image = PeFile.Open(built.Exe);
        var scoreRva = PdbFile.Open(pdbPath, image.Sections).Symbols.First(s => s.Name == "score_packet" && s.IsFunction).Rva!.Value;
        var before = await rig.Analysis.DecompileNative(built.Exe, $"rva:0x{scoreRva:X}");
        output.WriteLine(before);
        Assert.DoesNotContain("types: PDB", before);
        var native = rig.Workspace.Read(() => rig.Workspace.Natives[0]);
        Assert.NotNull((await rig.Pdbs.Load(native, pdbPath, false, null, false, TimeSpan.FromSeconds(30), 1 << 30, default)).State);
        var clock = Stopwatch.StartNew();
        var after = await EngineMeta.WithPushes(() => rig.Analysis.DecompileNative(native.Id, $"rva:0x{scoreRva:X}"));
        output.WriteLine($"after load_pdb ({clock.Elapsed.TotalSeconds:0.0} s):\n{after}");
        Assert.Contains("types: PDB fixture.pdb via Ghidra's PDB loader: loaded", after);
        Assert.Contains("sequence_number", after);
        Assert.Contains("next_packet", after);
        var session = await rig.Engines.Session(native, null, null, default);
        Assert.Equal("ghidra", session.ProviderId);
        Assert.Equal(NativePdbTypes.RouteGhidra, NativePdbTypes.Current(session)!.Route);
        Assert.Contains("(already in the database)", await EngineMeta.WithPushes(() => rig.Analysis.DecompileNative(native.Id, $"rva:0x{scoreRva:X}")));
    }

    [GhidraFact]
    public async Task Type_tools_edit_Ghidras_project_and_keep_the_edits_for_a_new_one()
    {
        var rig = Setup(_dir.File("cache"));
        var path = Sample();
        var user = new NativeUserTypePush(rig.Code);
        var types = new NativeTypeTools(rig.Workspace, rig.Engines, user, rig.Code, new NativeNamePush(rig.Code), new NativeTypePush());
        Assert.Contains("Declared 1 type(s): SampleHeader", await types.DeclareNativeTypes(path, "struct SampleHeader { unsigned short magic; int size; };", engine: "ghidra"));
        var set = await types.SetNativeType(path, Export, "int __fastcall CheckSumMappedFile(SampleHeader *base, ulonglong length, uint *header, uint *sum)", engine: "ghidra");
        output.WriteLine(set);
        Assert.Contains("SampleHeader * base", set);
        Assert.Contains("struct SampleHeader, 8 bytes", await types.ListNativeTypes(path, name: "SampleHeader", engine: "ghidra"));
        var frame = await types.GetNativeFrame(path, Export, engine: "ghidra", locals: true);
        output.WriteLine(frame);
        Assert.Contains("base  SampleHeader *", frame);
        Assert.Contains("SampleHeader *base", await rig.Analysis.DecompileNative(path, Export, engine: "ghidra"));
        // ida is the only other engine; an unknown one fails before the image is opened
        Assert.Equal(ErrorCode.InvalidArgument, (await Assert.ThrowsAsync<ToolError>(() => types.ListNativeTypes(path, engine: "binja"))).Code);

        // the edits are kept with the image's annotations: a new project (another cache) gets them again
        var again = Setup(_dir.File("cache-new"));
        var decompiled = await again.Analysis.DecompileNative(path, Export, engine: "ghidra");
        Assert.Contains("SampleHeader *base", decompiled);
    }

    /// <summary>Before the built-in index exists, the refs footer reads Ghidra's data references' strings from the image.</summary>
    [Trait("Speed", "Slow")]
    [GhidraFact]
    public async Task Refs_footer_labels_strings_without_the_built_in_index()
    {
        var rig = Setup(_dir.File("cache"));
        // the function that looks up PAL_RegisterModule with dlsym
        var text = await rig.Analysis.DecompileNative(NativeFormats.NativeFixtures.LinuxX64DbgShim, "rva:0x2D51A", engine: "ghidra", refs: true);
        output.WriteLine(text[text.IndexOf("// refs:", StringComparison.Ordinal)..]);
        Assert.Null(rig.Code.Ready(rig.Workspace.Read(() => rig.Workspace.Natives[0])));
        Assert.Matches(@"//   string\s+0x[0-9A-F]+  ""PAL_RegisterModule""", text);
    }

    [Fact]
    public void Image_strings_are_read_as_ascii_or_utf16()
    {
        var data = new byte[0x100];
        System.Text.Encoding.ASCII.GetBytes("hello world\0").CopyTo(data, 0);
        System.Text.Encoding.Unicode.GetBytes("wide\0").CopyTo(data, 0x40);
        System.Text.Encoding.ASCII.GetBytes("ab\0").CopyTo(data, 0x80);
        var image = CodeTestImage.Synthetic(NativeArch.X64, [0xC3], data);
        uint at = CodeTestImage.SyntheticDataRva;
        Assert.Equal("hello world", NativeAnalysisTools.ImageString(image, at));
        Assert.Equal("wide", NativeAnalysisTools.ImageString(image, at + 0x40));
        Assert.Null(NativeAnalysisTools.ImageString(image, at + 0x80));
        Assert.Null(NativeAnalysisTools.ImageString(image, CodeTestImage.SyntheticCodeRva));
    }

    [Trait("Speed", "Slow")]
    [GhidraFact]
    public async Task Call_tree_both_through_Ghidra_agrees_with_the_index()
    {
        var rig = Setup(_dir.File("cache"));
        await NativeIdaEngineTests.CallTreeBoth(rig.Tools, rig.Workspace, rig.Code, "ghidra", output);
    }

    /// <summary>Itanium RTTI classes of an ELF library become vftable and class structs in Ghidra.</summary>
    [Trait("Speed", "Slow")]
    [GhidraFact]
    public async Task Itanium_class_types_reach_the_pseudocode()
    {
        var rig = Setup(_dir.File("cache"));
        var path = NativeFormats.NativeFixtures.LinuxX64Coverage;
        var image = Native.NativeImageLoader.Open(path);
        var cls = Native.Itanium.CppRtti.Analyze(image).Classes.Single(c => c.Name == "vanguard::runtime::CInstrumentationMethod");
        var slot = cls.Vtables.Single(v => v.Offset == 0).SlotRvas.Last(s => s != 0);
        var text = await EngineMeta.WithPushes(() => rig.Analysis.DecompileNative(path, $"rva:0x{slot:X}", engine: "ghidra"));
        output.WriteLine(text);
        Assert.Matches(@"types: pushed .* and \d+ C\+\+ class\(es\) \([1-9]\d* structs, [1-9]\d* vftables", text);
    }

    /// <summary>Where IDA is installed too: function starts and call references of the same image from both engines agree.</summary>
    [GhidraFact]
    public async Task Ghidra_and_IDA_agree_on_function_starts_and_calls()
    {
        using var probe = new IdaProvider(new IdaProviderOptions { CacheRoot = _dir.File("cache") });
        if (!probe.CheckAvailability().IsAvailable) { output.WriteLine("IDA not available"); return; }
        var rig = Setup(_dir.File("cache"));
        var path = Sample();
        var native = rig.Workspace.LoadAny(path).Native!;
        var ida = await rig.Engines.Session(native, "ida", null, default);
        var ghidra = await rig.Engines.Session(native, "ghidra", null, default);
        var idaStarts = (await ida.ListFunctionsAsync()).Where(f => !f.Flags.HasFlag(NativeFunctionFlags.Thunk)).Select(f => f.StartRva).ToHashSet();
        var ghidraStarts = (await ghidra.ListFunctionsAsync()).Where(f => !f.Flags.HasFlag(NativeFunctionFlags.Thunk)).Select(f => f.StartRva).ToHashSet();
        int both = idaStarts.Intersect(ghidraStarts).Count();
        output.WriteLine($"functions: IDA {idaStarts.Count}, Ghidra {ghidraStarts.Count}, both {both}");
        Assert.True(both >= 0.9 * Math.Min(idaStarts.Count, ghidraStarts.Count), $"{both} common starts");

        var rva = native.Image.Exports.First(e => e.Name == Export).Rva;
        // calls to functions both list (IDA also types calls through an import slot as calls; Ghidra reads the slot)
        HashSet<(uint, uint)> Calls(IReadOnlyList<NativeXref> x) =>
            x.Where(c => c.Kind == NativeXrefKind.Call && idaStarts.Contains(c.ToRva) && ghidraStarts.Contains(c.ToRva)).Select(c => (c.FromRva, c.ToRva)).ToHashSet();
        var idaCalls = Calls(await ida.GetXrefsFromAsync(rva, wholeFunction: true));
        var ghidraCalls = Calls(await ghidra.GetXrefsFromAsync(rva, wholeFunction: true));
        output.WriteLine($"{Export} calls: IDA {idaCalls.Count}, Ghidra {ghidraCalls.Count}, both {idaCalls.Intersect(ghidraCalls).Count()}");
        Assert.Equal(idaCalls, ghidraCalls);
        // both sessions stay open on one image; auto prefers IDA's
        Assert.Contains("Engine: ida (server default auto: IDA has analyzed these bytes)", await rig.Tools.GetCfg(native.Id, Export));
        Assert.Contains("Engine: ghidra", await rig.Tools.GetCfg(native.Id, Export, engine: "ghidra"));
    }
}
