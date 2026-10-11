using System.Diagnostics;
using System.Text.RegularExpressions;
using NetDecompilerMcp.Core;
using NetDecompilerMcp.Native.Pdb;
using NetDecompilerMcp.Native.Pe;
using NetDecompilerMcp.Native.Providers;
using NetDecompilerMcp.Native.Providers.Ghidra;
using NetDecompilerMcp.Native.Providers.Ida;
using NetDecompilerMcp.Services;
using NetDecompilerMcp.Tools;
using Xunit.Abstractions;

namespace NetDecompilerMcp.Tests;

/// <summary>
/// The native tools through a real Ghidra (NDM_GHIDRA_DIR): engine=ghidra on the code tools and decompile_native, our
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
            new NativeAnalysisTools(workspace, engines, pager, names, code, new NativeTypePush()), engines, new PdbService(code));
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
        Assert.Contains("Engine: ghidra (server default auto: Ghidra's analysis of this image is complete in this session)", cfg);
        Assert.Contains(NativeEngineCode.Via("ghidra"), cfg);
        var xrefs = await rig.Tools.FindXrefs(native.Id, Export);
        Assert.Contains("Engine: ghidra", xrefs);
        var tree = await rig.Tools.NativeCallTree(native.Id, Export, depth: 1);
        Assert.Contains(NativeEngineCode.Via("ghidra"), tree);

        // a user name reaches Ghidra's listing and pseudocode
        var index = await rig.Code.Index(native, null, default);
        var callee = Regex.Match(tree, @"\n  (\S+)  0x([0-9A-F]+)").Groups[2].Value;
        var calleeRva = (uint)(Convert.ToUInt64(callee, 16) - native.Image.ImageBase);
        new NativeEditService(rig.Workspace, rig.Code).Rename(native, index, calleeRva, "NdmRenamedHelper", false);
        var decompiled = await rig.Analysis.DecompileNative(native.Id, Export, engine: "ghidra");
        output.WriteLine(decompiled);
        Assert.Contains("(ghidra, ", decompiled.Split('\n').First(l => l.StartsWith("// " + Export, StringComparison.Ordinal)));
        Assert.Contains("NdmRenamedHelper", decompiled);
        Assert.Contains("NdmRenamedHelper", await rig.Tools.NativeCallTree(native.Id, Export, depth: 1));

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
        var after = await rig.Analysis.DecompileNative(native.Id, $"rva:0x{scoreRva:X}");
        output.WriteLine($"after load_pdb ({clock.Elapsed.TotalSeconds:0.0} s):\n{after}");
        Assert.Contains("types: PDB fixture.pdb via Ghidra's PDB loader: loaded", after);
        Assert.Contains("sequence_number", after);
        Assert.Contains("next_packet", after);
        var session = await rig.Engines.Session(native, null, null, default);
        Assert.Equal("ghidra", session.ProviderId);
        Assert.Equal(NativePdbTypes.RouteGhidra, NativePdbTypes.Current(session)!.Route);
        Assert.Contains("(already in the database)", (await rig.Analysis.DecompileNative(native.Id, $"rva:0x{scoreRva:X}")).Split('\n')[0]);
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
        Assert.Contains("Engine: ida (server default auto: IDA's analysis", await rig.Tools.GetCfg(native.Id, Export));
        Assert.Contains("Engine: ghidra", await rig.Tools.GetCfg(native.Id, Export, engine: "ghidra"));
    }
}
