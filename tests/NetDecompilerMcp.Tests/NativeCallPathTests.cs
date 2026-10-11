using Iced.Intel;
using NetDecompilerMcp.Core;
using NetDecompilerMcp.Native.Annotations;
using NetDecompilerMcp.Services;
using NetDecompilerMcp.Tools;

namespace NetDecompilerMcp.Tests;

/// <summary>find_call_paths to native code: bounded backward search, ranked chains, roots, imports between images, managed entries.</summary>
public sealed class NativeCallPathTests : IDisposable
{
    private readonly TempDir _dir = new();

    public void Dispose() => _dir.Dispose();

    private const ulong Base = 0x180000000;

    /// <summary>
    /// lattice.dll: Top (entry, export) calls A1 and B1; Ai and Bi call A(i+1) and B(i+1); A6 and B6 call Goal (64 chains of 7
    /// calls). Short (export) calls Goal directly; Lonely (no callers, not exported) calls Goal; Mid calls Goal and is called by Short.
    /// </summary>
    private (string Path, Dictionary<string, uint> Rva) Lattice()
    {
        var a = new Assembler(64);
        var labels = new Dictionary<string, Label>();
        Label L(string name) => labels.TryGetValue(name, out var l) ? l : labels[name] = a.CreateLabel(name);
        void Function(string name, params string[] callees)
        {
            var l = L(name);
            a.Label(ref l);
            labels[name] = l;
            foreach (var c in callees) a.call(L(c));
            a.ret();
            for (int i = 0; i < 12; i++) a.int3();
        }
        Function("Top", "A1", "B1");
        for (int i = 1; i <= 6; i++)
        {
            var next = i < 6 ? new[] { $"A{i + 1}", $"B{i + 1}" } : ["Goal"];
            Function($"A{i}", next);
            Function($"B{i}", next);
        }
        Function("Short", "Goal", "Mid");
        Function("Mid", "Goal");
        Function("Lonely", "Goal");
        Function("Goal");
        var stream = new MemoryStream();
        var result = a.Assemble(new StreamCodeWriter(stream), Base + LinkedImages.Text, BlockEncoderOptions.ReturnNewInstructionOffsets);
        int Offset(string name) => (int)(result.GetLabelRIP(labels[name]) - Base - LinkedImages.Text);
        var code = stream.ToArray();
        var path = _dir.File("lattice.dll");
        File.WriteAllBytes(path, LinkedImages.Build("lattice.dll", [("Top", Offset("Top")), ("Short", Offset("Short")), ("Goal", Offset("Goal"))], [], _ => code));
        return (path, labels.Keys.ToDictionary(k => k, k => LinkedImages.Text + (uint)Offset(k)));
    }

    private static (AssemblyWorkspace Workspace, CallGraphTools Tools) Rig(TempDir dir, params string[] files)
    {
        var options = new ServerOptions { BackgroundIndexing = false };
        var ws = new AssemblyWorkspace(options);
        foreach (var f in files) ws.LoadAny(f);
        var code = new NativeCodeService(ws, options, null, new AnnotationStore(dir.File("ann")));
        var link = new NativeLinkService(ws, code);
        return (ws, new CallGraphTools(ws, new CallGraphService(ws), new OutputPager(options), link, code));
    }

    [Fact]
    public async Task Shortest_chains_come_first_from_roots_and_the_enumeration_is_bounded()
    {
        var (path, rva) = Lattice();
        var (ws, tools) = Rig(_dir, path);
        using var _ = ws;
        var text = await tools.FindCallPaths("native:lattice.dll!Goal", maxPaths: 10);
        NativeLinkTests.Has(text, "10 paths to native lattice.dll!Goal ([lattice.dll] Goal at ");
        // one call: from the export Short and from the uncalled Lonely; Mid is reached through Short, not a root
        var first = text.Split("\n#")[1..3];
        Assert.Contains("(1 native call; root: export)", first[0]);
        Assert.Contains("[lattice.dll] Short at", first[0]);
        Assert.Contains("(1 native call; root: no callers)", first[1]);
        Assert.Contains("  -> [lattice.dll] Goal at 0x18000", first[0]);
        Assert.Contains("(call at 0x18000", first[0]);
        Assert.DoesNotContain("root: no callers)\n  [lattice.dll] Mid", text);
        // the lattice has 64 chains of 7 calls from the entry point: 8 fit, and the cut is said
        Assert.Equal(8, text.Split("(7 native calls; root: entry point)").Length - 1);
        NativeLinkTests.Has(text, "[More paths exist: raise maxPaths (now 10) or give from]");
    }

    [Fact]
    public async Task Native_from_and_depth_limits_report_what_is_left()
    {
        var (path, rva) = Lattice();
        var (ws, tools) = Rig(_dir, path);
        using var _ = ws;
        var from = await tools.FindCallPaths("native:lattice.dll!Goal", from: $"native:lattice.dll!rva:0x{rva["A5"]:X}", maxPaths: 50);
        NativeLinkTests.Has(from, "2 paths to native lattice.dll!Goal");
        NativeLinkTests.Has(from, $"from lattice.dll!rva:0x{rva["A5"]:X}");
        NativeLinkTests.Has(from, "(2 native calls; root: from)");
        var shallow = await tools.FindCallPaths("native:lattice.dll!Goal", from: "native:lattice.dll!Top", maxDepth: 3);
        NativeLinkTests.Has(shallow, "none within 3 calls: ");
        NativeLinkTests.Has(shallow, "still have callers (raise maxDepth)");
        var e = await Assert.ThrowsAsync<ToolError>(() => tools.FindCallPaths("App::Main", from: "native:lattice.dll!Top"));
        Assert.Equal(ErrorCode.Unsupported, e.Code);
    }

    [Fact]
    public async Task Chains_cross_images_through_bound_imports()
    {
        var (app, prov, deep) = LinkedImages.Trio(_dir);
        var (ws, tools) = Rig(_dir, app, prov, deep);
        using var _ = ws;
        var text = await tools.FindCallPaths("native:deeplib.dll!Deep");
        // provlib!Plain calls deeplib!Deep through its import; app!Main calls provlib!Plain through its own
        NativeLinkTests.Has(text, "[app.dll] Main at 0x180001000  (entry point)");
        NativeLinkTests.Has(text, "-> [provlib.dll] Plain at 0x180001010  (import at 0x180001006)");
        NativeLinkTests.Has(text, "-> [deeplib.dll] Deep at 0x180001000  (import at 0x180001010)");
        NativeLinkTests.Has(text, "root: export");
    }

    [Fact]
    public async Task Calls_through_a_pointer_in_data_are_found_without_an_image_scan()
    {
        var path = _dir.File("ptrs.dll");
        File.WriteAllBytes(path, LinkedImages.Build("ptrs.dll", [("Run", 0), ("Cb", 0x20)], [],
            slots => new LinkedImages.Code(slots).CallImport("table").Ret().Pad(0x20).Ret().ToArray(),
            (blob, relocations) =>
            {
                blob.Align(8);
                uint table = blob.U64(Base + LinkedImages.Text + 0x20);
                relocations.Add(table);
                return new Dictionary<string, uint> { ["table"] = table };
            }));
        var (ws, tools) = Rig(_dir, path);
        using var _ = ws;
        var text = await tools.FindCallPaths("native:ptrs.dll!Cb");
        NativeLinkTests.Has(text, "[ptrs.dll] Run at 0x180001000  (entry point)");
        NativeLinkTests.Has(text, "-> [ptrs.dll] Cb at 0x180001020  (pointer at 0x180001000)");
        Assert.DoesNotContain("resolve_call_targets", text);
    }

    [Fact]
    public async Task An_open_engine_sessions_call_references_are_edges()
    {
        var path = _dir.File("eng.dll");
        File.WriteAllBytes(path, LinkedImages.Build("eng.dll", [("Hidden", 0), ("Goal", 0x20)], [],
            slots => new LinkedImages.Code(slots).Raw(0xFF, 0xD0).Ret().Pad(0x20).Ret().ToArray()));
        var options = new ServerOptions { BackgroundIndexing = false };
        var ws = new AssemblyWorkspace(options);
        using var _ = ws;
        var native = ws.LoadAny(path).Native!;
        var code = new NativeCodeService(ws, options, null, new AnnotationStore(_dir.File("ann")));
        var engine = new ScriptedEngine();
        engine.Add(LinkedImages.Text, "Hidden");
        engine.Add(LinkedImages.Text + 0x20, "Goal");
        engine.Xrefs.Add(new NetDecompilerMcp.Native.Providers.NativeXref(LinkedImages.Text, LinkedImages.Text + 0x20, NetDecompilerMcp.Native.Providers.NativeXrefKind.Call, LinkedImages.Text));
        using var engines = new NativeEngineService([engine], _dir.File("cache"), null, ws, options);
        await engines.Session(native, NetDecompilerMcp.Native.Providers.Ida.IdaProvider.ProviderId, null, default);
        var tools = new CallGraphTools(ws, new CallGraphService(ws), new OutputPager(options), new NativeLinkService(ws, code), code, engines);
        var text = await tools.FindCallPaths("native:eng.dll!Goal");
        NativeLinkTests.Has(text, "-> [eng.dll] Goal at 0x180001020  (engine at 0x180001000)");
    }

    [WindowsFact("P/Invoke DLL lookup is done on Windows hosts only.")]
    public async Task Managed_methods_reach_native_code_through_PInvoke()
    {
        var (app, prov, deep) = LinkedImages.Trio(_dir);
        var path = _dir.File("Managed.dll");
        File.WriteAllBytes(path, Roslyn.Compile("Managed", """
            using System.Runtime.InteropServices;
            public static class Interop { [DllImport("provlib.dll")] public static extern void Plain(); }
            public static class App { public static void Run() => Interop.Plain(); public static void Main() => Run(); }
            """, new Microsoft.CodeAnalysis.CSharp.CSharpCompilationOptions(Microsoft.CodeAnalysis.OutputKind.DynamicallyLinkedLibrary)));
        var (ws, tools) = Rig(_dir, path, app, prov, deep);
        using var _ = ws;
        var text = await tools.FindCallPaths("native:deeplib.dll!Deep", from: "App::Main");
        NativeLinkTests.Has(text, "after 3 managed methods and P/Invoke; root: managed)");
        NativeLinkTests.Has(text, "      -> Interop::Plain()");
        NativeLinkTests.Has(text, "        -> native: provlib.dll!Plain at 0x180001010 [provlib.dll]");
        NativeLinkTests.Has(text, "        -> [provlib.dll] Plain at 0x180001010");
        NativeLinkTests.Has(text, "          -> [deeplib.dll] Deep at 0x180001000  (import at 0x180001010)");
    }
}
