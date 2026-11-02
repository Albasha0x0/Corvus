using System.Text.RegularExpressions;
using Corvus.Core;
using Corvus.Native.Annotations;
using Corvus.Native.Providers;
using Corvus.Services;
using Corvus.Tools;

namespace Corvus.Tests;

/// <summary>The engine read tools answer the same after a restart.</summary>
public sealed partial class RestartStateEngineTests : IDisposable
{
    private readonly TempDir _dir = new();
    private readonly List<IDisposable> _owned = [];

    public void Dispose()
    {
        foreach (var d in _owned) d.Dispose();
        _dir.Dispose();
    }

    [GeneratedRegex(@"\b\d+(\.\d+)? ?(ms|s)\b|""elapsedMs"":\d+")]
    private static partial Regex Timing();

    private sealed record Process(NativeAnalysisTools Decompile, NativeSearchDecompiledTools Search, NativeEngineStatusTools Status, NativeEditTools Edit,
        ScriptedEngine Engine, NativeCodeService Code, LoadedNative Native);

    /// <summary>One server process on shared annotation and cache folders.</summary>
    private async Task<Process> Start()
    {
        var options = new ServerOptions { BackgroundIndexing = false };
        var workspace = new AssemblyWorkspace(options);
        var code = new NativeCodeService(workspace, options, null, new AnnotationStore(_dir.File("annotations")));
        var engine = new ScriptedEngine { NamesShowInText = true };
        engine.Add(0x1000, "target", "int target(void)", "{ return 1; }");
        engine.Add(0x1040, "caller", "int caller(void)", "{ return target(); }");
        var engines = new NativeEngineService([engine], _dir.File("cache"), code, workspace, options);
        _owned.Add(engines);
        _owned.Add(workspace);
        var native = workspace.LoadAny(McpProtocolTests.NativeSample(_dir)).Native!;
        await code.Index(native, null, default);
        var pager = new OutputPager(options);
        var names = new NativeNamePush(code);
        return new(new NativeAnalysisTools(workspace, engines, pager, names), new NativeSearchDecompiledTools(workspace, engines, pager, code, names),
            new NativeEngineStatusTools(workspace, engines), new NativeEditTools(workspace, code, new NativeEditService(workspace, code), null, engines, names),
            engine, code, native);
    }

    private static async Task<Dictionary<string, string>> Reads(Process p) => new(StringComparer.Ordinal)
    {
        ["decompile_native"] = Timing().Replace(await p.Decompile.DecompileNative(p.Native.Id, "rva:0x1000"), "~"),
        ["search_decompiled"] = Timing().Replace(await p.Search.SearchDecompiled(p.Native.Id, "return"), "~"),
        ["get_engine_status"] = Timing().Replace(await p.Status.GetEngineStatus(p.Native.Id), "~"),
    };

    // The second process never repeats the rename.
    [Fact]
    public async Task Engine_reads_answer_the_same_after_the_saved_names_reach_a_new_session()
    {
        var a = await Start();
        await a.Edit.RenameNative(a.Native.Id, "rva:0x1000", "RenamedTarget", dryRun: false);
        var first = await Reads(a);
        var pushed = Assert.Single(a.Engine.NamePushes);
        Assert.Contains(pushed.Items, i => i.Name == "RenamedTarget");

        var b = await Start();
        var second = await Reads(b);
        var differing = first.Where(p => p.Value != second[p.Key]).Select(p => p.Key).ToList();
        Assert.True(differing.Count == 0, "answers differ after a restart: "
            + string.Join("; ", differing.Select(t => $"{t}: [{first[t]}] vs [{second[t]}]")));
        Assert.Contains("RenamedTarget", second["decompile_native"]);
        Assert.All(first, p => Assert.False(string.IsNullOrWhiteSpace(p.Value), p.Key));
        var restored = Assert.Single(b.Engine.NamePushes);
        Assert.Equal(pushed.Stamp, restored.Stamp);
        Assert.Equal(pushed.Items.Select(i => (i.Rva, i.Name)), restored.Items.Select(i => (i.Rva, i.Name)));
    }
}
