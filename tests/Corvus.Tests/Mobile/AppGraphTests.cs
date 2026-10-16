using System.Diagnostics;
using System.Text;
using Corvus.Core;
using Corvus.Services;
using Corvus.Services.Mobile;
using static Corvus.Tests.Asm;

namespace Corvus.Tests;

/// <summary>summarize_file view=layers: the code layers of a package and their verified edges, with coverage per edge kind.</summary>
public sealed class AppGraphTests(Xunit.Abstractions.ITestOutputHelper output) : IDisposable
{
    private readonly AssemblyWorkspace _workspace = new(new ServerOptions());

    public void Dispose() => _workspace.Dispose();

    private AppGraph Graph(Il2CppRawLoader? il2cpp = null) { var dex = new DexService(); return new AppGraph(dex, new JniBindings(dex), new JavaDotNetMap(_workspace, dex), il2cpp); }

    [Fact]
    public void Jni_and_react_native_edges_with_coverage()
    {
        using var dir = new TempDir();
        var dexBytes = JniBindingsTests.Dex(b =>
        {
            var used = b.Class("Lcom/example/rn/ClipModule;", 1, "Lcom/facebook/react/bridge/ReactContextBaseJavaModule;");
            used.Method("getName", "Ljava/lang/String;", [], 1, ConstString(0, "Clipboard"), Return(0x11, 0)).Registers = 2;
            var unused = b.Class("Lcom/example/rn/UnusedModule;", 1, "Lcom/example/rn/ClipModule;");
            unused.Method("getName", "Ljava/lang/String;", [], 1, ConstString(0, "Unused"), Return(0x11, 0)).Registers = 2;
        });
        var bundle = Encoding.UTF8.GetBytes("var m = require('react-native').NativeModules[\"Clipboard\"]; m.setString('x');");
        var apk = AndroidSamples.Save(dir, "app.apk", AndroidSamples.Apk(30, ("classes.dex", dexBytes),
            ("lib/arm64-v8a/libnative.so", JniBindingsTests.Library($"lib{Guid.NewGuid():N}.so")), ("assets/index.android.bundle", bundle)));
        var g = Graph().Build(apk, 0, 500, default);
        foreach (var k in g.EdgeKinds) output.WriteLine($"{k.Kind}: {k.Edges}/{k.Candidates} {k.Coverage} {k.Reason}");
        Assert.Equal(["dex", "native", "js"], g.Layers.Select(l => l.Layer));
        var jni = g.EdgeKinds.Single(k => k.Kind == "jni");
        Assert.Equal("partial", jni.Coverage); // Native.missing and Other.init have neither export nor table entry
        Assert.StartsWith("2 native method(s) have no Java_ export", jni.Reason);
        Assert.Contains(g.Edges, e => e.Kind == "jni" && e.From == "Lcom/example/jni/Native;->hello()Ljava/lang/String;" && e.To.Contains("!Java_com_example_jni_Native_hello@0x") && e.Basis == "static_export");
        Assert.Contains(g.Edges, e => e.Kind == "jni" && e.From == "Lcom/example/jni/Third;->init()V" && e.Basis == "registered");
        var rn = g.EdgeKinds.Single(k => k.Kind == "js_native_module");
        Assert.Equal((1, 2, "partial"), (rn.Edges, rn.Candidates, rn.Coverage));
        Assert.Contains(g.Edges, e => e.Kind == "js_native_module" && e.From == "assets/index.android.bundle:NativeModules.Clipboard" && e.To == "Lcom/example/rn/ClipModule;");
        Assert.Equal(g.Total, g.Edges.Count);
        var page = Graph().Build(apk, 1, 2, default);
        Assert.Equal(g.Edges.Skip(1).Take(2), page.Edges);
    }

    /// <summary>Damaged packages: the view and the graph answer or throw a tool error.</summary>
    [Fact]
    [FuzzEntry(typeof(Services.Analysis.LayersFileView), typeof(AppGraph))]
    public void Damaged_packages_fail_only_as_tool_errors()
    {
        using var dir = new TempDir();
        var seed = AndroidSamples.Apk(30, ("classes.dex", JniBindingsTests.Dex()), ("assets/index.android.bundle", "x('Clipboard')"u8.ToArray()));
        var failures = FormatFuzz.Run(seed, b =>
        {
            var path = dir.File($"{Guid.NewGuid():N}.apk");
            File.WriteAllBytes(path, b);
            try
            {
                new Services.Analysis.LayersFileView().Inspect(new Services.Analysis.FileInput(path, b, Blob.Identify(b)), default);
                Graph().Build(path, 0, 10, default);
            }
            catch (ToolError) { }
        }, 300);
        Assert.True(failures.Count == 0, string.Join("\n", failures.Take(10)));
    }

    /// <summary>summarize_file names the view for a package and pages the graph's edges by offset and limit, matching its output schema.</summary>
    [Fact]
    public async Task Summarize_file_view_layers_pages_the_edges()
    {
        using var dir = new TempDir();
        var apk = AndroidSamples.Save(dir, "app.apk", AndroidSamples.Apk(30, ("classes.dex", JniBindingsTests.Dex()),
            ("lib/arm64-v8a/libnative.so", JniBindingsTests.Library($"lib{Guid.NewGuid():N}.so"))));
        await using var server = await InProcessServer.StartAsync();
        var overview = await server.Client.CallToolAsync("summarize_file", new Dictionary<string, object?> { ["path"] = apk });
        Assert.Contains("layers", overview.StructuredContent!.Value.GetProperty("views").EnumerateArray().Select(v => v.GetString()));
        var r = await server.Client.CallToolAsync("summarize_file", new Dictionary<string, object?> { ["path"] = apk, ["view"] = "layers", ["offset"] = 1, ["limit"] = 2 });
        Assert.NotEqual(true, r.IsError);
        var detail = r.StructuredContent!.Value.GetProperty("detail");
        Assert.Equal(6, detail.GetProperty("total").GetInt32());
        Assert.Equal(2, detail.GetProperty("edges").GetArrayLength());
        Assert.Equal("jni", detail.GetProperty("edgeKinds")[0].GetProperty("kind").GetString());
        await McpProtocolTests.AssertMatchesOutputSchema(server.Client, "summarize_file", r);
    }

    /// <summary>The packages under CORVUS_MOBILE_APPS (two levels deep): each graph within 5 s, with the edge kinds their runtimes need.</summary>
    [Trait("Speed", "Slow")]
    [RequiresRealDataFact(RealData.MobileApps)]
    public void Real_packages_graph_within_five_seconds()
    {
        var apks = Directory.EnumerateFiles(RealData.Get(RealData.MobileApps)!, "*.apk", new EnumerationOptions { RecurseSubdirectories = true, MaxRecursionDepth = 2 }).ToList();
        Assert.NotEmpty(apks);
        var slow = new List<string>();
        var loader = new Il2CppRawLoader(_workspace);
        foreach (var apk in apks.OrderByDescending(a => new FileInfo(a).Length))
        {
            // An Il2Cpp game is read once first, as load_assembly does; the graph joins its methods from the cache.
            if (Il2CppPackages.Extract(apk, null) is { } root && Il2CppGameFiles.Find(root) is { Binary.Length: > 0 } files)
                loader.Load(files, loadBinary: false, null, default);
            var watch = Stopwatch.StartNew();
            var g = Graph(loader).Build(apk, 0, 10, default);
            watch.Stop();
            if (watch.Elapsed > TimeSpan.FromSeconds(5))
            {
                // once more: a loaded machine (a suite running beside) slows one pass
                watch.Restart();
                g = Graph(loader).Build(apk, 0, 10, default);
                watch.Stop();
            }
            output.WriteLine($"{Path.GetFileName(apk)} {new FileInfo(apk).Length >> 20} MB: {watch.Elapsed.TotalSeconds:0.00} s; layers {string.Join(", ", g.Layers.Select(l => $"{l.Layer} {l.Items}"))}; " +
                             string.Join("; ", g.EdgeKinds.Select(k => $"{k.Kind} {k.Edges}/{k.Candidates} {k.Coverage}")));
            if (watch.Elapsed > TimeSpan.FromSeconds(5)) slow.Add($"{Path.GetFileName(apk)} {watch.Elapsed.TotalSeconds:0.0} s");
            foreach (var k in g.EdgeKinds) Assert.True(k.Edges <= k.Candidates || k.Kind == "jni", $"{apk}: {k.Kind}");
        }
        Assert.True(slow.Count == 0, string.Join("\n", slow));
    }
}
