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

    private AppGraph Graph(AotBuildLoader? aot = null) { var dex = new DexService(); return new AppGraph(dex, new JniBindings(dex), new JavaDotNetMap(_workspace, dex), aot); }

    [Fact]
    public void JNI_and_React_Native_edges_are_listed_with_coverage()
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
        // Native.missing and Other.init have neither export nor table entry.
        Assert.Equal("partial", jni.Coverage);
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

    [Fact]
    public void Cordova_and_capacitor_calls_join_their_plugin_classes()
    {
        using var dir = new TempDir();
        var dexBytes = JniBindingsTests.Dex(b =>
        {
            var camera = b.Class("Lorg/apache/cordova/camera/CameraLauncher;", 1, "Lorg/apache/cordova/CordovaPlugin;");
            camera.Method("execute", "Z", ["Ljava/lang/String;", "Lorg/json/JSONArray;", "Lorg/apache/cordova/CallbackContext;"], 1,
                ConstString(0, "takePicture"), Return(0x0f, 0)).Registers = 5;
            b.Class("Lorg/apache/cordova/CoreAndroid;", 1, "Lorg/apache/cordova/CordovaPlugin;");
            var plugin = b.Class("Lcom/capacitorjs/plugins/camera/CameraPlugin;", 1, "Lcom/getcapacitor/Plugin;");
            plugin.Annotations.Add(("Lcom/getcapacitor/annotation/CapacitorPlugin;", 1, [("name", "Camera")]));
            plugin.Method("getPhoto", "V", ["Lcom/getcapacitor/PluginCall;"], 1, ReturnVoid()).Annotations.Add(("Lcom/getcapacitor/PluginMethod;", 1, []));
            plugin.Method("pickImages", "V", ["Lcom/getcapacitor/PluginCall;"], 1, ReturnVoid()).Annotations.Add(("Lcom/getcapacitor/PluginMethod;", 1, []));
        });
        var config = AxmlWriter.Write(new AxmlWriter.Node("widget").Add(
            new AxmlWriter.Node("feature", AxmlWriter.String("name", "Camera", ns: null))
                .Add(new AxmlWriter.Node("param", AxmlWriter.String("name", "android-package", ns: null), AxmlWriter.String("value", "org.apache.cordova.camera.CameraLauncher", ns: null))),
            new AxmlWriter.Node("feature", AxmlWriter.String("name", "CoreAndroid", ns: null))
                .Add(new AxmlWriter.Node("param", AxmlWriter.String("name", "android-package", ns: null), AxmlWriter.String("value", "org.apache.cordova.CoreAndroid", ns: null)))));
        var cordova = Encoding.UTF8.GetBytes(
            "exec(function (r) { done(r, 1); }, fail, 'Camera', 'takePicture', [q, 50]);\n" +
            "cordova.exec(null, null, \"CoreAndroid\", action, []);\n" +
            "exec(ok, fail, 'Geolocation', 'getLocation', []); // no feature\n" +
            "codeexec(a, b, 'Not', 'Exec', []);");
        var capacitor = Encoding.UTF8.GetBytes("const Camera = registerPlugin('Camera', { web: () => import('./web') });\nCamera.getPhoto({ quality: 90 });\nconst Share = registerPlugin(\"Share\");");
        var apk = AndroidSamples.Save(dir, "hybrid.apk", AndroidSamples.Apk(30, ("classes.dex", dexBytes), ("res/xml/config.xml", config),
            ("assets/www/plugins/camera.js", cordova), ("assets/www/app.js", capacitor)));
        var g = Graph().Build(apk, 0, 500, default);
        foreach (var e in g.Edges.Where(e => e.Kind.EndsWith("_plugin", StringComparison.Ordinal))) output.WriteLine($"{e.Kind}: {e.From} -> {e.To} ({e.Basis})");
        Assert.Contains(g.Layers, l => l.Layer == "web" && l.Items == 2);
        var cordovaKind = g.EdgeKinds.Single(k => k.Kind == "cordova_plugin");
        Assert.Equal((2, 3, "partial"), (cordovaKind.Edges, cordovaKind.Candidates, cordovaKind.Coverage));
        Assert.Equal("1 call(s) unbound: Geolocation (no config.xml feature)", cordovaKind.Reason);
        Assert.Contains(g.Edges, e => e.Kind == "cordova_plugin" && e.From == "assets/www/plugins/camera.js:exec(Camera.takePicture)"
            && e.To == "Lorg/apache/cordova/camera/CameraLauncher;->execute" && e.Basis == "config_feature, action_string");
        Assert.Contains(g.Edges, e => e.Kind == "cordova_plugin" && e.From == "assets/www/plugins/camera.js:exec(CoreAndroid.?)" && e.Basis == "config_feature");
        var capacitorKind = g.EdgeKinds.Single(k => k.Kind == "capacitor_plugin");
        Assert.Equal((2, 3, "partial"), (capacitorKind.Edges, capacitorKind.Candidates, capacitorKind.Coverage));
        Assert.StartsWith("1 plugin(s) with no native class", capacitorKind.Reason);
        Assert.Contains(g.Edges, e => e.Kind == "capacitor_plugin" && e.From == "assets/www/app.js:registerPlugin(Camera)" && e.To == "Lcom/capacitorjs/plugins/camera/CameraPlugin;");
        Assert.Contains(g.Edges, e => e.Kind == "capacitor_plugin" && e.From == "assets/www/app.js:Camera.getPhoto()"
            && e.To == "Lcom/capacitorjs/plugins/camera/CameraPlugin;->getPhoto(Lcom/getcapacitor/PluginCall;)V");
        Assert.DoesNotContain(g.Edges, e => e.From.Contains("pickImages", StringComparison.Ordinal));
    }

    /// <summary>
    /// CORVUS_HYBRID_APPS: Cordova and Capacitor packages. Each must join its plugin calls; every class Capacitor's own
    /// registry (assets/capacitor.plugins.json) lists, and every Cordova service its exec() calls name, must be bound or
    /// named in the coverage reason.
    /// </summary>
    [RequiresRealDataFact("CORVUS_HYBRID_APPS")]
    [Trait("Speed", "Slow")]
    public void Real_hybrid_packages_join_their_plugin_calls()
    {
        var failures = new List<string>();
        int packages = 0;
        foreach (var apk in Directory.EnumerateFiles(Environment.GetEnvironmentVariable("CORVUS_HYBRID_APPS")!, "*.apk", SearchOption.AllDirectories).Order(StringComparer.Ordinal))
        {
            var name = Path.GetFileName(apk);
            var g = Graph().Build(apk, 0, 2000, default);
            var bridges = g.EdgeKinds.Where(k => k.Kind is "cordova_plugin" or "capacitor_plugin").ToList();
            foreach (var k in bridges) output.WriteLine($"{name}: {k.Kind} {k.Edges}/{k.Candidates} {k.Coverage} {k.Reason}");
            foreach (var e in g.Edges.Where(e => e.Kind.EndsWith("_plugin", StringComparison.Ordinal)).Take(12)) output.WriteLine($"  {e.From} -> {e.To} ({e.Basis})");
            foreach (var n in g.Notes.Where(n => n.StartsWith("Capacitor", StringComparison.Ordinal) || n.StartsWith("Cordova", StringComparison.Ordinal))) output.WriteLine($"  note: {n}");
            if (bridges.Count == 0 || bridges.All(k => k.Edges == 0)) failures.Add($"{name}: no plugin call joined");
            using var zip = System.IO.Compression.ZipFile.OpenRead(apk);
            if (zip.GetEntry("assets/capacitor.plugins.json") is { } registry)
            {
                using var s = registry.Open();
                foreach (var plugin in System.Text.Json.JsonDocument.Parse(s).RootElement.EnumerateArray())
                {
                    var descriptor = "L" + plugin.GetProperty("classpath").GetString()!.Replace('.', '/') + ";";
                    var classpath = plugin.GetProperty("classpath").GetString()!;
                    if (!g.Edges.Any(e => e.To.StartsWith(descriptor, StringComparison.Ordinal)) && !g.Notes.Any(n => n.StartsWith("Capacitor: ", StringComparison.Ordinal) && n.Contains(classpath, StringComparison.Ordinal)))
                        failures.Add($"{name}: registry class {classpath} is neither joined nor noted");
                }
            }
            packages++;
        }
        Assert.True(packages > 0, "no packages");
        Assert.True(failures.Count == 0, string.Join("\n", failures));
    }

    /// <summary>Damaged packages: the view and the graph answer or throw a tool error.</summary>
    [Trait("Smoke", "push")]
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

    /// <summary>The packages under CORVUS_MOBILE_APPS (two levels deep), as the graph tests read them.</summary>
    private static List<string> MobilePackages() =>
        Directory.EnumerateFiles(RealData.Get(RealData.MobileApps)!, "*.apk", new EnumerationOptions { RecurseSubdirectories = true, MaxRecursionDepth = 2 }).ToList();

    /// <summary>The smallest package and the smallest AOT build under CORVUS_MOBILE_APPS: each graph has the edge kinds its runtimes need.</summary>
    [Trait("Speed", "Slow")]
    [RequiresRealDataFact(RealData.MobileApps)]
    public void Real_packages_graph_with_the_edges_their_runtimes_need()
    {
        var apks = MobilePackages().OrderBy(a => new FileInfo(a).Length).ToList();
        Assert.NotEmpty(apks);
        var aotApk = apks.FirstOrDefault(a => { using var zip = System.IO.Compression.ZipFile.OpenRead(a); return zip.Entries.Any(e => Core.Mobile.AndroidRuntime.IsAotEntry(e.FullName)); });
        var loader = new AotBuildLoader(_workspace);
        foreach (var apk in new[] { apks[0], aotApk }.OfType<string>().Distinct())
            GraphOf(loader, apk);
    }

    /// <summary>Every package under CORVUS_MOBILE_APPS: each graph within 5 s on a quiet machine (MachineLoad scales it).</summary>
    [Trait("Speed", "Slow")]
    [Trait(PerfBudget.Trait, PerfBudget.Timing)]
    [Trait("Tier", "Release")]
    [RequiresRealDataFact(RealData.MobileApps)]
    public void Real_packages_graph_within_five_seconds()
    {
        var apks = MobilePackages();
        Assert.NotEmpty(apks);
        var loader = new AotBuildLoader(_workspace);
        foreach (var apk in apks.OrderByDescending(a => new FileInfo(a).Length))
            GraphOf(loader, apk);
    }

    /// <summary>Builds the graph of <paramref name="apk"/>, reports its time and checks its edge kinds.</summary>
    private void GraphOf(AotBuildLoader loader, string apk)
    {
        // An AOT build is read once first, as load_assembly does; the graph joins its methods from the cache.
        var files = AotPackages.Extract(apk, null) is { } root && AotBuildFiles.Find(root) is { Binary.Length: > 0 } found ? found : null;
        if (files != null) loader.Load(files, loadBinary: false, null, default);
        var before = MachineLoad.Factor();
        var paused = GC.GetTotalPauseDuration();
        var watch = Stopwatch.StartNew();
        var g = Graph(loader).Build(apk, 0, 10, default);
        watch.Stop();
        // The calibration before and after misses what only the work's span saw: the process's
        // collection pauses (other tests allocate in it too) and the machine's memory load.
        var span = $"collection pauses {(GC.GetTotalPauseDuration() - paused).TotalSeconds:0.00} s, memory load {GC.GetGCMemoryInfo().MemoryLoadBytes * 100 / Math.Max(1, GC.GetGCMemoryInfo().HighMemoryLoadThresholdBytes)} % of the high threshold";
        var (_, load) = MachineLoad.Budget(TimeSpan.FromSeconds(5), before, MachineLoad.Factor());
        output.WriteLine($"{Path.GetFileName(apk)} {new FileInfo(apk).Length >> 20} MB: {watch.Elapsed.TotalSeconds:0.00} s ({load}; {span}); layers {string.Join(", ", g.Layers.Select(l => $"{l.Layer} {l.Items}"))}; " +
                         string.Join("; ", g.EdgeKinds.Select(k => $"{k.Kind} {k.Edges}/{k.Candidates} {k.Coverage}")));
        PerfBudget.Time("mobile/app-graph", watch.Elapsed, TimeSpan.FromSeconds(5), output, $"{load}; {span}");
        foreach (var k in g.EdgeKinds) Assert.True(k.Edges <= k.Candidates || k.Kind == "jni", $"{apk}: {k.Kind}");
        // The graph joins the build's methods from the cache the load filled; it reads no metadata itself.
        if (files != null) Assert.True(g.Layers.Single(l => l.Layer == "aot").Items > 0, $"{apk}: the AOT layer was not joined from the cache");
    }
}
