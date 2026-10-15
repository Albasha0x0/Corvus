using Corvus.Core;
using Corvus.Services.Analysis;
using Corvus.Tests.NativeFormats;

namespace Corvus.Tests;

/// <summary>The Electron graph on the syntax tree: the alias, wrapper and pairing shapes of REA issues #3535, #3315, #3551, #3536, #3539 and #3431.</summary>
public sealed class ElectronGraphTests : IDisposable
{
    private readonly TempDir _dir = new();
    public void Dispose() => _dir.Dispose();

    private static List<ElectronRow> Graph(params (string Path, string Text)[] files)
    {
        var names = files.Select(f => f.Path).ToHashSet(StringComparer.Ordinal);
        var graph = new ElectronGraph { Exists = names.Contains };
        foreach (var (path, text) in files) graph.Add(path, text, default);
        return graph.Finish();
    }

    private static ElectronRow Row(List<ElectronRow> rows, string kind, string value) =>
        rows.FirstOrDefault(r => r.Kind == kind && r.Value == value) ?? throw new Xunit.Sdk.XunitException(
            $"no {kind} '{value}' in:\n" + string.Join("\n", rows.Select(r => $"{r.Kind} {r.Value} {r.Site} ({r.Call}) {r.Link}")));

    /// <summary>#3535: esbuild's declared __require shim and __toESM interop still name ipcMain.</summary>
    [Fact]
    public void Esbuild_require_shim_resolves_electron()
    {
        var rows = Graph(("main.js", """
            var __require = ((x) => typeof require !== "undefined" ? require : x)(function(x) { throw Error("Dynamic require of " + x); });
            var import_electron = __toESM(__require("electron"));
            import_electron.ipcMain.handle("esb:ping", () => "pong");
            """), ("preload.js", """var e = __require("electron"); e.ipcRenderer.invoke("esb:ping");"""));
        Assert.StartsWith("paired with ipcRenderer.invoke at preload.js:1:", Row(rows, "ipc-main", "esb:ping").Link);
    }

    /// <summary>Destructuring with renames, and a contextBridge method that forwards its channel, called from a page.</summary>
    [Fact]
    public void Renamed_destructuring_and_bridge_wrappers_pair_channels()
    {
        var rows = Graph(
            ("main.js", """
                const { ipcMain: m } = require("electron");
                m.handle("d:x", () => 1);
                m.handle("d:y", () => 2);
                """),
            ("preload.js", """
                const { ipcRenderer: r, contextBridge: cb } = require("electron");
                cb.exposeInMainWorld("api", { ping: () => r.invoke("d:x"), invoke: (ch, ...a) => r.invoke(ch, ...a) });
                """),
            ("page.js", """document.onclick = () => window.api.invoke("d:y", 1);"""));
        Assert.Contains("ipcRenderer.invoke at preload.js:2:", Row(rows, "ipc-main", "d:x").Link);
        var viaBridge = Row(rows, "ipc-renderer", "d:y");
        Assert.Equal("ipcRenderer.invoke via window.api.invoke", viaBridge.Call);
        Assert.StartsWith("page.js:1:", viaBridge.Site);
        Assert.StartsWith("paired with ipcMain.handle at main.js:3:", viaBridge.Link);
        Assert.Equal("ipcRenderer.invoke d:x", Row(rows, "bridge-method", "api.ping").Link);
        Assert.StartsWith("forwards argument 1", Row(rows, "bridge-method", "api.invoke").Link);
        Assert.Equal("api", Row(rows, "bridge-key", "api").Value);
        Assert.Contains(rows, r => r.Kind == "bridge-call" && r.Value == "api.invoke");
    }

    /// <summary>#3551 and #3315: renamed webpack factory parameters, an external module, and export getters.</summary>
    [Fact]
    public void Webpack_externals_and_export_getters_resolve()
    {
        var rows = Graph(
            ("main.js", """
                (()=>{var o={4482:t=>{"use strict";t.exports=require("electron")},
                12:(t,e,r)=>{const a=r(4482);a.ipcMain.on("wp:send",()=>{})}};})();
                """),
            ("renderer.js", """
                (()=>{var o={4482:t=>{t.exports=require("electron")},
                77:(t,e,r)=>{r.d(e,{I:()=>o.ipcRenderer});var o=r(4482)},
                90:(t,e,r)=>{const s=r(77);s.I.send("wp:send",1)}};})();
                """));
        var send = Row(rows, "ipc-renderer", "wp:send");
        Assert.Equal("ipcRenderer.send", send.Call);
        Assert.StartsWith("paired with ipcMain.on at main.js:2:", send.Link);
    }

    /// <summary>#3536: BrowserWindow options built from constants; the preload path through path.join and __dirname.</summary>
    [Fact]
    public void Window_options_from_constants_name_the_preload()
    {
        var rows = Graph(("dist/main/main.js", """
            const path = require("path");
            const { BrowserWindow } = require("electron");
            const PRELOAD = path.join(__dirname, "..", "preload", "index.js");
            const opts = { width: 800, webPreferences: { preload: PRELOAD, contextIsolation: true } };
            new BrowserWindow(opts);
            """), ("dist/preload/index.js", "1;"));
        var window = Row(rows, "window", "dist/preload/index.js");
        Assert.Equal("new BrowserWindow", window.Call);
        Assert.Equal("preload dist/preload/index.js (in the app)", window.Link);
        Assert.Equal("in the app", Row(rows, "preload", "dist/preload/index.js").Link);
    }

    /// <summary>#3539: a wrapper function whose parameter is the channel; main-to-renderer sends paired with renderer listeners.</summary>
    [Fact]
    public void Request_wrappers_and_main_to_renderer_sends_pair()
    {
        var rows = Graph(
            ("renderer.js", """
                const { ipcRenderer } = require("electron");
                function call(channel, payload) { return ipcRenderer.invoke(channel, payload); }
                const get = (key) => call("wrap:get", key);
                ipcRenderer.on("push:update", () => {});
                """),
            ("main.js", """
                const { ipcMain, BrowserWindow } = require("electron");
                ipcMain.handle("wrap:get", () => 1);
                const win = new BrowserWindow({});
                win.webContents.send("push:update", 2);
                """));
        var wrapped = Row(rows, "ipc-renderer", "wrap:get");
        Assert.Equal("ipcRenderer.invoke via call", wrapped.Call);
        Assert.StartsWith("paired with ipcMain.handle at main.js:2:", wrapped.Link);
        Assert.StartsWith("paired with webContents.send at main.js:4:", Row(rows, "ipc-renderer", "push:update").Link);
        Assert.Equal("(no preload)", Row(rows, "window", "(no preload)").Value);
        Assert.Equal((2, 2), ElectronGraph.Pairing(rows));
    }

    /// <summary>#3431: node: prefixed fs and synchronous child_process calls are sinks.</summary>
    [Fact]
    public void Node_prefixed_fs_and_sync_child_process_are_sinks()
    {
        var rows = Graph(("main.js", """
            const { execSync } = require("node:child_process");
            const fs = require("node:fs");
            execSync("whoami");
            fs.writeFileSync("/tmp/out", "x");
            ipcMain.handle("lonely", () => 0);
            """));
        Assert.Equal("child_process.execSync", Row(rows, "sink-child_process", "whoami").Call);
        Assert.Equal("fs.writeFileSync", Row(rows, "sink-fs", "/tmp/out").Call);
        Assert.Equal("unpaired: no renderer sends this channel", Row(rows, "ipc-main", "lonely").Link);
    }

    /// <summary>require('x.node').fn reaches the add-on's native function through its N-API registration.</summary>
    [Fact]
    public void Native_calls_join_the_addon_function()
    {
        var app = _dir.File("app.asar");
        File.WriteAllBytes(app, AsarWriter.Build([AsarWriter.Text("main.js", "const native = require(\"./build/Release/addon.node\");\nnative.hello();")]).Archive);
        Directory.CreateDirectory(Path.Combine(app + ".unpacked", "build", "Release"));
        File.WriteAllBytes(Path.Combine(app + ".unpacked", "build", "Release", "addon.node"), NodeApiTests.ElfAddon());
        using var ws = new AssemblyWorkspace();
        var row = Assert.Single(new UnpackService(ws).Search(app, "native-call", "electron", 100, AnalysisLimits.Default, default).Items);
        Assert.Contains($"RVA 0x{ElfWriter.TextRva + NodeApiTests.Hello:X}, function 'hello'", row.Detail);
    }

    /// <summary>A button's text followed through its onClick, a bridge method, IPC and the main handler into the add-on's function.</summary>
    [Fact]
    public void Feature_trace_reaches_the_native_function()
    {
        var app = _dir.File("app.asar");
        File.WriteAllBytes(app, AsarWriter.Build([
            AsarWriter.Text("renderer.js", "const view = () => jsx(\"button\", { onClick: () => window.api.openSettings(), children: \"Open settings\" });"),
            AsarWriter.Text("preload.js", "const { contextBridge, ipcRenderer } = require(\"electron\");\ncontextBridge.exposeInMainWorld(\"api\", { openSettings: () => ipcRenderer.invoke(\"settings:open\") });"),
            AsarWriter.Text("main.js", "const { ipcMain } = require(\"electron\");\nconst native = require(\"./build/Release/addon.node\");\nfunction open() { return native.hello(); }\nipcMain.handle(\"settings:open\", () => open());"),
        ]).Archive);
        Directory.CreateDirectory(Path.Combine(app + ".unpacked", "build", "Release"));
        File.WriteAllBytes(Path.Combine(app + ".unpacked", "build", "Release", "addon.node"), NodeApiTests.ElfAddon());
        using var ws = new AssemblyWorkspace();
        var row = Assert.Single(new UnpackService(ws).Search(app, "Open settings", "feature", 100, AnalysisLimits.Default, default).Items);
        var steps = row.Detail!.Split(" -> ");
        Assert.StartsWith("literal \"Open settings\" at renderer.js:1:", steps[0]);
        Assert.StartsWith("handler onClick at renderer.js:1:", steps[1]);
        Assert.StartsWith("bridge-call window.api.openSettings api.openSettings at renderer.js:1:", steps[2]);
        Assert.StartsWith("bridge method api.openSettings at preload.js:2:", steps[3]);
        Assert.StartsWith("ipc-renderer ipcRenderer.invoke settings:open at preload.js:2:", steps[4]);
        Assert.StartsWith("ipcMain.handle at main.js:4:", steps[5]);
        Assert.StartsWith("native-call call hello at main.js:3:", steps[6]);
        Assert.Contains($"RVA 0x{ElfWriter.TextRva + NodeApiTests.Hello:X}, function 'hello'", steps[7]);
    }

    /// <summary>Mutated scripts: rows or call-shape rows, never an exception.</summary>
    [Fact]
    [FuzzEntry(typeof(Corvus.Services.Web.JsProgram), typeof(ElectronGraph))]
    public void Fuzzed_scripts_never_throw()
    {
        var seed = System.Text.Encoding.UTF8.GetBytes("""
            const {ipcMain:m,BrowserWindow:W}=require("electron");const p=require("path");m.handle(`a:${1}`,()=>0);
            new W({webPreferences:{preload:p.join(__dirname,"p.js")}});(()=>{var o={1:t=>{t.exports=require("electron")},2:(t,e,r)=>{r(1).ipcRenderer.send("a:1")}}})();
            """);
        var failures = FormatFuzz.Run(seed, b =>
        {
            var graph = new ElectronGraph { KeepTexts = true };
            graph.Add("main.js", System.Text.Encoding.UTF8.GetString(b), default);
            graph.Finish();
            graph.Trace("a:", default);
        }, 300);
        Assert.True(failures.Count == 0, string.Join("\n", failures.Take(20)));
    }
}

/// <summary>The graph on installed Electron apps: time, rows, literal channels paired and native joins.</summary>
[Trait("Speed", "Slow")]
[Trait("Data", "Real")]
public sealed class ElectronGraphRealTests(Xunit.Abstractions.ITestOutputHelper output)
{
    [RequiresRealDataFact(RealData.ElectronApps)]
    public void Real_apps_pair_their_channels()
    {
        var archives = Directory.EnumerateFiles(RealData.Path(RealData.ElectronApps), "app.asar",
            new EnumerationOptions { RecurseSubdirectories = true, MaxRecursionDepth = 6, IgnoreInaccessible = true }).ToList();
        Assert.NotEmpty(archives);
        using var ws = new AssemblyWorkspace();
        foreach (var asar in archives)
        {
            var sw = System.Diagnostics.Stopwatch.StartNew();
            var facts = ElectronInspector.Of(asar, File.ReadAllBytes(asar), default)!;
            var seconds = sw.Elapsed.TotalSeconds;
            var (channels, paired) = ElectronGraph.Pairing(facts.Surface);
            var joins = new UnpackService(ws).Search(asar, "native-call", "electron", 2000, AnalysisLimits.Default, default).Items;
            output.WriteLine($"{asar}: {new FileInfo(asar).Length / 1048576.0:0.0} MiB in {seconds:0.00} s; " +
                             string.Join(", ", facts.Surface.GroupBy(r => r.Kind).Select(g => $"{g.Count()} {g.Key}")) +
                             $"; literal channels {paired}/{channels} paired; native calls {joins.Count}, joined {joins.Count(j => j.Detail!.Contains("RVA 0x", StringComparison.Ordinal))}");
            foreach (var r in facts.Surface.Where(r => r.Link?.StartsWith("unpaired", StringComparison.Ordinal) == true).Take(15))
                output.WriteLine($"    {r.Kind} {r.Value} {r.Site} ({r.Call}) {r.Link}");
            foreach (var n in facts.Notes.Take(5)) output.WriteLine("    note: " + n);
        }
    }
}
