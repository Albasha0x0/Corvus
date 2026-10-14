using System.IO.Compression;
using System.Text;
using Corvus.Core;
using Corvus.Services.Analysis;

namespace Corvus.Tests;

/// <summary>search_container kind=electron (the surface rows of an app's scripts) and kind=endpoint (request templates of a capture).</summary>
public sealed class ElectronSurfaceTests : IDisposable
{
    private readonly TempDir _dir = new();
    private readonly Corvus.Core.AssemblyWorkspace _ws = new();
    public void Dispose() { _ws.Dispose(); _dir.Dispose(); }

    private const string Main = """
        const { ipcMain, shell } = require("electron");
        const cp = require("child_process");
        new BrowserWindow({ webPreferences: { preload: path.join(__dirname, "preload.js"), contextIsolation: true } });
        ipcMain.handle("app:open", (e, url) => shell.openExternal(url));
        ipcMain.on('log', () => {});
        const native = require("./build/Release/addon.node");
        """;
    private const string Preload = """
        contextBridge.exposeInMainWorld("api", { open: u => ipcRenderer.invoke("app:open", u) });
        """;

    private string App()
    {
        var path = _dir.File("app.zip");
        using var zip = ZipFile.Open(path, ZipArchiveMode.Create);
        foreach (var (name, text) in new[] { ("main.js", Main), ("preload.js", Preload), ("node_modules/dep/index.js", "ipcMain.handle(\"dep\", f);") })
            using (var w = new StreamWriter(zip.CreateEntry(name).Open(), Encoding.UTF8)) w.Write(text);
        return path;
    }

    [Fact]
    public void Electron_rows_name_each_boundary_with_its_site()
    {
        var app = App();
        var found = new UnpackService(_ws).Search(app, "*", "electron", 100, AnalysisLimits.Default, default);
        var rows = found.Items.Select(m => $"{m.Detail} = {m.Name}").ToList();
        Assert.Contains(rows, r => r.StartsWith("ipc-main at main.js:4:") && r.EndsWith("= app:open"));
        Assert.Contains(rows, r => r.StartsWith("ipc-main at main.js:5:") && r.EndsWith("= log"));
        Assert.Contains(rows, r => r.StartsWith("sink-shell at main.js:4:") && r.EndsWith("= url"));
        Assert.Contains(rows, r => r.StartsWith("sink-child_process at main.js:2:"));
        Assert.Contains(rows, r => r.StartsWith("native-require at main.js:6:") && r.EndsWith("= ./build/Release/addon.node"));
        Assert.Contains(rows, r => r.StartsWith("bridge-key at preload.js:1:") && r.EndsWith("= api"));
        Assert.Contains(rows, r => r.StartsWith("ipc-renderer at preload.js:1:") && r.EndsWith("= app:open"));
        Assert.DoesNotContain(rows, r => r.Contains("node_modules"));
        // the query matches the channel or the row kind
        Assert.Equal(2, new UnpackService(_ws).Search(app, "ipc-main", "electron", 100, AnalysisLimits.Default, default).Total);
    }

    [Fact]
    public void Endpoint_templates_fold_ids_and_hide_values()
    {
        var har = _dir.File("capture.har");
        static string Entry(string method, string url, int status) =>
            "{\"request\":{\"method\":\"" + method + "\",\"url\":\"" + url + "\"},\"response\":{\"status\":" + status +
            ",\"content\":{\"mimeType\":\"application/json\",\"text\":\"{}\"}}}";
        File.WriteAllText(har, "{\"log\":{\"entries\":[" + string.Join(",",
            Entry("GET", "https://api.example.com/users/42?token=secret&page=2", 200),
            Entry("GET", "https://api.example.com/users/7?page=3&token=x", 404),
            Entry("POST", "https://api.example.com/login", 200)) + "]}}");
        var found = new UnpackService(_ws).Search(har, "*", "endpoint", 100, AnalysisLimits.Default, default);
        var rows = found.Items.Select(m => $"{m.Name} | {m.Detail}").ToList();
        Assert.Contains("GET https://api.example.com/users/{n}?page=…&token=… | 2 request(s), status 200, 404", rows);
        Assert.Contains("POST https://api.example.com/login | 1 request(s), status 200", rows);
        Assert.DoesNotContain(rows, r => r.Contains("secret"));
    }
}
