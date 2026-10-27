using System.Diagnostics;
using System.Text.RegularExpressions;
using Corvus.Core;
using Corvus.Native.Providers.Live.Inspector;
using Corvus.Services;
using Corvus.Services.Web;
using Corvus.Tools;

namespace Corvus.Tests;

/// <summary>Sessions on a V8 inspector: stop points at original source lines through the script's map, and paused frames named back.</summary>
public sealed partial class LiveInspectorTests : IDisposable
{
    private readonly AssemblyWorkspace _workspace = new();
    private readonly TempDir _dir = new();
    private readonly LiveSessionService _service;
    private readonly LiveSessionTools _tools;
    private readonly Xunit.Abstractions.ITestOutputHelper _output;

    public LiveInspectorTests(Xunit.Abstractions.ITestOutputHelper output)
    {
        _output = output;
        _service = new LiveSessionService(_workspace, new NativeCodeService(_workspace, SharedCodeIndex.Options()));
        _tools = new LiveSessionTools(new ServerOptions { AllowLiveAttach = true }, _service);
    }

    // src/app.ts as a compiler emits it: a "use strict" line first, and the loop body on a line of its own.
    private const string Original = """
        function add(a: number, b: number): number {
          const sum = a + b;
          console.log("sum", sum);
          return sum;
        }

        let total = 0;
        for (let i = 0; i < 3; i++) total = add(total, i);
        console.log("done", total);
        """;

    private const string Generated = """
        "use strict";
        function add(a, b) {
            const sum = a + b;
            console.log("sum", sum);
            return sum;
        }
        let total = 0;
        for (let i = 0; i < 3; i++)
            total = add(total, i);
        console.log("done", total);
        //# sourceMappingURL=app.js.map
        """;

    // Generated lines 2-6 map to original lines 1-5, 7-8 to 7-8, line 9 column 5 to line 8 column 29, line 10 to line 9.
    private const string Map = """{"version":3,"file":"app.js","sources":["../src/app.ts"],"names":[],"mappings":";AAAA;AACA;AACA;AACA;AACA;AAEA;AACA;IAA4B;AAC5B"}""";

    public void Dispose()
    {
        _service.Dispose();
        _workspace.Dispose();
        _dir.Dispose();
    }

    [Fact]
    public void An_original_line_maps_to_its_generated_position_or_the_next_line_with_code()
    {
        var map = SourceMap.Parse(System.Text.Encoding.UTF8.GetBytes(Map));
        Assert.Equal("src/app.ts", map.Sources[0]);
        var (line, segments) = map.Generated(0, 2)!.Value;
        Assert.Equal((2, 3, 0), (line, segments[0].Line, segments[0].Column));
        // Line 6 (0-based 5) is blank: the next line with code is 7.
        Assert.Equal(6, map.Generated(0, 5)!.Value.Line);
        // Line 8 has two generated positions: the loop head and its body.
        Assert.Equal([(7, 0), (8, 4)], map.Generated(0, 7)!.Value.Segments.Select(s => (s.Line, s.Column)));
        Assert.Null(map.Generated(0, 9));
    }

    [Theory]
    [InlineData("inspector:192.168.1.5:9229", "not a loopback address")]
    [InlineData("inspector:ws://10.0.0.2:9229/abc", "not a loopback address")]
    [InlineData("inspector:http", "is not a port")]
    public async Task An_inspector_off_this_machine_or_without_a_port_is_refused(string program, string reason)
    {
        var e = await Assert.ThrowsAsync<ToolError>(() => InspectorEndpoint.ResolveAsync(program, default));
        Assert.Contains(reason, e.Message);
    }

    [RequiresRealDataFact("CORVUS_NODE")]
    [Trait("Speed", "Slow")]
    public async Task Native_actions_on_an_inspector_session_are_refused_by_name()
    {
        await using var node = await Node.StartAsync(Write(), _dir);
        var opened = await _tools.LiveSession("attach", program: "inspector:" + node.WebSocket);
        Assert.Contains("(inspector)", opened);
        var watch = await Assert.ThrowsAsync<ToolError>(() => _tools.LiveWatchCalls("live-1", "set", at: "app.js:3"));
        Assert.Contains("A watch works on native code", watch.Message);
        // Ops sent straight to the worker are refused there.
        var read = await Assert.ThrowsAsync<ToolError>(() => _service.ReadAsync(_service.Get("live-1"), 0x1000, 16, default));
        Assert.Contains("'read' works on native code", read.Message);
        // The program is held at its first statement, so the IPC recorder cannot be evaluated yet.
        var ipc = await Assert.ThrowsAsync<ToolError>(() => _tools.LiveSession("ipc", session: "live-1"));
        Assert.Contains("paused and evaluates nothing until it runs", ipc.Message);
        await _tools.LiveSession("close", session: "live-1");
    }

    /// <summary>
    /// node --inspect-brk runs dist/app.js, held at its first statement; a stop point at src/app.ts:3 is set on the
    /// generated line its map gives, the paused frames name src/app.ts again, and the program runs on to its end after close.
    /// </summary>
    [RequiresRealDataFact("CORVUS_NODE")]
    [Trait("Speed", "Slow")]
    public async Task A_stop_point_at_an_original_line_stops_there_and_names_the_frames_by_their_sources()
    {
        await using var node = await Node.StartAsync(Write(), _dir);
        var opened = await _tools.LiveSession("attach", program: "inspector:" + node.WebSocket);
        Assert.Contains("suspended", opened);
        Assert.Contains("app.js  map: 1 source(s)", await _tools.LiveSession("status", session: "live-1"));

        var set = await _tools.LiveBreak("live-1", "set", at: "src/app.ts:3");
        _output.WriteLine(set);
        Assert.Contains("s1 set at app.js:4:1 from src/app.ts:3", set);
        Assert.Contains("program started", await _tools.LiveBreak("live-1", "continue"));
        var stop = await _tools.LiveBreak("live-1", wait: true, waitSeconds: 60);
        _output.WriteLine(stop);
        Assert.Matches(@"#0 add app\.js:4:\d+ = src/app\.ts:3:1", stop);
        Assert.Matches(@"#1 \(anonymous\) app\.js:9:\d+ = src/app\.ts:8:29", stop);
        Assert.Contains("s1 src/app.ts:3 at app.js:4:1 from src/app.ts:3, 1 hit(s)", stop);

        await _tools.LiveBreak("live-1", "continue");
        Assert.Matches(@"#0 add app\.js:4:\d+ = src/app\.ts:3:1", await _tools.LiveBreak("live-1", wait: true, waitSeconds: 60));
        await _tools.LiveSession("close", session: "live-1");
        Assert.Equal(["sum 0", "sum 1", "sum 3", "done 3"], await node.OutputAsync());
        Assert.Contains("console.log: sum 0", await _tools.LiveEvents("live-1", kind: "output"));
    }

    /// <summary>
    /// CORVUS_ELECTRON runs a hidden-window app written here: its main process under --inspect stops at a plain line of
    /// main.js, its page under --remote-debugging-port at src/page.ts:3 through dist/page.js's map; both close and run on.
    /// </summary>
    [RequiresRealDataFact("CORVUS_ELECTRON")]
    [Trait("Speed", "Slow")]
    public async Task An_electron_main_process_and_its_page_each_stop_at_their_lines()
    {
        var app = Path.Combine(_dir.Path, "app");
        Directory.CreateDirectory(Path.Combine(app, "dist"));
        File.WriteAllText(Path.Combine(app, "package.json"), """{"name":"sample","main":"main.js"}""");
        File.WriteAllText(Path.Combine(app, "main.js"), """
            const { app, BrowserWindow } = require('electron');
            const path = require('path');
            let ticks = 0;
            function tick() {
              ticks += 1;
              return ticks;
            }
            app.whenReady().then(() => {
              new BrowserWindow({ show: false }).loadFile(path.join(__dirname, 'index.html'));
              setInterval(tick, 200);
            });
            """);
        File.WriteAllText(Path.Combine(app, "index.html"), """<!DOCTYPE html><html><head><title>sample page</title></head><body><p id="count">0</p><script src="dist/page.js"></script></body></html>""");
        // src/page.ts lines 1-6 are generated lines 2-7, after "use strict".
        File.WriteAllText(Path.Combine(app, "dist", "page.js"), """
            "use strict";
            let count = 0;
            function render() {
                count += 1;
                document.getElementById("count").textContent = String(count);
            }
            setInterval(render, 200);
            //# sourceMappingURL=page.js.map
            """);
        File.WriteAllText(Path.Combine(app, "dist", "page.js.map"), """{"version":3,"sources":["../src/page.ts"],"names":[],"mappings":";AAAA;AACA;AACA;AACA;AACA;AACA"}""");

        var info = new ProcessStartInfo(Environment.GetEnvironmentVariable("CORVUS_ELECTRON")!) { RedirectStandardError = true, UseShellExecute = false };
        foreach (var a in new[] { "--inspect=0", "--remote-debugging-port=0", app }) info.ArgumentList.Add(a);
        using var electron = Process.Start(info)!;
        try
        {
            string? main = null, pages = null;
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(60));
            while ((main == null || pages == null) && await electron.StandardError.ReadLineAsync(cts.Token) is { } line)
            {
                if (line.StartsWith("Debugger listening on ", StringComparison.Ordinal)) main = line["Debugger listening on ".Length..].Trim();
                else if (Regex.Match(line, @"DevTools listening on ws://(?<host>[^/]+)/") is { Success: true } m) pages = m.Groups["host"].Value;
            }
            Assert.NotNull(main);
            Assert.NotNull(pages);
            // The rest of stderr is read, so a full pipe never stalls the program.
            _ = electron.StandardError.ReadToEndAsync();

            await _tools.LiveSession("attach", program: "inspector:" + main);
            var mainSet = await _tools.LiveBreak("live-1", "set", at: "main.js:5");
            _output.WriteLine(mainSet);
            Assert.Contains("s1 set at main.js:5 in 2 loaded script(s) ending in main.js", mainSet);
            var mainStop = await _tools.LiveBreak("live-1", wait: true, waitSeconds: 60);
            _output.WriteLine(mainStop);
            Assert.Matches(@"#0 tick main\.js:5:\d+", mainStop);
            await _tools.LiveSession("close", session: "live-1");

            var page = await _tools.LiveSession("attach", program: $"inspector:{pages}#page");
            _output.WriteLine(page);
            Assert.Contains("target page \"sample page\"", page);
            Assert.Contains("s1 set at page.js:4:1 from src/page.ts:3", await _tools.LiveBreak("live-2", "set", at: "src/page.ts:3"));
            var stop = await _tools.LiveBreak("live-2", wait: true, waitSeconds: 60);
            _output.WriteLine(stop);
            Assert.Matches(@"#0 render page\.js:4:\d+ = src/page\.ts:3:1", stop);
            await _tools.LiveSession("close", session: "live-2");
            // Both sessions closed with the program still running.
            Assert.False(electron.HasExited);
        }
        finally
        {
            electron.Kill(entireProcessTree: true);
        }
    }

    /// <summary>CORVUS_ELECTRON: each IPC route of a generated app is counted with its value shape and sites on both sides; an unused listener is reported as not seen.</summary>
    [RequiresRealDataFact("CORVUS_ELECTRON")]
    [Trait("Speed", "Slow")]
    public async Task An_electron_apps_ipc_routes_are_counted_by_shape_and_joined_to_their_code()
    {
        var app = Path.Combine(_dir.Path, "ipc");
        Directory.CreateDirectory(app);
        File.WriteAllText(Path.Combine(app, "package.json"), """{"name":"sample","main":"main.js"}""");
        File.WriteAllText(Path.Combine(app, "main.js"), """
            const { app, BrowserWindow, ipcMain } = require('electron');
            const path = require('path');
            ipcMain.handle('settings:get', async (event, key) => ({ key, value: 42, tags: ['a'] }));
            ipcMain.on('log:write', (event, entry) => {});
            ipcMain.on('unused:ping', () => {});
            app.whenReady().then(() => {
              const win = new BrowserWindow({ show: false, webPreferences: { preload: path.join(__dirname, 'preload.js') } });
              win.loadFile(path.join(__dirname, 'index.html'));
              setInterval(() => win.webContents.send('clock:tick', { at: Date.now() }), 200);
            });
            """);
        File.WriteAllText(Path.Combine(app, "preload.js"), """
            const { contextBridge, ipcRenderer } = require('electron');
            contextBridge.exposeInMainWorld('api', {
              get: (key) => ipcRenderer.invoke('settings:get', key),
              log: (text) => ipcRenderer.send('log:write', { level: 'info', text }),
              onTick: (f) => ipcRenderer.on('clock:tick', (event, value) => f(value)),
            });
            """);
        File.WriteAllText(Path.Combine(app, "index.html"), """<!DOCTYPE html><html><head><title>sample</title></head><body><script src="page.js"></script></body></html>""");
        File.WriteAllText(Path.Combine(app, "page.js"), """
            window.api.onTick(() => {});
            setInterval(async () => { await window.api.get('theme'); window.api.log('saved'); }, 200);
            """);

        var info = new ProcessStartInfo(Environment.GetEnvironmentVariable("CORVUS_ELECTRON")!) { RedirectStandardError = true, UseShellExecute = false };
        foreach (var a in new[] { "--inspect=0", app }) info.ArgumentList.Add(a);
        using var electron = Process.Start(info)!;
        try
        {
            string? main = null;
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(60));
            while (main == null && await electron.StandardError.ReadLineAsync(cts.Token) is { } line)
                if (line.StartsWith("Debugger listening on ", StringComparison.Ordinal)) main = line["Debugger listening on ".Length..].Trim();
            Assert.NotNull(main);
            _ = electron.StandardError.ReadToEndAsync();
            await _tools.LiveSession("attach", program: "inspector:" + main);

            // Messages sent before the first read are not recorded: read until every route has been seen.
            LiveIpcLedger ledger;
            var until = DateTime.UtcNow.AddSeconds(30);
            while ((ledger = await _service.IpcAsync(_service.Get("live-1"), default)).Rows.Count(r => r.Count > 0) < 4 && DateTime.UtcNow < until)
                await Task.Delay(300);
            var text = await _tools.LiveSession("ipc", session: "live-1");
            _output.WriteLine(text);

            Assert.Equal(app, ledger.App);
            var seen = ledger.Rows.Where(r => r.Count > 0).Select(r => $"{r.Direction} {r.Kind} {r.Channel} {r.Shape}").Order(StringComparer.Ordinal);
            Assert.Equal(
            [
                "main-to-renderer invoke-result settings:get {key:string,tags:[string],value:number}",
                "main-to-renderer send clock:tick ({at:number})",
                "renderer-to-main invoke settings:get (string)",
                "renderer-to-main send log:write ({level:string,text:string})",
            ], seen.Where(s => !s.StartsWith("main-to-renderer invoke-error", StringComparison.Ordinal)));
            var invoke = ledger.Rows.Single(r => r.Kind == "invoke");
            Assert.Matches(@"^main listener main\.js:3:\d+ \(ipcMain\.handle\); renderer sender preload\.js:3:\d+ \(ipcRenderer\.invoke\)$", invoke.Code);
            var tick = ledger.Rows.Single(r => r.Channel == "clock:tick" && r.Count > 0);
            Assert.Matches(@"^main sender main\.js:9:\d+ \(webContents\.send\); renderer listener preload\.js:5:\d+ \(ipcRenderer\.on\)$", tick.Code);
            var unused = ledger.Rows.Single(r => r.Channel == "unused:ping");
            Assert.Equal((0, "renderer-to-main"), (unused.Count, unused.Direction));
            Assert.Matches(@"^main listener main\.js:5:\d+ \(ipcMain\.on\); no renderer sender read$", unused.Code);
            Assert.Contains("value shapes only, never values", text);
            Assert.DoesNotContain("theme", text);

            // The recorder keeps counting between reads.
            var before = invoke.Count;
            await Task.Delay(1000);
            Assert.True((await _service.IpcAsync(_service.Get("live-1"), default)).Rows.Single(r => r.Kind == "invoke").Count > before);
            await _tools.LiveSession("close", session: "live-1");
            Assert.False(electron.HasExited);
        }
        finally
        {
            electron.Kill(entireProcessTree: true);
        }
    }

    private string Write()
    {
        Directory.CreateDirectory(Path.Combine(_dir.Path, "src"));
        Directory.CreateDirectory(Path.Combine(_dir.Path, "dist"));
        File.WriteAllText(Path.Combine(_dir.Path, "src", "app.ts"), Original);
        File.WriteAllText(Path.Combine(_dir.Path, "dist", "app.js.map"), Map);
        var js = Path.Combine(_dir.Path, "dist", "app.js");
        File.WriteAllText(js, Generated);
        return js;
    }

    /// <summary>node --inspect-brk=0 on a script, its WebSocket URL read from the line it writes to stderr.</summary>
    private sealed partial class Node : IAsyncDisposable
    {
        private readonly Process _process;
        private readonly Task<string> _stdout;

        private Node(Process process, string webSocket)
        {
            _process = process;
            WebSocket = webSocket;
            _stdout = process.StandardOutput.ReadToEndAsync();
        }

        public string WebSocket { get; }

        public static async Task<Node> StartAsync(string script, TempDir dir)
        {
            var exe = Environment.GetEnvironmentVariable("CORVUS_NODE") is { Length: > 0 } n ? n : "node";
            var info = new ProcessStartInfo(exe) { RedirectStandardError = true, RedirectStandardOutput = true, UseShellExecute = false, WorkingDirectory = dir.Path };
            info.ArgumentList.Add("--inspect-brk=0");
            info.ArgumentList.Add(script);
            var process = Process.Start(info)!;
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
            while (await process.StandardError.ReadLineAsync(cts.Token) is { } line)
                if (Listening().Match(line) is { Success: true } m) return new Node(process, m.Value);
            process.Kill();
            throw new InvalidOperationException("node wrote no inspector URL");
        }

        /// <summary>The program's output lines once it ends (within 30 s).</summary>
        public async Task<string[]> OutputAsync()
        {
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
            await _process.WaitForExitAsync(cts.Token);
            return (await _stdout).Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        }

        public ValueTask DisposeAsync()
        {
            if (!_process.HasExited) _process.Kill();
            _process.Dispose();
            return ValueTask.CompletedTask;
        }

        [GeneratedRegex(@"ws://\S+")]
        private static partial Regex Listening();
    }
}
