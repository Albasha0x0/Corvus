using Corvus.Core;
using Corvus.Services.Web;

namespace Corvus.Tests;

/// <summary>analyze_js view=flow: data flow on the syntax tree, with the alias and crash shapes of REA issues #3535, #3551, #3315, #3536, #3539, #3431 and #3839.</summary>
public sealed class JsFlowTests(Xunit.Abstractions.ITestOutputHelper output) : IDisposable
{
    private readonly TempDir _dir = new();
    public void Dispose() => _dir.Dispose();

    private JsFlowResult Flow(string text, string query, bool back = false, JsFlow.Budget? budget = null, string? path = null)
    {
        var p = JsProgram.Build("app.js", text, [], default)!;
        var r = new JsFlow(p, null, path, default).Run(query, 0, 0, back, 200, budget ?? JsFlow.Budget.Default, default);
        output.WriteLine(Show(r));
        return r;
    }

    private static string Show(JsFlowResult r) =>
        $"{r.Query}: {r.Total} flows, partial {r.Partial ?? "no"}\n" +
        string.Join("\n", r.Flows.Take(30).Select(f => f.End + ": " + string.Join(" | ", f.Steps.Select(s => $"{s.Kind} {s.Text} @{s.Site}" +
            (s.Module != null ? $" [m {s.Module}]" : "") + (s.Endpoint != null ? $" E[{s.Endpoint.Verb} {s.Endpoint.Url} {s.Endpoint.Client}]" : "") + (s.Link != null ? $" L[{s.Link}]" : "")))));

    private static JsFlowPath Ending(JsFlowResult r, string end, string lastText) =>
        r.Flows.FirstOrDefault(f => f.End == end && f.Steps[^1].Text.Contains(lastText, StringComparison.Ordinal))
        ?? throw new Xunit.Sdk.XunitException($"no {end} flow ending in '{lastText}':\n{Show(r)}");

    /// <summary>Over MCP: every analyze_js view passes the argument check, and view=flow carries its structured record.</summary>
    [Fact]
    public async Task Every_view_passes_the_argument_check()
    {
        var js = _dir.File("app.js");
        File.WriteAllText(js, "function get(path) { return fetch(\"https://api.example.com\" + path); }\nget(\"/a\");");
        await using var server = await InProcessServer.StartAsync();
        foreach (var view in new[] { "endpoints", "secrets", "runtime", "flow", "origins" })
        {
            var r = await server.Client.CallToolAsync("analyze_js", new Dictionary<string, object?> { ["path"] = js, ["view"] = view, ["query"] = view is "flow" or "origins" ? "\"/a\"" : null });
            var text = string.Concat(r.Content.OfType<ModelContextProtocol.Protocol.TextContentBlock>().Select(b => b.Text));
            Assert.True(r.IsError != true, $"{view}: {text}");
            if (view == "flow")
                Assert.Equal("sink", r.StructuredContent!.Value.GetProperty("flow").GetProperty("flows")[0].GetProperty("end").GetString());
        }
    }

    /// <summary>A literal through a URL wrapper's parameter and a concatenation into fetch; the sink carries view=endpoints' row.</summary>
    [Fact]
    public void Literal_reaches_fetch_through_a_wrapper_with_its_endpoint()
    {
        var r = Flow("""
            const BASE = "https://api.example.com/v1";
            function getJson(path) { return fetch(BASE + path).then(r => r.json()); }
            async function load() { const data = await getJson("/settings"); render(data.items); }
            """, "\"/settings\"");
        var f = Ending(r, "sink", "fetch argument 1 (network)");
        Assert.Equal(["seed", "argument", "through", "sink"], f.Steps.Select(s => s.Kind));
        Assert.Equal("1 to parameter path of getJson", f.Steps[1].Text);
        Assert.Equal("2:33", f.Steps[^1].Site);
        Assert.Equal("GET https://api.example.com/v1/settings fetch via getJson", $"{f.Steps[^1].Endpoint!.Verb} {f.Steps[^1].Endpoint!.Url} {f.Steps[^1].Endpoint!.Client}");
        Assert.Null(r.Partial);
    }

    /// <summary>The tool: text with each step's position, the same endpoint record as view=endpoints, arguments checked.</summary>
    [Fact]
    public void Analyze_js_view_flow_joins_the_endpoint_rows()
    {
        var js = _dir.File("app.js");
        File.WriteAllText(js, """
            const BASE = "https://api.example.com/v1";
            function getJson(path) { return fetch(BASE + path); }
            getJson("/settings");
            """);
        var tools = new Corvus.Tools.WebTools(new OutputPager(new ServerOptions()));
        var text = tools.AnalyzeJs(js, "origins", query: "getJson");
        Assert.Contains("origins of getJson: 1 seed(s)", text, StringComparison.Ordinal);
        Assert.Contains("<- argument parameter path of getJson from getJson(\"/settings\") at 3:9", text, StringComparison.Ordinal);
        var forward = tools.AnalyzeJs(js, "flow", query: "\"/settings\"");
        Assert.Contains("sink fetch argument 1 (network) at 2:33; endpoint GET https://api.example.com/v1/settings [fetch via getJson]", forward, StringComparison.Ordinal);
        File.WriteAllText(js + ".map", """{"version":3,"sources":["src/app.ts"],"names":[],"mappings":"AAAA;AACA;AACA"}""");
        Assert.Contains("sink fetch argument 1 (network) at 2:33 <- src/app.ts:2:1", tools.AnalyzeJs(js, "flow", query: "\"/settings\""), StringComparison.Ordinal);
        var rows = new List<Corvus.Services.Analysis.Endpoints.CodeEndpoint>();
        var program = JsAnalysis.Program(js, default);
        Corvus.Services.Analysis.Endpoints.JsEndpoints.Scan(program, program.Path, rows, default);
        var step = new JsFlow(program, null, js, default).Run("\"/settings\"", 0, 0, false, 10, JsFlow.Budget.Default, default).Flows[0].Steps[^1];
        Assert.Equal(JsAnalysis.Endpoint(rows.Single(e => e.Client.Contains(" via ", StringComparison.Ordinal)), null), step.Endpoint);
        Assert.Contains("sink fetch argument 1 (network) at 2:33", tools.AnalyzeJs(js, "flow", line: 3, column: 9), StringComparison.Ordinal);
        Assert.Equal(ErrorCode.InvalidArgument, Assert.Throws<ToolError>(() => tools.AnalyzeJs(js, "flow")).Code);
        Assert.Equal(ErrorCode.NotFound, Assert.Throws<ToolError>(() => tools.AnalyzeJs(js, "flow", query: "nothingHere")).Code);
    }

    /// <summary>Back from fetch: the URL's parts to the constant and to the caller's literal.</summary>
    [Fact]
    public void Sinks_back_reach_their_origins()
    {
        var r = Flow("""
            const BASE = "https://api.example.com/v1";
            function getJson(path) { return fetch(BASE + path); }
            getJson("/settings");
            """, "sink:fetch", back: true);
        Assert.Equal("BASE = \"https://api.example.com/v1\"", Ending(r, "origin", "literal \"https://api.example.com/v1\"").Steps[^2].Text);
        Assert.StartsWith("parameter path of getJson from getJson(", Ending(r, "origin", "literal \"/settings\"").Steps[^2].Text);
    }

    /// <summary>A parameter captured by a closure, nested in request options; a promise's resolve into a WebSocket send.</summary>
    [Fact]
    public void Closures_and_promises_carry_values()
    {
        var r = Flow("""
            function make(token) { return () => fetch("/api", { headers: { auth: token } }); }
            const go = make(localStorage.getItem("t")); go();
            const ws = new WebSocket("wss://push.example.com");
            function later(secret) { new Promise(r => r(secret)).then(v => ws.send(v)); }
            later(go);
            """, "token");
        var f = Ending(r, "sink", "fetch argument 2 (network)");
        Assert.Contains(f.Steps, s => s.Kind == "closure" && s.Text.StartsWith("token read inside", StringComparison.Ordinal));
        var p = Ending(Flow("""
            const ws = new WebSocket("wss://push.example.com");
            function later(secret) { new Promise(r => r(secret)).then(v => ws.send(v)); }
            """, "secret"), "sink", "WebSocket.send argument 1 (network)");
        Assert.Equal(["seed", "closure", "promise", "argument", "sink"], p.Steps.Select(s => s.Kind));
        Assert.Equal("2:16", p.Steps[0].Site);
    }

    /// <summary>#3551 and #3315: a webpack export getter under renamed factory parameters, read in another module and fetched.</summary>
    [Fact]
    public void Webpack_export_getters_cross_modules()
    {
        var r = Flow("""
            (()=>{var o={
            10:(t,e,r)=>{r.d(e,{U:()=>a});const a="https://api.example.com/x"},
            20:(t,e,r)=>{const s=r(10);fetch(s.U)}
            };})();
            """, "\"api.example.com\"");
        var f = Ending(r, "sink", "fetch argument 1");
        Assert.Contains(f.Steps, s => s.Kind == "export" && s.Text == "U of module 10");
        Assert.Equal("20", f.Steps[^1].Module);
        Assert.Contains(Flow("""
            (()=>{var o={10:(t,e,r)=>{t.exports=function(u){return fetch(u)}},20:(t,e,r)=>{const g=r(10);g("/m")}};})();
            """, "\"/m\"").Flows, x => x.End == "sink");
    }

    /// <summary>#3431: node: prefixed fs writes and synchronous child_process calls are sinks; an environment variable is an explicit unknown.</summary>
    [Fact]
    public void Node_prefixed_fs_and_sync_child_process_sinks()
    {
        var r = Flow("""
            import { writeFileSync } from "node:fs";
            import { execSync } from "node:child_process";
            const target = process.env.HOME + "/.bashrc";
            writeFileSync(target, "x");
            execSync("id");
            """, "sinks", back: true);
        Assert.Contains(r.Flows, f => f.Steps[0].Text == "fs.writeFileSync argument 1 (fs-write)" && f.End == "unknown" && f.Steps[^1].Text == "the global process.env.HOME");
        Assert.Contains(r.Flows, f => f.Steps[0].Text == "child_process.execSync argument 1 (child_process)" && f.Steps[^1].Text == "literal \"id\"");
    }

    /// <summary>#3535: esbuild's __require shim and __toESM; #3539: a channel wrapper; the IPC sink links to the channel's pairing across the app's scripts.</summary>
    [Fact]
    public void Ipc_sinks_link_to_the_channel_pairing()
    {
        File.WriteAllText(_dir.File("package.json"), "{}");
        File.WriteAllText(_dir.File("main.js"), """
            var import_electron = __toESM(__require("electron"));
            import_electron.ipcMain.handle("wrap:get", () => 1);
            """);
        var preload = _dir.File("preload.js");
        File.WriteAllText(preload, """
            var e = __require("electron");
            function call(channel, payload) { return e.ipcRenderer.invoke(channel, payload); }
            const get = (key) => call("wrap:get", key);
            """);
        var p = JsProgram.Build("preload.js", File.ReadAllText(preload), [], default)!;
        var r = new JsFlow(p, null, preload, default).Run("\"wrap:get\"", 0, 0, false, 50, JsFlow.Budget.Default, default);
        output.WriteLine(Show(r));
        var sink = Ending(r, "sink", "ipcRenderer.invoke argument 1 (ipc)").Steps[^1];
        Assert.StartsWith("ipcRenderer.invoke via call wrap:get: paired with ipcMain.handle at main.js:2:", sink.Link);
    }

    /// <summary>A contextBridge method's parameter: an unknown that names the bridge key and the page calls the Electron graph pairs with it.</summary>
    [Fact]
    public void Bridge_parameters_name_the_page_calls()
    {
        File.WriteAllText(_dir.File("package.json"), "{}");
        var preload = _dir.File("preload.js");
        File.WriteAllText(preload, """
            const { contextBridge, ipcRenderer } = require("electron");
            contextBridge.exposeInMainWorld("api", { invoke: (ch, ...args) => ipcRenderer.invoke(ch, ...args) });
            """);
        File.WriteAllText(_dir.File("page.js"), """document.onclick = () => window.api.invoke("d:y", 1);""");
        var p = JsProgram.Build("preload.js", File.ReadAllText(preload), [], default)!;
        var r = new JsFlow(p, null, preload, default).Run("sink:ipc", 0, 0, true, 50, JsFlow.Budget.Default, default);
        output.WriteLine(Show(r));
        var leaf = Ending(r, "unknown", "parameter ch of api.invoke, exposed to the page by contextBridge").Steps[^1];
        Assert.StartsWith("called by the page at page.js:1:", leaf.Link);
    }

    /// <summary>#3536: window options built from constants reach new BrowserWindow.</summary>
    [Fact]
    public void Window_options_from_constants_reach_the_window()
    {
        var r = Flow("""
            const path = require("path");
            const { BrowserWindow } = require("electron");
            const PRELOAD = path.join(__dirname, "preload.js");
            const opts = { width: 800, webPreferences: { preload: PRELOAD } };
            new BrowserWindow(opts).loadURL("app://index.html");
            """, "PRELOAD");
        Assert.Equal("new BrowserWindow argument 1 (window)", Ending(r, "sink", "new BrowserWindow").Steps[^1].Text);
    }

    /// <summary>#3839: getters reading this[symbol] fields stay one unknown each, not a combinatorial expansion.</summary>
    [Fact]
    [Trait(PerfBudget.Trait, PerfBudget.Timing)]
    public void Computed_receiver_getters_stay_bounded()
    {
        var names = Enumerable.Range(0, 300).Select(i => "g" + i).ToList();
        var cls = "const M = Symbol(); class Request { constructor(init) { this[M] = init; }\n" +
                  string.Join("\n", names.Select((n, i) => $"  get {n}() {{ return P.brandCheck(this, U), this[M].{n} ? this[M].{n}.stream : this.{names[(i + 1) % names.Count]}; }}")) +
                  "\n}\nconst req = new Request(globalThis.init);\n" + string.Join("\n", names.Select(n => $"fetch(req.{n});"));
        var sw = System.Diagnostics.Stopwatch.StartNew();
        var r = Flow(cls, "sinks", back: true);
        PerfBudget.Check(sw.Elapsed.TotalSeconds < 5, $"{sw.Elapsed.TotalSeconds:0.0} s", output);
        // About seven steps per getter; an expansion through the getter chain grows with its square or worse.
        Assert.InRange(r.Steps, 1, 20 * names.Count);
        Assert.Null(r.Partial);
        Assert.Contains(r.Flows, f => f.End == "unknown" && f.Steps[^1].Link == "dynamic property");
    }

    /// <summary>A step budget stops the walk and says so.</summary>
    [Fact]
    public void Budget_marks_partial_results()
    {
        var code = string.Join("\n", Enumerable.Range(0, 200).Select(i => $"function f{i}(x) {{ return f{i + 1}(x + 1); }}")) + "\nfunction f200(x) { return fetch(x); }\nf0(\"/a\");";
        var r = Flow(code, "\"/a\"", budget: new JsFlow.Budget(50, TimeSpan.FromSeconds(10), long.MaxValue));
        Assert.StartsWith("step budget (50)", r.Partial);
        Assert.DoesNotContain(r.Flows, f => f.End == "sink");
        Assert.Contains(Flow(code, "\"/a\"").Flows, f => f.End == "sink");
    }

    /// <summary>Mutated scripts: flows, a not-found error or a parse failure, never another exception.</summary>
    [Fact]
    [FuzzEntry(typeof(JsFlow))]
    public void Fuzzed_scripts_never_throw()
    {
        var seed = System.Text.Encoding.UTF8.GetBytes("""
            const {ipcRenderer:i}=require("electron");class A{get x(){return this[M].y}m(u){return fetch(u)}}
            function w(c,p){return i.invoke(c,p)}w("a:b",new A().m("/x"));(()=>{var o={1:(t,e,r)=>{r.d(e,{U:()=>"/u"})},2:(t,e,r)=>{fetch(r(1).U)}}})();
            new Promise(r=>r(1)).then(v=>eval(v));
            """);
        var failures = FormatFuzz.Run(seed, b =>
        {
            var p = JsProgram.Build("app.js", System.Text.Encoding.UTF8.GetString(b), [], default);
            if (p == null) return;
            var flow = new JsFlow(p, null, null, default);
            foreach (var (q, back) in new[] { ("sinks", true), ("\"a\"", false), ("w", false), ("x", true) })
                try { flow.Run(q, 0, 0, back, 20, new JsFlow.Budget(5000, TimeSpan.FromSeconds(5), long.MaxValue), default); }
                catch (ToolError e) when (e.Code == ErrorCode.NotFound) { }
        }, 300);
        Assert.True(failures.Count == 0, string.Join("\n", failures.Take(20)));
    }
}

/// <summary>
/// Data flow on pdf.js from the pdfjs-dist npm package: every effect sink traced back, timed and with the bytes the walk
/// allocates. wasm/openjpeg_nowasm_fallback.js (5.3.x, 462,316 bytes) is the file of REA #2498 (84 s, 1.24 GB there).
/// </summary>
[Trait("Speed", "Slow")]
[Trait("Data", "Real")]
public sealed class JsFlowRealTests(Xunit.Abstractions.ITestOutputHelper output)
{
    [RequiresRealDataFact(RealData.Pdfjs)]
    [Trait(PerfBudget.Trait, PerfBudget.Timing)]
    public void Pdfjs_sinks_back_within_budget()
    {
        var files = Directory.EnumerateFiles(RealData.Path(RealData.Pdfjs), "*.*js", new EnumerationOptions { RecurseSubdirectories = true, MaxRecursionDepth = 6 })
            .Where(f => Path.GetFileName(f) is "openjpeg_nowasm_fallback.js" or "pdf.min.mjs" or "pdf.mjs" or "pdf.worker.min.mjs" or "pdf.worker.mjs").OrderBy(f => f, StringComparer.Ordinal).ToList();
        Assert.NotEmpty(files);
        foreach (var file in files)
        {
            GC.Collect();
            long before = GC.GetAllocatedBytesForCurrentThread();
            var sw = System.Diagnostics.Stopwatch.StartNew();
            var program = JsAnalysis.Program(file, default);
            var parsed = sw.Elapsed.TotalSeconds;
            var flow = new JsFlow(program, JsAnalysis.TryMap(file), null, default);
            var indexed = sw.Elapsed.TotalSeconds;
            var r = flow.Run("sinks", 0, 0, true, 50, JsFlow.Budget.Default, default);
            var walked = sw.Elapsed.TotalSeconds;
            // the wider walks: every string literal (the first 500) forward, and the Emscripten Module object forward
            var literals = flow.Run("\"\"", 0, 0, false, 500, JsFlow.Budget.Default, default);
            var module = program.Text.Contains("var Module=", StringComparison.Ordinal) ? flow.Run("Module", 0, 0, false, 50, JsFlow.Budget.Default, default) : null;
            var seconds = sw.Elapsed.TotalSeconds;
            var mb = (GC.GetAllocatedBytesForCurrentThread() - before) / 1048576.0;
            output.WriteLine($"{Path.GetRelativePath(RealData.Path(RealData.Pdfjs), file)}: {new FileInfo(file).Length:N0} bytes; parse {parsed:0.00} s, index {indexed - parsed:0.00} s, " +
                             $"sinks back {walked - indexed:0.00} s, literals and Module forward {seconds - walked:0.00} s, total {seconds:0.00} s, {mb:0} MB allocated; " +
                             $"sinks: {r.Seeds} argument(s), {r.Steps:N0} steps, {r.Total} flows ({r.Origins} origins, {r.Unknowns} unknown), partial {r.Partial ?? "no"}; " +
                             $"literals: {literals.Seeds} seeds, {literals.Steps:N0} steps, {literals.Sinks} to a sink, {literals.Unknowns} unknown, partial {literals.Partial ?? "no"}" +
                             (module != null ? $"; Module: {module.Steps:N0} steps, {module.Sinks} to a sink, {module.Unknowns} unknown, partial {module.Partial ?? "no"}" : ""));
            foreach (var f in r.Flows.Take(5)) output.WriteLine("    " + string.Join(" <- ", f.Steps.Select(s => $"{s.Kind} {s.Text} {s.Site}")));
            foreach (var g in literals.Flows.Where(f => f.End != "sink").GroupBy(f => f.Steps[^1].Link ?? f.Steps[^1].Text.Split(' ')[0]).OrderByDescending(g => g.Count()).Take(6))
                output.WriteLine($"    literal flows ending '{g.Key}': {g.Count()}, e.g. {g.First().Steps[^1].Text}");
            if (Path.GetFileName(file) == "openjpeg_nowasm_fallback.js")
            {
                PerfBudget.Check(seconds < 2, $"{seconds:0.00} s", output);
                Assert.True(mb < 200, $"{mb:0} MB");
                Assert.Null(r.Partial ?? literals.Partial ?? module?.Partial);
            }
        }
    }
}
