using System.Net;
using System.Net.WebSockets;
using System.Text;
using System.Text.Json.Nodes;
using Corvus.Core;
using Corvus.Native.Providers.Live.Inspector;
using Corvus.Services;
using Corvus.Tools;

namespace Corvus.Tests;

/// <summary>Sessions on a browser page through <c>cdp:</c>, against a loopback endpoint that speaks the documented DevTools messages.</summary>
public sealed class LiveCdpTests : IDisposable
{
    private readonly AssemblyWorkspace _workspace = new();
    private readonly LiveSessionService _service;
    private readonly LiveSessionTools _tools;
    private readonly FakeBrowser _browser = new();
    private readonly string _dir = Directory.CreateTempSubdirectory("corvus-cdp-").FullName;

    public LiveCdpTests()
    {
        _service = new LiveSessionService(_workspace, new NativeCodeService(_workspace, SharedCodeIndex.Options()));
        _tools = new LiveSessionTools(new ServerOptions { AllowLiveAttach = true }, _service, results: new ResultStore(ResultCacheOptions.MemoryOnly));
    }

    public void Dispose()
    {
        _service.Dispose();
        _workspace.Dispose();
        _browser.Dispose();
        try { Directory.Delete(_dir, true); } catch (IOException) { }
    }

    [Fact]
    public async Task A_cdp_endpoint_resolves_a_page_and_skips_other_targets()
    {
        var target = await InspectorEndpoint.ResolveAsync($"cdp:{_browser.Port}", default);
        Assert.Equal(("page", "p1"), (target.Type, target.Id));
    }

    [Fact]
    public async Task A_cdp_page_is_selected_by_title_or_url()
    {
        Assert.Equal("p2", (await InspectorEndpoint.ResolveAsync($"cdp:{_browser.Port}#Second", default)).Id);
        Assert.Equal("p2", (await InspectorEndpoint.ResolveAsync($"cdp:{_browser.Port}#/second.html", default)).Id);
    }

    [Fact]
    public async Task A_cdp_endpoint_does_not_select_a_service_worker()
    {
        var e = await Assert.ThrowsAsync<ToolError>(() => InspectorEndpoint.ResolveAsync($"cdp:{_browser.Port}#worker", default));
        Assert.Contains("none matching 'worker' among its pages", e.Message);
    }

    [Theory]
    [InlineData("cdp:192.168.1.5:9222", "not a loopback address")]
    [InlineData("cdp:ws://10.0.0.2:9222/devtools/page/p1", "not a loopback address")]
    [InlineData("cdp:http", "is not a port")]
    public async Task A_cdp_endpoint_off_this_machine_or_without_a_port_is_refused(string program, string reason)
    {
        var e = await Assert.ThrowsAsync<ToolError>(() => InspectorEndpoint.ResolveAsync(program, default));
        Assert.Contains(reason, e.Message);
    }

    [Fact]
    public async Task A_page_session_lists_scripts_sets_a_stop_point_and_reports_console_output()
    {
        var opened = await _tools.LiveSession("attach", program: $"cdp:{_browser.Port}");
        Assert.Contains("(inspector)", opened);
        var status = await _tools.LiveSession("status", session: "live-1");
        Assert.Contains("inspector target page \"First\"", status);
        Assert.Contains("main.js", status);
        var refused = await Assert.ThrowsAsync<ToolError>(() => _tools.LiveSession("snapshot", session: "live-1"));
        Assert.Contains("live-1 is a browser page session", refused.Message);

        var set = await _tools.LiveBreak("live-1", "set", at: "main.js:3");
        Assert.Contains("main.js:3", set);
        await _browser.PauseAtAsync("1", 2);
        var stop = await _tools.LiveBreak("live-1", wait: true, waitSeconds: 30);
        Assert.Contains("#0 tick main.js:3", stop);

        await _tools.LiveBreak("live-1", "continue");
        await _browser.ConsoleAsync("log", "ready");
        Assert.Contains("console.log: ready", await WaitForAsync(() => _tools.LiveEvents("live-1", kind: "output"), "ready"));
        await _tools.LiveSession("close", session: "live-1");
        Assert.Contains("Debugger.disable", _browser.Received);
    }

    [Fact]
    public async Task A_page_session_reports_called_functions_from_precise_coverage()
    {
        await _tools.LiveSession("attach", program: $"cdp:{_browser.Port}");
        Assert.Contains("no coverage is running", (await Assert.ThrowsAsync<ToolError>(() => _tools.LiveSession("coverage", session: "live-1"))).Message);
        Assert.Contains("coverage started", await _tools.LiveSession("coverage", session: "live-1", modules: "start"));
        var taken = await _tools.LiveSession("coverage", session: "live-1", modules: "take");
        Assert.Contains("2 function(s) called", taken);
        Assert.Contains("main.js:2 tick x3", taken);
        Assert.Contains("unknown:unknown (anonymous) x1", taken);
        Assert.DoesNotContain("idle", taken);
        Assert.Contains("coverage stopped", await _tools.LiveSession("coverage", session: "live-1", modules: "stop"));
        Assert.Contains("Profiler.startPreciseCoverage", _browser.Received);
        Assert.Contains("Profiler.stopPreciseCoverage", _browser.Received);
    }

    [Fact]
    public async Task A_page_session_lists_listeners_with_their_handler_positions()
    {
        await _tools.LiveSession("attach", program: $"cdp:{_browser.Port}");
        var listed = await _tools.LiveSession("listeners", session: "live-1");
        Assert.Contains("1 listener(s) on 3 element(s)", listed);
        Assert.Contains("click body#app > div.box.wide > button http://localhost/main.js:7 capture", listed);
        Assert.DoesNotContain("cut at", listed);
        var status = await _tools.LiveSession("status", session: "live-1");
        Assert.Contains("initiator: http://localhost/index.html:4", status);
    }

    [Fact]
    public async Task A_listener_walk_past_its_element_bound_names_the_cut()
    {
        _browser.ExtraElements = 2100;
        await _tools.LiveSession("attach", program: $"cdp:{_browser.Port}");
        var listed = await _tools.LiveSession("listeners", session: "live-1");
        Assert.Contains("on 2000 element(s)", listed);
        Assert.Contains("Walk cut at 2000 elements", listed);
    }

    [Fact]
    public async Task A_node_session_refuses_listeners_with_a_reason()
    {
        await _tools.LiveSession("attach", program: $"inspector:{_browser.Port}#n1");
        var e = await Assert.ThrowsAsync<ToolError>(() => _tools.LiveSession("listeners", session: "live-1"));
        Assert.Contains("a Node or Electron main process has none", e.Message);
        Assert.DoesNotContain("Unknown", e.Message);
    }

    [Fact]
    public async Task A_page_screenshot_is_written_with_its_hash()
    {
        await _tools.LiveSession("attach", program: $"cdp:{_browser.Port}");
        var path = Path.Combine(_dir, "page.png");
        var saved = await _tools.LiveSession("screenshot", session: "live-1", outputPath: path);
        var bytes = File.ReadAllBytes(path);
        Assert.Equal(FakeBrowser.Image, bytes);
        Assert.Contains($"size: {bytes.Length} bytes", saved);
        Assert.Contains("sha256: " + Convert.ToHexStringLower(System.Security.Cryptography.SHA256.HashData(bytes)), saved);
        Assert.Contains("Page.captureScreenshot", _browser.Received);
    }

    [Fact]
    public async Task A_screenshot_path_through_a_link_is_refused()
    {
        await _tools.LiveSession("attach", program: $"cdp:{_browser.Port}");
        var target = Path.Combine(_dir, "target.png");
        File.WriteAllBytes(target, [1]);
        var link = Path.Combine(_dir, "link.png");
        File.CreateSymbolicLink(link, target);
        var e = await Assert.ThrowsAsync<ToolError>(() => _tools.LiveSession("screenshot", session: "live-1", outputPath: link, overwrite: true));
        Assert.Contains("link", e.Message);
        Assert.Equal([1], File.ReadAllBytes(target));
        Assert.DoesNotContain("Page.captureScreenshot", _browser.Received);
    }

    [Fact]
    public async Task A_page_without_the_tool_api_reports_not_offered()
    {
        await _tools.LiveSession("attach", program: $"cdp:{_browser.Port}");
        Assert.Contains("tools not offered", await _tools.LiveSession("page_tools", session: "live-1"));
        _browser.ModelContext = "throws";
        Assert.Contains("tools unknown: registry failed", await _tools.LiveSession("page_tools", session: "live-1"));
        _browser.ModelContext = "offered";
        var listed = await _tools.LiveSession("page_tools", session: "live-1");
        Assert.Contains("1 tool(s)", listed);
        Assert.Contains("tool search | Find items | schema 42", listed);
    }

    [Fact]
    public async Task Two_page_reads_compare_by_script_hash_and_listener_row()
    {
        await _tools.LiveSession("attach", program: $"cdp:{_browser.Port}");
        var first = ResultId(await _tools.LiveSession("page_state", session: "live-1"));
        await _tools.LiveSession("close", session: "live-1");
        _browser.ScriptHash = "h1b";
        _browser.ListenerLine = 9;
        _browser.ModelContext = "offered";
        await _tools.LiveSession("attach", program: $"cdp:{_browser.Port}");
        var second = ResultId(await _tools.LiveSession("page_state", session: "live-2"));
        var diff = await _tools.LiveSession("page_diff", arguments: [first, second]);
        Assert.Contains("changed script http://localhost/main.js: h1 -> h1b", diff);
        Assert.Contains("added listener click body#app > div.box.wide > button http://localhost/main.js:10 capture", diff);
        Assert.Contains("removed listener click body#app > div.box.wide > button http://localhost/main.js:7 capture", diff);
        Assert.Contains("added tool search", diff);
        Assert.Contains("removed tools not offered", diff);
        Assert.Contains("no difference", await _tools.LiveSession("page_diff", arguments: [first, first]));
    }

    private static string ResultId(string text) => System.Text.RegularExpressions.Regex.Match(text, "result: (r-[0-9a-f]+)").Groups[1].Value;

    private static async Task<string> WaitForAsync(Func<Task<string>> read, string text)
    {
        var until = DateTime.UtcNow.AddSeconds(30);
        while (true)
        {
            var value = await read();
            if (value.Contains(text, StringComparison.Ordinal) || DateTime.UtcNow > until) return value;
            await Task.Delay(100);
        }
    }

    /// <summary>A loopback browser: /json/list names a service worker and two pages; the first socket answers the commands a page session sends.</summary>
    private sealed class FakeBrowser : IDisposable
    {
        private readonly HttpListener _http = new();
        private readonly CancellationTokenSource _stop = new();
        private readonly List<string> _received = [];
        private readonly TaskCompletionSource _connected = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private WebSocket? _socket;

        public FakeBrowser()
        {
            using var probe = new System.Net.Sockets.TcpListener(IPAddress.Loopback, 0);
            probe.Start();
            Port = ((IPEndPoint)probe.LocalEndpoint).Port;
            probe.Stop();
            _http.Prefixes.Add($"http://127.0.0.1:{Port}/");
            _http.Start();
            _ = Task.Run(AcceptAsync);
        }

        public int Port { get; }

        /// <summary>Elements added under the body beyond the three the document holds.</summary>
        public int ExtraElements { get; set; }

        /// <summary>Hash the first script reports.</summary>
        public string ScriptHash { get; set; } = "h1";

        /// <summary>Zero-based line of the button listener's handler.</summary>
        public int ListenerLine { get; set; } = 6;

        /// <summary>Null: no tool API; "throws": the registry throws; "offered": one tool.</summary>
        public string? ModelContext { get; set; }

        /// <summary>Bytes the screenshot returns.</summary>
        public static readonly byte[] Image = [0x89, 0x50, 0x4E, 0x47, 1, 2, 3];

        public string Received { get { lock (_received) return string.Join(',', _received); } }

        private string Entry(string id, string type, string title, string url) =>
            new JsonObject { ["id"] = id, ["type"] = type, ["title"] = title, ["url"] = url, ["webSocketDebuggerUrl"] = $"ws://127.0.0.1:{Port}/devtools/page/{id}" }.ToJsonString();

        private async Task AcceptAsync()
        {
            try
            {
                while (!_stop.IsCancellationRequested)
                {
                    var context = await _http.GetContextAsync();
                    if (context.Request.IsWebSocketRequest)
                    {
                        var ws = await context.AcceptWebSocketAsync(null);
                        _socket = ws.WebSocket;
                        _connected.TrySetResult();
                        _ = Task.Run(() => ServeAsync(ws.WebSocket));
                        continue;
                    }
                    var body = Encoding.UTF8.GetBytes("[" + string.Join(',', Entry("w1", "service_worker", "worker", "http://localhost/sw.js"),
                        Entry("p1", "page", "First", "http://localhost/first.html"), Entry("p2", "page", "Second", "http://localhost/second.html"),
                        Entry("n1", "node", "Program", "file:///app/server.js")) + "]");
                    context.Response.ContentType = "application/json";
                    await context.Response.OutputStream.WriteAsync(body);
                    context.Response.Close();
                }
            }
            catch (Exception ex) when (ex is HttpListenerException or ObjectDisposedException or InvalidOperationException) { }
        }

        private async Task ServeAsync(WebSocket ws)
        {
            var buffer = new byte[16 * 1024];
            try
            {
                while (ws.State == WebSocketState.Open)
                {
                    var r = await ws.ReceiveAsync(buffer, _stop.Token);
                    if (r.MessageType == WebSocketMessageType.Close) break;
                    var request = JsonNode.Parse(buffer.AsMemory(0, r.Count).ToArray())!;
                    var method = request["method"]!.GetValue<string>();
                    lock (_received) _received.Add(method);
                    JsonNode result = method switch
                    {
                        "Runtime.evaluate" => Evaluate(request["params"]!["expression"]!.GetValue<string>()),
                        "Page.captureScreenshot" => new JsonObject { ["data"] = Convert.ToBase64String(Image) },
                        "Debugger.setBreakpointByUrl" => new JsonObject
                        {
                            ["breakpointId"] = "bp1",
                            ["locations"] = new JsonArray(new JsonObject { ["scriptId"] = "1", ["lineNumber"] = request["params"]!["lineNumber"]!.GetValue<int>(), ["columnNumber"] = 0 }),
                        },
                        "Debugger.getScriptSource" => new JsonObject { ["scriptSource"] = "// source\nfunction tick() {}\n" },
                        "Profiler.takePreciseCoverage" => Coverage(),
                        "DOM.getDocument" => new JsonObject { ["root"] = Document() },
                        "DOM.resolveNode" => new JsonObject { ["object"] = new JsonObject { ["objectId"] = "o" + request["params"]!["nodeId"]!.GetValue<int>() } },
                        "DOMDebugger.getEventListeners" => Listeners(request["params"]!["objectId"]!.GetValue<string>()),
                        _ => new JsonObject(),
                    };
                    await SendAsync(new JsonObject { ["id"] = request["id"]!.DeepClone(), ["result"] = result });
                    if (method == "Debugger.enable")
                    {
                        await SendAsync(Parsed("1", "http://localhost/main.js", ScriptHash));
                    }
                }
            }
            catch (Exception ex) when (ex is WebSocketException or OperationCanceledException or ObjectDisposedException) { }
        }

        private JsonObject Evaluate(string expression)
        {
            if (!expression.Contains("modelContext", StringComparison.Ordinal))
                return new JsonObject { ["result"] = new JsonObject { ["type"] = "string", ["value"] = "FakeChrome/1.0" } };
            return ModelContext switch
            {
                "throws" => new JsonObject { ["result"] = Value(new JsonObject { ["state"] = "unknown", ["message"] = "registry failed" }) },
                "offered" => new JsonObject
                {
                    ["result"] = Value(new JsonObject
                    {
                        ["state"] = "offered",
                        ["rows"] = new JsonArray(new JsonObject { ["name"] = "search", ["description"] = "Find items", ["schema"] = 42 }),
                    }),
                },
                _ => new JsonObject { ["result"] = Value(new JsonObject { ["state"] = "not offered" }) },
            };
        }

        private static JsonObject Value(JsonObject value) => new() { ["type"] = "object", ["value"] = value };

        // Script 1 is parsed; script 9 is not, and its function reads unknown.
        private static JsonObject Coverage() => new()
        {
            ["result"] = new JsonArray(
                new JsonObject
                {
                    ["scriptId"] = "1",
                    ["functions"] = new JsonArray(Function("tick", 11, 3), Function("idle", 0, 0)),
                },
                new JsonObject { ["scriptId"] = "9", ["functions"] = new JsonArray(Function("", 0, 1)) }),
        };

        private static JsonObject Function(string name, int offset, int count) => new()
        {
            ["functionName"] = name,
            ["isBlockCoverage"] = false,
            ["ranges"] = new JsonArray(new JsonObject { ["startOffset"] = offset, ["endOffset"] = offset + 5, ["count"] = count }),
        };

        private static JsonObject Element(int id, string name, JsonArray? attributes, params JsonObject[] children) => new()
        {
            ["nodeId"] = id,
            ["nodeType"] = 1,
            ["nodeName"] = name,
            ["attributes"] = attributes ?? [],
            ["children"] = new JsonArray(children.Select(c => (JsonNode)c).ToArray()),
        };

        // body#app holds div.box.wide with one button, plus ExtraElements empty divs.
        private JsonObject Document()
        {
            var body = Element(3, "BODY", new JsonArray("id", "app"), Element(4, "DIV", new JsonArray("class", "box wide"), Element(5, "BUTTON", null)));
            var extra = (JsonArray)body["children"]!;
            for (int i = 0; i < ExtraElements; i++) extra.Add(Element(100 + i, "DIV", null));
            return new JsonObject
            {
                ["nodeId"] = 1,
                ["nodeType"] = 9,
                ["nodeName"] = "#document",
                ["children"] = new JsonArray(new JsonObject { ["nodeId"] = 2, ["nodeType"] = 1, ["nodeName"] = "HTML", ["children"] = new JsonArray(body) }),
            };
        }

        private JsonObject Listeners(string objectId) => new()
        {
            ["listeners"] = objectId != "o5" ? new JsonArray() : new JsonArray(new JsonObject
            {
                ["type"] = "click", ["useCapture"] = true, ["passive"] = false, ["once"] = false, ["scriptId"] = "1", ["lineNumber"] = ListenerLine, ["columnNumber"] = 0,
            }),
        };

        private static JsonObject Parsed(string id, string url, string hash) => new()
        {
            ["method"] = "Debugger.scriptParsed",
            ["params"] = new JsonObject
            {
                ["scriptId"] = id, ["url"] = url, ["length"] = 10, ["hash"] = hash,
                ["stackTrace"] = new JsonObject { ["callFrames"] = new JsonArray(new JsonObject { ["functionName"] = "load", ["url"] = "http://localhost/index.html", ["lineNumber"] = 3 }) },
            },
        };

        private async Task SendAsync(JsonObject message) =>
            await _socket!.SendAsync(Encoding.UTF8.GetBytes(message.ToJsonString()), WebSocketMessageType.Text, true, _stop.Token);

        public async Task PauseAtAsync(string script, int line)
        {
            await _connected.Task;
            await SendAsync(new JsonObject
            {
                ["method"] = "Debugger.paused",
                ["params"] = new JsonObject
                {
                    ["reason"] = "other",
                    ["hitBreakpoints"] = new JsonArray("bp1"),
                    ["callFrames"] = new JsonArray(new JsonObject
                    {
                        ["functionName"] = "tick",
                        ["url"] = "",
                        ["location"] = new JsonObject { ["scriptId"] = script, ["lineNumber"] = line, ["columnNumber"] = 4 },
                    }),
                },
            });
        }

        public async Task ConsoleAsync(string type, string text)
        {
            await _connected.Task;
            await SendAsync(new JsonObject
            {
                ["method"] = "Runtime.consoleAPICalled",
                ["params"] = new JsonObject { ["type"] = type, ["args"] = new JsonArray(new JsonObject { ["type"] = "string", ["value"] = text }) },
            });
        }

        public void Dispose()
        {
            _stop.Cancel();
            try { _http.Close(); } catch (ObjectDisposedException) { }
            _socket?.Dispose();
            _stop.Dispose();
        }
    }
}
