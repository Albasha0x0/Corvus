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

    public LiveCdpTests()
    {
        _service = new LiveSessionService(_workspace, new NativeCodeService(_workspace, SharedCodeIndex.Options()));
        _tools = new LiveSessionTools(new ServerOptions { AllowLiveAttach = true }, _service);
    }

    public void Dispose()
    {
        _service.Dispose();
        _workspace.Dispose();
        _browser.Dispose();
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
                        Entry("p1", "page", "First", "http://localhost/first.html"), Entry("p2", "page", "Second", "http://localhost/second.html")) + "]");
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
                        "Runtime.evaluate" => new JsonObject { ["result"] = new JsonObject { ["type"] = "string", ["value"] = "FakeChrome/1.0" } },
                        "Debugger.setBreakpointByUrl" => new JsonObject
                        {
                            ["breakpointId"] = "bp1",
                            ["locations"] = new JsonArray(new JsonObject { ["scriptId"] = "1", ["lineNumber"] = request["params"]!["lineNumber"]!.GetValue<int>(), ["columnNumber"] = 0 }),
                        },
                        "Debugger.getScriptSource" => new JsonObject { ["scriptSource"] = "// source\n" },
                        _ => new JsonObject(),
                    };
                    await SendAsync(new JsonObject { ["id"] = request["id"]!.DeepClone(), ["result"] = result });
                    if (method == "Debugger.enable")
                    {
                        await SendAsync(Parsed("1", "http://localhost/main.js"));
                    }
                }
            }
            catch (Exception ex) when (ex is WebSocketException or OperationCanceledException or ObjectDisposedException) { }
        }

        private static JsonObject Parsed(string id, string url) => new()
        {
            ["method"] = "Debugger.scriptParsed",
            ["params"] = new JsonObject { ["scriptId"] = id, ["url"] = url, ["length"] = 10, ["hash"] = "h" + id },
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
