using System.Diagnostics;
using System.IO.Compression;
using System.Text;
using System.Text.Json;
using Corvus.Core;
using Corvus.Services.Analysis;
using Xunit.Abstractions;

namespace Corvus.Tests;

/// <summary>
/// search_container kind=request on HAR, mitmproxy and .saz captures (names only unless values=true, GraphQL operations,
/// WebSocket messages, SSE and NDJSON shapes), and kind=endpoint comparing two captures.
/// </summary>
[Collection(nameof(SerialTimingTests))] // the 500 MB budget measures the whole process
public sealed class CaptureRequestTests(ITestOutputHelper output) : IDisposable
{
    private readonly TempDir _dir = new();
    private readonly AssemblyWorkspace _ws = new();
    public void Dispose() { _ws.Dispose(); _dir.Dispose(); }

    private const string Token = "Bearer eyJhbGciOiJIUzI1NiJ9.c2VjcmV0", Session = "s3cr3t-session", Theme = "dark";

    private static object Header(string name, string value) => new { name, value };

    private static object Entry(string method, string url, int status, object[]? headers = null, object[]? cookies = null, object? postData = null,
        string? mime = null, string? text = null, object[]? messages = null, double time = 12.5)
    {
        var entry = new Dictionary<string, object?>
        {
            ["startedDateTime"] = "2026-10-15T10:00:00.000Z",
            ["time"] = time,
            ["request"] = new Dictionary<string, object?>
            {
                ["method"] = method, ["url"] = url, ["httpVersion"] = "HTTP/2", ["headers"] = headers ?? [], ["cookies"] = cookies ?? [],
                ["queryString"] = Array.Empty<object>(), ["postData"] = postData, ["headersSize"] = -1, ["bodySize"] = -1,
            },
            ["response"] = new Dictionary<string, object?>
            {
                ["status"] = status, ["statusText"] = "", ["httpVersion"] = "HTTP/2", ["headers"] = Array.Empty<object>(), ["cookies"] = Array.Empty<object>(),
                ["content"] = new { size = text?.Length ?? 0, mimeType = mime ?? "", text }, ["redirectURL"] = "", ["headersSize"] = -1, ["bodySize"] = -1,
            },
            ["timings"] = new { send = 0, wait = time, receive = 0 },
        };
        if (messages != null) entry["_webSocketMessages"] = messages;
        return entry;
    }

    private string WriteHar(string name, params object[] entries)
    {
        var path = _dir.File(name);
        File.WriteAllBytes(path, JsonSerializer.SerializeToUtf8Bytes(new { log = new { version = "1.2", creator = new { name = "test", version = "1" }, entries } }));
        return path;
    }

    private string App() => WriteHar("app.har",
        Entry("GET", "https://api.example.com/v1/users/42?page=2&token=abc", 200,
            [Header(":authority", "api.example.com"), Header("authorization", Token), Header("accept", "application/json"), Header("cookie", $"sid={Session}; theme={Theme}")],
            [new { name = "sid", value = Session }, new { name = "theme", value = Theme }], mime: "application/json", text: """{"id":42,"name":"Ada","roles":[{"id":1,"name":"admin"}]}"""),
        Entry("POST", "https://api.example.com/graphql", 200, [Header("content-type", "application/json")], postData: new
        {
            mimeType = "application/json",
            text = """[{"operationName":"GetUser","query":"query GetUser($id: ID!) { user(id: $id) { name } }","variables":{"id":"42"}},{"query":"mutation { logout }"},{"operationName":"Feed","extensions":{"persistedQuery":{"version":1,"sha256Hash":"abc"}}}]""",
        }, mime: "application/json", text: """[{"data":{"user":{"name":"Ada"}}}]"""),
        Entry("GET", "https://api.example.com/v1/stream", 200, mime: "text/event-stream",
            text: "event: delta\ndata: {\"choices\":[{\"delta\":{\"content\":\"Hel\"}}]}\n\nevent: delta\ndata: {\"choices\":[{\"delta\":{\"content\":\"lo\"}}]}\n\ndata: [DONE]\n\n"),
        Entry("GET", "https://api.example.com/v1/export", 200, mime: "application/x-ndjson", text: "{\"id\":1,\"v\":\"a\"}\n{\"id\":2,\"v\":\"b\"}\n{\"error\":\"x\"}\n"),
        Entry("GET", "wss://rt.example.com/socket", 101, messages:
        [
            new { type = "send", time = 1.0, opcode = 1, data = """{"type":"subscribe","channel":"prices"}""" },
            new { type = "receive", time = 1.1, opcode = 1, data = """{"type":"tick","price":101.5}""" },
            new { type = "receive", time = 1.2, opcode = 1, data = """{"type":"tick","price":101.7}""" },
            new { type = "receive", time = 1.3, opcode = 2, data = Convert.ToBase64String([1, 2, 3]) },
        ]));

    private UnpackService.ContainerSearch Requests(string path, string query = "*", bool values = false, int offset = 0, int limit = 100) =>
        new UnpackService(_ws).Search(path, query, "request", limit, AnalysisLimits.Default, default, offset, values: values);

    [Fact]
    public void Har_requests_show_names_and_never_values_by_default()
    {
        var found = Requests(App());
        Assert.Equal(5, found.Total);
        var all = string.Join("\n", found.Items.Select(i => i.Name + " " + i.Detail) .Concat(found.Notes));
        foreach (var secret in new[] { Token, Session, Theme, "abc", "Ada", "Hel", "101.5", "prices", "42?" })
            Assert.DoesNotContain(secret, all);
        var user = found.Items[0];
        Assert.Equal("GET https://api.example.com/v1/users/{n}?page=…&token=…", user.Name);
        Assert.Equal("api.example.com", user.Path);
        Assert.Contains("#1; status 200; HTTP/2; 13 ms; request headers: :authority, authorization, accept; cookies: sid, theme", user.Detail);
        Assert.Contains("response application/json", user.Detail);

        Assert.Contains("GraphQL query GetUser, mutation (anonymous), query Feed (persisted)", found.Items[1].Detail);
        Assert.Contains("body application/json", found.Items[1].Detail);
        Assert.Contains("SSE 3 message(s): delta {choices[{delta{content}}]} x2, message text x1", found.Items[2].Detail);
        Assert.Contains("NDJSON 3 message(s): {id,v} x2, {error} x1", found.Items[3].Detail);
        Assert.Contains("WebSocket 4 message(s), 1 sent, 3 received: received {price,type} x2, received binary x1, sent {channel,type} x1", found.Items[4].Detail);

        // the query matches names in the detail; paging keeps capture order
        Assert.Equal(["#1"], Requests(App(), "authorization").Items.Select(i => i.Detail!.Split(';')[0]));
        Assert.Equal("#2", Assert.Single(Requests(App(), offset: 1, limit: 1).Items).Detail!.Split(';')[0]);
    }

    [Fact]
    public void Values_are_shown_only_when_asked()
    {
        var found = Requests(App(), values: true);
        var user = found.Items[0];
        Assert.Equal("GET https://api.example.com/v1/users/42?page=2&token=abc", user.Name);
        Assert.Contains($"authorization: {Token}", user.Detail);
        Assert.Contains($"cookies: sid={Session}, theme={Theme}", user.Detail);
        Assert.Contains("> {\"type\":\"subscribe\",\"channel\":\"prices\"}", found.Items[4].Detail);
        Assert.Contains("values shown", found.Notes[0]);
        Assert.Contains("values applies to kind=request only", Assert.Throws<ToolError>(() =>
            new UnpackService(_ws).Search(App(), "*", "endpoint", 10, AnalysisLimits.Default, default, values: true)).Message);
    }

    [Fact]
    public void Flows_and_saz_give_the_same_request_side()
    {
        static byte[] B(string s) => Encoding.UTF8.GetBytes(s);
        var flow = new Dictionary<string, object?>
        {
            ["version"] = 19, ["type"] = "http",
            ["request"] = new Dictionary<string, object?>
            {
                ["host"] = "api.example.com", ["port"] = 443, ["method"] = B("POST"), ["scheme"] = B("https"), ["path"] = B("/graphql"), ["http_version"] = B("HTTP/1.1"),
                ["headers"] = new List<object?> { new List<object?> { B("Cookie"), B($"sid={Session}") }, new List<object?> { B("Content-Type"), B("application/json") } },
                ["content"] = B("""{"query":"query Me { me { id } }"}"""), ["timestamp_start"] = 1700000000.0,
            },
            ["response"] = new Dictionary<string, object?>
            {
                ["status_code"] = 200, ["headers"] = new List<object?> { new List<object?> { B("content-type"), B("application/json") } },
                ["content"] = B("""{"data":{"me":{"id":"1"}}}"""), ["timestamp_end"] = 1700000000.25,
            },
        };
        var flows = _dir.File("app.flows");
        File.WriteAllBytes(flows, CaptureTests.TNet(flow));
        var row = Assert.Single(Requests(flows).Items);
        Assert.Equal("POST https://api.example.com/graphql", row.Name);
        Assert.Equal("#1; status 200; HTTP/1.1; 250 ms; request headers: Content-Type; cookies: sid; body application/json 34 B; GraphQL query Me; response application/json 26 B", row.Detail);

        var saz = _dir.File("app.saz");
        using (var zip = ZipFile.Open(saz, ZipArchiveMode.Create))
        {
            void Add(string name, string text) { using var s = zip.CreateEntry(name).Open(); s.Write(B(text)); }
            Add("raw/01_c.txt", $"POST https://api.example.com/graphql HTTP/1.1\r\nHost: api.example.com\r\nCookie: sid={Session}\r\nContent-Type: application/json\r\nContent-Length: 34\r\n\r\n" + """{"query":"query Me { me { id } }"}""");
            Add("raw/01_s.txt", "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 26\r\n\r\n");
        }
        row = Assert.Single(Requests(saz).Items);
        Assert.Equal("#1; status 200; HTTP/1.1; request headers: Host, Content-Type, Content-Length; cookies: sid; body application/json 34 B; GraphQL query Me; response application/json 26 B", row.Detail);
        Assert.DoesNotContain(Session, row.Detail);
    }

    [Fact]
    [FuzzEntry(typeof(CaptureRequests), typeof(MessageShapes))]
    public void Fuzzed_captures_read_or_decline()
    {
        var failures = FormatFuzz.Run(File.ReadAllBytes(App()), b =>
        {
            try
            {
                CaptureRequests.Read(new MemoryStream(b), r => RequestSearchKind.Row(r, values: false), [], texts: true, default);
            }
            catch (ToolError) { } // a damaged HAR says so
        }, 600);
        Assert.True(failures.Count == 0, string.Join("\n", failures.Take(5)));
    }

    [Fact]
    public void Not_a_request_capture_is_refused()
    {
        var path = _dir.File("notes.json");
        File.WriteAllText(path, """{"log":{"level":"debug"}}""");
        Assert.Equal(ErrorCode.Unsupported, Assert.Throws<ToolError>(() => Requests(path)).Code);
    }

    /// <summary>W-P3-15: two HAR files of one app's releases compared template by template.</summary>
    [Fact]
    public void Two_captures_compare_by_template()
    {
        var before = WriteHar("v1.har",
            Entry("GET", "https://api.example.com/v1/users/1", 200, [Header("accept", "application/json")], mime: "application/json", text: """{"id":1,"name":"a"}"""),
            Entry("GET", "https://api.example.com/v1/legacy", 200),
            Entry("GET", "https://api.example.com/v1/health", 200),
            Entry("POST", "https://api.example.com/graphql", 200, postData: new { mimeType = "application/json", text = """{"operationName":"Feed","query":"query Feed { feed { id } }"}""" }),
            Entry("GET", "https://api.example.com/v1/stream", 200, mime: "text/event-stream", text: "data: {\"delta\":\"x\"}\n\n"));
        var after = WriteHar("v2.har",
            Entry("GET", "https://api.example.com/v1/users/2", 200, [Header("accept", "application/json"), Header("x-client-version", "2")], mime: "application/json",
                text: """{"id":2,"name":"b","avatar":{"url":"u"}}"""),
            Entry("GET", "https://api.example.com/v1/users/3", 404, [Header("accept", "application/json")]),
            Entry("GET", "https://api.example.com/v2/search?q=z", 200),
            Entry("GET", "https://api.example.com/v1/health", 200),
            Entry("POST", "https://api.example.com/graphql", 200, postData: new { mimeType = "application/json", text = """{"operationName":"Feed2","query":"query Feed2 { feed { id } }"}""" }),
            Entry("GET", "https://api.example.com/v1/stream", 200, mime: "text/event-stream", text: "event: delta\ndata: {\"delta\":\"x\",\"usage\":{\"tokens\":1}}\n\n"));
        var diff = new UnpackService(_ws).Search(before, "*", "endpoint", 100, AnalysisLimits.Default, default, capture: after);
        var rows = diff.Items.Select(r => $"{r.Seen} {r.Name}: {r.Detail}").ToList();
        Assert.Equal(
        [
            "added GET https://api.example.com/v2/search?q=…: 1 request(s), status 200",
            "removed GET https://api.example.com/v1/legacy: 1 request(s), status 200",
            "changed GET https://api.example.com/v1/stream: 1 -> 1 request(s); shapes +SSE delta {delta,usage{tokens}}, -SSE message {delta}",
            "changed GET https://api.example.com/v1/users/{n}: 1 -> 2 request(s); status 200 -> 200, 404; request headers +x-client-version; shapes +{avatar{url},id,name}, -{id,name}",
            "changed POST https://api.example.com/graphql: 1 -> 1 request(s); GraphQL +query Feed2, -query Feed",
            "same GET https://api.example.com/v1/health: 1 -> 1 request(s)",
        ], rows);
        Assert.StartsWith($"{before} (5 request(s)) compared with {after} (6): 1 added, 1 removed, 3 changed, 1 same", diff.Notes[0]);
        Assert.DoesNotContain(diff.Items, r => (r.Detail ?? "").Contains("\"b\"", StringComparison.Ordinal));
    }

    /// <summary>The batch target: a 500 MB HAR streamed in under 10 s and 300 MB of memory.</summary>
    [Fact]
    [Trait("Speed", "Slow")]
    [Trait(PerfBudget.Trait, PerfBudget.Timing)]
    public async Task A_500_MB_har_is_streamed_within_its_budget()
    {
        var path = _dir.File("big.har");
        var body = new string('x', 6000);
        long written;
        using (var w = new StreamWriter(path, false, new UTF8Encoding(false), 1 << 20))
        {
            w.Write("""{"log":{"version":"1.2","creator":{"name":"t","version":"1"},"entries":[""");
            int i = 0;
            while (w.BaseStream.Length < 500L * 1024 * 1024)
            {
                if (i > 0) w.Write(',');
                w.Write($$$"""{"startedDateTime":"2026-10-15T10:00:00Z","time":5,"request":{"method":"GET","url":"https://api.example.com/v1/items/{{{i}}}?k={{{i}}}","httpVersion":"HTTP/2","headers":[{"name":"authorization","value":"Bearer t{{{i}}}"},{"name":"accept","value":"*/*"}],"cookies":[{"name":"sid","value":"s{{{i}}}"}],"queryString":[],"headersSize":-1,"bodySize":0},"response":{"status":200,"statusText":"","httpVersion":"HTTP/2","headers":[],"cookies":[],"content":{"size":6000,"mimeType":"text/plain","text":"{{{body}}}"},"redirectURL":"","headersSize":-1,"bodySize":6000},"timings":{"send":0,"wait":5,"receive":0}}""");
                i++;
            }
            w.Write("]}}");
            w.Flush();
            written = w.BaseStream.Length;
        }
        GC.Collect();
        long before = ProcessMemory.Private(), peak = before;
        using var done = new CancellationTokenSource();
        var sampler = Task.Run(async () =>
        {
            while (!done.IsCancellationRequested)
            {
                peak = Math.Max(peak, ProcessMemory.Private());
                await Task.Delay(20);
            }
        });
        var sw = Stopwatch.StartNew();
        var found = Requests(path, "authorization", limit: 10);
        sw.Stop();
        done.Cancel();
        await sampler;
        Console.WriteLine($"{written / 1e6:N0} MB HAR, {found.Searched:N0} requests in {sw.Elapsed.TotalSeconds:0.00} s, private memory +{(peak - before) / 1e6:N0} MB");
        Assert.Equal(found.Searched, found.Total);
        PerfBudget.Time("containers/har-stream", sw.Elapsed, TimeSpan.FromSeconds(10), output);
        Assert.True(peak - before < 300L * 1024 * 1024, $"{(peak - before) / 1e6:N0} MB");
    }
}
