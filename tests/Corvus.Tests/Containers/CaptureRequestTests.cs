using System.Diagnostics;
using System.IO.Compression;
using System.Text;
using System.Text.Json;
using Corvus.Core;
using Corvus.Services.Analysis;
using Xunit.Abstractions;

namespace Corvus.Tests;

/// <summary>search_container kind=request on HAR, mitmproxy and .saz captures, and kind=endpoint across two captures.</summary>
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

    // A 4-byte length prefix with 2 trailing bytes, a 2-byte prefix, and an unframed sent message.
    private string Gateway() => WriteHar("gateway.har",
        Entry("GET", "https://gateway.example/session", 200, mime: "application/json", text: """{"server":{"host":"relay.example","port":7000}}"""),
        Entry("GET", "wss://relay.example:7000/socket", 101, messages:
        [
            new { type = "receive", time = 1.0, opcode = 2, data = Convert.ToBase64String([0, 0, 0, 3, 0x61, 0x62, 0x63, 0, 0]) },
            new { type = "receive", time = 1.1, opcode = 2, data = Convert.ToBase64String([0, 2, 0x78, 0x79]) },
            new { type = "send", time = 1.2, opcode = 2, data = Convert.ToBase64String([0xFF, 0xFF, 0xFF]) },
        ]));

    private static GatewayResponse Reply(int sequence, string json) => new(sequence, "https://g.example/s", Encoding.UTF8.GetBytes(json));

    [Fact]
    public void A_clipped_binary_message_leaves_the_framing_unknown()
    {
        var clipped = new CapturedMessage(false, new string('A', CaptureRequests.MaxMessageText), true, Clipped: true);
        Assert.Equal($"; framing received: unknown, a message is clipped at {CaptureRequests.MaxMessageText:N0}", RequestSearchKind.Framing([clipped], sent: false));
    }

    [Fact]
    public void An_unclipped_flow_message_of_48_KB_is_not_reported_clipped()
    {
        var data = Convert.ToBase64String(new byte[48 * 1024]);
        Assert.DoesNotContain("clipped", RequestSearchKind.Framing([new CapturedMessage(false, data, true)], sent: false));
    }

    [Fact]
    public void A_binary_message_that_is_not_base64_leaves_the_framing_unknown()
    {
        Assert.Equal("; framing sent: unknown, a message is not base64", RequestSearchKind.Framing([new CapturedMessage(true, "not*base64!", true)], sent: true));
    }

    [Fact]
    public void A_capture_without_binary_messages_has_no_framing_clause()
    {
        Assert.Equal("", RequestSearchKind.Framing([new CapturedMessage(false, "hi", false)], sent: false));
        Assert.Equal("", RequestSearchKind.Framing([], sent: true));
    }

    [Fact]
    public void A_message_count_at_the_bound_marks_the_framing_partial()
    {
        var m = new CapturedMessage(false, Convert.ToBase64String([0, 0, 0, 1, 0x61]), true);
        var clause = RequestSearchKind.Framing(Enumerable.Repeat(m, CaptureRequests.MaxMessages).ToList(), sent: false);
        Assert.Contains($"partial: {CaptureRequests.MaxMessages:N0} of {CaptureRequests.MaxMessages:N0} messages read", clause);
    }

    [Fact]
    public void A_response_with_no_later_matching_request_is_named_not_joined()
    {
        var notes = RequestSearchKind.Flow([Reply(1, """{"host":"a.example","port":1}""")], [new(2, "b.example", 2)], 1);
        Assert.Contains("#1 not joined: no later connect names a.example:1", notes);
        Assert.StartsWith("connection flow: 0 join(s) from 1 of 1 JSON response(s)", notes[0]);
    }

    [Fact]
    public void Unjoined_lines_stop_at_ten_and_count_the_remainder()
    {
        var responses = Enumerable.Range(1, 12).Select(i => Reply(i, $$"""{"host":"h{{i}}.example","port":{{i}}}""")).ToList();
        var notes = RequestSearchKind.Flow(responses, [], 12);
        Assert.Equal(10, notes.Count(n => n.Contains("not joined: ")));
        Assert.Contains("+2 more not joined", notes);
    }

    [Fact]
    public void Joins_stop_at_ten_and_count_the_remainder_apart_from_unjoined_lines()
    {
        var responses = Enumerable.Range(1, 12).Select(i => Reply(i, $$"""{"host":"h{{i}}.example","port":{{i}}}""")).Append(Reply(13, """{"host":"x.example","port":99}""")).ToList();
        var connects = Enumerable.Range(1, 12).Select(i => new ConnectCall(100 + i, $"h{i}.example", i)).ToList();
        var notes = RequestSearchKind.Flow(responses, connects, 13);
        Assert.Contains("+2 more join(s)", notes);
        Assert.Contains("#13 not joined: no later connect names x.example:99", notes);
    }

    [Fact]
    public void A_response_without_a_host_and_port_pair_adds_no_line()
    {
        var notes = RequestSearchKind.Flow([Reply(1, """{"id":1}""")], [], 1);
        Assert.Equal(["connection flow: 0 join(s) from 1 of 1 JSON response(s), 0 request URL(s) indexed; no response names a host and port."], notes);
    }

    [Fact]
    public void Responses_past_the_read_bound_report_a_partial_count()
    {
        var notes = RequestSearchKind.Flow([Reply(1, """{"id":1}""")], [], 1001);
        Assert.Contains("1 of 1,001 JSON response(s)", notes[0]);
        Assert.Contains("partial: the first 1,000 were read", notes[0]);
    }

    [Fact]
    public void Clipped_and_untyped_responses_are_reported_unknown_not_absent()
    {
        var notes = RequestSearchKind.Flow([], [], 0, clipped: 2, otherText: 3);
        Assert.Contains($"2 JSON response(s) clipped at {CaptureRequests.MaxText:N0} were not read (unknown)", notes[1]);
        Assert.Contains("3 response(s) not typed as JSON were not scanned (unknown)", notes[2]);
    }

    [Fact]
    public void A_flow_message_is_clipped_by_bytes_and_marked_clipped()
    {
        var flow = new Dictionary<string, object?>
        {
            ["version"] = 19, ["type"] = "http",
            ["request"] = new Dictionary<string, object?> { ["host"] = "h.example", ["port"] = 80, ["method"] = new byte[] { 71, 69, 84 }, ["scheme"] = "http"u8.ToArray(), ["path"] = "/"u8.ToArray(), ["headers"] = new List<object?>() },
            ["websocket"] = new Dictionary<string, object?>
            {
                ["messages"] = new List<object?>
                {
                    new List<object?> { 2L, false, new byte[CaptureRequests.MaxMessageText], 1.0 },
                    new List<object?> { 2L, false, new byte[CaptureRequests.MaxMessageText + 1], 1.0 },
                },
            },
        };
        var messages = CaptureRequests.FromFlow(flow, 0)!.Messages!;
        Assert.False(messages[0].Clipped);
        Assert.True(messages[1].Clipped);
    }

    [Fact]
    public void A_cancelled_search_throws_before_reading_the_capture()
    {
        using var cts = new CancellationTokenSource();
        cts.Cancel();
        Assert.ThrowsAny<OperationCanceledException>(() => new UnpackService(_ws).Search(Gateway(), "*", "request", 10, AnalysisLimits.Default, cts.Token));
    }

    [Fact]
    public void A_gateway_response_is_joined_to_the_later_request_that_connects_to_its_host_and_port()
    {
        var found = Requests(Gateway());
        Assert.Contains(found.Notes, n => n.Contains("1 join(s) from 1 of 1 JSON response(s)"));
        Assert.Contains(found.Notes, n => n == "#1 $.server.host, $.server.port -> request #2 relay.example:7000");
    }

    [Fact]
    public void A_WebSocket_row_names_the_inferred_length_prefix_and_byte_order()
    {
        var detail = Requests(Gateway()).Items.Single(i => i.Detail!.Contains("WebSocket")).Detail;
        Assert.Contains("framing received: [u32 big-endian payload length][payload], 2 frame(s) in 2 message(s)", detail);
        Assert.Contains("framing sent: no length prefix explains 1 binary message(s)", detail);
    }

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

        // The query matches names in the detail; paging keeps capture order.
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
            // A damaged HAR says so.
            catch (ToolError) { }
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
        if (ChildTest.Rerun(this, output)) return;
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
