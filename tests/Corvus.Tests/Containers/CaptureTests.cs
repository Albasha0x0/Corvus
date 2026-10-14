using System.Globalization;
using System.IO.Compression;
using System.Text;
using System.Text.Json;
using Corvus.Core;
using Corvus.Services.Analysis;

namespace Corvus.Tests;

/// <summary>HAR files and mitmproxy flow files as containers of responses: names from URLs, bodies decoded, hostile URLs kept inside.</summary>
public sealed class CaptureTests : IDisposable
{
    private readonly TempDir _dir = new();
    private readonly AssemblyWorkspace _workspace = new(new ServerOptions());

    public void Dispose()
    {
        _workspace.Dispose();
        _dir.Dispose();
    }

    private static byte[] Gzip(byte[] data)
    {
        var ms = new MemoryStream();
        using (var z = new GZipStream(ms, CompressionLevel.Fastest)) z.Write(data);
        return ms.ToArray();
    }

    private static byte[] Brotli(byte[] data)
    {
        var ms = new MemoryStream();
        using (var z = new BrotliStream(ms, CompressionLevel.Fastest)) z.Write(data);
        return ms.ToArray();
    }

    private static object Entry(string method, string url, int status, string mime, string? text, string? encoding = null, string? contentEncoding = null) => new
    {
        request = new { method, url, headers = Array.Empty<object>() },
        response = new
        {
            status,
            headers = contentEncoding == null ? Array.Empty<object>() : [new { name = "Content-Encoding", value = contentEncoding }],
            content = encoding == null ? (object)new { size = text?.Length ?? 0, mimeType = mime, text } : new { size = 0, mimeType = mime, text, encoding },
        },
    };

    private static byte[] Har() => JsonSerializer.SerializeToUtf8Bytes(new
    {
        log = new
        {
            version = "1.2",
            entries = new[]
            {
                Entry("GET", "https://app.example/", 200, "text/html; charset=utf-8", "<html>hi</html>"),
                Entry("GET", "https://app.example/api/items?page=2", 200, "application/json", "{\"items\":[]}"),
                Entry("GET", "https://cdn.example:8443/img/logo.png", 200, "image/png", Convert.ToBase64String([0x89, 0x50, 0x4E, 0x47]), "base64"),
                Entry("GET", "https://app.example/packed.js", 200, "application/javascript", Convert.ToBase64String(Gzip("var x=1;"u8.ToArray())), "base64", "gzip"),
                Entry("GET", "https://evil.example/a/..%2F..%2F..%2Fescape.txt", 200, "text/plain", "x"),
                Entry("POST", "https://app.example/submit", 204, "text/plain", null),
                Entry("GET", "data:text/plain,hello", 200, "text/plain", "hello"),
            },
        },
    });

    [Fact]
    public void HarListsResponsesNamedByUrl()
    {
        var path = _dir.File("session.har");
        File.WriteAllBytes(path, Har());
        var listing = new UnpackService(_workspace).List(path, AnalysisLimits.Default, default);
        Assert.Equal(Captures.HarKind, listing.Container);
        var query = listing.Files!.Single(f => f.Path.StartsWith("app.example/api/items_q", StringComparison.Ordinal));
        Assert.EndsWith(".json", query.Path);
        Assert.Equal(
        [
            "app.example/index.html: GET 200 text/html; https://app.example/",
            "cdn.example_8443/img/logo.png: GET 200 image/png; https://cdn.example:8443/img/logo.png",
            "app.example/packed.js: GET 200 application/javascript, gzip decoded; https://app.example/packed.js",
            "evil.example/a/.._.._.._escape.txt: GET 200 text/plain; https://evil.example/a/..%2F..%2F..%2Fescape.txt",
            "app.example/submit.txt: POST 204 text/plain, no body; https://app.example/submit",
        ], listing.Files!.Where(f => f != query && !f.Path.StartsWith("data-url", StringComparison.Ordinal)).Select(f => $"{f.Path}: {f.Detail}"));
        Assert.StartsWith("7 response(s), 6 with a body", listing.Notes[0]);
    }

    [Fact]
    public void HarUnpacksDecodedBodiesInsideTheOutput()
    {
        var path = _dir.File("session.har");
        File.WriteAllBytes(path, Har());
        var output = _dir.File("out");
        var report = new UnpackService(_workspace).Unpack(path, output, load: false, AnalysisLimits.Default, default);
        Assert.Equal("var x=1;", File.ReadAllText(Path.Combine(output, "app.example", "packed.js.bin")));
        Assert.Equal([0x89, 0x50, 0x4E, 0x47], File.ReadAllBytes(Path.Combine(output, "cdn.example_8443", "img", "logo.png")));
        Assert.Equal(6, report.Files.Count);
        Assert.All(report.Files, f => Assert.StartsWith(output + Path.DirectorySeparatorChar, f.Path));
    }

    [Fact]
    public void OtherJsonIsNotACapture()
    {
        var contents = Containers.Open("""{"log":{"level":"debug"}}"""u8.ToArray(), "settings.json", AnalysisLimits.Default, default);
        Assert.Equal("none", contents.Kind);
    }

    /// <summary>tnetstring encoding: byte[] ',' string ';' long '#' bool '!' null '~' dictionary '}' list ']'.</summary>
    private static byte[] TNet(object? value)
    {
        byte[] body;
        char type;
        switch (value)
        {
            case byte[] b: body = b; type = ','; break;
            case string s: body = Encoding.UTF8.GetBytes(s); type = ';'; break;
            case int or long: body = Encoding.ASCII.GetBytes(Convert.ToString(value, CultureInfo.InvariantCulture)!); type = '#'; break;
            case bool v: body = Encoding.ASCII.GetBytes(v ? "true" : "false"); type = '!'; break;
            case null: body = []; type = '~'; break;
            case IDictionary<string, object?> d: body = [.. d.SelectMany(kv => TNet(Encoding.UTF8.GetBytes(kv.Key)).Concat(TNet(kv.Value)))]; type = '}'; break;
            case IEnumerable<object?> l: body = [.. l.SelectMany(TNet)]; type = ']'; break;
            default: throw new ArgumentException(value.GetType().Name);
        }
        return [.. Encoding.ASCII.GetBytes($"{body.Length}:"), .. body, (byte)type];
    }

    private static byte[] B(string s) => Encoding.UTF8.GetBytes(s);

    private static Dictionary<string, object?> Flow(string type, string host, int port, string path, string scheme, byte[]? content, params (string, string)[] headers) => new()
    {
        ["version"] = 19,
        ["type"] = type,
        ["request"] = new Dictionary<string, object?>
        {
            ["host"] = host, ["port"] = port, ["method"] = B("GET"), ["scheme"] = B(scheme), ["path"] = B(path), ["headers"] = new List<object?>(), ["content"] = B(""),
        },
        ["response"] = new Dictionary<string, object?>
        {
            ["status_code"] = 200, ["reason"] = B("OK"),
            ["headers"] = headers.Select(h => (object?)new List<object?> { B(h.Item1), B(h.Item2) }).ToList(),
            ["content"] = content,
        },
    };

    private static byte[] Flows() =>
    [
        .. TNet(Flow("http", "api.example", 443, "/v1/config?x=1", "https", Gzip(B("{\"a\":1}")), ("content-type", "application/json"), ("content-encoding", "gzip"))),
        .. TNet(Flow("http", "api.example", 8080, "/script", "http", Brotli(B("alert(1)")), ("Content-Type", "text/javascript"), ("Content-Encoding", "br"))),
        .. TNet(Flow("websocket", "ws.example", 443, "/socket", "https", null)),
        .. TNet(Flow("http", "api.example", 443, "/broken", "https", B("not gzip"), ("content-encoding", "gzip"))),
    ];

    [Fact]
    public void MitmproxyFlowsListAndDecodeResponses()
    {
        var path = _dir.File("capture.flows");
        File.WriteAllBytes(path, Flows());
        var listing = new UnpackService(_workspace).List(path, AnalysisLimits.Default, default);
        Assert.Equal(Captures.FlowKind, listing.Container);
        var files = listing.Files!.Select(f => $"{f.Path} {f.Size}: {f.Detail}").ToList();
        Assert.Matches(@"^api\.example/v1/config_q[0-9a-f]{8}\.json 7: GET 200 application/json, gzip decoded; https://api\.example/v1/config\?x=1$", files[0]);
        Assert.Equal("api.example_8080/script.js 8: GET 200 text/javascript, br decoded; http://api.example:8080/script", files[1]);
        Assert.Equal("api.example/broken.bin 8: GET 200, gzip body not decoded; https://api.example/broken", files[2]);
        Assert.Contains(listing.Notes, n => n.StartsWith("1 flow(s) that are not HTTP", StringComparison.Ordinal));

        var output = _dir.File("out");
        new UnpackService(_workspace).Unpack(path, output, load: false, AnalysisLimits.Default, default);
        Assert.Equal("alert(1)", File.ReadAllText(Path.Combine(output, "api.example_8080", "script.js.bin")));
    }

    [Fact]
    public void DamagedFlowFilesKeepWhatWasRead()
    {
        var flows = Flows();
        var damaged = flows[..(flows.Length - 10)];
        var contents = Containers.Open(damaged, "x.flows", AnalysisLimits.Default, default);
        Assert.Equal(Captures.FlowKind, contents.Kind);
        Assert.Equal(2, contents.Entries!.Count);
        Assert.Contains(contents.Notes, n => n.StartsWith("Flow file damaged at byte", StringComparison.Ordinal));
    }

    [Fact]
    [Trait("Speed", "Slow")]
    public void FlowFuzzNeverThrowsUnexpectedly()
    {
        var failures = FormatFuzz.Run(Flows(), bytes =>
        {
            try { Containers.Open(bytes, "x.flows", AnalysisLimits.Default, default, allFiles: true); }
            catch (ToolError) { }
        }, 2000);
        Assert.Empty(failures);
    }
}
