using System.Text;
using Corvus.Core;
using Corvus.Core.Pcap;
using Corvus.Native.Providers;
using Corvus.Services.Analysis;
using Xunit.Abstractions;

namespace Corvus.Tests;

/// <summary>
/// HTTP/3 in captures. http3.pcap, http3.keys and the qlog files are built by Http3Fixtures/build.py with aioquic 1.2.0:
/// one connection (AES-256-GCM), five requests (one an upload, one gzip-encoded, one a 404), a key update after the second;
/// http3-v2-chacha.* repeats it over QUIC version 2 with ChaCha20-Poly1305.
/// </summary>
public sealed class Http3Tests(ITestOutputHelper output)
{
    private static string Fixture(string name) => Path.Combine(AppContext.BaseDirectory, "Containers", "Http3Fixtures", name);

    private static (CaptureObjects.Result Result, List<QuicCapture.Section> Sections) Read(bool withKeys, string stem = "http3")
    {
        TlsKeyLog? keys = null;
        if (withKeys)
        {
            keys = new TlsKeyLog();
            keys.Add(File.ReadAllText(Fixture(stem + ".keys")));
        }
        using var s = File.OpenRead(Fixture(stem + ".pcap"));
        var sections = new List<QuicCapture.Section>();
        return (CaptureObjects.Read(s, keys, AnalysisLimits.Default, default, sections), sections);
    }

    private static string Hex(string spaced) => spaced.Replace(" ", "");

    [Fact]
    public void The_rfc_9204_examples_decode_with_the_dynamic_table()
    {
        var q = new Qpack { MaxCapacity = 220 };
        Assert.Equal([(":path", "/index.html")], q.Decode(Convert.FromHexString(Hex("0000 510b 2f69 6e64 6578 2e68 746d 6c")))!);
        q.Encoder(Convert.FromHexString(Hex("3fbd01 c00f 7777 772e 6578 616d 706c 652e 636f 6d c10c 2f73 616d 706c 652f 7061 7468")));
        Assert.Equal(2, q.Inserts);
        Assert.Equal([(":authority", "www.example.com"), (":path", "/sample/path")], q.Decode(Convert.FromHexString("03811011"))!);
        // An instruction cut between two writes waits for its second half.
        var insert = Convert.FromHexString(Hex("4a63 7573 746f 6d2d 6b65 790c 6375 7374 6f6d 2d76 616c 7565"));
        q.Encoder(insert.AsSpan(0, 5));
        Assert.Equal(2, q.Inserts);
        q.Encoder(insert.AsSpan(5));
        q.Encoder([0x02]);
        Assert.Equal([(":authority", "www.example.com"), (":path", "/"), ("custom-key", "custom-value")], q.Decode(Convert.FromHexString("050080c181"))!);
        q.Encoder(Convert.FromHexString(Hex("810d 6375 7374 6f6d 2d76 616c 7565 32")));
        Assert.Equal(5, q.Inserts);
        // Absolute index 0 was evicted by the last insert.
        Assert.Null(q.Decode(Convert.FromHexString("060084")));
        Assert.Equal([("custom-key", "custom-value2")], q.Decode(Convert.FromHexString("060080"))!);
        Assert.True(q.Healthy);
    }

    [Fact]
    public void Http3_objects_are_exported_from_a_decrypted_capture()
    {
        var (result, _) = Read(withKeys: true);
        var items = result.Contents.Items.ToDictionary(i => i.Name, i => i.Bytes);
        foreach (var i in result.Contents.Items) output.WriteLine($"{i.Name} {i.Bytes.Length} {i.Origin}");
        Assert.Equal("<html><body>index</body></html>\n", Encoding.ASCII.GetString(items["h3.example.test/index.html"]));
        Assert.Equal(Enumerable.Range(0, 60000).Select(i => (byte)(i * 7 % 256)), items["h3.example.test/data.bin"]);
        Assert.Equal(string.Concat(Enumerable.Repeat("notes line\n", 400)), Encoding.ASCII.GetString(items["h3.example.test/notes.txt"]));
        Assert.Equal("received 2000 bytes\n", Encoding.ASCII.GetString(items["h3.example.test/upload.txt"]));
        Assert.Equal(Enumerable.Range(0, 2000).Select(i => (byte)(i % 250)), items["requests/h3.example.test/upload.bin"]);
        Assert.Equal("not found\n", Encoding.ASCII.GetString(items["h3.example.test/missing.txt"]));
        var tls = Assert.Single(result.Tls);
        Assert.Equal(("10.0.0.2:443", "h3.example.test", "QUIC v1", "0x1302", "h3", "decrypted"), (tls.Server, tls.ServerName, tls.Version, tls.Cipher, tls.Alpn, tls.Outcome));
        Assert.Contains(result.Contents.Notes, n => n.StartsWith("1 QUIC connection(s): 1 decrypted; 6 HTTP/3 object(s)", StringComparison.Ordinal));
    }

    // Bodies after the key update need the aiortc/aioquic#745 workaround: the fixture library derives it with "quic ku".
    [Fact]
    public void Quic_v2_with_chacha20_poly1305_exports_the_same_objects()
    {
        var (result, _) = Read(withKeys: true, stem: "http3-v2-chacha");
        var items = result.Contents.Items.ToDictionary(i => i.Name, i => i.Bytes);
        Assert.Equal(Enumerable.Range(0, 60000).Select(i => (byte)(i * 7 % 256)), items["h3.example.test/data.bin"]);
        Assert.Equal(string.Concat(Enumerable.Repeat("notes line\n", 400)), Encoding.ASCII.GetString(items["h3.example.test/notes.txt"]));
        Assert.Equal(Enumerable.Range(0, 2000).Select(i => (byte)(i % 250)), items["requests/h3.example.test/upload.bin"]);
        var tls = Assert.Single(result.Tls);
        Assert.Equal(("QUIC v2", "0x1303", "decrypted"), (tls.Version, tls.Cipher, tls.Outcome));
    }

    [Fact]
    public void Without_keys_the_initial_packets_still_name_the_server_and_cipher()
    {
        var (result, sections) = Read(withKeys: false);
        Assert.DoesNotContain(result.Contents.Items, i => i.Name.StartsWith("h3.example.test/", StringComparison.Ordinal));
        Assert.Empty(sections);
        var tls = Assert.Single(result.Tls);
        Assert.Equal(("h3.example.test", "0x1302", "h3", "no keys for this session"), (tls.ServerName, tls.Cipher, tls.Alpn, tls.Outcome));
    }

    [Fact]
    public void Fuzzed_captures_never_throw()
    {
        var keys = new TlsKeyLog();
        keys.Add(File.ReadAllText(Fixture("http3.keys")));
        var failures = FormatFuzz.Run(File.ReadAllBytes(Fixture("http3.pcap")), b => CaptureObjects.Read(new MemoryStream(b), keys, AnalysisLimits.Default, default), 200);
        Assert.True(failures.Count == 0, string.Join("\n", failures.Take(20)));
    }

    private static QlogFileView.Facts Qlog(string path, long offset = 0, int? limit = null)
    {
        var f = FileInput.Open(path);
        f.Options = new FileViewOptions("qlog", Offset: offset, Limit: limit);
        return (QlogFileView.Facts)new QlogFileView().Inspect(f, default)!.Detail;
    }

    [Fact]
    public void A_qlog_trace_reports_its_vantage_point_packets_and_a_page_of_events()
    {
        var q = Qlog(Fixture("client.qlog"), offset: 270, limit: 5);
        Assert.Equal(("JSON", "0.3", 278L), (q.Format, q.Version, q.Events));
        var t = Assert.Single(q.Traces);
        Assert.Equal(("client", "55ce5ddd70142556", 278L, 1L), (t.Vantage, t.Odcid, t.Events, t.Dropped));
        Assert.Equal(new Dictionary<string, long> { ["1RTT"] = 23, ["initial"] = 2, ["handshake"] = 1 }, t.PacketsSent);
        Assert.Equal(new Dictionary<string, long> { ["1RTT"] = 59, ["initial"] = 1, ["handshake"] = 1 }, t.PacketsReceived);
        Assert.Equal(61, t.Counts["transport:packet_received"]);
        Assert.Equal(5, q.Page.Count);
        Assert.Equal(275, q.Next);
        Assert.Equal(308, Qlog(Fixture("server.qlog")).Traces[0].Events);
    }

    [Fact]
    public void Json_seq_and_draft_array_events_read_as_the_json_form_does()
    {
        using var dir = new TempDir();
        var seq = dir.File("client.sqlog");
        var doc = System.Text.Json.Nodes.JsonNode.Parse(File.ReadAllText(Fixture("client.qlog")))!;
        var trace = doc["traces"]![0]!;
        var sb = new StringBuilder();
        sb.Append('\x1E').Append("""{"qlog_version":"0.3","qlog_format":"JSON-SEQ","trace":{"vantage_point":{"type":"client"},"common_fields":{"ODCID":"55ce5ddd70142556"}}}""").Append('\n');
        foreach (var e in trace["events"]!.AsArray()) sb.Append('\x1E').Append(e!.ToJsonString()).Append('\n');
        File.WriteAllText(seq, sb.ToString());
        var q = Qlog(seq);
        Assert.Equal(("JSON-SEQ", 278L, "client"), (q.Format, q.Events, q.Traces[0].Vantage));
        Assert.Equal(26, q.Traces[0].PacketsSent.Values.Sum());

        // Draft 02 form: events are arrays named by event_fields.
        var draft = dir.File("draft.qlog");
        File.WriteAllText(draft, """
            {"qlog_version":"draft-02","traces":[{"vantage_point":{"type":"server"},"event_fields":["relative_time","category","event","data"],
             "events":[[0,"transport","packet_sent",{"packet_type":"initial"}],[3.5,"transport","packet_received",{"packet_type":"1RTT"}],
                       [9,"connectivity","connection_closed",{"owner":"local","error_code":0,"reason":"done"}]]}]}
            """);
        var d = Qlog(draft);
        var t = Assert.Single(d.Traces);
        Assert.Equal(("server", 3L, 0.0, 9.0), (t.Vantage, t.Events, t.First, t.Last));
        Assert.Equal(1, t.PacketsSent["initial"]);
        Assert.Equal(["local, error_code=0, reason \"done\""], t.Closes);
    }

    [Fact]
    [FuzzEntry(typeof(Core.Pcap.Qlog), typeof(QlogFileView))]
    public void Fuzzed_qlog_files_never_throw()
    {
        using var dir = new TempDir();
        var path = dir.File("fuzz.qlog");
        var failures = FormatFuzz.Run(File.ReadAllBytes(Fixture("server.qlog")).AsSpan(0, 6000).ToArray(), b =>
        {
            File.WriteAllBytes(path, b);
            try { new QlogFileView().Inspect(FileInput.Open(path), default); }
            catch (ToolError e) when (e.Code == ErrorCode.MalformedInput) { }
        }, 200);
        Assert.True(failures.Count == 0, string.Join("\n", failures.Take(20)));
    }

    // tshark (CORVUS_TSHARK) decodes the fixture with its key log; compared: every HTTP/3 field section, its stream and its
    // field lines in order.
    [RequiresRealDataFact("CORVUS_TSHARK")]
    [Trait("Speed", "Slow")]
    public void Field_sections_equal_what_tshark_decodes()
    {
        var run = ExternalTools.Run(RealData.Path("CORVUS_TSHARK"), ["-r", Fixture("http3.pcap"), "-o", "tls.keylog_file:" + Fixture("http3.keys"),
            "-Y", "http3.headers.header", "-T", "fields", "-E", "separator=|", "-E", "occurrence=a", "-e", "quic.stream.stream_id",
            "-e", "http3.header.header.name", "-e", "http3.headers.header.value"], TimeSpan.FromMinutes(5), 1 << 26, default);
        Assert.Equal(0, run.ExitCode);
        var expected = new List<string>();
        foreach (var line in run.Text.Replace("\r", "").Split('\n', StringSplitOptions.RemoveEmptyEntries))
        {
            var parts = line.Split('|');
            var names = parts[1].Split(',');
            var values = parts[2].Split(',');
            // A frame carrying several streams lists them all; its headers belong to the request stream (id % 4 == 0).
            long stream = parts[0].Split(',').Select(long.Parse).Where(s => s % 4 == 0).Last();
            expected.Add($"{stream} " + string.Join("; ", names.Zip(values, (n, v) => $"{n}={v}")));
        }
        var (_, sections) = Read(withKeys: true);
        var actual = sections.Select(s => $"{s.Stream} " + string.Join("; ", s.Fields.Select(f => $"{f.Name}={f.Value}"))).ToList();
        foreach (var a in actual) output.WriteLine(a);
        Assert.Equal(expected, actual);
    }
}
