using System.Buffers.Binary;
using System.Text;
using Corvus.Core;
using Corvus.Core.Pcap;
using Corvus.Services.Analysis;

namespace Corvus.Tests;

/// <summary>pcap / pcapng reading (link types, byte orders, time resolutions), flows, DNS, TLS ClientHello, HTTP; summarize_file view=pcap and kind=endpoint.</summary>
public sealed class PcapTests : IDisposable
{
    private readonly TempDir _dir = new();
    private readonly AssemblyWorkspace _ws = new();
    public void Dispose() { _ws.Dispose(); _dir.Dispose(); }

    internal static readonly byte[] Client = [10, 0, 0, 2], Web = [93, 184, 216, 34], Resolver = [8, 8, 8, 8];
    internal const long T0 = 1_700_000_000;

    // ---- packet builders ----

    internal static byte[] Ipv4(byte protocol, byte[] src, byte[] dst, byte[] transport)
    {
        var ip = new byte[20 + transport.Length];
        ip[0] = 0x45;
        BinaryPrimitives.WriteUInt16BigEndian(ip.AsSpan(2), (ushort)ip.Length);
        ip[8] = 64;
        ip[9] = protocol;
        src.CopyTo(ip, 12);
        dst.CopyTo(ip, 16);
        transport.CopyTo(ip, 20);
        return ip;
    }

    internal static byte[] Tcp(byte[] src, ushort sport, byte[] dst, ushort dport, byte flags, uint seq, byte[] payload)
    {
        var t = new byte[20 + payload.Length];
        BinaryPrimitives.WriteUInt16BigEndian(t, sport);
        BinaryPrimitives.WriteUInt16BigEndian(t.AsSpan(2), dport);
        BinaryPrimitives.WriteUInt32BigEndian(t.AsSpan(4), seq);
        t[12] = 5 << 4;
        t[13] = flags;
        payload.CopyTo(t, 20);
        return Ipv4(6, src, dst, t);
    }

    internal static byte[] Udp(byte[] src, ushort sport, byte[] dst, ushort dport, byte[] payload)
    {
        var u = new byte[8 + payload.Length];
        BinaryPrimitives.WriteUInt16BigEndian(u, sport);
        BinaryPrimitives.WriteUInt16BigEndian(u.AsSpan(2), dport);
        BinaryPrimitives.WriteUInt16BigEndian(u.AsSpan(4), (ushort)u.Length);
        payload.CopyTo(u, 8);
        return Ipv4(17, src, dst, u);
    }

    internal static byte[] Ethernet(byte[] ip, bool vlan = false) =>
        [.. new byte[12], .. vlan ? new byte[] { 0x81, 0x00, 0x00, 0x05 } : [], 0x08, 0x00, .. ip];

    internal static byte[] Sll(byte[] ip) => [0, 0, 0, 1, 0, 6, .. new byte[8], 0x08, 0x00, .. ip];

    internal static byte[] Name(string name) => [.. name.Split('.').SelectMany(l => (byte[])[(byte)l.Length, .. Encoding.ASCII.GetBytes(l)]), 0];

    internal static byte[] DnsQuery() => [0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0, .. Name("api.example.com"), 0, 1, 0, 1];

    /// <summary>api.example.com CNAME edge.example.net (at offset 45), then edge.example.net (a pointer to it) A 93.184.216.34.</summary>
    internal static byte[] DnsResponse() =>
    [
        0x12, 0x34, 0x81, 0x80, 0, 1, 0, 2, 0, 0, 0, 0, .. Name("api.example.com"), 0, 1, 0, 1,
        0xC0, 0x0C, 0, 5, 0, 1, 0, 0, 0, 60, 0, 18, .. Name("edge.example.net"),
        0xC0, 45, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, .. Web,
    ];

    internal static byte[] ClientHello(string sni, params string[] alpn)
    {
        byte[] U16(int v) => [(byte)(v >> 8), (byte)v];
        byte[] host = Encoding.ASCII.GetBytes(sni);
        byte[] sniExt = [0, 0, .. U16(host.Length + 5), .. U16(host.Length + 3), 0, .. U16(host.Length), .. host];
        byte[] list = [.. alpn.SelectMany(a => (byte[])[(byte)a.Length, .. Encoding.ASCII.GetBytes(a)])];
        byte[] alpnExt = [0, 16, .. U16(list.Length + 2), .. U16(list.Length), .. list];
        byte[] padding = [0, 21, .. U16(300), .. new byte[300]]; // makes the hello span two segments when split
        byte[] extensions = [.. sniExt, .. alpnExt, .. padding];
        byte[] body = [3, 3, .. new byte[32], 0, 0, 2, 0x13, 0x01, 1, 0, .. U16(extensions.Length), .. extensions];
        byte[] handshake = [1, 0, .. U16(body.Length), .. body];
        return [0x16, 3, 1, .. U16(handshake.Length), .. handshake];
    }

    internal static readonly byte[] Request = Encoding.ASCII.GetBytes("GET /users/42?token=secret HTTP/1.1\r\nUser-Agent: t\r\nHOST: api.example.com\r\n\r\n");

    /// <summary>A DNS lookup, a TLS connection (SYN, then the ClientHello in one or two segments, VLAN tagged) and an HTTP request.</summary>
    internal static List<byte[]> Packets(bool splitHello = false)
    {
        var hello = ClientHello("api.example.com", "h2", "http/1.1");
        var list = new List<byte[]>
        {
            Udp(Client, 53000, Resolver, 53, DnsQuery()),
            Udp(Resolver, 53, Client, 53000, DnsResponse()),
            Tcp(Client, 50000, Web, 443, 0x02, 1000, []),
            Tcp(Web, 443, Client, 50000, 0x12, 5000, []),
        };
        if (splitHello)
        {
            list.Add(Tcp(Client, 50000, Web, 443, 0x18, 1001, hello[..40]));
            list.Add(Tcp(Client, 50000, Web, 443, 0x18, 1001, hello[..40])); // a retransmission
            list.Add(Tcp(Client, 50000, Web, 443, 0x18, 1041, hello[40..]));
        }
        else list.Add(Tcp(Client, 50000, Web, 443, 0x18, 1001, hello));
        list.Add(Tcp(Client, 50001, Web, 80, 0x18, 1, Request));
        return list;
    }

    // ---- capture writers ----

    internal static byte[] Pcap(IReadOnlyList<byte[]> frames, int linkType = 1, bool big = false, bool nano = false)
    {
        var o = new MemoryStream();
        void U32(uint v) { var b = new byte[4]; if (big) BinaryPrimitives.WriteUInt32BigEndian(b, v); else BinaryPrimitives.WriteUInt32LittleEndian(b, v); o.Write(b); }
        void U16(ushort v) { var b = new byte[2]; if (big) BinaryPrimitives.WriteUInt16BigEndian(b, v); else BinaryPrimitives.WriteUInt16LittleEndian(b, v); o.Write(b); }
        U32(nano ? 0xA1B23C4D : 0xA1B2C3D4); U16(2); U16(4); U32(0); U32(0); U32(65535); U32((uint)linkType);
        for (int i = 0; i < frames.Count; i++)
        {
            U32((uint)(T0 + i)); U32(nano ? 250_000_000u : 250_000u); U32((uint)frames[i].Length); U32((uint)frames[i].Length);
            o.Write(frames[i]);
        }
        return o.ToArray();
    }

    internal static byte[] Block(uint type, byte[] body)
    {
        var padded = body.Length % 4 == 0 ? body : [.. body, .. new byte[4 - body.Length % 4]];
        uint length = (uint)(12 + padded.Length);
        var b = new byte[length];
        BinaryPrimitives.WriteUInt32LittleEndian(b, type);
        BinaryPrimitives.WriteUInt32LittleEndian(b.AsSpan(4), length);
        padded.CopyTo(b, 8);
        BinaryPrimitives.WriteUInt32LittleEndian(b.AsSpan((int)length - 4), length);
        return b;
    }

    internal static byte[] Le(params uint[] values) => [.. values.SelectMany(BitConverter.GetBytes)];

    /// <summary>Interface 0 Ethernet (microseconds), interface 1 SLL with if_tsresol 9 (nanoseconds); one frame each, a skipped block between.</summary>
    internal static byte[] PcapNg(IReadOnlyList<byte[]> ethernet, byte[] sll)
    {
        var o = new MemoryStream();
        o.Write(Block(0x0A0D0D0A, [.. Le(0x1A2B3C4D), 1, 0, 0, 0, .. Enumerable.Repeat((byte)0xFF, 8)]));
        o.Write(Block(1, [1, 0, 0, 0, .. Le(65535)]));
        o.Write(Block(1, [113, 0, 0, 0, .. Le(65535), 9, 0, 1, 0, 9, 0, 0, 0, 0, 0, 0, 0]));
        o.Write(Block(5, Le(0, 0))); // interface statistics: skipped
        ulong micros = (ulong)T0 * 1_000_000;
        foreach (var f in ethernet)
            o.Write(Block(6, [.. Le(0, (uint)(micros >> 32), (uint)micros, (uint)f.Length, (uint)f.Length), .. f]));
        ulong nanos = (ulong)(T0 + 10) * 1_000_000_000;
        o.Write(Block(6, [.. Le(1, (uint)(nanos >> 32), (uint)nanos, (uint)sll.Length, (uint)sll.Length), .. sll]));
        return o.ToArray();
    }

    internal static List<byte[]> EthernetFrames(bool splitHello = false) =>
        [.. Packets(splitHello).Select((p, i) => Ethernet(p, vlan: i == 2))];

    // ---- tests ----

    [Fact]
    public void Pcap_flows_have_client_server_counts_and_times()
    {
        var c = CaptureAnalysis.Read(Pcap(EthernetFrames()), default);
        Assert.Empty(c.Issues);
        Assert.Equal(("pcap", 6L), (c.Format, c.Packets));
        Assert.Equal(new DateTime(2023, 11, 14, 22, 13, 20, 250, DateTimeKind.Utc), c.First);
        var flows = c.Flows().Select(f => $"{f.Protocol} {f.Client} > {f.Server} {f.Packets}").Order().ToList();
        Assert.Equal(["tcp 10.0.0.2:50000 > 93.184.216.34:443 3", "tcp 10.0.0.2:50001 > 93.184.216.34:80 1", "udp 10.0.0.2:53000 > 8.8.8.8:53 2"], flows);
        Assert.Equal(4L, c.Protocols["tcp"]);
    }

    [Fact]
    public void Pcap_big_endian_nanoseconds_reads_the_same()
    {
        var c = CaptureAnalysis.Read(Pcap(EthernetFrames(), big: true, nano: true), default);
        Assert.Empty(c.Issues);
        Assert.Equal(6L, c.Packets);
        Assert.Equal(new DateTime(2023, 11, 14, 22, 13, 20, 250, DateTimeKind.Utc), c.First);
        Assert.Equal(3, c.FlowCount);
    }

    [Fact]
    public void Pcapng_interfaces_keep_their_link_types_and_resolutions()
    {
        var sll = Sll(Udp(Client, 40000, Resolver, 53, DnsQuery()));
        var c = CaptureAnalysis.Read(PcapNg(EthernetFrames(), sll), default);
        Assert.Empty(c.Issues);
        Assert.Equal(("pcapng", 2, 7L), (c.Format, c.Interfaces, c.Packets));
        Assert.Equal([1, 113], c.LinkTypes);
        Assert.Equal(DateTime.UnixEpoch.AddSeconds(T0 + 10), c.Last);
        Assert.Contains(c.Flows(), f => f.Client == "10.0.0.2:40000" && f.Server == "8.8.8.8:53");
    }

    [Fact]
    public void Dns_questions_and_answers_follow_compression()
    {
        var c = CaptureAnalysis.Read(Pcap(EthernetFrames()), default);
        var names = c.DnsNames().ToDictionary(d => d.Name);
        Assert.Equal((1, 1, "A"), (names["api.example.com"].Queries, names["api.example.com"].Responses, Assert.Single(names["api.example.com"].Types)));
        Assert.Equal("CNAME edge.example.net", Assert.Single(names["api.example.com"].Answers));
        Assert.Equal("A 93.184.216.34", Assert.Single(names["edge.example.net"].Answers));
    }

    [Fact]
    public void Tls_client_hello_gives_sni_and_alpn()
    {
        var c = CaptureAnalysis.Read(Pcap(EthernetFrames()), default);
        var tls = Assert.Single(c.ServerNames());
        Assert.Equal(("api.example.com", 1), (tls.ServerName, tls.Hellos));
        Assert.Equal(["h2", "http/1.1"], tls.Alpn);
        Assert.Equal("93.184.216.34:443", Assert.Single(tls.Servers));
        Assert.Equal("api.example.com", c.Flows().Single(f => f.Server.EndsWith(":443", StringComparison.Ordinal)).ServerName);
    }

    [Fact]
    public void Tls_client_hello_split_over_segments_is_joined()
    {
        var c = CaptureAnalysis.Read(Pcap(EthernetFrames(splitHello: true)), default);
        var tls = Assert.Single(c.ServerNames());
        Assert.Equal(("api.example.com", 1), (tls.ServerName, tls.Hellos));
        Assert.Equal(["h2", "http/1.1"], tls.Alpn);
    }

    [Fact]
    public void Http_request_line_and_host_header()
    {
        var c = CaptureAnalysis.Read(Pcap(EthernetFrames()), default);
        Assert.Equal(new CaptureHttpRequest("GET", "api.example.com", "/users/42?token=secret", 1), Assert.Single(c.Requests()));
    }

    [Fact]
    public void Sll_and_raw_ip_link_types_decode()
    {
        var raw = CaptureAnalysis.Read(Pcap(Packets(), linkType: 101), default);
        var sll = CaptureAnalysis.Read(Pcap([.. Packets().Select(Sll)], linkType: 113), default);
        Assert.Equal((3, 3), (raw.FlowCount, sll.FlowCount));
        Assert.Single(sll.ServerNames());
    }

    [Fact]
    public void Flow_cap_is_noted()
    {
        var frames = Enumerable.Range(0, CaptureAnalysis.MaxFlows + 5).Select(i => Udp(Client, (ushort)(1024 + i % 60000), [10, 0, (byte)(i >> 8), (byte)i], 9999, [])).ToList();
        var c = CaptureAnalysis.Read(Pcap(frames, linkType: 101), default);
        Assert.Equal(CaptureAnalysis.MaxFlows, c.FlowCount);
        Assert.Contains(c.Notes, n => n.StartsWith($"stopped at {CaptureAnalysis.MaxFlows:N0} flows", StringComparison.Ordinal));
    }

    [Fact]
    public void View_summarizes_a_capture()
    {
        var bytes = Pcap(EthernetFrames());
        var view = new PcapFileView().Inspect(new FileInput("c.pcap", bytes, Blob.Identify(bytes)), default)!;
        var facts = (PcapFileView.Facts)view.Detail;
        Assert.Equal(["Ethernet"], facts.LinkTypes);
        Assert.Equal(new PcapFileView.Request("api.example.com", "GET http://api.example.com/users/{n}?token=…", 1), Assert.Single(facts.Http));
        Assert.Contains(view.Highlights, h => h.StartsWith("pcap capture (Ethernet): 6 packets, 3 TCP/UDP flows", StringComparison.Ordinal));
        Assert.Contains("TLS server names: api.example.com.", view.Highlights);
        Assert.Null(new PcapFileView().Inspect(new FileInput("x.bin", [1, 2, 3, 4], "data"), default));
    }

    [Fact]
    public void Endpoint_search_lists_capture_rows()
    {
        var path = _dir.File("capture.pcapng");
        File.WriteAllBytes(path, PcapNg(EthernetFrames(), Sll(Udp(Client, 40000, Resolver, 53, DnsQuery()))));
        var rows = new UnpackService(_ws).Search(path, "*", "endpoint", 100, AnalysisLimits.Default, default).Items.Select(m => $"{m.Name} | {m.Detail}").ToList();
        Assert.Contains("GET http://api.example.com/users/{n}?token=… | 1 request(s)", rows);
        Assert.Contains("tls://api.example.com | 1 ClientHello(s), ALPN h2, http/1.1", rows);
        Assert.Contains("dns://api.example.com | 2 query(ies), CNAME edge.example.net", rows);
        Assert.DoesNotContain(rows, r => r.Contains("secret", StringComparison.Ordinal));
    }

    [Fact]
    [FuzzEntry(typeof(CaptureAnalysis))]
    public void Fuzzed_pcap_never_throws()
    {
        var failures = FormatFuzz.Run(Pcap(EthernetFrames(splitHello: true)), b => CaptureAnalysis.Read(b, default), 1500);
        Assert.True(failures.Count == 0, string.Join("\n", failures.Take(20)));
    }

    [Fact]
    [FuzzEntry(typeof(PcapFileView))]
    public void Fuzzed_pcapng_never_throws()
    {
        var seed = PcapNg(EthernetFrames(splitHello: true), Sll(Udp(Resolver, 53, Client, 40000, DnsResponse())));
        var failures = FormatFuzz.Run(seed, b => new PcapFileView().Inspect(new FileInput("c.pcapng", b, "data"), default), 1500);
        Assert.True(failures.Count == 0, string.Join("\n", failures.Take(20)));
    }
}
