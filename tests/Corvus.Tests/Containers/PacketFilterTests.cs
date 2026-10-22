using Corvus.Core;
using Corvus.Core.Pcap;
using Corvus.Services.Analysis;
using Xunit.Abstractions;
using static Corvus.Tests.PcapTests;

namespace Corvus.Tests;

/// <summary>search_container kind=packet: display filters over in-process fields, rows, paging and errors.</summary>
public sealed class PacketFilterTests : IDisposable
{
    private readonly TempDir _dir = new();
    private readonly AssemblyWorkspace _ws = new();
    public void Dispose() { _ws.Dispose(); _dir.Dispose(); }

    /// <summary>Frame numbers matching <paramref name="filter"/> on the split-hello capture (8 frames, see <see cref="PcapTests.Packets"/>).</summary>
    private static List<long> Frames(string filter, byte[]? capture = null)
    {
        var result = PacketQuery.Run(new MemoryStream(capture ?? Pcap(EthernetFrames(splitHello: true))), PacketFilter.Parse(filter), 0, 1000, default);
        return [.. result.Rows.Select(r => r.Frame)];
    }

    [Theory]
    [InlineData("*", new long[] { 1, 2, 3, 4, 5, 6, 7, 8 })]
    [InlineData("udp", new long[] { 1, 2 })]
    [InlineData("not udp", new long[] { 3, 4, 5, 6, 7, 8 })]
    [InlineData("ip.addr==8.8.8.8", new long[] { 1, 2 })]
    [InlineData("ip.src == 10.0.0.0/8 && tcp.port == 443", new long[] { 3, 5, 6, 7 })]
    [InlineData("ip.dst != 93.184.216.34", new long[] { 1, 2, 4 })]
    [InlineData("tcp.flags.syn==1 and tcp.flags.ack==0", new long[] { 3 })]
    [InlineData("tcp.dstport in {80, 443} and tcp.len > 0", new long[] { 5, 6, 7, 8 })]
    [InlineData("(udp.port == 53) or (tcp.dstport == 80)", new long[] { 1, 2, 8 })]
    public void Addresses_ports_and_protocols(string filter, long[] frames) => Assert.Equal(frames, Frames(filter));

    [Theory]
    [InlineData("dns.qry.name contains \"example\"", new long[] { 1, 2 })]
    [InlineData("dns.a == 93.184.216.34", new long[] { 2 })]
    [InlineData("dns.cname matches \"^EDGE\\\\.\"", new long[] { 2 })]
    [InlineData("dns.flags.response == 0", new long[] { 1 })]
    [InlineData("http.host == \"api.example.com\" && http.request.method == GET", new long[] { 8 })]
    [InlineData("http.request.uri contains \"/users/\"", new long[] { 8 })]
    [InlineData("tls.sni == \"api.example.com\"", new long[] { 7 })]
    [InlineData("tls.handshake.extensions_alpn_str == h2", new long[] { 7 })]
    [InlineData("tls.handshake.ja4 == \"t12d0103h2_0f2cb44170f4_4298e3b3ed58\" and tls.handshake.ja3 contains \"\"", new long[] { 7 })]
    [InlineData("tls", new long[] { 7 })]
    public void Dns_http_and_tls_fields(string filter, long[] frames) => Assert.Equal(frames, Frames(filter));

    [Fact]
    public void Rows_carry_time_endpoints_and_the_named_fields_paged()
    {
        var path = _dir.File("c.pcapng");
        File.WriteAllBytes(path, PcapNg(EthernetFrames(), Sll(Udp(Client, 40000, Resolver, 53, DnsQuery()))));
        var search = new UnpackService(_ws).Search(path, "dns.qry.name == api.example.com", "packet", 2, AnalysisLimits.Default, default, offset: 1);
        Assert.Equal((3, 1), (search.Total, search.Offset));
        Assert.Equal(["2", "7"], search.Items.Select(m => m.Path));
        Assert.Equal("frame 2 2023-11-14T22:13:20.000000Z 8.8.8.8:53 -> 10.0.0.2:53000 dns", search.Items[0].Name);
        Assert.Equal("dns.qry.name=api.example.com", search.Items[0].Detail);
        Assert.Equal("pcapng capture", search.Container);
    }

    [Fact]
    public void Bad_filters_are_reported()
    {
        var path = _dir.File("c.pcap");
        File.WriteAllBytes(path, Pcap(EthernetFrames()));
        var search = new UnpackService(_ws);
        var syntax = Assert.Throws<ToolError>(() => search.Search(path, "ip.addr == ", "packet", 10, AnalysisLimits.Default, default));
        Assert.Equal(ErrorCode.InvalidArgument, syntax.Code);
        var address = Assert.Throws<ToolError>(() => search.Search(path, "ip.addr == example.com", "packet", 10, AnalysisLimits.Default, default));
        Assert.Contains("needs an address", address.Message);
    }

    [Fact]
    public void Fuzzed_capture_never_throws_under_every_field()
    {
        var filter = PacketFilter.Parse(string.Join(" or ", PacketFields.Names));
        var failures = FormatFuzz.Run(Pcap(EthernetFrames(splitHello: true)), b => PacketQuery.Run(new MemoryStream(b), filter, 0, 10, default), 1500);
        Assert.True(failures.Count == 0, string.Join("\n", failures.Take(20)));
    }
}

/// <summary>Filter throughput on a 1 GiB pcapng, measured without other tests running.</summary>
[Collection(nameof(SerialTimingTests))]
public sealed class PacketFilterSpeedTests(ITestOutputHelper output) : IDisposable
{
    private readonly TempDir _dir = new();
    private readonly AssemblyWorkspace _ws = new();
    public void Dispose() { _ws.Dispose(); _dir.Dispose(); }

    [Fact]
    [Trait("Speed", "Slow")]
    [Trait(PerfBudget.Trait, PerfBudget.Timing)]
    public void One_gigabyte_pcapng_filters_at_200_megabytes_per_second()
    {
        // one round: the 8 frames of a DNS lookup, a split ClientHello and an HTTP request, then 40 bulk segments of 1,400 bytes
        var frames = EthernetFrames(splitHello: true);
        for (int i = 0; i < 40; i++) frames.Add(Ethernet(Tcp(Web, 443, Client, 50000, 0x10, (uint)(5001 + i * 1400), new byte[1400])));
        var round = new MemoryStream();
        foreach (var f in frames) round.Write(Block(6, [.. Le(0, 0, 0, (uint)f.Length, (uint)f.Length), .. f]));
        var path = _dir.File("large.pcapng");
        long rounds = (1L << 30) / round.Length;
        using (var o = new FileStream(path, FileMode.Create, FileAccess.Write, FileShare.None, 1 << 20))
        {
            o.Write(Block(0x0A0D0D0A, [.. Le(0x1A2B3C4D), 1, 0, 0, 0, .. Enumerable.Repeat((byte)0xFF, 8)]));
            o.Write(Block(1, [1, 0, 0, 0, .. Le(65535)]));
            var bytes = round.ToArray();
            for (long r = 0; r < rounds; r++) o.Write(bytes);
        }
        long length = new FileInfo(path).Length;
        var clock = System.Diagnostics.Stopwatch.StartNew();
        var search = new UnpackService(_ws).Search(path,
            "(ip.addr == 8.8.8.8 and dns.qry.name contains \"example\") or tls.sni == api.example.com or http.host == \"api.example.com\"",
            "packet", 10, AnalysisLimits.Default, default);
        clock.Stop();
        double rate = length / clock.Elapsed.TotalSeconds / (1 << 20);
        output.WriteLine($"{length:N0} bytes, {rounds * frames.Count:N0} frames in {clock.Elapsed.TotalSeconds:F2} s: {rate:F0} MB/s, {search.Total:N0} matches");
        Assert.Equal(rounds * 4, search.Total);
        PerfBudget.Check(rate >= 200, $"{rate:F0} MB/s", output);
    }
}
