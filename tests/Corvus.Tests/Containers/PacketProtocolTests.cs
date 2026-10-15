using System.Buffers.Binary;
using System.Text;
using Corvus.Core;
using Corvus.Core.Pcap;
using Corvus.Native.Providers;
using Corvus.Services.Analysis;
using Xunit.Abstractions;
using static Corvus.Tests.PcapTests;

namespace Corvus.Tests;

/// <summary>Captures of cleartext HTTP/2, QUIC Initials, SMB2 and Kerberos, built frame by frame.</summary>
internal static class ProtocolCaptures
{
    private static readonly byte[] Server = [10, 0, 0, 9];

    private static byte[] Ascii(string s) => Encoding.ASCII.GetBytes(s);
    private static byte[] Utf16(string s) => Encoding.Unicode.GetBytes(s);

    // ---- HTTP/2 ----

    private static byte[] H2(byte type, byte flags, uint stream, byte[] payload) =>
        [(byte)(payload.Length >> 16), (byte)(payload.Length >> 8), (byte)payload.Length, type, flags, (byte)(stream >> 24), (byte)(stream >> 16), (byte)(stream >> 8), (byte)stream, .. payload];

    private static byte[] Literal(string s) => [(byte)s.Length, .. Ascii(s)];

    /// <summary>
    /// h2c on port 80: frame 1 the preface, SETTINGS and GET /api/v1 (Huffman authority, three entries added to the dynamic
    /// table); 2 the server's SETTINGS and :status 200; 3 GET /api/v2 by dynamic indexes, its HEADERS whole and its
    /// CONTINUATION started; 4 the rest of the CONTINUATION.
    /// </summary>
    public static byte[] Http2()
    {
        byte[] first = [0x82, 0x86, 0x44, .. Literal("/api/v1"), 0x41, 0x8C, .. Convert.FromHexString("F1E3C2E5F23A6BA0AB90F4FF"), 0x7A, .. Literal("corvus-test")];
        byte[] second = [0x82, 0x86, 0xBF, 0x44, .. Literal("/api/v2"), 0xBF];
        byte[] a = [.. "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"u8, .. H2(4, 0, 0, []), .. H2(1, 0x05, 1, first)];
        byte[] continuation = H2(9, 0x04, 3, second[3..]);
        byte[] b = [.. H2(1, 0x01, 3, second[..3]), .. continuation[..5]];
        byte[] c = continuation[5..];
        byte[] s = [.. H2(4, 0, 0, []), .. H2(1, 0x04, 1, [0x88])];
        return Pcap(
        [
            Ethernet(Tcp(Client, 50002, Server, 80, 0x18, 1, a)),
            Ethernet(Tcp(Server, 80, Client, 50002, 0x18, 7000, s)),
            Ethernet(Tcp(Client, 50002, Server, 80, 0x18, (uint)(1 + a.Length), b)),
            Ethernet(Tcp(Client, 50002, Server, 80, 0x18, (uint)(1 + a.Length + b.Length), c)),
        ]);
    }

    // ---- QUIC ----

    /// <summary>Frame 1 a client Initial for quic.example.com; frames 2–4 one for split.example.com over three packets.</summary>
    public static byte[] Quic()
    {
        var datagrams = File.ReadAllLines(Path.Combine(AppContext.BaseDirectory, "Containers", "QuicInitials.txt"))
            .Where(l => !l.StartsWith('#')).Select(l => Convert.FromBase64String(l.Split(' ')[1]));
        return Pcap([.. datagrams.Select((d, i) => Ethernet(Udp(Client, (ushort)(51000 + (i == 0 ? 0 : 1)), Web, 443, d)))]);
    }

    // ---- SMB2 ----

    private static byte[] Smb2(ushort command, bool response, ulong message, uint tree, byte[] body)
    {
        var h = new byte[64];
        h[0] = 0xFE; "SMB"u8.CopyTo(h.AsSpan(1));
        BinaryPrimitives.WriteUInt16LittleEndian(h.AsSpan(4), 64);
        BinaryPrimitives.WriteUInt16LittleEndian(h.AsSpan(12), command);
        BinaryPrimitives.WriteUInt16LittleEndian(h.AsSpan(14), 1);
        BinaryPrimitives.WriteUInt32LittleEndian(h.AsSpan(16), response ? 1u : 0u);
        BinaryPrimitives.WriteUInt64LittleEndian(h.AsSpan(24), message);
        BinaryPrimitives.WriteUInt32LittleEndian(h.AsSpan(36), tree);
        BinaryPrimitives.WriteUInt64LittleEndian(h.AsSpan(40), 0x1234);
        byte[] smb = [.. h, .. body];
        return [0, (byte)(smb.Length >> 16), (byte)(smb.Length >> 8), (byte)smb.Length, .. smb];
    }

    private static byte[] U16(int v) => BitConverter.GetBytes((ushort)v);
    private static byte[] U32(uint v) => BitConverter.GetBytes(v);

    /// <summary>NTLMSSP AUTHENTICATE (Unicode) with empty responses and the given domain, user and host.</summary>
    private static byte[] NtlmAuthenticate(string domain, string user, string host)
    {
        byte[] d = Utf16(domain), u = Utf16(user), w = Utf16(host);
        byte[] Field(int length, int offset) => [.. U16(length), .. U16(length), .. U32((uint)offset)];
        return [.. "NTLMSSP\0"u8, .. U32(3), .. Field(0, 64), .. Field(0, 64), .. Field(d.Length, 64), .. Field(u.Length, 64 + d.Length),
            .. Field(w.Length, 64 + d.Length + u.Length), .. Field(0, 64), .. U32(0x00000201), .. d, .. u, .. w];
    }

    /// <summary>
    /// Port 445: 1 SESSION_SETUP with NTLMSSP (EXAMPLE\alice on WS01); 2–3 TREE_CONNECT \\fs01\share (tree 5); 4–5 CREATE
    /// docs\report.txt; 6–7 READ by its file id.
    /// </summary>
    public static byte[] Smb()
    {
        byte[] fileId = Convert.FromHexString("0102030405060708090A0B0C0D0E0F10");
        var blob = NtlmAuthenticate("EXAMPLE", "alice", "WS01");
        byte[] setup = [0x19, 0, 0, 1, .. U32(0), .. U32(0), .. U16(88), .. U16(blob.Length), .. new byte[8], .. blob];
        var path = Utf16(@"\\fs01\share");
        byte[] connect = [9, 0, 0, 0, .. U16(72), .. U16(path.Length), .. path];
        byte[] connected = [16, 0, 1, 0, .. U32(0), .. U32(0), .. U32(0x1F01FF)];
        var name = Utf16(@"docs\report.txt");
        byte[] create = [57, 0, 0, 0, .. U32(2), .. new byte[16], .. U32(0x80), .. U32(0), .. U32(7), .. U32(1), .. U32(0), .. U16(120), .. U16(name.Length), .. U32(0), .. U32(0), .. name];
        byte[] created = [89, 0, 0, 0, .. U32(1), .. new byte[48], .. U32(0x20), .. U32(0), .. fileId, .. U32(0), .. U32(0), 0];
        byte[] read = [49, 0, 0x50, 0, .. U32(16), .. new byte[8], .. fileId, .. U32(0), .. U32(0), .. U32(0), .. U16(0), .. U16(0), 0];
        byte[] data = [17, 0, 0x50, 0, .. U32(4), .. U32(0), .. U32(0), .. "data"u8];
        byte[][] messages =
        [
            Smb2(1, false, 1, 0, setup), Smb2(3, false, 2, 0, connect), Smb2(3, true, 2, 5, connected), Smb2(5, false, 3, 5, create),
            Smb2(5, true, 3, 5, created), Smb2(8, false, 4, 5, read), Smb2(8, true, 4, 5, data),
        ];
        uint client = 1, server = 1;
        var frames = new List<byte[]>();
        for (int i = 0; i < messages.Length; i++)
        {
            bool response = i is 2 or 4 or 6;
            frames.Add(Ethernet(response ? Tcp(Server, 445, Client, 50445, 0x18, server, messages[i]) : Tcp(Client, 50445, Server, 445, 0x18, client, messages[i])));
            if (response) server += (uint)messages[i].Length; else client += (uint)messages[i].Length;
        }
        return Pcap(frames);
    }

    // ---- Kerberos ----

    private static byte[] Der(int tag, params byte[][] parts)
    {
        byte[] content = [.. parts.SelectMany(p => p)];
        byte[] length = content.Length < 128 ? [(byte)content.Length] : content.Length < 256 ? [0x81, (byte)content.Length] : [0x82, (byte)(content.Length >> 8), (byte)content.Length];
        return [(byte)tag, .. length, .. content];
    }

    private static byte[] Ctx(int n, byte[] inner) => Der(0xA0 | n, inner);
    private static byte[] Seq(params byte[][] parts) => Der(0x30, parts);
    private static byte[] Int(int v) => Der(0x02, [(byte)v]);
    private static byte[] Text(string s) => Der(0x1B, Ascii(s));
    private static byte[] Principal(int type, params string[] names) => Seq(Ctx(0, Int(type)), Ctx(1, Seq([.. names.Select(Text)])));
    private static byte[] Encrypted() => Seq(Ctx(0, Int(18)), Ctx(2, Der(0x04, new byte[16])));
    private static byte[] Body(byte[]? client, string service0, string service1) =>
        Seq([Ctx(0, Der(0x03, [0, 0x40, 0x81, 0, 0x10])), .. client != null ? [Ctx(1, client)] : Array.Empty<byte[]>(), Ctx(2, Text("EXAMPLE.COM")),
            Ctx(3, Principal(2, service0, service1)), Ctx(5, Der(0x18, Ascii("20370913024805Z"))), Ctx(7, Int(42)), Ctx(8, Seq(Int(18)))]);

    /// <summary>Frame 1 an AS-REQ for alice over UDP; frame 2 a TGS-REQ for cifs/fs01.example.com over TCP, its krbtgt ticket in PA-TGS-REQ.</summary>
    public static byte[] Kerberos()
    {
        var asReq = Der(0x6A, Seq(Ctx(1, Int(5)), Ctx(2, Int(10)), Ctx(4, Body(Principal(1, "alice"), "krbtgt", "EXAMPLE.COM"))));
        var ticket = Der(0x61, Seq(Ctx(0, Int(5)), Ctx(1, Text("EXAMPLE.COM")), Ctx(2, Principal(2, "krbtgt", "EXAMPLE.COM")), Ctx(3, Encrypted())));
        var apReq = Der(0x6E, Seq(Ctx(0, Int(5)), Ctx(1, Int(14)), Ctx(2, Der(0x03, [0, 0, 0, 0, 0])), Ctx(3, ticket), Ctx(4, Encrypted())));
        var tgsReq = Der(0x6C, Seq(Ctx(1, Int(5)), Ctx(2, Int(12)), Ctx(3, Seq(Seq(Ctx(1, Int(1)), Ctx(2, Der(0x04, apReq))))), Ctx(4, Body(null, "cifs", "fs01.example.com"))));
        return Pcap(
        [
            Ethernet(Udp(Client, 52000, Server, 88, asReq)),
            Ethernet(Tcp(Client, 52001, Server, 88, 0x18, 1, [.. BitConverter.GetBytes(BinaryPrimitives.ReverseEndianness(tgsReq.Length)), .. tgsReq])),
        ]);
    }
}

/// <summary>In-process HTTP/2 (HPACK), QUIC Initial, SMB2 and Kerberos fields.</summary>
public sealed class PacketProtocolTests
{
    internal static List<long> Frames(byte[] capture, string filter) =>
        [.. PacketQuery.Run(new MemoryStream(capture), PacketFilter.Parse(filter), 0, 1000, default).Rows.Select(r => r.Frame)];

    [Theory]
    [InlineData("http2", new long[] { 1, 2, 3, 4 })]
    [InlineData("http2.headers.authority == \"www.example.com\"", new long[] { 1, 3 })]
    [InlineData("http2.headers.path == \"/api/v2\"", new long[] { 4 })]
    [InlineData("http2.headers.status == 200", new long[] { 2 })]
    [InlineData("http2.header.value == \"corvus-test\"", new long[] { 1, 4 })]
    [InlineData("http2.type == 9", new long[] { 4 })]
    public void Http2_headers_decode_through_the_dynamic_table(string filter, long[] frames) =>
        Assert.Equal(frames, Frames(ProtocolCaptures.Http2(), filter));

    [Fact]
    public void Quic_initial_server_names_are_decrypted_and_joined()
    {
        var capture = ProtocolCaptures.Quic();
        Assert.Equal([1, 2, 3, 4], Frames(capture, "quic.version == 1 && quic.long.packet_type == 0"));
        Assert.Equal([1], Frames(capture, "tls.handshake.extensions_server_name == \"quic.example.com\""));
        var split = Assert.Single(Frames(capture, "tls.sni == \"split.example.com\""));
        Assert.True(split > 2, $"frame {split}: the hello ends in a later packet");
        Assert.Equal([1], Frames(capture, "tls.alpn == h3 && tls.sni contains quic"));
    }

    [Theory]
    [InlineData("smb2.cmd == 5", new long[] { 4, 5 })]
    [InlineData("smb2.tree == \"\\\\\\\\fs01\\\\share\"", new long[] { 2, 3, 4, 5, 6, 7 })]
    [InlineData("smb2.filename == \"docs\\\\report.txt\"", new long[] { 4, 5, 6, 7 })]
    [InlineData("ntlmssp.auth.username == alice && ntlmssp.auth.domain == EXAMPLE && ntlmssp.auth.hostname == WS01", new long[] { 1 })]
    public void Smb2_tree_and_file_names_follow_their_ids(string filter, long[] frames) =>
        Assert.Equal(frames, Frames(ProtocolCaptures.Smb(), filter));

    [Theory]
    [InlineData("kerberos.CNameString == alice", new long[] { 1 })]
    [InlineData("kerberos.SNameString == krbtgt", new long[] { 1, 2 })]
    [InlineData("kerberos.SNameString == \"fs01.example.com\" && kerberos.msg_type == 12", new long[] { 2 })]
    [InlineData("kerberos.realm == \"EXAMPLE.COM\"", new long[] { 1, 2 })]
    public void Kerberos_principals_and_realms(string filter, long[] frames) =>
        Assert.Equal(frames, Frames(ProtocolCaptures.Kerberos(), filter));

    [Fact]
    public void Fuzzed_protocol_captures_never_throw()
    {
        var filter = PacketFilter.Parse(string.Join(" or ", PacketFields.Names));
        foreach (var seed in new[] { ProtocolCaptures.Http2(), ProtocolCaptures.Quic(), ProtocolCaptures.Smb(), ProtocolCaptures.Kerberos() })
        {
            var failures = FormatFuzz.Run(seed, b => PacketQuery.Run(new MemoryStream(b), filter, 0, 10, default), 500);
            Assert.True(failures.Count == 0, string.Join("\n", failures.Take(20)));
        }
    }

    [Fact]
    public void Hpack_huffman_strings_decode()
    {
        Assert.Equal("www.example.com", Hpack.Huffman(Convert.FromHexString("F1E3C2E5F23A6BA0AB90F4FF")));
        Assert.Equal("no-cache", Hpack.Huffman(Convert.FromHexString("A8EB10649CBF")));
        Assert.Null(Hpack.Huffman([0xFF, 0xFF, 0xFF, 0xFF])); // the EOS symbol
    }
}

/// <summary>Fields outside the in-process set: TShark through CORVUS_TSHARK, and the answer without it.</summary>
[Collection(ExternalToolEnvironmentCollection.Name)]
public sealed class PacketTSharkTests(ITestOutputHelper output) : IDisposable
{
    private readonly TempDir _dir = new();
    private readonly AssemblyWorkspace _ws = new();
    public void Dispose() { _ws.Dispose(); _dir.Dispose(); }

    [Fact]
    public void Other_fields_need_tshark_and_name_the_variable()
    {
        var path = _dir.File("c.pcap");
        File.WriteAllBytes(path, Pcap(EthernetFrames()));
        using var env = new EnvironmentScope().Set("CORVUS_TSHARK", _dir.File("missing"));
        var e = Assert.Throws<ToolError>(() => new UnpackService(_ws).Search(path, "sip.Method == INVITE", "packet", 10, AnalysisLimits.Default, default));
        Assert.Equal(ErrorCode.Unsupported, e.Code);
        Assert.Contains("sip.Method", e.Message);
        Assert.Contains("CORVUS_TSHARK", e.Remediation);
    }

    [Fact]
    public void Other_fields_pass_to_tshark_and_its_rows_are_paged()
    {
        var path = _dir.File("c.pcap");
        File.WriteAllBytes(path, Pcap(EthernetFrames()));
        using var fake = new FakeTool();
        var lines = string.Concat(Enumerable.Range(1, 3).Select(n => $"{n}\t1700000000.5\t10.0.0.2\t\t10.0.0.9\t\t\t5060\t\t5060\tSIP\tINVITE\n"));
        fake.On("--version", stdout: "TShark (Wireshark) 4.6.9 (v4.6.9-0)\n").On("-Y sip\\.Method == INVITE", stdout: lines);
        using var env = new EnvironmentScope().Set("CORVUS_TSHARK", fake.CopyAs("tshark")).Set(FakeTool.ScriptVariable, fake.ScriptPath);
        var search = new UnpackService(_ws).Search(path, "sip.Method == INVITE", "packet", 1, AnalysisLimits.Default, default, offset: 1);
        Assert.Equal(3, search.Total);
        var row = Assert.Single(search.Items);
        Assert.Equal(("2", "frame 2 2023-11-14T22:13:20.500000Z 10.0.0.2:5060 -> 10.0.0.9:5060 sip", "sip.Method=INVITE"), (row.Path, row.Name, row.Detail));
        Assert.Contains(search.Notes, n => n.StartsWith("decoded by TShark 4.6.9", StringComparison.Ordinal));
        var call = fake.ArgumentLists.Last();
        Assert.Equal(["-e", "sip.Method"], call[^2..]);
    }

    /// <summary>TShark (CORVUS_TSHARK) selects the same frames as the in-process fields on every fixture capture.</summary>
    [Trait("Speed", "Slow")]
    [RequiresRealDataFact("CORVUS_TSHARK")]
    public void In_process_fields_select_what_tshark_selects()
    {
        var captures = new (string Name, byte[] Bytes, string[] Filters)[]
        {
            ("basic", Pcap(EthernetFrames(splitHello: true)),
            [
                "udp", "not udp", "ip.addr==8.8.8.8", "ip.src == 10.0.0.0/8 && tcp.port == 443", "ip.dst != 93.184.216.34", "tcp.flags.syn==1 and tcp.flags.ack==0",
                "tcp.dstport in {80, 443} and tcp.len > 0", "dns", "dns.qry.name contains \"example\"", "dns.a == 93.184.216.34", "dns.cname == \"edge.example.net\"",
                "dns.flags.response == 0", "dns.qry.type == 1", "http", "http.host == \"api.example.com\"", "http.request.method == \"GET\"", "http.request.uri contains \"/users/\"",
                "http.user_agent == \"t\"", "tls", "tls.handshake.extensions_server_name == \"api.example.com\"", "tls.handshake.extensions_alpn_str == \"h2\"",
            ]),
            ("http2", ProtocolCaptures.Http2(),
            [
                "http2", "http2.headers.authority == \"www.example.com\"", "http2.headers.path == \"/api/v2\"", "http2.headers.status == 200",
                "http2.header.value == \"corvus-test\"", "http2.type == 9", "http2.headers.method == \"GET\"", "http2.headers.user_agent == \"corvus-test\"",
            ]),
            ("quic", ProtocolCaptures.Quic(),
            [
                "quic", "quic.version == 1", "quic.long.packet_type == 0", "tls.handshake.extensions_server_name == \"quic.example.com\"",
                "tls.handshake.extensions_server_name == \"split.example.com\"", "tls.handshake.extensions_alpn_str == \"h3\"",
            ]),
            ("smb2", ProtocolCaptures.Smb(),
            [
                "smb2", "smb2.cmd == 5", "smb2.tree contains \"share\"", "smb2.filename == \"docs\\\\report.txt\"", "ntlmssp.auth.username == \"alice\"",
                "ntlmssp.auth.domain == \"EXAMPLE\"", "ntlmssp.auth.hostname == \"WS01\"",
            ]),
            ("kerberos", ProtocolCaptures.Kerberos(),
            [
                "kerberos", "kerberos.CNameString == \"alice\"", "kerberos.SNameString == \"krbtgt\"", "kerberos.SNameString == \"cifs\"", "kerberos.realm == \"EXAMPLE.COM\"",
                "kerberos.msg_type == 12",
            ]),
        };
        var tool = ExternalTools.TShark;
        var exe = ExternalTools.Locate(tool)!.Value.Path;
        var differ = new List<string>();
        int compared = 0;
        foreach (var (name, bytes, filters) in captures)
        {
            var path = _dir.File(name + ".pcap");
            File.WriteAllBytes(path, bytes);
            foreach (var filter in filters)
            {
                var run = ExternalTools.Run(exe, ["-r", path, "-n", "-2", "-Y", filter, "-T", "fields", "-e", "frame.number"], TimeSpan.FromMinutes(2), 1 << 20, default);
                if (run.ExitCode != 0) { differ.Add($"{name}: {filter}: tshark failed: {run.Stderr.Trim()}"); continue; }
                var expected = run.Text.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).Select(long.Parse).ToList();
                var actual = PacketProtocolTests.Frames(bytes, filter);
                compared++;
                if (!expected.SequenceEqual(actual)) differ.Add($"{name}: {filter}: tshark [{string.Join(",", expected)}], ours [{string.Join(",", actual)}]");
            }
        }
        foreach (var d in differ) output.WriteLine(d);
        output.WriteLine($"{compared - differ.Count} of {compared} filters select the same frames");
        Assert.Empty(differ);
    }
}
