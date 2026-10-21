using System.Diagnostics;
using System.IO.Compression;
using System.Text;
using System.Text.Json;
using Corvus.Core;
using Corvus.Core.Pcap;
using Corvus.Services.Analysis;
using static Corvus.Tests.PcapTests;

namespace Corvus.Tests;

/// <summary>
/// unpack_container on pcap / pcapng (W-P1-1): TCP reassembled, HTTP/1.x and HTTP/2 objects exported, TLS 1.2 and 1.3
/// decrypted with a key log (OpenSSL-made sessions), other streams written, JA3 / JA4 / JA4S fingerprints.
/// </summary>
[Collection(nameof(SerialTimingTests))] // the 1 GiB budget measures the whole process
public sealed class CaptureObjectsTests : IDisposable
{
    private readonly TempDir _dir = new();
    private readonly AssemblyWorkspace _ws = new();
    public void Dispose() { _ws.Dispose(); _dir.Dispose(); }

    private static readonly byte[] Server = [10, 0, 0, 80];

    /// <summary>
    /// One TCP connection: SYN, SYN-ACK, then each write cut into segments of <paramref name="mss"/> bytes; with
    /// <paramref name="shuffle"/> each write's segments go out of order and the first is sent twice.
    /// </summary>
    internal static List<byte[]> Connection(ushort clientPort, ushort serverPort, IEnumerable<(bool FromClient, byte[] Data)> writes, int mss = 1400,
        bool shuffle = false, byte[]? server = null, Func<bool, int, bool>? drop = null)
    {
        server ??= Server;
        uint c = 1000, s = 50_000;
        var frames = new List<byte[]>
        {
            Ethernet(Tcp(Client, clientPort, server, serverPort, 0x02, c - 1, [])),
            Ethernet(Tcp(server, serverPort, Client, clientPort, 0x12, s - 1, [])),
        };
        int index = 0;
        foreach (var (fromClient, data) in writes)
        {
            var segments = new List<byte[]>();
            for (int at = 0; at < data.Length; at += mss)
            {
                var piece = data[at..Math.Min(data.Length, at + mss)];
                uint seq = fromClient ? c : s;
                if (drop?.Invoke(fromClient, index++) != true)
                    segments.Add(Ethernet(fromClient ? Tcp(Client, clientPort, server, serverPort, 0x18, seq, piece) : Tcp(server, serverPort, Client, clientPort, 0x18, seq, piece)));
                if (fromClient) c += (uint)piece.Length; else s += (uint)piece.Length;
            }
            if (shuffle && segments.Count > 1) { segments.Reverse(); segments.Add(segments[^1]); }
            frames.AddRange(segments);
        }
        frames.Add(Ethernet(Tcp(Client, clientPort, server, serverPort, 0x11, c, [])));
        frames.Add(Ethernet(Tcp(server, serverPort, Client, clientPort, 0x11, s, [])));
        return frames;
    }

    private static byte[] A(string s) => Encoding.ASCII.GetBytes(s);

    private static byte[] Gzip(string text)
    {
        var ms = new MemoryStream();
        using (var g = new GZipStream(ms, CompressionLevel.Optimal, leaveOpen: true)) g.Write(Encoding.UTF8.GetBytes(text));
        return ms.ToArray();
    }

    private UnpackService.UnpackReport Unpack(string name, byte[] capture, string? keyLog = null)
    {
        var path = _dir.File(name);
        File.WriteAllBytes(path, capture);
        return new UnpackService(_ws).Unpack(path, _dir.File(name + "_out"), load: false, AnalysisLimits.Default, default, keyLog: keyLog);
    }

    private static Dictionary<string, byte[]> Files(UnpackService.UnpackReport r) =>
        r.Files.ToDictionary(f => Path.GetRelativePath(r.OutputDirectory, f.Path).Replace('\\', '/'), f => File.ReadAllBytes(f.Path));

    [Fact]
    public void Http1_objects_are_reassembled_from_shuffled_segments()
    {
        var json = Gzip("""{"items":[1,2,3]}""");
        var page = new string('x', 5000);
        var frames = Connection(50000, 80,
        [
            (true, A("GET /api/items?page=2 HTTP/1.1\r\nHost: shop.example.com\r\n\r\n")),
            (false, [.. A($"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Encoding: gzip\r\nContent-Length: {json.Length}\r\n\r\n"), .. json]),
            (true, A("GET /index.html HTTP/1.1\r\nHost: shop.example.com\r\n\r\n")),
            (false, A($"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nTransfer-Encoding: chunked\r\n\r\n{2500:x}\r\n{page[..2500]}\r\n{2500:x}\r\n{page[2500..]}\r\n0\r\n\r\n")),
            (true, A("HEAD /index.html HTTP/1.1\r\nHost: shop.example.com\r\n\r\n")),
            (false, A("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 5000\r\n\r\n")),
            (true, A("GET /logo.png HTTP/1.1\r\nHost: shop.example.com\r\n\r\n")),
            (false, A("HTTP/1.1 304 Not Modified\r\n\r\n")),
        ], mss: 700, shuffle: true);
        var report = Unpack("shop.pcap", Pcap(frames));
        var files = Files(report);
        Assert.Equal("""{"items":[1,2,3]}""", Encoding.UTF8.GetString(files.Single(f => f.Key.StartsWith("shop.example.com/api/items_q", StringComparison.Ordinal)).Value));
        Assert.Equal(page, Encoding.ASCII.GetString(files["shop.example.com/index.html"]));
        Assert.Equal(2, files.Count);
        Assert.Contains(report.Notes, n => n.StartsWith("4 response(s), 2 with a body", StringComparison.Ordinal));
        Assert.Contains(report.Notes, n => n.Contains("1 TCP connection(s) reassembled.", StringComparison.Ordinal));
    }

    [Fact]
    public void A_gap_is_counted_and_marked_on_the_body_it_cuts()
    {
        var body = new string('a', 3000);
        // segment 2 of the response (bytes 1400-2799 of the write) is never captured
        var frames = Connection(50001, 80,
        [
            (true, A("GET /big.txt HTTP/1.1\r\nHost: files.example.com\r\n\r\n")),
            (false, A($"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {body.Length}\r\n\r\n{body}")),
        ], drop: (fromClient, i) => !fromClient && i == 2);
        var report = Unpack("gap.pcap", Pcap(frames));
        Assert.Contains(report.Notes, n => n.Contains("1 gap(s) of 1,400 bytes never captured", StringComparison.Ordinal));
        Assert.Equal(body.Length - 1400, Files(report)["files.example.com/big.txt"].Length);
        var entry = Assert.Single(CaptureObjects.Read(new MemoryStream(Pcap(frames)), null, AnalysisLimits.Default, default).Contents.Entries!);
        Assert.Contains("1,400 body bytes not captured", entry.Detail);
    }

    [Fact]
    public void Request_bodies_are_exported_under_requests()
    {
        var frames = Connection(50004, 80,
        [
            (true, A("POST /upload HTTP/1.1\r\nHost: files.example.com\r\nContent-Type: text/plain\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n")),
            (false, A("HTTP/1.1 201 Created\r\nContent-Type: application/json\r\nContent-Length: 9\r\n\r\n{\"id\":42}")),
        ]);
        var report = Unpack("post.pcap", Pcap(frames));
        var files = Files(report);
        Assert.Equal("hello world", Encoding.ASCII.GetString(files["requests/files.example.com/upload.txt"]));
        Assert.Equal("{\"id\":42}", Encoding.ASCII.GetString(files["files.example.com/upload.json"]));
        Assert.Contains(report.Notes, n => n.StartsWith("1 response(s), 1 with a body; 1 request body(ies) under requests/", StringComparison.Ordinal));
    }

    private static byte[] WithAck(byte[] frame, uint ack)
    {
        System.Buffers.Binary.BinaryPrimitives.WriteUInt32BigEndian(frame.AsSpan(14 + 20 + 8), ack); // Ethernet, IPv4, TCP acknowledgment number
        return frame;
    }

    [Fact]
    public void A_hole_the_receiver_acknowledged_ends_at_once_and_the_next_response_pairs_with_its_request()
    {
        // the answer to /one is never captured; the client's ACKs pass it, so /two and /three are answered in step
        static byte[] Response(string body) => A($"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {body.Length}\r\n\r\n{body}");
        byte[] one = Response("first"), two = Response("second"), three = Response("third");
        byte[] get1 = A("GET /one HTTP/1.1\r\nHost: files.example.com\r\n\r\n"), get2 = A("GET /two HTTP/1.1\r\nHost: files.example.com\r\n\r\n"), get3 = A("GET /three HTTP/1.1\r\nHost: files.example.com\r\n\r\n");
        uint c = 1000, s = 50_000;
        ushort port = 50005;
        var frames = new List<byte[]>
        {
            Ethernet(Tcp(Client, port, Server, 80, 0x02, c - 1, [])),
            Ethernet(Tcp(Server, 80, Client, port, 0x12, s - 1, [])),
            WithAck(Ethernet(Tcp(Client, port, Server, 80, 0x18, c, get1)), s),
            WithAck(Ethernet(Tcp(Client, port, Server, 80, 0x18, c + (uint)get1.Length, get2)), s + (uint)one.Length),
            Ethernet(Tcp(Server, 80, Client, port, 0x18, s + (uint)one.Length, two)),
            WithAck(Ethernet(Tcp(Client, port, Server, 80, 0x18, c + (uint)(get1.Length + get2.Length), get3)), s + (uint)(one.Length + two.Length)),
            Ethernet(Tcp(Server, 80, Client, port, 0x18, s + (uint)(one.Length + two.Length), three)),
        };
        var files = Files(Unpack("hole.pcap", Pcap(frames)));
        Assert.Equal("second", Encoding.ASCII.GetString(files["files.example.com/two.txt"]));
        Assert.Equal("third", Encoding.ASCII.GetString(files["files.example.com/three.txt"]));
        Assert.Equal(2, files.Count);
    }

    /// <summary>A TLS 1.3 record sealed with a traffic secret (AES-128-GCM): the payload, its inner content type, then the tag.</summary>
    private static byte[] Sealed(byte[] secret, ulong seq, byte content, byte[] payload)
    {
        var key = TlsStream.ExpandLabel(System.Security.Cryptography.HashAlgorithmName.SHA256, secret, "key", 16);
        var iv = TlsStream.ExpandLabel(System.Security.Cryptography.HashAlgorithmName.SHA256, secret, "iv", 12);
        for (int i = 0; i < 8; i++) iv[11 - i] ^= (byte)(seq >> (8 * i));
        byte[] inner = [.. payload, content];
        byte[] header = [23, 3, 3, (byte)((inner.Length + 16) >> 8), (byte)(inner.Length + 16)];
        var cipher = new byte[inner.Length];
        var tag = new byte[16];
        using (var gcm = new System.Security.Cryptography.AesGcm(key, 16)) gcm.Encrypt(iv, inner, cipher, tag, header);
        return [.. header, .. cipher, .. tag];
    }

    private static byte[] PlainRecord(byte type, byte[] body) => [type, 3, 1, (byte)(body.Length >> 8), (byte)body.Length, .. body];

    [Fact]
    public void Tls_13_early_data_decrypts_with_the_early_traffic_secret()
    {
        // a resumed session: the client's first request goes out as 0-RTT data before the ServerHello
        byte[] early = [.. Enumerable.Repeat((byte)1, 32)], clientHs = [.. Enumerable.Repeat((byte)2, 32)], serverHs = [.. Enumerable.Repeat((byte)3, 32)],
            clientApp = [.. Enumerable.Repeat((byte)4, 32)], serverApp = [.. Enumerable.Repeat((byte)5, 32)];
        var random = new string('0', 64);
        var keyLog = _dir.File("early.keys");
        File.WriteAllLines(keyLog, [.. new[] { ("CLIENT_EARLY_TRAFFIC_SECRET", early), ("CLIENT_HANDSHAKE_TRAFFIC_SECRET", clientHs), ("SERVER_HANDSHAKE_TRAFFIC_SECRET", serverHs),
            ("CLIENT_TRAFFIC_SECRET_0", clientApp), ("SERVER_TRAFFIC_SECRET_0", serverApp) }.Select(k => $"{k.Item1} {random} {Convert.ToHexStringLower(k.Item2)}")]);
        var hello = Hello(0x0303, [0x1301], [0x2b, 0x2a], versions: [0x0304]);
        byte[] serverHello = [2, 0, 0, 46, 3, 3, .. new byte[32], 0, 0x13, 0x01, 0, 0, 6, 0, 0x2b, 0, 2, 3, 4];
        byte[] encryptedExtensions = [8, 0, 0, 6, 0, 4, 0, 0x2a, 0, 0], finished = [20, 0, 0, 32, .. new byte[32]];
        static byte[] Get(string path) => A($"GET {path} HTTP/1.1\r\nHost: tls.example.com\r\n\r\n");
        static byte[] Ok(string body) => A($"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {body.Length}\r\n\r\n{body}");
        var frames = Connection(51100, 443,
        [
            (true, [.. PlainRecord(22, hello), .. Sealed(early, 0, 23, Get("/early"))]),
            (false, [.. PlainRecord(22, serverHello), .. Sealed(serverHs, 0, 22, encryptedExtensions), .. Sealed(serverHs, 1, 22, finished), .. Sealed(serverApp, 0, 23, Ok("sent early"))]),
            (true, [.. Sealed(early, 1, 22, [5, 0, 0, 0]), .. Sealed(clientHs, 0, 22, finished), .. Sealed(clientApp, 0, 23, Get("/second"))]),
            (false, Sealed(serverApp, 1, 23, Ok("sent after the handshake"))),
        ]);
        var files = Files(Unpack("early.pcap", Pcap(frames), keyLog));
        Assert.Equal("sent early", Encoding.ASCII.GetString(files["tls.example.com/early.txt"]));
        Assert.Equal("sent after the handshake", Encoding.ASCII.GetString(files["tls.example.com/second.txt"]));
    }

    [Fact]
    public void Other_tcp_streams_are_written_by_direction()
    {
        var frames = Connection(50002, 25, [(false, A("220 mail.example.com ESMTP\r\n")), (true, A("EHLO client\r\n")), (false, A("250 OK\r\n"))]);
        var files = Files(Unpack("smtp.pcap", Pcap(frames)));
        Assert.Equal("EHLO client\r\n", Encoding.ASCII.GetString(files["streams/00000_10.0.0.2_50002_to_10.0.0.80_25.client.bin"]));
        Assert.Equal("220 mail.example.com ESMTP\r\n250 OK\r\n", Encoding.ASCII.GetString(files["streams/00000_10.0.0.2_50002_to_10.0.0.80_25.server.bin"]));
    }

    private static byte[] H2(byte type, byte flags, uint stream, byte[] payload) =>
        [(byte)(payload.Length >> 16), (byte)(payload.Length >> 8), (byte)payload.Length, type, flags, (byte)(stream >> 24), (byte)(stream >> 16), (byte)(stream >> 8), (byte)stream, .. payload];

    private static byte[] Literal(string s) => [(byte)s.Length, .. A(s)];

    [Fact]
    public void Http2_streams_give_their_responses()
    {
        // GET /a and /b on streams 1 and 3 (literal :path, :authority added to the table, then indexed), answers interleaved
        byte[] first = [0x82, 0x86, 0x44, .. Literal("/a"), 0x41, .. Literal("h2.example.com")];
        byte[] second = [0x82, 0x86, 0x44, .. Literal("/b"), 0xBF];
        byte[] status = [0x88, 0x5F, .. Literal("text/plain")]; // :status 200, content-type literal
        var frames = Connection(50003, 80,
        [
            (true, [.. "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"u8, .. H2(4, 0, 0, []), .. H2(1, 0x05, 1, first), .. H2(1, 0x05, 3, second)]),
            (false, [.. H2(4, 0, 0, []), .. H2(1, 0x04, 1, status), .. H2(1, 0x04, 3, [0x88]), .. H2(0, 0, 1, A("alpha ")), .. H2(0, 1, 3, A("bravo")), .. H2(0, 1, 1, A("one"))]),
        ], mss: 30);
        var files = Files(Unpack("h2.pcap", Pcap(frames)));
        Assert.Equal("alpha one", Encoding.ASCII.GetString(files["h2.example.com/a.txt"]));
        Assert.Equal("bravo", Encoding.ASCII.GetString(files["h2.example.com/b.bin"]));
    }

    /// <summary>The OpenSSL sessions of TlsSessions.txt: key log lines and each side's writes.</summary>
    private static List<(string Name, List<string> Keys, List<(bool FromClient, byte[] Data)> Writes)> Sessions()
    {
        var sessions = new List<(string, List<string>, List<(bool, byte[])>)>();
        foreach (var line in File.ReadAllLines(Path.Combine(AppContext.BaseDirectory, "Containers", "TlsSessions.txt")))
        {
            if (line.StartsWith('#')) continue;
            var (tag, rest) = (line[..line.IndexOf(' ')], line[(line.IndexOf(' ') + 1)..]);
            if (tag == "session") sessions.Add((rest.Split(' ')[0], [], []));
            else if (tag == "key") sessions[^1].Item2.Add(rest);
            else sessions[^1].Item3.Add((tag == "c", Convert.FromBase64String(rest)));
        }
        return sessions;
    }

    private static List<byte[]> TlsFrames() =>
        [.. Sessions().SelectMany((s, i) => Connection((ushort)(51000 + i), 443, s.Writes, mss: 500, shuffle: i % 2 == 1))];

    [Fact]
    public void Tls_12_and_13_sessions_decrypt_with_the_key_log()
    {
        var keyLog = _dir.File("keys.log");
        File.WriteAllLines(keyLog, ["# SSLKEYLOGFILE", .. Sessions().SelectMany(s => s.Keys)]);
        var report = Unpack("tls.pcap", Pcap(TlsFrames()), keyLog);
        var files = Files(report);
        var me = files.Single(f => f.Key.StartsWith("tls.example.com/api/me_q", StringComparison.Ordinal));
        Assert.Equal("""{"user":{"id":7,"name":"Ada"}}""", Encoding.UTF8.GetString(me.Value));
        Assert.Equal("hello world", Encoding.ASCII.GetString(files.Single(f => f.Key.StartsWith("tls.example.com/api/v12_q", StringComparison.Ordinal)).Value));
        Assert.Single(files, f => f.Key.StartsWith("tls.example.com/api/chacha_q", StringComparison.Ordinal));
        Assert.Single(files, f => f.Key.StartsWith("tls.example.com/api/sha384_q", StringComparison.Ordinal));
        Assert.Contains(report.Notes, n => n.StartsWith("4 TLS connection(s): 4 decrypted; key log of 4 session(s)", StringComparison.Ordinal));
        using var tls = JsonDocument.Parse(files["tls.json"]);
        var rows = tls.RootElement.EnumerateArray().Select(e => $"{e.GetProperty("Version").GetString()} {e.GetProperty("Cipher").GetString()} {e.GetProperty("Outcome").GetString()}").ToList();
        Assert.Equal(["TLS 1.3 0x1302 decrypted", "TLS 1.2 0xc02b decrypted", "TLS 1.2 0xcca9 decrypted", "TLS 1.2 0xc02c decrypted"], rows);
        Assert.StartsWith("t13d", tls.RootElement[0].GetProperty("Ja4").GetString());
        Assert.StartsWith("t12d", tls.RootElement[1].GetProperty("Ja4").GetString());
        Assert.StartsWith("t130", tls.RootElement[0].GetProperty("Ja4S").GetString());
    }

    [Fact]
    public void A_pcapng_carries_its_own_keys_and_without_keys_only_handshakes_are_read()
    {
        // the key log as a decryption secrets block before the packets, as editcap --inject-secrets writes it
        var keys = Encoding.ASCII.GetBytes(string.Join("\n", Sessions().SelectMany(s => s.Keys)) + "\n");
        var o = new MemoryStream();
        o.Write(Block(0x0A0D0D0A, [.. Le(0x1A2B3C4D), 1, 0, 0, 0, .. Enumerable.Repeat((byte)0xFF, 8)]));
        o.Write(Block(1, [1, 0, 0, 0, .. Le(65535)]));
        o.Write(Block(10, [.. Le(0x544C534B, (uint)keys.Length), .. keys]));
        foreach (var f in TlsFrames()) o.Write(Block(6, [.. Le(0, 0, 0, (uint)f.Length, (uint)f.Length), .. f]));
        var report = Unpack("tls.pcapng", o.ToArray());
        Assert.Contains(report.Notes, n => n.StartsWith("4 TLS connection(s): 4 decrypted; key log of 4 session(s) (from the capture's decryption secrets)", StringComparison.Ordinal));

        var plain = Unpack("nokeys.pcap", Pcap(TlsFrames()));
        Assert.Contains(plain.Notes, n => n.StartsWith("4 TLS connection(s): 4 no key log.", StringComparison.Ordinal));
        Assert.Contains(plain.Notes, n => n.StartsWith("4 TLS stream(s) without keys not written", StringComparison.Ordinal));
        Assert.Equal(["tls.json"], Files(plain).Keys);
    }

    [Fact]
    public void Ja3_and_ja4_equal_their_published_examples()
    {
        // JA4's README: a Chrome hello with 15 ciphers, 16 extensions (SNI, ALPN h2), these signature algorithms, GREASE
        ushort[] ciphers = [0x0A0A, 0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014, 0x009c, 0x009d, 0x002f, 0x0035];
        ushort[] extensions = [0x1A1A, 0x0000, 0x0010, 0x0005, 0x000a, 0x000b, 0x000d, 0x0012, 0x0015, 0x0017, 0x001b, 0x0023, 0x002b, 0x002d, 0x0033, 0x4469, 0xff01];
        var hello = Hello(0x0303, ciphers, extensions, sni: "example.com", alpn: "h2", sigalgs: [0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601], versions: [0x0304, 0x0303]);
        Assert.Equal("t13d1516h2_8daaf6152771_e5627efa2ab1", TlsHello.Parse(hello)!.Ja4());

        // JA3's README: 769,47-53-5-10-49161-49162-49171-49172-50-56-19-4,0-10-11,23-24-25,0
        var old = Hello(0x0301, [47, 53, 5, 10, 49161, 49162, 49171, 49172, 50, 56, 19, 4], [0, 10, 11], sni: "example.com", groups: [23, 24, 25], formats: [0]);
        Assert.Equal("ada70206e40642a3e4461f35503241d5", TlsHello.Parse(old)!.Ja3());
    }

    /// <summary>A ClientHello handshake message (type 1 onwards) with the extension types given in order.</summary>
    private static byte[] Hello(ushort version, ushort[] ciphers, ushort[] extensions, string? sni = null, string? alpn = null, ushort[]? sigalgs = null,
        ushort[]? versions = null, ushort[]? groups = null, byte[]? formats = null)
    {
        static byte[] U16(int v) => [(byte)(v >> 8), (byte)v];
        var ext = new List<byte>();
        foreach (var type in extensions)
        {
            byte[] data = type switch
            {
                0 when sni != null => [.. U16(sni.Length + 3), 0, .. U16(sni.Length), .. A(sni)],
                0x10 when alpn != null => [.. U16(alpn.Length + 1), (byte)alpn.Length, .. A(alpn)],
                0x0d when sigalgs != null => [.. U16(sigalgs.Length * 2), .. sigalgs.SelectMany(v => U16(v))],
                0x2b when versions != null => [(byte)(versions.Length * 2), .. versions.SelectMany(v => U16(v))],
                0x0a when groups != null => [.. U16(groups.Length * 2), .. groups.SelectMany(v => U16(v))],
                0x0b when formats != null => [(byte)formats.Length, .. formats],
                _ => [],
            };
            ext.AddRange([.. U16(type), .. U16(data.Length), .. data]);
        }
        byte[] body = [.. U16(version), .. new byte[32], 0, .. U16(ciphers.Length * 2), .. ciphers.SelectMany(v => U16(v)), 1, 0, .. U16(ext.Count), .. ext];
        return [1, 0, .. U16(body.Length), .. body];
    }

    [Fact]
    public void Dns_carried_data_and_periodic_connections_are_worth_reviewing()
    {
        var rng = new Random(7);
        string Label() => new([.. Enumerable.Range(0, 32).Select(_ => "abcdefghijklmnopqrstuvwxyz0123456789"[rng.Next(36)])]);
        var timed = new List<(long Seconds, byte[] Frame)>();
        for (int i = 0; i < 25; i++)
        {
            byte[] query = [0x12, (byte)i, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0, .. Name($"{Label()}.t.example.org"), 0, 16, 0, 1];
            timed.Add((i, Ethernet(Udp(Client, (ushort)(40000 + i), Resolver, 53, query))));
        }
        for (int i = 0; i < 8; i++) timed.Add((100 + 60 * i + (i % 2), Ethernet(Tcp(Client, (ushort)(52000 + i), Server, 8443, 0x02, 1, []))));
        var o = new MemoryStream();
        o.Write(Block(0x0A0D0D0A, [.. Le(0x1A2B3C4D), 1, 0, 0, 0, .. Enumerable.Repeat((byte)0xFF, 8)]));
        o.Write(Block(1, [1, 0, 0, 0, .. Le(65535)]));
        foreach (var (seconds, f) in timed)
        {
            ulong micros = (ulong)(T0 + seconds) * 1_000_000;
            o.Write(Block(6, [.. Le(0, (uint)(micros >> 32), (uint)micros, (uint)f.Length, (uint)f.Length), .. f]));
        }
        var path = _dir.File("patterns.pcapng");
        File.WriteAllBytes(path, o.ToArray());
        var view = (PcapFileView.Facts)new PcapFileView().Inspect(new FileInput(path, File.ReadAllBytes(path), "data"), default)!.Detail;
        Assert.Equal(2, view.Noteworthy.Count);
        Assert.StartsWith("DNS names: 25 distinct names under example.org, first labels 32 characters on average", view.Noteworthy[0]);
        Assert.StartsWith("periodic tcp: 10.0.0.2 to 10.0.0.80:8443 every 60.1 s (8 connections", view.Noteworthy[1]);
    }

    [Fact]
    [FuzzEntry(typeof(CaptureObjects), typeof(TlsHello))]
    public void Fuzzed_captures_reassemble_or_stop()
    {
        var keys = new TlsKeyLog();
        foreach (var k in Sessions().SelectMany(s => s.Keys)) keys.Add(k);
        var failures = FormatFuzz.Run(Pcap(TlsFrames().Take(30).ToList()), b => CaptureObjects.Read(new MemoryStream(b), keys, AnalysisLimits.Default, default), 400);
        Assert.True(failures.Count == 0, string.Join("\n", failures.Take(5)));
        var hello = Hello(0x0303, [0x1301], [0, 0x10], sni: "a.example", alpn: "h2");
        failures = FormatFuzz.Run(hello, b => TlsHello.Parse(b)?.Ja4(), 1000);
        Assert.True(failures.Count == 0, string.Join("\n", failures.Take(5)));
    }

    /// <summary>The batch target: a 1 GiB capture reassembled within 512 MB (TLS without keys, segments out of order).</summary>
    [Fact]
    [Trait("Speed", "Slow")]
    public async Task A_1_GiB_capture_is_reassembled_within_its_budget()
    {
        var path = _dir.File("big.pcap");
        var record = new byte[16 * 1024 + 5];
        record[0] = 23; record[1] = 3; record[2] = 3; record[3] = 0x40; record[4] = 0;
        var hello = ClientHello("big.example.com", "h2");
        using (var f = new FileStream(path, FileMode.Create, FileAccess.Write, FileShare.None, 1 << 20))
        {
            var header = Pcap([]);
            f.Write(header);
            long written = header.Length;
            for (ushort port = 1024; written < 1L << 30; port++)
            {
                var writes = new List<(bool, byte[])> { (true, hello) };
                for (int i = 0; i < 64; i++) writes.Add((false, record));
                foreach (var frame in Connection(port, 443, writes, mss: 1400, shuffle: port % 3 == 0))
                {
                    var r = new byte[16 + frame.Length];
                    BitConverter.TryWriteBytes(r.AsSpan(8), frame.Length);
                    BitConverter.TryWriteBytes(r.AsSpan(12), frame.Length);
                    frame.CopyTo(r, 16);
                    f.Write(r);
                    written += r.Length;
                }
            }
        }
        GC.Collect();
        long before = ProcessMemory.Private(), peak = before;
        var sw = Stopwatch.StartNew();
        CaptureObjects.Result result;
        using (var s = File.OpenRead(path))
        {
            var reader = Task.Run(() => CaptureObjects.Read(s, null, AnalysisLimits.Default, default));
            while (!reader.IsCompleted) { peak = Math.Max(peak, ProcessMemory.Private()); await Task.Delay(50); }
            result = await reader;
        }
        Console.WriteLine($"{new FileInfo(path).Length / 1e9:0.00} GB capture, {result.Tls.Count:N0} TLS connections in {sw.Elapsed.TotalSeconds:0.0} s, private memory +{(peak - before) / 1e6:N0} MB");
        Assert.True(result.Tls.Count > 900);
        Assert.True(peak - before < 512L * 1024 * 1024, $"{(peak - before) / 1e6:N0} MB");
    }
}
