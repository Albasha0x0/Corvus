using System.Buffers.Binary;
using System.Text;

namespace Corvus.Core.Pcap;

/// <summary>How a field's values compare.</summary>
public enum FieldType : byte { Address, Number, Text, Protocol }

/// <summary>Protocols whose state spans frames; a filter turns on only those it names.</summary>
[Flags]
internal enum PacketLayers
{
    None = 0,
    /// <summary>A ClientHello split over in-order TCP segments.</summary>
    TlsHello = 1,
    /// <summary>Cleartext HTTP/2: each direction's stream and HPACK table.</summary>
    Http2 = 2,
    /// <summary>QUIC Initial CRYPTO frames joined per connection.</summary>
    Quic = 4,
    /// <summary>SMB2 tree, file and message ids mapped to names.</summary>
    Smb2 = 8,
}

/// <summary>One value of a field in one frame.</summary>
internal readonly record struct FieldValue(UInt128 Address, bool V6, long Number, string? Text)
{
    public static FieldValue Of(long n) => new(0, false, n, null);
    public static FieldValue Of(string s) => new(0, false, 0, s);
    public static FieldValue Of(bool v6, UInt128 a) => new(a, v6, 0, null);

    public string Display(FieldType type) => type switch
    {
        FieldType.Address => PacketDecoder.Address(V6, Address),
        FieldType.Number => Number.ToString(System.Globalization.CultureInfo.InvariantCulture),
        _ => Text ?? "",
    };
}

/// <summary>A field the filter can name: its type, the values of a frame, and the cross-frame state it needs.</summary>
internal sealed class PacketField(string name, FieldType type, Action<PacketView, List<FieldValue>> values, bool v6 = false, PacketLayers layers = PacketLayers.None)
{
    public string Name { get; } = name;
    public FieldType Type { get; } = type;
    public bool V6 { get; } = v6;
    public PacketLayers Layers { get; } = layers;
    public void Collect(PacketView v, List<FieldValue> into) => values(v, into);
    public bool Present(PacketView v) => v.Values(this).Count > 0;
}

/// <summary>The fields decoded in-process, by their Wireshark names (with a few short aliases).</summary>
internal static class PacketFields
{
    private static readonly Dictionary<string, PacketField> ByName = new(StringComparer.OrdinalIgnoreCase);
    private static readonly Dictionary<string, string> Aliases = new(StringComparer.OrdinalIgnoreCase)
    {
        ["tls.sni"] = "tls.handshake.extensions_server_name",
        ["tls.alpn"] = "tls.handshake.extensions_alpn_str",
        ["ssl"] = "tls",
        ["dns.name"] = "dns.qry.name",
    };

    static PacketFields()
    {
        static void Add(PacketField f) => ByName[f.Name] = f;
        static void Proto(string name, Func<PacketView, bool> test, PacketLayers layers = PacketLayers.None) =>
            Add(new PacketField(name, FieldType.Protocol, (v, o) => { if (test(v)) o.Add(FieldValue.Of(1)); }, layers: layers));
        static void Num(string name, Func<PacketView, long?> get) => Add(new PacketField(name, FieldType.Number, (v, o) => { if (get(v) is { } n) o.Add(FieldValue.Of(n)); }));

        Num("frame.number", v => v.Number);
        Num("frame.len", v => v.OriginalLength);
        Num("frame.cap_len", v => v.Data.Length);

        Proto("ip", v => v.Ip && !v.P.V6);
        Proto("ipv6", v => v.Ip && v.P.V6);
        Add(new PacketField("ip.addr", FieldType.Address, (v, o) => { if (v.Ip && !v.P.V6) { o.Add(FieldValue.Of(false, v.P.Src)); o.Add(FieldValue.Of(false, v.P.Dst)); } }));
        Add(new PacketField("ip.src", FieldType.Address, (v, o) => { if (v.Ip && !v.P.V6) o.Add(FieldValue.Of(false, v.P.Src)); }));
        Add(new PacketField("ip.dst", FieldType.Address, (v, o) => { if (v.Ip && !v.P.V6) o.Add(FieldValue.Of(false, v.P.Dst)); }));
        Num("ip.proto", v => v.Ip && !v.P.V6 ? v.P.Protocol : null);
        Add(new PacketField("ipv6.addr", FieldType.Address, (v, o) => { if (v.Ip && v.P.V6) { o.Add(FieldValue.Of(true, v.P.Src)); o.Add(FieldValue.Of(true, v.P.Dst)); } }, v6: true));
        Add(new PacketField("ipv6.src", FieldType.Address, (v, o) => { if (v.Ip && v.P.V6) o.Add(FieldValue.Of(true, v.P.Src)); }, v6: true));
        Add(new PacketField("ipv6.dst", FieldType.Address, (v, o) => { if (v.Ip && v.P.V6) o.Add(FieldValue.Of(true, v.P.Dst)); }, v6: true));
        Num("ipv6.nxt", v => v.Ip && v.P.V6 ? v.P.Protocol : null);

        Proto("tcp", v => v.Tcp);
        Proto("udp", v => v.Udp);
        Proto("icmp", v => v.Ip && !v.P.V6 && v.P.Protocol == 1 && !v.P.Fragment);
        Proto("icmpv6", v => v.Ip && v.P.V6 && v.P.Protocol == 58 && !v.P.Fragment);
        foreach (var (proto, tcp) in new[] { ("tcp", true), ("udp", false) })
        {
            Add(new PacketField(proto + ".port", FieldType.Number, (v, o) => { if (tcp ? v.Tcp : v.Udp) { o.Add(FieldValue.Of(v.P.SrcPort)); o.Add(FieldValue.Of(v.P.DstPort)); } }));
            Num(proto + ".srcport", v => (tcp ? v.Tcp : v.Udp) ? v.P.SrcPort : null);
            Num(proto + ".dstport", v => (tcp ? v.Tcp : v.Udp) ? v.P.DstPort : null);
        }
        Num("tcp.len", v => v.Tcp ? v.P.PayloadLength : null);
        Num("tcp.seq_raw", v => v.Tcp ? v.P.Seq : null);
        Num("tcp.flags", v => v.Tcp ? v.P.TcpFlags : null);
        foreach (var (flag, bit) in new[] { ("fin", 0x01), ("syn", 0x02), ("reset", 0x04), ("push", 0x08), ("ack", 0x10), ("urg", 0x20) })
            Num("tcp.flags." + flag, v => v.Tcp ? (v.P.TcpFlags & bit) != 0 ? 1 : 0 : null);
        Num("udp.length", v => v.Udp ? v.P.PayloadLength + 8 : null);

        Proto("dns", v => v.Dns != null);
        Text("dns.qry.name", v => v.Dns?.Names);
        Add(new PacketField("dns.qry.type", FieldType.Number, (v, o) => { foreach (var t in v.Dns?.Types ?? []) o.Add(FieldValue.Of(t)); }));
        Num("dns.id", v => v.Dns?.Id);
        Num("dns.flags.response", v => v.Dns is { } d ? d.Response ? 1 : 0 : null);
        Add(new PacketField("dns.a", FieldType.Address, (v, o) => { foreach (var a in v.Dns?.A ?? []) o.Add(FieldValue.Of(false, a)); }));
        Add(new PacketField("dns.aaaa", FieldType.Address, (v, o) => { foreach (var a in v.Dns?.Aaaa ?? []) o.Add(FieldValue.Of(true, a)); }, v6: true));
        Text("dns.cname", v => v.Dns?.Cnames);

        Proto("http", v => v.Http != null);
        Text("http.host", v => v.Http?.Host is { } h ? [h] : null);
        Text("http.request.method", v => v.Http?.Method is { } m ? [m] : null);
        Text("http.request.uri", v => v.Http?.Uri is { } u ? [u] : null);
        Text("http.user_agent", v => v.Http?.UserAgent is { } a ? [a] : null);
        Num("http.response.code", v => v.Http?.Status);
        Proto("http.request", v => v.Http?.Method != null);
        Proto("http.response", v => v.Http?.Status != null);

        const PacketLayers hello = PacketLayers.TlsHello | PacketLayers.Quic;
        Proto("tls", v => v.TlsRecord, hello);
        Text("tls.handshake.extensions_server_name", v => v.Hello?.Sni is { } s ? [s] : null, hello);
        Text("tls.handshake.extensions_alpn_str", v => v.Hello?.Alpn, hello);
        Text("tls.handshake.ja3", v => v.Hello?.Ja3 is { } j ? [j] : null, hello);
        Text("tls.handshake.ja4", v => v.Hello?.Ja4 is { } j ? [j] : null, hello);
        Add(new PacketField("tls.handshake.type", FieldType.Number, (v, o) => { if (v.Hello != null) o.Add(FieldValue.Of(1)); }, layers: hello));

        Proto("http2", v => v.Http2 != null, PacketLayers.Http2);
        Add(new PacketField("http2.type", FieldType.Number, (v, o) => { foreach (var t in v.Http2?.Types ?? []) o.Add(FieldValue.Of(t)); }, layers: PacketLayers.Http2));
        Add(new PacketField("http2.streamid", FieldType.Number, (v, o) => { foreach (var s in v.Http2?.Streams ?? []) o.Add(FieldValue.Of(s)); }, layers: PacketLayers.Http2));
        Text("http2.header.name", v => v.Http2?.Headers.Select(h => h.Name).ToList(), PacketLayers.Http2);
        Text("http2.header.value", v => v.Http2?.Headers.Select(h => h.Value).ToList(), PacketLayers.Http2);
        foreach (var header in new[] { ":authority", ":method", ":path", ":scheme", "user-agent" })
            Text("http2.headers." + header.TrimStart(':').Replace('-', '_'), v => v.Http2?.Headers.Where(h => h.Name == header).Select(h => h.Value).ToList(), PacketLayers.Http2);
        Add(new PacketField("http2.headers.status", FieldType.Number, (v, o) =>
        {
            foreach (var (name, value) in v.Http2?.Headers ?? [])
                if (name == ":status" && long.TryParse(value, System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out var code)) o.Add(FieldValue.Of(code));
        }, layers: PacketLayers.Http2));

        Proto("quic", v => v.Quic != null, PacketLayers.Quic);
        Add(new PacketField("quic.version", FieldType.Number, (v, o) => { if (v.Quic != null) o.Add(FieldValue.Of(v.Quic.Version)); }, layers: PacketLayers.Quic));
        Add(new PacketField("quic.long.packet_type", FieldType.Number, (v, o) => { if (v.Quic is { PacketType: >= 0 } q) o.Add(FieldValue.Of(q.PacketType)); }, layers: PacketLayers.Quic));
        Text("quic.dcid", v => v.Quic is { } q ? [q.Dcid] : null, PacketLayers.Quic);
        Text("quic.scid", v => v.Quic is { } q ? [q.Scid] : null, PacketLayers.Quic);

        Proto("smb2", v => v.Smb2 != null, PacketLayers.Smb2);
        Add(new PacketField("smb2.cmd", FieldType.Number, (v, o) => { foreach (var c in v.Smb2?.Commands ?? []) o.Add(FieldValue.Of(c)); }, layers: PacketLayers.Smb2));
        Text("smb2.tree", v => v.Smb2?.Trees, PacketLayers.Smb2);
        Text("smb2.filename", v => v.Smb2?.Files, PacketLayers.Smb2);
        Text("ntlmssp.auth.username", v => v.Smb2?.Users, PacketLayers.Smb2);
        Text("ntlmssp.auth.domain", v => v.Smb2?.Domains, PacketLayers.Smb2);
        Text("ntlmssp.auth.hostname", v => v.Smb2?.Hosts, PacketLayers.Smb2);

        Proto("kerberos", v => v.Kerberos != null);
        Num("kerberos.msg_type", v => v.Kerberos?.MsgType);
        Text("kerberos.CNameString", v => v.Kerberos?.CNames);
        Text("kerberos.SNameString", v => v.Kerberos?.SNames);
        Text("kerberos.realm", v => v.Kerberos?.Realms);
        Text("kerberos.crealm", v => v.Kerberos?.CRealms);
    }

    private static void Text(string name, Func<PacketView, IReadOnlyList<string>?> get, PacketLayers layers = PacketLayers.None) =>
        ByName[name] = new PacketField(name, FieldType.Text, (v, o) => { foreach (var s in get(v) ?? []) o.Add(FieldValue.Of(s)); }, layers: layers);

    public static PacketField? Find(string name) =>
        ByName.GetValueOrDefault(Aliases.GetValueOrDefault(name, name));

    /// <summary>Every in-process field and protocol name, sorted.</summary>
    public static IEnumerable<string> Names => ByName.Keys.Order(StringComparer.Ordinal);
}

/// <summary>DNS facts of one message: question names and types, answers.</summary>
internal sealed record DnsFacts(int Id, bool Response, List<string> Names, List<long> Types, List<UInt128> A, List<UInt128> Aaaa, List<string> Cnames);

/// <summary>An HTTP/1.x request or response start.</summary>
internal sealed record HttpFacts(string? Method, string? Uri, string? Host, string? UserAgent, long? Status);

/// <summary>A ClientHello's server name, ALPN protocols and, for a whole hello, its JA3 and JA4 fingerprints.</summary>
internal sealed record HelloFacts(string? Sni, List<string> Alpn, string? Ja3 = null, string? Ja4 = null)
{
    /// <summary>A record holding a ClientHello (cut short: no fingerprints); null when it holds none.</summary>
    public static HelloFacts? Of(ReadOnlySpan<byte> record, bool quic = false)
    {
        if (!CaptureAnalysis.ClientHello(record, out var sni, out var alpn)) return null;
        var hello = record.Length > 5 ? TlsHello.Parse(record[5..]) : null;
        return new HelloFacts(sni, alpn, hello?.Ja3(), hello?.Ja4(quic));
    }
}

/// <summary>One frame as the filter reads it, protocol fields decoded on first use; one view is reused for every frame.</summary>
internal sealed class PacketView
{
    private readonly Dictionary<PacketField, List<FieldValue>> _values = [];
    private readonly Stack<List<FieldValue>> _free = new();

    public long Number;
    public long Micros;
    public int OriginalLength;
    public int LinkType;
    public ReadOnlyMemory<byte> Data;
    public bool Ip;
    public DecodedPacket P;
    /// <summary>A ClientHello completed by this frame: joined over TCP segments, or from QUIC Initial CRYPTO frames.</summary>
    public HelloFacts? JoinedHello;
    // Set by the trackers of the layers the filter names.
    public Http2Facts? Http2;
    public QuicFacts? Quic;
    public Smb2Facts? Smb2;

    private bool _dnsDone, _httpDone, _helloDone, _kerberosDone;
    private DnsFacts? _dns;
    private HttpFacts? _http;
    private HelloFacts? _hello;
    private KerberosFacts? _kerberos;

    public bool Tcp => Ip && !P.Fragment && P.Protocol == PacketDecoder.Tcp;
    public bool Udp => Ip && !P.Fragment && P.Protocol == PacketDecoder.Udp;
    public ReadOnlySpan<byte> Payload => (Tcp || Udp) && P.PayloadLength > 0 ? Data.Span.Slice(P.PayloadStart, P.PayloadLength) : default;

    internal void Reset(long number, in PcapFrame frame)
    {
        foreach (var list in _values.Values) { list.Clear(); _free.Push(list); }
        _values.Clear();
        Number = number;
        Micros = frame.Micros;
        OriginalLength = frame.OriginalLength;
        LinkType = frame.LinkType;
        Data = frame.Data;
        Ip = PacketDecoder.TryDecode(frame.LinkType, frame.Data.Span, out P);
        JoinedHello = null;
        Http2 = null;
        Quic = null;
        Smb2 = null;
        _dnsDone = _httpDone = _helloDone = _kerberosDone = false;
        _dns = null;
        _http = null;
        _hello = null;
        _kerberos = null;
    }

    /// <summary>A Kerberos message on port 88 (TCP with its 4-byte record mark).</summary>
    public KerberosFacts? Kerberos
    {
        get
        {
            if (_kerberosDone) return _kerberos;
            _kerberosDone = true;
            if ((Tcp || Udp) && (P.SrcPort == 88 || P.DstPort == 88) && Payload is { Length: > 4 } m)
                _kerberos = KerberosReader.Read(Tcp ? m[4..] : m);
            return _kerberos;
        }
    }

    /// <summary>The values of <paramref name="f"/> in this frame, collected once.</summary>
    public List<FieldValue> Values(PacketField f)
    {
        if (_values.TryGetValue(f, out var list)) return list;
        list = _free.Count > 0 ? _free.Pop() : [];
        f.Collect(this, list);
        _values[f] = list;
        return list;
    }

    public DnsFacts? Dns
    {
        get
        {
            if (_dnsDone) return _dns;
            _dnsDone = true;
            if ((Tcp || Udp) && (P.SrcPort == 53 || P.DstPort == 53) && Payload is { Length: > 0 } m)
            {
                if (Tcp) m = m.Length >= 2 && BinaryPrimitives.ReadUInt16BigEndian(m) is var len && len <= m.Length - 2 ? m.Slice(2, len) : default;
                _dns = ReadDns(m);
            }
            return _dns;
        }
    }

    public HttpFacts? Http
    {
        get
        {
            if (_httpDone) return _http;
            _httpDone = true;
            if (Tcp && Payload is { Length: >= 12 } p) _http = ReadHttp(p);
            return _http;
        }
    }

    /// <summary>True for a payload starting a whole TLS record or completing a joined ClientHello, as Wireshark reassembles.</summary>
    public bool TlsRecord => JoinedHello != null
        || Tcp && Payload is { Length: >= 5 } p && p[0] is >= 20 and <= 24 && p[1] == 3 && p[2] <= 4 && 5 + BinaryPrimitives.ReadUInt16BigEndian(p[3..]) <= p.Length;

    public HelloFacts? Hello
    {
        get
        {
            if (_helloDone) return _hello;
            _helloDone = true;
            if (JoinedHello != null) return _hello = JoinedHello;
            if (Tcp && Payload is { Length: >= 6 } p && p[0] == 0x16 && p[5] == 1 && p.Length >= 5 + BinaryPrimitives.ReadUInt16BigEndian(p[3..]))
                _hello = HelloFacts.Of(p);
            return _hello;
        }
    }

    private static DnsFacts? ReadDns(ReadOnlySpan<byte> m)
    {
        if (m.Length < 12) return null;
        bool response = (m[2] & 0x80) != 0;
        int questions = BinaryPrimitives.ReadUInt16BigEndian(m[4..]), answers = BinaryPrimitives.ReadUInt16BigEndian(m[6..]);
        var facts = new DnsFacts(BinaryPrimitives.ReadUInt16BigEndian(m), response, [], [], [], [], []);
        int at = 12;
        for (int i = 0; i < Math.Min(questions, 16); i++)
        {
            if (CaptureAnalysis.Name(m, ref at) is not { } name || at + 4 > m.Length) return facts;
            facts.Names.Add(name);
            facts.Types.Add(BinaryPrimitives.ReadUInt16BigEndian(m[at..]));
            at += 4;
        }
        for (int i = 0; i < Math.Min(answers, 64); i++)
        {
            if (CaptureAnalysis.Name(m, ref at) is null || at + 10 > m.Length) return facts;
            int type = BinaryPrimitives.ReadUInt16BigEndian(m[at..]), length = BinaryPrimitives.ReadUInt16BigEndian(m[(at + 8)..]);
            int data = at + 10;
            at = data + length;
            if (at > m.Length) return facts;
            if (type == 1 && length == 4) facts.A.Add(BinaryPrimitives.ReadUInt32BigEndian(m[data..]));
            else if (type == 28 && length == 16) facts.Aaaa.Add(BinaryPrimitives.ReadUInt128BigEndian(m[data..]));
            else if (type == 5 && CaptureAnalysis.Name(m, ref data) is { } target) facts.Cnames.Add(target);
        }
        return facts;
    }

    private static readonly string[] Methods = ["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH", "CONNECT", "TRACE"];

    private static HttpFacts? ReadHttp(ReadOnlySpan<byte> payload)
    {
        var head = payload[..Math.Min(payload.Length, 8192)];
        int eol = head.IndexOf("\r\n"u8);
        var line = eol < 0 ? head : head[..eol];
        string? method = null, uri = null;
        long? status = null;
        if (line.StartsWith("HTTP/1."u8))
        {
            if (line.Length < 12 || line[8] != ' ' || !int.TryParse(line.Slice(9, 3), System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out var code)) return null;
            status = code;
        }
        else
        {
            int space = line[..Math.Min(line.Length, 8)].IndexOf((byte)' ');
            if (space < 3) return null;
            method = Encoding.ASCII.GetString(line[..space]);
            if (Array.IndexOf(Methods, method) < 0) return null;
            int version = line.LastIndexOf(" HTTP/1."u8);
            if (version <= space + 1) return null;
            uri = CaptureAnalysis.Printable(line[(space + 1)..version]);
        }
        string? host = null, agent = null;
        for (int at = eol + 2; eol >= 0 && at < head.Length;)
        {
            int next = head[at..].IndexOf("\r\n"u8);
            var header = next < 0 ? head[at..] : head.Slice(at, next);
            if (header.Length == 0) break;
            int colon = header.IndexOf((byte)':');
            if (colon > 0)
            {
                var name = header[..colon];
                if (host == null && Ascii.EqualsIgnoreCase(name, "host"u8)) host = CaptureAnalysis.Printable(header[(colon + 1)..]).Trim();
                else if (agent == null && Ascii.EqualsIgnoreCase(name, "user-agent"u8)) agent = CaptureAnalysis.Printable(header[(colon + 1)..]).Trim();
            }
            if (next < 0) break;
            at += next + 2;
        }
        return new HttpFacts(method, uri, host, agent, status);
    }
}
