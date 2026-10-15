using System.Buffers.Binary;
using System.Text;

namespace Corvus.Core.Pcap;

/// <summary>A TCP or UDP conversation: the client is the side that sent the SYN (else the first sender, or the high port).</summary>
public sealed record CaptureFlow(string Protocol, string Client, string Server, long Packets, long Bytes, DateTime First, DateTime Last, string? ServerName);

/// <summary>A DNS name seen in questions or answers, with its query types and A / AAAA / CNAME answers.</summary>
public sealed record CaptureDnsName(string Name, int Queries, int Responses, IReadOnlyList<string> Types, IReadOnlyList<string> Answers);

/// <summary>A TLS server name from ClientHello SNI, with the ALPN protocols offered and the servers it went to.</summary>
public sealed record CaptureTlsName(string ServerName, int Hellos, IReadOnlyList<string> Alpn, IReadOnlyList<string> Servers);

/// <summary>An HTTP/1.x request line and its Host header, counted.</summary>
public sealed record CaptureHttpRequest(string Method, string Host, string Target, int Count);

/// <summary>
/// One pass over a capture: per-protocol counts, flows, DNS names, TLS ClientHello SNI / ALPN and HTTP/1.x request lines.
/// Memory is bounded by the caps, not by the capture: a frame is decoded in place and dropped.
/// </summary>
public sealed class CaptureAnalysis
{
    public const int MaxFlows = 10_000, MaxNames = 500, MaxServerNames = 500, MaxRequests = 1000;
    private const int MaxHello = 16 * 1024 + 5, MaxListed = 16;

    public string Format { get; private set; } = "";
    public IReadOnlyList<int> LinkTypes { get; private set; } = [];
    public int Interfaces { get; private set; }
    public long Packets { get; private set; }
    public long Bytes { get; private set; }
    public DateTime? First { get; private set; }
    public DateTime? Last { get; private set; }
    public SortedDictionary<string, long> Protocols { get; } = new(StringComparer.Ordinal);
    public List<string> Issues { get; } = [];
    public List<string> Notes { get; } = [];
    public long HellosWithoutSni { get; private set; }

    private readonly Dictionary<FlowKey, FlowState> _flows = [];
    private readonly Dictionary<string, DnsState> _names = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, TlsState> _tls = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<(string, string, string), int> _http = [];
    private long _untracked, _droppedNames, _droppedTls, _droppedHttp, _undecoded;

    private readonly record struct FlowKey(byte Protocol, bool V6, UInt128 A, ushort PortA, UInt128 B, ushort PortB);

    private sealed class FlowState(bool v6, byte protocol, UInt128 client, ushort clientPort, UInt128 server, ushort serverPort, long first)
    {
        public readonly bool V6 = v6;
        public readonly byte Protocol = protocol;
        public readonly UInt128 Client = client, Server = server;
        public readonly ushort ClientPort = clientPort, ServerPort = serverPort;
        public long Packets, Bytes, First = first, Last = first;
        public bool HelloDone;
        public byte[]? Pending;
        public int PendingLength;
        public uint NextSeq;
        public string? ServerName;
    }

    private sealed class DnsState
    {
        public int Queries, Responses;
        public readonly SortedSet<string> Types = new(StringComparer.Ordinal), Answers = new(StringComparer.Ordinal);
    }

    private sealed class TlsState
    {
        public int Hellos;
        public readonly SortedSet<string> Alpn = new(StringComparer.Ordinal), Servers = new(StringComparer.Ordinal);
    }

    public static CaptureAnalysis Read(byte[] data, CancellationToken ct) => Read(new MemoryStream(data, writable: false), ct);

    public static CaptureAnalysis Read(Stream stream, CancellationToken ct)
    {
        var a = new CaptureAnalysis();
        var reader = new PcapReader(stream);
        foreach (var frame in reader.Frames(ct))
        {
            a.Packets++;
            a.Bytes += frame.Data.Length;
            if (frame.Micros > 0)
            {
                var time = Time(frame.Micros);
                if (a.First is not { } f || time < f) a.First = time;
                if (a.Last is not { } l || time > l) a.Last = time;
            }
            a.Frame(frame);
        }
        a.Format = reader.Format;
        a.LinkTypes = [.. reader.LinkTypes];
        a.Interfaces = reader.Interfaces;
        a.Issues.AddRange(reader.Issues);
        a.Finish();
        return a;
    }

    public IEnumerable<CaptureFlow> Flows() => _flows.Values.Select(s => new CaptureFlow(s.Protocol == PacketDecoder.Tcp ? "tcp" : "udp",
        PacketDecoder.Endpoint(s.V6, s.Client, s.ClientPort), PacketDecoder.Endpoint(s.V6, s.Server, s.ServerPort), s.Packets, s.Bytes,
        Time(s.First), Time(s.Last), s.ServerName));

    public int FlowCount => _flows.Count;

    public IEnumerable<CaptureDnsName> DnsNames() => _names.OrderBy(n => n.Key, StringComparer.OrdinalIgnoreCase)
        .Select(n => new CaptureDnsName(n.Key, n.Value.Queries, n.Value.Responses, [.. n.Value.Types], [.. n.Value.Answers]));

    public IEnumerable<CaptureTlsName> ServerNames() => _tls.OrderBy(n => n.Key, StringComparer.OrdinalIgnoreCase)
        .Select(n => new CaptureTlsName(n.Key, n.Value.Hellos, [.. n.Value.Alpn], [.. n.Value.Servers]));

    public IEnumerable<CaptureHttpRequest> Requests() => _http.OrderBy(r => r.Key.Item2, StringComparer.Ordinal).ThenBy(r => r.Key.Item3, StringComparer.Ordinal)
        .Select(r => new CaptureHttpRequest(r.Key.Item1, r.Key.Item2, r.Key.Item3, r.Value));

    private void Frame(PcapFrame frame)
    {
        var f = frame.Data.Span;
        if (!PacketDecoder.TryDecode(frame.LinkType, f, out var p)) { _undecoded++; Count("other"); return; }
        Count(p.Protocol switch { PacketDecoder.Tcp => "tcp", PacketDecoder.Udp => "udp", 1 or 58 => "icmp", _ => p.V6 ? "ipv6 other" : "ipv4 other" });
        if (p.Fragment || p.Protocol is not (PacketDecoder.Tcp or PacketDecoder.Udp)) return;
        var payload = f.Slice(p.PayloadStart, p.PayloadLength);

        bool srcLow = Compare(p.Src, p.SrcPort, p.Dst, p.DstPort) <= 0;
        var key = srcLow ? new FlowKey(p.Protocol, p.V6, p.Src, p.SrcPort, p.Dst, p.DstPort) : new FlowKey(p.Protocol, p.V6, p.Dst, p.DstPort, p.Src, p.SrcPort);
        if (!_flows.TryGetValue(key, out var flow))
        {
            if (_flows.Count >= MaxFlows) _untracked++;
            else
            {
                bool srcIsClient = p.Protocol == PacketDecoder.Tcp && (p.TcpFlags & 0x12) == 0x02 ? true
                    : p.Protocol == PacketDecoder.Tcp && (p.TcpFlags & 0x12) == 0x12 ? false
                    : !(p.SrcPort < 1024 && p.DstPort >= 1024);
                flow = srcIsClient ? new FlowState(p.V6, p.Protocol, p.Src, p.SrcPort, p.Dst, p.DstPort, frame.Micros)
                    : new FlowState(p.V6, p.Protocol, p.Dst, p.DstPort, p.Src, p.SrcPort, frame.Micros);
                _flows[key] = flow;
            }
        }
        if (flow != null)
        {
            flow.Packets++;
            flow.Bytes += frame.OriginalLength;
            if (frame.Micros < flow.First) flow.First = frame.Micros;
            if (frame.Micros > flow.Last) flow.Last = frame.Micros;
        }
        bool fromClient = flow != null ? p.Src == flow.Client && p.SrcPort == flow.ClientPort : !(p.SrcPort < 1024 && p.DstPort >= 1024);

        if (payload.Length == 0) return;
        if (p.SrcPort == 53 || p.DstPort == 53)
        {
            if (p.Protocol == PacketDecoder.Udp) Dns(payload);
            else if (payload.Length >= 2 && BinaryPrimitives.ReadUInt16BigEndian(payload) is var len && len <= payload.Length - 2) Dns(payload.Slice(2, len));
            return;
        }
        if (p.Protocol != PacketDecoder.Tcp || !fromClient) return;
        Http(payload);
        Tls(flow, p, payload);
    }

    private void Count(string protocol) => Protocols[protocol] = Protocols.GetValueOrDefault(protocol) + 1;

    private static int Compare(UInt128 a, ushort pa, UInt128 b, ushort pb) => a != b ? a.CompareTo(b) : pa.CompareTo(pb);

    /// <summary>The first client payload of a flow as a ClientHello; one split over in-order segments is joined (up to one TLS record).</summary>
    private void Tls(FlowState? flow, in DecodedPacket p, ReadOnlySpan<byte> payload)
    {
        if (flow == null) { Hello(null, p, payload); return; }
        if (flow.HelloDone) return;
        if (flow.Pending is { } buffer)
        {
            int ahead = unchecked((int)(p.Seq - flow.NextSeq));
            if (ahead < 0) return; // a retransmission
            if (ahead > 0) { flow.HelloDone = true; flow.Pending = null; return; } // a gap: no reassembly
            int take = Math.Min(payload.Length, buffer.Length - flow.PendingLength);
            payload[..take].CopyTo(buffer.AsSpan(flow.PendingLength));
            flow.PendingLength += take;
            flow.NextSeq = unchecked(flow.NextSeq + (uint)payload.Length);
            if (flow.PendingLength < buffer.Length) return;
            flow.HelloDone = true;
            flow.Pending = null;
            Hello(flow, p, buffer);
            return;
        }
        if (payload.Length < 6 || payload[0] != 0x16 || payload[5] != 1) { flow.HelloDone = true; return; }
        int need = Math.Min(5 + BinaryPrimitives.ReadUInt16BigEndian(payload[3..]), MaxHello);
        if (payload.Length >= need) { flow.HelloDone = true; Hello(flow, p, payload); return; }
        flow.Pending = new byte[need];
        payload.CopyTo(flow.Pending);
        flow.PendingLength = payload.Length;
        flow.NextSeq = unchecked(p.Seq + (uint)payload.Length);
    }

    private void Hello(FlowState? flow, in DecodedPacket p, ReadOnlySpan<byte> record)
    {
        if (!ClientHello(record, out var sni, out var alpn)) return;
        if (sni == null) { HellosWithoutSni++; return; }
        if (flow != null) flow.ServerName = sni;
        if (!_tls.TryGetValue(sni, out var state))
        {
            if (_tls.Count >= MaxServerNames) { _droppedTls++; return; }
            _tls[sni] = state = new TlsState();
        }
        state.Hellos++;
        foreach (var protocol in alpn) if (state.Alpn.Count < MaxListed) state.Alpn.Add(protocol);
        if (state.Servers.Count < MaxListed) state.Servers.Add(PacketDecoder.Endpoint(p.V6, p.Dst, p.DstPort));
    }

    /// <summary>SNI host name and ALPN protocols of a TLS record holding a ClientHello; a truncated hello gives what precedes the cut.</summary>
    internal static bool ClientHello(ReadOnlySpan<byte> r, out string? sni, out List<string> alpn)
    {
        sni = null;
        alpn = [];
        if (r.Length < 9 || r[0] != 0x16 || r[5] != 1) return false;
        int at = 9 + 2 + 32; // record and handshake headers, version, random
        if (at >= r.Length) return true;
        at += 1 + r[at]; // session id
        if (at + 2 > r.Length) return true;
        at += 2 + BinaryPrimitives.ReadUInt16BigEndian(r[at..]); // cipher suites
        if (at >= r.Length) return true;
        at += 1 + r[at]; // compression methods
        if (at + 2 > r.Length) return true;
        int end = Math.Min(r.Length, at + 2 + BinaryPrimitives.ReadUInt16BigEndian(r[at..]));
        at += 2;
        while (at + 4 <= end)
        {
            int type = BinaryPrimitives.ReadUInt16BigEndian(r[at..]), len = BinaryPrimitives.ReadUInt16BigEndian(r[(at + 2)..]);
            var ext = r.Slice(at + 4, Math.Min(len, end - at - 4));
            at += 4 + len;
            if (type == 0 && ext.Length >= 5 && ext[2] == 0)
            {
                int nameLength = BinaryPrimitives.ReadUInt16BigEndian(ext[3..]);
                if (nameLength > 0 && 5 + nameLength <= ext.Length) sni = Printable(ext.Slice(5, nameLength));
            }
            else if (type == 16 && ext.Length >= 2)
            {
                for (int i = 2; i < ext.Length && alpn.Count < MaxListed;)
                {
                    int n = ext[i];
                    if (n == 0 || i + 1 + n > ext.Length) break;
                    alpn.Add(Printable(ext.Slice(i + 1, n)));
                    i += 1 + n;
                }
            }
        }
        return true;
    }

    private static readonly string[] Methods = ["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH", "CONNECT", "TRACE"];

    /// <summary>A request line and Host header at the start of one segment (keep-alive requests each start a segment).</summary>
    private void Http(ReadOnlySpan<byte> payload)
    {
        int space = payload[..Math.Min(payload.Length, 8)].IndexOf((byte)' ');
        if (space < 3) return;
        var method = Encoding.ASCII.GetString(payload[..space]);
        if (Array.IndexOf(Methods, method) < 0) return;
        var head = payload[..Math.Min(payload.Length, 8192)];
        int eol = head.IndexOf("\r\n"u8);
        var line = eol < 0 ? head : head[..eol];
        int version = line.LastIndexOf(" HTTP/1."u8);
        if (version <= space + 1) return;
        var target = Printable(line[(space + 1)..version]);
        string host = "";
        for (int at = eol + 2; eol >= 0 && at < head.Length;)
        {
            int next = head[at..].IndexOf("\r\n"u8);
            var header = next < 0 ? head[at..] : head.Slice(at, next);
            if (header.Length == 0) break;
            if (header.Length > 5 && Ascii.EqualsIgnoreCase(header[..5], "host:"u8)) { host = Printable(header[5..]).Trim(); break; }
            if (next < 0) break;
            at += next + 2;
        }
        var key = (method, host, target.Length > 2048 ? target[..2048] : target);
        if (_http.TryGetValue(key, out int count)) _http[key] = count + 1;
        else if (_http.Count < MaxRequests) _http[key] = 1;
        else _droppedHttp++;
    }

    private void Dns(ReadOnlySpan<byte> m)
    {
        if (m.Length < 12) return;
        bool response = (m[2] & 0x80) != 0;
        int questions = BinaryPrimitives.ReadUInt16BigEndian(m[4..]), answers = BinaryPrimitives.ReadUInt16BigEndian(m[6..]);
        int at = 12;
        for (int i = 0; i < Math.Min(questions, 16); i++)
        {
            if (Name(m, ref at) is not { } name || at + 4 > m.Length) return;
            var state = Dns(name);
            if (state == null) { at += 4; continue; }
            if (response) state.Responses++; else state.Queries++;
            if (state.Types.Count < MaxListed) state.Types.Add(TypeName(BinaryPrimitives.ReadUInt16BigEndian(m[at..])));
            at += 4;
        }
        if (!response) return;
        for (int i = 0; i < Math.Min(answers, 64); i++)
        {
            if (Name(m, ref at) is not { } name || at + 10 > m.Length) return;
            int type = BinaryPrimitives.ReadUInt16BigEndian(m[at..]), length = BinaryPrimitives.ReadUInt16BigEndian(m[(at + 8)..]);
            int data = at + 10;
            at = data + length;
            if (at > m.Length) return;
            string? answer = type switch
            {
                1 when length == 4 => "A " + PacketDecoder.Address(false, BinaryPrimitives.ReadUInt32BigEndian(m[data..])),
                28 when length == 16 => "AAAA " + PacketDecoder.Address(true, BinaryPrimitives.ReadUInt128BigEndian(m[data..])),
                5 => Name(m, ref data) is { } target ? "CNAME " + target : null,
                _ => null,
            };
            if (answer != null && Dns(name) is { } state && state.Answers.Count < MaxListed) state.Answers.Add(answer);
        }
    }

    private DnsState? Dns(string name)
    {
        if (_names.TryGetValue(name, out var state)) return state;
        if (_names.Count >= MaxNames) { _droppedNames++; return null; }
        return _names[name] = new DnsState();
    }

    /// <summary>A DNS name with compression pointers followed (backwards only, so a loop cannot form); null when malformed.</summary>
    internal static string? Name(ReadOnlySpan<byte> m, ref int at)
    {
        var sb = new StringBuilder();
        int pos = at, jumps = 0;
        bool jumped = false;
        while (true)
        {
            if (pos >= m.Length) return null;
            int len = m[pos];
            if (len == 0) { pos++; break; }
            if ((len & 0xC0) == 0xC0)
            {
                if (pos + 2 > m.Length || ++jumps > 32) return null;
                int target = (len & 0x3F) << 8 | m[pos + 1];
                if (target >= pos) return null;
                if (!jumped) at = pos + 2;
                jumped = true;
                pos = target;
                continue;
            }
            if ((len & 0xC0) != 0 || pos + 1 + len > m.Length || sb.Length + len > 255) return null;
            if (sb.Length > 0) sb.Append('.');
            sb.Append(Printable(m.Slice(pos + 1, len)));
            pos += 1 + len;
        }
        if (!jumped) at = pos;
        return sb.Length == 0 ? "." : sb.ToString();
    }

    private static string TypeName(int type) => type switch
    {
        1 => "A", 2 => "NS", 5 => "CNAME", 6 => "SOA", 12 => "PTR", 15 => "MX", 16 => "TXT", 28 => "AAAA", 33 => "SRV", 64 => "SVCB", 65 => "HTTPS", 255 => "ANY",
        _ => $"TYPE{type}",
    };

    /// <summary>ASCII with control and non-ASCII bytes as '?', so names from the capture print safely.</summary>
    internal static string Printable(ReadOnlySpan<byte> b) => string.Create(b.Length, b.ToArray(), (chars, bytes) =>
    {
        for (int i = 0; i < bytes.Length; i++) chars[i] = bytes[i] is >= 0x20 and < 0x7F ? (char)bytes[i] : '?';
    });

    private void Finish()
    {
        if (_untracked > 0) Notes.Add($"stopped at {MaxFlows:N0} flows: {_untracked:N0} packets of later flows are not counted per flow");
        if (_droppedNames > 0) Notes.Add($"stopped at {MaxNames} DNS names: {_droppedNames:N0} more records not kept");
        if (_droppedTls > 0) Notes.Add($"stopped at {MaxServerNames} TLS server names: {_droppedTls:N0} more ClientHellos not kept");
        if (_droppedHttp > 0) Notes.Add($"stopped at {MaxRequests} distinct HTTP requests: {_droppedHttp:N0} more not kept");
        if (_undecoded > 0) Notes.Add($"{_undecoded:N0} frames are not IPv4 / IPv6 or use an undecoded link type");
        if (HellosWithoutSni > 0) Notes.Add($"{HellosWithoutSni:N0} ClientHellos carry no server name");
    }

    private static DateTime Time(long micros) =>
        DateTime.UnixEpoch.AddTicks(Math.Clamp(micros, 0, (DateTime.MaxValue.Ticks - DateTime.UnixEpoch.Ticks) / 10) * 10);
}
