using System.Globalization;

namespace Corvus.Core.Pcap;

/// <summary>
/// A pcap / pcapng capture as a container, read in one streaming pass: TCP reassembled (<see cref="TcpStreams"/>), HTTP/1.x,
/// HTTP/2 and HTTP/3 (<see cref="QuicCapture"/>) responses exported as files named host/path like HAR bodies (decoded by their Content-Encoding), TLS
/// decrypted with a key log (a file, or the pcapng's decryption secrets blocks), and every other TCP stream written as its
/// two directions under streams/. Encrypted streams without keys are counted, not written.
/// </summary>
internal static class CaptureObjects
{
    public const string Kind = "packet capture (HTTP objects and TCP streams)";

    public sealed record TlsSummary(string Server, string? ServerName, string Version, string Cipher, string? Alpn, string? Ja3, string? Ja4, string? Ja4S, string Outcome);

    public sealed class Result(ContainerContents contents)
    {
        public ContainerContents Contents { get; } = contents;
        public List<TlsSummary> Tls { get; } = [];
    }

    /// <summary>The capture's objects, streams and TLS summaries; <paramref name="sections"/> receives the HTTP/3 field sections decoded.</summary>
    public static Result Read(Stream stream, TlsKeyLog? keyLog, AnalysisLimits limits, CancellationToken ct, List<QuicCapture.Section>? sections = null)
    {
        var collector = new Captures.Collector(Kind, "capture", allFiles: true, limits, ct);
        var keys = keyLog ?? new TlsKeyLog();
        int fromBlocks = 0;
        var reader = new PcapReader(stream) { Secrets = text => { keys.Add(text); fromBlocks++; } };
        var tls = new List<(TcpConnectionInfo Info, TlsStream Stream)>();
        int http = 0, raw = 0, rawEncrypted = 0;
        long maxBody = Math.Min(limits.MaxItemBytes, Array.MaxLength);
        ITcpConsumer Open(TcpConnectionInfo info) => new Sniffer(info, keys, collector, maxBody, tls, () => http++, () => raw++, () => rawEncrypted++);
        var tcp = new TcpStreams(Open);
        var quic = new QuicCapture(keys, r => { http++; collector.Add(r); }, maxBody);
        long frames = 0;
        foreach (var f in reader.Frames(ct))
        {
            if ((++frames & 0xFFF) == 0) ct.ThrowIfCancellationRequested();
            var span = f.Data.Span;
            if (!PacketDecoder.TryDecode(f.LinkType, span, out var p) || p.Protocol is not (PacketDecoder.Tcp or PacketDecoder.Udp)) continue;
            int length = Math.Max(0, Math.Min(p.PayloadLength, span.Length - p.PayloadStart));
            if (p.Protocol == PacketDecoder.Udp) { if (!p.Fragment) quic.Add(p, span.Slice(p.PayloadStart, length)); }
            else tcp.Add(p, span.Slice(p.PayloadStart, length), f.Micros);
        }
        tcp.Finish();
        quic.Finish();
        sections?.AddRange(quic.Sections);
        var contents = collector.Contents();
        var notes = contents.Notes;
        notes.AddRange(reader.Issues);
        notes.Add($"{frames:N0} frames, {tcp.Connections:N0} TCP connection(s) reassembled" +
                  (tcp.Gaps > 0 ? $"; {tcp.Gaps:N0} gap(s) of {tcp.GapBytes:N0} bytes never captured (bodies across a gap are marked)" : "") + ".");
        if (tls.Count > 0)
        {
            var outcomes = tls.GroupBy(t => t.Stream.Outcome ?? "handshake not seen").Select(g => $"{g.Count()} {g.Key}");
            notes.Add($"{tls.Count} TLS connection(s): {string.Join(", ", outcomes)}" + (keys.Sessions > 0 ? $"; key log of {keys.Sessions} session(s)" +
                      (fromBlocks > 0 ? " (from the capture's decryption secrets)" : "") : "") + ".");
        }
        var quicConnections = quic.Connections.ToList();
        if (quicConnections.Count > 0)
            notes.Add($"{quicConnections.Count} QUIC connection(s): {string.Join(", ", quicConnections.GroupBy(q => q.Outcome).Select(g => $"{g.Count()} {g.Key}"))}" +
                      (quic.Responses > 0 ? $"; {quic.Responses} HTTP/3 object(s)" : "") + ".");
        if (raw > 0) notes.Add($"{raw} other TCP stream(s) written under streams/ (decrypted ones under tls-streams/), client and server bytes in two files.");
        if (rawEncrypted > 0) notes.Add($"{rawEncrypted} TLS stream(s) without keys not written (pass keyLog to decrypt).");
        var result = new Result(contents);
        foreach (var (info, s) in tls)
            result.Tls.Add(new TlsSummary(info.Server, s.ClientHello?.ServerName, Version(s.Version), $"0x{s.Cipher:x4}", s.Alpn,
                s.ClientHello?.Ja3(), s.ClientHello?.Ja4(), s.ServerHello?.Ja4(), s.Outcome ?? "handshake not seen"));
        foreach (var q in quicConnections)
            result.Tls.Add(new TlsSummary(q.Server, q.ServerName, q.Version, q.Cipher, q.Alpn, null, null, null, q.Outcome));
        return result;
    }

    public static string Version(ushort v) => v switch { 0x0304 => "TLS 1.3", 0x0303 => "TLS 1.2", 0x0302 => "TLS 1.1", 0x0301 => "TLS 1.0", 0 => "unknown", _ => $"0x{v:x4}" };

    /// <summary>A connection's protocol from its first bytes: TLS, HTTP/1.x, HTTP/2 (preface or ALPN h2), else a raw stream.</summary>
    private sealed class Sniffer(TcpConnectionInfo info, TlsKeyLog keys, Captures.Collector collector, long maxBody,
        List<(TcpConnectionInfo, TlsStream)> tls, Action http, Action raw, Action rawEncrypted) : ITcpConsumer
    {
        private ITcpConsumer? _chosen;
        private readonly MemoryStream _early = new();
        private const int MaxEarly = 1 << 20;

        public void Data(bool fromClient, ReadOnlySpan<byte> data)
        {
            if (_chosen == null)
            {
                if (!fromClient)
                {
                    // the server spoke first (a banner): hold it until the client's first bytes or the end
                    if (_early.Length + data.Length <= MaxEarly) _early.Write(data);
                    return;
                }
                _chosen = Choose(data);
                if (_early.Length > 0) _chosen.Data(false, _early.ToArray());
                _early.SetLength(0);
            }
            _chosen.Data(fromClient, data);
        }

        private ITcpConsumer Choose(ReadOnlySpan<byte> first)
        {
            if (first.Length >= 3 && first[0] == 0x16 && first[1] == 3)
            {
                TlsStream? stream = null;
                stream = new TlsStream(keys, alpn => App(alpn, "https", stream!));
                tls.Add((info, stream));
                return new Encrypted(stream, rawEncrypted);
            }
            return App(Sniff(first), "http", null);
        }

        /// <summary>The consumer of a plaintext stream (a TCP one, or a decrypted TLS one sniffed on its first client bytes).</summary>
        private ITcpConsumer App(string? alpn, string scheme, TlsStream? over)
        {
            var server = info.ServerPort is 80 or 443 ? Host(info.Server) : info.Server;
            void Emit(CapturedResponse r) { http(); collector.Add(r); }
            if (alpn == "h2") return new Http2Stream(scheme, server, Emit, maxBody);
            if (alpn is "http/1.1" or "http/1.0") return new Http1Stream(scheme, server, Emit, maxBody);
            if (over != null && alpn == null) return new Lazy(first => App(Sniff(first) ?? "", scheme, null));
            raw();
            return new Raw(info, collector, maxBody, scheme == "https" ? "tls-streams" : "streams");
        }

        private static string? Sniff(ReadOnlySpan<byte> first) =>
            Http1Stream.LooksLikeRequest(first) ? "http/1.1" : Http2Stream.LooksLikePreface(first) ? "h2" : null;

        private static string Host(string endpoint) => endpoint.StartsWith('[') ? endpoint[..(endpoint.IndexOf(']') + 1)] : endpoint.Split(':')[0];

        public void Gap(bool fromClient, long bytes) => _chosen?.Gap(fromClient, bytes);

        public void End()
        {
            if (_chosen == null && _early.Length > 0)
            {
                _chosen = App(null, "http", null);
                _chosen.Data(false, _early.ToArray());
            }
            _chosen?.End();
        }
    }

    /// <summary>A TLS connection: decrypted into its inner consumer, or counted as an encrypted stream when nothing decrypts.</summary>
    private sealed class Encrypted(TlsStream tls, Action rawEncrypted) : ITcpConsumer
    {
        public void Data(bool fromClient, ReadOnlySpan<byte> data) => tls.Data(fromClient, data);
        public void Gap(bool fromClient, long bytes) => tls.Gap(fromClient, bytes);

        public void End()
        {
            if (tls.Decrypted == 0) rawEncrypted();
            tls.End();
        }
    }

    /// <summary>A consumer chosen on the client's first bytes; server bytes before them are held.</summary>
    private sealed class Lazy(Func<byte[], ITcpConsumer> choose) : ITcpConsumer
    {
        private ITcpConsumer? _chosen;
        private readonly MemoryStream _early = new();

        public void Data(bool fromClient, ReadOnlySpan<byte> data)
        {
            if (_chosen == null && !fromClient) { _early.Write(data); return; }
            if (_chosen == null)
            {
                _chosen = choose(data.ToArray());
                if (_early.Length > 0) _chosen.Data(false, _early.ToArray());
            }
            _chosen.Data(fromClient, data);
        }

        public void Gap(bool fromClient, long bytes) => _chosen?.Gap(fromClient, bytes);

        public void End()
        {
            if (_chosen == null && _early.Length > 0) { _chosen = choose([]); _chosen.Data(false, _early.ToArray()); }
            _chosen?.End();
        }
    }

    /// <summary>A stream that is no HTTP: each direction's bytes written as one file, gaps filled with nothing and noted.</summary>
    private sealed class Raw(TcpConnectionInfo info, Captures.Collector collector, long maxBody, string folder) : ITcpConsumer
    {
        private readonly MemoryStream _client = new(), _server = new();
        private long _gaps;
        private bool _cut;

        public void Data(bool fromClient, ReadOnlySpan<byte> data)
        {
            var s = fromClient ? _client : _server;
            if (s.Length + data.Length > maxBody) { _cut = true; return; }
            s.Write(data);
        }

        public void Gap(bool fromClient, long bytes) => _gaps += bytes;

        public void End()
        {
            string name = $"{folder}/{info.Index.ToString("D5", CultureInfo.InvariantCulture)}_{Safe(info.Client)}_to_{Safe(info.Server)}";
            string detail = $"TCP stream {info.Client} -> {info.Server}" + (_gaps > 0 ? $", {_gaps:N0} bytes not captured" : "") + (_cut ? $", cut at {maxBody:N0} bytes" : "");
            if (_client.Length > 0) collector.AddFile(name + ".client.bin", _client.ToArray(), detail + ", client bytes");
            if (_server.Length > 0) collector.AddFile(name + ".server.bin", _server.ToArray(), detail + ", server bytes");
        }

        private static string Safe(string endpoint) => endpoint.Replace("[", "").Replace("]", "").Replace(':', '_');
    }
}
