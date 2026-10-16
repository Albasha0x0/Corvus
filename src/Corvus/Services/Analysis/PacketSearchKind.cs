using System.Globalization;
using Corvus.Core;
using Corvus.Core.Pcap;
using Corvus.Native.Providers;

namespace Corvus.Services.Analysis;

/// <summary>
/// search_container kind=packet on a pcap / pcapng capture: the query is a Wireshark display filter over the fields decoded
/// in-process (addresses, ports, DNS, HTTP, TLS server names); rows are the matching frames in capture order, streamed.
/// </summary>
internal sealed class PacketSearchKind : IContainerSearchKind
{
    public IReadOnlyList<string> Kinds => ["packet"];

    public IEnumerable<ContainerMatch> Search(ContainerScope scope, string kind, Func<string, bool> matches, CancellationToken ct) => [];

    public UnpackService.ContainerSearch SearchFile(string path, string query, int offset, int limit, ContainerSearchArgs args, CancellationToken ct)
    {
        var source = InputFiles.RequireRegularFile(path, "capture file");
        if (!File.Exists(source)) throw Targets.FileNotFound(source);
        PacketFilter filter;
        try { filter = PacketFilter.Parse(query); }
        catch (PacketFilterException ex) { throw new ToolError(ErrorCode.InvalidArgument, $"filter: {ex.Message}.", "pass a display filter such as: ip.addr==10.0.0.1 and tcp.port==443, or * for every frame"); }
        using var stream = Open(source);
        var head = new byte[4];
        if (stream.ReadAtLeast(head, 4, throwOnEndOfStream: false) < 4 || !PcapReader.Looks(head))
            throw new ToolError(ErrorCode.Unsupported, $"{Path.GetFileName(source)} is not a pcap or pcapng capture.", "kind=packet reads captures; kind=endpoint also reads HAR, mitmproxy and .saz");
        stream.Position = 0;
        PacketQueryResult result;
        var notes = new List<string>();
        if (filter.Unknown.Count > 0)
        {
            stream.Dispose();
            var probe = ExternalTools.Probe(ExternalTools.TShark);
            if (!probe.Usable)
                throw new ToolError(ErrorCode.Unsupported, $"not decoded in-process: {string.Join(", ", filter.Unknown)}; TShark is {probe.Problem}.",
                    $"{probe.Remediation} for any Wireshark field; in-process: {string.Join(", ", PacketFields.Names)}");
            result = TShark(probe.Path!, source, filter, offset, limit, ct);
            notes.Add($"decoded by TShark {probe.Version} for {string.Join(", ", filter.Unknown)}");
        }
        else
        {
            result = PacketQuery.Run(stream, filter, offset, limit, ct);
            notes.Add("TCP is not reassembled except a ClientHello over in-order segments and cleartext HTTP/2 streams");
        }
        var items = result.Rows.Select(r => new ContainerMatch(r.Frame.ToString(CultureInfo.InvariantCulture), Describe(r), "packet")
        {
            Detail = r.Fields.Count > 0 ? string.Join("; ", r.Fields.Select(f => $"{f.Field}={f.Value}")) : null,
        }).ToList();
        notes.InsertRange(0, result.Issues);
        notes.Insert(result.Issues.Count, result.Frames >= 0 ? $"{result.Frames:N0} frames read, {result.Matched:N0} match." : $"{result.Matched:N0} frames match.");
        return new UnpackService.ContainerSearch(source, $"{result.Format} capture", (int)Math.Clamp(result.Frames, 0, int.MaxValue), items, offset,
            (int)Math.Min(result.Matched, int.MaxValue), notes);
    }

    /// <summary>
    /// The filter run by TShark (any Wireshark field, on any OS where it is installed): its field output streamed line by
    /// line, every match counted, the page kept. Frames read are not counted (-1).
    /// </summary>
    private static PacketQueryResult TShark(string exe, string source, PacketFilter filter, int offset, int limit, CancellationToken ct)
    {
        var tool = ExternalTools.TShark;
        var named = filter.Fields.Where(f => f.Contains('.')).ToList();
        var args = ExternalTools.Arguments(tool, "fields", ("file", source), ("filter", filter.Text));
        foreach (var f in named) args.AddRange(ExternalTools.Arguments(tool, "field", ("field", f)));
        var rows = new List<PacketRow>();
        long matched = 0;
        var sink = new LineSink(line =>
        {
            var c = line.Split('\t');
            if (c.Length < 11 + named.Count || !long.TryParse(c[0], NumberStyles.None, CultureInfo.InvariantCulture, out var frame)) return;
            if (matched++ < offset || rows.Count >= limit) return;
            DateTime? time = decimal.TryParse(c[1], NumberStyles.Float, CultureInfo.InvariantCulture, out var epoch) && epoch > 0
                ? DateTime.UnixEpoch.AddTicks((long)Math.Min(epoch * TimeSpan.TicksPerSecond, (decimal)(DateTime.MaxValue.Ticks - DateTime.UnixEpoch.Ticks))) : null;
            string Host(int v4, int v6, int tcp, int udp)
            {
                var address = c[v4].Length > 0 ? c[v4] : c[v6].Length > 0 ? $"[{c[v6]}]" : "";
                var port = c[tcp].Length > 0 ? c[tcp] : c[udp];
                return address.Length == 0 ? "" : port.Length > 0 ? $"{address}:{port}" : address.Trim('[', ']');
            }
            var fields = named.Select((f, i) => (f, c[11 + i])).Where(f => f.Item2.Length > 0).Select(f => (f.f, f.Item2.Length > 200 ? f.Item2[..200] + "…" : f.Item2)).ToList();
            rows.Add(new PacketRow(frame, time, Host(2, 3, 6, 7), Host(4, 5, 8, 9), c[10].ToLowerInvariant(), fields));
        });
        var size = new FileInfo(source).Length;
        var timeout = TimeSpan.FromSeconds(Math.Clamp(size / (2 << 20), 60, 3600)); // 2 MB/s at the slowest
        var run = ExternalTools.Run(exe, args, timeout, long.MaxValue, ct, sink: sink);
        sink.Flush();
        if (run.StartError != null) throw new ToolError(ErrorCode.Unsupported, $"TShark could not be started: {run.StartError}.", ExternalTools.Remediation(tool));
        if (run.TimedOut) throw new ToolError(ErrorCode.Timeout, $"TShark did not finish within {timeout.TotalSeconds:N0} s.", "narrow the filter with in-process fields, or split the capture");
        if (run.ExitCode != 0)
        {
            var reason = run.Stderr.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).FirstOrDefault() ?? $"exit code {run.ExitCode}";
            throw new ToolError(ErrorCode.InvalidArgument, $"TShark: {reason}", "check the field names against Wireshark's display filter reference");
        }
        var format = Path.GetExtension(source).Equals(".pcapng", StringComparison.OrdinalIgnoreCase) ? "pcapng" : "pcap";
        return new PacketQueryResult(format, -1, matched, rows, []);
    }

    /// <summary>A write-only stream that hands each UTF-8 line to <paramref name="line"/>.</summary>
    private sealed class LineSink(Action<string> line) : Stream
    {
        private readonly MemoryStream _pending = new();

        public override void Write(byte[] buffer, int offset, int count) => Write(buffer.AsSpan(offset, count));

        public override void Write(ReadOnlySpan<byte> buffer)
        {
            while (buffer.Length > 0)
            {
                int eol = buffer.IndexOf((byte)'\n');
                if (eol < 0) { _pending.Write(buffer); return; }
                _pending.Write(buffer[..eol]);
                Emit();
                buffer = buffer[(eol + 1)..];
            }
        }

        private void Emit()
        {
            var text = System.Text.Encoding.UTF8.GetString(_pending.GetBuffer(), 0, (int)_pending.Length).TrimEnd('\r');
            _pending.SetLength(0);
            if (text.Length > 0) line(text);
        }

        public override void Flush() { if (_pending.Length > 0) Emit(); }
        public override bool CanRead => false;
        public override bool CanSeek => false;
        public override bool CanWrite => true;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
    }

    /// <summary>"frame 7 2023-11-14T22:13:20.250000Z 10.0.0.2:53000 -> 8.8.8.8:53 dns".</summary>
    private static string Describe(PacketRow r) =>
        $"frame {r.Frame}" + (r.Time is { } t ? " " + t.ToString("yyyy-MM-ddTHH:mm:ss.ffffffZ", CultureInfo.InvariantCulture) : "") +
        (r.Source.Length > 0 ? $" {r.Source} -> {r.Destination}" : "") + $" {r.Protocol}";

    /// <summary>A sequential read with a large buffer: the filter runs at disk speed.</summary>
    internal static FileStream Open(string path) => new(path, FileMode.Open, FileAccess.Read, FileShare.Read, 1 << 20, FileOptions.SequentialScan);
}
