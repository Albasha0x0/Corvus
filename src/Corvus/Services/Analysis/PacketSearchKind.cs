using System.Globalization;
using Corvus.Core;
using Corvus.Core.Pcap;

namespace Corvus.Services.Analysis;

/// <summary>
/// search_container kind=packet on a pcap / pcapng capture: the query is a Wireshark display filter over the fields decoded
/// in-process (addresses, ports, DNS, HTTP, TLS server names); rows are the matching frames in capture order, streamed.
/// </summary>
internal sealed class PacketSearchKind : IContainerSearchKind
{
    public IReadOnlyList<string> Kinds => ["packet"];

    public IEnumerable<ContainerMatch> Search(ContainerScope scope, string kind, Func<string, bool> matches, CancellationToken ct) => [];

    public UnpackService.ContainerSearch SearchFile(string path, string query, int offset, int limit, CancellationToken ct)
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
        if (filter.Unknown.Count > 0)
            throw new ToolError(ErrorCode.Unsupported, $"not decoded in-process: {string.Join(", ", filter.Unknown)}.",
                $"in-process fields: {string.Join(", ", PacketFields.Names)}");
        var result = PacketQuery.Run(stream, filter, offset, limit, ct);
        var items = result.Rows.Select(r => new ContainerMatch(r.Frame.ToString(CultureInfo.InvariantCulture), Describe(r), "packet")
        {
            Detail = r.Fields.Count > 0 ? string.Join("; ", r.Fields.Select(f => $"{f.Field}={f.Value}")) : null,
        }).ToList();
        var notes = new List<string>(result.Issues)
        {
            $"{result.Frames:N0} frames read, {result.Matched:N0} match; TCP is not reassembled except a ClientHello over in-order segments.",
        };
        return new UnpackService.ContainerSearch(source, $"{result.Format} capture", (int)Math.Min(result.Frames, int.MaxValue), items, offset,
            (int)Math.Min(result.Matched, int.MaxValue), notes);
    }

    /// <summary>"frame 7 2023-11-14T22:13:20.250000Z 10.0.0.2:53000 -> 8.8.8.8:53 dns".</summary>
    private static string Describe(PacketRow r) =>
        $"frame {r.Frame}" + (r.Time is { } t ? " " + t.ToString("yyyy-MM-ddTHH:mm:ss.ffffffZ", CultureInfo.InvariantCulture) : "") +
        (r.Source.Length > 0 ? $" {r.Source} -> {r.Destination}" : "") + $" {r.Protocol}";

    /// <summary>A sequential read with a large buffer: the filter runs at disk speed.</summary>
    internal static FileStream Open(string path) => new(path, FileMode.Open, FileAccess.Read, FileShare.Read, 1 << 20, FileOptions.SequentialScan);
}
