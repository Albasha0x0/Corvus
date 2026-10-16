using System.Buffers.Binary;

namespace Corvus.Core.Pcap;

/// <summary>A frame that matched: number (from 1), time, endpoints, the top protocol decoded and the values of the fields the filter names.</summary>
public sealed record PacketRow(long Frame, DateTime? Time, string Source, string Destination, string Protocol, IReadOnlyList<(string Field, string Value)> Fields);

/// <summary>One filtered pass: frames read, frames matched, the requested page of rows and what the reader reported.</summary>
public sealed record PacketQueryResult(string Format, long Frames, long Matched, IReadOnlyList<PacketRow> Rows, IReadOnlyList<string> Issues);

/// <summary>
/// Runs a <see cref="PacketFilter"/> over a capture in one streaming pass: every frame is decoded in place and dropped,
/// matches are counted and only the page asked for is kept, so memory does not grow with the capture.
/// </summary>
public static class PacketQuery
{
    private const int MaxPending = 10_000, MaxHello = 16 * 1024 + 5, MaxValue = 200;

    public static PacketQueryResult Run(Stream stream, PacketFilter filter, int offset, int limit, CancellationToken ct)
    {
        if (filter.Unknown.Count > 0) throw new InvalidOperationException("the filter names fields outside the in-process set");
        var reader = new PcapReader(stream);
        var view = new PacketView();
        var rows = new List<PacketRow>();
        var pending = (filter.Layers & PacketLayers.TlsHello) != 0 ? new Dictionary<(bool, UInt128, ushort, UInt128, ushort), Pending>() : null;
        var http2 = (filter.Layers & PacketLayers.Http2) != 0 ? new Http2Tracker() : null;
        var quic = (filter.Layers & PacketLayers.Quic) != 0 ? new QuicTracker() : null;
        var smb2 = (filter.Layers & PacketLayers.Smb2) != 0 ? new Smb2Tracker() : null;
        var shown = filter.Fields.Select(PacketFields.Find).OfType<PacketField>().Where(f => f.Type != FieldType.Protocol).ToList();
        long number = 0, matched = 0;
        foreach (var frame in reader.Frames(ct))
        {
            view.Reset(++number, frame);
            if (pending != null && view.Tcp) JoinHello(view, pending);
            http2?.Observe(view);
            quic?.Observe(view);
            smb2?.Observe(view);
            if (!filter.Matches(view)) continue;
            if (matched++ < offset || rows.Count >= limit) continue;
            rows.Add(Row(view, shown));
        }
        return new PacketQueryResult(reader.Format, number, matched, rows, reader.Issues);
    }

    private sealed class Pending(byte[] buffer, int length, uint next)
    {
        public readonly byte[] Buffer = buffer;
        public int Length = length;
        public uint Next = next;
    }

    /// <summary>A ClientHello split over in-order segments of one direction, joined; the frame that completes it carries it.</summary>
    private static void JoinHello(PacketView v, Dictionary<(bool, UInt128, ushort, UInt128, ushort), Pending> pending)
    {
        var p = v.Payload;
        if (p.Length == 0) return;
        var key = (v.P.V6, v.P.Src, v.P.SrcPort, v.P.Dst, v.P.DstPort);
        if (pending.Count > 0 && pending.TryGetValue(key, out var open))
        {
            int ahead = unchecked((int)(v.P.Seq - open.Next));
            if (ahead < 0) return; // a retransmission
            pending.Remove(key);
            if (ahead > 0) return; // a gap: not reassembled
            int take = Math.Min(p.Length, open.Buffer.Length - open.Length);
            p[..take].CopyTo(open.Buffer.AsSpan(open.Length));
            open.Length += take;
            if (open.Length < open.Buffer.Length) { open.Next = unchecked(open.Next + (uint)p.Length); pending[key] = open; return; }
            if (HelloFacts.Of(open.Buffer) is { } joined) v.JoinedHello = joined;
            return;
        }
        if (p.Length < 6 || p[0] != 0x16 || p[5] != 1) return;
        int need = Math.Min(5 + BinaryPrimitives.ReadUInt16BigEndian(p[3..]), MaxHello);
        if (p.Length >= need || pending.Count >= MaxPending) return;
        var buffer = new byte[need];
        p.CopyTo(buffer);
        pending[key] = new Pending(buffer, p.Length, unchecked(v.P.Seq + (uint)p.Length));
    }

    private static PacketRow Row(PacketView v, List<PacketField> shown)
    {
        var fields = new List<(string, string)>();
        foreach (var f in shown)
        {
            var values = v.Values(f);
            if (values.Count == 0) continue;
            var text = string.Join(",", values.Select(x => x.Display(f.Type)).Distinct());
            fields.Add((f.Name, text.Length > MaxValue ? text[..MaxValue] + "…" : text));
        }
        DateTime? time = v.Micros > 0 ? DateTime.UnixEpoch.AddTicks(Math.Min(v.Micros, (DateTime.MaxValue.Ticks - DateTime.UnixEpoch.Ticks) / 10) * 10) : null;
        if (!v.Ip) return new PacketRow(v.Number, time, "", "", PacketDecoder.LinkTypeName(v.LinkType), fields);
        bool ports = v.Tcp || v.Udp;
        string src = ports ? PacketDecoder.Endpoint(v.P.V6, v.P.Src, v.P.SrcPort) : PacketDecoder.Address(v.P.V6, v.P.Src);
        string dst = ports ? PacketDecoder.Endpoint(v.P.V6, v.P.Dst, v.P.DstPort) : PacketDecoder.Address(v.P.V6, v.P.Dst);
        return new PacketRow(v.Number, time, src, dst, Protocol(v), fields);
    }

    /// <summary>The highest protocol decoded in the frame, as Wireshark's protocol column would name it.</summary>
    internal static string Protocol(PacketView v)
    {
        if (v.Kerberos != null) return "kerberos";
        if (v.Smb2 != null) return "smb2";
        if (v.Http2 != null) return "http2";
        if (v.Quic != null) return "quic";
        if (v.Dns != null) return "dns";
        if (v.Http != null) return "http";
        if (v.TlsRecord) return "tls";
        if (v.Tcp) return "tcp";
        if (v.Udp) return "udp";
        if (v.P.Fragment) return v.P.V6 ? "ipv6 fragment" : "ip fragment";
        return v.P.Protocol switch { 1 => "icmp", 58 => "icmpv6", var n => $"{(v.P.V6 ? "ipv6" : "ip")} proto {n}" };
    }
}
