namespace Corvus.Core.Pcap;

/// <summary>Who a TCP connection joins: the client (the side that sent the SYN, else the higher port) and the server.</summary>
internal sealed record TcpConnectionInfo(int Index, string Client, string Server, ushort ServerPort, long FirstMicros);

/// <summary>The in-order bytes of a TCP connection's two directions; a gap says how many bytes were never captured.</summary>
internal interface ITcpConsumer
{
    void Data(bool fromClient, ReadOnlySpan<byte> data);
    void Gap(bool fromClient, long bytes);
    void End();
}

/// <summary>
/// TCP reassembly: each direction's segments are put in sequence order, retransmitted and overlapping bytes dropped, and
/// handed on in order. Segments ahead of a hole wait up to <see cref="MaxPending"/> bytes per direction; past that, at a
/// FIN or RST and at the end of the capture the hole becomes a gap of its size. A connection ends at FIN or RST from both
/// sides, at RST, or when <see cref="MaxConnections"/> are open (the oldest ends).
/// </summary>
internal sealed class TcpStreams(Func<TcpConnectionInfo, ITcpConsumer> open)
{
    public const int MaxConnections = 20_000;
    private const int MaxPending = 4 << 20;

    private sealed class Direction
    {
        public bool Started, Finished;
        /// <summary>The next sequence number expected, and its offset in the stream (bytes delivered and skipped).</summary>
        public uint Next;
        public long Position;
        /// <summary>Segments ahead of a hole by stream offset.</summary>
        public readonly SortedDictionary<long, byte[]> Pending = [];
        public long PendingBytes;
    }

    private sealed class Connection(TcpConnectionInfo info, ITcpConsumer consumer, bool v6, UInt128 client, ushort clientPort)
    {
        public readonly TcpConnectionInfo Info = info;
        public readonly ITcpConsumer Consumer = consumer;
        public readonly bool V6 = v6;
        public readonly UInt128 Client = client;
        public readonly ushort ClientPort = clientPort;
        public readonly Direction FromClient = new(), FromServer = new();
        public long LastSeen;
    }

    private readonly Dictionary<(bool, UInt128, ushort, UInt128, ushort), Connection> _open = [];
    private int _count;
    private long _tick;

    public int Connections => _count;
    public long Gaps { get; private set; }
    public long GapBytes { get; private set; }

    public void Add(in DecodedPacket p, ReadOnlySpan<byte> payload, long micros)
    {
        if (p.Protocol != PacketDecoder.Tcp || p.Fragment) return;
        bool lowFirst = p.Src < p.Dst || (p.Src == p.Dst && p.SrcPort <= p.DstPort);
        var key = lowFirst ? (p.V6, p.Src, p.SrcPort, p.Dst, p.DstPort) : (p.V6, p.Dst, p.DstPort, p.Src, p.SrcPort);
        bool syn = (p.TcpFlags & 0x02) != 0, ack = (p.TcpFlags & 0x10) != 0, fin = (p.TcpFlags & 0x01) != 0, rst = (p.TcpFlags & 0x04) != 0;
        if (!_open.TryGetValue(key, out var c))
        {
            if (rst || (payload.Length == 0 && !syn)) return;
            if (_open.Count >= MaxConnections) Close(_open.MinBy(o => o.Value.LastSeen).Key);
            // the SYN's sender is the client; a SYN-ACK's receiver; else the higher port
            bool srcClient = syn ? !ack : p.SrcPort != p.DstPort ? p.SrcPort > p.DstPort : true;
            var (client, clientPort, server, serverPort) = srcClient ? (p.Src, p.SrcPort, p.Dst, p.DstPort) : (p.Dst, p.DstPort, p.Src, p.SrcPort);
            var info = new TcpConnectionInfo(_count++, PacketDecoder.Endpoint(p.V6, client, clientPort), PacketDecoder.Endpoint(p.V6, server, serverPort), serverPort, micros);
            c = _open[key] = new Connection(info, open(info), p.V6, client, clientPort);
        }
        c.LastSeen = ++_tick;
        bool fromClient = p.Src == c.Client && p.SrcPort == c.ClientPort;
        var d = fromClient ? c.FromClient : c.FromServer;
        if (!d.Started)
        {
            d.Started = true;
            d.Next = syn ? unchecked(p.Seq + 1) : p.Seq;
        }
        if (payload.Length > 0) Segment(c, fromClient, d, syn ? unchecked(p.Seq + 1) : p.Seq, payload);
        if (fin) d.Finished = true;
        if (rst || (c.FromClient.Finished && c.FromServer.Finished)) Close(key);
    }

    private void Segment(Connection c, bool fromClient, Direction d, uint seq, ReadOnlySpan<byte> payload)
    {
        long ahead = unchecked((int)(seq - d.Next));
        if (ahead + payload.Length <= 0) return; // all of it delivered already
        if (ahead <= 0)
        {
            Deliver(c, fromClient, d, payload[(int)-ahead..]);
            Drain(c, fromClient, d);
            return;
        }
        long at = d.Position + ahead;
        if (!d.Pending.TryGetValue(at, out var old) || old.Length < payload.Length)
        {
            d.PendingBytes += payload.Length - (old?.Length ?? 0);
            d.Pending[at] = payload.ToArray();
        }
        while (d.PendingBytes > MaxPending) Skip(c, fromClient, d);
    }

    private static void Deliver(Connection c, bool fromClient, Direction d, ReadOnlySpan<byte> data)
    {
        d.Next = unchecked(d.Next + (uint)data.Length);
        d.Position += data.Length;
        c.Consumer.Data(fromClient, data);
    }

    /// <summary>Waiting segments that now continue the stream.</summary>
    private static void Drain(Connection c, bool fromClient, Direction d)
    {
        while (d.Pending.Count > 0)
        {
            var (offset, bytes) = d.Pending.First();
            long ahead = offset - d.Position;
            if (ahead > 0) return;
            d.Pending.Remove(offset);
            d.PendingBytes -= bytes.Length;
            if (ahead + bytes.Length > 0) Deliver(c, fromClient, d, bytes.AsSpan((int)-ahead));
        }
    }

    /// <summary>The hole before the first waiting segment becomes a gap; the stream goes on from that segment.</summary>
    private void Skip(Connection c, bool fromClient, Direction d)
    {
        if (d.Pending.Count == 0) return;
        long ahead = d.Pending.First().Key - d.Position;
        if (ahead > 0)
        {
            Gaps++;
            GapBytes += ahead;
            c.Consumer.Gap(fromClient, ahead);
            d.Next = unchecked(d.Next + (uint)ahead);
            d.Position += ahead;
        }
        Drain(c, fromClient, d);
    }

    private void Close((bool, UInt128, ushort, UInt128, ushort) key)
    {
        var c = _open[key];
        _open.Remove(key);
        while (c.FromClient.Pending.Count > 0) Skip(c, true, c.FromClient);
        while (c.FromServer.Pending.Count > 0) Skip(c, false, c.FromServer);
        c.Consumer.End();
    }

    /// <summary>Ends every open connection (the capture is over).</summary>
    public void Finish()
    {
        foreach (var key in _open.Keys.ToList()) Close(key);
    }
}
