using System.Buffers.Binary;

namespace Corvus.Core.Pcap;

/// <summary>HTTP/2 frames that end in one TCP segment: frame types, stream ids and the headers of the blocks they complete.</summary>
internal sealed record Http2Facts(List<long> Types, List<long> Streams, List<(string Name, string Value)> Headers);

/// <summary>Cleartext HTTP/2 header blocks per direction; a gap or undecodable block stops the connection's decoding.</summary>
internal sealed class Http2Tracker
{
    private const int MaxConnections = 10_000, MaxBuffer = 1 << 20;
    private static readonly byte[] Preface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"u8.ToArray();

    private sealed class Direction
    {
        public readonly Hpack Hpack = new();
        public byte[] Buffer = new byte[4096];
        public int Length;
        public uint Next;
        public bool Started, Broken, AwaitPreface;
        public List<byte>? Block;
    }

    private readonly Dictionary<(bool, UInt128, ushort, UInt128, ushort), Direction> _directions = [];

    public void Observe(PacketView v)
    {
        if (!v.Tcp) return;
        var p = v.Payload;
        var key = (v.P.V6, v.P.Src, v.P.SrcPort, v.P.Dst, v.P.DstPort);
        if (!_directions.TryGetValue(key, out var d))
        {
            if (p.Length < Preface.Length || !p[..Preface.Length].SequenceEqual(Preface) || _directions.Count >= MaxConnections) return;
            d = _directions[key] = new Direction { AwaitPreface = true };
            _directions.TryAdd((v.P.V6, v.P.Dst, v.P.DstPort, v.P.Src, v.P.SrcPort), new Direction());
        }
        if (d.Broken || p.Length == 0) return;
        if (!d.Started) { d.Started = true; d.Next = v.P.Seq; }
        int ahead = unchecked((int)(v.P.Seq - d.Next));
        if (ahead < 0) return; // a retransmission
        if (ahead > 0 || d.Length + p.Length > MaxBuffer) { d.Broken = true; return; }
        if (d.Buffer.Length < d.Length + p.Length) Array.Resize(ref d.Buffer, Math.Max(d.Length + p.Length, d.Buffer.Length * 2));
        p.CopyTo(d.Buffer.AsSpan(d.Length));
        d.Length += p.Length;
        d.Next = unchecked(d.Next + (uint)p.Length);
        int at = 0;
        if (d.AwaitPreface)
        {
            if (d.Length < Preface.Length) return;
            at = Preface.Length;
            d.AwaitPreface = false;
        }
        Http2Facts? facts = null;
        while (d.Length - at >= 9)
        {
            var b = d.Buffer.AsSpan(at, d.Length - at);
            int length = b[0] << 16 | b[1] << 8 | b[2];
            if (b.Length < 9 + length) break;
            byte type = b[3], flags = b[4];
            uint stream = BinaryPrimitives.ReadUInt32BigEndian(b[5..]) & 0x7FFFFFFF;
            facts ??= new Http2Facts([], [], []);
            facts.Types.Add(type);
            facts.Streams.Add(stream);
            if (!Frame(d, type, flags, b.Slice(9, length), facts)) { d.Broken = true; break; }
            at += 9 + length;
        }
        if (at > 0 && !d.Broken)
        {
            d.Buffer.AsSpan(at, d.Length - at).CopyTo(d.Buffer);
            d.Length -= at;
        }
        v.Http2 = facts;
    }

    /// <summary>Decodes a header block fragment as Wireshark does; false when the block is malformed.</summary>
    private static bool Frame(Direction d, byte type, byte flags, ReadOnlySpan<byte> body, Http2Facts facts)
    {
        if (type is not (1 or 5 or 9)) return true;
        if (type != 9)
        {
            int skip = 0, pad = 0;
            if ((flags & 0x08) != 0) { if (body.Length < 1) return false; pad = body[0]; skip = 1; }
            if (type == 1 && (flags & 0x20) != 0) skip += 5;
            if (type == 5) skip += 4;
            if (skip + pad > body.Length) return false;
            body = body[skip..^pad];
            d.Block = [];
        }
        else if (d.Block == null) return false;
        d.Block!.AddRange(body);
        var headers = d.Hpack.Decode(System.Runtime.InteropServices.CollectionsMarshal.AsSpan(d.Block), out int consumed);
        if (headers == null) return false;
        facts.Headers.AddRange(headers);
        d.Block.RemoveRange(0, consumed);
        if ((flags & 0x04) == 0) return true;
        bool whole = d.Block.Count == 0;
        d.Block = null;
        return whole;
    }
}
