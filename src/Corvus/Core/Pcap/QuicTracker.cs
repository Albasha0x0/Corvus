using System.Buffers.Binary;

namespace Corvus.Core.Pcap;

/// <summary>A QUIC long-header packet: version, packet type and connection ids.</summary>
internal sealed record QuicFacts(long Version, long PacketType, string Dcid, string Scid);

/// <summary>QUIC long headers and client Initials decrypted until the ClientHello is whole, as Wireshark shows them.</summary>
internal sealed class QuicTracker
{
    private const int MaxConnections = 10_000, MaxHello = 16 * 1024;
    private const uint V1 = 1, V2 = 0x6b3343cf;

    private sealed class Crypto
    {
        public readonly byte[] Data = new byte[MaxHello];
        public readonly List<(int Start, int End)> Have = [];
        public bool Done;
    }

    private readonly Dictionary<string, Crypto> _connections = new(StringComparer.Ordinal);

    public void Observe(PacketView v)
    {
        if (!v.Udp) return;
        var p = v.Payload;
        if (p.Length < 7 || (p[0] & 0xC0) != 0xC0) return;
        uint version = BinaryPrimitives.ReadUInt32BigEndian(p[1..]);
        int at = 5;
        int dcidLength = p[at++];
        if (dcidLength > 20 || at + dcidLength >= p.Length) return;
        var dcid = p.Slice(at, dcidLength);
        at += dcidLength;
        int scidLength = p[at++];
        if (scidLength > 20 || at + scidLength > p.Length) return;
        var scid = p.Slice(at, scidLength);
        at += scidLength;
        if (version == 0) { v.Quic = new QuicFacts(0, -1, Convert.ToHexStringLower(dcid), Convert.ToHexStringLower(scid)); return; } // version negotiation
        int type = (p[0] >> 4) & 3;
        v.Quic = new QuicFacts(version, type, Convert.ToHexStringLower(dcid), Convert.ToHexStringLower(scid));
        bool initial = version == V1 && type == 0 || version == V2 && type == 1;
        if (!initial || dcidLength == 0) return;
        if (!QuicCapture.Varint(p, ref at, out var tokenLength) || tokenLength > (ulong)(p.Length - at)) return;
        at += (int)tokenLength;
        if (!QuicCapture.Varint(p, ref at, out var length) || length > (ulong)(p.Length - at) || length < 20) return;
        var key = Convert.ToHexStringLower(dcid);
        if (_connections.TryGetValue(key, out var crypto) && crypto.Done) return;
        // A server Initial uses other keys.
        if (QuicCapture.InitialPayload(version, dcid.ToArray(), p[..(at + (int)length)], at) is not { } plain) return;
        if (crypto == null)
        {
            if (_connections.Count >= MaxConnections) return;
            _connections[key] = crypto = new Crypto();
        }
        if (Frames(plain, crypto) && Hello(crypto) is { } hello) { crypto.Done = true; v.JoinedHello = hello; }
    }

    /// <summary>CRYPTO frame data placed at its offsets; false at a frame type that cannot be skipped.</summary>
    private static bool Frames(ReadOnlySpan<byte> b, Crypto crypto)
    {
        int at = 0;
        while (at < b.Length)
        {
            int start = at;
            if (!QuicCapture.Varint(b, ref at, out var type)) return false;
            switch (type)
            {
                case 0x00 or 0x01: break; // padding, ping
                case 0x02 or 0x03: // ack
                    {
                        if (!QuicCapture.Varint(b, ref at, out _) || !QuicCapture.Varint(b, ref at, out _) || !QuicCapture.Varint(b, ref at, out var ranges) || !QuicCapture.Varint(b, ref at, out _)) return false;
                        for (ulong i = 0; i < ranges * 2 + (type == 3 ? 3UL : 0); i++) if (!QuicCapture.Varint(b, ref at, out _)) return false;
                        break;
                    }
                case 0x06:
                    {
                        if (!QuicCapture.Varint(b, ref at, out var offset) || !QuicCapture.Varint(b, ref at, out var length) || length > (ulong)(b.Length - at)) return false;
                        if (offset < MaxHello)
                        {
                            int take = (int)Math.Min(length, MaxHello - offset);
                            b.Slice(at, take).CopyTo(crypto.Data.AsSpan((int)offset));
                            crypto.Have.Add(((int)offset, (int)offset + take));
                        }
                        at += (int)length;
                        break;
                    }
                case 0x1C or 0x1D: // connection close
                    {
                        if (!QuicCapture.Varint(b, ref at, out _) || (type == 0x1C && !QuicCapture.Varint(b, ref at, out _)) || !QuicCapture.Varint(b, ref at, out var reason) || reason > (ulong)(b.Length - at)) return false;
                        at += (int)reason;
                        break;
                    }
                default: return true;
            }
            if (at == start) return false;
        }
        return true;
    }

    /// <summary>The ClientHello once the CRYPTO stream holds it from offset 0 without gaps; null before.</summary>
    private static HelloFacts? Hello(Crypto crypto)
    {
        crypto.Have.Sort();
        int contiguous = 0;
        foreach (var (start, end) in crypto.Have)
        {
            if (start > contiguous) break;
            contiguous = Math.Max(contiguous, end);
        }
        if (contiguous < 4 || crypto.Data[0] != 1) return null;
        int need = 4 + (crypto.Data[1] << 16 | crypto.Data[2] << 8 | crypto.Data[3]);
        if (need > MaxHello || contiguous < need) return null;
        // A TLS record header in front, as the record reader expects one.
        byte[] record = [0x16, 3, 1, (byte)(need >> 8), (byte)need, .. crypto.Data.AsSpan(0, need)];
        return HelloFacts.Of(record, quic: true);
    }
}
