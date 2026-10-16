using System.Buffers.Binary;
using System.Security.Cryptography;

namespace Corvus.Core.Pcap;

/// <summary>A QUIC long-header packet: version, packet type and connection ids.</summary>
internal sealed record QuicFacts(long Version, long PacketType, string Dcid, string Scid);

/// <summary>
/// QUIC long headers, and client Initial packets decrypted with the keys their destination connection id derives (RFC 9001
/// for version 1, RFC 9369 for version 2): CRYPTO frames are joined per connection, in any order, until the ClientHello is
/// whole; the packet that completes it carries its server name and ALPN, as Wireshark shows them.
/// </summary>
internal sealed class QuicTracker
{
    private const int MaxConnections = 10_000, MaxHello = 16 * 1024;
    private const uint V1 = 1, V2 = 0x6b3343cf;
    private static readonly byte[] SaltV1 = Convert.FromHexString("38762cf7f55934b34d179ae6a4c80cadccbb7f0a");
    private static readonly byte[] SaltV2 = Convert.FromHexString("0dede3def700a6db819381be6e269dcbf9bd2ed9");

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
        if (!Varint(p, ref at, out var tokenLength) || tokenLength > (ulong)(p.Length - at)) return;
        at += (int)tokenLength;
        if (!Varint(p, ref at, out var length) || length > (ulong)(p.Length - at) || length < 20) return;
        var key = Convert.ToHexStringLower(dcid);
        if (_connections.TryGetValue(key, out var crypto) && crypto.Done) return;
        if (Decrypt(version, dcid, p[..(at + (int)length)], at) is not { } plain) return; // a server Initial: other keys
        if (crypto == null)
        {
            if (_connections.Count >= MaxConnections) return;
            _connections[key] = crypto = new Crypto();
        }
        if (Frames(plain, crypto) && Hello(crypto) is { } hello) { crypto.Done = true; v.JoinedHello = hello; }
    }

    /// <summary>The payload of a protected Initial, or null when it does not authenticate.</summary>
    private static byte[]? Decrypt(uint version, ReadOnlySpan<byte> dcid, ReadOnlySpan<byte> packet, int pnOffset)
    {
        string prefix = version == V2 ? "quicv2 " : "quic ";
        var initial = HKDF.Extract(HashAlgorithmName.SHA256, dcid.ToArray(), version == V2 ? SaltV2 : SaltV1);
        var client = ExpandLabel(initial, "client in", 32);
        var key = ExpandLabel(client, prefix + "key", 16);
        var iv = ExpandLabel(client, prefix + "iv", 12);
        var hp = ExpandLabel(client, prefix + "hp", 16);
        if (pnOffset + 4 + 16 > packet.Length) return null;
        using var aes = Aes.Create();
        aes.Key = hp;
        var mask = aes.EncryptEcb(packet.Slice(pnOffset + 4, 16), PaddingMode.None);
        var header = packet[..(pnOffset + 4)].ToArray();
        header[0] ^= (byte)(mask[0] & 0x0F);
        int pnLength = (header[0] & 3) + 1;
        ulong pn = 0;
        for (int i = 0; i < pnLength; i++)
        {
            header[pnOffset + i] ^= mask[1 + i];
            pn = pn << 8 | header[pnOffset + i];
        }
        var aad = header.AsSpan(0, pnOffset + pnLength);
        var sealedPart = packet[(pnOffset + pnLength)..];
        if (sealedPart.Length < 16) return null;
        var nonce = iv;
        for (int i = 0; i < 8; i++) nonce[11 - i] ^= (byte)(pn >> (8 * i));
        var plain = new byte[sealedPart.Length - 16];
        try
        {
            using var gcm = new AesGcm(key, 16);
            gcm.Decrypt(nonce, sealedPart[..^16], sealedPart[^16..], plain, aad);
        }
        catch (CryptographicException) { return null; }
        return plain;
    }

    /// <summary>TLS 1.3 HKDF-Expand-Label with an empty context.</summary>
    private static byte[] ExpandLabel(byte[] secret, string label, int length)
    {
        var full = System.Text.Encoding.ASCII.GetBytes("tls13 " + label);
        byte[] info = [(byte)(length >> 8), (byte)length, (byte)full.Length, .. full, 0];
        return HKDF.Expand(HashAlgorithmName.SHA256, secret, length, info);
    }

    /// <summary>CRYPTO frame data placed at its offsets; false at a frame type that cannot be skipped.</summary>
    private static bool Frames(ReadOnlySpan<byte> b, Crypto crypto)
    {
        int at = 0;
        while (at < b.Length)
        {
            int start = at;
            if (!Varint(b, ref at, out var type)) return false;
            switch (type)
            {
                case 0x00 or 0x01: break; // padding, ping
                case 0x02 or 0x03: // ack
                    {
                        if (!Varint(b, ref at, out _) || !Varint(b, ref at, out _) || !Varint(b, ref at, out var ranges) || !Varint(b, ref at, out _)) return false;
                        for (ulong i = 0; i < ranges * 2 + (type == 3 ? 3UL : 0); i++) if (!Varint(b, ref at, out _)) return false;
                        break;
                    }
                case 0x06:
                    {
                        if (!Varint(b, ref at, out var offset) || !Varint(b, ref at, out var length) || length > (ulong)(b.Length - at)) return false;
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
                        if (!Varint(b, ref at, out _) || (type == 0x1C && !Varint(b, ref at, out _)) || !Varint(b, ref at, out var reason) || reason > (ulong)(b.Length - at)) return false;
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
        // a TLS record header in front, as the record reader expects one
        byte[] record = [0x16, 3, 1, (byte)(need >> 8), (byte)need, .. crypto.Data.AsSpan(0, need)];
        return HelloFacts.Of(record, quic: true);
    }

    private static bool Varint(ReadOnlySpan<byte> b, ref int at, out ulong value)
    {
        value = 0;
        if (at >= b.Length) return false;
        int length = 1 << (b[at] >> 6);
        if (at + length > b.Length) return false;
        value = (ulong)(b[at] & 0x3F);
        for (int i = 1; i < length; i++) value = value << 8 | b[at + i];
        at += length;
        return true;
    }
}
