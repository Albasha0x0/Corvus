using System.Buffers.Binary;
using System.Net;

namespace Corvus.Core.Pcap;

/// <summary>
/// An IP packet's addresses (IPv4 in the low 32 bits), protocol and, for TCP and UDP, ports, TCP flags and sequence, and
/// the payload's range in the frame. <see cref="Fragment"/> marks a later IPv4 / IPv6 fragment: no transport header.
/// </summary>
internal readonly record struct DecodedPacket(bool V6, UInt128 Src, UInt128 Dst, byte Protocol, ushort SrcPort, ushort DstPort,
    byte TcpFlags, uint Seq, int PayloadStart, int PayloadLength, bool Fragment)
{
    /// <summary>The TCP acknowledgment number (meaningful with the ACK flag).</summary>
    public uint Ack { get; init; }
}

/// <summary>Link layer (Ethernet with 802.1Q / 802.1ad tags, Linux cooked SLL and SLL2, raw IP, null / loopback) to IP to TCP / UDP.</summary>
internal static class PacketDecoder
{
    public const byte Tcp = 6, Udp = 17;

    public static string LinkTypeName(int linkType) => linkType switch
    {
        0 => "null/loopback",
        1 => "Ethernet",
        12 or 14 or 101 => "raw IP",
        108 => "OpenBSD loopback",
        113 => "Linux cooked (SLL)",
        228 => "raw IPv4",
        229 => "raw IPv6",
        276 => "Linux cooked (SLL2)",
        _ => $"link type {linkType} (not decoded)",
    };

    public static bool TryDecode(int linkType, ReadOnlySpan<byte> f, out DecodedPacket p)
    {
        p = default;
        int at;
        int etherType;
        switch (linkType)
        {
            case 1:
                if (f.Length < 14) return false;
                at = 12;
                etherType = BinaryPrimitives.ReadUInt16BigEndian(f[at..]);
                for (int tags = 0; etherType is 0x8100 or 0x88A8 or 0x9100 && tags < 4; tags++)
                {
                    at += 4;
                    if (at + 2 > f.Length) return false;
                    etherType = BinaryPrimitives.ReadUInt16BigEndian(f[at..]);
                }
                at += 2;
                break;
            case 113:
                if (f.Length < 16) return false;
                etherType = BinaryPrimitives.ReadUInt16BigEndian(f[14..]);
                at = 16;
                break;
            case 276:
                if (f.Length < 20) return false;
                etherType = BinaryPrimitives.ReadUInt16BigEndian(f);
                at = 20;
                break;
            case 12 or 14 or 101:
                if (f.Length < 1) return false;
                etherType = (f[0] >> 4) == 6 ? 0x86DD : 0x0800;
                at = 0;
                break;
            case 228: etherType = 0x0800; at = 0; break;
            case 229: etherType = 0x86DD; at = 0; break;
            case 0 or 108:
                {
                    if (f.Length < 4) return false;
                    // the address family in the capturing host's order (null) or network order (loopback)
                    uint family = BinaryPrimitives.ReadUInt32LittleEndian(f);
                    if (family > 0xFFFF) family = BinaryPrimitives.ReadUInt32BigEndian(f);
                    etherType = family == 2 ? 0x0800 : family is 10 or 24 or 28 or 30 ? 0x86DD : 0;
                    at = 4;
                    break;
                }
            default: return false;
        }
        return etherType switch
        {
            0x0800 => Ipv4(f[at..], at, out p),
            0x86DD => Ipv6(f[at..], at, out p),
            _ => false,
        };
    }

    private static bool Ipv4(ReadOnlySpan<byte> ip, int start, out DecodedPacket p)
    {
        p = default;
        if (ip.Length < 20 || ip[0] >> 4 != 4) return false;
        int ihl = (ip[0] & 0xF) * 4, total = BinaryPrimitives.ReadUInt16BigEndian(ip[2..]);
        if (ihl < 20 || ihl > ip.Length || total < ihl) return false;
        ip = ip[..Math.Min(total, ip.Length)]; // drops Ethernet padding; a snapped packet keeps what was captured
        bool later = (BinaryPrimitives.ReadUInt16BigEndian(ip[6..]) & 0x1FFF) != 0;
        var src = BinaryPrimitives.ReadUInt32BigEndian(ip[12..]);
        var dst = BinaryPrimitives.ReadUInt32BigEndian(ip[16..]);
        p = new DecodedPacket(false, src, dst, ip[9], 0, 0, 0, 0, start + ip.Length, 0, later);
        return later || Transport(ip[ihl..], start + ihl, ref p);
    }

    private static bool Ipv6(ReadOnlySpan<byte> ip, int start, out DecodedPacket p)
    {
        p = default;
        if (ip.Length < 40 || ip[0] >> 4 != 6) return false;
        int payload = BinaryPrimitives.ReadUInt16BigEndian(ip[4..]);
        if (payload > 0) ip = ip[..Math.Min(40 + payload, ip.Length)]; // 0 is a jumbogram: the frame bounds it
        byte next = ip[6];
        int at = 40;
        bool later = false;
        for (int n = 0; n < 8 && next is 0 or 43 or 44 or 51 or 60; n++)
        {
            if (at + 8 > ip.Length) return false;
            byte following = ip[at];
            int len = next switch
            {
                44 => 8,
                51 => (ip[at + 1] + 2) * 4,
                _ => (ip[at + 1] + 1) * 8,
            };
            if (next == 44) later |= (BinaryPrimitives.ReadUInt16BigEndian(ip[(at + 2)..]) & 0xFFF8) != 0;
            next = following;
            at += len;
            if (at > ip.Length) return false;
        }
        p = new DecodedPacket(true, BinaryPrimitives.ReadUInt128BigEndian(ip[8..]), BinaryPrimitives.ReadUInt128BigEndian(ip[24..]), next,
            0, 0, 0, 0, start + ip.Length, 0, later);
        return later || Transport(ip[at..], start + at, ref p);
    }

    /// <summary>Fills ports and payload for TCP and UDP; other protocols keep none.</summary>
    private static bool Transport(ReadOnlySpan<byte> t, int start, ref DecodedPacket p)
    {
        if (p.Protocol == Tcp)
        {
            if (t.Length < 20) return false;
            int offset = (t[12] >> 4) * 4;
            if (offset < 20 || offset > t.Length) return false;
            p = p with
            {
                SrcPort = BinaryPrimitives.ReadUInt16BigEndian(t), DstPort = BinaryPrimitives.ReadUInt16BigEndian(t[2..]),
                Seq = BinaryPrimitives.ReadUInt32BigEndian(t[4..]), Ack = BinaryPrimitives.ReadUInt32BigEndian(t[8..]), TcpFlags = t[13], PayloadStart = start + offset, PayloadLength = t.Length - offset,
            };
        }
        else if (p.Protocol == Udp)
        {
            if (t.Length < 8) return false;
            int length = BinaryPrimitives.ReadUInt16BigEndian(t[4..]);
            p = p with
            {
                SrcPort = BinaryPrimitives.ReadUInt16BigEndian(t), DstPort = BinaryPrimitives.ReadUInt16BigEndian(t[2..]),
                PayloadStart = start + 8, PayloadLength = length >= 8 ? Math.Min(length, t.Length) - 8 : t.Length - 8,
            };
        }
        return true;
    }

    public static string Address(bool v6, UInt128 a)
    {
        if (!v6) return new IPAddress(BinaryPrimitives.ReverseEndianness((uint)a)).ToString();
        Span<byte> b = stackalloc byte[16];
        BinaryPrimitives.WriteUInt128BigEndian(b, a);
        return new IPAddress(b).ToString();
    }

    public static string Endpoint(bool v6, UInt128 a, ushort port) => v6 ? $"[{Address(true, a)}]:{port}" : $"{Address(false, a)}:{port}";
}
