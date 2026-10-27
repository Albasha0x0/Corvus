using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;

namespace Corvus.Core.Pcap;

/// <summary>The ClientHello or ServerHello fields that key derivation and fingerprints use.</summary>
internal sealed class TlsHello
{
    public bool Client;
    public ushort LegacyVersion;
    public byte[] Random = [];
    public List<ushort> Ciphers = [];
    public List<ushort> Extensions = [];
    public List<ushort> Groups = [];
    public List<byte> PointFormats = [];
    public List<ushort> SignatureAlgorithms = [];
    public List<string> Alpn = [];
    public List<ushort> Versions = [];
    public string? ServerName;

    /// <summary>The negotiated (server) or highest offered (client) version: supported_versions when present.</summary>
    public ushort Version => Versions.Where(v => !Grease(v)).DefaultIfEmpty(LegacyVersion).Max();

    /// <summary>GREASE values (RFC 8701): 0x?A?A with both bytes equal.</summary>
    public static bool Grease(ushort v) => (v & 0x0F0F) == 0x0A0A && (v >> 8) == (v & 0xFF);

    /// <summary>A hello message (type 1 or 2 with its 4-byte header); null when malformed or another message.</summary>
    public static TlsHello? Parse(ReadOnlySpan<byte> m)
    {
        if (m.Length < 4 || m[0] is not (1 or 2)) return null;
        int length = m[1] << 16 | m[2] << 8 | m[3];
        if (m.Length < 4 + length) return null;
        var b = m.Slice(4, length);
        var h = new TlsHello { Client = m[0] == 1 };
        try
        {
            int at = 0;
            h.LegacyVersion = BinaryPrimitives.ReadUInt16BigEndian(b);
            h.Random = b.Slice(2, 32).ToArray();
            at = 34;
            at += 1 + b[at]; // session id
            if (h.Client)
            {
                int n = BinaryPrimitives.ReadUInt16BigEndian(b[at..]);
                for (int i = 0; i + 1 < n; i += 2) h.Ciphers.Add(BinaryPrimitives.ReadUInt16BigEndian(b[(at + 2 + i)..]));
                at += 2 + n;
                at += 1 + b[at]; // compression methods
            }
            else
            {
                h.Ciphers.Add(BinaryPrimitives.ReadUInt16BigEndian(b[at..]));
                // Cipher and compression method.
                at += 3;
            }
            if (at + 2 > b.Length) return h;
            int end = Math.Min(b.Length, at + 2 + BinaryPrimitives.ReadUInt16BigEndian(b[at..]));
            at += 2;
            while (at + 4 <= end)
            {
                ushort type = BinaryPrimitives.ReadUInt16BigEndian(b[at..]);
                int len = BinaryPrimitives.ReadUInt16BigEndian(b[(at + 2)..]);
                if (at + 4 + len > end) break;
                var e = b.Slice(at + 4, len);
                at += 4 + len;
                h.Extensions.Add(type);
                switch (type)
                {
                    case 0 when e.Length >= 5 && e[2] == 0:
                        int nameLength = BinaryPrimitives.ReadUInt16BigEndian(e[3..]);
                        if (5 + nameLength <= e.Length) h.ServerName = CaptureAnalysis.Printable(e.Slice(5, nameLength));
                        break;
                    case 10 when e.Length >= 2:
                        U16List(e[2..Math.Min(e.Length, 2 + BinaryPrimitives.ReadUInt16BigEndian(e))], h.Groups);
                        break;
                    case 11 when e.Length >= 1:
                        foreach (var f in e[1..Math.Min(e.Length, 1 + e[0])]) h.PointFormats.Add(f);
                        break;
                    case 13 when e.Length >= 2:
                        U16List(e[2..Math.Min(e.Length, 2 + BinaryPrimitives.ReadUInt16BigEndian(e))], h.SignatureAlgorithms);
                        break;
                    case 16 when e.Length >= 2:
                        for (int i = 2; i < e.Length;)
                        {
                            int n = e[i];
                            if (n == 0 || i + 1 + n > e.Length) break;
                            h.Alpn.Add(CaptureAnalysis.Printable(e.Slice(i + 1, n)));
                            i += 1 + n;
                        }
                        break;
                    case 43 when h.Client && e.Length >= 1:
                        U16List(e[1..Math.Min(e.Length, 1 + e[0])], h.Versions);
                        break;
                    case 43 when !h.Client && e.Length >= 2:
                        h.Versions.Add(BinaryPrimitives.ReadUInt16BigEndian(e));
                        break;
                }
            }
            return h;
        }
        // A length past the message.
        catch (ArgumentOutOfRangeException) { return null; }
        catch (IndexOutOfRangeException) { return null; }
    }

    private static void U16List(ReadOnlySpan<byte> b, List<ushort> into)
    {
        for (int i = 0; i + 1 < b.Length; i += 2) into.Add(BinaryPrimitives.ReadUInt16BigEndian(b[i..]));
    }

    /// <summary>JA3 (client) or JA3S (server): the MD5 of version, ciphers, extensions (and for a client groups and point formats) as decimal lists, GREASE left out.</summary>
    public string Ja3()
    {
        static string L(IEnumerable<int> v) => string.Join("-", v);
        var text = Client
            ? $"{LegacyVersion},{L(Ciphers.Where(c => !Grease(c)).Select(c => (int)c))},{L(Extensions.Where(e => !Grease(e)).Select(e => (int)e))},{L(Groups.Where(g => !Grease(g)).Select(g => (int)g))},{L(PointFormats.Select(p => (int)p))}"
            : $"{LegacyVersion},{Ciphers[0]},{L(Extensions.Select(e => (int)e))}";
        return Convert.ToHexStringLower(MD5.HashData(Encoding.ASCII.GetBytes(text)));
    }

    /// <summary>The JA4 fingerprint of a ClientHello, or JA4S of a ServerHello.</summary>
    public string Ja4(bool quic = false)
    {
        string proto = quic ? "q" : "t";
        string version = Version switch { 0x0304 => "13", 0x0303 => "12", 0x0302 => "11", 0x0301 => "10", 0x0300 => "s3", 0xFEFF => "d1", 0xFEFD => "d2", 0xFEFC => "d3", _ => "00" };
        var alpn = Alpn.FirstOrDefault() ?? "";
        string a = alpn.Length == 0 ? "00" : alpn.Length == 1 ? $"{alpn}{alpn}" : $"{alpn[0]}{alpn[^1]}";
        if (a.Any(c => c > 0x7F || !char.IsAsciiLetterOrDigit(c))) a = Convert.ToHexStringLower(Encoding.UTF8.GetBytes(alpn))[..1] + Convert.ToHexStringLower(Encoding.UTF8.GetBytes(alpn))[^1..];
        var extensions = Extensions.Where(e => !Grease(e)).ToList();
        if (!Client)
            return $"{proto}{version}{Math.Min(99, extensions.Count):00}{a}_{Ciphers[0]:x4}_{Hash(string.Join(",", extensions.Select(e => e.ToString("x4"))))}";
        var ciphers = Ciphers.Where(c => !Grease(c)).ToList();
        string sni = ServerName != null ? "d" : "i";
        string first = $"{proto}{version}{sni}{Math.Min(99, ciphers.Count):00}{Math.Min(99, extensions.Count):00}{a}";
        string cipherHash = ciphers.Count == 0 ? "000000000000" : Hash(string.Join(",", ciphers.Order().Select(c => c.ToString("x4"))));
        var sorted = extensions.Where(e => e is not (0 or 16)).Order().Select(e => e.ToString("x4"));
        string extText = string.Join(",", sorted);
        if (SignatureAlgorithms.Count > 0) extText += "_" + string.Join(",", SignatureAlgorithms.Select(s => s.ToString("x4")));
        string extHash = extensions.Count == 0 ? "000000000000" : Hash(extText);
        return $"{first}_{cipherHash}_{extHash}";
    }

    internal static string Hash(string text) => Convert.ToHexStringLower(SHA256.HashData(Encoding.ASCII.GetBytes(text)))[..12];
}
