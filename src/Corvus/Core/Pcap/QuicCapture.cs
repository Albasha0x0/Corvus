using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;

namespace Corvus.Core.Pcap;

/// <summary>
/// QUIC connections in a capture (RFC 9000, 9001; version 2 per RFC 9369) and the HTTP/3 they carry (RFC 9114, QPACK per
/// RFC 9204). Initial packets decrypt with keys the client's first destination connection id derives and give the
/// ClientHello (server name, ALPN, client random) and the ServerHello (cipher suite); 0-RTT and 1-RTT packets decrypt with
/// the key log's traffic secrets, following key updates. STREAM frames are joined per stream in any order; HTTP/3 request
/// streams become responses (and uploaded request bodies) as HTTP/1.x and HTTP/2 ones do.
/// </summary>
internal sealed class QuicCapture(TlsKeyLog keys, Action<CapturedResponse> emit, long maxBody)
{
    private const int MaxConnections = 10_000, MaxCrypto = 64 * 1024, MaxStreams = 10_000, MaxFrame = 1 << 20;
    // Out-of-order STREAM bytes waiting for a gap, across all connections.
    private const long MaxPending = 64 << 20;
    private const uint V1 = 1, V2 = 0x6b3343cf;
    private static readonly byte[] SaltV1 = Convert.FromHexString("38762cf7f55934b34d179ae6a4c80cadccbb7f0a");
    private static readonly byte[] SaltV2 = Convert.FromHexString("0dede3def700a6db819381be6e269dcbf9bd2ed9");

    /// <summary>A connection: its server endpoint, the ClientHello's server name and ALPN, version, cipher suite and what decrypted.</summary>
    public sealed record Summary(string Server, string? ServerName, string Version, string Cipher, string? Alpn, string Outcome, long Decrypted);

    /// <summary>A decoded HTTP/3 field section: the connection's index, the stream, the sender and its field lines in order.</summary>
    public sealed record Section(int Connection, long Stream, bool FromClient, IReadOnlyList<(string Name, string Value)> Fields);

    private readonly Dictionary<(bool, UInt128, ushort, UInt128, ushort), Connection> _byTuple = [];
    private readonly List<Connection> _connections = [];
    private long _pending;

    /// <summary>The field sections decoded so far, in capture order.</summary>
    public List<Section> Sections { get; } = [];

    public int Responses { get; private set; }

    public IEnumerable<Summary> Connections => _connections.Select(c => new Summary(c.Server, c.Hello?.ServerName, c.Version == V2 ? "QUIC v2" : "QUIC v1",
        c.ServerHello is { Ciphers: [var s, ..] } ? $"0x{s:x4}" : "unknown", c.Hello?.Alpn.FirstOrDefault(), c.Outcome, c.Decrypted));

    /// <summary>A packet's keys: AEAD key, IV, header protection key, and the secret later generations derive from.</summary>
    private sealed record Keys(byte[] Key, byte[] Iv, byte[] Hp, byte[] Secret, ushort Suite, uint Version);

    private sealed class Direction
    {
        public Keys? Current, Previous, Early;
        public int Phase;
        public long[] Largest = [-1, -1, -1];
        public byte[]? Crypto;
        public List<(int Start, int End)> Have = [];
    }

    private sealed class Connection(int index, bool v6, UInt128 client, ushort clientPort, UInt128 server, ushort serverPort, uint version, byte[] dcid)
    {
        public readonly int Index = index;
        public readonly bool V6 = v6;
        public readonly UInt128 Client = client, ServerAddress = server;
        public readonly ushort ClientPort = clientPort, ServerPort = serverPort;
        public readonly uint Version = version;
        public readonly byte[] OriginalDcid = dcid;
        public readonly Direction FromClient = new(), FromServer = new();
        public int ClientCidLength = -1, ServerCidLength = -1;
        public TlsHello? Hello, ServerHello;
        public bool NoKeys;
        public long Decrypted;
        public readonly Dictionary<(long Id, bool FromClient), StreamBuffer> Streams = [];
        public readonly Http3 H3 = new();
        public string Server => PacketDecoder.Endpoint(V6, ServerAddress, ServerPort);
        public string Outcome => Decrypted > 0 ? "decrypted" : NoKeys ? "no keys for this session" : Hello == null ? "handshake not seen" : "nothing after the handshake decrypted";
    }

    private sealed class StreamBuffer
    {
        public long Delivered;
        public long? Fin;
        public bool Ended, Broken;
        public readonly SortedDictionary<long, byte[]> Pending = [];
    }

    public void Add(DecodedPacket p, ReadOnlySpan<byte> payload)
    {
        if (payload.Length < 5) return;
        var key = (p.V6, p.Src, p.SrcPort, p.Dst, p.DstPort);
        bool fromClient = true;
        if (!_byTuple.TryGetValue(key, out var c) && _byTuple.TryGetValue((p.V6, p.Dst, p.DstPort, p.Src, p.SrcPort), out c)) fromClient = false;
        if (c != null) fromClient = c.Client == p.Src && c.ClientPort == p.SrcPort;
        int at = 0;
        while (at < payload.Length)
        {
            var rest = payload[at..];
            if ((rest[0] & 0x80) == 0)
            {
                if (c != null) Short(c, fromClient, rest);
                return;
            }
            int used = Long(ref c, p, key, ref fromClient, rest);
            if (used <= 0) return;
            at += used;
        }
    }

    // A long-header packet; returns its length so coalesced packets after it are read, or 0 to stop.
    private int Long(ref Connection? c, DecodedPacket p, (bool, UInt128, ushort, UInt128, ushort) key, ref bool fromClient, ReadOnlySpan<byte> b)
    {
        if (b.Length < 7) return 0;
        uint version = BinaryPrimitives.ReadUInt32BigEndian(b[1..]);
        if (version == 0) return 0;
        int at = 5;
        int dcidLength = b[at++];
        if (dcidLength > 20 || at + dcidLength >= b.Length) return 0;
        var dcid = b.Slice(at, dcidLength);
        at += dcidLength;
        int scidLength = b[at++];
        if (scidLength > 20 || at + scidLength > b.Length) return 0;
        at += scidLength;
        if (version is not (V1 or V2)) return 0;
        int raw = (b[0] >> 4) & 3;
        // Version 2 permutes the packet type codes: Initial 1, 0-RTT 2, Handshake 3, Retry 0.
        int type = version == V2 ? (raw + 3) % 4 : raw;
        if (type == 3) return 0;
        if (type == 0)
        {
            if (!Varint(b, ref at, out var tokenLength) || tokenLength > (ulong)(b.Length - at)) return 0;
            at += (int)tokenLength;
        }
        if (!Varint(b, ref at, out var length) || length > (ulong)(b.Length - at)) return 0;
        int end = at + (int)length;
        var packet = b[..end];
        if (c == null)
        {
            if (type != 0 || dcidLength == 0 || _connections.Count >= MaxConnections) return end;
            var keysTry = Initial(version, dcid.ToArray(), true);
            if (Decrypt(packet, at, keysTry, null, false) is null) return end;
            c = new Connection(_connections.Count, p.V6, p.Src, p.SrcPort, p.Dst, p.DstPort, version, dcid.ToArray());
            _connections.Add(c);
            _byTuple[key] = c;
            fromClient = true;
        }
        var d = fromClient ? c.FromClient : c.FromServer;
        if (fromClient) c.ClientCidLength = scidLength; else c.ServerCidLength = scidLength;
        if (type == 0)
        {
            var k = Initial(c.Version, c.OriginalDcid, fromClient);
            if (Decrypt(packet, at, k, d, false) is { } plain) Frames(c, fromClient, plain.Payload, 0);
        }
        else if (type == 1 && fromClient)
        {
            d.Early ??= Traffic(c, "CLIENT_EARLY_TRAFFIC_SECRET");
            if (d.Early != null && Decrypt(packet, at, d.Early, d, false, space: 2) is { } plain)
            {
                c.Decrypted++;
                Frames(c, true, plain.Payload, 2);
            }
        }
        return end;
    }

    private void Short(Connection c, bool fromClient, ReadOnlySpan<byte> b)
    {
        int cid = fromClient ? c.ServerCidLength : c.ClientCidLength;
        if (cid < 0 || b.Length < 1 + cid + 20) return;
        var d = fromClient ? c.FromClient : c.FromServer;
        d.Current ??= Traffic(c, fromClient ? "CLIENT_TRAFFIC_SECRET_0" : "SERVER_TRAFFIC_SECRET_0");
        if (d.Current == null) return;
        int pnOffset = 1 + cid;
        var unprotected = Unprotect(b, pnOffset, d.Current, true, d.Largest[1], out long pn, out int pnLength, out byte first);
        if (unprotected == null) return;
        int phase = (first >> 2) & 1;
        byte[]? plain = null;
        if (phase == d.Phase) plain = Open(unprotected, pnOffset + pnLength, pn, d.Current);
        else
        {
            var next = Next(d.Current);
            plain = Open(unprotected, pnOffset + pnLength, pn, next);
            // aiortc/aioquic#745: aioquic 1.2.0 to 1.3.0 derive version 2 key updates with "quic ku"; no fix released.
            if (plain == null && d.Current.Version == V2) plain = Open(unprotected, pnOffset + pnLength, pn, next = Next(d.Current, "quic ku"));
            if (plain != null)
            {
                d.Previous = d.Current;
                d.Current = next;
                d.Phase = phase;
            }
            else if (d.Previous != null) plain = Open(unprotected, pnOffset + pnLength, pn, d.Previous);
        }
        if (plain == null) return;
        d.Largest[1] = Math.Max(d.Largest[1], pn);
        c.Decrypted++;
        Frames(c, fromClient, plain, 1);
    }

    private Keys? Traffic(Connection c, string label)
    {
        if (c.Hello == null) return null;
        var secret = keys.Find(c.Hello.Random, label);
        if (secret == null) { c.NoKeys = true; return null; }
        // 0-RTT keys use the resumed session's suite, which the ClientHello does not name; the 1-RTT suite is assumed.
        ushort suite = c.ServerHello is { Ciphers: [var s, ..] } ? s : (ushort)0x1301;
        return FromSecret(secret, suite, c.Version);
    }

    /// <summary>The payload of a client Initial protected with the keys <paramref name="dcid"/> derives; null when it does not authenticate.</summary>
    internal static byte[]? InitialPayload(uint version, byte[] dcid, ReadOnlySpan<byte> packet, int pnOffset) =>
        Decrypt(packet, pnOffset, Initial(version, dcid, true), null, false)?.Payload;

    private static Keys Initial(uint version, byte[] dcid, bool client)
    {
        var initial = HKDF.Extract(HashAlgorithmName.SHA256, dcid, version == V2 ? SaltV2 : SaltV1);
        var secret = ExpandLabel(HashAlgorithmName.SHA256, initial, client ? "client in" : "server in", 32);
        return FromSecret(secret, 0x1301, version);
    }

    private static Keys FromSecret(byte[] secret, ushort suite, uint version)
    {
        var hash = suite == 0x1302 ? HashAlgorithmName.SHA384 : HashAlgorithmName.SHA256;
        int keyLength = suite == 0x1301 ? 16 : 32;
        string prefix = version == V2 ? "quicv2 " : "quic ";
        return new Keys(ExpandLabel(hash, secret, prefix + "key", keyLength), ExpandLabel(hash, secret, prefix + "iv", 12),
            ExpandLabel(hash, secret, prefix + "hp", keyLength), secret, suite, version);
    }

    // The next key generation after a key update: a new secret, key and IV; header protection keeps its key.
    private static Keys Next(Keys k, string? label = null)
    {
        var hash = k.Suite == 0x1302 ? HashAlgorithmName.SHA384 : HashAlgorithmName.SHA256;
        var secret = ExpandLabel(hash, k.Secret, label ?? (k.Version == V2 ? "quicv2 ku" : "quic ku"), k.Secret.Length);
        var next = FromSecret(secret, k.Suite, k.Version);
        return next with { Hp = k.Hp };
    }

    /// <summary>TLS 1.3 HKDF-Expand-Label with an empty context.</summary>
    private static byte[] ExpandLabel(HashAlgorithmName hash, byte[] secret, string label, int length)
    {
        var full = Encoding.ASCII.GetBytes("tls13 " + label);
        byte[] info = [(byte)(length >> 8), (byte)length, (byte)full.Length, .. full, 0];
        return HKDF.Expand(hash, secret, length, info);
    }

    private sealed record Plain(byte[] Payload);

    private static Plain? Decrypt(ReadOnlySpan<byte> packet, int pnOffset, Keys k, Direction? d, bool shortHeader, int space = 0)
    {
        long largest = d?.Largest[space] ?? -1;
        var header = Unprotect(packet, pnOffset, k, shortHeader, largest, out long pn, out int pnLength, out _);
        if (header == null || Open(header, pnOffset + pnLength, pn, k) is not { } plain) return null;
        if (d != null) d.Largest[space] = Math.Max(d.Largest[space], pn);
        return new Plain(plain);
    }

    // The packet with header protection removed, its full packet number and the number's length; null when too short.
    private static byte[]? Unprotect(ReadOnlySpan<byte> packet, int pnOffset, Keys k, bool shortHeader, long largest, out long pn, out int pnLength, out byte first)
    {
        pn = 0;
        pnLength = 0;
        first = 0;
        if (pnOffset + 4 + 16 > packet.Length) return null;
        var mask = Mask(k, packet.Slice(pnOffset + 4, 16));
        var copy = packet.ToArray();
        copy[0] ^= (byte)(mask[0] & (shortHeader ? 0x1F : 0x0F));
        first = copy[0];
        pnLength = (copy[0] & 3) + 1;
        long truncated = 0;
        for (int i = 0; i < pnLength; i++)
        {
            copy[pnOffset + i] ^= mask[1 + i];
            truncated = truncated << 8 | copy[pnOffset + i];
        }
        pn = Expand(largest, truncated, pnLength * 8);
        return copy;
    }

    // RFC 9000 Appendix A.3: the packet number closest to the next one expected.
    private static long Expand(long largest, long truncated, int bits)
    {
        long expected = largest + 1, window = 1L << bits, half = window / 2, mask = window - 1;
        long candidate = (expected & ~mask) | truncated;
        if (candidate <= expected - half && candidate < (1L << 62) - window) return candidate + window;
        if (candidate > expected + half && candidate >= window) return candidate - window;
        return candidate;
    }

    private static byte[] Mask(Keys k, ReadOnlySpan<byte> sample)
    {
        if (k.Suite == 0x1303) return ChaCha20Block(k.Hp, BinaryPrimitives.ReadUInt32LittleEndian(sample), sample[4..16]);
        using var aes = Aes.Create();
        aes.Key = k.Hp;
        return aes.EncryptEcb(sample, PaddingMode.None);
    }

    private static byte[]? Open(byte[] packet, int headerLength, long pn, Keys k)
    {
        var sealedPart = packet.AsSpan(headerLength);
        if (sealedPart.Length < 16) return null;
        var nonce = (byte[])k.Iv.Clone();
        for (int i = 0; i < 8; i++) nonce[11 - i] ^= (byte)(pn >> (8 * i));
        var plain = new byte[sealedPart.Length - 16];
        try
        {
            if (k.Suite == 0x1303)
            {
                if (!ChaCha20Poly1305.IsSupported) return null;
                using var chacha = new ChaCha20Poly1305(k.Key);
                chacha.Decrypt(nonce, sealedPart[..^16], sealedPart[^16..], plain, packet.AsSpan(0, headerLength));
            }
            else
            {
                using var gcm = new AesGcm(k.Key, 16);
                gcm.Decrypt(nonce, sealedPart[..^16], sealedPart[^16..], plain, packet.AsSpan(0, headerLength));
            }
        }
        catch (CryptographicException) { return null; }
        return plain;
    }

    // RFC 8439 section 2.3: one 64-byte ChaCha20 block; header protection uses its first five bytes.
    private static byte[] ChaCha20Block(byte[] key, uint counter, ReadOnlySpan<byte> nonce)
    {
        Span<uint> s = stackalloc uint[16];
        s[0] = 0x61707865; s[1] = 0x3320646e; s[2] = 0x79622d32; s[3] = 0x6b206574;
        for (int i = 0; i < 8; i++) s[4 + i] = BinaryPrimitives.ReadUInt32LittleEndian(key.AsSpan(i * 4));
        s[12] = counter;
        for (int i = 0; i < 3; i++) s[13 + i] = BinaryPrimitives.ReadUInt32LittleEndian(nonce[(i * 4)..]);
        Span<uint> x = stackalloc uint[16];
        s.CopyTo(x);
        for (int round = 0; round < 10; round++)
        {
            Quarter(x, 0, 4, 8, 12); Quarter(x, 1, 5, 9, 13); Quarter(x, 2, 6, 10, 14); Quarter(x, 3, 7, 11, 15);
            Quarter(x, 0, 5, 10, 15); Quarter(x, 1, 6, 11, 12); Quarter(x, 2, 7, 8, 13); Quarter(x, 3, 4, 9, 14);
        }
        var output = new byte[64];
        for (int i = 0; i < 16; i++) BinaryPrimitives.WriteUInt32LittleEndian(output.AsSpan(i * 4), x[i] + s[i]);
        return output;
    }

    private static void Quarter(Span<uint> x, int a, int b, int c, int d)
    {
        x[a] += x[b]; x[d] = uint.RotateLeft(x[d] ^ x[a], 16);
        x[c] += x[d]; x[b] = uint.RotateLeft(x[b] ^ x[c], 12);
        x[a] += x[b]; x[d] = uint.RotateLeft(x[d] ^ x[a], 8);
        x[c] += x[d]; x[b] = uint.RotateLeft(x[b] ^ x[c], 7);
    }

    // The frames of a decrypted packet; an unknown frame type ends the packet, since its length is not known.
    private void Frames(Connection c, bool fromClient, ReadOnlySpan<byte> b, int space)
    {
        int at = 0;
        while (at < b.Length)
        {
            if (!Varint(b, ref at, out var type)) return;
            switch (type)
            {
                case 0x00 or 0x01 or 0x1E: break;
                case 0x02 or 0x03:
                {
                    if (!Varint(b, ref at, out _) || !Varint(b, ref at, out _) || !Varint(b, ref at, out var ranges) || !Varint(b, ref at, out _) || ranges > 10_000) return;
                    for (ulong i = 0; i < ranges * 2 + (type == 3 ? 3UL : 0); i++) if (!Varint(b, ref at, out _)) return;
                    break;
                }
                case 0x04: if (!Skip(b, ref at, 3)) return; break;
                case 0x05: if (!Skip(b, ref at, 2)) return; break;
                case 0x06:
                {
                    if (!Varint(b, ref at, out var offset) || !Varint(b, ref at, out var length) || length > (ulong)(b.Length - at)) return;
                    if (space == 0) Crypto(c, fromClient, (long)offset, b.Slice(at, (int)length));
                    at += (int)length;
                    break;
                }
                case 0x07:
                {
                    if (!Varint(b, ref at, out var length) || length > (ulong)(b.Length - at)) return;
                    at += (int)length;
                    break;
                }
                case >= 0x08 and <= 0x0F:
                {
                    if (!Varint(b, ref at, out var id)) return;
                    ulong offset = 0, length;
                    if ((type & 0x04) != 0 && !Varint(b, ref at, out offset)) return;
                    if ((type & 0x02) != 0) { if (!Varint(b, ref at, out length) || length > (ulong)(b.Length - at)) return; }
                    else length = (ulong)(b.Length - at);
                    if (offset > 1UL << 50) return;
                    Stream(c, (long)id, fromClient, (long)offset, b.Slice(at, (int)length), (type & 0x01) != 0);
                    at += (int)length;
                    break;
                }
                case 0x10 or 0x12 or 0x13 or 0x14 or 0x16 or 0x17 or 0x19: if (!Skip(b, ref at, 1)) return; break;
                case 0x11 or 0x15: if (!Skip(b, ref at, 2)) return; break;
                case 0x18:
                {
                    if (!Skip(b, ref at, 2) || at >= b.Length) return;
                    int cidLength = b[at];
                    at += 1 + cidLength + 16;
                    if (at > b.Length) return;
                    break;
                }
                case 0x1A or 0x1B: at += 8; if (at > b.Length) return; break;
                case 0x1C or 0x1D:
                {
                    if (!Varint(b, ref at, out _) || (type == 0x1C && !Varint(b, ref at, out _)) || !Varint(b, ref at, out var reason) || reason > (ulong)(b.Length - at)) return;
                    at += (int)reason;
                    break;
                }
                case 0x30: return;
                case 0x31:
                {
                    if (!Varint(b, ref at, out var length) || length > (ulong)(b.Length - at)) return;
                    at += (int)length;
                    break;
                }
                default: return;
            }
        }
    }

    private static bool Skip(ReadOnlySpan<byte> b, ref int at, int varints)
    {
        for (int i = 0; i < varints; i++) if (!Varint(b, ref at, out _)) return false;
        return true;
    }

    // Initial CRYPTO data: the ClientHello from the client and the ServerHello from the server, once whole.
    private static void Crypto(Connection c, bool fromClient, long offset, ReadOnlySpan<byte> data)
    {
        var d = fromClient ? c.FromClient : c.FromServer;
        if ((fromClient ? c.Hello : c.ServerHello) != null || offset >= MaxCrypto || d.Have.Count >= 4096) return;
        int take = (int)Math.Min(data.Length, MaxCrypto - offset);
        d.Crypto ??= new byte[MaxCrypto];
        data[..take].CopyTo(d.Crypto.AsSpan((int)offset));
        d.Have.Add(((int)offset, (int)offset + take));
        d.Have.Sort();
        int contiguous = 0;
        foreach (var (start, end) in d.Have)
        {
            if (start > contiguous) break;
            contiguous = Math.Max(contiguous, end);
        }
        if (contiguous < 4) return;
        int need = 4 + (d.Crypto[1] << 16 | d.Crypto[2] << 8 | d.Crypto[3]);
        if (need > contiguous) return;
        var hello = TlsHello.Parse(d.Crypto.AsSpan(0, need));
        if (hello == null || hello.Client != fromClient) return;
        if (fromClient) c.Hello = hello; else c.ServerHello = hello;
        d.Crypto = null;
        d.Have = [];
    }

    // STREAM data placed at its offset; in-order bytes go to HTTP/3, out-of-order ones wait within a capture-wide bound.
    private void Stream(Connection c, long id, bool fromClient, long offset, ReadOnlySpan<byte> data, bool fin)
    {
        if (!c.Streams.TryGetValue((id, fromClient), out var s))
        {
            if (c.Streams.Count >= MaxStreams) return;
            c.Streams[(id, fromClient)] = s = new StreamBuffer();
        }
        if (s.Ended || s.Broken) return;
        if (fin) s.Fin = offset + data.Length;
        long end = offset + data.Length;
        if (end > s.Delivered)
        {
            if (offset <= s.Delivered)
            {
                Deliver(c, id, fromClient, data[(int)(s.Delivered - offset)..]);
                s.Delivered = end;
                while (s.Pending.Count > 0 && s.Pending.First() is var (o, chunk) && o <= s.Delivered)
                {
                    s.Pending.Remove(o);
                    _pending -= chunk.Length;
                    if (o + chunk.Length > s.Delivered)
                    {
                        Deliver(c, id, fromClient, chunk.AsSpan((int)(s.Delivered - o)));
                        s.Delivered = o + chunk.Length;
                    }
                }
            }
            else if (_pending + data.Length > MaxPending) s.Broken = true;
            else if (!s.Pending.TryGetValue(offset, out var have) || have.Length < data.Length)
            {
                if (have != null) _pending -= have.Length;
                s.Pending[offset] = data.ToArray();
                _pending += data.Length;
            }
        }
        if (s.Fin is long f && s.Delivered >= f && !s.Ended)
        {
            s.Ended = true;
            c.H3.End(this, c, id, fromClient);
        }
    }

    private void Deliver(Connection c, long id, bool fromClient, ReadOnlySpan<byte> data)
    {
        if (data.Length > 0) c.H3.Data(this, c, id, fromClient, data);
    }

    public void Finish()
    {
        foreach (var c in _connections) c.H3.Finish(this, c);
    }

    private void Emit(CapturedResponse r)
    {
        Responses++;
        emit(r);
    }

    /// <summary>HTTP/3 over a connection's streams: control and QPACK streams per sender, request streams per exchange.</summary>
    private sealed class Http3
    {
        private readonly Qpack _clientTable = new(), _serverTable = new();
        private readonly Dictionary<(long, bool), Reader> _readers = [];
        private readonly Dictionary<long, Exchange> _exchanges = [];
        private readonly List<(long Stream, bool FromClient, byte[] Section)> _blocked = [];

        private sealed class Reader
        {
            public long UniType = -1;
            public readonly MemoryStream Buffer = new();
            public long DataLeft;
            public bool Broken;
        }

        private sealed class Exchange : HttpExchange
        {
            public MemoryStream? Request, Response;
            public bool RequestCut, ResponseCut, ServerEnded, Done;
            public int Blocked;
        }

        private Qpack Table(bool fromClient) => fromClient ? _clientTable : _serverTable;

        public void Data(QuicCapture q, Connection c, long id, bool fromClient, ReadOnlySpan<byte> data)
        {
            if (!_readers.TryGetValue((id, fromClient), out var r)) _readers[(id, fromClient)] = r = new Reader();
            if (r.Broken) return;
            bool uni = (id & 2) != 0;
            if (uni && r.UniType == 2) { Encoder(q, c, fromClient, data); return; }
            if (uni && r.UniType is not (-1 or 0)) return;
            if (r.Buffer.Length + data.Length > MaxFrame + 64 && r.DataLeft == 0) { r.Broken = true; return; }
            r.Buffer.Write(data);
            Frames(q, c, id, fromClient, r);
        }

        private void Encoder(QuicCapture q, Connection c, bool fromClient, ReadOnlySpan<byte> data)
        {
            Table(fromClient).Encoder(data);
            // Sections that waited on these inserts decode in arrival order.
            for (int i = 0; i < _blocked.Count;)
            {
                var (stream, side, section) = _blocked[i];
                if (side == fromClient && Table(side).Required(section) is long need && need <= Table(side).Inserts)
                {
                    _blocked.RemoveAt(i);
                    if (_exchanges.TryGetValue(stream, out var x)) x.Blocked--;
                    Headers(q, c, stream, side, section);
                }
                else i++;
            }
        }

        private void Frames(QuicCapture q, Connection c, long id, bool fromClient, Reader r)
        {
            var all = r.Buffer.GetBuffer().AsSpan(0, (int)r.Buffer.Length);
            int at = 0;
            if ((id & 2) != 0 && r.UniType == -1)
            {
                if (!Varint(all, ref at, out var type)) return;
                r.UniType = (long)Math.Min(type, long.MaxValue);
                if (r.UniType == 2) { Encoder(q, c, fromClient, all[at..]); r.Buffer.SetLength(0); return; }
                if (r.UniType != 0) { r.Buffer.SetLength(0); return; }
            }
            while (at < all.Length)
            {
                if (r.DataLeft > 0)
                {
                    int take = (int)Math.Min(r.DataLeft, all.Length - at);
                    Body(q, id, fromClient, all.Slice(at, take));
                    r.DataLeft -= take;
                    at += take;
                    continue;
                }
                int start = at;
                if (!Varint(all, ref at, out var type) || !Varint(all, ref at, out var length)) { at = start; break; }
                if (type == 0)
                {
                    r.DataLeft = (long)Math.Min(length, long.MaxValue);
                    continue;
                }
                if (length > MaxFrame) { r.Broken = true; return; }
                if ((ulong)(all.Length - at) < length) { at = start; break; }
                var payload = all.Slice(at, (int)length);
                at += (int)length;
                if (type == 1 && (id & 2) == 0)
                {
                    var section = payload.ToArray();
                    var table = Table(fromClient);
                    if (table.Required(section) is long need && need > table.Inserts && table.Healthy)
                    {
                        _blocked.Add((id, fromClient, section));
                        For(id).Blocked++;
                    }
                    else Headers(q, c, id, fromClient, section);
                }
                else if (type == 4 && r.UniType == 0) Settings(fromClient, payload);
            }
            var rest = all[at..].ToArray();
            r.Buffer.SetLength(0);
            r.Buffer.Write(rest);
        }

        // SETTINGS_QPACK_MAX_TABLE_CAPACITY (0x01) bounds the table the other side's encoder builds.
        private void Settings(bool fromClient, ReadOnlySpan<byte> payload)
        {
            int at = 0;
            while (at < payload.Length)
            {
                if (!Varint(payload, ref at, out var id) || !Varint(payload, ref at, out var value)) return;
                if (id == 1) Table(!fromClient).MaxCapacity = (long)Math.Min(value, 1UL << 30);
            }
        }

        private Exchange For(long id)
        {
            if (!_exchanges.TryGetValue(id, out var x)) _exchanges[id] = x = new Exchange();
            return x;
        }

        private void Headers(QuicCapture q, Connection c, long id, bool fromClient, byte[] section)
        {
            var fields = Table(fromClient).Decode(section);
            if (fields == null) return;
            q.Sections.Add(new Section(c.Index, id, fromClient, fields));
            if (_exchanges.Count >= MaxStreams && !_exchanges.ContainsKey(id)) return;
            var x = For(id);
            x.Take(fields, fromClient);
            if (!fromClient && x.Status >= 200) x.Response ??= new MemoryStream();
            if (x.ServerEnded && x.Blocked == 0) Complete(q, c, id, x, false);
        }

        private void Body(QuicCapture q, long id, bool fromClient, ReadOnlySpan<byte> data)
        {
            var x = For(id);
            if (fromClient)
            {
                x.Request ??= new MemoryStream();
                if (x.Request.Length + data.Length > q.MaxBody) x.RequestCut = true; else x.Request.Write(data);
            }
            else
            {
                x.Response ??= new MemoryStream();
                if (x.Response.Length + data.Length > q.MaxBody) x.ResponseCut = true; else x.Response.Write(data);
            }
        }

        public void End(QuicCapture q, Connection c, long id, bool fromClient)
        {
            if ((id & 2) != 0 || fromClient || !_exchanges.TryGetValue(id, out var x)) return;
            x.ServerEnded = true;
            if (x.Blocked == 0) Complete(q, c, id, x, false);
        }

        public void Finish(QuicCapture q, Connection c)
        {
            foreach (var (id, x) in _exchanges.ToList())
                if (!x.Done && (x.Response != null || x.Status > 0)) Complete(q, c, id, x, true);
        }

        private void Complete(QuicCapture q, Connection c, long id, Exchange x, bool cut)
        {
            if (x.Done) return;
            x.Done = true;
            string authority = x.Authority.Length > 0 ? x.Authority : c.Hello?.ServerName ?? c.Server;
            string url = $"{(x.Scheme.Length > 0 ? x.Scheme : "https")}://{authority}{x.Path}";
            if (x.Request is { Length: > 0 } || x.RequestCut)
                q.Emit(new CapturedResponse(x.Method, url, 0, null, null, x.RequestCut ? null : x.Request!.ToArray(),
                    x.RequestCut ? $"body over {q.MaxBody:N0} bytes, not kept" : null) { Request = true });
            q.Emit(new CapturedResponse(x.Method, url, x.Status, x.Mime, x.Encoding, x.ResponseCut ? null : x.Response?.ToArray(),
                x.ResponseCut ? $"body over {q.MaxBody:N0} bytes, not kept" : cut ? "the connection ended before the stream did" : null));
        }
    }

    private long MaxBody => maxBody;

    /// <summary>A QUIC variable-length integer (RFC 9000 section 16) at <paramref name="at"/>; false when the bytes end first.</summary>
    internal static bool Varint(ReadOnlySpan<byte> b, ref int at, out ulong value)
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
