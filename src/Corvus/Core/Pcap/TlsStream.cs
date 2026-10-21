using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;

namespace Corvus.Core.Pcap;

/// <summary>
/// One TLS connection's records: the ClientHello and ServerHello read (version, cipher suite, randoms, fingerprints) and,
/// when the key log holds the session's secrets, the records decrypted: TLS 1.3 (AES-GCM, ChaCha20-Poly1305; handshake
/// then application traffic secrets, key updates followed) and TLS 1.2 AEAD suites (AES-GCM, ChaCha20-Poly1305) from the
/// master secret. Application data goes on to <paramref name="inner"/>, created with the ALPN protocol once known.
/// </summary>
internal sealed class TlsStream(TlsKeyLog? keys, Func<string?, ITcpConsumer> inner) : ITcpConsumer
{
    private const int MaxRecord = (1 << 14) + 2048 + 5;
    private const int MaxHandshake = 1 << 20;

    public TlsHello? ClientHello { get; private set; }
    public TlsHello? ServerHello { get; private set; }
    public ushort Version => ServerHello?.Version ?? 0;
    public ushort Cipher => ServerHello is { Ciphers: [var c, ..] } ? c : (ushort)0;
    public string? Alpn { get; private set; }

    /// <summary>decrypted, no keys, unsupported cipher suite 0x..., or not decrypted: why.</summary>
    public string? Outcome { get; private set; }
    public long Decrypted { get; private set; }

    private ITcpConsumer? _inner;

    private sealed class Side(bool client)
    {
        public readonly bool Client = client;
        public readonly MemoryStream Buffer = new(), Handshake = new();
        public bool Encrypted, Broken;
        /// <summary>The client sends 0-RTT data under its early traffic secret until EndOfEarlyData, or until the server rejects it.</summary>
        public bool Early;
        public RecordCipher? Cipher;
        public ulong Seq;
        public byte[]? Secret;
    }

    private readonly Side _client = new(true), _server = new(false);

    public void Data(bool fromClient, ReadOnlySpan<byte> data)
    {
        var s = fromClient ? _client : _server;
        if (s.Broken) return;
        s.Buffer.Write(data);
        var all = s.Buffer.GetBuffer().AsSpan(0, (int)s.Buffer.Length);
        int at = 0;
        while (all.Length - at >= 5)
        {
            var r = all[at..];
            int length = BinaryPrimitives.ReadUInt16BigEndian(r[3..]);
            if (r[0] is < 20 or > 24 || r[1] != 3 || 5 + length > MaxRecord) { s.Broken = true; return; }
            if (r.Length < 5 + length) break;
            Record(s, r[..5], r.Slice(5, length));
            at += 5 + length;
            if (s.Broken) return;
        }
        var rest = all[at..].ToArray();
        s.Buffer.SetLength(0);
        s.Buffer.Write(rest);
    }

    private void Record(Side s, ReadOnlySpan<byte> header, ReadOnlySpan<byte> body)
    {
        byte type = header[0];
        if (type == 20) // change cipher spec: TLS 1.2 encrypts from the next record on; TLS 1.3 sends it for compatibility only
        {
            if (Version is > 0 and < 0x0304) { s.Encrypted = true; s.Seq = 0; s.Cipher = Keys12(s.Client); }
            return;
        }
        if (!s.Encrypted)
        {
            if (type == 22) Handshake(s, body, plain: true);
            return;
        }
        if (s.Cipher == null && s.Early) s.Cipher = EarlyCipher(s, header, body);
        if (s.Cipher == null) return;
        var plain = s.Cipher.Open(s.Seq, header, body);
        if (plain == null && s.Early && ServerHello != null)
        {
            // a server that rejects early data skips it, and the client goes on under its handshake secret
            s.Early = false;
            Switch(s, "CLIENT_HANDSHAKE_TRAFFIC_SECRET");
            plain = s.Cipher?.Open(s.Seq, header, body);
        }
        if (plain == null || s.Cipher == null)
        {
            Outcome = "records did not authenticate with the logged keys";
            s.Broken = true;
            return;
        }
        s.Seq++;
        byte content = type;
        int end = plain.Length;
        if (s.Cipher.Tls13)
        {
            while (end > 0 && plain[end - 1] == 0) end--;
            if (end == 0) return;
            content = plain[--end];
        }
        Outcome = "decrypted";
        var payload = plain.AsSpan(0, end);
        if (content == 23)
        {
            Decrypted += payload.Length;
            _inner ??= inner(Alpn);
            _inner.Data(s.Client, payload);
        }
        else if (content == 22 && s.Cipher.Tls13) Handshake(s, payload, plain: false);
    }

    /// <summary>Handshake messages, joined over records: hellos in plaintext; EncryptedExtensions, Finished and KeyUpdate decrypted.</summary>
    private void Handshake(Side s, ReadOnlySpan<byte> data, bool plain)
    {
        if (s.Handshake.Length + data.Length > MaxHandshake) { s.Handshake.SetLength(0); return; }
        s.Handshake.Write(data);
        var all = s.Handshake.GetBuffer().AsSpan(0, (int)s.Handshake.Length);
        int at = 0;
        while (all.Length - at >= 4)
        {
            var m = all[at..];
            int length = m[1] << 16 | m[2] << 8 | m[3];
            if (m.Length < 4 + length) break;
            Message(s, m[..(4 + length)], plain);
            at += 4 + length;
        }
        var rest = all[at..].ToArray();
        s.Handshake.SetLength(0);
        s.Handshake.Write(rest);
    }

    private static readonly byte[] RetryRandom = Convert.FromHexString("CF21AD74E59A6111BE1D8C021E65B891C2A211167ABB8C5E079E09E2C8A8339C");

    private void Message(Side s, ReadOnlySpan<byte> m, bool plain)
    {
        switch (m[0])
        {
            case 1 when plain && s.Client:
                ClientHello ??= TlsHello.Parse(m);
                if (ClientHello is { } hello1 && hello1.Extensions.Contains(42) && keys?.Find(hello1.Random, "CLIENT_EARLY_TRAFFIC_SECRET") is { } early)
                    (s.Encrypted, s.Early, s.Secret) = (true, true, early);
                break;
            case 2 when plain && !s.Client:
                if (TlsHello.Parse(m) is not { } hello || hello.Random.AsSpan().SequenceEqual(RetryRandom)) break;
                ServerHello = hello;
                Alpn = hello.Alpn.FirstOrDefault();
                if (Version == 0x0304) Start13();
                else if (keys is not { Sessions: > 0 }) Outcome = "no key log";
                else if (ClientHello == null || keys.Find(ClientHello.Random, "CLIENT_RANDOM") == null) Outcome = "no keys for this session in the key log";
                else if (Suite12(Cipher) == null) Outcome = $"cipher suite 0x{Cipher:x4} is not decrypted (AEAD suites are)";
                break;
            case 8 when !plain: // EncryptedExtensions: TLS 1.3's ALPN
                if (m.Length >= 6) Alpn ??= Extensions(m[6..Math.Min(m.Length, 6 + BinaryPrimitives.ReadUInt16BigEndian(m[4..]))]);
                break;
            case 5 when !plain && s.Early: // EndOfEarlyData
                s.Early = false;
                Switch(s, "CLIENT_HANDSHAKE_TRAFFIC_SECRET");
                break;
            case 20 when !plain: // Finished: application traffic keys from the next record
                Switch(s, s.Client ? "CLIENT_TRAFFIC_SECRET_0" : "SERVER_TRAFFIC_SECRET_0");
                break;
            case 24 when !plain && s.Secret != null: // KeyUpdate
            {
                var suite = Suite13(Cipher)!.Value;
                s.Secret = ExpandLabel(suite.Hash, s.Secret, "traffic upd", suite.Hash == HashAlgorithmName.SHA384 ? 48 : 32);
                s.Cipher = Cipher13(s.Secret, suite);
                s.Seq = 0;
                break;
            }
        }
    }

    private static string? Extensions(ReadOnlySpan<byte> e)
    {
        for (int at = 0; at + 4 <= e.Length;)
        {
            int type = BinaryPrimitives.ReadUInt16BigEndian(e[at..]), len = BinaryPrimitives.ReadUInt16BigEndian(e[(at + 2)..]);
            if (at + 4 + len > e.Length) return null;
            if (type == 16 && len >= 3 && e[at + 6] > 0 && 7 + e[at + 6] <= 4 + len) return Encoding.ASCII.GetString(e.Slice(at + 7, e[at + 6]));
            at += 4 + len;
        }
        return null;
    }

    private void Start13()
    {
        _client.Encrypted = _server.Encrypted = true;
        if (Suite13(Cipher) == null) { Outcome = $"cipher suite 0x{Cipher:x4} is not decrypted"; return; }
        if (keys is not { Sessions: > 0 }) { Outcome = "no key log"; return; }
        if (ClientHello == null || keys.Find(ClientHello.Random, "SERVER_HANDSHAKE_TRAFFIC_SECRET") == null) { Outcome = "no keys for this session in the key log"; return; }
        if (!_client.Early) Switch(_client, "CLIENT_HANDSHAKE_TRAFFIC_SECRET");
        Switch(_server, "SERVER_HANDSHAKE_TRAFFIC_SECRET");
    }

    private void Switch(Side s, string label)
    {
        if (keys == null || ClientHello == null || Suite13(Cipher) is not { } suite) return;
        s.Secret = keys.Find(ClientHello.Random, label);
        s.Cipher = s.Secret != null ? Cipher13(s.Secret, suite) : null;
        s.Seq = 0;
        if (s.Secret == null) Outcome = $"the key log has no {label}";
    }

    /// <summary>The early data's cipher: the resumed session's suite is named only in the ServerHello, so each offered TLS 1.3 suite is tried on the first record.</summary>
    private RecordCipher? EarlyCipher(Side s, ReadOnlySpan<byte> header, ReadOnlySpan<byte> body)
    {
        foreach (var c in ClientHello?.Ciphers ?? [])
            if (Suite13(c) is { } suite && Cipher13(s.Secret!, suite) is var cipher && cipher.Open(0, header, body) != null)
                return cipher;
        return null;
    }

    private static RecordCipher Cipher13(byte[] secret, (bool Gcm, int Key, HashAlgorithmName Hash) suite) =>
        new(true, suite.Gcm, ExpandLabel(suite.Hash, secret, "key", suite.Key), ExpandLabel(suite.Hash, secret, "iv", 12));

    private static (bool Gcm, int Key, HashAlgorithmName Hash)? Suite13(ushort cipher) => cipher switch
    {
        0x1301 => (true, 16, HashAlgorithmName.SHA256),
        0x1302 => (true, 32, HashAlgorithmName.SHA384),
        0x1303 => (false, 32, HashAlgorithmName.SHA256),
        _ => null,
    };

    /// <summary>TLS 1.2 AEAD suites: AES-GCM (RSA, DHE, ECDHE) and ChaCha20-Poly1305.</summary>
    private static (bool Gcm, int Key, HashAlgorithmName Hash)? Suite12(ushort cipher) => cipher switch
    {
        0x009C or 0x009E or 0xC02B or 0xC02F or 0x00A0 or 0x00A4 or 0x00A8 or 0x00AA or 0x00AC or 0xC02D or 0xC031 => (true, 16, HashAlgorithmName.SHA256),
        0x009D or 0x009F or 0xC02C or 0xC030 or 0x00A1 or 0x00A5 or 0x00A9 or 0x00AB or 0x00AD or 0xC02E or 0xC032 => (true, 32, HashAlgorithmName.SHA384),
        0xCCA8 or 0xCCA9 or 0xCCAA or 0xCCAB or 0xCCAC or 0xCCAD or 0xCCAE => (false, 32, HashAlgorithmName.SHA256),
        _ => null,
    };

    /// <summary>A TLS 1.2 side's cipher from the master secret: key_block = PRF(master, "key expansion", server_random + client_random).</summary>
    private RecordCipher? Keys12(bool client)
    {
        if (keys == null || ClientHello == null || ServerHello == null || Suite12(Cipher) is not { } suite) return null;
        if (keys.Find(ClientHello.Random, "CLIENT_RANDOM") is not { } master) return null;
        int ivLength = suite.Gcm ? 4 : 12;
        var block = Prf(suite.Hash, master, "key expansion", [.. ServerHello.Random, .. ClientHello.Random], 2 * suite.Key + 2 * ivLength);
        var key = block.AsSpan(client ? 0 : suite.Key, suite.Key).ToArray();
        var iv = block.AsSpan(2 * suite.Key + (client ? 0 : ivLength), ivLength).ToArray();
        return new RecordCipher(false, suite.Gcm, key, iv);
    }

    /// <summary>The TLS 1.2 PRF: P_hash(secret, label + seed).</summary>
    internal static byte[] Prf(HashAlgorithmName hash, byte[] secret, string label, byte[] seed, int length)
    {
        byte[] full = [.. Encoding.ASCII.GetBytes(label), .. seed];
        var output = new byte[length];
        byte[] a = full;
        for (int at = 0; at < length;)
        {
            a = HMac(hash, secret, a);
            var chunk = HMac(hash, secret, [.. a, .. full]);
            int n = Math.Min(chunk.Length, length - at);
            chunk.AsSpan(0, n).CopyTo(output.AsSpan(at));
            at += n;
        }
        return output;
    }

    private static byte[] HMac(HashAlgorithmName hash, byte[] key, byte[] data) =>
        hash == HashAlgorithmName.SHA384 ? HMACSHA384.HashData(key, data) : HMACSHA256.HashData(key, data);

    /// <summary>TLS 1.3 HKDF-Expand-Label with an empty context.</summary>
    internal static byte[] ExpandLabel(HashAlgorithmName hash, byte[] secret, string label, int length)
    {
        var full = Encoding.ASCII.GetBytes("tls13 " + label);
        byte[] info = [(byte)(length >> 8), (byte)length, (byte)full.Length, .. full, 0];
        return HKDF.Expand(hash, secret, length, info);
    }

    public void Gap(bool fromClient, long bytes) => (fromClient ? _client : _server).Broken = true;

    public void End() => _inner?.End();

    /// <summary>An AEAD record protection: TLS 1.3 (nonce = iv xor sequence, header as additional data) or TLS 1.2.</summary>
    internal sealed class RecordCipher(bool tls13, bool gcm, byte[] key, byte[] iv)
    {
        public bool Tls13 => tls13;
        private AesGcm? _gcm;
        private ChaCha20Poly1305? _chacha;

        public byte[]? Open(ulong seq, ReadOnlySpan<byte> header, ReadOnlySpan<byte> body)
        {
            Span<byte> nonce = stackalloc byte[12];
            ReadOnlySpan<byte> sealedPart;
            if (!tls13 && gcm)
            {
                if (body.Length < 8 + 16) return null;
                iv.CopyTo(nonce);
                body[..8].CopyTo(nonce[4..]);
                sealedPart = body[8..];
            }
            else
            {
                if (body.Length < 16) return null;
                iv.CopyTo(nonce);
                for (int i = 0; i < 8; i++) nonce[11 - i] ^= (byte)(seq >> (8 * i));
                sealedPart = body;
            }
            var plain = new byte[sealedPart.Length - 16];
            Span<byte> aad = stackalloc byte[13];
            scoped ReadOnlySpan<byte> additional;
            if (tls13) additional = header;
            else
            {
                BinaryPrimitives.WriteUInt64BigEndian(aad, seq);
                aad[8] = header[0];
                BinaryPrimitives.WriteUInt16BigEndian(aad[9..], BinaryPrimitives.ReadUInt16BigEndian(header[1..]));
                BinaryPrimitives.WriteUInt16BigEndian(aad[11..], (ushort)plain.Length);
                additional = aad;
            }
            try
            {
                if (gcm) (_gcm ??= new AesGcm(key, 16)).Decrypt(nonce, sealedPart[..^16], sealedPart[^16..], plain, additional);
                else (_chacha ??= new ChaCha20Poly1305(key)).Decrypt(nonce, sealedPart[..^16], sealedPart[^16..], plain, additional);
            }
            catch (CryptographicException) { return null; }
            return plain;
        }
    }
}
