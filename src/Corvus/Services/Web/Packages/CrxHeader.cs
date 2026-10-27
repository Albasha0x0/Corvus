using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;

namespace Corvus.Services.Web.Packages;

/// <summary>A CRX2 or CRX3 extension header: extension id, key proofs and how many verify over the signed data and zip.</summary>
public sealed record CrxHeader(int Version, string? ExtensionId, int Proofs, int Verified, IReadOnlyList<string> Notes)
{
    private const int MaxHeader = 1 << 20;

    /// <summary>Reads the header from the start of <paramref name="stream"/>; <paramref name="zipAt"/> is where the zip starts.</summary>
    public static CrxHeader Read(Stream stream, out long zipAt)
    {
        Span<byte> fixedPart = stackalloc byte[16];
        if (stream.ReadAtLeast(fixedPart, 12, throwOnEndOfStream: false) < 12) throw new InvalidDataException("a CRX header is shorter than 12 bytes");
        int version = (int)BinaryPrimitives.ReadUInt32LittleEndian(fixedPart[4..]);
        var notes = new List<string>();
        if (version == 3)
        {
            uint length = BinaryPrimitives.ReadUInt32LittleEndian(fixedPart[8..]);
            if (length > MaxHeader) throw new InvalidDataException($"a CRX3 header of {length:N0} bytes");
            var header = new byte[length];
            stream.Position = 12;
            stream.ReadExactly(header);
            zipAt = 12 + length;
            return Crx3(header, stream, zipAt, notes);
        }
        if (version == 2)
        {
            uint keyLength = BinaryPrimitives.ReadUInt32LittleEndian(fixedPart[8..]);
            uint sigLength = BinaryPrimitives.ReadUInt32LittleEndian(fixedPart[12..]);
            if (keyLength > MaxHeader || sigLength > MaxHeader) throw new InvalidDataException("a CRX2 key or signature over 1 MiB");
            var key = new byte[keyLength];
            var sig = new byte[sigLength];
            stream.Position = 16;
            stream.ReadExactly(key);
            stream.ReadExactly(sig);
            zipAt = 16 + keyLength + sigLength;
            int verified = 0;
            try
            {
                using var rsa = RSA.Create();
                rsa.ImportSubjectPublicKeyInfo(key, out _);
                stream.Position = zipAt;
                if (rsa.VerifyData(stream, sig, HashAlgorithmName.SHA1, RSASignaturePadding.Pkcs1)) verified = 1;
            }
            catch (CryptographicException ex) { notes.Add("CRX2 key: " + ex.Message); }
            return new CrxHeader(2, Id(SHA256.HashData(key)), 1, verified, notes);
        }
        throw new InvalidDataException($"CRX version {version} is not 2 or 3");
    }

    private static CrxHeader Crx3(byte[] header, Stream stream, long zipAt, List<string> notes)
    {
        var proofs = new List<(int Kind, byte[] Key, byte[] Signature)>();
        byte[]? signedData = null;
        foreach (var (field, value) in Fields(header))
        {
            if (field is 2 or 3)
            {
                byte[]? key = null, sig = null;
                foreach (var (f, v) in Fields(value))
                    if (f == 1) key = v;
                    else if (f == 2) sig = v;
                if (key != null && sig != null) proofs.Add((field, key, sig));
            }
            else if (field == 10000) signedData = value;
        }
        string? id = null;
        if (signedData != null)
            foreach (var (f, v) in Fields(signedData))
                if (f == 1 && v.Length == 16) id = Id(v);
        int verified = 0;
        if (signedData != null && proofs.Count > 0)
        {
            // Signed bytes: "CRX3 SignedData\0", the data length (LE32), the data, then the zip.
            var prefix = new MemoryStream();
            prefix.Write("CRX3 SignedData\0"u8);
            Span<byte> len = stackalloc byte[4];
            BinaryPrimitives.WriteUInt32LittleEndian(len, (uint)signedData.Length);
            prefix.Write(len);
            prefix.Write(signedData);
            foreach (var (kind, key, sig) in proofs)
            {
                try
                {
                    stream.Position = zipAt;
                    using var signed = new ConcatStream(prefix.ToArray(), stream);
                    bool ok;
                    if (kind == 2)
                    {
                        using var rsa = RSA.Create();
                        rsa.ImportSubjectPublicKeyInfo(key, out _);
                        ok = rsa.VerifyData(signed, sig, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
                    }
                    else
                    {
                        using var ecdsa = ECDsa.Create();
                        ecdsa.ImportSubjectPublicKeyInfo(key, out _);
                        ok = ecdsa.VerifyData(signed, sig, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence);
                    }
                    if (ok) verified++;
                }
                catch (CryptographicException ex) { notes.Add("CRX3 key proof: " + ex.Message); }
            }
        }
        if (id != null && !proofs.Any(p => p.Kind == 2 && Id(SHA256.HashData(p.Key)) == id))
            notes.Add("no RSA key proof matches the extension id");
        return new CrxHeader(3, id, proofs.Count, verified, notes);
    }

    /// <summary>An extension id: 16 bytes written as 32 letters a-p.</summary>
    private static string Id(ReadOnlySpan<byte> bytes)
    {
        var sb = new StringBuilder(32);
        foreach (var b in bytes[..16]) sb.Append((char)('a' + (b >> 4))).Append((char)('a' + (b & 15)));
        return sb.ToString();
    }

    /// <summary>The length-delimited fields of a protobuf message (wire type 2); other wire types are skipped.</summary>
    private static IEnumerable<(int Field, byte[] Value)> Fields(byte[] message)
    {
        int p = 0;
        while (p < message.Length)
        {
            ulong tag = Varint(message, ref p);
            int field = (int)(tag >> 3), wire = (int)(tag & 7);
            switch (wire)
            {
                case 0: Varint(message, ref p); break;
                case 1: p += 8; break;
                case 5: p += 4; break;
                case 2:
                {
                    ulong len = Varint(message, ref p);
                    if (len > (ulong)(message.Length - p)) yield break;
                    yield return (field, message[p..(p + (int)len)]);
                    p += (int)len;
                    break;
                }
                default: yield break;
            }
        }
    }

    private static ulong Varint(byte[] b, ref int p)
    {
        ulong v = 0;
        for (int shift = 0; shift < 64 && p < b.Length; shift += 7)
        {
            byte x = b[p++];
            v |= (ulong)(x & 0x7F) << shift;
            if ((x & 0x80) == 0) return v;
        }
        return v;
    }

    /// <summary>A prefix followed by the rest of a stream, for verifying a signature over both.</summary>
    private sealed class ConcatStream(byte[] prefix, Stream rest) : Stream
    {
        private int _at;
        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override void Flush() { }
        public override int Read(byte[] buffer, int offset, int count)
        {
            if (_at < prefix.Length)
            {
                int n = Math.Min(count, prefix.Length - _at);
                Array.Copy(prefix, _at, buffer, offset, n);
                _at += n;
                return n;
            }
            return rest.Read(buffer, offset, count);
        }
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }
}
