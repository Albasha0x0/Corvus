using System.Buffers.Binary;
using System.Numerics;

namespace Corvus.Services.Analysis;

/// <summary>
/// Blowfish with a 4 to 56 byte key and 8-byte blocks, big-endian words.
/// The initial tables are the hexadecimal digits of pi.
/// </summary>
internal sealed class BlowfishCipher : IDisposable
{
    private const int Rounds = 16;
    private static readonly Lazy<uint[]> Pi = new(PiWords);

    private readonly uint[] _p = new uint[Rounds + 2];
    private readonly uint[][] _s = [new uint[256], new uint[256], new uint[256], new uint[256]];

    public const int BlockSize = 8;

    public BlowfishCipher(ReadOnlySpan<byte> key)
    {
        if (key.Length is < 4 or > 56) throw new ArgumentException("A Blowfish key is 4 to 56 bytes.");
        var pi = Pi.Value;
        Array.Copy(pi, _p, _p.Length);
        for (int i = 0; i < 4; i++) Array.Copy(pi, _p.Length + 256 * i, _s[i], 0, 256);
        for (int i = 0, k = 0; i < _p.Length; i++)
        {
            uint word = 0;
            for (int j = 0; j < 4; j++) word = word << 8 | key[k++ % key.Length];
            _p[i] ^= word;
        }
        uint l = 0, r = 0;
        for (int i = 0; i < _p.Length; i += 2) { Encrypt(ref l, ref r); _p[i] = l; _p[i + 1] = r; }
        foreach (var box in _s)
            for (int i = 0; i < 256; i += 2) { Encrypt(ref l, ref r); box[i] = l; box[i + 1] = r; }
    }

    /// <summary>Clears the key-derived tables.</summary>
    public void Dispose()
    {
        Array.Clear(_p);
        foreach (var box in _s) Array.Clear(box);
    }

    public void EncryptBlock(ReadOnlySpan<byte> input, Span<byte> output)
    {
        uint l = BinaryPrimitives.ReadUInt32BigEndian(input), r = BinaryPrimitives.ReadUInt32BigEndian(input[4..]);
        Encrypt(ref l, ref r);
        BinaryPrimitives.WriteUInt32BigEndian(output, l);
        BinaryPrimitives.WriteUInt32BigEndian(output[4..], r);
    }

    public void DecryptBlock(ReadOnlySpan<byte> input, Span<byte> output)
    {
        uint l = BinaryPrimitives.ReadUInt32BigEndian(input), r = BinaryPrimitives.ReadUInt32BigEndian(input[4..]);
        for (int i = Rounds + 1; i > 1; i--)
        {
            l ^= _p[i];
            r ^= F(l);
            (l, r) = (r, l);
        }
        (l, r) = (r, l);
        r ^= _p[1];
        l ^= _p[0];
        BinaryPrimitives.WriteUInt32BigEndian(output, l);
        BinaryPrimitives.WriteUInt32BigEndian(output[4..], r);
    }

    private uint F(uint x) => (_s[0][x >> 24] + _s[1][x >> 16 & 0xFF] ^ _s[2][x >> 8 & 0xFF]) + _s[3][x & 0xFF];

    private void Encrypt(ref uint l, ref uint r)
    {
        for (int i = 0; i < Rounds; i++)
        {
            l ^= _p[i];
            r ^= F(l);
            (l, r) = (r, l);
        }
        (l, r) = (r, l);
        r ^= _p[Rounds];
        l ^= _p[Rounds + 1];
    }

    // Fraction of pi as 32-bit words: P-array (18) then the four S-boxes (1024).
    private static uint[] PiWords()
    {
        const int count = Rounds + 2 + 4 * 256;
        int bits = count * 32 + 64;
        var one = BigInteger.One << bits;
        var pi = 16 * Arctan(5, one) - 4 * Arctan(239, one);
        var fraction = pi - 3 * one;
        var words = new uint[count];
        for (int i = 0; i < count; i++) words[i] = (uint)((fraction >> bits - 32 * (i + 1)) & 0xFFFFFFFF);
        return words;
    }

    // arctan(1/x) in fixed point, by its alternating series.
    private static BigInteger Arctan(int x, BigInteger one)
    {
        var term = one / x;
        var sum = term;
        var square = (BigInteger)x * x;
        for (int n = 3; !term.IsZero; n += 2)
        {
            term /= square;
            sum += (n / 2 % 2 == 1 ? -1 : 1) * (term / n);
        }
        return sum;
    }
}
