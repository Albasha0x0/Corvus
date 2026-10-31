namespace Corvus.Core;

/// <summary>The TLSH digest of a byte stream (128 buckets, 1-byte checksum, "T1" form), fed in blocks.</summary>
public sealed class Tlsh
{
    /// <summary>Shortest input that has a digest.</summary>
    public const int MinLength = 50;

    private const int Buckets = 128, WindowTail = 4;

    // Pearson permutation and length capture bounds of the reference implementation (trendmicro/tlsh).
    private static readonly byte[] Pearson =
    [
        1, 87, 49, 12, 176, 178, 102, 166, 121, 193, 6, 84, 249, 230, 44, 163,
        14, 197, 213, 181, 161, 85, 218, 80, 64, 239, 24, 226, 236, 142, 38, 200,
        110, 177, 104, 103, 141, 253, 255, 50, 77, 101, 81, 18, 45, 96, 31, 222,
        25, 107, 190, 70, 86, 237, 240, 34, 72, 242, 20, 214, 244, 227, 149, 235,
        97, 234, 57, 22, 60, 250, 82, 175, 208, 5, 127, 199, 111, 62, 135, 248,
        174, 169, 211, 58, 66, 154, 106, 195, 245, 171, 17, 187, 182, 179, 0, 243,
        132, 56, 148, 75, 128, 133, 158, 100, 130, 126, 91, 13, 153, 246, 216, 219,
        119, 68, 223, 78, 83, 88, 201, 99, 122, 11, 92, 32, 136, 114, 52, 10,
        138, 30, 48, 183, 156, 35, 61, 26, 143, 74, 251, 94, 129, 162, 63, 152,
        170, 7, 115, 167, 241, 206, 3, 150, 55, 59, 151, 220, 90, 53, 23, 131,
        125, 173, 15, 238, 79, 95, 89, 16, 105, 137, 225, 224, 217, 160, 37, 123,
        118, 73, 2, 157, 46, 116, 9, 145, 134, 228, 207, 212, 202, 215, 69, 229,
        27, 188, 67, 124, 168, 252, 42, 4, 29, 108, 21, 247, 19, 205, 39, 203,
        233, 40, 186, 147, 198, 192, 155, 33, 164, 191, 98, 204, 165, 180, 117, 76,
        140, 36, 210, 172, 41, 54, 159, 8, 185, 232, 113, 196, 231, 47, 146, 120,
        51, 65, 28, 144, 254, 221, 93, 189, 194, 139, 112, 43, 71, 109, 184, 209,
    ];

    private static readonly uint[] LengthBounds =
    [
        1, 2, 3, 5, 7, 11, 17, 25, 38, 57,
        86, 129, 194, 291, 437, 656, 854, 1110, 1443, 1876,
        2439, 3171, 3475, 3823, 4205, 4626, 5088, 5597, 6157, 6772,
        7450, 8195, 9014, 9916, 10907, 11998, 13198, 14518, 15970, 17567,
        19323, 21256, 23382, 25720, 28292, 31121, 34233, 37656, 41422, 45564,
        50121, 55133, 60646, 66711, 73382, 80721, 88793, 97672, 107439, 118183,
        130002, 143002, 157302, 173032, 190335, 209369, 230306, 253337, 278670, 306538,
        337191, 370911, 408002, 448802, 493682, 543050, 597356, 657091, 722800, 795081,
        874589, 962048, 1058252, 1164078, 1280486, 1408534, 1549388, 1704327, 1874759, 2062236,
        2268459, 2495305, 2744836, 3019320, 3321252, 3653374, 4018711, 4420582, 4862641, 5348905,
        5883796, 6472176, 7119394, 7831333, 8614467, 9475909, 10423501, 11465851, 12612437, 13873681,
        15261050, 16787154, 18465870, 20312458, 22343706, 24578077, 27035886, 29739474, 32713425, 35984770,
        39583245, 43541573, 47895730, 52685306, 57953837, 63749221, 70124148, 77136564, 84850228, 93335252,
        102668779, 112935659, 124229227, 136652151, 150317384, 165349128, 181884040, 200072456, 220079703, 242087671,
        266296456, 292926096, 322218735, 354440623, 389884688, 428873168, 471760495, 518936559, 570830240, 627913311,
        690704607, 759775136, 835752671, 919327967, 1011260767, 1112386880, 1223623232, 1345985727, 1480584256, 1628642751,
        1791507135, 1970657856, 2167723648, 2384496256, 2622945920, 2885240448, 3173764736, 3491141248, 3840255616, 4224281216,
    ];

    private readonly uint[] _bucket = new uint[256];
    private readonly byte[] _tail = new byte[WindowTail];
    private long _length;
    private byte _checksum;

    /// <summary>Adds the next block of the input.</summary>
    public void Append(ReadOnlySpan<byte> block)
    {
        foreach (var c0 in block)
        {
            if (_length >= WindowTail)
            {
                byte c1 = _tail[0], c2 = _tail[1], c3 = _tail[2], c4 = _tail[3];
                _checksum = Map(1, c0, c1, _checksum);
                _bucket[Map(49, c0, c1, c2)]++;
                _bucket[Map(12, c0, c1, c3)]++;
                _bucket[Map(178, c0, c2, c3)]++;
                _bucket[Map(166, c0, c2, c4)]++;
                _bucket[Map(84, c0, c1, c4)]++;
                _bucket[Map(230, c0, c3, c4)]++;
            }
            _tail[3] = _tail[2];
            _tail[2] = _tail[1];
            _tail[1] = _tail[0];
            _tail[0] = c0;
            _length++;
        }
    }

    /// <summary>The digest of the input so far; Digest is null with the reason in Absent when the input is under 50 bytes or varies too little.</summary>
    public (string? Digest, string? Absent) Final()
    {
        if (_length < MinLength) return (null, $"input under {MinLength} bytes");
        var sorted = _bucket[..Buckets];
        Array.Sort(sorted);
        uint q1 = sorted[Buckets / 4 - 1], q2 = sorted[Buckets / 2 - 1], q3 = sorted[Buckets - Buckets / 4 - 1];
        // A digest needs a third quartile above zero and more than half of the buckets filled.
        if (q3 == 0 || _bucket.Take(Buckets).Count(b => b > 0) <= Buckets / 2) return (null, "too little variation");

        var bytes = new byte[3 + Buckets / 4];
        bytes[0] = SwapNibbles(_checksum);
        bytes[1] = SwapNibbles(LengthCode(_length));
        bytes[2] = SwapNibbles((byte)((q1 * 100 / q3 % 16) | (q2 * 100 / q3 % 16) << 4));
        for (int i = 0; i < Buckets / 4; i++)
        {
            int h = 0;
            for (int j = 0; j < 4; j++)
            {
                uint k = _bucket[4 * i + j];
                if (q3 < k) h += 3 << (j * 2);
                else if (q2 < k) h += 2 << (j * 2);
                else if (q1 < k) h += 1 << (j * 2);
            }
            bytes[bytes.Length - 1 - i] = (byte)h;
        }
        return ("T1" + Convert.ToHexString(bytes), null);
    }

    /// <summary>The digest of a whole buffer, as <see cref="Final"/>.</summary>
    public static (string? Digest, string? Absent) Of(ReadOnlySpan<byte> data)
    {
        var t = new Tlsh();
        t.Append(data);
        return t.Final();
    }

    private static byte Map(int salt, byte i, byte j, byte k) => Pearson[Pearson[Pearson[salt ^ i] ^ j] ^ k];

    private static byte SwapNibbles(byte b) => (byte)(b << 4 | b >> 4);

    private static byte LengthCode(long length)
    {
        int index = Array.FindIndex(LengthBounds, bound => length <= bound);
        return (byte)(index < 0 ? LengthBounds.Length - 1 : index);
    }
}
