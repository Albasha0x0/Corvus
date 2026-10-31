using Corvus.Core;
using Corvus.Native;

namespace Corvus.Services.Analysis;

/// <summary>survey_features "const:name" rules: crypto and hash algorithms found in native images by their constants.</summary>
// Tables match in any section; single constants only in code, as x86 immediates. ARM builds constants from 16-bit
// halves, so there only tables match.
internal sealed class CryptoConstantRules : ISurveyRuleProvider
{
    private const int MaxLocations = 5;
    private const long MaxScanBytes = 256L << 20;

    /// <summary>Describes one hit from the section bytes, the offset and the matched pattern; null adds no detail.</summary>
    private delegate string? DetailFn(ReadOnlySpan<byte> bytes, int at, byte[] pattern);

    /// <summary>A constant set: its byte patterns, whether they count only in code (an immediate) and an optional per-hit detail.</summary>
    private sealed record Constant(string Algorithm, bool CodeOnly, Pattern[] Patterns, DetailFn? Detail = null);

    /// <summary>Bytes to find, with the table they belong to when the rule covers several (null otherwise).</summary>
    private sealed record Pattern(byte[] Bytes, string? Table = null)
    {
        public static implicit operator Pattern(byte[] bytes) => new(bytes);
    }

    private static Pattern T(string table, byte[] bytes) => new(bytes, table);

    // Whether a table head in the given byte order sits at the offset.
    private static bool HeadAt(ReadOnlySpan<byte> bytes, int at, uint[] head, bool big)
    {
        if (at < 0 || at > bytes.Length) return false;
        var s = bytes[at..];
        return s.StartsWith(big ? Be(head) : Le(head));
    }

    // Whether the matched pattern is the big-endian form of the head.
    private static bool IsBig(byte[] pattern, uint[] head) => pattern.AsSpan().SequenceEqual(Be(head));

    private static readonly uint[] BlowfishP = [0x243F6A88, 0x85A308D3, 0x13198A2E, 0x03707344];
    private static readonly uint[] BlowfishS0 = [0xD1310BA6, 0x98DFB5AC, 0x2FFD72DB, 0xD01ADFB7];
    private static readonly uint[][] BlowfishS1To3 =
    [
        [0x4B7A70E9, 0xB5B32944, 0xDB75092E, 0xC4192623],
        [0xE93D5A68, 0x948140F7, 0xF64C261C, 0x94692934],
        [0x3A39CE37, 0xD3FAF5CF, 0xABC27737, 0x5AC52D1B],
    ];
    private static readonly uint[] CastS1 = [0x30FB40D4, 0x9FA0FF0B, 0x6BECCD2F, 0x3F258C7A];
    private static readonly uint[] CastS2 = [0x1E213F2F, 0x9C004DD3, 0x6003E540, 0xCF9FC949];

    // The P-array is 72 bytes; each S-box is 1024 bytes. One byte order holds throughout a table.
    private static string? BlowfishPDetail(ReadOnlySpan<byte> bytes, int at, byte[] pattern) =>
        HeadAt(bytes, at + 72, BlowfishS0, IsBig(pattern, BlowfishP)) ? "followed by S-box 0" : "P-array only, weak evidence";

    private static string? BlowfishSBoxDetail(ReadOnlySpan<byte> bytes, int at, byte[] pattern)
    {
        bool big = IsBig(pattern, BlowfishS0);
        for (int i = 0; i < BlowfishS1To3.Length; i++)
            if (!HeadAt(bytes, at + 1024 * (i + 1), BlowfishS1To3[i], big))
                return "S-box 0 only, partial; S-boxes 1 to 3 not at 1024-byte strides";
        return "4 S-boxes of 256 dwords, 64-bit block, key up to 448 bits";
    }

    private static string? CastDetail(ReadOnlySpan<byte> bytes, int at, byte[] pattern) =>
        HeadAt(bytes, at + 1024, CastS2, IsBig(pattern, CastS1)) ? "S-boxes 1 and 2 of 256 dwords, 64-bit block, key 40 to 128 bits" : "S-box 1 only, partial";

    private static byte[] Le(params uint[] words) => [.. words.SelectMany(BitConverter.GetBytes)];
    private static byte[] Be(params uint[] words) => [.. words.SelectMany(w => BitConverter.GetBytes(w).Reverse())];
    private static byte[] Le64(params ulong[] words) => [.. words.SelectMany(BitConverter.GetBytes)];

    private static readonly Dictionary<string, Constant> Constants = new(StringComparer.Ordinal)
    {
        ["aes"] = new("AES (S-box, inverse S-box, T-table or round constants)", false,
        [
            new byte[] {0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76},
            new byte[] {0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB},
            Le(0xC66363A5, 0xF87C7C84, 0xEE777799, 0xF67B7B8D),
            Be(0xC66363A5, 0xF87C7C84, 0xEE777799, 0xF67B7B8D),
            Le(0x51F4A750, 0x7E416553, 0x1A17A4C3, 0x3A275E96),
            Be(0x51F4A750, 0x7E416553, 0x1A17A4C3, 0x3A275E96),
            // Key expansion round constants, shared by the 128-, 192- and 256-bit schedules.
            new byte[] {0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36},
            Le(0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36),
            Be(0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36),
        ]),
        ["sha256"] = new("SHA-256 (initial values or round constants)", false, [Le(0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A), Le(0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5)]),
        ["sha512"] = new("SHA-512 (initial values or round constants)", false, [Le64(0x6A09E667F3BCC908, 0xBB67AE8584CAA73B), Le64(0x428A2F98D728AE22, 0x7137449123EF65CD)]),
        ["sha1-md5"] = new("MD5 / SHA-1 initial values", false, [Le(0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476)]),
        ["md5"] = new("MD5 round constants", false, [Le(0xD76AA478, 0xE8C7B756, 0x242070DB, 0xC1BDCEEE)]),
        ["crc32"] = new("CRC-32 table", false, [Le(0x00000000, 0x77073096, 0xEE0E612C, 0x990951BA)]),
        ["blowfish"] = new("Blowfish P-array", false, [Le(BlowfishP), Be(BlowfishP)], BlowfishPDetail),
        ["blowfish-sbox"] = new("Blowfish S-box", false, [Le(BlowfishS0), Be(BlowfishS0)], BlowfishSBoxDetail),
        ["cast"] = new("CAST-128 S-box", false, [Le(CastS1), Be(CastS1)], CastDetail),
        ["des"] = new("DES / 3DES (initial permutation, permuted choice 1 or S-box 1)", false,
        [
            T("DES initial permutation", [58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4]),
            T("DES initial permutation", Le(58, 50, 42, 34)),
            T("DES initial permutation", Be(58, 50, 42, 34)),
            T("DES permuted choice 1", [57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18]),
            T("DES permuted choice 1", Le(57, 49, 41, 33)),
            T("DES permuted choice 1", Be(57, 49, 41, 33)),
            // Rows 0 and 1 together: row 0 alone is a plain permutation of 0..15 that other tables contain.
            T("DES S-box 1", [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7, 0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8]),
            T("DES S-box 1", Le(14, 4, 13, 1, 2, 15, 11, 8)),
            T("DES S-box 1", Be(14, 4, 13, 1, 2, 15, 11, 8)),
        ]),
        ["twofish"] = new("Twofish (q0 or q1 permutation)", false,
        [
            T("Twofish q0", [0xA9, 0x67, 0xB3, 0xE8, 0x04, 0xFD, 0xA3, 0x76, 0x9A, 0x92, 0x80, 0x78, 0xE4, 0xDD, 0xD1, 0x38]),
            T("Twofish q0", Le(0xA9, 0x67, 0xB3, 0xE8)),
            T("Twofish q0", Be(0xA9, 0x67, 0xB3, 0xE8)),
            T("Twofish q1", [0x75, 0xF3, 0xC6, 0xF4, 0xDB, 0x7B, 0xFB, 0xC8, 0x4A, 0xD3, 0xE6, 0x6B, 0x45, 0x7D, 0xE8, 0x4B]),
            T("Twofish q1", Le(0x75, 0xF3, 0xC6, 0xF4)),
            T("Twofish q1", Be(0x75, 0xF3, 0xC6, 0xF4)),
        ]),
        ["camellia"] = new("Camellia (S-box 1 or key schedule constants Sigma)", false,
        [
            T("Camellia S-box 1", [0x70, 0x82, 0x2C, 0xEC, 0xB3, 0x27, 0xC0, 0xE5, 0xE4, 0x85, 0x57, 0x35, 0xEA, 0x0C, 0xAE, 0x41]),
            T("Camellia S-box 1", Le(0x70, 0x82, 0x2C, 0xEC)),
            T("Camellia S-box 1", Be(0x70, 0x82, 0x2C, 0xEC)),
            T("Camellia Sigma", Le64(0xA09E667F3BCC908B, 0xB67AE8584CAA73B2)),
            T("Camellia Sigma", Be(0xA09E667F, 0x3BCC908B, 0xB67AE858, 0x4CAA73B2)),
            T("Camellia Sigma", Le(0xA09E667F, 0x3BCC908B, 0xB67AE858, 0x4CAA73B2)),
        ]),
        ["sm4"] = new("SM4 (S-box, system parameter FK or fixed parameter CK)", false,
        [
            T("SM4 S-box", [0xD6, 0x90, 0xE9, 0xFE, 0xCC, 0xE1, 0x3D, 0xB7, 0x16, 0xB6, 0x14, 0xC2, 0x28, 0xFB, 0x2C, 0x05]),
            T("SM4 S-box", Le(0xD6, 0x90, 0xE9, 0xFE)),
            T("SM4 S-box", Be(0xD6, 0x90, 0xE9, 0xFE)),
            T("SM4 FK", Le(0xA3B1BAC6, 0x56AA3350, 0x677D9197, 0xB27022DC)),
            T("SM4 FK", Be(0xA3B1BAC6, 0x56AA3350, 0x677D9197, 0xB27022DC)),
            T("SM4 CK", Le(0x00070E15, 0x1C232A31, 0x383F464D, 0x545B6269)),
            T("SM4 CK", Be(0x00070E15, 0x1C232A31, 0x383F464D, 0x545B6269)),
        ]),
        ["chacha"] = new("ChaCha20 / Salsa20 constant", false, ["expand 32-byte k"u8.ToArray(), "expand 16-byte k"u8.ToArray()]),
        // x86 code writes initial values word by word as immediates, never as one table.
        ["sha256-code"] = new("SHA-256 initial values as immediates", true, [Le(0x6A09E667), Le(0xBB67AE85)]),
        ["sha1-md5-code"] = new("MD5 / SHA-1 initial values as immediates", true, [Le(0x67452301), Le(0x98BADCFE)]),
        // Each set holds the constant that tells TEA-family and RC5/RC6 apart.
        ["tea"] = new("TEA delta (additive)", true, [Le(0x9E3779B9)]),
        ["xtea"] = new("XTEA / TEA decryption start sum (delta x 32)", true, [Le(0xC6EF3720)]),
        ["xxtea"] = new("XXTEA / TEA delta (subtractive form)", true, [Le(0x61C88647)]),
        ["rc5-rc6"] = new("RC5 / RC6 key schedule (first table words)", false, [Le(0xB7E15163, 0x5618CB1C, 0xF45044D5), Be(0xB7E15163, 0x5618CB1C, 0xF45044D5)]),
        ["rc5-rc6-code"] = new("RC5 / RC6 P32 magic as immediate", true, [Le(0xB7E15163)]),
        ["serpent"] = new("Serpent S-box rows 0 and 1 (4-bit entries as bytes)", false,
        [
            new byte[] {0x3, 0x8, 0xF, 0x1, 0xA, 0x6, 0x5, 0xB, 0xE, 0xD, 0x4, 0x2, 0x7, 0x0, 0x9, 0xC},
            new byte[] {0xF, 0xC, 0x2, 0x7, 0x9, 0x0, 0x5, 0xA, 0x1, 0xB, 0xE, 0x8, 0x6, 0xD, 0x3, 0x4},
        ]),
        ["idea"] = new("IDEA modulus 65537 as immediate (low confidence)", true, [Le(0x10001)]),
        ["crc32-poly"] = new("CRC-32 polynomial (reflected)", true, [Le(0xEDB88320)]),
        ["fnv"] = new("FNV-1 hash constants", true, [Le(0x811C9DC5), Le(0x01000193)]),
        ["murmur3"] = new("MurmurHash3 constants", true, [Le(0xCC9E2D51), Le(0x1B873593)]),
    };

    public IReadOnlyCollection<string> Kinds => ["const"];

    public IEnumerable<Features.Rule> Rules =>
    [
        new("block cipher or stream cipher constants", "crypto", [["const:aes", "const:blowfish", "const:blowfish-sbox", "const:cast", "const:des", "const:twofish", "const:camellia", "const:sm4", "const:chacha", "const:tea", "const:xtea", "const:rc5-rc6", "const:rc5-rc6-code", "const:serpent"]]),
        new("possible block cipher constants", "crypto", [["const:xxtea", "const:idea"]]),
        new("hash or checksum constants", "crypto", [["const:sha256", "const:sha256-code", "const:sha512", "const:sha1-md5", "const:sha1-md5-code", "const:md5", "const:crc32", "const:crc32-poly", "const:fnv", "const:murmur3"]]),
    ];

    public Evidence? Evaluate(SurveySubject subject, string feature, CancellationToken ct)
    {
        if (subject.Native is not { } index || !Constants.TryGetValue(feature[(feature.IndexOf(':') + 1)..], out var constant)) return null;
        var image = index.Image;
        var locations = new List<string>();
        int count = 0;
        long budget = MaxScanBytes;
        foreach (var section in image.Sections)
        {
            bool code = (section.Access & (SectionAccess.Execute | SectionAccess.Code)) != 0;
            if (constant.CodeOnly && !code) continue;
            int size = (int)Math.Min(section.VirtualSize == 0 ? section.RawSize : Math.Min(section.VirtualSize, section.RawSize), budget);
            if (size <= 0) continue;
            budget -= size;
            var bytes = new byte[size];
            int read = image.Read(section.Rva, bytes);
            var found = new List<(Pattern Pattern, uint Start, uint End)>();
            foreach (var pattern in constant.Patterns)
                for (int from = 0; from < read;)
                {
                    ct.ThrowIfCancellationRequested();
                    int at = bytes.AsSpan(from, read - from).IndexOf(pattern.Bytes);
                    if (at < 0) break;
                    uint rva = section.Rva + (uint)(from + at);
                    found.Add((pattern, rva, rva + (uint)pattern.Bytes.Length));
                    from += at + pattern.Bytes.Length;
                }
            // Little- and big-endian word forms of one small-valued table overlap by 3 bytes: keep the
            // word-aligned hit, then the earliest, and count a table once.
            found.Sort((x, y) => (x.Start % 4 == 0 ? 0 : 1).CompareTo(y.Start % 4 == 0 ? 0 : 1) is var c and not 0 ? c : x.Start.CompareTo(y.Start));
            var kept = new List<(Pattern Pattern, uint Start, uint End)>();
            foreach (var hit in found)
                if (hit.Pattern.Table is null || !kept.Exists(k => k.Pattern.Table == hit.Pattern.Table && hit.Start < k.End && k.Start < hit.End))
                    kept.Add(hit);
            kept.Sort((x, y) => x.Start.CompareTo(y.Start));
            foreach (var (pattern, rva, _) in kept)
            {
                count++;
                if (locations.Count < MaxLocations)
                {
                    var detail = constant.Detail?.Invoke(bytes.AsSpan(0, read), (int)(rva - section.Rva), pattern.Bytes);
                    locations.Add($"{constant.Algorithm} @{NativeAddress.Va(image, rva)}" + (pattern.Table is { } table ? $" [{table}]" : "") + (index.FunctionAt(rva) is { } f ? $" in {Format.Within(f.Name, f.Start, rva)}" : $" in {section.Name}") + (detail is null ? "" : $" ({detail})"));
                }
            }
        }
        return count == 0 ? null : new Evidence(feature, count, locations);
    }
}
