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

    /// <summary>
    /// A constant set: its byte patterns, whether they count only in code (an immediate) and an optional per-hit detail.
    /// A set with a Shape has no patterns and matches code shapes, on x86 and x64 images only.
    /// A Version set reports the number that follows the match; a Weak set marks each hit as weak evidence.
    /// </summary>
    private sealed record Constant(
        string Algorithm, bool CodeOnly, Pattern[] Patterns, DetailFn? Detail = null,
        Func<byte[], int, CancellationToken, IEnumerable<(int At, int Length)>>? Shape = null,
        bool Version = false, bool Weak = false);

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
    private static byte[] Be64(params ulong[] words) => [.. words.SelectMany(w => BitConverter.GetBytes(w).Reverse())];
    private static byte[] Le16(params ushort[] words) => [.. words.SelectMany(BitConverter.GetBytes)];
    private static byte[] Be16(params ushort[] words) => [.. words.SelectMany(w => BitConverter.GetBytes(w).Reverse())];
    private static byte[] Le64(params ulong[] words) => [.. words.SelectMany(BitConverter.GetBytes)];

    // Big-endian bytes as published, then little-endian limbs, then
    // big-endian dwords stored little-endian.
    private static Pattern[] Forms(string hex)
    {
        var be = Convert.FromHexString(hex);
        var le = be.Reverse().ToArray();
        var dw = new byte[be.Length];
        for (int i = 0; i < be.Length; i += 4)
            for (int j = 0; j < 4; j++) dw[i + j] = be[i + 3 - j];
        return [be, le, dw];
    }

    private static Pattern[] Text(params string[] names) => [.. names.Select(n => (Pattern)System.Text.Encoding.ASCII.GetBytes(n))];

    private static readonly byte[] CodeLengthOrder = [16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15];

    // Version strings match their prefix and report the digits that follow.
    // Magics and 4-byte tags are weak evidence and report it. Alphabets are
    // matched as raw byte runs of 32 to 64 characters.
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
        ["sha224"] = new("SHA-224 (initial values)", false, [Le(0xC1059ED8, 0x367CD507, 0x3070DD17, 0xF70E5939), Be(0xC1059ED8, 0x367CD507, 0x3070DD17, 0xF70E5939)]),
        ["sha384"] = new("SHA-384 (initial values)", false, [Le64(0xCBBB9D5DC1059ED8, 0x629A292A367CD507), Be64(0xCBBB9D5DC1059ED8, 0x629A292A367CD507)]),
        ["sha512-code"] = new("SHA-512 initial values as immediates", true, [Le(0xF3BCC908), Le(0x84CAA73B)]),
        ["sha1-md5"] = new("MD5 / SHA-1 initial values", false, [Le(0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476)]),
        ["md5"] = new("MD5 round constants", false, [Le(0xD76AA478, 0xE8C7B756, 0x242070DB, 0xC1BDCEEE)]),
        ["crc32"] = new("CRC-32 table", false,
        [
            Le(0x00000000, 0x77073096, 0xEE0E612C, 0x990951BA),
            Le(0x00000000, 0x04C11DB7, 0x09823B6E, 0x0D4326D9),
            Be(0x00000000, 0x77073096, 0xEE0E612C, 0x990951BA),
            Be(0x00000000, 0x04C11DB7, 0x09823B6E, 0x0D4326D9),
        ]),
        ["crc32c"] = new("CRC-32C table", false, [Le(0x00000000, 0xF26B8303, 0xE13B70F7, 0x1350F3F4), Be(0x00000000, 0xF26B8303, 0xE13B70F7, 0x1350F3F4)]),
        ["crc32c-poly"] = new("CRC-32C polynomial (reflected)", true, [Le(0x82F63B78)]),
        ["crc64-poly"] = new("CRC-64 polynomial (reflected)", true, [Le64(0xC96C5795D7870F42), Le64(0x95AC9329AC4BC9B5)]),
        ["adler32"] = new("Adler-32 modulus reduction", true, [Le(0x80078071)]),
        ["lz4"] = new("LZ4 frame or legacy magic", false, [Le(0x184D2204), Le(0x184C2102)], Weak: true),
        ["zstd"] = new("Zstandard frame magic", false, [Le(0xFD2FB528)], Weak: true),
        ["deflate"] = new("Deflate code-length order", false,
        [
            CodeLengthOrder,
            Le16(CodeLengthOrder.Select(b => (ushort)b).ToArray()),
            Be16(CodeLengthOrder.Select(b => (ushort)b).ToArray()),
            Le(CodeLengthOrder.Select(b => (uint)b).ToArray()),
            Be(CodeLengthOrder.Select(b => (uint)b).ToArray()),
        ]),
        ["xz"] = new("XZ container magic", false, [new byte[] {0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00}]),
        ["brotli"] = new("Brotli static dictionary", false, ["timedownlifeleftback"u8.ToArray()]),
        ["lzfse"] = new("LZFSE block magic", false, ["bvx2"u8.ToArray(), "bvxn"u8.ToArray(), "bvx-"u8.ToArray()], Weak: true),
        ["base64"] = new("Base64 alphabet", false, ["ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"u8.ToArray(), "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"u8.ToArray()]),
        ["base32"] = new("Base32 alphabet", false, ["ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"u8.ToArray()]),
        ["base58"] = new("Base58 alphabet", false, ["123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"u8.ToArray()]),
        ["zlib-version"] = new("zlib version string", false, ["inflate 1."u8.ToArray(), "deflate 1."u8.ToArray()], Version: true),
        ["openssl-version"] = new("OpenSSL version string", false, ["OpenSSL 1."u8.ToArray(), "OpenSSL 3."u8.ToArray()], Version: true),
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
        ["chacha"] = new("ChaCha20 / Salsa20 constant (either key size, kept for compatibility)", false, ["expand 32-byte k"u8.ToArray(), "expand 16-byte k"u8.ToArray()]),
        ["chacha-256"] = new("ChaCha20 / Salsa20 constant for a 256-bit key (\"expand 32-byte k\")", false,
            ["expand 32-byte k"u8.ToArray(), Be(0x61707865, 0x3320646E, 0x79622D32, 0x6B206574)]),
        ["chacha-128"] = new("ChaCha20 / Salsa20 constant for a 128-bit key (\"expand 16-byte k\")", false,
            ["expand 16-byte k"u8.ToArray(), Be(0x61707865, 0x3120646E, 0x79622D36, 0x6B206574)]),
        // Salsa20 stores these words apart, so each is matched on its own.
        ["chacha-code"] = new("ChaCha20 / Salsa20 constant words as immediates", true,
            [Le(0x61707865), Le(0x3320646E), Le(0x3120646E), Le(0x79622D32), Le(0x79622D36), Le(0x6B206574)]),
        ["rc4-loop"] = new("RC4 state fill and swap loops (x86 and x64 code shape, heuristic)", true, [], Shape: Rc4Loops),
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
        ["p256"] = new("P-256 (field prime, base point x) [size=256 confidence=high]", false,
        [
            .. Forms("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF"),
            .. Forms("6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296"),
        ]),
        ["p384"] = new("P-384 (field prime, base point x) [size=384 confidence=high]", false,
        [
            .. Forms("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFE"
                + "FFFFFFFF0000000000000000FFFFFFFF"),
            .. Forms("AA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B9859F741E082542A38"
                + "5502F25DBF55296C3A545E3872760AB7"),
        ]),
        ["secp256k1"] = new("secp256k1 (field prime, base point x) [size=256 confidence=high]", false,
        [
            .. Forms("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F"),
            .. Forms("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"),
        ]),
        ["curve25519"] = new("Curve25519 (field prime 2^255-19) [size=256 confidence=high]", false,
            [.. Forms("7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFED")]),
        ["rsa"] = new("RSA (rsaEncryption object identifier) [size=in key blob confidence=medium]", false,
            [new byte[] {0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01}]),
        ["rsa-blob"] = new("RSA (key blob magic RSA1, RSA2 or RSA3) [confidence=low]", false,
            Text("RSA1", "RSA2", "RSA3")),
        ["hmac"] = new("HMAC (inner or outer pad block) [block=64 confidence=low]", false,
            [Enumerable.Repeat((byte)0x36, 64).ToArray(), Enumerable.Repeat((byte)0x5C, 64).ToArray()]),
        ["poly1305"] = new("Poly1305 (clamp mask of the 128-bit key half) [size=128 confidence=high]", false,
        [
            Le(0x0FFFFFFF, 0x0FFFFFFC, 0x0FFFFFFC, 0x0FFFFFFC),
            Be(0x0FFFFFFF, 0x0FFFFFFC, 0x0FFFFFFC, 0x0FFFFFFC),
        ]),
        ["kdf"] = new("Key derivation or CMAC (algorithm name string) [confidence=low]", false,
            Text("HKDF", "hkdf", "PBKDF2", "pbkdf2", "scrypt", "Scrypt", "argon2id", "Argon2id",
                "argon2i", "Argon2i", "argon2d", "Argon2d", "CMAC", "cmac", "AES-CMAC", "AES128-CMAC",
                "OMAC1")),
        ["murmur3"] = new("MurmurHash3 constants", true, [Le(0xCC9E2D51), Le(0x1B873593)]),
        ["sha3"] = new("SHA-3 (Keccak round constants)", false, [Le64(1, 0x8082, 0x800000000000808A, 0x8000000080008000), Be64(1, 0x8082, 0x800000000000808A, 0x8000000080008000)]),
        ["ripemd160"] = new("RIPEMD-160 (right-line round constants)", false, [Le(0x50A28BE6, 0x5C4DD124, 0x6D703EF3, 0x7A6D76E9), Be(0x50A28BE6, 0x5C4DD124, 0x6D703EF3, 0x7A6D76E9)]),
        ["ripemd160-code"] = new("RIPEMD-160 round constants as immediates", true, [Le(0x50A28BE6), Le(0xA953FD4E)]),
        ["whirlpool"] = new("Whirlpool S-box", false, [new byte[] {0x18, 0x23, 0xC6, 0xE8, 0x87, 0xB8, 0x01, 0x4F, 0x36, 0xA6, 0xD2, 0xF5, 0x79, 0x6F, 0x91, 0x52, 0x60, 0xBC, 0x9B, 0x8E, 0xA3, 0x0C, 0x7B, 0x35, 0x1D, 0xE0, 0xD7, 0xC2, 0x2E, 0x4B, 0xFE, 0x57}]),
        // BLAKE2 shares its initial values with SHA-2, so only the message
        // schedule identifies it.
        ["blake2"] = new("BLAKE2 (message schedule, rounds 1 and 2)", false,
        [
            new byte[] {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3},
            Le(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3),
        ]),
        // BLAKE3 shares its initial values with SHA-256, so only the message
        // permutation identifies it.
        ["blake3"] = new("BLAKE3 (message permutation)", false,
        [
            new byte[] {2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8},
            Le(2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8),
        ]),
        ["sm3"] = new("SM3 (initial values)", false, [Le(0x7380166F, 0x4914B2B9, 0x172442D7, 0xDA8A0600), Be(0x7380166F, 0x4914B2B9, 0x172442D7, 0xDA8A0600)]),
        ["sm3-code"] = new("SM3 round constants as immediates", true, [Le(0x79CC4519), Le(0x7A879D8A)]),
    };

    // Yields (offset, length) at the first compare of a fill and swap loop pair.
    // The fill loop stores bytes before its compare; the swap loop loads and
    // stores bytes between the two compares. Compares are cmp reg, 100h forms.
    private static IEnumerable<(int At, int Length)> Rc4Loops(byte[] b, int read, CancellationToken ct)
    {
        const int MaxGap = 192, FillReach = 48;
        var cmps = new List<int>();
        for (int i = 0; i + 5 <= read; i++)
        {
            if ((i & 0xFFFF) == 0) ct.ThrowIfCancellationRequested();
            int imm = b[i] == 0x3D ? i + 1 : b[i] == 0x81 && b[i + 1] >= 0xF8 && i + 6 <= read ? i + 2 : -1;
            if (imm >= 0 && b[imm] == 0 && b[imm + 1] == 1 && b[imm + 2] == 0 && b[imm + 3] == 0)
                cmps.Add(i);
        }
        for (int k = 0; k + 1 < cmps.Count; k++)
        {
            if (cmps[k + 1] - cmps[k] > MaxGap) continue;
            int fill = 0, loads = 0, stores = 0;
            for (int i = Math.Max(0, cmps[k] - FillReach); i < cmps[k] - 1; i++)
                if (IsByteMove(b, i, out bool store) && store) fill++;
            for (int i = cmps[k]; i < cmps[k + 1] - 1; i++)
                if (IsByteMove(b, i, out bool store)) { if (store) stores++; else loads++; }
            if (fill < 1 || stores < 2 || loads < 2) continue;
            yield return (cmps[k], cmps[k + 1] - cmps[k]);
            k++;
        }
    }

    // A byte move through a base+index operand: opcode 88 or 8A, ModRM mod 00, 01 or 10 with a SIB byte.
    private static bool IsByteMove(byte[] b, int i, out bool store)
    {
        store = b[i] == 0x88;
        return (b[i] == 0x88 || b[i] == 0x8A) && (b[i + 1] & 0x07) == 0x04 && (b[i + 1] & 0xC0) != 0xC0;
    }

    private static readonly string[] CipherKeys =
        ["aes", "blowfish", "blowfish-sbox", "cast", "des", "twofish", "camellia", "sm4", "serpent", "rc5-rc6"];

    // Table size in bytes from the signature: the AES S-box and the Blowfish P-array
    // with four S-boxes are exact; other tables get a bounded span.
    private static int TableSpan(string algorithm) => algorithm switch
    {
        "AES" => 256,
        "Blowfish" => 4168,
        _ => 1024,
    };

    /// <summary>
    /// A cipher table found in an image: its range, the algorithm name and the
    /// table kind (null when the rule has no table kind).
    /// </summary>
    internal sealed record CipherTable(uint Start, uint End, string Algorithm, string? Table);

    /// <summary>
    /// Every block cipher table in the image, in address order; empty when none
    /// is found. A range covers the table size of the algorithm from the
    /// signature, cut at the section end.
    /// Bounded by the survey scan limit.
    /// </summary>
    internal static IReadOnlyList<CipherTable> CipherTables(INativeImage image, CancellationToken ct)
    {
        var result = new List<CipherTable>();
        long budget = MaxScanBytes;
        foreach (var section in image.Sections)
        {
            int size = (int)Math.Min(section.VirtualSize == 0 ? section.RawSize : Math.Min(section.VirtualSize, section.RawSize), budget);
            if (size <= 0) continue;
            budget -= size;
            var bytes = new byte[size];
            int read = image.Read(section.Rva, bytes);
            foreach (var key in CipherKeys)
            {
                var constant = Constants[key];
                string name = constant.Algorithm.Split(" (")[0].Split(' ')[0];
                foreach (var pattern in constant.Patterns)
                    for (int from = 0; from < read;)
                    {
                        ct.ThrowIfCancellationRequested();
                        int at = bytes.AsSpan(from, read - from).IndexOf(pattern.Bytes);
                        if (at < 0) break;
                        uint rva = section.Rva + (uint)(from + at);
                        uint span = (uint)Math.Max(pattern.Bytes.Length, Math.Min(TableSpan(name), read - (from + at)));
                        result.Add(new CipherTable(rva, rva + span, name, pattern.Table));
                        from += at + pattern.Bytes.Length;
                    }
            }
        }
        return result.OrderBy(t => t.Start).ToList();
    }

    public IReadOnlyCollection<string> Kinds => ["const"];

    public IEnumerable<Features.Rule> Rules =>
    [
        new("block cipher or stream cipher constants", "crypto", [["const:aes", "const:blowfish", "const:blowfish-sbox", "const:cast", "const:des", "const:twofish", "const:camellia", "const:sm4", "const:chacha", "const:chacha-256", "const:chacha-128", "const:chacha-code", "const:rc4-loop", "const:tea", "const:xtea", "const:rc5-rc6", "const:rc5-rc6-code", "const:serpent"]]),
        new("possible block cipher constants", "crypto", [["const:xxtea", "const:idea"]]),
        new("asymmetric, authentication or key derivation structures", "crypto", [["const:p256", "const:p384", "const:secp256k1", "const:curve25519", "const:rsa", "const:rsa-blob", "const:hmac", "const:poly1305", "const:kdf"]]),
        new("hash or checksum constants", "crypto", [["const:sha256", "const:sha256-code", "const:sha512", "const:sha512-code", "const:sha224", "const:sha384", "const:sha1-md5", "const:sha1-md5-code", "const:md5", "const:crc32", "const:crc32-poly", "const:crc32c", "const:crc32c-poly", "const:crc64-poly", "const:adler32", "const:fnv", "const:murmur3", "const:sha3", "const:ripemd160", "const:ripemd160-code", "const:whirlpool", "const:blake2", "const:blake3", "const:sm3", "const:sm3-code"]]),
        new("compression format markers or tables", "crypto", [["const:lz4", "const:zstd", "const:deflate", "const:xz", "const:brotli", "const:lzfse"]]),
        new("text encoding alphabets", "crypto", [["const:base64", "const:base32", "const:base58"]]),
        new("crypto or compression library version strings", "crypto", [["const:zlib-version", "const:openssl-version"]]),
    ];

    // Reads the dotted number that ends a version prefix, e.g. "1.3.1".
    private static string VersionAfter(byte[] bytes, int at, int prefixLength)
    {
        int start = at + prefixLength - 2, end = at + prefixLength;
        while (end < bytes.Length && (bytes[end] is >= (byte)'0' and <= (byte)'9' or >= (byte)'a' and <= (byte)'z' or (byte)'.')) end++;
        return " " + System.Text.Encoding.ASCII.GetString(bytes, start, end - start).TrimEnd('.');
    }

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
            if (constant.Shape is not null && image.Arch is not (NativeArch.X86 or NativeArch.X64)) continue;
            int size = (int)Math.Min(section.VirtualSize == 0 ? section.RawSize : Math.Min(section.VirtualSize, section.RawSize), budget);
            if (size <= 0) continue;
            budget -= size;
            var bytes = new byte[size];
            int read = image.Read(section.Rva, bytes);
            if (constant.Shape is { } shape)
                foreach (var (at, length) in shape(bytes, read, ct))
                {
                    ct.ThrowIfCancellationRequested();
                    uint rva = section.Rva + (uint)at;
                    count++;
                    if (locations.Count < MaxLocations)
                        locations.Add($"{constant.Algorithm} @{NativeAddress.Va(image, rva)}" + (index.FunctionAt(rva) is { } f ? $" in {Format.Within(f.Name, f.Start, rva)}" : $" in {section.Name}"));
                }
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
                    int at = (int)(rva - section.Rva);
                    var detail = constant.Detail?.Invoke(bytes.AsSpan(0, read), at, pattern.Bytes);
                    locations.Add($"{constant.Algorithm}{(constant.Version ? VersionAfter(bytes, at, pattern.Bytes.Length) : "")} @{NativeAddress.Va(image, rva)}" + (pattern.Table is { } table ? $" [{table}]" : "") + (index.FunctionAt(rva) is { } f ? $" in {Format.Within(f.Name, f.Start, rva)}" : $" in {section.Name}") + (detail is null ? "" : $" ({detail})") + (constant.Weak ? " (weak evidence)" : ""));
                }
            }
        }
        return count == 0 ? null : new Evidence(feature, count, locations);
    }
}
