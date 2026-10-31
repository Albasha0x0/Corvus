using ModelContextProtocol.Protocol;

namespace Corvus.Tests;

/// <summary>survey_features crypto constants: AES, SHA-256 and Blowfish P-array constants and DES, Twofish, Camellia and SM4 tables in a raw image; ChaCha in e_sqlite3; CRC-32, MD5 and MurmurHash3 in libSkiaSharp.</summary>
public sealed class CryptoConstantTests : IDisposable
{
    private readonly TempDir _dir = new();

    public void Dispose() => _dir.Dispose();

    private static async Task<string> Survey(InProcessServer server, Dictionary<string, object?> args)
    {
        args["category"] = "crypto";
        var r = await server.Client.CallToolAsync("survey_features", args);
        return string.Concat(r.Content.OfType<TextContentBlock>().Select(b => b.Text));
    }

    private async Task<string> SurveyBytes(InProcessServer server, byte[] image)
    {
        var fixture = _dir.File($"blob{Guid.NewGuid():N}.bin");
        File.WriteAllBytes(fixture, image);
        var load = await server.Client.CallToolAsync("load_assembly", new Dictionary<string, object?> { ["path"] = fixture, ["format"] = "raw", ["arch"] = "x64" });
        return await Survey(server, new() { ["assembly"] = load.StructuredContent!.Value.GetProperty("ids")[0].GetString() });
    }

    private static byte[] Le(params uint[] words) => [.. words.SelectMany(BitConverter.GetBytes)];
    private static byte[] Be(params uint[] words) => [.. words.SelectMany(w => BitConverter.GetBytes(w).Reverse())];
    private static byte[] Pad(int n) => new byte[n];

    private const string Aes = "AES (S-box, inverse S-box, T-table or round constants)";
    private const string Pa = "Blowfish P-array";
    private const ulong ImageBase = 0x180000000;

    private static void AssertAt(string label, int offset, string text) =>
        Assert.Matches($"{System.Text.RegularExpressions.Regex.Escape(label)} @0x{offset:X}(?![0-9A-Fa-f])", text);

    [Fact]
    public async Task The_TEA_delta_is_named_without_the_XTEA_or_XXTEA_labels()
    {
        await using var server = await InProcessServer.StartAsync();
        var text = await SurveyBytes(server, [.. Pad(0x100), .. Le(0x9E3779B9), .. Pad(0x40)]);
        AssertAt("TEA delta (additive)", 0x100, text);
        Assert.DoesNotContain("XTEA", text);
        Assert.DoesNotContain("XXTEA", text);
    }

    [Fact]
    public async Task The_XTEA_start_sum_and_the_XXTEA_subtractive_delta_get_their_own_labels()
    {
        await using var server = await InProcessServer.StartAsync();
        var text = await SurveyBytes(server, [.. Pad(0x100), .. Le(0xC6EF3720), .. Pad(0x40), .. Le(0x61C88647), .. Pad(0x40)]);
        AssertAt("XTEA / TEA decryption start sum (delta x 32)", 0x100, text);
        AssertAt("XXTEA / TEA delta (subtractive form)", 0x144, text);
        Assert.DoesNotContain("TEA delta (additive)", text);
    }

    [Fact]
    public async Task An_RC5_key_schedule_table_is_named_once_in_either_byte_order()
    {
        await using var server = await InProcessServer.StartAsync();
        const string Rc5 = "RC5 / RC6 key schedule (first table words)";
        foreach (var table in new[] { Le(0xB7E15163, 0x5618CB1C, 0xF45044D5), Be(0xB7E15163, 0x5618CB1C, 0xF45044D5) })
        {
            var text = await SurveyBytes(server, [.. Pad(0x100), .. table, .. Pad(0x40)]);
            AssertAt(Rc5, 0x100, text);
            Assert.Single(System.Text.RegularExpressions.Regex.Matches(text, System.Text.RegularExpressions.Regex.Escape(Rc5) + " @0x"));
        }
    }

    [Fact]
    public async Task The_128_bit_and_256_bit_key_constants_are_named_apart()
    {
        await using var server = await InProcessServer.StartAsync();
        var k256 = await SurveyBytes(server, [.. Pad(0x40), .. "expand 32-byte k"u8.ToArray(), .. Pad(0x40)]);
        Assert.Contains("256-bit key", k256);
        Assert.DoesNotContain("128-bit key", k256);
        var k128 = await SurveyBytes(server, [.. Pad(0x40), .. "expand 16-byte k"u8.ToArray(), .. Pad(0x40)]);
        Assert.Contains("128-bit key", k128);
        Assert.DoesNotContain("256-bit key", k128);
    }

    [Fact]
    public async Task A_big_endian_constant_table_is_named_at_its_offset()
    {
        await using var server = await InProcessServer.StartAsync();
        var text = await SurveyBytes(server, [.. Pad(0x80), .. Be(0x61707865, 0x3320646E, 0x79622D32, 0x6B206574), .. Pad(0x40)]);
        AssertAt("ChaCha20 / Salsa20 constant for a 256-bit key (\"expand 32-byte k\")", 0x80, text);
    }

    [Fact]
    public async Task A_constant_word_loaded_as_an_immediate_is_named()
    {
        await using var server = await InProcessServer.StartAsync();
        var text = await SurveyBytes(server, [.. Pad(0x20), 0xB8, .. Le(0x61707865), 0xC3, .. Pad(0x20)]);
        Assert.Contains("constant words as immediates", text);
    }

    [Fact]
    public async Task An_RC4_fill_and_swap_loop_pair_is_named_in_each_compare_form()
    {
        await using var server = await InProcessServer.StartAsync();
        byte[] store = [0x88, 0x04, 0x0B], load = [0x8A, 0x04, 0x0B];
        byte[][] compares = [[0x81, 0xF9, 0, 1, 0, 0], [0x3D, 0, 1, 0, 0], [0x48, 0x3D, 0, 1, 0, 0], [0x48, 0x81, 0xF9, 0, 1, 0, 0]];
        foreach (var cmp in compares)
        {
            byte[] rc4 = [.. store, .. cmp, .. load, .. load, .. store, .. store, .. cmp];
            var hit = await SurveyBytes(server, [.. Pad(0x40), .. rc4, .. Pad(0x40)]);
            Assert.Contains("RC4 state fill and swap loops", hit);
        }
    }

    [Fact]
    public async Task The_XTEA_start_sum_does_not_name_the_TEA_delta()
    {
        await using var server = await InProcessServer.StartAsync();
        var text = await SurveyBytes(server, [.. Pad(0x100), .. Le(0xC6EF3720), .. Pad(0x40)]);
        AssertAt("XTEA / TEA decryption start sum (delta x 32)", 0x100, text);
        Assert.DoesNotContain("TEA delta", text);
    }

    [Fact]
    public async Task A_Serpent_S_box_row_1_is_named_at_its_offset()
    {
        await using var server = await InProcessServer.StartAsync();
        byte[] row = [0xF, 0xC, 0x2, 0x7, 0x9, 0x0, 0x5, 0xA, 0x1, 0xB, 0xE, 0x8, 0x6, 0xD, 0x3, 0x4];
        var text = await SurveyBytes(server, [.. Pad(0x100), .. row, .. Pad(0x40)]);
        AssertAt("Serpent S-box rows 0 and 1 (4-bit entries as bytes)", 0x100, text);
    }

    [Fact]
    public async Task A_Serpent_S_box_row_is_named_at_its_offset()
    {
        await using var server = await InProcessServer.StartAsync();
        byte[] row = [0x3, 0x8, 0xF, 0x1, 0xA, 0x6, 0x5, 0xB, 0xE, 0xD, 0x4, 0x2, 0x7, 0x0, 0x9, 0xC];
        var text = await SurveyBytes(server, [.. Pad(0x100), .. row, .. Pad(0x40)]);
        AssertAt("Serpent S-box rows 0 and 1 (4-bit entries as bytes)", 0x100, text);
    }

    [Fact]
    public async Task The_IDEA_modulus_is_reported_as_low_confidence()
    {
        await using var server = await InProcessServer.StartAsync();
        var text = await SurveyBytes(server, [.. Pad(0x100), .. Le(0x10001), .. Pad(0x40)]);
        AssertAt("IDEA modulus 65537 as immediate (low confidence)", 0x100, text);
    }

    [Fact]
    public async Task Two_compares_against_256_without_byte_moves_between_them_are_not_an_RC4_loop()
    {
        await using var server = await InProcessServer.StartAsync();
        byte[] store = [0x88, 0x04, 0x0B], load = [0x8A, 0x04, 0x0B], cmp = [0x81, 0xF9, 0, 1, 0, 0];
        var single = await SurveyBytes(server, [.. Pad(0x40), .. store, .. cmp, .. Pad(0x40)]);
        Assert.DoesNotContain("RC4 state fill and swap loops", single);
        var bare = await SurveyBytes(server, [.. Pad(0x40), .. store, .. cmp, .. cmp, .. Pad(0x40)]);
        Assert.DoesNotContain("RC4 state fill and swap loops", bare);
        var outside = await SurveyBytes(server, [.. load, .. load, .. store, .. store, .. store, .. cmp, .. Pad(0x20), .. cmp, .. load, .. load, .. store, .. store]);
        Assert.DoesNotContain("RC4 state fill and swap loops", outside);
    }

    [Fact]
    public async Task A_128_bit_big_endian_table_and_the_legacy_constant_are_both_named()
    {
        await using var server = await InProcessServer.StartAsync();
        var text = await SurveyBytes(server, [.. Pad(0x80), .. Be(0x61707865, 0x3120646E, 0x79622D36, 0x6B206574), .. Pad(0x40)]);
        AssertAt("ChaCha20 / Salsa20 constant for a 128-bit key (\"expand 16-byte k\")", 0x80, text);
        var legacy = await SurveyBytes(server, [.. Pad(0x40), .. "expand 32-byte k"u8.ToArray(), .. Pad(0x40)]);
        Assert.Contains("kept for compatibility", legacy);
    }

    [Fact]
    public async Task Constants_name_their_algorithms_in_a_raw_image()
    {
        await using var server = await InProcessServer.StartAsync();
        byte[] sbox = [0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76];
        var raw = await SurveyBytes(server, [.. Pad(0x100), .. sbox, .. Pad(0x40), .. Le(0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A), .. Pad(0x100)]);
        AssertAt(Aes, 0x100, raw);
        AssertAt("SHA-256 (initial values or round constants)", 0x150, raw);
    }

    private const string Des = "DES / 3DES (initial permutation, permuted choice 1 or S-box 1)";
    private const string Twofish = "Twofish (q0 or q1 permutation)";
    private const string Camellia = "Camellia (S-box 1 or key schedule constants Sigma)";
    private const string Sm4 = "SM4 (S-box, system parameter FK or fixed parameter CK)";

    private static byte[] Le64(params ulong[] words) => [.. words.SelectMany(BitConverter.GetBytes)];

    private static readonly byte[] DesIp = [58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4];
    private static readonly byte[] DesPc1 = [57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18];
    private static readonly byte[] DesS1 = [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7, 0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8];
    private static readonly byte[] Q0 = [0xA9, 0x67, 0xB3, 0xE8, 0x04, 0xFD, 0xA3, 0x76, 0x9A, 0x92, 0x80, 0x78, 0xE4, 0xDD, 0xD1, 0x38];
    private static readonly byte[] Q1 = [0x75, 0xF3, 0xC6, 0xF4, 0xDB, 0x7B, 0xFB, 0xC8, 0x4A, 0xD3, 0xE6, 0x6B, 0x45, 0x7D, 0xE8, 0x4B];
    private static readonly byte[] CamS1 = [0x70, 0x82, 0x2C, 0xEC, 0xB3, 0x27, 0xC0, 0xE5, 0xE4, 0x85, 0x57, 0x35, 0xEA, 0x0C, 0xAE, 0x41];
    private static readonly byte[] Sm4S = [0xD6, 0x90, 0xE9, 0xFE, 0xCC, 0xE1, 0x3D, 0xB7, 0x16, 0xB6, 0x14, 0xC2, 0x28, 0xFB, 0x2C, 0x05];
    private static readonly uint[] Sigma = [0xA09E667F, 0x3BCC908B, 0xB67AE858, 0x4CAA73B2];
    private static readonly uint[] Fk = [0xA3B1BAC6, 0x56AA3350, 0x677D9197, 0xB27022DC];
    private static readonly uint[] Ck = [0x00070E15, 0x1C232A31, 0x383F464D, 0x545B6269];

    public static IEnumerable<object[]> TablePatterns() =>
    [
        [Des, "DES initial permutation", DesIp],
        [Des, "DES initial permutation", Le(58, 50, 42, 34)],
        [Des, "DES initial permutation", Be(58, 50, 42, 34)],
        [Des, "DES permuted choice 1", DesPc1],
        [Des, "DES permuted choice 1", Le(57, 49, 41, 33)],
        [Des, "DES permuted choice 1", Be(57, 49, 41, 33)],
        [Des, "DES S-box 1", DesS1],
        [Des, "DES S-box 1", Le(14, 4, 13, 1, 2, 15, 11, 8)],
        [Des, "DES S-box 1", Be(14, 4, 13, 1, 2, 15, 11, 8)],
        [Twofish, "Twofish q0", Q0],
        [Twofish, "Twofish q0", Le(0xA9, 0x67, 0xB3, 0xE8)],
        [Twofish, "Twofish q0", Be(0xA9, 0x67, 0xB3, 0xE8)],
        [Twofish, "Twofish q1", Q1],
        [Twofish, "Twofish q1", Le(0x75, 0xF3, 0xC6, 0xF4)],
        [Twofish, "Twofish q1", Be(0x75, 0xF3, 0xC6, 0xF4)],
        [Camellia, "Camellia S-box 1", CamS1],
        [Camellia, "Camellia S-box 1", Le(0x70, 0x82, 0x2C, 0xEC)],
        [Camellia, "Camellia S-box 1", Be(0x70, 0x82, 0x2C, 0xEC)],
        [Camellia, "Camellia Sigma", Le64(0xA09E667F3BCC908B, 0xB67AE8584CAA73B2)],
        [Camellia, "Camellia Sigma", Be(Sigma)],
        [Camellia, "Camellia Sigma", Le(Sigma)],
        [Sm4, "SM4 S-box", Sm4S],
        [Sm4, "SM4 S-box", Le(0xD6, 0x90, 0xE9, 0xFE)],
        [Sm4, "SM4 S-box", Be(0xD6, 0x90, 0xE9, 0xFE)],
        [Sm4, "SM4 FK", Le(Fk)],
        [Sm4, "SM4 FK", Be(Fk)],
        [Sm4, "SM4 CK", Le(Ck)],
        [Sm4, "SM4 CK", Be(Ck)],
    ];

    [Theory]
    [MemberData(nameof(TablePatterns))]
    public async Task A_cipher_table_is_named_with_its_table_at_its_offset(string algorithm, string table, byte[] pattern)
    {
        await using var server = await InProcessServer.StartAsync();
        var text = await SurveyBytes(server, [.. Pad(0x100), .. pattern, .. Pad(0x40)]);
        AssertAt(algorithm, 0x100, text);
        Assert.Contains($"[{table}]", text);
    }

    [Theory]
    [MemberData(nameof(TablePatterns))]
    public async Task A_cipher_table_with_one_byte_changed_is_not_named(string algorithm, string table, byte[] pattern)
    {
        await using var server = await InProcessServer.StartAsync();
        var near = (byte[])pattern.Clone();
        near[near.Length / 2] ^= 0xFF;
        var text = await SurveyBytes(server, [.. Pad(0x100), .. near, .. Pad(0x40)]);
        Assert.DoesNotContain(algorithm, text);
        Assert.DoesNotContain($"[{table}]", text);
    }

    [Fact]
    public async Task The_first_DES_S_box_row_alone_is_not_named()
    {
        await using var server = await InProcessServer.StartAsync();
        var text = await SurveyBytes(server, [.. Pad(0x100), .. DesS1[..16], .. Pad(0x40)]);
        Assert.DoesNotContain(Des, text);
    }

    [Fact]
    public async Task The_AES_inverse_S_box_is_named_at_its_offset()
    {
        await using var server = await InProcessServer.StartAsync();
        byte[] inv = [0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB];
        var text = await SurveyBytes(server, [.. Pad(0x180), .. inv, .. Pad(0x80)]);
        AssertAt(Aes, 0x180, text);
        Assert.DoesNotContain(Pa, text);
    }

    [Fact]
    public async Task The_AES_little_endian_T_table_is_named_at_its_offset()
    {
        await using var server = await InProcessServer.StartAsync();
        var text = await SurveyBytes(server, [.. Pad(0x200), .. Le(0xC66363A5, 0xF87C7C84, 0xEE777799, 0xF67B7B8D), .. Pad(0x80)]);
        AssertAt(Aes, 0x200, text);
    }

    [Fact]
    public async Task A_Blowfish_P_array_alone_is_named_as_the_P_array_at_its_offset()
    {
        await using var server = await InProcessServer.StartAsync();
        var text = await SurveyBytes(server, [.. Pad(0x140), .. Le(0x243F6A88, 0x85A308D3, 0x13198A2E, 0x03707344), .. Pad(0x80)]);
        AssertAt(Pa, 0x140, text);
    }

    [Fact]
    public async Task A_second_Blowfish_P_array_is_named_at_both_offsets()
    {
        await using var server = await InProcessServer.StartAsync();
        byte[] p = Le(0x243F6A88, 0x85A308D3, 0x13198A2E, 0x03707344);
        var text = await SurveyBytes(server, [.. Pad(0x100), .. p, .. Pad(0x100), .. p, .. Pad(0x40)]);
        AssertAt(Pa, 0x100, text);
        AssertAt(Pa, 0x210, text);
    }

    [Fact]
    public async Task The_AES_big_endian_T_table_is_named_at_its_offset()
    {
        await using var server = await InProcessServer.StartAsync();
        var text = await SurveyBytes(server, [.. Pad(0x200), .. Be(0xC66363A5, 0xF87C7C84, 0xEE777799, 0xF67B7B8D), .. Pad(0x80)]);
        AssertAt(Aes, 0x200, text);
    }

    [Fact]
    public async Task The_AES_inverse_T_table_is_named_in_both_word_orders()
    {
        await using var server = await InProcessServer.StartAsync();
        var text = await SurveyBytes(server, [.. Pad(0x100), .. Le(0x51F4A750, 0x7E416553, 0x1A17A4C3, 0x3A275E96), .. Pad(0x100), .. Be(0x51F4A750, 0x7E416553, 0x1A17A4C3, 0x3A275E96), .. Pad(0x40)]);
        AssertAt(Aes, 0x100, text);
        AssertAt(Aes, 0x210, text);
    }

    private static readonly uint[] Rcon = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36];

    [Fact]
    public async Task The_AES_round_constants_are_named_as_bytes()
    {
        await using var server = await InProcessServer.StartAsync();
        var text = await SurveyBytes(server, [.. Pad(0x100), .. Rcon.Select(r => (byte)r), .. Pad(0x40)]);
        AssertAt(Aes, 0x100, text);
    }

    [Fact]
    public async Task The_AES_round_constants_are_named_as_little_endian_words()
    {
        await using var server = await InProcessServer.StartAsync();
        var text = await SurveyBytes(server, [.. Pad(0x100), .. Le(Rcon), .. Pad(0x40)]);
        AssertAt(Aes, 0x100, text);
    }

    [Fact]
    public async Task The_AES_round_constants_are_named_as_big_endian_words()
    {
        await using var server = await InProcessServer.StartAsync();
        var text = await SurveyBytes(server, [.. Pad(0x100), .. Be(Rcon), .. Pad(0x40)]);
        AssertAt(Aes, 0x100, text);
    }

    [Fact]
    public async Task A_round_constant_run_with_one_value_changed_is_not_named()
    {
        await using var server = await InProcessServer.StartAsync();
        byte[] near = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1C, 0x36];
        var text = await SurveyBytes(server, [.. Pad(0x100), .. near, .. Pad(0x40)]);
        Assert.DoesNotContain(Aes, text);
    }

    [Fact]
    public async Task A_Blowfish_big_endian_P_array_is_named_at_its_offset()
    {
        await using var server = await InProcessServer.StartAsync();
        var text = await SurveyBytes(server, [.. Pad(0x140), .. Be(0x243F6A88, 0x85A308D3, 0x13198A2E, 0x03707344), .. Pad(0x80)]);
        AssertAt(Pa, 0x140, text);
    }

    [Fact]
    public async Task A_Blowfish_S_box_is_named_at_its_offset()
    {
        await using var server = await InProcessServer.StartAsync();
        var text = await SurveyBytes(server, [.. Pad(0x300), .. Le(0xD1310BA6, 0x98DFB5AC, 0x2FFD72DB, 0xD01ADFB7), .. Pad(0x80)]);
        AssertAt("Blowfish S-box", 0x300, text);
    }

    [Fact]
    public async Task A_Blowfish_P_array_without_an_S_box_is_reported_as_weak_evidence()
    {
        await using var server = await InProcessServer.StartAsync();
        var text = await SurveyBytes(server, [.. Pad(0x140), .. Le(0x243F6A88, 0x85A308D3, 0x13198A2E, 0x03707344), .. Pad(0x80)]);
        Assert.Contains("weak", text, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task A_Blowfish_P_array_followed_by_S_box_0_is_not_weak_evidence()
    {
        await using var server = await InProcessServer.StartAsync();
        var text = await SurveyBytes(server, [.. Pad(0x40), .. Le(0x243F6A88, 0x85A308D3, 0x13198A2E, 0x03707344), .. Pad(56), .. Le(0xD1310BA6, 0x98DFB5AC, 0x2FFD72DB, 0xD01ADFB7), .. Pad(0x80)]);
        AssertAt(Pa, 0x40, text);
        Assert.Contains("followed by S-box 0", text);
    }

    [Fact]
    public async Task A_big_endian_Blowfish_P_array_followed_by_S_box_0_is_graded_as_followed()
    {
        await using var server = await InProcessServer.StartAsync();
        var text = await SurveyBytes(server, [.. Pad(0x40), .. Be(0x243F6A88, 0x85A308D3, 0x13198A2E, 0x03707344), .. Pad(56), .. Be(0xD1310BA6, 0x98DFB5AC, 0x2FFD72DB, 0xD01ADFB7), .. Pad(0x80)]);
        Assert.Contains("followed by S-box 0", text);
    }

    [Fact]
    public async Task A_Blowfish_P_array_followed_by_a_different_head_is_weak_evidence()
    {
        await using var server = await InProcessServer.StartAsync();
        var text = await SurveyBytes(server, [.. Pad(0x40), .. Le(0x243F6A88, 0x85A308D3, 0x13198A2E, 0x03707344), .. Pad(56), .. Le(0xD1310BA6, 0x98DFB5AC, 0x2FFD72DB, 0xD01ADFB8), .. Pad(0x80)]);
        Assert.Contains("weak", text, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task A_Blowfish_P_array_followed_by_an_S_box_in_the_other_byte_order_is_weak_evidence()
    {
        await using var server = await InProcessServer.StartAsync();
        var text = await SurveyBytes(server, [.. Pad(0x40), .. Le(0x243F6A88, 0x85A308D3, 0x13198A2E, 0x03707344), .. Pad(56), .. Be(0xD1310BA6, 0x98DFB5AC, 0x2FFD72DB, 0xD01ADFB7), .. Pad(0x80)]);
        Assert.Contains("weak", text, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task A_lone_Blowfish_S_box_is_named_as_partial_evidence()
    {
        await using var server = await InProcessServer.StartAsync();
        var text = await SurveyBytes(server, [.. Pad(0x300), .. Le(0xD1310BA6, 0x98DFB5AC, 0x2FFD72DB, 0xD01ADFB7), .. Pad(0x80)]);
        Assert.Contains("S-box 0 only, partial", text);
        Assert.Contains("not at 1024-byte strides", text);
    }

    private static byte[] FourBlowfishBoxes(Func<uint[], byte[]> order, Func<uint[], byte[]>? orderLast = null)
    {
        byte[] Box(Func<uint[], byte[]> f, params uint[] head) => [.. f(head), .. Pad(1024 - 16)];
        orderLast ??= order;
        return [.. Pad(0x200), .. Box(order, 0xD1310BA6, 0x98DFB5AC, 0x2FFD72DB, 0xD01ADFB7), .. Box(order, 0x4B7A70E9, 0xB5B32944, 0xDB75092E, 0xC4192623),
            .. Box(order, 0xE93D5A68, 0x948140F7, 0xF64C261C, 0x94692934), .. Box(orderLast, 0x3A39CE37, 0xD3FAF5CF, 0xABC27737, 0x5AC52D1B)];
    }

    [Fact]
    public async Task Four_big_endian_Blowfish_S_boxes_a_kilobyte_apart_are_named_as_full_evidence()
    {
        await using var server = await InProcessServer.StartAsync();
        var text = await SurveyBytes(server, FourBlowfishBoxes(h => Be(h)));
        AssertAt("Blowfish S-box", 0x200, text);
        Assert.Contains("4 S-boxes of 256 dwords", text);
    }

    [Fact]
    public async Task Four_little_endian_Blowfish_S_boxes_a_kilobyte_apart_are_named_as_full_evidence()
    {
        await using var server = await InProcessServer.StartAsync();
        var text = await SurveyBytes(server, FourBlowfishBoxes(h => Le(h)));
        AssertAt("Blowfish S-box", 0x200, text);
        Assert.Contains("4 S-boxes of 256 dwords", text);
    }

    [Fact]
    public async Task Blowfish_S_boxes_in_mixed_byte_orders_are_partial_evidence()
    {
        await using var server = await InProcessServer.StartAsync();
        var text = await SurveyBytes(server, FourBlowfishBoxes(h => Le(h), h => Be(h)));
        Assert.DoesNotContain("4 S-boxes of 256 dwords", text);
        Assert.Contains("S-box 0 only, partial", text);
    }

    [Fact]
    public async Task A_lone_CAST_S_box_is_named_as_partial_evidence()
    {
        await using var server = await InProcessServer.StartAsync();
        var text = await SurveyBytes(server, [.. Pad(0x100), .. Le(0x30FB40D4, 0x9FA0FF0B, 0x6BECCD2F, 0x3F258C7A), .. Pad(0x80)]);
        AssertAt("CAST-128 S-box", 0x100, text);
        Assert.Contains("partial", text);
    }

    [Fact]
    public async Task Two_CAST_S_boxes_a_kilobyte_apart_are_named_with_block_and_key_size()
    {
        await using var server = await InProcessServer.StartAsync();
        var text = await SurveyBytes(server, [.. Pad(0x100), .. Le(0x30FB40D4, 0x9FA0FF0B, 0x6BECCD2F, 0x3F258C7A), .. Pad(1024 - 16), .. Le(0x1E213F2F, 0x9C004DD3, 0x6003E540, 0xCF9FC949), .. Pad(0x40)]);
        AssertAt("CAST-128 S-box", 0x100, text);
        Assert.Contains("64-bit block, key 40 to 128 bits", text);
    }

    /// <summary>
    /// Builds blowfish.dll, whose export Cipher loads the address of a
    /// Blowfish P-array in its data section.
    /// </summary>
    private string BlowfishImage()
    {
        var path = _dir.File("blowfish.dll");
        File.WriteAllBytes(path, LinkedImages.Build("blowfish.dll", [("Cipher", 0)], [], CipherCode, PArrayData));
        return path;
    }

    private static byte[] CipherCode(Dictionary<string, uint> slots)
    {
        var a = new Iced.Intel.Assembler(64);
        a.sub(Iced.Intel.AssemblerRegisters.rsp, 0x28);
        a.AddInstruction(Iced.Intel.Instruction.Create(
            Iced.Intel.Code.Lea_r64_m,
            Iced.Intel.Register.RCX,
            new Iced.Intel.MemoryOperand(
                Iced.Intel.Register.RIP, (long)(ImageBase + slots["parray"]), 8)));
        a.add(Iced.Intel.AssemblerRegisters.rsp, 0x28);
        a.ret();
        var stream = new MemoryStream();
        a.Assemble(new Iced.Intel.StreamCodeWriter(stream), ImageBase + LinkedImages.Text);
        return stream.ToArray();
    }

    private static Dictionary<string, uint> PArrayData(PeBlob blob, List<uint> relocations)
    {
        blob.Align(4);
        return new() { ["parray"] = blob.Bytes(Le(0x243F6A88, 0x85A308D3, 0x13198A2E, 0x03707344)) };
    }

    [Fact]
    public async Task Immediate_only_cipher_constants_in_an_image_data_section_are_not_named()
    {
        var path = _dir.File("immediates.dll");
        File.WriteAllBytes(path, LinkedImages.Build("immediates.dll", [("Run", 0)], [], _ => [0xC3], (blob, _) =>
        {
            blob.Align(4);
            return new() { ["words"] = blob.Bytes(Le(0x10001, 0x9E3779B9, 0xC6EF3720, 0x61C88647, 0xB7E15163)) };
        }));
        await using var server = await InProcessServer.StartAsync();
        var text = await SurveyImage(server, path);
        Assert.DoesNotContain("IDEA", text);
        Assert.DoesNotContain("TEA", text);
        Assert.DoesNotContain("RC5", text);
    }

    private static string Lines(string text, string needle) =>
        string.Join('\n', text.Split('\n').Where(l => l.Contains(needle, StringComparison.Ordinal)));

    private static async Task<string> SurveyImage(InProcessServer server, string path)
    {
        var load = await server.Client.CallToolAsync("load_assembly", new Dictionary<string, object?> { ["path"] = path });
        return await Survey(server, new() { ["assembly"] = load.StructuredContent!.Value.GetProperty("ids")[0].GetString() });
    }

    [Fact]
    public async Task A_P_array_without_an_S_box_keeps_its_rule_label_and_match_count()
    {
        await using var server = await InProcessServer.StartAsync();
        var text = await SurveyImage(server, BlowfishImage());
        Assert.Contains("const:blowfish x1", text);
    }

    [Fact]
    public async Task A_Blowfish_P_array_in_an_image_data_section_is_named()
    {
        await using var server = await InProcessServer.StartAsync();
        var text = await SurveyImage(server, BlowfishImage());
        Assert.Contains(Pa, text);
    }

    [Fact(Skip = "The survey does not attribute data-section constants to the reading function.")]
    public async Task The_survey_names_the_function_that_reads_the_Blowfish_P_array()
    {
        await using var server = await InProcessServer.StartAsync();
        var text = await SurveyImage(server, BlowfishImage());
        Assert.Contains("Cipher", Lines(text, Pa));
    }

    [Fact(Skip = "The dossier lists the constant data operand without its algorithm.")]
    public async Task The_function_dossier_names_the_Blowfish_P_array_the_function_reads()
    {
        await using var server = await InProcessServer.StartAsync();
        var r = await server.Client.CallToolAsync("analyze_native_function", new Dictionary<string, object?>
        {
            ["image"] = BlowfishImage(),
            ["address"] = "Cipher",
            ["sections"] = "data",
        });
        var text = string.Concat(r.Content.OfType<TextContentBlock>().Select(b => b.Text));
        Assert.Contains("180002000", Lines(text, Pa), StringComparison.OrdinalIgnoreCase);
    }
    // The two library surveys scan megabytes of native code, so they run in the full set.
    [Fact]
    [Trait("Speed", "Slow")]
    public async Task Constants_name_their_algorithms_in_native_libraries()
    {
        await using var server = await InProcessServer.StartAsync();
        Assert.Contains("const:chacha", await Survey(server, new() { ["path"] = RealPackages.File("SQLitePCLRaw.lib.e_sqlite3", "2.1.11", "runtimes", "win-x64", "native", "e_sqlite3.dll") }));
        var skia = await Survey(server, new() { ["path"] = RealPackages.File("SkiaSharp.NativeAssets.Win32", "2.88.9", "runtimes", "win-x64", "native", "libSkiaSharp.dll") });
        Assert.Contains("const:crc32", skia);
        Assert.Contains("const:sha1-md5", skia);
        Assert.Contains("const:murmur3", skia);
    }
}
