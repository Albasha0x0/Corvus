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
    private const string Poly = "Poly1305 (clamp mask of the 128-bit key half) [size=128 confidence=high]";
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

    private static byte[] Round(int[] rotates, byte rotateModRm, byte add = 0x01, byte xor = 0x31)
    {
        var code = new List<byte>();
        foreach (var r in rotates) code.AddRange([add, 0xC8, xor, 0xC1, 0xC1, rotateModRm, (byte)r]);
        return [.. code];
    }

    [Fact]
    public async Task A_ChaCha_quarter_round_is_named_as_rotates_or_as_the_complementary_rotates()
    {
        await using var server = await InProcessServer.StartAsync();
        foreach (var (rotates, modRm) in new[] { (new[] { 16, 12, 8, 7 }, (byte)0xC0), (new[] { 16, 20, 24, 25 }, (byte)0xC8) })
        {
            var text = await SurveyBytes(server, [.. Pad(0x40), .. Round(rotates, modRm), .. Pad(0x40)]);
            Assert.Contains("ChaCha20 quarter round", text);
            Assert.DoesNotContain("Salsa20 quarter round", text);
        }
    }

    [Fact]
    public async Task A_Salsa_quarter_round_is_named_without_the_ChaCha_label()
    {
        await using var server = await InProcessServer.StartAsync();
        var text = await SurveyBytes(server, [.. Pad(0x40), .. Round([7, 9, 13, 18], 0xC0), .. Pad(0x40)]);
        Assert.Contains("Salsa20 quarter round", text);
        Assert.DoesNotContain("ChaCha20 quarter round", text);
    }

    [Fact]
    public async Task A_lone_rotate_by_16_is_not_a_quarter_round()
    {
        await using var server = await InProcessServer.StartAsync();
        var text = await SurveyBytes(server, [.. Pad(0x40), .. Round([16], 0xC0), .. Pad(0x40)]);
        Assert.DoesNotContain("quarter round", text);
    }

    [Fact]
    public async Task A_TEA_round_is_named_without_its_constants()
    {
        await using var server = await InProcessServer.StartAsync();
        byte[] half = [0x89, 0xCA, 0xC1, 0xE2, 0x04, 0x89, 0xCB, 0xC1, 0xEB, 0x05, 0x31, 0xDA, 0x01, 0xCA];
        var text = await SurveyBytes(server, [.. Pad(0x40), .. half, .. half, .. Pad(0x40)]);
        Assert.Contains("TEA / XTEA round", text);
        Assert.DoesNotContain("XXTEA mixing step", text);
    }

    [Fact]
    public async Task An_XXTEA_mixing_step_is_named_without_its_constants()
    {
        await using var server = await InProcessServer.StartAsync();
        byte[] mx = [0xC1, 0xE9, 0x05, 0xC1, 0xE2, 0x02, 0x31, 0xD1, 0xC1, 0xEA, 0x03, 0xC1, 0xE0, 0x04, 0x31, 0xC2, 0x01, 0xD1, 0x01, 0xC8];
        var text = await SurveyBytes(server, [.. Pad(0x40), .. mx, .. Pad(0x40)]);
        Assert.Contains("XXTEA mixing step", text);
        Assert.DoesNotContain("TEA / XTEA round", text);
    }

    [Fact]
    public async Task A_ChaCha_round_with_memory_operand_add_and_xor_is_named()
    {
        await using var server = await InProcessServer.StartAsync();
        var code = new List<byte>();
        foreach (var r in new[] { 16, 12, 8, 7 })
            code.AddRange([0x03, 0x45, 0x08, 0x33, 0x4D, 0x0C, 0xC1, 0xC1, 0xC0, (byte)r]);
        var text = await SurveyBytes(server, [.. Pad(0x40), .. code, .. Pad(0x40)]);
        Assert.Contains("ChaCha20 quarter round", text);
    }

    [Fact]
    public async Task Rotates_without_add_and_xor_steps_are_not_a_quarter_round()
    {
        await using var server = await InProcessServer.StartAsync();
        byte[] rots = [.. new byte[] { 16, 12, 8, 7 }.SelectMany(r => new byte[] { 0xC1, 0xC0, r })];
        var text = await SurveyBytes(server, [.. Pad(0x40), .. rots, .. Pad(0x40)]);
        Assert.DoesNotContain("quarter round", text);
    }

    [Fact]
    public async Task Rotates_in_the_wrong_order_or_amounts_are_not_a_quarter_round()
    {
        await using var server = await InProcessServer.StartAsync();
        foreach (var rotates in new[] { new[] { 12, 16, 8, 7 }, new[] { 16, 12, 8, 9 } })
        {
            var text = await SurveyBytes(server, [.. Pad(0x40), .. Round(rotates, 0xC0), .. Pad(0x40)]);
            Assert.DoesNotContain("quarter round", text);
        }
    }

    [Fact]
    public async Task ChaCha_rotate_amounts_do_not_name_a_Salsa_round()
    {
        await using var server = await InProcessServer.StartAsync();
        var text = await SurveyBytes(server, [.. Pad(0x40), .. Round([16, 12, 8, 7], 0xC0), .. Pad(0x40)]);
        Assert.DoesNotContain("Salsa20 quarter round", text);
    }

    [Fact]
    public async Task A_shl_4_and_shr_5_routine_without_add_and_xor_is_not_named_TEA()
    {
        await using var server = await InProcessServer.StartAsync();
        byte[] half = [0x89, 0xCA, 0xC1, 0xE2, 0x04, 0x89, 0xCB, 0xC1, 0xEB, 0x05];
        var text = await SurveyBytes(server, [.. Pad(0x40), .. half, .. half, .. Pad(0x40)]);
        Assert.DoesNotContain("TEA / XTEA round", text);
    }

    [Fact]
    public async Task XXTEA_shifts_spread_beyond_the_span_are_not_named()
    {
        await using var server = await InProcessServer.StartAsync();
        byte[] gap = new byte[40];
        byte[] mx = [0xC1, 0xE9, 0x05, .. gap, 0xC1, 0xE2, 0x02, 0x31, 0xD1, 0x01, 0xC8, .. gap, 0xC1, 0xEA, 0x03, 0x31, 0xC2, 0x01, 0xD1, .. gap, 0xC1, 0xE0, 0x04];
        var text = await SurveyBytes(server, [.. Pad(0x40), .. mx, .. Pad(0x40)]);
        Assert.DoesNotContain("XXTEA mixing step", text);
    }

    [Fact]
    public async Task Two_unrolled_XXTEA_mixing_steps_do_not_name_a_TEA_round()
    {
        await using var server = await InProcessServer.StartAsync();
        byte[] mx = [0xC1, 0xE9, 0x05, 0xC1, 0xE2, 0x02, 0x31, 0xD1, 0xC1, 0xEA, 0x03, 0xC1, 0xE0, 0x04, 0x31, 0xC2, 0x01, 0xD1, 0x01, 0xC8];
        var text = await SurveyBytes(server, [.. Pad(0x40), .. mx, .. mx, .. Pad(0x40)]);
        Assert.Contains("XXTEA mixing step", text);
        Assert.DoesNotContain("TEA / XTEA round", text);
    }

    private static byte[] Loop(params byte[][] body)
    {
        byte[] code = [.. body.SelectMany(x => x)];
        return [.. code, 0x75, (byte)(-(code.Length + 2))];
    }

    private static readonly byte[] Step16 = [0x83, 0xC0, 0x10], Step8 = [0x83, 0xC0, 0x08], Call = [0xE8, 0, 0, 0, 0];
    private static readonly byte[] XorMem = [0x31, 0x07], Bswap = [0x0F, 0xC8];

    [Fact]
    public async Task A_block_loop_without_xor_or_counter_is_an_ECB_shape_with_its_block_width()
    {
        await using var server = await InProcessServer.StartAsync();
        var wide = await SurveyBytes(server, [.. Pad(0x40), .. Loop(Step16, Call), .. Pad(0x40)]);
        Assert.Contains("[mode=ECB confidence=low] @0x40 in", wide);
        Assert.Contains("block=16 bytes", wide);
        var narrow = await SurveyBytes(server, [.. Pad(0x40), .. Loop(Step8, Call), .. Pad(0x40)]);
        Assert.Contains("block=8 bytes", narrow);
    }

    [Fact]
    public async Task A_block_loop_that_xors_before_the_block_call_is_a_CBC_shape()
    {
        await using var server = await InProcessServer.StartAsync();
        var text = await SurveyBytes(server, [.. Pad(0x40), .. Loop(XorMem, Step16, Call), .. Pad(0x40)]);
        Assert.Contains("[mode=CBC confidence=medium]", text);
        Assert.DoesNotContain("mode=ECB", text);
    }

    [Fact]
    public async Task A_block_loop_with_a_counter_and_a_keystream_xor_is_a_CTR_shape()
    {
        await using var server = await InProcessServer.StartAsync();
        var text = await SurveyBytes(server, [.. Pad(0x40), .. Loop(Bswap, Step16, Call, XorMem), .. Pad(0x40)]);
        Assert.Contains("[mode=CTR confidence=medium]", text);
        Assert.DoesNotContain("mode=CBC", text);
    }

    [Fact]
    public async Task Carry_less_multiply_and_the_reduction_constant_are_a_GCM_tag_shape()
    {
        await using var server = await InProcessServer.StartAsync();
        var clmul = await SurveyBytes(server, [.. Pad(0x40), 0x66, 0x0F, 0x3A, 0x44, 0xC1, 0x00, .. Pad(0x40)]);
        Assert.Contains("GCM tag production", clmul);
        var soft = await SurveyBytes(server, [.. Pad(0x40), 0x35, 0, 0, 0, 0xE1, .. Pad(0x40)]);
        Assert.Contains("GCM tag production", soft);
    }

    [Fact]
    public async Task An_AES_key_assist_and_a_software_round_constant_doubling_are_a_schedule_shape()
    {
        await using var server = await InProcessServer.StartAsync();
        var ni = await SurveyBytes(server, [.. Pad(0x40), 0x66, 0x0F, 0x3A, 0xDF, 0xC1, 0x01, .. Pad(0x40)]);
        Assert.Contains("AES key schedule expansion without tables", ni);
        var soft = await SurveyBytes(server, [.. Pad(0x40), 0xD0, 0xE0, 0x34, 0x1B, .. Pad(0x40)]);
        Assert.Contains("AES key schedule expansion without tables", soft);
    }

    private async Task<string> Loops(byte[] body)
    {
        await using var server = await InProcessServer.StartAsync();
        return await SurveyBytes(server, [.. Pad(0x40), .. body, .. Pad(0x40)]);
    }

    [Fact]
    public async Task A_loop_without_a_block_call_names_no_block_mode_shape()
    {
        var text = await Loops(Loop(Step16, XorMem, [0x90, 0x90]));
        Assert.DoesNotContain("Block loop", text);
    }

    [Fact]
    public async Task A_cdecl_stack_cleanup_around_a_call_is_not_a_block_step()
    {
        var text = await Loops(Loop(Call, [0x83, 0xC4, 0x10]));
        Assert.DoesNotContain("block loop", text);
        Assert.DoesNotContain("Block loop", text);
    }

    [Fact]
    public async Task A_loop_index_increment_with_a_trailing_xor_is_not_a_CTR_shape()
    {
        var text = await Loops(Loop([0xFF, 0xC1], Step16, Call, XorMem));
        Assert.DoesNotContain("mode=CTR", text);
    }

    [Fact]
    public async Task A_register_zeroing_xor_in_the_body_is_not_a_CBC_shape()
    {
        var text = await Loops(Loop([0x66, 0x0F, 0xEF, 0xC0], Step16, Call));
        Assert.DoesNotContain("mode=CBC", text);
        Assert.Contains("mode=ECB", text);
    }

    [Fact]
    public async Task A_block_loop_names_exactly_one_mode()
    {
        var text = await Loops(Loop(XorMem, Step16, Call));
        Assert.Equal(1, new[] { "mode=ECB", "mode=CBC", "mode=CTR" }.Count(m => text.Contains(m)));
    }

    [Fact]
    public async Task A_loop_closed_by_an_unconditional_backward_jump_is_a_block_loop()
    {
        byte[] code = [.. Step16, .. Call];
        var text = await Loops([.. code, 0xEB, (byte)(-(code.Length + 2))]);
        Assert.Contains("block=16 bytes", text);
    }

    [Fact]
    public async Task A_64_bit_reduction_constant_and_a_REX_carry_less_multiply_are_a_GCM_tag_shape()
    {
        var wide = await Loops([0x48, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0xE1]);
        Assert.Contains("GCM tag production", wide);
        var rex = await Loops([0x66, 0x44, 0x0F, 0x3A, 0x44, 0xC1, 0x00]);
        Assert.Contains("GCM tag production", rex);
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
    public async Task Format_markers_and_alphabets_are_named_at_their_offsets()
    {
        await using var server = await InProcessServer.StartAsync();
        var text = await SurveyBytes(server, [.. Pad(0x100), .. Le(0xFD2FB528), .. Pad(0x40), .. Le(0x00000000, 0xF26B8303, 0xE13B70F7, 0x1350F3F4), .. Pad(0x40), .. "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"u8.ToArray(), .. Pad(0x40), .. "inflate 1.3.1"u8.ToArray(), .. Pad(0x40)]);
        AssertAt("Zstandard frame magic", 0x100, text);
        Assert.Contains("(weak evidence)", Lines(text, "Zstandard"));
        AssertAt("CRC-32C table", 0x144, text);
        AssertAt("Base58 alphabet", 0x194, text);
        AssertAt("zlib version string 1.3.1", 0x20E, text);
    }

    [Fact]
    public async Task CRC_32_tables_are_named_in_both_byte_orders_and_bit_orders()
    {
        await using var server = await InProcessServer.StartAsync();
        var text = await SurveyBytes(server, [.. Pad(0x100), .. Le(0, 0x77073096, 0xEE0E612C, 0x990951BA), .. Pad(0x40), .. Be(0, 0x77073096, 0xEE0E612C, 0x990951BA), .. Pad(0x40), .. Le(0, 0x04C11DB7, 0x09823B6E, 0x0D4326D9), .. Pad(0x40), .. Be(0, 0x04C11DB7, 0x09823B6E, 0x0D4326D9), .. Be(0, 0xF26B8303, 0xE13B70F7, 0x1350F3F4)]);
        AssertAt("CRC-32 table", 0x100, text);
        AssertAt("CRC-32 table", 0x150, text);
        AssertAt("CRC-32 table", 0x1A0, text);
        AssertAt("CRC-32 table", 0x1F0, text);
        AssertAt("CRC-32C table", 0x200, text);
    }

    [Fact]
    public async Task Checksum_polynomials_are_named_in_code()
    {
        await using var server = await InProcessServer.StartAsync();
        var text = await SurveyBytes(server, [.. Pad(0x100), .. Le(0x82F63B78), .. Pad(0x40), .. BitConverter.GetBytes(0xC96C5795D7870F42UL), .. Pad(0x40), .. Le(0x80078071), .. Pad(0x40)]);
        AssertAt("CRC-32C polynomial (reflected)", 0x100, text);
        AssertAt("CRC-64 polynomial (reflected)", 0x144, text);
        AssertAt("Adler-32 modulus reduction", 0x18C, text);
    }

    [Fact]
    public async Task Checksum_polynomials_in_a_data_section_are_not_named()
    {
        await using var server = await InProcessServer.StartAsync();
        var path = _dir.File("poly.dll");
        File.WriteAllBytes(path, LinkedImages.Build("poly.dll", [("Cipher", 0)], [], CipherCode, (blob, _) =>
        {
            blob.Align(8);
            return new() { ["parray"] = blob.Bytes([.. Le(0x82F63B78), .. Le(0x80078071), .. BitConverter.GetBytes(0xC96C5795D7870F42UL)]) };
        }));
        var text = await SurveyImage(server, path);
        Assert.DoesNotContain("CRC-32C polynomial", text);
        Assert.DoesNotContain("Adler-32", text);
        Assert.DoesNotContain("CRC-64", text);
    }

    [Fact]
    public async Task Compression_markers_are_named_at_their_offsets()
    {
        await using var server = await InProcessServer.StartAsync();
        var text = await SurveyBytes(server, [.. Pad(0x100), .. Le(0x184D2204), .. Pad(0x40), .. "bvx2"u8.ToArray(), .. Pad(0x40), .. new byte[] { 0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00 }, .. Pad(0x40), .. "timedownlifeleftback"u8.ToArray(), .. Pad(0x40)]);
        AssertAt("LZ4 frame or legacy magic", 0x100, text);
        AssertAt("LZFSE block magic", 0x144, text);
        AssertAt("XZ container magic", 0x188, text);
        AssertAt("Brotli static dictionary", 0x1CE, text);
        Assert.DoesNotContain("const:lzma", text);
    }

    [Fact]
    public async Task The_Deflate_code_length_order_is_named_as_bytes_words_and_dwords()
    {
        await using var server = await InProcessServer.StartAsync();
        byte[] order = [16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15];
        var words = order.SelectMany(b => new byte[] { b, 0 }).ToArray();
        var dwords = order.SelectMany(b => new byte[] { b, 0, 0, 0 }).ToArray();
        var text = await SurveyBytes(server, [.. Pad(0x100), .. order, .. Pad(0x40), .. words, .. Pad(0x40), .. dwords, .. Pad(0x40)]);
        AssertAt("Deflate code-length order", 0x100, text);
        AssertAt("Deflate code-length order", 0x153, text);
        AssertAt("Deflate code-length order", 0x1B9, text);
    }

    [Fact]
    public async Task Text_alphabets_are_named_and_the_hex_digits_alone_are_not()
    {
        await using var server = await InProcessServer.StartAsync();
        var text = await SurveyBytes(server, [.. Pad(0x100), .. "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"u8.ToArray(), .. Pad(0x40), .. "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"u8.ToArray(), .. Pad(0x40), .. "0123456789abcdef"u8.ToArray(), .. Pad(0x40)]);
        AssertAt("Base64 alphabet", 0x100, text);
        AssertAt("Base32 alphabet", 0x180, text);
        Assert.DoesNotContain("const:hex", text);
    }

    [Fact]
    public async Task An_OpenSSL_version_string_reports_its_version()
    {
        await using var server = await InProcessServer.StartAsync();
        var text = await SurveyBytes(server, [.. Pad(0x100), .. "OpenSSL 3.0.13 30 Jan 2024"u8.ToArray(), .. Pad(0x40)]);
        AssertAt("OpenSSL version string 3.0.13", 0x100, text);
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

    [Fact]
    public async Task The_survey_names_the_function_that_reads_the_Blowfish_P_array()
    {
        await using var server = await InProcessServer.StartAsync();
        var text = await SurveyImage(server, BlowfishImage());
        Assert.Contains("used by Cipher", Lines(text, Pa));
    }

    private const int CallerCount = 10;

    // Cipher (16 bytes) loads the P-array; ten exports of 14 bytes each call it.
    private string BlowfishCallersImage(int count = CallerCount)
    {
        var exports = new List<(string, object)> { ("Cipher", 0) };
        for (int i = 0; i < count; i++) exports.Add(($"Decode{i}", 16 + 14 * i));
        var path = _dir.File($"blowfish-callers-{count}.dll");
        File.WriteAllBytes(path, LinkedImages.Build("blowfish-callers.dll", [.. exports], [], slots =>
        {
            var a = new Iced.Intel.Assembler(64);
            a.sub(Iced.Intel.AssemblerRegisters.rsp, 0x28);
            a.AddInstruction(Iced.Intel.Instruction.Create(
                Iced.Intel.Code.Lea_r64_m, Iced.Intel.Register.RCX,
                new Iced.Intel.MemoryOperand(Iced.Intel.Register.RIP, (long)(ImageBase + slots["parray"]), 8)));
            a.add(Iced.Intel.AssemblerRegisters.rsp, 0x28);
            a.ret();
            for (int i = 0; i < count; i++)
            {
                a.sub(Iced.Intel.AssemblerRegisters.rsp, 0x28);
                a.call(ImageBase + LinkedImages.Text);
                a.add(Iced.Intel.AssemblerRegisters.rsp, 0x28);
                a.ret();
            }
            var stream = new MemoryStream();
            a.Assemble(new Iced.Intel.StreamCodeWriter(stream), ImageBase + LinkedImages.Text);
            return stream.ToArray();
        }, PArrayData));
        return path;
    }

    [Fact]
    public async Task The_survey_lists_all_ten_callers_of_the_function_that_reads_the_Blowfish_P_array()
    {
        await using var server = await InProcessServer.StartAsync();
        var line = Lines(await SurveyImage(server, BlowfishCallersImage()), Pa);
        Assert.Contains("used by Cipher; 10 callers: ", line);
        for (int i = 0; i < CallerCount; i++) Assert.Contains($"Decode{i}", line);
    }

    [Fact]
    public async Task A_reader_without_callers_adds_no_callers_suffix()
    {
        await using var server = await InProcessServer.StartAsync();
        var line = Lines(await SurveyImage(server, BlowfishImage()), Pa);
        Assert.Contains("(used by Cipher)", line);
        Assert.DoesNotContain("caller", line);
    }

    [Fact]
    public async Task A_table_without_readers_keeps_its_line_unchanged()
    {
        await using var server = await InProcessServer.StartAsync();
        var line = Lines(await SurveyBytes(server, [.. Pad(0x100), .. Le(0x243F6A88, 0x85A308D3, 0x13198A2E, 0x03707344)]), Pa);
        Assert.DoesNotContain("used by", line);
    }

    [Fact]
    public async Task More_than_thirty_two_callers_are_counted_and_cut_with_a_marker()
    {
        await using var server = await InProcessServer.StartAsync();
        var line = Lines(await SurveyImage(server, BlowfishCallersImage(40)), Pa);
        Assert.Contains("40 callers: ", line);
        Assert.Contains(", ...", line);
        Assert.DoesNotContain("Decode39", line);
    }

    [Fact]
    public async Task A_single_caller_is_counted_in_the_singular()
    {
        await using var server = await InProcessServer.StartAsync();
        var line = Lines(await SurveyImage(server, BlowfishCallersImage(1)), Pa);
        Assert.Contains("; 1 caller: Decode0", line);
        Assert.DoesNotContain("1 callers", line);
    }

    // Cipher reads the P-array, Wrap calls Cipher, Loader calls Wrap.
    private string BlowfishWrapperImage()
    {
        var path = _dir.File("blowfish-wrapper.dll");
        File.WriteAllBytes(path, LinkedImages.Build("blowfish-wrapper.dll", [("Cipher", 0), ("Wrap", 16), ("Loader", 30)], [], slots =>
        {
            var a = new Iced.Intel.Assembler(64);
            a.sub(Iced.Intel.AssemblerRegisters.rsp, 0x28);
            a.AddInstruction(Iced.Intel.Instruction.Create(
                Iced.Intel.Code.Lea_r64_m, Iced.Intel.Register.RCX,
                new Iced.Intel.MemoryOperand(Iced.Intel.Register.RIP, (long)(ImageBase + slots["parray"]), 8)));
            a.add(Iced.Intel.AssemblerRegisters.rsp, 0x28);
            a.ret();
            foreach (var target in new ulong[] { 0, 16 })
            {
                a.sub(Iced.Intel.AssemblerRegisters.rsp, 0x28);
                a.call(ImageBase + LinkedImages.Text + target);
                a.add(Iced.Intel.AssemblerRegisters.rsp, 0x28);
                a.ret();
            }
            var stream = new MemoryStream();
            a.Assemble(new Iced.Intel.StreamCodeWriter(stream), ImageBase + LinkedImages.Text);
            return stream.ToArray();
        }, PArrayData));
        return path;
    }

    [Fact]
    public async Task The_survey_names_a_loader_that_reaches_the_reader_through_a_wrapper()
    {
        await using var server = await InProcessServer.StartAsync();
        var line = Lines(await SurveyImage(server, BlowfishWrapperImage()), Pa);
        Assert.Contains("; 1 caller: Wrap; 1 caller through wrappers: Loader", line);
    }

    [Fact]
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

    private static byte[] Be64(params ulong[] words) => [.. words.SelectMany(w => BitConverter.GetBytes(w).Reverse())];

    private static readonly byte[] Blake2Schedule = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3];
    private static readonly byte[] Blake3Permutation = [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8];

    private static byte[] Dwords(byte[] bytes) => Le([.. bytes.Select(b => (uint)b)]);

    private static byte[] Table(string form) => form switch
    {
        "sha3_le" => Le64(1, 0x8082, 0x800000000000808A, 0x8000000080008000),
        "sha3_be" => Be64(1, 0x8082, 0x800000000000808A, 0x8000000080008000),
        "ripemd160_le" => Le(0x50A28BE6, 0x5C4DD124, 0x6D703EF3, 0x7A6D76E9),
        "ripemd160_be" => Be(0x50A28BE6, 0x5C4DD124, 0x6D703EF3, 0x7A6D76E9),
        "whirlpool" => [0x18, 0x23, 0xC6, 0xE8, 0x87, 0xB8, 0x01, 0x4F, 0x36, 0xA6, 0xD2, 0xF5, 0x79, 0x6F, 0x91, 0x52, 0x60, 0xBC, 0x9B, 0x8E, 0xA3, 0x0C, 0x7B, 0x35, 0x1D, 0xE0, 0xD7, 0xC2, 0x2E, 0x4B, 0xFE, 0x57],
        "blake2_bytes" => Blake2Schedule,
        "blake2_dwords" => Dwords(Blake2Schedule),
        "blake3_bytes" => Blake3Permutation,
        "blake3_dwords" => Dwords(Blake3Permutation),
        "sm3_le" => Le(0x7380166F, 0x4914B2B9, 0x172442D7, 0xDA8A0600),
        "sm3_be" => Be(0x7380166F, 0x4914B2B9, 0x172442D7, 0xDA8A0600),
        "sha224_le" => Le(0xC1059ED8, 0x367CD507, 0x3070DD17, 0xF70E5939),
        "sha224_be" => Be(0xC1059ED8, 0x367CD507, 0x3070DD17, 0xF70E5939),
        "sha384_le" => Le64(0xCBBB9D5DC1059ED8, 0x629A292A367CD507),
        "sha384_be" => Be64(0xCBBB9D5DC1059ED8, 0x629A292A367CD507),
        _ => throw new ArgumentException(form),
    };

    [Theory]
    [InlineData("SHA-3 (Keccak round constants)", "sha3_le")]
    [InlineData("SHA-3 (Keccak round constants)", "sha3_be")]
    [InlineData("RIPEMD-160 (right-line round constants)", "ripemd160_le")]
    [InlineData("RIPEMD-160 (right-line round constants)", "ripemd160_be")]
    [InlineData("Whirlpool S-box", "whirlpool")]
    [InlineData("BLAKE2 (message schedule, rounds 1 and 2)", "blake2_bytes")]
    [InlineData("BLAKE2 (message schedule, rounds 1 and 2)", "blake2_dwords")]
    [InlineData("BLAKE3 (message permutation)", "blake3_bytes")]
    [InlineData("BLAKE3 (message permutation)", "blake3_dwords")]
    [InlineData("SM3 (initial values)", "sm3_le")]
    [InlineData("SM3 (initial values)", "sm3_be")]
    [InlineData("SHA-224 (initial values)", "sha224_le")]
    [InlineData("SHA-224 (initial values)", "sha224_be")]
    [InlineData("SHA-384 (initial values)", "sha384_le")]
    [InlineData("SHA-384 (initial values)", "sha384_be")]
    public async Task Digest_tables_are_named_at_their_offsets(string label, string form)
    {
        await using var server = await InProcessServer.StartAsync();
        var text = await SurveyBytes(server, [.. Pad(0x120), .. Table(form), .. Pad(0x80)]);
        AssertAt(label, 0x120, text);
    }

    [Theory]
    [InlineData("blake2_bytes")]
    [InlineData("blake2_dwords")]
    [InlineData("blake3_bytes")]
    [InlineData("blake3_dwords")]
    public async Task A_BLAKE_table_does_not_name_SHA_2(string form)
    {
        await using var server = await InProcessServer.StartAsync();
        var text = await SurveyBytes(server, [.. Pad(0x120), .. Table(form), .. Pad(0x80)]);
        Assert.DoesNotContain("SHA-256", text);
        Assert.DoesNotContain("SHA-512", text);
    }

    [Theory]
    [InlineData("RIPEMD-160 round constants as immediates", 0x50A28BE6)]
    [InlineData("SM3 round constants as immediates", 0x79CC4519)]
    [InlineData("SHA-512 initial values as immediates", 0xF3BCC908)]
    public async Task Round_constant_immediates_are_named_in_a_raw_code_image(string label, uint immediate)
    {
        await using var server = await InProcessServer.StartAsync();
        var text = await SurveyBytes(server, [.. Pad(0x100), .. Le(immediate), .. Pad(0x40)]);
        AssertAt(label, 0x100, text);
    }

    [Theory]
    [InlineData("RIPEMD-160 round constants as immediates", 0x50A28BE6)]
    [InlineData("SM3 round constants as immediates", 0x79CC4519)]
    public async Task Round_constant_immediates_are_not_named_in_a_data_section(string label, uint immediate)
    {
        await using var server = await InProcessServer.StartAsync();
        var path = _dir.File("immediates.dll");
        File.WriteAllBytes(path, LinkedImages.Build("immediates.dll", [("Cipher", 0)], [], CipherCode, (blob, _) =>
        {
            blob.Align(4);
            return new() { ["parray"] = blob.Bytes(Le(immediate)) };
        }));
        var text = await SurveyImage(server, path);
        Assert.DoesNotContain(label, text);
    }

    [Theory]
    [InlineData("P-256 (field prime, base point x) [size=256 confidence=high]", "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF")]
    [InlineData("P-256 (field prime, base point x) [size=256 confidence=high]", "6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296")]
    [InlineData("P-384 (field prime, base point x) [size=384 confidence=high]", "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFF")]
    [InlineData("P-384 (field prime, base point x) [size=384 confidence=high]", "AA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B9859F741E082542A385502F25DBF55296C3A545E3872760AB7")]
    [InlineData("secp256k1 (field prime, base point x) [size=256 confidence=high]", "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F")]
    [InlineData("secp256k1 (field prime, base point x) [size=256 confidence=high]", "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798")]
    [InlineData("Curve25519 (field prime 2^255-19) [size=256 confidence=high]", "7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFED")]
    public async Task A_curve_parameter_is_named_in_each_byte_and_dword_form(string label, string hex)
    {
        await using var server = await InProcessServer.StartAsync();
        var be = Convert.FromHexString(hex);
        var le = be.Reverse().ToArray();
        var dw = new byte[be.Length];
        for (int i = 0; i < be.Length; i += 4)
            for (int j = 0; j < 4; j++) dw[i + j] = be[i + 3 - j];
        foreach (var form in new[] { be, le, dw })
        {
            var text = await SurveyBytes(server, [.. Pad(0x100), .. form, .. Pad(0x40)]);
            AssertAt(label, 0x100, text);
        }
    }

    [Fact]
    public async Task Poly1305_clamp_masks_are_counted_once_per_form()
    {
        await using var server = await InProcessServer.StartAsync();
        var text = await SurveyBytes(server, [.. Pad(0x100), .. Le(0x0FFFFFFF, 0x0FFFFFFC, 0x0FFFFFFC, 0x0FFFFFFC), .. Pad(0x40)]);
        AssertAt(Poly, 0x100, text);
        Assert.Contains("const:poly1305 x1", text);
        var big = await SurveyBytes(server, [.. Pad(0x100), .. Be(0x0FFFFFFF, 0x0FFFFFFC, 0x0FFFFFFC, 0x0FFFFFFC), .. Pad(0x40)]);
        AssertAt(Poly, 0x100, big);
    }

    [Fact]
    public async Task The_rsaEncryption_object_identifier_is_named_at_medium_confidence()
    {
        await using var server = await InProcessServer.StartAsync();
        byte[] oid = [0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01];
        var text = await SurveyBytes(server, [.. Pad(0x100), .. oid, .. Pad(0x40)]);
        AssertAt("RSA (rsaEncryption object identifier) [size=in key blob confidence=medium]", 0x100, text);
    }

    [Fact]
    public async Task An_RSA_key_blob_magic_is_named_separately_at_low_confidence()
    {
        await using var server = await InProcessServer.StartAsync();
        var text = await SurveyBytes(server, [.. Pad(0x100), .. "RSA2"u8.ToArray(), .. Pad(0x40)]);
        AssertAt("RSA (key blob magic RSA1, RSA2 or RSA3) [confidence=low]", 0x100, text);
        Assert.DoesNotContain("rsaEncryption", text);
    }

    [Fact]
    public async Task An_HMAC_pad_block_is_named_at_low_confidence()
    {
        await using var server = await InProcessServer.StartAsync();
        var text = await SurveyBytes(server, [.. Pad(0x100), .. Enumerable.Repeat((byte)0x5C, 64), .. Pad(0x40)]);
        AssertAt("HMAC (inner or outer pad block) [block=64 confidence=low]", 0x100, text);
    }

    [Theory]
    [InlineData("HKDF")]
    [InlineData("hkdf")]
    [InlineData("PBKDF2")]
    [InlineData("scrypt")]
    [InlineData("Scrypt")]
    [InlineData("argon2id")]
    [InlineData("Argon2id")]
    [InlineData("CMAC")]
    [InlineData("cmac")]
    [InlineData("AES-CMAC")]
    public async Task A_key_derivation_name_string_is_named_as_low_confidence(string name)
    {
        await using var server = await InProcessServer.StartAsync();
        var text = await SurveyBytes(server, [.. Pad(0x100), .. System.Text.Encoding.ASCII.GetBytes(name), .. Pad(0x40)]);
        AssertAt("Key derivation or CMAC (algorithm name string) [confidence=low]", 0x100, text);
    }
}
