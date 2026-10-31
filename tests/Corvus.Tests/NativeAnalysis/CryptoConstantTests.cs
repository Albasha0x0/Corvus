using ModelContextProtocol.Protocol;

namespace Corvus.Tests;

/// <summary>survey_features crypto constants: AES, SHA-256 and Blowfish P-array constants in a raw image; ChaCha in e_sqlite3; CRC-32, MD5 and MurmurHash3 in libSkiaSharp.</summary>
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
    public async Task Constants_name_their_algorithms_in_a_raw_image()
    {
        await using var server = await InProcessServer.StartAsync();
        byte[] sbox = [0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76];
        var raw = await SurveyBytes(server, [.. Pad(0x100), .. sbox, .. Pad(0x40), .. Le(0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A), .. Pad(0x100)]);
        AssertAt(Aes, 0x100, raw);
        AssertAt("SHA-256 (initial values or round constants)", 0x150, raw);
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
