using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Corvus.Core;
using Corvus.Services.Analysis;
using Corvus.Tools;

namespace Corvus.Tests;

/// <summary>Dry-run block cipher transforms on self-built fixtures: published vectors, range, padding and refusals.</summary>
public sealed class TransformVerifierTests : IDisposable
{
    private readonly TempDir _dir = new();
    private readonly AssemblyWorkspace _workspace = new(new ServerOptions());

    public void Dispose()
    {
        _workspace.Dispose();
        _dir.Dispose();
    }

    private UnpackTools Tools => new(new UnpackService(_workspace));

    private string Input(byte[] bytes)
    {
        var path = _dir.File("range.bin");
        File.WriteAllBytes(path, bytes);
        return path;
    }

    private string Parameters(object value)
    {
        var path = _dir.File("parameters.json");
        File.WriteAllText(path, JsonSerializer.Serialize(value));
        return path;
    }

    [Theory]
    [InlineData("aes-128", "ecb")]
    [InlineData("aes-128", "cbc")]
    [InlineData("blowfish", "ecb")]
    [InlineData("blowfish", "cbc")]
    public void The_published_vector_of_each_algorithm_and_mode_matches(string algorithm, string mode)
    {
        var record = TransformVerifier.Run("unused", algorithm, mode, null);
        Assert.Equal("match", record.Vector);
        Assert.StartsWith("not run", record.Validation);
    }

    [Fact]
    public void An_aes_ecb_range_decodes_to_the_expected_output_after_the_offset()
    {
        var key = RandomNumberGenerator.GetBytes(16);
        var plain = Encoding.ASCII.GetBytes("thirty-two bytes of fixture text");
        using var aes = Aes.Create();
        aes.Key = key;
        var cipher = aes.EncryptEcb(plain, PaddingMode.PKCS7);
        var input = Input([.. new byte[5], .. cipher, .. new byte[3]]);
        var record = TransformVerifier.Run(input, "aes-128", "ecb", Parameters(new
        {
            key = Convert.ToHexString(key), offset = 5, length = cipher.Length, padding = "pkcs7", expected = Convert.ToHexString(plain),
        }));
        Assert.Equal("expected output matches; pkcs7 padding valid", record.Validation);
        Assert.Equal((5L, (long)cipher.Length, (long)plain.Length), (record.Offset, record.Length, record.OutputLength));
        Assert.Equal(Convert.ToHexStringLower(SHA256.HashData(plain)), record.OutputSha256);
    }

    [Fact]
    public void A_blowfish_cbc_encode_then_decode_returns_the_input()
    {
        var key = RandomNumberGenerator.GetBytes(16);
        var iv = RandomNumberGenerator.GetBytes(8);
        var plain = Encoding.ASCII.GetBytes("round trip of thirteen");
        var args = new { key = Convert.ToHexString(key), iv = Convert.ToHexString(iv), direction = "encode", padding = "pkcs7" };
        var encoded = TransformVerifier.Run(Input(plain), "blowfish", "cbc", Parameters(args));
        Assert.Equal(24, encoded.OutputLength);
        // An independent encoder built on the cipher gives the expected output.
        var checkedRun = TransformVerifier.Run(Input(plain), "blowfish", "cbc", Parameters(new
        {
            key = args.key, iv = args.iv, direction = "encode", padding = "pkcs7", expected = Convert.ToHexString(BlowfishEncode(key, iv, plain)),
        }));
        Assert.Equal("expected output matches", checkedRun.Validation);
        Assert.Equal(encoded.OutputSha256, checkedRun.OutputSha256);
    }

    private static byte[] BlowfishEncode(byte[] key, byte[] iv, byte[] plain)
    {
        var cipher = new BlowfishCipher(key);
        var padded = new byte[(plain.Length / 8 + 1) * 8];
        plain.CopyTo(padded, 0);
        Array.Fill(padded, (byte)(padded.Length - plain.Length), plain.Length, padded.Length - plain.Length);
        var chain = iv.ToArray();
        for (int at = 0; at < padded.Length; at += 8)
        {
            for (int j = 0; j < 8; j++) padded[at + j] ^= chain[j];
            cipher.EncryptBlock(padded.AsSpan(at, 8), padded.AsSpan(at, 8));
            Array.Copy(padded, at, chain, 0, 8);
        }
        return padded;
    }

    [Fact]
    public void A_wrong_key_reports_invalid_pkcs7_padding_and_a_valid_vector()
    {
        var plain = new byte[16];
        using var aes = Aes.Create();
        aes.Key = new byte[16];
        var cipher = aes.EncryptEcb(plain, PaddingMode.PKCS7);
        var record = TransformVerifier.Run(Input(cipher), "aes-128", "ecb", Parameters(new { key = new string('1', 32) }));
        Assert.Equal("pkcs7 padding invalid", record.Validation);
        Assert.Equal("match", record.Vector);
    }

    [Fact]
    public void An_unknown_algorithm_is_refused_with_the_accepted_names()
    {
        var e = Assert.Throws<ToolError>(() => TransformVerifier.Run("unused", "rot13", null, null));
        Assert.Contains("aes-128, blowfish", e.Remediation);
    }

    [Fact]
    public void A_length_past_the_file_end_is_refused()
    {
        var input = Input(new byte[16]);
        var e = Assert.Throws<ToolError>(() => TransformVerifier.Run(input, "aes-128", "ecb", Parameters(new { key = new string('0', 32), offset = 8, length = 16 })));
        Assert.Contains("runs past the file end", e.Message);
    }

    private ToolError Refused(string content, object parameters, Action<string>? also = null)
    {
        var e = Assert.Throws<ToolError>(() => TransformVerifier.Run(Input(Encoding.ASCII.GetBytes(content)), "aes-128", "ecb", Parameters(parameters)));
        also?.Invoke(e.Message);
        return e;
    }

    [Fact]
    public async Task The_tool_reports_the_record_and_never_the_key()
    {
        var key = RandomNumberGenerator.GetBytes(16);
        var input = Input(new byte[16]);
        var parameters = Parameters(new { key = Convert.ToHexString(key), padding = "none" });
        var collector = Corvus.Mcp.ToolOutput.Collect();
        var text = await Tools.UnpackContainer(input, algorithm: "aes-128", parameterFile: parameters);
        var page = Assert.IsType<UnpackPage>(collector.Value);
        var json = page.Transform!.ToJsonString();
        Assert.Contains("\"algorithm\":\"aes-128\"", json, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("Vector: match", text);
        Assert.DoesNotContain(Convert.ToHexString(key), json + text, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task A_mode_without_an_algorithm_is_refused_with_the_next_call()
    {
        var e = await Assert.ThrowsAsync<ToolError>(() => Tools.UnpackContainer(Input(new byte[16]), mode: "cbc"));
        Assert.Contains("pass algorithm as aes-128 or blowfish", e.Remediation);
    }

    [Fact]
    public async Task An_algorithm_with_extraction_parameters_is_refused()
    {
        var e = await Assert.ThrowsAsync<ToolError>(() => Tools.UnpackContainer(Input(new byte[16]), outputDirectory: _dir.File("out"), algorithm: "aes-128"));
        Assert.Contains("outputDirectory", e.Message);
    }

    [Theory]
    [InlineData("\"16\"")]
    [InlineData("16.0")]
    public void A_non_integer_offset_is_refused(string value)
    {
        var input = Input(new byte[32]);
        var file = _dir.File("parameters.json");
        File.WriteAllText(file, "{\"key\":\"" + new string('0', 32) + "\",\"offset\":" + value + "}");
        var e = Assert.Throws<ToolError>(() => TransformVerifier.Run(input, "aes-128", "ecb", file));
        Assert.Contains("offset must be a JSON integer", e.Message);
    }

    [Fact]
    public void A_non_string_iv_is_refused()
    {
        var e = Refused("0123456789abcdef", new { key = new string('0', 32), iv = 5 });
        Assert.Contains("iv must be a JSON string", e.Message);
    }

    [Fact]
    public void Invalid_padding_is_reported_beside_an_expected_output_match()
    {
        var input = Input(new byte[16]);
        var record = TransformVerifier.Run(input, "aes-128", "ecb", Parameters(new { key = new string('0', 32), expected = "" }));
        Assert.Contains("pkcs7 padding invalid", record.Validation);
        Assert.StartsWith("expected output", record.Validation);
    }

    [Fact]
    public void Zeros_padding_is_removed_and_reported()
    {
        var key = new byte[16];
        using var aes = Aes.Create();
        aes.Key = key;
        var cipher = aes.EncryptEcb([.. "abc"u8.ToArray(), .. new byte[13]], PaddingMode.None);
        var record = TransformVerifier.Run(Input(cipher), "aes-128", "ecb", Parameters(new { key = Convert.ToHexString(key), padding = "zeros", expected = Convert.ToHexString("abc"u8) }));
        Assert.Equal("expected output matches; zeros padding: 13 trailing zero byte(s) removed", record.Validation);
    }

    [Fact]
    public void A_blowfish_range_decodes_to_the_input()
    {
        var key = RandomNumberGenerator.GetBytes(12);
        var plain = "eight by"u8.ToArray();
        var cipher = new byte[8];
        using (var bf = new BlowfishCipher(key)) bf.EncryptBlock(plain, cipher);
        var record = TransformVerifier.Run(Input(cipher), "blowfish", "ecb", Parameters(new { key = Convert.ToHexString(key), padding = "none", expected = Convert.ToHexString(plain) }));
        Assert.Equal("expected output matches", record.Validation);
    }

    [Fact]
    public void Malformed_hex_is_refused_without_echoing_it()
    {
        var e = Refused("0123456789abcdef", new { key = "not-hex-secret" });
        Assert.DoesNotContain("not-hex-secret", e.Message + e.Remediation);
    }

    [Fact]
    public void A_parameter_file_without_a_key_is_refused()
    {
        var e = Refused("0123456789abcdef", new { padding = "none" });
        Assert.Contains("no key", e.Message);
    }

    [Fact]
    public void A_cbc_iv_of_the_wrong_length_is_refused()
    {
        var input = Input(new byte[16]);
        var e = Assert.Throws<ToolError>(() => TransformVerifier.Run(input, "aes-128", "cbc", Parameters(new { key = new string('0', 32), iv = "0011", padding = "none" })));
        Assert.Contains("cbc needs a 16-byte iv", e.Remediation + e.Message);
    }

    [Fact]
    public void An_empty_range_is_refused_with_its_offset_and_length()
    {
        var e = Refused("0123456789abcdef", new { key = new string('0', 32), offset = 4, length = 0 });
        Assert.Contains("range is empty", e.Message, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("offset 4", e.Message);
    }

    [Fact]
    public void A_range_over_the_cap_is_refused()
    {
        var path = _dir.File("big.bin");
        using (var fs = new FileStream(path, FileMode.Create)) fs.SetLength(TransformVerifier.MaxRange + 16);
        var e = Assert.Throws<ToolError>(() => TransformVerifier.Run(path, "aes-128", "ecb", Parameters(new { key = new string('0', 32), padding = "none" })));
        Assert.Contains("range limit", e.Message);
    }

    [Fact]
    public void A_cancelled_token_stops_the_transform()
    {
        var input = Input(new byte[32]);
        using var cts = new CancellationTokenSource();
        cts.Cancel();
        Assert.ThrowsAny<OperationCanceledException>(() => TransformVerifier.Run(input, "aes-128", "ecb", Parameters(new { key = new string('0', 32), padding = "none" }), cts.Token));
    }
}
