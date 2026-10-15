using ModelContextProtocol.Protocol;

namespace Corvus.Tests;

/// <summary>survey_features crypto constants: AES S-box and SHA-256 IV in a raw fixture; ChaCha in e_sqlite3; CRC-32, MD5 and MurmurHash3 in libSkiaSharp.</summary>
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

    [Fact]
    public async Task Constants_name_their_algorithms()
    {
        await using var server = await InProcessServer.StartAsync();
        var fixture = _dir.File("blob.bin");
        byte[] sbox = [0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76];
        byte[] iv = [.. new uint[] { 0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A }.SelectMany(BitConverter.GetBytes)];
        File.WriteAllBytes(fixture, [.. new byte[0x100], .. sbox, .. new byte[0x40], .. iv, .. new byte[0x100]]);
        var load = await server.Client.CallToolAsync("load_assembly", new Dictionary<string, object?> { ["path"] = fixture, ["format"] = "raw", ["arch"] = "x64" });
        var id = load.StructuredContent!.Value.GetProperty("ids")[0].GetString();
        var raw = await Survey(server, new() { ["assembly"] = id });
        Assert.Contains("AES (S-box, inverse S-box or T-table) @0x100", raw);
        Assert.Contains("SHA-256 (initial values or round constants) @0x150", raw);

        Assert.Contains("const:chacha", await Survey(server, new() { ["path"] = RealPackages.File("SQLitePCLRaw.lib.e_sqlite3", "2.1.11", "runtimes", "win-x64", "native", "e_sqlite3.dll") }));
        var skia = await Survey(server, new() { ["path"] = RealPackages.File("SkiaSharp.NativeAssets.Win32", "2.88.9", "runtimes", "win-x64", "native", "libSkiaSharp.dll") });
        Assert.Contains("const:crc32", skia);
        Assert.Contains("const:sha1-md5", skia);
        Assert.Contains("const:murmur3", skia);
    }
}
