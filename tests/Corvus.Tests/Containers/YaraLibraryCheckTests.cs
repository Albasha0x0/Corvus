using System.Security.Cryptography;
using Corvus.Native.Providers.Worker.Yara;

namespace Corvus.Tests;

/// <summary>The SHA-256 check on the YARA-X library a release ships.</summary>
public sealed class YaraLibraryCheckTests : IDisposable
{
    private readonly TempDir _dir = new();
    public void Dispose() => _dir.Dispose();

    private string Library(out string hash)
    {
        var path = _dir.File(YaraX.FileName);
        File.WriteAllBytes(path, [1, 2, 3]);
        hash = Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(path)));
        return path;
    }

    [Fact]
    public void A_shipped_library_with_the_build_s_hash_loads()
    {
        var path = Library(out var hash);
        Assert.Null(YaraX.Refusal(path, new Dictionary<string, string> { ["win-x64"] = hash }, "win-x64"));
    }

    [Fact]
    public void A_replaced_shipped_library_is_refused_with_both_hashes()
    {
        var path = Library(out var hash);
        var refusal = YaraX.Refusal(path, new Dictionary<string, string> { ["win-x64"] = new string('0', 64) }, "win-x64");
        Assert.NotNull(refusal);
        Assert.Contains(hash, refusal, StringComparison.OrdinalIgnoreCase);
        Assert.Contains(new string('0', 64), refusal);
    }

    [Fact]
    public void A_library_for_a_platform_the_build_did_not_ship_is_refused()
    {
        var path = Library(out var hash);
        Assert.Contains("linux-x64", YaraX.Refusal(path, new Dictionary<string, string> { ["win-x64"] = hash }, "linux-x64"));
    }

    [Fact]
    public void A_build_made_without_the_release_libraries_checks_nothing()
    {
        var path = Library(out _);
        Assert.Null(YaraX.Refusal(path, new Dictionary<string, string>(), "win-x64"));
    }
}
