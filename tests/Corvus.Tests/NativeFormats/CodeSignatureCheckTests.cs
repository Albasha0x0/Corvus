using Corvus.Native.MachO;
using Xunit.Abstractions;

namespace Corvus.Tests;

/// <summary>Mach-O signatures checked page by page: a shipped signed dylib matches, one flipped byte makes it damaged.</summary>
public sealed class CodeSignatureCheckTests(ITestOutputHelper output)
{
    private static byte[] Signed() =>
        File.ReadAllBytes(RealPackages.File("Microsoft.NETCore.App.Runtime.osx-arm64", "10.0.11", "runtimes", "osx-arm64", "native", "libclrjit.dylib"));

    [Fact]
    public void A_shipped_signature_matches_and_a_flipped_byte_is_damage()
    {
        var bytes = Signed();
        var good = SignatureVerdict.Of(MachOFile.FromBytes(bytes, "libclrjit.dylib"));
        output.WriteLine($"{good.Verdict} ({good.Identifier}, team {good.TeamId})");
        Assert.Empty(good.Reasons);
        Assert.Contains("code pages match", good.Verdict);
        Assert.DoesNotContain("trusted", good.Verdict);

        var image = MachOFile.FromBytes(bytes);
        var text = image.Sections.First(s => s.Name.EndsWith("__text", StringComparison.Ordinal));
        bytes[text.RawOffset + 64] ^= 0xFF;
        var flipped = SignatureVerdict.Of(MachOFile.FromBytes(bytes, "libclrjit.dylib"));
        output.WriteLine($"{flipped.Verdict}: {string.Join("; ", flipped.Reasons)}");
        Assert.StartsWith("damaged", flipped.Verdict);
        Assert.Equal(1, flipped.PagesDiffering);
    }
}
