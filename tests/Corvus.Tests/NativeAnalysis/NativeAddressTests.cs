using Corvus.Core;
using Corvus.Native;
using Corvus.Native.Code;
using Corvus.Tools;

namespace Corvus.Tests;

public class NativeAddressTests
{
    private const uint First = 0x1000, Second = 0x1010, Third = 0x1020, Fourth = 0x1030;

    /// <summary>Four one-instruction functions, exported as First, Bach (a hex-shaped name), Third and Fourth.</summary>
    private static CodeTestImage Image(bool exports = true)
    {
        var code = new byte[0x40];
        Array.Fill(code, (byte)0xCC);
        foreach (var at in new[] { First, Second, Third, Fourth }) code[at - CodeTestImage.SyntheticCodeRva] = 0xC3;
        return CodeTestImage.Synthetic(NativeArch.X64, code, exports: exports
            ? [new("First", 1, First, null), new("Bach", 2, Second, null), new("Third", 3, Third, null), new("Fourth", 4, Fourth, null)]
            : null, entry: First);
    }

    [Fact]
    public void HexShapedNamesResolveAsNamesBeforeNumbers()
    {
        var image = Image();
        var index = NativeCodeIndex.Build(image);
        Assert.Equal(Second, NativeAddress.Parse(image, "Bach"));
        Assert.Equal(Second, NativeCodeTools.Address(index, "Bach"));
        index.SetSourceName(Third, "Each", NativeNameSource.User);
        Assert.Equal(Third, NativeCodeTools.Address(index, "Each"));

        // Without such a name the trailing-h form is a MASM number; 0x and # are always numbers.
        Assert.Equal(0xBACu, NativeAddress.Parse(image, "0BACh"));
        Assert.Equal(0xEACu, NativeCodeTools.Address(index, "0EACh"));
        Assert.Equal(0xBACu, NativeAddress.Parse(Image(exports: false), "Bach"));
        Assert.Equal(Second, NativeAddress.Parse(image, "0x1010"));
        Assert.Equal(Second, NativeAddress.Parse(image, "#4112"));
    }

    [Fact]
    public void EngineDefaultNamesResolveToTheirAddress()
    {
        var image = Image();
        foreach (var name in new[] { "FUN_140001010", "thunk_FUN_140001010", "LAB_140001010", "DAT_140001010", "PTR_DAT_140001010", "PTR_FUN_140001010", "sub_1010",
                     "sub_140001010", "loc_140001010" })
            Assert.Equal(Second, NativeAddress.Parse(image, name));
        // a real name wins over the default form, and a malformed default name is not found
        var index = NativeCodeIndex.Build(image);
        index.SetSourceName(Third, "FUN_140001010", NativeNameSource.User);
        Assert.Equal(Third, NativeCodeTools.Address(index, "FUN_140001010"));
        Assert.Equal(ErrorCode.NotFound, Assert.Throws<ToolError>(() => NativeAddress.Parse(image, "FUN_14000101g")).Code);
        Assert.Equal(ErrorCode.NotFound, Assert.Throws<ToolError>(() => NativeAddress.Parse(image, "FUN_150001010")).Code);
        Assert.Null(NativeAddress.DefaultName("switchD_140001010"));
    }

    [Theory]
    [InlineData(NativeArch.X64)]
    [InlineData(NativeArch.Arm64)]
    public void NameOnAJumpThunkAndItsTargetMeansTheTarget(NativeArch arch)
    {
        // An incremental-link thunk at First (the export) jumps to Third, which the PDB names the same.
        var code = new byte[0x40];
        int at = (int)(First - CodeTestImage.SyntheticCodeRva), rel = (int)(Third - First);
        if (arch == NativeArch.X64) { code[at] = 0xE9; BitConverter.GetBytes(rel - 5).CopyTo(code, at + 1); }
        else BitConverter.GetBytes(0x14000000u | (uint)(rel / 4)).CopyTo(code, at);
        var image = CodeTestImage.Synthetic(arch, code, exports: [new("Body", 1, First, null)], entry: First);
        var index = NativeCodeIndex.Build(image);
        index.SetSourceName(Third, "Body", NativeNameSource.Pdb);

        Assert.Equal(Third, NativeCodeTools.Address(index, "Body"));
        Assert.Equal(Third, index.AddressOfName("Body"));
        // Two bodies with one name stay ambiguous.
        index.SetSourceName(Fourth, "Body", NativeNameSource.User);
        Assert.Equal(ErrorCode.Ambiguous, Assert.Throws<ToolError>(() => NativeCodeTools.Address(index, "Body")).Code);
    }

    [Fact]
    public void NameOnSeveralAddressesIsAmbiguousAndListsThem()
    {
        var image = Image();
        var index = NativeCodeIndex.Build(image);
        index.SetSourceName(Third, "Twin", NativeNameSource.User);
        index.SetSourceName(Fourth, "Twin", NativeNameSource.Pdb);

        var error = Assert.Throws<ToolError>(() => NativeCodeTools.Address(index, "Twin"));
        Assert.Equal(ErrorCode.Ambiguous, error.Code);
        Assert.Contains("0x140001020 (user)", error.Message);
        Assert.Contains("0x140001030 (pdb)", error.Message);
        Assert.Equal(ErrorCode.Ambiguous, Assert.Throws<ToolError>(() => index.AddressOfName("Twin")).Code);
        Assert.Equal([(Third, NativeNameSource.User), (Fourth, NativeNameSource.Pdb)], index.Sourced.AddressesOf("Twin"));

        // A source name that collides with an export elsewhere is ambiguous too.
        index.SetSourceName(Fourth, "Bach", NativeNameSource.Pdb);
        var collision = Assert.Throws<ToolError>(() => NativeCodeTools.Address(index, "Bach"));
        Assert.Contains("0x140001010 (export)", collision.Message);
        Assert.Contains("0x140001030 (pdb)", collision.Message);

        // Unique names and numbers still resolve.
        Assert.Equal(Third, NativeCodeTools.Address(index, "Twin"));
        Assert.Equal(First, NativeCodeTools.Address(index, "First"));
        Assert.Equal(Fourth, NativeCodeTools.Address(index, "0x1030"));
        index.SetSourceName(Fourth, null, NativeNameSource.Pdb);
        Assert.Equal(Second, NativeCodeTools.Address(index, "Bach"));
        Assert.Equal(Fourth, index.AddressOfName("Fourth"));
    }

    [Fact]
    public void ReplacedLayersKeepTheNameMapExact()
    {
        var names = new SourcedNames();
        names.ReplaceNames(NativeNameSource.Pdb, new Dictionary<uint, string> { [1] = "a", [2] = "a", [3] = "a", [4] = "b" });
        Assert.Equal([1u, 2, 3], names.AddressesOf("a").Select(c => c.Rva));
        names.SetName(2, "c", NativeNameSource.User);
        Assert.Equal([1u, 3], names.AddressesOf("a").Select(c => c.Rva));
        names.ReplaceNames(NativeNameSource.Pdb, new Dictionary<uint, string> { [3] = "a" });
        Assert.Equal([3u], names.AddressesOf("a").Select(c => c.Rva));
        Assert.Empty(names.AddressesOf("b"));
        Assert.Equal([(2u, NativeNameSource.User)], names.AddressesOf("c"));
    }
    [Theory]
    [InlineData("Packet::length", "Packet", "length", null)]
    [InlineData("Game::Player::health", "Game::Player", "health", null)]
    [InlineData("Packet.length", "Packet", "length", null)]
    [InlineData("Packet+0x18", "Packet", null, 0x18)]
    [InlineData("Packet + 18h", "Packet", null, 0x18)]
    public void Struct_member_targets_parse(string text, string type, string? member, int? offset) =>
        Assert.Equal((type, member, offset), NativeCodeTools.FieldTarget(text));

    [Theory]
    [InlineData("0x180001000")]
    [InlineData("KERNEL32!ExitProcess")]
    [InlineData("First+0x4z")]
    [InlineData("::x")]
    public void Other_addresses_are_not_struct_members(string text) => Assert.Null(NativeCodeTools.FieldTarget(text));
}
