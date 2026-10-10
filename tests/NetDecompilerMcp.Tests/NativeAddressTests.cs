using NetDecompilerMcp.Core;
using NetDecompilerMcp.Native;
using NetDecompilerMcp.Native.Code;
using NetDecompilerMcp.Tools;

namespace NetDecompilerMcp.Tests;

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
}
