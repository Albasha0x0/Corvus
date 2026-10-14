using Corvus.Core;
using Corvus.Native;
using Corvus.Services;

namespace Corvus.Tests;

/// <summary>A patch shorter than the instructions it covers is filled with the architecture's own NOP.</summary>
public class PatchPaddingTests
{
    private static byte[] Pad(NativeArch arch, int used, int length)
    {
        var bytes = new byte[length];
        NativeEditService.PadWithNops(CodeTestImage.Synthetic(arch, [0xC3]), bytes, used);
        return bytes;
    }

    [Fact]
    public void X86PadsWith0x90() => Assert.Equal([0, 0x90, 0x90], Pad(NativeArch.X64, 1, 3));

    [Fact]
    public void Arm64PadsWithWholeNops() => Assert.Equal([0, 0, 0, 0, 0x1F, 0x20, 0x03, 0xD5], Pad(NativeArch.Arm64, 4, 8));

    [Fact]
    public void Arm64RefusesPartialInstructions() =>
        Assert.Equal(ErrorCode.InvalidArgument, Assert.Throws<ToolError>(() => Pad(NativeArch.Arm64, 2, 8)).Code);

    [Fact]
    public void OtherArchitecturesRefusePadding() =>
        Assert.Equal(ErrorCode.Unsupported, Assert.Throws<ToolError>(() => Pad(NativeArch.Arm, 2, 4)).Code);
}
