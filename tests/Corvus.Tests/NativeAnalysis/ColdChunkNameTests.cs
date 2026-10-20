using Corvus.Core;
using Corvus.Native;
using Corvus.Native.Code;
using Corvus.Services;

namespace Corvus.Tests;

/// <summary>A function whose cold block sits before its entry: addresses in the block are named with a negative offset.</summary>
public sealed class ColdChunkNameTests
{
    private const uint Code = CodeTestImage.SyntheticCodeRva;

    [Fact]
    public void An_address_before_the_entry_reads_as_a_negative_offset()
    {
        // 0x00 cold: mov eax, 1; ret    0x10 main: test ecx, ecx; jz cold; xor eax, eax; ret
        var code = new byte[0x20];
        new byte[] { 0xB8, 1, 0, 0, 0, 0xC3 }.CopyTo(code, 0);
        new byte[] { 0x85, 0xC9, 0x0F, 0x84, 0xE8, 0xFF, 0xFF, 0xFF, 0x31, 0xC0, 0xC3 }.CopyTo(code, 0x10);
        var image = CodeTestImage.Synthetic(NativeArch.X64, code, entry: Code + 0x10, exports: [new NativeExport("main", 1, Code + 0x10, null)]);
        var index = NativeCodeIndex.Build(image);
        var f = index.FunctionAt(Code + 5);
        Assert.NotNull(f);
        Assert.Equal(Code + 0x10, f.Start);
        Assert.Equal("main-0xB", Format.Within("main", f.Start, Code + 5));
        Assert.Equal("main+0x2", Format.Within("main", f.Start, Code + 0x12));
        Assert.Equal("app.exe!main-0xB", new LiveFrameName(0x1000, "app.exe", null, Code + 5, "main", -0xB, null, null).Display);
    }
}
