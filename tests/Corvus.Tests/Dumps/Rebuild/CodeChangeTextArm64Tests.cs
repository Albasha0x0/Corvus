using Corvus.Native;
using Corvus.Native.Dump.Rebuild;

namespace Corvus.Tests;

/// <summary>A changed ARM64 code range is shown as instructions from a four-byte boundary.</summary>
public sealed class CodeChangeTextArm64Tests
{
    private const ulong Base = 0x180001000;

    private static string? Names(ulong address) => address == Base + 0x20 ? "target_fn" : null;

    private static byte[] Words(params uint[] words)
    {
        var bytes = new byte[words.Length * 4];
        for (int i = 0; i < words.Length; i++)
            System.Buffers.Binary.BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(i * 4), words[i]);
        return bytes;
    }

    [Fact]
    public void An_arm64_change_is_decoded_from_its_four_byte_boundary()
    {
        // add x0, x0, #1 becomes add x0, x0, #2: the first differing byte is mid-word.
        var file = Words(0xD503201F, 0x91000400, 0xD503201F);
        var memory = Words(0xD503201F, 0x91000800, 0xD503201F);
        var text = CodeChangeText.Describe(memory, file, Base, NativeArch.Arm64, -1, Names);
        Assert.NotNull(text);
        Assert.StartsWith("add", text);
        Assert.Contains("#2", text);
        Assert.DoesNotContain(CodeChangeText.FromRangeStart, text);
    }
    [Fact]
    public void An_arm64_branch_target_is_named()
    {
        // bl +0x20 from the changed word at Base.
        var file = Words(0xD503201F, 0xD503201F);
        var memory = Words(0x94000008, 0xD503201F);
        var text = CodeChangeText.Describe(memory, file, Base, NativeArch.Arm64, -1, Names);
        Assert.Contains("target_fn", text);
        Assert.StartsWith("bl", text);
    }
}