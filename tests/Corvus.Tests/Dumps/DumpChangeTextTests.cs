using Corvus.Native;
using Corvus.Native.Dump;
using Corvus.Native.Dump.Rebuild;
using Corvus.Services;

namespace Corvus.Tests;

/// <summary>A changed code range that is not a jump or call is shown as instructions.</summary>
public sealed class DumpChangeTextTests : IDisposable
{
    private readonly TempDir _dir = new();

    public void Dispose() => _dir.Dispose();

    private string Row(RuntimeSectionImage image)
    {
        using var service = new MinidumpService();
        var rows = service.Changes(image.DumpPath, image.ImageDir, image.ModuleName, 0, 50, CancellationToken.None).Rows;
        return Assert.Single(rows, r => r.Kind == "code").Description ?? "";
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void A_non_transfer_code_change_shows_its_instructions(bool is64)
    {
        // The file section has no raw data; memory holds mov ebx, 1 then ret.
        var image = RuntimeSectionFixtures.NoRawData(_dir, is64, ".rt", [0xBB, 1, 0, 0, 0, 0xC3], true, false);
        Assert.Equal("code changed: mov ebx, 1; ret", Row(image));
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void A_change_inside_an_instruction_is_shown_from_its_start(bool is64)
    {
        // The file bytes are zero; the first difference is the second byte of a 2-byte instruction.
        var image = RuntimeSectionFixtures.ShortRawData(_dir, is64, ".rt", [0, 0, 0, 0], [0xB8, 0x44, 0x33, 0x22, 0x11, 0xC3]);
        var text = Row(image);
        Assert.StartsWith("code changed: mov eax, 11223344h; ret", text);
    }

    [Fact]
    public void A_changed_arm64_range_shows_its_instructions()
    {
        // mov x0, #1 then ret.
        byte[] memoryBytes = [0x20, 0x00, 0x80, 0xD2, 0xC0, 0x03, 0x5F, 0xD6];
        var builder = new MinidumpBuilder();
        builder.Memory.Add((0x10000, new byte[0x1000]));
        string path = _dir.File("arm.dmp");
        File.WriteAllBytes(path, builder.Build());
        using var memory = MinidumpFile.Open(path);
        var text = MinidumpService.CodeText(memoryBytes, new byte[memoryBytes.Length], 0x10000, NativeArch.Arm64, 0,
            memory, new ExportMap(memory));
        Assert.StartsWith("code changed: mov x0, #1", text);
        Assert.Contains("ret", text);
    }
}
