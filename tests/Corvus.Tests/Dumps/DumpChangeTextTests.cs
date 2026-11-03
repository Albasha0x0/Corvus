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
        // Regression for 5f8b7e2b5: the file holds mov eax, 0 across its raw data end; memory changes byte 3.
        var image = RuntimeSectionFixtures.ShortRawData(_dir, is64, ".rt", [0xB8, 0, 0], [0x44, 0, 0xC3]);
        Assert.Equal("code changed: mov eax, 440000h; ret", Row(image));
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void A_range_after_the_section_start_is_decoded_from_the_section_start(bool is64)
    {
        // Regression for 5f8b7e2b5: byte 2 of mov eax, 0 changes, 2 bytes after the section start.
        var dump = Text(is64, Section(0x40), m => m[0x1002] = 0x44);
        Assert.Equal("code changed: mov eax, 4400h", Row(dump));
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void A_section_start_within_the_lead_in_limit_is_used(bool is64)
    {
        var dump = Text(is64, Section(0x500), m => m[0x1000 + MinidumpService.MaxLeadInBytes] = 0xC3);
        Assert.Equal("code changed: ret", Row(dump));
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void A_section_start_past_the_lead_in_limit_decodes_from_the_range_start(bool is64)
    {
        var dump = Text(is64, Section(0x800), m => m[0x1000 + MinidumpService.MaxLeadInBytes + 1] = 0xC3);
        Assert.Equal("code changed: ret " + CodeChangeText.FromRangeStart, Row(dump));
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void A_section_without_raw_data_is_decoded_from_its_start(bool is64)
    {
        // The file section has no raw data, so the file reads as zeros up to the range.
        var image = RuntimeSectionFixtures.NoRawData(_dir, is64, ".rt", [0, 0, 0xB8, 1, 0, 0, 0, 0xC3], true, false);
        Assert.Equal("code changed: mov eax, 1; ret", Row(image));
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void A_code_range_on_a_page_not_captured_is_unknown(bool is64)
    {
        // The section is the second one, at RVA 0x2000: page 2.
        var image = RuntimeSectionFixtures.NoRawData(_dir, is64, ".rt", [0xBB, 1, 0, 0, 0, 0xC3], true, false, [2]);
        using var service = new MinidumpService();
        var rows = service.Changes(image.DumpPath, image.ImageDir, image.ModuleName, 0, 50, CancellationToken.None).Rows;
        Assert.DoesNotContain(rows, r => r.Kind == "code");
        Assert.Contains(rows, r => r.Kind == "unknown" && r.Rva == "0x2000");
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void A_code_range_that_does_not_decode_names_the_reason(bool is64)
    {
        var dump = Text(is64, Section(0x40), m => { m[0x1010] = 0x0F; m[0x1011] = 0x04; });
        Assert.Equal("bytes changed: the bytes do not decode", Row(dump));
    }

    private static byte[] Section(int length)
    {
        var bytes = Enumerable.Repeat((byte)0x90, length).ToArray();
        byte[] head = [0xB8, 0, 0, 0, 0, 0xC3];
        head.CopyTo(bytes, 0);
        return bytes;
    }

    private RuntimeSectionImage Text(bool is64, byte[] code, Action<byte[]> change)
    {
        var spec = new PeSpec(is64, [new SectionSpec(".text", 0x60000020, code)]);
        return Dump(_dir, spec, null, change);
    }

    /// <summary>Builds a dump of one image whose mapped bytes <paramref name="changeMemory"/> edits, and its file.</summary>
    internal static RuntimeSectionImage Dump(TempDir dir, PeSpec spec, Action<byte[]>? editFile, Action<byte[]> changeMemory)
    {
        var file = RebuildFixtures.Pe(spec);
        editFile?.Invoke(file);
        var mapped = RebuildFixtures.Mapped(file);
        changeMemory(mapped);
        int nt = System.Buffers.Binary.BinaryPrimitives.ReadInt32LittleEndian(file.AsSpan(0x3C));
        uint stamp = System.Buffers.Binary.BinaryPrimitives.ReadUInt32LittleEndian(file.AsSpan(nt + 8));
        var builder = new MinidumpBuilder { ProcessorArchitecture = spec.Is64Bit ? (ushort)9 : (ushort)0 };
        builder.Modules.Add(new MinidumpBuilder.Module(spec.Base, (uint)mapped.Length, stamp, "app.exe"));
        builder.Memory.Add((spec.Base, mapped));
        string images = dir.File("image-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(images);
        File.WriteAllBytes(Path.Combine(images, "app.exe"), file);
        string path = dir.File($"text-{Guid.NewGuid():N}.dmp");
        File.WriteAllBytes(path, builder.Build());
        return new RuntimeSectionImage(path, images, 0x1000, spec.Base, "app.exe");
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
