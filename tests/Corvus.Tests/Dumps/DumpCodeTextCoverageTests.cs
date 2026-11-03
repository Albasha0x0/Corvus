using System.Buffers.Binary;
using Corvus.Services;

namespace Corvus.Tests;

/// <summary>The changes view shows changed code as text only where it read both sides.</summary>
public sealed class DumpCodeTextCoverageTests : IDisposable
{
    private const ushort Arm64Machine = 0xAA64;
    private const uint AddX0X0Imm1 = 0x91000400;
    private const uint AddX0X0Imm2 = 0x91000800;
    private const uint Nop = 0xD503201F;
    private const uint Ret = 0xD65F03C0;
    private readonly TempDir _dir = new();

    public void Dispose() => _dir.Dispose();

    private static byte[] Tail(int length) => Enumerable.Repeat((byte)0x90, length).ToArray();

    private static IReadOnlyList<MinidumpService.ModuleChange> Rows(string dump, string folder, string module)
    {
        using var service = new MinidumpService();
        return service.Changes(dump, folder, module, 0, 100, CancellationToken.None).Rows;
    }

    // Page index (RVA / 4 KB) of the second page of the section under test.
    private static int SecondPage(RuntimeSectionImage probe) => (int)(probe.SectionRva / 0x1000) + 1;

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void A_code_row_on_a_page_not_captured_is_unknown_with_its_reason_for_a_section_with_no_raw_data(bool is64)
    {
        var probe = RuntimeSectionFixtures.NoRawData(_dir, is64, ".rt", Tail(0x2000), true, false);
        var image = RuntimeSectionFixtures.NoRawData(_dir, is64, ".rt", Tail(0x2000), true, false, [SecondPage(probe)]);

        var rows = Rows(image.DumpPath, image.ImageDir, image.ModuleName);

        AssertUncaptured(rows, image.Base + (ulong)(SecondPage(probe) * 0x1000));
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void A_code_row_on_a_page_not_captured_is_unknown_with_its_reason_for_a_section_with_short_raw_data(bool is64)
    {
        var probe = RuntimeSectionFixtures.ShortRawData(_dir, is64, ".rt", [0x55, 0xC3], Tail(0x2000));
        var image = RuntimeSectionFixtures.ShortRawData(_dir, is64, ".rt", [0x55, 0xC3], Tail(0x2000),
            uncapturedPages: [SecondPage(probe)]);

        var rows = Rows(image.DumpPath, image.ImageDir, image.ModuleName);

        AssertUncaptured(rows, image.Base + (ulong)(SecondPage(probe) * 0x1000));
    }

    private static void AssertUncaptured(IReadOnlyList<MinidumpService.ModuleChange> rows, ulong page)
    {
        // The section row spans the whole run and counts the bytes not captured.
        bool Covers(MinidumpService.ModuleChange r) => r.Kind != "section"
            && Convert.ToUInt64(r.Start, 16) <= page && page < Convert.ToUInt64(r.Start, 16) + (ulong)r.Length;
        var row = Assert.Single(rows, Covers);
        Assert.Equal("unknown", row.Kind);
        Assert.Contains("not captured", row.Description);
        Assert.DoesNotContain("code changed", row.Description);
    }

    // An ARM64 image: the machine field of an x64 image set to ARM64, with instruction words as code.
    private (string Dump, string Folder) Arm64(int rawSize, int offset, uint before, uint after)
    {
        var words = new byte[Math.Max(0x400, offset + 0x100)];
        for (int i = 0; i < words.Length; i += 4) BinaryPrimitives.WriteUInt32LittleEndian(words.AsSpan(i), Nop);
        BinaryPrimitives.WriteUInt32LittleEndian(words.AsSpan(offset), before);
        var spec = new PeSpec(true, [new SectionSpec(".text", 0x60000020, words)]);
        var file = RebuildFixtures.Pe(spec);
        int nt = BinaryPrimitives.ReadInt32LittleEndian(file.AsSpan(0x3C));
        BinaryPrimitives.WriteUInt16LittleEndian(file.AsSpan(nt + 4), Arm64Machine);
        var text = PointerTableFixtures.Sections(file).First(s => s.Name == ".text");
        if (rawSize < words.Length)
        {
            // Raw data ends before the changed word; the file holds zeros there.
            BinaryPrimitives.WriteUInt32LittleEndian(file.AsSpan(text.Header + 16), (uint)rawSize);
        }
        var mapped = RebuildFixtures.Mapped(file);
        BinaryPrimitives.WriteUInt32LittleEndian(mapped.AsSpan((int)text.Rva + offset), after);

        string folder = Directory.CreateDirectory(_dir.File($"arm64-{Guid.NewGuid():N}")).FullName;
        File.WriteAllBytes(Path.Combine(folder, "app.dll"), file);
        uint stamp = BinaryPrimitives.ReadUInt32LittleEndian(file.AsSpan(nt + 8));
        var builder = new MinidumpBuilder { ProcessorArchitecture = 12 };
        builder.Modules.Add(new MinidumpBuilder.Module(spec.Base, (uint)mapped.Length, stamp, "app.dll"));
        builder.Memory.Add((spec.Base, mapped));
        string dump = _dir.File($"arm64-{Guid.NewGuid():N}.dmp");
        File.WriteAllBytes(dump, builder.Build());
        return (dump, folder);
    }

    [Fact]
    public void A_changed_arm64_instruction_is_shown_as_text_through_a_dump()
    {
        var (dump, folder) = Arm64(0x400, 0x20, Nop, Ret);

        var rows = Rows(dump, folder, "app.dll");

        var row = Assert.Single(rows, r => r.Kind == "code");
        Assert.StartsWith("code changed: ret", row.Description);
    }

    [Fact]
    public void An_arm64_instruction_written_past_the_raw_data_is_shown_as_text_through_a_dump()
    {
        var (dump, folder) = Arm64(0x200, 0x300, 0, Ret);

        var rows = Rows(dump, folder, "app.dll");

        var row = Assert.Single(rows, r => r.Kind == "code");
        Assert.StartsWith("code changed: ret", row.Description);
    }

    [Fact]
    public void An_arm64_change_shorter_than_one_instruction_is_shown_as_text_through_a_dump()
    {
        var (dump, folder) = Arm64(0x400, 0x20, AddX0X0Imm1, AddX0X0Imm2);

        var rows = Rows(dump, folder, "app.dll");

        var row = Assert.Single(rows, r => r.Kind == "code");
        Assert.StartsWith("code changed: add", row.Description);
        Assert.Contains("#2", row.Description);
    }

    [Fact]
    public void An_arm64_change_past_the_lead_in_limit_is_decoded_from_its_word()
    {
        // The section start lies farther back than MaxLeadInBytes.
        var (dump, folder) = Arm64(0x1000, 0x900, AddX0X0Imm1, AddX0X0Imm2);

        var rows = Rows(dump, folder, "app.dll");

        var row = Assert.Single(rows, r => r.Kind == "code");
        Assert.StartsWith("code changed: add", row.Description);
        Assert.Contains("#2", row.Description);
    }
}
