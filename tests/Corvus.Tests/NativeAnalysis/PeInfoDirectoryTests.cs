using Corvus.Native.Pe;

namespace Corvus.Tests;

/// <summary>get_pe_info: SafeSEH on 64-bit images, relocation sections the directory skips, the exception table's section.</summary>
public sealed class PeInfoDirectoryTests
{
    private static byte[] Blocks(int entries)
    {
        var bytes = new List<byte>();
        for (int page = 0; entries > 0; page++)
        {
            int n = Math.Min(entries, 0x200);
            bytes.AddRange(BitConverter.GetBytes((uint)(page * 0x1000)));
            bytes.AddRange(BitConverter.GetBytes((uint)(8 + n * 2)));
            for (int i = 0; i < n; i++) bytes.AddRange(BitConverter.GetBytes((ushort)(0xA000 | i)));
            entries -= n;
        }
        return [.. bytes];
    }

    private static async Task<string> PeInfo(PeBuilder b)
    {
        using var dir = new TempDir();
        var path = dir.File("image.dll");
        File.WriteAllBytes(path, b.Build());
        using var h = new NativeToolHarness(backgroundIndexing: false);
        return await h.Native.GetPeInfo(path);
    }

    [Fact]
    public async Task A_64_bit_image_lists_no_SafeSEH()
    {
        var b = new PeBuilder();
        b.EntryPoint = b.Add(".text", [0xC3], 0x60000020).Rva;
        var text = await PeInfo(b);
        Assert.DoesNotContain("SafeSEH", text);
    }

    [Fact]
    public async Task SafeSEH_stays_off_on_a_32_bit_image_without_a_handler_table()
    {
        var b = new PeBuilder { Is64 = false, Machine = 0x14C };
        b.EntryPoint = b.Add(".text", [0xC3], 0x60000020).Rva;
        var text = await PeInfo(b);
        Assert.Matches("off: [^\n]*SafeSEH", text);
    }

    [Fact]
    public async Task A_reloc_section_the_directory_does_not_point_at_is_named_with_its_entries()
    {
        var b = new PeBuilder();
        b.EntryPoint = b.Add(".text", [0xC3], 0x60000020).Rva;
        var orphan = b.Add(".reloc", Blocks(1000), 0x42000040);
        var other = b.Add(".data", new byte[0x100], 0xC0000040);
        b.Directories[PeDirectory.BaseRelocation] = (other.Rva, 0);
        Assert.Contains($"Relocations: section .reloc (rva 0x{orphan.Rva:X}) holds 1000 entries, but the base relocation directory does not point at it", await PeInfo(b));
    }

    [Fact]
    public async Task A_reloc_section_the_directory_points_at_is_not_reported()
    {
        var b = new PeBuilder();
        b.EntryPoint = b.Add(".text", [0xC3], 0x60000020).Rva;
        var reloc = b.Add(".reloc", Blocks(100), 0x42000040);
        b.Directories[PeDirectory.BaseRelocation] = (reloc.Rva, (uint)reloc.Data.Length);
        Assert.DoesNotContain("Relocations: section", await PeInfo(b));
    }

    [Fact]
    public async Task An_exception_table_outside_pdata_names_its_section()
    {
        var b = new PeBuilder();
        b.EntryPoint = b.Add(".text", [0xC3], 0x60000020).Rva;
        var table = b.Add(".prot", new byte[24], 0x40000040);
        Assert.Contains("section .prot (not .pdata)", await PeInfo(WithTable(b, table, 12)));
    }

    [Fact]
    public async Task An_exception_table_in_pdata_adds_no_section_note()
    {
        var b = new PeBuilder();
        b.EntryPoint = b.Add(".text", [0xC3], 0x60000020).Rva;
        var table = b.Add(".pdata", new byte[24], 0x40000040);
        var text = await PeInfo(WithTable(b, table, 12));
        Assert.Contains("Exception directory: 1 function range", text);
        Assert.DoesNotContain("not .pdata", text);
    }

    // One runtime function: begin, end and unwind RVAs.
    private static PeBuilder WithTable(PeBuilder b, PeBuilder.Section table, uint size)
    {
        var code = b.Sections[0].Rva;
        BitConverter.GetBytes(code).CopyTo(table.Data, 0);
        BitConverter.GetBytes(code + 1).CopyTo(table.Data, 4);
        BitConverter.GetBytes(code).CopyTo(table.Data, 8);
        b.Directories[PeDirectory.Exception] = (table.Rva, size);
        return b;
    }
}
