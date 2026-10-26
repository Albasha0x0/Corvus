using Corvus.Core;
using Corvus.Core.Firmware;

namespace Corvus.Tests;

/// <summary>iNES and NES 2.0 ROM images: the header, the CPU's view of PRG-ROM at power-on, and the files they unpack to.</summary>
public sealed class InesRomTests
{
    private static string Fixture => Path.Combine(AppContext.BaseDirectory, "Engines", "IsaFixtures", "nrom.nes");

    /// <summary>An iNES 1.0 header, then each 16 KiB PRG bank filled with its index and ending in that bank's vectors.</summary>
    private static byte[] Rom(int prgBanks, int chrBanks, int mapper, bool trainer = false, bool nes2 = false)
    {
        var b = new byte[16 + (trainer ? 512 : 0) + prgBanks * 0x4000 + chrBanks * 0x2000];
        "NES\x1A"u8.CopyTo(b);
        b[4] = (byte)prgBanks;
        b[5] = (byte)chrBanks;
        b[6] = (byte)((mapper & 0x0F) << 4 | (trainer ? 4 : 0) | 1);
        b[7] = (byte)(mapper & 0xF0 | (nes2 ? 8 : 0));
        if (nes2) b[8] = (byte)(mapper >> 8 | 2 << 4);
        int prg = 16 + (trainer ? 512 : 0);
        for (int i = 0; i < prgBanks; i++)
        {
            var bank = b.AsSpan(prg + i * 0x4000, 0x4000);
            bank.Fill((byte)i);
            // NMI, reset, IRQ: 0xC0N0, 0xC0N2, 0xC0N4 for bank N.
            for (int v = 0; v < 3; v++) BitConverter.GetBytes((ushort)(0xC000 | i << 4 | v * 2)).CopyTo(bank[(0x3FFA + v * 2)..]);
        }
        return b;
    }

    [Fact]
    public void An_nrom_image_mirrors_its_bank_and_names_its_vectors()
    {
        var data = File.ReadAllBytes(Fixture);
        var rom = InesRom.Read(data);
        Assert.Equal((false, 0, 16384L, 8192L, "vertical", (0, 0), false), (rom.Nes2, rom.Mapper, rom.PrgSize, rom.ChrSize, rom.Mirroring, rom.CpuBanks, rom.Switchable));
        Assert.Equal((0xC016, 0xC000, 0xC01C), (rom.Nmi, rom.Reset, rom.Irq));
        Assert.Empty(rom.Issues);
        var cpu = rom.CpuView(data);
        Assert.Equal(data.AsSpan(16, 0x4000).ToArray(), cpu[..0x4000]);
        Assert.Equal(cpu[..0x4000], cpu[0x4000..]);
        Assert.Equal("ines rom", Blob.Identify(data));
    }

    [Fact]
    public void A_switching_mapper_shows_bank_0_and_the_last_bank_and_lists_every_bank()
    {
        var data = Rom(8, 2, mapper: 1, trainer: true);
        var rom = InesRom.Read(data);
        Assert.Equal((1, (0, 7), true, 0xC072), (rom.Mapper, rom.CpuBanks, rom.Switchable, (int)rom.Reset));
        var opened = Containers.Open(data, "mmc1.nes", new AnalysisLimits(), default, allFiles: true);
        Assert.Equal(["prg-cpu.bin", .. Enumerable.Range(0, 8).Select(i => $"prg-bank-{i}.bin"), "trainer.bin", "chr-rom.bin"], opened.Items.Select(i => i.Name));
        Assert.Equal(0x8000, opened.Items[0].Bytes.Length);
        Assert.Equal(7, opened.Items[^3].Bytes[0]);
        var notes = string.Join("\n", opened.Notes);
        Assert.Contains("mapper 1, 128 KiB PRG-ROM, 16 KiB CHR-ROM, vertical mirroring", notes);
        Assert.Contains("format=raw arch=6502 base=0x8000 entry=0xC072", notes);
        Assert.Contains("the other 6 are prg-bank-N.bin", notes);
    }

    [Fact]
    public void A_32_kib_mapper_shows_the_last_32_kib_and_nes_2_reads_the_12_bit_mapper()
    {
        var rom = InesRom.Read(Rom(8, 0, mapper: 7));
        Assert.Equal(((6, 7), 0xC072), (rom.CpuBanks, (int)rom.Reset));
        var nes2 = InesRom.Read(Rom(2, 1, mapper: 0x10A, nes2: true));
        Assert.Equal((true, 0x10A, 2), (nes2.Nes2, nes2.Mapper, nes2.Submapper));
    }

    [Fact]
    public void A_cut_image_is_named_and_text_in_the_header_drops_the_high_mapper_nibble()
    {
        var data = Rom(2, 1, mapper: 0x42);
        var cut = InesRom.Read(data.AsSpan(0, 16 + 0x8000 + 100));
        Assert.Contains("inside CHR-ROM", Assert.Single(cut.Issues));
        "Ni"u8.CopyTo(data.AsSpan(12));
        Assert.Equal(2, InesRom.Read(data).Mapper);
        data[4] = 0;
        var e = Assert.Throws<ToolError>(() => Containers.Open(data, "empty.nes", new AnalysisLimits(), default, allFiles: true));
        Assert.Equal(ErrorCode.MalformedInput, e.Code);
    }

    [Fact]
    [FuzzEntry(typeof(InesRom), typeof(InesRomReader))]
    public void Fuzzed_rom_images_never_throw()
    {
        var failures = FormatFuzz.Run(Rom(4, 1, mapper: 4), b =>
        {
            try { InesRom.Read(b); } catch (InvalidDataException) { }
            try { Containers.Open(b, "fuzz.nes", new AnalysisLimits(), default, allFiles: true); }
            catch (ToolError e) when (e.Code == ErrorCode.MalformedInput) { }
        }, 300);
        Assert.Empty(failures);
    }
}
