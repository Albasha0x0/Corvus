using System.Text;
using NetDecompilerMcp.Native;
using NetDecompilerMcp.Native.Pe;
using NetDecompilerMcp.Services.Analysis;
using NetDecompilerMcp.Tests.NativeFormats;

namespace NetDecompilerMcp.Tests;

/// <summary>Packer and protector detection (never unpacking): UPX on PE and ELF, PE protector section names, entropy.</summary>
public sealed class PackerDetectionTests
{
    private static byte[] Noise(int length)
    {
        var b = new byte[length];
        new Random(3).NextBytes(b);
        return b;
    }

    /// <summary>A PE as UPX writes it: UPX0 empty on disk, UPX1 compressed, "3.96\0UPX!" with the header's version and format in the headers.</summary>
    private static byte[] UpxPe()
    {
        var b = new PeBuilder();
        b.Add("UPX0", [], 0xE0000080, virtualSize: 0x10000);
        b.Add("UPX1", Noise(0x2000), 0xE0000040);
        b.EntryPoint = b.Sections[1].Rva;
        var file = b.Build();
        var marker = Encoding.ASCII.GetBytes("3.96\0UPX!");
        marker.CopyTo(file, 0x1E0);
        file[0x1E0 + marker.Length] = 13;
        file[0x1E0 + marker.Length + 1] = 36;
        return file;
    }

    [Fact]
    public void Upx_pe_is_named_with_its_version_and_format()
    {
        var found = Assert.Single(PackerDetection.OfFile("packed.exe", UpxPe()));
        Assert.Equal("UPX", found.Name);
        Assert.Equal("packer", found.Kind);
        Assert.Contains("section names UPX0, UPX1", found.Evidence);
        Assert.Contains("UPX! pack header at file 0x1E5, UPX 3.96, win64/pe", found.Evidence);
    }

    [Fact]
    public void Upx_elf_is_named_from_l_info_and_p_info()
    {
        // l_info (checksum, UPX!, l_lsize, version 14, format 22) and p_info (progid, unpacked size, block size) at the start of the code, the stub's string after
        var text = new byte[0x400];
        var info = new byte[] { 1, 2, 3, 4, (byte)'U', (byte)'P', (byte)'X', (byte)'!', 0x34, 0x0C, 14, 22, 0, 0, 0, 0, 0x60, 0x38, 0x26, 0, 0xF0, 0x09, 0x26, 0 };
        info.CopyTo(text, 0);
        Encoding.ASCII.GetBytes("$Info: This file is packed with the UPX executable packer http://upx.sf.net $").CopyTo(text, 0x100);
        var elf = new ElfWriter { Machine = ElfWriter.EmX64, Type = 2, Base = 0x400000, Entry = ElfWriter.TextRva, Text = text, Hash = ElfWriter.HashKind.None, SectionHeaders = false };
        var found = Assert.Single(PackerDetection.OfFile("packed", elf.Build()));
        Assert.Equal("UPX", found.Name);
        Assert.Contains("(UPX! version 14, linux/amd64), p_info: unpacked size 2,504,800 bytes", found.Evidence);
        Assert.Contains("stub string", found.Evidence);
    }

    [Fact]
    public void Protector_sections_and_high_entropy_code_are_reported()
    {
        var b = new PeBuilder();
        b.Add(".text", [0xC3], 0x60000020);
        b.Add(".vmp0", new byte[0x200], 0x60000020);
        b.Add(".vmp1", new byte[0x200], 0xE0000040);
        var vmp = Assert.Single(PackerDetection.OfFile("p.dll", b.Build()));
        Assert.Equal(("VMProtect", "protector", "section names .vmp0, .vmp1"), (vmp.Name, vmp.Kind, vmp.Evidence));

        var plain = new PeBuilder();
        plain.Add(".text", Noise(0x4000), 0x60000020);
        var noisy = Assert.Single(PackerDetection.OfFile("n.dll", plain.Build()));
        Assert.Equal("suspicious", noisy.Kind);
        Assert.Contains("code section .text has entropy 7.9", noisy.Evidence);

        var ordinary = new PeBuilder();
        ordinary.Add(".text", Enumerable.Repeat((byte)0x90, 0x4000).ToArray(), 0x60000020);
        Assert.Empty(PackerDetection.OfFile("o.dll", ordinary.Build()));
    }

    /// <summary>A raw size past the end of the file: the entropy is the file's bytes, not gigabytes of zero fill read and counted.</summary>
    [Fact]
    public void Entropy_covers_the_bytes_in_the_file_only()
    {
        var b = new PeBuilder();
        var text = b.Add(".text", Noise(0x4000), 0x60000020, virtualSize: 0x7FFF0000);
        text.RawOffset = 0x400;
        text.RawSize = 0x7FFF0000;
        var noisy = Assert.Single(PackerDetection.OfFile("huge.dll", b.Build()));
        Assert.Contains("code section .text has entropy 7.9", noisy.Evidence);
        Assert.Contains("over 16,384 bytes", noisy.Evidence);
    }

    [Fact]
    public async Task Get_pe_info_and_summarize_file_report_it()
    {
        using var dir = new TempDir();
        var path = dir.File("packed.exe");
        File.WriteAllBytes(path, UpxPe());
        using var h = new NativeToolHarness(backgroundIndexing: false);
        Assert.Contains("Packed: UPX (packer): section names UPX0, UPX1; UPX! pack header", await h.Native.GetPeInfo(path));
        var summary = new InspectionService(new Core.AssemblyWorkspace(new Core.ServerOptions())).Summarize(null, path, CancellationToken.None);
        Assert.Contains(summary.Highlights, l => l.StartsWith("Packed with UPX (packer): section names UPX0, UPX1", StringComparison.Ordinal));
        Assert.Equal("UPX", Assert.Single(summary.Packers!).Name);
    }
}
