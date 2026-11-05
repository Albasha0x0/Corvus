using System.Text;
using Corvus.Core;
using Corvus.Native;
using Corvus.Native.Pe;
using Corvus.Services.Analysis;
using Corvus.Tests.NativeFormats;

namespace Corvus.Tests;

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
        Assert.Equal("packing tool", found.Kind);
        Assert.Contains("section names UPX0, UPX1", found.Evidence);
        Assert.Contains("UPX! pack header at file 0x1E5, UPX 3.96, win64/pe", found.Evidence);
    }

    [Fact]
    public void Upx_elf_is_named_from_l_info_and_p_info()
    {
        // l_info (checksum, UPX!, l_lsize, version 14, format 22) and p_info (progid, unpacked size, block size) at the start of the code, the stub's string after.
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
        Assert.Equal(("VMProtect", "hardening tool", "section names .vmp0, .vmp1"), (vmp.Name, vmp.Kind, vmp.Evidence));

        var plain = new PeBuilder();
        plain.Add(".text", Noise(0x4000), 0x60000020);
        var noisy = Assert.Single(PackerDetection.OfFile("n.dll", plain.Build()));
        Assert.Equal("suspicious", noisy.Kind);
        Assert.Contains("code section .text has entropy 7.9", noisy.Evidence);
        Assert.Equal(("info", "packer/hardening-tool"), (FindingRules.ToFinding(vmp).Level, vmp.Rule));
        Assert.Equal(("review", "packer/high-entropy-code"), (FindingRules.ToFinding(noisy).Level, noisy.Rule));

        var ordinary = new PeBuilder();
        ordinary.Add(".text", Enumerable.Repeat((byte)0x90, 0x4000).ToArray(), 0x60000020);
        Assert.Empty(PackerDetection.OfFile("o.dll", ordinary.Build()));
    }

    private static byte[] ExportingDll(params string[] exports) => ExportingDllWith(null, exports);

    private static byte[] ExportingDllWith(string? extraSection, params string[] exports) =>
        ExportingDllCode(Enumerable.Repeat((byte)0x90, 0x400).ToArray(), extraSection, exports);

    private static byte[] ExportingDllCode(byte[] code, string? extraSection, params string[] exports)
    {
        var b = new PeBuilder();
        var text = b.Add(".text", code, 0x60000020);
        b.EntryPoint = text.Rva;
        if (extraSection != null) b.Add(extraSection, new byte[0x200], 0x60000020);
        uint table = 0, tableSize = 0;
        b.Add(".rdata", rva =>
        {
            var blob = new PeBlob(rva);
            table = blob.Zero(40);
            uint dll = blob.Ascii("sdk.dll");
            blob.Align(4);
            uint eat = blob.U32(text.Rva);
            for (int i = 1; i < exports.Length; i++) blob.U32(text.Rva);
            var nameRvas = exports.Select(blob.Ascii).ToList();
            blob.Align(4);
            uint names = blob.U32(nameRvas[0]);
            foreach (var n in nameRvas.Skip(1)) blob.U32(n);
            uint ordinals = blob.U16(0);
            for (int i = 1; i < exports.Length; i++) blob.U16((ushort)i);
            blob.Patch32(table + 12, dll);
            blob.Patch32(table + 16, 1);
            blob.Patch32(table + 20, (uint)exports.Length);
            blob.Patch32(table + 24, (uint)exports.Length);
            blob.Patch32(table + 28, eat);
            blob.Patch32(table + 32, names);
            blob.Patch32(table + 36, ordinals);
            tableSize = blob.Here - table;
            return blob.ToArray();
        });
        b.Directories[PeDirectory.Export] = (table, tableSize);
        return b.Build();
    }

    [Fact]
    public void A_protector_sdk_module_is_named_from_its_export_sets()
    {
        var found = Assert.Single(PackerDetection.OfFile("sdk.dll", ExportingDll("VMStart", "VMEnd", "CustomVM00", "CustomVM01", "SECheckDebugger")));
        Assert.Equal(("Themida", "SDK stub"), (found.Name, found.Kind));
        Assert.StartsWith("SDK exports VMStart, VMEnd, 2 CustomVM*, 1 SECheck*; 1,024 bytes of code, entropy 0.00", found.Evidence);
        Assert.Equal("packer/hardening-tool", found.Rule);
    }

    [Fact]
    public void Sdk_exports_over_large_code_stay_a_hardening_tool()
    {
        var found = Assert.Single(PackerDetection.OfFile("sdk.dll", ExportingDllCode(Noise(0x4000), null, "VMStart", "VMEnd", "SECheckDebugger")));
        Assert.Equal("hardening tool", found.Kind);
    }

    [Fact]
    public void Sdk_exports_over_small_high_entropy_code_stay_a_hardening_tool()
    {
        var found = Assert.Single(PackerDetection.OfFile("sdk.dll", ExportingDllCode(Noise(0x400), null, "VMStart", "VMEnd", "SECheckDebugger")));
        Assert.Equal("hardening tool", found.Kind);
    }

    [Fact]
    public async Task Get_pe_info_names_a_protector_sdk_stub()
    {
        using var dir = new TempDir();
        var path = dir.File("sdk.dll");
        File.WriteAllBytes(path, ExportingDll("VMStart", "VMEnd", "SECheckDebugger"));
        using var h = new NativeToolHarness(backgroundIndexing: false);
        var text = await h.Native.GetPeInfo(path);
        Assert.Contains("SDK stub: Themida: SDK exports", text);
        Assert.DoesNotContain("Packed: Themida", text);
    }

    [Fact]
    public void Two_export_groups_name_a_protector_sdk_module()
    {
        var found = Assert.Single(PackerDetection.OfFile("sdk.dll", ExportingDll("CustomVM1", "SECheckDebugger")));
        Assert.StartsWith("SDK exports 1 CustomVM*, 1 SECheck*", found.Evidence);
    }

    [Fact]
    public void A_protector_section_and_sdk_exports_report_one_finding()
    {
        var found = Assert.Single(PackerDetection.OfFile("sdk.dll", ExportingDllWith(".themida", "VMStart", "VMEnd", "SECheckDebugger")));
        Assert.StartsWith("section names", found.Evidence);
    }

    [Fact]
    public void A_truncated_export_table_reports_no_exception()
    {
        var bytes = ExportingDll("VMStart", "VMEnd", "SECheckDebugger");
        var cut = PackerDetection.OfFile("sdk.dll", bytes[..(bytes.Length - 40)]);
        Assert.True(cut.Count <= 1);
    }

    [Fact]
    public void Summarize_file_lists_a_protector_sdk_module()
    {
        var path = Path.Combine(Path.GetTempPath(), "sdk-" + Guid.NewGuid().ToString("N") + ".dll");
        File.WriteAllBytes(path, ExportingDll("VMStart", "VMEnd", "SECheckDebugger"));
        try
        {
            var summary = new InspectionService(new AssemblyWorkspace()).Summarize(null, path, default);
            var facts = Assert.IsType<NativeFileView.Facts>(summary.Views["native"].Detail);
            Assert.Contains(facts.Packers!, p => p.Name == "Themida");
        }
        finally { File.Delete(path); }
    }

    [Fact]
    public void A_single_matching_export_is_not_a_protector_sdk()
    {
        Assert.Empty(PackerDetection.OfFile("lib.dll", ExportingDll("VMStart", "Other")));
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
        Assert.Contains("Packed: UPX (packing tool): section names UPX0, UPX1; UPX! pack header", await h.Native.GetPeInfo(path));
        var summary = new InspectionService(new Core.AssemblyWorkspace(new Core.ServerOptions())).Summarize(null, path, CancellationToken.None);
        Assert.Contains(summary.Highlights, l => l.StartsWith("Packed with UPX (packing tool): section names UPX0, UPX1", StringComparison.Ordinal));
        Assert.Equal("UPX", Assert.Single(summary.Packers!).Name);
    }
}
