using System.Buffers.Binary;
using Corvus.Native;
using Corvus.Native.Pe;

namespace Corvus.Tests;

/// <summary>ARM64X and ARM64EC images: CHPE metadata, the code map and the x64 view the ARM64X dynamic relocations describe.</summary>
public sealed class PeHybridTests
{
    private const ulong Base = 0x180000000;

    /// <summary>
    /// A hybrid image: .text, and .rdata holding the load configuration (CHPE pointer, dynamic relocation table offset and section), the
    /// CHPE metadata (code map of an ARM64, an ARM64EC and an x64 range; alternate entry point; auxiliary IAT) and, for ARM64X, the ARM64X
    /// relocations that make the x64 view: machine AMD64, entry point 0x1040, a replaced export directory.
    /// </summary>
    internal static byte[] Hybrid(ushort machine)
    {
        var b = new PeBuilder { Machine = machine, ImageBase = Base, EntryPoint = 0x1000 };
        b.Add(".text", new byte[0x100], 0x60000020);
        var rdata = new byte[0x400];
        const uint RdataRva = 0x2000, Lc = 0, Meta = 0x140, Map = 0x1C0, Table = 0x200;
        BinaryPrimitives.WriteUInt32LittleEndian(rdata.AsSpan((int)Lc), 0x140);
        BinaryPrimitives.WriteUInt64LittleEndian(rdata.AsSpan((int)Lc + 200), Base + RdataRva + Meta);
        BinaryPrimitives.WriteUInt32LittleEndian(rdata.AsSpan((int)Lc + 224), Table);
        BinaryPrimitives.WriteUInt16LittleEndian(rdata.AsSpan((int)Lc + 228), 2);
        void U32(uint at, uint v) => BinaryPrimitives.WriteUInt32LittleEndian(rdata.AsSpan((int)at), v);
        U32(Meta, 2); U32(Meta + 4, RdataRva + Map); U32(Meta + 8, 3); U32(Meta + 40, 0x1080); U32(Meta + 44, RdataRva + 0x300);
        U32(Map, 0x1000 | 0); U32(Map + 4, 0x40);
        U32(Map + 8, 0x1040 | 1); U32(Map + 12, 0x80);
        U32(Map + 16, 0x10C0 | 2); U32(Map + 20, 0x40);
        if (machine == 0xAA64)
        {
            // version 1, then symbol 6 (ARM64X) and one block over the headers: machine (2 bytes), entry point and export RVA (4 bytes each)
            var block = new List<byte>();
            void Entry(uint offset, int log2, ulong value)
            {
                block.AddRange(BitConverter.GetBytes((ushort)((log2 << 14) | (1 << 12) | (int)offset)));
                block.AddRange(BitConverter.GetBytes(value).Take(1 << log2));
            }
            Entry(PeBuilder.PeOffset + 4, 1, 0x8664);
            Entry(PeBuilder.PeOffset + 24 + 16, 2, 0x1040);
            Entry(PeBuilder.PeOffset + 24 + 112, 2, 0x2380);
            while (block.Count % 4 != 0) block.Add(0);
            uint blockSize = 8 + (uint)block.Count;
            U32(Table, 1); U32(Table + 4, 12 + blockSize);
            BinaryPrimitives.WriteUInt64LittleEndian(rdata.AsSpan((int)Table + 8), 6);
            U32(Table + 16, blockSize);
            U32(Table + 20, 0); U32(Table + 24, blockSize);
            block.ToArray().CopyTo(rdata, (int)Table + 28);
        }
        b.Add(".rdata", rdata);
        b.Directories[PeDirectory.LoadConfig] = (RdataRva + Lc, 0x140);
        return b.Build();
    }

    [Fact]
    public void Arm64x_reports_the_code_map_and_its_x64_view()
    {
        var pe = PeFile.FromBytes(Hybrid(0xAA64), "hybrid.dll");
        var h = Assert.IsType<PeHybrid>(PeHybrid.Of(pe));
        Assert.Equal("ARM64X", h.Kind);
        Assert.Equal(2u, h.MetadataVersion);
        Assert.Equal(["ARM64", "ARM64EC", "x64"], h.CodeRanges.Select(r => r.Arch));
        Assert.Equal(0x1040u, h.CodeRanges[1].Rva);
        Assert.Equal((0x1080u, 0x2300u), (h.AlternateEntryRva!.Value, h.AuxiliaryIatRva!.Value));
        Assert.Equal((3, "AMD64", 0x1040u), (h.Arm64XFixups, h.ViewMachine, h.ViewEntryRva!.Value));
        Assert.Equal(["export"], h.ViewDirectories);
        Assert.StartsWith("ARM64X executable", pe.KindText());
    }

    [Fact]
    public void Arm64ec_is_an_x64_image_with_chpe_metadata()
    {
        var pe = PeFile.FromBytes(Hybrid(0x8664), "ec.dll");
        var h = Assert.IsType<PeHybrid>(PeHybrid.Of(pe));
        Assert.Equal("ARM64EC", h.Kind);
        Assert.Null(h.ViewMachine);
        Assert.Equal(3, h.CodeRanges.Count);
        Assert.Null(PeHybrid.Of(PeFile.FromBytes(new PeBuilder { Machine = 0xAA64 }.Build())));
    }

    [Fact]
    public void Code_of_the_other_instruction_set_is_not_decoded()
    {
        var arm = new Native.Code.ImageCode(PeFile.FromBytes(Hybrid(0xAA64), "hybrid.dll"));
        Assert.Equal((true, true, false), (arm.IsCode(0x1000), arm.IsCode(0x1040), arm.IsCode(0x10C0)));
        Assert.Equal(-1, arm.BitIndex(0x10C0));
        var x64 = new Native.Code.ImageCode(PeFile.FromBytes(Hybrid(0x8664), "ec.dll"));
        Assert.Equal((false, false, true), (x64.IsCode(0x1000), x64.IsCode(0x1040), x64.IsCode(0x10C0)));
    }

    [Fact]
    public async Task Get_pe_info_names_the_hybrid()
    {
        using var dir = new TempDir();
        var path = dir.File("hybrid.dll");
        File.WriteAllBytes(path, Hybrid(0xAA64));
        using var h = new NativeToolHarness(backgroundIndexing: false);
        var text = await h.Native.GetPeInfo(path);
        Assert.Contains("ARM64X: ARM64 code and ARM64EC / x64 code in one file; this is the ARM64 view; the x64 view (3 ARM64X fixups): machine AMD64, entry point 0x180001040, its own export directories", text);
        Assert.Contains("CHPE metadata version 2: code map of 3 ranges (ARM64 64 bytes, ARM64EC 128 bytes, x64 64 bytes), alternate entry point 0x180001080", text);
    }
}
