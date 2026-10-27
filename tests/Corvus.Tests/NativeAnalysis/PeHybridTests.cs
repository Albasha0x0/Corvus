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
    internal static byte[] Hybrid(ushort machine, byte[]? text = null)
    {
        var b = new PeBuilder { Machine = machine, ImageBase = Base, EntryPoint = 0x1000 };
        b.Add(".text", text ?? new byte[0x100], 0x60000020);
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
            // Version 1, then symbol 6 (ARM64X) and one block over the headers: machine (2 bytes), entry point and export RVA (4 bytes each).
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
    public void Code_of_the_other_instruction_set_is_decoded_as_that_set()
    {
        // ARM64 at 0x1000: bl 0x10C0; ret. x64 at 0x10C0: mov eax, 1; ret
        var text = new byte[0x100];
        BinaryPrimitives.WriteUInt32LittleEndian(text, 0x94000030);
        BinaryPrimitives.WriteUInt32LittleEndian(text.AsSpan(4), 0xD65F03C0);
        new byte[] { 0xB8, 1, 0, 0, 0, 0xC3 }.CopyTo(text, 0xC0);
        var image = PeFile.FromBytes(Hybrid(0xAA64, text), "hybrid.dll");
        Assert.Equal([(0x10C0u, 0x1100u)], Native.Code.ImageCode.OtherInstructionSet(image));
        var index = Native.Code.NativeCodeIndex.Build(image);
        Assert.Equal([0x1000u, 0x10C0u], index.Functions.Select(f => f.Start));
        Assert.All(index.Functions, f => Assert.Equal(0, (int)(f.Flags & Native.Code.FunctionFlags.InvalidCode)));
        Assert.Equal(2, index.FunctionByStart(0x10C0)!.InstructionCount);
        Assert.Equal(2, Native.Calls.Arm64Trace.For(index).Code(index.FunctionByStart(0x1000)!, default).Blocks.Sum(b => b.Length));
        var lines = index.CreateDisassembler().Disassemble(0x1000, 2).Concat(index.CreateDisassembler().Disassemble(0x10C0, 2)).Select(l => l.Text.Replace("  ", " ")).ToList();
        Assert.StartsWith("bl", lines[0]);
        Assert.Equal(["mov eax, 1", "ret"], lines[2..].Select(l => string.Join(' ', l.Split(' ', StringSplitOptions.RemoveEmptyEntries))));
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
