using NetDecompilerMcp.Native.Elf;
using NetDecompilerMcp.Services.Analysis;
using NetDecompilerMcp.Native.NativeAot;
using NetDecompilerMcp.Tests.NativeFormats;

namespace NetDecompilerMcp.Tests;

/// <summary>NativeAOT module headers in ELF images: row pointers filled by RELATIVE relocations, found through symbols or the __modules list.</summary>
public class NativeAotElfTests
{
    private const uint RelativeX64 = 8;

    /// <summary>
    /// An x64 ELF whose data holds the debug header cookie, a frozen region and two module headers whose row pointers are
    /// zero in the file; the first is named by the given way, the second only a scan would find.
    /// </summary>
    private static ElfFile Image(bool symbols, bool modulesSection) => ElfFile.FromBytes(Bytes(symbols, modulesSection), "app");

    private static byte[] Bytes(bool symbols, bool modulesSection)
    {
        var data = new PeBlob(ElfWriter.DataRva);
        var relocations = new List<ElfWriter.Reloc>();
        uint modules = data.U64(0);
        uint cookie = data.Bytes("DNDH"u8);
        data.U16(5);
        data.U16(0);
        data.Align(8);
        uint region = data.Zero(32);
        uint Header()
        {
            data.Align(8);
            uint at = data.U32(NativeAotLocator.Signature);
            data.U16(16);
            data.U16(0);
            data.U32(0);
            data.U16(1);
            data.Bytes([24, 1]);
            data.U32(SectionId.FrozenObjectRegion);
            data.U32(1);
            relocations.Add(new(data.U64(0), RelativeX64, Addend: region));
            relocations.Add(new(data.U64(0), RelativeX64, Addend: region + 32));
            return at;
        }
        uint first = Header();
        Header();
        if (modulesSection) relocations.Add(new(modules, RelativeX64, Addend: first));
        var w = new ElfWriter
        {
            Machine = ElfWriter.EmX64,
            Data = data.ToArray(),
            DataSectionName = modulesSection ? "__modules" : ".data",
            Relocations = relocations,
            StaticSymbols = symbols ? [new("__ReadyToRunHeader", first, 48, Type: 1), new("DotNetRuntimeDebugHeader", cookie, 6, Type: 1)] : [],
        };
        return w.Build();
    }

    [Theory]
    [InlineData(true, false)]
    [InlineData(false, true)]
    public void ListedHeader_IsTheOneTheImageNames(bool symbols, bool modulesSection)
    {
        var image = Image(symbols, modulesSection);
        Assert.True(NativeAotLocator.HasMarkers(image));
        var aot = NativeAotImage.Open(image)!;
        var header = Assert.Single(aot.Headers);
        Assert.True(header.Relocated);
        var row = Assert.Single(header.Sections);
        Assert.Equal((SectionId.FrozenObjectRegion, 32u), (row.Id, row.Length));
        Assert.Equal(".NET 10", aot.Runtime);
        if (symbols) Assert.Equal(5, aot.DebugHeaderMajor);
    }

    [Fact]
    public void SummarizeFile_ReportsNativeAotElf()
    {
        using var dir = new TempDir();
        var path = dir.File("app");
        File.WriteAllBytes(path, Bytes(symbols: true, modulesSection: false));
        using var env = new Env();
        var summary = new InspectionService(env.Workspace).Summarize(null, path, default);
        Assert.Equal("NativeAOT executable", summary.Container);
        Assert.Contains("ReadyToRun 16.0", Assert.Single(summary.Notes, n => n.StartsWith("NativeAOT", StringComparison.Ordinal)));
        var aot = Assert.IsType<NativeAotSummary>(summary.NativeAot);
        Assert.Equal((".NET 10", 5), (aot.Runtime, aot.DebugHeaderVersion));
    }

    [Fact]
    public void UnlistedHeaders_AreScannedFor()
    {
        var image = Image(symbols: false, modulesSection: false);
        Assert.False(NativeAotLocator.HasMarkers(image));
        var aot = NativeAotImage.Open(image)!;
        Assert.Equal(2, aot.Headers.Count);
        Assert.All(aot.Headers, h => Assert.Equal(ElfWriter.DataRva + 16, h.Sections[0].StartRva)); // after the module slot and the cookie
    }
}
