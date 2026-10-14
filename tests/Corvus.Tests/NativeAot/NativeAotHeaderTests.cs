using System.Buffers.Binary;
using Corvus.Core;
using Corvus.Native.NativeAot;
using Corvus.Native.Pe;
using Corvus.Services.Analysis;

namespace Corvus.Tests;

public class NativeAotHeaderTests
{
    internal static NativeAotBuilder Sample(ushort major = 16)
    {
        var b = new NativeAotBuilder { Major = major };
        b.Blob(BlobId.EmbeddedMetadata, [0xFD, 0xDF, 0xAD, 0xDE, 0]);
        b.Blob(BlobId.StackTraceMethodRvaToTokenMapping, [0, 0, 0, 0, 0, 0, 0, 0]);
        b.Row(206, NativeAotBuilder.DataRva, NativeAotBuilder.DataRva + 0x40);
        b.Row(204, NativeAotBuilder.DataRva + 0x40, 0, flags: 0);
        b.Data.Zero(0x80);
        return b;
    }

    [Fact]
    public void Locator_FindsHeader_WithRowsAndVersion()
    {
        var b = Sample();
        var image = b.Image();
        var header = Assert.Single(NativeAotLocator.Find(image));
        Assert.Equal(b.HeaderRva, header.Rva);
        Assert.Equal((16, 0), (header.MajorVersion, header.MinorVersion));
        Assert.True(header.Relocated);
        Assert.Equal(".NET 10", header.Format.Runtime);
        Assert.Equal(MetadataDialect.Net10, header.Format.Metadata);
        Assert.Equal(4, header.Sections.Count);
        Assert.Equal(5u, header.Blob(BlobId.EmbeddedMetadata)!.Length);
        Assert.Equal("FrozenObjectRegion", header.Section(206)!.Name);
        Assert.False(header.Section(204)!.HasEnd);
        Assert.False(header.IsDehydrated);
    }

    [Fact]
    public void Locator_RejectsHeader_WhenRowStartsAreNotRelocated()
    {
        var b = Sample();
        b.RelocateRows = false;
        b.Pointer(b.Data, NativeAotBuilder.DataRva); // the image still has relocations, just not at the rows
        Assert.Empty(NativeAotLocator.Find(b.Image()));
    }

    [Fact]
    public void Locator_RejectsWrongShape()
    {
        var image = Sample().Image();
        var header = Assert.Single(NativeAotLocator.Find(image));
        var bytes = image.FileBytes.ToArray();
        Assert.True(image.TryRvaToFileOffset(header.Rva, out long at));
        bytes[at + 14] = 16; // row size of a 32-bit image in a 64-bit one
        Assert.Empty(NativeAotLocator.Find(Native.Pe.PeFile.FromBytes(bytes)));
        bytes[at + 14] = 24;
        bytes[at + 12] = 0; // no rows
        bytes[at + 13] = 0;
        Assert.Empty(NativeAotLocator.Find(Native.Pe.PeFile.FromBytes(bytes)));
    }

    [Theory]
    [InlineData(8, ".NET 7", true, MethodTableLayout.Net7)]
    [InlineData(9, ".NET 8", true, MethodTableLayout.Net8)]
    [InlineData(10, ".NET 9", true, MethodTableLayout.Net9)]
    [InlineData(16, ".NET 10", true, MethodTableLayout.Net9)]
    [InlineData(20, ".NET 10", false, MethodTableLayout.Net9)]
    [InlineData(31, ".NET 11 (development)", true, MethodTableLayout.Net9)]
    [InlineData(5, ".NET 7", false, MethodTableLayout.Net7)]
    public void Formats_ByHeaderMajor(int major, string runtime, bool exact, MethodTableLayout layout)
    {
        var f = NativeAotFormats.For((ushort)major);
        Assert.Equal((runtime, exact, layout), (f.Runtime, f.Exact, f.Layout));
    }

    [Fact]
    public void Locator_AndCrawlers_SurviveSectionSizesBeyondTheFile()
    {
        var bytes = Sample().Build();
        int pe = BinaryPrimitives.ReadInt32LittleEndian(bytes.AsSpan(0x3C));
        int table = pe + 24 + BinaryPrimitives.ReadUInt16LittleEndian(bytes.AsSpan(pe + 20));
        for (int at = table; bytes[at] != 0; at += 40)
        {
            BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(at + 8), 0xFFFFFF00); // VirtualSize
            BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(at + 16), 0xFFFFFF00); // SizeOfRawData
        }
        PeFile image;
        try { image = PeFile.FromBytes(bytes); }
        catch (ToolError) { return; } // refused at load: nothing for the locator to read
        NativeAotLocator.Find(image);
        NativeAotImage.Open(image);
    }

    [Fact]
    public void Formats_TokenEncodingChangesIn10()
    {
        Assert.Equal((24, 8), (NativeAotFormats.For(10).TokenShift, NativeAotFormats.For(10).RecordHandleTypeBits));
        Assert.Equal((25, 7), (NativeAotFormats.For(16).TokenShift, NativeAotFormats.For(16).RecordHandleTypeBits));
    }

    [Fact]
    public void Detection_HeaderOnly_IsNativeAot()
    {
        var bytes = Sample(10).Build(); // no .managed section, no debug header export: .NET 9+ shape
        Assert.Equal("NativeAOT executable", Blob.Identify(bytes));
        var contents = Containers.Open(bytes, "app.exe", AnalysisLimits.Default, default);
        Assert.Equal("NativeAOT executable", contents.Kind);
        Assert.Contains(".NET 9, ReadyToRun 10.0", Assert.Single(contents.Notes));
        Assert.Contains("method names present", contents.Notes[0]);
        Assert.Contains("apply automatically (list_functions, disassemble, decompile_native); get_nativeaot_info", contents.Notes[0]);
    }

    [Fact]
    public void Detection_PlainNativePe_IsNotNativeAot()
    {
        var b = new NativeAotBuilder { WithHydratedSection = false };
        b.Data.U64(0x00525452); // "RTR\0" without a header shape
        Assert.Equal("native PE", Blob.Identify(b.Build()));
    }

    [Fact]
    public void SummarizeFile_ReportsNativeAotBlock()
    {
        using var dir = new TempDir();
        var path = dir.File("app.exe");
        File.WriteAllBytes(path, Sample(9).Build());
        using var env = new Env();
        var summary = new InspectionService(env.Workspace).Summarize(null, path, default);
        Assert.Equal("NativeAOT executable", summary.Container);
        var aot = Assert.IsType<NativeAotSummary>(summary.NativeAot);
        Assert.Equal((".NET 8", "9.0", false), (aot.Runtime, aot.ReadyToRunVersion, aot.Dehydrated));
        Assert.Contains(aot.Sections, s => s.Name == "EmbeddedMetadata" && s.Size == 5);
        Assert.Equal(NativeAotStage.Complete, aot.Stages[0].Status);
    }
}
