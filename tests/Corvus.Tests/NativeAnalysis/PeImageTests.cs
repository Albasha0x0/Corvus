using System.Buffers.Binary;
using Corvus.Core;
using Corvus.Native.Pe;
using Corvus.Services.Analysis;

namespace Corvus.Tests;

/// <summary>The light PE parser behind file identification, containers and ReadyToRun / NativeAOT detection, on crafted images.</summary>
public class PeImageTests : IDisposable
{
    private readonly TempDir _dir = new();
    private readonly AssemblyWorkspace _workspace = new(new ServerOptions());

    public void Dispose()
    {
        _workspace.Dispose();
        _dir.Dispose();
    }

    private string Save(string name, byte[] bytes)
    {
        var path = _dir.File(name);
        File.WriteAllBytes(path, bytes);
        return path;
    }

    /// <summary>A COR20 header at the start of a ".cor" section; ManagedNativeHeader points to "RTR\0" when readyToRun.</summary>
    private static PeBuilder Managed(bool readyToRun, int headerOffset = PeBuilder.PeOffset, int padSections = 0)
    {
        var b = new PeBuilder { HeaderOffset = headerOffset };
        for (int i = 0; i < padSections; i++) b.Add($".p{i}", [0xCC]);
        var cor = b.Add(".cor", rva =>
        {
            var blob = new PeBlob(rva);
            blob.U32(72);
            blob.Zero(60);
            uint native = blob.U32(0);
            blob.U32(readyToRun ? 0x48u : 0);
            blob.Patch32(native, readyToRun ? rva + 72 : 0);
            blob.Bytes("RTR\0"u8);
            blob.Zero(60);
            return blob.ToArray();
        });
        b.Directories[PeImage.ComDescriptorDirectory] = (cor.Rva, 72);
        return b;
    }

    [Fact]
    public void Large_lfanew_and_many_sections_parse_and_detection_agrees_with_full_parser()
    {
        var bytes = Managed(readyToRun: true, headerOffset: 0x2400, padSections: 120).Build();

        var pe = PeImage.TryParse(bytes);
        Assert.NotNull(pe);
        Assert.Equal(121, pe.Sections.Count);
        Assert.Empty(pe.Overlaps);
        Assert.True(pe.IsDotNet(bytes));
        Assert.True(pe.IsReadyToRun(bytes));
        Assert.True(AssemblyTraits.IsReadyToRun(bytes));
        Assert.Equal(".NET assembly", Blob.Identify(bytes));

        var full = PeFile.FromBytes(bytes);
        Assert.True(full.IsDotNet);
        Assert.Equal(pe.Sections.Count, full.Sections.Count);
    }

    [Fact]
    public void NativeAOT_images_past_old_limits_are_detected_everywhere()
    {
        var b = new PeBuilder { HeaderOffset = 0x1800 };
        for (int i = 0; i < 100; i++) b.Add($".p{i}", [0xCC]);
        b.Add(".managed", [0xC3], 0x60000020);
        var bytes = b.Build();

        Assert.Equal("NativeAOT executable", Blob.Identify(bytes));
        Assert.Equal("NativeAOT executable", Containers.Open(bytes, "app.exe", AnalysisLimits.Default, default).Kind);
        Assert.Equal("NativeAOT executable", new InspectionService(_workspace).Summarize(null, Save("app.exe", bytes), default).Container);
    }

    [Fact]
    public void Lfanew_outside_the_file_is_not_PE()
    {
        var bytes = Managed(readyToRun: false).Build();
        BinaryPrimitives.WriteInt32LittleEndian(bytes.AsSpan(0x3C), bytes.Length - 8);
        Assert.Null(PeImage.TryParse(bytes));
        BinaryPrimitives.WriteInt32LittleEndian(bytes.AsSpan(0x3C), 2); // would overlap "MZ"
        Assert.Null(PeImage.TryParse(bytes));
    }

    [Fact]
    public void Ambiguous_RVAs_of_overlapping_sections_are_reported_not_guessed()
    {
        var b = Managed(readyToRun: false, padSections: 1);
        var cor = b.Sections[1];
        // ".low" spans the page of ".cor" virtually but backs only its first 0x10 bytes from another file location.
        b.Sections[0] = new PeBuilder.Section { Name = ".low", Rva = cor.Rva - 0x1000, VirtualSize = 0x2000, Data = new byte[0x10] };
        var bytes = b.Build();

        var pe = PeImage.TryParse(bytes)!;
        Assert.Contains(pe.Overlaps, o => o.Contains("'.low'") && o.Contains("'.cor'"));
        Assert.Equal(PeImage.RvaMapping.Ambiguous, pe.MapRva(cor.Rva).Status);
        Assert.Equal(-1, pe.RvaToOffset(cor.Rva));
        Assert.Equal(PeImage.RvaMapping.Mapped, pe.MapRva(cor.Rva - 0x1000).Status);
        Assert.Equal(PeImage.RvaMapping.VirtualOnly, pe.MapRva(cor.Rva - 0x800).Status);
        Assert.False(pe.IsDotNet(bytes)); // the CLI header sits in the ambiguous range

        Assert.Contains(PeFile.FromBytes(bytes).Issues, i => i.Message.Contains("overlaps", StringComparison.Ordinal));
        Assert.Contains(new InspectionService(_workspace).Summarize(null, Save("overlap.dll", bytes), default).Notes,
            n => n.Contains("overlap", StringComparison.Ordinal) && n.Contains("ambiguous", StringComparison.Ordinal));
    }

    [Fact]
    public void Overlapping_sections_backed_by_the_same_bytes_are_not_ambiguous()
    {
        var cor = Managed(readyToRun: false).Sections[0];
        // Two headers describing the same RVA range from the same raw data.
        var twin = new PeBuilder();
        twin.Sections.Add(new PeBuilder.Section { Name = ".cor", Rva = cor.Rva, VirtualSize = cor.VirtualSize, Data = cor.Data, RawOffset = 0x400 });
        twin.Sections.Add(new PeBuilder.Section { Name = ".alias", Rva = cor.Rva, VirtualSize = cor.VirtualSize, Data = cor.Data, RawOffset = 0x400 });
        twin.Directories[PeImage.ComDescriptorDirectory] = (cor.Rva, 72);
        var aliased = twin.Build();

        var pe = PeImage.TryParse(aliased)!;
        Assert.NotEmpty(pe.Overlaps);
        Assert.Equal(PeImage.RvaMapping.Mapped, pe.MapRva(cor.Rva).Status);
        Assert.True(pe.IsDotNet(aliased));
    }
}
