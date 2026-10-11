using NetDecompilerMcp.Native;
using NetDecompilerMcp.Native.Providers;
using NetDecompilerMcp.Native.Providers.Ghidra;
using NetDecompilerMcp.Native.Providers.Ida;
using Xunit.Abstractions;

namespace NetDecompilerMcp.Tests;

/// <summary>The engine read views against a real Ghidra, on a copy of a system DLL analyzed once for the class.</summary>
[Trait("Speed", "Slow")]
public sealed class NativeGhidraViewTests(ITestOutputHelper output, GhidraCacheFixture shared) : IClassFixture<GhidraCacheFixture>
{
    private const string Export = "CheckSumMappedFile";
    private static readonly NativeOpenOptions Offline = new() { Symbols = SymbolMode.Off };

    private async Task<GhidraSession> Open() => (GhidraSession)await shared.Provider.OpenAsync(shared.Sample, null, Offline);

    [GhidraFact]
    public async Task Image_info_is_the_engine_view_of_the_image()
    {
        await using var s = await Open();
        var info = await s.GetEngineInfoAsync();
        output.WriteLine($"{info.Version} {info.Language} {info.Compiler} {info.Format} {info.Functions} functions, {info.ExternalFunctions} external, " +
                         $"{info.Blocks.Count} blocks, analysis {info.Analysis}");
        Assert.StartsWith("12.", info.Version);
        Assert.Equal("x86:LE:64:default", info.Language);
        Assert.Equal("windows", info.Compiler);
        Assert.Contains("Portable Executable", info.Format);
        Assert.Equal((8, "little"), (info.PointerSize, info.Endian));
        Assert.Equal(s.FunctionCount, info.Functions);
        Assert.True(info.ExternalFunctions > 10);
        Assert.Equal(AnalysisCache.HashFile(shared.Sample), info.Sha256);
        Assert.Contains(info.Blocks, b => b.Name == ".text" && b.Permissions == "r-x" && b.Initialized && b.Start == s.ImageBase + 0x1000);
        Assert.NotEmpty(info.EntryPoints);
        Assert.Contains(NativeIdaProviderTests.ExportRva(shared.Sample, Export), info.EntryPoints);
        Assert.Equal("complete", info.Analysis);
    }
}

/// <summary>The engine read views against a real IDA (idalib), on a system DLL analyzed once for the class.</summary>
[Trait("Speed", "Slow")]
public sealed class NativeIdaViewTests(ITestOutputHelper output, IdaCacheFixture shared) : IClassFixture<IdaCacheFixture>
{
    private const string Export = "CheckSumMappedFile";
    private static readonly NativeOpenOptions Offline = new() { Symbols = SymbolMode.Off };

    private async Task<IdaSession> Open() => (IdaSession)await shared.Provider.OpenAsync(NativeIdaProviderTests.System64, null, Offline);

    [IdaFact]
    public async Task Image_info_is_the_engine_view_of_the_image()
    {
        await using var s = await Open();
        var info = await s.GetEngineInfoAsync();
        output.WriteLine($"{info.Version} {info.Language} {info.Compiler} {info.Format} {info.Functions} functions, {info.ExternalFunctions} external, " +
                         $"{info.Blocks.Count} blocks, analysis {info.Analysis}");
        Assert.StartsWith("9.", info.Version);
        Assert.Equal("metapc:LE:64", info.Language);
        Assert.Equal("pe", info.Format);
        Assert.Equal((8, "little"), (info.PointerSize, info.Endian));
        Assert.True(info.Functions > 100);
        Assert.True(info.ExternalFunctions > 10);
        Assert.Equal(AnalysisCache.HashFile(NativeIdaProviderTests.System64), info.Sha256);
        Assert.Contains(info.Blocks, b => b.Name == ".text" && b.Permissions.StartsWith('r') && b.Initialized);
        Assert.Contains(NativeIdaProviderTests.ExportRva(NativeIdaProviderTests.System64, Export), info.EntryPoints);
        Assert.Equal("complete", info.Analysis);
    }
}
