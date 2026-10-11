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

    [GhidraFact]
    public async Task Defined_data_lists_typed_items_with_values_and_strings()
    {
        await using var s = await Open();
        var data = await s.ListDataAsync(100_000);
        output.WriteLine($"{data.Total} items; " + string.Join("; ", data.Items.Take(8).Select(d => $"0x{d.Rva:X} {d.Size} {d.Type} {d.Label} = {d.Value}")));
        Assert.True(data.Total > 200, $"{data.Total} items");
        Assert.Equal(data.Total, data.Items.Count);
        Assert.True(data.Items.Zip(data.Items.Skip(1)).All(p => p.First.Rva < p.Second.Rva));
        Assert.Contains(data.Items, d => d.IsString && d.Value != null && d.Size > 1);
        Assert.Contains(data.Items, d => d.Label != null && d.Type.Length > 0);
        Assert.Equal(5, (await s.ListDataAsync(5)).Items.Count);
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

    [IdaFact]
    public async Task Defined_data_lists_typed_items_with_values_and_strings()
    {
        await using var s = await Open();
        var data = await s.ListDataAsync(100_000);
        output.WriteLine($"{data.Total} items; " + string.Join("; ", data.Items.Take(8).Select(d => $"0x{d.Rva:X} {d.Size} {d.Type} {d.Label} = {d.Value}")));
        Assert.True(data.Total > 200, $"{data.Total} items");
        Assert.True(data.Items.Zip(data.Items.Skip(1)).All(p => p.First.Rva < p.Second.Rva));
        Assert.Contains(data.Items, d => d.IsString && d.Value != null && d.Size > 1);
        Assert.Contains(data.Items, d => d.Label != null && d.Type.Length > 0);
        Assert.Equal(5, (await s.ListDataAsync(5)).Items.Count);
    }
}
