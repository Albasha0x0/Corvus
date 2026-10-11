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

    [GhidraFact]
    public async Task Defined_strings_include_unreferenced_ones()
    {
        await using var s = await Open();
        var strings = await s.ListStringsAsync(100_000);
        output.WriteLine($"{strings.Count} strings; " + string.Join("; ", strings.Take(6).Select(x => $"0x{x.Rva:X} {x.Type} {x.Text}")));
        Assert.True(strings.Count > 20);
        Assert.Contains(strings, x => x.Type == "unicode" && x.Text.Length > 2);
        Assert.Contains(strings, x => x.Text == Export);
    }

    [GhidraFact]
    public async Task Namespaces_list_cpp_classes_with_functions_and_vftables_and_the_libraries()
    {
        var dll = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "System32", "msvcp_win.dll");
        if (!File.Exists(dll)) return;
        await using var s = await shared.Provider.OpenAsync(shared.Copy(dll), null, Offline);
        var list = await s.ListNamespacesAsync();
        var classes = list.Where(n => n.Kind == "class").ToList();
        output.WriteLine($"{classes.Count} classes, {list.Count(n => n.Kind == "library")} libraries; " +
                         string.Join("; ", classes.Where(c => c.Vftable != null).Take(6).Select(c => $"{c.Name} {c.Functions} 0x{c.Vftable:X}")));
        Assert.True(classes.Count > 10);
        Assert.Contains(classes, c => c.Name.StartsWith("std::", StringComparison.Ordinal) && c.Functions > 0);
        Assert.Contains(classes, c => c.Vftable != null);
        Assert.Contains(list, n => n.Kind == "library");
        Assert.Equal(list.Select(n => n.Name).Order(StringComparer.Ordinal), list.Select(n => n.Name));
    }

    [GhidraFact]
    public async Task Function_record_has_prototype_convention_storage_and_thunk_target()
    {
        await using var s = await Open();
        var rva = NativeIdaProviderTests.ExportRva(shared.Sample, Export);
        var r = await s.GetFunctionRecordAsync(rva + 2);
        output.WriteLine(string.Join("\n", NetDecompilerMcp.Tools.NativeEngineCode.RecordLines(r, x => $"0x{x:X}")));
        Assert.Equal(rva, r.Start);
        Assert.Contains(Export, r.Prototype);
        Assert.Equal("__fastcall", r.CallingConvention);
        Assert.NotNull(r.SignatureSource);
        Assert.Equal(4, r.Parameters.Count);
        Assert.Equal("RCX:8", r.Parameters[0].Storage);
        Assert.Contains(r.Ranges, x => x.Start == rva && x.End > rva);
        var thunk = (await s.ListFunctionsAsync()).First(f => f.Flags.HasFlag(NativeFunctionFlags.Thunk));
        var t = await s.GetFunctionRecordAsync(thunk.StartRva);
        output.WriteLine($"{t.Name} -> {t.ThunkTargetName}");
        Assert.NotNull(t.ThunkTargetName);
        Assert.Equal(Core.ErrorCode.NotFound, (await Assert.ThrowsAsync<Core.ToolError>(() => s.GetFunctionRecordAsync(0x10))).Code);
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

    [IdaFact]
    public async Task Defined_strings_include_unreferenced_ones()
    {
        await using var s = await Open();
        var strings = await s.ListStringsAsync(100_000);
        output.WriteLine($"{strings.Count} strings; " + string.Join("; ", strings.Take(6).Select(x => $"0x{x.Rva:X} {x.Type} {x.Text}")));
        Assert.True(strings.Count > 20);
        Assert.Contains(strings, x => x.Type == "C_16" && x.Text.Length > 2);
        Assert.Contains(strings, x => x.Type == "C" && x.Text == Export);
    }

    [IdaFact]
    public async Task Function_record_has_prototype_convention_storage_and_thunk_target()
    {
        await using var s = await Open();
        var rva = NativeIdaProviderTests.ExportRva(NativeIdaProviderTests.System64, Export);
        var r = await s.GetFunctionRecordAsync(rva + 2);
        output.WriteLine(string.Join("\n", NetDecompilerMcp.Tools.NativeEngineCode.RecordLines(r, x => $"0x{x:X}")));
        Assert.Equal(rva, r.Start);
        Assert.Contains(Export, r.Prototype);
        Assert.Contains(r.CallingConvention, new[] { "__fastcall", "__stdcall" }); // IDA keeps the x64 type library's __stdcall
        Assert.Equal(4, r.Parameters.Count);
        Assert.Equal("rcx", r.Parameters[0].Storage);
        Assert.Contains(r.Ranges, x => x.Start == rva && x.End > rva);
        var thunk = (await s.ListFunctionsAsync()).First(f => f.Flags.HasFlag(NativeFunctionFlags.Thunk));
        var t = await s.GetFunctionRecordAsync(thunk.StartRva);
        output.WriteLine($"{t.Name} -> {t.ThunkTargetName}");
        Assert.NotNull(t.ThunkTargetName);
        Assert.Equal(Core.ErrorCode.NotFound, (await Assert.ThrowsAsync<Core.ToolError>(() => s.GetFunctionRecordAsync(0x10))).Code);
    }
}