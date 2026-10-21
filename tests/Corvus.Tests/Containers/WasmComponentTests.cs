using Corvus.Core;
using Corvus.Core.WebAssembly;
using Corvus.Native;
using Corvus.Services.Analysis;

namespace Corvus.Tests;

/// <summary>A WebAssembly component built here: two core modules and a nested component holding a third.</summary>
public sealed class WasmComponentTests
{
    private static readonly byte[] Header = [0x00, 0x61, 0x73, 0x6D, 0x0D, 0x00, 0x01, 0x00];
    private static readonly byte[] Small = [0x00, 0x61, 0x73, 0x6D, 0x01, 0x00, 0x00, 0x00, 0x01, 0x04, 0x01, 0x60, 0x00, 0x00];

    private static byte[] Section(byte id, byte[] body)
    {
        var size = new List<byte>();
        uint n = (uint)body.Length;
        do { byte b = (byte)(n & 0x7F); n >>= 7; size.Add(n != 0 ? (byte)(b | 0x80) : b); } while (n != 0);
        return [id, .. size, .. body];
    }

    private static byte[] Component() =>
    [
        .. Header,
        .. Section(1, WasmTests.Sample()),
        .. Section(0, [4, .. "name"u8]),
        .. Section(1, Small),
        .. Section(4, [.. Header, .. Section(1, Small)]),
    ];

    [Fact]
    public void Component_lists_its_core_modules_and_nested_ones()
    {
        var c = Containers.Open(Component(), "app.wasm", AnalysisLimits.Default, default, allFiles: true);
        Assert.Equal("wasm component", c.Kind);
        Assert.Equal(["core0.wasm", "core1.wasm", "component0/core0.wasm"], c.Items.Select(i => i.Name));
        Assert.Equal(WasmTests.Sample(), c.Items[0].Bytes);
        Assert.StartsWith("a WebAssembly component of 3 core modules: core0.wasm (", c.Notes[0]);
    }

    [Fact]
    public void Component_opens_as_its_largest_core_module()
    {
        var image = new WasmImage(Component(), "app.wasm");
        Assert.Equal("env", Assert.Single(image.Imports).Module);
        Assert.Equal("run", Assert.Single(image.Exports).Name);
        Assert.Single(image.DeclaredFunctions);
        Assert.Contains(image.Issues, i => i.Message.StartsWith("a WebAssembly component of 3 core modules: this view is core0.wasm", StringComparison.Ordinal));
        Assert.Equal(Component().Length, image.FileSize);

        using var dir = new TempDir();
        var path = dir.File("app.wasm");
        File.WriteAllBytes(path, Component());
        var view = new WasmFileView().Inspect(new FileInput(path, File.ReadAllBytes(path), "wasm"), default)!;
        Assert.Equal(1, ((WasmFileView.Facts)view.Detail).DefinedFunctions);
        Assert.StartsWith("WebAssembly component of 3 core modules", view.Highlights[0]);
    }

    [Fact]
    [FuzzEntry(typeof(WasmComponent))]
    public void Fuzzed_components_never_throw_unexpectedly()
    {
        var failures = FormatFuzz.Run(Component(), b =>
        {
            WasmComponent.CoreModules(b, []);
            try { Containers.Open(b, "x.wasm", AnalysisLimits.Default, default, allFiles: true); } catch (ToolError) { }
            try { _ = new WasmImage(b, "x.wasm"); } catch (ToolError) { }
        }, 500);
        Assert.True(failures.Count == 0, string.Join("\n", failures.Take(20)));
    }
}
