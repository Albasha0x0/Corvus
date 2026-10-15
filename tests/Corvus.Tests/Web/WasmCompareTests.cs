using Corvus.Core.WebAssembly;
using Corvus.Tools;
using Xunit.Abstractions;
using static Corvus.Core.WebAssembly.WasmType;

namespace Corvus.Tests;

/// <summary>compare_native_images on two WebAssembly builds: interface changes, functions paired by name and by body.</summary>
public sealed class WasmCompareTests(ITestOutputHelper output) : IDisposable
{
    private readonly TempDir _dir = new();
    public void Dispose() => _dir.Dispose();

    /// <summary>Build 1: env.log imported, run and helper exported, an unnamed worker; build 2 adds env.time, drops helper, widens run, edits helper's body and moves the worker.</summary>
    private static (byte[] Old, byte[] New) Builds()
    {
        static byte[] Build(bool second)
        {
            var b = new WasmModuleBuilder();
            uint v = b.Type([], []), run = b.Type(second ? [I32, I32] : [I32], [I32]);
            b.ImportFunc("env", "log", v);
            if (second) b.ImportFunc("env", "time", v);
            if (second) b.Func(v, new WasmAsm().I32(9).Op(0x1A).Bytes); // a new function first: the others move
            uint worker = b.Func(v, new WasmAsm().I32(42).Op(0x1A).Op(0x10).U(0).Bytes);
            uint helper = b.Func(v, new WasmAsm().I32(second ? 2 : 1).Op(0x1A).Bytes);
            uint main = b.Func(run, new WasmAsm().Op(0x10).U(worker).Op(0x20).U(0).Bytes);
            b.Export("run", Corvus.Core.WebAssembly.WasmExternal.Func, main);
            if (!second) b.Export("helper", Corvus.Core.WebAssembly.WasmExternal.Func, helper);
            b.Names(null, new Dictionary<int, Dictionary<uint, string>> { [1] = new() { [helper] = "helper" } });
            return b.Build();
        }
        return (Build(false), Build(true));
    }

    [Fact]
    public void Interface_and_functions_of_two_builds()
    {
        var (oldBytes, newBytes) = Builds();
        var a = new Corvus.Native.WasmImage(oldBytes, "old.wasm");
        var b = new Corvus.Native.WasmImage(newBytes, "new.wasm");
        var c = WasmInterface.Compare(a.Module, a.FunctionNames, a.NameSources, b.Module, b.FunctionNames, b.NameSources);
        Assert.Equal(["import env.time added", "export helper removed", "export run changed"], c.Interface.Select(x => $"{x.Kind} {x.Name} {x.Change}"));
        var run = c.Pairs.Single(p => p.Name == "run");
        Assert.True(run.SignatureChanged);
        var helper = c.Pairs.Single(p => p.Name == "helper");
        Assert.Equal(("name", true, false), (helper.Basis, helper.BodyChanged, helper.SignatureChanged));
        // the unnamed worker moved from function 1 to 3 with its body unchanged (its call to env.log keeps its name)
        var worker = c.Pairs.Single(p => p.Old == 1);
        Assert.Equal((3u, "identical_body", false), (worker.New, worker.Basis, worker.BodyChanged));
        Assert.Equal([1u, 2u], c.OnlyNew); // the new import env.time and the new function
    }

    [Fact]
    public async Task Two_runtime_releases_compared_through_the_tool()
    {
        using var h = new NativeToolHarness(backgroundIndexing: false);
        var tools = new NativeDiffTools(h.Workspace, h.Code);
        var old = WasmTextTests.DotnetNative("9.0.11");
        var current = WasmTextTests.DotnetNative("10.0.11");
        var summary = await tools.CompareNativeImages(old, current, view: "changed", limit: 5);
        output.WriteLine(summary);
        Assert.Contains("(WebAssembly):", summary);
        Assert.Contains("identical", summary);
        var iface = await tools.CompareNativeImages(old, current, view: "interface", limit: 30);
        Assert.Contains("export ", iface);
        output.WriteLine(iface);
    }
}
