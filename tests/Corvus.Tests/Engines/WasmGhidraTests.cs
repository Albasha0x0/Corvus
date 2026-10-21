using Corvus.Core;
using Corvus.Native.Providers.Ida;
using Corvus.Services;
using Corvus.Tools;

namespace Corvus.Tests;

/// <summary>engine=ghidra on a WebAssembly module: Ghidra 12.1.4 ships no WebAssembly language, so the answer is unsupported with the next step.</summary>
[Trait("Speed", "Slow")]
public sealed class WasmGhidraTests : IDisposable
{
    private readonly TempDir _dir = new();
    public void Dispose() => _dir.Dispose();

    [GhidraFact]
    public async Task Ghidra_without_a_webassembly_language_answers_unsupported_before_starting()
    {
        var options = new ServerOptions { TimeoutSeconds = 600, BackgroundIndexing = false, Engine = EngineMode.Ghidra };
        using var workspace = new AssemblyWorkspace(options);
        var code = new NativeCodeService(workspace, options, null, new Native.Annotations.AnnotationStore(_dir.File("annotations")));
        using var engines = new NativeEngineService(new IdaProviderOptions { CacheRoot = _dir.File("cache") }, code, workspace, options);
        var analysis = new NativeAnalysisTools(workspace, engines, new OutputPager(options), new NativeNamePush(code), code, new NativeTypePush(), new NativeUserTypePush(code));
        var (name, bytes) = WasmFixtures.Valid().First(m => new Corvus.Native.WasmImage(m.Bytes, m.Name).Module.Bodies.Count > 0);
        var path = _dir.File(name);
        File.WriteAllBytes(path, bytes);
        var native = workspace.LoadAny(path).Native!;
        var wasm = (Corvus.Native.WasmImage)native.Image;
        var function = wasm.FunctionNames[wasm.Module.ImportedFunctions];
        var error = await Assert.ThrowsAsync<ToolError>(() => analysis.DecompileNative(native.Id, function, engine: "ghidra"));
        Assert.Equal(ErrorCode.Unsupported, error.Code);
        Assert.Contains("has no WebAssembly language", error.Message);
        Assert.Contains("omit engine for the built-in WebAssembly lift", error.Remediation);
        Assert.Equal(0, engines.Ghidra!.WorkersStarted);
        // without engine the built-in lift answers
        Assert.Contains(function, await analysis.DecompileNative(native.Id, function));
    }
}
