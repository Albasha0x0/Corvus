using Corvus.Core;
using Corvus.Native;
using Corvus.Native.Annotations;
using Corvus.Native.Calls;
using Corvus.Native.Code;
using Corvus.Native.Pe;
using Corvus.Native.Providers.Ida;
using Corvus.Services;
using Corvus.Tests.NativeFormats;
using Corvus.Tools;
using Xunit.Abstractions;

namespace Corvus.Tests;

/// <summary>Unwind frames, ARM64 call sites, the dossier, call paths and feature traces on real images and a real engine.</summary>
public sealed class NativeIntrospectionRealTests(ITestOutputHelper output) : IDisposable
{
    private readonly TempDir _dir = new();
    private readonly List<IDisposable> _owned = [];

    public void Dispose()
    {
        foreach (var d in _owned) d.Dispose();
        _dir.Dispose();
    }

    [Trait("Speed", "Slow")]
    [Fact]
    public async Task Arm64_pe_unwind_data_call_sites_and_dossier()
    {
        var path = NativeFixtures.WinArm64DbgShim;
        var pe = PeFile.Open(path);
        int read = pe.RuntimeFunctions.Count(f => UnwindFrames.Of(pe, f.BeginRva) != null);
        output.WriteLine($"{read} of {pe.RuntimeFunctions.Count} unwind records read");
        Assert.True(read >= pe.RuntimeFunctions.Count * 95 / 100, $"{read} of {pe.RuntimeFunctions.Count}");

        var index = NativeCodeIndex.Build(pe);
        var sites = Arm64CallSites.For(index);
        var set = sites.DynamicImports();
        output.WriteLine($"{set.GetProcAddressSites} resolver calls, {set.Imports.Count} named");
        int floats = 0;
        foreach (var f in index.Functions.Take(300))
            floats += sites.CallsIn(f).Sum(c => c.Arguments.Count(a => a.Location.StartsWith('d') || a.Location.StartsWith('s')));
        output.WriteLine($"{floats} floating-point arguments in the first 300 functions");

        var options = new ServerOptions { BackgroundIndexing = false };
        var ws = new AssemblyWorkspace(options);
        _owned.Add(ws);
        var code = new NativeCodeService(ws, options, null, new AnnotationStore(_dir.File("ann")));
        var tools = new NativeFunctionTools(ws, code, new OutputPager(options));
        var export = pe.Exports.First(e => e.Name != null && e.ForwardedTo == null).Name!;
        var text = await tools.AnalyzeNativeFunction(path, export, sections: "frame,signature,callers,params");
        output.WriteLine(text);
        Assert.Contains("unwind data (ARM64", text);
        Assert.DoesNotContain("error:", text);
    }

    [Trait("Speed", "Slow")]
    [WindowsFact]
    public void X64_unwind_data_of_a_system_dll()
    {
        var pe = PeFile.Open(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "kernel32.dll"));
        var frames = pe.RuntimeFunctions.Select(f => UnwindFrames.Of(pe, f.BeginRva)).ToList();
        Assert.True(frames.Count(f => f != null) >= frames.Count * 99 / 100);
        Assert.Contains(frames, f => f is { Saved.Count: > 0, Allocation: > 0 });
    }

    [Trait("Speed", "Slow")]
    [IdaFact]
    public async Task An_open_ida_session_feeds_call_paths_and_feature_traces()
    {
        var dll = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "version.dll");
        var options = new ServerOptions { TimeoutSeconds = 300, BackgroundIndexing = false };
        var ws = new AssemblyWorkspace(options);
        _owned.Add(ws);
        var code = new NativeCodeService(ws, options, null, new AnnotationStore(_dir.File("ann")));
        var engines = new NativeEngineService(new IdaProviderOptions { CacheRoot = _dir.File("cache") }, code, ws, options);
        _owned.Add(engines);
        var native = ws.LoadAny(dll).Native!;
        await engines.Session(native, IdaProvider.ProviderId, null, default);
        var pager = new OutputPager(options);
        var paths = await new CallGraphTools(ws, new CallGraphService(ws), pager, new NativeLinkService(ws, code), code, engines)
            .FindCallPaths("native:version.dll!GetFileVersionInfoSizeW");
        output.WriteLine(paths);
        Assert.Contains("to native version.dll!GetFileVersionInfoSizeW", paths);
        var feature = await new NativeFeatureTools(ws, code, pager, engines).TraceNativeFeature(native.Id, "VarFileInfo");
        output.WriteLine(feature);
        Assert.Contains("Feature trace of \"VarFileInfo\"", feature);
        Assert.DoesNotContain("; failed:", feature);
    }
}
