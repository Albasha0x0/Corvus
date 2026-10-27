using Corvus.Core;
using Corvus.Native.Providers.Ida;
using Corvus.Services;
using Corvus.Tests.NativeFormats;
using Corvus.Tools;
using Xunit.Abstractions;

namespace Corvus.Tests;

/// <summary>DWARF of a stripped ELF library (its separate debug file) reaching IDA's and Ghidra's pseudocode: names, types and prototypes.</summary>
[Trait("Speed", "Slow")]
public sealed class DwarfEngineTypesTests(ITestOutputHelper output) : IDisposable
{
    private const string Library = "libSystem.Native.so";
    private readonly TempDir _dir = new();
    private readonly List<IDisposable> _owned = [];

    public void Dispose()
    {
        foreach (var d in _owned) d.Dispose();
        _dir.Dispose();
    }

    private async Task<string> Decompile(EngineMode mode)
    {
        var options = new ServerOptions { TimeoutSeconds = 600, BackgroundIndexing = false, Engine = mode };
        var workspace = new AssemblyWorkspace(options);
        var code = new NativeCodeService(workspace, options, null, new Native.Annotations.AnnotationStore(_dir.File("annotations")));
        var engines = new NativeEngineService(new IdaProviderOptions { CacheRoot = _dir.File("cache") }, code, workspace, options);
        _owned.Add(engines);
        _owned.Add(workspace);
        var names = new NativeNamePush(code);
        var analysis = new NativeAnalysisTools(workspace, engines, new OutputPager(options), names, code, new NativeTypePush(), new NativeUserTypePush(code));
        // The image without its debug file: the engine's analysis has no DWARF of its own.
        var image = Path.Combine(Directory.CreateDirectory(_dir.File("bin")).FullName, Library);
        File.Copy(NativeFixtures.NativeAotLib("linux-x64", Library), image, overwrite: true);
        var debug = Path.Combine(Directory.CreateDirectory(_dir.File("symbols")).FullName, Library + ".dbg");
        File.Copy(NativeFixtures.NativeAotLib("linux-x64", Library + ".dbg"), debug, overwrite: true);
        var native = workspace.LoadAny(image).Native!;
        Assert.NotNull((await new PdbService(code).Load(native, debug, false, null, false, TimeSpan.FromSeconds(30), 1 << 30, default)).State);
        var text = await EngineMeta.WithPushes(() => analysis.DecompileNative(native.Id, "SystemNative_FStat"));
        output.WriteLine(text);
        var session = await engines.Session(native, null, null, default);
        Assert.Equal(NativePdbTypes.RouteDwarf, NativePdbTypes.Current(session)!.Route);
        foreach (var m in NativePdbTypes.Current(session)!.OwnApplied?.DeclarationMessages ?? []) output.WriteLine("refused: " + m);
        return text;
    }

    [IdaFact]
    public async Task Dwarf_types_and_prototypes_reach_idas_pseudocode()
    {
        var text = await Decompile(EngineMode.Ida);
        Assert.Contains("types: DWARF libSystem.Native.so.dbg via the server's DWARF reader", text);
        Assert.Contains("SystemNative_FStat(", text);
        Assert.Contains("FileStatus *output", text);
        Assert.Contains("output->Size = ", text);
        Assert.DoesNotContain("declaration errors", text); // generated padding never takes a member's name (glibc FILE's __pad1)
    }

    [GhidraFact]
    public async Task Dwarf_types_and_prototypes_reach_ghidras_pseudocode()
    {
        var text = await Decompile(EngineMode.Ghidra);
        Assert.Contains("types: DWARF libSystem.Native.so.dbg via the server's DWARF reader", text);
        Assert.Contains("SystemNative_FStat(", text);
        Assert.Contains("FileStatus *output", text);
        Assert.Contains("output->Size = ", text);
        Assert.DoesNotContain("Unknown calling convention", text); // a prototype without one takes the compiler spec's default
        Assert.DoesNotContain("declaration errors", text); // C++ enum bases (enum E : unsigned int) are taken
    }
}
