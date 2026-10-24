using Corvus.Core;
using Corvus.Native;
using Corvus.Native.Providers;
using Corvus.Native.Providers.Ghidra;
using Corvus.Native.Providers.Ida;
using Corvus.Services;
using Corvus.Tests.NativeFormats;
using Xunit.Abstractions;

namespace Corvus.Tests;

/// <summary>
/// The engines on ELF and Mach-O: header facts (architecture, image base) the sessions verify against (quick), and IDA
/// on real ARM64 / ARM ELF and Mach-O libraries: base agreement with our model, function starts against the declared
/// unwind starts, Thumb functions, and a universal slice opened as a thin file (slow, IDA installed).
/// </summary>
public sealed class NativeIdaFormatsTests(ITestOutputHelper output) : IDisposable
{
    private readonly TempDir _dir = new();
    private readonly List<IDisposable> _owned = [];

    public void Dispose()
    {
        foreach (var d in _owned) d.Dispose();
        _dir.Dispose();
    }

    [Fact]
    public void HeadersComeFromTheImageModel()
    {
        Assert.Equal((NativeArch.Arm64, 0UL), IdaSession.ReadHeader(NativeFixtures.LinuxArm64DbgShim, "libdbgshim.so"));
        Assert.Equal((NativeArch.Arm, 0UL), IdaSession.ReadHeader(NativeFixtures.LinuxArmDbgShim, "libdbgshim.so"));
        Assert.Equal((NativeArch.Arm64, 0UL), IdaSession.ReadHeader(NativeFixtures.OsxArm64DbgShim, "libdbgshim.dylib"));
        Assert.Equal((NativeArch.Arm64, 0x1_0000_0000UL), IdaSession.ReadHeader(NativeFixtures.OsxArm64AppHost, "apphost"));
        Assert.Equal(ErrorCode.InvalidArgument, Assert.Throws<ToolError>(() => IdaSession.ReadHeader(NativeFixtures.OsxFatSkia, "libSkiaSharp.dylib")).Code);
        Assert.Equal(NativeArch.Arm64, GhidraSession.ReadHeader(NativeFixtures.OsxArm64DbgShim, "libdbgshim.dylib").Arch);
        Assert.Equal((NativeArch.Arm64, (ulong?)0, true), GhidraSession.ReadHeader(NativeFixtures.LinuxArm64DbgShim, "libdbgshim.so") is var h ? (h.Arch, h.ImageBase, h.IsElf) : default);
    }

    private IdaProvider Provider()
    {
        var provider = new IdaProvider(new IdaProviderOptions { CacheRoot = _dir.File("cache") });
        _owned.Add(provider);
        return provider;
    }

    /// <summary>Opens <paramref name="path"/> in IDA and compares its function starts with the image's declared starts.</summary>
    private async Task<IReadOnlyList<NativeFunctionInfo>> Agree(string path, NativeArch arch)
    {
        var image = NativeImageLoader.Open(path);
        await using var s = await Provider().OpenAsync(path, null, new NativeOpenOptions { Symbols = SymbolMode.Off });
        Assert.Equal(arch, s.Arch);
        Assert.Equal(image.ImageBase, s.ImageBase);
        var functions = await s.ListFunctionsAsync();
        var starts = functions.Select(f => f.StartRva).ToHashSet();
        var declared = image.DeclaredFunctions.Where(d => d.Source is DeclaredSource.Unwind or DeclaredSource.FunctionStarts).Select(d => d.Rva).Distinct().ToList();
        int found = declared.Count(starts.Contains);
        output.WriteLine($"{Path.GetFileName(path)} ({arch}): base 0x{s.ImageBase:X}, IDA {functions.Count} functions; {found} of {declared.Count} declared starts are IDA functions; decompiler {s.DecompilerAvailable}");
        Assert.True(declared.Count == 0 || found >= declared.Count * 0.95, $"{found} of {declared.Count}");
        if (s.DecompilerAvailable && image.Exports.FirstOrDefault(e => e.ForwardedTo == null && starts.Contains(e.Rva)) is { } export)
            Assert.Contains("{", (await s.DecompileAsync(export.Rva)).Text);
        return functions;
    }

    [IdaFact]
    [Trait("Speed", "Slow")]
    public Task ElfArm64() => Agree(NativeFixtures.LinuxArm64DbgShim, NativeArch.Arm64);

    [IdaFact]
    [Trait("Speed", "Slow")]
    public Task MachOArm64() => Agree(NativeFixtures.OsxArm64DbgShim, NativeArch.Arm64);

    [IdaFact]
    [Trait("Speed", "Slow")]
    public async Task ElfArmFunctionsCarryTheThumbFlag()
    {
        var functions = await Agree(NativeFixtures.LinuxArmDbgShim, NativeArch.Arm);
        int thumb = functions.Count(f => (f.Flags & NativeFunctionFlags.Thumb) != 0);
        output.WriteLine($"Thumb: {thumb} of {functions.Count}");
        Assert.True(thumb > functions.Count / 2);
    }

    /// <summary>
    /// The smallest Android package of CORVUS_IL2CPP_MOBILE (see <see cref="Il2CppMobileTests"/>): IDA opens its libil2cpp.so
    /// at our image base, and the Il2Cpp method starts are compared with IDA's functions.
    /// </summary>
    [IdaFact]
    [Trait("Speed", "Slow")]
    public async Task Il2CppMobileBinaryAgreesWithIda()
    {
        if (RealData.Get("CORVUS_IL2CPP_MOBILE") is not { } root || !Directory.Exists(root)) { output.WriteLine("CORVUS_IL2CPP_MOBILE not set"); return; }
        var package = Directory.EnumerateFiles(root, "*.apk").OrderBy(f => new FileInfo(f).Length).FirstOrDefault();
        if (package == null) return;
        var cache = RealData.Get(Il2CppRawLoader.RootVariable) ?? _dir.File("il2cpp");
        var files = Il2CppBuildFiles.Find(Il2CppPackages.Extract(package, null, cache)!)!;
        var options = new ServerOptions { TimeoutSeconds = 1800, BackgroundIndexing = false };
        var workspace = new AssemblyWorkspace(options);
        _owned.Add(workspace);
        var model = new Il2CppRawLoader(workspace).Load(files, loadBinary: true, null, default, cache).Model;
        var native = Assert.Single(workspace.Natives);
        EngineSeed.Copy(_dir.File("cache"), files.Binary, "ida");
        var code = new NativeCodeService(workspace, options, null, new Native.Annotations.AnnotationStore(_dir.File("annotations")));
        var engines = new NativeEngineService(new IdaProviderOptions { CacheRoot = _dir.File("cache") }, code, workspace, options);
        _owned.Add(engines);
        var watch = System.Diagnostics.Stopwatch.StartNew();
        var session = await engines.Session(native, "ida", null, default);
        Assert.Equal(native.Image.ImageBase, session.ImageBase);
        var partial = !session.AnalysisComplete;
        Assert.True(await EngineSeed.CompleteAsync(session), "IDA's analysis is still partial after three reanalysis rounds");
        var starts = (await session.ListFunctionsAsync()).Select(f => f.StartRva).ToHashSet();
        var methods = model.Methods.Select(m => m.Address).Distinct().ToList();
        int found = methods.Count(starts.Contains);
        output.WriteLine($"{Path.GetFileName(package)} libil2cpp.so ({native.Image.Arch}): IDA {starts.Count} functions in {watch.Elapsed.TotalSeconds:0} s{(partial ? " (open's analysis partial, completed by reanalysis)" : "")}, base 0x{session.ImageBase:X}; " +
                         $"{found} of {methods.Count} Il2Cpp method starts are IDA functions");
        Assert.True(found >= methods.Count * 0.85); // IDA alone misses starts reached only through method-pointer tables (92.5% on a Unity 2022 build)
    }

    /// <summary>Ghidra on the same ELF and Mach-O libraries: loaded at our image base, with functions at the declared starts.</summary>
    [GhidraFact]
    [Trait("Speed", "Slow")]
    public async Task GhidraLoadsElfAndMachOAtOurBase()
    {
        var provider = new GhidraProvider(new GhidraProviderOptions { CacheRoot = _dir.File("ghidra") });
        _owned.Add(provider);
        foreach (var path in new[] { NativeFixtures.LinuxArm64DbgShim, NativeFixtures.OsxArm64DbgShim })
        {
            var image = NativeImageLoader.Open(path);
            await using var s = await provider.OpenAsync(path, null, new NativeOpenOptions { Symbols = SymbolMode.Off });
            Assert.Equal((NativeArch.Arm64, image.ImageBase), (s.Arch, s.ImageBase));
            var starts = (await s.ListFunctionsAsync()).Select(f => f.StartRva).ToHashSet();
            var declared = image.DeclaredFunctions.Where(d => d.Source is DeclaredSource.Unwind or DeclaredSource.FunctionStarts).Select(d => d.Rva).Distinct().ToList();
            int found = declared.Count(starts.Contains);
            output.WriteLine($"Ghidra {Path.GetFileName(path)}: base 0x{s.ImageBase:X}, {starts.Count} functions; {found} of {declared.Count} declared starts");
            Assert.True(found >= declared.Count * 0.9, $"{found} of {declared.Count}");
        }
    }

    [IdaFact]
    [Trait("Speed", "Slow")]
    public async Task UniversalSliceOpensAsAThinFile()
    {
        var fat = _dir.File("libdual.dylib");
        var arm64 = File.ReadAllBytes(NativeFixtures.OsxArm64DbgShim);
        File.WriteAllBytes(fat, MachOWriter.Fat([(MachOWriter.CpuX64, 3, new MachOWriter { CpuType = MachOWriter.CpuX64 }.Build()), (MachOWriter.CpuArm64, 0, arm64)]));
        var options = new ServerOptions { TimeoutSeconds = 300, BackgroundIndexing = false };
        var workspace = new AssemblyWorkspace(options);
        _owned.Add(workspace);
        var code = new NativeCodeService(workspace, options, null, new Native.Annotations.AnnotationStore(_dir.File("annotations")));
        var engines = new NativeEngineService(new IdaProviderOptions { CacheRoot = _dir.File("cache") }, code, workspace, options);
        _owned.Add(engines);
        var native = workspace.LoadAny(fat, "arm64").Native!;
        var session = await engines.Session(native, "ida", null, default);
        Assert.Equal(Convert.ToHexStringLower(System.Security.Cryptography.SHA256.HashData(arm64)), session.Sha256);
        Assert.Equal((NativeArch.Arm64, 0UL), (session.Arch, session.ImageBase));
    }
}
