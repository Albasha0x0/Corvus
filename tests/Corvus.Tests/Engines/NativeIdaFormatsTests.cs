using Corvus.Core;
using Corvus.Native;
using Corvus.Native.Providers;
using Corvus.Native.Providers.Ghidra;
using Corvus.Native.Providers.Ida;
using Corvus.Services;
using Corvus.Tests.NativeFormats;
using Xunit.Abstractions;

namespace Corvus.Tests;

/// <summary>Engines on ELF and Mach-O: header facts (quick), and IDA on real ARM libraries for base, unwind starts, Thumb and universal slices (slow).</summary>
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
    public void Headers_come_from_the_image_model()
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
    public Task An_ELF_ARM64_image_agrees_with_IDA() => Agree(NativeFixtures.LinuxArm64DbgShim, NativeArch.Arm64);

    [IdaFact]
    [Trait("Speed", "Slow")]
    public Task A_MachO_ARM64_image_agrees_with_IDA() => Agree(NativeFixtures.OsxArm64DbgShim, NativeArch.Arm64);

    [IdaFact]
    [Trait("Speed", "Slow")]
    public async Task ELF_ARM_functions_carry_the_Thumb_flag()
    {
        var functions = await Agree(NativeFixtures.LinuxArmDbgShim, NativeArch.Arm);
        int thumb = functions.Count(f => (f.Flags & NativeFunctionFlags.Thumb) != 0);
        output.WriteLine($"Thumb: {thumb} of {functions.Count}");
        Assert.True(thumb > functions.Count / 2);
    }

    /// <summary>The smallest package of CORVUS_AOT_MOBILE: IDA opens its libil2cpp.so at our base, and metadata method starts match IDA's functions.</summary>
    [IdaFact]
    [Trait("Speed", "Slow")]
    public async Task A_native_library_from_an_Android_package_agrees_with_IDA()
    {
        if (RealData.Get("CORVUS_AOT_MOBILE") is not { } root || !Directory.Exists(root)) { output.WriteLine("CORVUS_AOT_MOBILE not set"); return; }
        var package = Directory.EnumerateFiles(root, "*.apk").OrderBy(f => new FileInfo(f).Length).FirstOrDefault();
        if (package == null) return;
        var cache = RealData.Get(AotBuildLoader.RootVariable) ?? _dir.File("aot");
        var files = AotBuildFiles.Find(AotPackages.Extract(package, null, cache)!)!;
        var options = new ServerOptions { TimeoutSeconds = 1800, BackgroundIndexing = false };
        var workspace = new AssemblyWorkspace(options);
        _owned.Add(workspace);
        var model = new AotBuildLoader(workspace).Load(files, loadBinary: true, null, default, cache).Model;
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
                         $"{found} of {methods.Count} AOT method starts are IDA functions");
        Assert.True(found >= methods.Count * 0.85); // IDA alone misses starts reached only through method-pointer tables (92.5% on an engine 2022 build)
    }

    [IdaFact]
    [Trait("Speed", "Slow")]
    public async Task Universal_slice_opens_as_a_thin_file()
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

/// <summary>Ghidra on ARM ELF and Mach-O libraries.</summary>
public sealed class NativeGhidraFormatsTests(ITestOutputHelper output) : IDisposable
{
    private readonly TempDir _dir = new();
    private readonly List<IDisposable> _owned = [];

    public void Dispose()
    {
        foreach (var d in _owned) d.Dispose();
        _dir.Dispose();
    }

    /// <summary>
    /// Ghidra on the IDA tests' ELF and Mach-O libraries: loaded at our image
    /// base, with functions at the declared starts.
    /// </summary>
    [GhidraFact]
    [Trait("Speed", "Slow")]
    public async Task Ghidra_loads_ELF_and_MachO_at_the_image_model_base()
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
}
