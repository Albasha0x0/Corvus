using System.Security.Cryptography;
using System.Text;
using Corvus.Native.Annotations;
using Corvus.Native.Code;
using Corvus.Native.NativeAot;
using Corvus.Native.Pdb;
using Corvus.Native.Pe;
using Corvus.Services;
using Xunit.Abstractions;

namespace Corvus.Tests;

/// <summary>Runs only with CORVUS_NATIVEAOT_SAMPLES=1 on Windows: needs the .NET SDK and the C++ build tools (x64 and x86) NativeAOT links with.</summary>
public sealed class NativeAotSamplesTheoryAttribute : TheoryAttribute
{
    public NativeAotSamplesTheoryAttribute()
    {
        if (!OperatingSystem.IsWindows()) Skip = "NativeAOT samples are built for Windows.";
        else if (Environment.GetEnvironmentVariable(NativeAotSampleTests.Variable) != "1")
            Skip = $"Set {NativeAotSampleTests.Variable}=1 to build the NativeAOT samples with the SDK.";
    }
}

/// <summary>Recovered names of NativeAotSample builds match the build's own PDB.</summary>
[Trait("Speed", "Slow")]
public class NativeAotSampleTests(ITestOutputHelper log)
{
    public const string Variable = "CORVUS_NATIVEAOT_SAMPLES";

    /// <summary>Build matrix: target framework, runtime identifier and the MSBuild properties passed to dotnet publish.</summary>
    private static readonly Dictionary<string, (string Tfm, string Runtime, string Rid, string[] Properties)> Variants = new()
    {
        ["net7"] = ("net7.0", ".NET 7", "win-x64", []),
        ["net8"] = ("net8.0", ".NET 8", "win-x64", []),
        ["net9"] = ("net9.0", ".NET 9", "win-x64", []),
        ["net10"] = ("net10.0", ".NET 10", "win-x64", []),
        ["net10-x86"] = ("net10.0", ".NET 10", "win-x86", []),
        ["net10-dehydrated"] = ("net10.0", ".NET 10", "win-x64", ["IlcDehydrate=true"]),
        ["net10-nostacktrace"] = ("net10.0", ".NET 10", "win-x64", ["StackTraceSupport=false"]),
    };

    public static readonly TheoryData<string> Names = new(Variants.Keys);

    private static readonly string Cache = Path.Combine(LeakGuard.SharedTemp, "corvus-test-data", "nativeaot-samples");

    /// <summary>The folder of <paramref name="variant"/>'s published build, cached per source, project, variant and SDK; an exhaustive run publishes afresh in <paramref name="scratch"/>; a failed publish fails the test.</summary>
    private static string Published(string variant, TempDir scratch)
    {
        var (tfm, _, rid, properties) = Variants[variant];
        var source = File.ReadAllBytes(Path.Combine(AppContext.BaseDirectory, "NativeAotSample", "Program.cs"));
        var (sdkCode, sdk) = Tools.Dotnet(null, "--version");
        Assert.True(sdkCode == 0, $"dotnet --version failed ({sdkCode}): {sdk}");
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        hash.AppendData(source);
        hash.AppendData(Encoding.UTF8.GetBytes(string.Join("\n", Project, tfm, rid, string.Join(";", properties), sdk.Trim())));
        var key = Convert.ToHexStringLower(hash.GetHashAndReset())[..16];
        var dir = Path.Combine(Cache, $"{variant}-{key}");
        if (!SweepScope.Exhaustive && File.Exists(Path.Combine(dir, "app.exe"))) return dir;
        // Builds of this variant under another key: an older SDK or sample.
        if (Directory.Exists(Cache))
            foreach (var old in Directory.EnumerateDirectories(Cache, $"{variant}-*").Where(d => Path.GetFileName(d).Length == variant.Length + 17 && d != dir))
            {
                try { Directory.Delete(old, true); }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
            }

        // Published in a folder of this process, then moved in place; another process may win.
        var work = SweepScope.Exhaustive ? scratch.File("build") : Path.Combine(Cache, $"{variant}-{key}-{Environment.ProcessId}-{Guid.NewGuid():N}");
        Directory.CreateDirectory(work);
        File.WriteAllBytes(Path.Combine(work, "Program.cs"), source);
        File.WriteAllText(Path.Combine(work, "app.csproj"), Project.Replace("TFM", tfm));
        string[] args = ["publish", "app.csproj", "-c", "Release", "-r", rid, "-o", "out", .. properties.Select(p => "-p:" + p)];
        var (code, output) = Tools.Dotnet(work, args);
        Assert.True(code == 0, $"dotnet publish failed ({code}):\n{output}");
        if (SweepScope.Exhaustive) return Path.Combine(work, "out");
        try { Directory.Move(Path.Combine(work, "out"), dir); }
        catch (IOException) when (File.Exists(Path.Combine(dir, "app.exe"))) { }
        try { Directory.Delete(work, true); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
        return dir;
    }

    private const string Project = """
        <Project Sdk="Microsoft.NET.Sdk">
          <PropertyGroup>
            <OutputType>Exe</OutputType>
            <TargetFramework>TFM</TargetFramework>
            <PublishAot>true</PublishAot>
            <InvariantGlobalization>true</InvariantGlobalization>
            <NoWarn>$(NoWarn);IL2026;IL2075;IL2072;IL3050</NoWarn>
          </PropertyGroup>
        </Project>
        """;

    [NativeAotSamplesTheory]
    [MemberData(nameof(Names))]
    public async Task Sample_names_match_the_PDB(string variant)
    {
        var (_, runtime, _, properties) = Variants[variant];
        using var dir = new TempDir();
        var published = Published(variant, dir);
        Directory.CreateDirectory(dir.File("out"));
        foreach (var file in Directory.EnumerateFiles(published)) File.Copy(file, dir.File(Path.Combine("out", Path.GetFileName(file))));

        var exe = dir.File(Path.Combine("out", "app.exe"));
        var pe = PeFile.Open(exe);
        var aot = NativeAotImage.Open(pe) ?? throw new InvalidOperationException("no NativeAOT header");
        Assert.Equal(runtime, aot.Runtime);
        Assert.All(aot.Summary().Stages.Where(s => s.Name != "stack-trace map" && s.Name != "rehydration"), s => Assert.Equal(NativeAotStage.Complete, s.Status));

        var pdb = PdbFile.Open(Path.ChangeExtension(exe, ".pdb"), pe.Sections);
        var symbols = pdb.Symbols.Where(s => s.Rva != null).GroupBy(s => s.Rva!.Value).ToDictionary(g => g.Key, g => g.Select(s => s.Name).ToList());
        // ILC symbols spell names with '_' for '.'; compiler-generated names are mangled further, hence the 95 % bar.
        int agree = aot.Names.Methods.Count(m => symbols.TryGetValue(m.Rva, out var n) && n.Any(x => x.Contains(m.Name.Name.Replace('.', '_'), StringComparison.Ordinal)));
        Assert.True(agree >= 0.95 * aot.Names.Methods.Count, $"{agree} of {aot.Names.Methods.Count} method names agree with the PDB");
        var vtables = symbols.Where(s => s.Value.Any(n => n.StartsWith("??_7", StringComparison.Ordinal))).Select(s => s.Key).ToHashSet();
        var found = aot.Types.ByRva.Keys.ToHashSet();
        int matched = found.Count(vtables.Contains);
        Assert.True(matched >= 0.97 * vtables.Count, $"{matched} of {vtables.Count} MethodTables found");
        Assert.True(found.Count - matched <= Math.Max(2, found.Count / 100), $"{found.Count - matched} false MethodTables");

        var methods = aot.Names.Methods.Select(m => m.Name.Full).ToHashSet();
        Assert.Contains("Sample.Zoo.Reflected::Hello()", methods); // invoke map: present with or without stack-trace data
        if (!properties.Contains("StackTraceSupport=false"))
        {
            Assert.Contains("Sample.Zoo.Program::Thrower(int)", methods);
            Assert.Contains("Sample.Zoo.Program::Compute(int, int)", methods);
        }
        // Statics: the types found agree with the PDB's statics symbols (__GCSTATICS / __NONGCSTATICS / thread statics index).
        static string Plain(string s) => new([.. s.Where(char.IsLetterOrDigit)]);
        var owned = aot.Statics.Bases.Where(b => b.Owner != null && symbols.TryGetValue(b.Rva, out var n) && n.Any(x => x.Contains("STATIC", StringComparison.Ordinal))).ToList();
        int ownersAgree = owned.Count(b => symbols[b.Rva].Any(n => Plain(n).Contains(Plain(b.Owner!.Split('<')[0]), StringComparison.Ordinal)));
        log.WriteLine($"{variant}: statics {aot.Statics.Stage.Detail}; {ownersAgree} of {owned.Count} types agree with the PDB");
        if (!properties.Contains("StackTraceSupport=false")) // owners come from named methods
            Assert.True(owned.Count > 20 && ownersAgree >= 0.85 * owned.Count, $"{ownersAgree} of {owned.Count} statics types agree with the PDB");

        // Interface dispatch cells at the PDB's cell symbols.
        var cellSymbols = symbols.Where(s => s.Value.Any(n => n.Contains("__InterfaceDispatchCell_", StringComparison.Ordinal))).Select(s => s.Key).ToHashSet();
        int cellsFound = aot.Dispatch.Cells.Count(c => cellSymbols.Contains(c.Rva));
        // The first cell may carry the section's start symbol instead.
        Assert.True(cellsFound >= 0.95 * cellSymbols.Count && aot.Dispatch.Cells.Count - cellsFound <= 1, $"{cellsFound} of {cellSymbols.Count} dispatch cells, {aot.Dispatch.Cells.Count} found");

        // Dispatch maps (.NET 7: through the optional fields and the dispatch map table): most implementations are named bodies.
        var impls = aot.Types.ByRva.Values.SelectMany(aot.Types.Implementations).Where(i => i.Code != 0).ToList();
        Assert.True(impls.Count > 100, $"{impls.Count} interface implementations");
        if (!properties.Contains("StackTraceSupport=false"))
            Assert.True(impls.Count(i => aot.Names.MethodAt.ContainsKey(i.Code)) > impls.Count / 2, "interface implementations named");
        var types = aot.Types.ByRva.Values.Select(t => t.Name).ToHashSet();
        Assert.Contains("Sample.Zoo.Dog", types);
        Assert.Contains("Sample.Zoo.Box<Sample.Zoo.Point>", types);

        // After load (no PDB service): the nativeaot layer names the functions; the rest is runtime and C library code.
        using var env = new Env();
        var service = new NativeCodeService(env.Workspace, env.Options, null, new AnnotationStore(dir.File("ann")));
        var native = env.Workspace.LoadAny(exe).Native!;
        var index = await service.Index(native, null, default);
        int named = index.Functions.Count(f => index.Sourced.NameAt(f.Start) is { Source: NativeNameSource.NativeAot });
        var managed = pdb.Symbols.Where(s => s.Rva is { } r && pe.SectionAt(r) is { IsExecutable: true } && s.Name.Contains("__", StringComparison.Ordinal))
            .Select(s => s.Rva!.Value).ToHashSet();
        int managedNamed = managed.Count(r => index.Sourced.NameAt(r) is { Source: NativeNameSource.NativeAot });
        log.WriteLine($"{variant}: {named} of {index.Functions.Count} functions named ({100.0 * named / index.Functions.Count:0.0} %); " +
                      $"{managedNamed} of {managed.Count} managed PDB code symbols ({100.0 * managedNamed / Math.Max(1, managed.Count):0.0} %)");
        if (!properties.Contains("StackTraceSupport=false")) Assert.True(managedNamed > 0.8 * managed.Count, $"{managedNamed} of {managed.Count} managed code symbols named");
    }
}
