using NetDecompilerMcp.Native.Annotations;
using NetDecompilerMcp.Native.Code;
using NetDecompilerMcp.Native.NativeAot;
using NetDecompilerMcp.Native.Pdb;
using NetDecompilerMcp.Native.Pe;
using NetDecompilerMcp.Services;
using Xunit.Abstractions;

namespace NetDecompilerMcp.Tests;

/// <summary>Runs only with NDM_NATIVEAOT_SAMPLES=1 on Windows: needs the .NET SDK and the C++ build tools NativeAOT links with.</summary>
public sealed class NativeAotSamplesTheoryAttribute : TheoryAttribute
{
    public NativeAotSamplesTheoryAttribute()
    {
        if (!OperatingSystem.IsWindows()) Skip = "NativeAOT samples are built for win-x64.";
        else if (Environment.GetEnvironmentVariable(NativeAotSampleTests.Variable) != "1")
            Skip = $"Set {NativeAotSampleTests.Variable}=1 to build the NativeAOT samples with the SDK.";
    }
}

/// <summary>
/// Builds NativeAotSample/Program.cs with the SDK for several target frameworks and compiler options and checks the
/// recovered names against the build's own PDB (method symbols at the named addresses, `vftable` symbols at MethodTables).
/// </summary>
[Trait("Speed", "Slow")]
public class NativeAotSampleTests(ITestOutputHelper log)
{
    public const string Variable = "NDM_NATIVEAOT_SAMPLES";

    /// <summary>Build matrix: target framework and the MSBuild properties passed to dotnet publish.</summary>
    private static readonly Dictionary<string, (string Tfm, string Runtime, string[] Properties)> Variants = new()
    {
        ["net8"] = ("net8.0", ".NET 8", []),
        ["net9"] = ("net9.0", ".NET 9", []),
        ["net10"] = ("net10.0", ".NET 10", []),
        ["net10-dehydrated"] = ("net10.0", ".NET 10", ["IlcDehydrate=true"]),
        ["net10-nostacktrace"] = ("net10.0", ".NET 10", ["StackTraceSupport=false"]),
    };

    public static readonly TheoryData<string> Names = new(Variants.Keys);

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
    public async Task Sample_NamesMatchThePdb(string variant)
    {
        var (tfm, runtime, properties) = Variants[variant];
        using var dir = new TempDir();
        File.Copy(Path.Combine(AppContext.BaseDirectory, "NativeAotSample", "Program.cs"), dir.File("Program.cs"));
        File.WriteAllText(dir.File("app.csproj"), Project.Replace("TFM", tfm));
        string[] args = ["publish", "app.csproj", "-c", "Release", "-r", "win-x64", "-o", "out", .. properties.Select(p => "-p:" + p)];
        var (code, output) = Tools.Dotnet(dir.Path, args);
        Assert.True(code == 0, $"dotnet publish failed ({code}):\n{output}");

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
