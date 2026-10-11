using dnlib.DotNet;
using Corvus.Core;

namespace Corvus.Tests;

/// <summary>
/// export_project frameworks and references: an assembly without a TargetFrameworkAttribute exported as .NET Framework 4.0
/// (netstandard1.x contracts, a Unity Assembly-CSharp), references of the referenced libraries were missing (CS0012), and
/// a .NET Standard library's dependencies bound to .NET Framework or runtime copies (Vector&lt;T&gt; not found, CS1705).
/// </summary>
public sealed class ExportFrameworkTests : IDisposable
{
    private readonly TempDir _dir = new();
    public void Dispose() => _dir.Dispose();

    /// <summary>A module without a TargetFrameworkAttribute whose base types come from these assemblies.</summary>
    private static ModuleDefMD ReferencingModule(params (string Name, Version Version)[] references)
    {
        var corlib = references[0];
        var module = new ModuleDefUser("Lib.dll", Guid.NewGuid(), new AssemblyRefUser(corlib.Name, corlib.Version)) { Kind = ModuleKind.Dll };
        new AssemblyDefUser("Lib", new Version(1, 0, 0, 0)).Modules.Add(module);
        int n = 0;
        foreach (var (name, version) in references)
            module.Types.Add(new TypeDefUser("Lib", "T" + n++, new TypeRefUser(module, "System", "Object", new AssemblyRefUser(name, version))));
        using var ms = new MemoryStream();
        module.Write(ms);
        return ModuleDefMD.Load(ms.ToArray());
    }

    [Theory]
    [InlineData("System.Runtime", "4.0.0.0", null, ".NETStandard,Version=v1.0", "netstandard1.0")]
    [InlineData("System.Runtime", "4.0.20.0", null, ".NETStandard,Version=v1.3", "netstandard1.3")]
    [InlineData("netstandard", "2.0.0.0", null, ".NETStandard,Version=v2.0", "netstandard2.0")]
    [InlineData("mscorlib", "2.0.0.0", null, ".NETFramework,Version=v3.5", "net35")]
    [InlineData("mscorlib", "4.0.0.0", "UnityEngine.CoreModule", ".NETFramework,Version=v4.8", "net48")]
    [InlineData("mscorlib", "4.0.0.0", "netstandard", ".NETFramework,Version=v4.8", "net48")]
    [InlineData("mscorlib", "4.0.0.0", null, null, null)]
    public void FrameworkIsInferredFromTheCoreAssemblies(string core, string version, string? other, string? expected, string? shortName)
    {
        var refs = new List<(string, Version)> { (core, Version.Parse(version)) };
        if (other != null) refs.Add((other, new Version(2, 0, 0, 0)));
        using var module = ReferencingModule([.. refs]);
        Assert.Null(Frameworks.TargetFrameworkOf(module));
        Assert.Equal(expected, Frameworks.InferTargetFramework(module));
        Assert.Equal(shortName, Frameworks.ShortName(expected));
        Assert.Equal(expected?.StartsWith(".NETStandard,Version=v1.", StringComparison.Ordinal) == true || core == "mscorlib" && other != "netstandard",
            Frameworks.ResolvesAsNetFramework(module));
    }

    /// <summary>A netstandard1.0 library: exported as such, and its contracts bind to .NET Framework, not to the newest runtime.</summary>
    [Trait("Speed", "Slow")]
    [Fact]
    public void NetStandardOneLibraryExportsAsSuchAndBindsLikeNetFramework()
    {
        using var env = new Env(RealPackages.Lib("System.Collections.Immutable", "1.3.1", "netstandard1.0", "System.Collections.Immutable.dll"));
        var project = File.ReadAllText(env.Decompiler.ExportProject(env.Fixture, _dir.File("out"), null, default).ProjectFile!);
        Assert.Contains("<TargetFramework>netstandard1.0</TargetFramework>", project);
        Assert.Contains("inferred from the referenced core assemblies", project);
        Assert.DoesNotContain("Framework64", project);
        if (Frameworks.NetFrameworkFile("mscorlib") != null) // Volatile.Read(ref T); the newest runtime has ref readonly
            Assert.Contains("Volatile.Read(ref location)", env.Decompile("System.Collections.Immutable.ImmutableInterlocked::Update<T>"));
    }

    [Fact]
    public void NetStandardDependenciesBindToTheirPackages()
    {
        using var env = new Env(RealPackages.Lib("System.Text.Json", "10.0.1", "netstandard2.0", "System.Text.Json.dll"));
        var module = env.Fixture.Module;
        foreach (var name in new[] { "System.Numerics.Vectors", "System.Runtime.CompilerServices.Unsafe" })
        {
            var r = module.GetAssemblyRefs().Single(a => a.Name == name);
            var target = env.Workspace.LocateReference(name, r.Version, r.PublicKeyOrToken?.Token?.Data, env.Fixture.FilePath, false, Frameworks.RequesterFramework(module));
            var file = Assert.IsType<string>(target?.File);
            Assert.False(Frameworks.InNetFrameworkDirectory(file), file);
            Assert.Null(Frameworks.SharedFrameworkMajor(file));
            Assert.Contains("netstandard", file, StringComparison.OrdinalIgnoreCase);
        }
    }

    /// <summary>
    /// A .NET Standard 1.x library with a TargetFrameworkAttribute kept references to .NET Framework facades (CS1069: forwarded
    /// to mscorlib); its contracts outside the standard library are their 4.3.0 packages instead.
    /// </summary>
    [Trait("Speed", "Slow")]
    [Fact]
    public void NetStandardOneContractsArePackagesNotFrameworkFacades()
    {
        using var env = new Env(RealPackages.Lib("Newtonsoft.Json", "13.0.1", "netstandard1.3", "Newtonsoft.Json.dll"));
        var project = File.ReadAllText(env.Decompiler.ExportProject(env.Fixture, _dir.File("out"), null, default).ProjectFile!);
        Assert.Contains("<TargetFramework>netstandard1.3</TargetFramework>", project);
        Assert.DoesNotMatch(@"<HintPath>[^<]*Microsoft\.NET[\\/]Framework", project);
        Assert.Contains("<PackageReference Include=\"Microsoft.CSharp\" Version=\"4.3.0\" />", project);
        Assert.Contains("<PackageReference Include=\"System.Runtime.Serialization.Primitives\" Version=\"4.3.0\" />", project);
    }

    /// <summary>
    /// A .NET Framework 4.6.2 library got the installed runtime's System.ValueTuple facade (forwarding to an mscorlib the 4.6.2
    /// reference assemblies do not have: CS8179) and its System.Numerics.Vectors 4.0 (no Vector&lt;T&gt;).
    /// </summary>
    [Trait("Speed", "Slow")]
    [Fact]
    public void NetFrameworkLibrariesDoNotReferenceRuntimeFacadesOrOlderFrameworkCopies()
    {
        using var env = new Env(RealPackages.Lib("System.Text.Json", "10.0.1", "net462", "System.Text.Json.dll"));
        var project = File.ReadAllText(env.Decompiler.ExportProject(env.Fixture, _dir.File("out"), null, default).ProjectFile!);
        Assert.Contains("<TargetFramework>net462</TargetFramework>", project);
        Assert.DoesNotMatch(@"<HintPath>[^<]*Microsoft\.NET[\\/]Framework[^<]*(ValueTuple|Numerics\.Vectors)", project);
        Assert.DoesNotContain("<Reference Include=\"System.Numerics.Vectors\" />", project);
    }

    /// <summary>A portable library the SDK project writer refuses (Profile328) failed as an internal error.</summary>
    [Trait("Speed", "Slow")]
    [Fact]
    public void PortableProfilesWithoutAnSdkFrameworkAreUnsupported()
    {
        using var env = new Env(RealPackages.Lib("Newtonsoft.Json", "12.0.2", "portable-net40+sl5+win8+wp8+wpa81", "Newtonsoft.Json.dll"));
        var error = Assert.Throws<ToolError>(() => env.Decompiler.ExportProject(env.Fixture, _dir.File("out"), null, default));
        Assert.Equal(ErrorCode.Unsupported, error.Code);
        Assert.Contains("Profile328", error.Message);
    }

    /// <summary>App uses Mid only; Mid exposes a type of Base, which the project then needs too (CS0012).</summary>
    [Fact]
    public void DependenciesOfReferencedLibrariesAreReferenced()
    {
        var app = Directory.CreateDirectory(_dir.File("app")).FullName;
        var lowest = ReferenceResolutionTests.Compile("Base", "namespace Base { public class Shape { } }");
        var mid = ReferenceResolutionTests.Compile("Mid", "namespace Mid { public class Canvas { public Base.Shape Shape = new Base.Shape(); } }", lowest);
        File.WriteAllBytes(Path.Combine(app, "Base.dll"), lowest);
        File.WriteAllBytes(Path.Combine(app, "Mid.dll"), mid);
        File.WriteAllBytes(Path.Combine(app, "App.dll"), ReferenceResolutionTests.Compile("App",
            "namespace App { public static class Program { public static object Draw() => new Mid.Canvas(); } }", mid, lowest));
        using var env = new Env(Path.Combine(app, "App.dll"));
        var project = File.ReadAllText(env.Decompiler.ExportProject(env.Fixture, _dir.File("out"), null, default).ProjectFile!);
        Assert.Contains("<!-- dependencies of the referenced libraries -->", project);
        Assert.Matches(@"<Reference Include=""Base"">\s*<HintPath>[^<]*app[\\/]Base\.dll</HintPath>", project);
        Assert.DoesNotContain("<Reference Include=\"System.Runtime\"", project);
    }
}
