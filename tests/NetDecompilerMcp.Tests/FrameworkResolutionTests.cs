using dnlib.DotNet;
using NetDecompilerMcp.Core;
using NetDecompilerMcp.Services;

namespace NetDecompilerMcp.Tests;

/// <summary>
/// References resolve to the right framework and the right build: the requested .NET major version, .NET Framework
/// for .NET Framework apps, assemblies embedded in a loaded Costura host, and project export without framework paths.
/// </summary>
public class FrameworkResolutionTests : IDisposable
{
    private readonly TempDir _dir = new();
    public void Dispose() => _dir.Dispose();

    private static readonly byte[] MicrosoftToken = [0xb0, 0x3f, 0x5f, 0x7f, 0x11, 0xd5, 0x0a, 0x3a];
    private static readonly byte[] EcmaToken = [0xb7, 0x7a, 0x5c, 0x56, 0x19, 0x34, 0xe0, 0x89];

    private string Folder(string name)
    {
        var path = _dir.File(name);
        Directory.CreateDirectory(path);
        return path;
    }

    [Fact]
    public void AnOlderMajorVersion_ResolvesToThatFramework_WhenInstalled()
    {
        // .NET 5 and later: assembly versions follow the runtime's major version (.NET Core 3.1's System.Runtime is 4.2.2.0)
        var installed = Frameworks.All.Value.Where(s => s.Name == "Microsoft.NETCore.App" && s.Version.Major >= 5).Select(s => s.Version.Major).Distinct().OrderBy(m => m).ToList();
        if (installed.Count < 2) return; // needs two installed .NET 5+ versions
        int older = installed[0], newest = installed[^1];
        var file = new AssemblyWorkspace(new ServerOptions()).FindAssemblyFile("System.Runtime", null, MicrosoftToken, new Version(older, 0, 0, 0));
        Assert.NotNull(file);
        Assert.Equal(older, System.Reflection.AssemblyName.GetAssemblyName(file!).Version!.Major);
        // no version: the newest, as before
        var any = new AssemblyWorkspace(new ServerOptions()).FindAssemblyFile("System.Runtime", null, MicrosoftToken);
        Assert.Equal(newest, System.Reflection.AssemblyName.GetAssemblyName(any!).Version!.Major);
    }

    [Fact]
    public void LoadedBuildOfAnotherMajor_ElsewhereIsOnlyALastResort()
    {
        // distinct builds (the fixture helper derives the MVID from the name; the workspace treats equal MVIDs as one module)
        static byte[] Lib(int major) => ContainerFixtures.Module("Lib", m => { m.Assembly.Version = new Version(major, 0, 0, 0); m.Mvid = Guid.NewGuid(); });
        static string? Where(AssemblyWorkspace.ReferenceTarget? t) => t?.Loaded?.FilePath ?? t?.File;
        var v2 = Folder("v2");
        var v1 = Folder("v1");
        File.WriteAllBytes(Path.Combine(v2, "Lib.dll"), Lib(2));
        File.WriteAllBytes(Path.Combine(v1, "Lib.dll"), Lib(1));
        using var ws = new AssemblyWorkspace(new ServerOptions());
        ws.LoadDirectory(v2, false); // the other major first
        ws.LoadDirectory(v1, false);
        var requester = Path.Combine(Folder("app"), "App.dll");
        Assert.Equal(Path.Combine(v1, "Lib.dll"), Where(ws.LocateReference("Lib", new Version(1, 0, 0, 0), null, requester, false)));
        // only the other major loaded and no file anywhere: still resolved (better than nothing)
        using var only2 = new AssemblyWorkspace(new ServerOptions());
        only2.LoadDirectory(v2, false);
        File.Delete(Path.Combine(v1, "Lib.dll"));
        Assert.Equal(Path.Combine(v2, "Lib.dll"), Where(only2.LocateReference("Lib", new Version(1, 0, 0, 0), null, requester, false)));
    }

    [Fact]
    public void NetFrameworkApp_ReadsFrameworkAssembliesFromNetFramework()
    {
        if (Frameworks.NetFrameworkFile("mscorlib") is not { } netfxCorlib) return; // Windows with .NET Framework 4
        // an app that says it targets .NET Framework, next to a loaded modern .NET runtime folder's mscorlib facade
        var app = Path.Combine(Folder("netfx-app"), "App.dll");
        File.WriteAllBytes(app, ReferenceResolutionTests.Compile("App", "[assembly: System.Runtime.Versioning.TargetFramework(\".NETFramework,Version=v4.8\")] public class A { }"));
        using var ws = new AssemblyWorkspace(new ServerOptions());
        var loaded = ws.Load(app);
        Assert.True(Frameworks.TargetsNetFramework(loaded.Module));
        ws.Load(Path.Combine(Path.GetDirectoryName(typeof(object).Assembly.Location)!, "mscorlib.dll")); // .NET's facade, version 4.0.0.0
        var target = ws.LocateReference("mscorlib", new Version(4, 0, 0, 0), EcmaToken, app, netFramework: true)!;
        Assert.Equal(netfxCorlib, target.File, ignoreCase: true);
        Assert.False(Frameworks.TargetsNetFramework(ws.Get("mscorlib").Module));
        Assert.True(Frameworks.IsModernNet(ws.Get("mscorlib").Module));
        // a modern app is unaffected: the loaded facade
        Assert.NotNull(ws.LocateReference("mscorlib", new Version(4, 0, 0, 0), EcmaToken, app, netFramework: false)!.Loaded);
    }

    [Fact]
    public void CosturaEmbeddedAssemblies_ResolveReferences_ForDecompilingAndPatching()
    {
        // App references TestFixture, which ships only inside it as a Costura resource
        var fixture = File.ReadAllBytes(Env.FixturePath);
        var appImage = ReferenceResolutionTests.Compile("App", """
            public class Shop
            {
                public static string Who() => typeof(Fixture.Model.Account).Name;
                public int Price() => 1;
            }
            """, fixture);
        using (var module = ModuleDefMD.Load(appImage))
        {
            module.Resources.Add(new EmbeddedResource("costura.testfixture.dll.compressed", ContainerFixtures.Deflate(fixture)));
            var ms = new MemoryStream();
            module.Write(ms);
            appImage = ms.ToArray();
        }
        var path = Path.Combine(Folder("costura"), "App.exe");
        File.WriteAllBytes(path, appImage);

        using var env = new Env(path);
        var app = env.Fixture;
        var target = env.Workspace.LocateReference("TestFixture", null, null, path, false)!;
        Assert.Equal(("App", "embedded in App"), (target.EmbeddedIn, target.Describe()));
        var info = env.Workspace.Read(() => env.Report.Build(app));
        Assert.True(System.Text.RegularExpressions.Regex.IsMatch(info, @"TestFixture, Version=[^\]]*\[embedded in App\]"), info);
        Assert.Contains("typeof(Account)", env.Decompile("Shop::Who"));
        // the type's decompiled context needs Fixture.Model: compiles against the embedded copy
        env.Edit(() => env.Edits.PatchMethodCSharp(env.One("Shop::Price"), "return new Fixture.Model.Account(\"p\").Balance;", false, default));
        Assert.Contains("Balance", env.Decompile("Shop::Price"));
    }

    [Fact]
    public void Patch_DropsUsingsOfNamespacesThatNoReferenceProvides()
    {
        // App uses Gone.Thing inside a method body; Gone.dll is not shipped: the decompiled context's "using Gone;" fails
        var gone = ReferenceResolutionTests.Compile("Gone", "namespace Gone { public class Thing { } }");
        var path = Path.Combine(Folder("nogone"), "App.dll");
        File.WriteAllBytes(path, ReferenceResolutionTests.Compile("App", """
            using Gone;
            public class A
            {
                public static object Make() { return new Thing(); }
                public int N() => 1;
            }
            """, gone));
        using var env = new Env(path);
        env.Edit(() => env.Edits.PatchMethodCSharp(env.One("A::N"), "return 2;", false, default));
        Assert.Contains("return 2;", env.Decompile("A::N"));
    }

    [Fact]
    public void ExportedProject_DoesNotPinFrameworkAssemblies()
    {
        using var env = new Env();
        var result = env.Decompiler.ExportProject(env.Fixture, _dir.File("export"), null, default);
        var csproj = File.ReadAllText(result.ProjectFile!);
        Assert.DoesNotContain("System.Runtime", csproj);
        Assert.DoesNotContain(Path.GetDirectoryName(typeof(object).Assembly.Location)!, csproj);
    }
}
