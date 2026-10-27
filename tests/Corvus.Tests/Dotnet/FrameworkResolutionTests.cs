using dnlib.DotNet;
using Corvus.Core;
using Corvus.Services;

namespace Corvus.Tests;

/// <summary>References resolve to the right framework version, .NET Framework, or a Costura-embedded copy.</summary>
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

    // Regression: on a GitHub runner a call waited over 20 s while a downloaded pack was written out (CI on e579b9a2).
    [Fact]
    public void A_reference_pack_is_written_without_its_documentation_files()
    {
        var bytes = new MemoryStream();
        using (var zip = new System.IO.Compression.ZipArchive(bytes, System.IO.Compression.ZipArchiveMode.Create, leaveOpen: true))
            foreach (var name in new[] { "ref/net6.0/System.Runtime.dll", "ref/net6.0/System.Runtime.xml", "data/FrameworkList.xml", "lib/net6.0/x.dll", "Microsoft.NETCore.App.Ref.nuspec" })
                using (var w = new StreamWriter(zip.CreateEntry(name).Open())) w.Write(name);
        bytes.Position = 0;
        var folder = Folder("pack");
        using (var zip = new System.IO.Compression.ZipArchive(bytes, System.IO.Compression.ZipArchiveMode.Read))
            ReferencePacks.Extract(zip, folder);
        Assert.Equal(["data/FrameworkList.xml", "ref/net6.0/System.Runtime.dll"],
            Directory.EnumerateFiles(folder, "*", SearchOption.AllDirectories).Select(f => Path.GetRelativePath(folder, f).Replace('\\', '/')).Order(StringComparer.Ordinal));
    }

    private sealed class FakeFeed(Func<string, byte[]?> answer) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct) =>
            Task.FromResult(answer(request.RequestUri!.ToString()) is { } body
                ? new HttpResponseMessage(System.Net.HttpStatusCode.OK) { Content = new ByteArrayContent(body) }
                : new HttpResponseMessage(System.Net.HttpStatusCode.NotFound));
    }

    [Fact]
    public void A_pack_is_extracted_only_when_it_matches_the_catalog_hash()
    {
        var package = new MemoryStream();
        using (var zip = new System.IO.Compression.ZipArchive(package, System.IO.Compression.ZipArchiveMode.Create, leaveOpen: true))
            using (var w = new StreamWriter(zip.CreateEntry("ref/net6.0/System.Runtime.dll").Open())) w.Write("dll");
        var good = package.ToArray();
        var hash = Convert.ToBase64String(System.Security.Cryptography.SHA512.HashData(good));
        (string? Dir, string? Problem) Download(byte[] served, string root)
        {
            using var http = new HttpClient(new FakeFeed(url => url switch
            {
                "https://api.nuget.org/v3-flatcontainer/test.app.ref/index.json" => """{"versions":["6.0.1","7.0.0"]}"""u8.ToArray(),
                "https://api.nuget.org/v3/registration5-semver1/test.app.ref/6.0.1.json" =>
                    """{"catalogEntry":"https://api.nuget.org/v3/catalog0/data/2024.01.01/test.app.ref.6.0.1.json"}"""u8.ToArray(),
                "https://api.nuget.org/v3/catalog0/data/2024.01.01/test.app.ref.6.0.1.json" =>
                    System.Text.Encoding.UTF8.GetBytes($$"""{"packageHash":"{{hash}}","packageHashAlgorithm":"SHA512"}"""),
                "https://api.nuget.org/v3-flatcontainer/test.app.ref/6.0.1/test.app.ref.6.0.1.nupkg" => served,
                _ => null,
            }));
            return ReferencePacks.Download(http, "Test.App.Ref", 6, Folder(root));
        }

        var accepted = Download(good, "good");
        Assert.Null(accepted.Problem);
        Assert.True(File.Exists(Path.Combine(accepted.Dir!, "System.Runtime.dll")));

        var tampered = (byte[])good.Clone();
        tampered[^1] ^= 1;
        var refused = Download(tampered, "tampered");
        Assert.Null(refused.Dir);
        Assert.Equal("reference pack test.app.ref 6.0.1 refused: its SHA-512 does not match nuget.org's package hash", refused.Problem);
        Assert.Empty(Directory.EnumerateFileSystemEntries(Folder("tampered")));
    }

    [Fact]
    public void An_older_major_version_resolves_to_that_framework_when_installed()
    {
        // From .NET 5, assembly versions follow the runtime's major version.
        var installed = Frameworks.All.Value.Where(s => s.Name == "Microsoft.NETCore.App" && s.Version.Major >= 5).Select(s => s.Version.Major).Distinct().OrderBy(m => m).ToList();
        if (installed.Count < 2) return; // needs two installed .NET 5+ versions
        int older = installed[0], newest = installed[^1];
        var file = new AssemblyWorkspace(new ServerOptions()).FindAssemblyFile("System.Runtime", null, MicrosoftToken, new Version(older, 0, 0, 0));
        Assert.NotNull(file);
        Assert.Equal(older, System.Reflection.AssemblyName.GetAssemblyName(file!).Version!.Major);
        // Without a version: the newest.
        var any = new AssemblyWorkspace(new ServerOptions()).FindAssemblyFile("System.Runtime", null, MicrosoftToken);
        Assert.Equal(newest, System.Reflection.AssemblyName.GetAssemblyName(any!).Version!.Major);
    }

    [Fact]
    public void Loaded_build_of_another_major_elsewhere_is_only_a_last_resort()
    {
        // Fresh MVIDs: the workspace treats equal MVIDs as one module.
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
        // Only the other major available: used as a fallback.
        using var only2 = new AssemblyWorkspace(new ServerOptions());
        only2.LoadDirectory(v2, false);
        File.Delete(Path.Combine(v1, "Lib.dll"));
        Assert.Equal(Path.Combine(v2, "Lib.dll"), Where(only2.LocateReference("Lib", new Version(1, 0, 0, 0), null, requester, false)));
    }

    [Fact]
    public void NET_Framework_app_reads_framework_assemblies_from_NET_Framework()
    {
        if (Frameworks.NetFrameworkFile("mscorlib") is not { } netfxCorlib) return; // Windows with .NET Framework 4
        // A .NET Framework app with a modern mscorlib facade also loaded.
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
        // A modern app gets the loaded facade.
        Assert.NotNull(ws.LocateReference("mscorlib", new Version(4, 0, 0, 0), EcmaToken, app, netFramework: false)!.Loaded);
    }

    [Fact]
    public void Costura_embedded_assemblies_resolve_references_for_decompiling_and_patching()
    {
        // TestFixture ships only as a Costura resource inside App.
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
        // The patch compiles against the embedded copy.
        env.Edit(() => env.Edits.PatchMethodCSharp(env.One("Shop::Price"), "return new Fixture.Model.Account(\"p\").Balance;", false, default));
        Assert.Contains("Balance", env.Decompile("Shop::Price"));
    }

    [Fact]
    public void Patch_drops_usings_of_namespaces_that_no_reference_provides()
    {
        // Gone.dll is not shipped, so the decompiled context's "using Gone;" cannot resolve.
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
    public void Exported_project_does_not_pin_framework_assemblies()
    {
        using var env = new Env();
        var result = env.Decompiler.ExportProject(env.Fixture, _dir.File("export"), null, default);
        var csproj = File.ReadAllText(result.ProjectFile!);
        Assert.DoesNotContain("System.Runtime", csproj);
        Assert.DoesNotContain(Path.GetDirectoryName(typeof(object).Assembly.Location)!, csproj);
    }
}
