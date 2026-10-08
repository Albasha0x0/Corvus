using dnlib.DotNet;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using NetDecompilerMcp.Core;
using NetDecompilerMcp.Services;

namespace NetDecompilerMcp.Tests;

/// <summary>
/// Several builds or runtime families loaded side by side (a managed's current folder, an older memory dump, an Il2Cpp
/// dummy-DLL set): a reference binds to the right same-named assembly.
/// </summary>
public class ReferenceResolutionTests : IDisposable
{
    private readonly TempDir _dir = new();
    public void Dispose() => _dir.Dispose();

    private string Folder(string name)
    {
        var path = _dir.File(name);
        Directory.CreateDirectory(path);
        return path;
    }

    private static string Write(string folder, string file, byte[] bytes)
    {
        var path = Path.Combine(folder, file);
        File.WriteAllBytes(path, bytes);
        return path;
    }

    private static TypeDefUser AddType(ModuleDefUser m, string ns, string name)
    {
        var t = new TypeDefUser(ns, name, m.CorLibTypes.Object.TypeDefOrRef) { Attributes = TypeAttributes.Public | TypeAttributes.Class };
        m.Types.Add(t);
        return t;
    }

    /// <summary>C# compiled against the running framework plus <paramref name="references"/>.</summary>
    internal static byte[] Compile(string name, string source, params byte[][] references)
    {
        var tpa = ((string)AppContext.GetData("TRUSTED_PLATFORM_ASSEMBLIES")!).Split(Path.PathSeparator)
            .Where(p => p.EndsWith(".dll", StringComparison.OrdinalIgnoreCase)).Select(p => MetadataReference.CreateFromFile(p));
        var compilation = CSharpCompilation.Create(name, [CSharpSyntaxTree.ParseText(source)],
            [.. tpa, .. references.Select(r => MetadataReference.CreateFromImage(r))],
            new CSharpCompilationOptions(OutputKind.DynamicallyLinkedLibrary));
        using var ms = new MemoryStream();
        var result = compilation.Emit(ms);
        Assert.True(result.Success, string.Join("\n", result.Diagnostics.Where(d => d.Severity == DiagnosticSeverity.Error)));
        return ms.ToArray();
    }

    [Fact]
    public void TwoBuildsSideBySide_AReferenceBindsToItsSiblingInTheSameFolder()
    {
        var older = Folder("build-old");
        var newer = Folder("build-new");
        Write(older, "Base.dll", ContainerFixtures.Module("Base", m => AddType(m, "Base", "Old")));
        var baseNew = ContainerFixtures.Module("Base", m => AddType(m, "Base", "New"));
        Write(newer, "Base.dll", baseNew);
        Write(newer, "App.dll", Compile("App", "public static class App { public static System.Type T() => typeof(Base.New); }", baseNew));

        using var ws = new AssemblyWorkspace(new ServerOptions());
        ws.LoadDirectory(older, false);   // the older build is loaded first: name-only matching would pick its Base
        ws.LoadDirectory(newer, false);
        var app = ws.Get("App");
        var siblingBase = ws.Get("Base#2");
        Assert.Equal(Path.Combine(newer, "Base.dll"), siblingBase.FilePath);

        var reference = ws.Read(() => app.Module.GetTypeRefs().Single(t => t.FullName == "Base.New"));
        var resolved = ws.Read(() => reference.ResolveTypeDef());
        Assert.NotNull(resolved);
        Assert.Same(siblingBase.Module, resolved!.Module);
        Assert.Contains("loaded as Base#2", ws.Read(() => new AssemblyReport(ws, new Il2CppService(ws)).Build(app)));
        Assert.Contains("typeof(New)", new DecompilerService(ws, new ServerOptions()).DecompileMembers(app,
            [ws.Read(() => app.Module.Types.Single(t => t.Name == "App").Methods.Single(m => m.Name == "T"))], default));
    }

    [Fact]
    public void Il2CppDummyMscorlib_DoesNotStandInForTheRealOne()
    {
        // an Il2Cpp dummy-DLL set: "mscorlib" without a public key, defining its own List<T>; its folder becomes a
        // search directory when it is loaded
        var dummy = Folder("DummyDll");
        Write(dummy, "mscorlib.dll", ContainerFixtures.Module("mscorlib", m =>
        {
            m.Assembly.Version = new Version(4, 0, 0, 0);
            var list = AddType(m, "System.Collections.Generic", "List`1");
            list.GenericParameters.Add(new GenericParamUser(0, GenericParamAttributes.NonVariant, "T"));
        }));
        // a managed folder: a library referencing the real mscorlib (Microsoft's token), and an app on .NET using List<T>
        var managed = Folder("Managed");
        var plugin = ContainerFixtures.Module("Plugin", m => AddType(m, "Plugin", "Marker"));
        Write(managed, "Plugin.dll", plugin);
        Write(managed, "Host.dll", Compile("Host", """
            public class Host
            {
                public static System.Type P() => typeof(Plugin.Marker);
                public int N() { var list = new System.Collections.Generic.List<int>(); return list.Count; }
            }
            """, plugin));

        using var env = new Env(Path.Combine(managed, "Host.dll"));
        env.Workspace.LoadDirectory(dummy, false);
        env.Workspace.LoadDirectory(managed, false);

        // the patch compilation sees one List<T> (CS0433 "exists in both mscorlib and System.Private.CoreLib" before)
        env.Edit(() => env.Edits.AddMembersCSharp(env.One("Host", NetDecompilerMcp.Core.SymbolKind.Type),
            "public int Twice(int x) { var list = new System.Collections.Generic.List<int> { x, x }; return list.Count; }", false, default));
        Assert.Contains("Twice", env.Decompile("Host"));
        env.Edit(() => env.Edits.PatchMethodCSharp(env.One("Host::N"), "var list = new System.Collections.Generic.List<int>(); list.Add(1); return list.Count;", false, default));
        var patched = env.Decompile("Host::N");
        Assert.True(patched.Contains("new List<int> { 1 }"), patched);

        // and the report does not claim the dummy mscorlib serves Plugin's reference
        var report = env.Workspace.Read(() => new AssemblyReport(env.Workspace, new Il2CppService(env.Workspace)).Build(env.Workspace.Get("Plugin")));
        Assert.DoesNotContain("[loaded as mscorlib]", report);
        Assert.True(System.Text.RegularExpressions.Regex.IsMatch(report,
            @"mscorlib, Version=[0-9.]+, Culture=neutral, PublicKeyToken=b77a5c561934e089\s+\[resolvable from search path\]"), report);
    }

    [Fact]
    public void WithinOneFolder_TokenlessReferencesStillBind()
    {
        // Il2Cpp dummy DLLs reference each other without tokens; same-folder binding must keep working
        var dummy = Folder("Dummies");
        Write(dummy, "Core.dll", ContainerFixtures.Module("Core", m => AddType(m, "Core", "Thing")));
        using var ws = new AssemblyWorkspace(new ServerOptions());
        ws.LoadDirectory(dummy, false);
        Assert.Same(ws.Get("Core"), ws.FindReference("Core", null, null, Path.Combine(dummy, "Other.dll")));
        Assert.Same(ws.Get("Core"), ws.FindReference("Core", null, null, null));
        Assert.Null(ws.FindReference("Core", null, [1, 2, 3, 4, 5, 6, 7, 8], Path.Combine(_dir.Path, "elsewhere", "x.dll")));
    }
}
