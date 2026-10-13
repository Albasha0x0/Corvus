using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;

namespace Corvus.Tests;

/// <summary>
/// C# patches against a framework assembly whose name the runtime also uses for an older facade (WPF's WindowsBase 9.0 beside
/// the runtime's WindowsBase 4.0; CS1705 and CS7069 in bloxstrap, compactgui and screentogif).
/// </summary>
public sealed class CSharpReferenceVersionTests : IDisposable
{
    private readonly TempDir _dir = new();

    public void Dispose() => _dir.Dispose();

    private static byte[] CompileWithout(string name, string source, string without, params byte[][] references)
    {
        var platform = Roslyn.PlatformReferences.Where(r => !string.Equals(Path.GetFileNameWithoutExtension(r.Display), without, StringComparison.OrdinalIgnoreCase));
        var compilation = CSharpCompilation.Create(name, [CSharpSyntaxTree.ParseText(source)], [.. platform, .. references.Select(r => MetadataReference.CreateFromImage(r))],
            new CSharpCompilationOptions(OutputKind.DynamicallyLinkedLibrary));
        using var ms = new MemoryStream();
        var result = compilation.Emit(ms);
        Assert.True(result.Success, string.Join("\n", result.Diagnostics.Where(d => d.Severity == DiagnosticSeverity.Error)));
        return ms.ToArray();
    }

    private string Patch(string app, string method, string code)
    {
        using var env = new Env(app);
        return env.Workspace.Read(() => env.Edits.PatchMethodCSharp(env.One(method), code, dryRun: true, default));
    }

    [Fact]
    public void AFrameworkAssemblyNewerThanTheRuntimesFacadeOfTheSameNameIsKept()
    {
        var desktop = Directory.CreateDirectory(_dir.File("desktop")).FullName;
        var windowsBase = CompileWithout("WindowsBase", "[assembly: System.Reflection.AssemblyVersion(\"9.0.0.0\")] namespace System.Windows { public class DependencyObject { public int Id; } }",
            "WindowsBase");
        File.WriteAllBytes(Path.Combine(desktop, "WindowsBase.dll"), windowsBase);
        File.WriteAllBytes(Path.Combine(desktop, "App.dll"),
            CompileWithout("App", "namespace App { public class View : System.Windows.DependencyObject { public int Run() { return Id; } } }", "WindowsBase", windowsBase));
        Assert.Contains("compiled OK", Patch(Path.Combine(desktop, "App.dll"), "App.View::Run", "return Id + 1;"));
    }
}
