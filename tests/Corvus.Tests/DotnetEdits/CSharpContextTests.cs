using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;

namespace Corvus.Tests;

/// <summary>C# patches whose decompiled context or references bound differently from the original (harness rows that failed to compile).</summary>
[Trait("Speed", "Slow")]
public sealed class CSharpContextTests : IDisposable
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

    /// <summary>Adding members compiles the whole decompiled type (a body patch compiles only the body).</summary>
    private string AddMember(string app, string type)
    {
        using var env = new Env(app);
        return env.Workspace.Read(() => env.Edits.AddMembersCSharp(env.One(type, Core.SymbolKind.Type), "public static int Probe2() { return 7; }", dryRun: true, default));
    }

    [Fact]
    public void A_framework_assembly_newer_than_the_runtimes_facade_of_the_same_name_is_kept()
    {
        var desktop = Directory.CreateDirectory(_dir.File("desktop")).FullName;
        var windowsBase = CompileWithout("WindowsBase", "[assembly: System.Reflection.AssemblyVersion(\"9.0.0.0\")] namespace System.Windows { public class DependencyObject { public int Id; } }",
            "WindowsBase");
        File.WriteAllBytes(Path.Combine(desktop, "WindowsBase.dll"), windowsBase);
        File.WriteAllBytes(Path.Combine(desktop, "App.dll"),
            CompileWithout("App", "namespace App { public class View : System.Windows.DependencyObject { public int Run() { return Id; } } }", "WindowsBase", windowsBase));
        Assert.Contains("compiled OK", Patch(Path.Combine(desktop, "App.dll"), "App.View::Run", "return Id + 1;"));
    }

    /// <summary>Regression: usings moved into the type's namespace bound an imported type before the enclosing namespace's (CS0115, CS1503).</summary>
    [Fact]
    public void An_enclosing_namespaces_type_binds_before_an_imported_one_of_the_same_name()
    {
        File.WriteAllBytes(_dir.File("Nest.dll"), Roslyn.Compile("Nest", """
            namespace A.B { public abstract class Node { protected Node(int x) { } public abstract int Run(); } }
            namespace A.B.C.Internal { public class Node { } public static class Helper { public static int Get() => 1; } }
            namespace A.B.C
            {
                public class X : A.B.Node
                {
                    public X() : base(1) { }
                    public override int Run() => A.B.C.Internal.Helper.Get();
                    public A.B.C.Internal.Node Make() => new A.B.C.Internal.Node();
                }
            }
            """, new CSharpCompilationOptions(OutputKind.DynamicallyLinkedLibrary)));
        Assert.Contains("compiled OK", AddMember(_dir.File("Nest.dll"), "A.B.C.X"));
    }

    /// <summary>Regression: the stand-in for a missing base library declared an out parameter as ref, failing every override (CS0115).</summary>
    [Fact]
    public void Overrides_with_out_parameters_of_a_missing_base_compile()
    {
        var options = new CSharpCompilationOptions(OutputKind.DynamicallyLinkedLibrary);
        var baseLib = Roslyn.Compile("BaseLib", "namespace BaseLib { public abstract class FileSystem { public virtual int Info(out int size) { size = 0; return 0; } } }", options);
        File.WriteAllBytes(_dir.File("Fs.dll"), Roslyn.Compile("Fs",
            "namespace Fs { public class Mem : BaseLib.FileSystem { public override int Info(out int size) { size = 4; return 1; } public int Probe() => 1; } }",
            options, [MetadataReference.CreateFromImage(baseLib)])); // BaseLib.dll is missing
        Assert.Contains("compiled OK", AddMember(_dir.File("Fs.dll"), "Fs.Mem"));
    }
}
