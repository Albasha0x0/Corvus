using System.Runtime.Loader;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using NetDecompilerMcp.Services.Simplify;
using SymbolKind = NetDecompilerMcp.Core.SymbolKind;

namespace NetDecompilerMcp.Tests;

/// <summary>
/// simplify_methods with class instances the evaluated code creates: singletons whose fields are set at startup and only
/// read afterwards (as .NET Reactor's provably-constant conditions read a field of a &lt;Module&gt; object), instance and virtual
/// calls, and instances that are modified later, which must stay. The fixture runs before and after.
/// </summary>
public sealed class SimplifyInstanceTests : IDisposable
{
    private readonly TempDir _dir = new();

    public void Dispose() => _dir.Dispose();

    private const string Source = """
        namespace Inst
        {
            internal sealed class Config
            {
                public int Mode;
                public string Name;
                public Config(int mode) { Mode = mode; Name = "cfg" + mode.ToString(); }
                public string GetName() => Name;
            }

            internal static class Holder
            {
                internal static Config Instance = new Config(3);
            }

            // Reactor-style: a singleton whose fields nothing ever writes.
            internal sealed class Flags
            {
                internal int A;
                internal int B;
            }

            internal static class FlagsHolder
            {
                internal static Flags F = new Flags();
            }

            public abstract class Shape
            {
                public abstract int Sides();
                public virtual string Describe() => "shape:" + Sides().ToString();
            }

            public sealed class Tri : Shape
            {
                public override int Sides() => 3;
            }

            public class Sq : Shape
            {
                public override int Sides() => 4;
                public override string Describe() => "square";
            }

            // Reactor-style with an initializer the evaluator cannot run: Never is never written, so it is 0 on any object.
            internal sealed class Guard
            {
                internal int Never;
            }

            internal static class GuardHolder
            {
                internal static Guard G = Make();
                internal static Guard Missing;
                private static Guard Make() { System.IO.File.Exists("not-evaluable"); return new Guard(); }
            }

            internal sealed class CounterObj
            {
                internal int N;
            }

            public static class Counter
            {
                internal static CounterObj C = new CounterObj();
                public static void Bump() => C.N++;
            }

            public static class Use
            {
                public static int Mode(int x)
                {
                    if (Holder.Instance.Mode == 3) return x + 1;
                    return x - 1;
                }

                public static int ConstantCondition(int x)
                {
                    if (FlagsHolder.F.A != 0) return -x;
                    if (FlagsHolder.F.B == 0) x *= 2;
                    return x;
                }

                public static string Name() => Holder.Instance.GetName();

                public static string Shapes() => new Tri().Describe() + "," + new Sq().Describe();

                public static int Reactor(int x)
                {
                    if (GuardHolder.G.Never != 0) return -x;
                    return x + 7;
                }

                public static int NullSingleton(int x)
                {
                    if (GuardHolder.Missing.Never != 0) return -x;
                    return x + 7;
                }

                public static int Mutated(int x)
                {
                    if (Counter.C.N == 0) return x;
                    return -x;
                }
            }
        }
        """;

    private string Fixture()
    {
        var path = _dir.File("Inst.dll");
        if (File.Exists(path)) return path;
        var references = ((string)AppContext.GetData("TRUSTED_PLATFORM_ASSEMBLIES")!).Split(Path.PathSeparator)
            .Where(p => p.EndsWith(".dll", StringComparison.OrdinalIgnoreCase)).Select(p => MetadataReference.CreateFromFile(p));
        var compilation = CSharpCompilation.Create("Inst", [CSharpSyntaxTree.ParseText(Source)], references,
            new CSharpCompilationOptions(OutputKind.DynamicallyLinkedLibrary, optimizationLevel: OptimizationLevel.Release));
        using var ms = new MemoryStream();
        var result = compilation.Emit(ms);
        Assert.True(result.Success, string.Join("\n", result.Diagnostics.Where(d => d.Severity == DiagnosticSeverity.Error)));
        File.WriteAllBytes(path, ms.ToArray());
        return path;
    }

    private static string Simplify(Env env, string symbol) =>
        env.Edit(() => env.Edits.SimplifyMethods(env.One(symbol).Assembly, env.One(symbol), SimplifyOptions.Parse(null, null, null), false, default));

    private static List<Instruction> Body(Env env, string method) => env.Def<MethodDef>(method, SymbolKind.Method).Body.Instructions.ToList();

    private static object? Run(byte[] image, string method, params object?[] args)
    {
        var context = new AssemblyLoadContext(null, isCollectible: true);
        try
        {
            var asm = context.LoadFromStream(new MemoryStream(image));
            return asm.GetType("Inst.Use", throwOnError: true)!.GetMethod(method)!.Invoke(null, args);
        }
        finally
        {
            context.Unload();
        }
    }

    [Theory]
    [InlineData("Mode", 1)]
    [InlineData("ConstantCondition", 2)]
    public void ConditionsOnFieldsOfSingletonsFold(string method, int branches)
    {
        using var env = new Env(Fixture());
        var report = Simplify(env, "Inst.Use::" + method);
        Assert.Contains($"folded {branches} constant branch(es)", report);
        var code = Body(env, "Inst.Use::" + method);
        Assert.DoesNotContain(code, i => i.OpCode.FlowControl == FlowControl.Cond_Branch || i.OpCode.Code is Code.Ldsfld or Code.Ldfld);
        var image = env.Fixture.GetImageBytes();
        foreach (var x in new[] { 0, 5, -3 })
            Assert.Equal(Run(env.Fixture.OriginalBytes, method, x), Run(image, method, x));
    }

    [Theory]
    [InlineData("Name", "cfg3")]
    [InlineData("Shapes", "shape:3,square")]
    public void InstanceAndVirtualCallsFoldToLiterals(string method, string literal)
    {
        using var env = new Env(Fixture());
        var report = Simplify(env, "Inst.Use::" + method);
        Assert.Contains($"-> \"{literal}\"", report);
        Assert.Equal([Code.Ldstr, Code.Ret], Body(env, "Inst.Use::" + method).Select(i => i.OpCode.Code));
        Assert.Equal(literal, Run(env.Fixture.GetImageBytes(), method));
    }

    /// <summary>
    /// A field nothing writes is its default on every object, even when the singleton's initializer cannot be evaluated;
    /// the load stays, so a null singleton still throws as it did.
    /// </summary>
    [Theory]
    [InlineData("Reactor")]
    [InlineData("NullSingleton")]
    public void FieldsNothingWritesFoldWithTheirLoadKept(string method)
    {
        using var env = new Env(Fixture());
        var report = Simplify(env, "Inst.Use::" + method);
        Assert.Contains("folded 1 constant branch(es)", report);
        var code = Body(env, "Inst.Use::" + method);
        Assert.DoesNotContain(code, i => i.OpCode.FlowControl == FlowControl.Cond_Branch);
        Assert.Contains(code, i => i.Operand is IField { Name.String: "Never" });
        var image = env.Fixture.GetImageBytes();
        foreach (var x in new[] { 0, 5 })
        {
            var (expected, actual) = (RunOrError(env.Fixture.OriginalBytes, method, x), RunOrError(image, method, x));
            if (method == "NullSingleton")
            {
                Assert.IsType<NullReferenceException>(expected);
                Assert.IsType<NullReferenceException>(actual);
            }
            else Assert.Equal(expected, actual);
        }
    }

    private static object? RunOrError(byte[] image, string method, params object?[] args)
    {
        try { return Run(image, method, args); }
        catch (System.Reflection.TargetInvocationException ex) { return ex.InnerException; }
    }

    [Fact]
    public void FieldsOfInstancesModifiedLaterStay()
    {
        using var env = new Env(Fixture());
        var before = string.Join("\n", Body(env, "Inst.Use::Mutated"));
        var report = Simplify(env, "Inst.Use::Mutated");
        Assert.Contains("0 of 1 method(s) changed", report);
        Assert.Equal(before, string.Join("\n", Body(env, "Inst.Use::Mutated")));
    }
}
