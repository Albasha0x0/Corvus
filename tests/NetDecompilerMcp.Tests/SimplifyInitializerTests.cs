using System.Reflection;
using System.Runtime.Loader;
using dnlib.DotNet;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using NetDecompilerMcp.Services.Simplify;

namespace NetDecompilerMcp.Tests;

/// <summary>
/// simplify_methods on a static constructor whose own calls need the state it is building: a call folds (or a call
/// through a delegate field resolves) on the state as it stands at the call when the constructor reaches it at most
/// once; a call in a loop, or one that writes the type's own statics, is kept and reported. The fields the constructor
/// sets are compared before and after.
/// </summary>
public sealed class SimplifyInitializerTests : IDisposable
{
    private readonly TempDir _dir = new();

    public void Dispose() => _dir.Dispose();

    private const string Source = """
        using System;

        namespace Ini
        {
            // Evaluated first (types run in order): reading T.R runs T's whole initializer, and U's within it.
            public static class A
            {
                public static string Use() => Get();
                private static string Get() => T.R;
            }

            public static class T
            {
                private static string S; // set by reflection only
                public static readonly string R;

                static T()
                {
                    U.Touch();        // U's initializer sets S by reflection: no call reaches T from it
                    R = Helper();     // "set-by-U"
                }

                private static string Helper() => S ?? "none";
            }

            public static class U
            {
                static U() => typeof(T).GetField("S", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Static).SetValue(null, "set-by-U");
                public static void Touch() { }
            }

            public static class Init
            {
                private static readonly string[] Table;
                private static readonly string Prefix;
                private static readonly Func<int, string> D;
                private static string Last;

                public static readonly string E, G, A, L, C;

                static Init()
                {
                    Table = new[] { "x", "y", "z" };
                    E = WithPrefix(0);                         // Prefix is still null here: "x"
                    Prefix = "p:";
                    G = WithPrefix(1);                         // "p:y"
                    D = Decode;
                    A = D(2);                                  // through the field set just before
                    for (int k = 0; k < 2; k++) L = L + Get(1); // the call runs twice: kept
                    C = Remember(0);                           // writes Last: kept
                }

                private static string WithPrefix(int i) => Prefix + Table[i];
                private static string Get(int i) => Table[i];
                private static string Decode(int i) => "abcdef".Substring(i, 2);
                private static string Remember(int i)
                {
                    Last = Table[i] + "!";
                    return Table[i];
                }

                public static string Fields() => string.Join("|", E, G, A, L, C, Last);
            }
        }
        """;

    private string Fixture()
    {
        var path = _dir.File("Ini.dll");
        if (File.Exists(path)) return path;
        File.WriteAllBytes(path, Roslyn.Release("Ini", Source));
        return path;
    }

    private static string Fields(byte[] image)
    {
        var context = new AssemblyLoadContext(null, isCollectible: true);
        try
        {
            var asm = context.LoadFromStream(new MemoryStream(image));
            return (string)asm.GetType("Ini.Init", throwOnError: true)!.GetMethod("Fields")!.Invoke(null, [])!;
        }
        finally
        {
            context.Unload();
        }
    }

    private static string Simplify(Env env, bool dryRun = false) =>
        env.Edit(() => env.Edits.SimplifyMethods(env.One("Ini.Init::.cctor").Assembly, env.One("Ini.Init::.cctor"), SimplifyOptions.Parse(null, null, null), dryRun, default));

    [Fact]
    public void CallsInsideTheInitializerUseTheStateAtTheCall()
    {
        using var env = new Env(Fixture());
        var before = Fields(env.Fixture.OriginalBytes);
        Assert.Equal("x|p:y|cd|yy|x|x!", before);

        var report = Simplify(env);
        Assert.Contains("1 of 1 method(s) changed", report);
        Assert.Contains("Ini.Init::WithPrefix(int) -> \"x\"", report);
        Assert.Contains("Ini.Init::WithPrefix(int) -> \"p:y\"", report);
        Assert.Contains("Ini.Init::D.Invoke -> Ini.Init::Decode(int)", report);
        Assert.Contains("Ini.Init::Decode(int) -> \"cd\"", report);
        Assert.Matches(@"Ini\.Init::Get\(int\): needs the static state of Ini\.Init inside its own static constructor, at IL_\w{4}, which can run more than once there \[static-initializer\]", report);
        Assert.Contains("Ini.Init::Decode(int) -> \"cd\"", report);
        Assert.Matches(@"Ini\.Init::Remember\(int\): writes static field Ini\.Init::Last of the type whose static constructor is running \[mutable-static\]", report);

        var calls = env.Def<MethodDef>("Ini.Init::.cctor").Body.Instructions.Where(i => i.OpCode.Code is dnlib.DotNet.Emit.Code.Call or dnlib.DotNet.Emit.Code.Callvirt).Select(i => ((IMethod)i.Operand).Name.String).ToList();
        Assert.DoesNotContain("WithPrefix", calls);
        Assert.DoesNotContain("Invoke", calls);
        Assert.DoesNotContain("Decode", calls);
        Assert.Contains("Get", calls);
        Assert.Contains("Remember", calls);
        Assert.Equal(before, Fields(env.Fixture.GetImageBytes()));
    }

    [Fact]
    public void TypesInitializedWithinItStartOverWhenTheyTouchedItsState()
    {
        // T's own initializer runs again to its call of Helper: U's initializer, known from the run for A.Use, wrote
        // T.S by reflection, so it runs again too (rather than leaving S unset there).
        using var env = new Env(Fixture());
        var assembly = env.One("Ini.T::.cctor").Assembly;
        var report = env.Edit(() => env.Edits.SimplifyMethods(assembly, null, SimplifyOptions.Parse(null, null, null), true, default));
        Assert.Contains("Ini.A::Get() -> \"set-by-U\"", report);
        Assert.Contains("Ini.T::Helper() -> \"set-by-U\"", report);
        Assert.DoesNotContain("\"none\"", report);
    }

    [Fact]
    public void OutsideTheInitializerTheStateIsTheFinishedOne()
    {
        // The same helpers called from elsewhere still see the constructor's whole run (or are kept as before).
        using var env = new Env(Fixture());
        var report = env.Edit(() => env.Edits.SimplifyMethods(env.One("Ini.Init::Fields").Assembly, env.One("Ini.Init::Fields"), SimplifyOptions.Parse(null, null, null), true, default));
        Assert.DoesNotContain("which can run more than once", report);
        Assert.DoesNotContain("whose static constructor is running", report);
    }
}
