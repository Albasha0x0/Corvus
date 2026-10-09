using System.Runtime.Loader;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using NetDecompilerMcp.Services.Simplify;

namespace NetDecompilerMcp.Tests;

/// <summary>
/// simplify_methods on loads kept only for their effect (<c>_ = S.F;</c>): a repeat goes when the same load always ran
/// before it and its receivers cannot have changed; otherwise both stay. Every case runs before and after.
/// </summary>
public sealed class SimplifyLoadTests : IDisposable
{
    private readonly TempDir _dir = new();

    public void Dispose() => _dir.Dispose();

    private const string Source = """
        using System;

        namespace Ld
        {
            public sealed class Cfg
            {
                public int Mode;
                public readonly Cfg Inner;
                public Cfg(bool inner) { if (inner) Inner = new Cfg(false); }
            }

            public static class Holder
            {
                public static readonly Cfg Inst = new Cfg(true);
                public static Cfg Mutable = new Cfg(true);
                public static readonly Cfg Empty = null;
            }

            public static class Use
            {
                public static int Twice(int a) { _ = Holder.Inst.Mode; int x = a + 1; _ = Holder.Inst.Mode; return x; }
                public static int Chain(int a) { _ = Holder.Inst.Inner.Mode; _ = Holder.Inst.Inner.Mode; return a; }
                public static int Arg(int a) => ArgRoot(a == 0 ? null : Holder.Inst);
                private static int ArgRoot(Cfg c) { _ = c.Mode; _ = c.Mode; return 1; }
                public static int Branch(int a) { if (a > 0) _ = Holder.Inst.Mode; _ = Holder.Inst.Mode; return 2; }
                public static int Guarded(int a)
                {
                    try { _ = Holder.Empty.Mode; } catch (NullReferenceException) { a += 10; }
                    _ = Holder.Empty.Mode;
                    return a;
                }
                public static int Reassigned(int a)
                {
                    _ = Holder.Mutable.Mode;
                    if (a > 0) Holder.Mutable = null;
                    _ = Holder.Mutable.Mode;
                    return 3;
                }
                public static int Stored(int a) => StoredArg(Holder.Inst, a);
                private static int StoredArg(Cfg c, int a) { _ = c.Mode; if (a > 0) c = null; _ = c.Mode; return 4; }
            }
        }
        """;

    private string Fixture()
    {
        var path = _dir.File("Ld.dll");
        if (File.Exists(path)) return path;
        File.WriteAllBytes(path, Roslyn.Release("Ld", Source));
        return path;
    }

    /// <summary>What each argument gives: the result, or the exception thrown (each call in a fresh context).</summary>
    private static string Outcomes(byte[] image, string method) => string.Join(", ", new[] { 0, 1 }.Select(a =>
    {
        var context = new AssemblyLoadContext(null, isCollectible: true);
        try
        {
            var m = context.LoadFromStream(new MemoryStream(image)).GetType("Ld.Use", throwOnError: true)!.GetMethod(method)!;
            try { return $"{m.Invoke(null, [a])}"; }
            catch (System.Reflection.TargetInvocationException e) { return e.InnerException!.GetType().Name; }
        }
        finally
        {
            context.Unload();
        }
    }));

    private static int KeptLoads(Env env, string method) =>
        env.Def<MethodDef>(method).Body.Instructions.Count(i => i.OpCode.Code == Code.Pop);

    [Theory]
    [InlineData("Ld.Use::Twice", "Ld.Use::Twice")]
    [InlineData("Ld.Use::Chain", "Ld.Use::Chain")]
    [InlineData("Ld.Use::Arg", "Ld.Use::ArgRoot")]
    public void ARepeatOfALoadThatAlwaysRanFirstGoes(string entry, string method)
    {
        using var env = new Env(Fixture());
        var before = Outcomes(env.Fixture.OriginalBytes, entry.Split("::")[1]);
        Assert.Equal(2, KeptLoads(env, method));
        var report = env.Edit(() => env.Edits.SimplifyMethods(env.One(method).Assembly, env.One(method), SimplifyOptions.Parse(null, null, null), false, default));
        Assert.Contains("removed 1 repeated load(s) kept only for their effect", report);
        Assert.Equal(1, KeptLoads(env, method));
        Assert.Equal(before, Outcomes(env.Fixture.GetImageBytes(), entry.Split("::")[1]));
    }

    [Theory]
    [InlineData("Ld.Use::Branch", "Ld.Use::Branch")]       // the first load runs only on one path
    [InlineData("Ld.Use::Guarded", "Ld.Use::Guarded")]     // the first may throw into the catch, which then reaches the second
    [InlineData("Ld.Use::Reassigned", "Ld.Use::Reassigned")] // the static is written in between
    [InlineData("Ld.Use::Stored", "Ld.Use::StoredArg")]    // the argument is stored to in between
    public void ALoadThatMayDoSomethingNewStays(string entry, string method)
    {
        using var env = new Env(Fixture());
        var before = Outcomes(env.Fixture.OriginalBytes, entry.Split("::")[1]);
        int loads = KeptLoads(env, method);
        var report = env.Edit(() => env.Edits.SimplifyMethods(env.One(method).Assembly, env.One(method), SimplifyOptions.Parse(null, null, null), false, default));
        Assert.DoesNotContain("repeated load", report);
        Assert.Equal(loads, KeptLoads(env, method));
        Assert.Equal(before, Outcomes(env.Fixture.GetImageBytes(), entry.Split("::")[1]));
    }
}
