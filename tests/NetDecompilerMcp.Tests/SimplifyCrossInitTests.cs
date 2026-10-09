using System.Runtime.Loader;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using NetDecompilerMcp.Services.Simplify;

namespace NetDecompilerMcp.Tests;

/// <summary>
/// A static constructor that writes another type's static field: modelled when every read of the field is ordered
/// against the write (the target's own initialization runs first, the writer's initialization runs precisely, and the
/// field is read only by the target's initialization, the writer's, or the writer's own methods); otherwise the read
/// keeps the mutable-static bail-out. The program runs the same before and after.
/// </summary>
public sealed class SimplifyCrossInitTests : IDisposable
{
    private readonly TempDir _dir = new();

    public void Dispose() => _dir.Dispose();

    private const string Source = """
        namespace Cross
        {
            internal static class Store
            {
                internal static string Key;
                internal static int[] Table;
                internal static string Other;
                internal static string Key2;
                static Store() { Key = "own"; }
                public static string Peek() => Other; // a read the writer's initialization is not ordered before
            }

            public static class Writer
            {
                public static readonly string Copy;
                static Writer()
                {
                    Store.Key = Store.Key + ":" + Make("k", 3); // Store's initializer has run: "own:kkk"
                    Store.Table = new[] { 1, 2, 3 };
                    Store.Table[1] = 7;
                    Copy = Store.Key + "!";
                    Tag = Helper(); // folding the call would drop its write to Store.Key2
                }
                public static readonly string Tag;
                private static string Helper()
                {
                    Store.Key2 = "z";
                    return "h";
                }
                public static string GetKey2() => Store.Key2 + Tag;
                private static string Make(string s, int n)
                {
                    var r = "";
                    for (int i = 0; i < n; i++) r += s;
                    return r;
                }
                public static string Get()
                {
                    int v = Store.Table[1];
                    return Store.Key + v;
                }
                public static string GetCopy() => Copy;
            }

            // Store.Other is also read by Store.Peek, which can run before this initializer.
            public static class Writer2
            {
                static Writer2() { Store.Other = "o"; }
                public static string Get() => Store.Other;
            }

            // Two initializers write the same field: the value depends on which runs first.
            internal static class Shared { internal static string V; }
            public static class W1 { static W1() { Shared.V = "1"; } public static string Get() => Shared.V; }
            public static class W2 { static W2() { Shared.V = "2"; } public static string Get() => Shared.V; }

            // No static constructor of its own (beforefieldinit): calling Get need not run the initializer first.
            internal static class Target3 { internal static string V; }
            public static class Relaxed
            {
                private static readonly int Unused = Set();
                private static int Set() { Target3.V = "x"; return 0; }
                public static string Get() => Target3.V;
            }

            // Written outside any initializer.
            internal static class Target4 { internal static string V; }
            public static class Late
            {
                static Late() { }
                public static void Set() { Target4.V = "y"; }
                public static string Get() => Target4.V;
            }

            public static class Use
            {
                public static string All()
                {
                    Late.Set();
                    return string.Join("|", Writer.Get(), Writer.GetCopy(), Writer.GetKey2(), Writer2.Get(), Store.Peek(), W1.Get(), W2.Get(), Relaxed.Get(), Late.Get());
                }
            }
        }
        """;

    private string Fixture()
    {
        var path = _dir.File("Cross.dll");
        if (File.Exists(path)) return path;
        File.WriteAllBytes(path, Roslyn.Release("Cross", Source));
        return path;
    }

    private static string Run(byte[] image)
    {
        var context = new AssemblyLoadContext(null, isCollectible: true);
        try
        {
            var asm = context.LoadFromStream(new MemoryStream(image));
            return (string)asm.GetType("Cross.Use", throwOnError: true)!.GetMethod("All")!.Invoke(null, [])!;
        }
        finally
        {
            context.Unload();
        }
    }

    private static string Simplify(Env env, string scope, bool dryRun = true) =>
        env.Edit(() => env.Edits.SimplifyMethods(env.One(scope).Assembly, env.One(scope), SimplifyOptions.Parse(null, null, null), dryRun, default));

    [Fact]
    public void OrderedWritesFromAnotherInitializerFold()
    {
        using var env = new Env(Fixture());
        var before = Run(env.Fixture.OriginalBytes);
        // Store's own initializer runs before the writer's first access, which then overwrites Key.
        Assert.StartsWith("own:kkk7|own:kkk!|zh|o|o|", before);
        var report = Simplify(env, "Cross.Use", dryRun: false);
        Assert.Contains("folded Cross.Writer::Get() -> \"own:kkk7\"", report);
        Assert.Contains("folded Cross.Writer::GetCopy() -> \"own:kkk!\"", report);
        Assert.Contains("folded Cross.Writer::GetKey2() -> \"zh\"", report);
        Assert.Equal(before, Run(env.Fixture.GetImageBytes()));
    }

    [Fact]
    public void UnorderedWritesKeepTheBailout()
    {
        using var env = new Env(Fixture());
        var report = Simplify(env, "Cross.Use");
        // Store.Other is read by Store.Peek, which can run before Writer2's initializer: the write and the reads keep the
        // bail-outs they had.
        Assert.Contains("Cross.Writer2::Get(): static constructor of Cross.Writer2 cannot be evaluated: writes static field Cross.Store::Other outside its static constructor [static-initializer]", report);
        Assert.Contains("Cross.Store::Peek(): reads mutable static field Cross.Store::Other [mutable-static]", report);
        // Two writers; a writer without a static constructor of its own; a write outside any initializer.
        Assert.Contains("Cross.W1::Get(): static constructor of Cross.W1 cannot be evaluated: writes static field Cross.Shared::V outside its static constructor [static-initializer]", report);
        Assert.Contains("Cross.W2::Get(): static constructor of Cross.W2 cannot be evaluated: writes static field Cross.Shared::V outside its static constructor [static-initializer]", report);
        Assert.Contains("Cross.Relaxed::Get(): reads mutable static field Cross.Target3::V [mutable-static]", report);
        Assert.Contains("Cross.Late::Get(): reads mutable static field Cross.Target4::V [mutable-static]", report);
    }

    [Fact]
    public void TheWritersOwnInitializerKeepsCallsThatWriteTheField()
    {
        using var env = new Env(Fixture());
        var before = Run(env.Fixture.OriginalBytes);
        var report = Simplify(env, "Cross.Writer::.cctor", dryRun: false);
        Assert.Contains("folded Cross.Writer::Make(string, int) -> \"kkk\"", report);
        Assert.Contains("Cross.Writer::Helper(): writes static field Cross.Store::Key2 outside its static constructor [mutable-static]", report);
        Assert.Equal(before, Run(env.Fixture.GetImageBytes()));
    }
}
