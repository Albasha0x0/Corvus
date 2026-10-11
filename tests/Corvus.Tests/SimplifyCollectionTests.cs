using System.Runtime.Loader;
using dnlib.DotNet;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Corvus.Services.Simplify;

namespace Corvus.Tests;

/// <summary>
/// simplify_methods with Dictionary and List: helpers that memoize their result in a static dictionary fold to the
/// literal on first and repeated calls; collections built and enumerated by the code fold; each way a collection falls
/// outside the cache rule is reported and the call kept. The fixture runs before and after.
/// </summary>
public sealed class SimplifyCollectionTests : IDisposable
{
    private readonly TempDir _dir = new();

    public void Dispose() => _dir.Dispose();

    private const string Source = """
        using System;
        using System.Collections.Generic;

        namespace Coll
        {
            internal static class Decoder
            {
                private static readonly Dictionary<int, string> Cache = new Dictionary<int, string>();
                private static readonly Dictionary<string, string> Named = new Dictionary<string, string>();
                private static readonly object Sync = new object();

                private static string Compute(int k)
                {
                    var chars = new char[3];
                    for (int i = 0; i < 3; i++) chars[i] = (char)('a' + (k + i) % 26);
                    return new string(chars);
                }

                internal static string Get(int k)
                {
                    if (Cache.TryGetValue(k, out var s)) return s;
                    s = Compute(k);
                    Cache[k] = s;
                    return s;
                }

                internal static string GetLocked(int k)
                {
                    lock (Sync)
                    {
                        if (!Cache.ContainsKey(k)) Cache.Add(k, Compute(k));
                        return Cache[k];
                    }
                }

                internal static string GetLockedOnCache(string name)
                {
                    lock (Named)
                    {
                        if (Named.TryGetValue(name, out var s)) return s;
                        s = name.ToUpperInvariant() + "!";
                        Named[name] = s;
                        return s;
                    }
                }
            }

            // One class per way out of the cache rule, so that each initializer runs on its own.
            internal static class BadCount
            {
                private static readonly Dictionary<int, string> Counted = new Dictionary<int, string>();

                // Depends on what the cache holds: one more entry each call.
                internal static string Next()
                {
                    Counted[Counted.Count] = "x";
                    return Counted.Count.ToString();
                }
            }

            internal static class BadComparer
            {
                private static readonly Dictionary<string, string> Folded = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
                internal static string Comparer() => Folded.TryGetValue("a", out var s) ? s : "none";
            }

            internal static class GoodComparer
            {
                private static readonly Dictionary<string, string> Exact = new Dictionary<string, string>(StringComparer.Ordinal);
                internal static string Get(string k)
                {
                    if (!Exact.TryGetValue(k, out var s)) Exact[k] = s = k + k;
                    return s;
                }
            }

            internal static class BadEscape
            {
                private static readonly Dictionary<int, string> Passed = new Dictionary<int, string>();
                internal static string Escapes() => Fill(Passed);
                private static string Fill(Dictionary<int, string> d)
                {
                    d[d.Count] = "x";
                    return d[0];
                }
            }

            internal static class BadVisible
            {
                public static readonly Dictionary<int, string> Visible = new Dictionary<int, string>();
                internal static string Public()
                {
                    if (!Visible.ContainsKey(1)) Visible[1] = "one";
                    return Visible[1];
                }
            }

            internal static class BadWritten
            {
                private static Dictionary<int, string> Reset = new Dictionary<int, string>();
                internal static string Written() => Reset.ContainsKey(1) ? "one" : "none";
                public static void Clear() => Reset = new Dictionary<int, string>();
            }

            internal static class Make
            {
                internal static string Built()
                {
                    var parts = new List<string>();
                    for (int i = 0; i < 4; i++) parts.Add(Decoder.Get(i));
                    parts.Insert(1, "-");
                    parts.RemoveAt(0);
                    var text = "";
                    foreach (var p in parts) text += p;
                    return text + parts.Count.ToString() + (parts.Contains("-") ? "y" : "n") + parts.IndexOf("bcd").ToString();
                }

                internal static string Ordered()
                {
                    var d = new Dictionary<string, int>();
                    d["zeta"] = 1;
                    d["alpha"] = 2;
                    d["mid"] = 3;
                    var text = "";
                    foreach (var pair in d) text += pair.Key + pair.Value.ToString();
                    return text;
                }

                internal static string AfterRemoval()
                {
                    var d = new Dictionary<int, string> { [1] = "a", [2] = "b", [3] = "c" };
                    d.Remove(2);
                    d[4] = "d";
                    var text = "";
                    foreach (var pair in d) text += pair.Value;
                    return text;
                }
            }

            public static class Use
            {
                public static string Memo() => Decoder.Get(3) + Decoder.Get(3) + Decoder.Get(25);
                public static string Locked() => Decoder.GetLocked(7) + "|" + Decoder.GetLocked(7);
                public static string LockedOnCache() => Decoder.GetLockedOnCache("ab") + Decoder.GetLockedOnCache("ab");

                public static string Built() => Make.Built();
                public static string Ordered() => Make.Ordered();
                public static string OrdinalComparer() => GoodComparer.Get("x") + GoodComparer.Get("x");

                public static string Next() => BadCount.Next();
                public static string Comparer() => BadComparer.Comparer();
                public static string Escapes() => BadEscape.Escapes();
                public static string Public() => BadVisible.Public();
                public static string Written() => BadWritten.Written();
                public static string AfterRemoval() => Make.AfterRemoval();
            }
        }
        """;

    private string Fixture()
    {
        var path = _dir.File("Coll.dll");
        if (File.Exists(path)) return path;
        File.WriteAllBytes(path, Roslyn.Release("Coll", Source));
        return path;
    }

    private static string Simplify(Env env, string symbol) =>
        env.Edit(() => env.Edits.SimplifyMethods(env.One(symbol).Assembly, env.One(symbol), SimplifyOptions.Parse(null, null, null), false, default));

    private static object? Run(byte[] image, string method)
    {
        var context = new AssemblyLoadContext(null, isCollectible: true);
        try
        {
            var asm = context.LoadFromStream(new MemoryStream(image));
            return asm.GetType("Coll.Use", throwOnError: true)!.GetMethod(method)!.Invoke(null, []);
        }
        finally
        {
            context.Unload();
        }
    }

    [Theory]
    [InlineData("Memo")]
    [InlineData("Locked")]
    [InlineData("LockedOnCache")]
    [InlineData("Built")]
    [InlineData("Ordered")]
    [InlineData("OrdinalComparer")]
    public void HelpersThroughCachesAndCollectionsFoldToTheLiteral(string method)
    {
        using var env = new Env(Fixture());
        var expected = (string)Run(env.Fixture.OriginalBytes, method)!;
        var report = Simplify(env, "Coll.Use::" + method);
        Assert.Contains($"-> {Core.Format.Literal(expected)}", report);
        var code = env.Def<MethodDef>("Coll.Use::" + method).Body.Instructions;
        Assert.Equal(["ldstr", "ret"], code.Select(i => i.OpCode.Name));
        Assert.Equal(expected, Run(env.Fixture.GetImageBytes(), method));
    }

    [Theory]
    [InlineData("Next", "cache-dependent", "the result differs when the call is made again")]
    [InlineData("Comparer", "cache-dependent", "a dictionary with a custom comparer")]
    [InlineData("Escapes", "cache-dependent", "is used other than through its own methods")]
    [InlineData("Public", "cache-dependent", "is visible to other assemblies")]
    [InlineData("Written", "mutable-static", "reads mutable static field Coll.BadWritten::Reset")]
    [InlineData("AfterRemoval", "platform-dependent", "after a removal")]
    public void CollectionsOutsideTheModelAreKeptAndReported(string method, string code, string why)
    {
        using var env = new Env(Fixture());
        var report = Simplify(env, "Coll.Use::" + method);
        Assert.Contains("0 of 1 method(s) changed", report);
        Assert.Matches($@"Coll\.Use::{method}\(\) IL_\w{{4}} .*{System.Text.RegularExpressions.Regex.Escape(why)}.* \[{code}\]", report);
    }
}
