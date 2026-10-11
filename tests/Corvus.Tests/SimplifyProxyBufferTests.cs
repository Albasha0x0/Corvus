using System.Runtime.Loader;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Corvus.Services.Simplify;

namespace Corvus.Tests;

/// <summary>
/// A buffer held in a static field and passed through a call whose target is resolved (a call through a static delegate
/// field, as obfuscators route calls): the proof that the buffer stays as its initializer left it follows the call into
/// the target, a framework method or a module method, so calls reading the buffer through the proxy fold; a target that
/// writes into the buffer keeps the bail-out. The fixture runs before and after.
/// </summary>
public sealed class SimplifyProxyBufferTests : IDisposable
{
    private readonly TempDir _dir = new();

    public void Dispose() => _dir.Dispose();

    private const string Source = """
        using System;
        using System.Reflection;
        using System.Reflection.Emit;
        using System.Text;

        namespace Buf
        {
            internal delegate string GetStr(object encoding, byte[] bytes, int index, int count);
            internal delegate int Peek(byte[] bytes, int index);
            internal delegate void Poke(byte[] bytes, int index);

            internal static class Proxies
            {
                // ldarg.0..3; call GetStrImpl; ret
                internal static GetStr Strings()
                {
                    var dm = new DynamicMethod(string.Empty, typeof(string), new[] { typeof(object), typeof(byte[]), typeof(int), typeof(int) }, typeof(Proxies).Module, true);
                    var il = dm.GetILGenerator();
                    il.Emit(OpCodes.Ldarg_0);
                    il.Emit(OpCodes.Ldarg_1);
                    il.Emit(OpCodes.Ldarg_2);
                    il.Emit(OpCodes.Ldarg_3);
                    il.Emit(OpCodes.Call, typeof(Proxies).GetMethod("GetStrImpl", BindingFlags.Static | BindingFlags.NonPublic));
                    il.Emit(OpCodes.Ret);
                    return (GetStr)dm.CreateDelegate(typeof(GetStr));
                }

                internal static Delegate Of(Type type, string name) =>
                    Delegate.CreateDelegate(type, typeof(Proxies).GetMethod(name, BindingFlags.Static | BindingFlags.NonPublic));

                private static string GetStrImpl(object encoding, byte[] b, int i, int n) => ((Encoding)encoding).GetString(b, i, n);
                private static int PeekImpl(byte[] b, int i) => b[i] * 2;
                private static void PokeImpl(byte[] b, int i) { b[i] = 0; }
            }

            public static class Store
            {
                private static readonly byte[] Data;
                private static readonly GetStr Str = Proxies.Strings();
                private static readonly Peek PeekF = (Peek)Proxies.Of(typeof(Peek), "PeekImpl");

                static Store() { Data = new byte[] { 104, 105, 33, 21 }; }

                public static string Text(int n) => Str(Encoding.ASCII, Data, 0, n);
                public static string Last() => PeekF(Data, 3).ToString();
            }

            // The same reads, and a call through a proxy that writes into the buffer.
            public static class Store2
            {
                private static readonly byte[] Data;
                private static readonly GetStr Str = Proxies.Strings();
                private static readonly Poke PokeF = (Poke)Proxies.Of(typeof(Poke), "PokeImpl");

                static Store2() { Data = new byte[] { 104, 105, 33 }; }

                public static string Text(int n) => Str(Encoding.ASCII, Data, 0, n);
                public static void Clear() => PokeF(Data, 0);
            }

            public static class Use
            {
                public static string All() => string.Join("|", Store.Text(3), Store.Last(), Store2.Text(2));
            }
        }
        """;

    private string Fixture()
    {
        var path = _dir.File("Buf.dll");
        if (File.Exists(path)) return path;
        File.WriteAllBytes(path, Roslyn.Release("Buf", Source));
        return path;
    }

    private static string Run(byte[] image)
    {
        var context = new AssemblyLoadContext(null, isCollectible: true);
        try
        {
            var asm = context.LoadFromStream(new MemoryStream(image));
            return (string)asm.GetType("Buf.Use", throwOnError: true)!.GetMethod("All")!.Invoke(null, [])!;
        }
        finally
        {
            context.Unload();
        }
    }

    [Fact]
    public void BuffersReadThroughResolvedCallsStayVisible()
    {
        using var env = new Env(Fixture());
        var before = Run(env.Fixture.OriginalBytes);
        Assert.Equal("hi!|42|hi", before);
        var report = env.Edit(() => env.Edits.SimplifyMethods(env.Fixture, env.One("Buf.Use::All"), SimplifyOptions.Parse(null, null, null), false, default));
        Assert.Contains("folded Buf.Store::Text(int) -> \"hi!\"", report);
        Assert.Contains("folded Buf.Store::Last() -> \"42\"", report);
        // Store2's buffer is written through a proxy: it may change, so reads of it are not folded.
        Assert.Contains("Buf.Store2::Text(int): the object in static field Buf.Store2::Data may be modified by other code [mutable-static]", report);
        Assert.Equal(before, Run(env.Fixture.GetImageBytes()));
    }
}
