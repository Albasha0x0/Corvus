using System.Runtime.Loader;
using System.Text;
using dnlib.DotNet;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using NetDecompilerMcp.Services.Simplify;

namespace NetDecompilerMcp.Tests;

/// <summary>
/// simplify_methods over helpers that build strings from the assembly's own embedded resources: a packed string table
/// (BinaryReader), a text file (StreamReader), an XOR blob (Stream.Read, Position), the resource list; each way out of
/// the read-only, own-module subset is reported and the call kept. The fixture runs before and after.
/// </summary>
public sealed class SimplifyResourceTests : IDisposable
{
    private readonly TempDir _dir = new();

    public void Dispose() => _dir.Dispose();

    private const string Source = """
        using System;
        using System.IO;
        using System.Reflection;
        using System.Text;

        namespace Res
        {
            internal static class Packed
            {
                // Res.strings.bin: an int32 count, then strings with a 7-bit length prefix.
                internal static string Get(int i)
                {
                    using (var s = typeof(Packed).Assembly.GetManifestResourceStream("Res.strings.bin"))
                    using (var r = new BinaryReader(s, Encoding.UTF8))
                    {
                        int n = r.ReadInt32();
                        if (i >= n) return "?";
                        for (int k = 0; k < i; k++) r.ReadString();
                        return r.ReadString();
                    }
                }

                // Res.lines.txt, found through the type's namespace.
                internal static string Line(int i)
                {
                    using (var s = Assembly.GetExecutingAssembly().GetManifestResourceStream(typeof(Packed), "lines.txt"))
                    using (var reader = new StreamReader(s, Encoding.UTF8))
                    {
                        string line = null;
                        for (int k = 0; k <= i; k++) line = reader.ReadLine();
                        return line;
                    }
                }

                // Res.blob: XOR 0x5A, read at an offset.
                internal static string Xor(int offset, int length)
                {
                    var s = Assembly.GetExecutingAssembly().GetManifestResourceStream("Res.blob");
                    var buffer = new byte[length];
                    s.Position = offset;
                    int read = s.Read(buffer, 0, length);
                    s.Dispose();
                    for (int k = 0; k < read; k++) buffer[k] ^= 0x5A;
                    return Encoding.ASCII.GetString(buffer, 0, read) + (s.CanRead ? "/open" : "/closed");
                }

                internal static string Names() => string.Join(",", Assembly.GetExecutingAssembly().GetManifestResourceNames());

                internal static string Missing() => Assembly.GetExecutingAssembly().GetManifestResourceStream("Res.nope") == null ? "none" : "some";

                internal static string Derived()
                {
                    var r = new Reader(new byte[] { 0x48, 0, 0x69, 0 });
                    return Encoding.ASCII.GetString(new[] { (byte)r.U16(), (byte)r.U16() }) + (r.Position == 4 ? "@4" : "@?");
                }

                internal static string FromMemory()
                {
                    var bytes = new byte[] { 3, 0x41, 0x42, 0x43 };
                    using (var r = new BinaryReader(new MemoryStream(bytes))) return r.ReadString();
                }
            }

            // SmartAssembly's shape: a reader derived from MemoryStream, set up by the base constructor.
            internal sealed class Reader : MemoryStream
            {
                public Reader(byte[] buffer) : base(buffer, false) { }
                public int U16() => ReadByte() | (ReadByte() << 8);
            }

            internal sealed class Counting : MemoryStream
            {
                private int _reads;
                public Counting(byte[] buffer) : base(buffer) { }
                public int Next() { _reads++; return ReadByte(); }
            }

            internal static class Bad
            {
                internal static string Counted() => Encoding.ASCII.GetString(new[] { (byte)new Counting(new byte[] { 0x41 }).Next() });

                internal static string Empty()
                {
                    var m = new MemoryStream();
                    m.WriteByte(1);
                    return "x";
                }

                internal static string WriteInto()
                {
                    var m = new MemoryStream(new byte[4]);
                    m.WriteByte(1);
                    return "x";
                }

                internal static string FromFile() => File.ReadAllText("settings-that-does-not-exist.ini");
                internal static string Network() => System.Net.Dns.GetHostName() + "!";
                internal static string Foreign() => typeof(string).Assembly.GetManifestResourceStream("x") == null ? "none" : "some";
                internal static string Entry() => Assembly.GetEntryAssembly() == null ? "none" : "some";
            }

            public static class Use
            {
                public static string Get1() => Packed.Get(1);
                public static string Get2() => Packed.Get(2);
                public static string Line1() => Packed.Line(1);
                public static string Xor() => Packed.Xor(2, 5);
                public static string Names() => Packed.Names();
                public static string Missing() => Packed.Missing();
                public static string FromMemory() => Packed.FromMemory();
                public static string Derived() => Packed.Derived();
                public static string Counted() => Bad.Counted();

                public static string Empty() => Bad.Empty();
                public static string WriteInto() => Bad.WriteInto();
                public static string FromFile() => Bad.FromFile();
                public static string Network() => Bad.Network();
                public static string Foreign() => Bad.Foreign();
                public static string Entry() => Bad.Entry();
            }
        }
        """;

    private static byte[] StringTable(params string[] items)
    {
        using var ms = new MemoryStream();
        using (var w = new BinaryWriter(ms, Encoding.UTF8, leaveOpen: true))
        {
            w.Write(items.Length);
            foreach (var item in items) w.Write(item);
        }
        return ms.ToArray();
    }

    private string Fixture()
    {
        var path = _dir.File("Res.dll");
        if (File.Exists(path)) return path;
        var compilation = CSharpCompilation.Create("Res", [CSharpSyntaxTree.ParseText(Source)], Roslyn.PlatformReferences,
            new CSharpCompilationOptions(OutputKind.DynamicallyLinkedLibrary, optimizationLevel: OptimizationLevel.Release));
        var table = StringTable("zero", "héllo wörld", "two");
        var lines = Encoding.UTF8.GetPreamble().Concat(Encoding.UTF8.GetBytes("first\r\nsecond line\nthird")).ToArray();
        var blob = Encoding.ASCII.GetBytes("..SECRET..").Select(b => (byte)(b ^ 0x5A)).ToArray();
        ResourceDescription Resource(string name, byte[] data) => new(name, () => new MemoryStream(data), isPublic: true);
        using var ms = new MemoryStream();
        var result = compilation.Emit(ms, manifestResources: [Resource("Res.strings.bin", table), Resource("Res.lines.txt", lines), Resource("Res.blob", blob)]);
        Assert.True(result.Success, string.Join("\n", result.Diagnostics.Where(d => d.Severity == DiagnosticSeverity.Error)));
        File.WriteAllBytes(path, ms.ToArray());
        return path;
    }

    private static string Simplify(Env env, string symbol, SimplifyOptions? options = null) =>
        env.Edit(() => env.Edits.SimplifyMethods(env.One(symbol).Assembly, env.One(symbol), options ?? SimplifyOptions.Parse(null, null, null), false, default));

    private static object? Run(byte[] image, string method)
    {
        var context = new AssemblyLoadContext(null, isCollectible: true);
        try
        {
            var asm = context.LoadFromStream(new MemoryStream(image));
            return asm.GetType("Res.Use", throwOnError: true)!.GetMethod(method)!.Invoke(null, []);
        }
        finally
        {
            context.Unload();
        }
    }

    [Theory]
    [InlineData("Get1")]
    [InlineData("Get2")]
    [InlineData("Line1")]
    [InlineData("Xor")]
    [InlineData("Names")]
    [InlineData("Missing")]
    [InlineData("FromMemory")]
    [InlineData("Derived")]
    public void HelpersReadingOwnResourcesFoldToTheLiteral(string method)
    {
        using var env = new Env(Fixture());
        var expected = (string)Run(env.Fixture.OriginalBytes, method)!;
        var report = Simplify(env, "Res.Use::" + method);
        Assert.Contains($"-> {Core.Format.Literal(expected)}", report);
        Assert.Equal(["ldstr", "ret"], env.Def<MethodDef>("Res.Use::" + method).Body.Instructions.Select(i => i.OpCode.Name));
        Assert.Equal(expected, Run(env.Fixture.GetImageBytes(), method));
    }

    [Theory]
    [InlineData("Empty", "writable-stream", "creates an empty MemoryStream")]
    [InlineData("WriteInto", "writable-stream", "the evaluator only reads streams")]
    [InlineData("FromFile", "external-io", "files and the network differ between runs")]
    [InlineData("Network", "external-io", "files and the network differ between runs")]
    [InlineData("Foreign", "external-io", "reads the resources of another assembly")]
    [InlineData("Entry", "external-io", "the entry assembly is the host's")]
    [InlineData("Counted", "unmodeled-instance", "its base class System.IO.MemoryStream belongs to another assembly")]
    public void ResourceUseOutsideTheModelIsKeptAndReported(string method, string code, string why)
    {
        using var env = new Env(Fixture());
        var report = Simplify(env, "Res.Use::" + method);
        Assert.Contains("0 of 1 method(s) changed", report);
        Assert.Matches($@"Res\.Use::{method}\(\) IL_\w{{4}} .*{System.Text.RegularExpressions.Regex.Escape(why)}.* \[{code}\]", report);
    }

    [Fact]
    public void ResourceBytesCountAgainstTheMemoryCap()
    {
        using var env = new Env(Fixture());
        var report = Simplify(env, "Res.Use::Get1", new SimplifyOptions(Limits: new EvaluationLimits(MemoryLimit: 32)));
        Assert.Contains("[memory-limit]", report);
        Assert.Contains("0 of 1 method(s) changed", report);
    }
}
