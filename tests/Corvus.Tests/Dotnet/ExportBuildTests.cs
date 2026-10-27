using System.Diagnostics;
using System.Text.RegularExpressions;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;

namespace Corvus.Tests;

/// <summary>Exported projects build: span-slicing ref temporaries and stackalloc initializers become compilable C#.</summary>
public class ExportBuildTests
{
    private const string Patterns = """
        using System;
        // The code older compilers emit for span ranges (x[i..]): a ref temporary per slice.
        public static class Slices
        {
            public static int Sum(ReadOnlySpan<byte> input, int from)
            {
                int total = 0;
                for (int i = from; i + 4 <= input.Length; i += 4)
                {
                    ref ReadOnlySpan<byte> r = ref input;
                    int s = i;
                    total += Take(r.Slice(s, r.Length - s));
                }
                ref ReadOnlySpan<byte> tail = ref input;
                total += tail.Slice(input.Length - 1, 1)[0];
                return total;
            }
            static int Take(ReadOnlySpan<byte> s) => s[0] + s.Length;

            public static ulong Mix(Span<ulong> zz, ulong a)
            {
                Span<ulong> tmp = stackalloc ulong[3];
                { ref Span<ulong> r = ref zz; Acc(r.Slice(1, r.Length - 1), a); }
                { ref Span<ulong> r = ref tmp; Acc(r.Slice(1, r.Length - 1), a + 1); }
                { ref Span<ulong> r = ref tmp; Acc(r.Slice(0, r.Length), a + 2); }
                return tmp[0] ^ tmp[1] ^ zz[0] ^ zz[1];
            }
            static void Acc(Span<ulong> s, ulong v) { s[0] ^= v; }

            // Both branches reuse the temporary; the output span is a parameter (wider escape scope).
            public static int Copy(ReadOnlySpan<byte> input, Span<byte> output, bool forward)
            {
                int i = 0;
                if (forward)
                {
                    for (; i < input.Length - 4; i += 4)
                    {
                        ref ReadOnlySpan<byte> r = ref input; int s = i;
                        ReadOnlySpan<byte> part = r.Slice(s, 4);
                        ref Span<byte> o = ref output; s = i;
                        part.CopyTo(o.Slice(s, o.Length - s));
                    }
                    { ref ReadOnlySpan<byte> r = ref input; int s = i; r.Slice(s, r.Length - s).CopyTo(output.Slice(i)); }
                }
                else
                {
                    ref ReadOnlySpan<byte> r = ref input; int s = 1;
                    r.Slice(s, r.Length - s).CopyTo(output);
                }
                return output[0] + output[output.Length - 1] * 3;
            }

            public static unsafe int Table()
            {
                ReadOnlySpan<byte> t = stackalloc byte[10] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 };
                Span<int> w = stackalloc int[4] { -1, 70000, 3, int.MaxValue };
                int s = 0;
                foreach (var b in t) s += b;
                foreach (var x in w) s ^= x;
                return s;
            }

            public static long Run()
            {
                var data = new byte[37];
                for (int i = 0; i < data.Length; i++) data[i] = (byte)(i * 7 + 3);
                long h = Sum(data, 2) * 31 + Sum(data, 5);
                var zz = new ulong[] { 5, 9, 11 };
                h = h * 31 + (long)Mix(zz, 0xABCDEF);
                var outA = new byte[37]; var outB = new byte[36];
                h = h * 31 + Copy(data, outA, true);
                h = h * 31 + Copy(data, outB, false);
                foreach (var b in outA) h = h * 17 + b;
                foreach (var b in outB) h = h * 13 + b;
                return h * 31 + Table();
            }
        }
        """;

    [Trait("Speed", "Slow")]
    [Fact]
    public void Patterns_decompile_to_code_that_builds_and_behaves_the_same()
    {
        using var dir = new TempDir();
        var path = dir.File("Patterns.dll");
        File.WriteAllBytes(path, CompileRelease("Patterns", Patterns));
        using var env = new Env(path);
        var code = env.Decompile("Slices");
        Assert.DoesNotContain("PrivateImplementationDetails", code);
        Assert.Contains("stackalloc byte[10] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 }", code);
        var rebuilt = AssertBuilds(env, dir.File("out"));
        Assert.Equal(Run(path), Run(rebuilt));
    }

    /// <summary>Slices.Run() of an assembly, in its own load context.</summary>
    private static long Run(string assembly)
    {
        var context = new System.Runtime.Loader.AssemblyLoadContext(null, isCollectible: true);
        try
        {
            var asm = context.LoadFromStream(new MemoryStream(File.ReadAllBytes(assembly)));
            return (long)asm.GetType("Slices")!.GetMethod("Run")!.Invoke(null, null)!;
        }
        finally { context.Unload(); }
    }

    /// <summary>A class of its own: the longest export starts with the first tests, not after the others of this class.</summary>
    [Trait("Speed", "Slow")]
    public sealed class BouncyCastle
    {
        /// <summary>Rewritten span code in digests, SCrypt and AEAD modes gives the original results after rebuild.</summary>
        [Fact]
        public void BouncyCastle_rebuilt_from_export_behaves_the_same()
        {
            var path = RealPackages.Lib("BouncyCastle.Cryptography", "2.6.2", "net6.0", "BouncyCastle.Cryptography.dll");
            using var dir = new TempDir();
            using var env = new Env(path);
            var rebuilt = AssertBuilds(env, dir.File("out"));
            var expected = CryptoResults(path);
            Assert.Equal(expected, CryptoResults(rebuilt));
            Assert.Equal(8, expected.Count);
        }
    }

    private static List<string> CryptoResults(string assembly)
    {
        var context = new System.Runtime.Loader.AssemblyLoadContext(null, isCollectible: true);
        try
        {
            var asm = context.LoadFromStream(new MemoryStream(File.ReadAllBytes(assembly)));
            Type T(string name) => asm.GetType("Org.BouncyCastle." + name, throwOnError: true)!;
            object Call(object target, string method, Type[] types, params object?[] args) =>
                target.GetType().GetMethod(method, types)!.Invoke(target, args)!;
            var data = Enumerable.Range(0, 1000).Select(i => (byte)(i * 31 + 7)).ToArray();
            var results = new List<string>();

            foreach (var name in new[] { "Blake2bDigest", "Blake2sDigest", "Blake3Digest", "KeccakDigest", "Sha256Digest" })
            {
                var digest = Activator.CreateInstance(T("Crypto.Digests." + name))!;
                Call(digest, "BlockUpdate", [typeof(byte[]), typeof(int), typeof(int)], data, 3, 990);
                var output = new byte[(int)Call(digest, "GetDigestSize", [])];
                Call(digest, "DoFinal", [typeof(byte[]), typeof(int)], output, 0);
                results.Add(name + " " + Convert.ToHexString(output));
            }

            var scrypt = T("Crypto.Generators.SCrypt").GetMethod("Generate", [typeof(byte[]), typeof(byte[]), typeof(int), typeof(int), typeof(int), typeof(int)])!;
            results.Add("SCrypt " + Convert.ToHexString((byte[])scrypt.Invoke(null, [data[..20], data[20..36], 1024, 8, 2, 64])!));

            foreach (var mode in new[] { "GcmBlockCipher", "CcmBlockCipher" })
            {
                var cipher = Activator.CreateInstance(T("Crypto.Modes." + mode), Activator.CreateInstance(T("Crypto.Engines.AesEngine")))!;
                var key = Activator.CreateInstance(T("Crypto.Parameters.KeyParameter"), (object)data[..16])!;
                var parameters = Activator.CreateInstance(T("Crypto.Parameters.AeadParameters"), key, 128, data[16..28], data[40..60])!;
                Call(cipher, "Init", [typeof(bool), T("Crypto.ICipherParameters")], true, parameters);
                var input = data[..333];
                var output = new byte[(int)Call(cipher, "GetOutputSize", [typeof(int)], input.Length)];
                int n = (int)Call(cipher, "ProcessBytes", [typeof(byte[]), typeof(int), typeof(int), typeof(byte[]), typeof(int)], input, 0, input.Length, output, 0);
                n += (int)Call(cipher, "DoFinal", [typeof(byte[]), typeof(int)], output, n);
                results.Add(mode + " " + Convert.ToHexString(output, 0, n));
            }
            return results;
        }
        finally { context.Unload(); }
    }

    /// <summary>Real libraries export to projects that build (opt-in: CORVUS_EXPORT_REAL=1; slow).</summary>
    [OptInTheory("CORVUS_EXPORT_REAL")]
    [InlineData("Newtonsoft.Json", "13.0.4", "net6.0", "Newtonsoft.Json.dll")]
    [InlineData("NLog", "6.1.4", "netstandard2.1", "NLog.dll")]
    [InlineData("System.Text.Json", "10.0.1", "net8.0", "System.Text.Json.dll")]
    [InlineData("SharpCompress", "0.48.1", "net8.0", "SharpCompress.dll")]
    [InlineData("AsmResolver.PE", "6.0.0-beta.5", "net8.0", "AsmResolver.PE.dll")]
    [InlineData("Iced", "1.21.0", "netstandard2.1", "Iced.dll")]
    [InlineData("dnlib", "4.5.0", "net6.0", "dnlib.dll")]
    [InlineData("ZstdSharp.Port", "0.8.8", "net8.0", "ZstdSharp.dll")]
    public void RealExport_Builds(string package, string version, string framework, string file)
    {
        var path = RealPackages.Lib(package, version, framework, file);
        using var dir = new TempDir();
        using var env = new Env(path);
        int failures = Corvus.Services.AstCleanup.Failures;
        AssertBuilds(env, dir.File("out"));
        Assert.True(failures == Corvus.Services.AstCleanup.Failures, Corvus.Services.AstCleanup.LastError); // no cleanup step failed
    }

    /// <summary>Regression: a .NET Framework project with an image in its .resx failed dotnet build (MSB3822, MSB3823).</summary>
    [Fact]
    [Trait("Speed", "Slow")]
    public void NET_Framework_export_with_binary_resources_uses_preserialized_resources()
    {
        using var dir = new TempDir();
        var resources = new MemoryStream();
        using (var writer = new System.Resources.ResourceWriter(resources))
        {
            writer.AddResource("Title", "text");
            writer.AddResource("Icon", new byte[] { 1, 2, 3 });
        }
        var compilation = CSharpCompilation.Create("Forms",
            [CSharpSyntaxTree.ParseText("[assembly: System.Runtime.Versioning.TargetFramework(\".NETFramework,Version=v4.5.2\")] public class Form1 { }")],
            Roslyn.PlatformReferences, new CSharpCompilationOptions(OutputKind.DynamicallyLinkedLibrary));
        var path = dir.File("Forms.dll");
        using (var file = File.Create(path))
            Assert.True(compilation.Emit(file, manifestResources: [new ResourceDescription("Form1.resources", () => new MemoryStream(resources.ToArray()), true)]).Success);
        using var env = new Env(path);
        var project = File.ReadAllText(env.Decompiler.ExportProject(env.Fixture, dir.File("out"), null, default).ProjectFile!);
        Assert.Contains("<GenerateResourceUsePreserializedResources>True</GenerateResourceUsePreserializedResources>", project);
        Assert.Contains("<PackageReference Include=\"System.Resources.Extensions\"", project);
        Assert.Contains("<TargetFramework>net462</TargetFramework>", project);
        Assert.Contains("was net452", project);
    }

    /// <summary>A reference to a core library of any version (65535.65535.65535.65535) builds; in-process compilations report CS1705, so patches rewrite it.</summary>
    [Trait("Speed", "Slow")]
    [Fact]
    public void Export_referencing_a_library_with_any_version_core_library_builds()
    {
        using var dir = new TempDir();
        // A .NET Framework library as some transformation tools write it: mscorlib, Version=65535.65535.65535.65535.
        var mscorlib = new dnlib.DotNet.AssemblyRefUser("mscorlib", new Version(65535, 65535, 65535, 65535),
            new dnlib.DotNet.PublicKeyToken("b77a5c561934e089"));
        var module = new dnlib.DotNet.ModuleDefUser("Lib.dll", Guid.NewGuid(), mscorlib) { Kind = dnlib.DotNet.ModuleKind.Dll };
        new dnlib.DotNet.AssemblyDefUser("Lib", new Version(1, 0, 0, 0)).Modules.Add(module);
        var marker = new dnlib.DotNet.TypeDefUser("L", "Marker", module.CorLibTypes.Object.TypeDefOrRef) { Attributes = dnlib.DotNet.TypeAttributes.Public };
        module.Types.Add(marker);
        var v = new dnlib.DotNet.MethodDefUser("V", dnlib.DotNet.MethodSig.CreateStatic(module.CorLibTypes.String),
            dnlib.DotNet.MethodAttributes.Public | dnlib.DotNet.MethodAttributes.Static) { Body = new dnlib.DotNet.Emit.CilBody() };
        v.Body.Instructions.Add(dnlib.DotNet.Emit.OpCodes.Ldstr.ToInstruction("x"));
        v.Body.Instructions.Add(dnlib.DotNet.Emit.OpCodes.Ret.ToInstruction());
        marker.Methods.Add(v);
        module.Write(dir.File("Lib.dll"));
        File.WriteAllBytes(dir.File("App.dll"), ReferenceResolutionTests.Compile("App",
            "namespace App { public static class C { public static int Run() => L.Marker.V().Length; } }", File.ReadAllBytes(dir.File("Lib.dll"))));
        using var env = new Env(dir.File("App.dll"));
        AssertBuilds(env, dir.File("out"));
        Assert.DoesNotContain(Directory.GetFiles(dir.File("out"), "Lib.dll", SearchOption.AllDirectories), f => !f.Contains("bin-out", StringComparison.Ordinal));
    }

    /// <summary>Each assembly listed in CORVUS_EXPORT_LIST builds after export; errors go to "&lt;list&gt;.report.txt".</summary>
    [Trait("Speed", "Slow")]
    [Fact]
    public void ExportList_Builds()
    {
        var list = Environment.GetEnvironmentVariable("CORVUS_EXPORT_LIST");
        if (string.IsNullOrEmpty(list) || !File.Exists(list)) return;
        var report = new System.Text.StringBuilder();
        int failed = 0;
        foreach (var path in File.ReadAllLines(list).Select(l => l.Trim()).Where(l => l.Length > 0 && File.Exists(l)))
        {
            var outDir = Path.Combine(list + ".out", Path.GetFileNameWithoutExtension(path));
            if (Directory.Exists(outDir)) Directory.Delete(outDir, recursive: true);
            using var env = new Env(path);
            var (_, errors) = Build(env, outDir);
            if (errors.Count > 0) failed++;
            report.AppendLine($"{Path.GetFileName(path)}: {errors.Count} errors  " +
                              string.Join(", ", errors.GroupBy(e => Regex.Match(e, @"CS\d+").Value).OrderByDescending(g => g.Count()).Select(g => $"{g.Key}x{g.Count()}")));
            foreach (var e in errors.Take(150)) report.AppendLine("    " + e);
        }
        File.WriteAllText(list + ".report.txt", report.ToString());
        if (Corvus.Services.AstCleanup.Logging)
            File.WriteAllLines(list + ".cleanup-log.txt", Corvus.Services.AstCleanup.Log.Distinct().Order());
        Assert.True(failed == 0, report.ToString());
    }

    /// <summary>Release build: the optimizer produces the patterns under test.</summary>
    private static byte[] CompileRelease(string name, string source)
    {
        return Roslyn.Compile(name, source,
            new CSharpCompilationOptions(OutputKind.DynamicallyLinkedLibrary, optimizationLevel: OptimizationLevel.Release, allowUnsafe: true));
    }

    /// <summary>Exports and builds; returns the built assembly's path and the compile errors.</summary>
    private static (string? Output, List<string> Errors) Build(Env env, string outDir)
    {
        var result = env.Decompiler.ExportProject(env.Fixture, outDir, null, default);
        var bin = Path.Combine(outDir, "bin-out");
        var (exitCode, output) = Tools.Dotnet(null, "build", result.ProjectFile!, "-nologo", "-c", "Release", "-o", bin, "-clp:NoSummary;ErrorsOnly");
        var errors = Regex.Matches(output, @"[^\\/\r\n]+\.cs\(\d+,\d+\): error CS\d+: [^\[\r\n]*").Select(m => m.Value.Trim()).Distinct().ToList();
        if (exitCode != 0 && errors.Count == 0) errors.Add(output);
        var built = Path.Combine(bin, Path.GetFileName(env.Fixture.FilePath));
        return (File.Exists(built) ? built : null, errors);
    }

    private static string AssertBuilds(Env env, string outDir)
    {
        var (built, errors) = Build(env, outDir);
        Assert.True(errors.Count == 0 && built != null, $"{errors.Count} errors:\n" + string.Join("\n", errors.Take(40)));
        return built!;
    }
}
