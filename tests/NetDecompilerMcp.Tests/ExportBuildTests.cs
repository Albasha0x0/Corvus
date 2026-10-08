using System.Diagnostics;
using System.Text.RegularExpressions;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;

namespace NetDecompilerMcp.Tests;

/// <summary>
/// Exported projects build: the engine's span-slicing ref temporaries and stackalloc initializers are rewritten into
/// compilable C#. A small source covers each pattern; real libraries from the NuGet cache cover the rest.
/// </summary>
public class ExportBuildTests
{
    private const string Patterns = """
        using System;
        // the code older compilers emit for span ranges (x[i..]): a ref temporary per slice
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

            // both branches reuse the temporary; the output span is a parameter (wider escape scope)
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

    [Fact]
    public void Patterns_Decompile_ToCode_ThatBuildsAndBehavesTheSame()
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

    /// <summary>
    /// BouncyCastle (net6.0): the export builds, and the methods the cleanup rewrote (span slicing in digests, AEAD modes,
    /// SCrypt) give the same results in the rebuilt library as in the original.
    /// </summary>
    [Fact]
    public void BouncyCastle_RebuiltFromExport_BehavesTheSame()
    {
        var path = RealPackages.Lib("BouncyCastle.Cryptography", "2.6.2", "net6.0", "BouncyCastle.Cryptography.dll");
        using var dir = new TempDir();
        using var env = new Env(path);
        var rebuilt = AssertBuilds(env, dir.File("out"));
        var expected = CryptoResults(path);
        Assert.Equal(expected, CryptoResults(rebuilt));
        Assert.Equal(8, expected.Count);
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

    /// <summary>Real libraries export to projects that build with no errors (opt-in: NDM_EXPORT_REAL=1, a few minutes).</summary>
    [Theory]
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
        if (Environment.GetEnvironmentVariable("NDM_EXPORT_REAL") != "1") return;
        var path = RealPackages.Lib(package, version, framework, file);
        using var dir = new TempDir();
        using var env = new Env(path);
        int failures = NetDecompilerMcp.Services.AstCleanup.Failures;
        AssertBuilds(env, dir.File("out"));
        Assert.True(failures == NetDecompilerMcp.Services.AstCleanup.Failures, NetDecompilerMcp.Services.AstCleanup.LastError); // no cleanup step failed on it
    }

    /// <summary>
    /// Every assembly listed in the file NDM_EXPORT_LIST (one path per line) exports to a project that builds with no
    /// errors. Errors by assembly are written to "&lt;list&gt;.report.txt", the projects to "&lt;list&gt;.out".
    /// </summary>
    [Fact]
    public void ExportList_Builds()
    {
        var list = Environment.GetEnvironmentVariable("NDM_EXPORT_LIST");
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
        if (NetDecompilerMcp.Services.AstCleanup.Logging)
            File.WriteAllLines(list + ".cleanup-log.txt", NetDecompilerMcp.Services.AstCleanup.Log.Distinct().Order());
        Assert.True(failed == 0, report.ToString());
    }

    /// <summary>A release build, as libraries ship: the patterns come from the optimizer.</summary>
    private static byte[] CompileRelease(string name, string source)
    {
        var tpa = ((string)AppContext.GetData("TRUSTED_PLATFORM_ASSEMBLIES")!).Split(Path.PathSeparator)
            .Where(p => p.EndsWith(".dll", StringComparison.OrdinalIgnoreCase)).Select(p => MetadataReference.CreateFromFile(p));
        var compilation = CSharpCompilation.Create(name, [CSharpSyntaxTree.ParseText(source)], tpa,
            new CSharpCompilationOptions(OutputKind.DynamicallyLinkedLibrary, optimizationLevel: OptimizationLevel.Release, allowUnsafe: true));
        using var ms = new MemoryStream();
        var result = compilation.Emit(ms);
        Assert.True(result.Success, string.Join("\n", result.Diagnostics.Where(d => d.Severity == DiagnosticSeverity.Error)));
        return ms.ToArray();
    }

    /// <summary>Exports and builds; returns the built assembly's path and the compile errors.</summary>
    private static (string? Output, List<string> Errors) Build(Env env, string outDir)
    {
        var result = env.Decompiler.ExportProject(env.Fixture, outDir, null, default);
        var bin = Path.Combine(outDir, "bin-out");
        var psi = new ProcessStartInfo("dotnet", $"build \"{result.ProjectFile}\" -nologo -c Release -o \"{bin}\" -clp:NoSummary;ErrorsOnly")
            { RedirectStandardOutput = true, RedirectStandardError = true, UseShellExecute = false };
        using var p = Process.Start(psi)!;
        var stdout = p.StandardOutput.ReadToEndAsync();
        var output = p.StandardError.ReadToEnd() + stdout.Result;
        p.WaitForExit();
        var errors = Regex.Matches(output, @"[^\\/\r\n]+\.cs\(\d+,\d+\): error CS\d+: [^\[\r\n]*").Select(m => m.Value.Trim()).Distinct().ToList();
        if (p.ExitCode != 0 && errors.Count == 0) errors.Add(output);
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
