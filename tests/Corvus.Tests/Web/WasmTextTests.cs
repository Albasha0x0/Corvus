using Corvus.Core.WebAssembly;
using Corvus.Native.Providers;
using Xunit.Abstractions;

namespace Corvus.Tests;

/// <summary>The WebAssembly module reader and text writer: fixtures, real Emscripten builds, wasm2wat equality.</summary>
public sealed partial class WasmTextTests(ITestOutputHelper output) : IDisposable
{
    private readonly TempDir _dir = new();
    public void Dispose() => _dir.Dispose();

    internal static string DotnetNative(string version) =>
        RealPackages.File("Microsoft.NETCore.App.Runtime.Mono.browser-wasm", version, "runtimes", "browser-wasm", "native", "dotnet.native.wasm");

    internal static readonly string[] RuntimeVersions = ["8.0.22", "9.0.11", "10.0.11"];

    /// <summary>The fixtures, the three runtime builds and, with CORVUS_WASM_DIR, every .wasm below that folder.</summary>
    internal static IEnumerable<(string Name, byte[] Bytes)> Corpus()
    {
        foreach (var f in WasmFixtures.Valid()) yield return f;
        foreach (var v in RuntimeVersions) yield return ($"dotnet.native {v}", File.ReadAllBytes(DotnetNative(v)));
        if (RealData.Get("CORVUS_WASM_DIR") is { } dir && Directory.Exists(dir))
            foreach (var file in Directory.EnumerateFiles(dir, "*.wasm", SearchOption.AllDirectories).Order(StringComparer.Ordinal))
                yield return (Path.GetRelativePath(dir, file), File.ReadAllBytes(file));
    }

    [Fact]
    public void Text_of_a_function_with_names_blocks_and_floats()
    {
        var m = WasmBinary.Read(WasmFixtures.Valid().Single(f => f.Name == "names").Bytes);
        Assert.Empty(m.Issues);
        var text = WatWriter.Function(m, 1)!;
        Assert.Equal("""
              (func $add_int__long_ (type $binary) (param $x i32) (param i64) (result i32)
                (local $sum i32) (local $x.1 i32)
                local.get $x
                local.get $sum
                i32.add
                global.get $counter
                i32.add
                call $log)

            """, text);
        Assert.Contains("(func $dup.1 (type 1))", WatWriter.Module(m));
    }

    [Fact]
    public void Float_literals_are_written_as_wabt_writes_them()
    {
        Assert.Equal("0x1.8p+0", WasmFloat.Hex32(0x3FC00000));
        Assert.Equal("-0x0p+0", WasmFloat.Hex64(0x8000000000000000));
        Assert.Equal("nan:0x200000", WasmFloat.Hex32(0x7FA00000));
        Assert.Equal("0x1.p-1074", WasmFloat.Hex64(1));
        Assert.Equal("2.14748e+09", WasmFloat.G(2147483648.0));
        Assert.Equal("0.1", WasmFloat.G(0.1));
        Assert.Equal("1e-05", WasmFloat.G(0.00001));
        Assert.Equal("123457", WasmFloat.G(123456.7));
    }

    [Fact]
    public void Real_module_reads_whole_and_prints()
    {
        var m = WasmBinary.Read(File.ReadAllBytes(DotnetNative("10.0.11")));
        Assert.Empty(m.Issues);
        Assert.Null(m.Unsupported);
        Assert.Equal(m.Functions.Count, m.Bodies.Count);
        var text = WatWriter.Module(m)!;
        Assert.StartsWith("(module\n  (type (;0;) (func", text, StringComparison.Ordinal);
        Assert.EndsWith(")\n", text, StringComparison.Ordinal);
    }

    [Fact]
    public void Fuzzed_modules_never_throw()
    {
        var seed = WasmFixtures.Valid().Single(f => f.Name == "names").Bytes;
        var failures = FormatFuzz.Run(seed, b =>
        {
            var m = WasmBinary.Read(b);
            WatWriter.Module(m);
        }, 2000);
        Assert.True(failures.Count == 0, string.Join("\n", failures.Take(20)));
    }

    /// <summary>
    /// wasm2wat (CORVUS_WASM_TO_TEXT) writes byte-equal text for every module of the corpus. The Windows build's MSVC printf
    /// spells NaN comments "-nan(ind)" and "nan(snan)"; they are read as glibc's "-nan" and "nan", which the Linux and macOS builds write.
    /// </summary>
    [Trait("Speed", "Slow")]
    [RequiresRealDataFact("CORVUS_WASM_TO_TEXT")]
    public void Text_equals_wasm2wat()
    {
        var tool = ExternalTools.WasmText;
        var exe = ExternalTools.Locate(tool)!.Value.Path;
        int compared = 0;
        var differ = new List<string>();
        foreach (var (name, bytes) in Corpus())
        {
            var path = _dir.File($"m{compared}.wasm");
            File.WriteAllBytes(path, bytes);
            var run = ExternalTools.Run(exe, ExternalTools.Arguments(tool, "text", ("module", path)), TimeSpan.FromMinutes(5), 1L << 31, default);
            compared++;
            if (run.ExitCode != 0) { differ.Add($"{name}: wasm2wat failed: {run.Stderr.Trim()}"); continue; }
            var expected = MsvcNan().Replace(run.Text.Replace("\r\n", "\n"), "(;=$1nan;)");
            var actual = WatWriter.Module(WasmBinary.Read(bytes)) ?? "<unsupported>";
            if (expected == actual) continue;
            var e = expected.Split('\n');
            var a = actual.Split('\n');
            int line = Enumerable.Range(0, Math.Min(e.Length, a.Length)).FirstOrDefault(k => e[k] != a[k], Math.Min(e.Length, a.Length));
            differ.Add($"{name} line {line + 1}:\n  wasm2wat: {(line < e.Length ? e[line] : "<end>")}\n  ours:     {(line < a.Length ? a[line] : "<end>")}");
        }
        foreach (var d in differ) output.WriteLine(d);
        output.WriteLine($"{compared - differ.Count} of {compared} modules byte-equal");
        Assert.Empty(differ);
    }

    [System.Text.RegularExpressions.GeneratedRegex(@"\(;=(-?)nan\([a-z]+\);\)")]
    private static partial System.Text.RegularExpressions.Regex MsvcNan();
}
