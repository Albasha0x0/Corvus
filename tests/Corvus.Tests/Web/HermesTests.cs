using System.Diagnostics;
using System.Globalization;
using System.Text.RegularExpressions;
using Corvus.Core;
using Corvus.Core.Hermes;
using Corvus.Native.Providers;
using Corvus.Services.Analysis;
using Corvus.Services.Web;
using Corvus.Tools;
using Xunit.Abstractions;

namespace Corvus.Tests;

/// <summary>
/// Hermes bytecode (React Native): the reader and disassembler on fixtures from every released compiler (versions 59–96),
/// the decompiled view, the Metro module table, the analyze_js views, and (with CORVUS_HBC_DISASSEMBLER) equality with hbcdump.
/// </summary>
public sealed partial class HermesTests(ITestOutputHelper output) : IDisposable
{
    private readonly TempDir _dir = new();
    public void Dispose() => _dir.Dispose();

    internal static string Fixture(string name) => Path.Combine(AppContext.BaseDirectory, "Web", "HermesFixtures", name);

    /// <summary>The bytecode version of every released Hermes compiler.</summary>
    public static TheoryData<int> Versions => new(59, 60, 62, 71, 74, 76, 83, 84, 85, 89, 90, 94, 96);

    private static HermesFile Read(string name) => HermesFile.Read(File.ReadAllBytes(Fixture(name)));

    [Theory]
    [MemberData(nameof(Versions))]
    public void Every_version_reads_and_decodes_whole(int version)
    {
        var f = Read($"sample-v{version}.hbc");
        Assert.Equal(version, f.Version);
        Assert.True(f.TableExact);
        Assert.Empty(f.Issues);
        Assert.Equal(["global", "add", "greet", "loop", "tryIt", "makeCounter", "", "sw", "cls", "api", "arrow", ""],
            Enumerable.Range(0, f.Functions.Count).Select(f.FunctionName));
        Assert.Contains("https://api.example.com/v1/login", Enumerable.Range(0, f.StringCount).Select(i => f.String(i)));
        var issues = new List<string>();
        foreach (var fn in f.Functions)
        {
            var code = HermesCode.Decode(f, fn, issues);
            Assert.Equal(fn.Size, code[^1].End);
        }
        Assert.Empty(issues);
        Assert.Equal(["LoadParam         r1, 1", "LoadParam         r0, 2", "Add               r0, r1, r0", "Ret               r0"],
            HermesCode.Decode(f, f.Functions[1]).Select(i => HermesCode.Text(f, i)));
        Assert.Equal(3, f.Handlers(f.Functions[4]).Count);
        Assert.Equal(("sample.js", 3), f.Locations(f.Functions[1]) is [var start, ..] ? (start.File, start.Line) : default);
    }

    [Theory]
    [MemberData(nameof(Versions))]
    public void Decompiled_view_is_structured_on_every_version(int version)
    {
        var index = new HermesIndex(Read($"sample-v{version}.hbc"));
        var text = string.Join("\n", Enumerable.Range(0, index.File.Functions.Count).Select(i => HermesDecompiler.Function(index, i)));
        Assert.DoesNotContain("goto ", text, StringComparison.Ordinal);
        Assert.Contains("fetch(\"https://api.example.com/v1/login\", { method: \"POST\", body: JSON.stringify({ user: \"u\" }) });", text, StringComparison.Ordinal);
        Assert.Contains("return a0 + a1;", text, StringComparison.Ordinal);
        Assert.Contains("obj = { x: 1, y: \"two\", z: [1, 2, 3], nested: { flag: true } };", text, StringComparison.Ordinal);
        Assert.Contains("r0 = new Date();", text, StringComparison.Ordinal);
        Assert.Contains("if (1 === a0) {\n    return \"one\";\n  }", text, StringComparison.Ordinal);
        Assert.Matches(@"try \{\n\s+try \{\n\s+r0 = a0\(\);\n\s+\} catch \(e\) \{\n\s+print\(""error: "" \+ e\.message\);", text);
        Assert.Matches(@"function fn6\(\) \{\n  r0 = v5_0 \+ 1;\n  v5_0 = r0;\n  return r0;", text);
    }

    [Fact]
    public void Decompiled_view_rebuilds_switch_await_yield_and_templates()
    {
        var index = new HermesIndex(Read("features-v96.hbc"));
        string Of(string name) => HermesDecompiler.Function(index, Enumerable.Range(0, index.File.Functions.Count).First(i => index.File.FunctionName(i) == name));
        Assert.Contains("switch (a0) {\n    case 0:\n      return \"a\";", Of("big"), StringComparison.Ordinal);
        Assert.Contains("return \"Hi \" + a0.name + \", you have \" + a0.count + \" messages\";", Of("template"), StringComparison.Ordinal);
        var body = HermesDecompiler.Function(index, Enumerable.Range(0, index.File.Functions.Count).Last(i => index.File.FunctionName(i).EndsWith("load", StringComparison.Ordinal)));
        Assert.Contains("async function /* body */", body, StringComparison.Ordinal);
        Assert.Contains("r1 = await fetch(a0, { headers: { Accept: \"application/json\" } });", body, StringComparison.Ordinal);
        Assert.Contains("throw new Error(\"HTTP \" + r1.status);", body, StringComparison.Ordinal);
        Assert.Contains("yield r4;", HermesDecompiler.Function(index, 2), StringComparison.Ordinal);
    }

    [Theory]
    [InlineData(59)]
    [InlineData(96)]
    public void Metro_modules_come_from_the_global_code(int version)
    {
        var index = new HermesIndex(Read($"metro-v{version}.hbc"));
        Assert.Equal([(0L, 3, "1"), (1L, 5, "")], index.Modules.Select(m => (m.Id, m.Function, string.Join(",", m.Dependencies))));
        Assert.Equal([0L], index.EntryModules);
        Assert.Equal(0, index.ModuleOf(4)!.Id);
        Assert.Equal(3, index.EnvironmentOwner(4, 0));
        var factory = HermesDecompiler.Function(index, 3);
        Assert.Contains("function fn3(global, require, importDefault, importAll, module, exports, dependencyMap) {", factory, StringComparison.Ordinal);
        Assert.Contains("v3_0 = require(dependencyMap[0] /* module 1 */);", factory, StringComparison.Ordinal);
        Assert.Contains("return v3_0.post(\"/v1/login\", { user: a0, password: a1 });", HermesDecompiler.Function(index, 4), StringComparison.Ordinal);
    }

    private string Apk(string fixture)
    {
        var path = _dir.File(Path.ChangeExtension(fixture, ".apk"));
        File.WriteAllBytes(path, ContainerFixtures.Zip(("AndroidManifest.xml", [0]), ("assets/index.android.bundle", File.ReadAllBytes(Fixture(fixture)))));
        return path;
    }

    [Fact]
    public void Analyze_js_reads_a_bundle_and_the_one_in_an_apk()
    {
        var tools = new WebTools(new OutputPager(new ServerOptions()));
        string Run(string path, string view, string? query = null) => tools.AnalyzeJs(path, view, query: query);
        var bundle = Fixture("metro-v96.hbc");
        Assert.Contains("Hermes bytecode version 96 (React Native)", Run(bundle, "summary"), StringComparison.Ordinal);
        Assert.Contains("Metro modules: 2, run first: 0", Run(bundle, "summary"), StringComparison.Ordinal);
        Assert.Contains("#4 login  2 params", Run(bundle, "functions", "login"), StringComparison.Ordinal);
        Assert.Contains("return fetch(\"https://api.example.com\" + a0", Run(bundle, "decompile", "post"), StringComparison.Ordinal);
        Assert.Matches(@"LoadConstString\s+r\d+, ""/v1/login""", Run(bundle, "disassemble", "#4"));
        Assert.Contains("string #", Run(bundle, "search", "example.com"), StringComparison.Ordinal);
        Assert.Contains("closure created in #3 fn3 at 0x", Run(bundle, "xrefs", "#4"), StringComparison.Ordinal);
        Assert.Contains("#6 fn6_post at 0x", Run(bundle, "xrefs", "POST"), StringComparison.Ordinal);
        Assert.Contains("1 fn5  20 bytes, 0 dependencies", Run(bundle, "modules"), StringComparison.Ordinal);
        Assert.Contains("required by (1): 0", Run(bundle, "refs", "1"), StringComparison.Ordinal);
        var module = Run(bundle, "module", "0");
        Assert.Contains("v3_0 = require(dependencyMap[0] /* module 1 */);", module, StringComparison.Ordinal);
        Assert.Contains("function fn4_login(a0, a1)", module, StringComparison.Ordinal);
        Assert.Contains("metro-v96.apk!assets/index.android.bundle: Hermes bytecode version 96", Run(Apk("metro-v96.hbc"), "summary"), StringComparison.Ordinal);
        Assert.Equal(ErrorCode.NotFound, Assert.Throws<ToolError>(() => Run(bundle, "decompile", "nothing")).Code);
    }

    [Fact]
    public void Summarize_file_and_search_container_find_the_bundle_in_an_apk()
    {
        var apk = Apk("metro-v59.hbc");
        var bytes = File.ReadAllBytes(apk);
        var view = new HermesFileView().Inspect(new FileInput(apk, bytes, Blob.Identify(bytes)), default)!;
        var facts = Assert.IsType<HermesFacts>(view.Detail);
        Assert.Equal((59, "assets/index.android.bundle", 7, 2), (facts.Version, facts.Bundle, facts.Functions, facts.MetroModules));
        Assert.Equal("hermes bytecode", Blob.Identify(File.ReadAllBytes(Fixture("metro-v59.hbc"))));
        using var ws = new AssemblyWorkspace(new ServerOptions());
        var found = new UnpackService(ws).Search(apk, "login", "hermes", 10, AnalysisLimits.Default, default);
        Assert.Contains(found.Items, m => m.Name == "/v1/login" && m.Path == "assets/index.android.bundle" && m.Detail!.StartsWith("string #", StringComparison.Ordinal));
        Assert.Contains(found.Items, m => m.Name == "login" && m.Detail == "function #4, Metro module 0");
    }

    [Fact]
    [FuzzEntry(typeof(HermesFile), typeof(HermesFileView))]
    public void Fuzzed_bundles_never_throw()
    {
        var failures = new List<string>();
        foreach (var seed in new[] { "sample-v96.hbc", "features-v89.hbc", "metro-v59.hbc" })
            failures.AddRange(FormatFuzz.Run(File.ReadAllBytes(Fixture(seed)), b =>
            {
                HermesFile f;
                try { f = HermesFile.Read(b); }
                catch (ToolError) { return; }
                var index = new HermesIndex(f);
                foreach (var fn in f.Functions)
                {
                    HermesDecompiler.Function(index, fn.Index);
                    f.Locations(fn);
                }
                new HermesFileView().Inspect(new FileInput("x.hbc", b, Blob.Identify(b)), default);
            }, 600));
        Assert.True(failures.Count == 0, string.Join("\n", failures.Take(20)));
    }

    /// <summary>
    /// hbcdump (CORVUS_HBC_DISASSEMBLER: one build, or a folder of builds for several versions) decodes the same instructions
    /// at the same offsets with the same operands, for every fixture a build reads and every bundle under CORVUS_HBC_DIR.
    /// </summary>
    [Trait("Speed", "Slow")]
    [RequiresRealDataFact("CORVUS_HBC_DISASSEMBLER")]
    public void Disassembly_equals_hbcdump()
    {
        var configured = RealData.Path("CORVUS_HBC_DISASSEMBLER");
        var builds = File.Exists(configured) ? [configured]
            : Directory.EnumerateFiles(configured, ExternalTools.HbcDisassembler.Files[0], SearchOption.AllDirectories).Order(StringComparer.Ordinal).ToList();
        var files = Directory.EnumerateFiles(Path.GetDirectoryName(Fixture("x"))!, "*.hbc").ToList();
        if (RealData.Get("CORVUS_HBC_DIR") is { } dir && Directory.Exists(dir)) files.AddRange(Directory.EnumerateFiles(dir, "*.hbc", SearchOption.AllDirectories));
        var perVersion = new SortedDictionary<int, (int Files, long Matched, long Total)>();
        var differ = new List<string>();
        foreach (var file in files)
        {
            var f = HermesFile.Read(File.ReadAllBytes(file));
            ExternalTools.RunResult? run = null;
            foreach (var exe in builds)
            {
                var r = ExternalTools.Run(exe, ExternalTools.Arguments(ExternalTools.HbcDisassembler, "objdump", ("file", file)), TimeSpan.FromMinutes(10), 1L << 32, default);
                if (r.ExitCode == 0 && r.Text.Contains($"file format HBC-{f.Version}", StringComparison.Ordinal)) { run = r; break; }
            }
            if (run == null) { output.WriteLine($"{Path.GetFileName(file)}: no hbcdump build reads version {f.Version}"); continue; }
            // functions with identical bytecode share it, so an address may be listed once per function
            var reference = new Dictionary<long, (string Name, long[] Operands)>();
            long listed = 0;
            foreach (var l in run.Text.Split('\n'))
                if (ObjdumpLine().Match(l) is { Success: true } m)
                {
                    listed++;
                    reference[Convert.ToInt64(m.Groups[1].Value, 16)] = (m.Groups[2].Value, [.. m.Groups[3].Value.Split(", ", StringSplitOptions.RemoveEmptyEntries).Select(Value)]);
                }
            long matched = 0, total = 0;
            foreach (var fn in f.Functions)
                foreach (var ins in HermesCode.Decode(f, fn))
                {
                    total++;
                    long at = fn.Offset + ins.Offset;
                    var ours = Enumerable.Range(0, ins.Op.Operands.Length).Select(i => ins.Op.Operands[i] switch
                    {
                        { IsJump: true } => fn.Offset + ins[i],
                        { Type: HermesOperandType.Double } => BitConverter.DoubleToInt64Bits(ins.Double),
                        { Type: HermesOperandType.Imm32 } => (long)(int)ins[i],
                        _ => ins[i],
                    }).ToArray();
                    if (reference.TryGetValue(at, out var r) && r.Name == ins.Name && r.Operands.SequenceEqual(ours)) matched++;
                    else if (differ.Count < 20) differ.Add($"{Path.GetFileName(file)} 0x{at:x}: ours {ins.Name} {string.Join(", ", ours)}, hbcdump {(reference.TryGetValue(at, out var rr) ? rr.Name + " " + string.Join(", ", rr.Operands) : "<none>")}");
                }
            Assert.True(listed == total, $"{Path.GetFileName(file)}: hbcdump lists {listed:N0} instructions, ours {total:N0}");
            var (n, m2, t) = perVersion.GetValueOrDefault(f.Version);
            perVersion[f.Version] = (n + 1, m2 + matched, t + total);
        }
        foreach (var (v, (n, m, t)) in perVersion) output.WriteLine($"version {v}: {m:N0} of {t:N0} instructions equal in {n} file(s)");
        foreach (var d in differ) output.WriteLine(d);
        Assert.NotEmpty(perVersion);
        Assert.Empty(differ);
    }

    // "0000038c:\t34 13 00 00 00   DeclareGlobalVar   $0x000013"; jump targets are absolute file offsets without '$'
    [GeneratedRegex(@"^([0-9a-f]{8}):\t(?:[0-9a-f]{2} )+[ \t]+(\w+)[ \t]*(.*?)\r?$")]
    private static partial Regex ObjdumpLine();

    private static long Value(string s) => s.StartsWith("%r", StringComparison.Ordinal) ? long.Parse(s[2..], CultureInfo.InvariantCulture)
        : s.StartsWith("$0x", StringComparison.Ordinal) ? (long)ulong.Parse(s[3..], NumberStyles.HexNumber, CultureInfo.InvariantCulture)
        : long.Parse(s, NumberStyles.HexNumber, CultureInfo.InvariantCulture);

    /// <summary>Every bundle under CORVUS_HBC_DIR: read and indexed in under a second (10 MB scale), every function decompiled.</summary>
    [Trait("Speed", "Slow")]
    [RequiresRealDataFact("CORVUS_HBC_DIR")]
    public void Real_bundles_read_fast_and_decompile_whole()
    {
        foreach (var file in Directory.EnumerateFiles(RealData.Path("CORVUS_HBC_DIR"), "*", SearchOption.AllDirectories).Where(p => HermesBundles.Applies(p)))
        {
            var bytes = File.ReadAllBytes(file);
            var clock = Stopwatch.StartNew();
            var f = HermesFile.Read(HermesBundles.FromPackage(bytes, out _)!);
            var read = clock.Elapsed;
            var index = new HermesIndex(f);
            var indexed = clock.Elapsed;
            clock.Restart();
            int gotos = 0;
            foreach (var fn in f.Functions)
                if (HermesDecompiler.Function(index, fn.Index).Contains("goto ", StringComparison.Ordinal)) gotos++;
            output.WriteLine($"{Path.GetFileName(file)} v{f.Version}, {bytes.Length:N0} bytes: read {read.TotalMilliseconds:N0} ms, indexed {indexed.TotalMilliseconds:N0} ms " +
                             $"({index.Instructions:N0} instructions, {index.Modules.Count:N0} modules); {f.Functions.Count:N0} functions decompiled in " +
                             $"{clock.Elapsed.TotalSeconds:N1} s, {gotos:N0} with a goto ({100.0 * gotos / Math.Max(1, f.Functions.Count):N1} %)");
            Assert.Empty(f.Issues);
            if (bytes.Length <= 16 << 20) Assert.True(indexed < TimeSpan.FromSeconds(1), $"{file}: read and indexed in {indexed.TotalMilliseconds:N0} ms");
        }
    }
}
