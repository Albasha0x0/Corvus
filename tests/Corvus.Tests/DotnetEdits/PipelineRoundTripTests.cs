using System.Diagnostics;
using System.Text;
using System.Text.RegularExpressions;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Corvus.Services.Simplify;
using Xunit.Abstractions;

namespace Corvus.Tests;

/// <summary>
/// Programs run through a post-build transformation pipeline, then simplified, behave like the originals, and simplifying
/// takes back at least the floor pinned per option and sample.
/// </summary>
/// <remarks>
/// CORVUS_PIPELINE_TOOL names the pipeline executable. Samples: every PipelineSamples/*.cs, plus CORVUS_PIPELINE_SAMPLES.
/// Optional: CORVUS_PIPELINE_PROFILES (default Build/Profiles beside the tool), CORVUS_PIPELINE_SEEDS (default 3 exhaustive,
/// else one by day), CORVUS_PIPELINE_SEED, CORVUS_PIPELINE_ONLY, CORVUS_PIPELINE_SAMPLE, CORVUS_PIPELINE_PARALLEL (default 1),
/// CORVUS_PIPELINE_BUDGET_MINUTES (default 90 exhaustive, else 45), CORVUS_PIPELINE_REPORT, CORVUS_PIPELINE_KEEP.
/// A processed build that already misbehaves is reported, not counted.
/// </remarks>
[Trait("Speed", "Slow")]
[Permit("reference-tool")]
public abstract class PipelineRoundTripTests(ITestOutputHelper output, int part) : IDisposable
{
    public const string ToolVariable = "CORVUS_PIPELINE_TOOL";

    /// <summary>Classes the round trips are dealt to; each takes a reference-tool permit of its own.</summary>
    public const int Parts = 6;

    public sealed class Part1(ITestOutputHelper output) : PipelineRoundTripTests(output, 0);
    public sealed class Part2(ITestOutputHelper output) : PipelineRoundTripTests(output, 1);
    public sealed class Part3(ITestOutputHelper output) : PipelineRoundTripTests(output, 2);
    public sealed class Part4(ITestOutputHelper output) : PipelineRoundTripTests(output, 3);
    public sealed class Part5(ITestOutputHelper output) : PipelineRoundTripTests(output, 4);
    public sealed class Part6(ITestOutputHelper output) : PipelineRoundTripTests(output, 5);

    /// <summary>Pairs no part has taken yet; a free part takes the next, so the parts end together.</summary>
    private static readonly System.Collections.Concurrent.ConcurrentDictionary<string, System.Collections.Concurrent.ConcurrentQueue<int>> Pending = new(StringComparer.Ordinal);

    /// <summary>The parts (0-based) whose classes this run executes, always including <paramref name="part"/>.</summary>
    private static SortedSet<int> PartsInRun(int part)
    {
        var parts = new SortedSet<int> { part };
        foreach (var type in typeof(PipelineRoundTripTests).GetNestedTypes())
            if (type.IsSubclassOf(typeof(PipelineRoundTripTests)) && LeakGuardFramework.RunClasses.Contains(type.FullName!))
                parts.Add(int.Parse(type.Name["Part".Length..]) - 1);
        return parts;
    }

    private readonly TempDir _dir = new();
    private bool _keep;

    public void Dispose()
    {
        if (_keep || Environment.GetEnvironmentVariable("CORVUS_PIPELINE_KEEP") != null) output.WriteLine($"files kept in {_dir.Path}");
        else _dir.Dispose();
    }

    /// <summary>Option ids of the external tool, verbatim: they are the tool's own names, as are the arguments in <see cref="Options"/>.</summary>
    private static class ToolIds
    {
        public const string ControlFlow = "ctrl flow";
        public const string Constants = "constants";
        public const string CallIndirection = "ref proxy";
        public const string Resources = "resources";
        public const string DebuggerCheck = "anti debug";
        public const string ResourceIntegrity = "integrity";
        public const string SelfCheck = "anti tamper";
        public const string DumpCheck = "anti dump";
        public const string DisassemblerOptOut = "anti ildasm";
        public const string Renaming = "rename";
        public const string MetadataNoise = "invalid metadata";
        public const string TypeScrambling = "typescramble";
        public const string Compression = "compressor";

        /// <summary>The project file's XML namespace, the element that enables one option and the one that sets the packer.</summary>
        public const string ProjectNamespace = "http://confuser.codeplex.com";
        public const string OptionElement = "protection";
        public const string PackerElement = "packer";

        /// <summary>Environment variable the resource-integrity option reads its signing key from.</summary>
        public const string SigningKeyVariable = "CONFUSER_INTEGRITY_KEY_PATH";
    }

    /// <summary>Percent of an option's added instructions simplifying must take back per sample (null: not checked); pinned from a clean 3-seed run, less one point.</summary>
    public sealed record Floors(double? Workload = null, double? BasicFlow = null, double? Constants = null, double? ExceptionFlow = null)
    {
        public double? For(string sample) => sample switch
        {
            "Workload" => Workload, "BasicFlow" => BasicFlow, "Constants" => Constants, "ExceptionFlow" => ExceptionFlow, _ => null,
        };
    }

    private static readonly Floors None = new(0, 0, 0, 0);

    /// <summary>One pipeline configuration: the rule's options and an optional <see cref="Packer"/>; a null floor checks behaviour only.</summary>
    public sealed record Option(string Name, string Rule, Floors? Floor = null, string? Packer = null);

    /// <summary>Pipeline options with their floors (<see cref="Floors"/>); the Constants sample fails its own checks after constant encoding, so it has no floor there.</summary>
    public static readonly Option[] Options =
    [
        new("control-flow switch normal", Rule(ToolIds.ControlFlow, ("type", "switch"), ("predicate", "normal"), ("intensity", "100")), new Floors(73, 89, 83, 52)),
        new("control-flow switch expression", Rule(ToolIds.ControlFlow, ("type", "switch"), ("predicate", "expression"), ("intensity", "100")), new Floors(66, 91, 84, 45)),
        new("control-flow switch native", Rule(ToolIds.ControlFlow, ("type", "switch"), ("predicate", "x86"), ("intensity", "100")), new Floors(89, 89, 82, 93)),
        new("control-flow switch filler", Rule(ToolIds.ControlFlow, ("type", "switch"), ("predicate", "expression"), ("junk", "true"), ("intensity", "100")), new Floors(67, 92, 83, 42)),
        new("constants normal", Rule(ToolIds.Constants, ("mode", "normal"), ("elements", "SNPI")), new Floors(0, 0, null, 0)),
        new("constants dynamic", Rule(ToolIds.Constants, ("mode", "dynamic"), ("elements", "SNPI")), new Floors(0, 0, null, 0)),
        new("constants native", Rule(ToolIds.Constants, ("mode", "x86"), ("elements", "SNPI")), new Floors(0, 0, null, 0)),
        new("call-indirection mild", Rule(ToolIds.CallIndirection, ("mode", "mild")), new Floors(2, 0, 0, 0)),
        new("call-indirection strong normal", Rule(ToolIds.CallIndirection, ("mode", "strong"), ("encoding", "normal")), None),
        new("call-indirection strong expression", Rule(ToolIds.CallIndirection, ("mode", "strong"), ("encoding", "expression")), None),
        new("call-indirection strong native", Rule(ToolIds.CallIndirection, ("mode", "strong"), ("encoding", "x86")), None),
        new("resources", Rule(ToolIds.Resources, ("mode", "normal")), None),
        new("resources dynamic", Rule(ToolIds.Resources, ("mode", "dynamic"))),
        new("debugger-check", Rule(ToolIds.DebuggerCheck, ("mode", "safe")), new Floors(7, 0, 0, 0)),
        new("debugger-check native", Rule(ToolIds.DebuggerCheck, ("mode", "win32"))),
        new("debugger-check profiler", Rule(ToolIds.DebuggerCheck, ("mode", "antinet"))),
        new("dump-check", Rule(ToolIds.DumpCheck)),
        new("disassembler opt-out", Rule(ToolIds.DisassemblerOptOut)),
        new("metadata noise", Rule(ToolIds.MetadataNoise)),
        new("renaming letters", Rule(ToolIds.Renaming, ("mode", "letters"))),
        new("renaming unicode", Rule(ToolIds.Renaming, ("mode", "unicode"))),
        new("type scrambling", Rule(ToolIds.TypeScrambling)),
        new("resource-integrity signed", Rule(ToolIds.ResourceIntegrity, ("resourcePattern", @"^(?!integrity\.).*"), ("checkMode", "manual")), new Floors(7, 6, 6, 6)),
        new("compression", "", Packer: Packer(ToolIds.Compression)),
        new("constants + control-flow", Rule(ToolIds.Constants, ("mode", "dynamic"), ("elements", "SNPI")) + Rule(ToolIds.ControlFlow, ("predicate", "expression"), ("intensity", "100")), new Floors(46, 45, null, 43)),
        new("constants + call-indirection + control-flow", Rule(ToolIds.Constants, ("mode", "normal"), ("elements", "SNPI")) +
                                                           Rule(ToolIds.CallIndirection, ("mode", "strong"), ("encoding", "expression")) +
                                                           Rule(ToolIds.ControlFlow, ("predicate", "normal"), ("intensity", "100")), new Floors(39, 40, null, 39)),
        new("all but self-check", Rule(ToolIds.Constants, ("mode", "dynamic"), ("elements", "SNPI")) + Rule(ToolIds.CallIndirection, ("mode", "strong"), ("encoding", "expression")) +
                                  Rule(ToolIds.ControlFlow, ("predicate", "expression"), ("intensity", "100")) + Rule(ToolIds.Resources, ("mode", "dynamic")) +
                                  Rule(ToolIds.DebuggerCheck, ("mode", "safe")) + Rule(ToolIds.DumpCheck) + Rule(ToolIds.DisassemblerOptOut), new Floors(41, 41, null, 40)),
        new("renaming + control-flow + constants", Rule(ToolIds.Renaming, ("mode", "letters")) + Rule(ToolIds.ControlFlow, ("predicate", "expression"), ("intensity", "100")) +
                                                   Rule(ToolIds.Constants, ("mode", "dynamic"), ("elements", "SNPI"))),
    ];

    /// <summary>Options not run because the tool fails or its output misbehaves; CORVUS_PIPELINE_RECHECK=1 runs them anyway.</summary>
    public static readonly (string Name, string? Rule, string Why)[] Skipped =
    [
        ("self-check", Rule(ToolIds.SelfCheck, ("mode", "normal")),
            "the processed build stores its method bodies in another form on disk and restores them at run time, so the bodies " +
            "on disk are not IL: nothing is simplified, and in a small module how many happen to decode depends on the tool's " +
            "own random key, not the seed (Constants: 1 of 5 bodies unreadable, 2 decoded to IL that does not verify, and the " +
            "unreadable one cannot be written back)"),
        ("control-flow jump", Rule(ToolIds.ControlFlow, ("type", "jump"), ("intensity", "100")),
            "the processed build crashes with an unhandled CLR exception (exit 0xE0434352) on every seed"),
        ("constants dynamic cfg", Rule(ToolIds.Constants, ("mode", "dynamic"), ("elements", "SNPI"), ("cfg", "true")),
            "the tool itself fails: dnlib's writer throws 'Error calculating max stack value' while saving"),
        ("profile strong", null, "uses constants with cfg=true: the tool fails ('Failed to calcuate maxstack')"),
        ("profile critical", null, "uses constants with cfg=true: the tool fails ('Failed to calcuate maxstack')"),
    ];

    /// <summary>Floors of the tool's bundled profiles that are run (see <see cref="Profiles"/>).</summary>
    public static readonly (string Name, Floors Floor)[] ProfileFloors =
    [
        ("profile balanced", new Floors(35, 31, 31, 30)),
    ];

    private static bool Recheck => Environment.GetEnvironmentVariable("CORVUS_PIPELINE_RECHECK") == "1";

    /// <summary>One option of the project file's rule, with its arguments.</summary>
    private static string Rule(string id, params (string Name, string Value)[] arguments) =>
        $"    <{ToolIds.OptionElement} id=\"{id}\">\n" + string.Concat(arguments.Select(a => $"      <argument name=\"{a.Name}\" value=\"{a.Value}\" />\n")) +
        $"    </{ToolIds.OptionElement}>\n";

    /// <summary>The project file's packer element, with its arguments.</summary>
    private static string Packer(string id, params (string Name, string Value)[] arguments) =>
        $"  <{ToolIds.PackerElement} id=\"{id}\">\n" + string.Concat(arguments.Select(a => $"    <argument name=\"{a.Name}\" value=\"{a.Value}\" />\n")) +
        $"  </{ToolIds.PackerElement}>\n";

    private sealed record Metrics(int Instructions, int Switches, int ModuleTypeCalls, int DelegateInvokes);

    private sealed record Row(string Sample, string Option, int Seed, string Outcome, Metrics Original, Metrics? Processed, Metrics? Simplified,
        int Changed, string Fallbacks, double? Floor)
    {
        public double Seconds { get; init; }

        /// <summary>What simplifying took back of the instructions the pipeline added, in percent.</summary>
        public double? Removed => Processed is { } p && Simplified is { } s && p.Instructions > Original.Instructions
            ? 100.0 * (p.Instructions - s.Instructions) / (p.Instructions - Original.Instructions)
            : null;
    }

    private sealed record Sample(string Name, string Source, byte[]? Resource);

    /// <summary>A compiled sample with what its original build prints.</summary>
    private sealed record Built(string Name, string Path, string Expected, Metrics Baseline);

    [Trait("Speed", "Slow")]
    [RequiresRealDataFact(ToolVariable)]
    public void Processed_programs_simplify_and_behave_the_same()
    {
        var tool = RealData.Path(ToolVariable);
        var seeds = Seeds();
        output.WriteLine($"seeds: {string.Join(", ", seeds)} (CORVUS_PIPELINE_SEED=<n> runs one)");
        int parallel = int.TryParse(Environment.GetEnvironmentVariable("CORVUS_PIPELINE_PARALLEL"), out int p) ? Math.Max(p, 1) : 1;
        var only = Environment.GetEnvironmentVariable("CORVUS_PIPELINE_ONLY");
        var onlySample = Environment.GetEnvironmentVariable("CORVUS_PIPELINE_SAMPLE");
        if (!Recheck) foreach (var (name, _, why) in Skipped) output.WriteLine($"skipped option {name}: {why}");

        bool Wanted(string name) => only == null || name.Contains(only, StringComparison.Ordinal);
        var options = Options.Where(o => Wanted(o.Name)).ToList();
        if (Recheck) options.AddRange(Skipped.Where(k => k.Rule != null && Wanted(k.Name)).Select(k => new Option(k.Name, k.Rule!)));
        foreach (var (name, rule) in Profiles(tool).Where(p => Wanted(p.Name) && (Recheck || Skipped.All(k => k.Name != p.Name))))
            options.Add(new Option(name, rule, ProfileFloors.FirstOrDefault(f => f.Name == name).Floor));

        var built = new List<Built>();
        foreach (var sample in Samples().Where(s => onlySample == null || s.Name.Contains(onlySample, StringComparison.Ordinal)))
        {
            var original = Compile(sample);
            var expected = RunProgram(original);
            Assert.True(expected.ExitCode == 0, $"{sample.Name}: the original does not run: {expected.Output}");
            built.Add(new Built(sample.Name, original, expected.Output, Measure(File.ReadAllBytes(original))));
        }

        // A part takes a sample and option pair with all its seeds, as each floor is the least over the seeds.
        var pairs = (from b in built from o in options select (Built: b, Option: o)).ToList();
        // The queue holds this run's pairs, so a part run alone takes only its own share.
        var inRun = PartsInRun(part);
        var pending = Pending.GetOrAdd(string.Join("|", pairs.Select(r => $"{r.Built.Name} / {r.Option.Name}").Append(string.Join(",", seeds)).Append(string.Join(",", inRun))),
            _ => new(Enumerable.Range(0, pairs.Count).Where(i => inRun.Contains(i % Parts))));
        var share = Enumerable.Range(0, pairs.Count).Count(i => inRun.Contains(i % Parts));
        var taken = new System.Collections.Concurrent.ConcurrentBag<(int Pair, int Seed, Row Row)>();
        var failures = new System.Collections.Concurrent.ConcurrentQueue<string>();
        SigningKey();
        // No pair starts once the budget is spent; the test then fails naming the slowest.
        var budget = TimeSpan.FromMinutes(double.TryParse(Environment.GetEnvironmentVariable("CORVUS_PIPELINE_BUDGET_MINUTES"), out var minutes) ? minutes : SweepScope.Exhaustive ? 90 : 45);
        var clock = Stopwatch.StartNew();
        Parallel.For(0, parallel, new ParallelOptions { MaxDegreeOfParallelism = parallel }, _ =>
        {
            while (clock.Elapsed <= budget && pending.TryDequeue(out var i))
                foreach (var seed in seeds)
                {
                    var started = clock.Elapsed;
                    var row = RoundTrip(tool, pairs[i].Built, pairs[i].Option, pairs[i].Option.Floor?.For(pairs[i].Built.Name), seed, failures);
                    taken.Add((i, seed, row with { Seconds = (clock.Elapsed - started).TotalSeconds }));
                }
        });
        var rows = taken.OrderBy(t => t.Pair).ThenBy(t => t.Seed).Select(t => t.Row).ToArray();
        foreach (var row in rows) output.WriteLine(Line(row));
        output.WriteLine($"part {part + 1}: {rows.Length} round trips ({taken.Select(t => t.Pair).Distinct().Count()} of the {share} pairs of parts {string.Join(", ", inRun.Select(p => p + 1))}) in {clock.Elapsed.TotalMinutes:0.0} min, median {Median(rows.Select(r => r.Seconds)):0.0} s");
        if (!pending.IsEmpty)
            failures.Enqueue($"{pending.Count} of {share} sample and option pairs left when this part's {budget.TotalMinutes:0} min budget ran out " +
                             $"(CORVUS_PIPELINE_BUDGET_MINUTES; CORVUS_PIPELINE_SEEDS, _ONLY and _SAMPLE narrow the run); slowest: " +
                             string.Join(", ", rows.OrderByDescending(r => r.Seconds).Take(5).Select(r => $"{r.Sample} / {r.Option} seed {r.Seed} {r.Seconds:0} s")));

        // The floors: the least any seed achieved, per sample and option.
        foreach (var group in rows.Where(r => r.Floor != null && r.Outcome == "same").GroupBy(r => (r.Sample, r.Option)))
        {
            var worst = group.Where(r => r.Removed != null).Select(r => r.Removed!.Value).DefaultIfEmpty(100).Min();
            if (worst < group.First().Floor)
                failures.Enqueue($"{group.Key.Sample} / {group.Key.Option} seeds {string.Join(",", group.Select(r => r.Seed))}: simplifying took back {worst:0.0}% of the added instructions, below the floor of {group.First().Floor}%");
        }

        var report = Report(rows, built.Select(b => b.Name).ToList(), options.Select(o => o.Name).ToList());
        if (Environment.GetEnvironmentVariable("CORVUS_PIPELINE_REPORT") is { Length: > 0 } path)
            File.WriteAllText(Path.ChangeExtension(path, $"part{part + 1}{Path.GetExtension(path)}"), report);
        output.WriteLine(report);
        Assert.True(failures.IsEmpty, string.Join("\n", failures));
    }

    private Row RoundTrip(string tool, Built sample, Option option, double? floor, int seed, System.Collections.Concurrent.ConcurrentQueue<string> failures)
    {
        var (name, expected, baseline) = (option.Name, sample.Expected, sample.Baseline);
        var work = Path.Combine(_dir.Path, $"{sample.Name}-{Regex.Replace(name, "[^A-Za-z0-9]+", "_")}-{seed}");
        var outDir = Path.Combine(work, "out");
        Directory.CreateDirectory(work);
        var file = Path.GetFileName(sample.Path);
        File.Copy(sample.Path, Path.Combine(work, file));
        var project = Path.Combine(work, "project.crproj");
        File.WriteAllText(project,
            $"<project outputDir=\"{outDir}\" baseDir=\"{work}\" seed=\"corvus-test-{name}-{seed}\" xmlns=\"{ToolIds.ProjectNamespace}\">\n" +
            $"  <rule pattern=\"true\" preset=\"none\">\n{option.Rule}  </rule>\n" + option.Packer +
            $"  <module path=\"{file}\" />\n</project>\n");
        Row Result(string outcome, Metrics? processed = null, Metrics? simplified = null, int changed = 0, string fallbacks = "") =>
            new(sample.Name, name, seed, outcome, baseline, processed, simplified, changed, fallbacks, floor);

        var psi = new ProcessStartInfo(tool, $"-n \"{project}\"") { WorkingDirectory = work };
        psi.Environment[ToolIds.SigningKeyVariable] = SigningKey(); // the resource-integrity option signs with it
        // The tool leaves a copy of the module in a folder of its own under TEMP: kept inside work, it goes with it.
        var temp = Directory.CreateDirectory(Path.Combine(work, "temp")).FullName;
        psi.Environment["TEMP"] = psi.Environment["TMP"] = temp;
        var (code, log) = Tools.Run(psi, 300_000);
        var processedPath = Path.Combine(outDir, file);
        if (code != 0 || !File.Exists(processedPath))
        {
            var errors = log.Split('\n').Where(l => l.Contains("ERROR") || l.Contains("Exception")).Take(2).Select(l => l.Trim());
            return Result($"tool failed ({code}): {string.Join(" / ", errors)}");
        }
        if (Blocked(processedPath) is { } quarantined) return Result($"processed build blocked by antivirus, not counted ({quarantined})");
        var processedBytes = File.ReadAllBytes(processedPath);
        var processedRun = RunProgram(processedPath);
        if (processedRun.Output != expected)
            return Result($"processed build misbehaves, not counted: {Diff(expected, processedRun.Output).Split('\n').Skip(1).FirstOrDefault()?.Trim()}", Measure(processedBytes));

        // The time limits scale with the machine's load, so a loaded run gives each method the same work as a quiet one.
        var load = MachineLoad.Factor();
        var quiet = new EvaluationLimits();
        var limits = quiet with { MethodTimeLimitMs = (int)(quiet.MethodTimeLimitMs * load), InitializerTimeLimitMs = (int)(quiet.InitializerTimeLimitMs * load) };
        var outcome = SimplifyHarness.Run(processedPath, new SimplifyOptions(Limits: limits));
        var fallbacks = string.Join(" ", outcome.Fallbacks().OrderByDescending(f => f.Value).Select(f => $"{f.Key} {f.Value}"));
        if (outcome.Problems.Count > 0)
        {
            failures.Enqueue($"{sample.Name} / {name} seed {seed}: {string.Join("; ", outcome.Problems.Take(3))}{(load > 1 ? $" (machine load x{load:0.00})" : "")}");
            return Result("engine problem", Measure(processedBytes), null, outcome.Changed, fallbacks);
        }
        // With no method changed, save_assembly writes the original bytes.
        var image = outcome.Changed == 0 ? processedBytes : outcome.Image!;
        var simplifiedPath = Path.Combine(work, "simplified", file);
        Directory.CreateDirectory(Path.GetDirectoryName(simplifiedPath)!);
        File.WriteAllBytes(simplifiedPath, image);
        var simplifiedRun = RunProgram(simplifiedPath);
        if (Blocked(simplifiedPath) is { } blocked)
            return Result($"simplified build blocked by antivirus, not counted ({blocked})", Measure(processedBytes), Measure(image), outcome.Changed, fallbacks);
        if (simplifiedRun.Output != expected)
        {
            failures.Enqueue($"{sample.Name} / {name} seed {seed}: the simplified build behaves differently:\n{Diff(expected, simplifiedRun.Output)}\n(kept in {work})");
            _keep = true;
            return Result("DIFFERS", Measure(processedBytes), Measure(image), outcome.Changed, fallbacks);
        }
        return Result("same", Measure(processedBytes), Measure(image), outcome.Changed, fallbacks);
    }

    private string? _key;

    /// <summary>A throwaway RSA key (XML) for options that sign the processed build.</summary>
    private string SigningKey()
    {
        if (_key != null) return _key;
        using var rsa = System.Security.Cryptography.RSA.Create(2048);
        _key = Path.Combine(_dir.Path, "signing-key.xml");
        File.WriteAllText(_key, rsa.ToXmlString(includePrivateParameters: true));
        return _key;
    }

    /// <summary>Embedded resources of the own samples, as {sample}.data.txt.</summary>
    private static readonly Dictionary<string, string> SampleResources = new()
    {
        ["Workload"] = "resource text: ünïcödé ✓\n",
    };

    /// <summary>Every PipelineSamples/*.cs in name order, plus the CORVUS_PIPELINE_SAMPLES projects that have a Program.cs.</summary>
    private static IEnumerable<Sample> Samples()
    {
        foreach (var file in Directory.GetFiles(Path.Combine(AppContext.BaseDirectory, "PipelineSamples"), "*.cs").Order(StringComparer.Ordinal))
        {
            var name = Path.GetFileNameWithoutExtension(file);
            yield return new Sample(name, File.ReadAllText(file), SampleResources.TryGetValue(name, out var text) ? Encoding.UTF8.GetBytes(text) : null);
        }
        if (RealData.Get("CORVUS_PIPELINE_SAMPLES") is not { } dir) yield break;
        foreach (var name in new[] { "BasicFlow", "Constants", "ExceptionFlow" })
        {
            var program = Path.Combine(dir, name, "Program.cs");
            if (File.Exists(program)) yield return new Sample(name, File.ReadAllText(program), null);
        }
    }

    /// <summary>The tool's bundled profiles: the rules of each .crproj, run on our module and seed.</summary>
    private static IEnumerable<(string Name, string Rule)> Profiles(string tool)
    {
        // Next to a release's executable, or two levels up from a source build's Release/bin.
        var toolDir = Path.GetDirectoryName(tool)!;
        var dir = RealData.Get("CORVUS_PIPELINE_PROFILES")
                  ?? new[] { Path.Combine(toolDir, "Build", "Profiles"), Path.Combine(toolDir, "..", "..", "Build", "Profiles") }.FirstOrDefault(Directory.Exists);
        if (dir == null || !Directory.Exists(dir)) yield break;
        foreach (var file in Directory.GetFiles(dir, "*.crproj").Order(StringComparer.Ordinal))
        {
            var text = Regex.Replace(File.ReadAllText(file), "<!--.*?-->", "", RegexOptions.Singleline);
            var rule = Regex.Match(text, "<rule[^>]*>(.*?)</rule>", RegexOptions.Singleline);
            if (rule.Success) yield return ("profile " + Path.GetFileNameWithoutExtension(file), rule.Groups[1].Value.Trim('\r', '\n') + "\n");
        }
    }

    /// <summary>Compiles a sample for .NET Framework 4.8, 32-bit preferred, as the tool's native modes need a 32-bit process.</summary>
    private string Compile(Sample sample)
    {
        var refs = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86), "Reference Assemblies", "Microsoft", "Framework", ".NETFramework", "v4.8");
        Assert.True(Directory.Exists(refs), $".NET Framework 4.8 reference assemblies not found at {refs}");
        var references = new[] { "mscorlib.dll", "System.dll", "System.Core.dll" }.Select(r => MetadataReference.CreateFromFile(Path.Combine(refs, r)));
        var compilation = CSharpCompilation.Create(sample.Name, [CSharpSyntaxTree.ParseText(sample.Source, new CSharpParseOptions(LanguageVersion.CSharp7_3))], references,
            new CSharpCompilationOptions(OutputKind.ConsoleApplication, optimizationLevel: OptimizationLevel.Release, platform: Platform.AnyCpu32BitPreferred));
        var path = Path.Combine(_dir.Path, sample.Name + ".exe");
        using var file = File.Create(path);
        var resources = sample.Resource is { } data
            ? new[] { new ResourceDescription($"{sample.Name}.data.txt", () => new MemoryStream(data), isPublic: true) }
            : null;
        var result = compilation.Emit(file, manifestResources: resources);
        Assert.True(result.Success, $"{sample.Name}: " + string.Join("\n", result.Diagnostics.Where(d => d.Severity == DiagnosticSeverity.Error)));
        return path;
    }

    /// <summary>Why antivirus software blocks the file; null when it can be read.</summary>
    private static string? Blocked(string path)
    {
        try
        {
            using var file = File.OpenRead(path);
            return null;
        }
        catch (IOException ex) when (ex.HResult is unchecked((int)0x800700E1) or unchecked((int)0x800700E2)) // ERROR_VIRUS_INFECTED / _DELETED
        {
            return ex.Message.Trim();
        }
    }

    private static (int ExitCode, string Output) RunProgram(string exe)
    {
        var psi = new ProcessStartInfo(exe) { WorkingDirectory = Path.GetDirectoryName(exe)!, StandardOutputEncoding = Encoding.UTF8 };
        var (code, text) = Tools.Run(psi, 60_000);
        return (code, $"exit {code}\n{text.ReplaceLineEndings("\n")}");
    }

    /// <summary>The whole module (names may be changed): instructions, switches, calls into &lt;Module&gt; and of module-defined delegates.</summary>
    private static Metrics Measure(byte[] image)
    {
        using var module = ModuleDefMD.Load(image);
        int instructions = 0, switches = 0, moduleCalls = 0, invokes = 0;
        foreach (var m in module.GetTypes().SelectMany(t => t.Methods).Where(m => m.HasBody))
        {
            IList<Instruction> code;
            try { code = m.Body.Instructions; }
            catch (Exception ex) when (ex is BadImageFormatException or InvalidOperationException) { continue; }
            foreach (var ins in code)
            {
                instructions++;
                if (ins.OpCode.Code == Code.Switch) switches++;
                if (ins.OpCode.FlowControl != FlowControl.Call || ins.Operand is not IMethod callee) continue;
                var owner = callee.DeclaringType?.ResolveTypeDef();
                if (owner == null || owner.Module != module) continue;
                if (owner.IsGlobalModuleType && !m.DeclaringType.IsGlobalModuleType) moduleCalls++;
                if (callee.Name == "Invoke" && owner.BaseType?.FullName == "System.MulticastDelegate") invokes++;
            }
        }
        return new Metrics(instructions, switches, moduleCalls, invokes);
    }

    /// <summary>The seeds to run: CORVUS_PIPELINE_SEED, else 1 to CORVUS_PIPELINE_SEEDS, else all three when exhaustive, else one by day.</summary>
    private static List<int> Seeds()
    {
        if (int.TryParse(Environment.GetEnvironmentVariable("CORVUS_PIPELINE_SEED"), out int one)) return [one];
        if (int.TryParse(Environment.GetEnvironmentVariable("CORVUS_PIPELINE_SEEDS"), out int n)) return [.. Enumerable.Range(1, n)];
        return SweepScope.Exhaustive ? [1, 2, 3] : [RunDay.DayNumber % 3 + 1];
    }

    // Read once per test process: parts that start on either side of midnight UTC keep one seed, and so one queue.
    private static readonly DateOnly RunDay = DateOnly.FromDateTime(DateTime.UtcNow);

    private static double Median(IEnumerable<double> values)
    {
        var v = values.Order().ToList();
        return v.Count == 0 ? 0 : v[v.Count / 2];
    }

    private static string Line(Row r)
    {
        string M(Metrics? m) => m == null ? "-" : $"{m.Instructions,6} ({100.0 * m.Instructions / r.Original.Instructions,4:0}%) {m.Switches,3} sw {m.ModuleTypeCalls,4} mod {m.DelegateInvokes,3} inv";
        var removed = r.Removed is { } x ? $"{x,5:0.0}% back" : "      -   ";
        return $"{r.Sample,-13} {r.Option,-44} s{r.Seed} {r.Seconds,5:0.0}s {r.Outcome,-9} processed {M(r.Processed)} | simplified {M(r.Simplified)} | {removed} | {r.Changed,3} changed | {r.Fallbacks}";
    }

    private static string Report(IReadOnlyList<Row> rows, List<string> samples, List<string> options)
    {
        var sb = new StringBuilder();
        foreach (var g in rows.GroupBy(r => r.Sample))
            sb.AppendLine($"{g.Key}: original {g.First().Original.Instructions} instructions, {g.First().Original.Switches} switches");
        if (!Recheck) foreach (var (name, _, why) in Skipped) sb.AppendLine($"skipped option {name}: {why}");
        foreach (var r in rows) sb.AppendLine(Line(r));
        sb.AppendLine().Append(Coverage(rows, samples, options));
        return sb.ToString();
    }

    /// <summary>Option by sample: seeds whose simplified build behaved the same and the least taken back; "tool"/"proc" not counted, "DIFF"/"ENGINE" failures.</summary>
    private static string Coverage(IReadOnlyList<Row> rows, List<string> samples, List<string> options)
    {
        string Cell(List<Row> runs)
        {
            if (runs.Count == 0) return "";
            if (runs.Any(r => r.Outcome == "DIFFERS")) return "DIFF";
            if (runs.Any(r => r.Outcome == "engine problem")) return "ENGINE";
            var same = runs.Where(r => r.Outcome == "same").ToList();
            if (same.Count == 0) return runs.All(r => r.Outcome.StartsWith("tool failed", StringComparison.Ordinal)) ? "tool" : "proc";
            var back = same.Where(r => r.Removed != null).Select(r => r.Removed!.Value).ToList();
            return $"{same.Count}/{runs.Count}" + (back.Count > 0 ? $" {back.Min():0}%" : "");
        }
        var sb = new StringBuilder("Coverage (seeds behaving the same / runs, least taken back):\n\n");
        sb.Append("| Option | ").Append(string.Join(" | ", samples)).Append(" |\n|---|").Append(string.Concat(samples.Select(_ => "---|"))).Append('\n');
        foreach (var option in options)
            sb.Append($"| {option} | ").Append(string.Join(" | ", samples.Select(s => Cell(rows.Where(r => r.Option == option && r.Sample == s).ToList())))).Append(" |\n");
        return sb.ToString();
    }

    private static string Diff(string expected, string actual)
    {
        var a = expected.Split('\n');
        var b = actual.Split('\n');
        var lines = new List<string>();
        for (int i = 0; i < Math.Max(a.Length, b.Length) && lines.Count < 8; i++)
        {
            var x = i < a.Length ? a[i] : "<none>";
            var y = i < b.Length ? b[i] : "<none>";
            if (x != y) lines.Add($"  expected: {x}\n  actual:   {y}");
        }
        return string.Join("\n", lines);
    }
}
