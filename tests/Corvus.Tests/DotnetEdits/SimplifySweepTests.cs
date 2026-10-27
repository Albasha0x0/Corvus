using System.Globalization;
using System.Text;
using Xunit.Abstractions;

namespace Corvus.Tests;

/// <summary>simplify_methods over real assemblies found on this machine, skipped when absent; CORVUS_SWEEP=full adds the largest.</summary>
[Trait("Speed", "Slow")]
public sealed class SimplifySweepTests(ITestOutputHelper output)
{
    /// <summary>Baseline whole-library time per method: 0.6 ms (measured ~0.3 ms when the guard was written).</summary>
    private const double BaselineMsPerMethod = 0.6;

    /// <summary>How far above the baseline a sweep may run; a regression shows as an order of magnitude. CORVUS_PERF_FACTOR overrides it.</summary>
    private static double PerfFactor =>
        double.TryParse(Environment.GetEnvironmentVariable("CORVUS_PERF_FACTOR"), NumberStyles.Float, CultureInfo.InvariantCulture, out var f) ? f : 5;

    /// <summary>Assemblies smaller than this have too few methods for a stable per-method time on their own.</summary>
    private const int PerfMinMethods = 2_000;

    [SweepFact]
    [Trait(PerfBudget.Trait, PerfBudget.Timing)]
    public void Libraries_simplify_without_crashes_and_round_trip()
    {
        var rows = new List<(SweepCatalog.Entry Entry, SimplifyHarness.Outcome? Outcome)>();
        foreach (var entry in SweepCatalog.Entries(SweepCatalog.Full))
            rows.Add((entry, entry.Path == null ? null : SimplifyHarness.Run(entry.Path)));

        output.WriteLine(Table(rows));
        var ran = rows.Where(r => r.Outcome != null).ToList();
        Assert.NotEmpty(ran);

        var problems = ran.SelectMany(r => r.Outcome!.Problems.Take(10).Select(p => $"{r.Entry.Origin} {r.Entry.Name}: {p}")).ToList();
        Assert.True(problems.Count == 0, "simplify sweep problems:\n" + string.Join("\n", problems));

        // Performance guard over the whole sweep, and for each assembly large enough to time on its own.
        int methods = ran.Sum(r => r.Outcome!.Methods);
        double total = ran.Sum(r => r.Outcome!.Total.TotalMilliseconds);
        double engine = ran.Sum(r => r.Outcome!.Elapsed.TotalMilliseconds);
        double allowed = BaselineMsPerMethod * PerfFactor;
        output.WriteLine($"Whole-library time: {total / methods:0.000} ms/method over {methods:N0} methods (engine alone {engine / methods:0.000} ms); " +
                         $"baseline {BaselineMsPerMethod} ms, limit {allowed:0.0} ms (CORVUS_PERF_FACTOR={PerfFactor})");
        PerfBudget.AtMost("dotnet/simplify-sweep", total / methods, allowed, "ms/method", output);
        var slowest = ran.Where(r => r.Outcome!.Methods >= PerfMinMethods).MaxBy(r => r.Outcome!.Total.TotalMilliseconds / r.Outcome.Methods);
        if (slowest.Outcome is { } o)
            PerfBudget.AtMost("dotnet/simplify-sweep-slowest-library", o.Total.TotalMilliseconds / o.Methods, allowed * 2, "ms/method", output,
                $"{slowest.Entry.Origin} {slowest.Entry.Name}, slowest method {o.Slowest.Method}, {o.Slowest.Time.TotalMilliseconds:0} ms");
    }

    [SweepFact]
    public void Repeated_runs_produce_identical_images()
    {
        var entries = SweepCatalog.Entries(full: false).Where(e => e.Path != null && e.Determinism).ToList();
        Assert.NotEmpty(entries);
        // Nothing here is timed, and methods take far less than the per-method limit.
        var results = new string?[entries.Count];
        Parallel.For(0, entries.Count, i =>
        {
            var entry = entries[i];
            SimplifyHarness.Outcome first = null!, second = null!;
            Parallel.Invoke(() => first = SimplifyHarness.Run(entry.Path!), () => second = SimplifyHarness.Run(entry.Path!));
            var problems = first.Problems.Concat(second.Problems).ToList();
            var differing = problems.Count > 0 ? [] : DeterminismFailures(first, second);
            results[i] = problems.Count > 0 ? $"{entry.Origin} {entry.Name}: {string.Join("; ", problems.Take(5))}"
                : differing.Count > 0 ? $"{entry.Origin} {entry.Name}: repeated runs differ in {string.Join(", ", differing.Take(10))}"
                : null;
            if (results[i] == null) lock (output) output.WriteLine($"{entry.Origin} {entry.Name}: {first.Image!.Length:N0} bytes, identical across runs");
        });
        var failures = results.Where(r => r != null).ToList();
        Assert.True(failures.Count == 0, string.Join("\n", failures));
    }

    /// <summary>Methods that differ between two runs' images; only a method that hit the wall-clock limit may differ.</summary>
    internal static List<string> DeterminismFailures(SimplifyHarness.Outcome first, SimplifyHarness.Outcome second)
    {
        if (first.Image!.AsSpan().SequenceEqual(second.Image)) return [];
        var differing = SimplifyHarness.DifferingMethods(first.Image!, second.Image!);
        if (differing.Count == 0) return ["image bytes differ while every method body agrees"];
        return differing.Where(m => !first.TimedOut(m) && !second.TimedOut(m)).ToList();
    }

    private static string Table(List<(SweepCatalog.Entry Entry, SimplifyHarness.Outcome? Outcome)> rows)
    {
        var sb = new StringBuilder();
        sb.AppendLine("| Origin | Assembly | Methods | Simplified | Folded | Const. branches | Dispatchers | Fallbacks | Engine ms | Total ms | Total ms/method | Slowest method | Status |");
        sb.AppendLine("|---|---|---:|---:|---:|---:|---:|---|---:|---:|---:|---|---|");
        foreach (var (entry, o) in rows)
        {
            if (o == null)
            {
                sb.AppendLine($"| {entry.Origin} | {entry.Name} | | | | | | | | | | | skipped: not found |");
                continue;
            }
            var changed = o.Changes.Where(c => c.Changed).ToList();
            var fallbacks = string.Join(", ", o.Fallbacks().OrderByDescending(f => f.Value).Select(f => $"{f.Key} {f.Value}"));
            double ms = o.Elapsed.TotalMilliseconds, totalMs = o.Total.TotalMilliseconds;
            sb.AppendLine(string.Create(CultureInfo.InvariantCulture,
                $"| {entry.Origin} | {entry.Name} | {o.Methods:N0} | {o.Changed:N0} | {changed.Sum(c => c.Folded.Count):N0} | " +
                $"{changed.Sum(c => c.ConstantBranches):N0} | {changed.Sum(c => c.Dispatchers):N0} | {fallbacks} | {ms:N0} | {totalMs:N0} | " +
                $"{totalMs / Math.Max(o.Methods, 1):0.000} | {o.Slowest.Method} {o.Slowest.Time.TotalMilliseconds:0} ms | " +
                $"{(o.Problems.Count == 0 ? "ok" : $"{o.Problems.Count} problem(s)")} |"));
        }
        return sb.ToString();
    }
}

/// <summary>Runs only when at least one sweep assembly is present on this machine.</summary>
public sealed class SweepFactAttribute : FactAttribute
{
    public SweepFactAttribute()
    {
        if (!SweepCatalog.Entries(full: false).Any(e => e.Path != null))
            Skip = "No sweep assemblies found (NuGet cache, shared framework, .NET Framework or SDK directories).";
    }
}

/// <summary>Where the sweep assemblies come from, located on this machine.</summary>
internal static class SweepCatalog
{
    /// <param name="Determinism">Also used by the determinism guard (mid-size, varied toolchains).</param>
    /// <param name="Large">Only with CORVUS_SWEEP=full.</param>
    public sealed record Entry(string Origin, string Name, string? Path, bool Determinism = false, bool Large = false);

    public static bool Full => string.Equals(Environment.GetEnvironmentVariable("CORVUS_SWEEP"), "full", StringComparison.OrdinalIgnoreCase);

    public static IEnumerable<Entry> Entries(bool full) => All().Where(e => full || !e.Large);

    private static IEnumerable<Entry> All()
    {
        // .NET Framework 4.x: reference assemblies, and the runtime's own libraries (C#, VB.NET, C++/CLI).
        var refs = ProgramFilesX86("Reference Assemblies", "Microsoft", "Framework", ".NETFramework", "v4.8");
        yield return new("netfx 4.8 reference", "mscorlib", File(refs, "mscorlib.dll"));
        yield return new("netfx 4.8 reference", "System.Xml", File(refs, "System.Xml.dll"));
        var netfx = WindowsDir("Microsoft.NET", "Framework64", "v4.0.30319");
        yield return new("netfx 4.x runtime", "System.Core", File(netfx, "System.Core.dll"));
        yield return new("netfx 4.x runtime (VB.NET)", "Microsoft.VisualBasic", File(netfx, "Microsoft.VisualBasic.dll"), Determinism: true);
        yield return new("netfx 4.x runtime (C++/CLI mixed)", "System.Data", File(netfx, "System.Data.dll"));
        yield return new("netfx 4.x runtime", "mscorlib", File(netfx, "mscorlib.dll"), Large: true);

        // Shared framework: ReadyToRun images compiled by crossgen (3.1) and crossgen2 (6.0 and later).
        yield return new("net ReadyToRun (newest)", "System.Linq", SharedFramework(null, "System.Linq.dll"));
        yield return new("net ReadyToRun (newest)", "System.Text.RegularExpressions", SharedFramework(null, "System.Text.RegularExpressions.dll"));
        yield return new("net ReadyToRun (newest)", "System.Collections.Immutable", SharedFramework(null, "System.Collections.Immutable.dll"));
        yield return new("net ReadyToRun (newest)", "System.Private.CoreLib", SharedFramework(null, "System.Private.CoreLib.dll"), Large: true);
        yield return new("net 6.0 ReadyToRun", "System.Text.Json", SharedFramework("6.", "System.Text.Json.dll"));
        yield return new("net 3.1 ReadyToRun (crossgen1)", "System.Linq", SharedFramework("3.", "System.Linq.dll"));
        yield return new("runtime pack win-x86 ReadyToRun", "System.Linq.Expressions", RuntimePack("microsoft.netcore.app.runtime.win-x86", "System.Linq.Expressions.dll"));

        // F#.
        yield return new("F# (newest SDK)", "FSharp.Core", Sdk(newest: true, "FSharp", "FSharp.Core.dll"), Determinism: true);
        yield return new("F# (oldest SDK)", "FSharp.Core", Sdk(newest: false, "FSharp", "FSharp.Core.dll"));

        // VB.NET (Roslyn's VB compiler is written in VB.NET).
        yield return new("VB.NET (NuGet)", "Microsoft.CodeAnalysis.VisualBasic", NuGet("microsoft.codeanalysis.visualbasic", "Microsoft.CodeAnalysis.VisualBasic.dll"), Large: true);

        // NuGet packages from different eras, compilers and post-processors.
        yield return new("NuGet (net20 era C#)", "Newtonsoft.Json 12", NuGet("newtonsoft.json", "Newtonsoft.Json.dll", version: "12.0.2", framework: "net20"));
        yield return new("NuGet (netstandard C#)", "Newtonsoft.Json 13", NuGet("newtonsoft.json", "Newtonsoft.Json.dll", version: "13.0.4", framework: "netstandard2.0"), Determinism: true);
        yield return new("NuGet", "DotNetZip", NuGet("dotnetzip.original", "Ionic.Zip.dll"));
        yield return new("NuGet (Fody weaver)", "Costura", NuGet("costura.fody", "Costura.dll"));
        yield return new("NuGet (generated decoder tables)", "Iced", NuGet("iced", "Iced.dll"), Determinism: true);
        yield return new("NuGet", "NLog", NuGet("nlog", "NLog.dll", framework: "netstandard2.1"));
        yield return new("NuGet", "SharpCompress", NuGet("sharpcompress", "SharpCompress.dll"));
        yield return new("NuGet", "LiteDB", NuGet("litedb", "LiteDB.dll"));
        yield return new("NuGet (source generators)", "MessagePack", NuGet("messagepack", "MessagePack.dll"));
        yield return new("NuGet (net20 target)", "LZMA SDK", NuGet("lzma-sdk", "SevenZip.dll", framework: "net20"));
        yield return new("NuGet", "dnlib", NuGet("dnlib", "dnlib.dll"));
        yield return new("NuGet", "BouncyCastle", NuGet("bouncycastle.cryptography", "BouncyCastle.Cryptography.dll"), Large: true);
        yield return new("NuGet", "MathNet.Numerics", NuGet("mathnet.numerics", "MathNet.Numerics.dll"), Large: true);
    }

    private static string? File(string? dir, string name) => dir != null && System.IO.File.Exists(System.IO.Path.Combine(dir, name)) ? System.IO.Path.Combine(dir, name) : null;

    private static string? Existing(string path) => Directory.Exists(path) ? path : null;

    private static string? WindowsDir(params string[] parts) =>
        OperatingSystem.IsWindows() ? Existing(System.IO.Path.Combine([Environment.GetFolderPath(Environment.SpecialFolder.Windows), .. parts])) : null;

    private static string? ProgramFilesX86(params string[] parts) =>
        OperatingSystem.IsWindows() ? Existing(System.IO.Path.Combine([Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86), .. parts])) : null;

    /// <summary>The dotnet root of the running runtime (…/shared/Microsoft.NETCore.App/x.y.z/System.Private.CoreLib.dll).</summary>
    private static string? DotnetRoot()
    {
        var dir = System.IO.Path.GetDirectoryName(typeof(object).Assembly.Location);
        for (int i = 0; i < 3 && dir != null; i++) dir = System.IO.Path.GetDirectoryName(dir);
        return dir != null && Directory.Exists(System.IO.Path.Combine(dir, "shared")) ? dir : null;
    }

    /// <summary>A shared-framework library of the newest installed version starting with <paramref name="prefix"/> (any when null).</summary>
    private static string? SharedFramework(string? prefix, string file)
    {
        var root = DotnetRoot() is { } d ? Existing(System.IO.Path.Combine(d, "shared", "Microsoft.NETCore.App")) : null;
        if (root == null) return null;
        return Directory.GetDirectories(root)
            .Where(v => prefix == null || System.IO.Path.GetFileName(v).StartsWith(prefix, StringComparison.Ordinal))
            .OrderByDescending(v => Version.TryParse(System.IO.Path.GetFileName(v).Split('-')[0], out var x) ? x : new Version())
            .Select(v => File(v, file)).FirstOrDefault(p => p != null);
    }

    private static string? Sdk(bool newest, params string[] parts)
    {
        var root = DotnetRoot() is { } d ? Existing(System.IO.Path.Combine(d, "sdk")) : null;
        if (root == null) return null;
        var versions = Directory.GetDirectories(root)
            .Select(v => (Dir: v, Version: Version.TryParse(System.IO.Path.GetFileName(v).Split('-')[0], out var x) ? x : null))
            .Where(v => v.Version != null).OrderBy(v => v.Version).Select(v => v.Dir).ToList();
        var ordered = newest ? versions.AsEnumerable().Reverse() : versions;
        return ordered.Select(v => File(System.IO.Path.Combine([v, .. parts[..^1]]), parts[^1])).FirstOrDefault(p => p != null);
    }

    private static string? NuGetRoot() => Existing(Environment.GetEnvironmentVariable("NUGET_PACKAGES") is { Length: > 0 } custom
        ? custom
        : System.IO.Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".nuget", "packages"));

    /// <summary>lib/&lt;framework&gt;/file of a package: the given version and framework, or the newest version and its first framework.</summary>
    private static string? NuGet(string id, string file, string? version = null, string? framework = null)
    {
        var package = NuGetRoot() is { } r ? Existing(System.IO.Path.Combine(r, id)) : null;
        if (package == null) return null;
        var versions = version != null
            ? [System.IO.Path.Combine(package, version)]
            : Directory.GetDirectories(package).OrderByDescending(v => Version.TryParse(System.IO.Path.GetFileName(v).Split('-')[0], out var x) ? x : new Version()).ToArray();
        foreach (var v in versions)
        {
            var lib = Existing(System.IO.Path.Combine(v, "lib"));
            if (lib == null) continue;
            var frameworks = framework != null ? [System.IO.Path.Combine(lib, framework)] : Directory.GetDirectories(lib).Order(StringComparer.Ordinal).ToArray();
            if (frameworks.Select(f => File(f, file)).FirstOrDefault(p => p != null) is { } found) return found;
        }
        return null;
    }

    /// <summary>runtimes/&lt;rid&gt;/lib/&lt;framework&gt;/file of the newest runtime pack in the NuGet cache.</summary>
    private static string? RuntimePack(string id, string file)
    {
        var package = NuGetRoot() is { } r ? Existing(System.IO.Path.Combine(r, id)) : null;
        if (package == null) return null;
        return Directory.GetDirectories(package)
            .OrderByDescending(v => Version.TryParse(System.IO.Path.GetFileName(v).Split('-')[0], out var x) ? x : new Version())
            .SelectMany(v => Existing(System.IO.Path.Combine(v, "runtimes")) is { } rt ? Directory.GetDirectories(rt) : [])
            .SelectMany(rid => Existing(System.IO.Path.Combine(rid, "lib")) is { } lib ? Directory.GetDirectories(lib) : [])
            .Select(f => File(f, file)).FirstOrDefault(p => p != null);
    }
}
