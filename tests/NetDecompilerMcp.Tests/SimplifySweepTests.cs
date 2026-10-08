using System.Globalization;
using System.Text;
using Xunit.Abstractions;

namespace NetDecompilerMcp.Tests;

/// <summary>
/// simplify_methods over real assemblies from several toolchains: .NET Framework reference and runtime libraries (C#,
/// VB.NET, mixed-mode C++/CLI), ReadyToRun shared-framework libraries of several .NET versions, F#, and NuGet packages
/// built by different compilers and IL weavers. Assemblies are found on this machine and skipped when absent;
/// NDM_SWEEP=full adds the largest ones.
/// </summary>
[Collection(SweepCollection.Name)]
public sealed class SimplifySweepTests(ITestOutputHelper output)
{
    [SweepFact]
    public void LibrariesSimplifyWithoutCrashesAndRoundTrip()
    {
        var rows = new List<(SweepCatalog.Entry Entry, SimplifyHarness.Outcome? Outcome)>();
        foreach (var entry in SweepCatalog.Entries(SweepCatalog.Full))
            rows.Add((entry, entry.Path == null ? null : SimplifyHarness.Run(entry.Path)));

        output.WriteLine(Table(rows));
        var ran = rows.Where(r => r.Outcome != null).ToList();
        Assert.NotEmpty(ran);

        var problems = ran.SelectMany(r => r.Outcome!.Problems.Take(10).Select(p => $"{r.Entry.Origin} {r.Entry.Name}: {p}")).ToList();
        Assert.True(problems.Count == 0, "simplify sweep problems:\n" + string.Join("\n", problems));
    }

    private static string Table(List<(SweepCatalog.Entry Entry, SimplifyHarness.Outcome? Outcome)> rows)
    {
        var sb = new StringBuilder();
        sb.AppendLine("| Origin | Assembly | Methods | Simplified | Folded | Const. branches | Dispatchers | Fallbacks | Engine ms | ms/method | Slowest method | Status |");
        sb.AppendLine("|---|---|---:|---:|---:|---:|---:|---|---:|---:|---|---|");
        foreach (var (entry, o) in rows)
        {
            if (o == null)
            {
                sb.AppendLine($"| {entry.Origin} | {entry.Name} | | | | | | | | | | skipped: not found |");
                continue;
            }
            var changed = o.Changes.Where(c => c.Changed).ToList();
            var fallbacks = string.Join(", ", o.Fallbacks().OrderByDescending(f => f.Value).Select(f => $"{f.Key} {f.Value}"));
            double ms = o.Elapsed.TotalMilliseconds;
            sb.AppendLine(string.Create(CultureInfo.InvariantCulture,
                $"| {entry.Origin} | {entry.Name} | {o.Methods:N0} | {o.Changed:N0} | {changed.Sum(c => c.Folded.Count):N0} | " +
                $"{changed.Sum(c => c.ConstantBranches):N0} | {changed.Sum(c => c.Dispatchers):N0} | {fallbacks} | {ms:N0} | " +
                $"{ms / Math.Max(o.Methods, 1):0.000} | {o.Slowest.Method} {o.Slowest.Time.TotalMilliseconds:0} ms | " +
                $"{(o.Problems.Count == 0 ? "ok" : $"{o.Problems.Count} problem(s)")}" +
                $"{(o.InvalidOriginalsReencoded > 0 ? $" ({o.InvalidOriginalsReencoded:N0} invalid original bodies re-encoded by the writer)" : "")} |"));
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
    /// <param name="Large">Only with NDM_SWEEP=full.</param>
    public sealed record Entry(string Origin, string Name, string? Path, bool Large = false);

    public static bool Full => string.Equals(Environment.GetEnvironmentVariable("NDM_SWEEP"), "full", StringComparison.OrdinalIgnoreCase);

    public static IEnumerable<Entry> Entries(bool full) => All().Where(e => full || !e.Large);

    private static IEnumerable<Entry> All()
    {
        // .NET Framework 4.x: reference assemblies, and the runtime's own libraries (C#, VB.NET, C++/CLI).
        var refs = ProgramFilesX86("Reference Assemblies", "Microsoft", "Framework", ".NETFramework", "v4.8");
        yield return new("netfx 4.8 reference", "mscorlib", File(refs, "mscorlib.dll"));
        yield return new("netfx 4.8 reference", "System.Xml", File(refs, "System.Xml.dll"));
        var netfx = WindowsDir("Microsoft.NET", "Framework64", "v4.0.30319");
        yield return new("netfx 4.x runtime", "System.Core", File(netfx, "System.Core.dll"));
        yield return new("netfx 4.x runtime (VB.NET)", "Microsoft.VisualBasic", File(netfx, "Microsoft.VisualBasic.dll"));
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
        yield return new("F# (newest SDK)", "FSharp.Core", Sdk(newest: true, "FSharp", "FSharp.Core.dll"));
        yield return new("F# (oldest SDK)", "FSharp.Core", Sdk(newest: false, "FSharp", "FSharp.Core.dll"));

        // VB.NET (Roslyn's VB compiler is written in VB.NET).
        yield return new("VB.NET (NuGet)", "Microsoft.CodeAnalysis.VisualBasic", NuGet("microsoft.codeanalysis.visualbasic", "Microsoft.CodeAnalysis.VisualBasic.dll"), Large: true);

        // NuGet packages from different eras, compilers and post-processors.
        yield return new("NuGet (net20 era C#)", "Newtonsoft.Json 12", NuGet("newtonsoft.json", "Newtonsoft.Json.dll", version: "12.0.2", framework: "net20"));
        yield return new("NuGet (netstandard C#)", "Newtonsoft.Json 13", NuGet("newtonsoft.json", "Newtonsoft.Json.dll", version: "13.0.4", framework: "netstandard2.0"));
        yield return new("NuGet", "DotNetZip", NuGet("dotnetzip.original", "Ionic.Zip.dll"));
        yield return new("NuGet (Fody weaver)", "Costura", NuGet("costura.fody", "Costura.dll"));
        yield return new("NuGet (generated decoder tables)", "Iced", NuGet("iced", "Iced.dll"));
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
