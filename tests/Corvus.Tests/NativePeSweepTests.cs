using System.Collections.Concurrent;
using System.Diagnostics;
using System.Text;
using Corvus.Core;
using Corvus.Native;
using Corvus.Native.Pe;
using Xunit.Abstractions;

namespace Corvus.Tests;

/// <summary>
/// The native PE parser over every PE file under System32 and SysWOW64: no exception, no internal error, bounded time,
/// and agreement with System.Reflection.PortableExecutable (headers, sections), AsmResolver.PE (imports, exports,
/// relocations, TLS, .pdata, CodeView, resources) and dumpbin (imports incl. delay-load, exports, load config).
/// CORVUS_PE_SWEEP_LIMIT caps the file count; CORVUS_PE_SWEEP_REPORT names a file for the full report.
/// </summary>
[Collection(SweepCollection.Name)]
public sealed class NativePeSweepTests(ITestOutputHelper output)
{
    [WindowsFact]
    [Trait("Speed", "Slow")]
    public void System32AndSysWow64AgreeWithOracles()
    {
        int limit = int.TryParse(Environment.GetEnvironmentVariable("CORVUS_PE_SWEEP_LIMIT"), out int l) ? l : int.MaxValue;
        var files = PeCorpus.Files().Take(limit).ToList();
        var failures = new ConcurrentBag<string>();
        var diffs = new ConcurrentBag<string>();
        var oracleGaps = new ConcurrentBag<string>();
        var parsed = new ConcurrentBag<string>();
        var issueAreas = new ConcurrentDictionary<string, int>();
        var issueSamples = new ConcurrentDictionary<string, ConcurrentQueue<string>>();
        int notPe = 0, unreadable = 0;
        var slowest = new ConcurrentBag<(double Ms, string Path)>();
        var clock = Stopwatch.StartNew();

        Parallel.ForEach(files, new ParallelOptions { MaxDegreeOfParallelism = Environment.ProcessorCount }, path =>
        {
            byte[] bytes;
            try { bytes = File.ReadAllBytes(path); }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { Interlocked.Increment(ref unreadable); return; }
            var timer = Stopwatch.StartNew();
            PeFile pe;
            try { pe = PeFile.FromBytes(bytes, path); }
            catch (ToolError e) when (e.Code == ErrorCode.MalformedInput) { Interlocked.Increment(ref notPe); return; }
            catch (Exception ex) { failures.Add($"{path}: construction threw {ex}"); return; }
            try
            {
                var issues = NativePeTests.TouchEverything(pe);
                // Parser bugs, and hard limits hit by real files (the limits are meant for hostile input only).
                foreach (var i in issues.Where(i => i.Message.StartsWith("internal error", StringComparison.Ordinal)
                    || i.Message.Contains("are read", StringComparison.Ordinal) || i.Message.Contains("not read", StringComparison.Ordinal)))
                    failures.Add($"{path}: {i.Area}: {i.Message}");
                foreach (var area in issues.Select(i => i.Area).Distinct()) issueAreas.AddOrUpdate(area, 1, (_, n) => n + 1);
                foreach (var i in issues)
                {
                    var samples = issueSamples.GetOrAdd(i.Area, _ => new ConcurrentQueue<string>());
                    if (samples.Count < 8) samples.Enqueue($"{path}: {i.Message}");
                }
            }
            catch (Exception ex) { failures.Add($"{path}: access threw {ex}"); return; }
            slowest.Add((timer.Elapsed.TotalMilliseconds, path));
            parsed.Add(path);

            foreach (var d in PeOracles.CompareWithWindows(pe, bytes, path)) diffs.Add($"{path}: {d}");
            if (PeOracles.CompareWithPeReader(pe, bytes) is { } h) foreach (var d in h) diffs.Add($"{path}: {d}");
            else oracleGaps.Add($"{path}: PEReader rejected the file");
            if (PeOracles.CompareWithAsmResolver(pe, bytes) is { } a)
                foreach (var d in a)
                    (d.StartsWith("oracle-failed", StringComparison.Ordinal) ? oracleGaps : diffs).Add($"{path}: {d}");
            else oracleGaps.Add($"{path}: AsmResolver rejected the file");
        });
        var parseTime = clock.Elapsed;

        int dumpbinFiles = 0;
        if (Dumpbin.Path != null)
        {
            var batches = parsed.Order(StringComparer.OrdinalIgnoreCase).Chunk(40).ToList();
            Parallel.ForEach(batches, new ParallelOptions { MaxDegreeOfParallelism = Math.Max(1, Environment.ProcessorCount / 2) }, batch =>
            {
                var results = Dumpbin.Run(batch, loadConfig: true);
                foreach (var path in batch)
                {
                    if (!results.TryGetValue(path, out var r)) { oracleGaps.Add($"{path}: no dumpbin output"); continue; }
                    Interlocked.Increment(ref dumpbinFiles);
                    var pe = PeFile.FromBytes(File.ReadAllBytes(path), path);
                    foreach (var d in PeOracles.CompareWithDumpbin(pe, r)) diffs.Add($"{path}: {d}");
                }
            });
        }

        var report = new StringBuilder();
        report.AppendLine($"candidates {files.Count}, parsed {parsed.Count}, not PE {notPe}, unreadable {unreadable}, dumpbin compared {dumpbinFiles} ({(Dumpbin.Path == null ? "dumpbin not found" : Dumpbin.Path)})");
        report.AppendLine($"parse + PEReader + AsmResolver {parseTime.TotalSeconds:0.0} s, total {clock.Elapsed.TotalSeconds:0.0} s");
        foreach (var (ms, path) in slowest.OrderByDescending(s => s.Ms).Take(5)) report.AppendLine($"  slow: {ms:0} ms {path}");
        report.AppendLine($"files with issues, by area: {string.Join(", ", issueAreas.OrderByDescending(a => a.Value).Select(a => $"{a.Key} {a.Value}"))}");
        foreach (var (area, samples) in issueSamples.OrderBy(s => s.Key))
            foreach (var sample in samples) report.AppendLine($"  issue {area}: {sample}");
        report.AppendLine($"failures {failures.Count}, disagreements {diffs.Count}, oracle gaps {oracleGaps.Count}");
        foreach (var group in diffs.GroupBy(d => Area(d)).OrderByDescending(g => g.Count()))
            report.AppendLine($"  {group.Key}: {group.Count()}");
        foreach (var f in failures.Take(50)) report.AppendLine("FAIL " + f);
        foreach (var d in diffs.Order().Take(300)) report.AppendLine("DIFF " + d);
        foreach (var g in oracleGaps.Order().Take(100)) report.AppendLine("GAP  " + g);
        if (Environment.GetEnvironmentVariable("CORVUS_PE_SWEEP_REPORT") is { Length: > 0 } reportPath)
            File.WriteAllText(reportPath, report + string.Join("\n", diffs.Order().Select(d => "DIFF " + d)) + "\n" + string.Join("\n", oracleGaps.Order().Select(g => "GAP  " + g)));
        output.WriteLine(report.ToString());

        Assert.True(parsed.Count >= Math.Min(limit, 1000), $"only {parsed.Count} PE files parsed\n{report}");
        Assert.Empty(failures);
        Assert.Empty(diffs);
    }

    private static string Area(string diff)
    {
        var parts = diff.Split(": ");
        return parts.Length >= 2 ? parts[1] : diff;
    }
}

/// <summary>Native PE files of this Windows installation.</summary>
internal static class PeCorpus
{
    /// <summary>Every file under System32 and SysWOW64 (recursively) that starts with "MZ", in a stable order.</summary>
    public static IEnumerable<string> Files()
    {
        if (!OperatingSystem.IsWindows()) yield break;
        var windows = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        var options = new EnumerationOptions { RecurseSubdirectories = true, IgnoreInaccessible = true, AttributesToSkip = FileAttributes.ReparsePoint };
        foreach (var root in new[] { "System32", "SysWOW64" })
        {
            var dir = Path.Combine(windows, root);
            if (!Directory.Exists(dir)) continue;
            foreach (var file in Directory.EnumerateFiles(dir, "*", options).Order(StringComparer.OrdinalIgnoreCase))
                if (StartsWithMz(file)) yield return file;
        }
    }

    /// <summary>Well-known System32 images by name, when present.</summary>
    public static string? System32(string name)
    {
        if (!OperatingSystem.IsWindows()) return null;
        var path = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), name);
        return File.Exists(path) ? path : null;
    }

    private static bool StartsWithMz(string path)
    {
        try
        {
            using var f = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete, 1, FileOptions.None);
            if (f.Length < 64 || f.Length > PeLimits.MaxFileSize) return false;
            Span<byte> head = stackalloc byte[2];
            return f.Read(head) == 2 && head[0] == 'M' && head[1] == 'Z';
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { return false; }
    }
}

/// <summary>A fact that runs only on Windows (by default: it reads the Windows installation's own images).</summary>
public sealed class WindowsFactAttribute : FactAttribute
{
    public WindowsFactAttribute(string reason = "Needs the PE files of a Windows installation.")
    {
        if (!OperatingSystem.IsWindows()) Skip = reason;
    }
}

/// <summary>A theory that runs only on Windows (by default: it reads the Windows installation's own images).</summary>
public sealed class WindowsTheoryAttribute : TheoryAttribute
{
    public WindowsTheoryAttribute(string reason = "Needs the PE files of a Windows installation.")
    {
        if (!OperatingSystem.IsWindows()) Skip = reason;
    }
}
