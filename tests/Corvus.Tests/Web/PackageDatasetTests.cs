using System.Collections.Concurrent;
using System.Text;
using System.Text.RegularExpressions;
using Corvus.Services.Web.Packages;
using Xunit.Abstractions;

namespace Corvus.Tests;

/// <summary>Package review on real package folders (CORVUS_PACKAGES_BAD, CORVUS_PACKAGES_GOOD): noteworthy share per subfolder.</summary>
public sealed class PackageDatasetTests(ITestOutputHelper output)
{
    /// <summary>Floors: known-bad noteworthy at least this often (measured 604 of 846; the goal is 0.90), ordinary ones at most this often.</summary>
    private const double Flagged = 0.71, FalsePositives = 0.05;

    [Trait("Speed", "Slow")]
    [RequiresRealDataFact("CORVUS_PACKAGES_BAD", "CORVUS_PACKAGES_GOOD")]
    public void Known_bad_packages_are_noteworthy_and_ordinary_ones_are_not()
    {
        var report = new StringBuilder();
        var bad = Measure(RealData.Path("CORVUS_PACKAGES_BAD"), "bad", report);
        var good = Measure(RealData.Path("CORVUS_PACKAGES_GOOD"), "good", report);
        if (RealData.Get("CORVUS_PACKAGES_REPORT") is { } path) File.WriteAllText(path, report.ToString());
        output.WriteLine($"known-bad noteworthy: {bad.Noteworthy} of {bad.Read} ({100.0 * bad.Noteworthy / bad.Read:F1}%); ordinary noteworthy: {good.Noteworthy} of {good.Read} ({100.0 * good.Noteworthy / good.Read:F1}%)");
        Assert.True(bad.Noteworthy >= bad.Read * Flagged && good.Noteworthy <= good.Read * FalsePositives, "below the floor");
    }

    private (int Read, int Noteworthy) Measure(string root, string set, StringBuilder report)
    {
        var rows = new ConcurrentBag<(string Group, string File, string Review, string Findings)>();
        var files = Directory.EnumerateFiles(root, "*", SearchOption.AllDirectories).ToList();
        Parallel.ForEach(files, new ParallelOptions { MaxDegreeOfParallelism = Math.Max(1, Environment.ProcessorCount / 2) }, file =>
        {
            var group = Path.GetRelativePath(root, Path.GetDirectoryName(file)!).Replace('\\', '/');
            PackageReport? r;
            try { r = PackageReview.Review(file, default); }
            catch (Exception ex) { rows.Add((group, Path.GetFileName(file), "error", ex.GetType().Name + ": " + ex.Message)); return; }
            var findings = r?.Findings.Select(f => $"{(f.Level == "noteworthy" ? "!" : "")}{f.Category}: {f.Detail}").Distinct() ?? [];
            rows.Add((group, Path.GetFileName(file), r?.Review ?? "unread", Regex.Replace(string.Join(" | ", findings), @"[\t\r\n]+", " ")));
        });
        foreach (var g in rows.GroupBy(r => r.Group).OrderBy(g => g.Key, StringComparer.Ordinal))
        {
            int read = g.Count(r => r.Review is not ("unread" or "error")), noteworthy = g.Count(r => r.Review == "noteworthy");
            output.WriteLine($"{set} {g.Key}: {noteworthy} of {read} noteworthy ({(read == 0 ? 0 : 100.0 * noteworthy / read):F1}%), {g.Count() - read} unread");
        }
        foreach (var r in rows.OrderBy(r => r.Group, StringComparer.Ordinal).ThenBy(r => r.File, StringComparer.Ordinal))
            report.AppendLine($"{set}\t{r.Group}\t{r.File}\t{r.Review}\t{r.Findings}");
        return (rows.Count(r => r.Review is not ("unread" or "error")), rows.Count(r => r.Review == "noteworthy"));
    }
}
