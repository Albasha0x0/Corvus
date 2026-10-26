using Corvus.DocsSite;

namespace Corvus.Tests;

/// <summary>The documentation site release.yml attaches: every tracked page written, every link between them resolved.</summary>
public sealed class DocsSiteTests
{
    [Fact]
    public void Every_tracked_page_is_written_and_every_link_and_heading_resolves()
    {
        using var dir = new TempDir();
        var report = Site.Build(DocsTests.RepoRoot(), dir.Path, "https://example.org/corvus/blob/v0.0.0");
        Assert.Empty(report.Broken);
        Assert.Contains(report.Pages, p => p is { Source: "README.md", Output: "index.html" });
        Assert.Contains(report.Pages, p => p is { Source: "docs/tools.md", Output: "docs/tools.html" });
        foreach (var page in report.Pages) Assert.True(File.Exists(Path.Combine(dir.Path, page.Output)), page.Output);
        Assert.DoesNotContain(".md\"", File.ReadAllText(Path.Combine(dir.Path, "docs", "features.html")), StringComparison.Ordinal);
    }

    // A folder outside any git work tree, so the build lists its files by walking it.
    [Fact]
    public void A_link_to_a_missing_file_or_heading_is_reported_and_other_files_point_at_the_source()
    {
        using var repo = new TempDir();
        using var site = new TempDir();
        Directory.CreateDirectory(repo.File("docs"));
        File.WriteAllText(repo.File("LICENSE"), "terms");
        File.WriteAllText(repo.File("docs/data.json"), "{}");
        File.WriteAllText(repo.File("README.md"),
            "# Start\n\n[a](docs/a.md#there) [b](docs/a.md#nowhere) [c](docs/missing.md) [d](LICENSE) [e](docs/data.json) [f](#start)\n");
        File.WriteAllText(repo.File("docs/a.md"), "# A page\n\n## There\n\n[back](../README.md)\n");

        var report = Site.Build(repo.Path, site.Path, "https://example.org/corvus/blob/v1");
        Assert.Equal(["README.md: docs/missing.md", "README.md: docs/a.md#nowhere"], report.Broken);
        Assert.Equal(["docs/data.json"], report.Copied);
        Assert.Equal(["A page", "Start"], report.Pages.Select(p => p.Title).Order(StringComparer.Ordinal));
        var index = File.ReadAllText(site.File("index.html"));
        Assert.Contains("href=\"docs/a.html#there\"", index, StringComparison.Ordinal);
        Assert.Contains("href=\"https://example.org/corvus/blob/v1/LICENSE\"", index, StringComparison.Ordinal);
        Assert.Contains("href=\"docs/data.json\"", index, StringComparison.Ordinal);
        Assert.Contains("href=\"../index.html\"", File.ReadAllText(site.File("docs/a.html")), StringComparison.Ordinal);
        Assert.True(File.Exists(site.File("docs/data.json")));
    }
}
