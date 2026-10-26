using System.Text.RegularExpressions;

namespace Corvus.Tests;

/// <summary>Every workflow pins its actions by commit SHA and is read-only by default; release.yml attests the release: build provenance for every asset and a CycloneDX SBOM.</summary>
public partial class ReleaseProvenanceTests
{
    private static readonly string Workflow = File.ReadAllText(Path.Combine(DocsTests.RepoRoot(), ".github", "workflows", "release.yml"));

    // Workflows and the repository's own composite actions.
    private static IEnumerable<(string Name, string Text)> GitHubFiles() =>
        Directory.EnumerateFiles(Path.Combine(DocsTests.RepoRoot(), ".github"), "*.yml", SearchOption.AllDirectories)
            .Order(StringComparer.Ordinal)
            .Select(f => (Path.GetRelativePath(DocsTests.RepoRoot(), f).Replace('\\', '/'), File.ReadAllText(f)));

    // A tag can be moved; a 40-digit commit SHA cannot. The comment names the version the SHA was taken from.
    [GeneratedRegex(@"^\s*(?:-\s+)?uses:\s*(\S+)(.*)$", RegexOptions.Multiline)]
    private static partial Regex Uses();

    [GeneratedRegex(@"^[\w.-]+/[\w./-]+@[0-9a-f]{40}$")]
    private static partial Regex Pinned();

    [GeneratedRegex(@"^\s*# v\d+\.\d+\.\d+\s*$")]
    private static partial Regex VersionComment();

    // Regression: ci.yml pinned actions by tag, the pattern the March 2026 trivy-action tag rewrite exploited.
    [Fact]
    public void EveryActionIsPinnedByCommitSha()
    {
        var uses = GitHubFiles().SelectMany(f => Uses().Matches(f.Text).Select(u => (f.Name, Match: u)))
            .Where(u => !u.Match.Groups[1].Value.StartsWith("./", StringComparison.Ordinal)).ToList();
        Assert.Contains(uses, u => u.Name.EndsWith("ci.yml", StringComparison.Ordinal));
        var unpinned = uses.Where(u => !Pinned().IsMatch(u.Match.Groups[1].Value) || !VersionComment().IsMatch(u.Match.Groups[2].Value.TrimEnd('\r')))
            .Select(u => $"{u.Name}: {u.Match.Value.Trim()}").ToList();
        Assert.True(unpinned.Count == 0, "pin by commit SHA with '# vX.Y.Z' after it:\n" + string.Join("\n", unpinned));
        // One action, one SHA: two pins of the same action at different commits would be a missed update. Actions in
        // one repository (actions/cache, actions/cache/restore) share its commit.
        var bySha = uses.Select(u => u.Match.Groups[1].Value.Split('@')).GroupBy(p => string.Join('/', p[0].Split('/').Take(2)))
            .Where(g => g.Select(p => p[1]).Distinct().Count() > 1).Select(g => g.Key);
        Assert.Empty(bySha);
    }

    [Fact]
    public void Every_workflow_is_read_only_unless_a_job_asks_for_more()
    {
        foreach (var (name, text) in GitHubFiles().Where(f => f.Name.StartsWith(".github/workflows/", StringComparison.Ordinal)))
            Assert.True(Regex.IsMatch(text, @"^permissions:\r?\n  contents: read\r?\n", RegexOptions.Multiline), $"{name}: no top-level 'permissions: contents: read'");
    }

    [Fact]
    public void ReleaseAssetsCarryProvenanceAndAnSbom()
    {
        var release = Workflow[Workflow.IndexOf("\n  release:", StringComparison.Ordinal)..Workflow.IndexOf("\n  publish:", StringComparison.Ordinal)];
        foreach (var permission in new[] { "id-token: write", "attestations: write", "artifact-metadata: write", "contents: write" })
            Assert.Contains(permission, release, StringComparison.Ordinal);
        Assert.Equal(2, Regex.Count(release, @"uses: actions/attest@"));
        Assert.Contains("dotnet-CycloneDX\" src/Corvus/Corvus.csproj", release, StringComparison.Ordinal);
        Assert.Contains("sbom-path: corvus-sbom.cdx.json", release, StringComparison.Ordinal);
        // Order: the SBOM is listed in SHA256SUMS, provenance covers SHA256SUMS, and the release attaches all of them.
        int At(string text) => release.IndexOf(text, StringComparison.Ordinal);
        Assert.True(At("-fn corvus-sbom.cdx.json") < At("sha256sum corvus-*"));
        // The test summary is listed and attested like the SBOM: corvus-* covers both.
        Assert.True(At("cp release/tests.json corvus-tests.json") is > 0 and var copied && copied < At("sha256sum corvus-*"));
        // The docs site is listed and has provenance like them, but the SBOM does not describe it.
        Assert.True(At("\"$GITHUB_WORKSPACE/corvus-docs.zip\"") is > 0 and var site && site < At("sha256sum corvus-*"));
        Assert.DoesNotContain("corvus-*.zip", release[release.LastIndexOf("uses: actions/attest@", StringComparison.Ordinal)..At("sbom-path:")], StringComparison.Ordinal);
        Assert.True(At("sha256sum corvus-*") < At("uses: actions/attest@"));
        Assert.True(At("uses: actions/attest@") < At("uses: softprops/action-gh-release@"));
        var provenance = release[At("uses: actions/attest@")..At("sbom-path:")];
        foreach (var subject in new[] { "corvus-*", "CorvusRE.*.nupkg", "SHA256SUMS" })
            Assert.Contains(subject, provenance, StringComparison.Ordinal);
    }
}
