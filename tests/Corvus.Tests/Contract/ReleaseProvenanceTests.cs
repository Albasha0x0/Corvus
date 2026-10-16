using System.Text.RegularExpressions;

namespace Corvus.Tests;

/// <summary>release.yml pins every action by commit SHA and attests the release: build provenance for every asset and a CycloneDX SBOM.</summary>
public partial class ReleaseProvenanceTests
{
    private static readonly string Workflow = File.ReadAllText(Path.Combine(DocsTests.RepoRoot(), ".github", "workflows", "release.yml"));

    // A tag can be moved; a 40-digit commit SHA cannot. The comment names the version the SHA was taken from.
    [GeneratedRegex(@"^\s*(?:-\s+)?uses:\s*(\S+)(.*)$", RegexOptions.Multiline)]
    private static partial Regex Uses();

    [GeneratedRegex(@"^[\w.-]+/[\w./-]+@[0-9a-f]{40}$")]
    private static partial Regex Pinned();

    [GeneratedRegex(@"^\s*# v\d+\.\d+\.\d+\s*$")]
    private static partial Regex VersionComment();

    [Fact]
    public void EveryActionIsPinnedByCommitSha()
    {
        var uses = Uses().Matches(Workflow).ToList();
        Assert.NotEmpty(uses);
        var unpinned = uses.Where(u => !Pinned().IsMatch(u.Groups[1].Value) || !VersionComment().IsMatch(u.Groups[2].Value.TrimEnd('\r')))
            .Select(u => u.Value.Trim()).ToList();
        Assert.True(unpinned.Count == 0, "pin by commit SHA with '# vX.Y.Z' after it:\n" + string.Join("\n", unpinned));
        // One action, one SHA: two pins of the same action at different commits would be a missed update.
        var bySha = uses.Select(u => u.Groups[1].Value.Split('@')).GroupBy(p => p[0]).Where(g => g.Select(p => p[1]).Distinct().Count() > 1).Select(g => g.Key);
        Assert.Empty(bySha);
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
        Assert.True(At("sha256sum corvus-*") < At("uses: actions/attest@"));
        Assert.True(At("uses: actions/attest@") < At("uses: softprops/action-gh-release@"));
        var provenance = release[At("uses: actions/attest@")..At("sbom-path:")];
        foreach (var subject in new[] { "corvus-*", "CorvusRE.*.nupkg", "SHA256SUMS" })
            Assert.Contains(subject, provenance, StringComparison.Ordinal);
    }
}
