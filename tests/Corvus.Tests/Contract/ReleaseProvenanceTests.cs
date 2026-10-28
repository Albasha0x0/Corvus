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
    public void Every_action_is_pinned_by_commit_SHA()
    {
        var uses = GitHubFiles().SelectMany(f => Uses().Matches(f.Text).Select(u => (f.Name, Match: u)))
            .Where(u => !u.Match.Groups[1].Value.StartsWith("./", StringComparison.Ordinal)).ToList();
        Assert.Contains(uses, u => u.Name.EndsWith("ci.yml", StringComparison.Ordinal));
        var unpinned = uses.Where(u => !Pinned().IsMatch(u.Match.Groups[1].Value) || !VersionComment().IsMatch(u.Match.Groups[2].Value.TrimEnd('\r')))
            .Select(u => $"{u.Name}: {u.Match.Value.Trim()}").ToList();
        Assert.True(unpinned.Count == 0, "pin by commit SHA with '# vX.Y.Z' after it:\n" + string.Join("\n", unpinned));
        // One SHA per action, shared within a repository; two pins of one action are a missed update.
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

    [GeneratedRegex(@"^  ([\w-]+):\s*$", RegexOptions.Multiline)]
    private static partial Regex Job();

    [GeneratedRegex(@"^\s+(?:id-token|contents|packages): write\s*$", RegexOptions.Multiline)]
    private static partial Regex WritePermission();

    // The jobs of a workflow by name, each up to the next job.
    private static IEnumerable<(string Name, string Text)> Jobs(string workflow)
    {
        var body = workflow.Replace("\r\n", "\n");
        body = body[(body.IndexOf("\njobs:\n", StringComparison.Ordinal) + 1)..];
        var starts = Job().Matches(body).ToList();
        for (int i = 0; i < starts.Count; i++)
            yield return (starts[i].Groups[1].Value, body[starts[i].Index..(i + 1 < starts.Count ? starts[i + 1].Index : body.Length)]);
    }

    [Fact]
    public void Every_job_that_writes_or_signs_runs_in_the_release_environment()
    {
        // Scorecard's token signs only its own result, on main pushes and a
        // schedule; a tag-only environment refuses those.
        var exempt = new HashSet<string> { ".github/workflows/scorecard.yml:analysis" };
        var gated = new List<string>();
        var open = new List<string>();
        foreach (var (name, text) in GitHubFiles().Where(f => f.Name.StartsWith(".github/workflows/", StringComparison.Ordinal)))
            foreach (var (job, body) in Jobs(text).Where(j => WritePermission().IsMatch(j.Text)))
            {
                var label = $"{name}:{job}";
                if (Regex.IsMatch(body, @"^    environment: release\s*$", RegexOptions.Multiline)) gated.Add(label);
                else if (!exempt.Contains(label)) open.Add(label);
            }
        Assert.True(open.Count == 0, "name 'environment: release' in:\n" + string.Join("\n", open));
        Assert.Equal(["release", "image", "publish"], gated.Where(g => g.StartsWith(".github/workflows/release.yml:", StringComparison.Ordinal)).Select(g => g.Split(':')[1]));
        // nuget.org's trusted publisher policy names the environment, so the
        // login stays in a gated job.
        var nuget = Jobs(Workflow).Single(j => j.Text.Contains("uses: NuGet/login@", StringComparison.Ordinal));
        Assert.Contains($".github/workflows/release.yml:{nuget.Name}", gated);
    }

    [Fact]
    public void A_republish_is_dispatched_from_its_tag()
    {
        var root = DocsTests.RepoRoot();
        var commands = new[] { ".github/workflows/release.yml", "release.ps1" }
            .SelectMany(f => Regex.Matches(File.ReadAllText(Path.Combine(root, f)), @"gh workflow run release\.yml[^\r\n""]*").Select(m => (f, m.Value)))
            .ToList();
        Assert.Equal(3, commands.Count);
        Assert.All(commands, c => Assert.Matches(@"--ref (vX\.Y\.Z|\$tag|\$TAG) -f tag=(vX\.Y\.Z|\$tag|\$TAG)", c.Value));
        // The tag-only environment refuses a run on a branch; the job says how
        // to dispatch it before anything runs.
        var publish = Jobs(Workflow).Single(j => j.Name == "publish").Text;
        Assert.True(publish.IndexOf("[ \"$TAG\" = \"$GITHUB_REF_NAME\" ]", StringComparison.Ordinal) is > 0 and var guard
            && guard < publish.IndexOf("uses: actions/checkout@", StringComparison.Ordinal));
    }

    [Fact]
    public void Release_assets_carry_provenance_and_an_SBOM()
    {
        var release = Workflow[Workflow.IndexOf("\n  release:", StringComparison.Ordinal)..Workflow.IndexOf("\n  image:", StringComparison.Ordinal)];
        foreach (var permission in new[] { "id-token: write", "attestations: write", "artifact-metadata: write", "contents: write" })
            Assert.Contains(permission, release, StringComparison.Ordinal);
        Assert.Equal(3, Regex.Count(release, @"uses: actions/attest@"));
        Assert.Contains("dotnet tool run dotnet-CycloneDX src/Corvus/Corvus.csproj", release, StringComparison.Ordinal);
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
        Assert.Contains("sha256sum corvus-* CorvusRE.*.nupkg > \"$RUNNER_TEMP/assets.sha256\"", release, StringComparison.Ordinal);
        Assert.Contains("subject-checksums: ${{ runner.temp }}/assets.sha256", release, StringComparison.Ordinal);
    }

    [Fact]
    public void Each_asset_ships_its_attestation_bundle_listed_in_SHA256SUMS()
    {
        var release = Workflow[Workflow.IndexOf("\n  release:", StringComparison.Ordinal)..Workflow.IndexOf("\n  image:", StringComparison.Ordinal)];
        int At(string text) => release.IndexOf(text, StringComparison.Ordinal) is >= 0 and var at ? at : throw new Xunit.Sdk.XunitException($"release job lacks: {text}");
        // The bundle step reads the same list the provenance step attests, so
        // every asset gets one.
        Assert.True(At("subject-checksums: ${{ runner.temp }}/assets.sha256") < At("BUNDLE: ${{ steps.provenance.outputs.bundle-path }}"));
        Assert.True(At("cp \"$BUNDLE\" \"$asset.sigstore.json\"; done < \"$RUNNER_TEMP/assets.sha256\"") < At("sha256sum *.sigstore.json; } > SHA256SUMS"));
        Assert.True(At("} > SHA256SUMS") < At("subject-path: SHA256SUMS"));
        Assert.True(At("SHA256SUMS.sigstore.json") < At("uses: softprops/action-gh-release@"));
        var files = release[At("uses: softprops/action-gh-release@")..];
        foreach (var asset in new[] { "corvus-*", "CorvusRE.*", "SHA256SUMS*" })
            Assert.Contains($"            {asset}\n", files, StringComparison.Ordinal);
        var docs = File.ReadAllText(Path.Combine(DocsTests.RepoRoot(), "docs", "installation.md"));
        Assert.Contains("gh attestation verify corvus-win-x64.zip --bundle corvus-win-x64.zip.sigstore.json --repo Albasha0x0/Corvus", docs, StringComparison.Ordinal);
    }

    [Fact]
    public void The_container_image_is_attested_in_the_registry_and_documented_without_network()
    {
        var image = Workflow[Workflow.IndexOf("\n  image:", StringComparison.Ordinal)..Workflow.IndexOf("\n  publish:", StringComparison.Ordinal)];
        foreach (var line in new[] { "id-token: write", "attestations: write", "artifact-metadata: write", "packages: write",
            "subject-digest: ${{ steps.push.outputs.digest }}", "push-to-registry: true" })
            Assert.Contains(line, image, StringComparison.Ordinal);
        Assert.True(image.IndexOf("imagetools create", StringComparison.Ordinal) < image.IndexOf("uses: actions/attest@", StringComparison.Ordinal));
        var root = DocsTests.RepoRoot();
        Assert.Matches(@"(?m)^  - package-ecosystem: docker\n    directory: /\n", File.ReadAllText(Path.Combine(root, ".github", "dependabot.yml")));
        foreach (var file in new[] { "Dockerfile", Path.Combine("docs", "installation.md") })
            Assert.All(Regex.Matches(File.ReadAllText(Path.Combine(root, file)), @"docker run [^\n]*").Select(m => m.Value),
                run => Assert.Contains("--network none", run, StringComparison.Ordinal));
    }

    [Fact]
    public void Release_tools_are_pinned_to_exact_versions_and_digests()
    {
        var problems = new List<string>();
        foreach (Match rustup in Regex.Matches(Workflow, @"rustup (?:toolchain install|default|update) [^\n&]*"))
            if (Regex.IsMatch(rustup.Value, @"\b(stable|beta|nightly)\b")) problems.Add($"a channel, not a version: {rustup.Value}");
        // A tool install outside a manifest takes whatever the feed serves for
        // a range or a missing version.
        foreach (Match install in Regex.Matches(Workflow, @"(?:dotnet tool install|cargo install)[^\n]*"))
            if (!install.Value.StartsWith("cargo install", StringComparison.Ordinal) || !install.Value.Contains("--locked --version", StringComparison.Ordinal))
                problems.Add($"not locked: {install.Value}");
        Assert.True(problems.Count == 0, string.Join("\n", problems));
        using var table = System.Text.Json.JsonDocument.Parse(File.ReadAllText(Path.Combine(DocsTests.RepoRoot(), "tests", "Corvus.Tests", "Support", "yara-x-assets.json")));
        Assert.Matches(@"^\d+\.\d+\.\d+$", table.RootElement.GetProperty("rust").GetString());
        Assert.Contains("rust=$(jq -r .rust \"$TABLE\")", Workflow, StringComparison.Ordinal);
        var tool = System.Text.Json.Nodes.JsonNode.Parse(File.ReadAllText(Path.Combine(DocsTests.RepoRoot(), ".config", "dotnet-tools.json")))!["tools"]!["cyclonedx"]!;
        Assert.Matches(@"^\d+\.\d+\.\d+$", (string?)tool["version"]);
        Assert.False((bool?)tool["rollForward"]);
    }

    [Fact]
    public void Every_download_in_a_workflow_is_checked_by_a_pinned_SHA_256()
    {
        var problems = new List<string>();
        var downloads = 0;
        foreach (var (name, text) in GitHubFiles())
            foreach (Match download in Regex.Matches(text, @"(?:curl [^\n]*-o (?<file>\S+) https://|Invoke-WebRequest https://\S+ -OutFile (?<file>\S+)|wget [^\n]*-O (?<file>\S+))[^\n]*"))
            {
                downloads++;
                var file = Regex.Escape(download.Groups["file"].Value);
                if (!Regex.IsMatch(text, $@"[0-9a-f]{{64}}  {file}"" \| sha256sum --check --strict|Get-FileHash {file} -Algorithm SHA256\)\.Hash -ne '[0-9a-f]{{64}}'"))
                    problems.Add($"{name}: no pinned SHA-256: {download.Value.Trim()}");
            }
        Assert.True(downloads >= 2, "the download pattern no longer finds the known downloads");
        Assert.True(problems.Count == 0, string.Join("\n", problems));
    }
}