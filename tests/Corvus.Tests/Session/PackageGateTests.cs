using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

namespace Corvus.Tests;

/// <summary>The package gate recipe: batch over a folder of changed packages, the baseline, and the workflow it shows.</summary>
public class PackageGateTests
{
    private static async Task<(int Code, JsonNode? Document)> Gate(params string[] args)
    {
        var (code, output, _) = await ToolCliTests.Run(["batch", .. args, "--json", "--no-index"]);
        return (code, output.Length > 0 ? JsonNode.Parse(output) : null);
    }

    [Fact]
    public async Task A_noteworthy_package_in_the_changed_folder_fails_the_gate_and_its_baseline_passes()
    {
        using var dir = new TempDir();
        var pkgs = Path.Combine(dir.Path, "pkgs");
        FileBatchTests.Package(Path.Combine(pkgs, "internal-auth-utils-99.0.0.tgz"));
        File.WriteAllText(Path.Combine(pkgs, "notes.txt"), "plain text");
        var sarif = dir.File("corvus.sarif");
        var (code, first) = await Gate("--file", pkgs, "--recurse", "--fail-on", "noteworthy", "--sarif", sarif);
        Assert.Equal(1, code);
        Assert.True((bool)first!["gate"]!["failed"]!);
        Assert.NotEmpty(JsonNode.Parse(File.ReadAllText(sarif))!["runs"]![0]!["results"]!.AsArray());

        var known = dir.File("known.json");
        File.WriteAllText(known, first.ToJsonString());
        (code, var second) = await Gate("--file", pkgs, "--recurse", "--fail-on", "noteworthy", "--baseline", known);
        Assert.Equal(0, code);
        Assert.False((bool)second!["gate"]!["failed"]!);
    }

    [Fact]
    public void The_recipe_workflow_holds_no_token_in_analysis_and_pins_its_actions()
    {
        var text = File.ReadAllText(Path.Combine(DocsTests.RepoRoot(), "docs", "recipes", "package-gate.md"));
        var yaml = Regex.Match(text, @"```yaml\r?\n(.*?)```", RegexOptions.Singleline | RegexOptions.NonBacktracking).Groups[1].Value;
        var analyze = yaml[yaml.IndexOf("  analyze:", StringComparison.Ordinal)..yaml.IndexOf("  upload:", StringComparison.Ordinal)];
        Assert.Matches(@"(?m)^permissions: \{\}\r?$", yaml);
        Assert.Contains("    permissions: {}", analyze, StringComparison.Ordinal);
        Assert.Contains("persist-credentials: false", analyze, StringComparison.Ordinal);
        Assert.DoesNotContain("secrets.", analyze, StringComparison.Ordinal);
        Assert.DoesNotContain("security-events", analyze, StringComparison.Ordinal);
        Assert.Contains("security-events: write", yaml[yaml.IndexOf("  upload:", StringComparison.Ordinal)..], StringComparison.Ordinal);
        Assert.Contains("npm ci --ignore-scripts", yaml, StringComparison.Ordinal);
        foreach (Match use in Regex.Matches(yaml, @"uses: (\S+)", RegexOptions.NonBacktracking))
            Assert.Matches(@"^[\w.-]+/[\w./-]+@[0-9a-f]{40}$", use.Groups[1].Value);
    }
}
