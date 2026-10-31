using System.Text.Json;
using System.Text.Json.Nodes;
using Corvus.Setup;

namespace Corvus.Tests;

/// <summary>batch --sarif over compare_folders steps: the findings new in an update, as SARIF results on the new side.</summary>
public class DiffSarifTests
{
    private static string Folder(TempDir dir, string name, string manifest, params (string Path, string Text)[] files)
    {
        var root = Path.Combine(dir.Path, name);
        Directory.CreateDirectory(root);
        File.WriteAllText(Path.Combine(root, "package.json"), manifest);
        foreach (var (path, text) in files) File.WriteAllText(Path.Combine(root, path), text);
        return root;
    }

    private static async Task<JsonNode> Diff(TempDir dir, string oldPath, string newPath, string name)
    {
        var steps = dir.File(name + ".jsonl");
        File.WriteAllText(steps, JsonSerializer.Serialize(new { tool = "compare_folders", args = new { oldPath, newPath } }));
        var target = dir.File(name + ".sarif");
        var (code, _, _) = await ToolCliTests.Run(["batch", steps, "--sarif", target, "--json", "--no-index"]);
        Assert.Equal(0, code);
        return JsonNode.Parse(File.ReadAllText(target))!["runs"]![0]!;
    }

    private static (string Old, string New) Update(TempDir dir)
    {
        var old = Folder(dir, "old", """{"name":"example-helper","version":"1.0.0","main":"index.js"}""", ("index.js", "module.exports = (a, b) => a + b;"));
        var @new = Folder(dir, "new", """{"name":"example-helper","version":"1.0.1","main":"index.js","scripts":{"postinstall":"node setup.js"}}""",
            ("index.js", "module.exports = (a, b) => a + b;"), ("setup.js", "require('https').get('https://example.invalid/setup');"));
        return (old, @new);
    }

    [Fact]
    public async Task A_new_install_hook_is_a_result_located_in_the_new_manifest()
    {
        using var dir = new TempDir();
        var (old, @new) = Update(dir);
        var run = await Diff(dir, old, @new, "update");
        var results = run["results"]!.AsArray();
        var hook = Assert.Single(results, r => (string?)r!["ruleId"] == "package/install-script")!;
        Assert.Equal("warning", (string?)hook["level"]);
        Assert.Equal("package.json", (string?)hook["locations"]![0]!["physicalLocation"]!["artifactLocation"]!["uri"]);
        Assert.Matches("^[0-9a-f]{64}$", (string?)hook["partialFingerprints"]!["corvusDiff/v1"]);
        Assert.All(results, r => Assert.Contains((string?)r!["level"], new[] { "error", "warning", "note" }));
    }

    [Fact]
    public async Task A_second_run_over_the_same_update_gives_the_same_fingerprints()
    {
        using var dir = new TempDir();
        var (old, @new) = Update(dir);
        string[] Prints(JsonNode run) => [.. run["results"]!.AsArray().Select(r => (string)r!["partialFingerprints"]!["corvusDiff/v1"]!).Order(StringComparer.Ordinal)];
        var first = Prints(await Diff(dir, old, @new, "first"));
        Assert.NotEmpty(first);
        Assert.Equal(first, Prints(await Diff(dir, old, @new, "second")));
    }

    [Fact]
    public async Task An_update_with_no_changes_gives_no_results()
    {
        using var dir = new TempDir();
        var (old, _) = Update(dir);
        var run = await Diff(dir, old, old, "same");
        Assert.Empty(run["results"]!.AsArray());
    }

    private static JsonObject Comparison(params JsonObject[] rows) => new()
    {
        ["old"] = new JsonObject { ["path"] = "old", ["kind"] = "folder", ["complete"] = true },
        ["new"] = new JsonObject { ["path"] = Path.GetFullPath("new"), ["kind"] = "folder", ["complete"] = true },
        ["changes"] = new JsonArray([.. rows]),
    };

    private static JsonObject Row(string kind, string key, string? @new, string? rule) =>
        new() { ["kind"] = kind, ["key"] = key, ["old"] = null, ["new"] = @new, ["rule"] = rule };

    [Fact]
    public void Lockfile_and_behaviour_rows_become_results_at_their_files_and_other_rows_do_not()
    {
        var log = SarifLog.BuildDiff([Comparison(
            Row("added", "package-lock.json: left-pad@1.0.0", "noteworthy: git https://example.invalid/x.git", "package/locked-source"),
            Row("added", "package-lock.json: other@2.0.0", "registry", null),
            Row("added", "malcontent/net/download at lib/a.js", "noteworthy (critical): downloads", "malcontent/net/download"),
            Row("added", "package/index.js: eval", "review at lib/b.js:7", "package/eval"),
            Row("removed", "package/old.js: eval", null, "package/eval"),
            Row("added", "endpoint: example.invalid", null, null))], Directory.GetCurrentDirectory());
        var results = log["runs"]![0]!["results"]!.AsArray();
        Assert.Equal(["package/locked-source", "malcontent/net/download", "package/eval"], results.Select(r => (string?)r!["ruleId"]));
        Assert.Equal(["error", "error", "warning"], results.Select(r => (string?)r!["level"]));
        var uris = results.Select(r => (string?)r!["locations"]![0]!["physicalLocation"]!["artifactLocation"]!["uri"]);
        Assert.Equal(["new/package-lock.json", "new/lib/a.js", "new/lib/b.js"], uris);
        Assert.Equal(7, (int?)results[2]!["locations"]![0]!["physicalLocation"]!["region"]!["startLine"]);
    }

    [Fact]
    public void Results_past_the_limit_are_cut_and_the_run_names_how_many_were_left_out()
    {
        var rows = Enumerable.Range(0, 5).Select(i => Row("added", $"package-lock.json: p{i}@1.0.0", "noteworthy: git x", "package/locked-source")).ToArray();
        var run = SarifLog.BuildDiff([Comparison(rows)], Directory.GetCurrentDirectory(), maxResults: 2)["runs"]![0]!;
        Assert.Equal(2, run["results"]!.AsArray().Count);
        var notification = run["invocations"]![0]!["toolExecutionNotifications"]![0]!;
        Assert.StartsWith("3 results left out.", (string?)notification["message"]!["text"]);
    }
}
