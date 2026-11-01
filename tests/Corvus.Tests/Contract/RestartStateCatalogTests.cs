using System.Text.RegularExpressions;

namespace Corvus.Tests;

/// <summary>The catalog checks behind the restart cases: every stateful tool has one, every state writer has a kind.</summary>
public class RestartStateCatalogTests
{
    private static bool Stateful(KeyValuePair<string, Corvus.Mcp.ToolContract> row) => row.Value.State != Corvus.Mcp.ToolState.None;

    [Fact]
    public void Every_stateful_tool_has_a_restart_case()
    {
        using var dir = new TempDir();
        var probes = RestartStateTests.Probes(dir);
        var uncovered = Corvus.Mcp.ToolContract.Table.Where(Stateful).Select(r => r.Key)
            .Where(t => !probes.ContainsKey(t) && !RestartStateTests.NoRestartCase.ContainsKey(t) && !RestartStateTests.HeldElsewhere.ContainsKey(t))
            .Order(StringComparer.Ordinal).ToList();
        Assert.True(uncovered.Count == 0, "stateful tools with no restart case: " + string.Join(", ", uncovered));
        Assert.All(RestartStateTests.HeldElsewhere.Values, m => Assert.NotNull(typeof(RestartStateTests).GetMethod(m)));
        Assert.All(RestartStateTests.NoRestartCase.Values, reason => Assert.NotEmpty(reason));
    }

    [Fact]
    public void Every_listed_tool_is_stateful_in_the_table()
    {
        using var dir = new TempDir();
        var listed = RestartStateTests.Probes(dir).Keys.Concat(RestartStateTests.NoRestartCase.Keys).Concat(RestartStateTests.HeldElsewhere.Keys)
            .Where(t => Corvus.Mcp.ToolContract.Of(t).State == Corvus.Mcp.ToolState.None).Distinct().Order(StringComparer.Ordinal).ToList();
        Assert.True(listed.Count == 0, "restart cases for tools the table marks stateless: " + string.Join(", ", listed));
    }

    /// <summary>The kind of state each folder under the data folder holds, and the folder name a non-literal argument stands for.</summary>
    private static readonly Dictionary<string, Corvus.Mcp.ToolState> Folders = new(StringComparer.Ordinal)
    {
        ["analysis"] = Corvus.Mcp.ToolState.Engine,
        ["aot"] = Corvus.Mcp.ToolState.Cache,
        ["bundles"] = Corvus.Mcp.ToolState.Live,
        ["dumpbuckets"] = Corvus.Mcp.ToolState.Cache,
        ["emulation"] = Corvus.Mcp.ToolState.Engine,
        ["frida"] = Corvus.Mcp.ToolState.None,
        ["ghidra_scripts"] = Corvus.Mcp.ToolState.Engine,
        ["java-sources"] = Corvus.Mcp.ToolState.Cache,
        ["packs"] = Corvus.Mcp.ToolState.None,
        ["relay"] = Corvus.Mcp.ToolState.None,
        ["results"] = Corvus.Mcp.ToolState.Results,
        ["rules"] = Corvus.Mcp.ToolState.None,
        ["symbols"] = Corvus.Mcp.ToolState.Cache,
        // Files in the data folder root: the marker id, analysis presets, the exports folder.
        ["FileName"] = Corvus.Mcp.ToolState.None,
        ["OutputGuard.ExportsFolder"] = Corvus.Mcp.ToolState.None,
    };

    [Fact]
    public void Every_folder_a_writer_creates_in_the_data_folder_has_a_state_kind()
    {
        var source = Path.Combine(DocsTests.RepoRoot(), "src", "Corvus");
        var found = Directory.EnumerateFiles(source, "*.cs", SearchOption.AllDirectories)
            .SelectMany(f => Regex.Matches(File.ReadAllText(f), @"DataFolder\.Combine\(\s*(""[^""]+""|[A-Za-z_.]+)").Select(m => m.Groups[1].Value.Trim('"')))
            .Distinct(StringComparer.Ordinal).Order(StringComparer.Ordinal).ToList();
        var unmapped = found.Where(f => !Folders.ContainsKey(f)).ToList();
        Assert.True(unmapped.Count == 0, "folders written with no state kind: " + string.Join(", ", unmapped));
        var kinds = Corvus.Mcp.ToolContract.Table.Values.Select(r => r.State).ToHashSet();
        Assert.All(Folders.Values.Where(k => k != Corvus.Mcp.ToolState.None), k => Assert.Contains(k, kinds));
    }
}
