using System.Text;
using System.Text.RegularExpressions;

namespace NetDecompilerMcp.Tests;

/// <summary>The README's tool tables, tool counts, prompt list and prompt count match the registered catalog.</summary>
[Collection(InProcessCatalogCollection.Name)]
public partial class ReadmeSyncTests
{
    [Fact]
    public void ToolTablesAndCounts_MatchRegisteredTools()
    {
        var registered = NetDecompilerMcp.Mcp.Catalog.OfThisBuild().Tools.Select(t => (string)t["name"]!).ToHashSet(StringComparer.Ordinal);
        var lines = File.ReadAllLines(Path.Combine(RepoRoot(), "README.md"));

        var listed = new HashSet<string>(StringComparer.Ordinal);
        bool inToolTable = false;
        var counts = new List<(int Line, int Count)>();
        for (int i = 0; i < lines.Length; i++)
        {
            var line = lines[i];
            if (!line.StartsWith('|')) inToolTable = false;
            else if (line.StartsWith("| Area | Tools |", StringComparison.Ordinal)) inToolTable = true;
            else if (inToolTable && Cells(line) is [_, var tools, ..] && CodeSpan().Match(tools) is { Success: true } first
                     && ToolName().IsMatch(first.Value)) // a row that starts with an option ("`engine=...` on ...") is a note
                foreach (Match m in ToolName().Matches(TopLevel(tools))) listed.Add(m.Groups[1].Value);

            foreach (Match m in ToolCount().Matches(line)) counts.Add((i + 1, int.Parse(m.Groups[1].Value)));
        }

        Assert.True(listed.SetEquals(registered),
            $"README tool tables: missing {string.Join(", ", registered.Except(listed).Order())}; not registered {string.Join(", ", listed.Except(registered).Order())}");
        Assert.NotEmpty(counts);
        foreach (var (line, count) in counts)
            Assert.True(count == registered.Count, $"README.md line {line}: {count} tools, {registered.Count} registered");
    }

    [Fact]
    public void PromptListAndCount_MatchRegisteredPrompts()
    {
        var registered = NetDecompilerMcp.Mcp.Catalog.OfThisBuild().Prompts.Select(p => (string)p["name"]!).Order(StringComparer.Ordinal).ToList();
        var readme = File.ReadAllText(Path.Combine(RepoRoot(), "README.md"));
        var counts = PromptCount().Matches(readme).Select(m => int.Parse(m.Groups[1].Value)).ToList();
        Assert.NotEmpty(counts);
        Assert.All(counts, c => Assert.Equal(registered.Count, c));
        var line = PromptLine().Match(readme);
        Assert.True(line.Success, "README.md has no **Prompts:** paragraph");
        Assert.Equal(registered, ToolName().Matches(TopLevel(line.Groups[1].Value)).Select(m => m.Groups[1].Value).Order(StringComparer.Ordinal));
    }

    private static string RepoRoot()
    {
        var root = AppContext.BaseDirectory;
        while (!File.Exists(Path.Combine(root, "NetDecompilerMcp.slnx"))) root = Path.GetDirectoryName(root) ?? throw new InvalidOperationException("repository root not found");
        return root;
    }

    /// <summary>A table row's cells; a pipe escaped inside a code span does not split.</summary>
    private static string[] Cells(string row) => CellSplit().Split(row.Trim().Trim('|')).Select(c => c.Trim()).ToArray();

    /// <summary>The text outside parentheses: tools are listed at the top level, their details and parameters in parentheses.</summary>
    private static string TopLevel(string cell)
    {
        var sb = new StringBuilder();
        int depth = 0;
        foreach (var c in cell)
        {
            if (c == '(') depth++;
            else if (c == ')') depth = Math.Max(0, depth - 1);
            else if (depth == 0) sb.Append(c);
        }
        return sb.ToString();
    }

    [GeneratedRegex(@"(?<!\\)\|")]
    private static partial Regex CellSplit();

    [GeneratedRegex(@"`[^`]*`")]
    private static partial Regex CodeSpan();

    [GeneratedRegex(@"`([a-z][a-z0-9_]*)`")]
    private static partial Regex ToolName();

    [GeneratedRegex(@"\b(\d+) tools\b")]
    private static partial Regex ToolCount();

    [GeneratedRegex(@"\b(\d+) prompts\b")]
    private static partial Regex PromptCount();

    /// <summary>The **Prompts:** paragraph, up to the blank line.</summary>
    [GeneratedRegex(@"\*\*Prompts:\*\*((?:.+\r?\n)+)")]
    private static partial Regex PromptLine();
}
