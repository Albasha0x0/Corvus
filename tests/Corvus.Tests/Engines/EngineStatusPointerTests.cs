using System.Text.RegularExpressions;
using Corvus.Mcp;

namespace Corvus.Tests;

/// <summary>Outside the engine toolset no text sends an agent to get_engine_status; server_status carries the engine sessions.</summary>
public sealed class EngineStatusPointerTests
{
    /// <summary>The only sources that may name get_engine_status: the tool itself, its contract rows and its toolset.</summary>
    private static readonly string[] Allowed = ["NativeEngineStatusTools.cs", "Engine.cs", "FileReads.cs", "Toolsets.cs", "IdaPython.cs"];

    [Fact]
    public void Nothing_outside_the_engine_toolset_points_to_get_engine_status()
    {
        // The idapython topic is the engine toolset's own.
        foreach (var (topic, text) in Guide.Topics.Where(t => t.Key != "idapython")) Assert.DoesNotContain("get_engine_status", text);
        Assert.DoesNotContain("get_engine_status", ServerInstructions.Text);
        var src = Path.Combine(RepoRoot(), "src", "Corvus");
        var offenders = Directory.EnumerateFiles(src, "*", SearchOption.AllDirectories)
            .Where(f => Regex.IsMatch(f, @"\.(cs|py|java)$") && !f.Contains($"{Path.DirectorySeparatorChar}obj{Path.DirectorySeparatorChar}") && !Allowed.Contains(Path.GetFileName(f)))
            .Where(f => File.ReadAllText(f).Contains("get_engine_status", StringComparison.Ordinal))
            .Select(Path.GetFileName).ToList();
        Assert.Empty(offenders);
        Assert.False(ToolContract.Of("get_engine_status").Core);
        Assert.False(ToolContract.Of("get_engine_status").Lean);
    }

    private static string RepoRoot()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir != null && !File.Exists(Path.Combine(dir.FullName, "Corvus.slnx"))) dir = dir.Parent;
        return dir?.FullName ?? throw new InvalidOperationException("no repository root");
    }
}
