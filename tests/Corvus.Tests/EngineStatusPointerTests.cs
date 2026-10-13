using System.Text.RegularExpressions;
using Corvus.Mcp;

namespace Corvus.Tests;

/// <summary>
/// get_engine_status is not in the core or lean profile (the engine toolset has it): no guide topic, server instruction or
/// error Next of the other tools sends an agent there; server_status carries the engine sessions instead.
/// </summary>
public sealed class EngineStatusPointerTests
{
    /// <summary>The only sources that may name get_engine_status: the tool itself, its contract row and its toolset.</summary>
    private static readonly string[] Allowed = ["NativeEngineStatusTools.cs", "Engine.cs", "Toolsets.cs", "IdaPython.cs"];

    [Fact]
    public void Nothing_outside_the_engine_toolset_points_to_get_engine_status()
    {
        // the idapython topic is the engine toolset's own
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
