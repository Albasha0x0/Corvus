using System.Diagnostics;

namespace Corvus.Tests;

/// <summary>
/// Real-client checks (E9): tests/agents/run-tasks.ps1 asks each installed agent client (Claude Code, Codex, Gemini CLI)
/// one known-answer question about the Notes sample through this build's server and grades the answer. Model calls cost
/// tokens, so it runs only with CORVUS_CLIENT_CHECKS=1; a client that is not installed is skipped by the script.
/// </summary>
public class ClientCheckTests
{
    public const string Variable = "CORVUS_CLIENT_CHECKS";

    [Fact]
    [Trait("Speed", "Slow")]
    public async Task EachInstalledClientAnswersTheCheckQuestion()
    {
        if (Environment.GetEnvironmentVariable(Variable) != "1") return; // opt-in: spends model tokens
        var root = DocsTests.RepoRoot();
        ProcessStartInfo start = new("pwsh") { RedirectStandardOutput = true, RedirectStandardError = true, WorkingDirectory = root };
        foreach (var arg in new[] { "-NoProfile", "-File", Path.Combine(root, "tests", "agents", "run-tasks.ps1"), "-Set", "check" }) start.ArgumentList.Add(arg);
        using var process = Process.Start(start)!;
        var output = process.StandardOutput.ReadToEndAsync();
        var error = await process.StandardError.ReadToEndAsync();
        using var timeout = new CancellationTokenSource(TimeSpan.FromMinutes(45));
        await process.WaitForExitAsync(timeout.Token);
        Assert.True(process.ExitCode == 0, $"client checks failed:\n{await output}\n{error}");
    }

    [Fact]
    public void TasksAndClientsAreWellFormed()
    {
        var dir = Path.Combine(DocsTests.RepoRoot(), "tests", "agents");
        var tasks = System.Text.Json.Nodes.JsonNode.Parse(File.ReadAllText(Path.Combine(dir, "tasks.json")))!["tasks"]!.AsArray();
        Assert.Equal(10, tasks.Count(t => t!["sets"]!.AsArray().Any(s => (string?)s == "bench")));
        Assert.Single(tasks, t => t!["sets"]!.AsArray().Any(s => (string?)s == "check"));
        Assert.Equal(tasks.Count, tasks.Select(t => (string?)t!["id"]).Distinct().Count());
        foreach (var t in tasks)
        {
            Assert.Contains("{v1}", (string?)t!["prompt"], StringComparison.Ordinal);
            Assert.All(t["expect"]!.AsArray(), e => _ = new System.Text.RegularExpressions.Regex((string)e!));
        }
        var clients = System.Text.Json.Nodes.JsonNode.Parse(File.ReadAllText(Path.Combine(dir, "clients.json")))!["clients"]!.AsObject();
        Assert.Equal(["claude", "codex", "gemini"], clients.Select(c => c.Key).Order(StringComparer.Ordinal));
        foreach (var client in clients.Select(c => c.Value))
        {
            Assert.StartsWith("CORVUS_CLIENT_", (string?)client!["variable"], StringComparison.Ordinal);
            Assert.Contains("{prompt}", client["args"]!.AsArray().Select(a => (string?)a));
            Assert.Contains((string?)client["output"], new[] { "claude-stream", "codex-jsonl", "gemini-json" });
        }
    }
}
