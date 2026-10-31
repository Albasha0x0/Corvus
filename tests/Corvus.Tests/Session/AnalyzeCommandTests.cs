using System.Text.Json;
using Corvus.Setup;

namespace Corvus.Tests;

/// <summary>The analyze command: its arguments and the background outcome it waits for.</summary>
public class AnalyzeCommandTests
{
    private static JsonElement Status(string stage) =>
        JsonDocument.Parse($$"""{"image":"a","engines":[{"engine":"ida","state":"open","stage":"{{stage}}"}]}""").RootElement;

    private static string? Outcome(string stage, string? engine = null) =>
        ToolCli.BackgroundState(Status(stage), engine).Outcome;

    [Fact]
    public void A_running_background_job_has_no_outcome_and_its_budget()
    {
        var state = ToolCli.BackgroundState(Status("background reanalysis: running 3 of 600 s"), null);
        Assert.Null(state.Outcome);
        Assert.True(state.Running);
        Assert.Equal(600, state.Budget);
    }

    [Fact]
    public void An_ended_background_job_reports_its_outcome() =>
        Assert.Equal("reanalysis ended in 4 s: complete; functions 10 before, 12 after",
            Outcome("background reanalysis ended in 4 s: complete; functions 10 before, 12 after"));

    [Fact]
    public void A_status_without_a_background_job_is_not_running()
    {
        var state = ToolCli.BackgroundState(Status("analysis"), null);
        Assert.Null(state.Outcome);
        Assert.False(state.Running);
    }

    [Fact]
    public void A_job_on_another_engine_is_ignored() =>
        Assert.Null(Outcome("background reanalysis ended in 4 s: complete", "ghidra"));

    [Fact]
    public void A_failed_job_exits_with_a_tool_error() =>
        Assert.Equal(ToolCli.Exit.ToolError, ToolCli.OutcomeExit("reanalysis failed after 4 s: engine closed"));

    [Fact]
    public void A_complete_outcome_that_mentions_failed_exits_ok() =>
        Assert.Equal(ToolCli.Exit.Ok, ToolCli.OutcomeExit("reanalysis ended in 4 s: complete; 3 functions failed to decompile"));

    [Fact]
    public async Task Analyze_rejects_an_image_pair()
    {
        var (code, _, error) = await ToolCliTests.Run("analyze", "a.exe", "image=b.exe");
        Assert.Equal(2, code);
        Assert.Contains("image=", error);
    }

    [Fact]
    public async Task Wait_rejects_background_false()
    {
        var (code, _, error) = await ToolCliTests.Run("analyze", "a.exe", "--wait", "background=false");
        Assert.Equal(2, code);
        Assert.Contains("background=", error);
    }

    [Fact]
    public async Task Analyze_without_an_image_is_a_usage_error()
    {
        var (code, _, error) = await ToolCliTests.Run("analyze", "--wait");
        Assert.Equal(2, code);
        Assert.Contains("analyze takes one image", error);
    }
}
