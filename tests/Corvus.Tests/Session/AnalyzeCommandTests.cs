using System.Text.Json;
using Corvus.Core;
using Corvus.Mcp;
using Corvus.Setup;
using ModelContextProtocol.Protocol;

namespace Corvus.Tests;

/// <summary>The analyze command: its arguments and the background outcome it waits for.</summary>
public class AnalyzeCommandTests
{
    private static CallToolResult Reply(string engines) => new()
    {
        Content = [new TextContentBlock { Text = "status" }],
        StructuredContent = JsonDocument.Parse($$"""{"image":"a","engines":[{{engines}}]}""").RootElement,
    };

    private static string Engine(string state, string extra = "") =>
        $$"""{"engine":"ida","state":"{{state}}"{{extra}}}""";

    private static string Job(string state, string? result = null, string? outcome = null) =>
        $$""","job":{"what":"reanalysis","state":"{{state}}","startedAt":"x","budgetSeconds":60,"outcome":{{(outcome == null ? "null" : $"\"{outcome}\"")}},"result":{{(result == null ? "null" : $"\"{result}\"")}}}""";

    private static CallToolResult Early() => ErrorResult.From(
        new ToolError(ErrorCode.Timeout, "analysis running", "get_engine_status image=a waitSeconds=30")
        { Details = new { stillRunning = true, image = "a" } }, "list_functions");

    /// <summary>Answers each tool call from a script and records the calls made.</summary>
    private sealed class Script(params Func<string, CallToolResult>[] replies)
    {
        public List<string> Calls { get; } = [];
        private int _next;

        public Task<CallToolResult?> Call(string tool, Dictionary<string, object?> args, CancellationToken ct)
        {
            Calls.Add(tool + (args.ContainsKey("analyzers") ? " analyzers" : ""));
            return Task.FromResult<CallToolResult?>(replies[Math.Min(_next++, replies.Length - 1)](tool));
        }
    }

    private static async Task<(int Code, string Error)> Wait(Script script, string? engine = null, int stallPolls = 150)
    {
        using var error = new StringWriter();
        var io = new CliIo(new StringWriter(), error, TextReader.Null);
        var arguments = new Dictionary<string, object?> { ["image"] = "a" };
        if (engine != null) arguments["engine"] = engine;
        var code = await ToolCli.AnalyzeWaitAsync(script.Call, "a", arguments, CliArgs.Parse(["--wait"]), io, CancellationToken.None,
            TimeSpan.Zero, stallPolls);
        return (code, error.ToString());
    }

    [Fact]
    public async Task A_first_analysis_that_ends_exits_zero_without_a_reanalysis()
    {
        var script = new Script(_ => Early(), _ => Reply(Engine("opening")),
            _ => Reply(Engine("open", ""","reusedDatabase":false,"analysis":"complete" """)));
        var (code, error) = await Wait(script);
        Assert.Equal(0, code);
        Assert.Contains("ida complete", error);
        Assert.Equal(["reanalyze_native analyzers", "get_engine_status", "get_engine_status"], script.Calls);
    }

    [Fact]
    public async Task A_first_analysis_that_ran_out_of_budget_exits_partial() =>
        Assert.Equal(ToolCli.Exit.Partial, (await Wait(new Script(_ => Early(),
            _ => Reply(Engine("open", ""","reusedDatabase":false,"analysis":"partial" """))))).Code);

    [Fact]
    public async Task A_failed_open_exits_with_a_tool_error()
    {
        var failed = Engine("failed", Job("ended", "failed", "engine closed").Replace("reanalysis", "open"));
        Assert.Equal(ToolCli.Exit.ToolError, (await Wait(new Script(_ => Early(), _ => Reply(failed)))).Code);
    }

    [Fact]
    public async Task A_cancelled_open_exits_with_its_own_code()
    {
        var cancelled = Engine("failed", Job("ended", "cancelled", "cancelled").Replace("reanalysis", "open"));
        Assert.Equal(ToolCli.Exit.JobCancelled, (await Wait(new Script(_ => Early(), _ => Reply(cancelled)))).Code);
    }

    [Fact]
    public async Task A_saved_analysis_is_followed_by_one_reanalysis_that_decides_the_exit()
    {
        var loaded = Engine("open", ""","reusedDatabase":true,"analysis":"complete" """);
        var script = new Script(
            _ => Reply(loaded),
            _ => Reply(loaded),
            _ => Reply(loaded),
            _ => Reply(Engine("open", ""","reusedDatabase":true""" + Job("running"))),
            _ => Reply(Engine("open", ""","reusedDatabase":true""" + Job("ended", "partial", "reanalysis ended in 4 s: partial"))));
        var (code, error) = await Wait(script);
        Assert.Equal(ToolCli.Exit.Partial, code);
        Assert.Equal(1, script.Calls.Count(c => c == "reanalyze_native"));
        Assert.Contains("reanalysis ended in 4 s: partial", error);
    }

    [Fact]
    public async Task An_open_session_with_no_analysis_state_exits_unknown()
    {
        var (code, error) = await Wait(new Script(_ => Early(), _ => Reply(Engine("open", ""","reusedDatabase":false"""))));
        Assert.Equal(ToolCli.Exit.Unknown, code);
        Assert.Contains("outcome is unknown", error);
    }

    [Fact]
    public async Task A_reanalysis_with_no_job_entry_exits_unknown()
    {
        var loaded = Engine("open", ""","reusedDatabase":true,"analysis":"complete" """);
        var (code, _) = await Wait(new Script(_ => Reply(loaded), _ => Reply(loaded), _ => Reply(loaded)));
        Assert.Equal(ToolCli.Exit.Unknown, code);
    }

    [Fact]
    public async Task An_analysis_that_stays_running_ends_the_wait_as_unknown()
    {
        var running = Engine("open", ""","reusedDatabase":false,"analysis":"running" """);
        var (code, error) = await Wait(new Script(_ => Early(), _ => Reply(running)), stallPolls: 3);
        Assert.Equal(ToolCli.Exit.Unknown, code);
        Assert.Contains("after 3 polls", error);
    }

    [Fact]
    public void A_still_running_early_answer_exits_with_its_own_code() =>
        Assert.Equal(ToolCli.Exit.Running, ToolCli.ExitCode(ToolCli.Split(Early()).Error));

    [Fact]
    public void A_one_shot_early_answer_names_the_session_and_the_wait()
    {
        var next = ToolCli.StillRunning(ToolCli.Split(Early()).Error);
        Assert.Contains("corvus serve --session NAME", next);
        Assert.Contains("corvus analyze a --wait", next);
    }

    [Fact]
    public void A_batch_step_that_is_still_running_is_not_failed()
    {
        Assert.Equal("running", ToolCli.StepState(ToolCli.Exit.Running));
        Assert.Equal("failed", ToolCli.StepState(ToolCli.Exit.Timeout));
        Assert.Equal("ok", ToolCli.StepState(ToolCli.Exit.Ok));
    }

    [Fact]
    public void A_timeout_without_running_work_keeps_exit_124() =>
        Assert.Equal(ToolCli.Exit.Timeout, ToolCli.ExitCode(ToolCli.Split(ErrorResult.From(new ToolError(ErrorCode.Timeout, "slow", "narrow it"), "t")).Error));

    [Fact]
    public void An_engine_entry_of_another_engine_is_ignored() =>
        Assert.Null(ToolCli.EngineJobState(Reply(Engine("open")).StructuredContent, "ghidra"));

    [Theory]
    [InlineData("complete", 0)]
    [InlineData("partial", 4)]
    [InlineData("failed", 1)]
    [InlineData("cancelled", 6)]
    public void Each_analysis_result_has_its_own_exit_code(string result, int exit) =>
        Assert.Equal(exit, ToolCli.ResultExit(result));

    [Fact]
    public async Task Analyze_rejects_an_image_pair()
    {
        var (code, _, error) = await ToolCliTests.Run("analyze", "a.exe", "image=b.exe");
        Assert.Equal(2, code);
        Assert.Contains("image=", error);
    }

    [Fact]
    public async Task Analyze_without_an_image_is_a_usage_error()
    {
        var (code, _, error) = await ToolCliTests.Run("analyze", "--wait");
        Assert.Equal(2, code);
        Assert.Contains("analyze takes one image", error);
    }
}
