using System.Text.Json;
using System.Text.Json.Nodes;
using Corvus.Core;
using Corvus.Mcp;
using Corvus.Setup;
using ModelContextProtocol.Protocol;

namespace Corvus.Tests;

/// <summary>batch --step-timeout: one step ends at its limit; the outer token and the later steps are unaffected.</summary>
public class StepTimeoutTests
{
    [Fact]
    public async Task A_delayed_step_expires_at_its_limit_and_is_cancelled()
    {
        var cancelled = new TaskCompletionSource();
        var (value, expired) = await ToolCli.WithStepLimit<int>(0.05, CancellationToken.None, async ct =>
        {
            try { await Task.Delay(Timeout.Infinite, ct); }
            catch (OperationCanceledException) { cancelled.SetResult(); throw; }
            return 1;
        });
        Assert.True(expired);
        Assert.Equal(0, value);
        await cancelled.Task.WaitAsync(TimeSpan.FromSeconds(30));
    }

    [Fact]
    public async Task A_step_inside_its_limit_returns_its_value()
    {
        var (value, expired) = await ToolCli.WithStepLimit(30, CancellationToken.None, _ => Task.FromResult(7));
        Assert.False(expired);
        Assert.Equal(7, value);
    }

    [Fact]
    public async Task An_outer_cancellation_is_not_reported_as_a_step_timeout()
    {
        using var outer = new CancellationTokenSource(50);
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            ToolCli.WithStepLimit<int>(30, outer.Token, async ct => { await Task.Delay(Timeout.Infinite, ct); return 1; }));
    }

    // Regression for the release changes job: a one-shot batch exited 5 on a
    // compare_assemblies step past the 30 s deadline, and its work was lost.
    [Fact]
    public async Task A_one_shot_batch_step_left_running_is_repeated_until_it_ends()
    {
        int calls = 0;
        var result = await ToolCli.JoinRunning(() => Task.FromResult<CallToolResult?>(++calls == 1 ? Running() : new CallToolResult()), CancellationToken.None);
        Assert.Equal(2, calls);
        Assert.NotEqual(true, result!.IsError);
    }

    [Fact]
    public async Task A_failed_step_is_not_repeated()
    {
        int calls = 0;
        var failed = new CallToolResult { IsError = true, Content = [new TextContentBlock { Text = "Error (not_found) in x: gone." }] };
        var result = await ToolCli.JoinRunning(() => { calls++; return Task.FromResult<CallToolResult?>(failed); }, CancellationToken.None);
        Assert.Equal(1, calls);
        Assert.Same(failed, result);
    }

    private static CallToolResult Running() => new()
    {
        IsError = true,
        Content = [new TextContentBlock { Text = ErrorResult.JsonMarker + """{"code":"timeout","details":{"stillRunning":true}}""" }],
    };

    [Theory]
    [InlineData("0")]
    [InlineData("-1")]
    [InlineData("86401")]
    [InlineData("x")]
    public void A_step_timeout_outside_the_range_is_a_usage_error(string text) =>
        Assert.Throws<UsageException>(() => ToolCli.StepSeconds(text));

    private static readonly ToolCli.FileBatchStep Strings = new("strings", "search_strings", "strings");

    private static Task<CallToolResult?> Page(bool more, int next, params string[] rows) => Task.FromResult<CallToolResult?>(new CallToolResult
    {
        StructuredContent = JsonSerializer.SerializeToElement(new JsonObject
        {
            ["items"] = new JsonArray([.. rows.Select(r => (JsonNode?)r)]), ["hasMore"] = more, ["nextOffset"] = next,
        }),
    });

    private static async Task<CallToolResult?> Stall(CancellationToken ct)
    {
        await Task.Delay(Timeout.Infinite, ct);
        return null;
    }

    private static Task<CallToolResult?> EndRunThenStall(CancellationTokenSource deadline, CancellationToken ct)
    {
        deadline.Cancel();
        return Stall(ct);
    }

    [Fact]
    public async Task A_stalled_first_call_gives_a_timeout_section_and_leaves_the_run_going()
    {
        var (section, timedOut) = await ToolCli.Step((_, _, ct) => Stall(ct), Strings,
            new() { ["limit"] = 10 }, CancellationToken.None, CancellationToken.None, 0.05);
        Assert.Equal("timeout", (string?)section["status"]);
        Assert.False(timedOut);
    }

    [Fact]
    public async Task A_stalled_later_page_keeps_the_rows_paged_so_far_and_leaves_the_run_going()
    {
        int calls = 0;
        var (section, timedOut) = await ToolCli.Step((_, _, ct) => ++calls == 1 ? Page(true, 2, "a", "b") : Stall(ct), Strings,
            new() { ["limit"] = 10 }, CancellationToken.None, CancellationToken.None, 0.2);
        Assert.Equal("timeout", (string?)section["status"]);
        Assert.Equal(2, section["result"]!["items"]!.AsArray().Count);
        Assert.False(timedOut);
    }

    [Fact]
    public async Task The_whole_run_deadline_wins_over_a_step_limit_that_expires_with_it()
    {
        using var deadline = new CancellationTokenSource();
        int calls = 0;
        var (section, timedOut) = await ToolCli.Step((_, _, ct) => ++calls == 1 ? Page(true, 2, "a") : EndRunThenStall(deadline, ct), Strings,
            new() { ["limit"] = 10 }, deadline.Token, CancellationToken.None, 0.05);
        Assert.Equal("timeout", (string?)section["status"]);
        Assert.True(timedOut);
    }

    [Theory]
    [InlineData(false, false)]
    [InlineData(true, true)]
    public void A_timed_out_batch_step_exits_124_and_stops_only_with_stop_on_error(bool stopOnError, bool stops)
    {
        var io = new CliIo(new StringWriter(), new StringWriter(), TextReader.Null);
        int exit = ToolCli.Exit.Ok;
        var stopped = ToolCli.ReportStepTimeout(io, true, 2, 3, "search_strings", 0.5, stopOnError, ref exit);
        Assert.Equal(stops, stopped);
        Assert.Equal(ToolCli.Exit.Timeout, exit);
        Assert.Contains("Step 2 of 3 (search_strings) timed out", io.Error.ToString());
        Assert.Equal("timeout", (string?)JsonNode.Parse(io.Out.ToString()!)!["error"]!["code"]);
    }

    [Fact]
    public void A_refused_step_record_is_an_error_with_the_step_and_no_content()
    {
        var record = ToolCli.RefusedStepRecord(2, "list_types", ToolCli.StepState(ToolCli.Exit.Usage), 7);
        Assert.Equal(2, (int)record["step"]!);
        Assert.Equal("list_types", (string?)record["tool"]);
        Assert.True((bool)record["isError"]!);
        Assert.Null(record["text"]);
        Assert.Null(record["structured"]);
        Assert.Equal("invalid_argument", (string?)record["error"]!["code"]);
        Assert.Contains("corvus help", (string?)record["error"]!["message"]);
    }

    [Fact]
    public async Task A_step_timeout_section_names_the_option_and_the_step()
    {
        var (section, _) = await ToolCli.Step((_, _, ct) => Stall(ct), Strings,
            new() { ["limit"] = 10 }, CancellationToken.None, CancellationToken.None, 0.05);
        var reason = (string?)section["reason"];
        Assert.Contains("--step-timeout", reason);
        Assert.Contains(Strings.Name, reason);
        Assert.Contains("raise --step-timeout", reason);
    }

    [Fact]
    public void A_limit_at_its_maximum_is_not_offered_for_raising()
    {
        Assert.Equal("--time-limit is at its maximum of 86400 s.", ToolCli.Raise("--time-limit", 86400));
        Assert.DoesNotContain("raise", ToolCli.Raise("--step-timeout", 86400));
    }
}
