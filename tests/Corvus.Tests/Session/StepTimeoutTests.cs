using System.Text.Json;
using System.Text.Json.Nodes;
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
        using var deadline = new CancellationTokenSource(50);
        int calls = 0;
        var (section, timedOut) = await ToolCli.Step((_, _, ct) => ++calls == 1 ? Page(true, 2, "a") : Stall(ct), Strings,
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
}
