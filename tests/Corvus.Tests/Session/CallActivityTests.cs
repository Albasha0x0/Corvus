using System.Text.Json;
using Microsoft.Extensions.DependencyInjection;
using ModelContextProtocol.Protocol;
using Corvus.Core;
using Corvus.Mcp;
using Corvus.Tools;

namespace Corvus.Tests;

/// <summary>The running and finished calls server_status lists in its calls section.</summary>
public sealed class CallActivityTests
{
    private static Task<CallToolResult> Call(IServiceProvider services, string tool, Func<CancellationToken, ValueTask<CallToolResult>> work) =>
        CallFilter.Run(new CallToolRequestParams { Name = tool, Arguments = new Dictionary<string, JsonElement> { ["assembly"] = JsonSerializer.SerializeToElement("app.dll") } },
            null, services, work, default).AsTask();

    private static readonly CallToolResult Done = new() { Content = [new TextContentBlock { Text = "done" }] };

    [Fact]
    public async Task A_call_is_listed_as_running_until_it_ends_then_as_finished_with_its_outcome()
    {
        using var services = new ServiceCollection().AddSingleton<CallActivity>().BuildServiceProvider();
        var activity = services.GetRequiredService<CallActivity>();
        var gate = new TaskCompletionSource<CallToolResult>(TaskCreationOptions.RunContinuationsAsynchronously);
        var running = Call(services, "list_types", _ => new ValueTask<CallToolResult>(gate.Task));
        // A status call running beside it is left out of the list.
        var status = new TaskCompletionSource<CallToolResult>(TaskCreationOptions.RunContinuationsAsynchronously);
        var statusCall = Call(services, "server_status", _ => new ValueTask<CallToolResult>(status.Task));

        Assert.Equal("none", CallsStatus.Activity(new CallActivity(), DateTimeOffset.UtcNow).Value);
        Assert.Matches(@"^running: list_types \d+\.\d s; finished, newest first: none$", CallsStatus.Activity(activity, DateTimeOffset.UtcNow).Value);

        gate.SetResult(Done);
        await running.WaitAsync(TimeSpan.FromMinutes(1));
        status.SetResult(Done);
        await statusCall.WaitAsync(TimeSpan.FromMinutes(1));
        await Call(services, "find_references", _ => throw new ToolError(ErrorCode.NotFound, "no such member")).WaitAsync(TimeSpan.FromMinutes(1));

        var (now, finished) = activity.Snapshot();
        Assert.Empty(now);
        Assert.Equal(["find_references", "server_status", "list_types"], finished.Select(c => c.Tool));
        Assert.Equal("not_found", finished[0].Outcome);
        Assert.Equal("ok", finished[2].Outcome);
        Assert.Matches(@"^running: none; finished, newest first: find_references not_found \d+ ms, server_status ok \d+ ms, list_types ok \d+ ms$",
            CallsStatus.Activity(activity, DateTimeOffset.UtcNow).Value);
    }

    [Fact]
    public void Finished_calls_are_bounded_and_kept_newest_first()
    {
        var activity = new CallActivity();
        for (int i = 0; i < CallActivity.Kept + 4; i++) activity.End(activity.Start($"t{i}"), i, "ok");
        var (_, finished) = activity.Snapshot();
        Assert.Equal(CallActivity.Kept, finished.Count);
        Assert.Equal($"t{CallActivity.Kept + 3}", finished[0].Tool);
        Assert.Equal("t4", finished[^1].Tool);
    }
}
