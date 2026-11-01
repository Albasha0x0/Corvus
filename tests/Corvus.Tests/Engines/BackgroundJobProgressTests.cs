using Corvus.Core;
using Corvus.Mcp;
using Corvus.Native.Providers;
using Microsoft.Extensions.DependencyInjection;
using ModelContextProtocol.Client;
using ModelContextProtocol.Protocol;

namespace Corvus.Tests;

public sealed class BackgroundJobProgressTests
{
    private static readonly DateTime Start = new(2026, 1, 1, 0, 0, 0, DateTimeKind.Utc);

    private static BackgroundJob Job(double budgetSeconds) =>
        new("reanalysis", "img", Start, TimeSpan.FromSeconds(budgetSeconds), Task.CompletedTask, new CancellationTokenSource());

    [Fact]
    public void Percent_is_the_elapsed_share_of_the_budget()
    {
        Assert.Equal(25, Job(100).Percent(Start.AddSeconds(25)));
    }

    [Fact]
    public void Percent_stays_below_100_after_the_budget_passes()
    {
        Assert.Equal(99, Job(100).Percent(Start.AddSeconds(500)));
    }

    [Fact]
    public void Percent_of_a_zero_budget_is_bounded()
    {
        Assert.Equal(50, Job(0).Percent(Start.AddSeconds(0.5)));
        Assert.Equal(99, Job(0).Percent(Start.AddDays(100000)));
    }

    [Fact]
    public void Remaining_is_the_budget_left()
    {
        Assert.Equal(TimeSpan.FromSeconds(60), Job(100).Remaining(Start.AddSeconds(40)));
    }

    [Fact]
    public void Remaining_is_zero_after_the_budget_passes()
    {
        Assert.Equal(TimeSpan.Zero, Job(100).Remaining(Start.AddSeconds(500)));
    }

    [Fact]
    public void Announce_sends_nothing_when_no_client_is_connected()
    {
        using var workspace = new AssemblyWorkspace(new ServerOptions { WatchFiles = false });
        var subscriptions = new ResourceSubscriptions(workspace, new ServiceCollection().BuildServiceProvider());
        subscriptions.Announce("image.bin: ended");
    }

    // MCP9005: logging is obsolete in the 2026-07-28 revision; earlier clients still read it.
#pragma warning disable MCP9005
    [Fact]
    public async Task Announce_sends_a_logging_notice_and_a_resource_update_to_a_subscribed_client()
    {
        await using var server = await InProcessServer.StartAsync("2025-06-18");
        var logged = new TaskCompletionSource<string>();
        var updated = new TaskCompletionSource<string>();
        await using var log = server.Client.RegisterNotificationHandler(NotificationMethods.LoggingMessageNotification, (n, _) =>
        {
            logged.TrySetResult(n.Params!.ToString());
            return ValueTask.CompletedTask;
        });
        await using var res = server.Client.RegisterNotificationHandler(NotificationMethods.ResourceUpdatedNotification, (n, _) =>
        {
            updated.TrySetResult(n.Params!["uri"]!.GetValue<string>());
            return ValueTask.CompletedTask;
        });
        await server.Client.SubscribeToResourceAsync("corvus://assemblies");

        server.Services.GetRequiredService<ResourceSubscriptions>().Announce("image.bin: ended");

        Assert.Contains("image.bin: ended", await logged.Task.WaitAsync(TimeSpan.FromSeconds(10)));
        Assert.Equal("corvus://assemblies", await updated.Task.WaitAsync(TimeSpan.FromSeconds(10)));
    }
#pragma warning restore MCP9005
}
