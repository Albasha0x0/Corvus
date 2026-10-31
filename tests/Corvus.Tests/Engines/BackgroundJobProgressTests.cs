using Corvus.Core;
using Corvus.Mcp;
using Corvus.Native.Providers;
using Microsoft.Extensions.DependencyInjection;

namespace Corvus.Tests;

public sealed class BackgroundJobProgressTests
{
    private static readonly DateTime Start = new(2026, 1, 1, 0, 0, 0, DateTimeKind.Utc);

    private static WorkerSessionBase.BackgroundJob Job(double budgetSeconds) =>
        new("reanalysis", Start, TimeSpan.FromSeconds(budgetSeconds), Task.CompletedTask);

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
}
