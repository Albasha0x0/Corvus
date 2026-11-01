namespace Corvus.Tests;

public class ContractSweepStallTests
{
    private static readonly TimeSpan Poll = TimeSpan.FromMilliseconds(20);

    [Fact]
    public async Task A_call_with_no_CPU_use_for_the_limit_is_reported_as_a_hang()
    {
        using var stop = new CancellationTokenSource();
        var cpu = TimeSpan.Zero;
        await ContractSweep.StalledAsync(new TaskCompletionSource().Task, () => cpu, stop, TimeSpan.FromMilliseconds(200), TimeSpan.FromMinutes(1), Poll);
        Assert.True(stop.IsCancellationRequested);
    }

    [Fact]
    public async Task A_slow_call_that_keeps_using_CPU_is_not_reported_as_a_hang()
    {
        using var stop = new CancellationTokenSource();
        var cpu = TimeSpan.Zero;
        var call = Task.Delay(TimeSpan.FromMilliseconds(600));
        await ContractSweep.StalledAsync(call, () => cpu += TimeSpan.FromMilliseconds(20), stop, TimeSpan.FromMilliseconds(200), TimeSpan.FromMinutes(1), Poll);
        Assert.False(stop.IsCancellationRequested);
    }

    [Fact]
    public async Task A_call_that_spins_on_CPU_is_ended_at_the_backstop()
    {
        using var stop = new CancellationTokenSource();
        var cpu = TimeSpan.Zero;
        await ContractSweep.StalledAsync(new TaskCompletionSource().Task, () => cpu += TimeSpan.FromMilliseconds(20), stop,
            TimeSpan.FromMilliseconds(200), TimeSpan.FromMilliseconds(400), Poll);
        Assert.True(stop.IsCancellationRequested);
    }
}
