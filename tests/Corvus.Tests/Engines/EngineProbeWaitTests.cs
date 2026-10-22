using Corvus.Core;
using Corvus.Native.Providers.Ida;

namespace Corvus.Tests;

/// <summary>A call waiting for an engine's availability check (it locates Python or Java by running them) stops when the call is cancelled (D4).</summary>
public sealed class EngineProbeWaitTests
{
    [Fact]
    [Trait(PerfBudget.Trait, PerfBudget.Timing)]
    public async Task A_cancelled_call_stops_waiting_for_the_availability_check()
    {
        var provider = new IdaProvider(new IdaProviderOptions { InstallDirectory = Path.Combine(Path.GetTempPath(), "corvus-no-ida-" + Guid.NewGuid().ToString("N")) });
        using var held = new ManualResetEventSlim();
        using var release = new ManualResetEventSlim();
        var holder = Task.Run(() =>
        {
            lock (provider.AvailabilityLock)
            {
                held.Set();
                release.Wait();
            }
        });
        held.Wait();
        using var cts = new CancellationTokenSource(TimeSpan.FromMilliseconds(200));
        var clock = System.Diagnostics.Stopwatch.StartNew();
        var waiter = Task.Run(() =>
        {
            using var scope = AssemblyWorkspace.CancelWaitsWith(cts.Token, "test");
            return provider.CheckAvailability();
        });
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => waiter);
        PerfBudget.Check(clock.Elapsed < TimeSpan.FromSeconds(5), $"the cancelled call returned after {clock.Elapsed}, budget 5 s");
        release.Set();
        await holder;
        Assert.False(provider.CheckAvailability().IsAvailable);
    }
}
