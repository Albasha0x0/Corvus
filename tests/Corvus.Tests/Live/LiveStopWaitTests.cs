using Corvus.Core;
using Microsoft.Extensions.Time.Testing;

namespace Corvus.Tests;

public sealed class LiveStopWaitTests
{
    private const string Idle = "no stop within 30 s; the session is running";

    [Fact]
    public async Task A_stop_after_a_minute_of_growing_events_is_returned()
    {
        var clock = new FakeTimeProvider();
        var events = 0;
        var slices = 0;
        var text = await LiveToolCalls.WaitStop(
            () => { clock.Advance(TimeSpan.FromSeconds(30)); return Task.FromResult(++slices < 3 ? Idle : "stopped at s1"); },
            () => Task.FromResult(++events),
            new StallRule(TimeSpan.FromSeconds(45), clock));
        Assert.Equal("stopped at s1", text);
    }

    [Fact]
    public async Task A_stalled_wait_ends_with_the_stall_text()
    {
        var clock = new FakeTimeProvider();
        var text = await LiveToolCalls.WaitStop(
            () => { clock.Advance(TimeSpan.FromSeconds(30)); return Task.FromResult(Idle); },
            () => Task.FromResult(4),
            new StallRule(TimeSpan.FromSeconds(45), clock));
        Assert.Contains(Idle, text);
        Assert.Contains("last progress: 4 event lines", text);
    }

    [Fact]
    public async Task A_held_thread_found_after_a_minute_of_growing_events_is_returned()
    {
        var clock = new FakeTimeProvider();
        var events = 0;
        var probes = 0;
        var found = await LiveToolCalls.Poll(
            () => { clock.Advance(TimeSpan.FromSeconds(10)); return Task.FromResult(++probes < 8 ? null : "7"); },
            () => Task.FromResult(++events),
            new StallRule(TimeSpan.FromSeconds(45), clock));
        Assert.Equal("7", found);
    }

    [Fact]
    public async Task A_poll_without_new_events_ends_empty_after_the_window()
    {
        var clock = new FakeTimeProvider();
        var found = await LiveToolCalls.Poll(
            () => { clock.Advance(TimeSpan.FromSeconds(10)); return Task.FromResult<string?>(null); },
            () => Task.FromResult(4),
            new StallRule(TimeSpan.FromSeconds(45), clock));
        Assert.Null(found);
    }
}
