using Corvus.Core;

namespace Corvus.Tests;

public sealed class WaitStopTests
{
    private const string Idle = "no stop within 30 s; the session is running";

    [Fact]
    public async Task A_session_that_never_stops_ends_with_its_last_progress()
    {
        var events = 0;
        var text = await LiveToolCalls.WaitStop(
            async () => { await Task.Delay(40); return Idle; },
            () => Task.FromResult(Math.Min(++events, 3)),
            new StallRule(TimeSpan.FromMilliseconds(100)));
        Assert.Contains(Idle, text);
        Assert.Contains("last progress: 3 event lines", text);
    }

    [Fact]
    public async Task Growing_events_keep_the_wait_going_until_a_stop_arrives()
    {
        var slices = 0;
        var events = 0;
        var text = await LiveToolCalls.WaitStop(
            async () => { await Task.Delay(40); return ++slices < 8 ? Idle : "stopped at s1"; },
            () => Task.FromResult(++events),
            new StallRule(TimeSpan.FromMilliseconds(100)));
        Assert.Equal("stopped at s1", text);
    }
}
