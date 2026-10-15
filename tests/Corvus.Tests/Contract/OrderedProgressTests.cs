using Corvus.Tools;
using ModelContextProtocol;
using ModelContextProtocol.Protocol;

namespace Corvus.Tests;

/// <summary>OrderedProgress coalescing: intermediate updates within MinInterval are held back, and none is lost at the end.</summary>
public class OrderedProgressTests
{
    private static ProgressNotificationValue Update(float progress, string message) => new() { Progress = progress, Total = 3, Message = message };

    [Fact]
    public void A_final_update_follows_the_latest_skipped_phase()
    {
        var progress = new OrderedProgress(null!);
        string Sent(ProgressNotificationValue value, long now) => string.Join(",", progress.Next(value, now).Select(v => v.Message));
        Assert.Equal("started", Sent(Update(0, "started"), 0));
        Assert.Equal("", Sent(Update(1, "compiling"), 10));      // within MinInterval: held back
        Assert.Equal("", Sent(Update(2, "applying"), 20));       // replaces the held-back update
        Assert.Equal("applying,done", Sent(Update(3, "done"), 30));
    }
}
