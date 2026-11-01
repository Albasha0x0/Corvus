using Corvus.Core;
using Corvus.Native.Providers;
using Corvus.Services.Analysis;

namespace Corvus.Tests;

/// <summary>Analysis tool errors name the call to repeat when the shared stall rule ends a run.</summary>
public sealed class ExternalToolStallTests
{
    // Task 296: the yara, TShark and malcontent ceilings.
    [Fact]
    public void A_stalled_yara_scan_is_retryable_and_names_the_variable_to_raise()
    {
        var e = YaraSearchKind.Stalled(new ToolError(ErrorCode.Timeout, "stalled on 'yara_scan'"), "a.bin");
        Assert.Equal(ErrorCode.Timeout, e.Code);
        Assert.True(e.Retryable);
        Assert.Contains("a.bin", e.Message);
        Assert.Contains("CORVUS_STALL_WINDOW", e.NextFor(null));
    }

    [Fact]
    public void A_watched_tool_writing_output_past_the_old_ceiling_is_not_stalled()
    {
        var clock = new Microsoft.Extensions.Time.Testing.FakeTimeProvider();
        var rule = new StallRule(TimeSpan.FromMinutes(10), clock);
        for (var i = 0; i < 40; i++)
        {
            clock.Advance(TimeSpan.FromMinutes(1));
            rule.Progress(null);
            Assert.False(rule.Stalled(TimeSpan.Zero));
        }
    }

    [Fact]
    public void A_silent_idle_tool_is_stalled_after_the_window()
    {
        var clock = new Microsoft.Extensions.Time.Testing.FakeTimeProvider();
        var rule = new StallRule(TimeSpan.FromMinutes(10), clock);
        var stalled = false;
        for (var i = 0; i < 12 && !stalled; i++)
        {
            clock.Advance(TimeSpan.FromMinutes(1));
            stalled = rule.Stalled(TimeSpan.Zero);
        }
        Assert.True(stalled);
    }
}
