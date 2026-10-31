using Microsoft.Extensions.Time.Testing;
using Corvus.Core;
using Corvus.Tools;

namespace Corvus.Tests;

/// <summary>The stall rule shared by worker requests.</summary>
public sealed class StallRuleTests
{
    private static readonly TimeSpan Window = TimeSpan.FromMinutes(10);

    [Fact]
    public void A_worker_using_CPU_is_not_stalled_however_long_it_runs()
    {
        var clock = new FakeTimeProvider();
        var rule = new StallRule(Window, clock);
        var cpu = TimeSpan.Zero;
        for (int minute = 0; minute < 180; minute++)
        {
            clock.Advance(TimeSpan.FromMinutes(1));
            cpu += TimeSpan.FromSeconds(6);
            Assert.False(rule.Stalled(cpu));
        }
    }

    [Fact]
    public void A_worker_reporting_progress_is_not_stalled_with_idle_CPU()
    {
        var clock = new FakeTimeProvider();
        var rule = new StallRule(Window, clock);
        for (int minute = 0; minute < 120; minute++)
        {
            clock.Advance(TimeSpan.FromMinutes(1));
            rule.Progress("entry " + minute);
            Assert.False(rule.Stalled(TimeSpan.Zero));
        }
    }

    [Fact]
    public void A_silent_idle_worker_is_stalled_after_the_window_and_names_its_last_unit()
    {
        var clock = new FakeTimeProvider();
        var rule = new StallRule(Window, clock);
        rule.Progress("entry 7");
        Assert.False(rule.Stalled(TimeSpan.Zero));
        var stalledAt = TimeSpan.Zero;
        for (int minute = 1; minute <= 30 && stalledAt == TimeSpan.Zero; minute++)
        {
            clock.Advance(TimeSpan.FromMinutes(1));
            if (rule.Stalled(TimeSpan.Zero)) stalledAt = TimeSpan.FromMinutes(minute);
        }
        Assert.Equal(Window, stalledAt);
        Assert.Equal("last progress: entry 7", rule.LastUnitText);
    }

    [Fact]
    public void A_silent_worker_with_unreadable_CPU_is_stalled_after_the_window()
    {
        var clock = new FakeTimeProvider();
        var rule = new StallRule(Window, clock);
        clock.Advance(Window);
        Assert.True(rule.Stalled(null));
        Assert.Equal("no progress unit was reported", rule.LastUnitText);
    }

    [Fact]
    public void The_stall_error_names_the_retry_call_and_the_window_variable()
    {
        var e = FileIsolation.Stalled(new ToolError(ErrorCode.Timeout, StallRule.MessagePrefix + "file_extract' (last progress: entry 7)"), "extract_container", "a.apk");
        Assert.Equal(ErrorCode.Timeout, e.Code);
        Assert.Contains("last progress: entry 7", e.Message);
        Assert.Contains("repeat the same extract_container call", e.Remediation!);
        Assert.Contains(ServerOptions.StallWindowVariable, e.Remediation!);
        Assert.False(e.Retryable);
    }
}
