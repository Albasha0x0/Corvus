using Corvus.Native.Providers;

namespace Corvus.Tests;

/// <summary><see cref="NativeOpenOptions.OpenWindow"/>: the limit and analysis budget of an engine open.</summary>
public class OpenWindowTests
{
    [Fact]
    public void An_open_has_no_time_limit_and_a_30_minute_stall_window_by_default()
    {
        var (limit, budget, stall) = new NativeOpenOptions().OpenWindow(TimeSpan.FromHours(3));
        Assert.Equal(Timeout.InfiniteTimeSpan, limit);
        Assert.Equal(TimeSpan.FromDays(7), budget);
        Assert.Equal(TimeSpan.FromMinutes(30), stall);
    }

    [Fact]
    public void A_zero_stall_window_turns_the_stall_check_off()
    {
        var o = new NativeOpenOptions { AnalysisStall = TimeSpan.Zero };
        Assert.Null(o.OpenWindow(TimeSpan.Zero).Stall);
        Assert.Null(o.StallLimit);
    }

    [Fact]
    public void A_set_open_limit_leaves_time_to_save_and_keeps_the_stall_window()
    {
        var o = new NativeOpenOptions { OpenTimeout = TimeSpan.FromMinutes(20) };
        var (limit, budget, stall) = o.OpenWindow(TimeSpan.FromMinutes(10));
        Assert.Equal(TimeSpan.FromMinutes(10), limit);
        Assert.Equal(TimeSpan.FromMinutes(8), budget);
        Assert.Equal(TimeSpan.FromMinutes(30), stall);
    }

    [Fact]
    public void A_set_budget_is_kept_beside_the_stall_window()
    {
        var o = new NativeOpenOptions { AnalysisBudget = TimeSpan.FromHours(2), AnalysisStall = TimeSpan.FromMinutes(5) };
        var (limit, budget, stall) = o.OpenWindow(TimeSpan.Zero);
        Assert.Equal(Timeout.InfiniteTimeSpan, limit);
        Assert.Equal(TimeSpan.FromHours(2), budget);
        Assert.Equal(TimeSpan.FromMinutes(5), stall);
    }

    [Fact]
    public void An_open_past_its_limit_keeps_one_second()
    {
        var (limit, _, _) = new NativeOpenOptions { OpenTimeout = TimeSpan.FromMinutes(1) }.OpenWindow(TimeSpan.FromMinutes(2));
        Assert.Equal(TimeSpan.FromSeconds(1), limit);
    }

    [Fact]
    public void A_reanalysis_without_a_budget_has_no_request_limit()
    {
        Assert.Equal(Timeout.InfiniteTimeSpan, EngineControl.ReanalysisTimeout(null));
        Assert.Equal(TimeSpan.FromSeconds(900), EngineControl.ReanalysisTimeout(600));
    }
}
