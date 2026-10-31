using Corvus.Native.Providers;

namespace Corvus.Tests;

/// <summary><see cref="NativeOpenOptions.OpenWindow"/>: the limit and analysis budget of an engine open.</summary>
public class OpenWindowTests
{
    [Fact]
    public void A_stall_limit_lifts_the_open_time_limit_and_the_analysis_budget()
    {
        var o = new NativeOpenOptions { OpenTimeout = TimeSpan.FromMinutes(20), AnalysisStall = TimeSpan.FromMinutes(5) };
        var (limit, budget, stall) = o.OpenWindow(TimeSpan.FromMinutes(1));
        Assert.Equal(Timeout.InfiniteTimeSpan, limit);
        Assert.Equal(TimeSpan.FromDays(7), budget);
        Assert.Equal(TimeSpan.FromMinutes(5), stall);
    }

    [Fact]
    public void Without_a_stall_limit_the_budget_leaves_time_to_save_inside_the_open_limit()
    {
        var o = new NativeOpenOptions { OpenTimeout = TimeSpan.FromMinutes(20), AnalysisStall = TimeSpan.Zero };
        var (limit, budget, stall) = o.OpenWindow(TimeSpan.FromMinutes(10));
        Assert.Equal(TimeSpan.FromMinutes(10), limit);
        Assert.Equal(TimeSpan.FromMinutes(8), budget);
        Assert.Null(stall);
    }

    [Fact]
    public void A_set_budget_is_kept_beside_a_stall_limit()
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
}
