using Corvus.Native;
using Corvus.Services;

namespace Corvus.Tests;

/// <summary>The expected first-analysis time: an initial rate on the code size, refined from measured opens stored in the cache root.</summary>
public sealed class OpenEstimateTests : IDisposable
{
    private readonly TempDir _dir = new();

    public void Dispose() => _dir.Dispose();

    [Fact]
    public void An_engine_with_no_history_uses_its_initial_rate_on_the_code_size()
    {
        var estimate = new OpenEstimate(_dir.Path);
        Assert.Equal(20, estimate.Seconds("ida", 10L << 20));
        Assert.Equal(80, estimate.Seconds("ghidra", 10L << 20));
        Assert.Equal(5, estimate.Seconds("ida", 1000));
    }

    [Fact]
    public void Measured_opens_replace_only_that_engines_initial_rate()
    {
        var estimate = new OpenEstimate(_dir.Path);
        estimate.Record("ida", 10L << 20, 100);
        estimate.Record("ida", 10L << 20, 100);
        estimate.Record("ida", 10L << 20, 400);
        Assert.Equal(50, new OpenEstimate(_dir.Path).Seconds("ida", 5L << 20));
        Assert.Equal(40, estimate.Seconds("ghidra", 5L << 20));
    }

    [Fact]
    public void A_corrupt_history_file_falls_back_to_the_initial_rate()
    {
        File.WriteAllText(Path.Combine(_dir.Path, OpenEstimate.FileName), "{ not json");
        Assert.Equal(20, new OpenEstimate(_dir.Path).Seconds("ida", 10L << 20));
    }

    [Fact]
    public void The_history_keeps_only_the_newest_samples_of_an_engine()
    {
        var estimate = new OpenEstimate(_dir.Path);
        for (int i = 0; i < OpenEstimate.MaxSamples; i++) estimate.Record("ida", 1L << 20, 100);
        for (int i = 0; i < OpenEstimate.MaxSamples; i++) estimate.Record("ida", 1L << 20, 10);
        Assert.Equal(10, estimate.Seconds("ida", 1L << 20));
    }

    [Fact]
    public void The_median_of_an_even_count_of_unordered_samples_is_used()
    {
        var estimate = new OpenEstimate(_dir.Path);
        foreach (var seconds in new double[] { 40, 10, 30, 20 }) estimate.Record("ida", 1L << 20, seconds);
        Assert.Equal(30, estimate.Seconds("ida", 1L << 20));
    }

    [Fact]
    public void Invalid_samples_in_the_history_are_ignored()
    {
        var path = Path.Combine(_dir.Path, OpenEstimate.FileName);
        File.WriteAllText(path, "{\"ida\":[[0,5],[-1,5],[1048576,0]]}");
        Assert.Equal(20, new OpenEstimate(_dir.Path).Seconds("ida", 10L << 20));
        File.WriteAllText(path, "{\"ida\":[[1048576,1e308]]}");
        Assert.Equal(86400, new OpenEstimate(_dir.Path).Seconds("ida", 10L << 20));
    }

    [Fact]
    public void Only_an_open_with_an_analysis_stage_of_a_second_is_recorded()
    {
        var estimate = new OpenEstimate(_dir.Path);
        Assert.False(estimate.RecordOpen("ida", 10L << 20, 0.4, 100));
        Assert.Equal(20, estimate.Seconds("ida", 10L << 20));
        Assert.True(estimate.RecordOpen("ida", 10L << 20, 1, 100));
        Assert.Equal(100, estimate.Seconds("ida", 10L << 20));
    }

    [Fact]
    public void Code_bytes_sum_only_the_executable_sections()
    {
        var sections = new[]
        {
            new NativeSection(".text", 0x1000, 300, 0, 200, SectionAccess.Execute, 0),
            new NativeSection(".data", 0x2000, 5000, 0, 100, SectionAccess.Read, 0),
            new NativeSection(".code", 0x3000, 0, 0, 40, SectionAccess.Code, 0),
        };
        Assert.Equal(340, OpenEstimate.CodeBytes(sections));
    }
}
