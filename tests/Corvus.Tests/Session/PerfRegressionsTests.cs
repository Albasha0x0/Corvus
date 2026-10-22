namespace Corvus.Tests;

public sealed class PerfRegressionsTests
{
    [Fact]
    public void A_regression_is_the_median_of_each_samples_worst_value_past_one_and_a_half_times_its_baseline()
    {
        static PerfRegressions.Measurement M(string name, double value, string op = "<=", string unit = "ms") => new("C.T", name, value, unit, op);
        IReadOnlyList<IReadOnlyList<PerfRegressions.Measurement>> samples =
        [
            [M("a", 16), M("a", 5), M("b", 16), M("r", 19, ">=", "MB/s"), M("nobase", 999), M("units", 99)],
            [M("a", 20), M("b", 1), M("r", 25, ">=", "MB/s")],
            [M("a", 14), M("b", 1), M("r", 18, ">=", "MB/s")],
        ];
        (double, string)? Baseline(string name) => name switch
        {
            "a" or "b" => (10, "ms"), "r" => (30, "MB/s"), "units" => (10, "s"), _ => null,
        };
        var found = PerfRegressions.Find(samples, Baseline);
        // a: worst per sample 16, 20, 14, median 16 > 15; b: median 1; r: median 19 < 20; no baseline or another unit: skipped.
        Assert.Equal(["a", "r"], found.Select(r => r.Name));
        Assert.Equal("a: median 16 ms of 3 sample(s), baseline <= 10 ms", found[0].Text);
        Assert.Equal(["C.T"], found[0].Tests);
    }

    [Fact]
    public void A_perf_line_is_read_from_a_trx_file_under_its_test_name()
    {
        using var dir = new TempDir();
        var trx = dir.File("perf.trx");
        File.WriteAllText(trx, """
            <TestRun xmlns="http://microsoft.com/schemas/VisualStudio/TeamTest/2010">
              <Results>
                <UnitTestResult testId="1" outcome="Passed"><Output><StdOut>other
            perf: containers/x 12.5 ms (budget &lt;= 100 ms) over budget; note
            perf: bad line</StdOut></Output></UnitTestResult>
              </Results>
              <TestDefinitions>
                <UnitTest id="1"><TestMethod className="Corvus.Tests.Outer+Inner" name="Case" /></UnitTest>
              </TestDefinitions>
            </TestRun>
            """);
        var m = Assert.Single(PerfRegressions.Read(trx));
        Assert.Equal(new PerfRegressions.Measurement("Corvus.Tests.Outer+Inner.Case", "containers/x", 12.5, "ms", "<="), m);
    }
}
