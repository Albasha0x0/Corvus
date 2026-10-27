using Corvus.Native.Providers;

namespace Corvus.Tests;

/// <summary>The Python search for the engine and session workers: a slow interpreter is unknown, not refused.</summary>
[Collection(ExternalToolEnvironmentCollection.Name)]
public class PythonLocatorTests
{
    [Fact]
    public void A_python_that_answers_late_is_unknown_and_found_by_a_search_with_more_time()
    {
        using var fake = new FakeTool();
        var python = fake.CopyAs("python");
        fake.On("^-I -c ", stdout: $"3 12 64\n{python}\n");
        // Regression (f0035bbb): a fixed 3 s answer reached a starved probe; the interpreter answers only after the first search ends.
        var gate = Path.Combine(fake.Directory, "gate");
        fake.Set("barriers", new System.Text.Json.Nodes.JsonObject
        {
            ["-I -c " + PythonLocator.ProbeScript] = new System.Text.Json.Nodes.JsonObject
            {
                ["touch"] = Path.Combine(fake.Directory, "asked"), ["waitFor"] = gate, ["seconds"] = 120,
            },
        });
        using var env = new EnvironmentScope().Set(FakeTool.ScriptVariable, fake.ScriptPath);

        var log = new List<string>();
        var (late, unanswered) = PythonLocator.Search([(python, "configured")], log, TimeSpan.FromMilliseconds(300), defaults: false);
        Assert.Equal((null, true), (late, unanswered));
        Assert.Contains("did not answer within", Assert.Single(log));

        File.WriteAllText(gate, "");
        var (found, _) = PythonLocator.Search([(python, "configured")], [], TimeSpan.FromSeconds(60), defaults: false);
        Assert.Equal((python, new Version(3, 12), 64, "configured"), (found?.Executable, found?.Version, found?.Bits, found?.Source));
    }

    [Fact]
    public void A_capped_wait_outlasts_its_limit_while_the_tree_uses_CPU_and_names_the_limit_that_stops_it()
    {
        // Regression (e0381416): idalib Python probes got no answer in 15 s under load. A virtual clock advances by each wait.
        var limit = TimeSpan.FromSeconds(1);
        bool Wait(Func<TimeSpan, bool> exited, Func<TimeSpan, TimeSpan?> cpu, TimeSpan cap, out string? stopped, out TimeSpan at)
        {
            var now = TimeSpan.Zero;
            var done = PythonLocator.WaitWhileBusy(w => exited(now += w), () => cpu(now), () => now, limit, cap, out stopped);
            at = now;
            return done;
        }

        // 1% of a core: a start squeezed by a busy machine, which answers after three limits.
        Assert.True(Wait(t => t >= 3 * limit, t => t * 0.01, 10 * limit, out _, out var answered));
        Assert.Equal(3 * limit, answered);
        Assert.False(Wait(_ => false, _ => TimeSpan.FromSeconds(2), 10 * limit, out var stopped, out var at));
        Assert.Equal(("did not answer within 1 s spent under 0.1% of a core", limit), (stopped, at));
        Assert.False(Wait(_ => false, t => t, 3 * limit, out stopped, out at));
        Assert.Equal(("did not answer within its overall limit of 3 s", 3 * limit), (stopped, at));
        Assert.False(Wait(_ => false, _ => null, 3 * limit, out stopped, out at));
        Assert.Equal(("did not answer within 1 s", limit), (stopped, at));
    }

    [Fact]
    public void A_capped_run_of_an_idle_child_stops_at_its_limit_and_names_it()
    {
        using var fake = new FakeTool();
        fake.On("slow", sleepMs: 20_000, stdout: "late");
        var clock = System.Diagnostics.Stopwatch.StartNew();
        var run = PythonLocator.RunCapture(FakeTool.Executable, ["slow"], TimeSpan.FromMilliseconds(500), fake.Environment, cap: TimeSpan.FromSeconds(15));
        Assert.True(run.TimedOut);
        Assert.Equal("did not answer within 0.5 s spent under 0.1% of a core", run.Stopped);
        Assert.True(clock.Elapsed < TimeSpan.FromSeconds(15), $"{clock.Elapsed}");
    }
}
