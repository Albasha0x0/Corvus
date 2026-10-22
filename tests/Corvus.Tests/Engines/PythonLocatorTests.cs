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
        fake.On("^-I -c ", stdout: $"3 12 64\n{python}\n", sleepMs: 3000);
        using var env = new EnvironmentScope().Set(FakeTool.ScriptVariable, fake.ScriptPath);

        var log = new List<string>();
        var (late, unanswered) = PythonLocator.Search([(python, "configured")], log, TimeSpan.FromMilliseconds(300), defaults: false);
        Assert.Equal((null, true), (late, unanswered));
        Assert.Contains("did not answer within", Assert.Single(log));

        var (found, _) = PythonLocator.Search([(python, "configured")], [], TimeSpan.FromSeconds(60), defaults: false);
        Assert.Equal((python, new Version(3, 12), 64, "configured"), (found?.Executable, found?.Version, found?.Bits, found?.Source));
    }
}
