using Xunit.Abstractions;

namespace Corvus.Tests;

/// <summary>TestPhases: a step that fails names the phases completed before it.</summary>
public class TestPhasesTests
{
    private sealed class Lines : ITestOutputHelper
    {
        public List<string> All { get; } = [];
        public void WriteLine(string message) => All.Add(message);
        public void WriteLine(string format, params object[] args) => All.Add(string.Format(format, args));
    }

    [Fact]
    public async Task A_step_that_throws_names_the_last_phase_reached_and_keeps_the_original_error()
    {
        var lines = new Lines();
        var phases = new TestPhases(lines);
        Assert.Equal(1, await phases.Run("server start", () => Task.FromResult(1)));
        var cause = new TimeoutException("no answer");
        var failed = await Assert.ThrowsAsync<InvalidOperationException>(() => phases.Run<int>("list_exports", () => throw cause));
        Assert.StartsWith("list_exports did not complete; last phase server start at ", failed.Message);
        Assert.Same(cause, failed.InnerException);
        Assert.Single(lines.All, l => l.StartsWith("phase server start at ", StringComparison.Ordinal));
        Assert.DoesNotContain(lines.All, l => l.Contains("list_exports", StringComparison.Ordinal));
    }
}
