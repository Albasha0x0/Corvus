using Xunit.Abstractions;
using Xunit.Sdk;

namespace Corvus.Tests;

/// <summary>
/// How the assembly runner schedules a collection that needs machine permits.
/// </summary>
public sealed class PermitSchedulingTests
{
    [Fact]
    public async Task A_collection_with_its_permits_runs_while_every_parallel_slot_is_taken()
    {
        // One parallel slot, held by a collection that ends only when the
        // permit collection has run.
        PermitSchedulingFixtures.Reset();
        var results = new ResultSink();
        var assembly = new TestAssembly(Reflector.Wrap(typeof(PermitSchedulingFixtures).Assembly));
        IXunitTestCase Case(Type type, string method)
        {
            var collection = new TestCollection(assembly, null, $"Test collection for {type.FullName}");
            var testClass = new TestClass(collection, Reflector.Wrap(type));
            return new XunitTestCase(new NullSink(), TestMethodDisplay.Method, TestMethodDisplayOptions.None,
                new TestMethod(testClass, testClass.Class.GetMethod(method, false)));
        }
        var cases = new[]
        {
            Case(typeof(PermitSchedulingFixtures.SlotHolder), nameof(PermitSchedulingFixtures.SlotHolder.Holds_the_slot_until_released)),
            Case(typeof(PermitSchedulingFixtures.PermitHolder), nameof(PermitSchedulingFixtures.PermitHolder.Releases_the_slot_holder)),
        };
        var options = new Options();
        options.SetValue("xunit.execution.MaxParallelThreads", 1);
        options.SetValue("xunit.execution.DisableParallelization", false);
        using var runner = new LeakGuardFramework.Runner(assembly, cases, new NullSink(), results, options, checkLeaks: false);
        var summary = await runner.RunAsync().WaitAsync(TimeSpan.FromMinutes(2));
        Assert.True(summary.Failed == 0, string.Join("\n", results.Failures));
        Assert.Equal(2, summary.Total);
    }

    private sealed class NullSink : LongLivedMarshalByRefObject, IMessageSink
    {
        public bool OnMessage(IMessageSinkMessage message) => true;
    }

    private sealed class ResultSink : LongLivedMarshalByRefObject, IMessageSink
    {
        public List<string> Failures { get; } = [];

        public bool OnMessage(IMessageSinkMessage message)
        {
            if (message is ITestFailed failed)
                lock (Failures) Failures.Add($"{failed.Test.DisplayName}: {string.Join(" ", failed.Messages)}");
            return true;
        }
    }

    private sealed class Options : ITestFrameworkExecutionOptions
    {
        private readonly Dictionary<string, object?> _values = [];

        public TValue GetValue<TValue>(string name) => _values.TryGetValue(name, out var v) && v is TValue t ? t : default!;

        public void SetValue<TValue>(string name, TValue value) => _values[name] = value;
    }
}

#pragma warning disable xUnit1000
/// <summary>
/// Test classes the runner test schedules; internal, so discovery leaves them
/// out of every run.
/// </summary>
internal static class PermitSchedulingFixtures
{
    private static TaskCompletionSource _released = new(TaskCreationOptions.RunContinuationsAsynchronously);

    public static void Reset() => _released = new(TaskCreationOptions.RunContinuationsAsynchronously);

    internal sealed class SlotHolder
    {
        // A permit collection queued behind this slot never runs, so the wait times out.
        [Fact]
        public async Task Holds_the_slot_until_released() => await _released.Task.WaitAsync(TimeSpan.FromSeconds(30));
    }

    [Permit("reference-tool")]
    internal sealed class PermitHolder
    {
        [Fact]
        public void Releases_the_slot_holder() => _released.TrySetResult();
    }
}
#pragma warning restore xUnit1000
