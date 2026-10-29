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
        // engine permit collection has run.
        // Regression: a quick set beside push run 359a54f6 timed out here while
        // the push run held every machine-wide reference-tool permit.
        PermitSchedulingFixtures.Reset();
        var permits = await Run(
            (typeof(PermitSchedulingFixtures.SlotHolder), nameof(PermitSchedulingFixtures.SlotHolder.Holds_the_slot_until_released)),
            (typeof(PermitSchedulingFixtures.EnginePermitHolder), nameof(PermitSchedulingFixtures.EnginePermitHolder.Releases_the_slot_holder)));
        Assert.Contains("engine-ida", permits);
    }

    [Fact]
    public async Task A_reference_tool_collection_waits_for_a_slot_while_every_slot_is_taken()
    {
        // One parallel slot; each collection holds it for 1.5 s and fails if
        // the other runs during its hold, whichever starts first.
        // Regression: the 359a54f6 full run ran 34 classes at once on 20 slots
        // while reference-tool collections ran outside them.
        PermitSchedulingFixtures.Reset();
        var permits = await Run(
            (typeof(PermitSchedulingFixtures.BriefSlotHolder), nameof(PermitSchedulingFixtures.BriefSlotHolder.Holds_the_slot_alone)),
            (typeof(PermitSchedulingFixtures.ReferenceToolWaiter), nameof(PermitSchedulingFixtures.ReferenceToolWaiter.Holds_its_permit_alone)));
        Assert.Contains("reference-tool", permits);
    }

    // Runs the cases on one parallel slot with permits from a folder of their
    // own, deleted afterwards; returns the permit resources the run took.
    private static async Task<List<string>> Run(params (Type Type, string Method)[] tests)
    {
        var permits = Path.Combine(LeakGuard.RunTemp, "permits-" + Guid.NewGuid().ToString("N")[..8]);
        MachinePermits.FolderScope.Value = permits;
        var results = new ResultSink();
        var assembly = new TestAssembly(Reflector.Wrap(typeof(PermitSchedulingFixtures).Assembly));
        var cases = tests.Select(t =>
        {
            var collection = new TestCollection(assembly, null, $"Test collection for {t.Type.FullName}");
            var testClass = new TestClass(collection, Reflector.Wrap(t.Type));
            return (IXunitTestCase)new XunitTestCase(new NullSink(), TestMethodDisplay.Method, TestMethodDisplayOptions.None,
                new TestMethod(testClass, testClass.Class.GetMethod(t.Method, false)));
        }).ToArray();
        var options = new Options();
        options.SetValue("xunit.execution.MaxParallelThreads", 1);
        options.SetValue("xunit.execution.DisableParallelization", false);
        try
        {
            using (var runner = new LeakGuardFramework.Runner(assembly, cases, new NullSink(), results, options, checkLeaks: false))
            {
                var summary = await runner.RunAsync().WaitAsync(TimeSpan.FromMinutes(2));
                Assert.True(summary.Failed == 0, string.Join("\n", results.Failures));
                Assert.Equal(tests.Length, summary.Total);
            }
            return Directory.Exists(permits) ? Directory.GetDirectories(permits).Select(d => Path.GetFileName(d)).ToList() : [];
        }
        finally
        {
            MachinePermits.FolderScope.Value = null;
            if (Directory.Exists(permits)) Directory.Delete(permits, recursive: true);
        }
    }

    [Fact]
    public async Task A_collection_whose_permit_wait_ends_is_skipped_naming_the_holder()
    {
        var permits = Path.Combine(LeakGuard.RunTemp, "permits-" + Guid.NewGuid().ToString("N")[..8]);
        var slots = Directory.CreateDirectory(Path.Combine(permits, "reference-tool")).FullName;
        MachinePermits.FolderScope.Value = permits;
        MachinePermits.MaxWaitScope.Value = TimeSpan.FromSeconds(1);
        MachinePermits.HolderLookupScope.Value = TimeSpan.FromSeconds(20);
        var holds = new List<FileStream>();
        var results = new ResultSink();
        var assembly = new TestAssembly(Reflector.Wrap(typeof(PermitSchedulingFixtures).Assembly));
        try
        {
            // Every slot is held as live-slot.ps1 holds one, by a live process.
            for (int i = 0; i < MachinePermits.Here["reference-tool"]; i++)
            {
                holds.Add(new FileStream(Path.Combine(slots, $"slot-{i}"), FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None));
                File.WriteAllText(Path.Combine(slots, $"slot-{i}.owner"), $"{Environment.ProcessId} script");
            }
            var collection = new TestCollection(assembly, null, $"Test collection for {typeof(PermitSchedulingFixtures.ReferenceToolWaiter).FullName}");
            var testClass = new TestClass(collection, Reflector.Wrap(typeof(PermitSchedulingFixtures.ReferenceToolWaiter)));
            var cases = new IXunitTestCase[]
            {
                new XunitTestCase(new NullSink(), TestMethodDisplay.Method, TestMethodDisplayOptions.None,
                    new TestMethod(testClass, testClass.Class.GetMethod(nameof(PermitSchedulingFixtures.ReferenceToolWaiter.Holds_its_permit_alone), false))),
            };
            using var runner = new LeakGuardFramework.Runner(assembly, cases, new NullSink(), results, new Options(), checkLeaks: false);
            var summary = await runner.RunAsync().WaitAsync(TimeSpan.FromMinutes(2));
            Assert.Equal((1, 1, 0), (summary.Total, summary.Skipped, summary.Failed));
            var reason = Assert.Single(results.Skips);
            Assert.StartsWith(MachinePermits.NotRunPrefix + "reference-tool held for ", reason);
            Assert.Contains($"held by process {Environment.ProcessId}", reason);
        }
        finally
        {
            foreach (var hold in holds) hold.Dispose();
            MachinePermits.FolderScope.Value = null;
            MachinePermits.MaxWaitScope.Value = null;
            MachinePermits.HolderLookupScope.Value = null;
            Directory.Delete(permits, recursive: true);
        }
    }

    private sealed class NullSink : LongLivedMarshalByRefObject, IMessageSink
    {
        public bool OnMessage(IMessageSinkMessage message) => true;
    }

    private sealed class ResultSink : LongLivedMarshalByRefObject, IMessageSink
    {
        public List<string> Failures { get; } = [];
        public List<string> Skips { get; } = [];

        public bool OnMessage(IMessageSinkMessage message)
        {
            if (message is ITestSkipped skipped)
                lock (Skips) Skips.Add(skipped.Reason);
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
    private static int _running;

    public static void Reset()
    {
        _released = new(TaskCreationOptions.RunContinuationsAsynchronously);
        _running = 0;
    }

    // Holds for 1.5 s; fails if another fixture runs at any point of the hold.
    private static async Task HoldAlone()
    {
        Assert.Equal(1, Interlocked.Increment(ref _running));
        try
        {
            await Task.Delay(TimeSpan.FromMilliseconds(750));
            Assert.Equal(1, Volatile.Read(ref _running));
            await Task.Delay(TimeSpan.FromMilliseconds(750));
            Assert.Equal(1, Volatile.Read(ref _running));
        }
        finally { Interlocked.Decrement(ref _running); }
    }

    internal sealed class SlotHolder
    {
        // A permit collection queued behind this slot never runs, so the wait times out.
        [Fact]
        public async Task Holds_the_slot_until_released() => await _released.Task.WaitAsync(TimeSpan.FromSeconds(30));
    }

    [Permit("engine-ida")]
    internal sealed class EnginePermitHolder
    {
        [Fact]
        public void Releases_the_slot_holder() => _released.TrySetResult();
    }

    internal sealed class BriefSlotHolder
    {
        [Fact]
        public Task Holds_the_slot_alone() => HoldAlone();
    }

    [Permit("reference-tool")]
    internal sealed class ReferenceToolWaiter
    {
        [Fact]
        public Task Holds_its_permit_alone() => HoldAlone();
    }
}
#pragma warning restore xUnit1000
