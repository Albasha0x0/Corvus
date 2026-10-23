using Xunit.Abstractions;
using Xunit.Sdk;

namespace Corvus.Tests;

/// <summary>RunTimeSkip: facts whose skip check starts processes decide it when they run, not at discovery.</summary>
public class RunTimeSkipTests
{
    [Fact]
    public void A_dotnet_target_fact_checks_nothing_when_made_and_gives_its_reason_when_run()
    {
        // The target of the other operating system, whose check ends before any process starts.
        var other = OperatingSystem.IsWindows() ? "linux-x64" : "win-x64";
        var reason = $"{other} programs run on {(OperatingSystem.IsWindows() ? "Linux" : "Windows")}.";
        Assert.Null(new DotnetTargetFactAttribute(other).Skip);
        Assert.Null(new SnapshotRunsFactAttribute(other).Skip);
        Assert.Equal(reason, new DotnetTargetFactAttribute(other).RunTimeSkip());
        Assert.Equal(reason, new SnapshotRunsFactAttribute(other).RunTimeSkip());
    }

    [Fact]
    public void Every_run_time_skip_attribute_names_the_discoverer_that_asks_it()
    {
        var attributes = typeof(IRunTimeSkip).Assembly.GetTypes().Where(t => typeof(IRunTimeSkip).IsAssignableFrom(t) && !t.IsInterface).ToList();
        Assert.NotEmpty(attributes);
        foreach (var type in attributes)
        {
            var discoverer = type.GetCustomAttributesData().Single(a => a.AttributeType == typeof(Xunit.Sdk.XunitTestCaseDiscovererAttribute));
            var expected = typeof(TheoryAttribute).IsAssignableFrom(type) ? RunTimeSkips.TheoryDiscoverer : RunTimeSkips.FactDiscoverer;
            Assert.Equal([expected, RunTimeSkips.Assembly], discoverer.ConstructorArguments.Select(a => (string)a.Value!));
            Assert.NotNull(Type.GetType($"{expected}, {RunTimeSkips.Assembly}"));
        }
    }

    [Fact]
    public void A_case_its_attribute_skips_when_it_runs_takes_no_permit()
    {
        var skipped = OperatingSystem.IsWindows() ? nameof(PermitSample.OnLinux) : nameof(PermitSample.OnWindows);
        Assert.Empty(MachinePermits.Needed([Case(skipped)]));
        Assert.Equal(["live"], MachinePermits.Needed([Case(nameof(PermitSample.Plain))]));
    }

    private static XunitTestCase Case(string method)
    {
        var assembly = new TestAssembly(Reflector.Wrap(typeof(PermitSample).Assembly));
        var testClass = new TestClass(new TestCollection(assembly, null, nameof(PermitSample)), Reflector.Wrap(typeof(PermitSample)));
        var testMethod = new TestMethod(testClass, Reflector.Wrap(typeof(PermitSample).GetMethod(method)!));
        return new XunitTestCase(new NullMessageSink(), TestMethodDisplay.ClassAndMethod, TestMethodDisplayOptions.None, testMethod);
    }

    // Abstract, so discovery leaves its methods out.
    [Permit("live")]
    public abstract class PermitSample
    {
        [DotnetTargetFact("linux-x64")] public void OnLinux() { }
        [DotnetTargetFact("win-x64")] public void OnWindows() { }
        public void Plain() { }
    }
}
