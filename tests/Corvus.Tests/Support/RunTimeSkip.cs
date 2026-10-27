using System.Reflection;
using Xunit.Abstractions;
using Xunit.Sdk;

namespace Corvus.Tests;

/// <summary>
/// A fact or theory whose skip check starts processes, so it is decided at run time rather than discovery, which builds
/// every attribute each run. Discoverers: <see cref="RunTimeSkipFactDiscoverer"/>, <see cref="RunTimeSkipTheoryDiscoverer"/>.
/// </summary>
public interface IRunTimeSkip
{
    /// <summary>Why the test is skipped, decided when it runs; null to run it.</summary>
    string? RunTimeSkip();
}

/// <summary>A test case that asks its method's <see cref="IRunTimeSkip"/> attribute for the skip reason when it runs.</summary>
public sealed class RunTimeSkipTestCase : XunitTestCase
{
    [Obsolete("Called by the deserializer only.")]
    public RunTimeSkipTestCase() { }

    public RunTimeSkipTestCase(IMessageSink diagnosticMessageSink, TestMethodDisplay display, TestMethodDisplayOptions options, ITestMethod testMethod,
        object[]? testMethodArguments = null)
        : base(diagnosticMessageSink, display, options, testMethod, testMethodArguments) { }

    public override Task<RunSummary> RunAsync(IMessageSink diagnosticMessageSink, IMessageBus messageBus, object[] constructorArguments,
        ExceptionAggregator aggregator, CancellationTokenSource cancellationTokenSource) =>
        new XunitTestCaseRunner(this, DisplayName, SkipReason ?? RunTimeSkips.Of(TestMethod), constructorArguments, TestMethodArguments, messageBus,
            aggregator, cancellationTokenSource).RunAsync();
}

/// <summary>A theory whose data is read when it runs, asking its <see cref="IRunTimeSkip"/> attribute for the skip reason first.</summary>
public sealed class RunTimeSkipTheoryTestCase : XunitTheoryTestCase
{
    [Obsolete("Called by the deserializer only.")]
    public RunTimeSkipTheoryTestCase() { }

    public RunTimeSkipTheoryTestCase(IMessageSink diagnosticMessageSink, TestMethodDisplay display, TestMethodDisplayOptions options, ITestMethod testMethod)
        : base(diagnosticMessageSink, display, options, testMethod) { }

    public override Task<RunSummary> RunAsync(IMessageSink diagnosticMessageSink, IMessageBus messageBus, object[] constructorArguments,
        ExceptionAggregator aggregator, CancellationTokenSource cancellationTokenSource) =>
        new XunitTheoryTestCaseRunner(this, DisplayName, SkipReason ?? RunTimeSkips.Of(TestMethod), constructorArguments, diagnosticMessageSink, messageBus,
            aggregator, cancellationTokenSource).RunAsync();
}

/// <summary>Discovers an <see cref="IRunTimeSkip"/> fact as a test case that decides its skip reason when it runs.</summary>
public sealed class RunTimeSkipFactDiscoverer(IMessageSink diagnosticMessageSink) : FactDiscoverer(diagnosticMessageSink)
{
    protected override IXunitTestCase CreateTestCase(ITestFrameworkDiscoveryOptions discoveryOptions, ITestMethod testMethod, IAttributeInfo factAttribute) =>
        new RunTimeSkipTestCase(DiagnosticMessageSink, discoveryOptions.MethodDisplayOrDefault(), discoveryOptions.MethodDisplayOptionsOrDefault(), testMethod);
}

/// <summary>Discovers an <see cref="IRunTimeSkip"/> theory as test cases that decide their skip reason when they run.</summary>
public sealed class RunTimeSkipTheoryDiscoverer(IMessageSink diagnosticMessageSink) : TheoryDiscoverer(diagnosticMessageSink)
{
    protected override IEnumerable<IXunitTestCase> CreateTestCasesForDataRow(ITestFrameworkDiscoveryOptions discoveryOptions, ITestMethod testMethod,
        IAttributeInfo theoryAttribute, object[] dataRow) =>
        [new RunTimeSkipTestCase(DiagnosticMessageSink, discoveryOptions.MethodDisplayOrDefault(), discoveryOptions.MethodDisplayOptionsOrDefault(), testMethod, dataRow)];

    protected override IEnumerable<IXunitTestCase> CreateTestCasesForTheory(ITestFrameworkDiscoveryOptions discoveryOptions, ITestMethod testMethod,
        IAttributeInfo theoryAttribute) =>
        [new RunTimeSkipTheoryTestCase(DiagnosticMessageSink, discoveryOptions.MethodDisplayOrDefault(), discoveryOptions.MethodDisplayOptionsOrDefault(), testMethod)];
}

/// <summary>The run-time skip reasons of test methods.</summary>
public static class RunTimeSkips
{
    /// <summary>The discoverer names an <see cref="IRunTimeSkip"/> attribute gives in its XunitTestCaseDiscoverer.</summary>
    public const string FactDiscoverer = "Corvus.Tests.RunTimeSkipFactDiscoverer", TheoryDiscoverer = "Corvus.Tests.RunTimeSkipTheoryDiscoverer", Assembly = "Corvus.Tests";

    /// <summary>The skip reason of the method's <see cref="IRunTimeSkip"/> attribute when it runs; null when it has none or runs.</summary>
    public static string? Of(ITestMethod testMethod) =>
        testMethod.Method.ToRuntimeMethod().GetCustomAttributes().OfType<IRunTimeSkip>().Select(a => a.RunTimeSkip()).FirstOrDefault(r => r != null);
}
