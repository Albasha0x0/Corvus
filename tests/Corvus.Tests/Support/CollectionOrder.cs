using Xunit.Abstractions;
using Xunit.Sdk;

[assembly: TestCollectionOrderer("Corvus.Tests.LongCollectionsFirst", "Corvus.Tests")]

namespace Corvus.Tests;

/// <summary>
/// Collections shared by several classes (the external tool environment, the sweeps) run their classes one after another,
/// and a few classes run several seconds each (stdio servers, sweeps); started first, they overlap the rest of the run
/// instead of ending it alone.
/// </summary>
public sealed class LongCollectionsFirst : ITestCollectionOrderer
{
    // The quick set's longest classes in a parallel run (trx timings); keep the list to the top few.
    private static readonly string[] LongClasses =
    [
        "McpProtocolTests+Notifications", "McpProtocolTests+Tools", "McpProtocolTests+Discovery", "McpProtocolTests+Cancellation",
        "McpProtocolTests+Lifetime", "McpProtocolTests+Concurrency", "McpProtocolTests+Errors", "ContractSweepTests", "QuickSweepTests",
        "ProtocolSampleTests", "ToolCliTests", "ToolsetTests", "WorkerConnectionTests", "WorkerSessionBaseTests", "SimplifyTests",
        "SaveFidelityTests", "CSharpAdvancedTests", "DeviceTests",
        // The full set's longest engine classes (2-8 min each): started late, they end the run alone.
        "EngineOutputTests+LargestFunction", "EngineControlRealTests+GhidraOpenStages", "EngineControlRealTests+GhidraPartialAnalysis",
        "NativeIdaEngineTests", "NativeIdaFormatsTests", "NativeGhidraEngineTests+Types", "ToolPackageTests",
        "NativeEngineEditTests+GhidraDefineAndOperands", "NativeEditParityTests+GhidraComments", "NativeGhidraEditTests",
        "NativeGhidraColdOpenTests", "NativeTypeEditEngineTests+GhidraRenames", "NativeTypeEditEngineTests+GhidraMembers",
    ];

    private readonly DefaultTestCollectionOrderer _default = new();

    public IEnumerable<ITestCollection> OrderTestCollections(IEnumerable<ITestCollection> testCollections) =>
        _default.OrderTestCollections(testCollections).OrderBy(c => c.CollectionDefinition != null ? 0
            : LongClasses.Any(l => c.DisplayName.EndsWith("." + l, StringComparison.Ordinal)) ? 1 : 2);
}
