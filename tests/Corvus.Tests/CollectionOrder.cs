using Xunit.Abstractions;
using Xunit.Sdk;

[assembly: TestCollectionOrderer("Corvus.Tests.SharedCollectionsFirst", "Corvus.Tests")]

namespace Corvus.Tests;

/// <summary>
/// Collections shared by several classes (the in-process catalog, the external tool environment) run their classes one
/// after another; started first, they overlap the rest of the run instead of ending it alone.
/// </summary>
public sealed class SharedCollectionsFirst : ITestCollectionOrderer
{
    private readonly DefaultTestCollectionOrderer _default = new();

    public IEnumerable<ITestCollection> OrderTestCollections(IEnumerable<ITestCollection> testCollections) =>
        _default.OrderTestCollections(testCollections).OrderBy(c => c.CollectionDefinition == null);
}
