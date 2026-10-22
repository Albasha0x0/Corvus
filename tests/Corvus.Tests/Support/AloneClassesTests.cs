namespace Corvus.Tests;

/// <summary>The classes a quick run starts in a test process of their own: those whose collection runs alone.</summary>
public sealed class AloneClassesTests
{
    [Fact]
    public void Classes_in_a_collection_that_runs_alone_are_listed_with_their_nesting_and_no_others()
    {
        var names = AloneClasses.Names(typeof(AloneClassesTests).Assembly);
        Assert.Contains(nameof(PoolStarvationTests), names);
        Assert.Contains(nameof(ConcurrencyTests), names);
        Assert.Contains($"{nameof(FileIsolationTests)}+{nameof(FileIsolationTests.InProcessParsingVariable)}", names);
        // A shared collection that runs beside the others, and the outer class of a listed nested one.
        Assert.DoesNotContain(nameof(ExternalToolsTests), names);
        Assert.DoesNotContain(nameof(FileIsolationTests), names);
    }
}
