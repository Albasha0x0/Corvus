namespace Corvus.Tests;

public sealed class EngineSeedTests
{
    /// <summary>A reopened cache keeps its database (and the edits in it): the seed goes only into a cache without an entry of that engine.</summary>
    [Fact]
    public void A_cache_with_an_entry_of_the_engine_is_left_as_it_is()
    {
        using var dir = new TempDir();
        Directory.CreateDirectory(Path.Combine(dir.File("cache"), "ghidra", "edited"));
        Directory.CreateDirectory(Path.Combine(dir.File("cache"), "ida", "edited"));
        EngineSeed.Copy(dir.File("cache"), Env.FixturePath);
        Assert.Empty(Directory.GetFiles(dir.File("cache"), "*", SearchOption.AllDirectories));
    }
}
