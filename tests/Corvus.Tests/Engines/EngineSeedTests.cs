using Xunit.Abstractions;

namespace Corvus.Tests;

public sealed class EngineSeedTests(ITestOutputHelper output)
{
    /// <summary>Seeds analysed cold again per run, a different set each day; unset, the check does not run.</summary>
    public const string ValidateVariable = "CORVUS_SEED_VALIDATE";

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

    [Fact, Trait("Speed", "Slow")]
    public void Seeds_match_a_cold_analysis_of_their_input()
    {
        if (!int.TryParse(Environment.GetEnvironmentVariable(ValidateVariable), out var count) || count <= 0)
        {
            output.WriteLine($"{ValidateVariable} is not set");
            return;
        }
        var differences = EngineSeed.Validate(count);
        Assert.True(differences.Count == 0, "seeds that differ from a cold analysis (removed):\n" + string.Join('\n', differences));
    }
}
