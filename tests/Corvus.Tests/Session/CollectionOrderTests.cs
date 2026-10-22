namespace Corvus.Tests;

/// <summary>LongCollectionsFirst: the class times it orders collections by.</summary>
public class CollectionOrderTests
{
    [Fact]
    public void Class_times_are_the_medians_of_the_runs_of_the_mode_or_of_every_mode()
    {
        var history = Path.Combine(Path.GetTempPath(), $"corvus-history-{Guid.NewGuid():N}.jsonl");
        string Line(string mode, string name, double seconds) =>
            $$"""{"kind":"class","run":"r","mode":"{{mode}}","name":"{{name}}","start":0,"end":1,"seconds":{{seconds}},"tests":1}""";
        File.WriteAllLines(history,
        [
            """{"kind":"run","run":"r","mode":"full"}""",
            Line("full", "Engine+Ghidra", 100), Line("full", "Engine+Ghidra", 300), Line("full", "Engine+Ghidra", 200),
            Line("quick", "Engine+Ghidra", 1), Line("quick", "Reader", 4),
        ]);
        try
        {
            var full = LongCollectionsFirst.ClassSeconds(history, "full");
            Assert.Equal(200, full["Engine+Ghidra"]);
            Assert.False(full.ContainsKey("Reader"));
            // A mode without runs, or none, takes every mode's runs.
            var any = LongCollectionsFirst.ClassSeconds(history, "perf");
            Assert.Equal(150, any["Engine+Ghidra"]);
            Assert.Equal(4, any["Reader"]);
            Assert.Empty(LongCollectionsFirst.ClassSeconds(history + ".missing", null));
        }
        finally { File.Delete(history); }
    }
}
