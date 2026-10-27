using System.Text.Json;
using Corvus.Core;

namespace Corvus.Tests;

/// <summary>TokenEstimate against recorded token counts of real responses (TokenCorpus); the estimate may run high, never low.</summary>
public class TokenEstimateCalibrationTests
{
    /// <summary>Per output class (all its files together): S1.2's band.</summary>
    private const double ClassLow = 1.00, ClassHigh = 1.30;

    /// <summary>Per file: never under, and a character-class estimate spreads about 1.45x across content kinds.</summary>
    private const double FileLow = 1.00, FileHigh = 1.50;

    private sealed record Entry(string File, int Chars, int Tokens, string Source);

    private static readonly string Root = Path.Combine(AppContext.BaseDirectory, "TokenCorpus");

    private static List<Entry> Entries()
    {
        using var doc = JsonDocument.Parse(File.ReadAllText(Path.Combine(Root, "counts.json")));
        return doc.RootElement.GetProperty("files").EnumerateArray()
            .Select(e => new Entry(e.GetProperty("file").GetString()!, e.GetProperty("chars").GetInt32(), e.GetProperty("tokens").GetInt32(), e.GetProperty("source").GetString()!))
            .ToList();
    }

    [Fact]
    public void Estimates_are_high_within_the_band()
    {
        var entries = Entries();
        var problems = new List<string>();
        var classes = new Dictionary<string, (long Estimate, long Tokens)>();
        foreach (var e in entries)
        {
            var text = File.ReadAllText(Path.Combine(Root, e.File));
            Assert.Equal(e.Chars, text.Length);
            int estimate = TokenEstimate.Of(text);
            double ratio = (double)estimate / e.Tokens;
            if (ratio is < FileLow or > FileHigh) problems.Add($"{e.File}: estimate {estimate} / {e.Source} {e.Tokens} = {ratio:0.000}");
            var cls = e.File[..e.File.IndexOf('/')];
            var sum = classes.GetValueOrDefault(cls);
            classes[cls] = (sum.Estimate + estimate, sum.Tokens + e.Tokens);
        }
        foreach (var (cls, sum) in classes)
        {
            double ratio = (double)sum.Estimate / sum.Tokens;
            if (ratio is < ClassLow or > ClassHigh) problems.Add($"class {cls}: {sum.Estimate} / {sum.Tokens} = {ratio:0.000}");
        }
        Assert.Equal(["bytes", "code", "edit", "error", "list", "report"], classes.Keys.Order(StringComparer.Ordinal));
        Assert.True(problems.Count == 0, string.Join("\n", problems));
    }

    [Fact]
    public void The_corpus_is_free_of_machine_paths()
    {
        foreach (var e in Entries())
        {
            var text = File.ReadAllText(Path.Combine(Root, e.File));
            Assert.DoesNotContain("New folder", text, StringComparison.OrdinalIgnoreCase);
            // User folders are written as C:\Users\user.
            Assert.DoesNotMatch(@"(?i)users(?>\\+)(?!user\\)", text);
        }
    }

    [Theory]
    [InlineData("", 0)]
    [InlineData("hello", 1)]
    [InlineData("hello world", 2)]
    [InlineData("GetTypeInfo", 3)]
    [InlineData("0x1800158E0", 9)]
    [InlineData("8B", 2)]
    [InlineData("\r\n\n", 2)]
    [InlineData("\"name\"", 1)]
    [InlineData("\U0001F600", 2)]
    [InlineData("é", 1)]
    [InlineData("䀦", 2)]
    [InlineData("information", 2)]
    [InlineData("strength", 1)]
    [InlineData("uintchanfunccallkind", 10)]
    [InlineData("MakaMdna", 3)]
    public void Tokens_are_counted_by_character_class(string text, int expected) => Assert.Equal(expected, TokenEstimate.Of(text));

    [Fact]
    public void Estimation_takes_one_pass_without_allocation()
    {
        var text = string.Concat(Enumerable.Repeat("  0x180112F40 GetTypeInfo(\"name\", 42); // é\U0001F600\r\n", 20_000));
        Assert.Equal(TokenEstimate.Of(text), TokenEstimate.Of(text.AsSpan()));
        // Best of three: under a loaded parallel run the runtime now and then charges the thread a few bytes of its own.
        int tokens = 0;
        long least = long.MaxValue;
        for (int i = 0; i < 3 && least > 0; i++)
        {
            long before = GC.GetAllocatedBytesForCurrentThread();
            tokens = TokenEstimate.Of(text.AsSpan());
            least = Math.Min(least, GC.GetAllocatedBytesForCurrentThread() - before);
        }
        Assert.Equal(0, least);
        // Linear: twice the text, twice the count (the line has no boundary effects).
        Assert.Equal(2 * tokens, TokenEstimate.Of(text + text));
        Assert.Equal(0, TokenEstimate.Of((string?)null));
    }
}
