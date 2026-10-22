using System.Text.Json;
using Xunit.Abstractions;
using Xunit.Sdk;

[assembly: TestCollectionOrderer("Corvus.Tests.LongCollectionsFirst", "Corvus.Tests")]

namespace Corvus.Tests;

/// <summary>
/// Starts the longest test classes first, by their recorded times (test.ps1's history, CORVUS_TEST_HISTORY), so they
/// overlap the many short ones instead of ending the run alone. Collections shared by several classes go first, as
/// their classes run one after another; classes without a record go last, in the default order.
/// </summary>
public sealed class LongCollectionsFirst : ITestCollectionOrderer
{
    private readonly DefaultTestCollectionOrderer _default = new();

    public IEnumerable<ITestCollection> OrderTestCollections(IEnumerable<ITestCollection> testCollections)
    {
        var seconds = Environment.GetEnvironmentVariable("CORVUS_TEST_HISTORY") is { Length: > 0 } history && File.Exists(history)
            ? ClassSeconds(history, Environment.GetEnvironmentVariable("CORVUS_TEST_MODE"))
            : [];
        return _default.OrderTestCollections(testCollections)
            .OrderBy(c => c.CollectionDefinition != null ? 0 : 1)
            .ThenByDescending(c => seconds.GetValueOrDefault(ClassOf(c)));
    }

    /// <summary>
    /// The median recorded seconds of each test class ("Outer+Nested") in a history file's runs of one mode, or of every
    /// mode when it is null or has no run; empty when the file cannot be read.
    /// </summary>
    internal static Dictionary<string, double> ClassSeconds(string historyPath, string? mode)
    {
        var byMode = new Dictionary<string, Dictionary<string, List<double>>>();
        try
        {
            foreach (var line in File.ReadLines(historyPath))
            {
                if (!line.StartsWith("{\"kind\":\"class\"", StringComparison.Ordinal)) continue;
                using var json = JsonDocument.Parse(line);
                var root = json.RootElement;
                var lineMode = root.GetProperty("mode").GetString() ?? "";
                if (!byMode.TryGetValue(lineMode, out var classes)) byMode[lineMode] = classes = [];
                var name = root.GetProperty("name").GetString() ?? "";
                if (!classes.TryGetValue(name, out var list)) classes[name] = list = [];
                list.Add(root.GetProperty("seconds").GetDouble());
            }
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or JsonException or KeyNotFoundException) { return []; }
        IEnumerable<Dictionary<string, List<double>>> chosen = mode != null && byMode.TryGetValue(mode, out var one) ? [one] : byMode.Values;
        return chosen.SelectMany(c => c).GroupBy(p => p.Key)
            .ToDictionary(g => g.Key, g => Median([.. g.SelectMany(p => p.Value)]));
    }

    // A class's own collection is named "Test collection for <namespace>.<class>".
    private static string ClassOf(ITestCollection collection) => collection.DisplayName[(collection.DisplayName.LastIndexOf('.') + 1)..];

    private static double Median(List<double> values)
    {
        values.Sort();
        return values.Count % 2 == 1 ? values[values.Count / 2] : (values[values.Count / 2 - 1] + values[values.Count / 2]) / 2;
    }
}
