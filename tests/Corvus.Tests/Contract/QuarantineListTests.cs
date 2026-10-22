using System.Globalization;
using System.Reflection;

namespace Corvus.Tests;

/// <summary>Ratchets/quarantine.txt: every entry names a test of this assembly, an owner, an issue and a date not yet past.</summary>
public class QuarantineListTests
{
    public const string Name = "quarantine";

    [Fact]
    public void Every_quarantined_test_exists_and_is_due_to_be_fixed_by_a_date_not_yet_past()
    {
        var file = Path.Combine(DocsTests.RepoRoot(), "tests", "Corvus.Tests", "Ratchets", Name + ".txt");
        var tests = typeof(QuarantineListTests).Assembly.GetTypes()
            .SelectMany(t => t.GetMethods(BindingFlags.Public | BindingFlags.Instance | BindingFlags.DeclaredOnly)
                .Where(m => m.GetCustomAttributes<FactAttribute>(inherit: true).Any())
                .Select(m => $"{t.FullName}.{m.Name}"))
            .ToHashSet(StringComparer.Ordinal);
        var problems = new List<string>();
        foreach (var (line, number) in File.ReadAllLines(file).Select((l, i) => (l.Trim(), i + 1)))
        {
            if (line.Length == 0 || line.StartsWith('#')) continue;
            var fields = line.Split('|').Select(f => f.Trim()).ToArray();
            if (fields.Length != 4 || fields.Any(f => f.Length == 0)
                || !DateTime.TryParseExact(fields[3], "yyyy-MM-dd", CultureInfo.InvariantCulture, DateTimeStyles.None, out var until))
            {
                problems.Add($"line {number}: expected 'test | owner | issue | yyyy-MM-dd'");
                continue;
            }
            if (!tests.Contains(fields[0])) problems.Add($"line {number}: no test named {fields[0]}");
            if (until < DateTime.Today) problems.Add($"line {number}: {fields[0]} was due to be fixed or removed by {fields[3]}");
        }
        Assert.True(problems.Count == 0, $"Ratchets/{Name}.txt:\n{string.Join("\n", problems)}");
    }
}
