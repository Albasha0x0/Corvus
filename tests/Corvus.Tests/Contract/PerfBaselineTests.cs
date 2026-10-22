using System.Globalization;
using System.Text.RegularExpressions;
using Xunit.Abstractions;

namespace Corvus.Tests;

/// <summary>Ratchets/perf-baseline.txt: well-formed lines, and a baseline for every measurement a test names.</summary>
public partial class PerfBaselineTests(ITestOutputHelper output)
{
    public const string Name = "perf-baseline";

    [GeneratedRegex("""PerfBudget\.(?:Time|AtMost|AtLeast)\(\$?"([^"{]+)(\{)?""")]
    private static partial Regex Measurement();

    [Fact]
    public void Every_measured_name_has_a_baseline_and_every_line_is_well_formed()
    {
        var root = Path.Combine(DocsTests.RepoRoot(), "tests", "Corvus.Tests");
        var problems = new List<string>();
        var names = new HashSet<string>(StringComparer.Ordinal);
        foreach (var (line, number) in File.ReadAllLines(Path.Combine(root, "Ratchets", Name + ".txt")).Select((l, i) => (l, i + 1)))
        {
            if (line.Length == 0 || line.StartsWith('#')) continue;
            var f = line.Split('\t');
            if (f.Length != 4 || f[1] is not ("windows" or "linux" or "macos") || !double.TryParse(f[2], NumberStyles.Float, CultureInfo.InvariantCulture, out _)
                || f[3].Length == 0 || !names.Add(f[0] + "\t" + f[1]))
                problems.Add($"line {number}: expected a new 'name<TAB>os<TAB>value<TAB>unit', got '{line}'");
        }
        var measured = names.Select(n => n.Split('\t')[0]).ToHashSet(StringComparer.Ordinal);
        // An interpolated name (a per-engine or per-target label) needs a baseline under its fixed prefix.
        foreach (var file in Directory.EnumerateFiles(root, "*.cs", SearchOption.AllDirectories).Where(p => !p.Contains($"{Path.DirectorySeparatorChar}obj{Path.DirectorySeparatorChar}")))
            foreach (Match m in Measurement().Matches(File.ReadAllText(file)))
            {
                var name = m.Groups[1].Value;
                if (m.Groups[2].Success ? !measured.Any(n => n.StartsWith(name, StringComparison.Ordinal)) : !measured.Contains(name))
                    problems.Add($"{Path.GetRelativePath(root, file)}: no baseline for {name}{(m.Groups[2].Success ? "..." : "")}");
            }
        Assert.True(problems.Count == 0, $"Ratchets/{Name}.txt:\n{string.Join("\n", problems)}");
    }

    // The tests/baseline-contract lines hold 10 ms (a ceiling) and 10 MB/s (a floor) on every OS.
    [Fact]
    public void A_baseline_looser_than_its_budget_fails_in_every_run()
    {
        PerfBudget.AtMost("tests/baseline-contract", 1, 10, "ms", output);
        PerfBudget.AtLeast("tests/baseline-contract-rate", 20, 10, "MB/s", output);
        Assert.Contains("looser", Assert.ThrowsAny<Exception>(() => PerfBudget.AtMost("tests/baseline-contract", 1, 9, "ms", output)).Message);
        Assert.Contains("looser", Assert.ThrowsAny<Exception>(() => PerfBudget.AtLeast("tests/baseline-contract-rate", 20, 11, "MB/s", output)).Message);
        Assert.Contains("the test measures s", Assert.ThrowsAny<Exception>(() => PerfBudget.AtMost("tests/baseline-contract", 1, 10, "s", output)).Message);
    }
}
