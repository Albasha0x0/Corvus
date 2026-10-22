using System.Globalization;
using System.Text.RegularExpressions;
using System.Xml.Linq;

namespace Corvus.Tests;

/// <summary>
/// The perf run's comparison with Ratchets/perf-baseline.txt: the <c>perf:</c> lines of each sample (a TRX file), the worst
/// value of a name within a sample (the largest for a <c>&lt;=</c> budget, the smallest for a <c>&gt;=</c> rate), the median
/// over the samples, and a regression when that median is more than <see cref="Factor"/> times past the baseline.
/// test.ps1 -Perf runs it as <c>dotnet exec Corvus.Tests.dll --perf-regressions trx...</c>.
/// </summary>
internal static partial class PerfRegressions
{
    public const string Flag = "--perf-regressions";

    /// <summary>How far past its baseline a median is a regression.</summary>
    public const double Factor = 1.5;

    /// <summary>One measurement line, from the test (filter form, Class+Nested.Method) that printed it.</summary>
    public sealed record Measurement(string Test, string Name, double Value, string Unit, string Op);

    /// <summary>A name whose median is past its baseline: the tests that measure it and the text that reports it.</summary>
    public sealed record Regression(string Name, IReadOnlyList<string> Tests, string Text);

    [GeneratedRegex(@"^perf: (\S+) (\S+) (\S+) \(budget (<=|>=) ", RegexOptions.Multiline)]
    private static partial Regex Line();

    /// <summary>The measurements in a test's output; lines that do not parse are skipped.</summary>
    public static IEnumerable<Measurement> Parse(string test, string output)
    {
        foreach (Match m in Line().Matches(output))
            if (double.TryParse(m.Groups[2].Value, NumberStyles.Float, CultureInfo.InvariantCulture, out var value))
                yield return new(test, m.Groups[1].Value, value, m.Groups[3].Value, m.Groups[4].Value);
    }

    /// <summary>The measurements of a TRX file, with each test named as test.ps1's Get-FailedTests names it.</summary>
    public static IEnumerable<Measurement> Read(string trxPath)
    {
        XNamespace t = "http://microsoft.com/schemas/VisualStudio/TeamTest/2010";
        var doc = XDocument.Load(trxPath);
        var names = doc.Descendants(t + "UnitTest").ToDictionary(u => (string)u.Attribute("id")!,
            u => $"{(string?)u.Element(t + "TestMethod")?.Attribute("className")}.{(string?)u.Element(t + "TestMethod")?.Attribute("name")}");
        foreach (var result in doc.Descendants(t + "UnitTestResult"))
            if (result.Element(t + "Output")?.Element(t + "StdOut")?.Value is { Length: > 0 } output && names.TryGetValue((string)result.Attribute("testId")!, out var test))
                foreach (var m in Parse(test, output)) yield return m;
    }

    /// <summary>
    /// The names whose median over <paramref name="samples"/> (one list of measurements per sample) is past the baseline
    /// <paramref name="baseline"/> gives; a name without a baseline, or with a baseline in another unit, is not compared.
    /// </summary>
    public static IReadOnlyList<Regression> Find(IReadOnlyList<IReadOnlyList<Measurement>> samples, Func<string, (double Value, string Unit)?> baseline)
    {
        var worst = new Dictionary<string, List<double>>(StringComparer.Ordinal);
        var shape = new Dictionary<string, (string Unit, string Op, SortedSet<string> Tests)>(StringComparer.Ordinal);
        foreach (var sample in samples)
            foreach (var group in sample.GroupBy(m => m.Name, StringComparer.Ordinal))
            {
                var first = group.First();
                if (!shape.TryGetValue(group.Key, out var s)) shape[group.Key] = s = (first.Unit, first.Op, new(StringComparer.Ordinal));
                foreach (var m in group) s.Tests.Add(m.Test);
                if (!worst.TryGetValue(group.Key, out var values)) worst[group.Key] = values = [];
                values.Add(first.Op == ">=" ? group.Min(m => m.Value) : group.Max(m => m.Value));
            }
        var regressions = new List<Regression>();
        foreach (var (name, values) in worst.OrderBy(w => w.Key, StringComparer.Ordinal))
        {
            var (unit, op, tests) = shape[name];
            if (baseline(name) is not { } b || b.Unit != unit) continue;
            values.Sort();
            var median = values.Count % 2 == 1 ? values[values.Count / 2] : (values[values.Count / 2 - 1] + values[values.Count / 2]) / 2;
            var past = op == ">=" ? median < b.Value / Factor : median > b.Value * Factor;
            if (past)
                regressions.Add(new(name, [.. tests], string.Create(CultureInfo.InvariantCulture,
                    $"{name}: median {median:0.###} {unit} of {values.Count} sample(s), baseline {op} {b.Value:0.###} {unit}")));
        }
        return regressions;
    }

    /// <summary>
    /// Prints a <c>test</c> line per test that measures a regressed name and a <c>regressed</c> line per name, tab-separated;
    /// exit code 0, or 2 on a missing file.
    /// </summary>
    public static int Main(string[] trxPaths)
    {
        if (trxPaths.Length == 0 || trxPaths.Any(p => !File.Exists(p)))
        {
            Console.Error.WriteLine($"no TRX file: {string.Join(", ", trxPaths.Where(p => !File.Exists(p)))}");
            return 2;
        }
        var regressions = Find([.. trxPaths.Select(p => (IReadOnlyList<Measurement>)[.. Read(p)])], PerfBudget.Baseline);
        foreach (var test in regressions.SelectMany(r => r.Tests).Distinct(StringComparer.Ordinal)) Console.WriteLine($"test\t{test}");
        foreach (var r in regressions) Console.WriteLine($"regressed\t{r.Name}\t{r.Text}");
        return 0;
    }
}
