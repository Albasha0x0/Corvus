using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

namespace Corvus.Tests;

/// <summary>Surviving mutants per target of tests/mutation.json (./test.ps1 -Mutation sets CORVUS_MUTATION_REPORT) only fall.</summary>
public class MutationTests
{
    public const string ReportVariable = "CORVUS_MUTATION_REPORT";

    private static readonly string Root = DocsTests.RepoRoot();

    [Fact]
    [Trait("Speed", "Slow")]
    public void Surviving_mutants_only_fall()
    {
        if (Environment.GetEnvironmentVariable(ReportVariable) is not { Length: > 0 } folder) return; // only after a mutation run
        var report = Directory.EnumerateFiles(folder, "mutation-report.json", SearchOption.AllDirectories).Single();
        var counts = Count(JsonNode.Parse(File.ReadAllText(report))!, Targets());
        File.WriteAllLines(Path.Combine(folder, "summary.txt"), counts.OrderBy(c => c.Key, StringComparer.Ordinal).Select(c =>
            $"{c.Key}: score {c.Value.Score:0.0}% ({c.Value.Killed} killed, {c.Value.Timeout} timed out, {c.Value.Survived} survived, {c.Value.NoCoverage} not covered)"));
        Assert.NotEmpty(counts);
        CountRatchet.Check("mutation-survivors", "surviving mutants (survived or not covered) per target of tests/mutation.json may only fall",
            counts.ToDictionary(c => c.Key, c => (double)(c.Value.Survived + c.Value.NoCoverage), StringComparer.Ordinal), floor: false, partial: true);
    }

    [Fact]
    public void Targets_name_files_that_exist()
    {
        var targets = Targets();
        Assert.NotEmpty(targets);
        foreach (var (name, (patterns, tests)) in targets)
        {
            Assert.False(string.IsNullOrWhiteSpace(tests), name);
            foreach (var pattern in patterns)
            {
                Assert.StartsWith("src/Corvus/", pattern, StringComparison.Ordinal);
                Assert.NotEmpty(Directory.EnumerateFiles(Path.Combine(Root, Path.GetDirectoryName(pattern)!), Path.GetFileName(pattern)));
            }
        }
    }

    [Fact]
    public void Report_is_split_per_target()
    {
        var report = JsonNode.Parse("""
            {"schemaVersion":"2","files":{
             "D:\\r\\src\\Corvus\\Core\\Sqlite.cs":{"mutants":[{"status":"Killed"},{"status":"Survived"},{"status":"NoCoverage"},{"status":"Ignored"}]},
             "D:\\r\\src\\Corvus\\Native\\Pe\\PeFile.cs":{"mutants":[{"status":"Timeout"},{"status":"CompileError"},{"status":"Survived"}]},
             "D:\\r\\src\\Corvus\\Core\\Other.cs":{"mutants":[{"status":"Survived"}]}}}
            """)!;
        var counts = Count(report, new() { ["sqlite"] = (["src/Corvus/Core/Sqlite*.cs"], "x"), ["pe"] = (["src/Corvus/Native/Pe/*.cs"], "x") });
        Assert.Equal((1, 0, 1, 1), (counts["sqlite"].Killed, counts["sqlite"].Timeout, counts["sqlite"].Survived, counts["sqlite"].NoCoverage));
        Assert.Equal((0, 1, 1, 0), (counts["pe"].Killed, counts["pe"].Timeout, counts["pe"].Survived, counts["pe"].NoCoverage));
        Assert.Equal(50.0, counts["pe"].Score);
    }

    internal sealed record Counts(int Killed, int Timeout, int Survived, int NoCoverage)
    {
        public double Score => Killed + Timeout + Survived + NoCoverage == 0 ? 100 : 100.0 * (Killed + Timeout) / (Killed + Timeout + Survived + NoCoverage);
    }

    private static Dictionary<string, (string[] Mutate, string Tests)> Targets() =>
        JsonNode.Parse(File.ReadAllText(Path.Combine(Root, "tests", "mutation.json")))!["targets"]!.AsObject().ToDictionary(
            t => t.Key, t => (t.Value!["mutate"]!.AsArray().Select(p => (string)p!).ToArray(), (string)t.Value["tests"]!), StringComparer.Ordinal);

    /// <summary>Mutant statuses per target whose patterns match the report's files; targets without a placed mutant are left out.</summary>
    internal static Dictionary<string, Counts> Count(JsonNode report, Dictionary<string, (string[] Mutate, string Tests)> targets)
    {
        var result = new Dictionary<string, Counts>(StringComparer.Ordinal);
        foreach (var (path, file) in report["files"]!.AsObject())
        {
            var normalized = path.Replace('\\', '/');
            var at = normalized.IndexOf("src/Corvus/", StringComparison.Ordinal);
            if (at < 0) continue;
            normalized = normalized[at..];
            foreach (var (name, (patterns, _)) in targets)
            {
                if (!patterns.Any(p => Regex.IsMatch(normalized, "^" + Regex.Escape(p).Replace(@"\*", "[^/]*") + "$"))) continue;
                var statuses = file!["mutants"]!.AsArray().Select(m => (string?)m!["status"]).ToList();
                var old = result.GetValueOrDefault(name) ?? new Counts(0, 0, 0, 0);
                result[name] = new Counts(old.Killed + statuses.Count(s => s == "Killed"), old.Timeout + statuses.Count(s => s == "Timeout"),
                    old.Survived + statuses.Count(s => s == "Survived"), old.NoCoverage + statuses.Count(s => s == "NoCoverage"));
            }
        }
        // The report lists every file of the project; a target none of whose mutants was placed was not part of this run.
        return result.Where(r => r.Value.Killed + r.Value.Timeout + r.Value.Survived + r.Value.NoCoverage > 0).ToDictionary(StringComparer.Ordinal);
    }
}
