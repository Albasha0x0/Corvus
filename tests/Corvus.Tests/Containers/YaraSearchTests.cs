using System.Diagnostics;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Corvus.Core;
using Corvus.Native.Providers.Worker;
using Corvus.Native.Providers.Worker.Yara;
using Corvus.Services.Analysis;

namespace Corvus.Tests;

/// <summary>search_container kind=yara: YARA-X rules run in a worker process over a file, named when they do not compile.</summary>
public sealed class YaraSearchTests : IDisposable
{
    private readonly TempDir _dir = new();
    private readonly AssemblyWorkspace _ws = new();

    public void Dispose()
    {
        _ws.Dispose();
        _dir.Dispose();
    }

    /// <summary>Text, wide, hex with a jump, regex, xor, a module and a built-in function: one rule each.</summary>
    private const string FixtureRules = """
        import "pe"
        rule text_ascii : marker { meta: author = "fixture" strength = 3 strings: $a = "corvus" condition: $a }
        rule text_wide_nocase { strings: $w = "FIXTURE" wide nocase condition: $w }
        rule hex_jump { strings: $h = { 63 6F [1-4] 75 73 } condition: $h }
        rule regex_version { strings: $r = /ver[0-9]\.[0-9]+/ condition: $r }
        rule xor_secret { strings: $x = "secret" xor(1-255) condition: $x }
        rule pe_sections { condition: pe.is_pe and pe.number_of_sections == 2 }
        rule starts_with_mz { condition: uint16(0) == 0x5A4D and filesize < 1MB }
        rule absent_text { strings: $n = "not in any fixture" condition: $n }
        """;

    private static WorkerPool Pool() => new(new WorkerPoolOptions
    {
        Enabled = true,
        MemoryLimitBytes = 0,
        Start = WorkerPool.OwnCommand() with { Environment = new Dictionary<string, string?> { [YaraX.LibraryVariable] = YaraTestTools.Library } },
    });

    /// <summary>An x64 image whose .rdata holds the fixture strings, and a text file with them.</summary>
    private List<string> FixtureFiles()
    {
        var b = new PeBuilder();
        b.EntryPoint = b.Add(".text", [0xC3], 0x60000020).Rva;
        var data = new List<byte>(Encoding.ASCII.GetBytes("corvus ver1.22 co--us\0"));
        data.AddRange(Encoding.Unicode.GetBytes("Fixture\0"));
        data.AddRange(Encoding.ASCII.GetBytes("secret").Select(c => (byte)(c ^ 0x21)));
        b.Add(".rdata", [.. data]);
        var image = _dir.File("fixture.dll");
        File.WriteAllBytes(image, b.Build());
        var text = _dir.File("notes.txt");
        File.WriteAllText(text, "a corvus note, ver2.5 and corvus again\n");
        return [image, text];
    }

    private static async Task<YaraScanResult> Scan(WorkerPool pool, string rules, string path) =>
        (await pool.RunAsync("yara", YaraOps.ScanOp, new JsonObject { ["rules"] = rules, ["path"] = path }, TimeSpan.FromSeconds(60), CancellationToken.None))
        .Deserialize<YaraScanResult>(YaraOps.Json)!;

    [YaraFact(cli: true)]
    public async Task Matches_equal_the_yr_command_line_on_the_fixture_rules()
    {
        var rules = _dir.File("fixture.yar");
        File.WriteAllText(rules, FixtureRules);
        using var pool = Pool();
        foreach (var file in FixtureFiles())
        {
            var ours = (await Scan(pool, rules, file)).Hits.SelectMany(h => h.Rules)
                .SelectMany(r => r.Patterns.Count == 0 ? [$"{r.Rule}"] : r.Patterns.Select(p => $"{r.Rule} {p.Pattern}@{p.Offset}")).Order().ToList();
            Assert.Equal(Reference(rules, file), ours);
            Assert.NotEmpty(ours);
        }
    }

    /// <summary>The rule and pattern@offset lines yr 1.22.0 prints for <paramref name="file"/> (ndjson with patterns).</summary>
    private static List<string> Reference(string rules, string file)
    {
        var psi = new ProcessStartInfo(YaraTestTools.Cli!) { RedirectStandardOutput = true, RedirectStandardError = true };
        foreach (var a in new[] { "scan", "--output-format", "ndjson", "--print-strings", "--disable-warnings", "--relaxed-re-syntax", rules, file }) psi.ArgumentList.Add(a);
        using var yr = Process.Start(psi)!;
        var output = yr.StandardOutput.ReadToEnd();
        yr.WaitForExit();
        var lines = new List<string>();
        foreach (var line in output.Split('\n', StringSplitOptions.RemoveEmptyEntries))
            foreach (var rule in JsonDocument.Parse(line).RootElement.GetProperty("rules").EnumerateArray())
            {
                var name = rule.GetProperty("identifier").GetString()!;
                var strings = rule.TryGetProperty("strings", out var s) ? s.EnumerateArray().ToList() : [];
                if (strings.Count == 0) lines.Add(name);
                foreach (var m in strings) lines.Add($"{name} {m.GetProperty("identifier").GetString()}@{m.GetProperty("offset").GetInt64()}");
            }
        return [.. lines.Order()];
    }

    [YaraFact]
    public void A_rule_that_does_not_compile_is_named_with_its_line_and_the_other_rules_still_run()
    {
        var rules = _dir.File("rules");
        Directory.CreateDirectory(rules);
        File.WriteAllText(Path.Combine(rules, "good.yar"), "rule finds_corvus { strings: $a = \"corvus\" condition: $a }\n");
        File.WriteAllText(Path.Combine(rules, "bad.yar"), "rule fine { condition: true }\nrule broken {\n  condition: no_such_name\n}\n");
        var target = FixtureFiles()[1];
        using var pool = Pool();
        using var shared = WorkerPool.UseShared(pool);

        var found = new UnpackService(_ws).Search(target, rules, "yara", 10, AnalysisLimits.Default, default);
        Assert.Equal(["finds_corvus", "fine"], found.Items.Select(i => i.Name).Order());
        Assert.Equal("$a at 0x2+6, 0x1A+6", found.Items.Single(i => i.Name == "finds_corvus").Detail);
        Assert.Contains(found.Notes, n => n.StartsWith("YARA-X 1.22.0: 2 rules from 2 files; 1 errors, their rules not run", StringComparison.Ordinal));
        Assert.Contains(found.Notes, n => n.StartsWith($"{Path.Combine(rules, "bad.yar")}:3:14 rule broken: E009 unknown identifier `no_such_name`", StringComparison.Ordinal));
    }
}
