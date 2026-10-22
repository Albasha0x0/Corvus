using System.Diagnostics;
using System.IO.Compression;
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

    [YaraFact]
    public void A_rule_matching_only_inside_compressed_members_is_found_at_their_paths()
    {
        var marker = "corvus-marker-" + string.Concat(Enumerable.Range(0, 40).Select(i => (char)('a' + i % 26)));
        var text = string.Join("\n", Enumerable.Range(0, 200).Select(i => $"line {i} of the notes")) + "\n" + marker + "\n";
        var archive = _dir.File("bundle.zip");
        using (var zip = ZipFile.Open(archive, ZipArchiveMode.Create))
        {
            Add(zip, "docs/readme.txt", Encoding.ASCII.GetBytes(text));
            var inner = new MemoryStream();
            using (var nested = new ZipArchive(inner, ZipArchiveMode.Create, leaveOpen: true)) Add(nested, "deep/note.txt", Encoding.ASCII.GetBytes("nested " + text));
            Add(zip, "nested.zip", inner.ToArray());
        }
        // Deflate keeps no plain copy of the marker, so a scan of the file alone finds nothing.
        Assert.DoesNotContain(marker, Encoding.Latin1.GetString(File.ReadAllBytes(archive)));
        var rules = _dir.File("marker.yar");
        File.WriteAllText(rules, $"rule finds_marker {{ strings: $a = \"{marker}\" condition: $a }}\n");
        using var pool = Pool();
        using var shared = WorkerPool.UseShared(pool);

        var found = new UnpackService(_ws).Search(archive, rules, "yara", 10, AnalysisLimits.Default, default);
        Assert.Equal(["docs/readme.txt", "nested.zip_unpacked/deep/note.txt"], found.Items.Select(i => i.Path).Order());
        Assert.All(found.Items, i => Assert.Equal("finds_marker", i.Name));
        Assert.Equal(4, found.Searched);
        Assert.Contains(found.Notes, n => n.Contains("; 3 container members scanned;", StringComparison.Ordinal));
    }

    [YaraFact]
    public void A_dump_is_scanned_by_region_with_virtual_addresses_and_module_rules()
    {
        // Two adjacent ranges at 0x20000000 that join into one region, one range at 0x30000000, and a module's image.
        var b = new PeBuilder();
        b.EntryPoint = b.Add(".text", [0xC3], 0x60000020).Rva;
        b.Add(".rdata", [1, 2, 3, 4]);
        var image = b.Build();
        var heap = new byte[0x1000];
        Encoding.ASCII.GetBytes("alpha-marker").CopyTo(heap, 0x10);
        var other = new byte[0x1000];
        Encoding.ASCII.GetBytes("beta-marker").CopyTo(other, 0x20);
        var dump = new MinidumpBuilder { FullMemory = true };
        dump.Modules.Add(new MinidumpBuilder.Module(0x7FF6_0000_0000, 0x10000, 0x5F000000, @"C:\app\fixture.dll"));
        dump.Memory.Add((0x2000_0000, new byte[0x1000]));
        dump.Memory.Add((0x2000_1000, heap));
        dump.Memory.Add((0x3000_0000, other));
        dump.Memory.Add((0x7FF6_0000_0000, image));
        var path = _dir.File("process.dmp");
        File.WriteAllBytes(path, dump.Build());
        var rules = _dir.File("memory.yar");
        File.WriteAllText(rules, """
            import "pe"
            rule split_pair { strings: $a = "alpha-marker" $b = "beta-marker" condition: $a and $b }
            rule module_pe { condition: pe.is_pe and pe.number_of_sections == 2 }
            rule at_mz { condition: uint16(0) == 0x5A4D }
            rule alpha_alone { strings: $a = "alpha-marker" condition: $a and filesize > 0 }
            """);
        using var pool = Pool();
        using var shared = WorkerPool.UseShared(pool);

        var found = new UnpackService(_ws).Search(path, rules, "yara", 20, AnalysisLimits.Default, default);
        var imageEnd = 0x7FF6_0000_0000 + image.Length;
        Assert.Equal(
        [
            "0x20000000-0x20002000 alpha_alone $a at 0x20001010+12",
            "0x20000000-0x20002000 split_pair $a at 0x20001010+12",
            "0x30000000-0x30001000 split_pair $b at 0x30000020+11",
            $"0x7FF600000000-0x{imageEnd:X} fixture.dll at_mz ",
            $"0x7FF600000000-0x{imageEnd:X} fixture.dll module_pe ",
        ], found.Items.Select(i => $"{i.Path} {i.Name} {i.Detail}").Order(StringComparer.Ordinal));
        Assert.Equal("dump", found.Container);
        Assert.Equal(3, found.Searched);
        Assert.Contains(found.Notes, n => n.StartsWith("Process memory: 3 regions", StringComparison.Ordinal) && n.Contains("cross a region boundary are not matched"));
    }

    [Fact]
    public async Task Without_the_library_the_scan_is_refused_naming_the_platform()
    {
        var rules = _dir.File("one.yar");
        File.WriteAllText(rules, "rule any { condition: true }\n");
        // The build output holds no runtimes/<rid>/native build, so only the variable could supply one.
        using var pool = new WorkerPool(new WorkerPoolOptions
        {
            Enabled = true,
            MemoryLimitBytes = 0,
            Start = WorkerPool.OwnCommand() with { Environment = new Dictionary<string, string?> { [YaraX.LibraryVariable] = _dir.File("absent.dll") } },
        });

        var e = await Assert.ThrowsAsync<ToolError>(() => Scan(pool, rules, rules));
        Assert.Equal(ErrorCode.ProviderUnavailable, e.Code);
        Assert.Contains($"YARA-X 1.22.0 is not available for {System.Runtime.InteropServices.RuntimeInformation.RuntimeIdentifier}", e.Message);
    }

    private static void Add(ZipArchive zip, string name, byte[] bytes)
    {
        using var entry = zip.CreateEntry(name, CompressionLevel.Optimal).Open();
        entry.Write(bytes);
    }
}
