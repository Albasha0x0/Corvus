using System.IO.Compression;
using System.Text.Json.Nodes;
using Corvus.Native.Providers.Worker;
using Corvus.Native.Providers.Worker.Yara;

namespace Corvus.Tests;

/// <summary>batch --file --json: the fixed read-only steps over one file, written as one corvus.batch/1 document.</summary>
public class FileBatchTests
{
    private static async Task<(int Code, JsonNode? Document, string Out)> Batch(params string[] args)
    {
        var (code, output, _) = await ToolCliTests.Run(["batch", .. args, "--json", "--no-index"]);
        return (code, output.Length > 0 ? JsonNode.Parse(output) : null, output);
    }

    private static JsonNode Section(JsonNode document, string name) => document["sections"]!.AsArray().Single(s => (string?)s!["name"] == name)!;

    [Fact]
    public async Task A_container_over_its_file_limit_is_partial_and_keeps_the_files_read()
    {
        using var dir = new TempDir();
        var zip = Path.Combine(dir.Path, "five.zip");
        using (var archive = ZipFile.Open(zip, ZipArchiveMode.Create))
            for (int i = 0; i < 5; i++)
                using (var writer = new StreamWriter(archive.CreateEntry($"d/f{i}.txt").Open())) writer.Write("text");
        var (code, document, _) = await Batch("--file", zip, "--limit", "containerFiles=3");
        Assert.Equal(0, code);
        Assert.Equal("corvus.batch/1", (string?)document!["schema"]);
        Assert.False((bool)document["complete"]!);
        Assert.Equal(3, (int)document["limits"]!["containerFiles"]!);
        Assert.Equal("zip", (string?)document["file"]!["type"]);
        Assert.Equal("complete", (string?)Section(document, "summary")["status"]);
        var container = Section(document, "container");
        Assert.Equal("partial", (string?)container["status"]);
        Assert.Equal("containerFiles", (string?)container["limit"]);
        Assert.Equal(3, container["result"]!["items"]!.AsArray().Count);
        Assert.Equal(5, (int)container["result"]!["total"]!);
        Assert.Equal("not_applicable", (string?)Section(document, "strings")["status"]);
        Assert.Equal("not_applicable", (string?)Section(document, "yara")["status"]);
    }

    [Fact]
    public async Task A_dotnet_assembly_gets_its_typed_strings_and_no_container_listing()
    {
        using var dir = new TempDir();
        var dll = Path.Combine(dir.Path, "Lib.dll");
        File.WriteAllBytes(dll, Roslyn.Release("Lib", """public static class C { public static string U() => "https://example.com/api/items"; }"""));
        var (code, document, _) = await Batch("--file", dll);
        Assert.Equal(0, code);
        Assert.Equal("not_applicable", (string?)Section(document!, "container")["status"]);
        var strings = Section(document!, "strings");
        Assert.Equal("complete", (string?)strings["status"]);
        Assert.Contains(strings["result"]!["items"]!.AsArray(), i => (string?)i!["value"] == "https://example.com/api/items");
    }

    [Fact]
    public async Task A_run_the_time_limit_ends_still_writes_its_document_and_exits_124()
    {
        using var dir = new TempDir();
        var file = Path.Combine(dir.Path, "plain.bin");
        File.WriteAllBytes(file, new byte[64]);
        var (code, document, _) = await Batch("--file", file, "--time-limit", "0.001");
        Assert.Equal(124, code);
        Assert.False((bool)document!["complete"]!);
        Assert.Equal("timeout", (string?)Section(document, "summary")["status"]);
        Assert.Equal("not_applicable", (string?)Section(document, "yara")["status"]);
    }

    [YaraFact]
    public async Task Given_rules_the_yara_section_lists_the_rules_that_matched()
    {
        using var dir = new TempDir();
        var file = dir.File("notes.txt");
        File.WriteAllText(file, "a fixture note for the batch scan");
        var rules = dir.File("batch.yar");
        File.WriteAllText(rules, """
            rule names_the_fixture { strings: $a = "fixture note" condition: $a }
            rule absent_text { strings: $n = "not in the fixture" condition: $n }
            """);
        using var pool = new WorkerPool(new WorkerPoolOptions
        {
            Enabled = true,
            MemoryLimitBytes = 0,
            Start = WorkerPool.OwnCommand() with { Environment = new Dictionary<string, string?> { [YaraX.LibraryVariable] = YaraTestTools.Library } },
        });
        using var shared = WorkerPool.UseShared(pool);
        var (code, document, _) = await Batch("--file", file, "--rules", rules);
        Assert.Equal(0, code);
        var yara = Section(document!, "yara");
        Assert.Equal("complete", (string?)yara["status"]);
        Assert.Equal("names_the_fixture", Assert.Single(yara["result"]!["items"]!.AsArray())!["name"]!.GetValue<string>());
    }

    [Fact]
    public async Task With_the_worker_host_off_the_yara_section_is_unavailable_and_names_the_variable()
    {
        using var dir = new TempDir();
        var file = dir.File("notes.txt");
        File.WriteAllText(file, "text");
        var rules = dir.File("batch.yar");
        File.WriteAllText(rules, "rule any_text { condition: true }");
        using var pool = new WorkerPool(new WorkerPoolOptions { Enabled = false });
        using var shared = WorkerPool.UseShared(pool);
        var (code, document, _) = await Batch("--file", file, "--rules", rules);
        Assert.Equal(0, code);
        var yara = Section(document!, "yara");
        Assert.Equal("unavailable", (string?)yara["status"]);
        Assert.Contains(WorkerPool.EnableVariable, (string?)yara["reason"]);
    }

    [Fact]
    public async Task A_missing_file_or_bad_limit_is_a_usage_error_with_nothing_on_stdout()
    {
        using var dir = new TempDir();
        var (code, _, output) = await Batch("--file", Path.Combine(dir.Path, "absent.bin"));
        Assert.Equal(2, code);
        Assert.Empty(output);
        (code, _, output) = await Batch("--file", dir.Path, "--limit", "noSuchLimit=3");
        Assert.Equal(2, code);
        Assert.Empty(output);
        (code, _, output) = await Batch("--file", dir.Path, "--rules", Path.Combine(dir.Path, "absent.yar"));
        Assert.Equal(2, code);
        Assert.Empty(output);
    }
}
