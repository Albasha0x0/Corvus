using System.IO.Compression;
using System.Text.Json;
using System.Text.Json.Nodes;
using Corvus.Native.Providers.Worker;
using Corvus.Native.Providers.Worker.Yara;
using Corvus.Setup;
using ModelContextProtocol.Protocol;

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
    public async Task A_container_longer_than_one_response_page_is_listed_to_its_end_below_the_limit()
    {
        using var dir = new TempDir();
        var zip = Path.Combine(dir.Path, "many.zip");
        // Long member names keep one default response page well under the 300 members.
        using (var archive = ZipFile.Open(zip, ZipArchiveMode.Create))
            for (int i = 0; i < 300; i++)
                using (var writer = new StreamWriter(archive.CreateEntry($"dir/sub/file_{i:D4}_with_a_longer_name_for_width.txt").Open())) writer.Write("text");
        var (code, document, _) = await Batch("--file", zip);
        Assert.Equal(0, code);
        var container = Section(document!, "container");
        Assert.Equal("complete", (string?)container["status"]);
        Assert.Null(container["limit"]);
        Assert.Equal(300, container["result"]!["items"]!.AsArray().Count);
        Assert.False((bool)container["result"]!["hasMore"]!);
    }

    [Fact]
    public void A_result_whose_coverage_is_partial_gives_a_partial_section_with_its_reason()
    {
        var result = new CallToolResult
        {
            Content = [new TextContentBlock { Text = "rows" }],
            StructuredContent = JsonSerializer.SerializeToElement(new
            {
                items = new[] { new { path = "a.txt" } },
                hasMore = false,
                coverage = new { status = "partial", reason = "members over the size cap were not read", limitations = new[] { "size-cap" } },
            }),
        };
        var section = ToolCli.Section(new ToolCli.FileBatchStep("container", "search_container", "containerFiles"), result);
        Assert.Equal("partial", (string?)section["status"]);
        Assert.Equal("members over the size cap were not read", (string?)section["reason"]);
        Assert.Null(section["limit"]);
        Assert.Single(section["result"]!["items"]!.AsArray());
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
    public async Task A_zip_holding_an_assembly_gets_its_typed_strings_with_the_member_path()
    {
        using var dir = new TempDir();
        var zip = Path.Combine(dir.Path, "app.zip");
        using (var archive = ZipFile.Open(zip, ZipArchiveMode.Create))
        using (var stream = archive.CreateEntry("lib/Lib.dll").Open())
            stream.Write(Roslyn.Release("Lib", """public static class C { public static string U() => "https://example.com/api/items"; }"""));
        var (code, document, _) = await Batch("--file", zip);
        Assert.Equal(0, code);
        var strings = Section(document!, "strings");
        Assert.Equal("complete", (string?)strings["status"]);
        var url = Assert.Single(strings["result"]!["items"]!.AsArray(), i => (string?)i!["value"] == "https://example.com/api/items")!;
        Assert.StartsWith("lib/Lib.dll: ", (string?)url["locations"]![0]);
    }

    [Fact]
    public async Task A_zip_without_a_unity_build_has_a_unity_section_that_does_not_apply()
    {
        using var dir = new TempDir();
        var zip = Path.Combine(dir.Path, "notes.zip");
        using (var archive = ZipFile.Open(zip, ZipArchiveMode.Create))
        using (var writer = new StreamWriter(archive.CreateEntry("notes.txt").Open())) writer.Write("text");
        var (code, document, _) = await Batch("--file", zip);
        Assert.Equal(0, code);
        var unity = Section(document!, "unity");
        Assert.Equal("not_applicable", (string?)unity["status"]);
        Assert.Contains("not_a_unity_build", (string?)unity["reason"]);
        Assert.True((bool)document!["complete"]!);
    }

    [Fact]
    public async Task A_single_file_that_is_not_a_package_is_not_read_as_a_unity_build()
    {
        using var dir = new TempDir();
        var file = Path.Combine(dir.Path, "plain.bin");
        File.WriteAllBytes(file, new byte[64]);
        var (_, document, _) = await Batch("--file", file);
        Assert.Equal("not_applicable", (string?)Section(document!, "unity")["status"]);
    }

    [Fact]
    public async Task An_android_package_with_il2cpp_metadata_gets_the_unity_overview()
    {
        using var dir = new TempDir();
        var apk = Path.Combine(dir.Path, "app.apk");
        using (var archive = ZipFile.Open(apk, ZipArchiveMode.Create))
            foreach (var (name, bytes) in new (string, byte[])[]
                     {
                         ("lib/arm64-v8a/libil2cpp.so", [0x7F, 0x45, 0x4C, 0x46, 2]),
                         ("lib/arm64-v8a/libunity.so", [0x7F, 0x45, 0x4C, 0x46, 2]),
                         ("assets/bin/Data/Managed/Metadata/global-metadata.dat", UnityOverviewTests.Metadata(27, ["Player"])),
                         ("assets/bin/Data/data.unity3d", [.. "UnityFS\0"u8, 0, 0, 0, 8, .. "5.x.x\0"u8, .. "2021.1.5f1\0"u8, 0, 0, 0, 0]),
                     })
                using (var stream = archive.CreateEntry(name).Open()) stream.Write(bytes);
        var (code, document, _) = await Batch("--file", apk);
        Assert.Equal(0, code);
        var unity = Section(document!, "unity");
        Assert.Equal("complete", (string?)unity["status"]);
        Assert.Equal("il2cpp", (string?)unity["result"]!["backend"]!["kind"]);
        Assert.Equal("readable", (string?)unity["result"]!["backend"]!["metadataState"]);
        Assert.Equal("2021.1.5f1", (string?)unity["result"]!["engine"]!["version"]);
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

    [Fact]
    public async Task A_unity_asset_file_gets_its_field_strings_in_the_strings_section()
    {
        using var dir = new TempDir();
        var file = Path.Combine(dir.Path, "sharedassets0.assets");
        File.WriteAllBytes(file, UnityAssetStringsTests.ConfigFile());
        var (code, document, _) = await Batch("--file", file);
        Assert.Equal(0, code);
        var strings = Section(document!, "strings");
        Assert.Equal("complete", (string?)strings["status"]);
        var items = strings["result"]!["items"]!.AsArray();
        var url = Assert.Single(items, i => (string?)i!["value"] == UnityAssetStringsTests.Url)!;
        Assert.Equal("sharedassets0.assets: Endpoints (Script: Net.Config).url", (string?)url["locations"]![0]);
        Assert.Contains(items, i => (string?)i!["type"] == "encoded" && (string?)i["detail"] == "base64, 32 bytes");
        Assert.Equal(1 << 30, (double)document!["limits"]!["assetBytes"]!);
    }

    [Fact]
    public async Task A_build_folder_gets_its_asset_strings_and_a_folder_without_one_does_not_apply()
    {
        using var dir = new TempDir();
        var data = Directory.CreateDirectory(Path.Combine(dir.Path, "App", "App_Data")).FullName;
        File.WriteAllBytes(Path.Combine(data, "level0"), UnityAssetStringsTests.ConfigFile());
        var (_, document, _) = await Batch("--file", Path.Combine(dir.Path, "App"));
        var strings = Section(document!, "strings");
        Assert.Equal("complete", (string?)strings["status"]);
        Assert.Contains(strings["result"]!["items"]!.AsArray(), i => (string?)i!["value"] == UnityAssetStringsTests.Url);
        var plain = Directory.CreateDirectory(Path.Combine(dir.Path, "plain")).FullName;
        File.WriteAllText(Path.Combine(plain, "notes.txt"), "text");
        (_, document, _) = await Batch("--file", plain);
        strings = Section(document!, "strings");
        Assert.Equal("not_applicable", (string?)strings["status"]);
        Assert.Contains("not_a_unity_build", (string?)strings["reason"]);
    }

    [Fact]
    public async Task An_asset_layout_that_did_not_read_makes_the_strings_section_partial_with_its_reason()
    {
        using var dir = new TempDir();
        var file = Path.Combine(dir.Path, "level0");
        File.WriteAllBytes(file, UnityAssetStringsTests.ConfigFile(typeTrees: false));
        var (_, document, _) = await Batch("--file", file);
        var strings = Section(document!, "strings");
        Assert.Equal("partial", (string?)strings["status"]);
        Assert.Contains("partial or unknown", (string?)strings["reason"]);
        Assert.False((bool)document!["complete"]!);
    }

    [Fact]
    public async Task An_asset_byte_limit_makes_the_strings_section_partial_and_keeps_the_rows_read()
    {
        using var dir = new TempDir();
        var data = Directory.CreateDirectory(Path.Combine(dir.Path, "App", "App_Data")).FullName;
        var first = UnityAssetStringsTests.ConfigFile();
        File.WriteAllBytes(Path.Combine(data, "level0"), first);
        File.WriteAllBytes(Path.Combine(data, "level1"), UnityAssetStringsTests.ConfigFile());
        var (_, document, _) = await Batch("--file", Path.Combine(dir.Path, "App"), "--limit", $"assetBytes={first.Length}");
        var strings = Section(document!, "strings");
        Assert.Equal("partial", (string?)strings["status"]);
        Assert.Contains("level1 and 0 later files are not", (string?)strings["reason"]);
        Assert.Contains(strings["result"]!["items"]!.AsArray(), i => (string?)i!["value"] == UnityAssetStringsTests.Url);
    }
}
