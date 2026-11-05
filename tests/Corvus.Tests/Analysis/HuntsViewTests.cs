using System.Text.Json.Nodes;
using Corvus.Core;
using Corvus.Services;
using Corvus.Services.Analysis;
using Corvus.Services.Analysis.Hunts;

namespace Corvus.Tests;

/// <summary>summarize_file view=hunts over a program built from source with a URL, a pipe and a library name.</summary>
public sealed class HuntsViewTests : IDisposable
{
    private readonly TempDir _dir = new();
    private readonly AssemblyWorkspace _ws = new();
    public void Dispose() { _ws.Dispose(); _dir.Dispose(); }

    private string Program()
    {
        var bytes = InspectionTests.Compile("Caller", """
            public static class Caller
            {
                public static object Open() => new System.Uri("https://opened.example.com/a");
                public static string Pipe() => @"\\.\pipe\svc-test-pipe";
                public static object Load() => System.Runtime.InteropServices.NativeLibrary.Load("helper-lib.dll");
                public static string Name() => "https://named.example.com/b";
            }
            """);
        var path = _dir.File("Caller.dll");
        File.WriteAllBytes(path, bytes);
        return path;
    }

    private HuntSet Hunts(string path)
    {
        var summary = new InspectionService(_ws).Summarize(null, path, default, new FileViewOptions("hunts"));
        return (HuntSet)summary.Views["hunts"].Detail;
    }

    [Fact]
    public void The_view_returns_queries_for_the_URL_the_pipe_and_the_library_name()
    {
        var set = Hunts(Program());
        Assert.Contains(set.Hunts, h => h.Table == "DeviceNetworkEvents" && h.Kql.Contains("opened.example.com", StringComparison.Ordinal));
        Assert.Contains(set.Hunts, h => h.Table == "DeviceEvents" && h.Kql.Contains(@"\\svc-test-pipe", StringComparison.Ordinal));
        Assert.Contains(set.Hunts, h => h.Table == "DeviceImageLoadEvents" && h.Kql.Contains("helper-lib.dll", StringComparison.Ordinal));
        Assert.Contains(set.Hunts, h => h.Table == "DeviceFileEvents" && h.Facts[0].StartsWith("sha1:", StringComparison.Ordinal));
    }

    [Fact]
    public void A_URL_found_only_as_a_string_gets_no_network_query()
    {
        var set = Hunts(Program());
        Assert.DoesNotContain(set.Hunts, h => h.Kql.Contains("named.example.com", StringComparison.Ordinal));
        Assert.Contains(set.Notes, n => n.Contains("found only as strings", StringComparison.Ordinal));
    }

    [Fact]
    public void Every_query_of_the_view_passes_the_check()
    {
        Assert.All(Hunts(Program()).Hunts, h => Assert.Empty(KqlCheck.Diagnostics(h.Kql)));
    }

    [Fact]
    public async Task The_hunts_path_writes_valid_JSON_with_a_rule_body_per_query()
    {
        var path = Program();
        var tools = new Corvus.Tools.InspectionTools(new InspectionService(_ws), _ws);
        var file = _dir.File("hunts.json");
        var text = await tools.SummarizeFile(path: path, view: "hunts", huntsPath: file);
        Assert.Contains($"written to {file}", text);
        var root = JsonNode.Parse(File.ReadAllBytes(file))!;
        var hunts = root["hunts"]!.AsArray();
        var rules = root["detectionRules"]!.AsArray();
        Assert.NotEmpty(hunts);
        Assert.Equal(hunts.Count, rules.Count);
        foreach (var rule in rules)
        {
            Assert.False(string.IsNullOrEmpty((string?)rule!["id"]));
            Assert.False(string.IsNullOrEmpty((string?)rule["displayName"]));
            Assert.False(string.IsNullOrEmpty((string?)rule["queryCondition"]!["queryText"]));
            Assert.Equal("P1D", (string?)rule["schedule"]!["frequency"]);
            Assert.Equal("disabled", (string?)rule["status"]);
            Assert.Equal("SHA1", (string?)rule["detectionAction"]!["alertTemplate"]!["entityMappings"]!["files"]![0]!["sha1Column"]);
        }
    }

    [Fact]
    public async Task The_hunts_path_refuses_an_existing_file_unless_overwrite_is_set()
    {
        var path = Program();
        var tools = new Corvus.Tools.InspectionTools(new InspectionService(_ws), _ws);
        var file = _dir.File("hunts.json");
        await tools.SummarizeFile(path: path, huntsPath: file);
        var refused = await Assert.ThrowsAsync<ToolError>(() => tools.SummarizeFile(path: path, huntsPath: file));
        Assert.Equal(ErrorCode.Conflict, refused.Code);
        await tools.SummarizeFile(path: path, huntsPath: file, overwrite: true);
    }

    [Fact]
    public void A_file_that_is_not_a_PE_image_gives_a_note_and_keeps_the_SHA1_hunts()
    {
        var path = _dir.File("data.bin");
        File.WriteAllBytes(path, "plain data, no image"u8.ToArray());
        var set = Hunts(path);
        Assert.Contains(set.Notes, n => n.Contains("PE images only", StringComparison.Ordinal));
        Assert.Contains(set.Hunts, h => h.Facts[0].StartsWith("sha1:", StringComparison.Ordinal));
    }

    // A header that fails to parse still gets its strings read.
    private string Image(string name, byte[] body)
    {
        var bytes = new byte[256 + body.Length];
        bytes[0] = (byte)'M';
        bytes[1] = (byte)'Z';
        bytes[0x3C] = 0xF0;
        body.CopyTo(bytes, 256);
        var path = _dir.File(name);
        File.WriteAllBytes(path, bytes);
        return path;
    }

    private static byte[] Text(params string[] strings) => System.Text.Encoding.ASCII.GetBytes(string.Join('\0', strings) + "\0");

    // Field test 10: quotes are legal in a pipe name.
    [Fact]
    public void A_pipe_name_with_a_quote_is_kept_whole()
    {
        var set = Hunts(Image("pipe.exe", Text(@"\\.\pipe\evil'pipe\sub")));
        var hunt = Assert.Single(set.Hunts, h => h.Table == "DeviceEvents");
        Assert.Contains(@"endswith '\\evil\'pipe\\sub'", hunt.Kql, StringComparison.Ordinal);
    }

    // Field test 10: a path with an apostrophe was dropped.
    [Fact]
    public void A_file_path_with_an_apostrophe_is_kept()
    {
        var set = Hunts(Image("path.exe", Text(@"C:\Users\Public\o'brien\drop.exe")));
        Assert.Single(set.Hunts, h => h.Table == "DeviceFileEvents" && h.Facts[0].StartsWith("file_path:", StringComparison.Ordinal));
    }

    // Field test 12a: the stem of ".ni.dll" is empty.
    [Fact]
    public void A_library_name_with_a_leading_dot_is_not_a_library()
    {
        var set = Hunts(Image("dots.exe", Text(".ni.dll", "plugin.dll")));
        var hunt = Assert.Single(set.Hunts, h => h.Facts[0].StartsWith("dll_name:", StringComparison.Ordinal));
        Assert.Equal(["dll_name:plugin.dll"], hunt.Facts);
    }

    // Field test 13: a catalog signature is not read.
    [Fact]
    public void A_PE_image_without_an_embedded_signature_gives_a_signer_note()
    {
        var set = Hunts(Image("unsigned.exe", Text("nothing")));
        Assert.Contains(set.Notes, n => n.Contains("signer is unknown", StringComparison.Ordinal) && n.Contains("catalog", StringComparison.Ordinal));
    }

    // Field test 14: a zip has no process or image-load events.
    [Fact]
    public void A_zip_gets_the_file_event_query_and_a_note_pointing_at_its_entries()
    {
        var path = _dir.File("pack.zip");
        using (var zip = System.IO.Compression.ZipFile.Open(path, System.IO.Compression.ZipArchiveMode.Create))
            using (var w = new StreamWriter(zip.CreateEntry("a.txt").Open())) w.Write("hello");
        var set = Hunts(path);
        Assert.Equal("DeviceFileEvents", Assert.Single(set.Hunts, h => h.Facts[0].StartsWith("sha1:", StringComparison.Ordinal)).Table);
        Assert.DoesNotContain(set.Hunts, h => h.Table is "DeviceProcessEvents" or "DeviceImageLoadEvents");
        Assert.Contains(set.Notes, n => n.Contains("unpack_container", StringComparison.Ordinal));
    }

    [Fact]
    public void A_PE_image_keeps_the_process_and_image_load_queries_of_its_hash()
    {
        var tables = Hunts(Program()).Hunts.Where(h => h.Facts[0].StartsWith("sha1:", StringComparison.Ordinal)).Select(h => h.Table).ToList();
        Assert.Contains("DeviceProcessEvents", tables);
        Assert.Contains("DeviceImageLoadEvents", tables);
    }

    // Field test 20: a name read from compressed bytes is noise.
    [Fact]
    public void A_string_inside_a_high_entropy_region_gives_no_hunt_and_one_note()
    {
        var body = new byte[16_384];
        new Random(7).NextBytes(body);
        var hidden = Text(@"\\.\pipe\hidden-pipe");
        hidden.CopyTo(body, 5_000);
        var plain = Text(@"\\.\pipe\plain-pipe");
        var set = Hunts(Image("packed.exe", [.. plain, .. new byte[4_096], .. body]));
        Assert.DoesNotContain(set.Hunts, h => h.Kql.Contains("hidden-pipe", StringComparison.Ordinal));
        Assert.Contains(set.Hunts, h => h.Kql.Contains("plain-pipe", StringComparison.Ordinal));
        Assert.Single(set.Notes, n => n.Contains("high-entropy", StringComparison.Ordinal));
    }

    // Field test 15f: a hash is computed, not decoded.
    [Fact]
    public void The_file_hash_carries_the_computed_evidence_class()
    {
        Assert.All(Hunts(Program()).Hunts.Where(h => h.Facts[0].StartsWith("sha1:", StringComparison.Ordinal)), h => Assert.Equal(IndicatorEvidence.Computed, h.Evidence));
    }

    // Field test 15e: only 10 extracted values were read.
    [Fact]
    public void A_program_with_many_pipe_names_is_read_past_ten_values()
    {
        var lines = string.Join('\n', Enumerable.Range(0, 30).Select(i => $"public static string P{i}() => @\"\\\\.\\pipe\\many-{i:D2}\";"));
        var path = _dir.File("Many.dll");
        File.WriteAllBytes(path, InspectionTests.Compile("Many", "public static class Many {\n" + lines + "\n}"));
        var set = Hunts(path);
        Assert.Contains(set.Hunts, h => h.Kql.Contains("many-29", StringComparison.Ordinal));
        Assert.DoesNotContain(set.Notes, n => n.Contains("extracted values were read", StringComparison.Ordinal));
    }

    // Field test 15d: the views list left hunts out.
    [Fact]
    public void The_overview_lists_the_hunts_view_for_a_file()
    {
        var summary = new InspectionService(_ws).Summarize(null, Program(), default, new FileViewOptions("overview"));
        Assert.Contains("hunts", Corvus.Tools.ContainerText.Summary(summary, "overview").Views);
    }

    // Field test 15a: a query inside a table cell showed its line breaks as \n.
    [Fact]
    public void A_query_prints_as_an_indented_block_with_real_line_breaks()
    {
        var summary = new InspectionService(_ws).Summarize(null, Program(), default, new FileViewOptions("hunts"));
        var text = Corvus.Tools.ContainerText.Summary(Corvus.Tools.ContainerText.Summary(summary, "hunts"));
        Assert.Contains("\n    DeviceFileEvents\n    | where SHA1 == '", text, StringComparison.Ordinal);
        Assert.DoesNotContain("\\n", text, StringComparison.Ordinal);
    }

    // Field test 15b: view=hunts refused offset.
    [Fact]
    public async Task The_hunts_view_pages_with_offset_and_limit()
    {
        var tools = new Corvus.Tools.InspectionTools(new InspectionService(_ws), _ws);
        var path = Program();
        var first = await tools.SummarizeFile(path: path, view: "hunts", limit: 2);
        Assert.Contains("[More: offset=2]", first, StringComparison.Ordinal);
        var next = await tools.SummarizeFile(path: path, view: "hunts", offset: 2, limit: 2);
        Assert.Contains("(showing 3-4)", next, StringComparison.Ordinal);
        Assert.DoesNotContain(first.Split('\n').First(l => l.TrimStart().StartsWith("sha1-", StringComparison.Ordinal)), next.Split('\n'));
    }

    [Fact]
    public void A_truncated_PE_image_reports_unknown_headers_and_keeps_the_SHA1_hunts()
    {
        var path = _dir.File("cut.exe");
        var bytes = new byte[256];
        bytes[0] = (byte)'M';
        bytes[1] = (byte)'Z';
        bytes[0x3C] = 0xF0;
        File.WriteAllBytes(path, bytes);
        var set = Hunts(path);
        Assert.Contains(set.Hunts, h => h.Facts[0].StartsWith("sha1:", StringComparison.Ordinal));
    }
}
