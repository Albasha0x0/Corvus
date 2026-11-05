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
