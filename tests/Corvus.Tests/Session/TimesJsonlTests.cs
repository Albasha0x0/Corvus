using System.IO.Compression;
using System.Text.Json.Nodes;

namespace Corvus.Tests;

/// <summary>batch --file --times-jsonl: stored file times written as Timesketch JSON lines.</summary>
public sealed class TimesJsonlTests : IDisposable
{
    private readonly TempDir _dir = new();

    public void Dispose() => _dir.Dispose();

    private string Link()
    {
        var path = _dir.File("sample.lnk");
        File.WriteAllBytes(path, ShellLinkTests.Shortcut("/c echo"));
        return path;
    }

    // Entries are added out of time order, the first two sharing one time.
    private string Archive()
    {
        var path = _dir.File("sample.zip");
        using var zip = ZipFile.Open(path, ZipArchiveMode.Create);
        zip.CreateEntry("late.txt").LastWriteTime = new DateTimeOffset(2024, 6, 1, 0, 0, 0, TimeSpan.Zero);
        zip.CreateEntry("early.txt").LastWriteTime = new DateTimeOffset(2024, 1, 1, 0, 0, 0, TimeSpan.Zero);
        zip.CreateEntry("also-early.txt").LastWriteTime = new DateTimeOffset(2024, 1, 1, 0, 0, 0, TimeSpan.Zero);
        return path;
    }

    [Fact]
    public async Task Each_stored_time_is_one_line_with_the_timesketch_fields()
    {
        var output = _dir.File("times.jsonl");
        var (code, text, _) = await ToolCliTests.Run("batch", "--file", Link(), "--times-jsonl", output);
        Assert.Equal(0, code);
        Assert.Contains("3 event(s)", text);
        var lines = File.ReadAllLines(output).Select(l => JsonNode.Parse(l)!).ToList();
        Assert.Equal(3, lines.Count);
        Assert.All(lines, l =>
        {
            Assert.Equal("2026-01-02T03:04:05.000000+00:00", (string?)l["datetime"]);
            Assert.Equal("corvus:file_times", (string?)l["data_type"]);
            Assert.Equal("sample.lnk", (string?)l["source_file"]);
            Assert.NotNull(l["message"]);
        });
        Assert.Contains(lines, l => (string?)l["timestamp_desc"] == "Link creation time");
    }

    [Fact]
    public async Task The_lines_are_sorted_by_time()
    {
        var output = _dir.File("times.jsonl");
        var (code, _, _) = await ToolCliTests.Run("batch", "--file", Archive(), "--times-jsonl", output);
        Assert.Equal(0, code);
        var stamps = File.ReadAllLines(output).Select(l => (string)JsonNode.Parse(l)!["datetime"]!).ToList();
        Assert.Equal(3, stamps.Count);
        Assert.Equal(stamps.OrderBy(s => s, StringComparer.Ordinal), stamps);
        Assert.StartsWith("2024-06", stamps[2]);
    }

    [Fact]
    public async Task An_unknown_file_prints_the_note_and_writes_no_lines()
    {
        var plain = _dir.File("plain.txt");
        File.WriteAllText(plain, "no stored times");
        var output = _dir.File("times.jsonl");
        var (code, text, _) = await ToolCliTests.Run("batch", "--file", plain, "--times-jsonl", output);
        Assert.Equal(0, code);
        Assert.Contains("0 event(s)", text);
        Assert.Contains("format not recognized", text);
        Assert.Empty(File.ReadAllLines(output));
    }

    [Fact]
    public async Task The_input_file_is_refused_as_output()
    {
        var link = Link();
        var (code, _, error) = await ToolCliTests.Run("batch", "--file", link, "--times-jsonl", link);
        Assert.Equal(2, code);
        Assert.Contains("must not name the input", error);
    }

    [Fact]
    public async Task A_folder_is_refused_as_output()
    {
        var (code, _, error) = await ToolCliTests.Run("batch", "--file", Link(), "--times-jsonl", _dir.Path);
        Assert.Equal(2, code);
        Assert.Contains("names a file, not a folder", error);
    }

    [Fact]
    public async Task It_does_not_go_with_json_or_recurse()
    {
        var link = Link();
        foreach (var other in new[] { "--json", "--jsonl", "--recurse" })
        {
            var (code, _, error) = await ToolCliTests.Run("batch", "--file", link, "--times-jsonl", _dir.File("t.jsonl"), other);
            Assert.Equal(2, code);
            Assert.Contains("does not go with", error);
        }
    }
}
