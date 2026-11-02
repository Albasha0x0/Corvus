using System.Text.Json.Nodes;
using Corvus.Core.Logs;
using static Corvus.Setup.ToolCli;

namespace Corvus.Tests;

/// <summary>batch --file --evtx-jsonl: event log records written as JSON lines for Timesketch and Zircolite.</summary>
public sealed class EvtxJsonlTests : IDisposable
{
    private readonly TempDir _dir = new();

    public void Dispose() => _dir.Dispose();

    private string Log(byte[] bytes)
    {
        var path = _dir.File("sample.evtx");
        File.WriteAllBytes(path, bytes);
        return path;
    }

    [Fact]
    public async Task Each_event_is_one_line_with_the_timesketch_fields_and_the_nested_event_shape()
    {
        var log = Log(EvtxSamples.Log([EvtxTests.Sample(1), EvtxTests.Sample(2, 7)]));
        var output = _dir.File("events.jsonl");
        var (code, text, _) = await ToolCliTests.Run("batch", "--file", log, "--evtx-jsonl", output);
        Assert.Equal(0, code);
        Assert.Contains("2 event(s)", text);
        var lines = File.ReadAllLines(output).Select(l => JsonNode.Parse(l)!).ToList();
        Assert.Equal(2, lines.Count);
        var first = lines[0];
        Assert.Equal("2026-01-02T03:04:06.123456+00:00", (string?)first["datetime"]);
        Assert.Equal("Event Created", (string?)first["timestamp_desc"]);
        Assert.StartsWith("Sample-Provider event 4104", (string?)first["message"]);
        var system = first["Event"]!["System"]!;
        Assert.Equal("Sample-Provider", (string?)system["Provider"]!["#attributes"]!["Name"]);
        Assert.Equal(4104, (int)system["EventID"]!);
        Assert.Equal(1200, (int)system["Execution"]!["#attributes"]!["ProcessID"]!);
        Assert.Equal(@"C:\work\report.txt", (string?)first["Event"]!["EventData"]!["Path"]);
        Assert.Equal(7, (int)lines[1]["Event"]!["System"]!["EventID"]!);
    }

    [Fact]
    public async Task A_record_in_free_space_is_written_and_marked_recovered()
    {
        var log = Log(EvtxSamples.Log([EvtxTests.Sample(1)], free: [EvtxTests.Sample(90, 1102)]));
        var output = _dir.File("events.jsonl");
        var (code, _, _) = await ToolCliTests.Run("batch", "--file", log, "--evtx-jsonl", output);
        Assert.Equal(0, code);
        var lines = File.ReadAllLines(output).Select(l => JsonNode.Parse(l)!).ToList();
        Assert.Equal(2, lines.Count);
        Assert.True((bool)lines[1]["recovered"]!);
        Assert.Null(lines[0]["recovered"]);
    }

    [Fact]
    public async Task A_file_that_is_not_an_event_log_is_refused_and_writes_no_output()
    {
        var plain = _dir.File("plain.txt");
        File.WriteAllText(plain, "not a log");
        var output = _dir.File("events.jsonl");
        var (code, _, error) = await ToolCliTests.Run("batch", "--file", plain, "--evtx-jsonl", output);
        Assert.Equal(2, code);
        Assert.Contains("not a readable event log", error);
        Assert.False(File.Exists(output));
    }

    [Fact]
    public async Task The_option_without_batch_file_is_refused()
    {
        var (code, _, error) = await ToolCliTests.Run("batch", "steps.jsonl", "--evtx-jsonl", _dir.File("e.jsonl"));
        Assert.Equal(2, code);
        Assert.Contains("--evtx-jsonl goes with batch --file", error);
    }

    [Fact]
    public async Task An_output_equal_to_the_input_is_refused()
    {
        var log = Log(EvtxSamples.Log([EvtxTests.Sample(1)]));
        var (code, _, error) = await ToolCliTests.Run("batch", "--file", log, "--evtx-jsonl", log);
        Assert.Equal(2, code);
        Assert.Contains("must not name the input", error);
    }

    [Fact]
    public async Task An_output_in_a_missing_folder_is_a_usage_error_and_leaves_no_file()
    {
        var log = Log(EvtxSamples.Log([EvtxTests.Sample(1)]));
        var output = Path.Combine(_dir.File("absent"), "events.jsonl");
        var (code, _, error) = await ToolCliTests.Run("batch", "--file", log, "--evtx-jsonl", output);
        Assert.Equal(2, code);
        Assert.Contains("cannot write", error);
    }

    [Fact]
    public async Task A_log_with_no_readable_event_names_the_reader_notes()
    {
        var bytes = EvtxSamples.Log([EvtxTests.Sample(1)]);
        Array.Clear(bytes, EvtxFile.HeaderSize, 8);
        var log = Log(bytes);
        var (code, text, _) = await ToolCliTests.Run("batch", "--file", log, "--evtx-jsonl", _dir.File("events.jsonl"));
        Assert.Equal(0, code);
        Assert.Contains("0 event(s)", text);
        Assert.Contains("No event was readable", text);
    }

    [Fact]
    public void Repeated_and_empty_data_names_are_kept_as_distinct_keys()
    {
        var e = new EvtxFile.Event(1, DateTime.UnixEpoch, 0, 0, false, "", "P", 1, 4, null, null, null, null, null, null,
            [new("a", "1"), new("a", "2"), new("", "3")]);
        var data = EvtxLine(e)["Event"]!["EventData"]!;
        Assert.Equal("1", (string?)data["a"]);
        Assert.Equal("2", (string?)data["a_2"]);
        Assert.Equal("3", (string?)data[""]);
    }

    [Fact]
    public void A_record_with_no_creation_time_uses_the_written_time_and_says_so()
    {
        var e = new EvtxFile.Event(1, new DateTime(2026, 1, 2, 3, 4, 5, DateTimeKind.Utc), 0, 0, false, "", null, null, null, null, null, null, null, null, null, []);
        var line = EvtxLine(e);
        Assert.Equal("2026-01-02T03:04:05.000000+00:00", (string?)line["datetime"]);
        Assert.Equal("Record Written", (string?)line["timestamp_desc"]);
    }
}
