using System.Text;
using System.Text.Json;
using Corvus.Services;

namespace Corvus.Tests;

/// <summary>
/// A recording a server kept is read back as what it holds, or as nothing
/// when it is damaged.
/// </summary>
public sealed class RestartStateRecordingTests
{
    private static readonly DateTime At = new(2026, 11, 1, 12, 0, 0, DateTimeKind.Utc);

    private static byte[] Json(object value) => Encoding.UTF8.GetBytes(JsonSerializer.Serialize(value));

    /// <summary>
    /// Writes <paramref name="bytes"/> as the file of an earlier server's
    /// recording and returns the reader of that folder.
    /// </summary>
    private static LiveRecordings Earlier(TempDir dir, string folder, string name, byte[] bytes)
    {
        var root = dir.File("recordings");
        var path = Path.Combine(root, "20260101000000000-1-0001", folder);
        Directory.CreateDirectory(path);
        File.WriteAllBytes(Path.Combine(path, name), bytes);
        return new LiveRecordings(() => root);
    }

    // Each file is damaged by random byte changes, truncation and splices.
    [Fact]
    [FuzzEntry(typeof(LiveRecordings))]
    public void Fuzzed_recordings_are_read_without_an_unexpected_exception()
    {
        using var dir = new TempDir();
        var header = new LiveSavedHeader("live-1", "scripted", "prog", false, 1, At, At, "closed", null, "live_session action=attach program=prog", 0);
        var events = Encoding.UTF8.GetBytes(string.Join('\n',
            JsonSerializer.Serialize(new LiveRingEvent(1, At, "stop", 7, 0x1000, "stop point s1 hit 1")),
            JsonSerializer.Serialize(new LiveRingEvent(2, At, "exit", null, null, "session closed", "w1"))));
        var timeline = new LiveTimelineRecord("tl-1", "live-1", "prog", 1, "scripted trace", At, null, 0, "start", At, [new(1, At, "file", "a.txt")]);
        var coverage = new LiveCoverageRecord("cov-1", "live-1", "prog", "img", "ab", 100, 0x1000, At, null, false, false, 0, "start", At,
            [new(1, "f")], new Dictionary<uint, long> { [1] = 2 }, new Dictionary<uint, string> { [2] = "short" });
        var console = new LiveConsoleRecord("con-1", "prog", ["a"], "host", 120, 30, 1, At, 0, 0, "start", At,
            [new(1, At, "hi", false), new(2, At, "pro", true)], [new(new(1, "send a", "send", "a", 0, 0), "running", 1, null)]);

        var cases = new (string Folder, string Name, byte[] Seed, Func<LiveRecordings, object?> Read)[]
        {
            ("live-1", "session.json", Json(header), r => Touch(r.ReadSession("live-1"))),
            ("live-1", "events.jsonl", events, r => Touch(r.ReadSession("live-1"))),
            ("live-1", "tl-1.json", Json(timeline), r => r.ReadRun<LiveTimelineRecord>("tl-1") is { } k ? new LiveTimelineRun(k).Record() : null),
            ("live-1", "cov-1.json", Json(coverage), r => r.ReadRun<LiveCoverageRecord>("cov-1") is { } k ? new LiveCoverageRun(k).Record() : null),
            ("console", "con-1.json", Json(console), r => r.ReadRun<LiveConsoleRecord>("con-1") is { } k ? new LiveConsoleRun(k).Record() : null),
        };
        foreach (var (folder, name, seed, read) in cases)
        {
            using var own = new TempDir();
            // The session file beside an events file keeps the session readable.
            var reader = Earlier(own, folder, name, seed);
            if (name == "events.jsonl") File.WriteAllBytes(Path.Combine(own.File("recordings"), "20260101000000000-1-0001", folder, "session.json"), Json(header));
            var path = Path.Combine(own.File("recordings"), "20260101000000000-1-0001", folder, name);
            var failures = FormatFuzz.Run(seed, bytes =>
            {
                File.WriteAllBytes(path, bytes);
                read(reader);
            }, 200);
            Assert.True(failures.Count == 0, name + ": " + string.Join("\n", failures.Take(10)));
        }
    }

    private static object? Touch(LiveSavedSession? session) => session?.Page(0, null, null, 10);

    // The header build takes a lock that the appending thread holds, as a session does.
    [Fact]
    public async Task Appending_while_the_header_is_saved_does_not_deadlock()
    {
        using var dir = new TempDir();
        using var server = new LiveRecordings(() => dir.File("recordings"));
        var session = new object();
        using var log = server.OpenEvents("live-1", unkept => { lock (session) return new { unkept }; });
        var append = Task.Run(() =>
        {
            for (var i = 1; i <= 2000; i++)
                lock (session) log.Append(new LiveRingEvent(i, At, "stop", 1, 0x1000, "stop point"));
        });
        var save = Task.Run(() => { for (var i = 0; i < 500; i++) log.Save(); });
        await Task.WhenAll(append, save).WaitAsync(TimeSpan.FromMinutes(2));
    }

    [Fact]
    public void A_cut_last_line_keeps_the_events_before_it()
    {
        using var dir = new TempDir();
        var header = new LiveSavedHeader("live-1", "scripted", "prog", false, 1, At, At, "closed", null, "live_session action=attach program=prog", 0);
        var reader = Earlier(dir, "live-1", "session.json", Json(header));
        var line = JsonSerializer.Serialize(new LiveRingEvent(1, At, "stop", 7, 0x1000, "stop point s1 hit 1"));
        File.WriteAllText(Path.Combine(dir.File("recordings"), "20260101000000000-1-0001", "live-1", "events.jsonl"), line + "\n" + line[..20]);
        var session = reader.ReadSession("live-1");
        Assert.Single(session!.Events);
        Assert.Equal("stop point s1 hit 1", session.Events[0].Text);
    }
}
