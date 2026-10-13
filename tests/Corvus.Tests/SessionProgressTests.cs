using System.Collections.Concurrent;
using System.Diagnostics;
using System.Text.Json;
using ModelContextProtocol;
using ModelContextProtocol.Protocol;

namespace Corvus.Tests;

/// <summary>load_session over the protocol: progress from its first step, and its text and record pages.</summary>
[Collection(InProcessCatalogCollection.Name)]
public sealed class SessionProgressTests : IDisposable
{
    private readonly TempDir _dir = new();

    public void Dispose() => _dir.Dispose();

    [Fact]
    public async Task LoadSessionReportsProgressFromItsFirstStep()
    {
        await using var server = await InProcessServer.StartAsync();
        var session = _dir.File("work.session.json");
        Assert.NotEqual(true, (await server.Client.CallToolAsync("save_session", new Dictionary<string, object?> { ["outputPath"] = session })).IsError);

        var updates = new ConcurrentQueue<(long Ms, ProgressNotificationParams Value)>();
        var clock = Stopwatch.StartNew();
        await using var handler = server.Client.RegisterNotificationHandler(NotificationMethods.ProgressNotification, (n, _) =>
        {
            updates.Enqueue((clock.ElapsedMilliseconds, n.Params.Deserialize<ProgressNotificationParams>(McpJsonUtilities.DefaultOptions)!));
            return ValueTask.CompletedTask;
        });
        var result = await server.Client.CallToolAsync("load_session", new Dictionary<string, object?> { ["path"] = session }, new Progress());
        Assert.NotEqual(true, result.IsError);
        for (int i = 0; i < 250 && !updates.Any(u => u.Value.Progress.Progress == u.Value.Progress.Total); i++) await Task.Delay(20);
        Assert.True(updates.TryPeek(out var first), "no progress");
        Assert.InRange(first.Ms, 0, 5_000);
        Assert.StartsWith("Reading work.session.json", first.Value.Progress.Message);

        var text = string.Concat(result.Content.OfType<TextContentBlock>().Select(b => b.Text));
        Assert.StartsWith($"Session {session}, targetBuild=same: already_loaded 1\nNote: items on files", text);
        Assert.Contains("Nothing changed (dry run); pass dryRun=false to apply.\n1 item (showing 1-1):\n  file     TestFixture  already_loaded (same_build), 1: TestFixture", text);
        var record = JsonDocument.Parse(result.StructuredContent!.Value.GetRawText()).RootElement;
        Assert.Equal((1, false), (record.GetProperty("total").GetInt32(), record.GetProperty("hasMore").GetBoolean()));
    }

    private sealed class Progress : IProgress<ProgressNotificationValue>
    {
        public void Report(ProgressNotificationValue value) { }
    }
}
