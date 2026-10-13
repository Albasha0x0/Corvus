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
        // Handlers may run concurrently, so arrival order is not send order: the first step is the lowest progress.
        var first = updates.OrderBy(u => u.Value.Progress.Progress).ThenBy(u => u.Ms).FirstOrDefault();
        Assert.Equal("Reading work.session.json", first.Value?.Progress.Message);
        Assert.InRange(first.Ms, 0, 5_000);

        var text = string.Concat(result.Content.OfType<TextContentBlock>().Select(b => b.Text));
        // The per-user note store is shared by the test run, so a notes row may follow the file's.
        Assert.StartsWith($"Session {session}, targetBuild=same: already_loaded 1", text);
        Assert.Contains("\nNote: items on files that are not loaded yet report would_apply without checking them\nNothing changed (dry run); pass dryRun=false to apply.\n", text);
        Assert.Contains("\n  file     TestFixture  already_loaded (same_build), 1: TestFixture\n", text);
        var record = JsonDocument.Parse(result.StructuredContent!.Value.GetRawText()).RootElement;
        Assert.False(record.GetProperty("hasMore").GetBoolean());
        Assert.Equal(record.GetProperty("total").GetInt32(), record.GetProperty("items").GetArrayLength());
    }

    private sealed class Progress : IProgress<ProgressNotificationValue>
    {
        public void Report(ProgressNotificationValue value) { }
    }
}
