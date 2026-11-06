using System.Diagnostics;

using Corvus.Native.Providers.Worker;

namespace Corvus.Tests;

/// <summary>The rule proof through the "files" worker: arguments cross the pipe and a cancelled call ends the scan.</summary>
public sealed class RuleProofIsolationTests : FileIsolationTestBase
{
    private string CleanFolder(int count)
    {
        var folder = Path.Combine(_dir.Path, "clean");
        Directory.CreateDirectory(folder);
        for (int i = 0; i < count; i++) File.WriteAllText(Path.Combine(folder, "note" + i + ".txt"), "plain text " + i);
        return folder;
    }

    [Fact]
    public async Task A_worker_reads_the_clean_folder_and_names_the_files_it_read()
    {
        var clean = CleanFolder(25);
        using var pool = Pool();
        using var shared = WorkerPool.UseShared(pool);
        await using var session = await Session(false);

        var result = await Call(session, "summarize_file", new() { ["path"] = Env.FixturePath, ["view"] = "hunts", ["cleanFolder"] = clean, ["minFiles"] = 5 });

        Assert.True(result.IsError != true, Whole(result));
        Assert.Contains("25 of 25 files read", Whole(result), StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_cancelled_call_ends_the_scan_in_the_worker_and_the_next_read_succeeds()
    {
        var clean = CleanFolder(20_000);
        using var pool = Pool();
        using var shared = WorkerPool.UseShared(pool);
        await using var session = await Session(false);
        using var cts = new CancellationTokenSource();
        var clock = Stopwatch.StartNew();

        var call = session.Client.CallToolAsync("summarize_file",
            new Dictionary<string, object?> { ["path"] = Env.FixturePath, ["view"] = "hunts", ["cleanFolder"] = clean, ["maxFiles"] = 100_000 },
            cancellationToken: cts.Token).AsTask();
        await Task.Delay(1000);
        cts.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => call);

        Assert.True(clock.Elapsed < TimeSpan.FromSeconds(30), "The cancelled call ran " + clock.Elapsed);
        await ReadsAsync(session, Env.FixturePath);
    }
}
