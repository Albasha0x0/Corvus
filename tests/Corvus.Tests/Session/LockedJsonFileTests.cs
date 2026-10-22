using System.Diagnostics;
using Corvus.Core;
using Xunit.Abstractions;

namespace Corvus.Tests;

/// <summary>Locked JSON records: updates re-read under a lock, so concurrent writers keep each other's records.</summary>
public class LockedJsonFileTests(ITestOutputHelper output) : IDisposable
{
    private readonly TempDir _dir = new();
    public void Dispose() => _dir.Dispose();

    private string Records => _dir.File(Path.Combine("store", "records.json"));

    [Fact]
    public void ConcurrentUpdates_KeepEveryRecord()
    {
        Parallel.For(0, 4, writer =>
        {
            for (int i = 0; i < 25; i++)
            {
                // the records, not the wait limit, are under test: a loaded machine can hold the lock past the 2 s default
                var (_, problem) = LockedJsonFile.Update<Dictionary<string, int>>(Records, current =>
                {
                    var next = current ?? [];
                    next[$"{writer}-{i}"] = i;
                    return next;
                }, timeout: TimeSpan.FromSeconds(60));
                Assert.Null(problem);
            }
        });
        var (all, readProblem) = LockedJsonFile.Read<Dictionary<string, int>>(Records);
        Assert.Null(readProblem);
        Assert.Equal(100, all!.Count);
        Assert.Empty(Directory.GetFiles(Path.GetDirectoryName(Records)!, "*.tmp"));
    }

    [Fact]
    [Trait(PerfBudget.Trait, PerfBudget.Timing)]
    public void HeldLock_TimesOut_AndLeavesTheFileUntouched()
    {
        LockedJsonFile.Update<Dictionary<string, int>>(Records, _ => new() { ["a"] = 1 });
        var before = File.ReadAllBytes(Records);
        // Another process holding the lock looks like this to the updater.
        using (new FileStream(LockedJsonFile.LockPathFor(Records), FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None))
        {
            var clock = Stopwatch.StartNew();
            var (written, problem) = LockedJsonFile.Update<Dictionary<string, int>>(Records, _ => new() { ["b"] = 2 }, timeout: TimeSpan.FromMilliseconds(300));
            Assert.Null(written);
            Assert.Contains("timed out", problem);
            Assert.True(clock.Elapsed >= TimeSpan.FromMilliseconds(250), $"gave up after {clock.Elapsed}");
            PerfBudget.Time("session/json-lock-give-up", clock.Elapsed, TimeSpan.FromSeconds(10), output);
        }
        Assert.Equal(before, File.ReadAllBytes(Records));
        Assert.Null(LockedJsonFile.Update<Dictionary<string, int>>(Records, d => d).Problem); // released: usable again
    }

    [Fact]
    public void MalformedFile_IsLeftUntouched()
    {
        Directory.CreateDirectory(Path.GetDirectoryName(Records)!);
        File.WriteAllText(Records, "{ \"a\": ");
        var (written, problem) = LockedJsonFile.Update<Dictionary<string, int>>(Records, _ => new() { ["b"] = 2 });
        Assert.Null(written);
        Assert.Contains("left untouched", problem);
        Assert.Equal("{ \"a\": ", File.ReadAllText(Records));
    }

    [Fact]
    public void NullMerge_DeletesTheFile()
    {
        LockedJsonFile.Update<Dictionary<string, int>>(Records, _ => new() { ["a"] = 1 });
        Assert.Null(LockedJsonFile.Update<Dictionary<string, int>>(Records, _ => null).Problem);
        Assert.False(File.Exists(Records));
        Assert.Equal((null, null), LockedJsonFile.Read<Dictionary<string, int>>(Records));
    }
}
