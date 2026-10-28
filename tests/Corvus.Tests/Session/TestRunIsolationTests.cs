using Corvus.Native.Annotations;
using Corvus.Native.Providers;

namespace Corvus.Tests;

/// <summary>What a test run keeps to itself: its annotations folder, removed by the next run once the run has ended.</summary>
public class TestRunIsolationTests
{
    [Fact]
    public void A_run_keeps_sidecars_and_journals_in_a_folder_of_its_own()
    {
        // Regression: a killed server's unsaved-edit journal in the shared data folder reached later runs' NotesTests.
        Assert.Equal(LeakGuard.RunAnnotations, Environment.GetEnvironmentVariable(AnnotationStore.RootVariable));
        Assert.Equal(Path.GetFullPath(LeakGuard.RunAnnotations), new AnnotationStore().Root);
        Assert.StartsWith($"corvus-test-annotations-{Environment.ProcessId}-", Path.GetFileName(LeakGuard.RunAnnotations));
    }

    [Fact]
    public void An_ended_run_s_annotations_folder_is_removed_at_the_next_start()
    {
        // No process has this id, so the run that named the folder has ended.
        var ended = Path.Combine(LeakGuard.SharedTemp, $"corvus-test-annotations-{int.MaxValue - 3}-{Guid.NewGuid().ToString("N")[..8]}");
        Directory.CreateDirectory(Path.Combine(ended, "journal"));
        File.WriteAllText(Path.Combine(ended, "journal", "0000.1.a.edits.json"), "{}");
        var live = Path.Combine(LeakGuard.SharedTemp, $"corvus-test-annotations-{Environment.ProcessId}-{Guid.NewGuid().ToString("N")[..8]}");
        Directory.CreateDirectory(live);
        try
        {
            LeakGuard.RemoveEndedRuns();
            Assert.False(Directory.Exists(ended));
            Assert.True(Directory.Exists(live));
        }
        finally
        {
            foreach (var dir in new[] { ended, live })
                if (Directory.Exists(dir)) Directory.Delete(dir, true);
        }
    }

    // Reproduces the push run on d2fd7992: a tool folder of an ended server
    // failed the leak check.
    [Fact]
    public void An_ended_process_s_tool_folder_is_swept_and_a_running_one_s_is_reported()
    {
        using var run = new TempDir();
        // No process has this id, so the process that named the folder has ended.
        var ended = Directory.CreateDirectory(run.File(Path.Combine(PrivateFolder.TempRootName, "run", $"{int.MaxValue - 3}-a"))).FullName;
        File.WriteAllText(Path.Combine(ended, "left.dll"), "x");
        Assert.Empty(LeakGuard.Leftovers(run.Path));
        var running = Directory.CreateDirectory(run.File(Path.Combine(PrivateFolder.TempRootName, "run", $"{Environment.ProcessId}-b"))).FullName;
        File.WriteAllText(Path.Combine(running, "left.dll"), "x");
        Assert.Equal([PrivateFolder.TempRootName + "/run"], LeakGuard.Leftovers(run.Path));
        Assert.True(Directory.Exists(running));
    }
}
