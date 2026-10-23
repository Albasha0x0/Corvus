using Corvus.Native.Annotations;

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
}
