using System.Diagnostics;

namespace Corvus.Tests;

/// <summary>test.ps1 -Status on a background run whose record outlived its process.</summary>
public class BackgroundRunStatusTests
{
    [Fact]
    [Trait("Speed", "Slow")]
    public void A_run_that_ended_without_a_result_is_reported_as_not_running()
    {
        using var dir = new TempDir();
        // No git on this machine.
        if (!Git(dir.Path, "init", "-q")) return;
        // test.ps1 with the modules it imports, as they sit beside it in the repository.
        foreach (var file in Directory.GetFiles(DocsTests.RepoRoot(), "test*.ps*1"))
            File.Copy(file, Path.Combine(dir.Path, Path.GetFileName(file)));
        var gitDir = Path.Combine(dir.Path, ".git");
        File.WriteAllText(Path.Combine(gitDir, "corvus-background.result"), "0123abcd running since 2026-01-01 00:00");
        // This process with another start time: the recorded process is gone.
        File.WriteAllText(Path.Combine(gitDir, "corvus-background.json"),
            $$"""{ "pid": {{Environment.ProcessId}}, "started": 1, "commit": "0123abcd0123abcd0123abcd0123abcd0123abcd", "dir": "x", "strength": "routine" }""");

        ProcessStartInfo start = new("pwsh") { RedirectStandardOutput = true, RedirectStandardError = true, WorkingDirectory = dir.Path };
        foreach (var arg in new[] { "-NoProfile", "-NonInteractive", "-File", Path.Combine(dir.Path, "test.ps1"), "-Status" })
            start.ArgumentList.Add(arg);
        Process? process;
        try { process = Process.Start(start); }
        // No pwsh on this machine.
        catch (System.ComponentModel.Win32Exception) { return; }
        using (process)
        {
            var output = process!.StandardOutput.ReadToEnd();
            var error = process.StandardError.ReadToEnd();
            process.WaitForExit();
            Assert.True(process.ExitCode == 0, error);
            Assert.Contains($"0123abcd not running (pid {Environment.ProcessId} gone, no result)", output);
        }
    }

    private static bool Git(string dir, params string[] args)
    {
        ProcessStartInfo start = new("git") { RedirectStandardOutput = true, RedirectStandardError = true, WorkingDirectory = dir };
        foreach (var arg in args) start.ArgumentList.Add(arg);
        try
        {
            using var p = Process.Start(start)!;
            p.WaitForExit();
            return p.ExitCode == 0;
        }
        catch (System.ComponentModel.Win32Exception) { return false; }
    }
}
