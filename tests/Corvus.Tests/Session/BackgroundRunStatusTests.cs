using System.Diagnostics;

namespace Corvus.Tests;

/// <summary>test.ps1 -Status and -Wait on a recorded background run.</summary>
public class BackgroundRunStatusTests
{
    [Fact]
    [Trait("Speed", "Slow")]
    public void A_run_that_ended_without_a_result_is_reported_as_not_running()
    {
        using var dir = new TempDir();
        // No git on this machine.
        if (!Copy(dir.Path)) return;
        var gitDir = Path.Combine(dir.Path, ".git");
        File.WriteAllText(Path.Combine(gitDir, "corvus-background.result"), "0123abcd running since 2026-01-01 00:00");
        // This process with another start time: the recorded process is gone.
        File.WriteAllText(Path.Combine(gitDir, "corvus-background.json"),
            $$"""{ "pid": {{Environment.ProcessId}}, "started": 1, "commit": "0123abcd0123abcd0123abcd0123abcd0123abcd", "dir": "x", "strength": "routine" }""");

        // No pwsh on this machine.
        if (Script(dir.Path, "-Status") is not { } status) return;
        Assert.True(status.Code == 0, status.Error);
        Assert.Contains($"0123abcd not running (pid {Environment.ProcessId} gone, no result)", status.Output);
    }

    [Fact]
    [Trait("Speed", "Slow")]
    public void A_wait_returns_when_the_recorded_run_ends_and_exits_with_its_result()
    {
        using var dir = new TempDir();
        // No git on this machine.
        if (!Copy(dir.Path)) return;
        var gitDir = Path.Combine(dir.Path, ".git");
        File.WriteAllText(Path.Combine(gitDir, "corvus-background.result"), "0123abcd passed at 2026-01-01 00:00");
        // The recorded run: a process that ends after 3 s.
        ProcessStartInfo sleep = new("pwsh") { RedirectStandardOutput = true };
        foreach (var arg in new[] { "-NoProfile", "-NonInteractive", "-Command", "Start-Sleep -Seconds 3" })
            sleep.ArgumentList.Add(arg);
        Process? run;
        try { run = Process.Start(sleep); }
        // No pwsh on this machine.
        catch (System.ComponentModel.Win32Exception) { return; }
        using (run)
        {
            File.WriteAllText(Path.Combine(gitDir, "corvus-background.json"),
                $$"""{ "pid": {{run!.Id}}, "started": {{run.StartTime.ToUniversalTime().Ticks}}, "commit": "0123abcd0123abcd0123abcd0123abcd0123abcd", "dir": "x", "strength": "routine" }""");
            var (code, output, error) = Script(dir.Path, "-Wait")!.Value;
            Assert.True(run.HasExited, "returned while the recorded run was going");
            Assert.True(code == 0, error);
            Assert.Contains("0123abcd passed at", output);
        }
        File.WriteAllText(Path.Combine(gitDir, "corvus-background.result"), "0123abcd FAILED (exit 1) at 2026-01-01 00:00");
        Assert.Equal(1, Script(dir.Path, "-Wait")!.Value.Code);
    }

    [Fact]
    [Trait("Speed", "Slow")]
    public void Status_names_the_failed_CI_jobs_and_an_unknown_release_result()
    {
        // Regression: -Status reported the offload passed on eadaaa2b while its
        // CI test jobs failed.
        using var dir = new TempDir();
        // No git on this machine.
        if (!Copy(dir.Path)) return;
        Git(dir.Path, "-c", "user.name=t", "-c", "user.email=t@t", "commit", "-q", "--allow-empty", "-m", "c");
        Git(dir.Path, "update-ref", "refs/remotes/origin/main", "HEAD");
        Git(dir.Path, "remote", "add", "origin", "https://github.com/owner/app.git");
        // Stands in for gh: a failed CI push run with two failed jobs; the
        // release list fails as without a login.
        var gh = Path.Combine(dir.Path, "gh.ps1");
        File.WriteAllText(gh, """
            $a = $args -join ' '
            if ($a -match '^run list -R owner/app --workflow ci\.yml .*--commit [0-9a-f]{40} --event push') {
                '[{"databaseId":11,"status":"completed","conclusion":"failure","headSha":"0123abcd0123","headBranch":"main","createdAt":"2026-01-01T00:00:00Z"}]'; exit 0
            }
            if ($a -match '^run view 11 -R owner/app --json jobs') {
                '{"jobs":[{"name":"test (ubuntu-latest)","conclusion":"failure"},{"name":"test (windows-latest)","conclusion":"success"},{"name":"test (macos-latest)","conclusion":"failure"}]}'; exit 0
            }
            [Console]::Error.WriteLine('To get started with GitHub CLI, please run:  gh auth login'); exit 4
            """);

        // No pwsh on this machine.
        if (Script(dir.Path, "-Status", ("CORVUS_TEST_GH", gh)) is not { } status) return;
        Assert.True(status.Code == 0, status.Error);
        Assert.Contains("CI workflow on main ", status.Output);
        Assert.Contains(": failure in run 11 on main (0123abcd) at 2026-01-01 00:00 UTC; failed jobs: test (ubuntu-latest), test (macos-latest)", status.Output);
        Assert.Contains("Release workflow: unknown (gh exit 4: To get started with GitHub CLI", status.Output);
    }

    // test.ps1 with the modules it imports, as they sit beside it in the repository, in a new repository; false without git.
    private static bool Copy(string dir)
    {
        if (!Git(dir, "init", "-q")) return false;
        foreach (var file in Directory.GetFiles(DocsTests.RepoRoot(), "test*.ps*1"))
            File.Copy(file, Path.Combine(dir, Path.GetFileName(file)));
        return true;
    }

    // Runs the copied test.ps1 with one switch and an optional environment
    // variable; null without pwsh.
    private static (int Code, string Output, string Error)? Script(string dir, string option, (string Name, string Value)? variable = null)
    {
        ProcessStartInfo start = new("pwsh") { RedirectStandardOutput = true, RedirectStandardError = true, WorkingDirectory = dir };
        if (variable is { } v) start.Environment[v.Name] = v.Value;
        foreach (var arg in new[] { "-NoProfile", "-NonInteractive", "-File", Path.Combine(dir, "test.ps1"), option })
            start.ArgumentList.Add(arg);
        Process? process;
        try { process = Process.Start(start); }
        catch (System.ComponentModel.Win32Exception) { return null; }
        using (process)
        {
            var output = process!.StandardOutput.ReadToEnd();
            var error = process.StandardError.ReadToEnd();
            process.WaitForExit();
            return (process.ExitCode, output, error);
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
