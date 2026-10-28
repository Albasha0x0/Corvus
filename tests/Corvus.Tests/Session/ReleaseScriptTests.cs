using System.Diagnostics;

namespace Corvus.Tests;

/// <summary>release.ps1 takes its targets from release.yml, names this repository, and parses.</summary>
public class ReleaseScriptTests
{
    private static readonly string Script = File.ReadAllText(Path.Combine(DocsTests.RepoRoot(), "release.ps1"));

    [Fact]
    public void Targets_come_from_the_workflow_and_the_repository_is_this_one()
    {
        Assert.Contains(".github/workflows/release.yml", Script);
        Assert.Contains("'SHA256SUMS'", Script);
        Assert.Contains("docs/release-notes.md", Script);
        Assert.DoesNotMatch(@"\b(?:win|linux|osx)-(?:x64|arm64)\b", Script);
        Assert.Contains($"$Repo = '{Corvus.Setup.Installation.DefaultRepository}'", Script);
    }

    [Fact]
    public void The_release_script_checks_and_lists_every_channel()
    {
        // Assets the verification expects, matching what release.yml attaches.
        Assert.Contains("\"corvus-$_.mcpb\"", Script);
        Assert.Contains($"\"{Corvus.Setup.Installation.PackageId}.$Version.nupkg\"", Script);
        var workflow = File.ReadAllText(Path.Combine(DocsTests.RepoRoot(), ".github", "workflows", "release.yml"));
        Assert.Contains($"{Corvus.Setup.Installation.PackageId}.*.nupkg", workflow);
        Assert.Contains("dotnet pack src/Corvus/Corvus.csproj", workflow);
        foreach (var channel in new[] { "MCP bundle:", ".NET tool:", "nuget.org:", "MCP Registry:", "winget, Scoop, Homebrew:", "plugin marketplace" })
            Assert.Contains(channel, Script);
        // The repository stays private until the user decides: the script itself never pushes a package anywhere.
        Assert.DoesNotMatch(@"(?m)^\s*(?:Run|&)\s.*nuget push", Script);
    }

    [Fact]
    public void The_tagged_commit_and_the_release_carry_the_test_summary()
    {
        Assert.Contains("$testSummary = 'release/tests.json'", Script);
        Assert.Contains("$assets += 'corvus-tests.json'", Script);
        Assert.Contains("$assets += 'corvus-sbom.cdx.json', 'corvus-docs.zip', 'install.ps1', 'install.sh'", Script);
        Assert.True(Script.IndexOf("Write-TestSummary (Join-Path $root $testSummary)", StringComparison.Ordinal)
            < Script.IndexOf("Run 'git' @('add', '-A')", StringComparison.Ordinal), "the summary is written after the commit");
        var workflow = File.ReadAllText(Path.Combine(DocsTests.RepoRoot(), ".github", "workflows", "release.yml"));
        Assert.Contains("cp release/tests.json corvus-tests.json", workflow);
    }

    // Fixture: a ledger line, one push run with its class records, two family stamps and the last run, all on HEAD.
    [Fact]
    [Trait("Speed", "Slow")]
    public void The_summary_reports_the_recorded_pass_and_names_what_is_unknown()
    {
        if (BundleTests.FindOnPath(OperatingSystem.IsWindows() ? "pwsh.exe" : "pwsh") is not { } pwsh) return;
        var root = DocsTests.RepoRoot();
        using var git = Process.Start(new ProcessStartInfo("git", ["-C", root, "rev-parse", "HEAD"]) { RedirectStandardOutput = true })!;
        var head = git.StandardOutput.ReadToEnd().Trim();
        git.WaitForExit();
        using var dir = new TempDir();
        var evidence = Directory.CreateDirectory(Path.Combine(dir.Path, "git")).FullName;
        var shortHead = head[..8];
        File.WriteAllText(Path.Combine(evidence, "corvus-full-passes.txt"), $"{head} {new string('a', 40)} sampled reused 2026-10-20T10:00\n");
        File.WriteAllText(Path.Combine(evidence, "corvus-test-history.jsonl"), string.Join("\n",
            $$$"""{"kind":"run","run":"r1","mode":"push","commit":"{{{shortHead}}}","at":"2026-10-20 10:00","code":0,"permits":{"engine-ida":1.0},"tests":3,"failed":0}""",
            """{"kind":"class","run":"r1","mode":"push","name":"ReleaseScriptTests","tests":2}""",
            """{"kind":"class","run":"r1","mode":"push","name":"BundleTests","tests":1}""") + "\n");
        File.WriteAllText(Path.Combine(evidence, "corvus-family-stamps.json"),
            $$$"""{"Session":{"key":"k","mode":"sampled","commit":"{{{shortHead}}}","at":"2026-10-20 10:00"},"Containers":{"key":"k","mode":"exhaustive","commit":"0badc0de","at":"2026-10-19 09:00"}}""");
        File.WriteAllText(Path.Combine(evidence, "corvus-last-run.json"), $$$"""{"commit":"{{{shortHead}}}","deferred":["HostOnlyTests"]}""");
        var output = Path.Combine(dir.Path, "tests.json");

        var psi = new ProcessStartInfo(pwsh) { RedirectStandardOutput = true, RedirectStandardError = true, UseShellExecute = false };
        foreach (var a in new[] { "-NoProfile", "-File", Path.Combine(root, "release.ps1"), "-Version", "9.8.7", "-Summary", output, "-Evidence", evidence })
            psi.ArgumentList.Add(a);
        using var p = Process.Start(psi)!;
        var log = p.StandardOutput.ReadToEnd() + p.StandardError.ReadToEnd();
        p.WaitForExit();
        Assert.True(p.ExitCode == 0, log);

        var summary = System.Text.Json.Nodes.JsonNode.Parse(File.ReadAllText(output))!;
        Assert.Equal(head, (string?)summary["commit"]);
        Assert.Equal("sampled", (string?)summary["strength"]);
        Assert.True((bool)summary["reusedEarlierPasses"]!);
        Assert.Equal(3, (int)summary["testsRun"]!);
        Assert.Equal("ran", (string?)summary["engines"]!["ida"]);
        Assert.StartsWith("not in this run", (string?)summary["engines"]!["ghidra"]);
        Assert.Equal(["HostOnlyTests"], summary["deferred"]!["classes"]!.AsArray().Select(c => (string)c!));
        var families = summary["families"]!.AsArray().ToDictionary(f => (string)f!["name"]!, f => f!["tests"]!.ToString());
        Assert.Equal("2", families["Session"]);
        // No run on record for the Containers stamp's commit.
        Assert.Equal("unknown", families["Containers"]);
    }

    // Regression for c43ad0b8: a second run with -Push stopped on the tag the
    // first run made (v2.7.1).
    // Fixture: a repository holding the script and workflow, its main tagged,
    // and a bare repository as origin.
    // Regression for v2.7.2 (18598077): an expired asset link failed the
    // download, and the notes, set after it, never reached the release.
    [Fact]
    public void The_notes_reach_the_release_before_a_retried_asset_download()
    {
        int notes = Script.IndexOf("'release', 'edit', $tag", StringComparison.Ordinal);
        int download = Script.IndexOf("gh release download $tag", StringComparison.Ordinal);
        Assert.True(notes > 0 && download > notes, "the notes edit comes before the asset download");
        Assert.Contains("failed 3 times", Script);
        Assert.DoesNotContain("Run 'gh' @('release', 'download'", Script);
    }

    [Fact]
    [Trait("Speed", "Slow")]
    public void A_run_with_push_pushes_a_tag_an_earlier_run_made_and_refuses_one_on_another_commit()
    {
        if (BundleTests.FindOnPath(OperatingSystem.IsWindows() ? "pwsh.exe" : "pwsh") is not { } pwsh) return;
        using var dir = new TempDir();
        var origin = Path.Combine(dir.Path, "origin.git");
        var work = Directory.CreateDirectory(Path.Combine(dir.Path, "work")).FullName;
        Git(dir.Path, "init", "-q", "--bare", origin);
        Git(work, "init", "-q", "-b", "main");
        File.Copy(Path.Combine(DocsTests.RepoRoot(), "release.ps1"), Path.Combine(work, "release.ps1"));
        Directory.CreateDirectory(Path.Combine(work, ".github", "workflows"));
        File.Copy(Path.Combine(DocsTests.RepoRoot(), ".github", "workflows", "release.yml"), Path.Combine(work, ".github", "workflows", "release.yml"));
        Git(work, "add", "-A");
        Git(work, "commit", "-q", "-m", "chore(release): version 9.8.7");
        Git(work, "remote", "add", "origin", origin);

        Git(work, "tag", "-a", "v9.8.6", "-m", "Corvus 9.8.6");
        File.WriteAllText(Path.Combine(work, "notes.txt"), "later");
        Git(work, "add", "-A");
        Git(work, "commit", "-q", "-m", "docs(release): a later commit");
        var (code, log) = RunRelease(pwsh, work, "9.8.6", TimeSpan.FromSeconds(60));
        Assert.True(code == 1 && log.Contains("tag v9.8.6 exists"), log);

        Git(work, "tag", "-a", "v9.8.7", "-m", "Corvus 9.8.7");
        // The script waits for the release workflow after pushing; the pushed
        // refs are the result.
        RunRelease(pwsh, work, "9.8.7", TimeSpan.FromSeconds(60), until: () => Git(origin, "tag", "--list", "v9.8.7").Length > 0);
        Assert.Equal(Git(work, "rev-parse", "main"), Git(origin, "rev-parse", "main"));
        Assert.Equal(Git(work, "rev-parse", "v9.8.7"), Git(origin, "rev-parse", "v9.8.7"));
        Assert.Empty(Git(origin, "tag", "--list", "v9.8.6"));
    }

    private static string Git(string dir, params string[] args)
    {
        var psi = new ProcessStartInfo("git") { RedirectStandardOutput = true, RedirectStandardError = true, UseShellExecute = false };
        foreach (var a in new[] { "-C", dir, "-c", "user.name=t", "-c", "user.email=t@example.invalid" }.Concat(args))
            psi.ArgumentList.Add(a);
        using var p = Process.Start(psi)!;
        var output = p.StandardOutput.ReadToEnd();
        var error = p.StandardError.ReadToEnd();
        p.WaitForExit();
        Assert.True(p.ExitCode == 0, $"git {string.Join(' ', args)}: {error}");
        return output.Trim();
    }

    private static (int Code, string Log) RunRelease(string pwsh, string work, string version, TimeSpan limit, Func<bool>? until = null)
    {
        var psi = new ProcessStartInfo(pwsh) { RedirectStandardOutput = true, RedirectStandardError = true, UseShellExecute = false, WorkingDirectory = work };
        foreach (var a in new[] { "-NoProfile", "-File", Path.Combine(work, "release.ps1"), "-Version", version, "-Push", "-Repo", "corvus-test/none" })
            psi.ArgumentList.Add(a);
        using var p = Process.Start(psi)!;
        var output = p.StandardOutput.ReadToEndAsync();
        var error = p.StandardError.ReadToEndAsync();
        var end = DateTime.UtcNow + limit;
        while (!p.HasExited && DateTime.UtcNow < end && !(until?.Invoke() ?? false)) Thread.Sleep(250);
        var stopped = !p.HasExited;
        if (stopped) p.Kill(entireProcessTree: true);
        p.WaitForExit();
        var log = output.Result + error.Result;
        Assert.True(until != null ? until() : !stopped, log);
        return (p.ExitCode, log);
    }

    [Fact]
    [Trait("Speed", "Slow")]
    public void The_release_script_parses_as_PowerShell()
    {
        var path = Path.Combine(DocsTests.RepoRoot(), "release.ps1");
        ProcessStartInfo start = new("pwsh") { RedirectStandardOutput = true, RedirectStandardError = true };
        foreach (var arg in new[] { "-NoProfile", "-Command",
                     $"$e=$null; [void][System.Management.Automation.Language.Parser]::ParseFile('{path.Replace("'", "''")}', [ref]$null, [ref]$e); $e.Count" })
            start.ArgumentList.Add(arg);
        Process? process;
        try { process = Process.Start(start); }
        catch (System.ComponentModel.Win32Exception) { return; } // no pwsh on this machine
        using (process)
        {
            var output = process!.StandardOutput.ReadToEnd();
            process.WaitForExit();
            Assert.Equal("0", output.Trim());
        }
    }
}
