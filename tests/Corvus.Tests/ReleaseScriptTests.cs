using System.Diagnostics;

namespace Corvus.Tests;

/// <summary>release.ps1 takes its targets from release.yml, names this repository, and parses.</summary>
public class ReleaseScriptTests
{
    private static readonly string Script = File.ReadAllText(Path.Combine(DocsTests.RepoRoot(), "release.ps1"));

    [Fact]
    public void TargetsComeFromTheWorkflowAndTheRepositoryIsOurs()
    {
        Assert.Contains(".github/workflows/release.yml", Script);
        Assert.Contains("'SHA256SUMS'", Script);
        Assert.Contains("docs/release-notes.md", Script);
        Assert.DoesNotMatch(@"\b(?:win|linux|osx)-(?:x64|arm64)\b", Script);
        Assert.Contains($"$Repo = '{Corvus.Setup.Installation.DefaultRepository}'", Script);
    }

    [Fact]
    [Trait("Speed", "Slow")]
    public void ParsesAsPowerShell()
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
