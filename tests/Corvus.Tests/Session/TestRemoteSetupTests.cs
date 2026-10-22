namespace Corvus.Tests;

/// <summary>test-remote-setup.ps1: preparing a test host over ssh, and its check of what a host is missing.</summary>
public sealed class TestRemoteSetupTests : IDisposable
{
    private readonly TempDir _dir = new();

    public void Dispose() => _dir.Dispose();

    private static string Script => Quote(Path.Combine(DocsTests.RepoRoot(), "test-remote-setup.ps1"));

    private static string Quote(string path) => "'" + path.Replace("'", "''") + "'";

    [Fact]
    [Trait("Speed", "Slow")]
    public void A_setup_copies_its_files_to_the_host_and_runs_there_with_its_exit_code()
    {
        var log = _dir.File("transport.log");
        // The stand-in ssh answers the host run with a missing tool and exit 1; every call is logged.
        var ssh = _dir.File("ssh.ps1");
        File.WriteAllText(ssh, $$"""
            Add-Content {{Quote(log)}} ("ssh " + ($args -join ' '))
            if (($args -join ' ') -match '-OnHost') { 'Not ready: 1 missing.'; exit 1 }
            exit 0
            """);
        var scp = _dir.File("scp.ps1");
        File.WriteAllText(scp, $$"""
            Add-Content {{Quote(log)}} ("scp " + (($args | ForEach-Object { [IO.Path]::GetFileName($_.TrimEnd('/')) }) -join ' '))
            exit 0
            """);
        var lines = TestReuseTests.Run($$"""
            $env:CORVUS_TEST_SSH = {{Quote(ssh)}}; $env:CORVUS_TEST_SCP = {{Quote(scp)}}
            & {{Script}} -Target tester@host2 -Check -Repository https://example.invalid/repo.git
            'exit=' + $LASTEXITCODE
            Get-Content {{Quote(log)}}
            """);
        if (lines is ["skip"]) return;
        Assert.Contains("Not ready: 1 missing.", lines);
        Assert.Contains("exit=1", lines);
        Assert.Contains(lines, l => l.StartsWith("scp ") && l.EndsWith("test-remote-setup.ps1 fetch-remote-tools.ps1 remote-tools-assets.json tester@host2:corvus-test-host"));
        Assert.Contains(lines, l => l.StartsWith("ssh ") && l.Contains("BatchMode=yes") && l.EndsWith(
            @"tester@host2 powershell -NoProfile -ExecutionPolicy Bypass -File corvus-test-host\test-remote-setup.ps1 -OnHost -Repository https://example.invalid/repo.git -Check"));
    }

    [Fact]
    [Trait("Speed", "Slow")]
    public void A_check_of_an_empty_host_folder_names_each_missing_tool_and_changes_nothing()
    {
        var host = Path.Combine(_dir.Path, "host");
        var lines = TestReuseTests.Run($$"""
            & {{Script}} -OnHost -Check -ToolsOnly -Base {{Quote(host)}} -Repository https://example.invalid/repo.git
            'exit=' + $LASTEXITCODE
            'created=' + (Test-Path {{Quote(host)}})
            """);
        if (lines is ["skip"]) return;
        using var table = System.Text.Json.JsonDocument.Parse(File.ReadAllText(Path.Combine(DocsTests.RepoRoot(), "tests", "Corvus.Tests", "Support", "remote-tools-assets.json")));
        foreach (var tool in table.RootElement.GetProperty("tools").EnumerateArray())
            Assert.Contains($"missing: {tool.GetProperty("name").GetString()} {tool.GetProperty("version").GetString()}", lines);
        Assert.Contains("missing: the clone of https://example.invalid/repo.git", lines);
        Assert.Contains("missing: frida (its pinned release comes with the clone)", lines);
        Assert.Contains("exit=1", lines);
        Assert.Contains("created=False", lines);
    }
}
