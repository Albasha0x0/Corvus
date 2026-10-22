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
    public void Real_data_is_copied_where_the_host_lacks_it_and_refused_when_space_runs_short()
    {
        var log = _dir.File("transport.log");
        var assemblies = Path.Combine(_dir.Path, "asm");
        var bundles = Path.Combine(_dir.Path, "pairs");
        Directory.CreateDirectory(assemblies);
        Directory.CreateDirectory(bundles);
        File.WriteAllText(Path.Combine(assemblies, "a.dll"), "abc");
        File.WriteAllText(Path.Combine(bundles, "old.js"), "12345");
        // The stand-in ssh decodes each host script: the query is answered with a host that holds the assemblies
        // folder's copy already and has the free space the free.txt file names; every other script is logged.
        var free = _dir.File("free.txt");
        var ssh = _dir.File("ssh.ps1");
        File.WriteAllText(ssh, $$"""
            if (($args -join ' ') -notmatch '-EncodedCommand (\S+)') { exit 1 }
            $script = [Text.Encoding]::Unicode.GetString([Convert]::FromBase64String($Matches[1]))
            if ($script -match 'ConvertTo-Json') {
                $assemblies = @{ Value = 'C:\Users\t\corvus-data\CORVUS_ASSEMBLY_DIR\asm'; Exists = $true; Marker = '3 asm' }
                @{ Home = 'C:\Users\t'; Free = [long](Get-Content {{Quote(free)}}); Vars = @{ CORVUS_ASSEMBLY_DIR = $assemblies } } | ConvertTo-Json -Compress -Depth 4
                exit 0
            }
            Add-Content {{Quote(log)}} ("ssh " + $script.Replace("`n", ' '))
            exit 0
            """);
        var scp = _dir.File("scp.ps1");
        File.WriteAllText(scp, $$"""
            Add-Content {{Quote(log)}} ("scp " + (($args | Select-Object -Last 3 | ForEach-Object { [IO.Path]::GetFileName("$_".TrimEnd('/')) }) -join ' '))
            exit 0
            """);
        var lines = TestReuseTests.Run($$"""
            $env:CORVUS_TEST_SSH = {{Quote(ssh)}}; $env:CORVUS_TEST_SCP = {{Quote(scp)}}
            Get-ChildItem Env:CORVUS_* | Where-Object Name -notlike 'CORVUS_TEST_*' | ForEach-Object { Remove-Item "Env:$($_.Name)" }
            $env:CORVUS_ASSEMBLY_DIR = {{Quote(assemblies)}}; $env:CORVUS_BUNDLE_PAIRS = {{Quote(bundles)}}
            Set-Content {{Quote(free)}} 100
            & {{Script}} -Target tester@host2 -Data
            'refused=' + $LASTEXITCODE
            Set-Content {{Quote(free)}} (100GB)
            & {{Script}} -Target tester@host2 -Data
            'copied=' + $LASTEXITCODE
            if (Test-Path {{Quote(log)}}) { Get-Content {{Quote(log)}} }
            """);
        if (lines is ["skip"]) return;
        Assert.Contains(lines, l => l.StartsWith("Refused: the copy would leave under 10 GB free on tester@host2"));
        Assert.Contains("refused=1", lines);
        Assert.Contains(lines, l => l.StartsWith("Real data: 1 to copy (0.0 GB), 1 kept; 100.0 GB free on tester@host2."));
        Assert.Contains("- copied CORVUS_BUNDLE_PAIRS (0 MB)", lines);
        Assert.Contains("copied=0", lines);
        Assert.Contains(lines, l => l.Contains("not copied, programs the host installs itself:") && l.Contains("CORVUS_TSHARK"));
        // Only the missing folder travels, after its old copy is cleared, and its variable is set to the copy.
        Assert.Contains("scp -q pairs CORVUS_BUNDLE_PAIRS", lines);
        Assert.DoesNotContain(lines, l => l.StartsWith("scp ") && l.Contains("asm"));
        Assert.Contains(lines, l => l.StartsWith("ssh ") && l.Contains("Remove-Item") && l.Contains(@"corvus-data\CORVUS_BUNDLE_PAIRS"));
        Assert.Contains(lines, l => l.StartsWith("ssh ") && l.Contains(@"SetEnvironmentVariable('CORVUS_BUNDLE_PAIRS', (Join-Path $HOME 'corvus-data\CORVUS_BUNDLE_PAIRS\pairs'), 'User')") && l.Contains("'5 pairs'"));
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
