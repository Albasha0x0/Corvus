using System.Diagnostics;

namespace Corvus.Tests;

/// <summary>test-reuse.psm1: which families a change makes stale, and which families a run's results let us record.</summary>
public class TestReuseTests
{
    private const string Trx = """
        <TestRun xmlns="http://microsoft.com/schemas/VisualStudio/TeamTest/2010">
          <Results>
            <UnitTestResult testId="1" outcome="Passed" />
            <UnitTestResult testId="2" outcome="Failed" />
            <UnitTestResult testId="3" outcome="Passed" />
            <UnitTestResult testId="4" outcome="NotExecuted" />
          </Results>
          <TestDefinitions>
            <UnitTest id="1"><TestMethod className="Corvus.Tests.DotnetA" name="M" /></UnitTest>
            <UnitTest id="2"><TestMethod className="Corvus.Tests.EngineB+Nested" name="M" /></UnitTest>
            <UnitTest id="3"><TestMethod className="Corvus.Tests.EngineC" name="M" /></UnitTest>
            <UnitTest id="4"><TestMethod className="Corvus.Tests.WebD" name="M" /></UnitTest>
          </TestDefinitions>
        </TestRun>
        """;

    [Fact]
    [Trait("Speed", "Slow")]
    public void OnlyChangedFamiliesRerunAndOnlyCleanFamiliesAreRecorded()
    {
        var module = Path.Combine(DocsTests.RepoRoot(), "test-reuse.psm1");
        var trx = Path.Combine(Path.GetTempPath(), $"corvus-reuse-{Guid.NewGuid():N}.trx");
        File.WriteAllText(trx, Trx);
        try
        {
            var lines = Run($$"""
                Import-Module '{{module.Replace("'", "''")}}'
                $f = 'Dotnet', 'Engines', 'Contract', 'Session'
                $base = "100644 blob a1`tsrc/Corvus/Tools/Dotnet/X.cs", "100644 blob b1`tsrc/Corvus/Core/Y.cs", "100644 blob c1`tdocs/tools.md", "100644 blob d1`ttests/Corvus.Tests/Engines/T.cs"
                $k0 = Get-FamilyKeys $base $f @('Session') 'env'
                function Changed($lines, $environment = 'env') { $k = Get-FamilyKeys $lines $f @('Session') $environment; ($f | Where-Object { $k[$_] -ne $k0[$_] }) -join ',' }
                'own=' + (Changed ($base -replace 'a1', 'a2'))
                'shared=' + (Changed ($base -replace 'b1', 'b2'))
                'docs=' + (Changed ($base -replace 'c1', 'c2'))
                'test=' + (Changed ($base -replace 'd1', 'd2'))
                'env=' + (Changed $base 'other')
                $stamps = [pscustomobject]@{ Dotnet = [pscustomobject]@{ key = $k0.Dotnet; mode = 'exhaustive' }; Engines = [pscustomobject]@{ key = $k0.Engines; mode = 'sampled' }; Contract = [pscustomobject]@{ key = $k0.Contract; mode = 'exhaustive' } }
                'stale-sampled=' + ((Get-StaleFamilies $k0 $stamps $false) -join ',')
                'stale-exhaustive=' + ((Get-StaleFamilies $k0 $stamps $true) -join ',')
                $map = @{ Dotnet = @('DotnetA'); Engines = @('EngineB', 'EngineC'); Web = @('WebD') }
                'passed=' + ((Get-PassedFamilies '{{trx}}' $map 1) -join ',')
                'unblamed=' + ((Get-PassedFamilies '{{trx}}' @{ Dotnet = @('DotnetA') } 1) -join ',')
                'filter-all=' + ($null -eq (Get-ReuseFilter @('Dotnet', 'Engines', 'Web') $map))
                'filter=' + (Get-ReuseFilter @('Web') $map)
                """);
            if (lines is ["skip"]) return; // no pwsh on this machine
            string Line(string name) => lines.Single(l => l.StartsWith(name + "=")).Substring(name.Length + 1);
            Assert.Equal("Dotnet", Line("own"));                       // a family's own source folder
            Assert.Equal("Dotnet,Engines,Contract,Session", Line("shared")); // shared code
            Assert.Equal("Session", Line("docs"));                     // repository files: only the families that read them
            Assert.Equal("Engines", Line("test"));
            Assert.Equal("Dotnet,Engines,Contract,Session", Line("env")); // SDK, OS build, engine settings
            Assert.Equal("Contract,Session", Line("stale-sampled"));   // Contract always runs; Session has no pass yet
            Assert.Equal("Contract,Engines,Session", Line("stale-exhaustive")); // a sampled pass does not count
            Assert.Equal("Dotnet", Line("passed"));                    // Engines had a failure; Web did not run
            Assert.Equal("", Line("unblamed"));                        // a failure outside the known classes records nothing
            Assert.Equal("True", Line("filter-all"));
            Assert.Contains("FullyQualifiedName~.WebD", Line("filter"));
            Assert.Contains("FullyQualifiedName~.McpProtocolTests", Line("filter"));
            Assert.DoesNotContain("DotnetA", Line("filter"));
        }
        finally { File.Delete(trx); }
    }

    [Fact]
    [Trait("Speed", "Slow")]
    public void PassesAreRecordedWithoutReplacingAnExhaustivePassOnTheSameKey()
    {
        var module = Path.Combine(DocsTests.RepoRoot(), "test-reuse.psm1");
        var stamps = Path.Combine(Path.GetTempPath(), $"corvus-stamps-{Guid.NewGuid():N}.json");
        File.WriteAllText(stamps, """{ "Dotnet": { "key": "k1", "mode": "exhaustive", "commit": "a", "at": "x" }, "Web": { "key": "w1", "mode": "sampled", "commit": "a", "at": "x" } }""");
        try
        {
            var lines = Run($$"""
                Import-Module '{{module.Replace("'", "''")}}'
                Save-FamilyPasses '{{stamps}}' @('Dotnet', 'Engines') @{ Dotnet = 'k1'; Engines = 'e1' } 'sampled' 'b'
                $s = Get-Content '{{stamps}}' -Raw | ConvertFrom-Json
                'dotnet=' + $s.Dotnet.mode + ',' + $s.Dotnet.commit
                'engines=' + $s.Engines.key + ',' + $s.Engines.mode + ',' + $s.Engines.commit
                'web=' + $s.Web.key
                """);
            if (lines is ["skip"]) return; // no pwsh on this machine
            string Line(string name) => lines.Single(l => l.StartsWith(name + "=")).Substring(name.Length + 1);
            Assert.Equal("exhaustive,a", Line("dotnet"));  // a sampled pass leaves the exhaustive one on the same key
            Assert.Equal("e1,sampled,b", Line("engines")); // a new family is recorded
            Assert.Equal("w1", Line("web"));               // families the run did not pass are kept
        }
        finally { File.Delete(stamps); }
    }

    [Fact]
    [Trait("Speed", "Slow")]
    public void DocumentationOnlyChangesAndFailedTestsAreNamed()
    {
        var module = Path.Combine(DocsTests.RepoRoot(), "test-reuse.psm1");
        var trx = Path.Combine(Path.GetTempPath(), $"corvus-reuse-{Guid.NewGuid():N}.trx");
        File.WriteAllText(trx, Trx);
        try
        {
            var lines = Run($$"""
                Import-Module '{{module.Replace("'", "''")}}'
                'docs=' + (Test-DocsOnly @('docs/release-notes.md', 'README.md'))
                'source=' + (Test-DocsOnly @('docs/tools.md', 'src/Corvus/X.cs'))
                'test-doc=' + (Test-DocsOnly @('tests/Corvus.Tests/Notes.md'))
                'script=' + (Test-DocsOnly @('test.ps1'))
                'none=' + (Test-DocsOnly @())
                'failed=' + ((Get-FailedTests '{{trx}}') -join ',')
                """);
            if (lines is ["skip"]) return; // no pwsh on this machine
            string Line(string name) => lines.Single(l => l.StartsWith(name + "=")).Substring(name.Length + 1);
            Assert.Equal("True", Line("docs"));
            Assert.Equal("False", Line("source"));
            Assert.Equal("False", Line("test-doc"));   // files under tests/ are test inputs
            Assert.Equal("False", Line("script"));
            Assert.Equal("False", Line("none"));
            Assert.Equal("Corvus.Tests.EngineB+Nested.M", Line("failed")); // the name a dotnet test filter takes
        }
        finally { File.Delete(trx); }
    }

    [Fact]
    [Trait("Speed", "Slow")]
    public void ACoverageMapKeysSharedCodeOnlyForTheFamiliesThatRanIt()
    {
        var module = Path.Combine(DocsTests.RepoRoot(), "test-reuse.psm1");
        var dir = Path.Combine(Path.GetTempPath(), $"corvus-reuse-{Guid.NewGuid():N}");
        Directory.CreateDirectory(Path.Combine(dir, "src", "Corvus", "Core"));
        File.WriteAllText(Path.Combine(dir, "src", "Corvus", "Core", "Y.cs"), "");
        File.WriteAllText(Path.Combine(dir, "coverage.cobertura.xml"), $"""
            <coverage><sources><source>{Path.Combine(dir, "src")}</source></sources><packages><package><classes>
              <class name="Y" filename="Corvus{Path.DirectorySeparatorChar}Core{Path.DirectorySeparatorChar}Y.cs" line-rate="0.5" />
              <class name="Z" filename="Corvus{Path.DirectorySeparatorChar}Core{Path.DirectorySeparatorChar}Z.cs" line-rate="0" />
            </classes></package></packages></coverage>
            """);
        var map = Path.Combine(dir, "map.json");
        File.WriteAllText(map, $$"""{ "at": "{{DateTime.Now:yyyy-MM-dd HH:mm}}", "families": { "Dotnet": ["src/Corvus/Core/Y.cs"], "Engines": [] } }""");
        try
        {
            var lines = Run($$"""
                Import-Module '{{module.Replace("'", "''")}}'
                'covered=' + ((Get-CoveredFiles '{{Path.Combine(dir, "coverage.cobertura.xml")}}' '{{dir}}') -join ',')
                $f = 'Dotnet', 'Engines'
                $c = Read-CoverageMap '{{map}}'
                $base = "100644 blob b1`tsrc/Corvus/Core/Y.cs", "100644 blob e1`tsrc/Corvus/Core/New.cs"
                $k0 = Get-FamilyKeys $base $f @() 'env' $c
                function Changed($lines) { $k = Get-FamilyKeys $lines $f @() 'env' $c; ($f | Where-Object { $k[$_] -ne $k0[$_] }) -join ',' }
                'mapped=' + (Changed ($base -replace 'b1', 'b2'))
                'unmapped=' + (Changed ($base -replace 'e1', 'e2'))
                'old=' + ($null -eq (Read-CoverageMap '{{map}}' -maxDays 0))
                """);
            if (lines is ["skip"]) return; // no pwsh on this machine
            string Line(string name) => lines.Single(l => l.StartsWith(name + "=")).Substring(name.Length + 1);
            Assert.Equal("src/Corvus/Core/Y.cs", Line("covered")); // only files with a line hit
            Assert.Equal("Dotnet", Line("mapped"));               // shared code only the Dotnet tests ran
            Assert.Equal("Dotnet,Engines", Line("unmapped"));     // a file the map does not know keeps the folder rules
            Assert.Equal("True", Line("old"));                    // an old map is not used
        }
        finally { Directory.Delete(dir, true); }
    }

    [Fact]
    [Trait("Speed", "Slow")]
    public void A_class_mapped_on_its_own_reruns_only_when_its_own_files_change()
    {
        var module = Path.Combine(DocsTests.RepoRoot(), "test-reuse.psm1");
        var dir = Path.Combine(Path.GetTempPath(), $"corvus-reuse-{Guid.NewGuid():N}");
        Directory.CreateDirectory(dir);
        var map = Path.Combine(dir, "map.json");
        File.WriteAllText(map, $$"""
            { "at": "{{DateTime.Now:yyyy-MM-dd HH:mm}}", "families": { "Mobile": ["src/Corvus/Core/Dex.cs"], "Containers": ["src/Corvus/Core/Zip.cs"] },
              "classes": { "JavapC": { "family": "Mobile", "files": ["src/Corvus/Core/Jvm.cs"] } } }
            """);
        var trx = Path.Combine(dir, "run.trx");
        File.WriteAllText(trx, """
            <TestRun xmlns="http://microsoft.com/schemas/VisualStudio/TeamTest/2010">
              <Results>
                <UnitTestResult testId="1" duration="00:00:20.0000000" outcome="Passed" />
                <UnitTestResult testId="2" duration="00:00:15.0000000" outcome="Passed" />
                <UnitTestResult testId="3" duration="00:00:01.0000000" outcome="Passed" />
              </Results>
              <TestDefinitions>
                <UnitTest id="1"><TestMethod className="Corvus.Tests.JavapC" name="A" /></UnitTest>
                <UnitTest id="2"><TestMethod className="Corvus.Tests.JavapC+Nested" name="B" /></UnitTest>
                <UnitTest id="3"><TestMethod className="Corvus.Tests.DexD" name="C" /></UnitTest>
              </TestDefinitions>
            </TestRun>
            """);
        try
        {
            var lines = Run($$"""
                Import-Module '{{module.Replace("'", "''")}}'
                'slow=' + ((Get-SlowClasses '{{trx}}') -join ',')
                'folded=' + ((Read-CoverageMap '{{map}}')['src/Corvus/Core/Jvm.cs'] -join ',')
                $cc = Read-ClassCoverage '{{map}}'
                $m = Split-ClassMap @{ Mobile = @('JavapC', 'DexD'); Containers = @('ZipE') } $cc
                'split=' + (($m.Keys | Sort-Object | ForEach-Object { "$_=$($m[$_] -join '+')" }) -join ',')
                $base = "100644 blob j1`tsrc/Corvus/Core/Jvm.cs", "100644 blob z1`tsrc/Corvus/Core/Zip.cs", "100644 blob t1`ttests/Corvus.Tests/Mobile/DexD.cs"
                $paths = $base | ForEach-Object { $_.Substring($_.IndexOf("`t") + 1) }
                $c = Add-ClassTestScopes (Read-CoverageMap '{{map}}' -Classes) $cc $paths
                $f = @($m.Keys)
                $k0 = Get-FamilyKeys $base $f @() 'env' $c
                function Changed($lines) { $k = Get-FamilyKeys $lines $f @() 'env' $c; ($f | Sort-Object | Where-Object { $k[$_] -ne $k0[$_] }) -join ',' }
                'reader=' + (Changed ($base -replace 'j1', 'j2'))
                'other=' + (Changed ($base -replace 'z1', 'z2'))
                'test=' + (Changed ($base -replace 't1', 't2'))
                'filter=' + (Get-ReuseFilter @('class:JavapC') $m)
                """);
            if (lines is ["skip"]) return; // no pwsh on this machine
            string Line(string name) => lines.Single(l => l.StartsWith(name + "=")).Substring(name.Length + 1);
            Assert.Equal("JavapC", Line("slow"));            // 35 s with its nested class; DexD is quick
            Assert.Equal("Mobile", Line("folded"));          // picking quick tests: the class counts for its family
            Assert.Equal("class:JavapC=JavapC,Containers=ZipE,Mobile=DexD", Line("split"));
            Assert.Equal("class:JavapC", Line("reader"));    // the reader only the class ran
            Assert.Equal("Containers", Line("other"));
            Assert.Equal("class:JavapC,Mobile", Line("test")); // its family's test folder
            Assert.Contains("FullyQualifiedName~.JavapC", Line("filter"));
            Assert.DoesNotContain("DexD", Line("filter"));
        }
        finally { Directory.Delete(dir, true); }
    }

    [Fact]
    [Trait("Speed", "Slow")]
    public void The_heavy_lock_script_is_called_to_take_and_release_and_no_variable_means_no_lock()
    {
        var module = Path.Combine(DocsTests.RepoRoot(), "test-reuse.psm1");
        var dir = Path.Combine(Path.GetTempPath(), $"corvus-reuse-{Guid.NewGuid():N}");
        Directory.CreateDirectory(dir);
        var calls = Path.Combine(dir, "calls.txt");
        var lockScript = Path.Combine(dir, "lock.ps1");
        File.WriteAllText(lockScript, $$"""
            param($Action, $Lane, $OwnerPid = 0)
            Add-Content '{{calls}}' "$Action $Lane $OwnerPid"
            """);
        try
        {
            var lines = Run($$"""
                Import-Module '{{module.Replace("'", "''")}}'
                $env:CORVUS_HEAVY_LOCK = $null
                'unset=' + (Enter-HeavyLock 'run')
                $before = Get-RunEnvironment
                $env:CORVUS_HEAVY_LOCK = '{{lockScript}}'
                'set=' + (Enter-HeavyLock 'run')
                Exit-HeavyLock 'run'
                'keyed=' + ($before -ne (Get-RunEnvironment))
                'pid=' + $PID
                """);
            if (lines is ["skip"]) return; // no pwsh on this machine
            string Line(string name) => lines.Single(l => l.StartsWith(name + "=")).Substring(name.Length + 1);
            Assert.Equal("False", Line("unset"));
            Assert.Equal("True", Line("set"));
            Assert.Equal([$"heavy run {Line("pid")}", "release run 0"], File.ReadAllLines(calls));
            Assert.Equal("False", Line("keyed")); // the lock does not change what a family pass proves
        }
        finally { Directory.Delete(dir, true); }
    }

    private static string[] Run(string script)
    {
        ProcessStartInfo start = new("pwsh") { RedirectStandardOutput = true, RedirectStandardError = true };
        foreach (var arg in new[] { "-NoProfile", "-NonInteractive", "-Command", script })
            start.ArgumentList.Add(arg);
        Process? process;
        try { process = Process.Start(start); }
        catch (System.ComponentModel.Win32Exception) { return ["skip"]; }
        using (process)
        {
            var output = process!.StandardOutput.ReadToEnd();
            var error = process.StandardError.ReadToEnd();
            process.WaitForExit();
            Assert.True(process.ExitCode == 0, error);
            return output.Split('\n', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries);
        }
    }
}
