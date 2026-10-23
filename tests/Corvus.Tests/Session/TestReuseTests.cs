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
    public void A_failed_run_keeps_its_results_and_names_each_failure_message()
    {
        var module = Path.Combine(DocsTests.RepoRoot(), "test-reuse.psm1");
        using var dir = new TempDir();
        var trx = dir.File("full.trx");
        File.WriteAllText(trx, Trx.Replace("""<UnitTestResult testId="2" outcome="Failed" />""",
            """<UnitTestResult testId="2" outcome="Failed"><Output><ErrorInfo><Message>worker did not start</Message></ErrorInfo></Output></UnitTestResult>"""));
        var kept = dir.File("kept");
        var lines = Run($$"""
            Import-Module '{{module.Replace("'", "''")}}'
            $m = Get-FailureMessages '{{trx}}'
            'message=' + $m['Corvus.Tests.EngineB+Nested.M']
            'count=' + $m.Count
            foreach ($i in 1..12) { Save-FailedRun '{{kept}}' ('20261023-0000{0:00}-abc' -f $i) @('{{trx}}', '{{trx}}', '{{dir.File("missing.trx")}}') }
            'kept=' + ((Get-ChildItem '{{kept}}' -Filter *.trx | Sort-Object Name | ForEach-Object Name) -join ',')
            """);
        if (lines is ["skip"]) return; // no pwsh on this machine
        string Line(string name) => lines.Single(l => l.StartsWith(name + "=")).Substring(name.Length + 1);
        Assert.Equal("worker did not start", Line("message"));
        Assert.Equal("1", Line("count"));
        // Twelve runs of two files each: the newest ten runs stay, each with its rerun's copy.
        var names = Line("kept").Split(',');
        Assert.Equal(20, names.Length);
        Assert.Contains("20261023-000003-abc.trx", names);
        Assert.Contains("20261023-000012-abc-2.trx", names);
        Assert.DoesNotContain(names, n => n.StartsWith("20261023-000002-"));
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
    public void The_heavy_lock_script_is_called_to_take_and_release_but_not_for_a_push_run()
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
                'push=' + (Enter-RunLock 'push' $true)
                'nightly=' + (Enter-RunLock 'nightly' $false)
                'keyed=' + ($before -ne (Get-RunEnvironment))
                'pid=' + $PID
                """);
            if (lines is ["skip"]) return; // no pwsh on this machine
            string Line(string name) => lines.Single(l => l.StartsWith(name + "=")).Substring(name.Length + 1);
            Assert.Equal("False", Line("unset"));
            Assert.Equal("True", Line("set"));
            Assert.Equal(("False", "True"), (Line("push"), Line("nightly")));
            // A push run relies on the machine-wide permits: only the run without reuse calls the lock script.
            Assert.Equal([$"heavy run {Line("pid")}", "release run 0", $"heavy nightly {Line("pid")}"], File.ReadAllLines(calls));
            Assert.Equal("False", Line("keyed")); // the lock does not change what a family pass proves
        }
        finally { Directory.Delete(dir, true); }
    }

    [Fact]
    [Trait("Speed", "Slow")]
    public void Quarantined_failures_pass_until_their_date_and_reruns_only_label_failures()
    {
        var module = Path.Combine(DocsTests.RepoRoot(), "test-reuse.psm1");
        var dir = Path.Combine(Path.GetTempPath(), $"corvus-quarantine-{Guid.NewGuid():N}");
        Directory.CreateDirectory(dir);
        try
        {
            File.WriteAllText(Path.Combine(dir, "run.trx"), Trx.Replace("<Results>", """<ResultSummary outcome="Failed"><Counters total="4" aborted="0" timeout="0" error="0" /></ResultSummary><Results>"""));
            File.WriteAllText(Path.Combine(dir, "aborted.trx"), Trx.Replace("<Results>", """<ResultSummary outcome="Aborted"><Counters total="4" aborted="1" timeout="0" error="0" /></ResultSummary><Results>"""));
            File.WriteAllText(Path.Combine(dir, "quarantine.txt"), """
                # comment
                Corvus.Tests.EngineB+Nested.M | test-audit | #7 | 2026-10-22
                Corvus.Tests.EngineC.M | test-audit | #8 | 2026-10-21
                """);
            File.WriteAllText(Path.Combine(dir, "bad.txt"), "Corvus.Tests.EngineC.M | test-audit | 2026-10-21" + Environment.NewLine);
            var lines = Run($$"""
                Import-Module '{{module.Replace("'", "''")}}'
                $q = Read-Quarantine '{{Path.Combine(dir, "quarantine.txt")}}'
                $today = [datetime]'2026-10-22'
                $one = Split-Quarantined @('Corvus.Tests.EngineB+Nested.M') $q $today
                'covered=' + ($one.Blocking -join ',') + '/' + ($one.Quarantined -join ',')
                $two = Split-Quarantined @('Corvus.Tests.EngineB+Nested.M', 'Corvus.Tests.EngineC.M') $q $today
                'expired=' + ($two.Blocking -join ',')
                'later=' + ((Split-Quarantined @('Corvus.Tests.EngineB+Nested.M') $q ([datetime]'2026-10-23')).Blocking -join ',')
                'missing=' + @(Read-Quarantine '{{Path.Combine(dir, "none.txt")}}').Count
                try { Read-Quarantine '{{Path.Combine(dir, "bad.txt")}}' | Out-Null; 'bad=accepted' } catch { 'bad=refused' }
                'completed=' + (Test-RunCompleted '{{Path.Combine(dir, "run.trx")}}') + ',' + (Test-RunCompleted '{{Path.Combine(dir, "aborted.trx")}}')
                'passed=' + ((Get-PassedTests '{{Path.Combine(dir, "run.trx")}}') -join ',')
                $labels = Get-FailureLabels @('A.M', 'B.M') @('B.M')
                'labels=' + ($labels -join ';')
                'unknown=' + ((Get-FailureLabels @('A.M') $null) -join ';')
                """);
            if (lines is ["skip"]) return; // no pwsh on this machine
            string Line(string name) => lines.Single(l => l.StartsWith(name + "=")).Substring(name.Length + 1);
            Assert.Equal("/Corvus.Tests.EngineB+Nested.M", Line("covered"));
            Assert.Equal("Corvus.Tests.EngineC.M", Line("expired"));   // an entry past its date covers nothing
            Assert.Equal("Corvus.Tests.EngineB+Nested.M", Line("later"));
            Assert.Equal("0", Line("missing"));
            Assert.Equal("refused", Line("bad"));                       // three fields
            Assert.Equal("True,False", Line("completed"));              // an aborted run is never let through
            Assert.Equal("Corvus.Tests.DotnetA.M,Corvus.Tests.EngineC.M", Line("passed")); // NotExecuted is not a pass
            Assert.Equal("A.M: failed;B.M: failed, passed on rerun (suspected flaky)", Line("labels"));
            Assert.Equal("A.M: failed (rerun did not complete)", Line("unknown"));
        }
        finally { Directory.Delete(dir, true); }
    }

    [Fact]
    [Trait("Speed", "Slow")]
    public void A_tool_changed_in_place_changes_the_run_environment()
    {
        var module = Path.Combine(DocsTests.RepoRoot(), "test-reuse.psm1");
        var dir = Path.Combine(Path.GetTempPath(), $"corvus-reuse-{Guid.NewGuid():N}");
        Directory.CreateDirectory(dir);
        var tool = Path.Combine(dir, "tool.exe");
        File.WriteAllText(tool, "v1");
        try
        {
            var lines = Run($$"""
                Import-Module '{{module.Replace("'", "''")}}'
                $env:CORVUS_ZZ_TOOL = '{{tool}}'
                $env:CORVUS_ZZ_FOLDER = '{{dir}}'
                $before = Get-RunEnvironment
                'same=' + ($before -eq (Get-RunEnvironment))
                (Get-Item '{{tool}}').LastWriteTimeUtc = [datetime]::UtcNow.AddDays(-1)
                'tool=' + ($before -ne (Get-RunEnvironment))
                $folderBefore = Get-RunEnvironment
                Set-Content '{{Path.Combine(dir, "new.dll")}}' 'x'
                (Get-Item '{{Path.Combine(dir, "new.dll")}}').LastWriteTimeUtc = [datetime]::UtcNow.AddDays(1)
                'folder=' + ($folderBefore -ne (Get-RunEnvironment))
                'text=' + (Get-PathStamp 'not a path')
                Remove-Item Env:CORVUS_ZZ_FOLDER
                $env:CORVUS_ANNOTATIONS_DIR = '{{Path.Combine(dir, "annotations")}}'
                New-Item -ItemType Directory $env:CORVUS_ANNOTATIONS_DIR | Out-Null
                $annotationsBefore = Get-RunEnvironment
                Set-Content (Join-Path $env:CORVUS_ANNOTATIONS_DIR 'journal.json') 'x'
                'annotations=' + ($annotationsBefore -eq (Get-RunEnvironment))
                """);
            if (lines is ["skip"]) return; // no pwsh on this machine
            string Line(string name) => lines.Single(l => l.StartsWith(name + "=")).Substring(name.Length + 1);
            Assert.Equal("True", Line("same"));
            Assert.Equal("True", Line("tool"));
            Assert.Equal("True", Line("folder"));
            Assert.Equal("", Line("text"));
            // The push run on 47be8db0 saw "same" fail: the test run's own annotations folder changed between calls.
            Assert.Equal("True", Line("annotations"));
        }
        finally { Directory.Delete(dir, true); }
    }

    [Fact]
    [Trait("Speed", "Slow")]
    public void A_file_copied_into_an_engine_folder_with_its_old_time_changes_the_folder_stamp()
    {
        var module = Path.Combine(DocsTests.RepoRoot(), "test-reuse.psm1");
        var dir = Path.Combine(Path.GetTempPath(), $"corvus-reuse-{Guid.NewGuid():N}");
        var lib = Path.Combine(dir, "lib", "plugins");
        Directory.CreateDirectory(lib);
        File.WriteAllText(Path.Combine(lib, "a.jar"), "v1");
        try
        {
            var lines = Run($$"""
                Import-Module '{{module.Replace("'", "''")}}'
                $before = Get-PathStamp '{{dir}}'
                'same=' + ($before -eq (Get-PathStamp '{{dir}}'))
                Set-Content '{{Path.Combine(lib, "b.jar")}}' 'x'
                (Get-Item '{{Path.Combine(lib, "b.jar")}}').LastWriteTimeUtc = [datetime]::UtcNow.AddYears(-2)
                'copied=' + ($before -ne (Get-PathStamp '{{dir}}'))
                """);
            if (lines is ["skip"]) return; // no pwsh on this machine
            string Line(string name) => lines.Single(l => l.StartsWith(name + "=")).Substring(name.Length + 1);
            Assert.Equal("True", Line("same"));
            Assert.Equal("True", Line("copied"));
        }
        finally { Directory.Delete(dir, true); }
    }

    [Fact]
    [Trait("Speed", "Slow")]
    public void A_process_a_test_run_starts_inherits_its_lowered_priority_unless_normal_is_set()
    {
        var module = Path.Combine(DocsTests.RepoRoot(), "test-reuse.psm1");
        // Each child reports the priority it was started with: Windows class or Unix nice value.
        const string child = "$p = Get-Process -Id $PID; if ($IsWindows) { $p.PriorityClass } else { (ps -o nice= -p $PID).Trim() }";
        var lines = Run($$"""
            Import-Module '{{module.Replace("'", "''")}}'
            'before=' + (pwsh -NoProfile -Command '{{child}}')
            $env:CORVUS_TEST_PRIORITY = 'normal'
            Set-RunPriority
            'kept=' + (pwsh -NoProfile -Command '{{child}}')
            $env:CORVUS_TEST_PRIORITY = $null
            Set-RunPriority
            'lowered=' + (pwsh -NoProfile -Command '{{child}}')
            """);
        if (lines is ["skip"]) return; // no pwsh on this machine
        string Line(string name) => lines.Single(l => l.StartsWith(name + "=")).Substring(name.Length + 1);
        Assert.Equal(OperatingSystem.IsWindows() ? "BelowNormal" : "10", Line("lowered"));
        Assert.Equal(Line("before"), Line("kept"));
    }

    [Fact]
    [Trait("Speed", "Slow")]
    public void A_failure_under_the_key_of_a_recorded_pass_is_a_selection_miss()
    {
        var module = Path.Combine(DocsTests.RepoRoot(), "test-reuse.psm1");
        var lines = Run($$"""
            Import-Module '{{module.Replace("'", "''")}}'
            $classMap = @{ Engines = @('EngineB'); Dotnet = @('DotnetA'); Contract = @('C'); 'class:SlowD' = @('SlowD') }
            $keys = @{ Engines = 'k1'; Dotnet = 'k2'; Contract = 'k3'; 'class:SlowD' = 'k4' }
            $stamps = [pscustomobject]@{ Engines = @{ key = 'k1' }; Dotnet = @{ key = 'old' }; Contract = @{ key = 'k3' }; 'class:SlowD' = @{ key = 'k4' } }
            $failed = 'Corvus.Tests.EngineB+Nested.M', 'Corvus.Tests.DotnetA.M', 'Corvus.Tests.C.M', 'Corvus.Tests.SlowD.M', 'Corvus.Tests.Unknown.M'
            'misses=' + (@(Get-SelectionMisses $failed $classMap $keys $stamps) -join ',')
            'none=' + @(Get-SelectionMisses $failed $classMap $keys $null).Count
            """);
        if (lines is ["skip"]) return; // no pwsh on this machine
        // Dotnet's key changed and Contract always runs; Engines and the class keyed on its own were reused.
        Assert.Equal(["Engines", "class:SlowD"], lines.Single(l => l.StartsWith("misses=")).Substring(7).Split(',').Order(StringComparer.Ordinal));
        Assert.Contains("none=0", lines);
    }

    [Fact]
    [Trait("Speed", "Slow")]
    public void A_release_finds_the_newest_full_pass_on_its_history_and_skips_one_on_another_branch()
    {
        var module = Path.Combine(DocsTests.RepoRoot(), "test-reuse.psm1");
        var dir = Path.Combine(Path.GetTempPath(), $"corvus-reuse-{Guid.NewGuid():N}");
        Directory.CreateDirectory(dir);
        try
        {
            var lines = Run($$"""
                Import-Module '{{module.Replace("'", "''")}}'
                Set-Location '{{dir}}'
                git init -q; git config user.email t@t; git config user.name t
                function Commit($m) { git commit -q --allow-empty -m $m; (git rev-parse HEAD).Trim() }
                $a = Commit a; $b = Commit b
                git checkout -q -b side $a; $side = Commit side
                git checkout -q -; $c = Commit c
                $ledger = Join-Path '{{dir}}' 'passes.txt'
                $legacy = Join-Path '{{dir}}' 'legacy.txt'
                'none=' + (Get-FullPass '{{dir}}' $ledger $legacy)
                Set-Content $legacy $a
                'legacy=' + ((Get-FullPass '{{dir}}' $ledger $legacy) -eq $a)
                Add-FullPass $ledger $b 'tree sampled'
                Add-FullPass $ledger $side 'tree sampled'
                'newest=' + ((Get-FullPass '{{dir}}' $ledger $legacy) -eq $b)
                1..250 | ForEach-Object { Add-FullPass $ledger $side 'tree sampled' }
                'bounded=' + @(Get-Content $ledger).Count
                """);
            if (lines is ["skip"]) return; // no pwsh on this machine
            Assert.Contains("none=", lines);
            Assert.Contains("legacy=True", lines);
            // The pass on the other branch is newer, but not on HEAD's history.
            Assert.Contains("newest=True", lines);
            Assert.Contains("bounded=200", lines);
        }
        finally
        {
            foreach (var f in Directory.EnumerateFiles(dir, "*", SearchOption.AllDirectories)) File.SetAttributes(f, FileAttributes.Normal);
            Directory.Delete(dir, true);
        }
    }

    /// <summary>The output lines of a pwsh script that must exit 0, or ["skip"] where there is no pwsh.</summary>
    internal static string[] Run(string script)
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
