namespace Corvus.Tests;

/// <summary>test-remote.psm1: which classes a whole-suite run offloads, the filters, and joining the results back.</summary>
public sealed class TestRemoteTests : IDisposable
{
    private readonly TempDir _dir = new();

    public void Dispose() => _dir.Dispose();

    private static string Module => Quote(Path.Combine(DocsTests.RepoRoot(), "test-remote.psm1"));

    private static string Quote(string path) => "'" + path.Replace("'", "''") + "'";

    /// <summary>A TRX file with one result per (class, outcome), an outcome "Passed@40" lasting 40 s (else 1 s).</summary>
    internal static string Trx(params (string Class, string Outcome)[] results)
    {
        static (string Outcome, int Seconds) Split(string o) => o.Split('@') is [var name, var s] ? (name, int.Parse(s)) : (o, 1);
        var tests = string.Join("\n", results.Select((r, i) => $"""<UnitTest id="{r.Class}-{i}"><TestMethod className="Corvus.Tests.{r.Class}" name="M{i}" /></UnitTest>"""));
        var outcomes = string.Join("\n", results.Select((r, i) =>
            $"""<UnitTestResult testId="{r.Class}-{i}" testName="M{i}" outcome="{Split(r.Outcome).Outcome}" duration="{TimeSpan.FromSeconds(Split(r.Outcome).Seconds):c}" />"""));
        int failed = results.Count(r => r.Outcome == "Failed");
        return $"""
            <TestRun xmlns="http://microsoft.com/schemas/VisualStudio/TeamTest/2010">
              <ResultSummary outcome="{(failed > 0 ? "Failed" : "Completed")}"><Counters total="{results.Length}" failed="{failed}" aborted="0" timeout="0" error="0" /></ResultSummary>
              <TestDefinitions>{tests}</TestDefinitions>
              <TestEntries />
              <Results>{outcomes}</Results>
            </TestRun>
            """;
    }

    [Fact]
    [Trait("Speed", "Slow")]
    public void Heavy_classes_are_grouped_for_offload_and_leave_the_local_filter()
    {
        var tests = Path.Combine(_dir.Path, "tests");
        void Source(string folder, string text, string file = "T.cs")
        {
            Directory.CreateDirectory(Path.Combine(tests, folder));
            File.WriteAllText(Path.Combine(tests, folder, file), text);
        }
        Source("Dotnet", "public sealed class FormatSweepTests { }\npublic class PlainTests { }");
        Source("DotnetEdits", "public abstract class PipelineRoundTripTests { public sealed class Part1 { } }");
        Source("Engines", "public class EngineSweepTests { }");
        Source("Engines", "public class GhidraReadTests { [GhidraFact] public void M() { } }\npublic sealed class GhidraCacheFixture { }", "G.cs");
        Source("Engines", "public class EngineMixTests { [IdaFact] public void A() { } [GhidraFact] public void B() { } }", "M.cs");
        Source("Engines", "public class GhidraSideTests { [GhidraFact] public void M() { } }\npublic class IdaSideTests { [IdaFact] public void M() { } }", "N.cs");
        Source("Engines", "public class ReleaseMixTests { [IdaFact] public void A() { }\n[Trait(\"Tier\", \"Release\")]\n[GhidraFact] public void B() { } }", "R.cs");
        Source("Live", "public class LiveMatrixTests { }\npublic abstract class LiveToolCalls { }");
        Source("NativeAnalysis", "public class IdaSweepTests { [IdaFact] public void M() { } }");
        Source("Containers", "public class CorpusSweepTests { [RequiresRealDataFact(\"CORVUS_X\")] public void M() { } }");
        Source("NativeFormats", "public class PeSweepTests { [WindowsFact] public void M() { } }");
        Source("Session", "public sealed class DeadlineTests { }\npublic sealed class ContractSweepFullTests { }", "S.cs");
        Source("Support", "public static class RealData { public const string Apps = \"CORVUS_APPS\"; }", "TestEnv.cs");
        Source("Mobile", "public class AppTests { const string Var = \"CORVUS_JARS\"; [RequiresRealDataFact(RealData.Apps, Var)] public void M() { } }", "A.cs");
        Source("Mobile", "public class OddTests { [RequiresRealDataFact(Pick())] public void M() { } }", "O.cs");
        Source("Web", "public class CaptureTests { [RequiresRealDataFact(\"CORVUS_TSHARK\")] public void M() { } }", "C.cs");
        Source("Mobile", "public class IdaDataTests { [RequiresRealDataFact(\"CORVUS_X\")] [IdaFact] public void M() { } }", "I.cs");
        Source("NativeAnalysis", "public class IdaImageTests { [IdaFact(RealData.Apps)] public void M() { } }", "V.cs");
        var lines = TestReuseTests.Run($$"""
            Import-Module {{Module}}
            'classes=' + ((Get-RemoteClasses {{Quote(tests)}}) -join ',')
            'cross=' + ((Get-RemoteClasses {{Quote(tests)}} -CrossPlatform) -join ',')
            $sweep = Get-RemoteClasses {{Quote(tests)}} sweep
            'sweep=' + ($sweep -join ',')
            'ghidra=' + ((Get-RemoteClasses {{Quote(tests)}} ghidra) -join ',')
            'live=' + ((Get-RemoteClasses {{Quote(tests)}} live -CrossPlatform) -join ',')
            'nightly=' + ((Get-RemoteClasses {{Quote(tests)}} nightly) -join ',')
            'mixed=' + ((Get-MixedClasses {{Quote(tests)}}) -join ',')
            'shard0=' + ((Get-RemoteShard $sweep 0 2) -join ',')
            'shard1=' + ((Get-RemoteShard $sweep 1 2) -join ',')
            'routine=' + (Get-LocalFilter 'Tier!=Release' @('FormatSweepTests', 'PipelineRoundTripTests'))
            'everything=' + (Get-LocalFilter '' @('FormatSweepTests'))
            'none=' + (Get-LocalFilter 'Tier!=Release' @())
            'remote=' + (Get-ClassFilter @('FormatSweepTests', 'PeSweepTests') $false)
            'release=' + (Get-ClassFilter @('FormatSweepTests') $true)
            'split=' + (Get-LocalFilter 'Tier!=Release' @('EngineMixTests', 'FormatSweepTests') @('EngineMixTests'))
            'rest=' + (Get-ClassFilter @('EngineMixTests', 'FormatSweepTests') $false @('EngineMixTests'))
            """);
        if (lines is ["skip"]) return;
        // Ghidra and live classes go as groups of their own, a class using both engines too; a class with IDA facts alone
        // stays here, beside a Ghidra class in its file or with Ghidra facts of the release tier only.
        Assert.Contains("classes=ContractSweepFullTests,EngineMixTests,FormatSweepTests,GhidraReadTests,GhidraSideTests,LiveMatrixTests,PeSweepTests,PipelineRoundTripTests", lines);
        Assert.Contains("cross=ContractSweepFullTests,EngineMixTests,FormatSweepTests,GhidraReadTests,GhidraSideTests,LiveMatrixTests,PipelineRoundTripTests", lines);
        Assert.Contains("sweep=ContractSweepFullTests,FormatSweepTests,PeSweepTests,PipelineRoundTripTests", lines);
        // A nightly class is never offloaded: real-data classes and those that
        // need an unloaded machine; one that also needs IDA stays here.
        Assert.Contains("nightly=AppTests,CaptureTests,CorpusSweepTests,DeadlineTests,OddTests", lines);
        Assert.Contains("ghidra=EngineMixTests,GhidraReadTests,GhidraSideTests", lines);
        Assert.Contains("mixed=EngineMixTests", lines);
        Assert.Contains("live=LiveMatrixTests", lines);
        Assert.Contains("shard0=ContractSweepFullTests,PeSweepTests", lines);
        Assert.Contains("shard1=FormatSweepTests,PipelineRoundTripTests", lines);
        Assert.Contains("routine=(Tier!=Release)&FullyQualifiedName!~.FormatSweepTests&FullyQualifiedName!~.PipelineRoundTripTests", lines);
        Assert.Contains("everything=FullyQualifiedName!~.FormatSweepTests", lines);
        Assert.Contains("none=Tier!=Release", lines);
        Assert.Contains("remote=(FullyQualifiedName~.FormatSweepTests|FullyQualifiedName~.PeSweepTests)&Tier!=Release", lines);
        Assert.Contains("release=FullyQualifiedName~.FormatSweepTests", lines);
        Assert.Contains("split=(Tier!=Release)&FullyQualifiedName!~.FormatSweepTests&(Engine!=ghidra|FullyQualifiedName!~.EngineMixTests)", lines);
        Assert.Contains("rest=((FullyQualifiedName~.EngineMixTests&Engine!=ida)|FullyQualifiedName~.FormatSweepTests)&Tier!=Release", lines);
    }

    [Fact]
    [Trait("Speed", "Slow")]
    public void Offload_shards_take_the_classes_by_the_seconds_recorded_on_their_platform_and_the_record_keeps_the_median()
    {
        var a = Path.Combine(_dir.Path, "a.trx");
        var b = Path.Combine(_dir.Path, "b.trx");
        var c = Path.Combine(_dir.Path, "c.trx");
        File.WriteAllText(a, Trx(("LongTests", "Passed@90"), ("LongTests", "Passed@10"), ("MidTests", "Passed@90")));
        File.WriteAllText(b, Trx(("LongTests", "Passed@300"), ("MidTests", "Passed@80")));
        File.WriteAllText(c, Trx(("LongTests", "Failed@50"), ("ShortTests", "Passed@10")));
        var record = Path.Combine(_dir.Path, "seconds.json");
        File.WriteAllText(record, """{ "linux": { "LinuxTests": 40, "LongTests": 5 }, "windows": { "GoneTests": 7, "ShortTests": 99 } }""");
        var lines = TestReuseTests.Run($$"""
            Import-Module {{Module}}
            Save-OffloadSeconds @({{Quote(a)}}, {{Quote(b)}}, {{Quote(c)}}) {{Quote(record)}} windows
            $seconds = Read-OffloadSeconds {{Quote(record)}} windows
            'linux=' + (Read-OffloadSeconds {{Quote(record)}} linux)['LongTests']
            'record=' + (($seconds.Keys | Sort-Object | ForEach-Object { "$_=$($seconds[$_])" }) -join ',')
            $classes = @('LongTests', 'MidTests', 'NewTests', 'ShortTests')
            'shard0=' + ((Get-RemoteShard $classes 0 2 $seconds) -join ',')
            'shard1=' + ((Get-RemoteShard $classes 1 2 $seconds) -join ',')
            'missing=' + ($null -eq (Read-OffloadSeconds {{Quote(Path.Combine(_dir.Path, "none.json"))}}))
            """);
        // Medians of 100, 300 and 50 s and of 90 and 80 s; a class absent from the results keeps its entry, and one
        // recorded only on Linux takes its Linux time.
        Assert.Contains("record=GoneTests=7,LinuxTests=40,LongTests=100,MidTests=85,ShortTests=10", lines);
        Assert.Contains("linux=5", lines);
        // Longest first, each to the shard with less so far: 100 to 0, 85 and 10 to 1, the unrecorded 1 s to 1.
        Assert.Contains("shard0=LongTests", lines);
        Assert.Contains("shard1=MidTests,NewTests,ShortTests", lines);
        Assert.Contains("missing=True", lines);
    }

    [Fact]
    [Trait("Speed", "Slow")]
    public void A_class_using_both_engines_joins_per_test_and_reruns_only_for_a_test_skipped_on_both_sides()
    {
        // Here M0 is an IDA test and M2 a plain one; there M0 skips, M1 is a Ghidra test, and M3 fails only there.
        var local = _dir.File("full.trx");
        File.WriteAllText(local, Trx(("MixTests", "Passed"), ("PlainTests", "Passed"), ("MixTests", "Passed"), ("MixTests", "Passed")));
        var remote = _dir.File("remote.trx");
        File.WriteAllText(remote, Trx(("MixTests", "NotExecuted"), ("MixTests", "Passed"), ("MixTests", "Passed"), ("MixTests", "Failed")));
        var skipped = _dir.File("skipped.trx");
        File.WriteAllText(skipped, Trx(("MixTests", "NotExecuted"), ("MixTests", "NotExecuted")));
        var ran = _dir.File("ran.trx");
        File.WriteAllText(ran, Trx(("MixTests", "Passed"), ("MixTests", "Passed")));
        var unran = _dir.File("unran.trx");
        File.WriteAllText(unran, Trx(("MixTests", "Passed"), ("MixTests", "NotExecuted")));
        var lines = TestReuseTests.Run($$"""
            Import-Module {{Module}}
            Import-Module {{Quote(Path.Combine(DocsTests.RepoRoot(), "test-reuse.psm1"))}}
            $got = [pscustomobject]@{ Started = $true; Trx = {{Quote(remote)}}; Failed = @(); Note = 'run 42' }
            'split=' + ((Get-RerunClasses $got @('MixTests') {{Quote(ran)}} @('MixTests') {{Quote(local)}}) -join ',')
            'whole=' + ((Get-RerunClasses $got @('MixTests') {{Quote(ran)}}) -join ',')
            'both=' + ((Get-SkippedOnBoth {{Quote(skipped)}} {{Quote(_dir.File("absent.trx"))}} {{Quote(ran)}} @('MixTests')) -join ',')
            'neither=' + ((Get-SkippedOnBoth {{Quote(skipped)}} {{Quote(local)}} {{Quote(unran)}} @('MixTests')) -join ',')
            Join-TrxFiles {{Quote(local)}} @({{Quote(local)}}, {{Quote(remote)}}) @() @('MixTests')
            'tests=' + ((Get-TestOutcomes {{Quote(local)}} | ForEach-Object { "$($_.Key -replace '^Corvus\.Tests\.', '')=$($_.Outcome)" } | Sort-Object) -join ',')
            'failed=' + ((Get-FailedTests {{Quote(local)}}) -join ',')
            'total=' + ([xml](Get-Content {{Quote(local)}} -Raw)).TestRun.ResultSummary.Counters.total
            """);
        if (lines is ["skip"]) return;
        // The IDA test skips there as expected; counted per class it would look like a skip there that ran here.
        Assert.Contains("split=", lines);
        Assert.Contains("whole=MixTests", lines);
        Assert.Contains("both=MixTests", lines);
        Assert.Contains("neither=", lines);
        Assert.Contains("tests=MixTests|M0=Passed,MixTests|M1=Passed,MixTests|M2=Passed,MixTests|M3=Failed,PlainTests|M1=Passed", lines);
        Assert.Contains("failed=Corvus.Tests.MixTests.M3", lines);
        Assert.Contains("total=5", lines);
    }

    [Fact]
    [Trait("Speed", "Slow")]
    public void Remote_results_join_the_local_ones_and_classes_that_skipped_there_rerun_here()
    {
        var remote = _dir.File("remote.trx");
        File.WriteAllText(remote, Trx(("FormatSweepTests", "Failed"), ("RoundTripTests", "Passed"), ("ToolSweepTests", "NotExecuted"), ("LocalSkipTests", "NotExecuted"), ("EarlyTests", "Passed"), ("LoadedTests", "Passed@5")));
        var local = _dir.File("full.trx");
        File.WriteAllText(local, Trx(("PlainTests", "Passed")));
        var before = _dir.File("last.trx");
        File.WriteAllText(before, Trx(("ToolSweepTests", "Passed"), ("LocalSkipTests", "NotExecuted"), ("EarlyTests", "Passed@40"), ("LoadedTests", "Passed@400")));
        var history = _dir.File("history.jsonl");
        File.WriteAllLines(history, [
            """{"kind":"run","run":"r1","mode":"push"}""",
            """{"kind":"test","run":"r1","mode":"push","name":"Corvus.Tests.LoadedTests.M0","class":"LoadedTests","start":10,"end":13,"outcome":"Passed","wait":0}""",
            """{"kind":"test","run":"r1","mode":"push","name":"Corvus.Tests.LoadedTests+Inner.M1","class":"LoadedTests+Inner","start":13,"end":16,"outcome":"Passed","wait":0}""",
            """{"kind":"test","run":"r2","mode":"push","name":"Corvus.Tests.LoadedTests.M0","class":"LoadedTests","start":0,"end":90,"outcome":"Passed","wait":0}""",
            """{"kind":"test","run":"r4","mode":"full","name":"Corvus.Tests.LoadedTests.M0","class":"LoadedTests","start":0,"end":0.5,"outcome":"NotExecuted","wait":0}""",
            """{"kind":"test","run":"r3","mode":"quick","name":"Corvus.Tests.EarlyTests.M0","class":"EarlyTests","start":0,"end":1,"outcome":"Passed","wait":0}"""]);
        var lines = TestReuseTests.Run($$"""
            Import-Module {{Module}}
            Import-Module {{Quote(Path.Combine(DocsTests.RepoRoot(), "test-reuse.psm1"))}}
            $fastest = Get-FastestClassSeconds {{Quote(history)}}
            'fastest=' + (($fastest.Keys | Sort-Object | ForEach-Object { "$_=$($fastest[$_])" }) -join ',')
            'loaded=' + ((Get-ProvedLessThere {{Quote(remote)}} {{Quote(before)}}) -join ',')
            $here = @(Get-ProvedLessThere {{Quote(remote)}} {{Quote(before)}} $fastest)
            'here=' + ($here -join ',')
            Join-TrxFiles {{Quote(local)}} @({{Quote(local)}}, {{Quote(remote)}}) $here
            'failed=' + ((Get-FailedTests {{Quote(local)}}) -join ',')
            $map = @{ Dotnet = @('PlainTests'); DotnetEdits = @('RoundTripTests'); Sweeps = @('FormatSweepTests'); Tools = @('ToolSweepTests') }
            'passed=' + ((Get-PassedFamilies {{Quote(local)}} $map 1) -join ',')
            'classes=' + ((Get-ClassOutcomes {{Quote(local)}} | ForEach-Object Class | Sort-Object) -join ',')
            'total=' + ([xml](Get-Content {{Quote(local)}} -Raw)).TestRun.ResultSummary.Counters.total
            Save-RemoteRecord {{Quote(_dir.Path)}} ([ordered]@{ target = 'github'; commit = 'abc'; at = 'now'; classes = 3; state = 'FAILED (exit 1)'; seconds = 12.5; note = $null })
            'status=' + (Get-RemoteStatus {{Quote(_dir.Path)}})
            Save-RemoteRecord {{Quote(_dir.Path)}} ([ordered]@{ target = 'github'; commit = 'def'; at = 'now'; classes = 3; state = 'running'; seconds = $null; note = $null })
            'running=' + (Get-RemoteStatus {{Quote(_dir.Path)}})
            """);
        if (lines is ["skip"]) return;
        // ToolSweepTests skipped a test there that ran here last time; LocalSkipTests skips here too; EarlyTests took 1 s
        // there and 40 s here; LoadedTests took 5 s there, 400 s in the last run here and 6 s in the fastest push run
        // that passed it.
        Assert.Contains("fastest=LoadedTests=6", lines);
        Assert.Contains("loaded=EarlyTests,LoadedTests,ToolSweepTests", lines);
        Assert.Contains("here=EarlyTests,ToolSweepTests", lines);
        Assert.Contains("failed=Corvus.Tests.FormatSweepTests.M0", lines);
        Assert.Contains("passed=Dotnet,DotnetEdits", lines);
        Assert.Contains("classes=FormatSweepTests,LoadedTests,LocalSkipTests,PlainTests,RoundTripTests", lines);
        Assert.Contains("total=5", lines);
        Assert.Contains("status=github: FAILED (exit 1) on abc at now (3 classes, 12.5 s)", lines);
        Assert.Contains("running=github: running (results joined when the local tests end) on def at now (3 classes)", lines);
    }

    [Fact]
    [Trait("Speed", "Slow")]
    public void A_class_that_failed_there_or_has_no_results_there_reruns_here_and_its_result_here_is_named()
    {
        var remote = _dir.File("remote.trx");
        File.WriteAllText(remote, Trx(("FormatSweepTests", "Failed"), ("RoundTripTests", "Passed"), ("ToolSweepTests", "NotExecuted")));
        var before = _dir.File("last.trx");
        File.WriteAllText(before, Trx(("ToolSweepTests", "Passed"), ("GoneTests", "Passed")));
        var here = _dir.File("here.trx");
        File.WriteAllText(here, Trx(("FormatSweepTests", "Passed"), ("RoundTripTests", "Failed")));
        var lines = TestReuseTests.Run($$"""
            Import-Module {{Module}}
            $failed = @(
                [pscustomobject]@{ Class = 'FormatSweepTests'; Platform = 'windows' },
                [pscustomobject]@{ Class = 'FormatSweepTests'; Platform = 'ubuntu' },
                [pscustomobject]@{ Class = 'RoundTripTests'; Platform = 'ubuntu' })
            $sent = 'FormatSweepTests', 'RoundTripTests', 'ToolSweepTests', 'GoneTests', 'NeverTests'
            $got = [pscustomobject]@{ Started = $true; Trx = {{Quote(remote)}}; Failed = $failed; Note = 'run 42' }
            'rerun=' + ((Get-RerunClasses $got $sent {{Quote(before)}}) -join ',')
            $none = [pscustomobject]@{ Started = $true; Trx = $null; Failed = @(); Note = 'run 42' }
            'notrx=' + ((Get-RerunClasses $none $sent {{Quote(before)}}) -join ',')
            'nolast=' + ((Get-RerunClasses $none $sent {{Quote(_dir.File("absent.trx"))}}) -join ',')
            'note=' + (Get-FailedThereNote $failed {{Quote(here)}} 'github')
            'unrun=' + (Get-FailedThereNote $failed $null 'github')
            """);
        if (lines is ["skip"]) return;
        // GoneTests has no results there but ran here last time; NeverTests ran in neither place.
        Assert.Contains("rerun=FormatSweepTests,GoneTests,RoundTripTests,ToolSweepTests", lines);
        Assert.Contains("notrx=GoneTests,ToolSweepTests", lines);
        Assert.Contains("nolast=FormatSweepTests,GoneTests,NeverTests,RoundTripTests,ToolSweepTests", lines);
        Assert.Contains("note=FormatSweepTests failed on github (ubuntu, windows), passed here; RoundTripTests failed on github (ubuntu), failed here", lines);
        Assert.Contains("unrun=FormatSweepTests failed on github (ubuntu, windows), not run here; RoundTripTests failed on github (ubuntu), not run here", lines);
    }

    /// <summary>A script standing in for gh: one CI run whose first offload job ended with <paramref name="conclusion"/>;
    /// its Windows shards hold <paramref name="trx"/>, its Linux shard <paramref name="linuxTrx"/>.</summary>
    private string FakeGh(string conclusion, string trx, string linuxTrx)
    {
        var path = _dir.File($"gh-{conclusion}.ps1");
        File.WriteAllText(path, $$"""
            $verb = "$($args[0]) $($args[1])"
            if ($verb -eq 'run list') { '[{"databaseId": 42}]'; exit 0 }
            if ($verb -eq 'run view') { '{"status": "completed", "jobs": [{"name": "offload (sweep windows-latest 0/2)", "status": "completed", "conclusion": "{{conclusion}}"}, {"name": "offload (sweep windows-latest 1/2)", "status": "completed", "conclusion": "success"}, {"name": "offload (live ubuntu-latest 0/1)", "status": "completed", "conclusion": "success"}, {"name": "test (windows-latest)", "status": "completed", "conclusion": "failure"}]}'; exit 0 }
            if ($verb -eq 'run download') {
                $to = $args[[array]::IndexOf($args, '-D') + 1]
                foreach ($shard in 0, 1) { New-Item -ItemType Directory -Force "$to/offload-sweep-windows-latest-$shard" | Out-Null; Copy-Item {{Quote(trx)}} "$to/offload-sweep-windows-latest-$shard/offload.trx" }
                New-Item -ItemType Directory -Force "$to/offload-live-ubuntu-latest-0" | Out-Null; Copy-Item {{Quote(linuxTrx)}} "$to/offload-live-ubuntu-latest-0/offload.trx"
                exit 0
            }
            exit 1
            """);
        return path;
    }

    [Fact]
    [Trait("Speed", "Slow")]
    public void A_finished_ci_run_brings_its_results_and_failures_back_and_a_missing_one_leaves_the_classes_here()
    {
        var trx = _dir.File("shard.trx");
        File.WriteAllText(trx, Trx(("FormatSweepTests", "Passed")));
        var linux = _dir.File("linux.trx");
        File.WriteAllText(linux, Trx(("LiveMatrixTests", "Failed"), ("LiveMatrixTests", "Passed")));
        var none = _dir.File("gh-none.ps1");
        File.WriteAllText(none, "'[]'; exit 0");
        var lines = TestReuseTests.Run($$"""
            Import-Module {{Module}}
            $env:CORVUS_TEST_GH = {{Quote(FakeGh("success", trx, linux))}}
            $r = Receive-GitHubRun (Wait-GitHubRun 'owner/repo' 'abc' 0 0) {{Quote(Path.Combine(_dir.Path, "ok"))}}
            'ok=' + $r.Started + ',' + $r.Note + ',' + ([xml](Get-Content $r.Trx -Raw)).TestRun.ResultSummary.Counters.total + ',' + (($r.Failed | ForEach-Object { "$($_.Class)@$($_.Platform)" }) -join ',')
            $env:CORVUS_TEST_GH = {{Quote(FakeGh("failure", trx, linux))}}
            $r = Receive-GitHubRun (Wait-GitHubRun 'owner/repo' 'abc' 0 0) {{Quote(Path.Combine(_dir.Path, "failed"))}}
            'failed=' + $r.Started + ',' + $r.Note
            $env:CORVUS_TEST_GH = {{Quote(none)}}
            $r = Receive-GitHubRun (Wait-GitHubRun 'owner/repo' 'abc' 0 0) {{Quote(Path.Combine(_dir.Path, "none"))}}
            'none=' + $r.Started + ',' + $r.Note
            $env:CORVUS_TEST_OFFLOAD = '0'
            'off=' + ($null -eq (Get-OffloadTarget {{Quote(DocsTests.RepoRoot())}} $false))
            Remove-Item Env:CORVUS_TEST_OFFLOAD
            'release=' + ($null -eq (Get-OffloadTarget {{Quote(DocsTests.RepoRoot())}} $true))
            """);
        if (lines is ["skip"]) return;
        // Both Windows shards joined, the Linux shard's failure named; the failed quick-set job is not an offload job.
        Assert.Contains("ok=True,run 42,2,LiveMatrixTests@ubuntu", lines);
        Assert.Contains("failed=True,offload (sweep windows-latest 0/2) ended failure in run 42", lines);
        Assert.Contains("none=False,no CI run for the commit after 0 s", lines);
        Assert.Contains("off=True", lines);
        // A release-strength run has no target: GitHub runs at routine strength.
        Assert.Contains("release=True", lines);
    }

    [Fact]
    public void A_push_run_leaves_nightly_classes_to_the_nightly_run_and_records_no_pass_for_their_families()
    {
        var git = _dir.Path;
        var lines = TestReuseTests.Run($$"""
            Import-Module {{Module}}
            $map = @{ Session = @('DeadlineTests', 'NotesTests'); Images = @('ImagesRealTests'); Dotnet = @('DotnetTests') }
            'passed=' + ((Get-UndeferredFamilies @('Dotnet', 'Images', 'Session') $map @('ImagesRealTests')) -join ',')
            'none=' + ((Get-UndeferredFamilies @('Dotnet', 'Images') $map @()) -join ',')
            Save-DeferredClasses {{Quote(git)}} 'abc1234' @('DeadlineTests', 'ImagesRealTests')
            'status=' + (Get-DeferredStatus {{Quote(git)}})
            Save-DeferredClasses {{Quote(git)}} 'abc1235' @()
            'cleared=' + [string]::IsNullOrEmpty((Get-DeferredStatus {{Quote(git)}}))
            """);
        if (lines is ["skip"]) return;
        Assert.Contains("passed=Dotnet,Session", lines);
        Assert.Contains("none=Dotnet,Images", lines);
        Assert.Contains(lines, l => l.StartsWith("status=abc1234 at ") && l.EndsWith(": DeadlineTests, ImagesRealTests"));
        Assert.Contains("cleared=True", lines);
    }
}
