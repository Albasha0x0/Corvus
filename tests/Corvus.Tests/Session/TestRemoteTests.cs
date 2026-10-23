namespace Corvus.Tests;

/// <summary>test-remote.psm1: which classes a whole-suite run offloads, the filters, and joining the results back.</summary>
public sealed class TestRemoteTests : IDisposable
{
    private readonly TempDir _dir = new();

    public void Dispose() => _dir.Dispose();

    private static string Module => Quote(Path.Combine(DocsTests.RepoRoot(), "test-remote.psm1"));

    private static string Quote(string path) => "'" + path.Replace("'", "''") + "'";

    // The host script lowers itself to below-normal priority, which a push run at full CPU starves: on 2fce80f1 it
    // had not ended after 60 s.
    private const int ScriptExitMs = 300_000;

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
            'host=' + ((Get-RemoteClasses {{Quote(tests)}} host) -join ',')
            'testhost=' + ((Get-RemoteClasses {{Quote(tests)}} -TestHost) -join ',')
            'withdata=' + ((Get-RemoteClasses {{Quote(tests)}} host -TestHost) -join ',') + ';' + ((Get-RemoteClasses {{Quote(tests)}} -TestHost -hostVariables CORVUS_X, CORVUS_APPS, CORVUS_JARS | Where-Object { $_ -in 'CorpusSweepTests', 'AppTests', 'OddTests' }) -join ',')
            'held=' + ((Get-HeldClasses {{Quote(tests)}} CORVUS_APPS) -join ';')
            'variables=' + ((Get-RealDataVariables {{Quote(tests)}}) -join ',') + ';' + ((Get-RealDataVariables {{Quote(tests)}} -Tools) -join ',')
            'mixed=' + ((Get-MixedClasses {{Quote(tests)}}) -join ',')
            'idahost=' + ((Get-IdaHostClasses {{Quote(tests)}} @{ IdaImageTests = 1000 } CORVUS_IDA_DIR) -contains 'IdaImageTests') + ',' + ((Get-IdaHostClasses {{Quote(tests)}} @{ IdaSweepTests = 1000 } CORVUS_IDA_DIR) -contains 'IdaSweepTests')
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
        // A host class goes to a test host only, never in a run that offloads to GitHub.
        Assert.Contains("host=AppTests,CaptureTests,CorpusSweepTests,DeadlineTests,OddTests", lines);
        // A real-data class goes to a host that has every variable its facts name; one whose variable cannot be read
        // from its facts, or that also needs IDA, stays here.
        Assert.Contains("withdata=AppTests,CaptureTests,CorpusSweepTests,DeadlineTests,OddTests;AppTests,CorpusSweepTests", lines);
        Assert.Contains("held=AppTests (CORVUS_JARS);CaptureTests (CORVUS_TSHARK);CorpusSweepTests (CORVUS_X);OddTests (?)", lines);
        // A variable that names a program is no data to copy.
        Assert.Contains("variables=CORVUS_APPS,CORVUS_JARS,CORVUS_X;CORVUS_TSHARK", lines);
        Assert.Contains("testhost=ContractSweepFullTests,DeadlineTests,EngineMixTests,FormatSweepTests,GhidraReadTests,GhidraSideTests,LiveMatrixTests,PeSweepTests,PipelineRoundTripTests", lines);
        Assert.Contains("ghidra=EngineMixTests,GhidraReadTests,GhidraSideTests", lines);
        Assert.Contains("mixed=EngineMixTests", lines);
        // An IDA fact given real-data variables keeps its class here, where the data is: dealt first by its weight, it
        // would go to the host.
        Assert.Contains("idahost=False,True", lines);
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
    public void The_ISA_sweep_stays_here_where_the_IDA_license_covers_every_decompiler_it_reads()
    {
        // Regression: the push run on 2fce80f1, where the test host's IDA refused RISC-V (license not available (HEXRV)).
        var lines = TestReuseTests.Run($$"""
            Import-Module {{Module}}
            # The heaviest IDA class is the first a test host with IDA takes.
            $ida = @(Get-IdaHostClasses {{Quote(Path.Combine(DocsTests.RepoRoot(), "tests", "Corvus.Tests"))}} @{ IsaEngineTests = 1000000 } @('CORVUS_IDA_DIR'))
            'ida=' + ($ida.Count -gt 0) + ',' + ($ida -contains 'IsaEngineTests')
            """);
        if (lines is ["skip"]) return;
        Assert.Contains("ida=True,False", lines);
    }

    [Fact]
    [Trait("Speed", "Slow")]
    public void A_test_host_with_ida_takes_about_half_the_ida_classes_by_recorded_time()
    {
        var tests = Path.Combine(_dir.Path, "tests");
        void Source(string folder, string text, string file)
        {
            Directory.CreateDirectory(Path.Combine(tests, folder));
            File.WriteAllText(Path.Combine(tests, folder, file), text);
        }
        Source("Engines", "public class IdaLongTests { [IdaFact] public void M() { } }", "A.cs");
        Source("Engines", "public class EngineMixTests { [IdaFact] public void A() { } [GhidraFact] public void B() { } }", "B.cs");
        Source("Engines", "public class IdaMidTests { [IdaFact] public void M() { } }", "C.cs");
        Source("Engines", "public class IdaNewTests { [IdaFact] public void M() { } }", "D.cs");
        Source("Mobile", "public class IdaDataTests { [RequiresRealDataFact(\"CORVUS_X\")] [IdaFact] public void M() { } }", "E.cs");
        var lines = TestReuseTests.Run($$"""
            Import-Module {{Module}}
            $seconds = @{ IdaLongTests = 100; EngineMixTests = 60; IdaMidTests = 50; IdaDataTests = 500 }
            'there=' + ((Get-IdaHostClasses {{Quote(tests)}} $seconds @('CORVUS_IDA_DIR', 'CORVUS_X')) -join ',')
            'noida=' + ((Get-IdaHostClasses {{Quote(tests)}} $seconds @('CORVUS_X')) -join ',')
            'github=' + ((Get-RemoteClasses {{Quote(tests)}}) -join ',')
            """);
        // Longest first, each to the machine with less so far: 100 there, 60 and 50 here, the unrecorded 1 s there.
        Assert.Contains("there=IdaLongTests,IdaNewTests", lines);
        Assert.Contains("noida=", lines);
        Assert.Contains("github=EngineMixTests", lines);
    }

    [Fact]
    [Trait("Speed", "Slow")]
    public void About_half_the_ghidra_classes_by_recorded_time_stay_here()
    {
        var tests = Path.Combine(_dir.Path, "ghidra-tests");
        void Source(string text, string file)
        {
            Directory.CreateDirectory(Path.Combine(tests, "Engines"));
            File.WriteAllText(Path.Combine(tests, "Engines", file), text);
        }
        Source("public class GhidraLongTests { [GhidraFact] public void M() { } }", "A.cs");
        Source("public class GhidraMidTests { [GhidraFact] public void M() { } }", "B.cs");
        Source("public class GhidraNewTests { [GhidraFact] public void M() { } }", "C.cs");
        Source("public class EngineMixTests { [IdaFact] public void A() { } [GhidraFact] public void B() { } }", "D.cs");
        var lines = TestReuseTests.Run($$"""
            Import-Module {{Module}}
            'here=' + ((Get-GhidraLocalClasses {{Quote(tests)}} @{ GhidraLongTests = 100; GhidraMidTests = 40; EngineMixTests = 500 }) -join ',')
            """);
        if (lines is ["skip"]) return;
        // Longest first, each to the machine with less so far: 100 there, 40 and the unrecorded 1 s here; a mixed class
        // is split by test instead.
        Assert.Contains("here=GhidraMidTests,GhidraNewTests", lines);
    }

    [Fact]
    [Trait("Speed", "Slow")]
    public void A_host_with_two_of_five_engine_permits_takes_two_fifths_of_the_engine_time()
    {
        var tests = Path.Combine(_dir.Path, "share-tests");
        Directory.CreateDirectory(Path.Combine(tests, "Engines"));
        foreach (var name in new[] { "GhidraATests", "GhidraBTests", "GhidraCTests", "GhidraDTests" })
            File.WriteAllText(Path.Combine(tests, "Engines", name + ".cs"), $"public class {name} {{ [GhidraFact] public void M() {{ }} }}");
        var lines = TestReuseTests.Run($$"""
            Import-Module {{Module}}
            $seconds = @{ GhidraATests = 100; GhidraBTests = 60; GhidraCTests = 50; GhidraDTests = 40 }
            'half=' + ((Get-GhidraLocalClasses {{Quote(tests)}} $seconds) -join ',')
            'part=' + ((Get-GhidraLocalClasses {{Quote(tests)}} $seconds 0.4) -join ',')
            """);
        if (lines is ["skip"]) return;
        // Half: 100 and 40 there, 60 and 50 here. Two fifths: 100 of the 250 s there, the rest here.
        Assert.Contains("half=GhidraBTests,GhidraCTests", lines);
        Assert.Contains("part=GhidraBTests,GhidraCTests,GhidraDTests", lines);
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
            'loaded=' + ((Get-SkippedOnHost {{Quote(remote)}} {{Quote(before)}}) -join ',')
            $here = @(Get-SkippedOnHost {{Quote(remote)}} {{Quote(before)}} $fastest)
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

    [Fact]
    [Trait("Speed", "Slow")]
    public void A_test_host_whose_ssh_never_returns_is_named_and_left_unused()
    {
        var pid = _dir.File("pid.txt");
        // The stand-in ssh records its process id and then hangs, as a session stuck after login does.
        var ssh = _dir.File("ssh.ps1");
        File.WriteAllText(ssh, $$"""
            Set-Content {{Quote(pid)}} $PID
            Start-Sleep -Seconds 600
            """);
        var lines = TestReuseTests.Run($$"""
            Import-Module {{Module}}
            & (Get-Module test-remote) { $script:ShortCallSeconds = 5 }
            $env:CORVUS_TEST_SSH = {{Quote(ssh)}}; $env:CORVUS_TEST_PUSH_RUN = '1'; $env:CORVUS_TEST_REMOTE = 'tester@stuck'
            $clock = [Diagnostics.Stopwatch]::StartNew()
            'answers=' + (Test-RemoteHost 'tester@stuck')
            'bounded=' + ($clock.Elapsed.TotalSeconds -lt 30)
            # Under load (the full run on c72de6da) the stand-in may be ended before it records its id; pid 0 is the Idle process.
            'ended=' + (-not (Test-Path {{Quote(pid)}}) -or -not (Get-Process -Id ([int](Get-Content {{Quote(pid)}})) -ErrorAction SilentlyContinue))
            'target=' + ((Get-OffloadTarget {{Quote(DocsTests.RepoRoot())}} $false).Kind -ne 'ssh')
            'variables=' + @(Get-HostVariables 'tester@stuck').Count
            """);
        if (lines is ["skip"]) return;
        Assert.Contains("answers=False", lines);
        Assert.Contains("Test host tester@stuck gave no answer within 5 s; not used.", lines);
        Assert.Contains("bounded=True", lines);
        Assert.Contains("ended=True", lines);
        Assert.Contains("target=True", lines);
        Assert.Contains("variables=0", lines);
    }

    [Fact]
    [Trait("Speed", "Slow")]
    public void A_test_host_that_answers_takes_the_classes_and_its_results_come_back()
    {
        var trx = _dir.File("host.trx");
        File.WriteAllText(trx, Trx(("FormatSweepTests", "Failed"), ("RoundTripTests", "Passed")));
        var sent = _dir.File("sent-run.ps1");
        // The stand-in ssh answers its probe unless the host is "down", names one real-data variable set there, and
        // reports a started run that exited 1; the stand-in scp keeps the run script it is sent and hands back the
        // host's TRX.
        var ssh = _dir.File("ssh.ps1");
        File.WriteAllText(ssh, """
            $line = $args -join ' '
            if ($line -match 'down ') { exit 255 }
            if ($line -match ' exit 0$') { exit 0 }
            if ($line -match '-EncodedCommand ') { 'CORVUS_APPS'; 'a line that names no variable'; exit 0 }
            if ($line -match '-File corvus-test-host/corvus-remote-\w+\.ps1$') { 'corvus-remote: started'; 'corvus-remote-run 1 1'; 'corvus-remote-exit 1'; exit 0 }
            exit 1
            """);
        var scp = _dir.File("scp.ps1");
        File.WriteAllText(scp, $$"""
            $from = $args[-2]; $to = $args[-1]
            if ($to -like '*:corvus-test-host/') { $args | Where-Object { "$_" -like '*corvus-remote-*.ps1' } | ForEach-Object { Copy-Item $_ {{Quote(sent)}} }; exit 0 }
            if ($from -like '*:corvus-test-host/results/*/run-1.trx') { Copy-Item {{Quote(trx)}} $to; exit 0 }
            exit 1
            """);
        var lines = TestReuseTests.Run($$"""
            Import-Module {{Module}}
            $env:CORVUS_TEST_SSH = {{Quote(ssh)}}; $env:CORVUS_TEST_SCP = {{Quote(scp)}}; $env:CORVUS_TEST_PUSH_RUN = '1'
            $env:CORVUS_TEST_REMOTE = 'tester@host2'
            $target = Get-OffloadTarget {{Quote(DocsTests.RepoRoot())}} $false
            'target=' + $target.Kind + ',' + $target.Name + ',' + ($target.Variables -join ',')
            $got = Receive-Offload (Start-Offload $target 'abc123' @('FormatSweepTests', 'RoundTripTests') $false {{Module}} @('RoundTripTests')) {{Quote(Path.Combine(_dir.Path, "back"))}}
            'got=' + $got.Started + ',' + $got.Note + ',' + (($got.Failed | ForEach-Object { "$($_.Class)@$($_.Platform)" }) -join ',') + ',' + ([xml](Get-Content $got.Trx -Raw)).TestRun.ResultSummary.Counters.total
            $script = Get-Content {{Quote(sent)}} -Raw
            'script=' + $script.Contains("cat-file -e 'abc123^{commit}'") + ',' + $script.Contains("--filter '(FullyQualifiedName~.FormatSweepTests|(FullyQualifiedName~.RoundTripTests&Engine!=ida))&Tier!=Release'")
            $env:CORVUS_TEST_REMOTE = 'tester@down'
            'down=' + ((Get-OffloadTarget {{Quote(DocsTests.RepoRoot())}} $false).Kind -ne 'ssh')
            $late = Receive-RemoteRun @{ Kind = 'ssh'; Host = 'tester@host2'; Output = @('corvus-remote: the commit did not reach the host from origin in 120 s') } {{Quote(Path.Combine(_dir.Path, "late"))}}
            'late=' + $late.Started + ',' + $late.Note
            $lost = Receive-RemoteRun @{ Kind = 'ssh'; Host = 'tester@host2'; Output = @('Connection refused') } {{Quote(Path.Combine(_dir.Path, "lost"))}}
            'lost=' + $lost.Started + ',' + $lost.Note
            """);
        if (lines is ["skip"]) return;
        Assert.Contains("target=ssh,tester@host2,CORVUS_APPS", lines);
        Assert.Contains("got=True,exit 1,FormatSweepTests@host,2", lines);
        Assert.Contains("script=True,True", lines);
        Assert.Contains("down=True", lines);
        Assert.Contains("late=False,the commit did not reach the host from origin in 120 s", lines);
        Assert.Contains("lost=False,ssh tester@host2 failed: Connection refused", lines);
    }

    [Fact]
    [Trait("Speed", "Slow")]
    public void A_run_that_waits_for_another_on_the_host_says_so_and_its_result_names_the_wait()
    {
        // The test holds the host's lock until the run script, started in a home without a clone, says it waits, and 1.5 s
        // more; the script then ends at once naming the missing commit.
        var home = Path.Combine(_dir.Path, "home");
        Directory.CreateDirectory(home);
        var script = _dir.File("run.ps1");
        var output = _dir.File("out.txt");
        var lines = TestReuseTests.Run($$"""
            Import-Module {{Module}}
            Set-Content {{Quote(script)}} (Get-RemoteRunScript 'abc123' 'FullyQualifiedName~X' 'wait1' -Bundle)
            $lock = [Threading.Mutex]::new($false, 'Global\corvus-test-host')
            try { [void]$lock.WaitOne() } catch [Threading.AbandonedMutexException] { }
            $env:USERPROFILE = {{Quote(home)}}; $env:HOME = {{Quote(home)}}
            $run = Start-Process (Get-Process -Id $PID).Path -ArgumentList '-NoProfile', '-File', {{Quote(script)}} -RedirectStandardOutput {{Quote(output)}} -PassThru -WindowStyle Hidden
            $said = [Diagnostics.Stopwatch]::StartNew()
            while (-not $run.HasExited -and $said.Elapsed.TotalSeconds -lt 60 -and -not ((Get-Content {{Quote(output)}} -ErrorAction SilentlyContinue) -contains 'corvus-remote: waiting for another run on the host')) { Start-Sleep -Milliseconds 100 }
            Start-Sleep -Milliseconds 1500
            $lock.ReleaseMutex()
            'ended=' + $run.WaitForExit({{ScriptExitMs}})
            $out = @(Get-Content {{Quote(output)}})
            'waiting=' + ($out -contains 'corvus-remote: waiting for another run on the host')
            'waited=' + [bool]($out | Where-Object { $_ -match '^corvus-remote-waited [1-9]\d*$' })
            $got = Receive-RemoteRun @{ Kind = 'ssh'; Host = 'tester@host2'; Output = $out } {{Quote(Path.Combine(_dir.Path, "back"))}}
            'got=' + $got.Started + ',' + $got.Note + ',' + ($got.Waited -ge 1)
            Save-TierRecord {{Quote(_dir.Path)}} ([ordered]@{ target = 'tester@host2'; commit = 'abc12345'; at = 'now'; state = 'not run'; classes = 1; seconds = 4; waited = 3; note = $got.Note })
            'status=' + (Get-TierStatus {{Quote(_dir.Path)}})
            """);
        if (lines is ["skip"]) return;
        Assert.Contains("ended=True", lines);
        Assert.Contains("waiting=True", lines);
        Assert.Contains("waited=True", lines);
        Assert.Contains("got=False,the commit did not reach the host,True", lines);
        Assert.Contains("status=not run on abc12345 at now on tester@host2 (1 classes, 4 s); waited 3 s for another run there; the commit did not reach the host", lines);
    }

    [Fact]
    [Trait("Speed", "Slow")]
    public void A_build_that_fails_on_a_file_removed_after_checkout_names_the_file()
    {
        // The host's clone is a one-commit repository; a stand-in dotnet first on PATH removes a tracked file from the
        // checked-out tree and fails, as a build does once another program on the host removed a fixture.
        var home = Path.Combine(_dir.Path, "home");
        var clone = Path.Combine(home, "corvus-test-host", "repo");
        Directory.CreateDirectory(Path.Combine(clone, "fixtures"));
        File.WriteAllText(Path.Combine(clone, "fixtures", "sample.ps1"), "'sample'");
        File.WriteAllText(Path.Combine(clone, "kept.txt"), "kept");
        var bin = Path.Combine(_dir.Path, "bin");
        Directory.CreateDirectory(bin);
        File.WriteAllText(Path.Combine(bin, "dotnet.cmd"), $"@del \"{Path.Combine(home, "corvus-test-host", "run", "fixtures", "sample.ps1")}\"\r\n@exit /b 1\r\n");
        var script = _dir.File("run.ps1");
        var output = _dir.File("out.txt");
        var lines = TestReuseTests.Run($$"""
            if (-not $IsWindows) { 'skip'; return }
            Import-Module {{Module}}
            $repo = {{Quote(clone)}}
            git -C $repo init --quiet; git -C $repo add -A
            git -C $repo -c user.name=t -c user.email=t@t commit --quiet -m one
            $commit = (git -C $repo rev-parse HEAD).Trim()
            Set-Content {{Quote(script)}} (Get-RemoteRunScript $commit 'FullyQualifiedName~X' 'gone1' -Bundle)
            $env:USERPROFILE = {{Quote(home)}}; $env:HOME = {{Quote(home)}}; $env:PATH = {{Quote(bin)}} + ';' + $env:PATH
            $run = Start-Process (Get-Process -Id $PID).Path -ArgumentList '-NoProfile', '-File', {{Quote(script)}} -RedirectStandardOutput {{Quote(output)}} -PassThru -WindowStyle Hidden
            'ended=' + $run.WaitForExit({{ScriptExitMs}})
            $got = Receive-RemoteRun @{ Kind = 'ssh'; Host = 'tester@host2'; Output = @(Get-Content {{Quote(output)}}) } {{Quote(Path.Combine(_dir.Path, "back"))}}
            'got=' + $got.Started + ',' + $got.Note
            # Git writes its objects read-only, which the folder's delete cannot remove.
            Get-ChildItem {{Quote(home)}} -Recurse -File -Force | ForEach-Object { $_.IsReadOnly = $false }
            """);
        if (lines is ["skip"]) return;
        Assert.Contains("ended=True", lines);
        Assert.Contains("got=False,the build failed: 1 tracked file removed on the host after checkout (fixtures/sample.ps1); see results/gone1/console.log", lines);
    }

    [Fact]
    public void A_commit_origin_lacks_goes_to_the_host_as_a_bundle_and_the_record_names_it()
    {
        // A push run starts before its push lands (the run on a5dbd1db waited 120 s for origin, then ran all here).
        var sent = _dir.File("sent.txt");
        var ssh = _dir.File("ssh.ps1");
        File.WriteAllText(ssh, """
            if (($args -join ' ') -match '-File corvus-test-host/corvus-remote-\w+\.ps1$') { 'corvus-remote: started'; 'corvus-remote-run 1 0'; 'corvus-remote-exit 0'; exit 0 }
            exit 0
            """);
        var scp = _dir.File("scp.ps1");
        File.WriteAllText(scp, $$"""
            if ($args[-1] -like '*:corvus-test-host/') {
                $script = $args | Where-Object { "$_" -like '*corvus-remote-*.ps1' } | ForEach-Object { Get-Content $_ -Raw }
                $bundles = @($args | Where-Object { "$_" -like '*.bundle' -and (Test-Path $_) })
                Set-Content {{Quote(sent)}} ("bundles=$($bundles.Count) wait=$($script.Contains('AddSeconds(0)')) fetch=$($script.Contains('fetch --quiet $bundle'))")
            }
            exit 1
            """);
        // Start-Offload bundles from the module's own repository: a copy in a repository of the test's own, whose
        // origin/main is set by hand, so a CI checkout without origin/main makes no difference.
        var repo = Path.Combine(_dir.Path, "repo");
        Directory.CreateDirectory(repo);
        var module = Path.Combine(repo, "test-remote.psm1");
        File.Copy(Path.Combine(DocsTests.RepoRoot(), "test-remote.psm1"), module);
        var lines = TestReuseTests.Run($$"""
            Import-Module {{Quote(module)}}
            $env:CORVUS_TEST_SSH = {{Quote(ssh)}}; $env:CORVUS_TEST_SCP = {{Quote(scp)}}
            Set-Location {{Quote(repo)}}
            git init -q; git config user.email t@t; git config user.name t
            Set-Content a.txt one; git add a.txt; git commit -q -m a
            $pushed = (git rev-parse HEAD).Trim(); git update-ref refs/remotes/origin/main $pushed
            Set-Content a.txt two; git commit -q -am b
            $commit = (git rev-parse HEAD).Trim()
            $job = Start-Offload @{ Kind = 'ssh'; Host = 'tester@host2'; Name = 'tester@host2' } $commit @('FormatSweepTests') $false {{Quote(module)}}
            'transport=' + $job.Transport
            $null = Receive-Job $job -Wait -AutoRemoveJob
            Get-Content {{Quote(sent)}}
            $known = Start-Offload @{ Kind = 'ssh'; Host = 'tester@host2'; Name = 'tester@host2' } $pushed @('FormatSweepTests') $false {{Quote(module)}}
            'known=' + $known.Transport
            $null = Receive-Job $known -Wait -AutoRemoveJob
            $git = {{Quote(_dir.Path)}}
            Save-RemoteRecord $git ([ordered]@{ target = 'tester@host2'; commit = 'abc'; at = 'now'; classes = 1; held = 0; state = 'passed'; seconds = 1; note = $null; transport = 'bundle' })
            Get-RemoteStatus $git
            """);
        // Git writes its objects read-only.
        foreach (var f in Directory.EnumerateFiles(repo, "*", SearchOption.AllDirectories)) File.SetAttributes(f, FileAttributes.Normal);
        if (lines is ["skip"]) return;
        Assert.Contains("transport=bundle", lines);
        Assert.Contains("bundles=1 wait=True fetch=True", lines);
        Assert.Contains("known=origin", lines);
        Assert.Contains("tester@host2: passed on abc at now (1 classes, 1 s); the commit went as a bundle, origin lacked it", lines);
    }

    [Fact]
    [Trait("Speed", "Slow")]
    public void A_filter_runs_repeatedly_on_the_host_from_the_working_tree_and_failed_runs_come_back()
    {
        var repo = Path.Combine(_dir.Path, "repo");
        Directory.CreateDirectory(repo);
        var trx = _dir.File("run.trx");
        File.WriteAllText(trx, Trx(("FormatSweepTests", "Failed")));
        var sent = _dir.File("sent-run.ps1");
        var bundles = _dir.File("bundles.txt");
        // The stand-in ssh reports two runs of which the second failed; the stand-in scp keeps the run script, notes
        // each bundle it is sent and hands back any run's TRX.
        var ssh = _dir.File("ssh.ps1");
        File.WriteAllText(ssh, """
            if (($args -join ' ') -match '-File corvus-test-host/corvus-remote-\w+\.ps1$') { 'corvus-remote: started'; 'corvus-remote-run 1 0'; 'corvus-remote-run 2 1'; 'corvus-remote-exit 1' }
            exit 0
            """);
        var scp = _dir.File("scp.ps1");
        File.WriteAllText(scp, $$"""
            $from = $args[-2]; $to = $args[-1]
            if ($to -like '*:corvus-test-host/') {
                $args | Where-Object { "$_" -like '*corvus-remote-*.ps1' } | ForEach-Object { Copy-Item $_ {{Quote(sent)}} }
                $args | Where-Object { "$_" -like '*.bundle' } | ForEach-Object { Add-Content {{Quote(bundles)}} (Test-Path $_) }
                exit 0
            }
            if ($from -like '*:corvus-test-host/results/*/run-*.trx') { Copy-Item {{Quote(trx)}} $to; exit 0 }
            exit 1
            """);
        var back = Path.Combine(_dir.Path, "back");
        var lines = TestReuseTests.Run($$"""
            Import-Module {{Module}}
            $env:CORVUS_TEST_SSH = {{Quote(ssh)}}; $env:CORVUS_TEST_SCP = {{Quote(scp)}}
            Set-Location {{Quote(repo)}}
            git init -q; git config user.email t@t; git config user.name t
            Set-Content a.txt one; git add a.txt; git commit -q -m a
            $head = (git rev-parse HEAD).Trim(); git update-ref refs/remotes/origin/main $head
            $clean = New-RemoteSnapshot {{Quote(repo)}} 'clean1'
            'clean=' + ($clean.Commit -eq $head) + ',' + ($clean.Bundle -eq '')
            Set-Content a.txt two; Set-Content b.txt new
            $dirty = New-RemoteSnapshot {{Quote(repo)}} 'dirty1'
            'dirty=' + ($dirty.Commit -ne $head) + ',' + (Test-Path $dirty.Bundle) + ',' + ((git show "$($dirty.Commit):b.txt").Trim()) + ',' + ((git status --porcelain) -join '|')
            Remove-Item $dirty.Bundle
            $code = Invoke-RemoteFilter {{Quote(repo)}} 'tester@host2' 'FullyQualifiedName~FormatSweepTests' 2 {{Quote(back)}} 6>$null
            'code=' + $code + ',' + ((Get-ChildItem {{Quote(back)}}).Name -join ',')
            'bundle=' + ((Get-Content {{Quote(bundles)}}) -join ',')
            $script = Get-Content {{Quote(sent)}} -Raw
            'script=' + $script.Contains('-le 2;') + ',' + $script.Contains("--filter 'FullyQualifiedName~FormatSweepTests'") + ',' + $script.Contains('AddSeconds(0)')
            """);
        // Git writes its objects read-only.
        foreach (var f in Directory.EnumerateFiles(repo, "*", SearchOption.AllDirectories)) File.SetAttributes(f, FileAttributes.Normal);
        if (lines is ["skip"]) return;
        Assert.Contains("clean=True,True", lines);
        // The snapshot leaves the index and the working tree as they were.
        Assert.Contains("dirty=True,True,new, M a.txt|?? b.txt", lines);
        Assert.Contains("code=1,run-2.trx", lines);
        Assert.Contains("bundle=True", lines);
        Assert.Contains("script=True,True,True", lines);
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
        Assert.Contains("release=True", lines);
    }

    [Fact]
    [Trait("Speed", "Slow")]
    public void Live_classes_a_host_left_take_the_windows_results_of_the_ci_live_jobs_without_waiting_for_the_rest()
    {
        // Test names follow each result's position, so a test keeps its name in both files: Epsilon's M4 ran here
        // last time and was skipped there, while each side skipped one Epsilon test.
        var shard0 = _dir.File("live0.trx");
        File.WriteAllText(shard0, Trx(("LiveAlphaTests", "Passed"), ("LiveBetaTests", "Failed"), ("LiveOtherTests", "Passed"), ("LiveOtherTests", "Passed"),
            ("LiveEpsilonTests", "NotExecuted"), ("LiveEpsilonTests", "Passed")));
        var shard1 = _dir.File("live1.trx");
        File.WriteAllText(shard1, Trx(("LiveOtherTests", "Passed"), ("LiveGammaTests", "Passed")));
        var linux = _dir.File("live-linux.trx");
        File.WriteAllText(linux, Trx(("LiveGammaTests", "Failed")));
        var sweep = _dir.File("sweep.trx");
        File.WriteAllText(sweep, Trx(("SweepOnlyTests", "Passed")));
        var last = _dir.File("last.trx");
        File.WriteAllText(last, Trx(("LiveAlphaTests", "Passed"), ("LiveGammaTests", "Passed"), ("LiveBetaTests", "Passed"), ("LiveDeltaTests", "Passed"),
            ("LiveEpsilonTests", "Passed"), ("LiveEpsilonTests", "NotExecuted")));
        // The sweep job is still running and its artifact downloads only without the live pattern.
        string Gh(string liveStatus)
        {
            var path = _dir.File($"gh-live-{liveStatus}.ps1");
            File.WriteAllText(path, $$"""
                $verb = "$($args[0]) $($args[1])"
                if ($verb -eq 'run list') { '[{"databaseId": 42}]'; exit 0 }
                if ($verb -eq 'run view') { '{"status": "in_progress", "jobs": [{"name": "offload (live windows-latest 0/2)", "status": "{{liveStatus}}", "conclusion": "failure"}, {"name": "offload (live windows-latest 1/2)", "status": "completed", "conclusion": "success"}, {"name": "offload (live ubuntu-latest 0/1)", "status": "completed", "conclusion": "failure"}, {"name": "offload (sweep windows-latest 0/2)", "status": "in_progress", "conclusion": null}]}'; exit 0 }
                if ($verb -eq 'run download') {
                    $to = $args[[array]::IndexOf($args, '-D') + 1]; $pattern = $args[[array]::IndexOf($args, '-p') + 1]
                    $shards = @{ 'offload-live-windows-latest-0' = {{Quote(shard0)}}; 'offload-live-windows-latest-1' = {{Quote(shard1)}}; 'offload-live-ubuntu-latest-0' = {{Quote(linux)}}; 'offload-sweep-windows-latest-0' = {{Quote(sweep)}} }
                    foreach ($name in $shards.Keys) { if ($name -like $pattern) { New-Item -ItemType Directory -Force "$to/$name" | Out-Null; Copy-Item $shards[$name] "$to/$name/offload.trx" } }
                    exit 0
                }
                exit 1
                """);
            return path;
        }
        var lines = TestReuseTests.Run($$"""
            Import-Module {{Module}}
            $classes = 'LiveAlphaTests', 'LiveBetaTests', 'LiveGammaTests', 'LiveDeltaTests', 'LiveEpsilonTests'
            $env:CORVUS_TEST_GH = {{Quote(Gh("completed"))}}
            $r = Receive-GitHubLive {{Quote(DocsTests.RepoRoot())}} 'abc' $classes {{Quote(last)}} {{Quote(Path.Combine(_dir.Path, "done"))}} @{} 0 0
            'done=' + ($r.Proved -join ',') + '|' + ($r.Drop -join ',') + '|' + $r.Note
            $env:CORVUS_TEST_GH = {{Quote(Gh("in_progress"))}}
            $r = Receive-GitHubLive {{Quote(DocsTests.RepoRoot())}} 'abc' $classes {{Quote(last)}} {{Quote(Path.Combine(_dir.Path, "running"))}} @{} 0 0
            'running=' + ($r.Proved -join ',') + '|' + $r.Note
            """);
        if (lines is ["skip"]) return;
        // Gamma failed on Linux only; Beta failed on Windows; Delta has no results there.
        Assert.Contains("done=LiveAlphaTests,LiveGammaTests|LiveBetaTests,LiveEpsilonTests,LiveOtherTests|offload (live windows-latest 0/2), offload (live ubuntu-latest 0/1) ended failure in run 42", lines);
        Assert.Contains("running=|run 42 did not finish in 0 min", lines);
    }

    [Fact]
    public void A_push_run_leaves_host_classes_to_the_nightly_run_and_records_no_pass_for_their_families()
    {
        var git = _dir.Path;
        var lines = TestReuseTests.Run($$"""
            Import-Module {{Module}}
            $hostGroup = 'DeadlineTests', 'ImagesRealTests', 'MemoryTests'
            'unsent=' + ((Get-DeferredClasses @('MemoryTests', 'ImagesRealTests') $hostGroup) -join ',')
            'left=' + ((Get-DeferredClasses @('DeadlineTests', 'MemoryTests', 'SweepTests') $hostGroup @('MemoryTests')) -join ',')
            $map = @{ Session = @('DeadlineTests', 'NotesTests'); Images = @('ImagesRealTests'); Dotnet = @('DotnetTests') }
            'passed=' + ((Get-UndeferredFamilies @('Dotnet', 'Images', 'Session') $map @('ImagesRealTests')) -join ',')
            'none=' + ((Get-UndeferredFamilies @('Dotnet', 'Images') $map @()) -join ',')
            Save-DeferredClasses {{Quote(git)}} 'abc1234' @('DeadlineTests', 'ImagesRealTests')
            'status=' + (Get-DeferredStatus {{Quote(git)}})
            Save-DeferredClasses {{Quote(git)}} 'abc1235' @()
            'cleared=' + [string]::IsNullOrEmpty((Get-DeferredStatus {{Quote(git)}}))
            """);
        if (lines is ["skip"]) return;
        Assert.Contains("unsent=ImagesRealTests,MemoryTests", lines);
        // A class that failed on the test host reruns here; a class outside the host group is not deferred.
        Assert.Contains("left=DeadlineTests", lines);
        Assert.Contains("passed=Dotnet,Session", lines);
        Assert.Contains("none=Dotnet,Images", lines);
        Assert.Contains(lines, l => l.StartsWith("status=abc1234 at ") && l.EndsWith(": DeadlineTests, ImagesRealTests"));
        Assert.Contains("cleared=True", lines);
    }

    [Fact]
    public void The_host_tier_names_the_test_classes_of_its_families_without_returned_ones()
    {
        var tests = Path.Combine(_dir.Path, "tests");
        void Source(string folder, string text)
        {
            Directory.CreateDirectory(Path.Combine(tests, folder));
            File.WriteAllText(Path.Combine(tests, folder, "T.cs"), text);
        }
        Source("Web", "public sealed class WasmTests { }\npublic static class WasmFixture { }");
        Source("Dumps", "public class MinidumpTests { public sealed class Nested { } }");
        Source("Live", "public class LiveTargetTests { }");
        var lines = TestReuseTests.Run($$"""
            Import-Module {{Module}}
            'all=' + ((Get-TierClasses {{Quote(tests)}}) -join ',')
            'returned=' + ((Get-TierClasses {{Quote(tests)}} @('Dumps')) -join ',')
            'families=' + ((Get-TierFamilies @('Dumps', 'Web')) -join ',')
            'filter=' + (Get-TierFilter 'Tier!=Release' @('WasmTests', 'MinidumpTests'))
            'bare=' + (Get-TierFilter '' @('WasmTests'))
            'none=' + (Get-TierFilter 'Tier!=Release' @())
            """);
        if (lines is ["skip"]) return;
        Assert.Contains("all=MinidumpTests,WasmTests", lines);
        Assert.Contains("returned=WasmTests", lines);
        Assert.Contains("families=Accuracy,Builds,Containers,DotnetEdits,Il2Cpp,Mobile,NativeAot,NativeEdits,NativeFormats,Support", lines);
        // A push run keeps the smoke tests of the classes it leaves out.
        Assert.Contains("filter=((Tier!=Release)&FullyQualifiedName!~.WasmTests&FullyQualifiedName!~.MinidumpTests)|Smoke=push", lines);
        Assert.Contains("bare=(FullyQualifiedName!~.WasmTests)|Smoke=push", lines);
        Assert.Contains("none=Tier!=Release", lines);
    }

    [Fact]
    public void A_tier_class_the_test_host_cannot_run_stays_here_and_is_named()
    {
        var tests = Path.Combine(_dir.Path, "tests");
        void Source(string folder, string file, string text)
        {
            Directory.CreateDirectory(Path.Combine(tests, folder));
            File.WriteAllText(Path.Combine(tests, folder, file), text);
        }
        Source("Support", "TestEnv.cs", "public static class RealData { public const string Apps = \"CORVUS_APPS\"; }");
        Source("Web", "W.cs", "public sealed class WasmTests { [Fact] public void M() { } }");
        Source("Mobile", "A.cs", "public class ApkRealTests { [RequiresRealDataFact(RealData.Apps)] public void M() { } }");
        Source("Mobile", "B.cs", "public class BundleRealTests { [RequiresRealDataFact(\"CORVUS_BUNDLES\")] public void M() { } }");
        Source("Il2Cpp", "I.cs", "public class MetaIdaTests { [IdaFact] public void M() { } }\npublic class MetaGhidraTests { [GhidraFact] public void M() { } }");
        Source("Dumps", "D.cs", "public class DumpLiveTests { [LiveRealDataFact] public void M() { } }");
        Source("NativeFormats", "F.cs", "public class FirmwareComparisonTests { [Fact] public void M() { } }");
        Source("Live", "L.cs", "public class LiveTargetTests { [Fact] public void M() { } }");
        var lines = TestReuseTests.Run($$"""
            Import-Module {{Module}}
            $split = Get-TierHostClasses {{Quote(tests)}} @(Get-TierClasses {{Quote(tests)}}) @('CORVUS_APPS', 'CORVUS_GHIDRA_DIR')
            'sent=' + ($split.Sent -join ',')
            'kept=' + ($split.Kept -join '; ')
            """);
        if (lines is ["skip"]) return;
        Assert.Contains("sent=ApkRealTests,MetaGhidraTests,WasmTests", lines);
        Assert.Contains("kept=BundleRealTests (CORVUS_BUNDLES not set there); DumpLiveTests (live real data); "
            + "FirmwareComparisonTests (this machine's inputs); MetaIdaTests (CORVUS_IDA_DIR not set there)", lines);
    }

    [Fact]
    public void A_tier_class_skipping_there_what_the_last_whole_run_skipped_here_passes_and_without_that_run_it_does_not()
    {
        // The hand run on 03378fef compared with a push run's TRX, which holds no tier class, so every skip counted.
        var remote = _dir.File("tier.trx");
        File.WriteAllText(remote, Trx(("YaraTests", "Passed"), ("YaraTests", "NotExecuted")));
        var whole = _dir.File("whole.trx");
        File.WriteAllText(whole, Trx(("YaraTests", "Passed"), ("YaraTests", "NotExecuted")));
        var lines = TestReuseTests.Run($$"""
            Import-Module {{Module}}
            Import-Module {{Quote(Path.Combine(DocsTests.RepoRoot(), "test-reuse.psm1"))}}
            $map = @{ Containers = @('YaraTests') }
            $got = [pscustomobject]@{ Started = $true; Trx = {{Quote(remote)}}; Failed = @(); Note = 'exit 0' }
            'baseline=' + ((Get-TierPasses $got @('YaraTests') $map {{Quote(whole)}}).Passed -join ',')
            $none = Get-TierPasses $got @('YaraTests') $map {{Quote(Path.Combine(_dir.Path, "absent.trx"))}}
            'none=' + ($none.Passed -join ',') + '|' + ($none.Unproven -join ',')
            """);
        if (lines is ["skip"]) return;
        Assert.Contains("baseline=Containers", lines);
        Assert.Contains("none=|YaraTests", lines);
    }

    [Fact]
    public void A_tier_family_that_failed_on_the_test_host_returns_to_push_runs_until_the_record_drops_it()
    {
        var tests = Path.Combine(_dir.Path, "tests");
        void Source(string folder, string text)
        {
            Directory.CreateDirectory(Path.Combine(tests, folder));
            File.WriteAllText(Path.Combine(tests, folder, "T.cs"), text);
        }
        Source("Web", "public sealed class WasmTests { }");
        Source("Dumps", "public class MinidumpTests { }\npublic class CoreDumpTests { }");
        Source("Live", "public class LiveTargetTests { }");
        var git = _dir.Path;
        var lines = TestReuseTests.Run($$"""
            Import-Module {{Module}}
            'of=' + ((Get-TierFamiliesOf {{Quote(tests)}} @('CoreDumpTests', 'LiveTargetTests')) -join ',')
            'none=' + ((Get-TierReturned {{Quote(git)}}) -join ',')
            Save-TierRecord {{Quote(git)}} ([ordered]@{ target = 'tester@host2'; commit = 'abc12345'; at = 'now'; state = 'failed'; classes = 3; seconds = 9
                recorded = @('Web'); failed = @('Dumps'); returned = @('Dumps'); unproven = @(); kept = @(); note = 'exit 1' })
            $returned = @(Get-TierReturned {{Quote(git)}})
            'returned=' + ($returned -join ',')
            'push=' + ((Get-TierClasses {{Quote(tests)}} $returned) -join ',')
            'status=' + (Get-TierStatus {{Quote(git)}})
            Save-TierRecord {{Quote(git)}} ([ordered]@{ target = 'tester@host2'; commit = 'def12345'; at = 'now'; state = 'passed'; classes = 3; seconds = 9
                recorded = @('Dumps', 'Web'); failed = @(); returned = @(); unproven = @(); kept = @(); note = 'exit 0' })
            'again=' + ((Get-TierReturned {{Quote(git)}}) -join ',')
            """);
        if (lines is ["skip"]) return;
        Assert.Contains("of=Dumps", lines);
        Assert.Contains("none=", lines);
        Assert.Contains("returned=Dumps", lines);
        Assert.Contains("push=WasmTests", lines);
        Assert.Contains("status=failed on abc12345 at now on tester@host2 (3 classes, 9 s); recorded: Web; failed there: Dumps; returned to push runs: Dumps; exit 1", lines);
        Assert.Contains("again=", lines);
    }

    [Fact]
    public void The_host_tier_records_only_families_whose_classes_all_passed_there_with_a_full_result()
    {
        var remote = _dir.File("tier.trx");
        File.WriteAllText(remote, Trx(("WasmTests", "Passed"), ("CaptureTests", "Passed"), ("MinidumpTests", "Failed"), ("ApkTests", "Passed"),
            ("MetaTests", "Passed"), ("EarlyTests", "Passed")));
        var clean = _dir.File("clean.trx");
        File.WriteAllText(clean, Trx(("WasmTests", "Passed"), ("CaptureTests", "Passed")));
        var before = _dir.File("last.trx");
        File.WriteAllText(before, Trx(("EarlyTests", "Passed@40"), ("DiffTests", "Passed")));
        var git = _dir.Path;
        var lines = TestReuseTests.Run($$"""
            Import-Module {{Module}}
            Import-Module {{Quote(Path.Combine(DocsTests.RepoRoot(), "test-reuse.psm1"))}}
            $map = @{ Web = @('WasmTests', 'CaptureTests', 'WasmTheoryAttribute'); Dumps = @('MinidumpTests'); Mobile = @('ApkTests', 'ApkRealTests'); Il2Cpp = @('MetaTests')
                'class:EarlyTests' = @('EarlyTests'); Builds = @('DiffTests') }
            $sent = 'WasmTests', 'CaptureTests', 'MinidumpTests', 'ApkTests', 'MetaTests', 'EarlyTests', 'DiffTests'
            $got = [pscustomobject]@{ Started = $true; Trx = {{Quote(remote)}}; Failed = @([pscustomobject]@{ Class = 'MinidumpTests'; Platform = 'host' }); Note = 'exit 1' }
            $proved = Get-TierPasses $got $sent $map {{Quote(before)}}
            'passed=' + ($proved.Passed -join ',')
            'failed=' + ($proved.Failed -join ',')
            'unproven=' + ($proved.Unproven -join ',')
            $cut = Get-TierPasses ([pscustomobject]@{ Started = $true; Trx = {{Quote(clean)}}; Failed = @(); Note = 'the connection ended before the run did' }) @('WasmTests', 'CaptureTests') $map {{Quote(before)}}
            'cut=' + ($cut.Passed -join ',')
            $none = Get-TierPasses ([pscustomobject]@{ Started = $true; Trx = $null; Failed = @(); Note = 'exit 0' }) @('WasmTests') $map {{Quote(before)}}
            'none=' + ($none.Passed -join ',') + '|' + ($none.Unproven -join ',')
            Save-TierRecord {{Quote(git)}} ([ordered]@{ target = 'tester@host2'; commit = 'abc12345'; at = 'now'; state = 'failed'; classes = 7; seconds = 90.5
                recorded = $proved.Passed; failed = $proved.Failed; unproven = $proved.Unproven; kept = @('ApkRealTests (CORVUS_APPS not set there)'); note = 'exit 1' })
            'status=' + (Get-TierStatus {{Quote(git)}})
            """);
        if (lines is ["skip"]) return;
        // Mobile has a class that was not sent, Web an attribute class (the hand run on 03378fef recorded no NativeAot
        // pass for one); EarlyTests took 1 s there and 40 s in the last run here; DiffTests has no result there.
        Assert.Contains("passed=Il2Cpp,Web", lines);
        Assert.Contains("failed=Dumps", lines);
        Assert.Contains("unproven=DiffTests,EarlyTests", lines);
        Assert.Contains("cut=", lines);
        Assert.Contains("none=|WasmTests", lines);
        Assert.Contains("status=failed on abc12345 at now on tester@host2 (7 classes, 90.5 s); recorded: Il2Cpp, Web; failed there: Dumps; "
            + "no full result there: DiffTests, EarlyTests; kept here: ApkRealTests (CORVUS_APPS not set there); exit 1", lines);
    }
}
