namespace Corvus.Tests;

/// <summary>test-remote.psm1: which classes a whole-suite run offloads, the filters, and joining the results back.</summary>
public sealed class TestRemoteTests : IDisposable
{
    private readonly TempDir _dir = new();

    public void Dispose() => _dir.Dispose();

    private static string Module => Quote(Path.Combine(DocsTests.RepoRoot(), "test-remote.psm1"));

    private static string Quote(string path) => "'" + path.Replace("'", "''") + "'";

    /// <summary>A TRX file with one result per (class, outcome).</summary>
    internal static string Trx(params (string Class, string Outcome)[] results)
    {
        var tests = string.Join("\n", results.Select((r, i) => $"""<UnitTest id="{r.Class}-{i}"><TestMethod className="Corvus.Tests.{r.Class}" name="M{i}" /></UnitTest>"""));
        var outcomes = string.Join("\n", results.Select((r, i) => $"""<UnitTestResult testId="{r.Class}-{i}" testName="M{i}" outcome="{r.Outcome}" />"""));
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
    public void Engine_free_heavy_classes_are_offloaded_and_leave_the_local_filter()
    {
        var tests = Path.Combine(_dir.Path, "tests");
        void Source(string folder, string text)
        {
            Directory.CreateDirectory(Path.Combine(tests, folder));
            File.WriteAllText(Path.Combine(tests, folder, "T.cs"), text);
        }
        Source("Dotnet", "public sealed class FormatSweepTests { }\npublic class PlainTests { }");
        Source("DotnetEdits", "public abstract class PipelineRoundTripTests { public sealed class Part1 { } }");
        Source("Engines", "public class EngineSweepTests { }");
        Source("Live", "public class LiveMatrixTests { }");
        Source("NativeAnalysis", "public class IdaSweepTests { [IdaFact] public void M() { } }");
        Source("Containers", "public class CorpusSweepTests { [RequiresRealDataFact(\"CORVUS_X\")] public void M() { } }");
        Source("NativeFormats", "public class PeSweepTests { [WindowsFact] public void M() { } }");
        var lines = TestReuseTests.Run($$"""
            Import-Module {{Module}}
            $all = Get-RemoteClasses {{Quote(tests)}}
            'classes=' + ($all -join ',')
            'cross=' + ((Get-RemoteClasses {{Quote(tests)}} -CrossPlatform) -join ',')
            'shard0=' + ((Get-RemoteShard $all 0 2) -join ',')
            'shard1=' + ((Get-RemoteShard $all 1 2) -join ',')
            'routine=' + (Get-LocalFilter 'Tier!=Release' @('FormatSweepTests', 'PipelineRoundTripTests'))
            'everything=' + (Get-LocalFilter '' @('FormatSweepTests'))
            'none=' + (Get-LocalFilter 'Tier!=Release' @())
            'remote=' + (Get-ClassFilter @('FormatSweepTests', 'PeSweepTests') $false)
            'release=' + (Get-ClassFilter @('FormatSweepTests') $true)
            """);
        if (lines is ["skip"]) return;
        Assert.Contains("classes=FormatSweepTests,PeSweepTests,PipelineRoundTripTests", lines);
        Assert.Contains("cross=FormatSweepTests,PipelineRoundTripTests", lines);
        Assert.Contains("shard0=FormatSweepTests,PipelineRoundTripTests", lines);
        Assert.Contains("shard1=PeSweepTests", lines);
        Assert.Contains("routine=(Tier!=Release)&FullyQualifiedName!~.FormatSweepTests&FullyQualifiedName!~.PipelineRoundTripTests", lines);
        Assert.Contains("everything=FullyQualifiedName!~.FormatSweepTests", lines);
        Assert.Contains("none=Tier!=Release", lines);
        Assert.Contains("remote=(FullyQualifiedName~.FormatSweepTests|FullyQualifiedName~.PeSweepTests)&Tier!=Release", lines);
        Assert.Contains("release=FullyQualifiedName~.FormatSweepTests", lines);
    }

    [Fact]
    [Trait("Speed", "Slow")]
    public void Remote_results_join_the_local_ones_and_classes_that_skipped_there_rerun_here()
    {
        var remote = _dir.File("remote.trx");
        File.WriteAllText(remote, Trx(("FormatSweepTests", "Failed"), ("RoundTripTests", "Passed"), ("ToolSweepTests", "NotExecuted"), ("LocalSkipTests", "NotExecuted")));
        var local = _dir.File("full.trx");
        File.WriteAllText(local, Trx(("PlainTests", "Passed")));
        var before = _dir.File("last.trx");
        File.WriteAllText(before, Trx(("ToolSweepTests", "Passed"), ("LocalSkipTests", "NotExecuted")));
        var lines = TestReuseTests.Run($$"""
            Import-Module {{Module}}
            Import-Module {{Quote(Path.Combine(DocsTests.RepoRoot(), "test-reuse.psm1"))}}
            $here = @(Get-SkippedOnHost {{Quote(remote)}} {{Quote(before)}})
            'here=' + ($here -join ',')
            Join-TrxFiles {{Quote(local)}} @({{Quote(local)}}, {{Quote(remote)}}) $here
            'failed=' + ((Get-FailedTests {{Quote(local)}}) -join ',')
            $map = @{ Dotnet = @('PlainTests'); DotnetEdits = @('RoundTripTests'); Sweeps = @('FormatSweepTests'); Tools = @('ToolSweepTests') }
            'passed=' + ((Get-PassedFamilies {{Quote(local)}} $map 1) -join ',')
            'classes=' + ((Get-ClassOutcomes {{Quote(local)}} | ForEach-Object Class | Sort-Object) -join ',')
            'total=' + ([xml](Get-Content {{Quote(local)}} -Raw)).TestRun.ResultSummary.Counters.total
            Save-RemoteRecord {{Quote(_dir.Path)}} ([ordered]@{ target = 'github'; commit = 'abc'; at = 'now'; classes = 3; state = 'FAILED (exit 1)'; seconds = 12.5; note = $null })
            'status=' + (Get-RemoteStatus {{Quote(_dir.Path)}})
            """);
        if (lines is ["skip"]) return;
        // ToolSweepTests skipped a test there that ran here last time; LocalSkipTests skips here too.
        Assert.Contains("here=ToolSweepTests", lines);
        Assert.Contains("failed=Corvus.Tests.FormatSweepTests.M0", lines);
        Assert.Contains("passed=Dotnet,DotnetEdits", lines);
        Assert.Contains("classes=FormatSweepTests,LocalSkipTests,PlainTests,RoundTripTests", lines);
        Assert.Contains("total=4", lines);
        Assert.Contains("status=github: FAILED (exit 1) on abc at now (3 classes, 12.5 s)", lines);
    }
}
