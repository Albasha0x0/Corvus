using System.Text.RegularExpressions;
using Corvus.Core;
using Corvus.Services;
using Corvus.Tools;

namespace Corvus.Tests;

/// <summary>Code coverage counted from stop events on a scripted backend: counts, the static call graph drawn with them, and two runs compared.</summary>
public sealed class LiveCoverageTests : IDisposable
{
    private const ulong Base = 0x7ff6_1000_0000;
    private static readonly string Sqlite = RealPackages.File("SQLitePCLRaw.lib.e_sqlite3", "2.1.11", "runtimes", "win-x64", "native", "e_sqlite3.dll");
    private readonly AssemblyWorkspace _workspace = new();
    private readonly LiveSessionService _service;
    private readonly ScriptedLiveBackend _backend;
    private readonly LiveSessionTools _tools;

    public LiveCoverageTests()
    {
        _backend = new ScriptedLiveBackend(Sqlite, Base, 0x200000);
        _service = new LiveSessionService(_workspace, new NativeCodeService(_workspace, new ServerOptions())) { Backend = _backend };
        _tools = new LiveSessionTools(new ServerOptions { AllowLive = true }, _service);
    }

    public void Dispose()
    {
        _service.Dispose();
        _workspace.Dispose();
    }

    private int Count(string op)
    {
        lock (_backend.Ops) return _backend.Ops.Count(o => o == op);
    }

    private async Task Until(Func<bool> done)
    {
        for (int i = 0; i < 100 && !done(); i++) await Task.Delay(20);
        Assert.True(done());
    }

    [Fact]
    public async Task Stops_at_function_starts_are_counted_resumed_and_cleared_at_the_hit_limit()
    {
        await _tools.LiveSession("attach", program: "4242");
        var start = await _tools.LiveCoverage("live-1", "start", match: "sqlite3_open", hitLimit: 2);
        var n = int.Parse(Regex.Match(start, @"cov-1 counting (\d+) functions of e_sqlite3\.dll").Groups[1].Value);
        Assert.True(n >= 3, start);
        Assert.Equal(n, Count("set"));

        var open = _service.GetCoverage("cov-1").Points.Select((p, i) => (p, i)).Single(x => x.p.Name == "sqlite3_open");
        var id = $"cov-1.{open.i + 1}";
        for (int i = 0; i < 3; i++) _backend.Hit(id, 7, Base + 0x10);
        await Until(() => Count("resume") == 3 && Count("clear") == 1);
        // the third stop came after the point reached its limit, so it is not counted
        var report = await _tools.LiveCoverage(action: "report", run: "cov-1");
        Assert.True(report.Contains($"cov-1 e_sqlite3.dll: 1 of {n} functions ran"), report);
        Assert.Matches(@"\s2\+\s+0x[0-9A-F]+\s+sqlite3_open\n", report);
        Assert.Empty(_service.Get("live-1").Held);
        Assert.Contains("No events.", await _tools.LiveEvents("live-1", kind: "stop"));

        var missed = await _tools.LiveCoverage(action: "report", run: "cov-1", show: "missed");
        Assert.Contains("sqlite3_open_v2", missed);
        Assert.DoesNotContain("  sqlite3_open\n", missed);
        Assert.Contains("complete", await _tools.LiveCoverage(action: "stop", run: "cov-1"));
        Assert.Equal(n, Count("clear"));
    }

    [Fact]
    public async Task Function_counts_are_drawn_on_the_static_call_graph()
    {
        await _tools.LiveSession("attach", program: "4242");
        await _tools.LiveCoverage("live-1", "start", match: "sqlite3_complete");
        var run = _service.GetCoverage("cov-1");
        var complete = run.Points.Select((p, i) => (p, i)).Single(x => x.p.Name == "sqlite3_complete");
        _backend.Hit($"cov-1.{complete.i + 1}", 7, Base + 0x10);
        await Until(() => run.Ran == 1);

        var all = await _tools.LiveCoverage(action: "report", run: "cov-1", show: "all", format: "dot");
        Assert.Contains("digraph \"cov-1\"", all);
        var n = Regex.Match(all, @"(n\d+) \[label=""sqlite3_complete\\n1""\];").Groups[1].Value;
        var n16 = Regex.Match(all, @"(n\d+) \[label=""sqlite3_complete16\\n-"" style=dashed\];").Groups[1].Value;
        Assert.True(n.Length > 0 && n16.Length > 0, all);
        Assert.Contains($"  {n16} -> {n};", all);
        Assert.Equal(ErrorCode.InvalidArgument, (await Assert.ThrowsAsync<ToolError>(() => _tools.LiveCoverage(action: "report", run: "cov-1", format: "svg"))).Code);
    }

    [Fact]
    public async Task The_diff_lists_the_functions_that_ran_in_only_one_run()
    {
        await _tools.LiveSession("attach", program: "4242");
        await _tools.LiveCoverage("live-1", "start", match: "sqlite3_open");
        await _tools.LiveCoverage("live-1", "start", match: "sqlite3_open");
        var points = _service.GetCoverage("cov-1").Points;
        int Index(string name) => points.Select((p, i) => (p, i)).Single(x => x.p.Name == name).i + 1;
        _backend.Hit($"cov-1.{Index("sqlite3_open")}", 7, Base + 0x10);
        _backend.Hit($"cov-1.{Index("sqlite3_open_v2")}", 7, Base + 0x10);
        _backend.Hit($"cov-2.{Index("sqlite3_open_v2")}", 7, Base + 0x10);
        _backend.Hit($"cov-2.{Index("sqlite3_open16")}", 7, Base + 0x10);
        await Until(() => _service.GetCoverage("cov-1").Ran == 2 && _service.GetCoverage("cov-2").Ran == 2);

        var diff = await _tools.LiveCoverage(action: "diff", run: "cov-1", other: "cov-2");

        Assert.True(diff.Contains($"cov-1 and cov-2 on e_sqlite3.dll: 1 function ran only in cov-1, 1 only in cov-2, 1 in both, {points.Count - 3} in neither"), diff);
        Assert.Matches(@"only in cov-1:\r?\n\s+1\s+0x[0-9A-F]+\s+sqlite3_open\r?\n", diff);
        Assert.Matches(@"only in cov-2:\r?\n\s+1\s+0x[0-9A-F]+\s+sqlite3_open16\r?\n", diff);
        Assert.Equal(ErrorCode.InvalidArgument, (await Assert.ThrowsAsync<ToolError>(() => _tools.LiveCoverage(action: "diff", run: "cov-1"))).Code);
    }
}
