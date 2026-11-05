using Corvus.Core;
using Corvus.Services;
using Corvus.Tools;

namespace Corvus.Tests;

/// <summary>live_events ordering of events stamped in the target.</summary>
public sealed class LiveEventOrderTests : IDisposable
{
    private const ulong Base = 0x7ff6_1000_0000;
    private static readonly string Sqlite = RealPackages.File("SQLitePCLRaw.lib.e_sqlite3", "2.1.11", "runtimes", "win-x64", "native", "e_sqlite3.dll");
    private readonly AssemblyWorkspace _workspace = new();
    private readonly LiveSessionService _service;
    private readonly LiveSessionTools _tools;

    public LiveEventOrderTests()
    {
        _service = new LiveSessionService(_workspace, new NativeCodeService(_workspace, SharedCodeIndex.Options()))
        {
            Backend = new ScriptedLiveBackend(Sqlite, Base, 0x200000),
        };
        _tools = new LiveSessionTools(new ServerOptions { AllowLive = true, AllowLiveAttach = true }, _service);
    }

    public void Dispose()
    {
        _service.Dispose();
        _workspace.Dispose();
    }

    [Fact]
    public async Task Events_stamped_out_of_receipt_order_are_listed_by_stamp()
    {
        await _tools.LiveSession("attach", program: "99994242");
        var s = _service.Get("live-1");
        // The stop arrives first; the batched call that ran before it arrives second.
        s.Add("stop", 5, Base, "stop point s1 hit 1", stampMs: 1_000_000.5);
        s.Add("call", 5, Base, "f()", source: "w1", stampMs: 1_000_000.25);

        var page = await _tools.LiveEvents("live-1", cursor: "1");
        Assert.True(page.IndexOf("call thread", StringComparison.Ordinal) < page.IndexOf("stop thread", StringComparison.Ordinal), page);
        var rows = s.Page(1, null, null, 10).Events;
        Assert.Equal(["call", "stop"], rows.Select(e => e.Kind));
        Assert.Equal([2L, 1L], rows.Select(e => e.Sequence));
    }

    [Fact]
    public async Task A_stamped_event_keeps_its_receipt_time_apart_from_its_stamp()
    {
        await _tools.LiveSession("attach", program: "99994242");
        var s = _service.Get("live-1");
        s.Add("stop", 5, Base, "stop point s1 hit 1", stampMs: 1_000_000.5);

        var e = s.Page(1, "stop", null, 10).Events[0];
        Assert.Equal(LiveSession.FromEpochMs(1_000_000.5), e.Time);
        Assert.True(e.Received > e.Time);
    }

    [Fact]
    public async Task Events_without_a_stamp_keep_arrival_order()
    {
        await _tools.LiveSession("attach", program: "99994242");
        var s = _service.Get("live-1");
        s.Add("output", null, null, "stdout: a");
        s.Add("call", 5, Base, "f()", source: "w1");
        s.Add("output", null, null, "stdout: b");

        Assert.Equal([1L, 2L, 3L], s.Page(1, null, null, 10).Events.Select(e => e.Sequence));
    }

    // Regression (21ad4520b): pages chosen by stamp repeated or skipped calls
    // that arrived late; LiveDotnetRealTests counted 1605 and 1598 of 1600.
    [Fact]
    public async Task Paging_late_stamped_events_lists_each_event_once()
    {
        await _tools.LiveSession("attach", program: "99994242");
        var s = _service.Get("live-1");
        // Batches arrive in reverse: each later batch ran earlier.
        for (int batch = 0; batch < 10; batch++)
            for (int i = 0; i < 7; i++)
                s.Add("call", 5, Base, $"f({batch}, {i})", source: "w1", stampMs: 1_000_000 + (10 - batch) * 100 + i);

        var seen = new List<string>();
        string? cursor = "1";
        for (int pages = 0; cursor != null && pages < 100; pages++)
        {
            var page = await _tools.LiveEvents("live-1", cursor: cursor, limit: 5);
            seen.AddRange(System.Text.RegularExpressions.Regex.Matches(page, @"#(\d+) call").Select(m => m.Groups[1].Value));
            cursor = System.Text.RegularExpressions.Regex.Match(page, @"more: cursor=(\d+)") is { Success: true } m2 ? m2.Groups[1].Value : null;
        }
        Assert.Equal(70, seen.Count);
        Assert.Equal(70, seen.Distinct().Count());
    }

    [Fact]
    public async Task A_stamp_outside_the_date_range_falls_back_to_arrival_time()
    {
        await _tools.LiveSession("attach", program: "99994242");
        var s = _service.Get("live-1");
        s.Add("stop", 5, Base, "stop point s1 hit 1", stampMs: double.NaN);
        s.Add("thread", 5, null, "thread started", stampMs: 1e300);
        var rows = s.Page(1, null, null, 10).Events;
        Assert.Equal(2, rows.Count);
        Assert.All(rows, e => Assert.Null(e.Received));
    }
}
