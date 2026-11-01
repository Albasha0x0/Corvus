using System.Diagnostics;
using Corvus.Native.Providers.Ida;

namespace Corvus.Tests;

/// <summary>The worker's analysis loop with a fake IDA module set and a fake clock.</summary>
public sealed class IdaCheckpointTests : IDisposable
{
    private readonly TempDir _dir = new();

    // Each analysis step advances the fake clock by one second.
    private const string Script = """
        import sys, types
        sys.path.insert(0, sys.argv[1])
        import ida_worker as w
        now = [0.0]
        w.time = types.SimpleNamespace(time=lambda: now[0], sleep=lambda s: None)
        def step(*a):
            now[0] += 1.0
            return True
        saves = []
        auto = types.SimpleNamespace(enable_auto=lambda on: None, auto_make_step=step, auto_is_ok=lambda: False,
                                     auto_wait=lambda: True, get_auto_state=lambda: None)
        loader = types.SimpleNamespace(PATH_TYPE_IDB=0, get_path=lambda t: "x.i64", save_database=lambda p, f: saves.append(now[0]) or True)
        m = types.SimpleNamespace(ida_auto=auto, ida_loader=loader, idautils=types.SimpleNamespace(ida_idaapi=types.SimpleNamespace(BADADDR=-1)))
        events = []
        w._sink = events.append
        connected = sys.argv[2] == "connected"
        w._connected = connected
        complete = w.analyze_within(m, 3000, checkpoint=1000)
        print(complete, len(saves), sum('"checkpoint"' in e for e in events))
        if len(sys.argv) > 3:
            order = []
            w._connected = False
            w._state["open"] = False
            w._state["auto"] = True
            saves.clear()
            loader.save_database = lambda p, f: order.append("save") or True
            node = types.SimpleNamespace(hashset_buf=lambda k, v: order.append("stamp"))
            w.stamp_node = lambda create: node
            w.batch_mode = lambda: None
            w.ida = lambda: m
            m.idapro = types.SimpleNamespace(open_database=lambda p, a, c: 0)
            w.os = types.SimpleNamespace(path=types.SimpleNamespace(isfile=lambda p: False), getpid=lambda: 0)
            try:
                w.op_open({"idb": "x.i64", "input": "x.exe", "sha256": "ab", "budget_seconds": 700})
            except Exception:
                pass
            print(order[:3])
        """;

    private string Run(string mode, string? extra = null)
    {
        var worker = Path.Combine(_dir.Path, "ida_worker.py");
        using (var resource = typeof(IdaProvider).Assembly.GetManifestResourceStream(IdaProvider.WorkerResource)!)
        using (var file = File.Create(worker)) resource.CopyTo(file);
        var script = Path.Combine(_dir.Path, "analysis.py");
        File.WriteAllText(script, Script);
        var start = new ProcessStartInfo("python") { RedirectStandardOutput = true, RedirectStandardError = true };
        foreach (var a in extra == null ? new[] { "-I", script, _dir.Path, mode } : ["-I", script, _dir.Path, mode, extra]) start.ArgumentList.Add(a);
        using var p = Process.Start(start)!;
        var output = p.StandardOutput.ReadToEnd();
        var error = p.StandardError.ReadToEnd();
        p.WaitForExit();
        Assert.True(p.ExitCode == 0, error);
        return output.Trim();
    }

    [Fact]
    public void A_partial_analysis_saves_the_database_and_reports_a_checkpoint_each_interval()
    {
        // Interval 1000 s, budget 3000 s, so saves land at 1000, 2000 and 3000 s.
        Assert.Equal("False 3 3", Run("owned"));
    }

    [Fact]
    public void The_input_stamp_is_written_before_the_first_checkpoint_save()
    {
        Assert.EndsWith("['stamp', 'save', 'save']", Run("owned", "open"));
    }

    [Fact]
    public void A_database_open_in_ida_is_never_saved_by_the_analysis_loop()
    {
        Assert.Equal("False 0 0", Run("connected"));
    }

    public void Dispose() => _dir.Dispose();
}
