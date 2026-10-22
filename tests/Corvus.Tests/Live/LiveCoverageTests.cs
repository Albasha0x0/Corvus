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
        _service = new LiveSessionService(_workspace, new NativeCodeService(_workspace, SharedCodeIndex.Options())) { Backend = _backend };
        _tools = new LiveSessionTools(new ServerOptions { AllowLive = true, AllowLiveAttach = true }, _service);
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

    // waits for an event, not a duration: a loaded machine took over 2 s to place a load's points
    private async Task Until(Func<bool> done)
    {
        var clock = System.Diagnostics.Stopwatch.StartNew();
        while (!done() && clock.Elapsed < TimeSpan.FromSeconds(30)) await Task.Delay(20);
        Assert.True(done());
    }

    /// <summary>
    /// A managed run's last read waits for a periodic read in progress instead of skipping, and a read that ends after the
    /// run is complete adds nothing: the counts reported complete stay as reported.
    /// </summary>
    [Fact]
    public async Task Last_read_of_a_managed_run_waits_for_the_one_in_progress()
    {
        var run = new LiveCoverageRun("cov-1", new LiveSession("live-1", "scripted", "app.exe", true, null!), "app.dll", "", [new(0x06000001, "A"), new(0x06000002, "B")]);
        var inProgress = new TaskCompletionSource();
        var periodic = run.SampleAsync(async () => { await inProgress.Task; run.MarkRan(0x06000001); }, wait: false);
        await run.SampleAsync(() => Task.CompletedTask, wait: false); // skipped while one is in progress
        var last = run.SampleAsync(() => { run.MarkRan(0x06000002); return Task.CompletedTask; }, wait: true);
        Assert.False(last.IsCompleted);
        inProgress.SetResult();
        await Task.WhenAll(periodic, last);
        Assert.Equal(2, run.Ran);
        run.Finish("complete");
        await run.SampleAsync(() => { run.MarkRan(0x06000003); return Task.CompletedTask; }, wait: true);
        Assert.Equal(2, run.Ran);
    }

    [Fact]
    public async Task Stops_at_function_starts_are_counted_resumed_and_cleared_at_the_hit_limit()
    {
        await _tools.LiveSession("attach", program: "4242");
        var start = await _tools.LiveCoverage("live-1", "start", match: "sqlite3_open", hitLimit: 2);
        var n = int.Parse(Regex.Match(start, @"cov-1 counting (\d+) functions of e_sqlite3\.dll").Groups[1].Value);
        Assert.True(n >= 2, start);
        Assert.Equal(n, Count("set"));
        // a coverage stop needs no stack or registers
        lock (_backend.Bare) Assert.Equal(n, _backend.Bare.Count(id => id.StartsWith("cov-1.", StringComparison.Ordinal)));
        // sqlite3_open_v2 is one jmp: a stop point there lands in the function it leads to, counting every caller of that one
        Assert.Contains("1 function left out: a single jump", start);
        Assert.Contains("a single jump", _service.GetCoverage("cov-1").Unplaced[_service.GetCoverage("cov-1").Points.Single(p => p.Name == "sqlite3_open_v2").Rva]);

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
        Assert.Contains("sqlite3_open16", missed);
        Assert.DoesNotContain("  sqlite3_open\n", missed);
        Assert.Contains("complete", await _tools.LiveCoverage(action: "stop", run: "cov-1"));
        Assert.Equal(n, Count("clear"));
    }

    [Fact]
    public async Task A_run_whose_program_ended_stays_ended_when_stopped()
    {
        await _tools.LiveSession("attach", program: "4242");
        await _tools.LiveCoverage("live-1", "start", match: "sqlite3_open");
        _backend.Worker!.Emit(new System.Text.Json.Nodes.JsonObject { ["event"] = "exit", ["reason"] = "process-terminated" });
        await Until(() => _service.GetCoverage("cov-1").State == "ended");

        var stop = await _tools.LiveCoverage(action: "stop", run: "cov-1");
        Assert.StartsWith("cov-1 ended with its program, before the stop: 0 of ", stop);
        Assert.Equal("ended", _service.GetCoverage("cov-1").State);
        Assert.Contains("ended", await _tools.LiveCoverage(action: "list"));
    }

    [Fact]
    public async Task A_run_whose_program_ends_while_it_starts_is_ended()
    {
        await _tools.LiveSession("attach", program: "4242");
        var session = _service.Get("live-1");
        _service.BeforeCoverageRun = async () =>
        {
            _backend.Worker!.Emit(new System.Text.Json.Nodes.JsonObject { ["event"] = "exit", ["reason"] = "process-terminated" });
            await Until(() => session.Ended != null);
        };
        await _tools.LiveCoverage("live-1", "start", match: "sqlite3_open");
        Assert.Equal("ended", _service.GetCoverage("cov-1").State);
    }

    [Fact]
    public async Task A_stop_point_inside_a_function_start_and_coverage_of_that_function_exclude_each_other()
    {
        await _tools.LiveSession("attach", program: "4242");
        var index = new NativeCodeService(_workspace, SharedCodeIndex.Options()).IndexOfOriginal(_workspace.Natives.Single(), default);
        var rva = index.AddressOfName("sqlite3_complete")!.Value;
        var second = index.Disassemble(rva, 2)[1].Rva - rva;
        Assert.True(second < 16);
        await _tools.LiveBreak("live-1", "set", at: $"sqlite3_complete+0x{second:X}");
        await _tools.LiveCoverage("live-1", "start", match: "sqlite3_complete");
        Assert.Equal($"s1 sits {second} bytes in, inside the bytes a hook at the start rewrites", _service.GetCoverage("cov-1").Unplaced[rva]);
        await _tools.LiveCoverage(action: "stop", run: "cov-1");
        await _tools.LiveBreak("live-1", "clear", stopPoint: "s1");

        await _tools.LiveCoverage("live-1", "start", match: "sqlite3_complete");
        var refused = await Assert.ThrowsAsync<ToolError>(() => _tools.LiveBreak("live-1", "set", at: $"sqlite3_complete+0x{second:X}"));
        Assert.Equal(ErrorCode.Conflict, refused.Code);
        Assert.Contains("coverage run cov-2 rewrites", refused.Message);
        Assert.Contains("s2 set", await _tools.LiveBreak("live-1", "set", at: "sqlite3_complete")); // the start itself shares the hook
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
        await _tools.LiveCoverage("live-1", "start", match: "sqlite3_column_");
        Assert.Contains("cov-1", await _tools.LiveCoverage("live-1", "report")); // run omitted: the session's only run
        await _tools.LiveCoverage("live-1", "start", match: "sqlite3_column_");
        Assert.Contains("needs run: cov-1, cov-2", (await Assert.ThrowsAsync<ToolError>(() => _tools.LiveCoverage("live-1", "report"))).Message);
        var run = _service.GetCoverage("cov-1");
        var placed = run.Placed;
        Assert.True(placed.Count >= 3, string.Join(", ", run.Points.Select(p => p.Name)));
        var (a, b, c) = (placed[0].Name, placed[1].Name, placed[2].Name);
        int Index(string name) => run.Points.Select((p, i) => (p, i)).Single(x => x.p.Name == name).i + 1;
        _backend.Hit($"cov-1.{Index(a)}", 7, Base + 0x10);
        _backend.Hit($"cov-1.{Index(b)}", 7, Base + 0x10);
        _backend.Hit($"cov-2.{Index(b)}", 7, Base + 0x10);
        _backend.Hit($"cov-2.{Index(c)}", 7, Base + 0x10);
        await Until(() => _service.GetCoverage("cov-1").Ran == 2 && _service.GetCoverage("cov-2").Ran == 2);

        var diff = await _tools.LiveCoverage(action: "diff", run: "cov-1", other: "cov-2");

        Assert.True(diff.Contains($"cov-1 and cov-2 on e_sqlite3.dll: 1 function ran only in cov-1, 1 only in cov-2, 1 in both, {placed.Count - 3} in neither"), diff);
        Assert.Matches($@"only in cov-1:\r?\n\s+1\s+0x[0-9A-F]+\s+{a}\r?\n", diff);
        Assert.Matches($@"only in cov-2:\r?\n\s+1\s+0x[0-9A-F]+\s+{c}\r?\n", diff);
        Assert.Equal(ErrorCode.InvalidArgument, (await Assert.ThrowsAsync<ToolError>(() => _tools.LiveCoverage(action: "diff", run: "cov-1"))).Code);
    }

    [Fact]
    public async Task A_run_on_a_module_loaded_later_waits_for_its_load_and_counts_from_its_first_call()
    {
        using var dir = new TempDir();
        var plugin = dir.File("plugin.dll");
        File.Copy(RealPackages.File("SQLitePCLRaw.lib.e_sqlite3", "2.1.2", "runtimes", "win-x64", "native", "e_sqlite3.dll"), plugin);
        await _tools.LiveSession("attach", program: "4242");
        Assert.Equal(ErrorCode.NotFound, (await Assert.ThrowsAsync<ToolError>(() => _tools.LiveCoverage("live-1", "start", match: "plugin!sqlite3_open"))).Code);
        _workspace.LoadAny(plugin);

        var start = await _tools.LiveCoverage("live-1", "start", match: "plugin!sqlite3_open");
        Assert.StartsWith("cov-1 waits for plugin to load, then counts ", start);
        Assert.Contains("waiting for plugin to load", await _tools.LiveCoverage(action: "report", run: "cov-1"));
        Assert.Equal(0, Count("set"));
        Assert.Contains("defer_module", _backend.Ops);

        const ulong PluginBase = 0x7ff7_0000_0000;
        _backend.Load("plugin.dll", plugin, PluginBase, 0x200000, heldBy: 77);
        await Until(() => Count("release_load") == 1);
        List<string> ops;
        lock (_backend.Ops) ops = [.. _backend.Ops];
        // the loading thread goes on only once every point is set
        Assert.True(ops.LastIndexOf("set") < ops.IndexOf("release_load"), string.Join(",", ops));
        Assert.Contains("undefer_module", ops);
        var run = _service.GetCoverage("cov-1");
        Assert.Null(run.PendingModule);
        var open = run.Points.Select((p, i) => (p, i)).Single(x => x.p.Name == "sqlite3_open");
        _backend.Hit($"cov-1.{open.i + 1}", 7, PluginBase + 0x10);
        await Until(() => run.Ran == 1);
        Assert.Contains("coverage run cov-1 set ", await _tools.LiveEvents("live-1", kind: "module"));
        Assert.Matches(@"\s1\s+0x[0-9A-F]+\s+sqlite3_open\n", await _tools.LiveCoverage(action: "report", run: "cov-1"));
    }

    /// <summary>A loaded module with no loaded image has its file read, as a module!name stop point reads it; one with no file is refused.</summary>
    [Fact]
    public async Task A_run_on_a_loaded_module_reads_its_image_from_its_file()
    {
        using var dir = new TempDir();
        var plugin = dir.File("plugin.dll");
        File.Copy(RealPackages.File("SQLitePCLRaw.lib.e_sqlite3", "2.1.2", "runtimes", "win-x64", "native", "e_sqlite3.dll"), plugin);
        await _tools.LiveSession("attach", program: "4242");
        _backend.Load("plugin.dll", plugin, 0x7ff7_0000_0000, 0x200000);
        await Until(() => _service.Get("live-1").Modules.Any(m => m.Name == "plugin.dll"));

        Assert.Matches(@"^cov-1 counting \d+ functions of plugin\.dll", await _tools.LiveCoverage("live-1", "start", match: "plugin!sqlite3_open"));
        var missing = await Assert.ThrowsAsync<ToolError>(() => _tools.LiveCoverage("live-1", "start", match: "system!open"));
        Assert.Equal(ErrorCode.Unsupported, missing.Code);
        Assert.Contains("/nowhere/system.dll", missing.Message);
    }

    /// <summary>
    /// A leading endbr64 stays in place under a hook, so a function whose first block leaves under 5 bytes after it is
    /// left out before any point is set; a point the backend refuses is left out with the instructions at its start.
    /// </summary>
    [Fact]
    public async Task Points_too_short_after_their_landing_pad_or_refused_name_their_instructions()
    {
        byte[] zero = [0xF3, 0x0F, 0x1E, 0xFA, 0x31, 0xC0, 0xC3];
        byte[] frame = [0xF3, 0x0F, 0x1E, 0xFA, 0x55, 0x48, 0x89, 0xE5, 0xB8, 0x01, 0x00, 0x00, 0x00, 0x5D, 0xC3];
        var text = Enumerable.Repeat((byte)0xCC, 0x30).ToArray();
        zero.CopyTo(text, 0);
        frame.CopyTo(text, 0x10);
        frame.CopyTo(text, 0x20);
        using var dir = new TempDir();
        var lib = dir.File("libplug.so");
        const uint T = NativeFormats.ElfWriter.TextRva;
        File.WriteAllBytes(lib, new NativeFormats.ElfWriter
        {
            Machine = NativeFormats.ElfWriter.EmX64, Text = text,
            Symbols = [new("fn_zero", T, (uint)zero.Length), new("fn_frame", T + 0x10, (uint)frame.Length), new("fn_refused", T + 0x20, (uint)frame.Length)],
        }.Build());
        const ulong LibBase = 0x7ff8_0000_0000;
        await _tools.LiveSession("attach", program: "4242");
        _backend.Load("libplug.so", lib, LibBase, 0x30000);
        await Until(() => _service.Get("live-1").Modules.Any(m => m.Name == "libplug.so"));
        _backend.Unhookable.Add(LibBase + T + 0x20);

        var start = await _tools.LiveCoverage("live-1", "start", match: "libplug.so!fn_");
        Assert.Contains("cov-1 counting 1 function of libplug.so", start);
        var unplaced = _service.GetCoverage("cov-1").Unplaced;
        Assert.Equal("too short to count with stop-based coverage: endbr64; xor eax, eax; ret leaves 3 byte(s) for the 5-byte jump a hook writes", unplaced[T]);
        Assert.False(unplaced.ContainsKey(T + 0x10));
        Assert.Equal("the stop point was refused: the function is 15 bytes long (endbr64; push rbp; mov rbp, rsp; mov eax, 1; pop rbp; ret), " +
            "too short for the jump a hook writes over its start after its endbr64.", unplaced[T + 0x20]);
    }

    /// <summary>A match over the cap names how many functions matched and narrower matches drawn from the image's names.</summary>
    [Fact]
    public async Task A_match_over_the_cap_suggests_narrower_matches_with_their_counts()
    {
        await _tools.LiveSession("attach", program: "4242");
        _service.CoverageLimit = 60;
        var over = await Assert.ThrowsAsync<ToolError>(() => _tools.LiveCoverage("live-1", "start", match: "sqlite3_"));
        Assert.Equal(ErrorCode.LimitExceeded, over.Code);
        Assert.Matches(@"^[\d,]+ functions of e_sqlite3\.dll have a name containing 'sqlite3_'; a run counts at most 60\.", over.Message);
        var suggested = Regex.Matches(over.Remediation!, @"match=(\S+) \((\d+)\)");
        Assert.True(suggested.Count >= 2, over.Remediation);
        Assert.All(suggested, s => Assert.InRange(int.Parse(s.Groups[2].Value), 2, 60));
        Assert.All(suggested, s => Assert.Contains("sqlite3_", s.Groups[1].Value));

        await _tools.LiveCoverage("live-1", "start", match: suggested[0].Groups[1].Value);
        Assert.Equal(int.Parse(suggested[0].Groups[2].Value), _service.GetCoverage("cov-1").Points.Count);
    }

    /// <summary>A run waiting for its module says up front what it leaves out, and counts what it then sets.</summary>
    [Fact]
    public async Task A_run_waiting_for_its_module_counts_what_it_sets_on_the_load()
    {
        using var dir = new TempDir();
        var plugin = dir.File("plugin.dll");
        File.Copy(RealPackages.File("SQLitePCLRaw.lib.e_sqlite3", "2.1.2", "runtimes", "win-x64", "native", "e_sqlite3.dll"), plugin);
        await _tools.LiveSession("attach", program: "4242");
        _workspace.LoadAny(plugin);

        var start = await _tools.LiveCoverage("live-1", "start", match: "plugin!sqlite3_");
        var counted = int.Parse(System.Text.RegularExpressions.Regex.Match(start, @"then counts ([\d,]+) function").Groups[1].Value.Replace(",", ""));
        Assert.Contains(" left out: ", start);
        _backend.Load("plugin.dll", plugin, 0x7ff7_0000_0000, 0x200000, heldBy: 77);
        await Until(() => Count("release_load") == 1);
        Assert.Equal(counted, _service.GetCoverage("cov-1").Placed.Count);
    }

    /// <summary>A run of every function sets a stop point per function, one request each: thousands of them.</summary>
    [Trait("Speed", "Slow")]
    [Fact]
    public async Task A_run_of_every_function_is_too_large_to_draw()
    {
        await _tools.LiveSession("attach", program: "4242");
        await _tools.LiveCoverage("live-1", "start");
        var all = _service.GetCoverage("cov-1").Placed.Count;
        Assert.True(all > 200, $"{all} functions");
        var dot = await Assert.ThrowsAsync<ToolError>(() => _tools.LiveCoverage(action: "report", run: "cov-1", show: "all", format: "dot"));
        Assert.Equal(ErrorCode.LimitExceeded, dot.Code);
        Assert.Contains("match=", dot.Remediation);
    }

    [Fact]
    public async Task Runs_of_two_builds_and_unknown_names_are_refused()
    {
        await _tools.LiveSession("attach", program: "4242");
        await _tools.LiveCoverage("live-1", "start", match: "sqlite3_open");
        Assert.Equal(ErrorCode.InvalidArgument, (await Assert.ThrowsAsync<ToolError>(() => _tools.LiveCoverage(action: "report", run: "cov-1", show: "some"))).Code);
        Assert.Equal(ErrorCode.NotFound, (await Assert.ThrowsAsync<ToolError>(() => _tools.LiveCoverage("live-1", "start", match: "nosuchmodule!open"))).Code);
        Assert.Equal(ErrorCode.NotFound, (await Assert.ThrowsAsync<ToolError>(() => _tools.LiveCoverage("live-1", "start", match: "no_function_has_this_name"))).Code);

        var old = RealPackages.File("SQLitePCLRaw.lib.e_sqlite3", "2.1.2", "runtimes", "win-x64", "native", "e_sqlite3.dll");
        _service.Backend = new ScriptedLiveBackend(old, Base, 0x200000) { ProcessId = 4343 };
        await _tools.LiveSession("attach", program: "4343");
        await _tools.LiveCoverage("live-2", "start", match: "sqlite3_column_");
        var builds = await Assert.ThrowsAsync<ToolError>(() => _tools.LiveCoverage(action: "diff", run: "cov-1", other: "cov-2"));
        Assert.Equal(ErrorCode.Conflict, builds.Code);
        Assert.Contains("different builds", builds.Message);
    }
}
