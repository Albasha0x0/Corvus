using System.Text.Json.Nodes;
using Corvus.Core;
using Corvus.Native.Providers;
using Corvus.Native.Providers.Live;
using Corvus.Services;
using Corvus.Tools;

namespace Corvus.Tests;

/// <summary>A scripted session backend: one program whose main module is a real image, stops on demand.</summary>
internal sealed class ScriptedLiveBackend(string mainPath, ulong mainBase, uint mainSize) : ILiveBackend
{
    public const int Pid = 4242;
    public FakeWorkerProcess? Worker { get; private set; }
    public readonly List<string> Ops = [];
    public string? Missing { get; init; }
    /// <summary>Bytes the program holds, by address.</summary>
    public readonly Dictionary<ulong, byte[]> Memory = [];
    private readonly Dictionary<string, ulong> _points = [];
    /// <summary>What the session script was told to read for each watch.</summary>
    public readonly Dictionary<string, List<string>> WatchedKinds = [];

    public string Name => "scripted";
    public (string Reason, string Remediation)? Unavailable() => Missing == null ? null : (Missing, "install it");

    public WorkerConnection Start()
    {
        Worker = new FakeWorkerProcess(ready: true) { Ops = Handle };
        return Worker.Connect(null);
    }

    /// <summary>A thread hitting stop point <paramref name="id"/>, called from <paramref name="caller"/>.</summary>
    public void Hit(string id, long thread, ulong caller) => Worker!.Emit(new JsonObject
    {
        ["event"] = "stop", ["point"] = id, ["tid"] = thread, ["hits"] = 1,
        ["registers"] = new JsonObject { ["pc"] = $"0x{_points[id]:x}", ["rcx"] = "0x5000", ["rsp"] = "0x9000" },
        ["frames"] = new JsonArray($"0x{_points[id]:x}", $"0x{caller:x}", "0x7ffe00001234"),
    });

    /// <summary>A batch of recorded calls of watch <paramref name="id"/>: (thread, ms, return address, arguments, return value) rows.</summary>
    public void Calls(string id, IEnumerable<(long Thread, long Ms, ulong Caller, string?[] Args, string Ret)> rows, long skipped) => Worker!.Emit(new JsonObject
    {
        ["event"] = "calls", ["watch"] = id, ["skipped"] = skipped,
        ["rows"] = new JsonArray(rows.Select(r => (JsonNode)new JsonArray(r.Thread, r.Ms, $"0x{r.Caller:x}", new JsonArray(r.Args.Select(a => (JsonNode?)a).ToArray()), r.Ret)).ToArray()),
    });

    public void ScriptMessage(string id, JsonNode payload) => Worker!.Emit(new JsonObject { ["event"] = "user_script", ["script"] = id, ["payload"] = payload });

    private JsonNode? Handle(string op, JsonObject args)
    {
        lock (Ops) Ops.Add(op);
        switch (op)
        {
            case "hello": return new JsonObject { ["frida"] = "test" };
            case "open":
                return new JsonObject
                {
                    ["pid"] = Pid, ["arch"] = "x64", ["suspended"] = args["spawn"] != null,
                    ["modules"] = new JsonArray(
                        new JsonObject { ["name"] = Path.GetFileName(mainPath), ["base"] = $"0x{mainBase:x}", ["size"] = mainSize, ["path"] = mainPath },
                        new JsonObject { ["name"] = "system.dll", ["base"] = "0x7ffe00000000", ["size"] = 0x10000, ["path"] = "/nowhere/system.dll" }),
                };
            case "set":
                _points[(string)args["id"]!] = Convert.ToUInt64(((string)args["address"]!)[2..], 16);
                return true;
            case "clear": return _points.Remove((string)args["id"]!);
            case "watch":
                WatchedKinds[(string)args["id"]!] = args["args"]!.AsArray().Select(k => (string)k!).ToList();
                return true;
            case "unwatch": return WatchedKinds.Remove((string)args["id"]!);
            case "load_script": return new JsonObject { ["loaded"] = (string)args["id"]! };
            case "unload_script": return new JsonObject { ["unloaded"] = true };
            case "resume": return new JsonObject { ["resumed"] = new JsonArray(), ["started"] = true };
            case "read":
                var at = Convert.ToUInt64(((string)args["address"]!)[2..], 16);
                return new JsonObject { ["bytes"] = Memory.TryGetValue(at, out var b) ? Convert.ToHexStringLower(b.AsSpan(0, Math.Min(b.Length, (int)args["length"]!))) : null };
            default: return null;
        }
    }
}

/// <summary>Sessions through the broker on a scripted backend: the join to the loaded image, stops, reads, events, close.</summary>
public sealed class LiveSessionTests : IDisposable
{
    private const ulong Base = 0x7ff6_1000_0000;
    private static readonly string Sqlite = RealPackages.File("SQLitePCLRaw.lib.e_sqlite3", "2.1.11", "runtimes", "win-x64", "native", "e_sqlite3.dll");
    private readonly AssemblyWorkspace _workspace = new();
    private readonly LiveSessionService _service;
    private readonly ScriptedLiveBackend _backend;
    private readonly LiveSessionTools _tools;

    public LiveSessionTests()
    {
        _backend = new ScriptedLiveBackend(Sqlite, Base, 0x200000);
        _service = new LiveSessionService(_workspace, new NativeCodeService(_workspace, new ServerOptions())) { Backend = _backend };
        _tools = new LiveSessionTools(new ServerOptions { AllowLive = true, AllowLiveSpawn = true }, _service);
    }

    public void Dispose()
    {
        _service.Dispose();
        _workspace.Dispose();
    }

    [Fact]
    public async Task A_stop_names_its_frames_through_the_loaded_image_and_reads_typed_memory()
    {
        var opened = await _tools.LiveSession("spawn", program: Sqlite);
        Assert.Contains("live-1 (scripted)", opened);
        Assert.Contains("suspended", opened);
        Assert.Contains("2 modules, 1 matched to loaded images", opened);

        var set = await _tools.LiveBreak("live-1", "set", at: "e_sqlite3!sqlite3_open");
        var image = _workspace.Natives.Single();
        var rva = new NativeCodeService(_workspace, new ServerOptions()).IndexOfOriginal(image, default).AddressOfName("sqlite3_open")!.Value;
        Assert.Contains($"s1 set at 0x{Base + rva:X} e_sqlite3.dll!sqlite3_open", set);

        Assert.Contains("program started", await _tools.LiveBreak("live-1", "continue"));
        _backend.Hit("s1", 77, Base + rva + 0x4);
        var stop = await _tools.LiveBreak("live-1", wait: true, waitSeconds: 10);
        Assert.True(stop.Contains("thread 77 stopped at s1 (e_sqlite3.dll!sqlite3_open)"), stop);
        Assert.True(stop.Contains($"#1 0x{Base + rva + 0x4:X} e_sqlite3.dll!sqlite3_open+0x4"), stop);
        Assert.Contains("#2 0x7FFE00001234 system.dll+0x1234", stop);
        Assert.Contains("live-1: stopped, 1 stop point(s)", stop);

        _backend.Memory[0x5000] = [1, 0, 0, 0, 0xFF, 0xFF, 0xFF, 0xFF];
        var read = await _tools.LiveRead("live-1", registers: "pc,rcx", memory: "rcx", type: "int32[2]");
        Assert.Contains($"pc   0x{Base + rva:x}  e_sqlite3.dll!sqlite3_open", read);
        Assert.Contains("[0] 1", read);
        Assert.Contains("[1] -1", read);
        var bad = await Assert.ThrowsAsync<ToolError>(() => _tools.LiveRead("live-1", memory: "0x6000"));
        Assert.Equal(ErrorCode.NotFound, bad.Code);

        var cleared = await _tools.LiveBreak("live-1", "clear", stopPoint: "s1");
        Assert.Contains("s1 cleared", cleared);
        Assert.Contains("0 stop point(s)", cleared);
        var closed = await _tools.LiveSession("close", session: "live-1");
        Assert.Contains("closed", closed);
        Assert.Contains("close", _backend.Ops);
    }

    [Fact]
    public async Task Events_page_with_a_cursor_and_never_resend()
    {
        await _tools.LiveSession("attach", program: "4242");
        await _tools.LiveBreak("live-1", "set", at: $"0x{Base + 0x1000:X}");
        for (int i = 0; i < 5; i++) _backend.Hit("s1", 100 + i, Base + 0x1010);
        await Task.Delay(200);
        var first = await _tools.LiveEvents("live-1", kind: "stop", limit: 3);
        Assert.Contains("thread 100", first);
        Assert.Contains("thread 102", first);
        Assert.DoesNotContain("thread 103", first);
        var cursor = System.Text.RegularExpressions.Regex.Match(first, @"cursor=(\d+)").Groups[1].Value;
        var second = await _tools.LiveEvents("live-1", cursor: cursor, kind: "stop");
        Assert.DoesNotContain("thread 102", second);
        Assert.Contains("thread 104", second);
        Assert.Contains("end of the ring", second);
        Assert.Contains("thread 103", await _tools.LiveEvents("live-1", thread: "103"));
    }

    [Fact]
    public async Task An_image_address_is_moved_to_where_the_module_is_loaded_and_waits_end_without_a_stop()
    {
        await _tools.LiveSession("attach", program: "app");
        var image = _workspace.Natives.Single().Image;
        var set = await _tools.LiveBreak("live-1", "set", at: $"0x{image.ImageBase + 0x1000:X}");
        Assert.Contains($"set at 0x{Base + 0x1000:X}", set);
        var none = await _tools.LiveBreak("live-1", wait: true, waitSeconds: 1);
        Assert.Contains("no stop within 1 s; the session is running", none);
        Assert.Equal(ErrorCode.NotFound, (await Assert.ThrowsAsync<ToolError>(() => _tools.LiveBreak("live-1", "set", at: "0x1234"))).Code);
    }

    [Fact]
    public async Task A_worker_that_dies_fails_its_session_and_the_events_stay_readable()
    {
        await _tools.LiveSession("attach", program: "app");
        _backend.Worker!.Kill();
        for (int i = 0; i < 50 && _service.Get("live-1").State != "failed"; i++) await Task.Delay(50);
        Assert.Equal("failed", _service.Get("live-1").State);
        Assert.Contains("exit", await _tools.LiveEvents("live-1", kind: "exit"));
        Assert.Equal(ErrorCode.Unsupported, (await Assert.ThrowsAsync<ToolError>(() => _tools.LiveRead("live-1", memory: "0x10"))).Code);
    }

    [Fact]
    public async Task Watched_calls_go_into_the_ring_decoded_with_their_callers_named_and_counted()
    {
        await _tools.LiveSession("attach", program: "4242");
        var set = await _tools.LiveWatchCalls("live-1", "set", at: "e_sqlite3!sqlite3_open", arguments: 2);
        Assert.Contains("w1 set at 0x", set);
        Assert.Contains("e_sqlite3.dll!sqlite3_open: sqlite3_open(a0, a1) (raw values); at most 10,000 calls/s recorded", set);
        Assert.Equal(["hex", "hex"], _backend.WatchedKinds["w1"]);
        var rva = new NativeCodeService(_workspace, new ServerOptions()).IndexOfOriginal(_workspace.Natives.Single(), default).AddressOfName("sqlite3_open")!.Value;
        _backend.Calls("w1", Enumerable.Range(0, 3).Select(i => (5L, 1000L + i * 10, Base + rva + 0x4, new string?[] { $"0x{0x100 + i:x}", "0x0" }, "0x0")), skipped: 7);
        for (int i = 0; i < 50 && !(await _tools.LiveWatchCalls("live-1")).Contains("3 call(s)"); i++) await Task.Delay(20);
        var list = await _tools.LiveWatchCalls("live-1");
        Assert.Contains("w1 e_sqlite3.dll!sqlite3_open: 3 call(s) recorded (100/s), 7 over the rate limit", list);
        var events = await _tools.LiveEvents("live-1", from: "w1");
        Assert.Contains("call thread 5 0x", events);
        Assert.True(events.Contains("e_sqlite3.dll!sqlite3_open+0x4: sqlite3_open(a0=0x100, a1=0x0) -> 0x0"), events);
        Assert.Contains("sqlite3_open(a0=0x102, a1=0x0)", events);
        Assert.Contains("w1 cleared", await _tools.LiveWatchCalls("live-1", "clear", watch: "w1"));
        Assert.Equal(ErrorCode.NotFound, (await Assert.ThrowsAsync<ToolError>(() => _tools.LiveWatchCalls("live-1", "clear", watch: "w1"))).Code);
    }

    [Fact]
    public async Task A_user_script_loads_only_with_live_scripting_and_its_messages_are_events()
    {
        await _tools.LiveSession("attach", program: "4242");
        var off = await Assert.ThrowsAsync<ToolError>(() => _tools.LiveScriptCalls("live-1", "load", source: "send(1);"));
        Assert.Contains(ServerOptions.LiveScriptingOption, off.Remediation);
        var tools = new LiveSessionTools(new ServerOptions { AllowLive = true, LiveScripting = true }, _service);
        var loaded = await tools.LiveScriptCalls("live-1", "load", source: "send({ hello: Process.id });");
        Assert.Contains("u1 loaded (inline)", loaded);
        _backend.ScriptMessage("u1", new JsonObject { ["hello"] = 4242 });
        for (int i = 0; i < 50 && !(await tools.LiveEvents("live-1", kind: "script")).Contains("hello"); i++) await Task.Delay(20);
        Assert.Contains("script: u1: {\"hello\":4242}", await tools.LiveEvents("live-1", kind: "script"));
        Assert.Contains("u1 unloaded", await tools.LiveScriptCalls("live-1", "unload", script: "u1"));
        Assert.Contains("0 script(s)", await tools.LiveScriptCalls("live-1"));
    }

    [Fact]
    public void A_known_api_is_decoded_with_names_strings_and_flags()
    {
        var plan = LiveWatchPlans.Build("kernel32!CreateFileW", null, 0, x64: true, Corvus.Native.Calls.ApiOs.Windows, 4);
        Assert.Equal("known API table", plan.Source);
        Assert.Equal(["wstr", "hex", "hex", "hex", "hex", "hex", "hex"], plan.ScriptKinds);
        var text = LiveWatchPlans.Describe(plan, ["C:\\data\\a.txt", "0x80000000", "0x1", "0x0", "0x3", "0x80", "0x0"], "0xffffffffffffffff");
        Assert.Equal("CreateFileW(lpFileName=\"C:\\\\data\\\\a.txt\", dwDesiredAccess=GENERIC_READ, dwShareMode=FILE_SHARE_READ, lpSecurityAttributes=0x0, " +
                     "dwCreationDisposition=OPEN_EXISTING, dwFlagsAndAttributes=FILE_ATTRIBUTE_NORMAL, hTemplateFile=0x0) -> 0xFFFFFFFFFFFFFFFF", text);
        var raw = LiveWatchPlans.Build("sub_1000", null, 0x1000, x64: true, Corvus.Native.Calls.ApiOs.Windows, 2);
        Assert.Equal("raw values", raw.Source);
        Assert.Equal("f(a0=0x10, a1=?) -> 0x1", LiveWatchPlans.Describe(raw with { Function = "f" }, ["0x10"], "0x1"));
    }

    [Fact]
    public async Task Processes_lists_local_programs_by_a_name_filter()
    {
        var self = System.Diagnostics.Process.GetCurrentProcess();
        var rows = await _tools.LiveSession("processes", program: self.ProcessName);
        Assert.Contains($"{self.Id,7} {self.ProcessName}", rows);
        Assert.Equal("No process matches.\n", await _tools.LiveSession("processes", program: "no-such-program-" + Guid.NewGuid().ToString("N")));
    }

    [Fact]
    public async Task A_missing_backend_names_its_next_step()
    {
        var service = new LiveSessionService(_workspace, new NativeCodeService(_workspace, new ServerOptions())) { Backend = new ScriptedLiveBackend(Sqlite, Base, 1) { Missing = "no frida" } };
        var tools = new LiveSessionTools(new ServerOptions { AllowLive = true }, service);
        var e = await Assert.ThrowsAsync<ToolError>(() => tools.LiveSession("attach", program: "app"));
        Assert.Equal(ErrorCode.ProviderUnavailable, e.Code);
        Assert.Equal("install it", e.Remediation);
    }
}
