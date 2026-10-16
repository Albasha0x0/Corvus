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
