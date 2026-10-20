using System.Text.RegularExpressions;
using System.Diagnostics;
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
    /// <summary>The arguments of the last open request (what the backend was asked to start or attach to).</summary>
    public JsonObject? LastOpen { get; private set; }
    /// <summary>The process id the session reports (a real child for snapshot tests).</summary>
    public int ProcessId { get; init; } = Pid;
    /// <summary>Bytes the program holds, by address.</summary>
    public readonly Dictionary<ulong, byte[]> Memory = [];
    private readonly Dictionary<string, ulong> _points = [];
    /// <summary>Addresses the backend cannot hook, as Frida refuses a function too short for its jump.</summary>
    public readonly HashSet<ulong> Unhookable = [];
    /// <summary>What the session script was told to read for each watch.</summary>
    public readonly Dictionary<string, List<string>> WatchedKinds = [];
    /// <summary>Lists the program's module after the system one, as Frida may order them.</summary>
    public bool MainListedLast { get; init; }
    /// <summary>Runs before the reply to a resume, as when a resumed thread stops again before the worker answers.</summary>
    public Action? BeforeResumeReply { get; set; }

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

    /// <summary>A thread hitting stop point <paramref name="id"/> with the given stack values, as the worker reports them.</summary>
    public void HitWith(string id, long thread, params ulong[] frames) => Worker!.Emit(new JsonObject
    {
        ["event"] = "stop", ["point"] = id, ["tid"] = thread, ["hits"] = 1,
        ["registers"] = new JsonObject { ["pc"] = $"0x{_points[id]:x}" },
        ["frames"] = new JsonArray([.. new[] { _points[id] }.Concat(frames).Select(f => (JsonNode)$"0x{f:x}")]),
    });

    /// <summary>A thread hitting stop point <paramref name="id"/> with the stack bytes at <paramref name="sp"/> and the frames the backend's own walk gave.</summary>
    public void HitWithStack(string id, long thread, ulong sp, byte[] stack, params ulong[] frames) => Worker!.Emit(new JsonObject
    {
        ["event"] = "stop", ["point"] = id, ["tid"] = thread, ["hits"] = 1,
        ["registers"] = new JsonObject { ["pc"] = $"0x{_points[id]:x}", ["sp"] = $"0x{sp:x}", ["rsp"] = $"0x{sp:x}", ["rbp"] = "0x0" },
        ["frames"] = new JsonArray([.. new[] { _points[id] }.Concat(frames).Select(f => (JsonNode)$"0x{f:x}")]),
        ["stack"] = Convert.ToHexStringLower(stack),
    });

    /// <summary>The program loading <paramref name="name"/> from <paramref name="path"/> at <paramref name="at"/>; <paramref name="heldBy"/>: the loading thread the worker holds.</summary>
    public void Load(string name, string path, ulong at, uint size, long? heldBy = null) => Worker!.Emit(new JsonObject
    {
        ["event"] = "module", ["action"] = "loaded", ["held"] = heldBy != null, ["tid"] = heldBy,
        ["module"] = new JsonObject { ["name"] = name, ["base"] = $"0x{at:x}", ["size"] = size, ["path"] = path },
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
                LastOpen = (JsonObject)args.DeepClone();
                JsonNode program = new JsonObject { ["name"] = Path.GetFileName(mainPath), ["base"] = $"0x{mainBase:x}", ["size"] = mainSize, ["path"] = mainPath };
                JsonNode system = new JsonObject { ["name"] = "system.dll", ["base"] = "0x7ffe00000000", ["size"] = 0x10000, ["path"] = "/nowhere/system.dll" };
                return new JsonObject
                {
                    ["pid"] = ProcessId, ["arch"] = "x64", ["suspended"] = args["spawn"] != null,
                    ["modules"] = MainListedLast ? new JsonArray(system, program) : new JsonArray(program, system),
                };
            case "set" or "watch" when Unhookable.Contains(Convert.ToUInt64(((string)args["address"]!)[2..], 16)):
                throw new InvalidOperationException($"Error: unable to intercept function at {args["address"]}; please file a bug");
            case "set":
                _points[(string)args["id"]!] = Convert.ToUInt64(((string)args["address"]!)[2..], 16);
                return true;
            case "clear": return _points.Remove((string)args["id"]!);
            case "watch":
                WatchedKinds[(string)args["id"]!] = args["args"]!.AsArray().Select(k => (string)k!).ToList();
                return true;
            case "unwatch": return WatchedKinds.Remove((string)args["id"]!);
            case "defer_module" or "undefer_module": return true;
            case "release_load": return new JsonObject { ["released"] = true };
            case "load_script":
                if (((string)args["source"]!).StartsWith("throw", StringComparison.Ordinal)) // the worker posts a top-level exception after its reply
                    _ = Task.Delay(20).ContinueWith(_ => Worker!.Emit(new JsonObject { ["event"] = "user_script", ["script"] = (string)args["id"]!, ["error"] = "Error: on purpose" }), TaskScheduler.Default);
                return new JsonObject { ["loaded"] = (string)args["id"]! };
            case "unload_script": return new JsonObject { ["unloaded"] = true };
            case "resume":
                BeforeResumeReply?.Invoke();
                return new JsonObject { ["resumed"] = args["thread"] is { } t ? new JsonArray((long)t) : new JsonArray(), ["started"] = true };
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
        _tools = new LiveSessionTools(new ServerOptions { AllowLive = true, AllowLiveAttach = true, AllowLiveSpawn = true }, _service);
    }

    public void Dispose()
    {
        _service.Dispose();
        _workspace.Dispose();
    }

    [Fact]
    public async Task The_programs_own_module_is_found_wherever_the_backend_lists_it()
    {
        var service = new LiveSessionService(_workspace, new NativeCodeService(_workspace, new ServerOptions())) { Backend = new ScriptedLiveBackend(Sqlite, Base, 0x200000) { MainListedLast = true } };
        var tools = new LiveSessionTools(new ServerOptions { AllowLiveSpawn = true }, service);
        await tools.LiveSession("spawn", program: Sqlite);
        Assert.Contains("e_sqlite3.dll!sqlite3_open", await tools.LiveBreak("live-1", "set", at: "sqlite3_open"));
        Assert.Matches(@"matched to loaded images:\s+0x7FF610000000 e_sqlite3\.dll", await tools.LiveSession("status", session: "live-1"));
        service.Dispose();
    }

    [Fact]
    public async Task A_thread_that_stops_again_before_the_resume_reply_keeps_its_new_stop()
    {
        await _tools.LiveSession("spawn", program: Sqlite);
        await _tools.LiveBreak("live-1", "set", at: "e_sqlite3!sqlite3_open");
        await _tools.LiveBreak("live-1", "continue");
        _backend.Hit("s1", 77, Base + 0x1010);
        Assert.Contains("thread 77 stopped at s1", await _tools.LiveBreak("live-1", wait: true, waitSeconds: 10));

        _backend.BeforeResumeReply = () => _backend.Hit("s1", 77, Base + 0x1020);
        await _tools.LiveBreak("live-1", "continue", thread: "77");
        var again = await _tools.LiveBreak("live-1", wait: true, waitSeconds: 5);
        Assert.True(again.Contains("thread 77 stopped at s1"), again);
        Assert.Contains("live-1: stopped", again);
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
        Assert.Contains("no readable memory", bad.Message);
        var hex = await _tools.LiveRead("live-1", memory: "0x5000", type: "int32"); // stack or heap: outside every module
        Assert.Contains("  1", hex);
        Assert.DoesNotContain("pc ", hex); // registers only when asked
        Assert.Contains("rcx", await _tools.LiveRead("live-1", registers: "all"));
        _backend.Memory[0x8000] = Enumerable.Range(0, 600).Select(i => (byte)i).ToArray();
        var rows = await _tools.LiveRead("live-1", memory: "0x8000", length: 600); // untyped bytes in 256-byte rows, the last one partial
        Assert.Contains("  +0x100 " + Convert.ToHexStringLower(Enumerable.Range(256, 256).Select(i => (byte)i).ToArray()), rows);
        Assert.Contains("  +0x200 " + Convert.ToHexStringLower(Enumerable.Range(512, 88).Select(i => (byte)i).ToArray()) + "\n", rows.ReplaceLineEndings("\n"));

        var cleared = await _tools.LiveBreak("live-1", "clear", stopPoint: "s1");
        Assert.Contains("s1 cleared", cleared);
        Assert.Contains("0 stop point(s)", cleared);
        var closed = await _tools.LiveSession("close", session: "live-1");
        Assert.Contains("closed", closed);
        Assert.Contains("close", _backend.Ops);
    }

    [Fact]
    public async Task A_point_in_a_module_not_yet_loaded_is_deferred_until_its_load_event()
    {
        await _tools.LiveSession("attach", program: "4242");
        var deferred = await _tools.LiveBreak("live-1", "set", at: "plugin!sqlite3_open");
        Assert.Contains("s1 deferred: plugin is not loaded; it is set when plugin loads, before the module's code runs", deferred);
        Assert.Contains("s1 plugin!sqlite3_open: deferred until plugin loads", deferred);
        Assert.Contains("w1 deferred", await _tools.LiveWatchCalls("live-1", "set", at: "plugin!sqlite3_close"));
        Assert.DoesNotContain("set", _backend.Ops);

        const ulong PluginBase = 0x7ff7_0000_0000;
        _backend.Load("plugin.dll", Sqlite, PluginBase, 0x200000, heldBy: 77);
        for (int i = 0; i < 100 && !_backend.Ops.Contains("release_load"); i++) await Task.Delay(50);
        // the loading thread goes on only once both are set
        List<string> ops;
        lock (_backend.Ops) ops = [.. _backend.Ops];
        Assert.True(ops.IndexOf("release_load") > ops.IndexOf("set") && ops.IndexOf("release_load") > ops.IndexOf("watch"), string.Join(",", ops));
        Assert.Contains("undefer_module", ops);
        var listed = await _tools.LiveBreak("live-1");
        Assert.Contains("s1 plugin!sqlite3_open at 0x7FF7", listed);
        Assert.DoesNotContain("deferred", listed);
        Assert.Contains("deferred stop point s1 set at plugin.dll!sqlite3_open", await _tools.LiveEvents("live-1", kind: "module"));
        Assert.Contains("w1", _backend.WatchedKinds.Keys);
        Assert.Contains("s2 deferred", await _tools.LiveBreak("live-1", "set", at: "other!f"));
        Assert.Contains("s2 cleared", await _tools.LiveBreak("live-1", "clear", stopPoint: "s2"));
    }

    [Fact]
    public async Task Name_plus_offset_resolves_and_a_point_inside_an_instruction_is_refused()
    {
        await _tools.LiveSession("attach", program: "4242");
        var index = new NativeCodeService(_workspace, new ServerOptions()).IndexOfOriginal(_workspace.Natives.Single(), default);
        var rva = index.AddressOfName("sqlite3_open")!.Value;
        var second = index.Disassemble(rva, 2)[1].Rva - rva;
        Assert.Contains($"set at 0x{Base + rva + second:X} e_sqlite3.dll!sqlite3_open+0x{second:X}",
            await _tools.LiveBreak("live-1", "set", at: $"sqlite3_open+0x{second:X}"));
        if (second > 1)
        {
            var inside = await Assert.ThrowsAsync<ToolError>(() => _tools.LiveBreak("live-1", "set", at: "e_sqlite3!sqlite3_open+0x1"));
            Assert.Contains("inside an instruction", inside.Message);
            Assert.Contains($"e_sqlite3.dll!sqlite3_open+0x{second:X}", inside.Remediation);
        }
        Assert.Equal(ErrorCode.InvalidArgument, (await Assert.ThrowsAsync<ToolError>(() => _tools.LiveBreak("live-1", "set", at: "sqlite3_open+0x7FFFFFFF"))).Code);
    }

    [Fact]
    public async Task Stack_values_that_cannot_be_code_are_left_out_and_unloaded_modules_name_by_export()
    {
        await _tools.LiveSession("attach", program: "4242");
        await _tools.LiveBreak("live-1", "set", at: "e_sqlite3!sqlite3_open");
        var old = RealPackages.File("SQLitePCLRaw.lib.e_sqlite3", "2.1.2", "runtimes", "win-x64", "native", "e_sqlite3.dll");
        const ulong LibBase = 0x7ff8_0000_0000;
        _backend.Load("old.dll", old, LibBase, 0x200000);
        var exportRva = Native.NativeImageLoader.Open(old).Exports.Single(e => e.Name == "sqlite3_close").Rva;
        await Task.Delay(100);
        var entry = Base + new NativeCodeService(_workspace, new ServerOptions()).IndexOfOriginal(_workspace.Natives.Single(), default).AddressOfName("sqlite3_open")!.Value;
        _backend.HitWith("s1", 9, 0x3e8, ulong.MaxValue, Base + 0x10, LibBase + exportRva + 2, entry, LibBase + exportRva + 2);
        var stop = await _tools.LiveBreak("live-1", wait: true, waitSeconds: 10);
        Assert.Single(Regex.Matches(stop, $@"#\d+ 0x{entry:X} "));
        Assert.Single(Regex.Matches(stop, $@"#\d+ 0x{LibBase + exportRva + 2:X} ")); // the return address beside the hook's copy
        Assert.DoesNotContain("0x3E8", stop);
        Assert.DoesNotContain("0xFFFFFFFFFFFFFFFF", stop);
        Assert.DoesNotContain($"0x{Base + 0x10:X}", stop);
        Assert.Contains($"#1 0x{LibBase + exportRva + 2:X} old.dll!sqlite3_close+0x2", stop);
    }

    [Fact]
    public async Task A_watch_and_a_stop_point_in_the_same_prologue_are_refused_in_either_order()
    {
        await _tools.LiveSession("attach", program: "4242");
        var index = new NativeCodeService(_workspace, new ServerOptions()).IndexOfOriginal(_workspace.Natives.Single(), default);
        var rva = index.AddressOfName("sqlite3_open")!.Value;
        var second = index.Disassemble(rva, 2)[1].Rva - rva;
        await _tools.LiveBreak("live-1", "set", at: $"sqlite3_open+0x{second:X}");
        var watch = await Assert.ThrowsAsync<ToolError>(() => _tools.LiveWatchCalls("live-1", "set", at: "sqlite3_open"));
        Assert.Equal(ErrorCode.Conflict, watch.Code);
        Assert.Contains($"{second} bytes into e_sqlite3.dll!sqlite3_open", watch.Message);
        await _tools.LiveBreak("live-1", "clear", stopPoint: "s1");
        Assert.Contains("w1 set", await _tools.LiveWatchCalls("live-1", "set", at: "sqlite3_open"));
        Assert.Equal(ErrorCode.Conflict, (await Assert.ThrowsAsync<ToolError>(() => _tools.LiveBreak("live-1", "set", at: $"sqlite3_open+0x{second:X}"))).Code);
        Assert.Contains("s2 set", await _tools.LiveBreak("live-1", "set", at: "sqlite3_open")); // the entry itself: the watch's own hook reports it
    }

    [Fact]
    public async Task Stop_points_whose_hook_jumps_overlap_are_refused_and_a_watch_is_set_only_at_a_function_start()
    {
        await _tools.LiveSession("attach", program: "4242");
        var index = new NativeCodeService(_workspace, new ServerOptions()).IndexOfOriginal(_workspace.Natives.Single(), default);
        var f = index.Functions.Where(f => f.Size >= 64 && index.NameAt(f.Start) is not null).OrderBy(f => f.Start).First();
        var name = index.NameAt(f.Start);
        var starts = index.Disassemble(f.Start, 12).Select(l => l.Rva - f.Start).ToList();
        var near = starts.First(o => o > 0);
        var far = starts.First(o => o >= LiveSessionService.WatchPatchBytes);
        await _tools.LiveBreak("live-1", "set", at: name);
        var overlap = await Assert.ThrowsAsync<ToolError>(() => _tools.LiveBreak("live-1", "set", at: $"{name}+0x{near:X}"));
        Assert.Equal(ErrorCode.Conflict, overlap.Code);
        Assert.Contains($"{near} bytes from s1", overlap.Message);
        Assert.Contains("s2 set", await _tools.LiveBreak("live-1", "set", at: $"{name}+0x{far:X}"));
        var inside = await Assert.ThrowsAsync<ToolError>(() => _tools.LiveWatchCalls("live-1", "set", at: $"{name}+0x{far:X}"));
        Assert.Equal(ErrorCode.InvalidArgument, inside.Code);
        Assert.Contains($"watch {name}", inside.Remediation);
    }

    [Fact]
    public async Task A_started_program_gets_the_runtime_location_and_the_callers_variables_but_not_the_servers_others()
    {
        var server = new System.Collections.Hashtable { ["DOTNET_ROOT"] = "/opt/dotnet", ["DOTNET_ROOT_X86"] = "/opt/x86", ["API_TOKEN"] = "kept-out" };
        var env = LiveSessionService.ProgramEnvironment(["APP_MODE=test", "EMPTY="], server);
        Assert.Equal(["APP_MODE", "DOTNET_ROOT", "DOTNET_ROOT_X86", "EMPTY"], env.Select(p => p.Key).Order());
        Assert.Equal(("/opt/dotnet", "test", ""), ((string?)env["DOTNET_ROOT"], (string?)env["APP_MODE"], (string?)env["EMPTY"]));
        await _tools.LiveSession("spawn", program: Sqlite, environment: ["APP_MODE=test"]);
        Assert.Equal("test", (string?)_backend.LastOpen!["environment"]!["APP_MODE"]);
        Assert.Equal(ErrorCode.InvalidArgument, (await Assert.ThrowsAsync<ToolError>(() => _tools.LiveSession("spawn", program: Sqlite, environment: ["NOEQUALS"]))).Code);
    }

    [Fact]
    public async Task Status_after_a_close_names_why_the_session_closed()
    {
        await _tools.LiveSession("spawn", program: Sqlite);
        var service = _service;
        await service.CloseAsync(service.Get("live-1"), "deadline");
        var status = await _tools.LiveSession("status", session: "live-1");
        Assert.Contains("closed (ended when the session closed (deadline))", status);
        Assert.DoesNotContain("exit code", status);
        Assert.Contains("session closed (deadline)", await _tools.LiveEvents("live-1", kind: "exit"));
    }

    [LiveTargetFact("win-x64")]
    [Trait("Speed", "Slow")]
    public async Task A_program_whose_exit_never_finishes_is_ended_with_its_exit_code()
    {
        // a TLS callback that never returns on process detach holds the exit, as a stuck DLL shutdown does
        const string Source = """
            #include <windows.h>
            static void NTAPI OnTls(PVOID h, DWORD reason, PVOID r) { if (reason == DLL_PROCESS_DETACH) for (;;) Sleep(10); }
            #pragma comment(linker, "/INCLUDE:_tls_used")
            #pragma comment(linker, "/INCLUDE:tls_callback")
            #pragma const_seg(".CRT$XLB")
            EXTERN_C const PIMAGE_TLS_CALLBACK tls_callback = OnTls;
            #pragma const_seg()
            int main(void) { Sleep(2000); return 7; }
            """;
        using var dir = new TempDir();
        using var program = Process.Start(LiveTarget.WinX64.Build(dir, "stuckexit", Source))!;
        var backend = new ScriptedLiveBackend(Sqlite, Base, 0x200000) { ProcessId = program.Id };
        using var service = new LiveSessionService(_workspace, new NativeCodeService(_workspace, new ServerOptions())) { Backend = backend };
        var tools = new LiveSessionTools(new ServerOptions { AllowLive = true, AllowLiveAttach = true }, service);
        var stuck = LiveSessionService.StuckExit;
        LiveSessionService.StuckExit = TimeSpan.FromSeconds(1);
        try
        {
            await tools.LiveSession("attach", program: $"{program.Id}");
            Assert.True(program.WaitForExit(30_000), "the program's exit was not finished");
            Assert.Equal(7, program.ExitCode);
            Assert.Contains("called ExitProcess(7) but its exit did not finish", await tools.LiveEvents("live-1", kind: "error"));
        }
        finally
        {
            LiveSessionService.StuckExit = stuck;
            if (!program.HasExited) program.Kill();
        }
    }

    [Fact]
    public async Task A_function_too_short_to_hook_is_refused_with_its_size()
    {
        await _tools.LiveSession("attach", program: "4242");
        var index = new NativeCodeService(_workspace, new ServerOptions()).IndexOfOriginal(_workspace.Natives.Single(), default);
        var shortest = index.Functions.Where(f => f.Size is > 0 and < 16).OrderBy(f => f.Start).First();
        _backend.Unhookable.Add(Base + shortest.Start);
        var refused = await Assert.ThrowsAsync<ToolError>(() => _tools.LiveBreak("live-1", "set", at: $"0x{Base + shortest.Start:X}"));
        Assert.Equal(ErrorCode.Unsupported, refused.Code);
        Assert.Contains($"the function is {shortest.Size} bytes long, too short", refused.Message);
        Assert.Contains("find_xrefs", refused.Remediation);
        Assert.Equal(ErrorCode.Unsupported, (await Assert.ThrowsAsync<ToolError>(() => _tools.LiveWatchCalls("live-1", "set", at: $"0x{Base + shortest.Start:X}"))).Code);
    }

    [Fact]
    public async Task The_exit_event_carries_the_exit_code_the_system_reports()
    {
        if (!OperatingSystem.IsWindows()) return;
        using var child = System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo(Path.Combine(Environment.SystemDirectory, "findstr.exe"), "x")
            { RedirectStandardInput = true, UseShellExecute = false, CreateNoWindow = true })!;
        var backend = new ScriptedLiveBackend(Sqlite, Base, 0x200000) { ProcessId = child.Id };
        using var service = new LiveSessionService(_workspace, new NativeCodeService(_workspace, new ServerOptions())) { Backend = backend };
        var tools = new LiveSessionTools(new ServerOptions { AllowLive = true, AllowLiveAttach = true }, service);
        await tools.LiveSession("attach", program: child.Id.ToString());
        child.StandardInput.Close(); // findstr exits 1: no line matched
        await child.WaitForExitAsync();
        backend.Worker!.Emit(new JsonObject { ["event"] = "exit", ["reason"] = "process-terminated" });
        for (int i = 0; i < 100 && service.Get("live-1").State != "exited"; i++) await Task.Delay(50);
        Assert.Contains("exited: process-terminated, exit code 1", await tools.LiveEvents("live-1", kind: "exit"));
    }

    [Fact]
    public async Task A_stop_with_its_stack_is_unwound_by_the_modules_cfi()
    {
        var lib = NativeFormats.NativeFixtures.NativeAotLib("linux-x64", "libSystem.Native.so");
        const ulong ElfBase = 0x7f00_0000_0000, Sp = 0x7ffc_0000_1000;
        var backend = new ScriptedLiveBackend(lib, ElfBase, Corvus.Native.NativeImageLoader.Open(lib).SizeOfImage);
        using var service = new LiveSessionService(_workspace, new NativeCodeService(_workspace, new ServerOptions())) { Backend = backend };
        var tools = new LiveSessionTools(new ServerOptions { AllowLive = true, AllowLiveAttach = true }, service);
        await tools.LiveSession("attach", program: "4242");
        await tools.LiveBreak("live-1", "set", at: "SystemNative_FStat");
        var index = new NativeCodeService(_workspace, new ServerOptions()).IndexOfOriginal(_workspace.Natives.Single(), default);
        ulong caller = ElfBase + index.AddressOfName("SystemNative_StrErrorR")!.Value + 0x10;
        // at the function's start the return address is at the stack pointer; the backend's walk put the word there twice
        backend.HitWithStack("s1", 77, Sp, [.. BitConverter.GetBytes(caller), .. new byte[8]], caller, caller);
        var stop = await tools.LiveBreak("live-1", wait: true, waitSeconds: 10);
        Assert.Contains($"#1 0x{caller:X} libSystem.Native.so!SystemNative_StrErrorR+0x10", stop);
        Assert.DoesNotContain("#2 ", stop);
    }

    [Fact]
    public async Task The_exit_status_event_gives_the_exit_code_where_no_process_handle_does()
    {
        await _tools.LiveSession("attach", program: "4242");
        _backend.Worker!.Emit(new JsonObject { ["event"] = "exit_status", ["tid"] = 77, ["code"] = 259 });
        _backend.Worker!.Emit(new JsonObject { ["event"] = "exit", ["reason"] = "process-terminated" });
        for (int i = 0; i < 100 && _service.Get("live-1").State != "exited"; i++) await Task.Delay(50);
        Assert.Contains("exited: process-terminated, exit code 3", await _tools.LiveEvents("live-1", kind: "exit"));
    }

    [Fact]
    public async Task A_crash_whose_exception_event_was_lost_is_recorded_from_the_exit_code()
    {
        if (!OperatingSystem.IsWindows()) return;
        using var child = System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo(Path.Combine(Environment.SystemDirectory, "cmd.exe"),
            "/c findstr x & exit /b -1073741819") { RedirectStandardInput = true, UseShellExecute = false, CreateNoWindow = true })!;
        var backend = new ScriptedLiveBackend(Sqlite, Base, 0x200000) { ProcessId = child.Id };
        using var service = new LiveSessionService(_workspace, new NativeCodeService(_workspace, new ServerOptions())) { Backend = backend };
        var tools = new LiveSessionTools(new ServerOptions { AllowLive = true, AllowLiveAttach = true }, service);
        await tools.LiveSession("attach", program: child.Id.ToString());
        child.StandardInput.Close();
        await child.WaitForExitAsync();
        backend.Worker!.Emit(new JsonObject { ["event"] = "exit", ["reason"] = "process-terminated" });
        for (int i = 0; i < 100 && service.Get("live-1").State != "exited"; i++) await Task.Delay(50);
        var events = await tools.LiveEvents("live-1", kind: "exception");
        Assert.Contains("EXCEPTION_ACCESS_VIOLATION (0xC0000005), from the exit code", events);
        Assert.Contains("exit code 0xC0000005", await tools.LiveEvents("live-1", kind: "exit"));
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
        var tools = new LiveSessionTools(new ServerOptions { AllowLive = true, AllowLiveAttach = true, LiveScripting = true }, _service);
        var loaded = await tools.LiveScriptCalls("live-1", "load", source: "send({ hello: Process.id });");
        Assert.Contains("u1 loaded (inline)", loaded);
        _backend.ScriptMessage("u1", new JsonObject { ["hello"] = 4242 });
        for (int i = 0; i < 50 && !(await tools.LiveEvents("live-1", kind: "script")).Contains("hello"); i++) await Task.Delay(20);
        Assert.Contains("script: u1: {\"hello\":4242}", await tools.LiveEvents("live-1", kind: "script"));
        Assert.Contains("u1 unloaded", await tools.LiveScriptCalls("live-1", "unload", script: "u1"));
        Assert.Contains("0 script(s)", await tools.LiveScriptCalls("live-1"));
        Assert.Contains("u2 reported error: Error: on purpose", await tools.LiveScriptCalls("live-1", "load", source: "throw new Error('on purpose');"));
    }

    [Fact]
    public async Task Event_pages_cut_to_the_output_budget_skip_no_event()
    {
        await _tools.LiveSession("attach", program: "4242");
        for (int i = 1; i <= 2000; i++) _backend.ScriptMessage("u1", new JsonObject { ["n"] = i, ["pad"] = new string('x', 60) });
        for (int i = 0; i < 100 && !(await _tools.LiveEvents("live-1", kind: "script", limit: 1000, cursor: "1990")).Contains("\"n\":2000"); i++) await Task.Delay(20);
        using var pipeline = new OutputPipeline();
        var seen = await pipeline.PageAll("live_events", 600, (cursor, ct) => _tools.LiveEvents("live-1", cursor: cursor, kind: "script", limit: 1000, cancellationToken: ct),
            "\"n\":(\\d+)");
        Assert.Equal(Enumerable.Range(1, 2000), seen);
    }

    /// <summary>Two sessions in one process would place their hooks independently: a second attach names the first.</summary>
    [Fact]
    public async Task A_process_already_in_a_session_is_not_attached_again()
    {
        await _tools.LiveSession("attach", program: "4242");
        var e = await Assert.ThrowsAsync<ToolError>(() => _tools.LiveSession("attach", program: "4242"));
        Assert.Equal((ErrorCode.Conflict, "Process 4242 is already in session live-1."), (e.Code, e.Message));
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
    public async Task A_function_with_dwarf_is_decoded_by_its_prototype()
    {
        var lib = NativeFormats.NativeFixtures.NativeAotLib("linux-x64", "libSystem.Native.so");
        var native = _workspace.LoadAny(lib).Native!;
        var code = new NativeCodeService(_workspace, new ServerOptions());
        await new PdbService(code).Load(native, lib + ".dbg", false, null, false, TimeSpan.FromSeconds(30), 1 << 30, default);
        var index = await code.Index(native, null, default);
        var fstat = index.AddressOfName("SystemNative_FStat")!.Value;
        var plan = LiveWatchPlans.Build("SystemNative_FStat", native, fstat, x64: true, Corvus.Native.Calls.ApiOs.Linux, 4);
        Assert.Equal("DWARF prototype", plan.Source);
        Assert.Equal("SystemNative_FStat(fd=-1, output=0x7FFC0000) -> 0", LiveWatchPlans.Describe(plan, ["0xffffffffffffffff", "0x7ffc0000"], "0x0"));
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
    public async Task A_snapshot_writes_the_process_as_a_dump_the_dump_tools_open()
    {
        if (!OperatingSystem.IsWindows()) return;
        using var child = System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo(Path.Combine(Environment.SystemDirectory, "findstr.exe"), "x")
            { RedirectStandardInput = true, UseShellExecute = false, CreateNoWindow = true })!;
        var dumps = new MinidumpService();
        var service = new LiveSessionService(_workspace, new NativeCodeService(_workspace, new ServerOptions())) { Backend = new ScriptedLiveBackend(Sqlite, Base, 0x200000) { ProcessId = child.Id } };
        var tools = new LiveSessionTools(new ServerOptions { AllowLive = true, AllowLiveAttach = true }, service, dumps);
        var dir = Path.Combine(Path.GetTempPath(), "corvus-test-" + Guid.NewGuid().ToString("N"));
        try
        {
            await tools.LiveSession("attach", program: child.Id.ToString());
            var path = Path.Combine(dir, "findstr.dmp");
            var snap = await tools.LiveSession("snapshot", session: "live-1", outputPath: path);
            Assert.Contains($"process {child.Id} written to {path}", snap);
            Assert.Contains("the program keeps running", snap);
            var id = System.Text.RegularExpressions.Regex.Match(snap, @"opened as (\S+);").Groups[1].Value;
            Assert.Contains("findstr.exe", await new MinidumpTools(dumps).OpenMinidump(id, "modules", limit: 200));
            Assert.False(child.HasExited);
            Assert.Equal(ErrorCode.Conflict, (await Assert.ThrowsAsync<ToolError>(() => tools.LiveSession("snapshot", session: "live-1", outputPath: path))).Code);
        }
        finally
        {
            service.Dispose();
            child.Kill();
            dumps.Dispose();
            if (Directory.Exists(dir)) Directory.Delete(dir, true);
        }
    }

    [Fact]
    public async Task A_missing_backend_names_its_next_step()
    {
        var service = new LiveSessionService(_workspace, new NativeCodeService(_workspace, new ServerOptions())) { Backend = new ScriptedLiveBackend(Sqlite, Base, 1) { Missing = "no frida" } };
        var tools = new LiveSessionTools(new ServerOptions { AllowLive = true, AllowLiveAttach = true }, service);
        var e = await Assert.ThrowsAsync<ToolError>(() => tools.LiveSession("attach", program: "app"));
        Assert.Equal(ErrorCode.ProviderUnavailable, e.Code);
        Assert.Equal("install it", e.Remediation);
    }
}
