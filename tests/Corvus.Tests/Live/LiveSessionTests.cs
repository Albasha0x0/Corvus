using System.Text.RegularExpressions;
using System.Diagnostics;
using System.Text.Json.Nodes;
using Corvus.Core;
using Corvus.Native.Code;
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
    /// <summary>Stop points set bare (no stack or registers sent).</summary>
    public readonly HashSet<string> Bare = [];
    /// <summary>The hit limit each counted point was set with.</summary>
    public readonly Dictionary<string, int> Limits = [];
    public string? Missing { get; init; }
    /// <summary>The arguments of the last open request (what the backend was asked to start or attach to).</summary>
    public JsonObject? LastOpen { get; private set; }
    /// <summary>The process id the session reports (a real child for snapshot tests).</summary>
    public int ProcessId { get; init; } = Pid;
    /// <summary>Bytes the program holds, by address.</summary>
    public readonly Dictionary<ulong, byte[]> Memory = [];
    private readonly Dictionary<string, ulong> _points = [];
    private bool _suspended;
    /// <summary>Held threads, one entry per stop waiting for its resume.</summary>
    private readonly List<long> _held = [];
    /// <summary>Addresses the backend cannot hook, as Frida refuses a function too short for its jump.</summary>
    public readonly HashSet<ulong> Unhookable = [];
    /// <summary>Exports the program's loader resolves (module!name), for modules with no file to read.</summary>
    public readonly Dictionary<string, ulong> Exports = [];
    /// <summary>What the session script was told to read for each watch.</summary>
    public readonly Dictionary<string, List<string>> WatchedKinds = [];
    /// <summary>Lists the program's module after the system one, as Frida may order them.</summary>
    public bool MainListedLast { get; init; }
    /// <summary>The program's architecture as Frida names it.</summary>
    public string Arch { get; init; } = "x64";
    /// <summary>Runs before the reply to a resume, as when a resumed thread stops again before the worker answers.</summary>
    public Action? BeforeResumeReply { get; set; }
    /// <summary>Runs before the reply to a close, as while the worker still ends its session.</summary>
    public Action? BeforeCloseReply { get; set; }
    /// <summary>Child processes the program started: an attach by one of these ids reports that id.</summary>
    public readonly HashSet<int> ChildPids = [];
    /// <summary>The child process ids resume_child let run, in order (negative: let run held at its code).</summary>
    public readonly List<int> ChildResumes = [];
    /// <summary>Whether a child resumed with hold reached its code before the reply.</summary>
    public bool ChildHoldReached { get; set; } = true;
    /// <summary>The child process ids drop_child named, in order.</summary>
    public readonly List<int> ChildDrops = [];
    /// <summary>The platform the program runs on, as Frida names it; null leaves it out of the open reply.</summary>
    public string? Platform { get; init; }
    /// <summary>Whether set_many is known; false answers it as an unknown op, as a backend without batches.</summary>
    public bool Batches { get; init; } = true;
    /// <summary>The version the hello reply names.</summary>
    public string FridaVersion { get; init; } = FridaVersions.TestedFrom.ToString();

    public string Name => "scripted";
    public (string Reason, string Remediation)? Unavailable() => Missing == null ? null : (Missing, "install it");

    public WorkerConnection Start()
    {
        Worker = new FakeWorkerProcess(ready: true) { Ops = Handle };
        return Worker.Connect(null);
    }

    /// <summary>A thread hitting stop point <paramref name="id"/>, called from <paramref name="caller"/>; a cleared point stops at the caller.</summary>
    public void Hit(string id, long thread, ulong caller) => Stop(thread, new JsonObject
    {
        ["event"] = "stop", ["point"] = id, ["tid"] = thread, ["hits"] = 1,
        ["registers"] = new JsonObject { ["pc"] = $"0x{_points.GetValueOrDefault(id, caller):x}", ["rcx"] = "0x5000", ["rsp"] = "0x9000" },
        ["frames"] = new JsonArray($"0x{_points.GetValueOrDefault(id, caller):x}", $"0x{caller:x}", "0x7ffe00001234"),
    });

    /// <summary>A thread passing counted point <paramref name="id"/>, which reports the hit and holds no thread.</summary>
    public void Pass(string id, long thread) => Worker!.Emit(new JsonObject
    {
        ["event"] = "stop", ["point"] = id, ["tid"] = thread, ["hits"] = 1, ["registers"] = new JsonObject(),
        ["frames"] = new JsonArray($"0x{_points[id]:x}"), ["counted"] = true,
    });

    /// <summary>A thread hitting stop point <paramref name="id"/> with the given stack values, as the worker reports them.</summary>
    public void HitWith(string id, long thread, params ulong[] frames) => Stop(thread, new JsonObject
    {
        ["event"] = "stop", ["point"] = id, ["tid"] = thread, ["hits"] = 1,
        ["registers"] = new JsonObject { ["pc"] = $"0x{_points[id]:x}" },
        ["frames"] = new JsonArray([.. new[] { _points[id] }.Concat(frames).Select(f => (JsonNode)$"0x{f:x}")]),
    });

    /// <summary>A thread hitting stop point <paramref name="id"/> with the stack bytes at <paramref name="sp"/> and the frames the backend's own walk gave.</summary>
    public void HitWithStack(string id, long thread, ulong sp, byte[] stack, params ulong[] frames) => Stop(thread, new JsonObject
    {
        ["event"] = "stop", ["point"] = id, ["tid"] = thread, ["hits"] = 1,
        ["registers"] = new JsonObject { ["pc"] = $"0x{_points[id]:x}", ["sp"] = $"0x{sp:x}", ["rsp"] = $"0x{sp:x}", ["rbp"] = "0x0" },
        ["frames"] = new JsonArray([.. new[] { _points[id] }.Concat(frames).Select(f => (JsonNode)$"0x{f:x}")]),
        ["stack"] = Convert.ToHexStringLower(stack),
    });

    private void Stop(long thread, JsonObject stop)
    {
        lock (_held) _held.Add(thread);
        Worker!.Emit(stop);
    }

    /// <summary>The program loading <paramref name="name"/> from <paramref name="path"/> at <paramref name="at"/>; <paramref name="heldBy"/>: the loading thread the worker holds.</summary>
    public void Load(string name, string path, ulong at, uint size, long? heldBy = null, string? unobserved = null) => Worker!.Emit(new JsonObject
    {
        ["event"] = "module", ["action"] = "loaded", ["held"] = heldBy != null, ["tid"] = heldBy, ["unobserved"] = unobserved,
        ["module"] = new JsonObject { ["name"] = name, ["base"] = $"0x{at:x}", ["size"] = size, ["path"] = path },
    });

    /// <summary>A batch of recorded calls of watch <paramref name="id"/>: (thread, ms, return address, arguments, return value) rows.</summary>
    public void Calls(string id, IEnumerable<(long Thread, long Ms, ulong Caller, string?[] Args, string Ret)> rows, long skipped) => Worker!.Emit(new JsonObject
    {
        ["event"] = "calls", ["watch"] = id, ["skipped"] = skipped,
        ["rows"] = new JsonArray(rows.Select(r => (JsonNode)new JsonArray(r.Thread, r.Ms, $"0x{r.Caller:x}", new JsonArray(r.Args.Select(a => (JsonNode?)a).ToArray()), r.Ret)).ToArray()),
    });

    /// <summary>The program starting a child process, as the worker reports it while the session follows children.</summary>
    public void Child(FakeWorkerProcess worker, int pid, string path, bool held)
    {
        lock (ChildPids) ChildPids.Add(pid);
        worker.Emit(new JsonObject
        {
            ["event"] = "child", ["pid"] = pid, ["parentPid"] = ProcessId, ["path"] = path, ["argv"] = new JsonArray(path, "--role", "two words"),
            ["origin"] = "spawn", ["held"] = held,
        });
    }

    public void ScriptMessage(string id, JsonNode payload) => Worker!.Emit(new JsonObject { ["event"] = "user_script", ["script"] = id, ["payload"] = payload });

    private JsonNode? Handle(string op, JsonObject args)
    {
        lock (Ops) Ops.Add(op);
        switch (op)
        {
            case "hello": return new JsonObject { ["frida"] = FridaVersion };
            case "open":
                LastOpen = (JsonObject)args.DeepClone();
                _suspended = args["spawn"] != null || args["stopped"] is { } stopped && (bool)stopped;
                JsonNode program = new JsonObject { ["name"] = Path.GetFileName(mainPath), ["base"] = $"0x{mainBase:x}", ["size"] = mainSize, ["path"] = mainPath };
                JsonNode system = new JsonObject { ["name"] = "system.dll", ["base"] = "0x7ffe00000000", ["size"] = 0x10000, ["path"] = "/nowhere/system.dll" };
                int pid;
                lock (ChildPids) pid = int.TryParse((string?)args["attach"], out var child) && ChildPids.Contains(child) ? child : ProcessId;
                return new JsonObject
                {
                    ["pid"] = pid, ["arch"] = Arch, ["platform"] = Platform, ["suspended"] = _suspended,
                    ["modules"] = MainListedLast ? new JsonArray(system, program) : new JsonArray(program, system),
                };
            case "set" or "watch" when Unhookable.Contains(Convert.ToUInt64(((string)args["address"]!)[2..], 16)):
                // Frida words a refused probe (a bare point) by instruction, a refused listener by function.
                throw new InvalidOperationException($"Error: unable to intercept {(args["bare"] is { } refusedBare && (bool)refusedBare ? "instruction" : "function")} at {args["address"]}; please file a bug");
            case "set":
                _points[(string)args["id"]!] = Convert.ToUInt64(((string)args["address"]!)[2..], 16);
                if (args["bare"] is { } bare && (bool)bare) lock (Bare) Bare.Add((string)args["id"]!);
                if (args["limit"] is { } limit) lock (Limits) Limits[(string)args["id"]!] = (int)limit;
                return true;
            case "set_many" when !Batches: return null;
            case "set_many":
                // Each point counts as a set, as one request each did.
                var results = new JsonArray();
                foreach (var p in args["points"]!.AsArray().Select(p => (JsonObject)p!))
                {
                    try { Handle("set", p); results.Add(new JsonObject { ["id"] = (string)p["id"]!, ["ok"] = true }); }
                    catch (InvalidOperationException e) { results.Add(new JsonObject { ["id"] = (string)p["id"]!, ["ok"] = false, ["error"] = new JsonObject { ["code"] = "failed", ["message"] = e.Message } }); }
                }
                return new JsonObject { ["results"] = results };
            case "clear": return _points.Remove((string)args["id"]!);
            case "watch":
                WatchedKinds[(string)args["id"]!] = args["args"]!.AsArray().Select(k => (string)k!).ToList();
                return true;
            case "unwatch": return WatchedKinds.Remove((string)args["id"]!);
            case "defer_module" or "undefer_module": return true;
            case "release_load": return new JsonObject { ["released"] = true };
            case "load_script":
                if (((string)args["source"]!).StartsWith("throw", StringComparison.Ordinal)) // the worker posts a top-level exception after its reply
                    new Thread(() => // its own thread: a busy thread pool could start it after the server's wait
                    {
                        Thread.Sleep(20);
                        Worker!.Emit(new JsonObject { ["event"] = "user_script", ["script"] = (string)args["id"]!, ["error"] = "Error: on purpose" });
                    }) { IsBackground = true }.Start();
                return new JsonObject { ["loaded"] = (string)args["id"]! };
            case "unload_script": return new JsonObject { ["unloaded"] = true };
            case "close":
                BeforeCloseReply?.Invoke();
                return null;
            case "resume_child":
                lock (ChildResumes) ChildResumes.Add(args["hold"] is { } hold && (bool)hold ? -(int)args["pid"]! : (int)args["pid"]!);
                return args["hold"] is null ? new JsonObject { ["resumed"] = true } : new JsonObject { ["resumed"] = true, ["held"] = ChildHoldReached };
            case "drop_child":
                lock (ChildDrops) ChildDrops.Add((int)args["pid"]!);
                return new JsonObject { ["dropped"] = true, ["kept"] = 0 };
            case "resume":
                BeforeResumeReply?.Invoke();
                // as the worker: a program started suspended runs on the first resume of every thread
                var started = _suspended && args["thread"] == null;
                if (started) _suspended = false;
                long[] resumed;
                lock (_held)
                {
                    resumed = [.. _held.Where(h => args["thread"] is not { } t || h == (long)t).Distinct()];
                    foreach (var r in resumed) _held.Remove(r);
                }
                return new JsonObject { ["resumed"] = new JsonArray([.. resumed.Select(r => (JsonNode)r)]), ["started"] = started };
            case "read":
                // as Frida reads: the whole range or nothing; the pages Memory touches are readable, zero outside its bytes
                ulong at = Convert.ToUInt64(((string)args["address"]!)[2..], 16);
                var bytes = new byte[(int)args["length"]!];
                for (int i = 0; i < bytes.Length; i++)
                {
                    var a = at + (ulong)i;
                    if (!Memory.Any(m => a / 4096 >= m.Key / 4096 && a / 4096 <= (m.Key + (ulong)m.Value.Length - 1) / 4096))
                        return new JsonObject { ["bytes"] = null };
                    bytes[i] = Memory.FirstOrDefault(m => a >= m.Key && a - m.Key < (ulong)m.Value.Length) is { Value: { } block, Key: var start } ? block[a - start] : (byte)0;
                }
                return new JsonObject { ["bytes"] = Convert.ToHexStringLower(bytes) };
            case "export":
                return new JsonObject { ["address"] = Exports.TryGetValue($"{args["module"]}!{args["name"]}", out var export) ? $"0x{export:x}" : null };
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
        _service = new LiveSessionService(_workspace, new NativeCodeService(_workspace, SharedCodeIndex.Options())) { Backend = _backend };
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
        var service = new LiveSessionService(_workspace, new NativeCodeService(_workspace, SharedCodeIndex.Options())) { Backend = new ScriptedLiveBackend(Sqlite, Base, 0x200000) { MainListedLast = true } };
        var tools = new LiveSessionTools(new ServerOptions { AllowLiveSpawn = true }, service);
        await tools.LiveSession("spawn", program: Sqlite);
        Assert.Contains("e_sqlite3.dll!sqlite3_open", await tools.LiveBreak("live-1", "set", at: "sqlite3_open"));
        Assert.Matches(@"matched to loaded images:\s+0x7FF610000000 e_sqlite3\.dll", await tools.LiveSession("status", session: "live-1"));
        service.Dispose();
    }

    [Fact]
    public async Task A_program_with_no_program_interpreter_is_refused_before_a_worker_starts()
    {
        using var dir = new TempDir();
        var linked = dir.File("linked");
        File.WriteAllBytes(linked, new NativeFormats.ElfWriter { Machine = NativeFormats.ElfWriter.EmX64, Type = 2, Interpreter = "/lib64/ld-linux-x86-64.so.2" }.Build());
        var unlinked = dir.File("unlinked");
        File.WriteAllBytes(unlinked, new NativeFormats.ElfWriter { Machine = NativeFormats.ElfWriter.EmX64, Type = 2 }.Build());
        Assert.False(Corvus.Native.Live.StaticProgram.Is(linked));
        Assert.True(Corvus.Native.Live.StaticProgram.Is(unlinked));

        var refused = await Assert.ThrowsAsync<ToolError>(() => _tools.LiveSession("spawn", program: unlinked));
        Assert.Equal(ErrorCode.Unsupported, refused.Code);
        Assert.Contains("statically linked", refused.Message);
        Assert.Contains("gcore", refused.Remediation);
        Assert.Null(_backend.Worker);
    }

    [Fact]
    public async Task A_module_without_a_file_resolves_its_export_through_the_program()
    {
        await _tools.LiveSession("spawn", program: Sqlite);
        var missing = await Assert.ThrowsAsync<ToolError>(() => _tools.LiveBreak("live-1", "set", at: "system!open"));
        Assert.Contains("could not be loaded as a native image", missing.Message);
        _backend.Exports["system.dll!open"] = 0x7ffe00001230;
        Assert.Contains("s1 set at 0x7FFE00001230 ", await _tools.LiveBreak("live-1", "set", at: "system!open"));
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
    public async Task A_stop_of_a_cleared_point_is_released()
    {
        await _tools.LiveSession("spawn", program: Sqlite);
        await _tools.LiveBreak("live-1", "set", at: "e_sqlite3!sqlite3_open");
        await _tools.LiveBreak("live-1", "continue");
        await _tools.LiveBreak("live-1", "clear", stopPoint: "s1");
        // The thread entered the hook before the clear and stops after it.
        _backend.Hit("s1", 77, Base + 0x1010);
        var s = _service.Get("live-1");
        int Resumes() { lock (_backend.Ops) return _backend.Ops.Count(o => o == "resume"); }
        for (int i = 0; i < 250 && Resumes() < 2; i++) await Task.Delay(20);
        Assert.Equal(2, Resumes());
        Assert.Equal("running", s.State);
        Assert.Contains("stop point s1 hit after it was cleared: thread released", await _tools.LiveEvents("live-1", kind: "stop"));
    }

    [Fact]
    public async Task A_module_loaded_as_an_assembly_is_matched_by_its_file_or_a_copy_of_it()
    {
        using var dir = new TempDir();
        var original = RealPackages.Lib("Newtonsoft.Json", "13.0.1", "netstandard2.0", "Newtonsoft.Json.dll");
        var copy = dir.File("Newtonsoft.Json.dll");
        File.Copy(original, copy);
        var asm = _workspace.Load(original);
        await _tools.LiveSession("spawn", program: Sqlite);
        uint size = BitConverter.ToUInt32(asm.OriginalBytes, BitConverter.ToInt32(asm.OriginalBytes, 0x3C) + 24 + 56);
        _backend.Load("Newtonsoft.Json.dll", copy, 0x7ff7_0000_0000, size);
        string status = "";
        for (int i = 0; i < 50 && !status.Contains("(assembly)", StringComparison.Ordinal); i++)
        {
            await Task.Delay(100);
            status = await _tools.LiveSession("status", session: "live-1");
        }
        Assert.Contains($"3 modules, 2 matched to loaded images", status);
        Assert.Contains($"0x7FF700000000 Newtonsoft.Json.dll  = {asm.Id} (assembly)", status);
        // another build under the same name is not that assembly
        File.WriteAllBytes(copy, [.. File.ReadAllBytes(original).Take(0x400), .. new byte[16]]);
        _backend.Load("Newtonsoft.Json.dll", copy, 0x7ff7_1000_0000, size);
        await Task.Delay(300);
        Assert.Contains("0x7FF710000000 Newtonsoft.Json.dll\n", (await _tools.LiveSession("status", session: "live-1")).ReplaceLineEndings("\n"));
    }

    [Fact]
    public async Task Continue_of_one_thread_leaves_a_suspended_program_suspended_and_says_so()
    {
        await _tools.LiveSession("spawn", program: Sqlite);
        Assert.Contains("no thread was held; the program is still suspended: continue without thread starts it", await _tools.LiveBreak("live-1", "continue", thread: "5"));
        Assert.Contains("program started", await _tools.LiveBreak("live-1", "continue"));
        Assert.Contains("no thread was held\n", (await _tools.LiveBreak("live-1", "continue")).ReplaceLineEndings("\n"));
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
        var rva = new NativeCodeService(_workspace, SharedCodeIndex.Options()).IndexOfOriginal(image, default).AddressOfName("sqlite3_open")!.Value;
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
        Assert.Contains(", 0 stop point(s)", cleared);
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
    public async Task A_deferred_point_in_a_module_the_agent_cannot_observe_fails_with_the_reason()
    {
        await _tools.LiveSession("attach", program: "4242");
        await _tools.LiveBreak("live-1", "set", at: "plugin!sqlite3_open");

        _backend.Load("plugin.dll", Sqlite, 0x7ff7_0000_0000, 0x200000, unobserved: "its entry point writes its code");
        var listed = "";
        for (int i = 0; i < 100 && !listed.Contains("failed"); i++, await Task.Delay(50)) listed = await _tools.LiveBreak("live-1");
        Assert.Contains("s1 plugin!sqlite3_open: failed (plugin.dll loaded): its entry point writes its code", listed);
        Assert.Contains("x64 machine", listed);
        Assert.DoesNotContain("set", _backend.Ops);
    }

    [Fact]
    public async Task A_deferred_point_not_set_at_the_load_is_reported_once_and_listed_as_failed()
    {
        // the session's code service carries an Il2Cpp layer naming sqlite3_open "Game_Player__Update"; the point is given in the managed form
        var code = new NativeCodeService(_workspace, SharedCodeIndex.Options());
        using var service = new LiveSessionService(_workspace, code) { Backend = new ScriptedLiveBackend(Sqlite, Base, 0x200000) };
        var backend = (ScriptedLiveBackend)service.Backend;
        var tools = new LiveSessionTools(new ServerOptions { AllowLive = true, AllowLiveAttach = true }, service);
        var native = _workspace.LoadAny(Sqlite).Native!;
        var index = await code.Index(native, null, default);
        var rva = index.AddressOfName("sqlite3_open")!.Value;
        NativeNameLayers.Of(native).Set(new NativeNameLayers.Layer(NativeNameSource.Il2Cpp, new Dictionary<uint, string> { [rva] = "Game_Player__Update" },
            new Dictionary<uint, string>(), "test"), index);
        await tools.LiveSession("attach", program: "4242");
        await tools.LiveBreak("live-1", "set", at: "plugin!Game.Player::Update()");
        await tools.LiveWatchCalls("live-1", "set", at: "plugin!no_such_function");

        backend.Load("plugin.dll", Sqlite, 0x7ff7_0000_0000, 0x200000, heldBy: 77);
        for (int i = 0; i < 100 && !backend.Ops.Contains("release_load"); i++) await Task.Delay(50);
        var first = await tools.LiveBreak("live-1");
        Assert.Contains("deferred stop point s1 at plugin!Game.Player::Update() was dropped (plugin.dll loaded): ", first);
        Assert.Contains("deferred watch w1 at plugin!no_such_function was dropped (plugin.dll loaded): ", first);
        Assert.Contains("0 stop point(s), 1 failed", first);
        Assert.Contains("s1 plugin!Game.Player::Update(): failed (plugin.dll loaded): ", first);
        Assert.Contains("Next: at=plugin.dll!Game_Player__Update (the il2cpp layer's name for it)", first);
        // said once; the list keeps the failed point until it is cleared
        var again = await tools.LiveBreak("live-1");
        Assert.DoesNotContain("was dropped", again);
        Assert.DoesNotContain("Next:", again);
        Assert.Contains("s1 plugin!Game.Player::Update(): failed", again);
        Assert.Contains("w1 plugin!no_such_function: failed (plugin.dll loaded): ", await tools.LiveWatchCalls("live-1"));
        Assert.DoesNotContain("failed", await tools.LiveBreak("live-1", "clear", stopPoint: "s1"));
        // set now: the same hint
        var refused = await Assert.ThrowsAsync<ToolError>(() => tools.LiveBreak("live-1", "set", at: "plugin!Game.Player::Update"));
        Assert.Equal("at=plugin.dll!Game_Player__Update (the il2cpp layer's name for it)", refused.Remediation);
        Assert.Contains("plugin.dll!Game_Player__Update", await tools.LiveBreak("live-1", "set", at: "plugin!Game_Player__Update"));
    }

    [Fact]
    public async Task Name_plus_offset_resolves_and_a_point_inside_an_instruction_is_refused()
    {
        await _tools.LiveSession("attach", program: "4242");
        var index = new NativeCodeService(_workspace, SharedCodeIndex.Options()).IndexOfOriginal(_workspace.Natives.Single(), default);
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
        var entry = Base + new NativeCodeService(_workspace, SharedCodeIndex.Options()).IndexOfOriginal(_workspace.Natives.Single(), default).AddressOfName("sqlite3_open")!.Value;
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
    public async Task A_frame_in_a_function_the_unwind_data_shows_unexported_is_not_named_after_the_export_below()
    {
        await _tools.LiveSession("attach", program: "4242");
        await _tools.LiveBreak("live-1", "set", at: "e_sqlite3!sqlite3_open");
        var old = RealPackages.File("SQLitePCLRaw.lib.e_sqlite3", "2.1.2", "runtimes", "win-x64", "native", "e_sqlite3.dll");
        const ulong LibBase = 0x7ff8_0000_0000;
        _backend.Load("old.dll", old, LibBase, 0x200000);
        var pe = (Native.Pe.PeFile)Native.NativeImageLoader.Open(old);
        var exports = pe.Exports.Select(e => e.Rva).ToHashSet();
        var inner = pe.RuntimeFunctions.First(f => !exports.Contains(f.BeginRva) && exports.Any(e => e < f.BeginRva) && f.EndRva - f.BeginRva > 8).BeginRva + 4;
        await Task.Delay(100);
        _backend.HitWith("s1", 9, LibBase + inner);
        var stop = await _tools.LiveBreak("live-1", wait: true, waitSeconds: 10);
        Assert.Matches($@"#1 0x{LibBase + inner:X} old\.dll\+0x{inner:X}\r?\n", stop);
    }

    // An unloaded ELF names frames by its .symtab and .dynsym functions, as
    // dump_stack does. A static function is not named after the export below
    // it, and a return address just past a noreturn call at a function's end
    // names that function.
    [Fact]
    public async Task An_unloaded_elf_names_frames_by_its_symbol_table_and_a_return_address_by_its_call()
    {
        await _tools.LiveSession("attach", program: "4242");
        await _tools.LiveBreak("live-1", "set", at: "e_sqlite3!sqlite3_open");
        using var dir = new TempDir();
        var lib = dir.File("libpython.so");
        const uint T = NativeFormats.ElfWriter.TextRva;
        File.WriteAllBytes(lib, new NativeFormats.ElfWriter
        {
            Machine = NativeFormats.ElfWriter.EmX64, Text = Enumerable.Repeat((byte)0x90, 0x60).ToArray(),
            Symbols = [new("Py_Exit", T, 0x10), new("Py_FdIsInteractive", T + 0x10, 0x10), new("PyErr_Print", T + 0x20, 0x10)],
            StaticSymbols = [new("handle_system_exit", T + 0x30, 0x20, Bind: 0)],
        }.Build());
        const ulong LibBase = 0x7ff8_0000_0000;
        _backend.Load("libpython.so", lib, LibBase, 0x30000);
        await Task.Delay(100);
        _backend.HitWith("s1", 9, LibBase + T + 0x10, LibBase + T + 0x38);
        var stop = await _tools.LiveBreak("live-1", wait: true, waitSeconds: 10);
        Assert.Contains($"#1 0x{LibBase + T + 0x10:X} libpython.so!Py_Exit+0x10", stop);
        Assert.Contains($"#2 0x{LibBase + T + 0x38:X} libpython.so!handle_system_exit+0x8", stop);
    }

    [Fact]
    public async Task A_watch_and_a_stop_point_in_the_same_prologue_are_refused_in_either_order()
    {
        await _tools.LiveSession("attach", program: "4242");
        var index = new NativeCodeService(_workspace, SharedCodeIndex.Options()).IndexOfOriginal(_workspace.Natives.Single(), default);
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
        var index = new NativeCodeService(_workspace, SharedCodeIndex.Options()).IndexOfOriginal(_workspace.Natives.Single(), default);
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
    public async Task A_wait_the_program_ends_says_the_program_ended()
    {
        await _tools.LiveSession("attach", program: "4242");
        var wait = _tools.LiveBreak("live-1", wait: true, waitSeconds: 60);
        await Task.Delay(200);
        _backend.Worker!.Emit(new JsonObject { ["event"] = "exit", ["reason"] = "process-terminated" });
        var text = await wait.WaitAsync(TimeSpan.FromSeconds(10));
        Assert.Contains("the program ended before a stop (exited: process-terminated", text);
        Assert.DoesNotContain("no stop within", text);
    }

    [Fact]
    public async Task Status_while_a_close_runs_names_why_the_session_closes()
    {
        await _tools.LiveSession("spawn", program: Sqlite);
        using var closing = new ManualResetEventSlim();
        using var release = new ManualResetEventSlim();
        _backend.BeforeCloseReply = () => { closing.Set(); release.Wait(10_000); };
        var close = _service.CloseAsync(_service.Get("live-1"), "deadline");
        Assert.True(closing.Wait(10_000), "the close never reached the worker");
        var status = await _tools.LiveSession("status", session: "live-1");
        release.Set();
        await close;
        Assert.Contains("closed (session closed (deadline))", status);
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
        using var service = new LiveSessionService(_workspace, new NativeCodeService(_workspace, SharedCodeIndex.Options())) { Backend = backend };
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
            // HasExited is true once the exit code is set; only the wait sees a program still in its exit.
            if (!program.WaitForExit(0)) program.Kill();
        }
    }

    // R-39: Frida reported process-terminated while the program stayed in its exit, and the stuck exit check stopped.
    [LiveTargetFact("win-x64")]
    [Trait("Speed", "Slow")]
    public async Task An_exit_reported_while_the_program_is_still_in_its_exit_waits_for_the_stuck_exit_check()
    {
        const string Source = """
            #include <windows.h>
            static void NTAPI OnTls(PVOID h, DWORD reason, PVOID r) { if (reason == DLL_PROCESS_DETACH) for (;;) Sleep(10); }
            #pragma comment(linker, "/INCLUDE:_tls_used")
            #pragma comment(linker, "/INCLUDE:tls_callback")
            #pragma const_seg(".CRT$XLB")
            EXTERN_C const PIMAGE_TLS_CALLBACK tls_callback = OnTls;
            #pragma const_seg()
            int main(void) { Sleep(1000); return 7; }
            """;
        using var dir = new TempDir();
        using var program = Process.Start(LiveTarget.WinX64.Build(dir, "stuckexit", Source))!;
        var backend = new ScriptedLiveBackend(Sqlite, Base, 0x200000) { ProcessId = program.Id };
        using var service = new LiveSessionService(_workspace, new NativeCodeService(_workspace, SharedCodeIndex.Options())) { Backend = backend };
        var tools = new LiveSessionTools(new ServerOptions { AllowLive = true, AllowLiveAttach = true }, service);
        var stuck = LiveSessionService.StuckExit;
        LiveSessionService.StuckExit = TimeSpan.FromSeconds(2);
        try
        {
            await tools.LiveSession("attach", program: $"{program.Id}");
            using (var h = Corvus.Native.Live.LiveNative.OpenProcess(Corvus.Native.Live.LiveNative.PROCESS_QUERY_LIMITED_INFORMATION, false, program.Id))
                for (var until = DateTime.UtcNow.AddSeconds(30); DateTime.UtcNow < until; await Task.Delay(50))
                    if (Corvus.Native.Live.LiveNative.GetExitCodeProcess(h, out var code) && code != Corvus.Native.Live.LiveNative.STILL_ACTIVE) break;
            backend.Worker!.Emit(new JsonObject { ["event"] = "exit", ["reason"] = "process-terminated" });
            Assert.True(program.WaitForExit(30_000), "the program's exit was not finished");
            var reported = DateTime.UtcNow.AddSeconds(10);
            while (!(await tools.LiveSession("status", session: "live-1")).Contains(", exited") && DateTime.UtcNow < reported) await Task.Delay(50);
            var events = await tools.LiveEvents("live-1");
            var error = events.IndexOf("called ExitProcess(7) but its exit did not finish", StringComparison.Ordinal);
            var exit = events.IndexOf("exited: process-terminated, exit code 7", StringComparison.Ordinal);
            Assert.True(error >= 0 && exit > error, events);
        }
        finally
        {
            LiveSessionService.StuckExit = stuck;
            // HasExited is true once the exit code is set; only the wait sees a program still in its exit.
            if (!program.WaitForExit(0)) program.Kill();
        }
    }

    [Fact]
    public async Task A_function_too_short_to_hook_is_refused_with_its_size()
    {
        await _tools.LiveSession("attach", program: "4242");
        var index = new NativeCodeService(_workspace, SharedCodeIndex.Options()).IndexOfOriginal(_workspace.Natives.Single(), default);
        var shortest = index.Functions.Where(f => f.Size is > 0 and < 16).OrderBy(f => f.Start).First();
        _backend.Unhookable.Add(Base + shortest.Start);
        var refused = await Assert.ThrowsAsync<ToolError>(() => _tools.LiveBreak("live-1", "set", at: $"0x{Base + shortest.Start:X}"));
        Assert.Equal(ErrorCode.Unsupported, refused.Code);
        Assert.Contains($"the function is {shortest.Size} bytes long (", refused.Message);
        Assert.Contains("), too short for the jump", refused.Message);
        Assert.Contains("find_xrefs", refused.Remediation);
        Assert.Equal(ErrorCode.Unsupported, (await Assert.ThrowsAsync<ToolError>(() => _tools.LiveWatchCalls("live-1", "set", at: $"0x{Base + shortest.Start:X}"))).Code);
    }

    // R-39: Frida reported process-terminated after the agent's exit status, before the exit code was set.
    [Fact]
    public async Task An_exit_reported_after_the_exit_status_waits_for_the_process_to_end()
    {
        if (!OperatingSystem.IsWindows()) return;
        using var child = Process.Start(new ProcessStartInfo(Path.Combine(Environment.SystemDirectory, "findstr.exe"), "x")
            { RedirectStandardInput = true, UseShellExecute = false, CreateNoWindow = true })!;
        var backend = new ScriptedLiveBackend(Sqlite, Base, 0x200000) { ProcessId = child.Id };
        using var service = new LiveSessionService(_workspace, new NativeCodeService(_workspace, SharedCodeIndex.Options())) { Backend = backend };
        var tools = new LiveSessionTools(new ServerOptions { AllowLive = true, AllowLiveAttach = true }, service);
        await tools.LiveSession("attach", program: child.Id.ToString());
        // The program is still running, as one whose exit has begun but whose exit code is not yet set.
        backend.Worker!.Emit(new JsonObject { ["event"] = "exit_status", ["code"] = 1 });
        backend.Worker!.Emit(new JsonObject { ["event"] = "exit", ["reason"] = "process-terminated" });
        await Task.Delay(1500);
        Assert.Contains(", running", await tools.LiveSession("status", session: "live-1"));
        child.StandardInput.Close();
        await child.WaitForExitAsync();
        for (var until = DateTime.UtcNow.AddSeconds(10); DateTime.UtcNow < until; await Task.Delay(50))
            if ((await tools.LiveSession("status", session: "live-1")).Contains(", exited")) break;
        Assert.Contains("exited: process-terminated, exit code 1", await tools.LiveEvents("live-1", kind: "exit"));
    }

    // R-39: Frida reported process-terminated before the agent's exit status, the program's exit just begun.
    [Fact]
    public async Task An_exit_reported_before_the_exit_status_waits_for_the_process_to_end()
    {
        if (!OperatingSystem.IsWindows()) return;
        using var child = Process.Start(new ProcessStartInfo(Path.Combine(Environment.SystemDirectory, "findstr.exe"), "x")
            { RedirectStandardInput = true, UseShellExecute = false, CreateNoWindow = true })!;
        var backend = new ScriptedLiveBackend(Sqlite, Base, 0x200000) { ProcessId = child.Id };
        using var service = new LiveSessionService(_workspace, new NativeCodeService(_workspace, SharedCodeIndex.Options())) { Backend = backend };
        var tools = new LiveSessionTools(new ServerOptions { AllowLive = true, AllowLiveAttach = true }, service);
        await tools.LiveSession("attach", program: child.Id.ToString());
        // The program is still running, its exit code not yet set, and no exit status has come.
        backend.Worker!.Emit(new JsonObject { ["event"] = "exit", ["reason"] = "process-terminated" });
        await Task.Delay(1500);
        Assert.Contains(", running", await tools.LiveSession("status", session: "live-1"));
        backend.Worker!.Emit(new JsonObject { ["event"] = "exit_status", ["code"] = 1 });
        child.StandardInput.Close();
        await child.WaitForExitAsync();
        for (var until = DateTime.UtcNow.AddSeconds(10); DateTime.UtcNow < until; await Task.Delay(50))
            if ((await tools.LiveSession("status", session: "live-1")).Contains(", exited")) break;
        Assert.Contains("exited: process-terminated, exit code 1", await tools.LiveEvents("live-1", kind: "exit"));
    }

    [Fact]
    public async Task The_exit_event_carries_the_exit_code_the_system_reports()
    {
        if (!OperatingSystem.IsWindows()) return;
        using var child = System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo(Path.Combine(Environment.SystemDirectory, "findstr.exe"), "x")
            { RedirectStandardInput = true, UseShellExecute = false, CreateNoWindow = true })!;
        var backend = new ScriptedLiveBackend(Sqlite, Base, 0x200000) { ProcessId = child.Id };
        using var service = new LiveSessionService(_workspace, new NativeCodeService(_workspace, SharedCodeIndex.Options())) { Backend = backend };
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
        using var service = new LiveSessionService(_workspace, new NativeCodeService(_workspace, SharedCodeIndex.Options())) { Backend = backend };
        var tools = new LiveSessionTools(new ServerOptions { AllowLive = true, AllowLiveAttach = true }, service);
        await tools.LiveSession("attach", program: "4242");
        await tools.LiveBreak("live-1", "set", at: "SystemNative_FStat");
        var index = new NativeCodeService(_workspace, SharedCodeIndex.Options()).IndexOfOriginal(_workspace.Natives.Single(), default);
        ulong caller = ElfBase + index.AddressOfName("SystemNative_StrErrorR")!.Value + 0x10;
        // at the function's start the return address is at the stack pointer; the backend's walk put the word there twice
        backend.HitWithStack("s1", 77, Sp, [.. BitConverter.GetBytes(caller), .. new byte[8]], caller, caller);
        var stop = await tools.LiveBreak("live-1", wait: true, waitSeconds: 10);
        Assert.Contains($"#1 0x{caller:X} libSystem.Native.so!SystemNative_StrErrorR+0x10", stop);
        Assert.DoesNotContain("#2 ", stop);
    }

    // CI run 39796597537: the scripted id 4242 opened a runner's process 4240, so an exit report was held for it.
    [Fact]
    public async Task An_id_off_a_multiple_of_four_holds_no_handle_to_the_process_it_rounds_to()
    {
        if (!OperatingSystem.IsWindows()) return;
        // This test process stands in for the process the id rounds down to.
        var backend = new ScriptedLiveBackend(Sqlite, Base, 0x200000) { ProcessId = Environment.ProcessId + 2 };
        using var service = new LiveSessionService(_workspace, new NativeCodeService(_workspace, SharedCodeIndex.Options())) { Backend = backend };
        var tools = new LiveSessionTools(new ServerOptions { AllowLive = true, AllowLiveAttach = true }, service);
        await tools.LiveSession("attach", program: backend.ProcessId.ToString());
        Assert.Null(service.Get("live-1").ProcessHandle);
        backend.Worker!.Emit(new JsonObject { ["event"] = "exit", ["reason"] = "process-terminated" });
        for (int i = 0; i < 100 && service.Get("live-1").State != "exited"; i++) await Task.Delay(50);
        Assert.Contains("exited: process-terminated", await tools.LiveEvents("live-1", kind: "exit"));
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
        using var service = new LiveSessionService(_workspace, new NativeCodeService(_workspace, SharedCodeIndex.Options())) { Backend = backend };
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
    public async Task A_filtered_page_with_every_match_ends_the_ring_and_its_poll_starts_past_the_rest()
    {
        await _tools.LiveSession("attach", program: "4242");
        await _tools.LiveBreak("live-1", "set", at: $"0x{Base + 0x1000:X}");
        _backend.Hit("s1", 100, Base + 0x1010);
        for (int i = 0; i < 5; i++) _backend.ScriptMessage("u1", new JsonObject { ["n"] = i });
        for (int i = 0; i < 100 && _service.Get("live-1").Sequence < 6; i++) await Task.Delay(20);
        var stops = await _tools.LiveEvents("live-1", kind: "stop");
        Assert.Contains("#1 stop thread 100", stops);
        Assert.Contains("end of the ring; poll again with cursor=7", stops);
        Assert.DoesNotContain("more:", stops);
        _backend.Hit("s1", 101, Base + 0x1010);
        for (int i = 0; i < 100 && _service.Get("live-1").Sequence < 7; i++) await Task.Delay(20);
        var next = await _tools.LiveEvents("live-1", cursor: "7", kind: "stop", limit: 1);
        Assert.Contains("#7 stop thread 101", next);
        Assert.Contains("end of the ring; poll again with cursor=8", next);
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
        var rva = new NativeCodeService(_workspace, SharedCodeIndex.Options()).IndexOfOriginal(_workspace.Natives.Single(), default).AddressOfName("sqlite3_open")!.Value;
        _backend.Calls("w1", Enumerable.Range(0, 3).Select(i => (5L, 1000L + i * 10, Base + rva + 0x4, new string?[] { $"0x{0x100 + i:x}", "0x0" }, "0x0")), skipped: 7);
        for (int i = 0; i < 50 && !(await _tools.LiveWatchCalls("live-1")).Contains("3 call(s)"); i++) await Task.Delay(20);
        var list = await _tools.LiveWatchCalls("live-1");
        Assert.Contains("w1 e_sqlite3.dll!sqlite3_open: 3 call(s) recorded (100/s), 7 over the rate limit; sqlite3_open(a0, a1) (raw values)", list);
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
        Assert.Contains(", 0 script(s)", await tools.LiveScriptCalls("live-1"));
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
        var code = new NativeCodeService(_workspace, SharedCodeIndex.Options());
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
        // findstr runs as the machine's own architecture.
        var arch = System.Runtime.InteropServices.RuntimeInformation.OSArchitecture == System.Runtime.InteropServices.Architecture.Arm64 ? "arm64" : "x64";
        var service = new LiveSessionService(_workspace, new NativeCodeService(_workspace, SharedCodeIndex.Options())) { Backend = new ScriptedLiveBackend(Sqlite, Base, 0x200000) { ProcessId = child.Id, Arch = arch } };
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
            Assert.Contains($"written to {path}", await tools.LiveSession("snapshot", session: "live-1", outputPath: path, overwrite: true));
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
    public async Task Strings_read_to_their_terminator_a_page_at_a_time_and_say_where_they_stop_short()
    {
        await _tools.LiveSession("attach", program: "4242");
        var text = new string('a', 300);
        _backend.Memory[0x10000] = [.. System.Text.Encoding.UTF8.GetBytes(text), 0];
        _backend.Memory[0x20000] = [.. System.Text.Encoding.Unicode.GetBytes(text), 0, 0];
        Assert.Contains($"  \"{text}\"\n", (await _tools.LiveRead("live-1", memory: "0x10000", type: "cstring")).ReplaceLineEndings("\n"));
        Assert.Contains($"  \"{text}\"\n", (await _tools.LiveRead("live-1", memory: "0x20000", type: "utf16")).ReplaceLineEndings("\n"));
        Assert.Contains($"  \"{text[..16]}\" (cut: no terminator in 16 bytes)", await _tools.LiveRead("live-1", memory: "0x10000", type: "cstring", length: 16));
        // a string that runs to the end of readable memory, and one across a page boundary
        _backend.Memory[0x30FF0] = [.. Enumerable.Repeat((byte)'b', 16)];
        Assert.Contains($"  \"{new string('b', 16)}\" (cut: unreadable memory at 0x31000)", await _tools.LiveRead("live-1", memory: "0x30FF0", type: "cstring"));
        _backend.Memory[0x40F00] = [.. Enumerable.Repeat((byte)'c', 0x180), 0, .. new byte[0x100]];
        Assert.Contains($"  \"{new string('c', 0x180)}\"\n", (await _tools.LiveRead("live-1", memory: "0x40F00", type: "cstring")).ReplaceLineEndings("\n"));
        Assert.Equal(ErrorCode.NotFound, (await Assert.ThrowsAsync<ToolError>(() => _tools.LiveRead("live-1", memory: "0x50000", type: "utf16"))).Code);
    }

    [Theory]
    [InlineData("x64", "0x8877665544332211")]
    [InlineData("ia32", "0x44332211")]
    public async Task A_pointer_is_as_wide_as_the_programs_pointers(string arch, string first)
    {
        var backend = new ScriptedLiveBackend(Sqlite, Base, 0x200000) { Arch = arch };
        using var service = new LiveSessionService(_workspace, new NativeCodeService(_workspace, SharedCodeIndex.Options())) { Backend = backend };
        var tools = new LiveSessionTools(new ServerOptions { AllowLive = true, AllowLiveAttach = true }, service);
        await tools.LiveSession("attach", program: "4242");
        backend.Memory[0x5000] = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x10];
        var read = await tools.LiveRead("live-1", memory: "0x5000", type: "pointer[2]");
        Assert.Contains($"[0] {first}", read);
        Assert.Contains(arch == "ia32" ? "[1] 0x88776655" : "[1] 0x10FFEEDDCCBBAA99", read);
    }

    [Fact]
    public async Task Every_value_type_decodes_and_bad_types_are_refused()
    {
        await _tools.LiveSession("attach", program: "4242");
        _backend.Memory[0x5000] = [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF];
        _backend.Memory[0x6000] = [.. BitConverter.GetBytes(0.5f), .. BitConverter.GetBytes(2.5)];
        foreach (var (type, value) in new[] { ("int8", "-1"), ("uint8", "255"), ("int16", "-1"), ("uint16", "65535"), ("int32", "-1"), ("uint32", "4294967295"), ("int64", "-1"), ("uint64", "18446744073709551615") })
            Assert.Contains($"  {value}\n", (await _tools.LiveRead("live-1", memory: "0x5000", type: type)).ReplaceLineEndings("\n"));
        Assert.Contains("  0.5\n", (await _tools.LiveRead("live-1", memory: "0x6000", type: "float")).ReplaceLineEndings("\n"));
        Assert.Contains("  2.5\n", (await _tools.LiveRead("live-1", memory: "0x6004", type: "double")).ReplaceLineEndings("\n"));
        foreach (var spaced in new[] { "uint16 [2]", "uint16[ 2 ]", " UINT16 [2] " })
            Assert.Matches(@"uint16\[2\]\r?\n  \[0\] 65535\r?\n  \[1\] 65535\r?\n", await _tools.LiveRead("live-1", memory: "0x5000", type: spaced));
        foreach (var bad in new[] { "int128", "uint32[0]", "uint32[x]", "uint8[5000]", "uint 32[2]" })
            Assert.Equal(ErrorCode.InvalidArgument, (await Assert.ThrowsAsync<ToolError>(() => _tools.LiveRead("live-1", memory: "0x5000", type: bad))).Code);
    }

    [Fact]
    public async Task Registers_are_read_only_from_held_threads()
    {
        await _tools.LiveSession("attach", program: "4242");
        var noThread = await Assert.ThrowsAsync<ToolError>(() => _tools.LiveRead("live-1"));
        Assert.Equal(ErrorCode.InvalidArgument, noThread.Code);
        _backend.Memory[0x5000] = [1, 0, 0, 0];
        Assert.Contains("no thread is held", await _tools.LiveRead("live-1", registers: "pc", memory: "0x5000", type: "int32"));
        await _tools.LiveBreak("live-1", "set", at: "sqlite3_open");
        _backend.Hit("s1", 77, Base + 0x1010);
        await _tools.LiveBreak("live-1", wait: true, waitSeconds: 10);
        var unknown = await Assert.ThrowsAsync<ToolError>(() => _tools.LiveRead("live-1", registers: "pc,xmm9"));
        Assert.Equal(ErrorCode.InvalidArgument, unknown.Code);
        Assert.Contains("xmm9", unknown.Message);
        Assert.Equal(ErrorCode.NotFound, (await Assert.ThrowsAsync<ToolError>(() => _tools.LiveRead("live-1", thread: "78"))).Code);
        Assert.Equal(ErrorCode.InvalidArgument, (await Assert.ThrowsAsync<ToolError>(() => _tools.LiveRead("live-1", thread: "t77"))).Code);
        Assert.Contains("thread 77 (held at s1)", await _tools.LiveRead("live-1", thread: "77"));
    }

    [Fact]
    public async Task Events_refuse_an_unknown_kind_or_source_and_count_what_the_ring_dropped()
    {
        await _tools.LiveSession("attach", program: "4242");
        Assert.Equal(ErrorCode.InvalidArgument, (await Assert.ThrowsAsync<ToolError>(() => _tools.LiveEvents("live-1", kind: "stops"))).Code);
        Assert.Equal(ErrorCode.NotFound, (await Assert.ThrowsAsync<ToolError>(() => _tools.LiveEvents("live-1", from: "w1"))).Code);
        Assert.Equal(ErrorCode.InvalidArgument, (await Assert.ThrowsAsync<ToolError>(() => _tools.LiveEvents("live-1", cursor: "next"))).Code);
        await _tools.LiveWatchCalls("live-1", "set", at: "sqlite3_open");
        await _tools.LiveWatchCalls("live-1", "clear", watch: "w1");
        Assert.Contains("No events.", await _tools.LiveEvents("live-1", from: "w1")); // a cleared watch keeps its id
        for (int i = 1; i <= Services.LiveSession.RingCapacity + 50; i++) _backend.ScriptMessage("u1", new JsonObject { ["n"] = i });
        for (int i = 0; i < 100 && _service.Get("live-1").Dropped < 50; i++) await Task.Delay(20);
        var page = await _tools.LiveEvents("live-1", cursor: "1", limit: 1);
        Assert.Contains($"50 events dropped (ring capacity {Services.LiveSession.RingCapacity:N0})", page);
        Assert.Contains("#51 script", page);
    }

    [Fact]
    public async Task A_call_flood_keeps_the_output_and_marks_the_calls_it_dropped()
    {
        await _tools.LiveSession("attach", program: "4242");
        var s = _service.Get("live-1");
        long Call() => s.Add("call", 5, Base, "f()", source: "w1");
        var head = s.Sequence;
        for (int i = 0; i < 100; i++) Call();
        var output = s.Add("output", null, null, "stdout: total 42");
        for (int i = 0; i < Services.LiveSession.CallRingCapacity + 50; i++) Call();
        var exit = s.Add("exit", null, null, "exited");
        Assert.Equal(150, s.CallsDropped);

        var page = await _tools.LiveEvents("live-1", cursor: $"{head + 1}", limit: 3);
        Assert.Contains($"150 call events dropped (ring capacity {Services.LiveSession.CallRingCapacity:N0})", page);
        Assert.Contains($"#{output} output: stdout: total 42", page);
        Assert.Contains($"#{exit} exit", await _tools.LiveEvents("live-1", kind: "exit"));
        Assert.DoesNotContain("dropped", await _tools.LiveEvents("live-1", cursor: $"{output + 51}", limit: 3));
    }

    [Fact]
    public async Task A_missing_backend_names_its_next_step()
    {
        var service = new LiveSessionService(_workspace, new NativeCodeService(_workspace, SharedCodeIndex.Options())) { Backend = new ScriptedLiveBackend(Sqlite, Base, 1) { Missing = "no frida" } };
        var tools = new LiveSessionTools(new ServerOptions { AllowLive = true, AllowLiveAttach = true }, service);
        var e = await Assert.ThrowsAsync<ToolError>(() => tools.LiveSession("attach", program: "app"));
        Assert.Equal(ErrorCode.ProviderUnavailable, e.Code);
        Assert.Equal("install it", e.Remediation);
    }

    [Fact]
    public void An_open_that_timed_out_points_at_the_program()
    {
        Assert.Contains("did not load the session's agent in time", FridaBackend.Remediation(ErrorCode.Timeout, "open"));
        Assert.Null(FridaBackend.Remediation(ErrorCode.Timeout, "set"));
        Assert.Null(FridaBackend.Remediation(ErrorCode.Failed, "open"));
    }

    [Fact]
    public async Task The_heap_tools_take_a_session_and_name_why_its_program_has_no_heap_to_read()
    {
        using var dumps = new MinidumpService(_workspace);
        var off = await Assert.ThrowsAsync<ToolError>(() => new MinidumpTools(dumps, _service, new ServerOptions()).DumpHeap("live-1"));
        Assert.Contains("Sessions on running programs are off", off.Message);
        var tools = new MinidumpTools(dumps, _service, new ServerOptions { AllowLiveSpawn = true });
        await _tools.LiveSession("spawn", program: Sqlite);
        var heap = await Assert.ThrowsAsync<ToolError>(() => tools.DumpHeap("live-1"));
        Assert.Equal(ErrorCode.Unsupported, heap.Code);
        Assert.Contains("the program of session live-1 has loaded no .NET runtime", heap.Message);
        Assert.Contains("has loaded no .NET runtime", (await Assert.ThrowsAsync<ToolError>(() => tools.DumpObject("live-1", "0x1000"))).Message);
        await _tools.LiveSession("close", session: "live-1");
        Assert.Contains("The program of session live-1 has ended", (await Assert.ThrowsAsync<ToolError>(() => tools.DumpHeap("live-1"))).Message);
    }
}
