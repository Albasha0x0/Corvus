using System.Buffers.Binary;
using System.ComponentModel;
using System.Globalization;
using System.Text;
using ModelContextProtocol.Server;
using Corvus.Core;
using Corvus.Mcp;
using Corvus.Services;

namespace Corvus.Tools;

/// <summary>Sessions on local programs, observation only; refused without --allow-live; spawn and attach need their own flags, and --live-allow limits both to listed programs.</summary>
[McpServerToolType]
public sealed partial class LiveSessionTools(ServerOptions options, LiveSessionService live, MinidumpService? dumps = null, Services.Mobile.DexService? dex = null)
{
    private readonly Services.Mobile.DexService _dex = dex ?? new();

    private const string SessionDescription = "Session id from live_session.";

    /// <summary>A module of the observed program and the loaded image it matched (null when none did).</summary>
    public sealed record LiveModule(string Name, string Base, string? Image, string? Sha256);

    /// <summary>An address a result names, as saved records carry it for read_result format=verify.</summary>
    public sealed record LiveNamedAddress(string Image, string Sha256, string Rva, string Name);

    public sealed record LiveSessionRow(string Session, string Backend, string Program, int ProcessId, string State);

    public sealed record LiveProcessRow(int ProcessId, string Name)
    {
        [Description("children: held, attached (and its session), running or resumed.")]
        public string? State { get; init; }
    }

    /// <summary>A snapshot of the session's process as a dump file, opened for the dump tools.</summary>
    public sealed record LiveSnapshot(string Path, long Bytes, [property: Description("Id for dump_stack, read_dump_memory and the other dump tools.")] string Dump);

    public sealed record LiveSessionReport(string Action,
        [property: Description("Session id; null for action=list and processes.")] string? Session,
        string? Backend, string? Program, int? ProcessId,
        [property: Description("suspended, running, stopped, exited, closed or failed.")] string? State,
        IReadOnlyList<LiveModule> Modules, IReadOnlyList<LiveSessionRow> Sessions)
    {
        public IReadOnlyList<LiveProcessRow>? Processes { get; init; }
        public LiveSnapshot? Snapshot { get; init; }
        [Description("action=ipc: one line per route: direction, kind, channel, shape, count, code sites.")]
        public string? Ipc { get; init; }
    }

    public sealed record LiveStopPoint(string Id,
        [property: Description("As given: a name, module!export, address or file:line.")] string Where,
        [property: Description("Null unless set.")] string? Address, int Hits)
    {
        [Description("The jump followed, if any.")]
        public string? Followed { get; init; }
        [Description(StateDescription)]
        public string State { get; init; } = "set";
    }

    public sealed record LiveFrame(string Address, string? Image, string? Name, string? Source);

    public sealed record LiveStop(string Thread,
        [property: Description("stop point, exception, exit or pause.")] string Reason,
        string? StopPoint, IReadOnlyList<LiveFrame> Frames);

    public sealed record LiveStopPointReport(string Session, IReadOnlyList<LiveStopPoint> StopPoints, LiveStop? Stop)
    {
        public IReadOnlyList<LiveNamedAddress>? NamedAddresses { get; init; }
    }

    public sealed record LiveWatch(string Id,
        [property: Description("As given: a name, module!export or address.")] string Where,
        [property: Description("Null unless set.")] string? Address, string? Name,
        string? Prototype,
        [property: Description("known API table, PDB or DWARF prototype, DWARF names or raw values.")] string? Decoding,
        int RateLimit, long Calls,
        [property: Description("Calls over the rate limit, not recorded.")] long Skipped,
        double? CallsPerSecond)
    {
        [Description("The jump followed, if any.")]
        public string? Followed { get; init; }
        [Description(StateDescription)]
        public string State { get; init; } = "set";
    }

    public sealed record LiveWatchReport(string Session, IReadOnlyList<LiveWatch> Watches)
    {
        public IReadOnlyList<LiveNamedAddress>? NamedAddresses { get; init; }
    }

    private const string StateDescription = "set, deferred (until its module loads or method compiles) or failed (deferred, then not set).";

    public sealed record LiveScript(string Id, [property: Description("The source's file, or inline.")] string Source);

    public sealed record LiveScriptReport(string Session, IReadOnlyList<LiveScript> Scripts);

    public sealed record LiveValue(string Name, string Type, string Value, string? Address);

    public sealed record LiveReadReport(string Session, string Thread, IReadOnlyList<LiveValue> Registers, IReadOnlyList<LiveValue> Memory)
    {
        public IReadOnlyList<LiveNamedAddress>? NamedAddresses { get; init; }
    }

    public sealed record LiveEvent(long Sequence,
        [property: Description("UTC, ISO 8601.")] string Time,
        string Kind,
        string? Thread, string? Address, string? Name, string Text);

    public sealed record LiveEventPage(string Session, IReadOnlyList<LiveEvent> Items,
        [property: Description("Cursor for the next page; null at the end of the ring.")] string? Cursor,
        [property: Description("Events dropped from the cursor to this page's end, calls included.")] int Dropped)
    {
        public IReadOnlyList<LiveNamedAddress>? NamedAddresses { get; init; }
    }

    [McpServerTool(Name = "live_session", Title = "Session on a program", UseStructuredContent = true, OutputSchemaType = typeof(LiveSessionReport))]
    [Description("Open, list, inspect or close a session on a program: id, backend, modules matched to images; snapshot saves a dump.")]
    public Task<string> LiveSession(
        [Description("What to do.")] string action = "list",
        [Description("attach: pid, name, inspector:PORT, jdwp:PORT, ttd:PATH; spawn: program path (starts suspended); processes: name filter; *_child: pid.")] string? program = null,
        [Description("spawn: program arguments.")] string[]? arguments = null,
        [Description("spawn: NAME=value variables.")] string[]? environment = null,
        [Description(SessionDescription)] string? session = null,
        [Description("snapshot: dump file (default temp).")] string? outputPath = null,
        [Description("Overwrite outputPath.")] bool overwrite = false,
        [Description("Hold children by image name (* any) at start.")] string[]? childNames = null,
        [Description("Download a missing DAC.")] bool downloadDac = false,
        [Description("adb serial; device runs frida-server.")] string? device = null,
        CancellationToken cancellationToken = default) =>
        Task.Run(async () =>
        {
            var a = action.Trim().ToLowerInvariant();
            Require(spawn: a == "spawn", attach: a == "attach");
            switch (a)
            {
                case "list":
                    var rows = live.Sessions.Select(s => new LiveSessionRow(s.Id, s.Backend, s.Program, s.ProcessId, s.State)).ToList();
                    return ToolOutput.With(rows.Count == 0 ? "No sessions.\n"
                            : string.Concat(rows.Select(r => $"{r.Session} ({r.Backend}): {r.Program} pid {r.ProcessId}, {r.State}\n")),
                        new LiveSessionReport("list", null, null, null, null, null, [], rows));
                case "processes":
                    var procs = LocalProcesses(program);
                    return ToolOutput.With(procs.Count == 0 ? "No process matches.\n" : string.Concat(procs.Select(p => $"{p.ProcessId,7} {p.Name}\n")),
                        new LiveSessionReport("processes", null, null, null, null, null, [], []) { Processes = procs });
                case "attach" or "spawn":
                    if (string.IsNullOrWhiteSpace(program))
                        throw new ToolError(ErrorCode.InvalidArgument, $"action={a} needs program.", a == "spawn" ? "program=<path to the program>" : "program=<process id or name>");
                    if (a == "attach" && program.Trim() == "0" && OperatingSystem.IsWindows() && string.IsNullOrWhiteSpace(device)) throw LiveProcessService.IdleProcess();
                    if (Native.Providers.Live.Inspector.InspectorEndpoint.Is(program) || Native.Providers.Live.Jdwp.JdwpWorker.Is(program))
                        return Report(a, await OpenInspector(a, program, device, childNames, cancellationToken).ConfigureAwait(false));
                    var names = childNames?.Where(n => !string.IsNullOrWhiteSpace(n)).Select(n => n.Trim()).ToList();
                    if (names?.Contains("*") == true) names = [];
                    else if (names is { Count: 0 }) names = null;
                    var serial = string.IsNullOrWhiteSpace(device) ? null : device.Trim();
                    if (serial != null && options.LiveScope.Count > 0)
                        throw new ToolError(ErrorCode.AccessDenied, "--live-allow names folders on this machine, so device sessions are refused while it is set.",
                            $"ask the user to start the server with {ServerOptions.LiveAllowOption} {ServerOptions.LiveAllowAnyValue} (any program) to open a device session");
                    // A recording runs nothing, so --live-allow, which scopes running programs, does not apply.
                    var recording = Native.Providers.Live.Ttd.TtdWorker.Is(program);
                    if (a == "spawn" && serial != null) RequireStartList();
                    var opened = await live.OpenAsync(a == "spawn", serial != null || recording ? program : Scoped(a == "spawn", program), arguments ?? [], cancellationToken,
                        a == "spawn" ? environment : null, names, downloadDac: downloadDac, device: serial).ConfigureAwait(false);
                    return Report(a, opened);
                case "children":
                    return Report(a, live.Get(RequireSession(session)));
                case "attach_child" or "release_child":
                    var parent = live.Get(RequireSession(session));
                    var pid = ChildId(program);
                    if (options.LiveScope.Count > 0) LiveProgramScope.Attach(pid.ToString(CultureInfo.InvariantCulture), options.LiveScope);
                    if (a == "release_child")
                    {
                        await live.ReleaseChildAsync(parent, pid, cancellationToken).ConfigureAwait(false);
                        return Report(a, parent);
                    }
                    return Report(a, await live.AttachChildAsync(parent, pid, cancellationToken).ConfigureAwait(false));
                case "status":
                    var current = live.Get(RequireSession(session));
                    await live.RefreshModulesAsync(current, cancellationToken).ConfigureAwait(false);
                    return Report(a, current);
                case "snapshot":
                    return await Snapshot(live.Get(RequireSession(session)), outputPath, overwrite, cancellationToken).ConfigureAwait(false);
                case "ipc":
                    var recorded = live.Get(RequireSession(session));
                    return Ipc(recorded, await live.IpcAsync(recorded, cancellationToken).ConfigureAwait(false));
                case "close":
                    var closing = live.Get(RequireSession(session));
                    await live.CloseAsync(closing, "closed by request").ConfigureAwait(false);
                    return Report(a, closing);
                default:
                    throw new ToolError(ErrorCode.InvalidArgument, $"Unknown action '{action}'.", "action=list, processes, attach, spawn, status, snapshot, ipc, close, children, attach_child or release_child");
            }
        }, cancellationToken);

    // A program already running under its inspector or JDWP agent; --live-allow is checked against its process once it is known.
    private async Task<Services.LiveSession> OpenInspector(string action, string program, string? device, string[]? childNames, CancellationToken ct)
    {
        if (action != "attach" || !string.IsNullOrWhiteSpace(device) || childNames != null)
            throw new ToolError(ErrorCode.InvalidArgument, "An inspector or JDWP agent is attached to: start the program with it yourself, on this machine, without childNames.",
                "action=attach program=inspector:PORT (Node --inspect=PORT) or jdwp:PORT (java -agentlib:jdwp=transport=dt_socket,server=y,address=127.0.0.1:PORT)");
        var opened = await live.OpenAsync(false, program, [], ct).ConfigureAwait(false);
        if (options.LiveScope.Count == 0) return opened;
        try
        {
            if (opened.ProcessId <= 0) throw new ToolError(ErrorCode.AccessDenied, "The target names no process, so --live-allow cannot be checked.",
                $"ask the user to start the server with {ServerOptions.LiveAllowOption} {ServerOptions.LiveAllowAnyValue} (any program)");
            LiveProgramScope.Attach(opened.ProcessId.ToString(CultureInfo.InvariantCulture), options.LiveScope);
        }
        catch (ToolError)
        {
            await live.CloseAsync(opened, "outside --live-allow").ConfigureAwait(false);
            throw;
        }
        return opened;
    }

    // Each channel route seen with its count and shape, then the routes only the code names; values are never kept.
    private static string Ipc(Services.LiveSession s, LiveIpcLedger ledger)
    {
        var text = new StringBuilder($"{s.Id} IPC in the Electron main process of {ledger.App ?? "an unknown app path"}: ");
        text.AppendLine($"{ledger.Rows.Count(r => r.Count > 0)} route(s) seen, {ledger.Rows.Count(r => r.Count == 0)} named by the code only; {ledger.CodeRows} IPC site(s) read from the code");
        var lines = ledger.Rows.Select(r => r.Count > 0 ? $"{r.Direction} {r.Kind} {r.Channel} {r.Shape} x{r.Count}: {r.Code}" : $"{r.Direction} {r.Channel} not seen: {r.Code}").ToList();
        foreach (var l in lines) text.AppendLine("  " + l);
        if (ledger.Dropped > 0) text.AppendLine($"{ledger.Dropped} message(s) of new routes not kept (limit {Native.Providers.Live.Inspector.ElectronIpc.MaxKeys} routes)");
        text.AppendLine("Recorded since the first action=ipc; value shapes only, never values.");
        return ToolOutput.With(text.ToString(), new LiveSessionReport("ipc", s.Id, s.Backend, s.Program, s.ProcessId, s.State, [], []) { Ipc = string.Join('\n', lines) });
    }

    private async Task<string> Snapshot(Services.LiveSession s, string? outputPath, bool overwrite, CancellationToken ct)
    {
        LiveSessionService.Live(s);
        if (s.ScriptRuntime is { } runtime) throw new ToolError(ErrorCode.Unsupported, $"{s.Id} is a {runtime.Kind} session: a snapshot writes a native process dump.", $"live_session action=attach program={s.ProcessId} opens a process session");
        if (dumps == null) throw new ToolError(ErrorCode.Unsupported, "This server has no dump reader.", "open the dump file with open_minidump");
        if (s.Emulated)
            throw new ToolError(ErrorCode.Unsupported,
                $"Process {s.ProcessId} is an {(s.Arch == "x64" ? "x64" : "x86")} program emulated on an ARM64 machine: its dump would hold the emulator's ARM64 threads, not the program's registers.",
                "save a snapshot of an ARM64 build of the program, or of this one on an x64 machine");
        var path = string.IsNullOrWhiteSpace(outputPath)
            ? Native.Providers.PrivateFolder.Temp("snapshots", $"{s.Id}-{s.ProcessId}-{DateTime.UtcNow:yyyyMMdd-HHmmss-fff}{(OperatingSystem.IsWindows() ? ".dmp" : ".core")}")
            : outputPath;
        // A held thread waits inside the backend; its stop's registers let the stack walk start at the stop.
        Native.Diagnostics.ProcessSnapshot.Stop? stop = null;
        var held = s.Held.FirstOrDefault();
        // A macOS core keeps lldb's registers; an ARM64 stop is recorded in a Windows dump only (a Linux core's NT_PRSTATUS is not rewritten).
        if (held != null && !OperatingSystem.IsMacOS() && (s.Arch is "x64" or "ia32" || s.Arch == "arm64" && OperatingSystem.IsWindows()))
        {
            var registers = new Dictionary<string, ulong>(StringComparer.OrdinalIgnoreCase);
            foreach (var (name, value) in held.Registers)
                if (ulong.TryParse(value.StartsWith("0x", StringComparison.OrdinalIgnoreCase) ? value[2..] : value, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out var v))
                    registers[name] = v;
            var (pc, sp) = s.Arch switch { "x64" => ("rip", "rsp"), "arm64" => ("pc", "sp"), _ => ("eip", "esp") };
            if (registers.ContainsKey(pc) && registers.ContainsKey(sp))
                stop = new((int)held.Thread, s.Arch, registers);
        }
        var bytes = Native.Diagnostics.ProcessSnapshot.Write(s.ProcessId, path, overwrite, ct, stop);
        var full = Path.GetFullPath(path);
        var report = await dumps.Summarize(full, null, ct).ConfigureAwait(false);
        var text = $"{s.Id}: process {s.ProcessId} written to {full} ({bytes:N0} bytes), opened as {report.Id}; the program keeps running\n" +
                   (stop != null ? $"the stop of thread {stop.ThreadId} at {held!.Point} is {(OperatingSystem.IsWindows() ? "the dump's exception (a breakpoint)" : "the core's signal (SIGTRAP), with the stop's registers")}; dump_stack walks from it\n" : "") +
                   $"next: open_minidump path={report.Id} view=threads, dump_stack dump={report.Id}\n";
        return ToolOutput.With(text, new LiveSessionReport("snapshot", s.Id, s.Backend, s.Program, s.ProcessId, s.State, [], []) { Snapshot = new LiveSnapshot(full, bytes, report.Id) });
    }

    /// <summary>Local processes by name (then id), those whose name contains <paramref name="filter"/> when given.</summary>
    private static List<LiveProcessRow> LocalProcesses(string? filter)
    {
        var rows = new List<LiveProcessRow>();
        foreach (var p in System.Diagnostics.Process.GetProcesses())
            using (p)
            {
                string name;
                // Process 0 is the System Idle Process, never a program to attach to.
                if (p.Id == 0) continue;
                try { name = p.ProcessName; }
                catch (InvalidOperationException) { continue; } // exited meanwhile
                if (string.IsNullOrWhiteSpace(filter) || name.Contains(filter.Trim(), StringComparison.OrdinalIgnoreCase)) rows.Add(new LiveProcessRow(p.Id, name));
            }
        return rows.OrderBy(r => r.Name, StringComparer.OrdinalIgnoreCase).ThenBy(r => r.ProcessId).ToList();
    }

    // A script session's own scripts, each with the map it names; the runtime's internal scripts are counted only.
    private static void Scripts(Services.LiveScriptRuntime js, StringBuilder text)
    {
        const int Shown = 100;
        if (js.Jvm)
        {
            Jvm(js, text);
            return;
        }
        List<Services.LiveScriptState> all;
        lock (js.Scripts) all = [.. js.Scripts.Values];
        var own = all.Where(s => s.Url.Length > 0 && !s.Url.StartsWith("node:", StringComparison.Ordinal)).OrderBy(s => s.Url, StringComparer.Ordinal).ToList();
        text.AppendLine($"inspector target {js.Target}{(js.Runtime != null ? $", {js.Runtime}" : "")}");
        text.AppendLine($"{all.Count} scripts, {own.Count} of the program, {own.Count(s => s.MapUrl != null)} naming a source map:");
        foreach (var s in own.Take(Shown))
            text.AppendLine($"  {s.Url}{(s.MapUrl == null ? "" : s.Map != null ? $"  map: {s.Map.Sources.Count} source(s)" : s.MapNote != null ? $"  map: {s.MapNote}" : "  map named")}");
        if (own.Count > Shown) text.AppendLine($"  ... {own.Count - Shown} more");
    }

    // A JVM's classes by source file, then every thread with its state and stack.
    private static void Jvm(Services.LiveScriptRuntime js, StringBuilder text)
    {
        const int Frames = 16;
        List<Services.LiveScriptState> classes;
        lock (js.Scripts) classes = [.. js.Scripts.Values];
        var files = classes.Select(c => c.Url).Distinct(StringComparer.Ordinal).Order(StringComparer.Ordinal).ToList();
        text.AppendLine($"JVM at {js.Target}{(js.Runtime != null ? $", {js.Runtime}" : "")}");
        text.AppendLine($"{classes.Count} classes of the program (JDK classes left out) from {files.Count} source file(s):");
        foreach (var f in files.Take(100)) text.AppendLine("  " + f);
        if (files.Count > 100) text.AppendLine($"  ... {files.Count - 100} more");
        text.AppendLine($"{js.Threads.Count} threads:");
        foreach (var t in js.Threads)
        {
            text.AppendLine($"  thread {t.Id} \"{t.Name}\" {t.Status}{(t.Held ? ", held at a stop point" : "")}, {t.Depth} frame(s)");
            for (int i = 0; i < Math.Min(Frames, t.Frames.Count); i++) text.AppendLine($"    #{i} {t.Frames[i].Display}");
            if (t.Depth > Frames) text.AppendLine($"    ... {t.Depth - Frames} more");
        }
    }

    private static int ChildId(string? program) =>
        int.TryParse(program?.Trim(), NumberStyles.None, CultureInfo.InvariantCulture, out var pid) && pid > 0 ? pid
            : throw new ToolError(ErrorCode.InvalidArgument, "This action needs the child's process id as program.", "program=<pid from live_session action=children>");

    private static string RequireSession(string? session) =>
        string.IsNullOrWhiteSpace(session) ? throw new ToolError(ErrorCode.InvalidArgument, "This action needs session.", "session=<id from live_session action=list>") : session;

    private static string Report(string action, Services.LiveSession s)
    {
        List<LiveModuleState> modules;
        lock (s.Modules) modules = s.Modules.ToList();
        var rows = modules.Select(m => new LiveModule(m.Name, Hex(m.Base), m.Image?.Id ?? m.Assembly?.Id, m.Image?.OriginalSha256 ?? m.Assembly?.OriginalSha256)).ToList();
        var text = new StringBuilder($"{s.Id} ({s.Backend}): {s.Program} pid {s.ProcessId}, {s.State}");
        if (s.Ended != null) text.Append($" ({s.Ended})");
        else if (s.Closed) text.Append($" (session closed ({s.CloseReason}))"); // the close is still ending the worker
        if (s.State == "suspended") text.Append("; set stop points, then live_break action=continue starts it");
        if (s.HeldBy != null && s.State == "suspended") text.Append($" (held by {s.HeldBy.Id})");
        text.AppendLine();
        List<LiveProcessRow>? children = null;
        if (s.ChildNames != null)
        {
            // A child's row: its command line, and its state with the session attached to it.
            lock (s.Children)
                children = s.Children.Select(c => new LiveProcessRow(c.ProcessId, c.CommandLine) { State = c.State + (c.Session != null ? " in " + c.Session : "") }).ToList();
            text.AppendLine($"follows child processes{(s.ChildNames.Count > 0 ? " named " + string.Join(", ", s.ChildNames) : "")}: {children.Count} started, {children.Count(c => c.State == "held")} held");
            foreach (var c in children) text.AppendLine($"  pid {c.ProcessId} {c.State}: {c.Name}");
            foreach (var (pid, name) in Services.LiveSessionService.StartedForProgram(s))
            {
                children.Add(new LiveProcessRow(pid, name) { State = "started by another process" });
                text.AppendLine($"  pid {pid} started by another process, not held: {name} (live_session action=attach program={pid})");
            }
        }
        if (s.ScriptRuntime is { } js) Scripts(js, text);
        else if (action != "children")
        {
            text.AppendLine($"{rows.Count} modules, {rows.Count(r => r.Image != null)} matched to loaded images:");
            foreach (var (m, state) in rows.Zip(modules))
                text.AppendLine($"  {m.Base} {m.Name}{(m.Image != null ? "  = " + m.Image + (state.Image == null ? " (assembly)" : "") : "")}");
        }
        else if (children == null) text.AppendLine("does not follow child processes: open the session with childNames=[\"*\"]");
        return ToolOutput.With(text.ToString(), new LiveSessionReport(action, s.Id, s.Backend, s.Program, s.ProcessId, s.State, action == "children" ? [] : rows, []) { Processes = children });
    }

    [McpServerTool(Name = "live_break", Title = "Stop points in a session", UseStructuredContent = true, OutputSchemaType = typeof(LiveStopPointReport))]
    [Description("Set, list or clear stop points; continue resumes held threads; wait returns the next stop with a named stack.")]
    public Task<string> LiveBreak(
        [Description(SessionDescription)] string session,
        [Description("What to do.")] string action = "list",
        [Description("set: name, module!export, address or file:line.")] string? at = null,
        [Description("clear: stop point id.")] string? stopPoint = null,
        [Description("continue: thread id; default all.")] string? thread = null,
        [Description("Wait for the next stop.")] bool wait = false,
        [Description("wait: seconds (1-300).")] int waitSeconds = 30,
        CancellationToken cancellationToken = default) =>
        Task.Run(async () =>
        {
            Require(spawn: false);
            var s = live.Get(session);
            var a = action.Trim().ToLowerInvariant();
            var head = new StringBuilder();
            switch (a)
            {
                case "list":
                    break;
                case "set":
                    LiveSessionService.Live(s);
                    if (string.IsNullOrWhiteSpace(at)) throw new ToolError(ErrorCode.InvalidArgument, "action=set needs at.", "at=<name>, module!export, file:line or 0xADDRESS");
                    if (await live.DeferAsync(s, at, watch: false, ct: cancellationToken).ConfigureAwait(false) is { } deferred)
                    {
                        head.AppendLine(Deferred(deferred));
                        break;
                    }
                    var point = await live.SetAsync(s, at, cancellationToken).ConfigureAwait(false);
                    head.AppendLine(point.Script != null ? $"{point.Id} set at {point.Script}"
                        : $"{point.Id} set at {Hex(point.Address)} {point.At.Display}{Src(point.At.Source)}{(point.Followed != null ? $" ({point.Followed})" : "")}");
                    break;
                case "clear":
                    LiveSessionService.Live(s);
                    if (string.IsNullOrWhiteSpace(stopPoint)) throw new ToolError(ErrorCode.InvalidArgument, "action=clear needs stopPoint.", "stopPoint=<id from action=list>");
                    if (!LiveSessionService.ClearDeferred(s, stopPoint.Trim())) await live.ClearAsync(s, stopPoint.Trim(), cancellationToken).ConfigureAwait(false);
                    head.AppendLine($"{stopPoint.Trim()} cleared");
                    break;
                case "continue":
                    var (resumed, started) = await live.ResumeAsync(s, ThreadId(thread), cancellationToken).ConfigureAwait(false);
                    head.AppendLine(started ? "program started" + (resumed.Count > 0 ? $"; resumed {resumed.Count} thread(s)" : "")
                        : resumed.Count == 0 ? "no thread was held" + (s.State == "suspended" ? "; the program is still suspended: continue without thread starts it" : "")
                        : $"resumed thread(s) {string.Join(", ", resumed)}");
                    break;
                default:
                    throw new ToolError(ErrorCode.InvalidArgument, $"Unknown action '{action}'.", "action=list, set, clear or continue");
            }
            LiveStop? stop = null;
            var named = new List<EvidenceName>();
            if (wait)
            {
                var held = await s.NextStopAsync(TimeSpan.FromSeconds(Math.Clamp(waitSeconds, 1, 300)), cancellationToken).ConfigureAwait(false);
                if (held == null)
                    head.AppendLine(s.Ended is { } ended ? $"the program ended before a stop ({ended})"
                        : s.Closed ? "the session closed before a stop"
                        : $"no stop within {Math.Clamp(waitSeconds, 1, 300)} s; the session is {s.State}");
                else if (held.ScriptFrames != null) stop = ScriptStop(held, await live.ScriptFramesAsync(s, held, cancellationToken).ConfigureAwait(false), head);
                else
                {
                    await live.FrameModulesAsync(s, held, cancellationToken).ConfigureAwait(false);
                    await live.IndexedAsync(s, TimeSpan.FromSeconds(15), cancellationToken).ConfigureAwait(false);
                    await live.ClrAsync(s, cancellationToken).ConfigureAwait(false);
                    stop = Stop(s, held, head, named, cancellationToken);
                    if (s.Device != null) await JavaFrames(s, held, head, cancellationToken).ConfigureAwait(false);
                }
            }
            var next = Dropped(s, head, watch: false, out var failedPoints);
            List<LiveStopPointState> points;
            lock (s.StopPoints) points = s.StopPoints.Values.OrderBy(p => int.Parse(p.Id[1..], CultureInfo.InvariantCulture)).ToList();
            List<LiveDeferred> deferredPoints;
            lock (s.Deferred) deferredPoints = s.Deferred.Where(d => !d.Watch).ToList();
            head.AppendLine($"{s.Id}: {s.State}, {points.Count} stop point(s){(deferredPoints.Count > 0 ? $", {deferredPoints.Count} deferred" : "")}{(failedPoints.Count > 0 ? $", {failedPoints.Count} failed" : "")}");
            foreach (var p in points) head.AppendLine($"  {p.Id} {p.Where} at {p.Script ?? $"{Hex(p.Address)} {p.At.Display}"}, {p.Hits} hit(s)");
            foreach (var d in deferredPoints) head.AppendLine($"  {d.Id} {d.Where}: {Until(d)}");
            foreach (var d in failedPoints) head.AppendLine($"  {d.Id} {d.Where}: failed ({d.Because}): {d.Reason}");
            if (next != null) head.AppendLine($"Next: {next}");
            named.AddRange(points.Select(p => p.At.Named).OfType<EvidenceName>());
            var rows = points.Select(p => new LiveStopPoint(p.Id, p.Where, p.Script != null ? null : Hex(p.Address), p.Hits) { Followed = p.Followed })
                .Concat(deferredPoints.Select(d => new LiveStopPoint(d.Id, d.Where, null, 0) { State = "deferred" }))
                .Concat(failedPoints.Select(d => new LiveStopPoint(d.Id, d.Where, null, 0) { State = "failed" })).ToList();
            return ToolOutput.With(head.ToString(), new LiveStopPointReport(s.Id, rows, stop) { NamedAddresses = Named(named) });
        }, cancellationToken);

    private LiveStop Stop(Services.LiveSession s, LiveHeldStop held, StringBuilder text, List<EvidenceName> named, CancellationToken ct)
    {
        var frames = live.StopFrames(s, held).Select((f, i) => live.Name(s, f, returnAddress: i > 0, ct)).ToList();
        named.AddRange(frames.Select(f => f.Named).OfType<EvidenceName>());
        text.AppendLine($"thread {held.Thread} stopped at {held.Point} ({frames.FirstOrDefault()?.Display ?? "?"})");
        for (int i = 0; i < frames.Count; i++) text.AppendLine($"  #{i} {Hex(frames[i].Address)} {frames[i].Display}{Src(frames[i].Source)}");
        return new LiveStop(held.Thread.ToString(CultureInfo.InvariantCulture), "stop point", held.Point,
            frames.Select(f => new LiveFrame(Hex(f.Address), f.Image?.Id ?? f.Module, f.Module == null ? null : f.Display, f.Source)).ToList()); // module+offset when no image is loaded
    }

    // A script frame has no address: Address names its script position, Name its function, Source its original position.
    private static LiveStop ScriptStop(LiveHeldStop held, IReadOnlyList<Services.LiveScriptFrame> frames, StringBuilder text)
    {
        text.AppendLine($"{(held.Thread != 1 ? $"thread {held.Thread} " : "")}stopped at {held.Point} ({frames.FirstOrDefault()?.Display ?? "?"})");
        for (int i = 0; i < frames.Count; i++) text.AppendLine($"  #{i} {frames[i].Display}");
        return new LiveStop(held.Thread.ToString(CultureInfo.InvariantCulture), held.Point.StartsWith('s') ? "stop point" : "pause", held.Point,
            [.. frames.Select(f => new LiveFrame(f.Position, f.Script, f.Function.Length > 0 ? f.Function : null, f.Original))]);
    }

    // Java frames are text only: the structured stop keeps the native stack.
    private async Task JavaFrames(Services.LiveSession s, LiveHeldStop held, StringBuilder text, CancellationToken ct)
    {
        var (java, unknown) = await live.JavaStackAsync(s, held.Thread, ct).ConfigureAwait(false);
        if (java == null)
        {
            text.AppendLine($"Java frames unknown: {unknown}");
            return;
        }
        text.AppendLine($"Java frames (ART, thread \"{java.Name}\", {java.State}): {java.Frames.Count}");
        var indexes = DexIndexes(s, java.ClassPath, text, ct);
        for (int i = 0; i < java.Frames.Count; i++)
        {
            var f = java.Frames[i];
            var match = indexes.Select(x => ArtStacks.Match(x, f)).FirstOrDefault(m => m != null);
            text.AppendLine($"  j{i} {f.Method}{Src(f.Source)}" + (match == null ? "" : $" = {match.Descriptor}" + (match.DexPc is { } pc ? $" dex pc {pc:x4}" : "")));
        }
    }

    // The class loaders' packages, pulled once per server; frames in them name their method for disassemble_dex.
    private List<Services.Mobile.DexIndex> DexIndexes(Services.LiveSession s, IReadOnlyList<string> classPath, StringBuilder text, CancellationToken ct)
    {
        var indexes = new List<Services.Mobile.DexIndex>();
        foreach (var file in classPath)
        {
            string? why = null;
            if (s.Device is not { } serial || live.DeviceCopy(serial, file) is not { } copy) why = "not pulled";
            else
                try
                {
                    indexes.Add(_dex.Index(copy, ct));
                    text.AppendLine($"DEX: {file} = {copy}");
                }
                catch (ToolError e) { why = e.Message; }
            if (why != null) text.AppendLine($"DEX unknown: {file} ({why})");
        }
        return indexes;
    }

    [McpServerTool(Name = "live_watch", Title = "Record calls in a session", UseStructuredContent = true, OutputSchemaType = typeof(LiveWatchReport))]
    [Description("Record each call of a function with arguments and result, decoded by prototype or known API, as events (live_events from=WATCH).")]
    public Task<string> LiveWatchCalls(
        [Description(SessionDescription)] string session,
        [Description("What to do.")] string action = "list",
        [Description("set: name, module!export or address.")] string? at = null,
        [Description("clear: watch id.")] string? watch = null,
        [Description("set: calls/s recorded (1-100000); the rest are counted.")] int rateLimit = 10_000,
        [Description("set: raw values without a prototype (0-16).")] int arguments = LiveWatchPlans.DefaultRawArguments,
        CancellationToken cancellationToken = default) =>
        Task.Run(async () =>
        {
            Require(spawn: false);
            var s = live.Get(session);
            var head = new StringBuilder();
            var next = Dropped(s, head, watch: true, out var failedWatches);
            switch (action.Trim().ToLowerInvariant())
            {
                case "list":
                    break;
                case "set":
                    LiveSessionService.Live(s);
                    if (string.IsNullOrWhiteSpace(at)) throw new ToolError(ErrorCode.InvalidArgument, "action=set needs at.", "at=<name>, module!export or 0xADDRESS");
                    if (await live.DeferAsync(s, at, watch: true, Math.Clamp(rateLimit, 1, 100_000), arguments, cancellationToken).ConfigureAwait(false) is { } deferred)
                    {
                        head.AppendLine(Deferred(deferred));
                        break;
                    }
                    var w = await live.WatchAsync(s, at, Math.Clamp(rateLimit, 1, 100_000), arguments, cancellationToken).ConfigureAwait(false);
                    head.AppendLine($"{w.Id} set at {Hex(w.Address)} {w.At.Display}: {w.Plan.Prototype} ({w.Plan.Source}); at most {w.PerSecond:N0} calls/s recorded{(w.Followed != null ? $" ({w.Followed})" : "")}");
                    break;
                case "clear":
                    LiveSessionService.Live(s);
                    if (string.IsNullOrWhiteSpace(watch)) throw new ToolError(ErrorCode.InvalidArgument, "action=clear needs watch.", "watch=<id from action=list>");
                    if (!LiveSessionService.ClearDeferred(s, watch.Trim())) await live.UnwatchAsync(s, watch.Trim(), cancellationToken).ConfigureAwait(false);
                    head.AppendLine($"{watch.Trim()} cleared");
                    break;
                default:
                    throw new ToolError(ErrorCode.InvalidArgument, $"Unknown action '{action}'.", "action=list, set or clear");
            }
            List<LiveWatchState> watches;
            lock (s.Watches) watches = s.Watches.Values.Where(x => !x.Cleared || x.Id == watch?.Trim()).OrderBy(x => int.Parse(x.Id[1..], CultureInfo.InvariantCulture)).ToList();
            head.AppendLine($"{s.Id}: {s.State}, {watches.Count(x => !x.Cleared)} watch(es)");
            var rows = new List<LiveWatch>();
            foreach (var x in watches.Where(x => !x.Cleared))
            {
                long calls, skipped;
                double? rate;
                lock (x) (calls, skipped, rate) = (x.Calls, x.Skipped, x.Rate);
                rows.Add(new LiveWatch(x.Id, x.Where, Hex(x.Address), x.At.Function == null ? null : x.At.Display, x.Plan.Prototype, x.Plan.Source, x.PerSecond, calls, skipped,
                    rate is { } r ? Math.Round(r) : null) { Followed = x.Followed });
                head.AppendLine($"  {x.Id} {x.At.Display}: {calls:N0} call(s) recorded{(rate is { } r2 ? $" ({r2:N0}/s)" : "")}{(skipped > 0 ? $", {skipped:N0} over the rate limit" : "")}; {x.Plan.Prototype} ({x.Plan.Source})");
            }
            List<LiveDeferred> deferredWatches;
            lock (s.Deferred) deferredWatches = s.Deferred.Where(d => d.Watch).ToList();
            foreach (var d in deferredWatches) head.AppendLine($"  {d.Id} {d.Where}: {Until(d)}");
            foreach (var d in failedWatches) head.AppendLine($"  {d.Id} {d.Where}: failed ({d.Because}): {d.Reason}");
            if (rows.Count > 0) head.AppendLine($"calls: live_events from={rows[0].Id}");
            if (next != null) head.AppendLine($"Next: {next}");
            rows.AddRange(deferredWatches.Select(d => new LiveWatch(d.Id, d.Where, null, null, null, null, d.PerSecond, 0, 0, null) { State = "deferred" }));
            rows.AddRange(failedWatches.Select(d => new LiveWatch(d.Id, d.Where, null, null, null, null, 0, 0, 0, null) { State = "failed" }));
            var named = watches.Select(x => x.At.Named).OfType<EvidenceName>().ToList();
            return ToolOutput.With(head.ToString(), new LiveWatchReport(s.Id, rows) { NamedAddresses = Named(named) });
        }, cancellationToken);

    [McpServerTool(Name = "live_script", Title = "User script in a session", UseStructuredContent = true, OutputSchemaType = typeof(LiveScriptReport))]
    [Description("Load, list or unload your Frida script in a session's program; its messages are events (live_events from=SCRIPT). Needs --live-scripting.")]
    public Task<string> LiveScriptCalls(
        [Description(SessionDescription)] string session,
        [Description("What to do.")] string action = "list",
        [Description("load: JavaScript source.")] string? source = null,
        [Description("load: a .js file instead.")] string? path = null,
        [Description("unload: script id.")] string? script = null,
        CancellationToken cancellationToken = default) =>
        Task.Run(async () =>
        {
            Require(spawn: false);
            if (!options.LiveScripting)
                throw new ToolError(ErrorCode.Unsupported, "User scripts in sessions are off in this server: a script runs inside the observed program with its rights.",
                    $"ask the user to start the server with {ServerOptions.LiveScriptingOption} (or {ServerOptions.LiveScriptingVariable}=1) as well");
            var s = live.Get(session);
            var head = new StringBuilder();
            switch (action.Trim().ToLowerInvariant())
            {
                case "list":
                    break;
                case "load":
                    if (string.IsNullOrWhiteSpace(source) == string.IsNullOrWhiteSpace(path))
                        throw new ToolError(ErrorCode.InvalidArgument, "action=load needs source or path (one of them).", "source=<JavaScript> or path=<script.js>");
                    string origin = "inline", text = source ?? "";
                    if (!string.IsNullOrWhiteSpace(path))
                    {
                        origin = InputFiles.RequireRegularFile(path);
                        if (new FileInfo(origin).Length > MaxScriptBytes)
                            throw new ToolError(ErrorCode.LimitExceeded, $"{origin} is over {MaxScriptBytes / 1024 / 1024} MB.", "load a smaller script");
                        text = await File.ReadAllTextAsync(origin, cancellationToken).ConfigureAwait(false);
                    }
                    else if (Encoding.UTF8.GetByteCount(text) > MaxScriptBytes)
                        throw new ToolError(ErrorCode.LimitExceeded, $"The source is over {MaxScriptBytes / 1024 / 1024} MB.", "load a smaller script");
                    var (id, error) = await live.LoadScriptAsync(s, text, origin, cancellationToken).ConfigureAwait(false);
                    head.AppendLine($"{id} loaded ({origin}); its messages: live_events from={id}");
                    if (error != null) head.AppendLine($"{id} reported {error}");
                    break;
                case "unload":
                    if (string.IsNullOrWhiteSpace(script)) throw new ToolError(ErrorCode.InvalidArgument, "action=unload needs script.", "script=<id from action=list>");
                    await live.UnloadScriptAsync(s, script.Trim(), cancellationToken).ConfigureAwait(false);
                    head.AppendLine($"{script.Trim()} unloaded");
                    break;
                default:
                    throw new ToolError(ErrorCode.InvalidArgument, $"Unknown action '{action}'.", "action=list, load or unload");
            }
            List<LiveScript> rows;
            lock (s.Scripts) rows = s.Scripts.OrderBy(x => int.Parse(x.Key[1..], CultureInfo.InvariantCulture)).Select(x => new LiveScript(x.Key, x.Value)).ToList();
            head.AppendLine($"{s.Id}: {s.State}, {rows.Count} script(s)");
            foreach (var r in rows) head.AppendLine($"  {r.Id} {r.Source}");
            return ToolOutput.With(head.ToString(), new LiveScriptReport(s.Id, rows));
        }, cancellationToken);

    private const int MaxScriptBytes = 1 << 20;

    [McpServerTool(Name = "live_read", Title = "Read a stopped thread", UseStructuredContent = true, OutputSchemaType = typeof(LiveReadReport))]
    [Description("Read a held thread's registers and program memory as typed values, named through the loaded images.")]
    public Task<string> LiveRead(
        [Description(SessionDescription)] string session,
        [Description("Thread id; default the first held.")] string? thread = null,
        [Description("Register names, comma-separated; default all.")] string? registers = null,
        [Description("An address, register or name to read.")] string? memory = null,
        [Description("memory: int8..uint64, float, double, pointer, cstring, utf16; [n] for arrays.")] string? type = null,
        [Description("memory: untyped bytes, or a string's limit (max 4096).")] int? length = null,
        [Description(RulesDescription)] string? rules = null,
        CancellationToken cancellationToken = default) =>
        Task.Run(async () =>
        {
            Require(spawn: false);
            var s = live.Get(session);
            LiveSessionService.Live(s);
            if (rules != null)
            {
                if (thread != null || registers != null || memory != null || type != null || length != null)
                    throw new ToolError(ErrorCode.InvalidArgument, "rules scans the whole program's writable memory; it takes no thread, registers, memory, type or length.",
                        "live_read session=<id> rules=<rules>");
                return await ScanAsync(s, rules, cancellationToken).ConfigureAwait(false);
            }
            var heldAll = s.Held;
            var tid = ThreadId(thread);
            var held = tid == null ? heldAll.FirstOrDefault() : heldAll.FirstOrDefault(h => h.Thread == tid);
            if (tid != null && held == null)
                throw new ToolError(ErrorCode.NotFound, $"Thread {tid} is not held at a stop point.", "live_break wait=true returns the next stop; registers are read from held threads");
            var text = new StringBuilder();
            var named = new List<EvidenceName>();
            var regs = new List<LiveValue>();
            if (held != null && (memory == null || registers != null)) // a memory read shows registers only when asked
            {
                var wanted = registers?.Trim().Equals("all", StringComparison.OrdinalIgnoreCase) == true ? null
                    : registers?.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).ToHashSet(StringComparer.OrdinalIgnoreCase);
                text.AppendLine($"thread {held.Thread} (held at {held.Point})");
                foreach (var (name, value) in held.Registers)
                {
                    if (wanted != null && !wanted.Contains(name)) continue;
                    var at = Number(value) is { } v ? live.Name(s, v, ct: cancellationToken) : null;
                    if (at?.Named is { } n) named.Add(n);
                    var where = at?.Module != null ? at.Display : null;
                    regs.Add(new LiveValue(name, "pointer", value, where));
                    text.AppendLine($"  {name,-4} {value}{(where != null ? "  " + where : "")}");
                }
                if (wanted != null && wanted.Except(held.Registers.Keys, StringComparer.OrdinalIgnoreCase).ToList() is { Count: > 0 } unknown)
                    throw new ToolError(ErrorCode.InvalidArgument, $"No register {string.Join(", ", unknown)} on {s.Arch}.", $"registers from: {string.Join(", ", held.Registers.Keys)}");
            }
            else if (memory == null)
                throw new ToolError(ErrorCode.InvalidArgument, "No thread is held, so there are no registers to read.", "pass memory=<address>, or live_break wait=true for a stop");
            else if (registers != null) text.AppendLine("no thread is held: registers are read from threads held at a stop point");
            var values = new List<LiveValue>();
            if (memory != null)
            {
                var address = held != null && held.Registers.TryGetValue(memory.Trim(), out var reg) && Number(reg) is { } r ? r
                    : await live.ResolveAsync(s, memory, cancellationToken, data: true).ConfigureAwait(false);
                var (kind, size, count) = ParseType(type, length, s.Arch is "ia32" or "arm" ? 4 : 8);
                string? cut = null;
                byte[] bytes;
                if (kind is "cstring" or "utf16")
                {
                    (bytes, cut) = await ReadStringAsync(s, address, kind == "utf16", size, cancellationToken).ConfigureAwait(false);
                    size = bytes.Length;
                }
                else bytes = await live.ReadAsync(s, address, size * count, cancellationToken).ConfigureAwait(false) ?? throw Unreadable(address);
                var at = live.Name(s, address, ct: cancellationToken);
                if (at.Named is { } n) named.Add(n);
                text.AppendLine($"{Hex(address)}{(at.Module != null ? " " + at.Display : "")}: {kind}{(type != null && count > 1 ? $"[{count}]" : "")}");
                // Untyped bytes go in rows, so a page too small for the whole read keeps its first rows.
                if (kind == "bytes" && bytes.Length > BytesPerRow) (size, count) = (BytesPerRow, (bytes.Length + BytesPerRow - 1) / BytesPerRow);
                for (int i = 0; i < count; i++)
                    if (kind == "bytes" && count > 1)
                    {
                        var row = Convert.ToHexStringLower(bytes.AsSpan(i * size, Math.Min(size, bytes.Length - i * size)));
                        values.Add(new LiveValue($"{memory.Trim()}+0x{i * size:X}", kind, row, Hex(address + (ulong)(i * size))));
                        text.AppendLine($"  +0x{i * size:X3} {row}");
                    }
                    else
                {
                    var v = Decode(kind, bytes.AsSpan(i * size, size)) + (cut != null ? $" (cut: {cut})" : "");
                    var name = count == 1 ? memory.Trim() : $"{memory.Trim()}[{i}]";
                    values.Add(new LiveValue(name, kind, v, Hex(address + (ulong)(i * size))));
                    text.AppendLine(count == 1 ? $"  {v}" : $"  [{i}] {v}");
                }
            }
            return ToolOutput.With(text.ToString(), new LiveReadReport(s.Id, held?.Thread.ToString(CultureInfo.InvariantCulture) ?? "", regs, values) { NamedAddresses = Named(named) });
        }, cancellationToken);

    private const int BytesPerRow = 256;

    private const string RulesDescription = "YARA rules (text, file, folder, pack:name) to scan writable memory.";

    /// <summary>Rule matches listed by a live scan; the count covers them all.</summary>
    private const int MaxScanRows = 500;

    /// <summary>live_read rules=: each rule that matched, at its first match's address named through the images, its patterns' matches in the value.</summary>
    private async Task<string> ScanAsync(Services.LiveSession s, string rules, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(rules)) throw new ToolError(ErrorCode.InvalidArgument, "rules is empty.", "pass rule text, a .yar file or folder, or pack:<name>");
        var scan = await live.ScanMemoryAsync(s, rules, ct).ConfigureAwait(false);
        var matches = scan.Result.Hits.SelectMany(h => h.Rules.Select(r => (h.Path, Rule: r))).ToList();
        var text = new StringBuilder($"{s.Id}: {matches.Count:N0} rule match(es) in {scan.Result.Regions:N0} memory regions\n");
        var rows = new List<LiveValue>();
        var named = new List<EvidenceName>();
        foreach (var (path, rule) in matches.Take(MaxScanRows))
        {
            var name = rule.Namespace is "default" or "" ? rule.Rule : $"{rule.Namespace}:{rule.Rule}";
            var detail = Services.Analysis.YaraSearchKind.Detail(rule) ?? "";
            string? where = path;
            if (rule.Patterns.Count > 0)
            {
                var at = (ulong)rule.Patterns.Min(p => p.Offset);
                var place = live.Name(s, at, ct: ct);
                if (place.Named is { } n) named.Add(n);
                where = Hex(at) + (place.Module != null ? " " + place.Display : "");
            }
            rows.Add(new LiveValue(name, "yara", detail, where));
            text.AppendLine($"  {name} at {where}{(detail.Length > 0 ? ": " + detail : "")}");
        }
        if (matches.Count > MaxScanRows) text.AppendLine($"{matches.Count - MaxScanRows:N0} more matches not listed (at most {MaxScanRows:N0}).");
        foreach (var note in Services.Analysis.YaraSearchKind.Notes(scan.Result, scan.FromQuery).Concat(scan.Notes)) text.AppendLine("Note: " + note);
        return ToolOutput.With(text.ToString(), new LiveReadReport(s.Id, "", [], rows) { NamedAddresses = Named(named) });
    }

    private static readonly Dictionary<string, int> Sizes = new(StringComparer.Ordinal)
    {
        ["int8"] = 1, ["uint8"] = 1, ["int16"] = 2, ["uint16"] = 2, ["int32"] = 4, ["uint32"] = 4, ["int64"] = 8, ["uint64"] = 8,
        ["float"] = 4, ["double"] = 8,
    };

    private const int MaxRead = 4096;

    /// <summary>The element kind, size and count to read; untyped reads are one "bytes" element (default 64), strings one element of at most <see cref="MaxRead"/>.</summary>
    private static (string Kind, int Size, int Count) ParseType(string? type, int? length, int pointerSize)
    {
        if (string.IsNullOrWhiteSpace(type)) return ("bytes", Math.Clamp(length ?? 64, 1, MaxRead), 1);
        var t = type.Trim().ToLowerInvariant();
        int count = 1;
        if (t.EndsWith(']') && t.IndexOf('[') is > 0 and var open)
        {
            // Spaces around the count and before the bracket are allowed, as in a C declaration.
            if (!int.TryParse(t[(open + 1)..^1].Trim(), NumberStyles.None, CultureInfo.InvariantCulture, out count) || count < 1)
                throw new ToolError(ErrorCode.InvalidArgument, $"Bad array count in '{type}'.", "type=uint32[4]");
            t = t[..open].TrimEnd();
        }
        if (t is "cstring" or "utf16") return (t, Math.Clamp(length ?? MaxRead, 2, MaxRead), 1);
        var size = t == "pointer" ? pointerSize : Sizes.GetValueOrDefault(t);
        if (size == 0)
            throw new ToolError(ErrorCode.InvalidArgument, $"Unknown type '{type}'.", "int8-int64, uint8-uint64, float, double, pointer, cstring or utf16, with [n] for an array");
        if (size * count > 4096) throw new ToolError(ErrorCode.InvalidArgument, $"{type} is {size * count} bytes; at most 4096 per read.", "read fewer elements");
        return (t, size, count);
    }

    private static string Decode(string kind, ReadOnlySpan<byte> b) => kind switch
    {
        "int8" => ((sbyte)b[0]).ToString(CultureInfo.InvariantCulture),
        "uint8" => b[0].ToString(CultureInfo.InvariantCulture),
        "int16" => BinaryPrimitives.ReadInt16LittleEndian(b).ToString(CultureInfo.InvariantCulture),
        "uint16" => BinaryPrimitives.ReadUInt16LittleEndian(b).ToString(CultureInfo.InvariantCulture),
        "int32" => BinaryPrimitives.ReadInt32LittleEndian(b).ToString(CultureInfo.InvariantCulture),
        "uint32" => BinaryPrimitives.ReadUInt32LittleEndian(b).ToString(CultureInfo.InvariantCulture),
        "int64" => BinaryPrimitives.ReadInt64LittleEndian(b).ToString(CultureInfo.InvariantCulture),
        "uint64" => BinaryPrimitives.ReadUInt64LittleEndian(b).ToString(CultureInfo.InvariantCulture),
        "float" => BinaryPrimitives.ReadSingleLittleEndian(b).ToString("R", CultureInfo.InvariantCulture),
        "double" => BinaryPrimitives.ReadDoubleLittleEndian(b).ToString("R", CultureInfo.InvariantCulture),
        "pointer" => Hex(b.Length == 4 ? BinaryPrimitives.ReadUInt32LittleEndian(b) : BinaryPrimitives.ReadUInt64LittleEndian(b)),
        "cstring" => Quote(Encoding.UTF8.GetString(b[..Math.Max(0, b.IndexOf((byte)0) is var z and >= 0 ? z : b.Length)])),
        "utf16" => Quote(Utf16(b)),
        _ => Convert.ToHexStringLower(b),
    };

    private static ToolError Unreadable(ulong address) =>
        new(ErrorCode.NotFound, $"The program has no readable memory at {Hex(address)}.", "check the address with live_session action=status (module ranges)");

    /// <summary>A string's bytes up to its terminator, at most <paramref name="limit"/>, read a page at a time; Cut says why it stopped without one.</summary>
    private async Task<(byte[] Bytes, string? Cut)> ReadStringAsync(Services.LiveSession s, ulong address, bool wide, int limit, CancellationToken ct)
    {
        const int Page = 4096;
        var buffer = new List<byte>();
        while (buffer.Count < limit)
        {
            var at = address + (ulong)buffer.Count;
            var chunk = await live.ReadAsync(s, at, (int)Math.Min((ulong)(limit - buffer.Count), Page - at % Page), ct).ConfigureAwait(false);
            if (chunk is not { Length: > 0 })
                return buffer.Count == 0 ? throw Unreadable(address) : ([.. buffer], $"unreadable memory at {Hex(at)}");
            buffer.AddRange(chunk);
            for (int i = 0; i + (wide ? 1 : 0) < buffer.Count; i += wide ? 2 : 1)
                if (buffer[i] == 0 && (!wide || buffer[i + 1] == 0)) return ([.. buffer.Take(i)], null);
        }
        return ([.. buffer], $"no terminator in {limit:N0} bytes");
    }

    private static string Utf16(ReadOnlySpan<byte> b)
    {
        var chars = System.Runtime.InteropServices.MemoryMarshal.Cast<byte, char>(b[..(b.Length & ~1)]);
        int end = chars.IndexOf('\0');
        return new string(end >= 0 ? chars[..end] : chars);
    }

    private static string Quote(string s) => "\"" + s.Replace("\\", "\\\\").Replace("\"", "\\\"").Replace("\n", "\\n").Replace("\r", "\\r") + "\"";

    [McpServerTool(Name = "live_events", Title = "Session events", UseStructuredContent = true, OutputSchemaType = typeof(LiveEventPage))]
    [Description("Page a session's events with a cursor and filters; polling never re-sends earlier ones.")]
    public Task<string> LiveEvents(
        [Description(SessionDescription)] string session,
        [Description("Cursor of an earlier page; default the oldest kept.")] string? cursor = null,
        [Description("Only this kind.")] string? kind = null,
        [Description("Only this thread id.")] string? thread = null,
        [Description("Only events of this watch or script id.")] string? from = null,
        [Description(ToolSupport.LimitDescription)] int limit = 100,
        [Description(ToolSupport.MaxTokensDescription)] int? maxTokens = null,
        CancellationToken cancellationToken = default) =>
        Task.Run(() =>
        {
            Require(spawn: false);
            var s = live.Get(session);
            long start = 0;
            if (!string.IsNullOrWhiteSpace(cursor) && !long.TryParse(cursor.Trim(), NumberStyles.None, CultureInfo.InvariantCulture, out start))
                throw new ToolError(ErrorCode.InvalidArgument, $"Bad cursor '{cursor}'.", "pass the cursor of an earlier page");
            var k = string.IsNullOrWhiteSpace(kind) ? null : kind.Trim().ToLowerInvariant();
            if (k != null && !EventKinds.Contains(k))
                throw new ToolError(ErrorCode.InvalidArgument, $"Unknown kind '{kind}'.", $"kind={string.Join(", ", EventKinds)}");
            var source = string.IsNullOrWhiteSpace(from) ? null : from.Trim();
            if (source != null && !s.Issued(source))
                throw new ToolError(ErrorCode.NotFound, $"Session {s.Id} has no watch or script '{from}'.", "live_watch and live_script action=list show their ids");
            var (events, gaps, last, more) = s.Page(start, k, ThreadId(thread), ToolSupport.ClampLimit(limit, 1_000), source);
            var named = new List<EvidenceName>();
            var rows = new List<LiveEvent>();
            var lines = new List<string>();
            foreach (var e in events)
            {
                string? name = null;
                if (e.Address is { } addr && e.Kind is "stop" or "exception" or "call")
                {
                    var at = live.Name(s, addr, ct: cancellationToken);
                    name = at.Module != null ? at.Display : null;
                    if (at.Named is { } n) named.Add(n);
                }
                rows.Add(new LiveEvent(e.Sequence, Iso(e.Time), e.Kind, e.Thread?.ToString(CultureInfo.InvariantCulture), e.Address is { } x ? Hex(x) : null, name, e.Text));
                lines.Add($"#{e.Sequence} {e.Kind}{(e.Thread != null ? " thread " + e.Thread : "")}{(e.Address is { } y ? " " + Hex(y) : "")}{(name != null ? " " + name : "")}: {e.Text}");
            }
            (string, object) Render(int count)
            {
                var kept = rows.Take(count).ToList();
                // Past the last matching event the whole ring was scanned: the next poll starts after its end.
                var cut = kept.Count > 0 && (count < rows.Count || more);
                var next = cut ? kept[^1].Sequence + 1 : Math.Max(start, last + 1);
                string? nextCursor = cut ? next.ToString(CultureInfo.InvariantCulture) : null;
                // One marker per ring counts the events evicted between the cursor and the end of this page.
                long calls = Services.LiveRingGaps.Count(gaps.Calls, start, next - 1), others = Services.LiveRingGaps.Count(gaps.Others, start, next - 1);
                var page = new StringBuilder();
                if (calls > 0) page.AppendLine($"{(calls == 1 ? "1 call event" : $"{calls:N0} call events")} dropped (ring capacity {Services.LiveSession.CallRingCapacity:N0})");
                if (others > 0) page.AppendLine($"{(others == 1 ? "1 event" : $"{others:N0} events")} dropped (ring capacity {Services.LiveSession.RingCapacity:N0})");
                foreach (var l in lines.Take(count)) page.AppendLine(l);
                page.AppendLine(kept.Count == 0 ? "No events." : nextCursor != null ? $"more: cursor={nextCursor}" : $"end of the ring; poll again with cursor={next}");
                var dropped = (int)Math.Min(int.MaxValue, calls + others);
                return (page.ToString(), new LiveEventPage(s.Id, kept, nextCursor, dropped) { NamedAddresses = Named(named) });
            }
            return FitPage(rows.Count, Render);
        }, cancellationToken);

    private static readonly string[] EventKinds = ["stop", "call", "script", "exception", "module", "thread", "child", "output", "error", "exit"];

    /// <summary>A cursor page cut to the output budget by rows before its cursor is set, so no rows are skipped; at least one row is kept.</summary>
    private static string FitPage(int count, Func<int, (string Text, object Record)> render)
    {
        var whole = render(count);
        if (OutputCall.Current is { } call && count > 1 && !Fits(whole))
        {
            int lo = 1, hi = count - 1;
            while (lo < hi)
            {
                int mid = (lo + hi + 1) / 2;
                if (Fits(render(mid))) lo = mid; else hi = mid - 1;
            }
            whole = render(lo);
        }
        return ToolOutput.With(whole.Text, whole.Record);

        bool Fits((string Text, object Record) page) =>
            call.Fits(page.Text) && call.Fits(System.Text.Json.JsonSerializer.SerializeToNode(page.Record, page.Record.GetType(), ToolOutput.Json)!.ToJsonString(ToolOutput.Wire));
    }

    private static IReadOnlyList<LiveNamedAddress>? Named(List<EvidenceName> named) =>
        named.Count == 0 ? null : named.Distinct().Select(n => new LiveNamedAddress(n.Image, n.Sha256, $"0x{n.Rva:X}", n.Name)).ToList();

    private static long? ThreadId(string? thread) =>
        string.IsNullOrWhiteSpace(thread) ? null
            : long.TryParse(thread.Trim(), NumberStyles.None, CultureInfo.InvariantCulture, out var t) ? t
            : throw new ToolError(ErrorCode.InvalidArgument, $"Bad thread id '{thread}'.", "a decimal thread id from a stop or live_events");

    private static ulong? Number(string s) =>
        s.StartsWith("0x", StringComparison.OrdinalIgnoreCase) && ulong.TryParse(s[2..], NumberStyles.HexNumber, CultureInfo.InvariantCulture, out var v) ? v : null;

    private static string Hex(ulong v) => $"0x{v:X}";
    private static string Src(string? source) => source != null ? "  " + source : "";

    private static string Deferred((LiveDeferred Point, bool Held) d) =>
        d.Point is { UntilCompiled: true, Unreadable: { } reason }
            ? $"{d.Point.Id} deferred: {d.Point.Module} has no code yet, and the program's runtime cannot be read: {reason}; it is set when the JIT compiles it"
        : d.Point.UntilCompiled
            ? $"{d.Point.Id} deferred: {d.Point.Module} has no code yet (the runtime compiles it at its first call); it is set once it is compiled, so the first calls may be missed"
            : $"{d.Point.Id} deferred: {d.Point.Module} is not loaded; it is set when {d.Point.Module} loads" +
              (d.Held ? ", before the module's code runs (a module whose entry point writes its code: once that returns)" : " (calls before then are missed)");

    /// <summary>Reports once the deferred points and watches that failed since the last call; returns the first one's next step.</summary>
    private static string? Dropped(Services.LiveSession s, StringBuilder text, bool watch, out List<LiveFailedPoint> failed)
    {
        string? next = null;
        // Read the list under the same lock, so a point listed as failed has had its next step said.
        lock (s.Failed)
        {
            failed = s.Failed.Where(d => d.Watch == watch).ToList();
            foreach (var d in s.Failed.Where(d => !d.Reported))
            {
                d.Reported = true;
                text.AppendLine($"deferred {(d.Watch ? "watch" : "stop point")} {d.Id} at {d.Where} was dropped ({d.Because}): {d.Reason}");
                next ??= d.Next;
            }
        }
        return next;
    }

    private static string Until(LiveDeferred d) => d.UntilCompiled ? $"deferred until {d.Module} is compiled" : $"deferred until {d.Module} loads";

    /// <summary>The error of a session call while sessions are off, naming the flag that turns them on.</summary>
    internal static ToolError SessionsOff(bool spawn = false, bool attach = false) =>
        new(ErrorCode.Unsupported, "Sessions on running programs are off in this server.",
            spawn ? $"ask the user to start the server with {ServerOptions.AllowLiveSpawnOption} (or {ServerOptions.AllowLiveSpawnVariable}=1)"
            : attach ? $"ask the user to start the server with {ServerOptions.AllowLiveAttachOption} (or {ServerOptions.AllowLiveAttachVariable}=1)"
            : $"ask the user to start the server with {ServerOptions.AllowLiveAttachOption} or {ServerOptions.AllowLiveSpawnOption}");

    /// <summary>The opt-in flags: starting a program needs --allow-live-spawn, attaching --allow-live-attach (each turns on --allow-live).</summary>
    private void Require(bool spawn, bool attach = false)
    {
        if (!options.AllowLive) throw SessionsOff(spawn, attach);
        if (spawn && !options.AllowLiveSpawn)
            throw new ToolError(ErrorCode.Unsupported, "Starting a program under a session is off in this server.",
                $"ask the user to start the server with {ServerOptions.AllowLiveSpawnOption} (or {ServerOptions.AllowLiveSpawnVariable}=1) as well");
        if (attach && !options.AllowLiveAttach)
            throw new ToolError(ErrorCode.Unsupported, "Attaching to a running program is off in this server.",
                $"ask the user to start the server with {ServerOptions.AllowLiveAttachOption} (or {ServerOptions.AllowLiveAttachVariable}=1) as well");
    }

    /// <summary>
    /// The program as the backend receives it: unchanged without --live-allow
    /// or with --live-allow *; else checked and resolved (full path or process
    /// id). A program is started only when the server lists what it may start.
    /// </summary>
    private string Scoped(bool spawn, string program)
    {
        if (spawn) RequireStartList();
        return options.LiveScope.Count == 0 ? program
            : spawn ? LiveProgramScope.Spawn(program, options.LiveScope) : LiveProgramScope.Attach(program, options.LiveScope);
    }

    private void RequireStartList()
    {
        if (options.LiveAllow.Count == 0 && !options.LiveAllowAny)
            throw new ToolError(ErrorCode.Unsupported, "Starting a program needs the list of programs a session may start; this server has none.",
                $"ask the user to start the server with {ServerOptions.LiveAllowOption} <program or folder> (repeatable), or {ServerOptions.LiveAllowOption} {ServerOptions.LiveAllowAnyValue} for any program");
    }
}
