using System.Buffers.Binary;
using System.ComponentModel;
using System.Globalization;
using System.Text;
using ModelContextProtocol.Server;
using Corvus.Core;
using Corvus.Mcp;
using Corvus.Services;

namespace Corvus.Tools;

/// <summary>
/// Sessions on local programs: open, stop points, typed reads and the event ring. Observation only; every tool refuses
/// calls unless the server starts with --allow-live; starting a program also needs --allow-live-spawn, attaching --allow-live-attach,
/// and --live-allow limits both to listed programs.
/// </summary>
[McpServerToolType]
public sealed partial class LiveSessionTools(ServerOptions options, LiveSessionService live, MinidumpService? dumps = null)
{
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
        string Kind,
        string? Thread, string? Address, string? Name, string Text);

    public sealed record LiveEventPage(string Session, IReadOnlyList<LiveEvent> Items,
        [property: Description("Cursor for the next page; null at the end of the ring.")] string? Cursor,
        [property: Description("Events dropped from the cursor to this page's end, calls included.")] int Dropped)
    {
        public IReadOnlyList<LiveNamedAddress>? NamedAddresses { get; init; }
    }

    [McpServerTool(Name = "live_session", Title = "Session on a local program", UseStructuredContent = true, OutputSchemaType = typeof(LiveSessionReport))]
    [Description("Open, list, inspect or close a session on a program: its id, backend and modules matched to images; snapshot saves the process as a dump.")]
    public Task<string> LiveSession(
        [Description("What to do.")] string action = "list",
        [Description("attach: pid or name; spawn: program path (started suspended); processes: name filter; *_child: child pid.")] string? program = null,
        [Description("spawn: program arguments.")] string[]? arguments = null,
        [Description("spawn: NAME=value variables.")] string[]? environment = null,
        [Description(SessionDescription)] string? session = null,
        [Description("snapshot: dump file (default: temp).")] string? outputPath = null,
        [Description("Overwrite outputPath.")] bool overwrite = false,
        [Description("Hold child processes by image name (* any) at start.")] string[]? childNames = null,
        [Description("Download a missing DAC.")] bool downloadDac = false,
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
                    var names = childNames?.Where(n => !string.IsNullOrWhiteSpace(n)).Select(n => n.Trim()).ToList();
                    if (names?.Contains("*") == true) names = [];
                    else if (names is { Count: 0 }) names = null;
                    var opened = await live.OpenAsync(a == "spawn", Scoped(a == "spawn", program), arguments ?? [], cancellationToken,
                        a == "spawn" ? environment : null, names, downloadDac: downloadDac).ConfigureAwait(false);
                    return Report(a, opened);
                case "children":
                    return Report(a, live.Get(RequireSession(session)));
                case "attach_child" or "release_child":
                    var parent = live.Get(RequireSession(session));
                    var pid = ChildId(program);
                    if (options.LiveAllow.Count > 0) LiveProgramScope.Attach(pid.ToString(CultureInfo.InvariantCulture), options.LiveAllow);
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
                case "close":
                    var closing = live.Get(RequireSession(session));
                    await live.CloseAsync(closing, "closed by request").ConfigureAwait(false);
                    return Report(a, closing);
                default:
                    throw new ToolError(ErrorCode.InvalidArgument, $"Unknown action '{action}'.", "action=list, processes, attach, spawn, status, snapshot, close, children, attach_child or release_child");
            }
        }, cancellationToken);

    private async Task<string> Snapshot(Services.LiveSession s, string? outputPath, bool overwrite, CancellationToken ct)
    {
        LiveSessionService.Live(s);
        if (dumps == null) throw new ToolError(ErrorCode.Unsupported, "This server has no dump reader.", "open the dump file with open_minidump");
        var path = string.IsNullOrWhiteSpace(outputPath)
            ? Path.Combine(Path.GetTempPath(), "corvus-snapshots", $"{s.Id}-{s.ProcessId}-{DateTime.UtcNow:yyyyMMdd-HHmmss-fff}{(OperatingSystem.IsWindows() ? ".dmp" : ".core")}")
            : outputPath;
        // a held thread waits inside the backend: its stop's registers let the walk start at the stop (on Windows the dump's
        // exception, an x86 program's x86 CONTEXT taken as the WoW64 thread's 32-bit side; in a Linux core the thread's own)
        Native.Diagnostics.ProcessSnapshot.Stop? stop = null;
        var held = s.Held.FirstOrDefault();
        if (s.Arch is "x64" or "ia32" && held != null)
        {
            var registers = new Dictionary<string, ulong>(StringComparer.OrdinalIgnoreCase);
            foreach (var (name, value) in held.Registers)
                if (ulong.TryParse(value.StartsWith("0x", StringComparison.OrdinalIgnoreCase) ? value[2..] : value, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out var v))
                    registers[name] = v;
            bool x64 = s.Arch == "x64";
            if (registers.ContainsKey(x64 ? "rip" : "eip") && registers.ContainsKey(x64 ? "rsp" : "esp"))
                stop = new((int)held.Thread, x64, registers);
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
                try { name = p.ProcessName; }
                catch (InvalidOperationException) { continue; } // exited meanwhile
                if (string.IsNullOrWhiteSpace(filter) || name.Contains(filter.Trim(), StringComparison.OrdinalIgnoreCase)) rows.Add(new LiveProcessRow(p.Id, name));
            }
        return rows.OrderBy(r => r.Name, StringComparer.OrdinalIgnoreCase).ThenBy(r => r.ProcessId).ToList();
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
            // a child's row: its command line, and its state with the session attached to it
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
        if (action != "children")
        {
            text.AppendLine($"{rows.Count} modules, {rows.Count(r => r.Image != null)} matched to loaded images:");
            foreach (var (m, state) in rows.Zip(modules))
                text.AppendLine($"  {m.Base} {m.Name}{(m.Image != null ? "  = " + m.Image + (state.Image == null ? " (assembly)" : "") : "")}");
        }
        else if (children == null) text.AppendLine("does not follow child processes: open the session with childNames=[\"*\"]");
        return ToolOutput.With(text.ToString(), new LiveSessionReport(action, s.Id, s.Backend, s.Program, s.ProcessId, s.State, action == "children" ? [] : rows, []) { Processes = children });
    }

    [McpServerTool(Name = "live_break", Title = "Stop points in a session", UseStructuredContent = true, OutputSchemaType = typeof(LiveStopPointReport))]
    [Description("Set, list or clear stop points (name, module!export, file:line, address); continue resumes held threads; wait returns the next stop with a named stack.")]
    public Task<string> LiveBreak(
        [Description(SessionDescription)] string session,
        [Description("What to do.")] string action = "list",
        [Description("set: a name, module!export, address or file:line.")] string? at = null,
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
                    head.AppendLine($"{point.Id} set at {Hex(point.Address)} {point.At.Display}{Src(point.At.Source)}{(point.Followed != null ? $" ({point.Followed})" : "")}");
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
                else
                {
                    await live.FrameModulesAsync(s, held, cancellationToken).ConfigureAwait(false);
                    await live.IndexedAsync(s, TimeSpan.FromSeconds(15), cancellationToken).ConfigureAwait(false);
                    await live.ClrAsync(s, cancellationToken).ConfigureAwait(false);
                    stop = Stop(s, held, head, named, cancellationToken);
                }
            }
            var next = Dropped(s, head);
            List<LiveStopPointState> points;
            lock (s.StopPoints) points = s.StopPoints.Values.OrderBy(p => int.Parse(p.Id[1..], CultureInfo.InvariantCulture)).ToList();
            List<LiveDeferred> deferredPoints;
            lock (s.Deferred) deferredPoints = s.Deferred.Where(d => !d.Watch).ToList();
            List<LiveFailedPoint> failedPoints;
            lock (s.Failed) failedPoints = s.Failed.Where(d => !d.Watch).ToList();
            head.AppendLine($"{s.Id}: {s.State}, {points.Count} stop point(s){(deferredPoints.Count > 0 ? $", {deferredPoints.Count} deferred" : "")}{(failedPoints.Count > 0 ? $", {failedPoints.Count} failed" : "")}");
            foreach (var p in points) head.AppendLine($"  {p.Id} {p.Where} at {Hex(p.Address)} {p.At.Display}, {p.Hits} hit(s)");
            foreach (var d in deferredPoints) head.AppendLine($"  {d.Id} {d.Where}: {Until(d)}");
            foreach (var d in failedPoints) head.AppendLine($"  {d.Id} {d.Where}: failed ({d.Because}): {d.Reason}");
            if (next != null) head.AppendLine($"Next: {next}");
            named.AddRange(points.Select(p => p.At.Named).OfType<EvidenceName>());
            var rows = points.Select(p => new LiveStopPoint(p.Id, p.Where, Hex(p.Address), p.Hits) { Followed = p.Followed })
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

    [McpServerTool(Name = "live_watch", Title = "Record calls in a session", UseStructuredContent = true, OutputSchemaType = typeof(LiveWatchReport))]
    [Description("Record every call of a function with arguments and return value, decoded by prototype (PDB, DWARF) or known API, as events (live_events from=<watch>).")]
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
            var next = Dropped(s, head);
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
            List<LiveFailedPoint> failedWatches;
            lock (s.Failed) failedWatches = s.Failed.Where(d => d.Watch).ToList();
            foreach (var d in failedWatches) head.AppendLine($"  {d.Id} {d.Where}: failed ({d.Because}): {d.Reason}");
            if (rows.Count > 0) head.AppendLine($"calls: live_events from={rows[0].Id}");
            if (next != null) head.AppendLine($"Next: {next}");
            rows.AddRange(deferredWatches.Select(d => new LiveWatch(d.Id, d.Where, null, null, null, null, d.PerSecond, 0, 0, null) { State = "deferred" }));
            rows.AddRange(failedWatches.Select(d => new LiveWatch(d.Id, d.Where, null, null, null, null, 0, 0, 0, null) { State = "failed" }));
            var named = watches.Select(x => x.At.Named).OfType<EvidenceName>().ToList();
            return ToolOutput.With(head.ToString(), new LiveWatchReport(s.Id, rows) { NamedAddresses = Named(named) });
        }, cancellationToken);

    [McpServerTool(Name = "live_script", Title = "User script in a session", UseStructuredContent = true, OutputSchemaType = typeof(LiveScriptReport))]
    [Description("Load, list or unload your own Frida script in a session's program; its messages become events (live_events from=<script>). Needs --live-scripting.")]
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
                    $"start the server with {ServerOptions.LiveScriptingOption} (or {ServerOptions.LiveScriptingVariable}=1) as well");
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
        [Description("Thread id; default the earliest held one.")] string? thread = null,
        [Description("Register names, comma-separated; default all.")] string? registers = null,
        [Description("An address, register or name to read.")] string? memory = null,
        [Description("memory: int8..uint64, float, double, pointer, cstring, utf16; [n] for arrays.")] string? type = null,
        [Description("memory: untyped bytes, or a string's limit (max 4096).")] int? length = null,
        CancellationToken cancellationToken = default) =>
        Task.Run(async () =>
        {
            Require(spawn: false);
            var s = live.Get(session);
            LiveSessionService.Live(s);
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
                // untyped bytes go in rows, so a page too small for the whole read keeps its first rows
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

    private static readonly Dictionary<string, int> Sizes = new(StringComparer.Ordinal)
    {
        ["int8"] = 1, ["uint8"] = 1, ["int16"] = 2, ["uint16"] = 2, ["int32"] = 4, ["uint32"] = 4, ["int64"] = 8, ["uint64"] = 8,
        ["float"] = 4, ["double"] = 8,
    };

    private const int MaxRead = 4096;

    /// <summary>
    /// The element kind, its size and the count to read; untyped reads are one "bytes" element of <paramref name="length"/>
    /// (default 64), strings one element whose size is the most bytes read (default <see cref="MaxRead"/>).
    /// </summary>
    private static (string Kind, int Size, int Count) ParseType(string? type, int? length, int pointerSize)
    {
        if (string.IsNullOrWhiteSpace(type)) return ("bytes", Math.Clamp(length ?? 64, 1, MaxRead), 1);
        var t = type.Trim().ToLowerInvariant();
        int count = 1;
        if (t.EndsWith(']') && t.IndexOf('[') is > 0 and var open)
        {
            // spaces around the count and before the bracket are allowed, as in a C declaration
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

    /// <summary>
    /// A string's bytes up to its terminator, at most <paramref name="limit"/>, read a page at a time so a string that ends
    /// just before unreadable memory still reads; Cut says why it stopped without a terminator.
    /// </summary>
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
    [Description("Page a session's event ring with a cursor and filters, so polling never re-sends earlier events.")]
    public Task<string> LiveEvents(
        [Description(SessionDescription)] string session,
        [Description("Cursor from an earlier page; default the oldest event kept.")] string? cursor = null,
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
                rows.Add(new LiveEvent(e.Sequence, e.Kind, e.Thread?.ToString(CultureInfo.InvariantCulture), e.Address is { } x ? Hex(x) : null, name, e.Text));
                lines.Add($"#{e.Sequence} {e.Kind}{(e.Thread != null ? " thread " + e.Thread : "")}{(e.Address is { } y ? " " + Hex(y) : "")}{(name != null ? " " + name : "")}: {e.Text}");
            }
            (string, object) Render(int count)
            {
                var kept = rows.Take(count).ToList();
                // past the last matching event the whole ring was scanned: the next poll starts after its end
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

    /// <summary>
    /// A cursor page cut to the call's output budget by rows, before its cursor is set: the cursor follows the last row shown,
    /// so a page the output layer would cut no longer skips the rows between. At least one row is kept.
    /// </summary>
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

    /// <summary>Says once which deferred points and watches could not be set since the last call; returns the first one's next step.</summary>
    private static string? Dropped(Services.LiveSession s, StringBuilder text)
    {
        string? next = null;
        lock (s.Failed)
            foreach (var d in s.Failed.Where(d => !d.Reported))
            {
                d.Reported = true;
                text.AppendLine($"deferred {(d.Watch ? "watch" : "stop point")} {d.Id} at {d.Where} was dropped ({d.Because}): {d.Reason}");
                next ??= d.Next;
            }
        return next;
    }

    private static string Until(LiveDeferred d) => d.UntilCompiled ? $"deferred until {d.Module} is compiled" : $"deferred until {d.Module} loads";

    /// <summary>The error of a session call while sessions are off, naming the flag that turns them on.</summary>
    internal static ToolError SessionsOff(bool spawn = false, bool attach = false) =>
        new(ErrorCode.Unsupported, "Sessions on running programs are off in this server.",
            spawn ? $"start the server with {ServerOptions.AllowLiveSpawnOption} (or {ServerOptions.AllowLiveSpawnVariable}=1)"
            : attach ? $"start the server with {ServerOptions.AllowLiveAttachOption} (or {ServerOptions.AllowLiveAttachVariable}=1)"
            : $"start the server with {ServerOptions.AllowLiveAttachOption} or {ServerOptions.AllowLiveSpawnOption}");

    /// <summary>The opt-in flags: starting a program needs --allow-live-spawn, attaching --allow-live-attach (each turns on --allow-live).</summary>
    private void Require(bool spawn, bool attach = false)
    {
        if (!options.AllowLive) throw SessionsOff(spawn, attach);
        if (spawn && !options.AllowLiveSpawn)
            throw new ToolError(ErrorCode.Unsupported, "Starting a program under a session is off in this server.",
                $"start the server with {ServerOptions.AllowLiveSpawnOption} (or {ServerOptions.AllowLiveSpawnVariable}=1) as well");
        if (attach && !options.AllowLiveAttach)
            throw new ToolError(ErrorCode.Unsupported, "Attaching to a running program is off in this server.",
                $"start the server with {ServerOptions.AllowLiveAttachOption} (or {ServerOptions.AllowLiveAttachVariable}=1) as well");
    }

    /// <summary>The program as the backend receives it: unchanged without --live-allow; with it, checked and resolved (full path or process id).</summary>
    private string Scoped(bool spawn, string program) =>
        options.LiveAllow.Count == 0 ? program
        : spawn ? LiveProgramScope.Spawn(program, options.LiveAllow) : LiveProgramScope.Attach(program, options.LiveAllow);
}
