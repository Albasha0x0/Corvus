using System.Globalization;
using System.Runtime.InteropServices;
using System.Text.Json;
using System.Text.Json.Nodes;
using Corvus.Core;

namespace Corvus.Services;

/// <summary>A process the session's program started while the session follows child processes.</summary>
public sealed class LiveChild(int processId, int parentId, string path, IReadOnlyList<string> arguments, string origin, bool held)
{
    public int ProcessId { get; } = processId;
    public int ParentId { get; } = parentId;
    public string Path { get; } = path;
    public IReadOnlyList<string> Arguments { get; } = arguments;
    /// <summary>spawn, fork or exec, as Frida names how the child began.</summary>
    public string Origin { get; } = origin;
    /// <summary>held (at its start), attached (a session of its own holds it), running (let go), or resumed (not in the name filter).</summary>
    public string State { get; internal set; } = held ? "held" : "resumed";
    /// <summary>The session attached to the child, while it is attached.</summary>
    public string? Session { get; internal set; }
    /// <summary>The gate's own session stays in the started child until the child's session closes (Linux).</summary>
    internal bool Handed { get; set; }

    public string CommandLine => string.Join(" ", Arguments.Select(a => a.Length == 0 || a.Any(char.IsWhiteSpace) ? "\"" + a + "\"" : a));
}

/// <summary>Child processes held by Frida's child gating until attached or released; closing the session releases them.</summary>
public sealed partial class LiveSessionService
{
    // Bound here, not in Native.Live: the process inspector there binds no API that changes a process.
    [DllImport("ntdll.dll")]
    private static extern int NtResumeProcess(Native.Live.SafeKernelHandle process);

    private void ChildStarted(LiveSession session, JsonElement body)
    {
        var pid = body.GetProperty("pid").GetInt32();
        var held = body.TryGetProperty("held", out var h) && h.ValueKind == JsonValueKind.True;
        var argv = body.TryGetProperty("argv", out var a) && a.ValueKind == JsonValueKind.Array
            ? a.EnumerateArray().Select(x => x.GetString() ?? "").ToList() : [];
        var child = new LiveChild(pid, body.TryGetProperty("parentPid", out var p) ? p.GetInt32() : session.ProcessId,
            body.GetProperty("path").GetString() ?? "", argv, body.TryGetProperty("origin", out var o) ? o.GetString() ?? "" : "", held);
        lock (session.Children) session.Children.Add(child);
        session.Add("child", null, null, $"child process {pid} started: {child.Path}" + (held
            ? $" (held at its start: live_session action=attach_child or release_child program={pid})"
            : " (resumed: not in childNames)"));
    }

    // A process older than the program has a reused parent id.
    /// <summary>Processes another process started for the program (WebView2 browser process), unseen by the gate; empty off Windows.</summary>
    public static List<(int ProcessId, string Name)> StartedForProgram(LiveSession session)
    {
        var found = new List<(int, string)>();
        if (!OperatingSystem.IsWindows() || session.Ended != null) return found;
        HashSet<int> known;
        lock (session.Children) known = session.Children.Select(c => c.ProcessId).ToHashSet();
        DateTime started;
        try { using var program = System.Diagnostics.Process.GetProcessById(session.ProcessId); started = program.StartTime; }
        catch (Exception e) when (e is ArgumentException or InvalidOperationException or System.ComponentModel.Win32Exception) { return found; }
        using var snapshot = Native.Live.LiveNative.CreateToolhelp32Snapshot(Native.Live.LiveNative.TH32CS_SNAPPROCESS, 0);
        if (snapshot.IsInvalid) return found;
        var entry = new Native.Live.LiveNative.PROCESSENTRY32W { dwSize = (uint)Marshal.SizeOf<Native.Live.LiveNative.PROCESSENTRY32W>() };
        for (bool more = Native.Live.LiveNative.Process32First(snapshot, ref entry); more; more = Native.Live.LiveNative.Process32Next(snapshot, ref entry))
        {
            int pid = (int)entry.th32ProcessID;
            if (entry.th32ParentProcessID != session.ProcessId || known.Contains(pid)) continue;
            try
            {
                using var child = System.Diagnostics.Process.GetProcessById(pid);
                if (child.StartTime >= started) found.Add((pid, entry.szExeFile));
            }
            catch (Exception e) when (e is ArgumentException or InvalidOperationException or System.ComponentModel.Win32Exception) { }
        }
        return found;
    }

    /// <summary>A child the session holds; the program that started it may have exited, as long as the session's worker still runs.</summary>
    private static LiveChild HeldChild(LiveSession parent, int pid)
    {
        if (parent.Closed || !parent.Worker.IsAlive) Live(parent);
        lock (parent.Children)
            return parent.Children.LastOrDefault(c => c.ProcessId == pid) is { } child
                ? child.State == "held" ? child
                    : throw new ToolError(ErrorCode.Conflict, $"Child process {pid} of {parent.Id} is {child.State}{(child.Session != null ? " in " + child.Session : "")}.",
                        child.Session != null ? $"use {child.Session}" : "live_session action=children shows the held ones")
                : throw new ToolError(ErrorCode.NotFound, $"Session {parent.Id} holds no child process {pid}.", $"live_session action=children session={parent.Id}");
    }

    // On Linux only the gate's tracer can attach at the child's start, so the child runs with its first thread held at
    // the program's code instead.
    /// <summary>Opens a session on a held child, held until its first continue and following its own children.</summary>
    public async Task<LiveSession> AttachChildAsync(LiveSession parent, int pid, CancellationToken ct)
    {
        var child = HeldChild(parent, pid);
        // A SIGSTOP hold is lost when Frida's attach to the stopped child fails, which it does under CPU load.
        var unheld = false;
        if (parent.Platform == "linux")
        {
            var r = await parent.Worker.RequestAsync("resume_child", new JsonObject { ["pid"] = pid, ["hold"] = true }, RequestTimeout, ct).ConfigureAwait(false);
            unheld = r.TryGetProperty("held", out var h) && h.ValueKind == JsonValueKind.False;
        }
        var session = await OpenAsync(false, pid.ToString(CultureInfo.InvariantCulture), [], ct, childNames: parent.ChildNames, downloadDac: parent.DownloadDac).ConfigureAwait(false);
        if (unheld) session.Add("child", null, null, $"child process {pid} reached none of its code within 5 s of its start: it runs unheld");
        session.HeldBy = parent;
        session.Suspended = true;
        child.State = "attached";
        child.Session = session.Id;
        return session;
    }

    /// <summary>Lets a held child run unobserved.</summary>
    public async Task ReleaseChildAsync(LiveSession parent, int pid, CancellationToken ct)
    {
        var child = HeldChild(parent, pid);
        await parent.Worker.RequestAsync("resume_child", new JsonObject { ["pid"] = pid }, RequestTimeout, ct).ConfigureAwait(false);
        child.State = "running";
    }

    /// <summary>A child session's first continue, when the parent's gate still holds the program: the gate lets it run.</summary>
    private async Task<bool> StartHeldChildAsync(LiveSession session, CancellationToken ct)
    {
        var parent = session.HeldBy!;
        LiveChild? child;
        lock (parent.Children) child = parent.Children.LastOrDefault(c => c.ProcessId == session.ProcessId && c.Session == session.Id);
        if (child == null || !parent.Worker.IsAlive) return false;
        child.Handed = parent.Platform == "linux";
        var r = await parent.Worker.RequestAsync("resume_child", new JsonObject { ["pid"] = session.ProcessId, ["keep"] = child.Handed }, RequestTimeout, ct).ConfigureAwait(false);
        return r.GetProperty("resumed").GetBoolean();
    }

    /// <summary>After a child session detaches, drops the gate's session in the child; ends a closed gate that keeps none.</summary>
    private static async Task DropHandedAsync(LiveSession session)
    {
        if (session.HeldBy is not { } parent) return;
        LiveChild? child;
        lock (parent.Children) child = parent.Children.LastOrDefault(c => c.Session == session.Id && c.Handed);
        if (child == null) return;
        child.Handed = false;
        if (!parent.Worker.IsAlive) return;
        try
        {
            var r = await parent.Worker.RequestAsync("drop_child", new JsonObject { ["pid"] = child.ProcessId }, TimeSpan.FromSeconds(5), CancellationToken.None).ConfigureAwait(false);
            if (!parent.Closed || r.GetProperty("kept").GetInt32() > 0) return;
        }
        catch (ToolError) { }
        await parent.Worker.ShutdownAsync("close", new JsonObject { ["end"] = false }, TimeSpan.FromSeconds(5)).ConfigureAwait(false);
        parent.Worker.Dispose();
    }

    /// <summary>Whether a started child's session is still open with the gate's session in its program.</summary>
    private bool KeepsHanded(LiveSession session)
    {
        lock (session.Children)
            return session.Children.Any(c => c.Handed && c.Session != null && _sessions.TryGetValue(c.Session, out var s) && !s.Closed);
    }

    /// <summary>At close, resumes every child still held; a child session that never continued returns to its parent's hold.</summary>
    private async Task CloseChildrenAsync(LiveSession session)
    {
        if (session.HeldBy is { } parent && session.Suspended)
            lock (parent.Children)
                foreach (var c in parent.Children.Where(c => c.Session == session.Id))
                {
                    c.State = "held";
                    c.Session = null;
                }
        foreach (var child in Holding(session))
        {
            try
            {
                if (child.Session != null && _sessions.TryGetValue(child.Session, out var attached))
                {
                    await ResumeAsync(attached, null, CancellationToken.None).ConfigureAwait(false);
                    attached.Add("child", null, null, $"started: {session.Id}, which held it at its start, closed");
                    continue;
                }
                if (session.Worker.IsAlive)
                {
                    await session.Worker.RequestAsync("resume_child", new JsonObject { ["pid"] = child.ProcessId }, TimeSpan.FromSeconds(5), CancellationToken.None).ConfigureAwait(false);
                    child.State = "running";
                    continue;
                }
            }
            catch (ToolError) { }
            ResumeDirectly(child);
        }
    }

    /// <summary>When the worker ended on its own, its held children are resumed through the OS (Windows).</summary>
    private void ResumeChildrenDirectly(LiveSession session)
    {
        foreach (var child in Holding(session)) ResumeDirectly(child);
    }

    /// <summary>The children the session's gate still holds: held ones, and attached ones whose session has not continued.</summary>
    private List<LiveChild> Holding(LiveSession session)
    {
        lock (session.Children)
            return session.Children.Where(c => c.State == "held"
                || c.State == "attached" && c.Session != null && _sessions.TryGetValue(c.Session, out var s) && s.Suspended && !s.Closed).ToList();
    }

    private void ResumeDirectly(LiveChild child)
    {
        if (!OperatingSystem.IsWindows()) return;
        const uint ProcessSuspendResume = 0x0800;
        using var h = Native.Live.LiveNative.OpenProcess(ProcessSuspendResume, false, child.ProcessId);
        if (h.IsInvalid || NtResumeProcess(h) < 0) return;
        if (child.Session == null) child.State = "running";
        else if (_sessions.TryGetValue(child.Session, out var attached)) attached.Suspended = false;
    }
}
