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
    /// <summary>The gate let the child go stopped for its session's attach (Linux); that session starts it.</summary>
    internal bool Stopped { get; set; }

    public string CommandLine => string.Join(" ", Arguments.Select(a => a.Length == 0 || a.Any(char.IsWhiteSpace) ? "\"" + a + "\"" : a));
}

/// <summary>
/// Child processes, as Frida's child gating holds them: a child the program starts waits at its start until it is attached
/// as a session of its own or let go; closing the session lets every child it still holds run.
/// </summary>
public sealed partial class LiveSessionService
{
    // bound here, not in Native.Live: the process inspector there binds no API that changes a process
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

    /// <summary>
    /// Processes that name the program as their parent but that another process started for it (the WebView2 runtime's
    /// browser process), so no hold saw them; Windows only. A process older than the program has a reused parent id.
    /// </summary>
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

    /// <summary>
    /// Opens a session on a held child; it stays held until that session's first continue, and follows its own children as
    /// the parent does. On Linux the gate lets the child go stopped (SIGSTOP), since only the gate's own tracer could
    /// attach to it there; the child session's first continue then resumes it itself.
    /// </summary>
    public async Task<LiveSession> AttachChildAsync(LiveSession parent, int pid, CancellationToken ct)
    {
        var child = HeldChild(parent, pid);
        var stopped = parent.Platform == "linux";
        if (stopped)
        {
            await parent.Worker.RequestAsync("resume_child", new JsonObject { ["pid"] = pid, ["stopped"] = true }, RequestTimeout, ct).ConfigureAwait(false);
            child.Stopped = true;
            child.State = "running";
        }
        LiveSession session;
        try
        {
            session = await OpenAsync(false, pid.ToString(CultureInfo.InvariantCulture), [], ct, childNames: parent.ChildNames, stopped: stopped, downloadDac: parent.DownloadDac).ConfigureAwait(false);
        }
        catch when (stopped)
        {
            Continue(pid); // a child let go stopped never stays stopped
            throw;
        }
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
        if (child == null || child.Stopped || !parent.Worker.IsAlive) return false;
        var r = await parent.Worker.RequestAsync("resume_child", new JsonObject { ["pid"] = session.ProcessId }, RequestTimeout, ct).ConfigureAwait(false);
        return r.GetProperty("resumed").GetBoolean();
    }

    /// <summary>
    /// At a session's close: every child it still holds runs on (through the worker, or directly when the worker is gone), an
    /// attached child whose session has not continued too, and a child session that never continued goes back to its
    /// parent's hold (on Linux it runs on, as its worker's close resumes it).
    /// </summary>
    private async Task CloseChildrenAsync(LiveSession session)
    {
        if (session.HeldBy is { } parent && session.Suspended)
            lock (parent.Children)
                foreach (var c in parent.Children.Where(c => c.Session == session.Id))
                {
                    c.State = c.Stopped ? "running" : "held";
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
        foreach (var child in Holding(session).Where(c => !c.Stopped)) ResumeDirectly(child);
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

    [DllImport("libc", EntryPoint = "kill", SetLastError = true)]
    private static extern int Kill(int pid, int signal);

    /// <summary>Sends SIGCONT (Linux).</summary>
    private static void Continue(int pid)
    {
        const int SigCont = 18; // Linux
        if (OperatingSystem.IsLinux()) _ = Kill(pid, SigCont);
    }
}
