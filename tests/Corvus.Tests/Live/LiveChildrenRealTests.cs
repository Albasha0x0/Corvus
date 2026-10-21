using System.Diagnostics;
using System.Globalization;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text.RegularExpressions;
using Corvus.Native.Providers;
using Corvus.Native.Providers.Live;
using Xunit.Abstractions;

namespace Corvus.Tests;

/// <summary>
/// A launcher that starts a child process and waits, per target: with childNames the child is held at its start,
/// attached as a session of its own and stopped at a stop point; a child still held when the session closes runs on;
/// without childNames the session sees only the launcher, as before. Every run ends with no process left.
/// </summary>
[Trait("Speed", "Slow")]
[Trait("Data", "Real")]
[Collection(LiveSessions.Collection)]
public sealed class LiveChildrenRealTests(ITestOutputHelper output) : LiveToolCalls(output), IDisposable
{
    private readonly TempDir _dir = new();

    public void Dispose() => _dir.Dispose();

    private (string Launcher, string Orders) Build(LiveTarget target) =>
        (target.Build(_dir, "launcher", LivePrograms.Launcher), target.Build(_dir, "orders", LivePrograms.Orders));

    private async Task<int> SpawnFollowing(InProcessServer server, string launcher, string orders, bool restricted = false)
    {
        var open = await Ok(server, "live_session", new()
        {
            ["action"] = "spawn", ["program"] = launcher, ["arguments"] = (restricted ? ["--restricted"] : Array.Empty<string>()).Concat([orders, "3", "0"]).ToArray(), ["childNames"] = new[] { "orders" },
        });
        Assert.Contains("follows child processes named orders: 0 started", open);
        var pid = int.Parse(Regex.Match(open, @"pid (\d+)").Groups[1].Value, CultureInfo.InvariantCulture);
        Assert.Contains("program started", await Ok(server, "live_break", new() { ["session"] = "live-1", ["action"] = "continue" }));
        return pid;
    }

    /// <summary>The held child's process id, once the launcher has started it.</summary>
    private async Task<int> HeldChild(InProcessServer server, string orders)
    {
        for (int i = 0; i < 300; i++)
        {
            var list = await Ok(server, "live_session", new() { ["action"] = "children", ["session"] = "live-1" }, log: false);
            if (Regex.Match(list, @"pid (\d+) held: (.*)") is { Success: true } held)
            {
                Output.WriteLine(list);
                Assert.Contains(Path.GetFileName(orders), held.Groups[2].Value);
                return int.Parse(held.Groups[1].Value, CultureInfo.InvariantCulture);
            }
            await Task.Delay(100);
        }
        Assert.Fail("no child was held within 30 s");
        return 0;
    }

    // ---- the child is held, attached, stopped in, and both programs end

    [LiveTargetFact("win-x64")] public Task Child_attached_on_win_x64() => ChildAttached(LiveTarget.WinX64);
    [LiveTargetFact("win-x86")] public Task Child_attached_on_win_x86() => ChildAttached(LiveTarget.WinX86);
    [LiveTargetFact("linux-x64")] public Task Child_attached_on_linux_x64() => ChildAttached(LiveTarget.LinuxX64);
    [LiveTargetFact("linux-x86")] public Task Child_attached_on_linux_x86() => ChildAttached(LiveTarget.LinuxX86);

    // The agent DLL loads from the worker's temp folder, which here grants only the user (as under a user profile):
    // a child under a restricted token reads it by the RESTRICTED entry the backend adds. The fixture folder gets the
    // same entry so the child can start.
    [LiveTargetFact("win-x64")] public Task Restricted_child_attached_on_win_x64() => ChildAttached(LiveTarget.WinX64, restricted: true);
    [LiveTargetFact("win-x86")] public Task Restricted_child_attached_on_win_x86() => ChildAttached(LiveTarget.WinX86, restricted: true);

    private async Task ChildAttached(LiveTarget target, bool restricted = false)
    {
        var (launcher, orders) = Build(target);
        if (restricted && OperatingSystem.IsWindows())
        {
            FridaBackend.AllowSandboxedReads(_dir.Path);
            UserOnly(Path.Combine(AnalysisCache.DefaultRoot, "workers", "live-temp"));
        }
        await using var server = await Server();
        var parent = await SpawnFollowing(server, launcher, orders, restricted);
        var child = await HeldChild(server, orders);

        var attached = await Ok(server, "live_session", new() { ["action"] = "attach_child", ["session"] = "live-1", ["program"] = child.ToString(CultureInfo.InvariantCulture) });
        Assert.Contains($"live-2 (frida): {child} pid {child}, suspended", attached);
        Assert.Contains("(held by live-1)", attached);
        Assert.Contains("s1 set at", await Ok(server, "live_break", new() { ["session"] = "live-2", ["action"] = "set", ["at"] = "AddLine" }));
        var stop = await Ok(server, "live_break", new() { ["session"] = "live-2", ["action"] = "continue", ["wait"] = true, ["waitSeconds"] = 60 });
        Assert.Contains("program started", stop);
        Assert.Matches($@"stopped at s1 \({Regex.Escape(target.Exe("orders"))}!AddLine\)", stop);
        await Ok(server, "live_break", new() { ["session"] = "live-2", ["action"] = "clear", ["stopPoint"] = "s1" });
        await Ok(server, "live_break", new() { ["session"] = "live-2", ["action"] = "continue" });

        Assert.Matches(@"exit code 0(?![0-9xX])", await UntilExited(server, "live-1"));
        var output = await Events(server, "live-1", kind: "output");
        Assert.Contains("lines 3", output);
        Assert.Contains("child exited 0", output);
        Assert.Contains($"pid {child} attached in live-2", await Ok(server, "live_session", new() { ["action"] = "children", ["session"] = "live-1" }));
        await Ok(server, "live_session", new() { ["action"] = "close", ["session"] = "live-2" });
        await Ok(server, "live_session", new() { ["action"] = "close", ["session"] = "live-1" });
        Ended(child);
        Ended(parent);
    }

    // The sandbox an attach refusal names is read from the target's token.
    [LiveTargetFact("win-x64")]
    public void Sandbox_read_from_a_restricted_child()
    {
        if (!OperatingSystem.IsWindows()) return;
        var launcher = LiveTarget.WinX64.Build(_dir, "launcher", LivePrograms.Launcher);
        var probe = LiveTarget.WinX64.Build(_dir, "probe", LivePrograms.Probe);
        FridaBackend.AllowSandboxedReads(_dir.Path);
        using var parent = Process.Start(new ProcessStartInfo(launcher) { ArgumentList = { "--restricted", probe, "x", "30" }, RedirectStandardOutput = true })!;
        Process? child = null;
        try
        {
            for (int i = 0; i < 100 && child == null; i++, Thread.Sleep(100))
                child = Process.GetProcessesByName("probe").FirstOrDefault(p => string.Equals(p.MainModule?.FileName, probe, StringComparison.OrdinalIgnoreCase));
            Assert.NotNull(child);
            Assert.Equal("a restricted token", ProcessSandbox.Describe(child.Id));
            Assert.Null(ProcessSandbox.Describe(parent.Id));
        }
        finally
        {
            child?.Kill();
            parent.Kill();
        }
    }

    // A process another process starts naming the program its parent (WebView2's browser process) passes no hold: children lists it to attach.
    [LiveTargetFact("win-x64")]
    public async Task Child_started_by_another_process_is_listed()
    {
        var launcher = LiveTarget.WinX64.Build(_dir, "launcher", LivePrograms.Launcher);
        var probe = LiveTarget.WinX64.Build(_dir, "probe", LivePrograms.Probe);
        await using var server = await Server();
        var open = await Ok(server, "live_session", new() { ["action"] = "spawn", ["program"] = probe, ["arguments"] = new[] { "x", "30" }, ["childNames"] = new[] { "*" } });
        var program = int.Parse(Regex.Match(open, @"pid (\d+)").Groups[1].Value, CultureInfo.InvariantCulture);
        await Ok(server, "live_break", new() { ["session"] = "live-1", ["action"] = "continue" });
        using var broker = Process.Start(new ProcessStartInfo(launcher) { ArgumentList = { "--parent", program.ToString(CultureInfo.InvariantCulture), probe, "y", "30" }, RedirectStandardOutput = true })!;
        int child = 0;
        try
        {
            for (int i = 0; i < 100 && child == 0; i++, await Task.Delay(100))
                if (Regex.Match(await Ok(server, "live_session", new() { ["action"] = "children", ["session"] = "live-1" }, log: false),
                        @"pid (\d+) started by another process, not held: probe\.exe \(live_session action=attach program=\1\)") is { Success: true } m)
                    child = int.Parse(m.Groups[1].Value, CultureInfo.InvariantCulture);
            Assert.NotEqual(0, child);
            Assert.Contains("0 started, 0 held", await Ok(server, "live_session", new() { ["action"] = "children", ["session"] = "live-1" }));
        }
        finally
        {
            if (child != 0) Process.GetProcessById(child).Kill();
            broker.Kill();
        }
        await Ok(server, "live_session", new() { ["action"] = "close", ["session"] = "live-1" });
        Ended(program);
    }

    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    private static void UserOnly(string folder)
    {
        var info = Directory.CreateDirectory(folder);
        var acl = new DirectorySecurity();
        acl.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        foreach (var sid in new[] { WindowsIdentity.GetCurrent().User!, new SecurityIdentifier("S-1-5-18") })
            acl.AddAccessRule(new FileSystemAccessRule(sid, FileSystemRights.FullControl,
                InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
                PropagationFlags.None, AccessControlType.Allow));
        info.SetAccessControl(acl);
    }

    // ---- a child still held at the close runs on

    [LiveTargetFact("win-x64")] public Task Held_child_runs_on_after_close_on_win_x64() => HeldChildRunsOn(LiveTarget.WinX64);
    [LiveTargetFact("win-x86")] public Task Held_child_runs_on_after_close_on_win_x86() => HeldChildRunsOn(LiveTarget.WinX86);
    [LiveTargetFact("linux-x64")] public Task Held_child_runs_on_after_close_on_linux_x64() => HeldChildRunsOn(LiveTarget.LinuxX64);
    [LiveTargetFact("linux-x86")] public Task Held_child_runs_on_after_close_on_linux_x86() => HeldChildRunsOn(LiveTarget.LinuxX86);

    private async Task HeldChildRunsOn(LiveTarget target)
    {
        var (launcher, orders) = Build(target);
        await using var server = await Server();
        var parent = await SpawnFollowing(server, launcher, orders);
        var child = await HeldChild(server, orders);
        await Ok(server, "live_session", new() { ["action"] = "close", ["session"] = "live-1" });
        Ended(parent);
        Ended(child);
    }

    // ---- without childNames the session sees only the launcher

    [LiveTargetFact("win-x64")] public Task Not_followed_on_win_x64() => NotFollowed(LiveTarget.WinX64);
    [LiveTargetFact("win-x86")] public Task Not_followed_on_win_x86() => NotFollowed(LiveTarget.WinX86);
    [LiveTargetFact("linux-x64")] public Task Not_followed_on_linux_x64() => NotFollowed(LiveTarget.LinuxX64);
    [LiveTargetFact("linux-x86")] public Task Not_followed_on_linux_x86() => NotFollowed(LiveTarget.LinuxX86);

    private async Task NotFollowed(LiveTarget target)
    {
        var (launcher, orders) = Build(target);
        await using var server = await Server();
        var parent = await Spawn(server, launcher, "live-1", orders, "3", "0");
        await Ok(server, "live_break", new() { ["session"] = "live-1", ["action"] = "continue" });
        Assert.Matches(@"exit code 0(?![0-9xX])", await UntilExited(server, "live-1"));
        Assert.Contains("child exited 0", await Events(server, "live-1", kind: "output"));
        Assert.Contains("No events.", await Events(server, "live-1", kind: "child"));
        Assert.Contains("does not follow child processes", await Ok(server, "live_session", new() { ["action"] = "children", ["session"] = "live-1" }));
        await Ok(server, "live_session", new() { ["action"] = "close", ["session"] = "live-1" });
        Ended(parent);
    }

    // ---- a program that starts a copy of itself through /proc/self/exe: the copy is held by the program's name, and a
    // stop point set in its session is hit there (fork and execv, and posix_spawn, which reports no fork)

    [LiveTargetFact("linux-x64")] public Task Copy_started_by_fork_and_exec_on_linux_x64() => CopyStopped(LiveTarget.LinuxX64, "fork");
    [LiveTargetFact("linux-x86")] public Task Copy_started_by_fork_and_exec_on_linux_x86() => CopyStopped(LiveTarget.LinuxX86, "fork");
    [LiveTargetFact("linux-x64")] public Task Copy_started_by_posix_spawn_on_linux_x64() => CopyStopped(LiveTarget.LinuxX64, "spawn");
    [LiveTargetFact("linux-x86")] public Task Copy_started_by_posix_spawn_on_linux_x86() => CopyStopped(LiveTarget.LinuxX86, "spawn");

    private async Task CopyStopped(LiveTarget target, string mode)
    {
        var exe = target.Build(_dir, "selfstart", LivePrograms.SelfStarter);
        await using var server = await Server();
        await Ok(server, "live_session", new() { ["action"] = "spawn", ["program"] = exe, ["arguments"] = new[] { mode }, ["childNames"] = new[] { "selfstart" } });
        await Ok(server, "live_break", new() { ["session"] = "live-1", ["action"] = "continue" });
        var copy = await HeldChild(server, exe);
        await Ok(server, "live_session", new() { ["action"] = "attach_child", ["session"] = "live-1", ["program"] = copy.ToString(CultureInfo.InvariantCulture) });
        Assert.Contains("s1 set at", await Ok(server, "live_break", new() { ["session"] = "live-2", ["action"] = "set", ["at"] = "libc.so.6!exit" }));
        var stop = await Ok(server, "live_break", new() { ["session"] = "live-2", ["action"] = "continue", ["wait"] = true, ["waitSeconds"] = 60 });
        Assert.Matches($@"thread {copy} stopped at s1 \(libc\.so\.6!", stop);
        Assert.Matches(@"selfstart!main\+0x[0-9A-F]+", stop);
        await Ok(server, "live_break", new() { ["session"] = "live-2", ["action"] = "continue" });
        Assert.Matches(@"exit code 0(?![0-9xX])", await UntilExited(server, "live-1"));
        Assert.Contains("copy exited 3", await Events(server, "live-1", kind: "output"));
        await Ok(server, "live_session", new() { ["action"] = "close", ["session"] = "live-2" });
        await Ok(server, "live_session", new() { ["action"] = "close", ["session"] = "live-1" });
        Ended(copy);
    }

    // ---- a child session closed before its first continue: the copy, let go stopped for that attach, runs on and exits

    [LiveTargetFact("linux-x64")] public Task Copy_runs_on_after_its_session_closes_unstarted_on_linux_x64() => CopyRunsOn(LiveTarget.LinuxX64);
    [LiveTargetFact("linux-x86")] public Task Copy_runs_on_after_its_session_closes_unstarted_on_linux_x86() => CopyRunsOn(LiveTarget.LinuxX86);

    private async Task CopyRunsOn(LiveTarget target)
    {
        var exe = target.Build(_dir, "selfstart", LivePrograms.SelfStarter);
        await using var server = await Server();
        await Ok(server, "live_session", new() { ["action"] = "spawn", ["program"] = exe, ["arguments"] = new[] { "fork" }, ["childNames"] = new[] { "selfstart" } });
        await Ok(server, "live_break", new() { ["session"] = "live-1", ["action"] = "continue" });
        var copy = await HeldChild(server, exe);
        await Ok(server, "live_session", new() { ["action"] = "attach_child", ["session"] = "live-1", ["program"] = copy.ToString(CultureInfo.InvariantCulture) });
        await Ok(server, "live_session", new() { ["action"] = "close", ["session"] = "live-2" });
        Assert.Matches(@"exit code 0(?![0-9xX])", await UntilExited(server, "live-1", 30));
        Assert.Contains("copy exited 3", await Events(server, "live-1", kind: "output"));
        await Ok(server, "live_session", new() { ["action"] = "close", ["session"] = "live-1" });
        Ended(copy);
    }

    // ---- a snapshot of a program while the child it started is held

    [LiveTargetFact("linux-x64")] public Task Snapshot_while_a_posix_spawn_child_is_held_on_linux_x64() => SnapshotWhileHeld(LiveTarget.LinuxX64, "spawn");
    [LiveTargetFact("linux-x64")] public Task Snapshot_while_a_fork_child_is_held_on_linux_x64() => SnapshotWhileHeld(LiveTarget.LinuxX64, "fork");

    private async Task SnapshotWhileHeld(LiveTarget target, string mode)
    {
        var exe = target.Build(_dir, "selfstart", LivePrograms.SelfStarter);
        await using var server = await Server();
        var open = await Ok(server, "live_session", new() { ["action"] = "spawn", ["program"] = exe, ["arguments"] = new[] { mode }, ["childNames"] = new[] { "selfstart" } });
        var parent = int.Parse(Regex.Match(open, @"pid (\d+)").Groups[1].Value, CultureInfo.InvariantCulture);
        await Ok(server, "live_break", new() { ["session"] = "live-1", ["action"] = "continue" });
        var copy = await HeldChild(server, exe);
        var sw = Stopwatch.StartNew();
        var (text, failed) = await Call(server, "live_session", new() { ["action"] = "snapshot", ["session"] = "live-1", ["outputPath"] = _dir.File("parent.core") });
        Output.WriteLine($"snapshot in {sw.ElapsedMilliseconds} ms: {text}");
        Assert.False(failed, text);
        Assert.NotEqual('T', Corvus.Native.Diagnostics.ProcessSnapshot.State(parent, parent));
        await Ok(server, "live_session", new() { ["action"] = "close", ["session"] = "live-1" });
        Ended(parent);
        Ended(copy);
    }

    // ---- a snapshot of a running child under coverage

    [LiveTargetFact("linux-x64")] public Task Snapshot_of_a_covered_copy_started_by_fork_on_linux_x64() => CoveredCopySnapshot(LiveTarget.LinuxX64, "fork");
    [LiveTargetFact("linux-x86")] public Task Snapshot_of_a_covered_copy_started_by_fork_on_linux_x86() => CoveredCopySnapshot(LiveTarget.LinuxX86, "fork");
    [LiveTargetFact("linux-x64")] public Task Snapshot_of_a_covered_copy_started_by_posix_spawn_on_linux_x64() => CoveredCopySnapshot(LiveTarget.LinuxX64, "spawn");
    [LiveTargetFact("linux-x86")] public Task Snapshot_of_a_covered_copy_started_by_posix_spawn_on_linux_x86() => CoveredCopySnapshot(LiveTarget.LinuxX86, "spawn");

    private async Task CoveredCopySnapshot(LiveTarget target, string mode)
    {
        var exe = target.Build(_dir, "selfstart", LivePrograms.SelfStarter);
        await using var server = await Server();
        var open = await Ok(server, "live_session", new() { ["action"] = "spawn", ["program"] = exe, ["arguments"] = new[] { mode, "8000" }, ["childNames"] = new[] { "selfstart" } });
        var parent = int.Parse(Regex.Match(open, @"pid (\d+)").Groups[1].Value, CultureInfo.InvariantCulture);
        await Ok(server, "live_break", new() { ["session"] = "live-1", ["action"] = "continue" });
        var copy = await HeldChild(server, exe);
        await Ok(server, "live_session", new() { ["action"] = "attach_child", ["session"] = "live-1", ["program"] = copy.ToString(CultureInfo.InvariantCulture) });
        Assert.Contains("counting", await Ok(server, "live_coverage", new() { ["session"] = "live-2", ["action"] = "start" }));
        await Ok(server, "live_break", new() { ["session"] = "live-2", ["action"] = "continue" });
        await Task.Delay(1000);
        var sw = Stopwatch.StartNew();
        var snapshot = await Ok(server, "live_session", new() { ["action"] = "snapshot", ["session"] = "live-2", ["outputPath"] = _dir.File("copy.core") });
        Output.WriteLine($"snapshot in {sw.ElapsedMilliseconds} ms");
        Assert.Contains("the program keeps running", snapshot);
        Assert.Contains("Tick", await Ok(server, "live_coverage", new() { ["action"] = "report", ["run"] = "cov-1" }));
        await Ok(server, "live_session", new() { ["action"] = "close", ["session"] = "live-2" });
        await Ok(server, "live_session", new() { ["action"] = "close", ["session"] = "live-1" });
        Ended(parent);
        Ended(copy);
    }
}
