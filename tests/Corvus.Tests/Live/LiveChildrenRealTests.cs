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
}
