using System.Diagnostics;
using Corvus.Native.Live;
using Xunit.Abstractions;

namespace Corvus.Tests;

/// <summary>Without CAP_SYS_PTRACE: ptrace_scope 1 refuses attach and snapshot with access_denied, 2 also refuses start; the value is restored.</summary>
[Trait("Speed", "Slow")]
[Trait("Data", "Real")]
[Permit("live")]
[Collection(nameof(LivePtraceScopeRealTests))]
public sealed class LivePtraceScopeRealTests(ITestOutputHelper output) : LiveToolCalls(output), IDisposable
{
    private readonly TempDir _dir = new();

    public void Dispose() => _dir.Dispose();

    [PtraceScopeFact]
    public async Task Scope_1_observes_started_programs_only_and_scope_2_refuses_every_session()
    {
        var exe = LiveTarget.LinuxX64.Build(_dir, "orders", LivePrograms.Orders);
        var original = File.ReadAllText(PtraceScope.SettingPath).Trim();
        using var program = Process.Start(new ProcessStartInfo(exe, "100000 5") { RedirectStandardOutput = true, UseShellExecute = false })!;
        try
        {
            await using var server = await Server();
            Set("1");
            var pid = await Spawn(server, exe, "live-1", "100000", "5");
            await Ok(server, "live_break", new() { ["session"] = "live-1", ["action"] = "set", ["at"] = "AddLine" });
            Assert.Matches(@"stopped at s1 \(orders!AddLine\)", await Ok(server, "live_break", new() { ["session"] = "live-1", ["action"] = "continue", ["wait"] = true, ["waitSeconds"] = 60 }));
            Assert.Contains("ptrace_scope is 1", await Refused(server, "live_session", new() { ["action"] = "snapshot", ["session"] = "live-1" }, "access_denied"));
            Assert.Contains($"pid {pid}, closed", await Ok(server, "live_session", new() { ["action"] = "close", ["session"] = "live-1" }));
            Ended(pid);
            Assert.Contains("ptrace_scope is 1", await Refused(server, "live_session", new() { ["action"] = "attach", ["program"] = $"{program.Id}" }, "access_denied"));

            Set("2");
            Assert.Contains("ptrace_scope is 2", await Refused(server, "live_session", new() { ["action"] = "spawn", ["program"] = exe, ["arguments"] = new[] { "3", "0" } }, "access_denied"));
            Assert.Contains("ptrace_scope is 2", await Refused(server, "live_session", new() { ["action"] = "attach", ["program"] = $"{program.Id}" }, "access_denied"));
            // A refused open leaves no session and no started program behind.
            Assert.DoesNotMatch(@"pid \d+, (running|suspended|stopped)", await Ok(server, "live_session", new() { ["action"] = "list" }));
            // This test builds orders in its own folder and other live classes run theirs elsewhere: only this copy counts.
            // An exited child is reaped once its worker is gone.
            for (int i = 0; i < 50 && Started(exe, program.Id).Count > 0; i++) await Task.Delay(100);
            Assert.Empty(Started(exe, program.Id));
        }
        finally
        {
            Set(original);
            if (!program.HasExited) program.Kill();
            program.WaitForExit(10_000);
        }
    }

    /// <summary>Processes running <paramref name="exe"/> other than <paramref name="except"/>.</summary>
    private static List<int> Started(string exe, int except) =>
        [.. Process.GetProcessesByName(Path.GetFileName(exe)).Where(p => p.Id != except).Where(p =>
        {
            try { return string.Equals(p.MainModule?.FileName, exe, StringComparison.Ordinal); }
            catch (Exception e) when (e is InvalidOperationException or System.ComponentModel.Win32Exception) { return false; }
        }).Select(p => p.Id)];

    private static void Set(string value)
    {
        var psi = new ProcessStartInfo("sudo") { RedirectStandardInput = true, RedirectStandardOutput = true, RedirectStandardError = true };
        foreach (var a in new[] { "-n", "tee", PtraceScope.SettingPath }) psi.ArgumentList.Add(a);
        using var p = Process.Start(psi)!;
        p.StandardInput.WriteLine(value);
        p.StandardInput.Close();
        var error = p.StandardError.ReadToEnd();
        p.WaitForExit();
        Assert.True(p.ExitCode == 0, error);
        Assert.Equal(value, File.ReadAllText(PtraceScope.SettingPath).Trim());
    }
}

/// <summary>ptrace_scope is machine-wide: the class runs alone, after the parallel classes, so no other session sees 1 or 2.</summary>
[CollectionDefinition(nameof(LivePtraceScopeRealTests), DisableParallelization = true)]
public sealed class LivePtraceScopeCollection;

/// <summary>Runs on Linux as a user without CAP_SYS_PTRACE that may set ptrace_scope with <c>sudo -n tee</c>, checked when a test runs.</summary>
[Xunit.Sdk.XunitTestCaseDiscoverer(RunTimeSkips.FactDiscoverer, RunTimeSkips.Assembly)]
public sealed class PtraceScopeFactAttribute : FactAttribute, IRunTimeSkip
{
    public string? RunTimeSkip() =>
        LiveTarget.LinuxX64.Missing is { } reason ? reason
        : Environment.IsPrivilegedProcess ? "Runs as a user without CAP_SYS_PTRACE (not root)."
        : !File.Exists(PtraceScope.SettingPath) ? "The kernel has no Yama ptrace_scope."
        : Tools.Run(Sudo("-n", "-l", "tee", PtraceScope.SettingPath), 30_000).ExitCode != 0
            ? $"This user may not set ptrace_scope (a sudoers entry for: tee {PtraceScope.SettingPath})."
            : null;

    private static ProcessStartInfo Sudo(params string[] args)
    {
        var psi = new ProcessStartInfo("sudo");
        foreach (var a in args) psi.ArgumentList.Add(a);
        return psi;
    }
}
