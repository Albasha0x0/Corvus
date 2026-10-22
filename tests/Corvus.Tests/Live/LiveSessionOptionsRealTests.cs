using System.Diagnostics;
using System.Text.RegularExpressions;
using Xunit.Abstractions;

namespace Corvus.Tests;

/// <summary>
/// live_session's options on each target: a started program's arguments, extra variables and working folder (the server's
/// other variables kept out), attach by process name, inspect_process by session id, a snapshot to a chosen file replaced
/// only with overwrite, and attach to a process id no process has.
/// </summary>
[Trait("Speed", "Slow")]
[Trait("Data", "Real")]
[Permit("live")]
public sealed class LiveSessionOptionsRealTests(ITestOutputHelper output) : LiveToolCalls(output), IDisposable
{
    private readonly TempDir _dir = new();

    public void Dispose() => _dir.Dispose();

    [LiveTargetFact("win-x64")] public Task Options_on_win_x64() => Options(LiveTarget.WinX64);
    [LiveTargetFact("win-x86")] public Task Options_on_win_x86() => Options(LiveTarget.WinX86);
    [LiveTargetFact("win-arm64")] public Task Options_on_win_arm64() => Options(LiveTarget.WinArm64);
    [LiveTargetFact("linux-x64")] public Task Options_on_linux_x64() => Options(LiveTarget.LinuxX64);
    [LiveTargetFact("osx-arm64")] public Task Options_on_osx_arm64() => Options(LiveTarget.MacArm64);
    [LiveTargetFact("linux-x86")] public Task Options_on_linux_x86() => Options(LiveTarget.LinuxX86);

    private async Task Options(LiveTarget target)
    {
        var exe = target.Build(_dir, "probe", LivePrograms.Probe);
        await using var server = await Server();

        var secret = Environment.GetEnvironmentVariable("PROBE_SECRET");
        Environment.SetEnvironmentVariable("PROBE_SECRET", "server only");
        try
        {
            var open = await Ok(server, "live_session", new()
            {
                ["action"] = "spawn", ["program"] = exe, ["arguments"] = new[] { "has space", "0" }, ["environment"] = new[] { "PROBE_MODE=audit" },
            });
            Assert.Contains("live-1 (frida): ", open);
            await Ok(server, "live_break", new() { ["session"] = "live-1", ["action"] = "continue" });
            Assert.Matches(@"exit code 3(?![0-9xX])", await UntilExited(server, "live-1"));
        }
        finally { Environment.SetEnvironmentVariable("PROBE_SECRET", secret); }
        string printed = "";
        for (int i = 0; i < 50 && !printed.Contains("arg1="); i++, await Task.Delay(100)) printed = await Events(server, "live-1", kind: "output");
        Assert.Contains("mode=audit", printed);
        Assert.Contains("secret=(none)", printed);
        Assert.Contains("argc=3 arg1=has space", printed);
        var cwd = Regex.Match(printed, @"cwd=([^\r\n]+)").Groups[1].Value;
        Assert.True(File.Exists(Path.Combine(cwd, "probe.c")), $"the program ran in {cwd}, not in its folder {_dir.Path}");
        await Ok(server, "live_session", new() { ["action"] = "close", ["session"] = "live-1" });

        // attach by a name no other process has
        var unique = "probe" + Guid.NewGuid().ToString("N")[..8];
        var named = target.Build(_dir, unique, LivePrograms.Probe);
        using var program = Process.Start(new ProcessStartInfo(named, "x 60") { RedirectStandardOutput = true, UseShellExecute = false })!;
        try
        {
            Assert.Contains($"pid {program.Id}", await Ok(server, "live_session", new() { ["action"] = "attach", ["program"] = target.Exe(unique) }));
            if (target.Windows)
            {
                var summary = await Ok(server, "inspect_process", new() { ["process"] = "live-2" });
                Assert.Contains($"{program.Id}", summary);
                Assert.Contains(target.Exe(unique), summary);
            }

            var path = _dir.File(target.Windows ? "probe.dmp" : "probe.core");
            var args = new Dictionary<string, object?> { ["action"] = "snapshot", ["session"] = "live-2", ["outputPath"] = path };
            if (target.Emulated) Assert.Contains("emulated on an ARM64 machine", await Refused(server, "live_session", args, "unsupported"));
            else
            {
                Assert.Contains($"written to {path}", await Ok(server, "live_session", args));
                var (again, refused) = await Call(server, "live_session", args);
                Assert.True(refused && again.Contains("\"code\":\"conflict\""), again);
                args["overwrite"] = true;
                Assert.Contains($"written to {path}", await Ok(server, "live_session", args));
            }

            await Ok(server, "live_session", new() { ["action"] = "close", ["session"] = "live-2" });
            Thread.Sleep(500);
            Assert.False(program.HasExited, "close ended a program the session attached to");
        }
        finally
        {
            if (!program.HasExited) program.Kill();
            program.WaitForExit(10_000);
        }

        var (missing, failed) = await Call(server, "live_session", new() { ["action"] = "attach", ["program"] = "999999999" });
        Assert.True(failed && missing.Contains("\"code\":\"not_found\""), missing);
    }
}
