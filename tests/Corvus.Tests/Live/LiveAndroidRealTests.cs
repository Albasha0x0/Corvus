using System.Diagnostics;
using Corvus.Core;
using Corvus.Native.Providers;
using Corvus.Native.Providers.Live;
using ModelContextProtocol.Protocol;
using Xunit.Abstractions;

namespace Corvus.Tests;

/// <summary>
/// Runs when CORVUS_LIVE_ANDROID names the adb serial of a device (an emulator) running frida-server, and Frida's Python
/// bindings and adb are found (checked when a test runs).
/// </summary>
[Xunit.Sdk.XunitTestCaseDiscoverer(RunTimeSkips.FactDiscoverer, RunTimeSkips.Assembly)]
public sealed class AndroidLiveFactAttribute : FactAttribute, IRunTimeSkip
{
    public const string Variable = "CORVUS_LIVE_ANDROID";

    private static readonly Lazy<string?> Missing = new(() =>
        string.IsNullOrWhiteSpace(Environment.GetEnvironmentVariable(Variable)) ? $"Set {Variable} to a device serial to run this test."
        : new FridaBackend().Unavailable() is { } f ? f.Reason
        : ExternalTools.Locate(ExternalTools.Adb) == null ? "adb is not found (CORVUS_ADB)." : null);

    public string? RunTimeSkip() => Missing.Value;
}

/// <summary>
/// A session on a program running on an Android device: a DEX built here runs under the device's app_process, stops at a
/// library export, and the stop shows native frames named from the device's own libraries and the thread's Java frames.
/// </summary>
[Trait("Speed", "Slow")]
[Trait("Data", "Real")]
[Permit("live")]
public sealed class LiveAndroidRealTests(ITestOutputHelper output) : IDisposable
{
    private const string Remote = "/data/local/tmp/corvus-ledger.dex";
    private readonly TempDir _dir = new();
    private readonly string _serial = Environment.GetEnvironmentVariable(AndroidLiveFactAttribute.Variable)?.Trim() ?? "";

    public void Dispose()
    {
        if (_serial.Length > 0) Adb("remove", ("remote", Remote));
        _dir.Dispose();
    }

    /// <summary>Ledger.main calls balanceOf(1234) and sleeps 100 ms in a loop; balanceOf logs through android.util.Log.i.</summary>
    internal static byte[] LedgerDex()
    {
        var b = new DexBuilder();
        var c = b.Class("LLedger;", source: "Ledger.java");
        var main = c.Method("main", "V", ["[Ljava/lang/String;"], 0x9,
            Asm.Const16(0, 1234),
            Asm.Invoke(0x71, "LLedger;->balanceOf(I)I", 0),
            Asm.ConstWide(1, 100),
            Asm.Invoke(0x71, "Ljava/lang/Thread;->sleep(J)V", 1, 2),
            Asm.Goto(-11));
        main.Registers = 4;
        main.Lines.AddRange([(0, 3), (2, 4), (5, 5)]);
        var balance = c.Method("balanceOf", "I", ["I"], 0x9,
            Asm.ConstString(0, "Ledger"),
            Asm.ConstString(1, "balance"),
            Asm.Invoke(0x71, "Landroid/util/Log;->i(Ljava/lang/String;Ljava/lang/String;)I", 0, 1),
            Asm.Return(0x0f, 2));
        balance.Registers = 3;
        balance.Lines.AddRange([(0, 9), (4, 10), (7, 11)]);
        return b.Build();
    }

    private string Adb(string op, params (string, string)[] values)
    {
        var adb = ExternalTools.Locate(ExternalTools.Adb)!.Value.Path;
        var r = ExternalTools.Run(adb, ExternalTools.Arguments(ExternalTools.Adb, op, [("serial", _serial), .. values]), TimeSpan.FromMinutes(1), 1 << 20, default);
        output.WriteLine($"adb {op}: exit {r.ExitCode} {r.Stderr.Trim()}");
        return r.Text;
    }

    private async Task<(string Text, bool IsError)> Call(InProcessServer server, string tool, Dictionary<string, object?> args)
    {
        var sw = Stopwatch.StartNew();
        var r = await server.Client.CallToolAsync(tool, args);
        var text = string.Concat(r.Content.OfType<TextContentBlock>().Select(b => b.Text));
        output.WriteLine($"{tool} ({sw.ElapsedMilliseconds} ms): {text}");
        return (text, r.IsError == true);
    }

    [AndroidLiveFact]
    public async Task A_device_program_stops_at_a_library_export_with_native_and_Java_frames()
    {
        var dex = _dir.File("ledger.dex");
        File.WriteAllBytes(dex, LedgerDex());
        new Corvus.Services.Mobile.DeviceService(new ServerOptions()).WaitReady(_serial, TimeSpan.FromSeconds(60), default);
        Adb("push", ("local", dex), ("remote", Remote));
        await using var server = await InProcessServer.StartAsync(options: new ServerOptions
        {
            BackgroundIndexing = false, WatchFiles = false, AllowLive = true, AllowLiveSpawn = true,
        });

        var (open, failed) = await Call(server, "live_session", new()
        {
            ["action"] = "spawn", ["device"] = _serial, ["program"] = "/system/bin/app_process64",
            ["arguments"] = new[] { "/data/local/tmp", "Ledger" }, ["environment"] = new[] { "CLASSPATH=" + Remote },
        });
        Assert.False(failed, open);
        Assert.Contains("live-1 (frida): ", open);
        Assert.Contains("suspended", open);

        var (set, e1) = await Call(server, "live_break", new() { ["session"] = "live-1", ["action"] = "set", ["at"] = "liblog.so!__android_log_buf_write" });
        Assert.False(e1, set);
        Assert.Matches(@"s1 set at 0x[0-9A-F]+ liblog\.so!__android_log_buf_write", set);

        var (stop, e2) = await Call(server, "live_break", new() { ["session"] = "live-1", ["action"] = "continue", ["wait"] = true, ["waitSeconds"] = 60 });
        Assert.False(e2, stop);
        Assert.Matches(@"thread \d+ stopped at s1 \(liblog\.so!__android_log_buf_write\)", stop);
        Assert.Matches(@"#1 0x[0-9A-F]+ libandroid_runtime\.so!", stop);
        Assert.Contains("Java frames (ART, thread \"main\", Native)", stop);
        Assert.Matches(@"j\d+ android\.util\.Log\.i ", stop);
        Assert.Matches(@"j\d+ Ledger\.balanceOf  Ledger\.java:10", stop);
        Assert.Matches(@"j\d+ Ledger\.main  Ledger\.java:4", stop);

        var (closed, e3) = await Call(server, "live_session", new() { ["action"] = "close", ["session"] = "live-1" });
        Assert.False(e3, closed);
    }
}
