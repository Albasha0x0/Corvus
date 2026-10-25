using System.Diagnostics;
using Corvus.Core;
using Corvus.Native.Providers;
using Corvus.Native.Providers.Live;
using ModelContextProtocol.Protocol;
using Xunit.Abstractions;
using static Corvus.Tests.AxmlWriter;

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

    private const string LedgerPackage = "com.example.ledger";

    /// <summary>
    /// An app whose launcher activity, LedgerActivity, logs through android.util.Log.i from run(), which it posts to the
    /// main looper every 100 ms (lines 20-23); targetSdkVersion 29, so a JAR signature installs it.
    /// </summary>
    internal static byte[] LedgerApk()
    {
        const string Activity = "Lcom/example/ledger/LedgerActivity;";
        var b = new DexBuilder();
        var c = b.Class(Activity, super: "Landroid/app/Activity;", source: "LedgerActivity.java");
        c.Interfaces.Add("Ljava/lang/Runnable;");
        c.Method("<init>", "V", [], 0x10001, Asm.Invoke(0x70, "Landroid/app/Activity;-><init>()V", 0), Asm.ReturnVoid()).Registers = 1;
        var create = c.Method("onCreate", "V", ["Landroid/os/Bundle;"], 0x1,
            Asm.Invoke(0x6f, "Landroid/app/Activity;->onCreate(Landroid/os/Bundle;)V", 0, 1),
            Asm.Invoke(0x6e, Activity + "->run()V", 0),
            Asm.ReturnVoid());
        create.Registers = 2;
        create.Lines.AddRange([(0, 10), (3, 11), (6, 12)]);
        var run = c.Method("run", "V", [], 0x1,
            Asm.ConstString(0, "Ledger"),
            Asm.ConstString(1, "balance"),
            Asm.Invoke(0x71, "Landroid/util/Log;->i(Ljava/lang/String;Ljava/lang/String;)I", 0, 1),
            Asm.NewInstance(0, "Landroid/os/Handler;"),
            Asm.Invoke(0x71, "Landroid/os/Looper;->getMainLooper()Landroid/os/Looper;"),
            Asm.Op11x(0x0c, 1),
            Asm.Invoke(0x70, "Landroid/os/Handler;-><init>(Landroid/os/Looper;)V", 0, 1),
            Asm.ConstWide(1, 100),
            Asm.Invoke(0x6e, "Landroid/os/Handler;->postDelayed(Ljava/lang/Runnable;J)Z", 0, 4, 1, 2),
            Asm.ReturnVoid());
        run.Registers = 5;
        run.Lines.AddRange([(0, 20), (4, 21), (7, 22), (24, 23)]);
        var manifest = AxmlWriter.Write(new Node("manifest", String("package", LedgerPackage, ns: null), Int("versionCode", 1, 0x0101021b)).Add(
            new Node("uses-sdk", Int("minSdkVersion", 23, 0x0101020c), Int("targetSdkVersion", 29, 0x01010270)),
            new Node("application").Add(
                new Node("activity", String("name", "com.example.ledger.LedgerActivity", 0x01010003), Bool("exported", true, 0x01010010)).Add(
                    new Node("intent-filter").Add(
                        new Node("action", String("name", "android.intent.action.MAIN", 0x01010003)),
                        new Node("category", String("name", "android.intent.category.LAUNCHER", 0x01010003)))))));
        return SignedApk.Build(("AndroidManifest.xml", manifest), ("classes.dex", b.Build()));
    }

    private string Adb(string op, params (string, string)[] values) => Adb(op, values, []);

    private string Adb(string op, (string, string)[] values, string[] extra)
    {
        var adb = ExternalTools.Locate(ExternalTools.Adb)!.Value.Path;
        var r = ExternalTools.Run(adb, [.. ExternalTools.Arguments(ExternalTools.Adb, op, [("serial", _serial), .. values]), .. extra], TimeSpan.FromMinutes(2), 1 << 20, default);
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
        // The class loader lists the DEX; the frame's line names its method and dex pc.
        Assert.Contains($"DEX: {Remote} = ", stop);
        Assert.Matches(@"j\d+ Ledger\.balanceOf  Ledger\.java:10 = LLedger;->balanceOf\(I\)I dex pc 0004", stop);
        Assert.Matches(@"j\d+ Ledger\.main  Ledger\.java:4", stop);

        var (closed, e3) = await Call(server, "live_session", new() { ["action"] = "close", ["session"] = "live-1" });
        Assert.False(e3, closed);
    }

    [AndroidLiveFact]
    public async Task An_installed_package_starts_and_its_main_thread_stops_with_Java_frames()
    {
        var apk = _dir.File("ledger.apk");
        File.WriteAllBytes(apk, LedgerApk());
        new Corvus.Services.Mobile.DeviceService(new ServerOptions()).WaitReady(_serial, TimeSpan.FromSeconds(60), default);
        Assert.Contains("Success", Adb("install", [], ["-r", apk]));
        try
        {
            await using var server = await InProcessServer.StartAsync(options: new ServerOptions
            {
                BackgroundIndexing = false, WatchFiles = false, AllowLive = true, AllowLiveSpawn = true,
            });
            var (open, failed) = await Call(server, "live_session", new() { ["action"] = "spawn", ["device"] = _serial, ["program"] = LedgerPackage });
            Assert.False(failed, open);
            Assert.Contains("suspended", open);

            // The stop point goes in once the activity runs: ART starts its Signal Catcher thread after the earliest logs.
            var (started, e1) = await Call(server, "live_break", new() { ["session"] = "live-1", ["action"] = "continue" });
            Assert.False(e1, started);
            await Task.Delay(TimeSpan.FromSeconds(5));
            var (set, e2) = await Call(server, "live_break", new() { ["session"] = "live-1", ["action"] = "set", ["at"] = "liblog.so!__android_log_buf_write" });
            Assert.False(e2, set);

            // Other threads log too; the activity's own log is the stop whose Java frames name LedgerActivity.run.
            string stop = "";
            for (int i = 0; i < 20 && !stop.Contains("LedgerActivity.run", StringComparison.Ordinal); i++)
            {
                (stop, var e3) = await Call(server, "live_break", new() { ["session"] = "live-1", ["action"] = "continue", ["wait"] = true, ["waitSeconds"] = 30 });
                Assert.False(e3, stop);
            }
            Assert.Contains("Java frames (ART, thread \"main\", Native)", stop);
            Assert.Matches(@"j\d+ android\.util\.Log\.i ", stop);
            Assert.Matches(@"DEX: /data/app/\S+/base\.apk = ", stop);
            Assert.Matches(@"j\d+ com\.example\.ledger\.LedgerActivity\.run  LedgerActivity\.java:21 = Lcom/example/ledger/LedgerActivity;->run\(\)V dex pc 0004", stop);

            var (closed, e4) = await Call(server, "live_session", new() { ["action"] = "close", ["session"] = "live-1" });
            Assert.False(e4, closed);
        }
        finally
        {
            Adb("uninstall", [], [LedgerPackage]);
        }
    }
}
