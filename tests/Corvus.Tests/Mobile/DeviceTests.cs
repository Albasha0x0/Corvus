using Corvus.Core;
using Corvus.Services.Mobile;

namespace Corvus.Tests;

/// <summary>The Android device tools against the fake adb, in nested classes that run side by side.</summary>
public abstract class DeviceTests : IDisposable
{
    private protected readonly TempDir _dir = new();
    private protected readonly FakeTool _fake = FakeDevice.Configure(new FakeTool(), AndroidSamples.Apk());

    public void Dispose()
    {
        _fake.Dispose();
        _dir.Dispose();
    }

    // Each fake adb call starts a .NET process: a saturated quick set delayed some past the 30 s quick-call limit,
    // which these tests do not measure.
    internal static readonly TimeSpan AdbLimit = TimeSpan.FromMinutes(2);

    private protected DeviceService Service(bool allowChanges = false) =>
        new(new ServerOptions { AllowDeviceChanges = allowChanges }) { Environment = _fake.Environment, AdbOverride = FakeTool.Executable, Short = AdbLimit };

    private protected static Dictionary<string, string> Facts(AndroidDeviceInfo info) => info.Properties.ToDictionary(p => p.Name, p => p.Value);

    public sealed class Info : DeviceTests
    {
        [Fact]
        public void A_device_is_ready_once_its_shell_reads_boot_completed()
        {
            _fake.On(@"shell getprop sys\.boot_completed$", "1\n");
            Service().WaitReady(FakeDevice.Serial, AdbLimit, default);
            Assert.Equal(["-s", FakeDevice.Serial, "shell", "getprop", "sys.boot_completed"], _fake.ArgumentLists.Last());
        }

        [Fact]
        public void A_listed_device_whose_shell_does_not_answer_is_named()
        {
            // The fake's shell sleeps past the check's limit, as an emulator that stopped answering does.
            _fake.On(@"shell getprop sys\.boot_completed$", "1\n", sleepMs: 60_000);
            var service = new DeviceService(new ServerOptions()) { Environment = _fake.Environment, AdbOverride = FakeTool.Executable, Short = TimeSpan.FromSeconds(2) };
            var e = Assert.Throws<ToolError>(() => service.WaitReady(FakeDevice.Serial, TimeSpan.FromSeconds(1), default));
            Assert.Equal(ErrorCode.ProviderUnavailable, e.Code);
            Assert.Contains($"device {FakeDevice.Serial} is listed as ready, but its shell did not answer", e.Message);
        }

        [Fact]
        public void Devices_list_their_states_and_keep_unparsed_lines()
        {
            var list = Service().Devices(default);
            Assert.Equal([(FakeDevice.Serial, "device", "sdk_gphone64_arm64"), ("R58M123ABC", "unauthorized", null)], list.Items.Select(d => (d.Serial, d.State, d.Model)));
            Assert.Equal(["garbage"], list.Unparsed);
            Assert.Equal(["devices", "-l"], _fake.ArgumentLists.Last());
        }

        [Fact]
        public void Device_info_summary_and_emulator_evidence_pins_the_only_ready_device()
        {
            var info = Service().DeviceInfo(null, null, 0, 100, default);
            Assert.Equal(FakeDevice.Serial, info.Serial);
            Assert.Equal(("34", "14", true, true), (info.Summary.Sdk, info.Summary.Release, info.Summary.Debuggable, info.Summary.Emulator));
            Assert.Equal(["arm64-v8a", "armeabi-v7a"], info.Summary.Abis);
            Assert.Contains("ro.kernel.qemu=1", info.Summary.EmulatorEvidence);
            Assert.Contains("ro.hardware=ranchu", info.Summary.EmulatorEvidence);
            // The unterminated multi-line value is not a property.
            Assert.Equal(9, info.Total);
            Assert.Equal(["-s", FakeDevice.Serial, "shell", "getprop"], _fake.ArgumentLists.Last());
            Assert.Equal(["ro.build.version.sdk"], Service().DeviceInfo(FakeDevice.Serial, "version.sdk", 0, 100, default).Properties.Select(p => p.Name));
        }

        [Fact]
        public void Device_info_views_list_processes_features_services_settings_and_files()
        {
            string Rows(string view, string? query = null, int offset = 0, int limit = 100) =>
                string.Join("; ", Service().DeviceInfo(null, query, offset, limit, default, view).Properties.Select(p => $"{p.Name}={p.Value}"));
            Assert.Equal("com.example.app=pid 4321, ppid 500, u0_a123", Rows("processes", "example"));
            Assert.Equal("system_server=pid 700, ppid 1, system", Rows("processes", offset: 1, limit: 1));
            Assert.Equal("android.hardware.camera=; android.software.vulkan.deqp.level=132383489; reqGlEsVersion=0x30002", Rows("features"));
            Assert.Equal("package=android.content.pm.IPackageManager", Rows("services", "package"));
            Assert.Equal("global/adb_enabled=1; global/airplane_mode_on=0; secure/android_id=0123456789abcdef; system/screen_brightness=102", Rows("settings"));
            Assert.Equal("note.txt=-rw-rw-rw- 22 bytes, 2024-01-02 03:05, shell:shell", Rows("files", limit: 2).Split("; ")[1]);
            Assert.Equal(ErrorCode.InvalidArgument, Assert.Throws<ToolError>(() => Rows("radio")).Code);
        }
    }

    public sealed class Capture : DeviceTests
    {
        [Fact]
        public void Screen_writes_the_exec_out_PNG_with_its_size_and_never_replaces_a_file()
        {
            var path = Path.GetFullPath(_dir.File("shots/screen.png"));
            var facts = Facts(Service().DeviceInfo(null, null, 0, 100, default, "screen", path));
            Assert.Equal((path, "1080x2400", FakeDevice.Screen.Length.ToString()), (facts["file"], facts["size"], facts["bytes"]));
            Assert.Equal(FakeDevice.Screen, File.ReadAllBytes(path));
            Assert.Equal(["-s", FakeDevice.Serial, "exec-out", "screencap", "-p"], _fake.ArgumentLists.Last());
            Assert.Equal(ErrorCode.Conflict, Assert.Throws<ToolError>(() => Service().DeviceInfo(null, null, 0, 100, default, "screen", path)).Code);
            Assert.Equal(["screen.png"], Directory.EnumerateFiles(_dir.File("shots")).Select(Path.GetFileName));
        }

        [Fact]
        public void Window_resolves_the_focused_activity_to_its_DEX_class()
        {
            var apk = AndroidSamples.Save(_dir, "app.apk", AndroidSamples.Apk(30, ("classes.dex", AndroidSamples.Dex())));
            var dex = new DexService();
            var service = new DeviceService(new ServerOptions(), dex) { Environment = _fake.Environment, AdbOverride = FakeTool.Executable, Short = AdbLimit };
            var unread = Facts(service.DeviceInfo(null, null, 0, 100, default, "window"));
            Assert.Equal(("com.example.app", "com.example.app.Main"), (unread["package"], unread["activity"]));
            Assert.StartsWith("no package read", unread["dex class"]);
            // A package read by a DEX tool is used without query.
            dex.ListClasses(apk, null, null, 0, 1, default);
            var facts = Facts(service.DeviceInfo(null, null, 0, 100, default, "window"));
            Assert.StartsWith($"{AndroidSamples.Main} in {apk}", facts["dex class"]);
            Assert.Equal("Landroid/app/Activity;", facts["extends"]);
            Assert.Contains("ActivityRecord{9f8e u0 com.example.app/.Main t12}", facts["focused app"]);
        }

        [Fact]
        public void Display_facts_name_sizes_density_screen_state_and_displays()
        {
            var facts = Facts(Service().DeviceInfo(null, null, 0, 100, default, "display"));
            Assert.Equal(("1080x2400", "720x1600", "420", "ON"), (facts["physical size"], facts["override size"], facts["physical density"], facts["screen state"]));
            Assert.StartsWith("uniqueId=\"local:4619827259835644672\", 1080 x 2400", facts["display \"Built-in Screen\""]);
        }

        [Fact]
        public void Bugreport_streams_the_zip_falls_back_to_a_pulled_zip_and_keeps_nothing_past_the_budget()
        {
            var streamed = Facts(Service().DeviceInfo(null, null, 0, 100, default, "bugreport", _dir.File("br")));
            Assert.Equal("bugreportz -s (streamed)", streamed["method"]);
            using (var zip = System.IO.Compression.ZipFile.OpenRead(streamed["file"]))
            using (var entry = new StreamReader(zip.GetEntry("bugreport-sdk_gphone64.txt")!.Open()))
                Assert.Equal("== dumpstate ==\n", entry.ReadToEnd());

            using var old = FakeDevice.Configure(new FakeTool()
                .On(@"exec-out bugreportz -s$", "Usage: bugreportz [-hpv]\n", exit: 1)
                .On(@"shell bugreportz$", "BEGIN:/bugreports/br.zip\nOK:/bugreports/br.zip\n")
                .On(@"stat -c %s /bugreports/br\.zip$", "2048\n")
                .On(@"pull /bugreports/br\.zip ", file: ContainerFixtures.Zip(("main_entry.txt", "x"u8.ToArray()))), AndroidSamples.Apk());
            DeviceService Old(long budget) => new(new ServerOptions()) { Environment = old.Environment, AdbOverride = FakeTool.Executable, MaxBugreportBytes = budget };
            var pulled = Facts(Old(1 << 20).DeviceInfo(null, null, 0, 100, default, "bugreport", _dir.File("br-old")));
            Assert.Equal("bugreportz, pulled from /bugreports/br.zip", pulled["method"]);
            Assert.True(File.Exists(pulled["file"]));
            var over = Assert.Throws<ToolError>(() => Old(1024).DeviceInfo(null, null, 0, 100, default, "bugreport", _dir.File("br-over")));
            Assert.Equal(ErrorCode.LimitExceeded, over.Code);
            Assert.Contains("pull_android_file", over.Remediation);
            var small = new DeviceService(new ServerOptions()) { Environment = _fake.Environment, AdbOverride = FakeTool.Executable, MaxBugreportBytes = 16, Short = AdbLimit };
            var cut = Assert.Throws<ToolError>(() => small.DeviceInfo(null, null, 0, 100, default, "bugreport", _dir.File("br-cut")));
            Assert.Equal(ErrorCode.LimitExceeded, cut.Code);
            Assert.Empty(Directory.EnumerateFileSystemEntries(_dir.File("br-cut")));
        }
    }

    public sealed class Packages : DeviceTests
    {
        [Fact]
        public void Packages_give_paths_UIDs_installers_and_dumpsys_info()
        {
            var packages = Service().Packages(null, null, null, 0, 100, default);
            var app = packages.Items.Single(p => p.Package == FakeDevice.Package);
            Assert.Equal(("/data/app/~~AbC==/com.example.app-XyZ==/base.apk", 10123, "com.android.vending"), (app.Path, app.Uid, app.Installer));
            Assert.Null(packages.Items.Single(p => p.Package == "com.android.settings").Installer);

            var info = Service().PackageInfo(FakeDevice.Package, null, default);
            Assert.Equal(("1.2", "42", 24, 34, "arm64-v8a", "/data/user/0/com.example.app"), (info.VersionName, info.VersionCode, info.MinSdk, info.TargetSdk, info.PrimaryCpuAbi, info.DataDir));
            Assert.Equal(["DEBUGGABLE", "HAS_CODE", "ALLOW_CLEAR_USER_DATA", "ALLOW_BACKUP"], info.Flags);
            Assert.Equal(("com.android.vending", 10123), (info.Installer, info.Uid));
            Assert.Equal((true, "install"), info.Permissions.Where(p => p.Name == "android.permission.INTERNET").Select(p => (p.Granted, p.Kind)).Single());
            var camera = info.Permissions.Single(p => p.Name == "android.permission.CAMERA");
            Assert.Equal((false, "runtime"), (camera.Granted, camera.Kind));
            Assert.Contains("USER_SENSITIVE_WHEN_GRANTED", camera.Flags);
            Assert.Equal((null, "requested"), info.Permissions.Where(p => p.Name == "android.permission.READ_EXTERNAL_STORAGE").Select(p => (p.Granted, p.Kind)).Single());
            Assert.Equal([(0, true), (10, false)], info.Users.Select(u => (u.User, u.Installed)));
            Assert.Equal(ErrorCode.NotFound, Assert.Throws<ToolError>(() => Service().PackageInfo("com.other", null, default)).Code);
            Assert.Equal(ErrorCode.InvalidArgument, Assert.Throws<ToolError>(() => Service().PackageInfo("com.example; reboot", null, default)).Code);
        }

        [Fact]
        public void Pull_package_every_split_into_an_empty_directory_then_reads_the_base()
        {
            var pulled = Service().PullPackage(FakeDevice.Package, _dir.File("apks"), null, default);
            Assert.Equal(["base.apk", "split_config.arm64_v8a.apk"], pulled.Files.Select(f => Path.GetFileName(f.Local)));
            Assert.Equal(Blob.Sha256(File.ReadAllBytes(pulled.Files[0].Local)), pulled.Files[0].Sha256);
            Assert.Equal("com.example.app", pulled.Summary!.Package);
            Assert.Equal(ErrorCode.Conflict, Assert.Throws<ToolError>(() => Service().PullPackage(FakeDevice.Package, _dir.File("apks"), null, default)).Code);
            Assert.Equal(ErrorCode.NotFound, Assert.Throws<ToolError>(() => Service().PullPackage("com.missing", _dir.File("none"), null, default)).Code);
        }

        [Fact]
        public void Pull_file_refuses_directories_and_leaves_nothing_on_failure()
        {
            var file = Service().PullFile("/data/local/tmp/notes.txt", _dir.File("out/notes.txt"), false, null, default);
            Assert.Equal("hello from the device\n", File.ReadAllText(file.Local));
            Assert.Equal(ErrorCode.Conflict, Assert.Throws<ToolError>(() => Service().PullFile("/data/local/tmp/notes.txt", file.Local, false, null, default)).Code);
            Assert.Equal(ErrorCode.InvalidArgument, Assert.Throws<ToolError>(() => Service().PullFile("/data/local/tmp/dir", _dir.File("d"), false, null, default)).Code);
            Assert.Equal(ErrorCode.Failed, Assert.Throws<ToolError>(() => Service().PullFile("/data/local/tmp/fail.txt", _dir.File("out/fail.txt"), false, null, default)).Code);
            Assert.Equal(ErrorCode.NotFound, Assert.Throws<ToolError>(() => Service().PullFile("/data/local/tmp/missing", _dir.File("out/missing"), false, null, default)).Code);
            Assert.Equal(["notes.txt"], Directory.EnumerateFiles(_dir.File("out")).Select(Path.GetFileName));
        }

        [Fact]
        public void Log_filters_and_parses_lines()
        {
            var error = Service().Log(null, null, null, "error", null, null, default).Lines;
            Assert.Equal(("01-02 03:04:05.679", 123, 456, "E", "App", "boom"), (error[1].Time, error[1].Pid, error[1].Tid, error[1].Priority, error[1].Tag, error[1].Message));
            Assert.Equal(["-s", FakeDevice.Serial, "logcat", "-d", "-v", "threadtime", "*:E"], _fake.ArgumentLists.Last());
            Assert.Equal("only pid", Service().Log(null, 999, null, null, null, null, default).Lines.Single().Message);
            var flood = Service().Log(null, null, "Flood", null, "100", "crash", default);
            Assert.Equal(5_000, flood.Lines.Count);
            Assert.Equal(["-s", FakeDevice.Serial, "logcat", "-d", "-v", "threadtime", "-b", "crash", "-t", "100", "Flood:V", "*:S"], _fake.ArgumentLists.Last());
            Assert.Equal(ErrorCode.InvalidArgument, Assert.Throws<ToolError>(() => Service().Log(null, null, "a b", null, null, null, default)).Code);
            Assert.Equal(ErrorCode.InvalidArgument, Assert.Throws<ToolError>(() => Service().Log(null, null, null, null, null, "kernel", default)).Code);
        }
    }

    public sealed class Changes : DeviceTests
    {
        [Fact]
        public void Install_and_uninstall_are_gated_then_map_failures()
        {
            var apk = AndroidSamples.Save(_dir, "app.apk", AndroidSamples.Apk());
            var gated = Assert.Throws<ToolError>(() => Service().Install(apk, true, false, false, null, default));
            Assert.Equal(ErrorCode.Unsupported, gated.Code);
            Assert.Contains("--allow-device-changes", gated.Remediation);
            Assert.DoesNotContain(_fake.ArgumentLists, a => a.Contains("install-multiple"));
            Assert.Equal(ErrorCode.Unsupported, Assert.Throws<ToolError>(() => Service().Uninstall(FakeDevice.Package, false, null, default)).Code);

            var allowed = Service(allowChanges: true);
            var installed = allowed.Install(apk, true, false, true, null, default);
            Assert.StartsWith("Installed 1 APK(s)", installed.Text);
            Assert.Equal(("install", "com.example.app", FakeDevice.Serial), (installed.Kind, installed.Package, installed.Serial));
            Assert.Equal(["-s", FakeDevice.Serial, "install-multiple", "-r", "-g", apk], _fake.ArgumentLists.Last());
            var set = AndroidSamples.Save(_dir, "app.apks", ContainerFixtures.Zip(("splits/base-master.apk", AndroidSamples.Apk()), ("splits/config.en.apk", [1])));
            Assert.StartsWith("Installed 2 APK(s)", allowed.Install(set, false, false, false, null, default).Text);
            var old = AndroidSamples.Save(_dir, "old.apk", AndroidSamples.Apk());
            var downgrade = Assert.Throws<ToolError>(() => allowed.Install(old, true, false, false, null, default));
            Assert.Equal(ErrorCode.Conflict, downgrade.Code);
            Assert.Contains("downgrade=true", downgrade.Remediation);
            Assert.StartsWith("Uninstalled com.example.app", allowed.Uninstall(FakeDevice.Package, true, null, default).Text);
            Assert.Equal(["-s", FakeDevice.Serial, "uninstall", "-k", FakeDevice.Package], _fake.ArgumentLists.Last());
            Assert.Equal(ErrorCode.NotFound, Assert.Throws<ToolError>(() => allowed.Uninstall("com.missing", false, null, default)).Code);
        }

        /// <summary>install_android_package replaces an installed app unless keepInstalled.</summary>
        [Trait("Speed", "Slow")]
        [Fact]
        public async Task Install_replaces_by_default_keep_installed_does_not()
        {
            var apk = AndroidSamples.Save(_dir, "app.apk", AndroidSamples.Apk());
            var tools = new Corvus.Tools.DeviceTools(Service(allowChanges: true));
            await tools.InstallAndroidPackage(apk);
            Assert.Equal(["-s", FakeDevice.Serial, "install-multiple", "-r", apk], _fake.ArgumentLists.Last());
            await tools.InstallAndroidPackage(apk, keepInstalled: true);
            Assert.Equal(["-s", FakeDevice.Serial, "install-multiple", apk], _fake.ArgumentLists.Last());
        }
    }
}

/// <summary>The device tools through CORVUS_ADB and an in-process server: the process environment, so one class at a time.</summary>
[Collection(ExternalToolEnvironmentCollection.Name)]
public sealed class DeviceEnvironmentTests : IDisposable
{
    private readonly TempDir _dir = new();
    private readonly FakeTool _fake = FakeDevice.Configure(new FakeTool(), AndroidSamples.Apk());
    private readonly EnvironmentScope _env = new EnvironmentScope().Set("CORVUS_ADB", FakeTool.Executable);

    public void Dispose()
    {
        _env.Dispose();
        _fake.Dispose();
        _dir.Dispose();
    }

    private DeviceService Service() => new(new ServerOptions()) { Environment = _fake.Environment, Short = DeviceTests.AdbLimit };

    /// <summary>A 1 MB log reads newest first in pages within the report budget; nextOffset walks to older lines.</summary>
    [Trait("Speed", "Slow")]
    [Fact]
    public async Task Log_pages_newest_first_within_the_budget()
    {
        using var script = new EnvironmentScope().Set(FakeTool.ScriptVariable, _fake.ScriptPath);
        await using var server = await InProcessServer.StartAsync();
        var page = await server.Client.CallToolAsync("read_android_log", new Dictionary<string, object?> { ["tag"] = "Flood" });
        var text = string.Concat(page.Content.OfType<ModelContextProtocol.Protocol.TextContentBlock>().Select(b => b.Text));
        var record = page.StructuredContent!.Value;
        Assert.Equal(5_000, record.GetProperty("total").GetInt32());
        Assert.True(TokenEstimate.Of(text) <= 4_200 && TokenEstimate.Of(record.GetRawText()) <= 4_200, $"{TokenEstimate.Of(text)} / {TokenEstimate.Of(record.GetRawText())}");
        int next = record.GetProperty("nextOffset").GetInt32();
        Assert.Equal(next, record.GetProperty("items").GetArrayLength());
        Assert.Contains($"[More: offset={next}]", text);
        Assert.Equal("Flood", record.GetProperty("items")[0].GetProperty("tag").GetString());
    }

    [Fact]
    public void Without_adb_provider_unavailable_naming_the_variable()
    {
        using var env = new EnvironmentScope().Set("CORVUS_ADB", _dir.File("none.exe"));
        var error = Assert.Throws<ToolError>(() => Service().Devices(default));
        Assert.Equal(ErrorCode.ProviderUnavailable, error.Code);
        Assert.Contains("CORVUS_ADB", error.Remediation);
        Assert.True(ServerOptions.Parse([ServerOptions.AllowDeviceChangesOption]).AllowDeviceChanges);
        Assert.False(new ServerOptions().AllowDeviceChanges);
    }
}
