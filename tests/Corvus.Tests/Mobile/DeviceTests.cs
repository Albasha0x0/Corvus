using Corvus.Core;
using Corvus.Services.Mobile;

namespace Corvus.Tests;

/// <summary>The Android device tools against the fake adb: parsing, serial selection, pulls, the log budget and the device-change gate.</summary>
[Collection(ExternalToolEnvironmentCollection.Name)]
public sealed class DeviceTests : IDisposable
{
    private readonly TempDir _dir = new();
    private readonly FakeTool _fake = FakeDevice.Configure(new FakeTool(), AndroidSamples.Apk());
    private readonly EnvironmentScope _env;

    public DeviceTests() => _env = new EnvironmentScope().Set("CORVUS_ADB", FakeTool.Executable);

    public void Dispose()
    {
        _env.Dispose();
        _fake.Dispose();
        _dir.Dispose();
    }

    private DeviceService Service(bool allowChanges = false) => new(new ServerOptions { AllowDeviceChanges = allowChanges }) { Environment = _fake.Environment };

    [Fact]
    public void Devices_RowsStatesAndUnparsedLines()
    {
        var list = Service().Devices(default);
        Assert.Equal([(FakeDevice.Serial, "device", "sdk_gphone64_arm64"), ("R58M123ABC", "unauthorized", null)], list.Items.Select(d => (d.Serial, d.State, d.Model)));
        Assert.Equal(["garbage"], list.Unparsed);
        Assert.Equal(["devices", "-l"], _fake.ArgumentLists.Last());
    }

    [Fact]
    public void DeviceInfo_SummaryAndEmulatorEvidence_PinsTheOnlyReadyDevice()
    {
        var info = Service().DeviceInfo(null, null, 0, 100, default);
        Assert.Equal(FakeDevice.Serial, info.Serial);
        Assert.Equal(("34", "14", true, true), (info.Summary.Sdk, info.Summary.Release, info.Summary.Debuggable, info.Summary.Emulator));
        Assert.Equal(["arm64-v8a", "armeabi-v7a"], info.Summary.Abis);
        Assert.Contains("ro.kernel.qemu=1", info.Summary.EmulatorEvidence);
        Assert.Contains("ro.hardware=ranchu", info.Summary.EmulatorEvidence);
        Assert.Equal(9, info.Total); // the unterminated multi-line value is not a property
        Assert.Equal(["-s", FakeDevice.Serial, "shell", "getprop"], _fake.ArgumentLists.Last());
        Assert.Equal(["ro.build.version.sdk"], Service().DeviceInfo(FakeDevice.Serial, "version.sdk", 0, 100, default).Properties.Select(p => p.Name));
    }

    [Fact]
    public void Packages_PathsUidsInstallers_AndPackageInfoFromDumpsys()
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
    public void PullPackage_EverySplit_IntoAnEmptyDirectory_ThenReadsTheBase()
    {
        var pulled = Service().PullPackage(FakeDevice.Package, _dir.File("apks"), null, default);
        Assert.Equal(["base.apk", "split_config.arm64_v8a.apk"], pulled.Files.Select(f => Path.GetFileName(f.Local)));
        Assert.Equal(Blob.Sha256(File.ReadAllBytes(pulled.Files[0].Local)), pulled.Files[0].Sha256);
        Assert.Equal("com.example.app", pulled.Summary!.Package);
        Assert.Equal(ErrorCode.Conflict, Assert.Throws<ToolError>(() => Service().PullPackage(FakeDevice.Package, _dir.File("apks"), null, default)).Code);
        Assert.Equal(ErrorCode.NotFound, Assert.Throws<ToolError>(() => Service().PullPackage("com.missing", _dir.File("none"), null, default)).Code);
    }

    [Fact]
    public void PullFile_RefusesDirectories_AndLeavesNothingOnFailure()
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
    public void Log_FiltersAndParsesLines()
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

    /// <summary>A 1 MB log reads newest first in pages within the report budget; nextOffset walks to older lines.</summary>
    [Trait("Speed", "Slow")]
    [Fact]
    public async Task Log_PagesNewestFirstWithinTheBudget()
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
    public void InstallAndUninstall_AreGated_ThenMapFailures()
    {
        var apk = AndroidSamples.Save(_dir, "app.apk", AndroidSamples.Apk());
        var gated = Assert.Throws<ToolError>(() => Service().Install(apk, true, false, false, null, default));
        Assert.Equal(ErrorCode.Unsupported, gated.Code);
        Assert.Contains("--allow-device-changes", gated.Remediation);
        Assert.DoesNotContain(_fake.ArgumentLists, a => a.Contains("install-multiple"));
        Assert.Equal(ErrorCode.Unsupported, Assert.Throws<ToolError>(() => Service().Uninstall(FakeDevice.Package, false, null, default)).Code);

        var allowed = Service(allowChanges: true);
        Assert.StartsWith("Installed 1 APK(s)", allowed.Install(apk, true, false, true, null, default));
        Assert.Equal(["-s", FakeDevice.Serial, "install-multiple", "-r", "-g", apk], _fake.ArgumentLists.Last());
        var set = AndroidSamples.Save(_dir, "app.apks", ContainerFixtures.Zip(("splits/base-master.apk", AndroidSamples.Apk()), ("splits/config.en.apk", [1])));
        Assert.StartsWith("Installed 2 APK(s)", allowed.Install(set, false, false, false, null, default));
        var old = AndroidSamples.Save(_dir, "old.apk", AndroidSamples.Apk());
        var downgrade = Assert.Throws<ToolError>(() => allowed.Install(old, true, false, false, null, default));
        Assert.Equal(ErrorCode.Conflict, downgrade.Code);
        Assert.Contains("downgrade=true", downgrade.Remediation);
        Assert.StartsWith("Uninstalled com.example.app", allowed.Uninstall(FakeDevice.Package, true, null, default));
        Assert.Equal(["-s", FakeDevice.Serial, "uninstall", "-k", FakeDevice.Package], _fake.ArgumentLists.Last());
        Assert.Equal(ErrorCode.NotFound, Assert.Throws<ToolError>(() => allowed.Uninstall("com.missing", false, null, default)).Code);
    }

    [Fact]
    public void WithoutAdb_ProviderUnavailableNamingTheVariable()
    {
        using var env = new EnvironmentScope().Set("CORVUS_ADB", _dir.File("none.exe"));
        var error = Assert.Throws<ToolError>(() => Service().Devices(default));
        Assert.Equal(ErrorCode.ProviderUnavailable, error.Code);
        Assert.Contains("CORVUS_ADB", error.Remediation);
        Assert.True(ServerOptions.Parse([ServerOptions.AllowDeviceChangesOption]).AllowDeviceChanges);
        Assert.False(new ServerOptions().AllowDeviceChanges);
    }
}
