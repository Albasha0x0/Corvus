using System.ComponentModel;
using ModelContextProtocol.Server;
using Corvus.Core;
using Corvus.Mcp;
using Corvus.Services.Mobile;

namespace Corvus.Tools;

[McpServerToolType]
public sealed class DeviceTools(DeviceService devices)
{
    private const string SerialDescription = "Device serial; optional with one device.";

    [McpServerTool(Name = "list_android_devices", Title = "List Android devices", UseStructuredContent = true)]
    [Description("Android devices and emulators adb sees: serial, state, product, model, transport. adb: CORVUS_ADB, else PATH, else SDK " +
                 "platform-tools.")]
    public Task<AndroidDeviceList> ListAndroidDevices(CancellationToken cancellationToken = default) =>
        Task.Run(() => devices.Devices(cancellationToken), cancellationToken);

    [McpServerTool(Name = "get_android_device_info", Title = "Android device info", UseStructuredContent = true, OutputSchemaType = typeof(AndroidDeviceInfo))]
    [Description("Device properties (getprop) with a summary: SDK, release, model, ABIs, fingerprint, patch level, build type, ro.debuggable, " +
                 "ro.secure, emulator; view=: processes, features, services, settings, files, screen (PNG), window (focused activity), display, " +
                 "bugreport (zip). Read-only.")]
    public Task<string> GetAndroidDeviceInfo(
        [Description(SerialDescription)] string? serial = null,
        [Description("Name or value filter; view=files: directory (default /data/local/tmp); window: local APK.")] string? query = null,
        [Description(ToolSupport.RowOffsetDescription)] int offset = 0,
        [Description("Most rows.")] int limit = 100,
        [Description("What to read.")] string view = "props",
        [Description("view=screen: new PNG path; bugreport: new or empty directory; default under temp.")] string? outputPath = null,
        CancellationToken cancellationToken = default) => Task.Run(() =>
    {
        view = view.Trim().ToLowerInvariant();
        var r = devices.DeviceInfo(serial, query, offset, ToolSupport.ClampLimit(limit), cancellationToken, view, outputPath);
        var s = r.Summary;
        var header = $"{r.Serial}: Android {s.Release} (SDK {s.Sdk}), {s.Manufacturer} {s.Model}, ABIs {string.Join(", ", s.Abis)}; {s.BuildType}"
                     + $"{(s.Debuggable == true ? ", ro.debuggable=1" : "")}{(s.Secure == false ? ", ro.secure=0" : "")}; patch {s.SecurityPatch}"
                     + $"{(s.Emulator ? $"; emulator ({string.Join(", ", s.EmulatorEvidence)})" : "")}\nfingerprint {s.Fingerprint}\n";
        bool pairs = view is "props" or "settings" or "screen" or "window" or "display" or "bugreport";
        return ToolOutput.List(r.Properties, r.Offset, ToolSupport.ClampLimit(limit), r.Total, p => pairs ? $"{p.Name} = {p.Value}" : $"{p.Name}  {p.Value}",
            rows => r with { Properties = rows }, view switch
            {
                "processes" => "process", "features" => "feature", "services" => "service", "settings" => "setting", "files" => "entry",
                "screen" or "window" or "display" or "bugreport" => "fact", _ => "property",
            }, header);
    }, cancellationToken);

    [McpServerTool(Name = "list_android_packages", Title = "List installed packages", UseStructuredContent = true, OutputSchemaType = typeof(AndroidPackageList))]
    [Description("Packages installed on a device (pm list packages -f -U -i): name, APK path, uid and installer.")]
    public Task<string> ListAndroidPackages(
        [Description(SerialDescription)] string? serial = null,
        [Description("Only package names containing this.")] string? query = null,
        [Description("Android user id (default: current).")] int? user = null,
        [Description(ToolSupport.RowOffsetDescription)] int offset = 0,
        [Description("Most packages.")] int limit = 150,
        [Description(ToolSupport.MaxTokensDescription)] int? maxTokens = null,
        CancellationToken cancellationToken = default) => Task.Run(() =>
    {
        var r = devices.Packages(serial, query, user, offset, ToolSupport.ClampLimit(limit), cancellationToken);
        return ToolOutput.List(r.Items, r.Offset, ToolSupport.ClampLimit(limit), r.Total,
            p => $"{p.Package}  {p.Path}{(p.Uid is { } u ? $"  uid {u}" : "")}{(p.Installer != null ? $"  installer {p.Installer}" : "")}",
            rows => r with { Items = rows }, "package", $"{r.Serial}\n");
    }, cancellationToken);

    [McpServerTool(Name = "get_android_package_info", Title = "Installed package info", UseStructuredContent = true)]
    [Description("One installed package (dumpsys package): versions, SDKs, paths, ABI, flags, install times, installer, uid, requested " +
                 "permissions with their grant state, and per-user state.")]
    public Task<AndroidPackageDetails> GetAndroidPackageInfo(
        [Description("Package name, e.g. com.example.app.")] string package,
        [Description(SerialDescription)] string? serial = null,
        CancellationToken cancellationToken = default) =>
        Task.Run(() => devices.PackageInfo(package, serial, cancellationToken), cancellationToken);

    [McpServerTool(Name = "pull_android_package", Title = "Pull installed package", UseStructuredContent = true)]
    [Description("Copy every APK of an installed package (base and splits) into a new or empty directory, with size and SHA-256 each, and summarize " +
                 "the base APK. A failed pull leaves no files.")]
    public Task<PulledPackage> PullAndroidPackage(
        [Description("Package name, e.g. com.example.app.")] string package,
        [Description("A new or empty directory to write the APKs to.")] string outputDirectory,
        [Description(SerialDescription)] string? serial = null,
        CancellationToken cancellationToken = default) =>
        Task.Run(() => devices.PullPackage(package, outputDirectory, serial, cancellationToken), cancellationToken);

    [McpServerTool(Name = "pull_android_file", Title = "Pull device file", UseStructuredContent = true)]
    [Description("Copies one device file (not a directory) to outputPath with its size and SHA-256; a failed pull leaves nothing.")]
    public Task<PulledFile> PullAndroidFile(
        [Description("Path on the device.")] string remotePath,
        [Description("The local file to write.")] string outputPath,
        [Description("Replace outputPath if it exists.")] bool overwrite = false,
        [Description(SerialDescription)] string? serial = null,
        CancellationToken cancellationToken = default) =>
        Task.Run(() => devices.PullFile(remotePath, outputPath, overwrite, serial, cancellationToken), cancellationToken);

    [McpServerTool(Name = "read_android_log", Title = "Read device log", UseStructuredContent = true, OutputSchemaType = typeof(AndroidLogPage))]
    [Description("Device log (logcat -d), newest lines first, by buffer, process, tag, priority and start time.")]
    public Task<string> ReadAndroidLog(
        [Description(SerialDescription)] string? serial = null,
        [Description("Only this process id.")] int? pid = null,
        [Description("Only this log tag.")] string? tag = null,
        [Description("Lowest priority.")] string? priority = null,
        [Description("Only lines since this time (\"01-31 12:00:00.000\") or the last N lines.")] string? since = null,
        [Description("Log buffer (default: main, system, crash).")] string? buffer = null,
        [Description("Lines to skip from the newest.")] int offset = 0,
        [Description("Most lines.")] int limit = 500,
        CancellationToken cancellationToken = default) => Task.Run(() =>
    {
        var log = devices.Log(serial, pid, tag, priority, since, buffer, cancellationToken);
        int total = log.Lines.Count, skip = Math.Clamp(offset, 0, total), take = Math.Min(ToolSupport.ClampLimit(limit), total - skip);
        // Newest first, so a page cut to the budget keeps the newest lines.
        var page = log.Lines.Skip(total - skip - take).Take(take).Reverse().ToList();
        static string Row(AndroidLogLine l) => l.Time == null ? l.Message : $"{l.Time} {l.Pid,5} {l.Tid,5} {l.Priority} {l.Tag}: {l.Message}";
        var header = $"{log.Serial}: newest first{(log.Capped ? $"; the log is over {DeviceService.MaxLogBytes >> 20} MB, older lines are not read (narrow with buffer, pid, tag, priority, since)" : "")}\n";
        return ToolOutput.List(page, skip, ToolSupport.ClampLimit(limit), total, Row, rows => new AndroidLogPage(log.Serial, rows, skip, total), "line", header);
    }, cancellationToken);

    [McpServerTool(Name = "install_android_package", Title = "Install package on device", UseStructuredContent = true, OutputSchemaType = typeof(EditOutcome))]
    [Description("Install an APK, a split set or a folder of APKs on a device in one session; failures come back by INSTALL_FAILED_ code. Changes the " +
                 "device: needs the server option --allow-device-changes.")]
    public Task<string> InstallAndroidPackage(
        [Description("An .apk, split set or folder of APKs.")] string path,
        [Description("Fail if the app is installed instead of replacing it.")] bool keepInstalled = false,
        [Description("Allow a lower version code.")] bool downgrade = false,
        [Description("Grant all requested runtime permissions.")] bool grantPermissions = false,
        [Description(SerialDescription)] string? serial = null,
        CancellationToken cancellationToken = default) =>
        Task.Run(() => Outcome(devices.Install(path, !keepInstalled, downgrade, grantPermissions, serial, cancellationToken)), cancellationToken);

    /// <summary>A device change as an edit outcome: the package (or the device when unknown) and its version code after an install.</summary>
    private static string Outcome(DeviceChange c) =>
        ToolOutput.Edit(new EditOutcome(true, false, [new EditChange(c.Kind, c.Package != null ? $"{c.Serial}:{c.Package}" : c.Serial, null, c.VersionCode)], []), c.Text);

    [McpServerTool(Name = "uninstall_android_package", Title = "Uninstall package from device", UseStructuredContent = true, OutputSchemaType = typeof(EditOutcome))]
    [Description("Remove an app (and its data unless keepData) from a device; needs the server option --allow-device-changes.")]
    public Task<string> UninstallAndroidPackage(
        [Description("Package name, e.g. com.example.app.")] string package,
        [Description("Keep app data and cache.")] bool keepData = false,
        [Description(SerialDescription)] string? serial = null,
        CancellationToken cancellationToken = default) =>
        Task.Run(() => Outcome(devices.Uninstall(package, keepData, serial, cancellationToken)), cancellationToken);
}
