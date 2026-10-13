using System.ComponentModel;
using ModelContextProtocol.Server;
using Corvus.Mcp;
using Corvus.Services.Mobile;

namespace Corvus.Tools;

[McpServerToolType]
public sealed class DeviceTools(DeviceService devices)
{
    private const string SerialDescription = "Device serial; optional with one device ready.";

    [McpServerTool(Name = "list_android_devices", Title = "List Android devices", UseStructuredContent = true)]
    [Description("Android devices and emulators adb sees: serial, state, product, model, transport. adb: CORVUS_ADB, else PATH, else the SDK's platform-tools.")]
    public Task<AndroidDeviceList> ListAndroidDevices(CancellationToken cancellationToken = default) =>
        Task.Run(() => devices.Devices(cancellationToken), cancellationToken);

    [McpServerTool(Name = "get_android_device_info", Title = "Android device info", UseStructuredContent = true, OutputSchemaType = typeof(AndroidDeviceInfo))]
    [Description("A device's properties (getprop) with a summary: SDK, release, model, ABIs, fingerprint, security " +
                 "patch, build type, ro.debuggable, ro.secure, and whether it is an emulator.")]
    public Task<string> GetAndroidDeviceInfo(
        [Description(SerialDescription)] string? serial = null,
        [Description("Only properties whose name or value contains this.")] string? query = null,
        [Description(ToolSupport.RowOffsetDescription)] int offset = 0,
        [Description("Most properties.")] int limit = 100,
        CancellationToken cancellationToken = default) => Task.Run(() =>
    {
        var r = devices.DeviceInfo(serial, query, offset, ToolSupport.ClampLimit(limit), cancellationToken);
        var s = r.Summary;
        var header = $"{r.Serial}: Android {s.Release} (SDK {s.Sdk}), {s.Manufacturer} {s.Model}, ABIs {string.Join(", ", s.Abis)}; {s.BuildType}"
                     + $"{(s.Debuggable == true ? ", ro.debuggable=1" : "")}{(s.Secure == false ? ", ro.secure=0" : "")}; patch {s.SecurityPatch}"
                     + $"{(s.Emulator ? $"; emulator ({string.Join(", ", s.EmulatorEvidence)})" : "")}\nfingerprint {s.Fingerprint}\n";
        return ToolOutput.List(r.Properties, r.Offset, ToolSupport.ClampLimit(limit), r.Total, p => $"{p.Name} = {p.Value}", rows => r with { Properties = rows }, "property", header);
    }, cancellationToken);

    [McpServerTool(Name = "list_android_packages", Title = "List installed packages", UseStructuredContent = true, OutputSchemaType = typeof(AndroidPackageList))]
    [Description("Packages installed on a device (pm list packages -f -U -i): name, APK path, uid and installer.")]
    public Task<string> ListAndroidPackages(
        [Description(SerialDescription)] string? serial = null,
        [Description("Only package names containing this.")] string? query = null,
        [Description("Android user id (default: the current one).")] int? user = null,
        [Description(ToolSupport.RowOffsetDescription)] int offset = 0,
        [Description("Most packages.")] int limit = 150,
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
    [Description("Copies every APK of an installed package (base and splits) into a new or empty directory, with size and SHA-256 each, and " +
                 "summarizes the base APK. A failed pull leaves no files.")]
    public Task<PulledPackage> PullAndroidPackage(
        [Description("Package name, e.g. com.example.app.")] string package,
        [Description("A new or empty directory to write the APKs to.")] string outputDirectory,
        [Description(SerialDescription)] string? serial = null,
        CancellationToken cancellationToken = default) =>
        Task.Run(() => devices.PullPackage(package, outputDirectory, serial, cancellationToken), cancellationToken);

    [McpServerTool(Name = "pull_android_file", Title = "Pull device file", UseStructuredContent = true)]
    [Description("Copies one file from a device (directories are refused) to outputPath, with its size and SHA-256; a failed pull leaves nothing behind.")]
    public Task<PulledFile> PullAndroidFile(
        [Description("The file's path on the device.")] string remotePath,
        [Description("The local file to write.")] string outputPath,
        [Description("Replace outputPath if it exists.")] bool overwrite = false,
        [Description(SerialDescription)] string? serial = null,
        CancellationToken cancellationToken = default) =>
        Task.Run(() => devices.PullFile(remotePath, outputPath, overwrite, serial, cancellationToken), cancellationToken);

    [McpServerTool(Name = "read_android_log", Title = "Read device log")]
    [Description("The device log so far (logcat -d), narrowed by process, tag, priority and start time; beyond maxBytes it is cut (truncated=true).")]
    public Task<string> ReadAndroidLog(
        [Description(SerialDescription)] string? serial = null,
        [Description("Only this process id.")] int? pid = null,
        [Description("Only this log tag.")] string? tag = null,
        [Description("Lowest priority.")] string? priority = null,
        [Description("Only lines since this time (logcat -t form, '01-31 12:00:00.000') or the last N lines.")] string? since = null,
        [Description("Most bytes of log to return.")] int maxBytes = 262_144,
        CancellationToken cancellationToken = default) =>
        Task.Run(() => devices.Log(serial, pid, tag, priority, since, maxBytes, cancellationToken), cancellationToken);

    [McpServerTool(Name = "install_android_package", Title = "Install package on device")]
    [Description("Installs an APK, a split set or a directory of APKs on a device in one session; failures come back by their " +
                 "INSTALL_FAILED_ code. Changes the device: needs the server option --allow-device-changes.")]
    public Task<string> InstallAndroidPackage(
        [Description("An .apk, a split set (.apks, .xapk, .apkm) or a directory of APKs.")] string path,
        [Description("Replace an installed app.")] bool replace = true,
        [Description("Allow a lower version code.")] bool downgrade = false,
        [Description("Grant every runtime permission the manifest requests.")] bool grantPermissions = false,
        [Description(SerialDescription)] string? serial = null,
        CancellationToken cancellationToken = default) =>
        Task.Run(() => devices.Install(path, replace, downgrade, grantPermissions, serial, cancellationToken), cancellationToken);

    [McpServerTool(Name = "uninstall_android_package", Title = "Uninstall package from device")]
    [Description("Removes an app from a device, with its data unless keepData. Changes the device: off unless the server runs with --allow-device-changes.")]
    public Task<string> UninstallAndroidPackage(
        [Description("Package name, e.g. com.example.app.")] string package,
        [Description("Keep the app's data and cache.")] bool keepData = false,
        [Description(SerialDescription)] string? serial = null,
        CancellationToken cancellationToken = default) =>
        Task.Run(() => devices.Uninstall(package, keepData, serial, cancellationToken), cancellationToken);
}
