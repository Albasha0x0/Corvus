using System.ComponentModel;
using ModelContextProtocol.Server;
using NetDecompilerMcp.Services.Mobile;

namespace NetDecompilerMcp.Tools;

[McpServerToolType]
public sealed class DeviceTools(DeviceService devices)
{
    private const string SerialDescription = "Device serial from list_android_devices; optional when exactly one device is ready.";

    [McpServerTool(Name = "list_android_devices", Title = "List Android devices", UseStructuredContent = true)]
    [Description("Android devices and emulators adb sees (adb devices -l): serial, state (device, unauthorized, offline), product, model, transport. " +
                 "adb comes from NDM_ADB, else PATH, else the Android SDK's platform-tools.")]
    public Task<AndroidDeviceList> ListAndroidDevices(CancellationToken cancellationToken = default) =>
        Task.Run(() => devices.Devices(cancellationToken), cancellationToken);

    [McpServerTool(Name = "get_android_device_info", Title = "Android device info", UseStructuredContent = true)]
    [Description("A device's properties (getprop), paged and filterable, with a summary: SDK, release, manufacturer, model, ABIs, fingerprint, security " +
                 "patch, build type, ro.debuggable, ro.secure, and whether it is an emulator with the evidence.")]
    public Task<AndroidDeviceInfo> GetAndroidDeviceInfo(
        [Description(SerialDescription)] string? serial = null,
        [Description("Only properties whose name or value contains this.")] string? query = null,
        [Description("Properties to skip.")] int offset = 0,
        [Description("Most properties to return (default 200).")] int limit = 200,
        CancellationToken cancellationToken = default) =>
        Task.Run(() => devices.DeviceInfo(serial, query, offset, limit, cancellationToken), cancellationToken);

    [McpServerTool(Name = "list_android_packages", Title = "List installed packages", UseStructuredContent = true)]
    [Description("Packages installed on a device (pm list packages -f -U -i): name, APK path, uid and installer.")]
    public Task<AndroidPackageList> ListAndroidPackages(
        [Description(SerialDescription)] string? serial = null,
        [Description("Only package names containing this.")] string? query = null,
        [Description("Android user id (default: the current user).")] int? user = null,
        [Description("Packages to skip.")] int offset = 0,
        [Description("Most packages to return (default 500).")] int limit = 500,
        CancellationToken cancellationToken = default) =>
        Task.Run(() => devices.Packages(serial, query, user, offset, limit, cancellationToken), cancellationToken);

    [McpServerTool(Name = "get_android_package_info", Title = "Installed package info", UseStructuredContent = true)]
    [Description("One installed package from dumpsys package: versions, SDKs, code path, data directory, ABI, flags, install and update times, " +
                 "installer, uid, every requested permission with its install or runtime grant state and flags, and per-user state.")]
    public Task<AndroidPackageDetails> GetAndroidPackageInfo(
        [Description("Package name, e.g. com.example.app.")] string package,
        [Description(SerialDescription)] string? serial = null,
        CancellationToken cancellationToken = default) =>
        Task.Run(() => devices.PackageInfo(package, serial, cancellationToken), cancellationToken);

    [McpServerTool(Name = "pull_android_package", Title = "Pull installed package", UseStructuredContent = true)]
    [Description("Copies every APK of an installed package (base and splits, from pm path) into a new or empty directory, with size and SHA-256 " +
                 "each, then reads the base APK as summarize_file does (manifest facts, runtimes, signature). A failed pull leaves no files.")]
    public Task<PulledPackage> PullAndroidPackage(
        [Description("Package name, e.g. com.example.app.")] string package,
        [Description("A new or empty directory to write the APKs to.")] string outputDirectory,
        [Description(SerialDescription)] string? serial = null,
        CancellationToken cancellationToken = default) =>
        Task.Run(() => devices.PullPackage(package, outputDirectory, serial, cancellationToken), cancellationToken);

    [McpServerTool(Name = "pull_android_file", Title = "Pull device file", UseStructuredContent = true)]
    [Description("Copies one file from a device (directories are refused) to outputPath, with its size and SHA-256; a failed pull leaves nothing behind.")]
    public Task<PulledFile> PullAndroidFile(
        [Description("The file's path on the device, e.g. /sdcard/Download/app.log.")] string remotePath,
        [Description("The local file to write.")] string outputPath,
        [Description("Replace outputPath if it exists.")] bool overwrite = false,
        [Description(SerialDescription)] string? serial = null,
        CancellationToken cancellationToken = default) =>
        Task.Run(() => devices.PullFile(remotePath, outputPath, overwrite, serial, cancellationToken), cancellationToken);

    [McpServerTool(Name = "read_android_log", Title = "Read device log")]
    [Description("The device log so far (logcat -d, threadtime format), narrowed by process, tag, priority and start time; beyond maxBytes it is cut " +
                 "and says truncated=true instead of failing.")]
    public Task<string> ReadAndroidLog(
        [Description(SerialDescription)] string? serial = null,
        [Description("Only this process id.")] int? pid = null,
        [Description("Only this log tag.")] string? tag = null,
        [Description("Lowest priority: V, D, I, W, E or F.")] string? priority = null,
        [Description("Only lines since this time, as logcat -t takes it ('01-31 12:00:00.000') or a line count.")] string? since = null,
        [Description("Most bytes of log to return (default 262144).")] int maxBytes = 262_144,
        CancellationToken cancellationToken = default) =>
        Task.Run(() => devices.Log(serial, pid, tag, priority, since, maxBytes, cancellationToken), cancellationToken);

    [McpServerTool(Name = "install_android_package", Title = "Install package on device")]
    [Description("Installs an APK, every APK of a split set (.apks, .xapk, .apkm) or of a directory on a device in one session (adb install-multiple); " +
                 "install failures come back by their code (INSTALL_FAILED_...). Changes the device: off unless the server runs with --allow-device-changes.")]
    public Task<string> InstallAndroidPackage(
        [Description("An .apk, a split set (.apks, .xapk, .apkm) or a directory of APKs.")] string path,
        [Description("Replace an installed app (default true).")] bool replace = true,
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
