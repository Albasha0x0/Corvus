using System.ComponentModel;
using System.Globalization;
using System.IO.Compression;
using System.Text;
using System.Text.RegularExpressions;
using NetDecompilerMcp.Core;
using NetDecompilerMcp.Native.Providers;

namespace NetDecompilerMcp.Services.Mobile;

public sealed record AndroidDevice(string Serial, string State, string? Product, string? Model, string? Device, string? TransportId);

public sealed record AndroidDeviceList(IReadOnlyList<AndroidDevice> Items, [property: Description("Lines adb printed that are not a device row.")] IReadOnlyList<string> Unparsed);

public sealed record AndroidDeviceSummary(string? Sdk, string? Release, string? Manufacturer, string? Model, IReadOnlyList<string> Abis, string? Fingerprint,
    string? SecurityPatch, string? BuildType, bool? Debuggable, bool? Secure,
    [property: Description("Whether the device is an emulator, from ro.kernel.qemu, ro.boot.qemu, ro.hardware and the fingerprint.")] bool Emulator,
    IReadOnlyList<string> EmulatorEvidence);

public sealed record AndroidProperty(string Name, string Value);

public sealed record AndroidDeviceInfo(string Serial, AndroidDeviceSummary Summary, IReadOnlyList<AndroidProperty> Properties, int Offset, int Total, bool Truncated);

public sealed record AndroidInstalledPackage(string Package, string? Path, int? Uid, string? Installer);

public sealed record AndroidPackageList(string Serial, IReadOnlyList<AndroidInstalledPackage> Items, int Offset, int Total, bool Truncated);

public sealed record AndroidPermissionState(string Name, bool? Granted, string Kind, string? Flags);

public sealed record AndroidPackageUser(int User, bool? Installed, string? Enabled);

public sealed record AndroidPackageDetails(string Serial, string Package, string? VersionName, string? VersionCode, int? MinSdk, int? TargetSdk, string? CodePath,
    string? DataDir, string? PrimaryCpuAbi, IReadOnlyList<string> Flags, string? FirstInstallTime, string? LastUpdateTime, string? Installer, int? Uid,
    [property: Description("Every requested permission with its grant state (install or runtime, per the first user).")] IReadOnlyList<AndroidPermissionState> Permissions,
    IReadOnlyList<AndroidPackageUser> Users);

public sealed record PulledFile(string Remote, string Local, long Size, string Sha256);

public sealed record PulledPackage(string Serial, string Package, IReadOnlyList<PulledFile> Files,
    [property: Description("The base APK read with the package reader: manifest facts, runtimes, signature.")] AndroidPackageFacts? Summary);

/// <summary>
/// Android devices through adb (NDM_ADB, else PATH, else the SDK's platform-tools), one short-lived call per operation with the
/// device serial pinned. Reading is always allowed; installing and uninstalling need the server option --allow-device-changes.
/// </summary>
public sealed partial class DeviceService(ServerOptions options)
{
    private static readonly TimeSpan Short = TimeSpan.FromSeconds(30), Long = TimeSpan.FromMinutes(10);
    private const long MaxTextBytes = 16L << 20;

    /// <summary>Extra environment for adb (tests).</summary>
    internal IReadOnlyDictionary<string, string?>? Environment { get; init; }

    private static ExternalTool Adb => ExternalTools.Adb;

    private string AdbPath()
    {
        var probe = ExternalTools.Probe(Adb);
        if (probe.Path is { } path && probe.Found) return path;
        throw new ToolError(ErrorCode.ProviderUnavailable, $"adb is not available: {probe.Problem}.", probe.Remediation);
    }

    private ExternalTools.RunResult Run(IEnumerable<string> args, TimeSpan timeout, long maxBytes, CancellationToken ct) =>
        ExternalTools.Run(AdbPath(), [.. args], timeout, maxBytes, ct, Environment);

    /// <summary>Stdout of a successful call; adb's own failures mapped to typed errors.</summary>
    private static string Check(ExternalTools.RunResult r, string what)
    {
        if (r.StartError != null) throw new ToolError(ErrorCode.ProviderUnavailable, $"adb could not be started: {r.StartError}", ExternalTools.Remediation(Adb));
        if (r.TimedOut) throw new ToolError(ErrorCode.Timeout, $"adb did not finish {what} in time.", "check the device connection (list_android_devices)");
        var err = r.Stderr.Trim();
        if (r.ExitCode != 0)
        {
            var message = err.Length > 0 ? err : r.Text.Trim();
            if (message.Contains("unauthorized", StringComparison.OrdinalIgnoreCase))
                throw new ToolError(ErrorCode.AccessDenied, $"{what}: the device is unauthorized.", "accept the USB debugging prompt on the device");
            if (message.Contains("not found", StringComparison.OrdinalIgnoreCase) && message.Contains("device", StringComparison.OrdinalIgnoreCase))
                throw new ToolError(ErrorCode.NotFound, $"{what}: {message}", "list_android_devices shows the connected devices");
            if (message.Contains("offline", StringComparison.OrdinalIgnoreCase))
                throw new ToolError(ErrorCode.ProviderUnavailable, $"{what}: the device is offline.", "reconnect it, then list_android_devices");
            throw new ToolError(ErrorCode.Failed, $"{what}: adb exited with code {r.ExitCode}: {Tail(message)}");
        }
        return r.Text;
    }

    private static string Tail(string text) => text.Length > 2_000 ? "..." + text[^2_000..] : text;

    public AndroidDeviceList Devices(CancellationToken ct)
    {
        var text = Check(Run(ExternalTools.Arguments(Adb, "devices"), Short, MaxTextBytes, ct), "listing devices");
        var items = new List<AndroidDevice>();
        var unparsed = new List<string>();
        foreach (var raw in text.Split('\n'))
        {
            var line = raw.Trim();
            if (line.Length == 0 || line.StartsWith("List of devices", StringComparison.Ordinal) || line.StartsWith('*')) continue;
            var parts = line.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length < 2) { unparsed.Add(line); continue; }
            var props = parts.Skip(2).Select(p => p.Split(':', 2)).Where(p => p.Length == 2).ToDictionary(p => p[0], p => p[1], StringComparer.Ordinal);
            items.Add(new AndroidDevice(parts[0], parts[1], props.GetValueOrDefault("product"), props.GetValueOrDefault("model"), props.GetValueOrDefault("device"),
                props.GetValueOrDefault("transport_id")));
        }
        return new AndroidDeviceList(items, unparsed);
    }

    /// <summary>The serial to pin: the one given, else the only device that is ready.</summary>
    private string Serial(string? serial, CancellationToken ct)
    {
        if (serial is { Length: > 0 } s) return s.Trim();
        var ready = Devices(ct).Items.Where(d => d.State == "device").ToList();
        return ready.Count switch
        {
            1 => ready[0].Serial,
            0 => throw new ToolError(ErrorCode.NotFound, "no device is connected and ready.", "connect a device or start an emulator, then list_android_devices"),
            _ => throw new ToolError(ErrorCode.Ambiguous, $"{ready.Count} devices are ready: {string.Join(", ", ready.Select(d => d.Serial))}.", "pass serial"),
        };
    }

    public AndroidDeviceInfo DeviceInfo(string? serial, string? query, int offset, int limit, CancellationToken ct)
    {
        var s = Serial(serial, ct);
        var text = Check(Run(ExternalTools.Arguments(Adb, "getprop", ("serial", s)), Short, MaxTextBytes, ct), "reading properties");
        var props = new List<AndroidProperty>();
        foreach (Match m in PropertyLine().Matches(text)) props.Add(new(m.Groups[1].Value, m.Groups[2].Value));
        var map = props.GroupBy(p => p.Name).ToDictionary(g => g.Key, g => g.Last().Value, StringComparer.Ordinal);
        string? P(string n) => map.TryGetValue(n, out var v) && v.Length > 0 ? v : null;
        var evidence = new List<string>();
        if (P("ro.kernel.qemu") == "1") evidence.Add("ro.kernel.qemu=1");
        if (P("ro.boot.qemu") == "1") evidence.Add("ro.boot.qemu=1");
        if (P("ro.hardware") is { } hw && (hw.Contains("goldfish", StringComparison.Ordinal) || hw.Contains("ranchu", StringComparison.Ordinal) || hw == "vbox86"))
            evidence.Add($"ro.hardware={hw}");
        if (P("ro.build.fingerprint") is { } fp && (fp.Contains("generic", StringComparison.Ordinal) || fp.Contains("/sdk_", StringComparison.Ordinal) || fp.Contains(":sdk_", StringComparison.Ordinal)))
            evidence.Add("fingerprint names an SDK image");
        var summary = new AndroidDeviceSummary(P("ro.build.version.sdk"), P("ro.build.version.release"), P("ro.product.manufacturer"), P("ro.product.model"),
            (P("ro.product.cpu.abilist") ?? P("ro.product.cpu.abi") ?? "").Split(',', StringSplitOptions.RemoveEmptyEntries), P("ro.build.fingerprint"),
            P("ro.build.version.security_patch"), P("ro.build.type"), P("ro.debuggable") is { } d ? d == "1" : null, P("ro.secure") is { } sec ? sec == "1" : null,
            evidence.Count > 0, evidence);
        var filtered = query is { Length: > 0 } q
            ? props.Where(p => p.Name.Contains(q, StringComparison.OrdinalIgnoreCase) || p.Value.Contains(q, StringComparison.OrdinalIgnoreCase)).ToList()
            : props;
        limit = Math.Clamp(limit, 1, 5_000);
        offset = Math.Max(0, offset);
        var page = filtered.Skip(offset).Take(limit).ToList();
        return new AndroidDeviceInfo(s, summary, page, offset, filtered.Count, offset + page.Count < filtered.Count);
    }

    [GeneratedRegex(@"^\[([^\]]+)\]: \[(.*)\]\s*$", RegexOptions.Multiline)]
    private static partial Regex PropertyLine();

    public AndroidPackageList Packages(string? serial, string? query, int? user, int offset, int limit, CancellationToken ct)
    {
        var s = Serial(serial, ct);
        var args = ExternalTools.Arguments(Adb, "packages", ("serial", s));
        if (user is { } u) args.AddRange(ExternalTools.Arguments(Adb, "user", ("user", u.ToString(CultureInfo.InvariantCulture))));
        var text = Check(Run(args, Short, MaxTextBytes, ct), "listing packages");
        var items = new List<AndroidInstalledPackage>();
        foreach (var raw in text.Split('\n'))
        {
            var line = raw.Trim();
            if (!line.StartsWith("package:", StringComparison.Ordinal)) continue;
            var rest = line["package:".Length..];
            int? uid = null;
            string? installer = null;
            foreach (var token in rest.Split(' ', StringSplitOptions.RemoveEmptyEntries).Skip(1))
                if (token.StartsWith("uid:", StringComparison.Ordinal) && int.TryParse(token[4..].Split(',')[0], NumberStyles.Integer, CultureInfo.InvariantCulture, out var id)) uid = id;
                else if (token.StartsWith("installer=", StringComparison.Ordinal)) installer = token[10..] is "null" ? null : token[10..];
            var head = rest.Split(' ', StringSplitOptions.RemoveEmptyEntries)[0];
            int eq = head.LastIndexOf('='); // the path itself may contain '='
            var (path, name) = eq > 0 ? (head[..eq], head[(eq + 1)..]) : (null, head);
            items.Add(new AndroidInstalledPackage(name, path, uid, installer));
        }
        var filtered = items.Where(i => query is not { Length: > 0 } q || i.Package.Contains(q, StringComparison.OrdinalIgnoreCase)).OrderBy(i => i.Package, StringComparer.Ordinal).ToList();
        limit = Math.Clamp(limit, 1, 5_000);
        offset = Math.Max(0, offset);
        var page = filtered.Skip(offset).Take(limit).ToList();
        return new AndroidPackageList(s, page, offset, filtered.Count, offset + page.Count < filtered.Count);
    }

    public AndroidPackageDetails PackageInfo(string package, string? serial, CancellationToken ct)
    {
        package = PackageName(package);
        var s = Serial(serial, ct);
        var text = Check(Run(ExternalTools.Arguments(Adb, "dumpsys", ("serial", s), ("package", package)), Short, MaxTextBytes, ct), $"reading package {package}").Replace("\r", "");
        var lines = text.Split('\n');
        int start = Array.FindIndex(lines, l => l.TrimStart().StartsWith($"Package [{package}]", StringComparison.Ordinal));
        if (start < 0) throw new ToolError(ErrorCode.NotFound, $"package {package} is not installed on {s}.", "list_android_packages finds installed packages");
        int indent = lines[start].Length - lines[start].TrimStart().Length;
        int end = start + 1;
        while (end < lines.Length && (lines[end].Trim().Length == 0 || lines[end].Length - lines[end].TrimStart().Length > indent)) end++;
        var block = lines[start..end];
        var values = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var line in block)
            foreach (Match m in KeyValue().Matches(line))
                values.TryAdd(m.Groups[1].Value, m.Groups[2].Value);
        string? V(string k) => values.TryGetValue(k, out var v) && v != "null" ? v : null;
        var permissions = new List<AndroidPermissionState>();
        var requested = new List<string>();
        var users = new List<AndroidPackageUser>();
        string section = "";
        int sectionIndent = 0;
        foreach (var line in block)
        {
            var trimmed = line.Trim();
            int lineIndent = line.Length - line.TrimStart().Length;
            if (trimmed.Length == 0) continue;
            if (trimmed is "requested permissions:" or "install permissions:" or "runtime permissions:" or "declared permissions:")
            {
                section = trimmed.TrimEnd(':');
                sectionIndent = lineIndent;
                continue;
            }
            if (UserLine().Match(trimmed) is { Success: true } user)
            {
                users.Add(new AndroidPackageUser(int.Parse(user.Groups[1].Value, CultureInfo.InvariantCulture),
                    KeyValue().Matches(trimmed).FirstOrDefault(m => m.Groups[1].Value == "installed")?.Groups[2].Value is { } i ? i == "true" : null,
                    KeyValue().Matches(trimmed).FirstOrDefault(m => m.Groups[1].Value == "enabled")?.Groups[2].Value));
                section = "";
                continue;
            }
            if (section.Length == 0 || lineIndent <= sectionIndent) { section = ""; continue; }
            if (section == "requested permissions") requested.Add(trimmed.Split(':')[0].Trim());
            else if (section is "install permissions" or "runtime permissions")
            {
                var name = trimmed.Split(':')[0].Trim();
                var granted = GrantedValue().Match(trimmed) is { Success: true } g ? g.Groups[1].Value == "true" : (bool?)null;
                var flags = FlagsValue().Match(trimmed) is { Success: true } f ? f.Groups[1].Value.Trim() : null;
                if (permissions.All(p => p.Name != name))
                    permissions.Add(new AndroidPermissionState(name, granted, section == "install permissions" ? "install" : "runtime", flags));
            }
        }
        foreach (var r in requested.Where(r => permissions.All(p => p.Name != r))) permissions.Add(new AndroidPermissionState(r, null, "requested", null));
        var flagsList = values.TryGetValue("flags", out _) ? FlagsField().Match(string.Join('\n', block)) is { Success: true } fl ? fl.Groups[1].Value.Split(' ', StringSplitOptions.RemoveEmptyEntries) : [] : [];
        int? Int(string? v) => int.TryParse(v, NumberStyles.Integer, CultureInfo.InvariantCulture, out var x) ? x : null;
        return new AndroidPackageDetails(s, package, V("versionName"), V("versionCode"), Int(V("minSdk")), Int(V("targetSdk")), V("codePath"), V("dataDir"),
            V("primaryCpuAbi"), flagsList, V("firstInstallTime"), V("lastUpdateTime"), V("installerPackageName") ?? V("installerPackageUid"), Int(V("userId") ?? V("appId")),
            permissions, users);
    }

    [GeneratedRegex(@"(?:^|\s)([A-Za-z][A-Za-z0-9]*)=(\S+?)(?=,?\s|$)")]
    private static partial Regex KeyValue();
    [GeneratedRegex(@"^User (\d+):")]
    private static partial Regex UserLine();
    [GeneratedRegex(@"granted=(true|false)")]
    private static partial Regex GrantedValue();
    [GeneratedRegex(@"flags=\[([^\]]*)\]")]
    private static partial Regex FlagsValue();
    [GeneratedRegex(@"\bflags=\[([^\]]*)\]")]
    private static partial Regex FlagsField();

    private static string PackageName(string package)
    {
        package = package.Trim();
        if (!PackagePattern().IsMatch(package)) throw new ToolError(ErrorCode.InvalidArgument, $"'{package}' is not a package name (letters, digits, _ and dots).");
        return package;
    }

    [GeneratedRegex(@"^[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z0-9_]+)*$")]
    private static partial Regex PackagePattern();

    /// <summary>Pulls every APK of an installed package (base and splits) into a new or empty directory and reads the base APK.</summary>
    public PulledPackage PullPackage(string package, string outputDirectory, string? serial, CancellationToken ct)
    {
        package = PackageName(package);
        var s = Serial(serial, ct);
        var text = Check(Run(ExternalTools.Arguments(Adb, "path", ("serial", s), ("package", package)), Short, MaxTextBytes, ct), $"locating {package}");
        var remotes = text.Split('\n').Select(l => l.Trim()).Where(l => l.StartsWith("package:", StringComparison.Ordinal)).Select(l => l["package:".Length..]).ToList();
        if (remotes.Count == 0) throw new ToolError(ErrorCode.NotFound, $"package {package} is not installed on {s}.", "list_android_packages finds installed packages");
        var dir = EmptyDirectory(outputDirectory);
        var files = new List<PulledFile>();
        try
        {
            foreach (var remote in remotes)
            {
                ct.ThrowIfCancellationRequested();
                var local = SafeFile.UnderRoot(dir, Blob.SafeRelativePath(Path.GetFileName(remote.Replace('\\', '/')), "package.apk"));
                Check(Run(ExternalTools.Arguments(Adb, "pull", ("serial", s), ("remote", remote), ("local", local)), Long, 1 << 20, ct), $"pulling {remote}");
                if (!File.Exists(local)) throw new ToolError(ErrorCode.IoError, $"adb reported success but {local} was not written.");
                var bytes = File.ReadAllBytes(local);
                files.Add(new PulledFile(remote, local, bytes.Length, Blob.Sha256(bytes)));
            }
        }
        catch
        {
            foreach (var f in files) TryDelete(f.Local);
            foreach (var f in Directory.EnumerateFiles(dir)) TryDelete(f);
            throw;
        }
        var basePath = files.FirstOrDefault(f => Path.GetFileName(f.Local) == "base.apk")?.Local ?? files[0].Local;
        return new PulledPackage(s, package, files, AndroidPackageService.Facts(basePath, File.ReadAllBytes(basePath), ct));
    }

    private static void TryDelete(string path)
    {
        try { File.Delete(path); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
    }

    private static string EmptyDirectory(string path)
    {
        var full = SafeFile.FullPath(path);
        if (File.Exists(full)) throw new ToolError(ErrorCode.Conflict, $"{full} is a file; pass a new or empty directory.");
        if (Directory.Exists(full) && Directory.EnumerateFileSystemEntries(full).Any())
            throw new ToolError(ErrorCode.Conflict, $"{full} is not empty; pass a new or empty directory.");
        Directory.CreateDirectory(full);
        return full;
    }

    /// <summary>Pulls one file; a directory on the device is refused and a failed pull leaves nothing behind.</summary>
    public PulledFile PullFile(string remotePath, string outputPath, bool overwrite, string? serial, CancellationToken ct)
    {
        var s = Serial(serial, ct);
        remotePath = remotePath.Trim();
        if (remotePath.Length == 0 || remotePath.Contains('\n', StringComparison.Ordinal)) throw new ToolError(ErrorCode.InvalidArgument, "remotePath is empty or has a line break.");
        var kind = Check(Run(ExternalTools.Arguments(Adb, "stat", ("serial", s), ("remote", remotePath)), Short, 4096, ct), $"checking {remotePath}").Trim();
        if (kind.Contains("directory", StringComparison.OrdinalIgnoreCase)) throw new ToolError(ErrorCode.InvalidArgument, $"{remotePath} is a directory; pull_android_file pulls one file.");
        if (kind.Contains("No such file", StringComparison.OrdinalIgnoreCase)) throw new ToolError(ErrorCode.NotFound, $"{remotePath} does not exist on {s}.");
        var full = SafeFile.FullPath(outputPath);
        if (Directory.Exists(full)) throw new ToolError(ErrorCode.InvalidArgument, $"{full} is a directory; pass the file to write.");
        if (File.Exists(full) && !overwrite) throw new ToolError(ErrorCode.Conflict, $"{full} exists.", "pass overwrite=true, or another outputPath");
        Directory.CreateDirectory(Path.GetDirectoryName(full)!);
        var partial = full + ".partial-" + Guid.NewGuid().ToString("N")[..8];
        try
        {
            Check(Run(ExternalTools.Arguments(Adb, "pull", ("serial", s), ("remote", remotePath), ("local", partial)), Long, 1 << 20, ct), $"pulling {remotePath}");
            if (!File.Exists(partial)) throw new ToolError(ErrorCode.IoError, $"adb reported success but wrote nothing for {remotePath}.");
            File.Move(partial, full, overwrite);
        }
        finally { TryDelete(partial); }
        var bytes = File.ReadAllBytes(full);
        return new PulledFile(remotePath, full, bytes.Length, Blob.Sha256(bytes));
    }

    /// <summary>The device log so far (logcat -d), cut at <paramref name="maxBytes"/> instead of failing.</summary>
    public string Log(string? serial, int? pid, string? tag, string? priority, string? since, int maxBytes, CancellationToken ct)
    {
        var s = Serial(serial, ct);
        var args = ExternalTools.Arguments(Adb, "logcat", ("serial", s));
        if (pid is { } p) args.Add($"--pid={p.ToString(CultureInfo.InvariantCulture)}");
        if (since is { Length: > 0 } t) { args.Add("-t"); args.Add(t.Trim()); }
        var level = priority?.Trim().ToUpperInvariant() switch
        {
            null or "" => null,
            "V" or "VERBOSE" => "V", "D" or "DEBUG" => "D", "I" or "INFO" => "I", "W" or "WARN" or "WARNING" => "W", "E" or "ERROR" => "E", "F" or "FATAL" => "F",
            var x => throw new ToolError(ErrorCode.InvalidArgument, $"unknown priority '{x}'; use V, D, I, W, E or F."),
        };
        if (tag is { Length: > 0 } tg)
        {
            if (tg.Any(char.IsWhiteSpace) || tg.Contains(':', StringComparison.Ordinal)) throw new ToolError(ErrorCode.InvalidArgument, $"tag '{tg}' has a space or colon.");
            args.Add($"{tg}:{level ?? "V"}");
            args.Add("*:S");
        }
        else if (level != null) args.Add($"*:{level}");
        int budget = Math.Clamp(maxBytes, 1_024, 8 << 20);
        var r = Run(args, Short, budget, ct);
        var text = r.Truncated ? r.Text : Check(r, "reading the log");
        int lines = text.Count(c => c == '\n');
        return $"{lines} line(s) from {s}{(r.Truncated ? $"; truncated=true at {budget:N0} bytes (raise maxBytes or narrow with pid, tag, priority, since)" : "")}\n{text}";
    }

    private void RequireChanges(string what)
    {
        if (!options.AllowDeviceChanges)
            throw new ToolError(ErrorCode.Unsupported, $"{what} changes a connected device, which this server does not allow.",
                $"start the server with {ServerOptions.AllowDeviceChangesOption} (or {ServerOptions.AllowDeviceChangesVariable}=1)");
    }

    /// <summary>Installs an APK, every APK of a split set (.apks / .xapk / .apkm) or of a directory, in one session.</summary>
    public string Install(string path, bool replace, bool downgrade, bool grantPermissions, string? serial, CancellationToken ct)
    {
        RequireChanges("install_android_package");
        var full = SafeFile.FullPath(path);
        string? temp = null;
        try
        {
            List<string> apks;
            if (Directory.Exists(full)) apks = [.. Directory.EnumerateFiles(full, "*.apk").Order(StringComparer.Ordinal)];
            else if (!File.Exists(full)) throw new ToolError(ErrorCode.NotFound, $"file not found: {full}");
            else if (full.EndsWith(".apk", StringComparison.OrdinalIgnoreCase)) apks = [full];
            else
            {
                temp = Directory.CreateTempSubdirectory("ndm-install-").FullName;
                using var zip = ZipFile.OpenRead(full);
                apks = [];
                foreach (var e in zip.Entries.Where(e => e.FullName.EndsWith(".apk", StringComparison.OrdinalIgnoreCase)))
                {
                    var local = SafeFile.UnderRoot(temp, Blob.SafeRelativePath(e.FullName, "split.apk"));
                    Directory.CreateDirectory(Path.GetDirectoryName(local)!);
                    e.ExtractToFile(local);
                    apks.Add(local);
                }
            }
            if (apks.Count == 0) throw new ToolError(ErrorCode.InvalidArgument, $"{full} has no APK to install.");
            var s = Serial(serial, ct);
            var args = ExternalTools.Arguments(Adb, "install", ("serial", s));
            if (replace) args.Add("-r");
            if (downgrade) args.Add("-d");
            if (grantPermissions) args.Add("-g");
            args.AddRange(apks);
            var r = Run(args, Long, MaxTextBytes, ct);
            var output = (r.Text + "\n" + r.Stderr).Trim();
            if (InstallFailure().Match(output) is { Success: true } failure)
            {
                var code = failure.Groups[1].Value;
                throw code switch
                {
                    "INSTALL_FAILED_VERSION_DOWNGRADE" => new ToolError(ErrorCode.Conflict, $"install failed: {failure.Value}", "pass downgrade=true"),
                    "INSTALL_FAILED_ALREADY_EXISTS" => new ToolError(ErrorCode.Conflict, $"install failed: {failure.Value}", "pass replace=true"),
                    "INSTALL_FAILED_UPDATE_INCOMPATIBLE" => new ToolError(ErrorCode.Conflict, $"install failed: {failure.Value}", "the installed app has another signature: uninstall it first"),
                    var c when c.StartsWith("INSTALL_PARSE_FAILED", StringComparison.Ordinal) => new ToolError(ErrorCode.MalformedInput, $"install failed: {failure.Value}"),
                    _ => new ToolError(ErrorCode.Failed, $"install failed: {failure.Value}"),
                };
            }
            Check(r, "installing");
            if (!output.Contains("Success", StringComparison.Ordinal)) throw new ToolError(ErrorCode.Failed, $"adb did not report success: {Tail(output)}");
            return $"Installed {apks.Count} APK(s) on {s}: {string.Join(", ", apks.Select(Path.GetFileName))}.";
        }
        finally
        {
            if (temp != null)
                try { Directory.Delete(temp, true); }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
        }
    }

    [GeneratedRegex(@"Failure \[([A-Z_]+)[^\]]*\]")]
    private static partial Regex InstallFailure();

    public string Uninstall(string package, bool keepData, string? serial, CancellationToken ct)
    {
        RequireChanges("uninstall_android_package");
        package = PackageName(package);
        var s = Serial(serial, ct);
        var args = ExternalTools.Arguments(Adb, "uninstall", ("serial", s));
        if (keepData) args.Add("-k");
        args.Add(package);
        var r = Run(args, Long, MaxTextBytes, ct);
        var output = (r.Text + "\n" + r.Stderr).Trim();
        if (output.Contains("Failure", StringComparison.Ordinal))
            throw new ToolError(output.Contains("DELETE_FAILED_INTERNAL_ERROR", StringComparison.Ordinal) || output.Contains("Unknown package", StringComparison.Ordinal)
                ? ErrorCode.NotFound : ErrorCode.Failed, $"uninstall failed: {Tail(output)}");
        Check(r, "uninstalling");
        return $"Uninstalled {package} from {s}{(keepData ? " (data kept)" : "")}.";
    }
}
