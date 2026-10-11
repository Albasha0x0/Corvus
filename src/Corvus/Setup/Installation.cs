using System.Diagnostics;
using System.Formats.Tar;
using System.IO.Compression;
using System.Runtime.InteropServices;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace Corvus.Setup;

/// <summary>
/// The per-user install layout written by the install scripts: &lt;root&gt;/versions/&lt;version&gt;/ holds each build,
/// &lt;root&gt;/current links to the active one, and client configurations point at the link so updates need no edits.
/// </summary>
internal static class Installation
{
    public const string DefaultRepository = "Albasha0x0/Corvus";
    public static string ExeName => OperatingSystem.IsWindows() ? "corvus.exe" : "corvus";
    public static string Version => typeof(Installation).Assembly.GetName().Version?.ToString(3) ?? "0.0.0";

    /// <summary>The install root when this process runs from &lt;root&gt;/versions/&lt;version&gt;/ or &lt;root&gt;/current/.</summary>
    public static string? Root()
    {
        var dir = Path.TrimEndingDirectorySeparator(AppContext.BaseDirectory);
        var parent = Path.GetDirectoryName(dir);
        if (parent == null) return null;
        if (Path.GetFileName(parent) == "versions") return Path.GetDirectoryName(parent);
        if (Path.GetFileName(dir) == "current" && Directory.Exists(Path.Combine(parent, "versions"))) return parent;
        return null;
    }

    /// <summary>Where the install scripts put the program: CORVUS_HOME, else %LOCALAPPDATA%\Corvus, else $XDG_DATA_HOME/Corvus (~/.local/share).</summary>
    public static string DefaultRoot(SetupEnvironment env) =>
        env.Set("CORVUS_HOME") ?? (env.Os == HostOs.Windows ? Path.Combine(env.LocalAppData, "Corvus") : Path.Combine(XdgData(env), "Corvus"));

    /// <summary>$XDG_DATA_HOME, else ~/.local/share.</summary>
    public static string XdgData(SetupEnvironment env) => env.Set("XDG_DATA_HOME") ?? env.InHome(".local", "share");

    /// <summary>How clients should start this server: the stable "current" path for an installed build.</summary>
    public static ServerLaunch Launch()
    {
        var process = Environment.ProcessPath ?? ExeName;
        if (Path.GetFileNameWithoutExtension(process).Equals("dotnet", StringComparison.OrdinalIgnoreCase))
            return new ServerLaunch(process, [Path.Combine(AppContext.BaseDirectory, Corvus.Relay.RelayBuilds.ProgramDll)]);
        if (Root() is { } root && File.Exists(Path.Combine(root, "current", ExeName)))
            return new ServerLaunch(Path.Combine(root, "current", ExeName), []);
        return new ServerLaunch(process, []);
    }

    private static string Rid => RuntimeInformation.RuntimeIdentifier;
    private static string AssetName => $"corvus-{Rid}" + (OperatingSystem.IsWindows() ? ".zip" : ".tar.gz");

    /// <summary>The first release published as Corvus; older releases have other asset and program names.</summary>
    public static readonly Version FirstRelease = new(1, 2, 0);

    /// <summary>The release asset listing every other asset's SHA-256, in sha256sum format.</summary>
    public const string ChecksumManifest = "SHA256SUMS";

    /// <summary>Null when <paramref name="manifest"/> lists <paramref name="assetName"/> with the SHA-256 of <paramref name="data"/>; else why not.</summary>
    public static string? VerifyChecksum(string manifest, string assetName, ReadOnlySpan<byte> data)
    {
        string? expected = null;
        foreach (var raw in manifest.Split('\n'))
        {
            // "<hex>  name" (text mode) or "<hex> *name" (binary mode).
            var line = raw.TrimEnd('\r');
            if (line.Length < 66 || line[64] != ' ' || line[65] is not (' ' or '*') || line[66..] != assetName) continue;
            expected = line[..64];
            break;
        }
        if (expected == null) return $"{ChecksumManifest} lists no {assetName}; refusing to install an unverified build.";
        var actual = Convert.ToHexStringLower(System.Security.Cryptography.SHA256.HashData(data));
        return actual.Equals(expected, StringComparison.OrdinalIgnoreCase)
            ? null
            : $"Checksum mismatch for {assetName} (expected {expected.ToLowerInvariant()}, got {actual}); the download is corrupt or was altered. Nothing was installed.";
    }

    /// <summary>The GitHub API address of the latest release, or of the release tagged v<paramref name="version"/>.</summary>
    public static string ReleaseApi(string repo, string? version) =>
        version is { Length: > 0 } v ? $"https://api.github.com/repos/{repo}/releases/tags/v{v.TrimStart('v')}" : $"https://api.github.com/repos/{repo}/releases/latest";

    /// <summary>
    /// Downloads the latest release (or <paramref name="version"/>, which may be older: a rollback) into versions/,
    /// switches "current" to it, removes unused versions and refreshes existing registrations. With
    /// <paramref name="dryRun"/> it only reports the release, asset and checksum manifest it would use.
    /// </summary>
    public static int Update(TextWriter output, string? version = null, bool dryRun = false)
    {
        if (Root() is not { } root)
        {
            output.WriteLine("This copy was not installed by the install script, so it cannot update itself.");
            output.WriteLine("Install with the one-line command in the README, or rebuild from source.");
            return 1;
        }
        var repo = Environment.GetEnvironmentVariable("CORVUS_REPO") is { Length: > 0 } r ? r : DefaultRepository;
        using var http = new HttpClient { Timeout = TimeSpan.FromMinutes(5) };
        http.DefaultRequestHeaders.UserAgent.ParseAdd("Corvus/" + Version);
        var token = Environment.GetEnvironmentVariable("GITHUB_TOKEN");
        if (!string.IsNullOrEmpty(token)) http.DefaultRequestHeaders.Authorization = new("Bearer", token);

        JsonNode release;
        try { release = JsonNode.Parse(http.GetStringAsync(ReleaseApi(repo, version)).GetAwaiter().GetResult())!; }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException or JsonException)
        {
            output.WriteLine($"Could not read {(version == null ? "the latest release" : $"release v{version.TrimStart('v')}")} of {repo}: {ex.Message}");
            return 1;
        }
        var tag = release["tag_name"]?.GetValue<string>() ?? "";
        var latest = tag.TrimStart('v');
        bool same = System.Version.TryParse(latest, out var lv) && System.Version.TryParse(Version, out var cv) && (version == null ? lv <= cv : lv == cv);
        if (same)
        {
            output.WriteLine($"Up to date ({Version}).");
            return 0;
        }
        if (System.Version.TryParse(latest, out var requested) && requested < FirstRelease)
        {
            output.WriteLine($"Release {tag} predates Corvus ({FirstRelease} is the first); it cannot replace this install.");
            return 1;
        }
        JsonNode? Asset(string name) => release["assets"]?.AsArray().FirstOrDefault(a => a?["name"]?.GetValue<string>() == name);
        var asset = Asset(AssetName);
        if (asset == null)
        {
            output.WriteLine($"Release {tag} has no build for {Rid} ({AssetName}).");
            return 1;
        }
        if (Asset(ChecksumManifest) is not { } sumsAsset)
        {
            output.WriteLine($"Release {tag} has no {ChecksumManifest} manifest; refusing to install an unverified build.");
            return 1;
        }
        if (dryRun)
        {
            output.WriteLine($"Would install {tag} ({AssetName}, verified against the release's {ChecksumManifest}) into {Path.Combine(root, "versions", latest)},");
            output.WriteLine($"point {Path.Combine(root, "current")} at it and refresh existing registrations (no clients are added).");
            output.WriteLine("Dry run: nothing was changed.");
            return 0;
        }

        output.WriteLine($"Downloading {tag} ({AssetName})...");
        byte[] Download(JsonNode item)
        {
            using var request = new HttpRequestMessage(HttpMethod.Get, item["url"]!.GetValue<string>());
            request.Headers.Accept.ParseAdd("application/octet-stream");
            using var response = http.Send(request);
            response.EnsureSuccessStatusCode();
            return response.Content.ReadAsByteArrayAsync().GetAwaiter().GetResult();
        }
        byte[] archive;
        string manifest;
        try
        {
            archive = Download(asset);
            manifest = System.Text.Encoding.UTF8.GetString(Download(sumsAsset));
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException)
        {
            output.WriteLine($"Download failed: {ex.Message}");
            return 1;
        }
        if (VerifyChecksum(manifest, AssetName, archive) is { } mismatch)
        {
            output.WriteLine(mismatch);
            return 1;
        }

        var versions = Path.Combine(root, "versions");
        var staging = Path.Combine(versions, ".new-" + Guid.NewGuid().ToString("N")[..8]);
        Directory.CreateDirectory(staging);
        if (AssetName.EndsWith(".zip", StringComparison.Ordinal))
            ZipFile.ExtractToDirectory(new MemoryStream(archive), staging);
        else
            TarFile.ExtractToDirectory(new GZipStream(new MemoryStream(archive), CompressionMode.Decompress), staging, overwriteFiles: true);

        var target = Path.Combine(versions, latest);
        if (Directory.Exists(target))
        {
            try { Directory.Delete(target, recursive: true); }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { target += "-" + Guid.NewGuid().ToString("N")[..6]; }
        }
        Directory.Move(staging, target);
        PointCurrent(root, target);
        RemoveUnusedVersions(root, target);

        output.WriteLine($"Updated {Version} -> {latest}.");
        var exe = Path.Combine(root, "current", ExeName);
        // Refresh only: an update never registers with clients detected since the install.
        using var p = Process.Start(new ProcessStartInfo(exe, "install --refresh-only") { UseShellExecute = false })!;
        p.WaitForExit();
        return p.ExitCode;
    }

    /// <summary>
    /// Puts &lt;root&gt;/current on the user's PATH (Windows) or links ~/.local/bin/corvus to the program in it, and removes
    /// <paramref name="dropRoot"/>'s entry or link (<paramref name="dropExe"/>), as the install scripts do.
    /// </summary>
    public static void PutOnPath(string root, string? dropRoot = null, string? dropExe = null)
    {
        var current = Path.Combine(root, "current");
        if (OperatingSystem.IsWindows())
        {
            var drop = dropRoot == null ? null : Path.Combine(dropRoot, "current");
            var entries = (Environment.GetEnvironmentVariable("Path", EnvironmentVariableTarget.User) ?? "")
                .Split(';', StringSplitOptions.RemoveEmptyEntries).Where(p => drop == null || !p.TrimEnd('\\').Equals(drop, StringComparison.OrdinalIgnoreCase)).ToList();
            if (!entries.Any(p => p.TrimEnd('\\').Equals(current, StringComparison.OrdinalIgnoreCase))) entries.Add(current);
            Environment.SetEnvironmentVariable("Path", string.Join(';', entries), EnvironmentVariableTarget.User);
            return;
        }
        var bin = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".local", "bin");
        Directory.CreateDirectory(bin);
        var link = Path.Combine(bin, ExeName);
        if (File.Exists(link) || new FileInfo(link).LinkTarget != null) File.Delete(link);
        File.CreateSymbolicLink(link, Path.Combine(current, ExeName));
        if (dropRoot != null && dropExe != null && Path.Combine(bin, dropExe) is var old && new FileInfo(old).LinkTarget is { } t && t.StartsWith(dropRoot, StringComparison.Ordinal))
            File.Delete(old);
    }

    /// <summary>Makes &lt;root&gt;/current a link to <paramref name="target"/> (a junction on Windows: no privileges needed).</summary>
    public static void PointCurrent(string root, string target)
    {
        var current = Path.Combine(root, "current");
        if (OperatingSystem.IsWindows())
        {
            if (Directory.Exists(current)) Directory.Delete(current); // removes the junction, not its target
            using var p = Process.Start(new ProcessStartInfo("cmd.exe", $"/c mklink /J \"{current}\" \"{target}\"")
                { UseShellExecute = false, RedirectStandardOutput = true, RedirectStandardError = true, CreateNoWindow = true })!;
            p.WaitForExit();
            if (p.ExitCode != 0) throw new IOException($"Could not link {current}: {p.StandardError.ReadToEnd().Trim()}");
        }
        else
        {
            var temp = current + ".new";
            if (File.Exists(temp) || Directory.Exists(temp)) File.Delete(temp);
            File.CreateSymbolicLink(temp, target);
            File.Move(temp, current, overwrite: true);
        }
    }

    /// <summary>Deletes versions other than the active one; those still running stay until a later update.</summary>
    public static void RemoveUnusedVersions(string root, string active)
    {
        foreach (var dir in Directory.EnumerateDirectories(Path.Combine(root, "versions")))
        {
            if (Path.GetFullPath(dir).Equals(Path.GetFullPath(active), StringComparison.OrdinalIgnoreCase)) continue;
            try { Directory.Delete(dir, recursive: true); }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
        }
    }

    /// <summary>Default location of per-user data: annotations, analysis and code-index caches, symbols, Il2Cpp caches, reference packs.</summary>
    public static string? DataRoot(SetupEnvironment env) =>
        env.Variable(Native.Providers.DataFolder.RootVariable) is { Length: > 0 } custom ? Path.GetFullPath(custom)
        : Path.IsPathFullyQualified(env.LocalAppData) ? Path.Combine(env.LocalAppData, Native.Providers.DataFolder.Name) : null;

    /// <summary>What uninstall deletes, in order (links are removed without following them), and the data entries it keeps.</summary>
    internal sealed record Removal(IReadOnlyList<(string Path, bool Link)> Delete, string? RootIfEmpty, string DataRoot, IReadOnlyList<string> Kept);

    /// <summary>The program files (current, versions/), or with <paramref name="purgeData"/> the install root and the data root.</summary>
    public static Removal PlanRemoval(string root, string dataRoot, bool purgeData)
    {
        var delete = new List<(string, bool)> { (Path.Combine(root, "current"), true) };
        if (purgeData)
        {
            delete.Add((root, false));
            if (!SamePath(root, dataRoot)) delete.Add((dataRoot, false));
            return new Removal(delete, null, dataRoot, []);
        }
        delete.Add((Path.Combine(root, "versions"), false));
        bool shared = SamePath(root, dataRoot);
        List<string> kept = Directory.Exists(dataRoot)
            ? [.. Directory.EnumerateFileSystemEntries(dataRoot).Select(Path.GetFileName).OfType<string>()
                .Where(n => !(shared && n is "versions" or "current")).Order(StringComparer.Ordinal)]
            : [];
        return new Removal(delete, root, dataRoot, kept);
    }

    private static bool SamePath(string a, string b) =>
        Path.TrimEndingDirectorySeparator(Path.GetFullPath(a)).Equals(Path.TrimEndingDirectorySeparator(Path.GetFullPath(b)),
            OperatingSystem.IsLinux() ? StringComparison.Ordinal : StringComparison.OrdinalIgnoreCase);

    /// <summary>Deletes the planned paths now; files in use stay behind.</summary>
    public static void Apply(Removal plan)
    {
        foreach (var (path, _) in plan.Delete)
        {
            try
            {
                var dir = new DirectoryInfo(path);
                if (dir.LinkTarget != null) { if (OperatingSystem.IsWindows()) dir.Delete(); else File.Delete(path); }
                else if (dir.Exists) dir.Delete(recursive: true);
                else if (File.Exists(path)) File.Delete(path);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
        }
        if (plan.RootIfEmpty is { } root && Directory.Exists(root) && !Directory.EnumerateFileSystemEntries(root).Any())
            Directory.Delete(root);
    }

    /// <summary>A cmd.exe command line that applies the plan once this process has exited and released its files.</summary>
    public static string DeferredWindowsCommand(Removal plan)
    {
        var steps = new List<string> { "ping -n 3 127.0.0.1 >nul" };
        steps.AddRange(plan.Delete.Select(d => d.Link ? $"rmdir \"{d.Path}\" 2>nul" : $"rmdir /s /q \"{d.Path}\" 2>nul"));
        if (plan.RootIfEmpty is { } root) steps.Add($"rmdir \"{root}\" 2>nul");
        return string.Join(" & ", steps);
    }

    /// <summary>
    /// Removes the program (versions/, current, its PATH entry or ~/.local/bin link) and keeps user data unless
    /// <paramref name="purgeData"/>. On Windows the running files are deleted after exit.
    /// </summary>
    public static void RemoveFiles(string root, string dataRoot, bool purgeData, TextWriter output)
    {
        var plan = PlanRemoval(root, dataRoot, purgeData);
        // Report first: this program's own files are deleted below, and later output may need to load one of them.
        Report(plan, root, output);
        output.Flush();
        var current = Path.Combine(root, "current");
        if (OperatingSystem.IsWindows())
        {
            var path = Environment.GetEnvironmentVariable("Path", EnvironmentVariableTarget.User) ?? "";
            var kept = path.Split(';', StringSplitOptions.RemoveEmptyEntries).Where(p => !p.TrimEnd('\\').Equals(current, StringComparison.OrdinalIgnoreCase));
            Environment.SetEnvironmentVariable("Path", string.Join(';', kept), EnvironmentVariableTarget.User);
            Process.Start(new ProcessStartInfo("cmd.exe", "/c " + DeferredWindowsCommand(plan)) { UseShellExecute = false, CreateNoWindow = true });
        }
        else
        {
            var link = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".local", "bin", ExeName);
            try
            {
                if (new FileInfo(link).LinkTarget is { } t && t.StartsWith(root, StringComparison.Ordinal)) File.Delete(link);
            }
            catch (IOException) { }
            Apply(plan);
        }
    }

    /// <summary>Deletes the data root when this copy was not installed by the install scripts.</summary>
    public static void PurgeData(string dataRoot, TextWriter output)
    {
        Apply(new Removal([(dataRoot, false)], null, dataRoot, []));
        output.WriteLine($"Removed {dataRoot}.");
    }

    public static void Report(Removal plan, string root, TextWriter output)
    {
        if (plan.RootIfEmpty == null)
        {
            output.WriteLine($"Removed {string.Join(" and ", plan.Delete.Where(d => !d.Link).Select(d => d.Path))}.");
            return;
        }
        output.WriteLine($"Removed the program files from {root}.");
        if (plan.Kept.Count > 0)
            output.WriteLine($"Kept your data in {plan.DataRoot} ({string.Join(", ", plan.Kept)}); delete that folder to remove it, or uninstall with --purge-data.");
    }
}
