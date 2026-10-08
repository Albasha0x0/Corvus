using System.Diagnostics;
using System.Formats.Tar;
using System.IO.Compression;
using System.Runtime.InteropServices;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace NetDecompilerMcp.Setup;

/// <summary>
/// The per-user install layout written by the install scripts: &lt;root&gt;/versions/&lt;version&gt;/ holds each build,
/// &lt;root&gt;/current links to the active one, and client configurations point at the link so updates need no edits.
/// </summary>
internal static class Installation
{
    public const string DefaultRepository = "Albasha0x0/Corvus";
    public static string ExeName => OperatingSystem.IsWindows() ? "NetDecompilerMcp.exe" : "NetDecompilerMcp";
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

    /// <summary>How clients should start this server: the stable "current" path for an installed build.</summary>
    public static ServerLaunch Launch()
    {
        var process = Environment.ProcessPath ?? ExeName;
        if (Path.GetFileNameWithoutExtension(process).Equals("dotnet", StringComparison.OrdinalIgnoreCase))
            return new ServerLaunch(process, [Path.Combine(AppContext.BaseDirectory, "NetDecompilerMcp.dll")]);
        if (Root() is { } root && File.Exists(Path.Combine(root, "current", ExeName)))
            return new ServerLaunch(Path.Combine(root, "current", ExeName), []);
        return new ServerLaunch(process, []);
    }

    private static string Rid => RuntimeInformation.RuntimeIdentifier;
    private static string AssetName => $"NetDecompilerMcp-{Rid}" + (OperatingSystem.IsWindows() ? ".zip" : ".tar.gz");

    /// <summary>Downloads the latest release into versions/, switches "current" to it and removes unused versions.</summary>
    public static int Update(TextWriter output)
    {
        if (Root() is not { } root)
        {
            output.WriteLine("This copy was not installed by the install script, so it cannot update itself.");
            output.WriteLine("Install with the one-line command in the README, or rebuild from source.");
            return 1;
        }
        var repo = Environment.GetEnvironmentVariable("NDM_REPO") is { Length: > 0 } r ? r : DefaultRepository;
        using var http = new HttpClient { Timeout = TimeSpan.FromMinutes(5) };
        http.DefaultRequestHeaders.UserAgent.ParseAdd("NetDecompilerMcp/" + Version);
        var token = Environment.GetEnvironmentVariable("GITHUB_TOKEN");
        if (!string.IsNullOrEmpty(token)) http.DefaultRequestHeaders.Authorization = new("Bearer", token);

        JsonNode release;
        try { release = JsonNode.Parse(http.GetStringAsync($"https://api.github.com/repos/{repo}/releases/latest").GetAwaiter().GetResult())!; }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException or JsonException)
        {
            output.WriteLine($"Could not read the latest release of {repo}: {ex.Message}");
            return 1;
        }
        var tag = release["tag_name"]?.GetValue<string>() ?? "";
        var latest = tag.TrimStart('v');
        if (System.Version.TryParse(latest, out var lv) && System.Version.TryParse(Version, out var cv) && lv <= cv)
        {
            output.WriteLine($"Up to date ({Version}).");
            return 0;
        }
        var asset = release["assets"]?.AsArray().FirstOrDefault(a => a?["name"]?.GetValue<string>() == AssetName);
        if (asset == null)
        {
            output.WriteLine($"Release {tag} has no build for {Rid} ({AssetName}).");
            return 1;
        }

        output.WriteLine($"Downloading {tag} ({AssetName})...");
        byte[] archive;
        try
        {
            using var request = new HttpRequestMessage(HttpMethod.Get, asset["url"]!.GetValue<string>());
            request.Headers.Accept.ParseAdd("application/octet-stream");
            using var response = http.Send(request);
            response.EnsureSuccessStatusCode();
            archive = response.Content.ReadAsByteArrayAsync().GetAwaiter().GetResult();
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException)
        {
            output.WriteLine($"Download failed: {ex.Message}");
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
        using var p = Process.Start(new ProcessStartInfo(exe, "install") { UseShellExecute = false })!;
        p.WaitForExit();
        return p.ExitCode;
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

    /// <summary>Removes the install folder and its PATH entry. On Windows the running files are deleted after exit.</summary>
    public static void RemoveFiles(string root, TextWriter output)
    {
        var current = Path.Combine(root, "current");
        if (OperatingSystem.IsWindows())
        {
            var path = Environment.GetEnvironmentVariable("Path", EnvironmentVariableTarget.User) ?? "";
            var kept = path.Split(';', StringSplitOptions.RemoveEmptyEntries).Where(p => !p.TrimEnd('\\').Equals(current, StringComparison.OrdinalIgnoreCase));
            Environment.SetEnvironmentVariable("Path", string.Join(';', kept), EnvironmentVariableTarget.User);
            Process.Start(new ProcessStartInfo("cmd.exe", $"/c ping -n 3 127.0.0.1 >nul & rmdir /s /q \"{root}\"")
                { UseShellExecute = false, CreateNoWindow = true });
        }
        else
        {
            var link = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".local", "bin", ExeName);
            try
            {
                if (new FileInfo(link).LinkTarget is { } t && t.StartsWith(root, StringComparison.Ordinal)) File.Delete(link);
            }
            catch (IOException) { }
            Directory.Delete(root, recursive: true);
        }
        output.WriteLine($"Removed {root}.");
    }
}
