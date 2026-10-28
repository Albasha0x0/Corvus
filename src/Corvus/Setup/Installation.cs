using System.Diagnostics;
using System.Formats.Tar;
using System.IO.Compression;
using System.Runtime.InteropServices;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace Corvus.Setup;

/// <summary>The per-user install layout: versions/&lt;version&gt;/ per build, current links to the active one, clients point at the link.</summary>
internal static class Installation
{
    public const string DefaultRepository = "Albasha0x0/Corvus";
    public static string ExeName => OperatingSystem.IsWindows() ? "corvus.exe" : "corvus";
    public static string Version => typeof(Installation).Assembly.GetName().Version?.ToString(3) ?? "0.0.0";

    /// <summary>The install root when this process runs from &lt;root&gt;/versions/&lt;version&gt;/ or &lt;root&gt;/current/.</summary>
    public static string? Root() => Core.OutputGuard.InstallRoot();

    public const string HomeVariable = "CORVUS_HOME";

    /// <summary>Where the install scripts put the program: CORVUS_HOME, else %LOCALAPPDATA%\Corvus, else $XDG_DATA_HOME/Corvus (~/.local/share).</summary>
    public static string DefaultRoot(SetupEnvironment env) =>
        env.Set(HomeVariable) ?? (env.Os == HostOs.Windows ? Path.Combine(env.LocalAppData, "Corvus") : Path.Combine(XdgData(env), "Corvus"));

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
            : $"Checksum mismatch for {assetName} (expected {expected.ToLowerInvariant()}, got {actual}): download corrupt or altered. Nothing was installed.";
    }

    /// <summary>The owner/name repository updates are read from; corvus.json refuses it.</summary>
    public const string RepositoryVariable = "CORVUS_REPO";

    /// <summary>Set to 1 to refuse a build whose provenance could not be checked; 0 skips the check (a self-built archive).</summary>
    public const string RequireAttestationVariable = "CORVUS_REQUIRE_ATTESTATION";

    /// <summary>The workflow that builds and attests every release asset, as a path in the repository.</summary>
    public const string ReleaseWorkflow = ".github/workflows/release.yml";

    /// <summary>What a provenance check concluded: verified, not checked (the reason is in the message) or refused.</summary>
    internal enum ProvenanceState { Verified, NotChecked, Refused }

    /// <summary>A provenance check's conclusion and the line to print for it.</summary>
    internal sealed record Provenance(ProvenanceState State, string Message);

    /// <summary>gh's exit code and combined output for <paramref name="arguments"/>, or null when gh is not on PATH.</summary>
    internal delegate (int ExitCode, string Output)? GhRunner(IReadOnlyList<string> arguments);

    // Output of a gh check that could not run (offline, rate limited, old gh), not a finding about the file.
    // Anything else on exit 1 refuses: an unrecognised failure is not a pass.
    private static readonly System.Text.RegularExpressions.Regex GhUnavailable = new(
        @"unknown command|unknown flag|sigstore verifier|trusted root|dial tcp|no such host|connection refused|connection reset|i/o timeout|timed out|timeout exceeded|TLS handshake|proxyconnect|HTTP (?:401|403|429|5\d\d)",
        System.Text.RegularExpressions.RegexOptions.IgnoreCase);

    /// <summary>Checks the archive's build provenance with gh attestation verify; not checked without gh or GitHub, refused on other failures.</summary>
    // A require of "1" refuses an unchecked archive; "0" skips the check.
    internal static Provenance CheckProvenance(string archivePath, string assetName, string repo, string? tag, string? require, GhRunner gh)
    {
        if (require == "0") return new(ProvenanceState.NotChecked, $"Provenance not checked ({RequireAttestationVariable}=0).");
        List<string> args = ["attestation", "verify", archivePath, "--repo", repo, "--signer-workflow", $"{repo}/{ReleaseWorkflow}"];
        if (tag is { Length: > 0 }) args.AddRange(["--source-ref", $"refs/tags/{tag}"]);
        string reason;
        if (gh(args) is not { } run) reason = "gh is not on PATH";
        else if (run.ExitCode == 0) return new(ProvenanceState.Verified, $"Provenance verified: {assetName} was built by {repo}'s release workflow.");
        // Exit code 4: gh needs authentication.
        else if (run.ExitCode == 4) reason = "gh is not signed in: gh auth login, or set GH_TOKEN";
        else if (run.ExitCode != 1 || GhUnavailable.IsMatch(run.Output)) reason = $"gh: {FirstLine(run.Output)}";
        else return new(ProvenanceState.Refused, $"Provenance check failed for {assetName} against {repo}'s release workflow: " +
            $"{FirstLine(run.Output)}. Nothing was installed.");
        return require == "1"
            ? new(ProvenanceState.Refused, $"Provenance not checked ({reason}) and {RequireAttestationVariable}=1; nothing was installed.")
            : new(ProvenanceState.NotChecked, $"Provenance not checked ({reason}).");
    }

    private static string FirstLine(string text) =>
        text.Split('\n').Select(l => l.Trim()).FirstOrDefault(l => l.Length > 0) is { } line
            ? (line.StartsWith("Error: ", StringComparison.Ordinal) ? line[7..] : line) : "no output";

    /// <summary>Runs gh from PATH with <paramref name="arguments"/> for at most 2 minutes; null when gh is not on PATH.</summary>
    internal static (int ExitCode, string Output)? RunGh(IReadOnlyList<string> arguments)
    {
        var name = OperatingSystem.IsWindows() ? "gh.exe" : "gh";
        var exe = (Environment.GetEnvironmentVariable("PATH") ?? "").Split(Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries)
            .Select(d => Path.Combine(d.Trim('"'), name)).FirstOrDefault(File.Exists);
        if (exe == null) return null;
        var start = new ProcessStartInfo(exe) { UseShellExecute = false, RedirectStandardOutput = true, RedirectStandardError = true, CreateNoWindow = true };
        foreach (var a in arguments) start.ArgumentList.Add(a);
        start.Environment["GH_PROMPT_DISABLED"] = "1";
        start.Environment["GH_NO_UPDATE_NOTIFIER"] = "1";
        Process p;
        try { p = Process.Start(start)!; }
        catch (System.ComponentModel.Win32Exception ex) { return (-1, $"could not start gh: {ex.Message}"); }
        using var _ = p;
        var stdout = p.StandardOutput.ReadToEndAsync();
        var stderr = p.StandardError.ReadToEndAsync();
        if (!p.WaitForExit(TimeSpan.FromMinutes(2)))
        {
            try { p.Kill(entireProcessTree: true); } catch (InvalidOperationException) { }
            return (-1, "timed out after 2 minutes");
        }
        return (p.ExitCode, stderr.GetAwaiter().GetResult() + "\n" + stdout.GetAwaiter().GetResult());
    }

    /// <summary>The NuGet package of the .NET tool (dotnet tool install -g, dotnet tool exec / dnx).</summary>
    public const string PackageId = "CorvusRE";

    /// <summary>The winget package of the release archive.</summary>
    public const string WingetId = "Albasha0x0.Corvus";

    /// <summary>The command that updates a copy of this install kind (<see cref="Mcp.ServerIdentity.ClassifyInstall"/>), or null for a build from source.</summary>
    public static string? UpdateCommand(string installKind, string? version = null) => installKind switch
    {
        "script" => "corvus update" + (version is { Length: > 0 } ? $" --version {version.TrimStart('v')}" : ""),
        "dotnet-tool" => $"dotnet tool update -g {PackageId}" + (version is { Length: > 0 } ? $" --version {version.TrimStart('v')}" : ""),
        "dnx" => $"dnx {PackageId}" + (version is { Length: > 0 } ? $"@{version.TrimStart('v')}" : "") + " --yes",
        "winget" => $"winget upgrade {WingetId}" + (version is { Length: > 0 } ? $" --version {version.TrimStart('v')}" : ""),
        "scoop" => "scoop update corvus",
        "homebrew" => "brew upgrade corvus",
        _ => null,
    };

    /// <summary>Why <c>update</c> cannot replace a copy the install scripts did not install, and what does.</summary>
    public static string NotSelfUpdating(string installKind, string? version = null) => installKind switch
    {
        "dotnet-tool" => $"This copy is the .NET tool {PackageId}, which the dotnet CLI updates: {UpdateCommand(installKind, version)}",
        "dnx" => $"This copy runs from the NuGet package cache, which starts the newest or pinned release each time: {UpdateCommand(installKind, version)}",
        "winget" or "scoop" or "homebrew" => $"This copy is managed by {installKind}, which updates it: {UpdateCommand(installKind, version)}",
        _ => "This copy was not installed by the install script, so it cannot update itself." + Environment.NewLine
            + "Install with the one-line command in the README, or rebuild from source.",
    };

    /// <summary>The GitHub API address of the latest release, or of the release tagged v<paramref name="version"/>.</summary>
    public static string ReleaseApi(string repo, string? version) =>
        version is { Length: > 0 } v ? $"https://api.github.com/repos/{repo}/releases/tags/v{v.TrimStart('v')}" : $"https://api.github.com/repos/{repo}/releases/latest";

    /// <summary>A warning when <paramref name="target"/> is older than the running <paramref name="current"/>, else null.</summary>
    public static string? DowngradeWarning(string current, string target) =>
        System.Version.TryParse(target.TrimStart('v'), out var t) && System.Version.TryParse(current, out var c) && t < c
            ? $"Warning: {target.TrimStart('v')} is older than the installed {current} (a downgrade); tools, options and saved formats may differ. " +
              $"corvus update returns to the latest release."
            : null;

    /// <summary>Installs the latest release or <paramref name="version"/> (older: a rollback) and refreshes registrations; dryRun only reports.</summary>
    public static int Update(TextWriter output, string? version = null, bool dryRun = false, string? installKind = null)
    {
        if (Root() is not { } root)
        {
            output.WriteLine(NotSelfUpdating(installKind ?? Mcp.ServerIdentity.InstallKind, version));
            return 1;
        }
        var repo = Environment.GetEnvironmentVariable(RepositoryVariable) is { Length: > 0 } r ? r : DefaultRepository;
        using var http = GitHubHttp.Create("Corvus/" + Version, Environment.GetEnvironmentVariable("GITHUB_TOKEN"));

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
        if (DowngradeWarning(Version, latest) is { } warning) output.WriteLine(warning);
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
        var signatureAsset = Asset(ReleaseSigning.SignatureAsset);
        if (dryRun)
        {
            output.WriteLine($"Would install {tag} ({AssetName}, checked against {ChecksumManifest}, its signature and, when gh can, its build provenance) into {Path.Combine(root, "versions", latest)},");
            output.WriteLine($"point {Path.Combine(root, "current")} at it and refresh existing registrations; no clients are added.");
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
        byte[] archive, manifest;
        byte[]? signature;
        try
        {
            archive = Download(asset);
            manifest = Download(sumsAsset);
            signature = signatureAsset != null ? Download(signatureAsset) : null;
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException)
        {
            output.WriteLine($"Download failed: {ex.Message}");
            return 1;
        }
        if (!VerifyDownload(output, AssetName, archive, manifest, signature, ReleaseSigning.PublicKey, repo, tag,
                Environment.GetEnvironmentVariable(RequireAttestationVariable), RunGh)) return 1;

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
        Corvus.Core.SafeFile.WhenReleased(() => Directory.Move(staging, target));
        PointCurrent(root, target);
        RemoveUnusedVersions(root, target, AppContext.BaseDirectory);

        output.WriteLine($"Updated {Version} -> {latest}.");
        var exe = Path.Combine(root, "current", ExeName);
        // Refresh only: an update never registers with clients detected since the install.
        using var p = Process.Start(new ProcessStartInfo(exe, "install --refresh-only") { UseShellExecute = false })!;
        p.WaitForExit();
        return p.ExitCode;
    }

    /// <summary>
    /// Checks a downloaded build: the signature of <paramref name="manifest"/>,
    /// the archive's SHA-256 in it, then its build provenance through
    /// <paramref name="gh"/>. Prints a line per check; false when one refuses.
    /// </summary>
    internal static bool VerifyDownload(TextWriter output, string assetName, byte[] archive, byte[] manifest, byte[]? signature, string publicKey,
        string repo, string? tag, string? require, GhRunner gh)
    {
        // The signature comes first: SHA256SUMS is trusted only once it is.
        var signed = ReleaseSigning.Check(manifest, signature, publicKey, require);
        output.WriteLine(signed.Message);
        if (signed.State == ReleaseSigning.SignatureState.Refused) return false;
        if (VerifyChecksum(System.Text.Encoding.UTF8.GetString(manifest), assetName, archive) is { } mismatch)
        {
            output.WriteLine(mismatch);
            return false;
        }
        // The attestation ties the archive to this repository's workflow.
        var check = Path.Combine(Path.GetTempPath(), "corvus-" + Guid.NewGuid().ToString("N")[..8], assetName);
        Provenance provenance;
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(check)!);
            File.WriteAllBytes(check, archive);
            provenance = CheckProvenance(check, assetName, repo, tag, require, gh);
        }
        finally { try { Directory.Delete(Path.GetDirectoryName(check)!, recursive: true); } catch (IOException) { } }
        output.WriteLine(provenance.Message);
        return provenance.State != ProvenanceState.Refused;
    }

    /// <summary>Puts current on PATH (Windows) or links ~/.local/bin/corvus to it, and removes the dropped root's entry or link.</summary>
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
            // Removes the junction, not its target.
            if (Directory.Exists(current)) Directory.Delete(current);
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
            // File.Move follows the link, finds a directory and refuses it.
            Core.Posix.Rename(temp, current);
        }
    }

    /// <summary>Deletes versions other than the active one; those still running stay until a later update.</summary>
    /// <summary>Deletes every version but <paramref name="active"/> and the running one: on Linux and macOS its deletion succeeds and the
    /// process then fails to load its next assembly; the next update removes it.</summary>
    public static void RemoveUnusedVersions(string root, string active, string running)
    {
        static string Full(string path) => Path.TrimEndingDirectorySeparator(Path.GetFullPath(path));
        foreach (var dir in Directory.EnumerateDirectories(Path.Combine(root, "versions")))
        {
            if (Full(dir).Equals(Full(active), StringComparison.OrdinalIgnoreCase)) continue;
            if (Full(running).StartsWith(Full(dir) + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase) || Full(running).Equals(Full(dir), StringComparison.OrdinalIgnoreCase)) continue;
            try { Directory.Delete(dir, recursive: true); }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
        }
    }

    /// <summary>Default location of per-user data: annotations, analysis and code-index caches, symbols, metadata caches, reference packs.</summary>
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

    /// <summary>Removes the program and its PATH entry or link, keeping user data unless <paramref name="purgeData"/>; Windows deletes after exit.</summary>
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
