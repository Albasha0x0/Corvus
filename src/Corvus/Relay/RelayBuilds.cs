using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Corvus.Native.Providers;

namespace Corvus.Relay;

/// <summary>One published build: its id and the marker text that announced it (null: a folder published without one).</summary>
public sealed record RelayBuild(string Id, string? Marker)
{
    public static RelayBuild From(string? marker) => new(RelayBuilds.IdOf(marker), marker);
}

/// <summary>The publish marker, staged copies of the publish folder, and the server program inside one.</summary>
public static class RelayBuilds
{
    /// <summary>Written by publish.ps1 as its last step; removed as its first.</summary>
    public const string MarkerName = ".build-complete";

    /// <summary>Files publish.ps1 renamed aside because a running process held them; never part of a build.</summary>
    public const string AsideInfix = ".aside-";

    private static int _sequence;

    public static string ProgramName => OperatingSystem.IsWindows() ? "corvus.exe" : "corvus";

    /// <summary>The server's main assembly, which a dotnet launch names.</summary>
    public const string ProgramDll = "corvus.dll";

    // Migration only: the main assembly before the rename, still named by registrations made then.
    private const string LegacyProgramDll = "NetDecompilerMcp.dll";

    /// <summary>Whether <paramref name="arg"/> names the server's main assembly, of this build or one from before the rename.</summary>
    public static bool IsProgramDll(string arg) =>
        Path.GetFileName(arg) is var name && (name.Equals(ProgramDll, StringComparison.OrdinalIgnoreCase) || name.Equals(LegacyProgramDll, StringComparison.OrdinalIgnoreCase));

    /// <summary>The marker's text, or null when there is none or it cannot be read (being written or replaced).</summary>
    public static string? ReadMarker(string directory)
    {
        try
        {
            // Shared for delete and write, so a publish replacing the marker never fails on the relay's read.
            using var stream = new FileStream(Path.Combine(directory, MarkerName), FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            using var reader = new StreamReader(stream);
            return reader.ReadToEnd().Trim();
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { return null; }
    }

    /// <summary>The marker's buildId, else a hash of its text; "unmarked" without one.</summary>
    public static string IdOf(string? marker)
    {
        if (string.IsNullOrEmpty(marker)) return "unmarked";
        try
        {
            using var doc = JsonDocument.Parse(marker);
            if (doc.RootElement.ValueKind == JsonValueKind.Object && doc.RootElement.TryGetProperty("buildId", out var id) && id.ValueKind == JsonValueKind.String)
                return id.GetString()!;
        }
        catch (JsonException) { }
        return Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(marker)))[..12];
    }

    /// <summary>The UTC time in a marker's buildId (yyyyMMddTHHmmssZ-...), or null when the marker has none.</summary>
    public static DateTime? BuiltAt(string? marker)
    {
        var id = IdOf(marker);
        return id.Length >= 16 && DateTime.TryParseExact(id[..16], "yyyyMMdd'T'HHmmss'Z'", System.Globalization.CultureInfo.InvariantCulture,
            System.Globalization.DateTimeStyles.AssumeUniversal | System.Globalization.DateTimeStyles.AdjustToUniversal, out var at) ? at : null;
    }

    /// <summary>The source tree above <paramref name="publishDirectory"/> (the folder holding publish.ps1 and src), or null when none is found.</summary>
    public static string? SourceRootOf(string publishDirectory)
    {
        for (var dir = new DirectoryInfo(Path.GetFullPath(publishDirectory)).Parent; dir != null; dir = dir.Parent)
            if (File.Exists(Path.Combine(dir.FullName, "publish.ps1")) && Directory.Exists(Path.Combine(dir.FullName, "src"))) return dir.FullName;
        return null;
    }

    /// <summary>A warning when the build is older than a source file, or its time is unknown; null when current or when no source tree is found.</summary>
    public static string? StaleSourceNote(string publishDirectory, string? marker)
    {
        if (SourceRootOf(publishDirectory) is not { } root || NewestSource(root) is not { } source) return null;
        if (BuiltAt(marker) is not { } built) return "the build time is unknown, so it cannot be compared with the source tree; publish again";
        return source > built
            ? $"the build is from {built:yyyy-MM-dd HH:mm} UTC, older than the source tree ({source:yyyy-MM-dd HH:mm} UTC); publish again"
            : null;
    }

    /// <summary>The newest write time of a source file under <paramref name="sourceRoot"/>/src, UTC; null when there is none or the tree cannot be read.</summary>
    public static DateTime? NewestSource(string sourceRoot)
    {
        var src = Path.Combine(sourceRoot, "src");
        try { return Newest(new DirectoryInfo(src)); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { return null; }
    }

    // Skips build output folders so a large tree is not walked twice.
    private static DateTime? Newest(DirectoryInfo directory)
    {
        DateTime? newest = null;
        var options = new EnumerationOptions { IgnoreInaccessible = true };
        foreach (var file in directory.EnumerateFiles("*.cs", options))
            if (newest == null || file.LastWriteTimeUtc > newest) newest = file.LastWriteTimeUtc;
        foreach (var sub in directory.EnumerateDirectories("*", options))
        {
            if (sub.Name is "obj" or "bin") continue;
            if (Newest(sub) is { } at && (newest == null || at > newest)) newest = at;
        }
        return newest;
    }

    /// <summary>Copies <paramref name="target"/> to a new folder under <paramref name="state"/>, so the server never runs files a republish replaces; IOException when a publish changed it meanwhile.</summary>
    public static string Stage(string target, string state, string? marker)
    {
        var dir = Path.Combine(state, "builds", $"{Environment.ProcessId}-{Interlocked.Increment(ref _sequence)}");
        // Left by an earlier process with the same id.
        if (Directory.Exists(dir)) Directory.Delete(dir, recursive: true);
        try
        {
            CopyTree(target, dir, skip: name => name == MarkerName || name.Contains(AsideInfix, StringComparison.Ordinal));
            if (ReadMarker(target) != marker) throw new IOException($"{target} changed while it was copied (a publish is running).");
            if (!File.Exists(Path.Combine(dir, ProgramName)) && !File.Exists(Path.Combine(dir, ProgramDll)))
                throw new IOException($"{target} holds no {ProgramName}.");
            return dir;
        }
        catch
        {
            TryDelete(dir);
            throw;
        }
    }

    /// <summary>Deletes staged builds of relays that are no longer running.</summary>
    public static void RemoveStale(string state)
    {
        var builds = Path.Combine(state, "builds");
        if (!Directory.Exists(builds)) return;
        foreach (var dir in Directory.EnumerateDirectories(builds))
        {
            var name = Path.GetFileName(dir);
            if (int.TryParse(name.AsSpan(0, Math.Max(0, name.IndexOf('-'))), out var pid) && pid != Environment.ProcessId && !Alive(pid)) TryDelete(dir);
        }
    }

    /// <summary>Starts the server in a staged folder: its apphost, else its dll under the dotnet host.</summary>
    public static ChildProcess Launch(string directory, IReadOnlyList<string> serverArgs, string? target = null)
    {
        var exe = Path.Combine(directory, ProgramName);
        var start = (File.Exists(exe) ? new ChildProcessStart(exe, serverArgs)
            : new ChildProcessStart(Native.Providers.Worker.WorkerPool.DotnetHost(), [Path.Combine(directory, ProgramDll), .. serverArgs])) with { OwnProgram = true };
        // The server refuses outputs in the folder it is published from.
        if (target != null) start = start with { Environment = new Dictionary<string, string?> { [TargetVariable] = target } };
        // The relayed server resolves relative paths against the relay's folder.
        return ChildProcess.Start(start with { WorkingDirectory = Environment.CurrentDirectory });
    }

    /// <summary>Names the publish folder for the server the relay starts.</summary>
    public const string TargetVariable = "CORVUS_RELAY_TARGET";

    /// <summary>Copies <paramref name="program"/>'s folder to a versioned, content-addressed folder under <paramref name="state"/>; returns the copy's program.</summary>
    public static string StageHost(string program, string state, bool dryRun)
    {
        var source = Path.GetDirectoryName(Path.GetFullPath(program))!;
        var main = Path.Combine(source, ProgramDll);
        var hash = Convert.ToHexStringLower(SHA256.HashData(File.ReadAllBytes(File.Exists(main) ? main : program)))[..12];
        var version = typeof(RelayBuilds).Assembly.GetName().Version?.ToString(3) ?? "0";
        var dir = Path.Combine(state, "host", $"{version}-{hash}");
        var staged = Path.Combine(dir, Path.GetFileName(program));
        if (dryRun || File.Exists(staged)) return staged;
        var temp = dir + ".tmp-" + Environment.ProcessId;
        TryDelete(temp);
        CopyTree(source, temp, skip: name => name == MarkerName || name.Contains(AsideInfix, StringComparison.Ordinal));
        try { Directory.Move(temp, dir); }
        // Another install staged it first.
        catch (IOException) when (File.Exists(staged)) { TryDelete(temp); }
        return staged;
    }

    /// <summary>Deletes half-made host copies and those whose version-hash name no client configuration text names; running copies stay.</summary>
    public static List<string> RemoveUnusedHosts(string state, IReadOnlyCollection<string> configurations)
    {
        var hosts = Path.Combine(state, "host");
        var removed = new List<string>();
        if (!Directory.Exists(hosts)) return removed;
        foreach (var dir in Directory.EnumerateDirectories(hosts))
        {
            var name = Path.GetFileName(dir);
            if (!name.Contains(".tmp-", StringComparison.Ordinal) && configurations.Any(c => c.Contains(name, StringComparison.OrdinalIgnoreCase))) continue;
            TryDelete(dir);
            if (!Directory.Exists(dir)) removed.Add(dir);
        }
        return removed;
    }

    /// <summary>Whether <paramref name="path"/> is <paramref name="directory"/> or inside it.</summary>
    public static bool IsInside(string path, string directory)
    {
        var full = Path.TrimEndingDirectorySeparator(Path.GetFullPath(path)) + Path.DirectorySeparatorChar;
        var root = Path.TrimEndingDirectorySeparator(Path.GetFullPath(directory)) + Path.DirectorySeparatorChar;
        return full.StartsWith(root, OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal);
    }

    public static void TryDelete(string dir)
    {
        try { if (Directory.Exists(dir)) Directory.Delete(dir, recursive: true); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
    }

    private static void CopyTree(string source, string destination, Func<string, bool> skip)
    {
        Directory.CreateDirectory(destination);
        foreach (var file in Directory.EnumerateFiles(source))
        {
            var name = Path.GetFileName(file);
            if (!skip(name)) File.Copy(file, Path.Combine(destination, name), overwrite: true);
        }
        foreach (var dir in Directory.EnumerateDirectories(source))
            CopyTree(dir, Path.Combine(destination, Path.GetFileName(dir)), skip);
    }

    private static bool Alive(int pid)
    {
        try
        {
            using var process = Process.GetProcessById(pid);
            return !process.HasExited;
        }
        catch (Exception ex) when (ex is ArgumentException or InvalidOperationException) { return false; }
    }
}
