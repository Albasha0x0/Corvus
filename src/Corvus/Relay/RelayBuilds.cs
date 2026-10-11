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

    /// <summary>
    /// Copies <paramref name="target"/> to a new folder under <paramref name="state"/>, so the server never runs from files
    /// a republish replaces. Throws IOException when the marker changed during the copy (a publish started).
    /// </summary>
    public static string Stage(string target, string state, string? marker)
    {
        var dir = Path.Combine(state, "builds", $"{Environment.ProcessId}-{Interlocked.Increment(ref _sequence)}");
        if (Directory.Exists(dir)) Directory.Delete(dir, recursive: true); // left by an earlier process with the same id
        try
        {
            CopyTree(target, dir, skip: name => name == MarkerName || name.Contains(AsideInfix, StringComparison.Ordinal));
            if (ReadMarker(target) != marker) throw new IOException($"{target} changed while it was copied (a publish is running).");
            if (!File.Exists(Path.Combine(dir, ProgramName)) && !File.Exists(Path.Combine(dir, "corvus.dll")))
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
    public static ChildProcess Launch(string directory, IReadOnlyList<string> serverArgs)
    {
        var exe = Path.Combine(directory, ProgramName);
        if (File.Exists(exe)) return ChildProcess.Start(new ChildProcessStart(exe, serverArgs));
        return ChildProcess.Start(new ChildProcessStart(DotnetHost(), [Path.Combine(directory, "corvus.dll"), .. serverArgs]));
    }

    /// <summary>
    /// Copies the folder of <paramref name="program"/> (this server's apphost or dll) to a versioned, content-addressed folder
    /// under <paramref name="state"/>, so a registered relay never runs from files a publish replaces; returns the copy's program.
    /// </summary>
    public static string StageHost(string program, string state, bool dryRun)
    {
        var source = Path.GetDirectoryName(Path.GetFullPath(program))!;
        var main = Path.Combine(source, "corvus.dll");
        var hash = Convert.ToHexStringLower(SHA256.HashData(File.ReadAllBytes(File.Exists(main) ? main : program)))[..12];
        var version = typeof(RelayBuilds).Assembly.GetName().Version?.ToString(3) ?? "0";
        var dir = Path.Combine(state, "host", $"{version}-{hash}");
        var staged = Path.Combine(dir, Path.GetFileName(program));
        if (dryRun || File.Exists(staged)) return staged;
        var temp = dir + ".tmp-" + Environment.ProcessId;
        TryDelete(temp);
        CopyTree(source, temp, skip: name => name == MarkerName || name.Contains(AsideInfix, StringComparison.Ordinal));
        try { Directory.Move(temp, dir); }
        catch (IOException) when (File.Exists(staged)) { TryDelete(temp); } // another install staged it first
        return staged;
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

    private static string DotnetHost()
    {
        if (Environment.ProcessPath is { } self && Path.GetFileNameWithoutExtension(self).Equals("dotnet", StringComparison.OrdinalIgnoreCase)) return self;
        var name = OperatingSystem.IsWindows() ? "dotnet.exe" : "dotnet";
        if (Environment.GetEnvironmentVariable("DOTNET_HOST_PATH") is { Length: > 0 } host && File.Exists(host)) return host;
        foreach (var dir in (Environment.GetEnvironmentVariable("PATH") ?? "").Split(Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries))
            if (Path.Combine(dir.Trim('"'), name) is var candidate && File.Exists(candidate)) return candidate;
        return name;
    }
}
