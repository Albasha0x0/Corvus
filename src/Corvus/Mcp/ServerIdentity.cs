using System.Diagnostics;
using System.Reflection;

namespace Corvus.Mcp;

/// <summary>Which copy of the server is running: its program, build, install channel and start time.</summary>
public static class ServerIdentity
{
    public const string Product = "Corvus";

    /// <summary>The server's program: the executable, or the server's .dll when it runs under the dotnet host.</summary>
    public static string Executable { get; } = FindExecutable();

    /// <summary>The informational version: the version, plus "+commit" when the build knew its source revision.</summary>
    public static string InformationalVersion { get; } =
        typeof(ServerIdentity).Assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion
        ?? typeof(ServerIdentity).Assembly.GetName().Version?.ToString(3) ?? "?";

    /// <summary>The source commit from <see cref="InformationalVersion"/>, or null.</summary>
    public static string? Commit => InformationalVersion.IndexOf('+') is var plus and >= 0 && InformationalVersion[(plus + 1)..] is { Length: > 0 } c ? c : null;

    public static DateTimeOffset StartedAt { get; } = StartTime();

    public static string InstallKind { get; } = ClassifyInstall(Executable);

    private static string FindExecutable()
    {
        var process = Environment.ProcessPath;
        if (process == null || Path.GetFileNameWithoutExtension(process).Equals("dotnet", StringComparison.OrdinalIgnoreCase))
            return typeof(ServerIdentity).Assembly.Location is { Length: > 0 } dll ? dll : process ?? "?";
        return Path.GetFullPath(process);
    }

    private static DateTimeOffset StartTime()
    {
        try
        {
            using var self = Process.GetCurrentProcess();
            return new DateTimeOffset(self.StartTime.ToUniversalTime(), TimeSpan.Zero);
        }
        catch (Exception ex) when (ex is InvalidOperationException or NotSupportedException or System.ComponentModel.Win32Exception)
        {
            return DateTimeOffset.UtcNow;
        }
    }

    /// <summary>
    /// How this copy was installed, from its path: script (&lt;root&gt;/versions or &lt;root&gt;/current of the install scripts),
    /// dotnet-tool, dnx (the NuGet package cache), winget, scoop, homebrew, else source (a build or publish folder).
    /// </summary>
    public static string ClassifyInstall(string executable)
    {
        var dir = Path.GetDirectoryName(Path.GetFullPath(executable)) ?? "";
        var parent = Path.GetDirectoryName(dir);
        if (Path.GetFileName(parent) == "versions" || (Path.GetFileName(dir) == "current" && parent != null && Directory.Exists(Path.Combine(parent, "versions"))))
            return "script";
        var p = "/" + dir.Replace('\\', '/').ToLowerInvariant() + "/";
        if (p.Contains("/.dotnet/tools/", StringComparison.Ordinal)) return "dotnet-tool";
        if (p.Contains("/.nuget/packages/", StringComparison.Ordinal)
            || Environment.GetEnvironmentVariable("NUGET_PACKAGES") is { Length: > 0 } cache && IsUnder(dir, cache)) return "dnx";
        if (p.Contains("/winget/packages/", StringComparison.Ordinal) || p.Contains("/winget/links/", StringComparison.Ordinal)) return "winget";
        if (p.Contains("/scoop/apps/", StringComparison.Ordinal)) return "scoop";
        if (p.Contains("/cellar/", StringComparison.Ordinal) || p.Contains("/caskroom/", StringComparison.Ordinal)) return "homebrew";
        return "source";
    }

    private static bool IsUnder(string path, string root) =>
        Path.GetFullPath(path).StartsWith(Path.TrimEndingDirectorySeparator(Path.GetFullPath(root)) + Path.DirectorySeparatorChar, PathComparison);

    private static StringComparison PathComparison => OperatingSystem.IsLinux() ? StringComparison.Ordinal : StringComparison.OrdinalIgnoreCase;

    /// <summary>Whether two paths name the same file, also through links (the install scripts' current link is a junction or symlink).</summary>
    public static bool SamePath(string a, string b)
    {
        try
        {
            return string.Equals(Path.GetFullPath(a), Path.GetFullPath(b), PathComparison) || string.Equals(RealPath(a), RealPath(b), PathComparison);
        }
        catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException)
        {
            return false;
        }
    }

    /// <summary>The path with every linked directory or file on it resolved.</summary>
    private static string RealPath(string path, int depth = 0)
    {
        var full = Path.GetFullPath(path);
        var root = Path.GetPathRoot(full) ?? "";
        var current = root;
        foreach (var part in full[root.Length..].Split([Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar], StringSplitOptions.RemoveEmptyEntries))
        {
            current = Path.Combine(current, part);
            try
            {
                FileSystemInfo info = Directory.Exists(current) ? new DirectoryInfo(current) : new FileInfo(current);
                // The target's own parents may be links too (macOS /var -> /private/var); 40 is the kernel's SYMLOOP_MAX.
                if (info.LinkTarget != null && info.ResolveLinkTarget(returnFinalTarget: true) is { } target)
                    current = depth < 40 ? RealPath(target.FullName, depth + 1) : target.FullName;
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { /* keep the path as written */ }
        }
        return current;
    }
}
