using System.Diagnostics;
using System.Globalization;
using Corvus.Core;
using Corvus.Native.Live;

namespace Corvus.Services;

/// <summary>
/// The programs a session may open (--live-allow): a program is inside when its image path is a listed file or lies under a
/// listed folder. Checked on the real image path, and the backend is handed what was checked (a full path or a process id).
/// </summary>
public static class LiveProgramScope
{
    private static readonly StringComparison PathComparison = OperatingSystem.IsLinux() ? StringComparison.Ordinal : StringComparison.OrdinalIgnoreCase;

    /// <summary>The full path of the program to start, when it lies inside <paramref name="allowed"/>.</summary>
    public static string Spawn(string program, IReadOnlyList<string> allowed)
    {
        var path = FindProgram(program.Trim())
                   ?? throw new ToolError(ErrorCode.NotFound, $"'{program}' is not a program file.", "pass the full path of the program");
        if (!Contains(allowed, path))
            throw Outside($"{path} is outside the programs sessions may open.", allowed);
        return path;
    }

    /// <summary>The process id to attach to: the one named, or the single process of that name whose image lies inside <paramref name="allowed"/>.</summary>
    public static string Attach(string program, IReadOnlyList<string> allowed)
    {
        var text = program.Trim();
        if (int.TryParse(text, NumberStyles.None, CultureInfo.InvariantCulture, out int pid))
        {
            var image = ImagePath(pid) ?? throw Outside($"The image path of process {pid} cannot be read, so it cannot be checked against the allowed programs.", allowed);
            if (!Contains(allowed, image)) throw Outside($"Process {pid} ({image}) is outside the programs sessions may open.", allowed);
            return text;
        }
        var name = text.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) ? text[..^4] : text;
        var named = new List<(int Pid, string? Image)>();
        foreach (var p in Process.GetProcessesByName(name))
            using (p)
                named.Add((p.Id, ImagePath(p.Id)));
        var inside = named.Where(n => n.Image != null && Contains(allowed, n.Image)).ToList();
        return inside.Count switch
        {
            1 => inside[0].Pid.ToString(CultureInfo.InvariantCulture),
            0 when named.Count == 0 => throw new ToolError(ErrorCode.NotFound, $"No process is named '{name}'.", "live_session action=processes lists them"),
            0 => throw Outside($"{named.Count} process(es) named '{name}', none inside the programs sessions may open.", allowed),
            _ => throw new ToolError(ErrorCode.Ambiguous, $"{inside.Count} processes named '{name}' are inside the allowed programs: {string.Join(", ", inside.Select(i => i.Pid))}.",
                "pass the process id"),
        };
    }

    /// <summary>True when <paramref name="path"/> is a listed file or lies under a listed folder (links resolved on both sides).</summary>
    public static bool Contains(IReadOnlyList<string> allowed, string path)
    {
        var target = Canonical(path);
        foreach (var entry in allowed)
        {
            var root = Canonical(entry);
            if (target.Equals(root, PathComparison)) return true;
            var folder = Path.EndsInDirectorySeparator(root) ? root : root + Path.DirectorySeparatorChar;
            if (Directory.Exists(root) && target.StartsWith(folder, PathComparison)) return true;
        }
        return false;
    }

    private static string Canonical(string path)
    {
        var full = Path.GetFullPath(path);
        try
        {
            FileSystemInfo info = Directory.Exists(full) ? new DirectoryInfo(full) : new FileInfo(full);
            if (info.ResolveLinkTarget(returnFinalTarget: true) is { } link) full = Path.GetFullPath(link.FullName);
        }
        catch (IOException) { }
        catch (UnauthorizedAccessException) { }
        return Path.TrimEndingDirectorySeparator(full);
    }

    /// <summary>The program file as given, or found on PATH (with PATHEXT on Windows) like a shell would.</summary>
    private static string? FindProgram(string program)
    {
        if (File.Exists(program)) return Path.GetFullPath(program);
        if (program.IndexOfAny([Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar]) >= 0) return null;
        var extensions = OperatingSystem.IsWindows() && !Path.HasExtension(program)
            ? (Environment.GetEnvironmentVariable("PATHEXT") ?? ".EXE").Split(';', StringSplitOptions.RemoveEmptyEntries)
            : [""];
        foreach (var dir in (Environment.GetEnvironmentVariable("PATH") ?? "").Split(Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries))
            foreach (var ext in extensions)
            {
                var candidate = Path.Combine(dir.Trim(), program + ext);
                if (File.Exists(candidate)) return Path.GetFullPath(candidate);
            }
        return null;
    }

    /// <summary>A process's image path from the operating system; null when it cannot be read.</summary>
    public static string? ImagePath(int pid)
    {
        try
        {
            if (OperatingSystem.IsWindows())
            {
                using var handle = LiveNative.OpenProcess(LiveNative.PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
                if (handle.IsInvalid) return null;
                var buffer = new char[32768];
                uint size = (uint)buffer.Length;
                return LiveNative.QueryFullProcessImageName(handle, 0, buffer, ref size) ? new string(buffer, 0, (int)size) : null;
            }
            if (OperatingSystem.IsLinux())
                return new FileInfo($"/proc/{pid}/exe").ResolveLinkTarget(returnFinalTarget: false)?.FullName;
            using var p = Process.GetProcessById(pid);
            return p.MainModule?.FileName;
        }
        catch (Exception e) when (e is ArgumentException or InvalidOperationException or IOException or UnauthorizedAccessException or System.ComponentModel.Win32Exception)
        {
            return null;
        }
    }

    private static ToolError Outside(string message, IReadOnlyList<string> allowed) =>
        new(ErrorCode.Unsupported, message,
            $"sessions may open programs in: {string.Join(", ", allowed)}; add the program or its folder with {ServerOptions.LiveAllowOption} when the server starts");
}
