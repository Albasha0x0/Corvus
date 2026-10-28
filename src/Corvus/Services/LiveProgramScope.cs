using System.Diagnostics;
using System.Globalization;
using System.Runtime.InteropServices;
using Corvus.Core;
using Corvus.Native.Live;

namespace Corvus.Services;

/// <summary>
/// The programs a session may open (--live-allow): a listed file or one under a listed folder, checked on the final image
/// path; the backend gets what was checked.
/// </summary>
public static class LiveProgramScope
{
    private static readonly StringComparison PathComparison = OperatingSystem.IsLinux() ? StringComparison.Ordinal : StringComparison.OrdinalIgnoreCase;

    /// <summary>The full path of the program to start, when it lies inside <paramref name="allowed"/>.</summary>
    public static string Spawn(string program, IReadOnlyList<string> allowed)
    {
        var path = FindProgram(program.Trim())
                   ?? throw new ToolError(ErrorCode.NotFound, $"'{program}' is not a program file.", "pass the full path of the program");
        var final = Canonical(path);
        if (!Contains(allowed, final))
            throw Outside($"{final} is outside the programs sessions may open.", allowed);
        return final;
    }

    /// <summary>The process id to attach to: the one named, or the single process of that name whose image lies inside <paramref name="allowed"/>.</summary>
    public static string Attach(string program, IReadOnlyList<string> allowed)
    {
        var text = program.Trim();
        if (int.TryParse(text, NumberStyles.None, CultureInfo.InvariantCulture, out int pid))
        {
            var image = ImagePath(pid) ?? throw Outside($"The image path of process {pid} cannot be read to check it against the allowed programs.", allowed);
            if (!Contains(allowed, image)) throw Outside($"Process {pid} ({image}) is outside the programs sessions may open.", allowed);
            return text;
        }
        if (text.IndexOfAny([Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar]) >= 0)
            throw new ToolError(ErrorCode.InvalidArgument, $"attach takes a process id or name, not a path: '{text}'.", "pass the process id or name; action=spawn starts a program by path");
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

    /// <summary>True when <paramref name="path"/> is a listed file or lies under a listed folder (both sides resolved to their final paths).</summary>
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

    /// <summary>The final path: junctions, symbolic links and short names resolved in every folder along it, not only the last.</summary>
    internal static string Canonical(string path) => InputFiles.FinalPath(path);

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

    /// <summary>
    /// Refuses this server's process and its ancestors, since a stop there would freeze the client; a name matches any of them.
    /// </summary>
    public static void RefuseOwnChain(string target)
    {
        var chain = OwnChain();
        var text = target.Trim();
        var name = text.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) ? text[..^4] : text;
        var hit = int.TryParse(text, NumberStyles.None, CultureInfo.InvariantCulture, out int pid)
            ? chain.FirstOrDefault(c => c.Pid == pid)
            : chain.FirstOrDefault(c => c.Name.Equals(name, StringComparison.OrdinalIgnoreCase));
        if (hit.Name == null) return;
        throw new ToolError(ErrorCode.Unsupported,
            $"Process {hit.Pid} ({hit.Name}) is {(hit.Pid == Environment.ProcessId ? "this server" : "one this server runs under")}: a session there could freeze the client driving it.",
            int.TryParse(text, NumberStyles.None, CultureInfo.InvariantCulture, out _) ? "attach to another process" : "pass the process id of the other process (live_session action=processes lists them)");
    }

    /// <summary>This process and its ancestors, nearest first; each parent must have started before its child, so a reused id ends the chain.</summary>
    internal static List<(int Pid, string Name)> OwnChain()
    {
        var chain = new List<(int, string)>();
        var parents = new Dictionary<int, (int Parent, string Name)>();
        if (OperatingSystem.IsWindows())
        {
            using var snapshot = LiveNative.CreateToolhelp32Snapshot(LiveNative.TH32CS_SNAPPROCESS, 0);
            if (snapshot.IsInvalid) return [(Environment.ProcessId, Path.GetFileNameWithoutExtension(Environment.ProcessPath ?? "corvus"))];
            var entry = new LiveNative.PROCESSENTRY32W { dwSize = (uint)Marshal.SizeOf<LiveNative.PROCESSENTRY32W>() };
            for (var ok = LiveNative.Process32First(snapshot, ref entry); ok; ok = LiveNative.Process32Next(snapshot, ref entry))
                parents[(int)entry.th32ProcessID] = ((int)entry.th32ParentProcessID, Path.GetFileNameWithoutExtension(entry.szExeFile));
        }
        else if (OperatingSystem.IsLinux())
        {
            foreach (var dir in Directory.EnumerateDirectories("/proc"))
                if (int.TryParse(Path.GetFileName(dir), out int id))
                    try
                    {
                        var stat = File.ReadAllText(Path.Combine(dir, "stat"));
                        int close = stat.LastIndexOf(')');
                        parents[id] = (int.Parse(stat[(close + 2)..].Split(' ')[1], CultureInfo.InvariantCulture), stat[(stat.IndexOf('(') + 1)..close]);
                    }
                    catch (Exception e) when (e is IOException or UnauthorizedAccessException or FormatException) { }
        }
        int pid = Environment.ProcessId;
        DateTime? childStart = null;
        while (pid > 0 && parents.TryGetValue(pid, out var p) && chain.Count < 64)
        {
            var start = StartTime(pid);
            if (childStart is { } c && start is { } s && s > c) break;
            chain.Add((pid, p.Name));
            if (p.Parent == pid) break;
            (pid, childStart) = (p.Parent, start ?? childStart);
        }
        if (chain.Count == 0) chain.Add((Environment.ProcessId, Path.GetFileNameWithoutExtension(Environment.ProcessPath ?? "corvus")));
        return chain;
    }

    private static DateTime? StartTime(int pid)
    {
        try
        {
            using var p = Process.GetProcessById(pid);
            return p.StartTime;
        }
        catch (Exception e) when (e is ArgumentException or InvalidOperationException or System.ComponentModel.Win32Exception or NotSupportedException) { return null; }
    }

    private static ToolError Outside(string message, IReadOnlyList<string> allowed) =>
        new(ErrorCode.Unsupported, message,
            $"sessions may open programs in: {string.Join(", ", allowed)}; add the program or its folder with {ServerOptions.LiveAllowOption} when the server starts");
}
