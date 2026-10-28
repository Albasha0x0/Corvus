using System.Runtime.InteropServices;

namespace Corvus.Core;

/// <summary>Checks on user-supplied input paths, and path equality as the host file system defines it.</summary>
public static class InputFiles
{
    /// <summary>Case-insensitive on Windows and macOS (their default file systems), case-sensitive elsewhere.</summary>
    public static readonly StringComparison PathComparison =
        OperatingSystem.IsWindows() || OperatingSystem.IsMacOS() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;

    public static readonly StringComparer PathComparer = StringComparer.FromComparison(PathComparison);

    public static bool SamePath(string? a, string? b) => string.Equals(a, b, PathComparison);

    /// <summary>Longest name NTFS, ext4 and APFS all take, checked in characters.</summary>
    public const int MaxNameLength = 255;

    /// <summary>What to pass instead of a path <see cref="PathProblem"/> rejects: a shorter one, or one without invalid characters.</summary>
    public static string PathHint(string path) =>
        path.Split('\\', '/').Any(n => n.Length > MaxNameLength) ? "Pass a shorter path." : "Pass an absolute path without invalid characters.";

    /// <summary>Why the host would reject <paramref name="path"/> as a file name, without touching the file system; null when none applies.</summary>
    /// <remarks>A colon past the drive is refused, so NTFS alternate data streams are too; empty input is the caller's to check.</remarks>
    public static string? PathProblem(string path)
    {
        if (path.Any(char.IsControl)) return "it contains a control character";
        var rest = path;
        if (OperatingSystem.IsWindows())
        {
            // The extended-length and device prefixes hold '?' and '.' as syntax, not as names.
            foreach (var prefix in new[] { @"\\?\UNC\", @"\\?\", @"\\.\" })
                if (rest.StartsWith(prefix, StringComparison.OrdinalIgnoreCase)) { rest = rest[prefix.Length..]; break; }
            if (rest.Length >= 2 && rest[1] == ':' && char.IsAsciiLetter(rest[0])) rest = rest[2..];
            if (rest.IndexOfAny(['<', '>', '"', '|', '?', '*', ':']) is >= 0 and var at)
                return $"'{rest[at]}' is not allowed in a Windows file name";
        }
        if (rest.Split(['\\', '/']).FirstOrDefault(n => n.Length > MaxNameLength) is { } name)
            return $"a name in it is {name.Length} characters long; the limit is {MaxNameLength}";
        return null;
    }

    /// <summary>Network paths in call arguments (<see cref="ServerOptions.AllowRemotePathsOption"/>); off by default and under CORVUS_OFFLINE.</summary>
    public static bool AllowRemote { get; set; }

    /// <summary>Why <paramref name="full"/>, a full path, is not on this machine ("a network path", "a device path"); null for a local path.</summary>
    /// <remarks>Reads drive types and link targets only; nothing on the path is opened. A local link to a remote target is remote.</remarks>
    public static string? RemoteProblem(string full, bool allowRemote) => OperatingSystem.IsWindows() ? WindowsRemoteProblem(full, allowRemote, 0) : null;

    private static string? WindowsRemoteProblem(string full, bool allowRemote, int depth)
    {
        const string Network = "a network path", Device = "a device path";
        var p = full.Replace('/', '\\');
        if (p.StartsWith(@"\\?\", StringComparison.Ordinal) && p.Length >= 7 && char.IsAsciiLetter(p[4]) && p[5] == ':' && p[6] == '\\') p = p[4..];
        else if (p.StartsWith(@"\\?\UNC\", StringComparison.OrdinalIgnoreCase)) return allowRemote ? null : Network;
        // A mounted volume is local; GLOBALROOT, pipes and other device names are not files.
        else if (p.StartsWith(@"\\?\Volume{", StringComparison.OrdinalIgnoreCase)) return null;
        else if (p.StartsWith(@"\\?\", StringComparison.Ordinal) || p.StartsWith(@"\\.\", StringComparison.Ordinal)) return Device;
        else if (p.StartsWith(@"\\", StringComparison.Ordinal)) return allowRemote ? null : Network;
        if (p.Length < 3 || !char.IsAsciiLetter(p[0]) || p[1] != ':' || p[2] != '\\') return Device;
        var type = new DriveInfo(p[..1]).DriveType;
        if (type == DriveType.Network) return allowRemote ? null : Network;
        if (type == DriveType.Unknown) return Device;
        // A link anywhere on the path is read, not followed, and its target checked in turn.
        if (depth >= 32) return "a path with too many links";
        var segments = p[3..].Split('\\', StringSplitOptions.RemoveEmptyEntries);
        var current = p[..3];
        for (int i = 0; i < segments.Length; i++)
        {
            current = Path.Combine(current, segments[i]);
            FileAttributes attributes;
            try { attributes = File.GetAttributes(current); }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { return null; }
            if ((attributes & FileAttributes.ReparsePoint) == 0) continue;
            string? target;
            try
            {
                target = (attributes & FileAttributes.Directory) != 0 ? new DirectoryInfo(current).LinkTarget : new FileInfo(current).LinkTarget;
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { return null; }
            // Other reparse points (cloud files, deduplication) keep their data on this volume.
            if (target == null) continue;
            if (target.StartsWith(@"\??\", StringComparison.Ordinal)) target = @"\\?\" + target[4..];
            var resolved = Path.GetFullPath(target, Path.GetDirectoryName(current)!);
            return WindowsRemoteProblem(Path.Combine([resolved, .. segments[(i + 1)..]]), allowRemote, depth + 1);
        }
        return null;
    }

    /// <summary>Throws invalid_argument naming <paramref name="shown"/> when <paramref name="full"/> is not on this machine; network paths pass with <see cref="AllowRemote"/> unless <paramref name="named"/> (a path found inside a file).</summary>
    public static void RequireLocal(string full, string shown, bool named = false)
    {
        if (RemoteProblem(full, AllowRemote && !named) is not { } problem) return;
        var next = problem == "a network path" && !named
            ? $"copy it to a local drive, or start the server with {ServerOptions.AllowRemotePathsOption}"
            : "pass the path of a local file";
        throw new ToolError(ErrorCode.InvalidArgument, $"{shown} is {problem}; only files on this machine are opened.", next) { Details = new { path = full, problem } };
    }

    /// <summary>The full path of a regular file, symlinks followed; directories, FIFOs, sockets and devices are refused, since reading a FIFO blocks until a writer appears.</summary>
    public static string RequireRegularFile(string path, string what = "file")
    {
        if (string.IsNullOrWhiteSpace(path)) throw new ToolError(ErrorCode.InvalidArgument, $"invalid path '{path}': the {what} path is empty.");
        if (PathProblem(path) is { } problem) throw new ToolError(ErrorCode.InvalidArgument, $"invalid {what} path: {problem}.", PathHint(path));
        string full;
        try { full = Path.GetFullPath(path); }
        catch (PathTooLongException) { throw new ToolError(ErrorCode.InvalidArgument, "a path is too long.", "Pass a shorter path."); }
        catch (Exception ex) when (ex is ArgumentException or NotSupportedException)
        {
            throw new ToolError(ErrorCode.InvalidArgument, $"invalid path '{path}': {ex.Message}");
        }
        RequireLocal(full, full);
        if (Directory.Exists(full)) throw new ToolError(ErrorCode.InvalidArgument, $"{full} is a directory; pass a {what}.");
        if (OperatingSystem.IsWindows() && full.StartsWith(@"\\.\", StringComparison.Ordinal))
            throw NotRegular(full, "a device", what);
        // Callers report a missing file in their own words.
        if (!File.Exists(full)) return full;
        if (!OperatingSystem.IsWindows() && UnixFileType(full) is { } kind) throw NotRegular(full, kind, what);
        return full;
    }

    private static ToolError NotRegular(string full, string kind, string what) =>
        new(ErrorCode.InvalidArgument, $"{full} is {kind}, not a regular {what}; reading it could block indefinitely.", "pass the path of a regular file");

    /// <summary>False for a FIFO, socket or device, which a probe must not open.</summary>
    public static bool IsRegularOrUnknown(string path) => OperatingSystem.IsWindows() || UnixFileType(path) == null;

    /// <summary>The kind of a non-regular file, or null for a regular one or when the type cannot be read.</summary>
    private static string? UnixFileType(string full)
    {
        try
        {
            if (SystemNativeStat(full, out var status) != 0) return null;
            return (status.Mode & 0xF000) switch
            {
                0x1000 => "a FIFO (named pipe)",
                0x2000 => "a character device",
                0x6000 => "a block device",
                0xC000 => "a socket",
                _ => null,
            };
        }
        // Not every host exposes the runtime's native shim (e.g. statically linked builds): no check then.
        catch (Exception ex) when (ex is DllNotFoundException or EntryPointNotFoundException) { return null; }
    }

    /// <summary>The leading fields of the runtime's own platform-neutral stat record; the padding covers the rest.</summary>
    [StructLayout(LayoutKind.Sequential, Size = 256)]
    private struct FileStatus
    {
        public int Flags;
        public int Mode;
    }

    // stat(2) through the .NET runtime's shim, whose FileStatus layout and S_IF* values are the same on every Unix.
    [DllImport("libSystem.Native", EntryPoint = "SystemNative_Stat")]
    private static extern int SystemNativeStat([MarshalAs(UnmanagedType.LPUTF8Str)] string path, out FileStatus status);
}
