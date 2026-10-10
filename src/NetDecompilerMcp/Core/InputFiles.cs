using System.Runtime.InteropServices;

namespace NetDecompilerMcp.Core;

/// <summary>Checks on user-supplied input paths, and path equality as the host file system defines it.</summary>
public static class InputFiles
{
    /// <summary>Case-insensitive on Windows and macOS (their default file systems), case-sensitive elsewhere.</summary>
    public static readonly StringComparison PathComparison =
        OperatingSystem.IsWindows() || OperatingSystem.IsMacOS() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;

    public static readonly StringComparer PathComparer = StringComparer.FromComparison(PathComparison);

    public static bool SamePath(string? a, string? b) => string.Equals(a, b, PathComparison);

    /// <summary>
    /// The full path of an existing regular file, symlinks followed. Directories, FIFOs, sockets and devices are refused
    /// with a typed error: reading a FIFO or a terminal blocks until a writer appears.
    /// </summary>
    public static string RequireRegularFile(string path, string what = "file")
    {
        if (string.IsNullOrWhiteSpace(path)) throw new ToolError(ErrorCode.InvalidArgument, $"invalid path '{path}': the {what} path is empty.");
        string full;
        try { full = Path.GetFullPath(path); }
        catch (PathTooLongException) { throw new ToolError(ErrorCode.InvalidArgument, "a path is too long.", "Pass a shorter path."); }
        catch (Exception ex) when (ex is ArgumentException or NotSupportedException)
        {
            throw new ToolError(ErrorCode.InvalidArgument, $"invalid path '{path}': {ex.Message}");
        }
        if (Directory.Exists(full)) throw new ToolError(ErrorCode.InvalidArgument, $"{full} is a directory; pass a {what}.");
        if (OperatingSystem.IsWindows() && full.StartsWith(@"\\.\", StringComparison.Ordinal))
            throw NotRegular(full, "a device", what);
        if (!File.Exists(full)) return full; // callers report a missing file in their own words
        if (!OperatingSystem.IsWindows() && UnixFileType(full) is { } kind) throw NotRegular(full, kind, what);
        return full;
    }

    private static ToolError NotRegular(string full, string kind, string what) =>
        new(ErrorCode.InvalidArgument, $"{full} is {kind}, not a regular {what}; reading it could block indefinitely.", "pass the path of a regular file");

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
