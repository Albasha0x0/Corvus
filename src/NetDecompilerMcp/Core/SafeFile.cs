using System.Text;

namespace NetDecompilerMcp.Core;

/// <summary>
/// The one way tools write output files: through a same-directory temp file and an atomic rename, never over an existing
/// file unless asked, never through a link at the target or under an output root, never to a Windows device name.
/// </summary>
public static class SafeFile
{
    private static readonly StringComparison PathComparison = OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;

    private static readonly HashSet<string> ReservedNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$",
        "COM0", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9", "COM\u00B9", "COM\u00B2", "COM\u00B3",
        "LPT0", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9", "LPT\u00B9", "LPT\u00B2", "LPT\u00B3",
    };

    /// <summary>True for a Windows device name, with or without an extension or trailing dots and spaces ("nul", "Con .txt", "COM1.tar.gz").</summary>
    public static bool IsReservedName(string segment)
    {
        var stem = segment.TrimEnd('.', ' ');
        int dot = stem.IndexOf('.');
        if (dot >= 0) stem = stem[..dot];
        return ReservedNames.Contains(stem.TrimEnd(' '));
    }

    /// <summary>Full path of an output file or directory; refuses device names and segments Windows would silently rename.</summary>
    public static string FullPath(string path)
    {
        if (string.IsNullOrWhiteSpace(path)) throw new ToolError(ErrorCode.InvalidArgument, "An output path is required.");
        if (OperatingSystem.IsWindows())
        {
            if (path.Replace('/', '\\').StartsWith(@"\\.\", StringComparison.Ordinal))
                throw new ToolError(ErrorCode.InvalidArgument, $"Refusing to write to a device path: {path}");
            CheckSegments(path, path);
        }
        var full = Path.GetFullPath(path);
        if (OperatingSystem.IsWindows()) CheckSegments(full[Path.GetPathRoot(full)!.Length..], path);
        return full;
    }

    private static void CheckSegments(string path, string shown)
    {
        foreach (var segment in path.Split(['\\', '/'], StringSplitOptions.RemoveEmptyEntries))
        {
            if (segment is "." or ".." || segment.EndsWith(':')) continue;
            if (IsReservedName(segment))
                throw new ToolError(ErrorCode.InvalidArgument, $"'{segment}' is a Windows device name and cannot be a file or directory name: {shown}");
            if (segment.EndsWith('.') || segment.EndsWith(' '))
                throw new ToolError(ErrorCode.InvalidArgument, $"'{segment}' ends with a dot or space, which Windows strips: {shown}");
        }
    }

    private static bool IsLink(string path)
    {
        try { return (File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0; }
        catch (Exception ex) when (ex is FileNotFoundException or DirectoryNotFoundException) { return false; }
    }

    private static void RefuseLink(string path)
    {
        if (IsLink(path)) throw new ToolError(ErrorCode.InvalidArgument, $"Refusing to write through a link or junction: {path}");
    }

    /// <summary>Full path of <paramref name="relative"/> under <paramref name="root"/>; throws if it escapes the root lexically or through a link.</summary>
    public static string UnderRoot(string root, string relative)
    {
        var fullRoot = FullPath(root).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar) + Path.DirectorySeparatorChar;
        if (OperatingSystem.IsWindows()) CheckSegments(relative, relative);
        var full = Path.GetFullPath(Path.Combine(fullRoot, relative));
        if (!full.StartsWith(fullRoot, PathComparison) || full.Length == fullRoot.Length)
            throw new ToolError(ErrorCode.InvalidArgument, $"Refusing to write outside {fullRoot}: {relative}");
        CheckNoLinksUnder(fullRoot, full);
        return full;
    }

    /// <summary>Refuses a link at <paramref name="full"/> or at any existing directory between the root (exclusive) and it.</summary>
    private static void CheckNoLinksUnder(string fullRoot, string full)
    {
        var rest = full[fullRoot.Length..].Split(Path.DirectorySeparatorChar, StringSplitOptions.RemoveEmptyEntries);
        var current = fullRoot;
        foreach (var segment in rest)
        {
            current = Path.Combine(current, segment);
            RefuseLink(current);
        }
    }

    /// <summary>
    /// Writes bytes atomically; an existing file is a Conflict unless <paramref name="overwrite"/>. <paramref name="beforeReplace"/>
    /// gets the flushed temp file before the rename and throws to abort, leaving the target untouched. Returns the full path.
    /// </summary>
    public static string WriteAllBytes(string path, ReadOnlySpan<byte> bytes, bool overwrite, Action<string>? beforeReplace = null) =>
        Write(FullPath(path), null, bytes, overwrite, beforeReplace);

    /// <summary>Writes UTF-8 text (no BOM) atomically; an existing file is a Conflict unless <paramref name="overwrite"/>.</summary>
    public static string WriteAllText(string path, string text, bool overwrite) => WriteAllBytes(path, Encoding.UTF8.GetBytes(text), overwrite);

    /// <summary>Writes under <paramref name="root"/>: the target and every directory below the root must not be links.</summary>
    public static string WriteUnderRoot(string root, string relative, ReadOnlySpan<byte> bytes, bool overwrite)
    {
        var full = UnderRoot(root, relative);
        return Write(full, FullPath(root), bytes, overwrite);
    }

    private static string Write(string full, string? root, ReadOnlySpan<byte> bytes, bool overwrite, Action<string>? beforeReplace = null)
    {
        var dir = Path.GetDirectoryName(full)!;
        Directory.CreateDirectory(dir);
        // Checked after creating the directories: an existing link on the way is refused, not followed.
        if (root != null) CheckNoLinksUnder(root.TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar, full);
        else RefuseLink(full);
        if (!overwrite && Path.Exists(full)) throw Exists(full);
        var temp = Path.Combine(dir, ".ndm-" + Guid.NewGuid().ToString("N") + ".tmp");
        try
        {
            using (var stream = new FileStream(temp, FileMode.CreateNew, FileAccess.Write, FileShare.None, 1 << 16))
            {
                stream.Write(bytes);
                stream.Flush(flushToDisk: true);
            }
            beforeReplace?.Invoke(temp);
            // Without overwrite the rename itself refuses an existing target, so a file created since the check is never replaced.
            try { File.Move(temp, full, overwrite); }
            catch (IOException) when (!overwrite && Path.Exists(full)) { throw Exists(full); }
        }
        finally
        {
            try { File.Delete(temp); }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
        }
        return full;
    }

    private static ToolError Exists(string full) =>
        new(ErrorCode.Conflict, $"{full} exists: pass overwrite=true to replace it.");
}
