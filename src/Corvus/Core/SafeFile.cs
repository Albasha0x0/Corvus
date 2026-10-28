using System.Text;

namespace Corvus.Core;

/// <summary>Atomic output file writes; never over an existing file unless asked, never through a link or to a device name.</summary>
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
        if (InputFiles.PathProblem(path) is { } problem) throw new ToolError(ErrorCode.InvalidArgument, $"invalid output path: {problem}.", InputFiles.PathHint(path));
        if (OperatingSystem.IsWindows())
        {
            if (path.Replace('/', '\\').StartsWith(@"\\.\", StringComparison.Ordinal))
                throw new ToolError(ErrorCode.InvalidArgument, $"Refusing to write to a device path: {path}");
            CheckSegments(path, path);
        }
        var full = Path.GetFullPath(path);
        InputFiles.RequireLocal(full, full);
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

    /// <summary>Writes bytes atomically and returns the full path; an existing file is a Conflict unless <paramref name="overwrite"/>.</summary>
    /// <remarks><paramref name="beforeReplace"/> gets the flushed temp file and throws to abort, leaving the target untouched.</remarks>
    public static string WriteAllBytes(string path, ReadOnlySpan<byte> bytes, bool overwrite, Action<string>? beforeReplace = null) =>
        Write(FullPath(path), null, bytes, overwrite, beforeReplace);

    /// <summary>Writes UTF-8 text (no BOM) atomically; an existing file is a Conflict unless <paramref name="overwrite"/>.</summary>
    public static string WriteAllText(string path, string text, bool overwrite) => WriteAllBytes(path, Encoding.UTF8.GetBytes(text), overwrite);

    /// <summary>Writes under <paramref name="root"/> with no links on the path; without <paramref name="flush"/> it saves ~15 ms per file on Windows.</summary>
    /// <remarks>Skip the flush only for files the source can give again, such as extracted ones.</remarks>
    public static string WriteUnderRoot(string root, string relative, ReadOnlySpan<byte> bytes, bool overwrite, bool flush = true)
    {
        var full = UnderRoot(root, relative);
        return Write(full, FullPath(root), bytes, overwrite, flush: flush);
    }

    private static string Write(string full, string? root, ReadOnlySpan<byte> bytes, bool overwrite, Action<string>? beforeReplace = null, bool flush = true)
    {
        var dir = Path.GetDirectoryName(full)!;
        Directory.CreateDirectory(dir);
        // Checked after creating the directories: an existing link on the way is refused, not followed.
        if (root != null) CheckNoLinksUnder(root.TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar, full);
        else RefuseLink(full);
        if (!overwrite && Path.Exists(full)) throw Exists(full);
        var temp = Path.Combine(dir, ".save-" + Guid.NewGuid().ToString("N") + ".tmp");
        try
        {
            using (var stream = new FileStream(temp, FileMode.CreateNew, FileAccess.Write, FileShare.None, 1 << 16))
            {
                stream.Write(bytes);
                stream.Flush(flushToDisk: flush);
            }
            beforeReplace?.Invoke(temp);
            // Without overwrite the placement refuses an existing target, so a file created since the check is never
            // replaced: a move on Windows, a hard link on Unix.
            try
            {
                if (overwrite || OperatingSystem.IsWindows() || !Posix.TryLink(temp, full)) File.Move(temp, full, overwrite);
            }
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

    /// <summary>Retries a move or delete for up to <paramref name="patience"/> (default 2 s) while a scanner holds the file; throws at once when <paramref name="lost"/>.</summary>
    /// <remarks><paramref name="lost"/> reports a lost race: another process put the target in place.</remarks>
    public static void WhenReleased(Action action, TimeSpan? patience = null, Func<bool>? lost = null)
    {
        var until = Environment.TickCount64 + (long)(patience ?? TimeSpan.FromSeconds(2)).TotalMilliseconds;
        for (int delay = 25; ; delay = Math.Min(delay * 2, 250))
        {
            try { action(); return; }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException && Environment.TickCount64 < until && lost?.Invoke() != true) { Thread.Sleep(delay); }
        }
    }
}
