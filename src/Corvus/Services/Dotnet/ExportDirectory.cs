using Corvus.Core;

namespace Corvus.Services;

/// <summary>
/// An export's output directory, written whole or not at all: the export fills a sibling staging folder, and
/// <see cref="Commit"/> moves it into place. Disposed without a commit, the staging folder is deleted. With overwrite, a
/// directory holding a previous export (its <see cref="Marker"/> lists every file) is replaced; any other content is refused.
/// </summary>
public sealed class ExportDirectory : IDisposable
{
    /// <summary>File an export leaves in its directory, listing the files it wrote (relative paths, one per line).</summary>
    public const string Marker = ".corvus-export";

    private bool _committed;

    private ExportDirectory(string final, string staging, bool replace)
    {
        Final = final;
        Staging = staging;
        Replace = replace;
    }

    /// <summary>Where the export ends up.</summary>
    public string Final { get; }

    /// <summary>Where the export writes until <see cref="Commit"/>; beside <see cref="Final"/>, so relative paths out of it match.</summary>
    public string Staging { get; }

    /// <summary>A previous export is replaced.</summary>
    public bool Replace { get; }

    /// <summary>Checks <paramref name="outputDirectory"/> and creates the staging folder; refuses a non-empty directory unless it is a previous export and overwrite is set.</summary>
    public static ExportDirectory Begin(string outputDirectory, bool overwrite)
    {
        var final = SafeFile.FullPath(outputDirectory).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        if (File.Exists(final))
            throw new ToolError(ErrorCode.Conflict, $"Output path is a file: {final}.", "pass a new or empty directory");
        bool replace = Directory.Exists(final) && Directory.EnumerateFileSystemEntries(final).Any();
        if (replace)
        {
            if (!overwrite)
                throw new ToolError(ErrorCode.Conflict, $"Output directory is not empty: {final}.",
                    "pass an empty or new directory, or overwrite=true to replace a previous export there") { Details = new { parameter = "overwrite" } };
            if (Foreign(final) is { } other)
                throw new ToolError(ErrorCode.Conflict, $"Output directory holds files that are not from a previous export ({other}): {final}.",
                    "pass an empty or new directory; overwrite replaces only a directory a previous export wrote");
        }
        var parent = Path.GetDirectoryName(final) ?? throw new ToolError(ErrorCode.InvalidArgument, $"Cannot export into a root directory: {final}.", "pass a folder below it");
        Directory.CreateDirectory(parent);
        var staging = Path.Combine(parent, $".{Path.GetFileName(final)}.corvus-{Guid.NewGuid().ToString("N")[..8]}");
        Directory.CreateDirectory(staging);
        return new ExportDirectory(final, staging, replace);
    }

    /// <summary>The first file in <paramref name="dir"/> no export marker lists, or null when every file is listed.</summary>
    private static string? Foreign(string dir)
    {
        var marker = Path.Combine(dir, Marker);
        if (!File.Exists(marker)) return "no " + Marker + " file";
        var listed = File.ReadAllLines(marker).Where(l => l.Length > 0).Select(l => l.Replace('\\', '/')).ToHashSet(StringComparer.OrdinalIgnoreCase);
        listed.Add(Marker);
        return Directory.EnumerateFiles(dir, "*", SearchOption.AllDirectories).Select(f => Path.GetRelativePath(dir, f).Replace('\\', '/'))
            .FirstOrDefault(f => !listed.Contains(f));
    }

    /// <summary>A path in the staging folder as it will be after the commit.</summary>
    public string ToFinal(string stagedPath) => Path.Combine(Final, Path.GetRelativePath(Staging, stagedPath));

    /// <summary>
    /// Writes the marker and moves the staging folder into place (replacing a previous export); returns the files, relative.
    /// <paramref name="patience"/> bounds the wait for a file another process holds open (default 2 s).
    /// </summary>
    public IReadOnlyList<string> Commit(TimeSpan? patience = null)
    {
        var files = Directory.EnumerateFiles(Staging, "*", SearchOption.AllDirectories).Select(f => Path.GetRelativePath(Staging, f).Replace('\\', '/'))
            .Order(StringComparer.Ordinal).ToList();
        File.WriteAllText(Path.Combine(Staging, Marker), string.Concat(files.Select(f => f + "\n")));
        if (Directory.Exists(Final))
        {
            // The check at Begin may be stale: something written since then is not deleted.
            if (Replace && Foreign(Final) is { } other)
                throw new ToolError(ErrorCode.Conflict, $"Output directory changed during the export ({other} appeared): {Final}.", "export again");
            SafeFile.WhenReleased(() => Directory.Delete(Final, recursive: true), patience);
        }
        SafeFile.WhenReleased(() => Directory.Move(Staging, Final), patience);
        _committed = true;
        return files;
    }

    public void Dispose()
    {
        if (_committed) return;
        try { if (Directory.Exists(Staging)) Directory.Delete(Staging, recursive: true); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
    }
}
