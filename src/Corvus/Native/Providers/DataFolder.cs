namespace Corvus.Native.Providers;

/// <summary>
/// The per-user data folder: annotations, notes, the analysis and code-index caches, engine databases, symbols, Il2Cpp
/// caches, reference packs and relay state. <see cref="RootVariable"/> replaces it; by default it is &lt;LocalAppData&gt;/Corvus.
/// </summary>
public static class DataFolder
{
    public const string Name = "Corvus";
    public const string RootVariable = "CORVUS_DATA_DIR";

    public static string Root =>
        Environment.GetEnvironmentVariable(RootVariable) is { Length: > 0 } custom
            ? Path.GetFullPath(custom)
            : Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData, Environment.SpecialFolderOption.Create), Name);

    public static string Combine(params string[] parts) => Path.Combine([Root, .. parts]);

    // Migration only: the folder's name before the rename.
    public const string LegacyName = "NetDecompilerMcp";

    /// <summary>Entries of an install-script layout that shares the folder (Windows): the program, not data, so never moved.</summary>
    private static readonly string[] ProgramEntries = ["versions", "current"];

    /// <summary>What <see cref="Migrate"/> did: entries moved, and entries copied because a move failed (their originals kept).</summary>
    public sealed record Migration(string From, string To, IReadOnlyList<string> Moved, IReadOnlyList<string> Copied);

    /// <summary>
    /// Brings data from the legacy folder into <paramref name="to"/>: each entry the new folder lacks is moved, or copied when
    /// the move fails (a file in use, another volume) with the original kept. Entries already present are left alone, so
    /// running it again changes nothing; the legacy folder is removed once empty. Null when there was nothing to bring.
    /// </summary>
    public static Migration? Migrate(string from, string to)
    {
        if (!Directory.Exists(from) || SamePath(from, to)) return null;
        List<string> moved = [], copied = [];
        foreach (var entry in Directory.EnumerateFileSystemEntries(from).Order(StringComparer.Ordinal))
        {
            var name = Path.GetFileName(entry);
            if (ProgramEntries.Contains(name, StringComparer.OrdinalIgnoreCase) || name.StartsWith(".new-", StringComparison.Ordinal)) continue;
            var target = Path.Combine(to, name);
            if (Path.Exists(target)) continue;
            Directory.CreateDirectory(to);
            bool isDirectory = Directory.Exists(entry);
            try
            {
                if (isDirectory) Directory.Move(entry, target);
                else File.Move(entry, target);
                moved.Add(name);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                try
                {
                    if (isDirectory) CopyTree(entry, target);
                    else File.Copy(entry, target);
                    copied.Add(name);
                }
                catch (Exception copy) when (copy is IOException or UnauthorizedAccessException)
                {
                    // A partial copy would be taken as migrated on the next start.
                    try { if (isDirectory) Directory.Delete(target, recursive: true); else File.Delete(target); }
                    catch (Exception clean) when (clean is IOException or UnauthorizedAccessException) { }
                }
            }
        }
        try { if (!Directory.EnumerateFileSystemEntries(from).Any()) Directory.Delete(from); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
        return moved.Count + copied.Count == 0 ? null : new Migration(from, to, moved, copied);
    }

    /// <summary>Whether a start with <paramref name="args"/> runs the migration: not for commands that only read (version, status, dry runs).</summary>
    public static bool MigratesOnStart(IReadOnlyList<string> args) =>
        args is not [("version" or "--version" or "-v" or "status"), ..] && !args.Contains("--dry-run");

    /// <summary>
    /// The migration for the default folder, reported on <paramref name="log"/> when it brought anything. Not when
    /// <see cref="RootVariable"/> chooses the folder: that one is the user's, not a renamed default.
    /// </summary>
    public static Migration? MigrateDefault(TextWriter log)
    {
        if (Environment.GetEnvironmentVariable(RootVariable) is { Length: > 0 }) return null;
        var local = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        if (!Path.IsPathFullyQualified(local)) return null;
        Migration? done;
        try { done = Migrate(Path.Combine(local, LegacyName), Path.Combine(local, Name)); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            log.WriteLine($"Could not move data from {Path.Combine(local, LegacyName)}: {ex.Message}");
            return null;
        }
        if (done != null) log.WriteLine(Describe(done));
        return done;
    }

    public static string Describe(Migration m) =>
        $"Moved data from {m.From} to {m.To}: {string.Join(", ", m.Moved.Concat(m.Copied))}"
        + (m.Copied.Count > 0 ? $" ({string.Join(", ", m.Copied)} copied; the originals were in use and stay in {m.From})." : ".");

    private static bool SamePath(string a, string b) =>
        Path.TrimEndingDirectorySeparator(Path.GetFullPath(a)).Equals(Path.TrimEndingDirectorySeparator(Path.GetFullPath(b)),
            OperatingSystem.IsLinux() ? StringComparison.Ordinal : StringComparison.OrdinalIgnoreCase);

    private static void CopyTree(string source, string destination)
    {
        Directory.CreateDirectory(destination);
        foreach (var file in Directory.EnumerateFiles(source)) File.Copy(file, Path.Combine(destination, Path.GetFileName(file)));
        foreach (var dir in Directory.EnumerateDirectories(source)) CopyTree(dir, Path.Combine(destination, Path.GetFileName(dir)));
    }
}
