using System.Security.Cryptography;
using System.Text.Json;
using Corvus.Core;
using Corvus.Native.Providers;

namespace Corvus.Services;

/// <summary>
/// A Ghidra archive (.gzf) as an input: the file it was made from loads as the native image (the bytes the archive keeps,
/// else the file of that name beside it), checked against the recorded SHA-256, and Ghidra opens the archive as its database.
/// A Ghidra project (.gpr) is read through a copy: one program of it is packed into an archive in the cache, which then
/// loads as above; the user's project is only read.
/// </summary>
internal static class PackedDatabaseInput
{
    public static bool Is(string path) => path.EndsWith(".gzf", StringComparison.OrdinalIgnoreCase) && File.Exists(path);

    public static bool IsProject(string path) => path.EndsWith(".gpr", StringComparison.OrdinalIgnoreCase) && File.Exists(path);

    /// <summary>
    /// Packs <paramref name="program"/> (null: the project's only program) of the project at <paramref name="path"/> from a copy
    /// made in the cache, then loads that archive. A project unchanged since (same files, sizes and write times) reuses the
    /// archive and so its database. Returns the image and the program's path in the project.
    /// </summary>
    public static async Task<(LoadedNative Native, string Program)> LoadProjectAsync(AssemblyWorkspace workspace, NativeEngineService? engines, string path,
        string? program, CancellationToken ct)
    {
        var gpr = InputFiles.RequireRegularFile(path, "Ghidra project");
        if (engines?.Ghidra is not { } ghidra)
            throw new ToolError(ErrorCode.ProviderUnavailable, "Reading a Ghidra project (.gpr) needs Ghidra, which this server has not set up.", "set CORVUS_GHIDRA_DIR, or load the original file");
        var name = Path.GetFileNameWithoutExtension(gpr);
        var parent = Path.GetDirectoryName(gpr)!;
        var rep = Path.Combine(parent, name + ".rep");
        if (!Directory.Exists(rep))
            throw new ToolError(ErrorCode.NotFound, $"{Path.GetFileName(gpr)} has no {name}.rep folder beside it: the project's data is missing.", "pass the .gpr of a complete project");
        var wanted = string.IsNullOrWhiteSpace(program) ? null : program.Trim();
        var dir = Path.Combine(ghidra.Directories.Root, "gpr", ProjectFingerprint(gpr, rep, wanted)[..16]);
        var gzf = Path.Combine(dir, "program.gzf");
        var chosen = Path.Combine(dir, "program.txt");
        if (!File.Exists(gzf) || !File.Exists(chosen))
        {
            Directory.CreateDirectory(dir);
            var copy = Path.Combine(dir, "copy");
            try
            {
                if (Directory.Exists(copy)) Directory.Delete(copy, recursive: true);
                File.Copy(gpr, Path.Combine(Directory.CreateDirectory(copy).FullName, name + ".gpr"));
                CopyTree(rep, Path.Combine(copy, name + ".rep"));
                var packed = Path.Combine(dir, "program.gzf.tmp");
                var at = await ghidra.PackProjectAsync(copy, name, wanted, packed, ct).ConfigureAwait(false);
                File.Move(packed, gzf, overwrite: true);
                File.WriteAllText(chosen, at);
            }
            finally
            {
                try { Directory.Delete(copy, recursive: true); } catch (IOException) { } catch (UnauthorizedAccessException) { }
            }
        }
        return (await LoadAsync(workspace, engines, gzf, ct, beside: parent).ConfigureAwait(false), File.ReadAllText(chosen));
    }

    /// <summary>The project's identity for reuse: its path, the program asked for, and each file's path, size and write time (lock files left out).</summary>
    private static string ProjectFingerprint(string gpr, string rep, string? program)
    {
        var sb = new System.Text.StringBuilder().Append(Path.GetFullPath(gpr)).Append('\n').Append(program).Append('\n');
        foreach (var f in Directory.EnumerateFiles(rep, "*", SearchOption.AllDirectories).Where(f => !IsLock(f)).Order(StringComparer.Ordinal).Prepend(gpr))
        {
            var info = new FileInfo(f);
            sb.Append(Path.GetRelativePath(rep, f)).Append(' ').Append(info.Length).Append(' ').Append(info.LastWriteTimeUtc.Ticks).Append('\n');
        }
        return Convert.ToHexStringLower(SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(sb.ToString())));
    }

    // a lock file belongs to the user's own open session; the copy must not inherit it
    private static bool IsLock(string file) =>
        Path.GetFileName(file) is var n && (n.EndsWith(".lock", StringComparison.OrdinalIgnoreCase) || n.EndsWith(".lock~", StringComparison.OrdinalIgnoreCase));

    private static void CopyTree(string from, string to)
    {
        Directory.CreateDirectory(to);
        foreach (var d in Directory.EnumerateDirectories(from, "*", SearchOption.AllDirectories))
            Directory.CreateDirectory(Path.Combine(to, Path.GetRelativePath(from, d)));
        foreach (var f in Directory.EnumerateFiles(from, "*", SearchOption.AllDirectories).Where(f => !IsLock(f)))
        {
            // shared read: the user's Ghidra may hold the project open
            using var source = new FileStream(f, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            using var target = File.Create(Path.Combine(to, Path.GetRelativePath(from, f)));
            source.CopyTo(target);
        }
    }

    public static async Task<LoadedNative> LoadAsync(AssemblyWorkspace workspace, NativeEngineService? engines, string path, CancellationToken ct, string? beside = null)
    {
        var gzf = InputFiles.RequireRegularFile(path, "Ghidra archive");
        if (engines?.Ghidra is not { } ghidra)
            throw new ToolError(ErrorCode.ProviderUnavailable, "Reading a Ghidra archive (.gzf) needs Ghidra, which this server has not set up.", "set CORVUS_GHIDRA_DIR, or load the original file");
        var sha = Hash(gzf);
        // unpacked once per archive content
        var dir = Path.Combine(ghidra.Directories.Root, "gzf", sha[..16]);
        var manifest = Path.Combine(dir, "original.json");
        Native.Providers.Ghidra.GhidraProvider.ArchiveOriginal original;
        if (File.Exists(manifest) && JsonSerializer.Deserialize<Native.Providers.Ghidra.GhidraProvider.ArchiveOriginal>(File.ReadAllText(manifest)) is { } known
            && (known.Path == null || File.Exists(known.Path)))
            original = known;
        else
        {
            original = await ghidra.OriginalOfAsync(gzf, dir, ct).ConfigureAwait(false);
            File.WriteAllText(manifest, JsonSerializer.Serialize(original));
            try { Directory.Delete(Path.Combine(dir, "scratch"), recursive: true); } catch (IOException) { } catch (UnauthorizedAccessException) { }
        }
        var file = original.Path ?? Path.Combine(beside ?? Path.GetDirectoryName(gzf)!, original.Name);
        if (!File.Exists(file))
            throw new ToolError(ErrorCode.NotFound, $"{Path.GetFileName(gzf)} keeps no copy of the file it was made from ({original.Name}).",
                $"place {original.Name}{(original.Sha256 != null ? $" (SHA-256 {original.Sha256})" : "")} beside the {(beside != null ? "project" : "archive")} and repeat");
        Verify(gzf, original, file);
        var (_, native) = workspace.LoadAny(file);
        if (native == null)
            throw new ToolError(ErrorCode.Unsupported, $"{original.Name}, the file {Path.GetFileName(gzf)} was made from, is not a native image.", "load_assembly the file itself");
        native.EngineDatabase = new PackedDatabase(gzf, sha);
        return native;
    }

    /// <summary>Refuses a file whose SHA-256 differs from the one the archive recorded: the analysis would not describe its bytes.</summary>
    internal static void Verify(string gzf, Native.Providers.Ghidra.GhidraProvider.ArchiveOriginal original, string file)
    {
        if (original.Sha256 is not { } recorded) return;
        var actual = Hash(file);
        if (!actual.Equals(recorded, StringComparison.OrdinalIgnoreCase))
            throw new ToolError(ErrorCode.Conflict, $"{Path.GetFileName(gzf)} was made from {original.Name} with SHA-256 {recorded}; {file} has {actual}.",
                "load the file the archive was made from, or load this file alone for a fresh analysis") { Details = new { reason = "hash_mismatch" } };
    }

    private static string Hash(string file)
    {
        using var stream = File.OpenRead(file);
        return Convert.ToHexStringLower(SHA256.HashData(stream));
    }
}
