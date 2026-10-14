using System.Security.Cryptography;
using System.Text.Json;
using Corvus.Core;
using Corvus.Native.Providers;

namespace Corvus.Services;

/// <summary>
/// A Ghidra archive (.gzf) as an input: the file it was made from loads as the native image (the bytes the archive keeps,
/// else the file of that name beside it), checked against the recorded SHA-256, and Ghidra opens the archive as its database.
/// </summary>
internal static class PackedDatabaseInput
{
    public static bool Is(string path) => path.EndsWith(".gzf", StringComparison.OrdinalIgnoreCase) && File.Exists(path);

    public static async Task<LoadedNative> LoadAsync(AssemblyWorkspace workspace, NativeEngineService? engines, string path, CancellationToken ct)
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
        var file = original.Path ?? Path.Combine(Path.GetDirectoryName(gzf)!, original.Name);
        if (!File.Exists(file))
            throw new ToolError(ErrorCode.NotFound, $"{Path.GetFileName(gzf)} keeps no copy of the file it was made from ({original.Name}).",
                $"place {original.Name}{(original.Sha256 != null ? $" (SHA-256 {original.Sha256})" : "")} beside the archive and repeat");
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
