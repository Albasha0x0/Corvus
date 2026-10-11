using System.Security.Cryptography;

namespace Corvus.Core;

/// <summary>
/// Where save_assembly / save_native write, and whether that is the loaded original, decided by file identity (so a
/// link, junction, short name or hard link to the original is the original too).
/// </summary>
public static class SaveTarget
{
    public sealed record Plan(string Path, bool IsOriginal);

    /// <summary>
    /// Refuses an existing file without <paramref name="overwrite"/>, and an original whose bytes on disk are no longer
    /// the ones loaded (<paramref name="originalSha256"/>). A link to the original resolves to the original itself.
    /// </summary>
    public static Plan Resolve(string target, string originalPath, string originalSha256, bool overwrite)
    {
        var full = SafeFile.FullPath(target);
        bool isOriginal = FileIdentity.Same(full, originalPath);
        if (isOriginal) full = FileIdentity.Resolve(full);
        if (Path.Exists(full) && !overwrite)
            throw new ToolError(ErrorCode.Conflict, $"{full} already exists. Pass overwrite=true to replace it{(isOriginal ? " (the original is backed up to .bak)" : "")}.");
        if (isOriginal && File.Exists(full) && !string.Equals(Sha256(full), originalSha256, StringComparison.OrdinalIgnoreCase))
            throw new ToolError(ErrorCode.ChangedOnDisk, $"{full} changed on disk since load; replacing it would lose those changes. Nothing was written.",
                "save to another path, or export the edits, reload the file and apply them again");
        return new(full, isOriginal);
    }

    /// <summary>Writes the loaded original bytes to &lt;path&gt;.bak once; an existing backup is kept. Returns the backup path.</summary>
    public static string Backup(string path, ReadOnlySpan<byte> originalBytes)
    {
        var backup = path + ".bak";
        try { SafeFile.WriteAllBytes(backup, originalBytes, overwrite: false); }
        catch (ToolError ex) when (ex.Code == ErrorCode.Conflict) { }
        return backup;
    }

    private static string Sha256(string path)
    {
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete, 1 << 16);
        return Convert.ToHexStringLower(SHA256.HashData(stream));
    }
}
