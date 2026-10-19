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
    /// Refuses the original without <paramref name="replaceOriginal"/> (<paramref name="overwrite"/> alone never replaces it),
    /// another existing file without <paramref name="overwrite"/>, and an original whose bytes on disk are neither the ones
    /// loaded (<paramref name="originalSha256"/>) nor this server's last save over it (<paramref name="savedSha256"/>).
    /// <paramref name="versioned"/> writes the first free name &lt;stem&gt;.N&lt;ext&gt; instead. A link to the original resolves to the original itself.
    /// </summary>
    public static Plan Resolve(string target, string originalPath, string originalSha256, bool overwrite, string? savedSha256 = null,
        bool replaceOriginal = false, bool versioned = false)
    {
        var full = SafeFile.FullPath(target);
        if (versioned) full = NextVersion(full);
        bool isOriginal = FileIdentity.Same(full, originalPath);
        if (isOriginal) full = FileIdentity.Resolve(full);
        if (isOriginal && File.Exists(full) && !replaceOriginal)
            throw new ToolError(ErrorCode.Conflict, $"{full} is the loaded original. Pass replaceOriginal=true to replace it (the original is backed up to .bak).",
                "save to another path, or pass versioned=true to write the next numbered copy");
        if (!isOriginal && Path.Exists(full) && !overwrite)
            throw new ToolError(ErrorCode.Conflict, $"{full} already exists. Pass overwrite=true to replace it, or versioned=true to write the next numbered copy.");
        if (isOriginal && File.Exists(full) && Sha256(full) is var onDisk && !string.Equals(onDisk, originalSha256, StringComparison.OrdinalIgnoreCase)
            && !string.Equals(onDisk, savedSha256, StringComparison.OrdinalIgnoreCase))
            throw new ToolError(ErrorCode.ChangedOnDisk, $"{full} changed on disk since load; replacing it would lose those changes. Nothing was written.",
                "save to another path, or export the edits, reload the file and apply them again");
        return new(full, isOriginal);
    }

    /// <summary>&lt;stem&gt;.1&lt;ext&gt;, &lt;stem&gt;.2&lt;ext&gt;, ...: the first that does not exist.</summary>
    private static string NextVersion(string path)
    {
        var stem = Path.Combine(Path.GetDirectoryName(path)!, Path.GetFileNameWithoutExtension(path));
        var ext = Path.GetExtension(path);
        for (int n = 1; n <= 100_000; n++)
            if (!Path.Exists($"{stem}.{n}{ext}")) return $"{stem}.{n}{ext}";
        throw new ToolError(ErrorCode.Conflict, $"Every numbered copy of {path} up to {stem}.100000{ext} exists.", "save to another path");
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
