using System.Security.Cryptography;

namespace Corvus.Core;

/// <summary>Where save_assembly and save_native write, and whether that is the original by file identity, links included.</summary>
public static class SaveTarget
{
    public sealed record Plan(string Path, bool IsOriginal);

    /// <summary>The write plan; refuses the original without <paramref name="replaceOriginal"/>, or when its bytes changed on disk.</summary>
    /// <remarks>"Changed" means neither the loaded bytes nor this server's last save over it; <paramref name="overwrite"/> alone never replaces the original.
    /// Another existing file needs <paramref name="overwrite"/>; <paramref name="versioned"/> takes the first free &lt;stem&gt;.N&lt;ext&gt;.</remarks>
    public static Plan Resolve(string target, string originalPath, string originalSha256, bool overwrite, string? savedSha256 = null,
        bool replaceOriginal = false, bool versioned = false)
    {
        var full = SafeFile.FullPath(target);
        if (versioned) full = NextVersion(full);
        bool isOriginal = FileIdentity.Same(full, originalPath);
        if (isOriginal) full = FileIdentity.Resolve(full);
        if (isOriginal && File.Exists(full) && !replaceOriginal)
            throw new ToolError(ErrorCode.Conflict, $"{full} is the loaded original. Pass replaceOriginal=true to replace it (the server needs {ServerOptions.AllowReplaceOriginalOption}; the original is backed up to .bak).",
                "save to another path, or pass versioned=true to write the next numbered copy");
        if (!isOriginal && Path.Exists(full) && !overwrite)
            throw new ToolError(ErrorCode.Conflict, $"{full} already exists. Pass overwrite=true to replace it, or versioned=true to write the next numbered copy.",
                "pass overwrite=true, versioned=true or another outputPath");
        if (isOriginal && File.Exists(full) && Sha256(full) is var onDisk && !string.Equals(onDisk, originalSha256, StringComparison.OrdinalIgnoreCase)
            && !string.Equals(onDisk, savedSha256, StringComparison.OrdinalIgnoreCase))
            throw new ToolError(ErrorCode.ChangedOnDisk, $"{full} changed on disk since load; replacing it would lose those changes. Nothing was written.",
                "save to another path, or export the edits, reload the file and apply them again");
        return new(full, isOriginal);
    }

    /// <summary>replaceOriginal needs the server switch, so a client cannot grant it to itself in a call.</summary>
    public static void RequireReplaceAllowed(bool replaceOriginal, ServerOptions? options)
    {
        if (replaceOriginal && options?.AllowReplaceOriginal != true)
            throw new ToolError(ErrorCode.Unsupported, "Replacing the loaded file is off in this server. Nothing was written.",
                $"start the server with {ServerOptions.AllowReplaceOriginalOption} (or {ServerOptions.AllowReplaceOriginalVariable}=1), or pass versioned=true");
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
