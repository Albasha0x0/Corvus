using System.Security.Cryptography;

namespace NetDecompilerMcp.Native.Providers;

/// <summary>Writes a worker script embedded in this assembly to a per-user directory, named by its content hash.</summary>
public static class EmbeddedScript
{
    public static byte[] Read(string resourceName)
    {
        using var s = typeof(EmbeddedScript).Assembly.GetManifestResourceStream(resourceName)
            ?? throw new InvalidOperationException($"embedded resource {resourceName} is missing");
        using var ms = new MemoryStream();
        s.CopyTo(ms);
        return ms.ToArray();
    }

    /// <summary>
    /// Path of <c>directory/stem-hash.ext</c> holding the resource bytes; written atomically when missing or different.
    /// Content-hash names let several server versions share the directory.
    /// </summary>
    public static string Extract(string resourceName, string directory, string stem, string extension)
    {
        var bytes = Read(resourceName);
        var hash = Convert.ToHexStringLower(SHA256.HashData(bytes))[..16];
        Directory.CreateDirectory(directory);
        var path = Path.Combine(directory, $"{stem}-{hash}{extension}");
        try
        {
            if (File.Exists(path) && File.ReadAllBytes(path).AsSpan().SequenceEqual(bytes)) return path;
        }
        catch (IOException) { }
        var temp = path + "." + Guid.NewGuid().ToString("N")[..8] + ".tmp";
        File.WriteAllBytes(temp, bytes);
        try
        {
            File.Move(temp, path, overwrite: true);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            // Another process may hold the same content open; it is identical by name.
            File.Delete(temp);
            if (!File.Exists(path)) throw;
        }
        return path;
    }
}
