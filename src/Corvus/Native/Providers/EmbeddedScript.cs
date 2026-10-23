using System.Security.Cryptography;

namespace Corvus.Native.Providers;

/// <summary>Writes a worker script embedded in this assembly to a per-user directory, named by its content hash.</summary>
public static class EmbeddedScript
{
    /// <summary>Names of the embedded resources starting with <paramref name="prefix"/>, ordinal order.</summary>
    public static IReadOnlyList<string> Names(string prefix) =>
        typeof(EmbeddedScript).Assembly.GetManifestResourceNames().Where(n => n.StartsWith(prefix, StringComparison.Ordinal)).Order(StringComparer.Ordinal).ToList();

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
        return Place(Path.Combine(directory, $"{stem}-{hash}{extension}"), bytes);
    }

    /// <summary>
    /// <paramref name="path"/>, a name that stands for its content, holding <paramref name="bytes"/>: written atomically
    /// when missing or different, so concurrent writers and readers never see a partial file. Throws when it cannot be written.
    /// </summary>
    public static string Place(string path, byte[] bytes)
    {
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
