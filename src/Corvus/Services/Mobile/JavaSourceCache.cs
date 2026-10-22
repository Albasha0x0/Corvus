using System.Security.Cryptography;
using System.Text;
using Corvus.Native.Providers;

namespace Corvus.Services.Mobile;

/// <summary>
/// Java decompiler output kept on disk by the input's SHA-256, the decompiler build and the request, so a later server answers
/// without starting a JVM. The content hash of a path is remembered by its length and write time: a warm read hashes nothing.
/// </summary>
public sealed class JavaSourceCache(string root)
{
    public const string FolderVariable = "CORVUS_JAVA_CACHE";
    private const int Format = 1; // bump when the decompile_java text around the decompiler's output changes

    public string Root { get; } = root;

    private int _inputsHashed;

    /// <summary>Input files hashed by this instance; a warm read leaves it unchanged.</summary>
    internal int InputsHashed => Volatile.Read(ref _inputsHashed);

    /// <summary>The configured folder: <see cref="FolderVariable"/> (<c>off</c> disables it), else <c>java-sources</c> in the data folder.</summary>
    public static JavaSourceCache? Default() =>
        Environment.GetEnvironmentVariable(FolderVariable) is { Length: > 0 } v
            ? v.Equals("off", StringComparison.OrdinalIgnoreCase) ? null : new JavaSourceCache(Path.GetFullPath(v))
            : new JavaSourceCache(DataFolder.Combine("java-sources"));

    /// <summary>The identity of a decompiler build: its file, length and write time; null when it is not found.</summary>
    public static string? Engine(ExternalTool tool) =>
        ExternalTools.Locate(tool) is { } at && new FileInfo(at.Path) is { Exists: true } f ? $"{tool.Id}|{f.FullName}|{f.Length}|{f.LastWriteTimeUtc.Ticks}" : null;

    /// <summary>The entry file of a request; null when the input cannot be read.</summary>
    public string? Entry(string input, string engine, string request, string? mapping)
    {
        if (ContentHash(input) is not { } content) return null;
        var mapStamp = mapping is { Length: > 0 } ? Stamp(mapping) ?? "missing" : "";
        return Path.Combine(Root, content[..2], content, Hash($"{Format}|{engine}|{mapStamp}|{request}")[..32] + ".txt");
    }

    public static string? Read(string? entry)
    {
        if (entry == null) return null;
        try { return File.ReadAllText(entry, Encoding.UTF8); }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException) { return null; }
    }

    /// <summary>Writes through a temporary file, so a reader never sees half an entry; a failed write leaves the cache as it was.</summary>
    public static void Write(string? entry, string text)
    {
        if (entry == null) return;
        var temp = $"{entry}.{Environment.ProcessId}.{Guid.NewGuid():N}.tmp";
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(entry)!);
            File.WriteAllText(temp, text, new UTF8Encoding(false));
            File.Move(temp, entry, overwrite: true);
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            try { File.Delete(temp); } catch (Exception d) when (d is IOException or UnauthorizedAccessException) { }
        }
    }

    /// <summary>The SHA-256 of a file's bytes, remembered on disk under its path, length and write time.</summary>
    internal string? ContentHash(string path)
    {
        if (Stamp(path) is not { } stamp) return null;
        var memo = Path.Combine(Root, "inputs", Hash(stamp)[..32]);
        if (Read(memo) is { Length: 64 } known) return known;
        string content;
        try
        {
            using var stream = File.OpenRead(path);
            content = Convert.ToHexStringLower(SHA256.HashData(stream));
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException) { return null; }
        Interlocked.Increment(ref _inputsHashed);
        Write(memo, content);
        return content;
    }

    private static string? Stamp(string path)
    {
        try
        {
            var f = new FileInfo(path);
            return f.Exists && Corvus.Core.InputFiles.IsRegularOrUnknown(f.FullName) ? $"{f.FullName}|{f.Length}|{f.LastWriteTimeUtc.Ticks}" : null;
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException) { return null; }
    }

    private static string Hash(string text) => Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(text)));
}
