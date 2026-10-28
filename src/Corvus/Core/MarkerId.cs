using System.Security.Cryptography;
using System.Text;

namespace Corvus.Core;

/// <summary>
/// A random id kept in the data folder; unpack and export markers carry it, so
/// a marker another account or an older build wrote does not match.
/// </summary>
public static class MarkerId
{
    private const string FileName = "marker.id";

    private static readonly Lazy<string> Value = new(Load);

    /// <summary>
    /// This data folder's id: 32 lower-case hex digits, created on first use.
    /// </summary>
    public static string Current => Value.Value;

    private static string Load()
    {
        var path = Native.Providers.DataFolder.Combine(FileName);
        if (Read(path) is { } kept) return kept;
        var id = Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(16));
        // Another process may write its id first: that one is kept.
        try { SafeFile.WritePrivate(path, Encoding.ASCII.GetBytes(id + "\n"), overwrite: false); }
        catch (ToolError ex) when (ex.Code == ErrorCode.Conflict && Read(path) is { } first) { return first; }
        return id;
    }

    private static string? Read(string path)
    {
        try { return File.ReadAllText(path).Trim() is { Length: 32 } id && id.All(char.IsAsciiHexDigitLower) ? id : null; }
        catch (Exception ex) when (ex is FileNotFoundException or DirectoryNotFoundException) { return null; }
    }
}
