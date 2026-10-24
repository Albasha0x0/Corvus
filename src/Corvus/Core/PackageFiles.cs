using System.IO.Compression;
using System.Text.RegularExpressions;

namespace Corvus.Core;

/// <summary>Package files recognised by extension: Android and iOS application packages, and zips that hold a build.</summary>
public static partial class PackageFiles
{
    private static readonly string[] AppPackageExtensions = [".apk", ".xapk", ".apks", ".apkm", ".aab", ".ipa"];
    private static readonly string[] SplitSetExtensions = [".xapk", ".apks", ".apkm"];

    /// <summary>True for an existing Android or iOS application package; false for any other or missing path.</summary>
    public static bool IsAppPackage(string path) =>
        AppPackageExtensions.Contains(Path.GetExtension(path).ToLowerInvariant()) && File.Exists(path);

    /// <summary>True for an existing application package or zip, either of which can hold a whole Unity build.</summary>
    public static bool IsUnityPackage(string path) =>
        IsAppPackage(path) || Path.GetExtension(path).Equals(".zip", StringComparison.OrdinalIgnoreCase) && File.Exists(path);

    /// <summary>
    /// True for an application package or zip whose entry names hold a Unity data folder (assets/bin/Data/,
    /// Payload/*.app/Data/, or *_Data/ with globalgamemanagers, data.unity3d or mainData). A split set is true when it
    /// holds APKs, whose entries are read only on extraction. False for any other, missing or unreadable file.
    /// </summary>
    public static bool HoldsUnityData(string path)
    {
        if (!IsUnityPackage(path)) return false;
        bool split = SplitSetExtensions.Contains(Path.GetExtension(path).ToLowerInvariant());
        try
        {
            using var zip = ZipFile.OpenRead(path);
            return zip.Entries.Any(e => split ? e.FullName.EndsWith(".apk", StringComparison.OrdinalIgnoreCase) : UnityData().IsMatch(e.FullName));
        }
        catch (Exception e) when (e is InvalidDataException or IOException or UnauthorizedAccessException) { return false; }
    }

    [GeneratedRegex(@"^(?:(?:base/)?assets/bin/Data/.|Payload/[^/]+\.app/Data/.|(?:[^/]+/)*[^/]+_Data/(?:globalgamemanagers|data\.unity3d|mainData)$)", RegexOptions.CultureInvariant)]
    private static partial Regex UnityData();
}
