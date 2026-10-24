using System.IO.Compression;
using System.Security.Cryptography;
using System.Text.Json;
using Corvus.Core;

namespace Corvus.Services;

/// <summary>
/// Il2Cpp builds inside app packages: .apk, split sets (.xapk / .apks / .apkm: a zip of a base APK and config.&lt;abi&gt;.apk
/// splits), .aab (base/ module) and .ipa (Payload/*.app). Only what the tools need is extracted (the native libraries of
/// one ABI, global-metadata.dat and the Unity version files) into a per-user cache keyed by the package's SHA-256, laid out as
/// the extracted package would be, so <see cref="Il2CppBuildFiles.Find"/> reads it.
/// </summary>
public static partial class Il2CppPackages
{
    public const string FolderName = "packages";
    internal const string MarkerFileName = "package.json";
    internal const int MaxPackages = 8;
    /// <summary>The Unity version is in the first bytes of data.unity3d; the rest (often hundreds of MB) is not needed.</summary>
    private const int VersionHeaderBytes = 1 << 16;
    private const long MaxEntryBytes = 2L << 30;
    private const int ExtractFormat = 4; // bump when what is extracted changes

    private static readonly string[] Extensions = [".apk", ".xapk", ".apks", ".apkm", ".aab", ".ipa"];

    public sealed record Marker(string Package, string Sha256, string? Slice, DateTime Created);

    public static bool IsPackage(string path) => Extensions.Contains(Path.GetExtension(path).ToLowerInvariant()) && File.Exists(path);

    /// <summary>A package unity_overview reads in place: the Il2Cpp packages, plus zipped desktop titles.</summary>
    public static bool IsUnityPackage(string path) => IsPackage(path) || Path.GetExtension(path).Equals(".zip", StringComparison.OrdinalIgnoreCase) && File.Exists(path);

    /// <summary>
    /// The extracted root of the Il2Cpp build in <paramref name="package"/>, or null when the package holds none
    /// (no global-metadata.dat). <paramref name="slice"/> picks the Android ABI. <paramref name="anyBackend"/> (unity_overview):
    /// a Mono build's assemblies and libraries too, and zipped desktop titles.
    /// </summary>
    public static string? Extract(string package, string? slice, string? cacheRoot = null, CancellationToken ct = default, bool anyBackend = false)
    {
        var full = Path.GetFullPath(package);
        string sha;
        try
        {
            using var stream = File.OpenRead(full);
            sha = Convert.ToHexStringLower(SHA256.HashData(stream));
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { throw new ToolError(ErrorCode.IoError, $"Cannot read {full}: {ex.Message}"); }
        var abi = slice != null ? Il2CppBuildFiles.AndroidAbi(slice) : null;
        var root = Path.Combine(Path.GetFullPath(cacheRoot ?? Il2CppRawLoader.DefaultRoot), FolderName);
        var dir = Path.Combine(root, $"{sha[..16]}-{ExtractFormat}" + (abi != null ? "-" + abi : "") + (anyBackend ? "-u" : ""));
        if (File.Exists(Path.Combine(dir, MarkerFileName)))
        {
            Touch(dir);
            return Directory.Exists(Path.Combine(dir, "app")) ? Path.Combine(dir, "app") : null;
        }
        var staging = dir + ".tmp-" + Environment.ProcessId;
        TryDelete(staging);
        try
        {
            var app = Path.Combine(staging, "app");
            Directory.CreateDirectory(app);
            bool found;
            var splits = Path.Combine(staging, "splits");
            using (var zip = OpenZip(full))
                found = ExtractApp(zip, IsAppBundle(zip) ? ".aab" : Path.GetExtension(full).ToLowerInvariant(), app, splits, abi, ct, anyBackend);
            TryDelete(splits);
            if (!found) Directory.Delete(app, true);
            File.WriteAllText(Path.Combine(staging, MarkerFileName), JsonSerializer.Serialize(new Marker(full, sha, abi, DateTime.UtcNow)));
            TryDelete(dir);
            SafeFile.WhenReleased(() => Directory.Move(staging, dir));
            Trim(root, dir);
            return found ? Path.Combine(dir, "app") : null;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            TryDelete(staging);
            throw new ToolError(ErrorCode.IoError, $"Cannot extract the Il2Cpp build from {full} under {root}: {ex.Message}", $"set {Il2CppRawLoader.RootVariable} to a writable folder");
        }
        catch
        {
            TryDelete(staging);
            throw;
        }
    }

    /// <summary>An Android App Bundle by its content (BundleConfig.pb, base/manifest/), whatever the file is called.</summary>
    private static bool IsAppBundle(ZipArchive zip) =>
        zip.GetEntry("BundleConfig.pb") != null || zip.Entries.Any(e => e.FullName.StartsWith("base/manifest/", StringComparison.Ordinal));

    private static ZipArchive OpenZip(string path)
    {
        try { return ZipFile.OpenRead(path); }
        catch (InvalidDataException ex) { throw new ToolError(ErrorCode.MalformedInput, $"{path} is not a readable zip package: {ex.Message}"); }
    }

    /// <summary>A file of the app as the package lays it out: its path inside the app, and how to open it.</summary>
    private sealed record Item(string Path, ZipArchiveEntry Entry);

    private static bool ExtractApp(ZipArchive zip, string extension, string destination, string splits, string? abi, CancellationToken ct, bool anyBackend = false)
    {
        var items = new List<Item>();
        var nested = new List<ZipArchive>();
        try
        {
            if (extension is ".xapk" or ".apks" or ".apkm")
            {
                // Split set: the base APK holds the metadata, config.<abi>.apk the native libraries.
                foreach (var e in zip.Entries.Where(e => e.FullName.EndsWith(".apk", StringComparison.OrdinalIgnoreCase) && e.Length < MaxEntryBytes))
                {
                    ct.ThrowIfCancellationRequested();
                    Directory.CreateDirectory(splits);
                    var copy = Path.Combine(splits, $"{nested.Count}.apk");
                    e.ExtractToFile(copy, overwrite: true);
                    ZipArchive inner;
                    try { inner = ZipFile.OpenRead(copy); }
                    catch (InvalidDataException) { continue; }
                    nested.Add(inner);
                    items.AddRange(inner.Entries.Select(x => new Item(x.FullName, x)));
                }
            }
            items.AddRange(zip.Entries.Select(e => new Item(
                extension == ".aab" && e.FullName.StartsWith("base/", StringComparison.Ordinal) ? e.FullName["base/".Length..]
                : extension == ".ipa" && e.FullName.StartsWith("Payload/", StringComparison.Ordinal) ? e.FullName["Payload/".Length..] : e.FullName, e)));

            var wanted = extension switch
            {
                ".ipa" => AppleFiles(items),
                ".zip" => DesktopFiles(items),
                _ => AndroidFiles(items, abi) is { Count: > 0 } il2cpp ? il2cpp : anyBackend ? MonoAndroidFiles(items) : [],
            };
            if (wanted.Count == 0) return false;
            foreach (var (item, limit) in wanted)
            {
                ct.ThrowIfCancellationRequested();
                if (item.Entry.Length > MaxEntryBytes)
                    throw new ToolError(ErrorCode.LimitExceeded, $"{item.Path} is {item.Entry.Length} bytes; entries up to {MaxEntryBytes} bytes are extracted");
                var target = Path.GetFullPath(Path.Combine(destination, item.Path.Replace('/', Path.DirectorySeparatorChar)));
                if (!target.StartsWith(destination + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase)) continue; // a path escaping the folder
                Directory.CreateDirectory(Path.GetDirectoryName(target)!);
                using var source = item.Entry.Open();
                using var output = File.Create(target);
                if (limit > 0)
                {
                    var buffer = new byte[limit];
                    output.Write(buffer, 0, source.ReadAtLeast(buffer, limit, throwOnEndOfStream: false));
                }
                else source.CopyTo(output);
            }
            return true;
        }
        finally
        {
            foreach (var n in nested) n.Dispose();
        }
    }

    /// <summary>Android: lib/&lt;abi&gt;/*.so of one ABI (the one with libil2cpp.so), the metadata and the version files under assets/bin/Data.</summary>
    private static List<(Item, int)> AndroidFiles(List<Item> items, string? abi)
    {
        const string data = "assets/bin/Data/";
        var metadata = items.FirstOrDefault(i => i.Path == data + "Managed/Metadata/" + Il2CppBuildFiles.MetadataFileName);
        if (metadata == null) return [];
        var libraries = items.Where(i => i.Path.StartsWith("lib/", StringComparison.Ordinal) && i.Path.EndsWith("/libil2cpp.so", StringComparison.Ordinal) && i.Path.Count(c => c == '/') == 2)
            .GroupBy(i => i.Path.Split('/')[1]).ToDictionary(g => g.Key, g => g.First());
        var chosen = abi != null ? libraries.GetValueOrDefault(abi)
            : Il2CppBuildFiles.AndroidAbis.Select(libraries.GetValueOrDefault).FirstOrDefault(i => i != null) ?? libraries.Values.FirstOrDefault();
        if (abi != null && chosen == null)
            throw new ToolError(ErrorCode.NotFound, $"The package has no lib/{abi}/libil2cpp.so" + (libraries.Count > 0 ? $"; ABIs: {string.Join(", ", libraries.Keys)}" : "") + ".",
                libraries.Count > 0 ? $"pass slice={libraries.Keys.First()}" : "the package holds no Il2Cpp library");
        var wanted = new List<(Item, int)> { (metadata, 0) };
        if (chosen != null)
        {
            // The ABI's other libraries too: P/Invoke declarations of the dummy assemblies bind to them.
            var folder = chosen.Path[..(chosen.Path.LastIndexOf('/') + 1)];
            wanted.AddRange(items.Where(i => i.Path.StartsWith(folder, StringComparison.Ordinal) && i.Path.EndsWith(".so", StringComparison.Ordinal) && i.Path.LastIndexOf('/') == folder.Length - 1)
                .GroupBy(i => i.Path).Select(g => (g.First(), 0)));
        }
        Version(items, data, wanted);
        return wanted;
    }

    /// <summary>Android Mono: the assemblies under assets/bin/Data/Managed, libunity and libmono of one ABI, and the version files.</summary>
    private static List<(Item, int)> MonoAndroidFiles(List<Item> items)
    {
        const string data = "assets/bin/Data/";
        var wanted = items.Where(i => i.Path.StartsWith(data + "Managed/", StringComparison.Ordinal) && i.Path.EndsWith(".dll", StringComparison.Ordinal)
                                      && i.Path.Count(c => c == '/') == 4).Select(i => (i, 0)).ToList();
        if (wanted.Count == 0) return [];
        var abis = items.Where(i => i.Path.StartsWith("lib/", StringComparison.Ordinal) && i.Path.EndsWith("/libunity.so", StringComparison.Ordinal)).Select(i => i.Path.Split('/')[1]).ToHashSet();
        if ((Il2CppBuildFiles.AndroidAbis.FirstOrDefault(abis.Contains) ?? abis.FirstOrDefault()) is { } abi)
            wanted.AddRange(items.Where(i => i.Path.StartsWith($"lib/{abi}/lib", StringComparison.Ordinal) && (i.Path.EndsWith("/libunity.so", StringComparison.Ordinal)
                || i.Path.Contains("/libmono", StringComparison.Ordinal))).Select(i => (i, 0)));
        Version(items, data, wanted);
        return wanted;
    }

    /// <summary>
    /// A zipped Windows or Linux title: the folder holding &lt;Product&gt;_Data becomes the build root (its paths shortened to
    /// that), with the executable, UnityPlayer, GameAssembly, the managed assemblies or the Il2Cpp metadata, and the version files.
    /// </summary>
    private static List<(Item, int)> DesktopFiles(List<Item> items)
    {
        var markers = items.Select(i => (i, m: DataMarker().Match(i.Path))).Where(x => x.m.Success).OrderBy(x => x.i.Path.Length).ToList();
        if (markers.Count == 0) return [];
        var top = markers[0].m.Groups[1].Value;
        var data = top + markers[0].m.Groups[2].Value + "_Data/";
        var under = items.Where(i => i.Path.StartsWith(top, StringComparison.Ordinal)).Select(i => new Item(i.Path[top.Length..], i.Entry)).ToList();
        var dataRel = data[top.Length..];
        bool Root(Item i) => !i.Path.Contains('/');
        var wanted = under.Where(i => Root(i) && (i.Path.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) || i.Path is "UnityPlayer.dll" or "UnityPlayer.so"
                || i.Path is "GameAssembly.dll" or "GameAssembly.so" || i.Path == markers[0].m.Groups[2].Value + ".x86_64"))
            .Concat(under.Where(i => i.Path.StartsWith(dataRel + "Managed/", StringComparison.Ordinal) && i.Path.EndsWith(".dll", StringComparison.Ordinal)))
            .Concat(under.Where(i => i.Path == dataRel + "il2cpp_data/Metadata/" + Il2CppBuildFiles.MetadataFileName))
            .Select(i => (i, 0)).ToList();
        Version(under, dataRel, wanted);
        return wanted;
    }

    // "<top>/<Product>_Data/globalgamemanagers" (or data.unity3d, mainData)
    [System.Text.RegularExpressions.GeneratedRegex(@"^((?:[^/]+/)*?)([^/]+)_Data/(?:globalgamemanagers|data\.unity3d|mainData)$")]
    private static partial System.Text.RegularExpressions.Regex DataMarker();

    /// <summary>iOS: the .app's UnityFramework (or main executable), the metadata and the version files under Data.</summary>
    private static List<(Item, int)> AppleFiles(List<Item> items)
    {
        var metadata = items.FirstOrDefault(i => i.Path.EndsWith(".app/Data/Managed/Metadata/" + Il2CppBuildFiles.MetadataFileName, StringComparison.Ordinal) && i.Path.Count(c => c == '/') == 4);
        if (metadata == null) return [];
        var app = metadata.Path[..(metadata.Path.IndexOf(".app/", StringComparison.Ordinal) + 4)];
        var binary = items.FirstOrDefault(i => i.Path == app + "/Frameworks/UnityFramework.framework/UnityFramework")
                     ?? items.FirstOrDefault(i => i.Path == app + "/" + Path.GetFileNameWithoutExtension(app));
        var wanted = new List<(Item, int)> { (metadata, 0) };
        if (binary != null) wanted.Add((binary, 0));
        Version(items, app + "/Data/", wanted);
        return wanted;
    }

    private static void Version(List<Item> items, string data, List<(Item, int)> wanted)
    {
        if (items.FirstOrDefault(i => i.Path == data + "globalgamemanagers") is { } managers) wanted.Add((managers, 0));
        else if (items.FirstOrDefault(i => i.Path == data + "data.unity3d") is { } bundle) wanted.Add((bundle, VersionHeaderBytes));
    }

    /// <summary>
    /// Keeps the <see cref="MaxPackages"/> most recently used extractions, any another workspace or server holds
    /// (<see cref="CacheHolds"/>), and any used within <see cref="Il2CppRawLoader.InUseWindow"/>.
    /// </summary>
    internal static void Trim(string root, string keep)
    {
        try
        {
            var recent = DateTime.UtcNow - Il2CppRawLoader.InUseWindow;
            foreach (var old in Directory.EnumerateDirectories(root).Where(d => File.Exists(Path.Combine(d, MarkerFileName)) && !d.Equals(keep, StringComparison.OrdinalIgnoreCase))
                         .OrderByDescending(Directory.GetLastWriteTimeUtc).Skip(MaxPackages - 1))
                if (Directory.GetLastWriteTimeUtc(old) < recent && !CacheHolds.InUse(old)) TryDelete(old);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
    }

    /// <summary>The package extraction folder holding <paramref name="path"/>, or null when the path is not inside one.</summary>
    internal static string? ExtractionOf(string path)
    {
        if (path.Length == 0) return null;
        for (var dir = Path.GetDirectoryName(Path.GetFullPath(path)); dir != null; dir = Path.GetDirectoryName(dir))
            if (File.Exists(Path.Combine(dir, MarkerFileName)) && string.Equals(Path.GetFileName(Path.GetDirectoryName(dir)), FolderName, StringComparison.OrdinalIgnoreCase))
                return dir;
        return null;
    }

    private static void Touch(string dir)
    {
        try { Directory.SetLastWriteTimeUtc(dir, DateTime.UtcNow); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
    }

    private static void TryDelete(string dir)
    {
        try { if (Directory.Exists(dir)) Directory.Delete(dir, true); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
    }
}
