using System.IO.Compression;
using System.Security.Cryptography;
using System.Text.Json;
using NetDecompilerMcp.Core;

namespace NetDecompilerMcp.Services;

/// <summary>
/// Il2Cpp games inside app packages: .apk, split sets (.xapk / .apks / .apkm: a zip of a base APK and config.&lt;abi&gt;.apk
/// splits), .aab (base/ module) and .ipa (Payload/*.app). Only what the reader needs is extracted (the game binary of one
/// ABI, global-metadata.dat and the Unity version files) into a per-user cache keyed by the package's SHA-256, laid out as
/// the extracted package would be, so <see cref="Il2CppGameFiles.Find"/> reads it.
/// </summary>
public static class Il2CppPackages
{
    public const string FolderName = "packages";
    private const string MarkerFileName = "package.json";
    private const int MaxPackages = 8;
    /// <summary>The Unity version is in the first bytes of data.unity3d; the rest (often hundreds of MB) is not needed.</summary>
    private const int VersionHeaderBytes = 1 << 16;
    private const long MaxEntryBytes = 2L << 30;

    private static readonly string[] Extensions = [".apk", ".xapk", ".apks", ".apkm", ".aab", ".ipa"];

    public sealed record Marker(string Package, string Sha256, string? Slice, DateTime Created);

    public static bool IsPackage(string path) => Extensions.Contains(Path.GetExtension(path).ToLowerInvariant()) && File.Exists(path);

    /// <summary>
    /// The extracted game root of the Il2Cpp game in <paramref name="package"/>, or null when the package holds none
    /// (no global-metadata.dat). <paramref name="slice"/> picks the Android ABI.
    /// </summary>
    public static string? Extract(string package, string? slice, string? cacheRoot = null, CancellationToken ct = default)
    {
        var full = Path.GetFullPath(package);
        string sha;
        try
        {
            using var stream = File.OpenRead(full);
            sha = Convert.ToHexStringLower(SHA256.HashData(stream));
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { throw new ToolError(ErrorCode.IoError, $"Cannot read {full}: {ex.Message}"); }
        var abi = slice != null ? Il2CppGameFiles.AndroidAbi(slice) : null;
        var root = Path.Combine(Path.GetFullPath(cacheRoot ?? Il2CppRawLoader.DefaultRoot), FolderName);
        var dir = Path.Combine(root, sha[..16] + (abi != null ? "-" + abi : ""));
        if (File.Exists(Path.Combine(dir, MarkerFileName)))
        {
            Touch(dir);
            return Directory.Exists(Path.Combine(dir, "game")) ? Path.Combine(dir, "game") : null;
        }
        var staging = dir + ".tmp-" + Environment.ProcessId;
        TryDelete(staging);
        try
        {
            var game = Path.Combine(staging, "game");
            Directory.CreateDirectory(game);
            bool found;
            var splits = Path.Combine(staging, "splits");
            using (var zip = OpenZip(full))
                found = ExtractGame(zip, Path.GetExtension(full).ToLowerInvariant(), game, splits, abi, ct);
            TryDelete(splits);
            if (!found) Directory.Delete(game, true);
            File.WriteAllText(Path.Combine(staging, MarkerFileName), JsonSerializer.Serialize(new Marker(full, sha, abi, DateTime.UtcNow)));
            TryDelete(dir);
            Directory.Move(staging, dir);
            Trim(root, dir);
            return found ? Path.Combine(dir, "game") : null;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            TryDelete(staging);
            throw new ToolError(ErrorCode.IoError, $"Cannot extract the Il2Cpp game from {full} under {root}: {ex.Message}", $"set {Il2CppRawLoader.RootVariable} to a writable folder");
        }
        catch
        {
            TryDelete(staging);
            throw;
        }
    }

    private static ZipArchive OpenZip(string path)
    {
        try { return ZipFile.OpenRead(path); }
        catch (InvalidDataException ex) { throw new ToolError(ErrorCode.MalformedInput, $"{path} is not a readable zip package: {ex.Message}"); }
    }

    /// <summary>A file of the app as the package lays it out: its path inside the app, and how to open it.</summary>
    private sealed record Item(string Path, ZipArchiveEntry Entry);

    private static bool ExtractGame(ZipArchive zip, string extension, string game, string splits, string? abi, CancellationToken ct)
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

            var wanted = extension == ".ipa" ? AppleFiles(items) : AndroidFiles(items, abi);
            if (wanted.Count == 0) return false;
            foreach (var (item, limit) in wanted)
            {
                ct.ThrowIfCancellationRequested();
                if (item.Entry.Length > MaxEntryBytes)
                    throw new ToolError(ErrorCode.LimitExceeded, $"{item.Path} is {item.Entry.Length} bytes; entries up to {MaxEntryBytes} bytes are extracted");
                var target = Path.GetFullPath(Path.Combine(game, item.Path.Replace('/', Path.DirectorySeparatorChar)));
                if (!target.StartsWith(game + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase)) continue; // a path escaping the folder
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

    /// <summary>Android: lib/&lt;abi&gt;/libil2cpp.so of one ABI, the metadata and the version files under assets/bin/Data.</summary>
    private static List<(Item, int)> AndroidFiles(List<Item> items, string? abi)
    {
        const string data = "assets/bin/Data/";
        var metadata = items.FirstOrDefault(i => i.Path == data + "Managed/Metadata/" + Il2CppGameFiles.MetadataFileName);
        if (metadata == null) return [];
        var libraries = items.Where(i => i.Path.StartsWith("lib/", StringComparison.Ordinal) && i.Path.EndsWith("/libil2cpp.so", StringComparison.Ordinal) && i.Path.Count(c => c == '/') == 2)
            .GroupBy(i => i.Path.Split('/')[1]).ToDictionary(g => g.Key, g => g.First());
        var chosen = abi != null ? libraries.GetValueOrDefault(abi)
            : Il2CppGameFiles.AndroidAbis.Select(libraries.GetValueOrDefault).FirstOrDefault(i => i != null) ?? libraries.Values.FirstOrDefault();
        if (abi != null && chosen == null)
            throw new ToolError(ErrorCode.NotFound, $"The package has no lib/{abi}/libil2cpp.so" + (libraries.Count > 0 ? $"; ABIs: {string.Join(", ", libraries.Keys)}" : "") + ".",
                libraries.Count > 0 ? $"pass slice={libraries.Keys.First()}" : "the package holds no Il2Cpp library");
        var wanted = new List<(Item, int)> { (metadata, 0) };
        if (chosen != null) wanted.Add((chosen, 0));
        Version(items, data, wanted);
        return wanted;
    }

    /// <summary>iOS: the .app's UnityFramework (or main executable), the metadata and the version files under Data.</summary>
    private static List<(Item, int)> AppleFiles(List<Item> items)
    {
        var metadata = items.FirstOrDefault(i => i.Path.EndsWith(".app/Data/Managed/Metadata/" + Il2CppGameFiles.MetadataFileName, StringComparison.Ordinal) && i.Path.Count(c => c == '/') == 4);
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

    /// <summary>Keeps the <see cref="MaxPackages"/> most recently used extractions.</summary>
    private static void Trim(string root, string keep)
    {
        try
        {
            foreach (var old in Directory.EnumerateDirectories(root).Where(d => File.Exists(Path.Combine(d, MarkerFileName)) && !d.Equals(keep, StringComparison.OrdinalIgnoreCase))
                         .OrderByDescending(Directory.GetLastWriteTimeUtc).Skip(MaxPackages - 1))
                TryDelete(old);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
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
