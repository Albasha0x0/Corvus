using System.IO.Compression;
using System.Security.Cryptography;
using System.Text.Json;
using Corvus.Core;

namespace Corvus.Services;

/// <summary>
/// Extracts the build files of an .apk, split set (.xapk, .apks, .apkm), .aab or .ipa into a per-user cache keyed by
/// SHA-256, laid out so <see cref="AotBuildFiles.Find"/> reads it. Only one ABI's native libraries, global-metadata.dat
/// and the version files are extracted.
/// </summary>
public static partial class AotPackages
{
    public const string FolderName = "packages";
    internal const string MarkerFileName = "package.json";
    internal const int MaxPackages = 8;
    /// <summary>The runtime version is in the first bytes of data.unity3d; the rest is not extracted.</summary>
    private const int VersionHeaderBytes = 1 << 16;
    private const long MaxEntryBytes = 2L << 30;
    // Bump when what is extracted changes.
    private const int ExtractFormat = 4;
    /// <summary>Assets mode: bytes extracted per entry and in total; entries past either are not extracted and are listed as skipped.</summary>
    public const long MaxAssetEntryBytes = 1L << 30, MaxAssetBytes = 4L << 30;
    /// <summary>Assets mode: data folder entries extracted at most.</summary>
    public const int MaxAssetEntries = 2_000;

    /// <summary>An extraction: the package, its hash and ABI, when it was made, and in assets mode the entries left out and whether a stop ended it.</summary>
    public sealed record Marker(string Package, string Sha256, string? Slice, DateTime Created, IReadOnlyList<string>? Skipped = null, bool Stopped = false);

    public static bool IsPackage(string path) => PackageFiles.IsAppPackage(path);

    /// <summary>A package summarize_build reads in place: an application package, or a zip of a desktop build.</summary>
    public static bool IsPlayerPackage(string path) => PackageFiles.IsPlayerPackage(path);

    /// <summary>
    /// The extracted build root of <paramref name="package"/>; null when it holds no build. <paramref name="slice"/> picks
    /// the Android ABI. <paramref name="anyBackend"/>
    /// adds Mono builds and zipped desktop builds; <paramref name="assets"/> adds bounded asset files, and a
    /// <paramref name="stop"/> leaves an extraction redone on the next call.
    /// </summary>
    public static string? Extract(string package, string? slice, string? cacheRoot = null, CancellationToken ct = default, bool anyBackend = false,
        bool assets = false, CancellationToken stop = default)
    {
        anyBackend |= assets;
        var full = Path.GetFullPath(package);
        string sha;
        try
        {
            using var stream = File.OpenRead(full);
            sha = Convert.ToHexStringLower(SHA256.HashData(stream));
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { throw new ToolError(ErrorCode.IoError, $"Cannot read {full}: {ex.Message}"); }
        var abi = slice != null ? AotBuildFiles.AndroidAbi(slice) : null;
        var root = Path.Combine(Path.GetFullPath(cacheRoot ?? AotBuildLoader.DefaultRoot), FolderName);
        var dir = Path.Combine(root, $"{sha[..16]}-{ExtractFormat}" + (abi != null ? "-" + abi : "") + (assets ? "-s" : anyBackend ? "-u" : ""));
        if (File.Exists(Path.Combine(dir, MarkerFileName)) && !(assets && ReadMarker(dir) is { Stopped: true }))
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
            var skipped = assets ? new List<string>() : null;
            bool stopped = false;
            using (var zip = OpenZip(full))
                found = ExtractApp(zip, IsAppBundle(zip) ? ".aab" : Path.GetExtension(full).ToLowerInvariant(), app, splits, abi, ct, anyBackend, skipped, stop, ref stopped);
            TryDelete(splits);
            if (!found) Directory.Delete(app, true);
            File.WriteAllText(Path.Combine(staging, MarkerFileName), JsonSerializer.Serialize(new Marker(full, sha, abi, DateTime.UtcNow, skipped, stopped)));
            TryDelete(dir);
            SafeFile.WhenReleased(() => Directory.Move(staging, dir));
            Trim(root, dir);
            return found ? Path.Combine(dir, "app") : null;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            TryDelete(staging);
            throw new ToolError(ErrorCode.IoError, $"Cannot extract the build from {full} under {root}: {ex.Message}", $"set {AotBuildLoader.RootVariable} to a writable folder");
        }
        catch
        {
            TryDelete(staging);
            throw;
        }
    }

    /// <summary>The marker of the extraction in <paramref name="dir"/>, or null when it is missing or does not read.</summary>
    private static Marker? ReadMarker(string dir)
    {
        try { return JsonSerializer.Deserialize<Marker>(File.ReadAllText(Path.Combine(dir, MarkerFileName))); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException) { return null; }
    }

    /// <summary>The asset entries an assets-mode extraction left out, with reasons; empty for another mode or a complete one.</summary>
    internal static IReadOnlyList<string> SkippedAssets(string app) =>
        Path.GetDirectoryName(Path.GetFullPath(app)) is { } dir && ReadMarker(dir) is { Skipped: { } skipped } ? skipped : [];

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

    /// <summary>Extracts the wanted files; non-null <paramref name="skipped"/> selects assets mode and lists entries left out.</summary>
    private static bool ExtractApp(ZipArchive zip, string extension, string destination, string splits, string? abi, CancellationToken ct, bool anyBackend,
        List<string>? skipped, CancellationToken stop, ref bool stopped)
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
                _ => AndroidFiles(items, abi) is { Count: > 0 } aot ? aot : anyBackend ? MonoAndroidFiles(items) : [],
            };
            var assetItems = skipped != null ? AssetFiles(items, extension, skipped) : [];
            if (wanted.Count == 0 && assetItems.Count == 0) return false;
            // An asset entry replaces the version header item of the same path, so data.unity3d is extracted whole.
            var assetPaths = assetItems.Select(i => i.Path).ToHashSet(StringComparer.Ordinal);
            wanted = [.. wanted.Where(w => !assetPaths.Contains(w.Item1.Path))];
            long assetBytes = 0;
            int assetCount = 0;
            foreach (var item in assetItems)
            {
                if (item.Entry.Length > MaxAssetEntryBytes)
                    skipped!.Add($"{item.Path}: {item.Entry.Length:N0} bytes, over the {MaxAssetEntryBytes:N0} byte limit per entry");
                else if (assetBytes + item.Entry.Length > MaxAssetBytes)
                    skipped!.Add($"{item.Path}: past the {MaxAssetBytes:N0} byte limit of extracted assets");
                else if (assetCount >= MaxAssetEntries)
                    skipped!.Add($"{item.Path}: past the {MaxAssetEntries:N0} entry limit of extracted assets");
                else
                {
                    assetBytes += item.Entry.Length;
                    assetCount++;
                    wanted.Add((item, 0));
                }
            }
            for (int w = 0; w < wanted.Count; w++)
            {
                var (item, limit) = wanted[w];
                ct.ThrowIfCancellationRequested();
                // Asset entries come last, so a stop leaves the build files whole.
                if (skipped != null && stop.IsCancellationRequested && assetPaths.Contains(item.Path))
                {
                    stopped = true;
                    skipped.Add($"{item.Path} and {wanted.Count - w - 1} more asset entries: the time limit ended the extraction");
                    break;
                }
                if (item.Entry.Length > MaxEntryBytes)
                    throw new ToolError(ErrorCode.LimitExceeded, $"{item.Path} is {item.Entry.Length} bytes; entries up to {MaxEntryBytes} bytes are extracted");
                var target = Path.GetFullPath(Path.Combine(destination, item.Path.Replace('/', Path.DirectorySeparatorChar)));
                // Skip a path that escapes the folder.
                if (!target.StartsWith(destination + Path.DirectorySeparatorChar, InputFiles.PathComparison)) continue;
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
        var metadata = items.FirstOrDefault(i => i.Path == data + "Managed/Metadata/" + AotBuildFiles.MetadataFileName);
        if (metadata == null) return [];
        var libraries = items.Where(i => i.Path.StartsWith("lib/", StringComparison.Ordinal) && i.Path.EndsWith("/libil2cpp.so", StringComparison.Ordinal) && i.Path.Count(c => c == '/') == 2)
            .GroupBy(i => i.Path.Split('/')[1]).ToDictionary(g => g.Key, g => g.First());
        var chosen = abi != null ? libraries.GetValueOrDefault(abi)
            : AotBuildFiles.AndroidAbis.Select(libraries.GetValueOrDefault).FirstOrDefault(i => i != null) ?? libraries.Values.FirstOrDefault();
        if (abi != null && chosen == null)
            throw new ToolError(ErrorCode.NotFound, $"The package has no lib/{abi}/libil2cpp.so" + (libraries.Count > 0 ? $"; ABIs: {string.Join(", ", libraries.Keys)}" : "") + ".",
                libraries.Count > 0 ? $"pass slice={libraries.Keys.First()}" : "the package holds no libil2cpp.so");
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
        if ((AotBuildFiles.AndroidAbis.FirstOrDefault(abis.Contains) ?? abis.FirstOrDefault()) is { } abi)
            wanted.AddRange(items.Where(i => i.Path.StartsWith($"lib/{abi}/lib", StringComparison.Ordinal) && (i.Path.EndsWith("/libunity.so", StringComparison.Ordinal)
                || i.Path.Contains("/libmono", StringComparison.Ordinal))).Select(i => (i, 0)));
        Version(items, data, wanted);
        return wanted;
    }

    /// <summary>A zipped Windows or Linux build: the folder holding &lt;Product&gt;_Data becomes the root, with its binaries, assemblies or metadata.</summary>
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
            .Concat(under.Where(i => i.Path == dataRel + "il2cpp_data/Metadata/" + AotBuildFiles.MetadataFileName))
            .Select(i => (i, 0)).ToList();
        Version(under, dataRel, wanted);
        return wanted;
    }

    /// <summary>Assets mode: the data folder's asset entries and Android streaming assets that start with UnityFS, in reader order.</summary>
    private static List<Item> AssetFiles(List<Item> items, string extension, List<string> skipped)
    {
        // Streaming assets are checked by their first bytes, so their number is bounded.
        const int maxChecked = 4_000;
        string data;
        IEnumerable<Item> pool = items;
        if (extension == ".zip")
        {
            var marker = items.Select(i => DataMarker().Match(i.Path)).Where(m => m.Success).OrderBy(m => m.Value.Length).FirstOrDefault();
            if (marker == null) return [];
            var top = marker.Groups[1].Value;
            pool = items.Where(i => i.Path.StartsWith(top, StringComparison.Ordinal)).Select(i => new Item(i.Path[top.Length..], i.Entry)).ToList();
            data = marker.Groups[2].Value + "_Data/";
        }
        else if (extension == ".ipa")
        {
            var app = items.Select(i => i.Path).FirstOrDefault(p => p.IndexOf(".app/Data/", StringComparison.Ordinal) is var at and > 0 && p.IndexOf('/') == at + 4);
            if (app == null) return [];
            data = app[..(app.IndexOf(".app/", StringComparison.Ordinal) + 4)] + "/Data/";
        }
        else data = "assets/bin/Data/";
        var found = pool.Where(i => i.Path.StartsWith(data, StringComparison.Ordinal) && Analysis.AssetFileStrings.IsAssetPath(i.Path[data.Length..])).ToList();
        if (extension is not (".zip" or ".ipa"))
        {
            var streaming = pool.Where(i => i.Path.StartsWith("assets/", StringComparison.Ordinal) && !i.Path.StartsWith("assets/bin/", StringComparison.Ordinal)
                                            && Analysis.AssetFileStrings.IsAssetPath(i.Path["assets/".Length..])).ToList();
            if (streaming.Count > maxChecked) skipped.Add($"assets/: {streaming.Count - maxChecked:N0} streaming asset entries past the first {maxChecked:N0} are not checked");
            found.AddRange(streaming.Take(maxChecked).Where(i => StartsAsBundle(i.Entry)));
        }
        return [.. found.DistinctBy(i => i.Path)
            .OrderBy(i => i.Path.StartsWith(data, StringComparison.Ordinal) ? Analysis.AssetFileStrings.Rank(i.Path[data.Length..]) : int.MaxValue)
            .ThenBy(i => i.Path, StringComparer.Ordinal)];
    }

    /// <summary>True when the entry starts with the UnityFS signature; false when it does not or does not read.</summary>
    private static bool StartsAsBundle(ZipArchiveEntry entry)
    {
        if (entry.Length < 8) return false;
        try
        {
            using var s = entry.Open();
            Span<byte> head = stackalloc byte[8];
            return s.ReadAtLeast(head, 8, throwOnEndOfStream: false) == 8 && head.SequenceEqual("UnityFS\0"u8);
        }
        catch (InvalidDataException) { return false; }
    }

    // Matches "<top>/<Product>_Data/globalgamemanagers", data.unity3d or mainData.
    [System.Text.RegularExpressions.GeneratedRegex(@"^((?:[^/]+/)*?)([^/]+)_Data/(?:globalgamemanagers|data\.unity3d|mainData)$")]
    private static partial System.Text.RegularExpressions.Regex DataMarker();

    /// <summary>iOS: the .app's UnityFramework (or main executable), the metadata and the version files under Data.</summary>
    private static List<(Item, int)> AppleFiles(List<Item> items)
    {
        var metadata = items.FirstOrDefault(i => i.Path.EndsWith(".app/Data/Managed/Metadata/" + AotBuildFiles.MetadataFileName, StringComparison.Ordinal) && i.Path.Count(c => c == '/') == 4);
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
    /// Keeps the <see cref="MaxPackages"/> most recent extractions, any another workspace holds, and any used within
    /// <see cref="AotBuildLoader.InUseWindow"/>.
    /// </summary>
    internal static void Trim(string root, string keep)
    {
        try
        {
            var recent = DateTime.UtcNow - AotBuildLoader.InUseWindow;
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
