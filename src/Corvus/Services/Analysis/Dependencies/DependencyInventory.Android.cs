using System.IO.Compression;
using System.Text;
using System.Text.RegularExpressions;

namespace Corvus.Services.Analysis.Dependencies;

internal static partial class DependencyInventory
{
    private const double EmbeddedVersion = 0.6, FileNameOnly = 0.3;
    private const int MaxSmallEntry = 64 * 1024;
    private const int MaxLibraryScan = 32 << 20;
    private const long MaxSplitBytes = 512L << 20;

    /// <summary>Version strings libraries compile into their code, by library; group 1 is the version.</summary>
    private static readonly (string Name, Regex Pattern)[] EmbeddedLibraries =
    [
        ("OpenSSL", OpenSslVersion()), ("zlib", ZlibVersion()), ("libpng", PngVersion()), ("libcurl", CurlVersion()), ("libjpeg-turbo", JpegTurboVersion()),
    ];

    [GeneratedRegex(@"OpenSSL (\d+\.\d+\.\d+[a-z]{0,2})[ \0]")]
    private static partial Regex OpenSslVersion();

    [GeneratedRegex(@"(?:deflate|inflate) (\d+\.\d+(?:\.\d+){0,2}) Copyright")]
    private static partial Regex ZlibVersion();

    [GeneratedRegex(@"libpng version (\d+\.\d+\.\d+)")]
    private static partial Regex PngVersion();

    [GeneratedRegex(@"libcurl/(\d+\.\d+\.\d+)")]
    private static partial Regex CurlVersion();

    [GeneratedRegex(@"libjpeg-turbo version (\d+\.\d+\.\d+)")]
    private static partial Regex JpegTurboVersion();

    [GeneratedRegex(@"^\d+(\.\d+)+([.-][0-9A-Za-z.+-]+)?$")]
    private static partial Regex MavenVersion();

    /// <summary>
    /// Adds an Android package's Java and native libraries; a split set is one app, located as "split.apk!/entry".
    /// Returns true when an APK of a split set holds global-metadata.dat.
    /// </summary>
    private static bool FromAndroid(Builder b, FileInput input, IReadOnlyDictionary<string, FileView> views, CancellationToken ct)
    {
        if (input.Kind != "zip") return false;
        bool single = input.HasZipEntry(n => n is "AndroidManifest.xml" or "base/manifest/AndroidManifest.xml");
        if (!single && !input.HasZipEntry(n => n.EndsWith(".apk", StringComparison.OrdinalIgnoreCase))) return false;
        if (b.Subject == null && views.GetValueOrDefault("android")?.Detail is Mobile.AndroidPackageFacts app)
            b.Subject = new DependencyComponent(b.NewRef($"android:{app.Package}"), app.Package, app.VersionName, "android", "application", null, Manifest,
                "manifest-analysis", "AndroidManifest.xml package and versionName");
        var opened = new List<ZipArchive>();
        bool aot = false;
        try
        {
            var outer = new ZipArchive(input.OpenRead(), ZipArchiveMode.Read);
            opened.Add(outer);
            var archives = new List<(ZipArchive Zip, string Prefix)>();
            if (single) archives.Add((outer, ""));
            else
            {
                int large = 0;
                foreach (var e in outer.Entries.Where(e => e.FullName.EndsWith(".apk", StringComparison.OrdinalIgnoreCase)))
                {
                    ct.ThrowIfCancellationRequested();
                    if (e.Length > MaxSplitBytes) { large++; continue; }
                    var nested = new ZipArchive(new MemoryStream(ReadBytes(e), writable: false), ZipArchiveMode.Read);
                    opened.Add(nested);
                    archives.Add((nested, e.FullName + "!/"));
                }
                if (archives.Count == 0 && large == 0) return false;
                if (large > 0) b.Notes.Add($"{large} APKs of the split set over {MaxSplitBytes >> 20} MiB were not read: their libraries are unknown");
            }
            b.Sources.Add(single
                ? $"Android package {Path.GetFileName(input.Path)} (META-INF version files, Maven properties, native libraries)"
                : $"Android split set {Path.GetFileName(input.Path)}: {archives.Count} APKs read (META-INF version files, Maven properties, native libraries)");
            var poms = new List<(string Group, string Artifact, string Version, string Location)>();
            var versionFiles = new List<(string Stem, string Version, string Location)>();
            var libraries = new Dictionary<string, List<(ZipArchiveEntry Entry, string Location)>>(StringComparer.Ordinal);
            foreach (var (zip, prefix) in archives)
                foreach (var e in zip.Entries)
                {
                    ct.ThrowIfCancellationRequested();
                    var location = prefix + e.FullName;
                    aot |= prefix.Length > 0 && e.FullName.EndsWith("/global-metadata.dat", StringComparison.Ordinal);
                    // An app bundle keeps the files of META-INF under base/root/ and the libraries under base/lib/.
                    var name = e.FullName.StartsWith("base/root/", StringComparison.Ordinal) ? e.FullName["base/root/".Length..]
                        : e.FullName.StartsWith("base/lib/", StringComparison.Ordinal) ? e.FullName["base/".Length..] : e.FullName;
                    if (name.StartsWith("META-INF/maven/", StringComparison.Ordinal) && name.EndsWith("/pom.properties", StringComparison.Ordinal) && e.Length <= MaxSmallEntry)
                    {
                        var p = Properties(ReadText(e));
                        if (p.GetValueOrDefault("groupId") is { Length: > 0 } g && p.GetValueOrDefault("artifactId") is { Length: > 0 } a && p.GetValueOrDefault("version") is { Length: > 0 } v)
                            poms.Add((g, a, v, location));
                    }
                    else if (name.StartsWith("META-INF/", StringComparison.Ordinal) && name.EndsWith(".version", StringComparison.Ordinal) && name.IndexOf('/', 9) < 0 && e.Length <= MaxSmallEntry)
                    {
                        var text = ReadText(e).Trim();
                        versionFiles.Add((name[9..^".version".Length], MavenVersion().IsMatch(text) ? text : "", location));
                    }
                    else if (name.StartsWith("lib/", StringComparison.Ordinal) && name.EndsWith(".so", StringComparison.Ordinal) && name.Count(c => c == '/') == 2)
                    {
                        var file = name[(name.LastIndexOf('/') + 1)..];
                        // .NET for Android keeps its assembly store in a .so; its assemblies are read as assemblies.
                        if (file.StartsWith("libassemblies.", StringComparison.Ordinal) || file == "libassembly-store.so") continue;
                        (libraries.TryGetValue(file, out var list) ? list : libraries[file] = []).Add((e, location));
                    }
                }
            foreach (var (g, a, v, location) in poms)
                Add(b, new DependencyComponent(b.NewRef(PurlMaven(g, a, v)), $"{g}:{a}", v, "maven", "library", PurlMaven(g, a, v), Manifest, "manifest-analysis",
                    "Maven pom.properties") { Locations = [location] }, location);
            foreach (var (stem, version, location) in versionFiles)
            {
                // AndroidX writes META-INF/<group>_<artifact>.version; a stem without a dotted group is a module name.
                int cut = stem.IndexOf('_');
                var group = cut > 0 ? stem[..cut] : null;
                var artifact = cut > 0 ? stem[(cut + 1)..] : null;
                bool coordinate = group != null && group.Contains('.') && artifact!.Length > 0 && !artifact.Contains('_');
                var known = version.Length > 0 ? version : null;
                if (coordinate && known != null && poms.Any(p => p.Group == group && p.Artifact == artifact && p.Version == known)) continue;
                var purl = coordinate && known != null ? PurlMaven(group!, artifact!, known) : null;
                Add(b, new DependencyComponent(b.NewRef(purl ?? $"maven:{stem}@{known}"), coordinate ? $"{group}:{artifact}" : stem, known, "maven", "library", purl,
                    purl != null ? Manifest : FileNameOnly, "manifest-analysis",
                    purl != null ? "META-INF version file (group_artifact.version)"
                        : known == null ? "META-INF version file; its content is not a version, so the version is unknown"
                        : "META-INF version file; its name gives no Maven group and artifact, so it has no package URL") { Locations = [location] }, location);
            }
            FromNativeLibraries(b, libraries, ct);
        }
        catch (InvalidDataException ex)
        {
            b.Notes.Add($"the Android package could not be read as a zip ({ex.Message}); its Java and native libraries are unknown");
        }
        finally
        {
            foreach (var z in opened) z.Dispose();
        }
        return aot;
    }

    /// <summary>Each native library once, with the ABIs it ships for, and the libraries its code names by version string.</summary>
    private static void FromNativeLibraries(Builder b, Dictionary<string, List<(ZipArchiveEntry Entry, string Location)>> libraries, CancellationToken ct)
    {
        int skipped = 0;
        foreach (var (file, entries) in libraries.OrderBy(l => l.Key, StringComparer.Ordinal))
        {
            b.Components.Add(new DependencyComponent(b.NewRef($"native:{file}"), file, null, "native", "library", null, FileNameOnly, "filename",
                "native library in the package; the file name gives no version") { Locations = [.. entries.Select(e => e.Location)] });
            foreach (var (e, location) in entries)
            {
                ct.ThrowIfCancellationRequested();
                if (e.Length > MaxLibraryScan) { skipped++; continue; }
                var text = Encoding.Latin1.GetString(ReadBytes(e));
                foreach (var (name, pattern) in EmbeddedLibraries)
                    foreach (var version in pattern.Matches(text).Select(m => m.Groups[1].Value).Distinct(StringComparer.Ordinal))
                        Add(b, new DependencyComponent(b.NewRef($"native:{name}@{version}"), name, version, "native", "library", null, EmbeddedVersion, "binary-analysis",
                            $"version string compiled into the native code") { Locations = [location] }, location);
            }
        }
        if (skipped > 0) b.Notes.Add($"{skipped} native libraries over {MaxLibraryScan >> 20} MiB were not scanned for version strings: the libraries compiled into them are unknown");
    }

    private static void Add(Builder b, DependencyComponent c, string location)
    {
        if (!Merge(b, c, location)) b.Components.Add(c);
    }

    private static string PurlMaven(string group, string artifact, string version) => $"pkg:maven/{Purl.Encode(group)}/{Purl.Encode(artifact)}@{Purl.Encode(version)}";

    private static Dictionary<string, string> Properties(string text)
    {
        var result = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var line in text.ReplaceLineEndings("\n").Split('\n'))
            if (line.Length > 0 && line[0] != '#' && line.IndexOf('=') is var i and > 0) result[line[..i].Trim()] = line[(i + 1)..].Trim();
        return result;
    }

    private static string ReadText(ZipArchiveEntry e) => Encoding.UTF8.GetString(ReadBytes(e));

    private static byte[] ReadBytes(ZipArchiveEntry e)
    {
        using var s = e.Open();
        using var m = new MemoryStream((int)Math.Min(e.Length, int.MaxValue));
        s.CopyTo(m);
        return m.ToArray();
    }
}
