using System.ComponentModel;
using Corvus.Core;
using Corvus.Native;

namespace Corvus.Services.Analysis;

/// <summary>
/// view=flutter: Dart AOT snapshots of a Flutter app (libapp.so, App.framework/App, or the one inside an APK or .ipa: version
/// hash, features with mode, architecture and OS, and the isolate's string pool as packages and dart: libraries) and the Dart
/// VM version of an engine (libflutter.so, Flutter.framework).
/// </summary>
internal sealed class FlutterFileView : IFileSummaryView
{
    public sealed record Facts(string Role, IReadOnlyList<DartSnapshot> Snapshots, string? DartVersion, string? EngineBuildId, IReadOnlyList<string> Notes)
    {
        [Description("The AOT image inside an APK or .ipa that was read.")]
        public string? Image { get; init; }

        public Pool? StringPool { get; init; }
    }

    /// <summary>The isolate snapshot's string pool in brief; search_container kind=dart pages every string.</summary>
    public sealed record Pool(long Start, long End, int PackageUris, int DartUris, int Identifiers,
        [property: Description("Packages the package: URIs name: the app's, pub's (with the version a pub cache path gives) and the Flutter SDK's.")] IReadOnlyList<DartPackage> Packages,
        [property: Description("dart: libraries.")] IReadOnlyList<string> Libraries, bool Capped);

    public string Name => "flutter";

    public FileView? Inspect(FileInput file, CancellationToken ct)
    {
        // An APK or .ipa gives its app image entry alone; any other file is gated on its head first.
        string? inner = null;
        byte[]? bytes = null;
        if (file.Kind == "zip")
        {
            if (file.HasZipEntry(DartPoolScan.IsAppEntry))
                using (var package = file.OpenRead()) bytes = DartPoolScan.AppImage(package, out inner);
        }
        else bytes = NativeImageLoader.Detect(file.Head) == NativeFileKind.Unknown ? null : file.Bytes;
        if (bytes == null || NativeImageLoader.Detect(bytes) == NativeFileKind.Unknown) return null;
        var snapshots = DartScan.Snapshots(bytes, ct);
        if (snapshots.Count > 0)
        {
            snapshots = Named(bytes, file.Path, snapshots);
            var s = snapshots.FirstOrDefault(x => x.Kind == "full-aot") ?? snapshots[0];
            var notes = new List<string>();
            if (snapshots.Select(x => x.Hash).Distinct().Count() > 1) notes.Add("snapshots carry different version hashes");
            notes.Add("The version hash names the Dart SDK the app was compiled with; the engine (libflutter.so) must carry the same hash.");
            Pool? pool = null;
            if (DartPoolScan.Isolate(snapshots) is { } isolate)
            {
                var p = DartPoolScan.Read(bytes, isolate, ct);
                pool = new Pool(p.Start, p.End, p.PackageUris, p.DartUris, p.Identifiers, p.Packages, p.Libraries, p.Capped);
                notes.Add("search_container kind=dart lists every URI and identifier of the pool with its offset.");
            }
            var facts = new Facts("Dart AOT snapshot", snapshots, null, null, notes) { Image = inner, StringPool = pool };
            string target = string.Join(" ", new[] { s.Architecture, s.Os }.Where(x => x != null));
            var highlights = new List<string>
            {
                $"Flutter/Dart AOT app{(inner != null ? $" ({inner})" : "")}: {snapshots.Count} snapshot(s), version hash {s.Hash}" + (target.Length > 0 ? $", {target}" : "") +
                (s.Mode != null ? $", {s.Mode} mode" : "") + ".",
            };
            if (pool is { Packages.Count: > 0 })
            {
                var pub = pool.Packages.Where(x => x.Kind == "pub").ToList();
                highlights.Add($"Dart packages: {(pool.Packages.FirstOrDefault(x => x.Kind == "app") is { } app ? $"app {app.Name}; " : "")}{pub.Count} from pub" +
                               (pub.Count > 0 ? $" ({string.Join(", ", pub.Take(12).Select(x => x.Version != null ? $"{x.Name} {x.Version}" : x.Name))}{(pub.Count > 12 ? ", ..." : "")})" : "") + ".");
            }
            return new FileView(facts, highlights);
        }
        if (DartScan.DartVersion(bytes, ct) is not { } version) return null;
        bool flutter = DartScan.IsFlutterEngine(bytes);
        string? buildId = BuildId(bytes, file.Path);
        var engine = new Facts(flutter ? "Flutter engine" : "Dart VM", [], version, buildId, []) { Image = inner };
        return new FileView(engine, [$"{engine.Role} with Dart {version}" + (buildId != null ? $"; build id {buildId}" : "") + "."]);
    }

    /// <summary>Snapshots whose offset a _kDart* symbol names, with that name.</summary>
    private static List<DartSnapshot> Named(byte[] bytes, string path, List<DartSnapshot> snapshots)
    {
        INativeImage image;
        try { image = NativeImageLoader.FromBytes(bytes, path); }
        catch (ToolError) { return snapshots; }
        var names = new Dictionary<long, string>();
        var symbols = image.Exports.Where(e => e.Name != null).Select(e => (Name: e.Name!, e.Rva)).Concat(image.Symbols.Select(s => (s.Name, s.Rva)));
        foreach (var (name, rva) in symbols)
            if (name.TrimStart('_').StartsWith("kDart", StringComparison.Ordinal) && name.EndsWith("SnapshotData", StringComparison.Ordinal) &&
                image.TryRvaToFileOffset(rva, out long offset))
                names.TryAdd(offset, name.TrimStart('_'));
        return [.. snapshots.Select(s => names.TryGetValue(s.Offset, out var n) ? s with { Symbol = n } : s)];
    }

    private static string? BuildId(byte[] bytes, string path)
    {
        try { return NativeImageLoader.FromBytes(bytes, path).BuildId; }
        catch (ToolError) { return null; }
    }
}
