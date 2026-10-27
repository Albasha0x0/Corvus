using System.ComponentModel;
using Corvus.Core;
using Corvus.Native;

namespace Corvus.Services.Analysis;

/// <summary>view=flutter: an app's Dart AOT snapshots (version hash, target, string pool, packages) or an engine's Dart VM version.</summary>
internal sealed class FlutterFileView : IFileSummaryView
{
    public sealed record Facts(string Role, IReadOnlyList<DartSnapshot> Snapshots, string? DartVersion, string? EngineBuildId, IReadOnlyList<string> Notes)
    {
        [Description("The AOT image inside an APK or .ipa that was read.")]
        public string? Image { get; init; }

        public Pool? StringPool { get; init; }

        public Names? CodeNames { get; init; }
    }

    /// <summary>Code named from the program snapshot's objects, as list_functions shows them (the dart layer).</summary>
    public sealed record Names(int Functions, int Named,
        [property: Description("Why the snapshot's objects were not read (another layout); the names are then unknown.")] string? Unsupported);

    /// <summary>The isolate snapshot's string pool in brief; search_container kind=dart pages every string.</summary>
    public sealed record Pool(long Start, long End, int PackageUris, int DartUris, int Identifiers,
        [property: Description("Packages the package: URIs name: the app's, pub's (with the version a pub cache path gives) and the Flutter SDK's.")] IReadOnlyList<DartPackage> Packages,
        [property: Description("dart: libraries.")] IReadOnlyList<string> Libraries, bool Capped)
    {
        [Description("Strings only in the data or instructions image, as string objects (older snapshots keep them there).")]
        public int ImageStrings { get; init; }
    }

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
        else bytes = NativeImageLoader.Detect(file.Head) == NativeFileKind.Unknown ? null : file.Image;
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
                var p = DartPoolScan.Read(bytes, isolate, ct, Images(bytes, file.Path, isolate));
                pool = new Pool(p.Start, p.End, p.PackageUris, p.DartUris, p.Identifiers, p.Packages, p.Libraries, p.Capped) { ImageStrings = p.ImageStrings };
                notes.Add("search_container kind=dart lists every URI, identifier and image string of the pool with its offset.");
            }
            Names? names = null;
            if (snapshots.Any(x => x.Symbol is "kDartSnapshotData" or "kDartIsolateSnapshotData"))
            {
                try
                {
                    if (DartNames.Read(NativeImageLoader.FromBytes(bytes, file.Path), ct) is var (program, _))
                        names = new Names(program.Functions, program.Code.Count, program.Unsupported);
                }
                catch (ToolError) { }
            }
            var facts = new Facts("Dart AOT snapshot", snapshots, null, null, notes) { Image = inner, StringPool = pool, CodeNames = names };
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
            if (names is { Unsupported: null })
                highlights.Add($"{names.Named:N0} code objects named from {names.Functions:N0} functions of the snapshot (list_functions shows them).");
            else if (names != null) highlights.Add($"Code names not read: {names.Unsupported}.");
            if (pool is { ImageStrings: > 0 })
                highlights.Add($"{pool.ImageStrings:N0} strings only as string objects of the data or instructions image (search_container kind=dart).");
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

    /// <summary>The isolate's data and instructions images, located by their _kDart* symbols; empty without those symbols.</summary>
    // Dart 3.13 renamed _kDartIsolateSnapshotData to _kDartSnapshotData and the instructions symbol to _kDartSnapshotText.
    internal static List<DartImage> Images(byte[] bytes, string path, DartSnapshot isolate)
    {
        INativeImage image;
        try { image = NativeImageLoader.FromBytes(bytes, path); }
        catch (ToolError) { return []; }
        var images = new List<DartImage>();
        foreach (var s in image.Symbols)
        {
            if (s.Size == 0 || !image.TryRvaToFileOffset(s.Rva, out long offset)) continue;
            var name = s.Name.TrimStart('_');
            if (name is "kDartIsolateSnapshotData" or "kDartSnapshotData" && offset == isolate.Offset && isolate.Offset + 4 + isolate.Length < offset + (long)s.Size)
                images.Add(new DartImage(isolate.Offset + 4 + isolate.Length, offset + (long)s.Size, "data image"));
            else if (name is "kDartIsolateSnapshotInstructions" or "kDartSnapshotText")
                images.Add(new DartImage(offset, offset + (long)s.Size, "instructions image"));
        }
        return images;
    }

    private static string? BuildId(byte[] bytes, string path)
    {
        try { return NativeImageLoader.FromBytes(bytes, path).BuildId; }
        catch (ToolError) { return null; }
    }
}
