using Corvus.Core;
using Corvus.Native;

namespace Corvus.Services.Analysis;

/// <summary>
/// view=flutter: Dart AOT snapshots of a Flutter app (libapp.so, App.framework/App: version hash, features with mode,
/// architecture and OS) and the Dart VM version of an engine (libflutter.so, Flutter.framework).
/// </summary>
internal sealed class FlutterFileView : IFileSummaryView
{
    public sealed record Facts(string Role, IReadOnlyList<DartSnapshot> Snapshots, string? DartVersion, string? EngineBuildId, IReadOnlyList<string> Notes);

    public string Name => "flutter";

    public FileView? Inspect(FileInput file, CancellationToken ct)
    {
        if (NativeImageLoader.Detect(file.Head) == NativeFileKind.Unknown) return null;
        var snapshots = DartScan.Snapshots(file.Bytes, ct);
        if (snapshots.Count > 0)
        {
            snapshots = Named(file, snapshots);
            var s = snapshots.FirstOrDefault(x => x.Kind == "full-aot") ?? snapshots[0];
            var notes = new List<string>();
            if (snapshots.Select(x => x.Hash).Distinct().Count() > 1) notes.Add("snapshots carry different version hashes");
            notes.Add("The version hash names the Dart SDK the app was compiled with; the engine (libflutter.so) must carry the same hash.");
            var facts = new Facts("Dart AOT snapshot", snapshots, null, null, notes);
            string target = string.Join(" ", new[] { s.Architecture, s.Os }.Where(x => x != null));
            return new FileView(facts, [$"Flutter/Dart AOT app: {snapshots.Count} snapshot(s), version hash {s.Hash}" + (target.Length > 0 ? $", {target}" : "") +
                                        (s.Mode != null ? $", {s.Mode} mode" : "") + "."]);
        }
        if (DartScan.DartVersion(file.Bytes, ct) is not { } version) return null;
        bool flutter = DartScan.IsFlutterEngine(file.Bytes);
        string? buildId = BuildId(file);
        var engine = new Facts(flutter ? "Flutter engine" : "Dart VM", [], version, buildId, []);
        return new FileView(engine, [$"{engine.Role} with Dart {version}" + (buildId != null ? $"; build id {buildId}" : "") + "."]);
    }

    /// <summary>Snapshots whose offset a _kDart* symbol names, with that name.</summary>
    private static List<DartSnapshot> Named(FileInput file, List<DartSnapshot> snapshots)
    {
        INativeImage image;
        try { image = NativeImageLoader.FromBytes(file.Bytes, file.Path); }
        catch (ToolError) { return snapshots; }
        var names = new Dictionary<long, string>();
        var symbols = image.Exports.Where(e => e.Name != null).Select(e => (Name: e.Name!, e.Rva)).Concat(image.Symbols.Select(s => (s.Name, s.Rva)));
        foreach (var (name, rva) in symbols)
            if (name.TrimStart('_').StartsWith("kDart", StringComparison.Ordinal) && name.EndsWith("SnapshotData", StringComparison.Ordinal) &&
                image.TryRvaToFileOffset(rva, out long offset))
                names.TryAdd(offset, name.TrimStart('_'));
        return [.. snapshots.Select(s => names.TryGetValue(s.Offset, out var n) ? s with { Symbol = n } : s)];
    }

    private static string? BuildId(FileInput file)
    {
        try { return NativeImageLoader.FromBytes(file.Bytes, file.Path).BuildId; }
        catch (ToolError) { return null; }
    }
}
