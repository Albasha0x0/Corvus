using Corvus.Core;

namespace Corvus.Services.Analysis;

/// <summary>
/// search_container kind=dart: the string pool of a Flutter app's Dart AOT isolate snapshot (libapp.so, App.framework/App, or
/// the one inside an APK or .ipa): package: and dart: URIs and identifier tokens, with their offset in the AOT image.
/// </summary>
internal sealed class DartSearchKind : IContainerSearchKind
{
    public IReadOnlyList<string> Kinds => ["dart"];

    public IEnumerable<ContainerMatch> Search(ContainerScope scope, string kind, Func<string, bool> matches, CancellationToken ct)
    {
        byte[] file;
        try { file = File.ReadAllBytes(scope.Source); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { yield break; }
        if (DartPoolScan.AppImage(file, out var inner) is not { } bytes) yield break;
        var snapshots = DartScan.Snapshots(bytes, ct);
        if (DartPoolScan.Isolate(snapshots) is not { } isolate) yield break;
        var path = inner ?? Path.GetFileName(scope.Source);
        foreach (var s in DartPoolScan.Read(bytes, isolate, ct, FlutterFileView.Images(bytes, path, isolate)).Strings)
            if (matches(s.Value) || matches(s.Kind))
                yield return new ContainerMatch(path, s.Value, "dart") { Detail = $"{s.Kind} at 0x{s.Offset:x}" + (s.Image != null ? $" in the {s.Image}" : "") };
    }
}
