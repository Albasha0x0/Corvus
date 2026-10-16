namespace Corvus.Services.Analysis;

/// <summary>
/// view=layers: an Android package's code layers and the verified edges between them (Mobile.AppGraph). The overview only
/// names the view; summarize_file builds the graph when it is asked for.
/// </summary>
internal sealed class LayersFileView : IFileSummaryView
{
    public string Name => "layers";

    public FileView? Inspect(FileInput file, CancellationToken ct) =>
        file.Kind == "zip" && file.HasZipEntry(n => n == "AndroidManifest.xml" || n == "base/manifest/AndroidManifest.xml" || n.EndsWith(".apk", StringComparison.Ordinal))
            ? new FileView(new { graph = "view=layers joins DEX, native, .NET, Il2Cpp and JS layers by verified edges; offset and limit page the edges" }, [])
            : null;
}
