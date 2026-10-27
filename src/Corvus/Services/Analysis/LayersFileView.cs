namespace Corvus.Services.Analysis;

/// <summary>view=layers: an Android package's code layers and verified edges; the graph is built only when the view is asked for.</summary>
internal sealed class LayersFileView : IFileSummaryView
{
    public string Name => "layers";

    public FileView? Inspect(FileInput file, CancellationToken ct) =>
        file.Kind == "zip" && file.HasZipEntry(n => n == "AndroidManifest.xml" || n == "base/manifest/AndroidManifest.xml" || n.EndsWith(".apk", StringComparison.Ordinal))
            ? new FileView(new { graph = "view=layers joins DEX, native, .NET, AOT and JS layers by verified edges; offset and limit page the edges" }, [])
            : null;
}
