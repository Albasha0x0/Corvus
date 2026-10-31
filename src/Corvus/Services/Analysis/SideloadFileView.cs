namespace Corvus.Services.Analysis;

/// <summary>view=sideload: an unsigned DLL beside a signed image that imports it, in an archive.</summary>
internal sealed class SideloadFileView : IFileSummaryView
{
    public string Name => "sideload";

    public FileView? Inspect(FileInput file, CancellationToken ct)
    {
        if (file.Streamed || file.Kind is not ("zip" or "7z" or "rar" or "tar")) return null;
        Core.ContainerContents opened;
        try { opened = Core.Containers.Open(file.Bytes, Path.GetFileName(file.Path), Core.AnalysisLimits.Default, ct, allFiles: true); }
        catch (Core.ToolError) { return null; }
        var (hits, notes) = SideloadReview.Scan(opened.Items.Select(i => new SideloadMember(i.Name, () => i.Bytes, null)), ct);
        return SideloadReview.View(hits, notes);
    }
}
