using NetDecompilerMcp.Native.Pe;

namespace NetDecompilerMcp.Native.MachO;

public sealed partial class MachOFile
{
    private ImageArea<CodeSignature?> signatureArea = null!;

    /// <summary>The embedded code signature (LC_CODE_SIGNATURE), or null when the image has none.</summary>
    public CodeSignature? CodeSignature => signatureArea.Value;

    private void InitAreas()
    {
        symbolArea = new("symbols", ParseSymbols, SymbolInfo.Empty);
        fixupArea = new("fixups", ParseFixups, FixupInfo.Empty);
        exportArea = new("exports", ParseExports, ExportInfo.Empty);
        unwindArea = new("unwind", ParseUnwind, UnwindInfo.Empty);
        signatureArea = new("code signature", ParseSignature, null);
    }

    private CodeSignature? ParseSignature(IssueLog log) =>
        commands.OfType<MachOLinkEditCommand>().FirstOrDefault(c => c.Command == 0x1D) is { } lc
            ? CodeSignature.Parse(FileWindow(lc.DataOffset, lc.DataSize), log)
            : null;
}
