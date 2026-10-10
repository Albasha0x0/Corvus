using System.ComponentModel;
using ModelContextProtocol;
using ModelContextProtocol.Protocol;
using ModelContextProtocol.Server;
using NetDecompilerMcp.Core;
using NetDecompilerMcp.Native.Patching;
using NetDecompilerMcp.Services;

namespace NetDecompilerMcp.Tools;

/// <summary>A native image's byte patches outside the session: export for IDA / patchers, and migration to a new build.</summary>
[McpServerToolType]
public sealed class NativePatchTools(AssemblyWorkspace workspace)
{
    public sealed record PatchExportReport(
        string Image,
        string OutputPath,
        [property: Description("ida, dif, ips, ips32 or json.")] string Format,
        [property: Description("Patches exported.")] int Patches,
        [property: Description("Relocation-table entry rewrites exported (2-byte edits in .reloc).")] int RelocationEdits,
        [property: Description("File bytes that differ from the original (patches, relocation edits and the PE checksum).")] int ChangedBytes,
        [property: Description("Entries in the script (ida), changed-byte lines (dif), records (ips) or patches (json).")] int Records,
        [property: Description("The recomputed PE checksum is part of the export (the original had a non-zero checksum).")] bool ChecksumUpdated,
        long Bytes,
        [property: Description("SHA-256 of the original file the patches apply to.")] string OriginalSha256,
        IReadOnlyList<string> Notes);

    private Task<LoadedNative> Resolve(string image, CancellationToken ct) => Task.Run(() =>
    {
        var id = workspace.Read(() => workspace.FindNative(image)?.Id);
        if (id == null && !string.IsNullOrWhiteSpace(image) && Path.IsPathFullyQualified(image.Trim()) && File.Exists(image.Trim()))
            id = workspace.LoadAny(image.Trim()).Native?.Id ?? throw new ToolError(ErrorCode.Unsupported, $"{image} is a .NET assembly, not a native image.", "use the .NET tools for it");
        return workspace.Read(() => workspace.GetNative(id ?? image));
    }, ct);

    [McpServerTool(Name = "export_native_patches", Title = "Export native patches", Destructive = false, Idempotent = true, OpenWorld = false, UseStructuredContent = true)]
    [Description("Write the image's in-memory byte patches for other tools: format=ida an IDAPython script (applies each patch at its RVA rebased to the " +
                 "database's image base, only where the original bytes are found, and prints a summary), dif IDA's .dif (file offsets, 'orig new' per " +
                 "changed byte), ips (file offsets below 16 MB) or ips32, json the full patch set (original bytes, assembly text, relocation edits, file " +
                 "hash; migrate_native_patches reads it). Relocation-table entry rewrites and the recomputed PE checksum are exported too, so a .dif or " +
                 "IPS applied to the original file gives exactly the bytes save_native writes.")]
    public async Task<PatchExportReport> ExportNativePatches(
        [Description(NativeTools.ImageDescription)] string image,
        [Description("Output file path.")] string outputPath,
        [Description("ida, dif, ips, ips32 or json (default json).")] string? format = null,
        CancellationToken cancellationToken = default)
    {
        var fmt = PatchExport.ParseFormat(format);
        if (string.IsNullOrWhiteSpace(outputPath)) throw new ToolError(ErrorCode.InvalidArgument, "An output path is required.");
        var native = await Resolve(image, cancellationToken);
        var result = await Task.Run(() => workspace.Read(() =>
        {
            var notes = new List<string>();
            var output = NativeEditService.OutputBytes(native, stripSignature: false, notes);
            var original = native.Patches.OriginalBytes();
            var pe = native.Image;
            var source = new PatchExportSource(native.FilePath, native.OriginalSha256, pe.ImageBase, pe.Arch, native.Patches.Patches.ToList(), original, output,
                pe.OptionalHeaderOffset + 64, offset => pe.TryFileOffsetToRva(offset, out var rva) ? rva : null);
            var rendered = PatchExport.Render(source, fmt);
            rendered.Notes.InsertRange(0, notes.Where(n => n.StartsWith("The file is Authenticode-signed", StringComparison.Ordinal)));
            return rendered;
        }), cancellationToken);

        var target = Path.GetFullPath(outputPath);
        Directory.CreateDirectory(Path.GetDirectoryName(target)!);
        var temp = target + ".tmp-" + Environment.ProcessId;
        try
        {
            await File.WriteAllBytesAsync(temp, result.Content, cancellationToken);
            File.Move(temp, target, overwrite: true);
        }
        finally { if (File.Exists(temp)) File.Delete(temp); }
        return new PatchExportReport(native.Id, target, PatchExport.Name(fmt), result.Patches, result.RelocationEdits, result.ChangedBytes, result.Records,
            result.ChecksumUpdated, result.Content.Length, native.OriginalSha256, result.Notes);
    }
}
