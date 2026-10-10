using System.ComponentModel;
using ModelContextProtocol;
using ModelContextProtocol.Protocol;
using ModelContextProtocol.Server;
using NetDecompilerMcp.Core;
using NetDecompilerMcp.Native;
using NetDecompilerMcp.Native.Annotations;
using NetDecompilerMcp.Native.Code;
using NetDecompilerMcp.Native.Patching;
using NetDecompilerMcp.Services;

namespace NetDecompilerMcp.Tools;

/// <summary>Native annotations (rename, comment, export) and byte/assembly patching with undo and save.</summary>
[McpServerToolType]
public sealed class NativeEditTools(AssemblyWorkspace workspace, NativeCodeService code, NativeEditService edits)
{
    private async Task<(LoadedNative Native, NativeCodeIndex Index)> Open(string image, IProgress<ProgressNotificationValue> progress, CancellationToken ct)
    {
        var native = await Task.Run(() =>
        {
            var id = workspace.Read(() => workspace.FindNative(image)?.Id);
            if (id == null && !string.IsNullOrWhiteSpace(image) && Path.IsPathFullyQualified(image.Trim()) && File.Exists(image.Trim()))
                id = workspace.LoadAny(image.Trim()).Native?.Id ?? throw new ToolError(ErrorCode.Unsupported, $"{image} is a .NET assembly, not a native image.", "use the .NET tools for it");
            return workspace.Read(() => workspace.GetNative(id ?? image));
        }, ct);
        var index = await code.Index(native, new Progress<CodeIndexProgress>(p =>
            progress.Report(new ProgressNotificationValue { Progress = p.Done, Total = p.Total > 0 ? p.Total : null, Message = $"indexing {native.Id}: {p.Phase}" })), ct);
        return (native, index);
    }

    private static uint Address(NativeCodeIndex index, string text) => NativeAddress.Parse(index.Image, text, name =>
    {
        if (name.StartsWith("sub_", StringComparison.OrdinalIgnoreCase) && NativeAddress.Number(name[4..]) is { } n)
        {
            if (n < index.Image.SizeOfImage && index.FunctionByStart((uint)n) != null) return (uint)n;
            if (n >= index.Image.ImageBase && n - index.Image.ImageBase < index.Image.SizeOfImage) return (uint)(n - index.Image.ImageBase);
        }
        return index.AddressOfName(name);
    });

    private const string RelocationsDescription =
        "Base relocations under the patch (the loader adds the load delta to each under ASLR / rebasing): auto (default) keeps an entry " +
        "where the new bytes still hold an address, neutralizes the rest (type ABSOLUTE) and adds entries for new absolute addresses by " +
        "reusing an ABSOLUTE slot of the page's relocation block; keep leaves every entry as it is; neutralize neutralizes every entry " +
        "under the patch. The report lists kept / neutralized / added entries; undo restores them. Ignored when extend=true.";

    private const string ExtendDescription =
        "When the new code is larger than a single in-place patch allows (or always, to keep the original site intact), place a relocation " +
        "stub in slack space: the site becomes a 5-byte jump to a file-backed code cave holding the new code, and control returns to the " +
        "instruction after the site. Refused with a reason code (branch_target_in_site, displaced_absolute_reloc, unwind_data, no_space, " +
        "no_space_at_site, arm64_unsupported) when unsafe. The stub is one undoable edit, exported and saved with the patch.";

    private const string StubModeDescription =
        "With extend=true, how the stub runs the new code relative to the site's displaced instructions: replace (default; the new code " +
        "runs instead of them), before (new code then the displaced originals), after (the displaced originals then the new code).";

    [McpServerTool(Name = "rename_native", Title = "Name a native address")]
    [Description("Give a name to a native address (a function start, or any address): the name shows up in list_functions, disassemble (labels and " +
                 "call targets), find_xrefs and native_call_tree, and is saved to a per-user sidecar keyed by the file's SHA-256, so it survives reloads " +
                 "and restarts. Names are C-identifier-like (<=255 chars) and unique unless allowDuplicate=true. An empty name clears it.")]
    public Task<string> RenameNative(
        [Description(NativeTools.ImageDescription)] string image,
        [Description(NativeTools.AddressDescription)] string address,
        [Description("The new name; empty to clear the name at this address.")] string name,
        [Description("Allow a name already used at another address.")] bool allowDuplicate = false,
        RequestContext<CallToolRequestParams> context = null!,
        CancellationToken cancellationToken = default) => OrderedProgress.Run(context, async progress =>
    {
        var (native, index) = await Open(image, progress, cancellationToken);
        var rva = Address(index, address);
        return string.IsNullOrWhiteSpace(name) ? edits.ClearName(native, index, rva) : edits.Rename(native, index, rva, name, allowDuplicate);
    });

    [McpServerTool(Name = "comment_native", Title = "Comment a native address")]
    [Description("Attach a comment to a native address; it shows up next to disassembly that references the address and is saved to the per-user sidecar " +
                 "keyed by the file's SHA-256 (so it survives reloads and restarts). An empty text clears the comment.")]
    public Task<string> CommentNative(
        [Description(NativeTools.ImageDescription)] string image,
        [Description(NativeTools.AddressDescription)] string address,
        [Description("The comment text; empty to clear it.")] string text,
        RequestContext<CallToolRequestParams> context = null!,
        CancellationToken cancellationToken = default) => OrderedProgress.Run(context, async progress =>
    {
        var (native, index) = await Open(image, progress, cancellationToken);
        return edits.Comment(native, index, Address(index, address), text);
    });

    [McpServerTool(Name = "export_native_annotations", Title = "Export native annotations")]
    [Description("Write the image's names and comments as an IDAPython script (format=ida), a Ghidra script (format=ghidra) or JSON (format=json). " +
                 "Scripts apply by RVA rebased to the database's own image base at run time.")]
    public Task<string> ExportNativeAnnotations(
        [Description(NativeTools.ImageDescription)] string image,
        [Description("Output file path.")] string outputPath,
        [Description("ida, ghidra or json (default json).")] string? format = null,
        RequestContext<CallToolRequestParams> context = null!,
        CancellationToken cancellationToken = default) => OrderedProgress.Run(context, async progress =>
    {
        var (native, _) = await Open(image, progress, cancellationToken);
        var fmt = AnnotationExport.ParseFormat(format);
        var ann = edits.Annotations(native);
        var text = AnnotationExport.Render(ann, fmt);
        var target = Path.GetFullPath(outputPath);
        Directory.CreateDirectory(Path.GetDirectoryName(target)!);
        await File.WriteAllTextAsync(target, text, cancellationToken);
        return $"Exported {ann.NameCount} name(s) and {ann.CommentCount} comment(s) to {target} ({fmt} format).";
    });

    [McpServerTool(Name = "patch_bytes", Title = "Patch native bytes")]
    [Description("Replace bytes at a native address with a hex string, in memory. The patch is recorded as an undoable edit and every read path " +
                 "(disassemble, strings, search_bytes, read_bytes) then sees the patched bytes. Over code, trailing bytes of a partly overwritten " +
                 "instruction are padded with NOPs; the patch is refused if it would start mid-instruction, run past the function end or hit " +
                 "zero-fill/header bytes, unless force=true. Base relocations under the patch are planned (see relocations). dryRun shows the " +
                 "before/after disassembly and the relocation changes without recording it.")]
    public Task<string> PatchBytes(
        [Description(NativeTools.ImageDescription)] string image,
        [Description(NativeTools.AddressDescription)] string address,
        [Description("Replacement bytes as hex (e.g. '90 90' or '9090' or '0x90,0x90').")] string hex,
        [Description("Override the safety checks (mid-instruction, past function end, header bytes, a new address with no free relocation slot).")] bool force = false,
        [Description("Preview only; do not record the patch.")] bool dryRun = false,
        [Description(RelocationsDescription)] string? relocations = null,
        [Description(ExtendDescription)] bool extend = false,
        [Description(StubModeDescription)] string? stubMode = null,
        RequestContext<CallToolRequestParams> context = null!,
        CancellationToken cancellationToken = default) => OrderedProgress.Run(context, async progress =>
    {
        var (native, index) = await Open(image, progress, cancellationToken);
        var rva = Address(index, address);
        var bytes = ParseHex(hex);
        if (extend)
        {
            var extended = edits.PrepareExtendedPatch(index, rva, bytes, null, PatchExtension.ParseMode(stubMode), $"patch_bytes {bytes.Length} bytes (stub)", null);
            return edits.ApplyPatch(native, index, extended, dryRun);
        }
        var mode = NativeEditService.ParseRelocationMode(relocations);
        var prepared = edits.PreparePatch(index, rva, bytes, force, $"patch_bytes {bytes.Length} bytes", mode);
        return edits.ApplyPatch(native, index, prepared, dryRun);
    });

    [McpServerTool(Name = "patch_asm", Title = "Assemble and patch native code")]
    [Description("Assemble x86/x64 instructions (multi-line; labels, numeric and symbol branch targets; a 'db <hex>' escape) and write them at a " +
                 "native address, in memory. Branch displacements and RIP-relative references are computed for the target address. Same safety rules " +
                 "and NOP padding as patch_bytes; the patch is recorded as an undoable edit. Absolute addresses (x86 [addr] operands, 'offset name' / " +
                 "symbol immediates, x64 imm64 addresses) get base relocations and overwritten ones are neutralized (see relocations). dryRun shows " +
                 "the before/after disassembly and the relocation changes without recording it.")]
    public Task<string> PatchAsm(
        [Description(NativeTools.ImageDescription)] string image,
        [Description(NativeTools.AddressDescription)] string address,
        [Description("Assembly, one instruction per line (e.g. 'jmp target' with a 'target:' label, or 'mov eax, 1\\nret').")] string assembly,
        [Description("Override the safety checks (mid-instruction, past function end, header bytes, a new address with no free relocation slot).")] bool force = false,
        [Description("Preview only; do not record the patch.")] bool dryRun = false,
        [Description(RelocationsDescription)] string? relocations = null,
        [Description(ExtendDescription)] bool extend = false,
        [Description(StubModeDescription)] string? stubMode = null,
        RequestContext<CallToolRequestParams> context = null!,
        CancellationToken cancellationToken = default) => OrderedProgress.Run(context, async progress =>
    {
        var (native, index) = await Open(image, progress, cancellationToken);
        var rva = Address(index, address);
        ulong startVa = index.Image.ImageBase + rva;
        Func<string, ulong?> resolve = name =>
        {
            try { return index.Image.ImageBase + Address(index, name); }
            catch (ToolError) { return null; }
        };
        if (extend)
        {
            // Assemble the new code at the eventual stub address inside the extension; here only validate it decodes.
            var newBytes = X86Assembler.Assemble(index.Image.Arch, startVa, assembly, resolve).Bytes;
            var extended = edits.PrepareExtendedPatch(index, rva, newBytes, assembly, PatchExtension.ParseMode(stubMode), "patch_asm (stub)", resolve);
            return edits.ApplyPatch(native, index, extended, dryRun);
        }
        var mode = NativeEditService.ParseRelocationMode(relocations);
        var result = X86Assembler.Assemble(index.Image.Arch, startVa, assembly, resolve);
        var prepared = edits.PreparePatch(index, rva, result.Bytes, force, "patch_asm", mode, result.Constants, assembly);
        return edits.ApplyPatch(native, index, prepared, dryRun);
    });

    [McpServerTool(Name = "list_native_edits", Title = "List native byte patches")]
    [Description("The in-memory byte patches of a native image, numbered; undo_native_edit reverts by number and save_native writes them to a file.")]
    public Task<string> ListNativeEdits(
        [Description(NativeTools.ImageDescription)] string image,
        RequestContext<CallToolRequestParams> context = null!,
        CancellationToken cancellationToken = default) => OrderedProgress.Run(context, async progress =>
    {
        var (native, _) = await Open(image, progress, cancellationToken);
        return edits.List(native);
    });

    [McpServerTool(Name = "undo_native_edit", Title = "Undo a native byte patch")]
    [Description("Undo one in-memory byte patch of a native image — the last by default, or any earlier one by number (from list_native_edits).")]
    public Task<string> UndoNativeEdit(
        [Description(NativeTools.ImageDescription)] string image,
        [Description("Patch number (1-based, from list_native_edits). Omit to undo the last.")] int? number = null,
        RequestContext<CallToolRequestParams> context = null!,
        CancellationToken cancellationToken = default) => OrderedProgress.Run(context, async progress =>
    {
        var (native, _) = await Open(image, progress, cancellationToken);
        return edits.Undo(native, number);
    });

    [McpServerTool(Name = "save_native", Title = "Save patched native image")]
    [Description("Write the patched native image to a file. Everything not patched is byte-for-byte identical to the original; the PE checksum is " +
                 "recomputed when the original had one; a signed file becomes unsigned (pass stripSignature=true to remove the certificate table). " +
                 "Writes atomically, never overwrites without overwrite=true (the original is backed up to .bak), and verifies by re-parsing and comparing " +
                 "every byte outside the patched ranges (and the relocation entries the patches rewrote), then re-parses the relocation table and " +
                 "checks that every patched range holds exactly its kept/added entries.")]
    public Task<string> SaveNative(
        [Description(NativeTools.ImageDescription)] string image,
        [Description("Output file path.")] string outputPath,
        [Description("Allow replacing an existing file.")] bool overwrite = false,
        [Description("Remove the Authenticode certificate table from the output.")] bool stripSignature = false,
        RequestContext<CallToolRequestParams> context = null!,
        CancellationToken cancellationToken = default) => OrderedProgress.Run(context, async progress =>
    {
        var (native, _) = await Open(image, progress, cancellationToken);
        return edits.Save(native, outputPath, overwrite, stripSignature);
    });

    private static byte[] ParseHex(string hex)
    {
        var t = (hex ?? "").Replace(",", " ").Replace("0x", " ", StringComparison.OrdinalIgnoreCase).Replace("\\x", " ");
        var compact = new string(t.Where(c => !char.IsWhiteSpace(c)).ToArray());
        if (compact.Length == 0 || compact.Length % 2 != 0 || !compact.All(Uri.IsHexDigit))
            throw new ToolError(ErrorCode.InvalidArgument, $"'{hex}' is not a hex byte string.", "pass bytes as hex, e.g. '90 90' or '9090'");
        var bytes = new byte[compact.Length / 2];
        for (int i = 0; i < bytes.Length; i++) bytes[i] = Convert.ToByte(compact.Substring(i * 2, 2), 16);
        return bytes;
    }
}
