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
public sealed class NativeEditTools(AssemblyWorkspace workspace, NativeCodeService code, NativeEditService edits, EditJournal? journal = null)
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
            if (n < index.Image.SizeOfImage && index.FunctionByStart((uint)n) != null) return [new((uint)n, "function")];
            if (n >= index.Image.ImageBase && n - index.Image.ImageBase < index.Image.SizeOfImage) return [new((uint)(n - index.Image.ImageBase), "function")];
        }
        return index.AddressesOfName(name);
    });

    private const string RelocationsDescription =
        "Base relocations under the patch: auto (default) keeps entries where the new bytes still hold an address, neutralizes the rest and " +
        "adds entries for new absolute addresses in a free slot of the page's block; keep leaves them; neutralize neutralizes all. Reported; " +
        "undo restores them. Ignored with extend=true.";

    private const string ExtendDescription =
        "Place the new code in a stub (a code cave or a new section, see placement): the site becomes a near jump to it and control returns " +
        "after the site. For code larger than the site, or to keep the site intact. Refused with a reason code when unsafe (branch_target_in_site, " +
        "displaced_absolute_reloc, unwind_data, no_space, no_space_at_site, no_header_space, stub_needs_reloc, unreachable_section, arm64_unsupported). One undoable edit.";

    private const string StubModeDescription =
        "With extend=true: replace (default; the new code instead of the displaced instructions), before (new code, then them) or after.";

    private const string PlacementDescription =
        "With extend=true: auto (default; a code cave if one fits, else a new executable section), cave (no_space when none fits) or " +
        "section (always new; header fields and checksum updated, undo restores the file byte-for-byte).";

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
    [Description("Write the image's names and comments as an IDAPython script (ida), a Ghidra script (ghidra) or JSON; the IDA script and JSON also " +
                 "carry the user's engine types (declarations, prototypes, global types, stack variables, locals). Scripts apply by RVA, rebased to the " +
                 "database's image base. header: a C header of declared types, function prototypes by name and externs of typed globals.")]
    public Task<string> ExportNativeAnnotations(
        [Description(NativeTools.ImageDescription)] string image,
        [Description("Output file path.")] string outputPath,
        [Description("ida, ghidra, json (default) or header.")] string? format = null,
        [Description("Replace outputPath if it exists.")] bool overwrite = false,
        RequestContext<CallToolRequestParams> context = null!,
        CancellationToken cancellationToken = default) => OrderedProgress.Run(context, async progress =>
    {
        var (native, index) = await Open(image, progress, cancellationToken);
        var fmt = AnnotationExport.ParseFormat(format);
        var ann = edits.Annotations(native);
        var text = fmt == AnnotationExport.Format.Header
            ? AnnotationHeader.Render(ann, index.NameAt, rva => index.FunctionByStart(rva) != null)
            : AnnotationExport.Render(ann, fmt);
        var target = SafeFile.WriteAllText(outputPath, text, overwrite);
        return $"Exported {ann.NameCount} name(s), {ann.CommentCount} comment(s) and {ann.UserTypes.Count} user type(s) to {target} ({fmt} format)" +
               (fmt == AnnotationExport.Format.Ghidra && ann.UserTypes.Count > 0 ? "; user types are not in Ghidra scripts." : ".");
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
        [Description(PlacementDescription)] string? placement = null,
        RequestContext<CallToolRequestParams> context = null!,
        CancellationToken cancellationToken = default) => OrderedProgress.Run(context, async progress =>
    {
        var (native, index) = await Open(image, progress, cancellationToken);
        var rva = Address(index, address);
        var bytes = ParseHex(hex);
        if (extend)
        {
            var extended = edits.PrepareExtendedPatch(index, rva, bytes, null, PatchExtension.ParseMode(stubMode), $"patch_bytes {bytes.Length} bytes (stub)", null, PatchExtension.ParsePlacement(placement));
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
        [Description(PlacementDescription)] string? placement = null,
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
            var extended = edits.PrepareExtendedPatch(index, rva, newBytes, assembly, PatchExtension.ParseMode(stubMode), "patch_asm (stub)", resolve, PatchExtension.ParsePlacement(placement));
            return edits.ApplyPatch(native, index, extended, dryRun);
        }
        var mode = NativeEditService.ParseRelocationMode(relocations);
        var result = X86Assembler.Assemble(index.Image.Arch, startVa, assembly, resolve);
        var prepared = edits.PreparePatch(index, rva, result.Bytes, force, "patch_asm", mode, result.Constants, assembly);
        return edits.ApplyPatch(native, index, prepared, dryRun);
    });

    [McpServerTool(Name = "list_native_edits", Title = "List native byte patches")]
    [Description("The in-memory byte patches of a native image, numbered; undo_native_edit reverts by number and save_native writes them to a file. " +
                 "Then the names by source: the user's (rename_native / comment_native) and each imported layer (pdb, il2cpp, ida) with counts, origin, " +
                 "source file and identity, and whether it was saved or restored from the saved copy when the image loaded (with the import time).")]
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
                 "Writes atomically, never overwrites without overwrite=true (the original, also through a link, is backed up to .bak; one changed on disk " +
                 "since load is refused), and verifies the written file before it replaces the target by re-parsing and comparing " +
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
        var report = edits.Save(native, outputPath, overwrite, stripSignature);
        journal?.Saved(native);
        return report;
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
