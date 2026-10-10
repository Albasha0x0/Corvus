using System.ComponentModel;
using ModelContextProtocol;
using ModelContextProtocol.Protocol;
using ModelContextProtocol.Server;
using NetDecompilerMcp.Core;
using NetDecompilerMcp.Native;
using NetDecompilerMcp.Native.Code;
using NetDecompilerMcp.Native.Diff;
using NetDecompilerMcp.Native.Patching;
using NetDecompilerMcp.Services;
using static NetDecompilerMcp.Tools.ToolSupport;

namespace NetDecompilerMcp.Tools;

/// <summary>A native image's byte patches outside the session: export for IDA / patchers, and migration to a new build.</summary>
[McpServerToolType]
public sealed class NativePatchTools(AssemblyWorkspace workspace, NativeCodeService code, NativeEditService edits)
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

    [McpServerTool(Name = "export_native_patches", Title = "Export native patches", UseStructuredContent = true)]
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

    // ---- migration ----

    public sealed record MigrationPatchEntry(
        int Number,
        string OldAddress,
        [property: Description("The mapped address in the new build, or null when it did not map.")] string? NewAddress,
        [property: Description("asm (re-assembled at the new address) or bytes (applied verbatim).")] string Origin,
        string Description,
        [property: Description("applied, would_apply (dryRun) or refused.")] string Status,
        [property: Description("Why refused: function_not_matched, ambiguous, changed_region, original_bytes_differ, assemble_failed, relocation_slot_unavailable, mid_instruction, past_function_end, conflicts_with_existing_patch, not_mapped, cannot_prepare; 'mapped' when applied.")] string Reason,
        string Detail,
        [property: Description("Mapping confidence 0-1.")] double Confidence,
        [property: Description("The function-match tier that carried the address (1 best .. 5 fuzzy), or null.")] int? Tier,
        [property: Description("The replacement bytes at the new address (re-assembled for patch_asm), hex; null when refused.")] string? ReplacementBytes);

    public sealed record ReasonCount(string Reason, int Count);

    public sealed record MigrationPatchReport(
        string OldImage,
        string NewImage,
        [property: Description("Where the patches came from: in_memory or the json file path.")] string Source,
        bool DryRun,
        int Patches,
        [property: Description("Patches applied (0 when dryRun).")] int Applied,
        [property: Description("Patches that would apply (dryRun).")] int WouldApply,
        int Refused,
        IReadOnlyList<ReasonCount> RefusedBy,
        int Offset, int Total, bool Truncated,
        IReadOnlyList<MigrationPatchEntry> Entries,
        [property: Description("What was not covered (functions that did not decode, capped work).")] IReadOnlyList<string> Notes);

    [McpServerTool(Name = "migrate_native_patches", Title = "Migrate patches to a new build", UseStructuredContent = true)]
    [Description("Carry byte patches from an old build to a new build. Each patch's old address is found in the new build through the build matcher " +
                 "(compare_native_images: function match + instruction alignment). A patch is reapplied only where the new build's ORIGINAL bytes at the " +
                 "mapped address match what the patch expected — exact for raw patch_bytes, ignoring relocated / RIP-relative / branch-displacement bytes for " +
                 "patch_asm patches (whose replacement is re-assembled at the new address). Survivors go through the normal patch path (safety checks and " +
                 "relocations). Every patch is reported applied or refused with a reason code and evidence. Source: the old build's in-memory patches " +
                 "(default) or an exported json (patchSet). dryRun shows everything without changing the new build.")]
    public async Task<MigrationPatchReport> MigrateNativePatches(
        [Description("The old build: native image id or path (its in-memory patches are the source unless patchSet is given).")] string oldImage,
        [Description("The new build: native image id or path. Load both builds; the second gets an id like name#2.")] string newImage,
        [Description("A patch set exported by export_native_patches (format=json): a file path or the JSON text. Omit to use the old build's in-memory patches.")] string? patchSet = null,
        [Description(DryRunDescription + " Default true: preview before changing the new build.")] bool dryRun = true,
        [Description("Match functions by names (exports, PDB, Il2Cpp, user); false matches on code alone.")] bool useNames = true,
        [Description("Entries to skip in the report.")] int offset = 0,
        [Description("Entries to return (default 200, max 5000).")] int limit = 200,
        CancellationToken cancellationToken = default)
    {
        var oldNative = await Resolve(oldImage, cancellationToken);
        var newNative = await Resolve(newImage, cancellationToken);
        if (ReferenceEquals(oldNative, newNative))
            throw new ToolError(ErrorCode.InvalidArgument, $"Both arguments name {oldNative.Id}.", "load the other build too and pass its id (e.g. name#2)");
        var oldIndex = await code.Index(oldNative, null, cancellationToken);
        var newIndex = await code.Index(newNative, null, cancellationToken);
        if (oldIndex.Support != CodeSupport.Full || newIndex.Support != CodeSupport.Full)
            throw new ToolError(ErrorCode.Unsupported, "Patch migration needs x86 or x64 code on both builds.");
        if (oldIndex.Image.Arch != newIndex.Image.Arch)
            throw new ToolError(ErrorCode.Unsupported, $"{oldNative.Id} is {oldIndex.Image.Arch} and {newNative.Id} is {newIndex.Image.Arch}; builds for different architectures are not migrated.");

        List<MigratablePatch> patches;
        string source;
        if (!string.IsNullOrWhiteSpace(patchSet))
        {
            var json = await ReadPatchSet(patchSet, cancellationToken);
            patches = PatchMigration.FromJson(json);
            source = File.Exists(patchSet.Trim()) ? Path.GetFullPath(patchSet.Trim()) : "json";
        }
        else
        {
            patches = workspace.Read(() => oldNative.Patches.Patches.Select(PatchMigration.From).ToList());
            source = "in_memory";
        }

        // Match the clean old build: in-memory patches would otherwise hide a patched function's identity.
        var matchOld = oldNative.HasPatches ? await Task.Run(() => code.IndexOfOriginal(oldNative, cancellationToken), cancellationToken) : oldIndex;
        var options = new MatchOptions { UseNames = useNames };
        var match = await Task.Run(() => MatchCache.Get(matchOld, newIndex, options, cancellationToken), cancellationToken);

        // Current new index used by the prepare path; it is rebuilt after each applied patch so later patches see earlier ones.
        var currentNew = newIndex;
        NativeEditService.PatchResult Prepare(NativeCodeIndex index, uint rva, byte[] replacement, string? assembly) =>
            edits.PreparePatch(index, rva, replacement, force: false, assembly != null ? "patch_asm (migrated)" : "patch_bytes (migrated)", RelocationMode.Auto, assembled: null, assembly: assembly);

        var steps = await Task.Run(() => PatchMigration.Plan(match, patches, (rva, repl, asm) => Prepare(currentNew, rva, repl, asm), cancellationToken), cancellationToken);

        int applied = 0;
        if (!dryRun)
        {
            var updated = new List<PatchMigrationStep>(steps.Count);
            foreach (var step in steps)
            {
                cancellationToken.ThrowIfCancellationRequested();
                if (!step.Apply || step.NewRva is not { } rva || step.NewReplacement is not { } repl) { updated.Add(step); continue; }
                try
                {
                    var prepared = Prepare(currentNew, rva, repl, step.Patch.Assembly);
                    edits.ApplyPatch(newNative, currentNew, prepared, dryRun: false);
                    currentNew = await code.Index(newNative, null, cancellationToken);
                    applied++;
                    updated.Add(step with { Status = "applied" });
                }
                catch (ToolError ex)
                {
                    updated.Add(step with { Apply = false, Status = "refused", Reason = ReasonFor(ex), Detail = ex.Message, NewReplacement = null });
                }
            }
            steps = updated;
        }

        var notes = new List<string>(match.Notes);
        if (patches.Count == 0) notes.Add(source == "in_memory" ? $"{oldNative.Id} has no in-memory patches to migrate" : "the patch set has no patches");
        if (source == "in_memory" && patches.Count > 0 && newNative.Patches.IsDirty && dryRun)
            notes.Add("the new build already has patches; migrated patches that conflict with them are refused");

        int wouldApply = dryRun ? steps.Count(s => s.Apply) : 0;
        int refused = steps.Count(s => !s.Apply);
        var refusedBy = steps.Where(s => !s.Apply).GroupBy(s => s.Reason).Select(g => new ReasonCount(g.Key, g.Count())).OrderByDescending(r => r.Count).ToList();

        offset = Math.Max(0, offset);
        limit = ClampLimit(limit, 5000);
        var o = oldIndex;
        var entries = steps.Select((s, i) => (s, i)).Skip(offset).Take(limit).Select(t => new MigrationPatchEntry(
            t.i + 1, NativeAddress.Va(o.Image, t.s.Patch.Rva), t.s.NewRva is { } r ? NativeAddress.Va(newIndex.Image, r) : null,
            t.s.Patch.FromAsm ? "asm" : "bytes", t.s.Patch.Description,
            t.s.Status == "apply" ? (dryRun ? "would_apply" : "refused") : t.s.Status,
            t.s.Reason, t.s.Detail, Math.Round(t.s.Confidence, 3), t.s.Tier,
            t.s.NewReplacement is { } nr ? Convert.ToHexString(nr) : null)).ToList();

        return new MigrationPatchReport(oldNative.Id, newNative.Id, source, dryRun, patches.Count, applied, wouldApply, refused, refusedBy,
            offset, steps.Count, offset + limit < steps.Count, entries, notes);
    }

    private static string ReasonFor(ToolError ex) =>
        ex.Message.Contains("relocation slot", StringComparison.OrdinalIgnoreCase) ? "relocation_slot_unavailable"
        : ex.Message.Contains("middle of an instruction", StringComparison.OrdinalIgnoreCase) ? "mid_instruction"
        : ex.Message.Contains("past the end", StringComparison.OrdinalIgnoreCase) ? "past_function_end"
        : ex.Code == ErrorCode.Conflict ? "conflicts_with_existing_patch"
        : "cannot_prepare";

    private static async Task<string> ReadPatchSet(string patchSet, CancellationToken ct)
    {
        var trimmed = patchSet.Trim();
        if (trimmed.StartsWith('{')) return patchSet;
        if (!Path.IsPathFullyQualified(trimmed) || !File.Exists(trimmed))
            throw new ToolError(ErrorCode.InvalidArgument, $"patchSet is neither JSON text nor an existing file path ({patchSet}).", "pass a file written by export_native_patches with format=json, or its JSON text");
        return await File.ReadAllTextAsync(trimmed, ct);
    }
}
