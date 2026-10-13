using System.ComponentModel;
using ModelContextProtocol;
using ModelContextProtocol.Protocol;
using ModelContextProtocol.Server;
using Corvus.Core;
using Corvus.Native;
using Corvus.Native.Code;
using Corvus.Native.Diff;
using Corvus.Native.Patching;
using Corvus.Services;
using static Corvus.Tools.ToolSupport;

namespace Corvus.Tools;

/// <summary>A native image's byte patches outside the session: export for IDA / patchers, and migration to a new build.</summary>
[McpServerToolType]
public sealed class NativePatchTools(AssemblyWorkspace workspace, NativeCodeService code, NativeEditService edits, EditJournal? journal = null)
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
        return Targets.Native(workspace, image);
    }, ct);

    [McpServerTool(Name = "export_native_patches", Title = "Export native patches", UseStructuredContent = true)]
    [Description("Write the image's in-memory byte patches for other tools: ida an IDAPython script (each patch at its rebased RVA, only where " +
                 "the original bytes are found), dif IDA's .dif, ips (file offsets below 16 MB) or ips32, json the full patch set (migrate_native_patches " +
                 "reads it). Relocation edits and the PE checksum are included, so a .dif or IPS applied to the original gives save_native's bytes.")]
    public async Task<PatchExportReport> ExportNativePatches(
        [Description(NativeTools.ImageDescription)] string image,
        [Description("Output file path.")] string outputPath,
        [Description("Default json.")] string? format = null,
        [Description("Replace outputPath if it exists.")] bool overwrite = false,
        CancellationToken cancellationToken = default)
    {
        var fmt = PatchExport.ParseFormat(format);
        if (string.IsNullOrWhiteSpace(outputPath)) throw new ToolError(ErrorCode.InvalidArgument, "An output path is required.");
        var native = await Resolve(image, cancellationToken);
        var result = await Task.Run(() => workspace.Read(() => NativeEditService.RenderPatches(native, fmt)), cancellationToken);

        var target = SafeFile.WriteAllBytes(outputPath, result.Content, overwrite);
        return new PatchExportReport(native.Id, target, PatchExport.Name(fmt), result.Patches, result.RelocationEdits, result.ChangedBytes, result.Records,
            result.ChecksumUpdated, result.Content.Length, native.OriginalSha256, result.Notes);
    }

    public sealed record MigrationPatchEntry(
        int Number,
        string OldAddress,
        [property: Description("The mapped address in the new build, or null when it did not map.")] string? NewAddress,
        [property: Description("asm (re-assembled at the new address) or bytes (applied verbatim).")] string Origin,
        string Description,
        [property: Description("applied, would_apply (dryRun) or refused.")] string Status,
        [property: Description("Why refused: function_not_matched, ambiguous, changed_region, original_bytes_differ, assemble_failed, relocation_slot_unavailable, mid_instruction, past_function_end, conflicts_with_existing_patch, not_mapped, extended_patch, cannot_prepare; 'mapped' when applied.")] string Reason,
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
    [Description("Carry byte patches from an old build to a new one through the build matcher (compare_native_images). A patch is reapplied " +
                 "only where the new build's original bytes at the mapped address match what it expected (patch_asm patches ignore relocated and " +
                 "displacement bytes and are re-assembled there), through the normal patch path; each is reported applied or refused with a reason " +
                 "code. The same image as old and new with patchSet replays a patch set on its own build (an export, or an unsaved session's journal).")]
    public async Task<MigrationPatchReport> MigrateNativePatches(
        [Description("The old build: native image id or path (its in-memory patches are the source unless patchSet).")] string oldImage,
        [Description("The new build: native image id or path (load both; the second gets an id like name#2).")] string newImage,
        [Description("A JSON patch set (export_native_patches format=json): path or text.")] string? patchSet = null,
        [Description(DryRunDescription)] bool dryRun = true,
        [Description("Match functions by export, PDB, Il2Cpp and user names first; false: code only.")] bool useNames = true,
        [Description("Entries to skip in the report.")] int offset = 0,
        [Description("Entries to return (max 5000).")] int limit = 200,
        CancellationToken cancellationToken = default)
    {
        var oldNative = await Resolve(oldImage, cancellationToken);
        var newNative = await Resolve(newImage, cancellationToken);
        bool sameBuild = ReferenceEquals(oldNative, newNative);
        if (sameBuild && string.IsNullOrWhiteSpace(patchSet))
            throw new ToolError(ErrorCode.InvalidArgument, $"Both arguments name {oldNative.Id}.",
                "load the other build too and pass its id (e.g. name#2), or pass patchSet to replay a patch set on this build");
        var oldIndex = await code.Index(oldNative, null, cancellationToken);
        var newIndex = await code.Index(newNative, null, cancellationToken);
        if (oldIndex.Support != CodeSupport.Full || newIndex.Support != CodeSupport.Full)
            throw new ToolError(ErrorCode.Unsupported, "Patch migration needs x86, x64 or ARM64 code on both builds.");
        if (oldIndex.Image.Arch != newIndex.Image.Arch)
            throw new ToolError(ErrorCode.Unsupported, $"{oldNative.Id} is {oldIndex.Image.Arch} and {newNative.Id} is {newIndex.Image.Arch}; builds for different architectures are not migrated.");

        List<MigratablePatch> patches;
        string source;
        if (!string.IsNullOrWhiteSpace(patchSet))
        {
            var json = await ReadPatchSet(patchSet, cancellationToken);
            patches = PatchMigration.FromJson(json);
            source = File.Exists(patchSet.Trim()) ? Path.GetFullPath(patchSet.Trim()) : "json";
            if (sameBuild && PatchMigration.ImageSha256(json) is { } made && !made.Equals(newNative.OriginalSha256, StringComparison.OrdinalIgnoreCase))
                throw new ToolError(ErrorCode.Conflict, $"The patch set was made for sha256 {made}; {newNative.Id} is sha256 {newNative.OriginalSha256}.",
                    "load the build it was made for as oldImage and pass this build as newImage to migrate it");
        }
        else
        {
            patches = workspace.Read(() => oldNative.Patches.Patches.Select(PatchMigration.From).ToList());
            source = "in_memory";
        }

        // Current new index used by the prepare path; it is rebuilt after each applied patch so later patches see earlier ones.
        var currentNew = newIndex;
        string origin = sameBuild ? "replayed" : "migrated";
        NativeEditService.PatchResult Prepare(NativeCodeIndex index, uint rva, byte[] replacement, string? assembly) =>
            edits.PreparePatch(index, rva, replacement, force: false, assembly != null ? $"patch_asm ({origin})" : $"patch_bytes ({origin})", RelocationMode.Auto, assembled: null, assembly: assembly);

        List<PatchMigrationStep> steps;
        IReadOnlyList<string> matchNotes = [];
        if (sameBuild)
            steps = await Task.Run(() => PatchMigration.PlanSameBuild(newIndex, patches, (rva, repl, asm) => Prepare(currentNew, rva, repl, asm), cancellationToken), cancellationToken);
        else
        {
            // Match the clean old build: in-memory patches would otherwise hide a patched function's identity.
            var matchOld = oldNative.HasPatches ? await Task.Run(() => code.IndexOfOriginal(oldNative, cancellationToken), cancellationToken) : oldIndex;
            var options = new MatchOptions { UseNames = useNames };
            var match = await Task.Run(() => MatchCache.Get(matchOld, newIndex, options, cancellationToken), cancellationToken);
            matchNotes = match.Notes;
            steps = await Task.Run(() => PatchMigration.Plan(match, patches, (rva, repl, asm) => Prepare(currentNew, rva, repl, asm), cancellationToken), cancellationToken);
        }

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
                    updated.Add(step with { Apply = false, Status = "refused", Reason = MigrationReasons.PatchRefusal(ex), Detail = ex.Message, NewReplacement = null });
                }
            }
            steps = updated;
        }

        var notes = new List<string>(matchNotes);
        if (!dryRun && applied > 0 && source != "in_memory" && source != "json") journal?.Replayed(source);
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

    private static async Task<string> ReadPatchSet(string patchSet, CancellationToken ct)
    {
        var trimmed = patchSet.Trim();
        if (trimmed.StartsWith('{')) return patchSet;
        if (!Path.IsPathFullyQualified(trimmed) || !File.Exists(trimmed))
            throw new ToolError(ErrorCode.InvalidArgument, $"patchSet is neither JSON text nor an existing file path ({patchSet}).", "pass a file written by export_native_patches with format=json, or its JSON text");
        return await File.ReadAllTextAsync(trimmed, ct);
    }
}
