using System.ComponentModel;
using ModelContextProtocol;
using ModelContextProtocol.Protocol;
using ModelContextProtocol.Server;
using Corvus.Core;
using Corvus.Mcp;
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

    [McpServerTool(Name = "export_native_patches", Title = "Export native patches", UseStructuredContent = true, OutputSchemaType = typeof(PatchExportReport))]
    [Description("Write the image's byte patches for other tools: ida an IDAPython script (at rebased RVAs, where the original bytes are found), dif " +
                 "an IDA .dif, ips (offsets below 16 MB) or ips32, json the full set (for migrate_native_patches). Relocation edits and PE checksum " +
                 "included: a .dif or IPS applied to the original gives the save_native bytes.")]
    public async Task<string> ExportNativePatches(
        [Description(NativeTools.ImageDescription)] string image,
        [Description("Output file path.")] string outputPath,
        [Description("Default json.")] string? format = null,
        [Description("Overwrite outputPath.")] bool overwrite = false,
        CancellationToken cancellationToken = default)
    {
        var r = await Export(image, outputPath, format, overwrite, cancellationToken);
        var text = $"Wrote {Plural(r.Patches, "patch")}{(r.RelocationEdits > 0 ? $" and {Plural(r.RelocationEdits, "relocation edit")}" : "")} of {r.Image} as {r.Format} " +
                   $"to {r.OutputPath} ({Plural(r.Records, "record")}, {r.Bytes:N0} bytes; {r.ChangedBytes} changed byte(s){(r.ChecksumUpdated ? " with the PE checksum" : "")}).\n" +
                   (r.Notes.Count > 0 ? "Note: " + string.Join("; ", r.Notes) + "\n" : "");
        return ToolOutput.Report(text, r);
    }

    /// <summary>export_native_patches as a record.</summary>
    internal async Task<PatchExportReport> Export(string image, string outputPath, string? format = null, bool overwrite = false, CancellationToken cancellationToken = default)
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
        string? NewAddress,
        [property: Description("asm (re-assembled at the new address) or bytes (applied verbatim).")] string Origin,
        string Description,
        [property: Description("applied, would_apply (dry run) or refused.")] string Status,
        [property: Description("How it was carried or why not (docs/migration-reasons.md).")] string Reason,
        string Detail,
        double Confidence,
        int? Tier,
        [property: Description("The replacement bytes at the new address, hex (re-assembled for patch_asm).")] string? ReplacementBytes);

    public sealed record ReasonCount(string Reason, int Count);

    public sealed record MigrationPatchReport(
        string OldImage,
        string NewImage,
        [property: Description("in_memory, json or the patch set's path.")] string Source,
        bool DryRun,
        bool Applied,
        [property: Description("The applied patches' edits (undo_native_edit).")] IReadOnlyList<EditId> EditIds,
        int Patches,
        [property: Description("Patches that apply (or would, in a dry run).")] int Carried,
        int Refused,
        IReadOnlyList<ReasonCount> RefusedBy,
        IReadOnlyList<MigrationPatchEntry> Items, int Offset, int Total,
        IReadOnlyList<string> Notes);

    [McpServerTool(Name = "migrate_native_patches", Title = "Migrate patches to a new build", UseStructuredContent = true, OutputSchemaType = typeof(MigrationPatchReport))]
    [Description("Carry byte patches from an old build to a new one via the build match (compare_native_images). A patch is reapplied only where " +
                 "the mapped address holds the original bytes (patch_asm patches re-assembled), else refused with a reason code. Same image " +
                 "as old and new, with patchSet: replays it.")]
    public Task<string> MigrateNativePatches(
        [Description("Old build: image id or path (its in-memory patches are the source unless patchSet).")] string oldImage,
        [Description("New build: image id or path (the second load gets an id like name#2).")] string newImage,
        [Description("A JSON patch set (export_native_patches format=json): path or text.")] string? patchSet = null,
        [Description(DryRunDefaultTrueDescription)] bool dryRun = true,
        [Description(NativeDiffTools.CodeOnlyDescription)] bool codeOnly = false,
        [Description(RowOffsetDescription)] int offset = 0,
        [Description(LimitDescription)] int limit = 100,
        [Description(MaxTokensDescription)] int? maxTokens = null,
        RequestContext<CallToolRequestParams> context = null!,
        CancellationToken cancellationToken = default) => OrderedProgress.Run(context, async progress =>
    {
        var r = await CarryPatches(oldImage, newImage, patchSet, dryRun, codeOnly, new ProgressSpan(progress, 0, 1, 1), cancellationToken);
        var head = new System.Text.StringBuilder();
        string refused = r.Refused == 0 ? "" : $"; {r.Refused} refused ({string.Join(", ", r.RefusedBy.Take(4).Select(x => $"{x.Reason} {x.Count}"))})";
        head.Append(dryRun ? $"Dry run: {r.Carried} of {Plural(r.Patches, "patch")} ({r.Source}) would apply to {r.NewImage}{refused}. Nothing recorded; dryRun=false applies them.\n"
            : $"{r.Carried} of {Plural(r.Patches, "patch")} ({r.Source}) applied to {r.NewImage}{refused}. " +
              (r.EditIds.Count > 0 ? $"Recorded as {string.Join(", ", r.EditIds)} (undo_native_edit editId={r.EditIds[0]}).\n" : "Nothing changed.\n"));
        foreach (var n in r.Notes) head.Append("Note: ").Append(n).Append('\n');
        return ToolOutput.List(r.Items, offset, limit, e =>
                $"#{e.Number} {e.OldAddress} -> {e.NewAddress ?? "-"} {e.Description}: {e.Status}" +
                (e.Status == "refused" ? $", {e.Reason} ({e.Detail})" : $" ({e.Reason}{(e.Tier is { } t ? $", tier {t}" : "")}){(e.ReplacementBytes is { } b ? " " + b : "")}"),
            rows => r with { Items = rows, Offset = offset }, "patch", head.ToString());
    });

    /// <summary>migrate_native_patches without paging (load_session uses it too).</summary>
    internal async Task<MigrationPatchReport> CarryPatches(string oldImage, string newImage, string? patchSet = null, bool dryRun = true, bool codeOnly = false,
        ProgressSpan progress = default, CancellationToken cancellationToken = default)
    {
        var pairs = new BuildPairs(workspace, code);
        var oldNative = await pairs.Resolve(oldImage, cancellationToken);
        var newNative = await pairs.Resolve(newImage, cancellationToken);
        bool sameBuild = ReferenceEquals(oldNative, newNative);
        if (sameBuild && string.IsNullOrWhiteSpace(patchSet))
            throw new ToolError(ErrorCode.InvalidArgument, $"Both arguments name {oldNative.Id}.",
                "load the other build too and pass its id (e.g. name#2), or pass patchSet to replay a patch set on this build");

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

        // the match is on both builds' original bytes; the live new index is rebuilt after each applied patch so later patches see earlier ones
        var pair = sameBuild ? null : await pairs.Match(oldImage, newImage, new MatchOptions { UseNames = !codeOnly }, progress.Part(0, 0.8), cancellationToken);
        var newIndex = pair?.NewIndex ?? (await pairs.Open(newImage, progress.Part(0, 0.8), cancellationToken)).Index;
        var oldIndex = pair?.OldIndex ?? newIndex;
        var currentNew = newIndex;
        string origin = sameBuild ? "replayed" : "migrated";
        NativeEditService.PatchResult Prepare(NativeCodeIndex index, uint rva, byte[] replacement, string? assembly) =>
            edits.PreparePatch(index, rva, replacement, force: false, assembly != null ? $"patch_asm ({origin})" : $"patch_bytes ({origin})", RelocationMode.Auto, assembled: null, assembly: assembly);

        progress.Part(0.8, 0.9).Report(0, "planning");
        var steps = sameBuild
            ? await Task.Run(() => PatchMigration.PlanSameBuild(newIndex, patches, (rva, repl, asm) => Prepare(currentNew, rva, repl, asm), cancellationToken), cancellationToken)
            : await Task.Run(() => PatchMigration.Plan(pair!.Match, patches, (rva, repl, asm) => Prepare(currentNew, rva, repl, asm), cancellationToken), cancellationToken);

        var ids = new List<EditId>();
        if (!dryRun)
        {
            var updated = new List<PatchMigrationStep>(steps.Count);
            foreach (var step in steps)
            {
                cancellationToken.ThrowIfCancellationRequested();
                progress.Part(0.9, 1).Report((double)updated.Count / Math.Max(1, steps.Count), "applying patches");
                if (!step.Apply || step.NewRva is not { } rva || step.NewReplacement is not { } repl) { updated.Add(step); continue; }
                try
                {
                    var prepared = Prepare(currentNew, rva, repl, step.Patch.Assembly);
                    if (edits.Apply(newNative, currentNew, prepared, dryRun: false).EditId is { } id) ids.Add(id);
                    currentNew = await code.Index(newNative, null, cancellationToken);
                    updated.Add(step with { Status = "applied" });
                }
                catch (ToolError ex)
                {
                    updated.Add(step with { Apply = false, Status = "refused", Reason = MigrationReasons.PatchRefusal(ex), Detail = ex.Message, NewReplacement = null });
                }
            }
            steps = updated;
        }

        var notes = sameBuild ? new List<string>() : new List<string>(pair!.Match.Notes);
        if (!dryRun && ids.Count > 0 && source != "in_memory" && source != "json") journal?.Replayed(source);
        if (patches.Count == 0) notes.Add(source == "in_memory" ? $"{oldNative.Id} has no in-memory patches to migrate" : "the patch set has no patches");
        if (source == "in_memory" && patches.Count > 0 && newNative.Patches.IsDirty && dryRun)
            notes.Add("the new build already has patches; migrated patches that conflict with them are refused");

        int carried = steps.Count(s => s.Apply);
        var refusedBy = steps.Where(s => !s.Apply).GroupBy(s => s.Reason).Select(g => new ReasonCount(g.Key, g.Count()))
            .OrderByDescending(r => r.Count).ThenBy(r => r.Reason, StringComparer.Ordinal).ToList();
        var entries = steps.Select((s, i) => new MigrationPatchEntry(
            i + 1, NativeAddress.Va(oldIndex.Image, s.Patch.Rva), s.NewRva is { } r ? NativeAddress.Va(newIndex.Image, r) : null,
            s.Patch.FromAsm ? "asm" : "bytes", s.Patch.Description,
            s.Status == "apply" ? (dryRun ? "would_apply" : "refused") : s.Status,
            s.Reason, s.Detail, Math.Round(s.Confidence, 3), s.Tier,
            s.NewReplacement is { } nr ? Convert.ToHexString(nr) : null)).ToList();

        return new MigrationPatchReport(oldNative.Id, newNative.Id, source, dryRun, ids.Count > 0, ids, patches.Count, carried, steps.Count - carried, refusedBy,
            entries, 0, entries.Count, notes);
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
