using System.ComponentModel;
using System.Text;
using ModelContextProtocol;
using ModelContextProtocol.Protocol;
using ModelContextProtocol.Server;
using Corvus.Core;
using Corvus.Mcp;
using Corvus.Native;
using Corvus.Native.Code;
using Corvus.Native.Diff;
using Corvus.Native.Patching;
using Corvus.Native.Pdb;
using Corvus.Services;
using static Corvus.Tools.ToolSupport;

namespace Corvus.Tools;

/// <summary>Carries work on an old native build to its new build through one function match, with one report.</summary>
[McpServerToolType]
public sealed class BuildUpdateTools(AssemblyWorkspace workspace, NativeCodeService code, NativeEditService edits, PdbService pdb,
    AotMetadataService aot, AotNavigator navigator, AotNativeNames aotNames, AotBuildLoader? aotBuild = null, NotesService? noteStore = null,
    AssemblyComparer? comparer = null)
{
    public const string Names = "names", Pdb = "pdb", MetadataNames = "metadata_names", Patches = "patches", Patterns = "patterns",
        MethodMapping = "method_mapping", NoteCategory = "notes", DotNet = "dotnet";
    private static readonly string[] CategoryOrder = [Names, Pdb, MetadataNames, Patches, Patterns, MethodMapping, NoteCategory, DotNet];
    private static readonly string[] Outcomes = ["carried", "would_carry", "already_present", "refused", "not_applicable", "ambiguous"];
    private const int MaxAotItems = 200_000;

    public sealed record ReasonCount(string Reason, int Count);

    public sealed record UpdateCategory(
        [property: Description("names, pdb, metadata_names, patches, patterns, method_mapping, notes or dotnet.")] string Category,
        [property: Description("applied, previewed (dryRun), reported (changes nothing), not_applicable, not_included or out_of_scope.")] string Status,
        int Considered,
        [property: Description("Carried to the new build (or would be, in a dry run).")] int Carried,
        [property: Description("Already on the new build (a re-run).")] int AlreadyPresent,
        int Refused, int NotApplicable, int Ambiguous,
        [property: Description("Item counts by reason code (docs/migration-reasons.md).")] IReadOnlyList<ReasonCount> Reasons,
        string Detail)
    {
        /// <summary>The reasons of the items not carried, for the summary.</summary>
        [System.Text.Json.Serialization.JsonIgnore] public IReadOnlyList<ReasonCount> NotCarriedBy { get; init; } = [];
    }

    public sealed record UpdateItem(
        string Category,
        [property: Description("name, comment, layer, patch, pattern, method, note; user types: declarations, type, local, stack_var.")] string Kind,
        string? OldAddress,
        string? NewAddress,
        [property: Description("The name, comment, patch description, new pattern or method identity.")] string Value,
        [property: Description("carried, would_carry, already_present, refused, not_applicable or ambiguous.")] string Outcome,
        [property: Description("Reason code: how it was carried or why not. Patterns: still_unique, now_ambiguous, not_found, points_elsewhere, not_unique_in_old. " +
                               "Method mapping: agree, disagree, metadata_only, removed.")] string Reason,
        [property: Description("0-1.")] double Confidence,
        [property: Description("Function-match tier (1 best .. 5 fuzzy), or null.")] int? Tier,
        string Detail);

    public sealed record MethodMappingSummary(
        [property: Description("Where the old build's metadata came from.")] string OldSource,
        [property: Description("Where the new build's metadata came from.")] string NewSource,
        int OldMethods, int NewMethods,
        [property: Description("Metadata identity and the native matcher give the same new RVA.")] int Agree,
        [property: Description("Agreements where the matcher did not pair the functions by name (an independent check).")] int AgreeIndependent,
        int Disagree,
        [property: Description("Mapped by metadata; the native matcher found no counterpart.")] int MetadataOnly,
        [property: Description("Methods with code in the old build and none of the same identity in the new build.")] int Removed,
        [property: Description("Method identities with code only in the new build.")] int Added,
        int Ambiguous);

    public sealed record UpdateReport(
        [property: Description("What carried over, what did not, and the next step.")] string Summary,
        string OldImage, string NewImage, bool DryRun,
        [property: Description("The journaled edits (undo_native_edit): names and comments, user types, patches.")] IReadOnlyList<EditId> EditIds,
        [property: Description("Categories included in this run.")] IReadOnlyList<string> Included,
        int OldFunctions, int NewFunctions, int FunctionsMatched,
        IReadOnlyList<UpdateCategory> Categories,
        [property: Description("The method mapping; null when not applicable.")] MethodMappingSummary? MethodMapping,
        IReadOnlyList<UpdateItem> Items, int Offset, int Total,
        [property: Description("What was not covered (functions that did not decode, capped work, scope).")] IReadOnlyList<string> Notes);

    private sealed record Item(string Category, string Kind, uint? OldRva, uint? NewRva, string Value, string Outcome, string Reason, double Confidence, int? Tier, string Detail);

    [McpServerTool(Name = "update_to_new_build", Title = "Update work to a new build", UseStructuredContent = true, OutputSchemaType = typeof(UpdateReport))]
    [Description("Carry names, comments, types, name layers, patches, code patterns and notes from an old native build to a new one " +
                 "through one function match. Re-runs report already_present; .NET pairs carry notes only.")]
    public Task<string> UpdateToNewBuild(
        [Description("Old build: image id or path.")] string oldImage,
        [Description("New build: image id or path.")] string newImage,
        [Description(DryRunDefaultTrueDescription)] bool dryRun = true,
        [Description("Categories to carry (default all).")] string[]? include = null,
        [Description("Patch set (export_native_patches json): text or path.")] string? patchSet = null,
        [Description("Placement of re-created patch stubs.")] string? stubPlacement = null,
        [Description("Dummy assemblies, old build.")] string[]? oldMetadata = null,
        [Description("Dummy assemblies, new build.")] string[]? newMetadata = null,
        [Description(NativeDiffTools.CodeOnlyDescription)] bool codeOnly = false,
        [Description("Most code patterns made (0-1000).")] int maxPatterns = 100,
        [Description("Only items of this category.")] string? category = null,
        [Description("Only items with this outcome.")] string? outcome = null,
        [Description(RowOffsetDescription)] int offset = 0,
        [Description(LimitDescription)] int limit = 100,
        [Description(MaxTokensDescription)] int? maxTokens = null,
        RequestContext<CallToolRequestParams> context = null!,
        CancellationToken cancellationToken = default) => OrderedProgress.Run(context, async progress =>
    {
        var r = await Update(oldImage, newImage, dryRun, include, patchSet, stubPlacement, oldMetadata, newMetadata, codeOnly, maxPatterns, category, outcome,
            0, int.MaxValue, progress, cancellationToken);
        var head = new StringBuilder(r.Summary).Append('\n');
        if (r.EditIds.Count > 0) head.Append($"Recorded as {string.Join(", ", r.EditIds)} (undo_native_edit editId={r.EditIds[0]}).\n");
        foreach (var c in r.Categories.Where(c => c.Considered > 0))
            head.Append($"{c.Category} ({c.Status}): {string.Join(", ", c.Reasons.Take(6).Select(x => $"{x.Reason} {x.Count}"))}\n");
        foreach (var n in r.Notes) head.Append("Note: ").Append(n).Append('\n');
        return ToolOutput.List(r.Items.Skip(Math.Max(0, offset)).ToList(), Math.Max(0, offset), limit, r.Total,
            i => $"{i.Category} {i.Kind} {i.OldAddress ?? "-"} -> {i.NewAddress ?? "-"} {Format.Literal(i.Value.Length <= 80 ? i.Value : i.Value[..77] + "...")}: {i.Outcome} ({i.Reason})",
            page => r with { Items = page, Offset = Math.Max(0, offset) }, "item", head.ToString());
    });

    /// <summary>update_to_new_build as a record: the items after the filters, from offset.</summary>
    internal Task<UpdateReport> Update(string oldImage, string newImage, bool dryRun = true, string[]? include = null, string? patchSet = null,
        string? stubPlacement = null, string[]? oldMetadata = null, string[]? newMetadata = null, bool codeOnly = false, int maxPatterns = 100, string? category = null,
        string? outcome = null, int offset = 0, int limit = 100, IProgress<ProgressNotificationValue>? progress = null, CancellationToken cancellationToken = default) =>
        UpdateCore(oldImage, newImage, dryRun, include, patchSet, stubPlacement, oldMetadata, newMetadata, codeOnly, maxPatterns, category, outcome, offset, limit,
            progress ?? new Progress<ProgressNotificationValue>(), cancellationToken);

    private async Task<UpdateReport> UpdateCore(string oldImage, string newImage, bool dryRun, string[]? include, string? patchSet, string? stubPlacement,
        string[]? oldMetadata, string[]? newMetadata, bool codeOnly, int maxPatterns, string? category, string? outcome, int offset, int limit,
        IProgress<ProgressNotificationValue> progress, CancellationToken cancellationToken)
    {
        var ct = cancellationToken;
        var included = ParseInclude(include);
        var placement = PatchExtension.ParsePlacement(stubPlacement);
        if (maxPatterns is < 0 or > 1000) throw new ToolError(ErrorCode.InvalidArgument, $"maxPatterns must be 0-1000, not {maxPatterns}.");
        var categoryFilter = string.IsNullOrWhiteSpace(category) ? null : category.Trim().ToLowerInvariant();
        if (categoryFilter != null && !CategoryOrder.Contains(categoryFilter))
            throw new ToolError(ErrorCode.InvalidArgument, $"Unknown category '{category}'.", "use " + string.Join(", ", CategoryOrder));
        var outcomeFilter = string.IsNullOrWhiteSpace(outcome) ? null : outcome.Trim().ToLowerInvariant();
        if (outcomeFilter != null && !Outcomes.Contains(outcomeFilter))
            throw new ToolError(ErrorCode.InvalidArgument, $"Unknown outcome '{outcome}'.", "use " + string.Join(", ", Outcomes));
        offset = Math.Max(0, offset);
        limit = Math.Max(1, limit);
        const int phases = 7;
        void Phase(int done, string message) => progress.Report(new ProgressNotificationValue { Progress = done, Total = phases, Message = message });
        if (comparer != null && await Task.Run(() => ManagedPair(oldImage, newImage), ct) is { } managed)
            return await Task.Run(() => DotNetUpdate(managed.Old, managed.New, dryRun, included, categoryFilter, outcomeFilter, offset, limit, ct), ct);

        var pair = await new BuildPairs(workspace, code).Match(oldImage, newImage, new MatchOptions { UseNames = !codeOnly },
            new ProgressSpan(progress, 0, 2, phases), ct);
        var (oldNative, newNative, newIndex, match) = (pair.Old, pair.New, pair.NewIndex, pair.Match);
        var mapper = new AddressMapper(match);
        var notes = match.Notes.Distinct().ToList();
        if (match.Old.Failed + match.New.Failed > 0)
            notes.Add($"{match.Old.Failed} old and {match.New.Failed} new function(s) could not be decoded and match only by name or import");
        notes.AddRange(match.Old.Index.Truncations.Select(t => "old: " + t));
        notes.AddRange(match.New.Index.Truncations.Select(t => "new: " + t));

        var items = new List<Item>();
        var editIds = new List<EditId>();
        var categories = new Dictionary<string, (string Status, string Detail, int? Carried)>();
        var patternTargets = new List<(string Kind, uint OldRva, uint? NewRva, string Value)>();
        string Carry(bool set) => set ? dryRun ? "would_carry" : "carried" : "refused";
        string Status() => dryRun ? "previewed" : "applied";

        // ---- names (user layer) ----
        Phase(2, "names");
        if (included.Contains(Names))
        {
            var oldAnn = code.Annotations(oldNative);
            var sources = NameMigration.UserItems(oldAnn);
            var newAnn = code.Annotations(newNative);
            var steps = await Task.Run(() => NameMigration.Plan(mapper, sources, match.New.Index, newAnn, new MigrationOptions(), ct), ct);
            foreach (var s in steps)
            {
                string result = s.Set ? Carry(true) : s.Reason is "same_name" or "same_comment" ? "already_present" : s.Reason == "ambiguous" ? "ambiguous" : "refused";
                items.Add(new Item(Names, s.Item.Kind, s.Item.OldRva, s.NewRva, s.Value, result, s.Reason, s.Confidence, s.Tier, s.Detail));
                if (s.Item.Kind == "name") patternTargets.Add(("name", s.Item.OldRva, s.NewRva, s.Value));
            }
            var typeSteps = await Task.Run(() => UserTypeMigration.Plan(mapper, oldAnn.UserTypes, newAnn.UserTypes, new MigrationOptions(), ct), ct);
            foreach (var s in typeSteps)
                items.Add(new Item(Names, s.Kind, s.OldRva, s.NewRva, s.Value, s.Set ? Carry(true) : s.Reason.StartsWith("same_", StringComparison.Ordinal) ? "already_present"
                    : s.Reason == "ambiguous" ? "ambiguous" : "refused", s.Reason, s.Confidence, s.Tier, s.Detail));
            if (!dryRun) editIds.AddRange(NativeDiffTools.ApplyMigration(edits.Journal, workspace, code, newNative, match.New.Index, steps, typeSteps, "update_to_new_build"));
            categories[Names] = (sources.Count + typeSteps.Count == 0 ? "not_applicable" : Status(),
                sources.Count + typeSteps.Count == 0 ? $"{oldNative.Id} has no user names, comments or types"
                    : $"{sources.Count} user name(s) and comment(s) and {typeSteps.Count} user type(s) of {oldNative.Id}", null);
        }

        Phase(3, "imported names");
        if (included.Contains(Pdb)) await PdbLayer(oldNative, newNative, dryRun, items, categories, ct);

        // ---- metadata: method mapping (read-only) and the names layer ----
        MethodMappingSummary? mappingSummary = null;
        if (included.Contains(MetadataNames))
        {
            var oldScope = await Task.Run(() => AotScope(oldNative, oldMetadata, notes, ct), ct);
            var newScope = await Task.Run(() => AotScope(newNative, newMetadata, notes, ct), ct);
            bool sameMetadata = oldScope.Scope != null && newScope.Scope != null && oldScope.Scope.ToHashSet().SetEquals(newScope.Scope);
            if (sameMetadata) notes.Add("both builds resolve to the same dummy assemblies: pass oldMetadata / newMetadata to tell them apart");
            mappingSummary = await Task.Run(() => AotMap(oldScope, newScope, sameMetadata, mapper, items, categories, ct), ct);
            await Task.Run(() => AotLayer(oldNative, newNative, sameMetadata ? (null, "") : newScope, newIndex, mapper, dryRun, items, categories, ct), ct);
        }

        Phase(4, "patches");
        if (included.Contains(Patches))
        {
            var applied = await PatchStep(oldNative, newNative, newIndex, match, mapper, patchSet, placement, dryRun, items, categories, notes, editIds, ct);
            patternTargets.AddRange(applied);
        }

        // ---- patterns (computed on both builds' original bytes; report only) ----
        Phase(5, "code patterns");
        if (included.Contains(Patterns))
            await Task.Run(() => PatternStep(match, patternTargets, maxPatterns, items, categories, notes, ct), ct);

        if (included.Contains(NoteCategory)) await Task.Run(() => NoteStep(oldNative, newNative, mapper, dryRun, items, categories, ct), ct);

        categories[DotNet] = ("out_of_scope", "native images only: for .NET builds use compare_assemblies, find_counterpart, export_edits + apply_edits", null);
        Phase(6, "report");

        var oldImg = match.Old.Index.Image;
        var newImg = newIndex.Image;
        var categoryList = CategoryOrder.Select(c => Summarize(c, items, categories, included)).ToList();
        var filtered = items.Where(i => (categoryFilter == null || i.Category == categoryFilter) && (outcomeFilter == null || i.Outcome == outcomeFilter)).ToList();
        var page = filtered.Skip(offset).Take(limit).Select(i => new UpdateItem(i.Category, i.Kind,
            i.OldRva is { } o ? NativeAddress.Va(oldImg, o) : null, i.NewRva is { } n ? NativeAddress.Va(newImg, n) : null,
            i.Value, i.Outcome, i.Reason, Math.Round(i.Confidence, 3), i.Tier, i.Detail)).ToList();
        Phase(7, "done");
        return new UpdateReport(Summary(oldNative.Id, newNative.Id, dryRun, match, categoryList, mappingSummary), oldNative.Id, newNative.Id, dryRun, editIds,
            CategoryOrder.Where(included.Contains).ToList(),
            match.Old.Functions.Length, match.New.Functions.Length, match.Pairs.Count, categoryList, mappingSummary,
            page, offset, filtered.Count, notes.Distinct().ToList());
    }

    private static HashSet<string> ParseInclude(string[]? include)
    {
        var set = new HashSet<string>(StringComparer.Ordinal);
        foreach (var part in include is { Length: > 0 } ? include.Select(i => i.Trim()).Where(i => i.Length > 0).DefaultIfEmpty("all") : ["all"])
        {
            switch (part.ToLowerInvariant())
            {
                case "all": set.UnionWith([Names, Pdb, MetadataNames, MethodMapping, Patches, Patterns, NoteCategory]); break;
                case "notes": set.Add(NoteCategory); break;
                case "names": set.Add(Names); break;
                case "pdb": set.Add(Pdb); break;
                case "metadata" or "metadata_names" or "method_mapping": set.Add(MetadataNames); set.Add(MethodMapping); break;
                case "patches": set.Add(Patches); break;
                case "patterns": set.Add(Patterns); break;
                default:
                    throw new ToolError(ErrorCode.InvalidArgument, $"Unknown category '{part}' in include.", "use names, pdb, metadata, patches, patterns, notes or all");
            }
        }
        return set;
    }

    /// <summary>Records the old build's notes again at the mapped addresses; a note with the same text there is already_present.</summary>
    private void NoteStep(LoadedNative oldNative, LoadedNative newNative, AddressMapper mapper, bool dryRun, List<Item> items,
        Dictionary<string, (string Status, string Detail, int? Carried)> categories, CancellationToken ct)
    {
        if (noteStore == null)
        {
            categories[NoteCategory] = ("not_applicable", "notes are not available in this server", null);
            return;
        }
        var old = noteStore.Read(oldNative.OriginalSha256.ToLowerInvariant()).Where(n => n.Anchor.Kind is NoteAnchor.Native or NoteAnchor.File).ToList();
        if (old.Count == 0)
        {
            categories[NoteCategory] = ("not_applicable", $"{oldNative.Id} has no notes", null);
            return;
        }
        var existing = noteStore.Read(newNative.OriginalSha256.ToLowerInvariant());
        var carried = new List<Note>();
        var newImage = mapper.Match.New.Index.Image;
        foreach (var n in old)
        {
            ct.ThrowIfCancellationRequested();
            var text = n.Text.Length > 80 ? n.Text[..77] + "..." : n.Text;
            uint? newRva = null;
            string reason = "file", detail = "a note on the whole file";
            double confidence = 1;
            int? tier = null;
            if (n.Anchor.Kind == NoteAnchor.Native)
            {
                var mapped = mapper.Map(n.Anchor.Rva!.Value, ct);
                (reason, detail, confidence, tier) = (mapped.Reason, mapped.Detail, mapped.Confidence, mapped.Pair?.Tier);
                if (mapped.NewRva is not { } to)
                {
                    items.Add(new Item(NoteCategory, "note", n.Anchor.Rva, null, text, mapped.Reason == "ambiguous" ? "ambiguous" : "refused", reason, confidence, tier, detail));
                    continue;
                }
                newRva = to;
            }
            if (existing.Any(e => e.Text == n.Text && e.Anchor.Kind == n.Anchor.Kind && e.Anchor.Rva == newRva))
            {
                items.Add(new Item(NoteCategory, "note", n.Anchor.Rva, newRva, text, "already_present", MigrationReasons.SameNote, confidence, tier, detail));
                continue;
            }
            var from = n.Anchor.Rva is { } r ? $"{oldNative.Id}@{NativeAddress.Va(mapper.Match.Old.Index.Image, r)}" : oldNative.Id;
            carried.Add(n with
            {
                Id = NotesService.NewId(),
                Anchor = n.Anchor with { Sha256 = newNative.OriginalSha256, Rva = newRva, Label = newRva is { } at ? $"{newNative.Id}@{NativeAddress.Va(newImage, at)}" : newNative.Id },
                Evidence = [.. n.Evidence.Take(NotesService.MaxEvidence - 1), $"carried from {from} ({reason})"],
                Revision = 1,
                Updated = DateTime.UtcNow,
            });
            items.Add(new Item(NoteCategory, "note", n.Anchor.Rva, newRva, text, dryRun ? "would_carry" : "carried", reason, confidence, tier, detail));
        }
        if (!dryRun && carried.Count > 0) noteStore.Import(carried);
        categories[NoteCategory] = (dryRun ? "previewed" : "applied", $"{old.Count} note(s) on {oldNative.Id}", null);
    }

    /// <summary>Both arguments name .NET assemblies (loaded, or paths of unloaded ones); null when either is a native image.</summary>
    private (LoadedAssembly Old, LoadedAssembly New)? ManagedPair(string oldImage, string newImage)
    {
        LoadedAssembly? One(string image)
        {
            if (string.IsNullOrWhiteSpace(image)) return null;
            Target target;
            try { target = Targets.Resolve(workspace, image, TargetKind.Any); }
            catch (ToolError) { return null; } // the native path reports it
            if (target.Notice != null) workspace.Notify(target.Notice);
            return target.Native == null ? target.Assembly : null;
        }
        return One(oldImage) is { } o && One(newImage) is { } n ? (o, n) : null;
    }

    /// <summary>A .NET pair: notes on members follow find_counterpart's match; the other categories belong to the native path.</summary>
    private UpdateReport DotNetUpdate(LoadedAssembly oldAsm, LoadedAssembly newAsm, bool dryRun, HashSet<string> included, string? categoryFilter, string? outcomeFilter,
        int offset, int limit, CancellationToken ct)
    {
        if (ReferenceEquals(oldAsm, newAsm))
            throw new ToolError(ErrorCode.InvalidArgument, $"Both arguments name {oldAsm.Id}.", "load the other build too and pass its id (e.g. name#2)");
        var cmp = workspace.Read(() => comparer!.Compare(oldAsm, newAsm, ct), ct);
        var items = new List<Item>();
        var categories = new Dictionary<string, (string Status, string Detail, int? Carried)>();
        foreach (var c in new[] { Names, Pdb, MetadataNames, MethodMapping, Patches, Patterns })
            if (included.Contains(c)) categories[c] = ("not_applicable", ".NET builds: export_edits, then apply_edits targetBuild=other", null);
        if (included.Contains(NoteCategory)) workspace.Read(() => DotNetNoteStep(oldAsm, newAsm, cmp, dryRun, items, categories, ct), ct);
        categories[DotNet] = ("reported", $"{cmp.TypeMap.Count} type(s) and {cmp.MemberMap.Count} member(s) matched; compare_assemblies lists the changes", null);

        var categoryList = CategoryOrder.Select(c => Summarize(c, items, categories, included)).ToList();
        var filtered = items.Where(i => (categoryFilter == null || i.Category == categoryFilter) && (outcomeFilter == null || i.Outcome == outcomeFilter)).ToList();
        var page = filtered.Skip(offset).Take(limit).Select(i => new UpdateItem(i.Category, i.Kind,
            i.OldRva is { } o ? $"0x{o:X8}" : null, i.NewRva is { } n ? $"0x{n:X8}" : null,
            i.Value, i.Outcome, i.Reason, Math.Round(i.Confidence, 3), i.Tier, i.Detail)).ToList();
        var sb = new StringBuilder(dryRun ? "Dry run (nothing changed): " : "Applied: ");
        sb.Append($"{oldAsm.Id} -> {newAsm.Id} (.NET), {cmp.MemberMap.Count} member(s) matched. ");
        AppendCategories(sb, categoryList, dryRun, null);
        sb.Append("Edits: export_edits, then apply_edits targetBuild=other.");
        int Methods(LoadedAssembly a) => workspace.Read(() => a.Module.GetTypes().Sum(t => t.Methods.Count));
        return new UpdateReport(sb.ToString(), oldAsm.Id, newAsm.Id, dryRun, [], CategoryOrder.Where(included.Contains).ToList(),
            Methods(oldAsm), Methods(newAsm), cmp.MemberMap.Keys.Count(k => k is dnlib.DotNet.MethodDef), categoryList, null,
            page, offset, filtered.Count, ["a .NET pair: notes are mapped by find_counterpart; addresses are metadata tokens"]);
    }

    /// <summary>Records the old build's member notes on their counterparts; ambiguous and unmatched members are reported, not guessed.</summary>
    private int DotNetNoteStep(LoadedAssembly oldAsm, LoadedAssembly newAsm, AssemblyComparer.Comparison cmp, bool dryRun, List<Item> items,
        Dictionary<string, (string Status, string Detail, int? Carried)> categories, CancellationToken ct)
    {
        if (noteStore == null)
        {
            categories[NoteCategory] = ("not_applicable", "notes are not available in this server", null);
            return 0;
        }
        var oldMvid = oldAsm.Module.Mvid?.ToString();
        var newMvid = newAsm.Module.Mvid?.ToString();
        var old = noteStore.Read(oldAsm.OriginalSha256.ToLowerInvariant()).Where(n => n.Anchor.Kind == NoteAnchor.File)
            .Concat(oldMvid == null ? [] : noteStore.Read(new NoteAnchor(NoteAnchor.DotNet, Mvid: oldMvid).StoreKey).Where(n => n.Anchor.Kind == NoteAnchor.DotNet))
            .ToList();
        if (old.Count == 0)
        {
            categories[NoteCategory] = ("not_applicable", $"{oldAsm.Id} has no notes", null);
            return 0;
        }
        var existing = noteStore.Read(newAsm.OriginalSha256.ToLowerInvariant())
            .Concat(newMvid == null ? [] : noteStore.Read(new NoteAnchor(NoteAnchor.DotNet, Mvid: newMvid).StoreKey)).ToList();
        var carried = new List<Note>();
        foreach (var n in old)
        {
            ct.ThrowIfCancellationRequested();
            var text = n.Text.Length > 80 ? n.Text[..77] + "..." : n.Text;
            NoteAnchor anchor;
            string reason = "file", detail = "a note on the whole file";
            double confidence = 1;
            uint? newToken = null;
            if (n.Anchor.Kind == NoteAnchor.DotNet)
            {
                var member = MetadataUtil.Try(() => oldAsm.Module.ResolveToken(n.Anchor.Token!.Value) as dnlib.DotNet.IMemberDef);
                if (member == null)
                {
                    items.Add(new Item(NoteCategory, "note", n.Anchor.Token, null, text, "refused", "not_in_old_build", 0, null, $"token 0x{n.Anchor.Token:X8} names no member of {oldAsm.Id}"));
                    continue;
                }
                var found = comparer!.FindCounterpart(cmp, member);
                if (found.Candidates is { } candidates)
                {
                    items.Add(new Item(NoteCategory, "note", n.Anchor.Token, null, text, "ambiguous", "ambiguous", 0, null,
                        $"{Format.MemberLabel(member)}: {found.How} ({string.Join(", ", candidates.Take(3).Select(Format.MemberLabel))})"));
                    continue;
                }
                if (found.Match is not { } match || newMvid == null)
                {
                    items.Add(new Item(NoteCategory, "note", n.Anchor.Token, null, text, "refused", "no_counterpart", 0, null, $"{Format.MemberLabel(member)}: {found.How}"));
                    continue;
                }
                newToken = match.MDToken.Raw;
                (reason, detail) = (MigrationReasons.Counterpart, $"{Format.MemberLabel(member)} -> {Format.MemberLabel(match)} ({found.How}{(found.Tier != null ? ", " + found.Tier : "")})");
                confidence = found.Confidence switch { "exact" => 1, "strong" => 0.9, _ => 0.7 };
                anchor = n.Anchor with { Sha256 = newAsm.OriginalSha256, Mvid = newMvid, Token = newToken, Label = $"{newAsm.Id}:{Format.MemberLabel(match)}" };
            }
            else anchor = n.Anchor with { Sha256 = newAsm.OriginalSha256, Label = newAsm.Id };
            if (existing.Any(e => e.Text == n.Text && e.Anchor.Kind == n.Anchor.Kind && e.Anchor.Token == newToken))
            {
                items.Add(new Item(NoteCategory, "note", n.Anchor.Token, newToken, text, "already_present", MigrationReasons.SameNote, confidence, null, detail));
                continue;
            }
            carried.Add(n with
            {
                Id = NotesService.NewId(),
                Anchor = anchor,
                Evidence = [.. n.Evidence.Take(NotesService.MaxEvidence - 1), $"carried from {n.Anchor.Label ?? oldAsm.Id} ({reason})"],
                Revision = 1,
                Updated = DateTime.UtcNow,
            });
            items.Add(new Item(NoteCategory, "note", n.Anchor.Token, newToken, text, dryRun ? "would_carry" : "carried", reason, confidence, null, detail));
        }
        if (!dryRun && carried.Count > 0) noteStore.Import(carried);
        categories[NoteCategory] = (dryRun ? "previewed" : "applied", $"{old.Count} note(s) on {oldAsm.Id}", null);
        return carried.Count;
    }

    private static UpdateCategory Summarize(string name, List<Item> items, Dictionary<string, (string Status, string Detail, int? Carried)> categories, HashSet<string> included)
    {
        if (!categories.TryGetValue(name, out var c))
            c = included.Contains(name) || name == DotNet ? ("not_applicable", "nothing to carry", null) : ("not_included", "not in include", null);
        var mine = items.Where(i => i.Category == name).ToList();
        int carried = c.Carried ?? mine.Count(i => i.Outcome is "carried" or "would_carry");
        static List<ReasonCount> Count(IEnumerable<Item> list) => list.GroupBy(i => i.Reason).Select(g => new ReasonCount(g.Key, g.Count()))
            .OrderByDescending(r => r.Count).ThenBy(r => r.Reason, StringComparer.Ordinal).ToList();
        return new UpdateCategory(name, c.Status, mine.Count, carried, mine.Count(i => i.Outcome == "already_present"), mine.Count(i => i.Outcome == "refused"),
            mine.Count(i => i.Outcome == "not_applicable"), mine.Count(i => i.Outcome == "ambiguous"), Count(mine), c.Detail)
            { NotCarriedBy = Count(mine.Where(i => i.Outcome is "refused" or "not_applicable" or "ambiguous")) };
    }

    private static string Summary(string oldId, string newId, bool dryRun, MatchResult match, List<UpdateCategory> categories, MethodMappingSummary? map)
    {
        var sb = new StringBuilder();
        sb.Append(dryRun ? "Dry run (nothing changed): " : "Applied: ");
        sb.Append($"{oldId} -> {newId}, {match.Pairs.Count} of {match.Old.Functions.Length} old functions matched. ");
        AppendCategories(sb, categories, dryRun, map);
        sb.Append(dryRun ? "Run again with dryRun=false to apply." : "Run again to verify: carried items then report already_present.");
        return sb.ToString();
    }

    private static void AppendCategories(StringBuilder sb, List<UpdateCategory> categories, bool dryRun, MethodMappingSummary? map)
    {
        foreach (var c in categories.Where(c => c.Status is not ("not_included" or "out_of_scope")))
        {
            if (c.Category == MethodMapping && map != null)
            {
                sb.Append($"method mapping: {map.Agree} agree, {map.Disagree} disagree, {map.MetadataOnly} metadata only, {map.Removed} removed, {map.Added} added. ");
                continue;
            }
            if (c.Status == "not_applicable" && c.Considered == 0) { sb.Append($"{c.Category}: not applicable ({c.Detail}). "); continue; }
            sb.Append($"{c.Category}: {c.Carried} {(dryRun ? "would carry" : "carried")}");
            if (c.AlreadyPresent > 0) sb.Append($", {c.AlreadyPresent} already present");
            int other = c.Refused + c.NotApplicable + c.Ambiguous;
            if (other > 0)
                sb.Append($", {other} not ({string.Join(", ", c.NotCarriedBy.Take(4).Select(r => $"{r.Reason} {r.Count}"))})");
            sb.Append(". ");
        }
    }

    private async Task PdbLayer(LoadedNative oldNative, LoadedNative newNative, bool dryRun, List<Item> items,
        Dictionary<string, (string Status, string Detail, int? Carried)> categories, CancellationToken ct)
    {
        var oldLayer = NativeNameLayers.OfOrNull(oldNative)?.Get(NativeNameSource.Pdb);
        var oldState = PdbService.StateOf(oldNative);
        string oldWhat = oldState != null ? $"{oldState.Path} ({PdbService.Identity(oldState.Pdb)})" : oldLayer?.Info?.SourcePath ?? "none";
        if (PdbService.StateOf(newNative) is { Verified: true } loaded)
        {
            items.Add(new Item(Pdb, "layer", null, null, loaded.Path, "already_present", "pdb_loaded", 1, null,
                $"{newNative.Id} already has its matching PDB ({loaded.Names.Count} names)"));
            categories[Pdb] = (Status(dryRun), $"old: {oldWhat}", null);
            return;
        }
        PdbLocation location;
        try { location = await Task.Run(() => PdbLocator.Locate(newNative.RequirePe("carrying a PDB")), ct); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ToolError) { location = new PdbLocation(null, [new PdbProbe("-", ex.Message)], []); }
        if (location.Path is { } path)
        {
            if (dryRun)
                items.Add(new Item(Pdb, "layer", null, null, path, "would_carry", "matching_pdb_found", 1, null, $"would load {path}, the new build's own matching PDB"));
            else
            {
                try
                {
                    var r = await pdb.Load(newNative, path, download: false, server: null, force: false, TimeSpan.FromSeconds(30), long.MaxValue, ct);
                    items.Add(new Item(Pdb, "layer", null, null, path, "carried", "matching_pdb_loaded", 1, null,
                        $"loaded {path}: {r.NamesApplied} names applied, {r.UserNamesKept} user names kept" + (r.SaveProblem != null ? $"; not saved: {r.SaveProblem}" : "")));
                }
                catch (ToolError ex)
                {
                    items.Add(new Item(Pdb, "layer", null, null, path, "refused", "pdb_unreadable", 0, null, ex.Message));
                }
            }
            categories[Pdb] = (Status(dryRun), $"old: {oldWhat}", null);
            return;
        }
        var cv = newNative.Pe?.CodeView;
        var detail = $"no PDB matching {newNative.Id} (" + (cv is { Format: "RSDS" } ? $"wants {cv.Guid:D} age {cv.Age}" : "no RSDS debug record") +
                     $"); looked in: {string.Join("; ", location.Probes.Take(4).Select(p => $"{p.Location}: {p.Outcome}"))}";
        if (oldLayer != null || oldState != null)
            items.Add(new Item(Pdb, "layer", null, null, oldWhat, "not_applicable", "pdb_mismatch", 0, null,
                $"the old build's PDB names belong to that build only; {detail}. load_pdb with the new build's PDB (download=true for a symbol server)"));
        categories[Pdb] = (oldLayer != null || oldState != null ? Status(dryRun) : "not_applicable",
            oldLayer != null || oldState != null ? $"old: {oldWhat}" : "neither build has PDB names", null);
    }

    private static string Status(bool dryRun) => dryRun ? "previewed" : "applied";

    /// <summary>The dummy assemblies of <paramref name="native"/>: given, loaded, read from metadata beside it, or last applied; null when none.</summary>
    private (List<LoadedAssembly>? Scope, string Source) AotScope(LoadedNative native, string[]? explicitScope, List<string> notes, CancellationToken ct)
    {
        if (explicitScope?.Where(s => !string.IsNullOrWhiteSpace(s)).Select(s => s.Trim()).ToList() is { Count: > 0 } ids)
        {
            var given = workspace.Read(() => ids.Select(workspace.Get).Distinct().Where(a => aot.GetIndex(a).Count > 0).ToList());
            if (given.Count == 0)
                throw new ToolError(ErrorCode.InvalidArgument, $"'{string.Join(", ", ids)}' names no dummy assembly (methods with [Address] attributes).",
                    "pass the ids of the build's dummy assemblies (list_assemblies), or omit it to find them");
            return (given, "assemblies " + string.Join(", ", given.Select(a => a.Id)));
        }
        if (FromDumps(native) is { } found) return found;
        AotBuildFiles? build = null;
        try { build = AotBuildFiles.Find(native.FilePath, native.SliceName); }
        catch (ToolError ex) { notes.Add($"{native.Id}: {ex.Message}"); }
        if (build != null && string.Equals(Path.GetFullPath(build.Binary), native.FilePath, StringComparison.OrdinalIgnoreCase))
        {
            try
            {
                (aotBuild ?? new AotBuildLoader(workspace)).Load(build, loadBinary: false, null, ct);
                if (FromDumps(native) is { } read) return read;
            }
            catch (ToolError ex) { notes.Add($"{native.Id}: metadata {build.Metadata} not read: {ex.Message}"); }
        }
        if (AotNativeNames.Of(native) is { } applied) return (applied.Image.Assemblies.ToList(), $"the dummy assemblies apply_metadata_names used ({applied.Assemblies})");
        return (null, "");
    }

    private (List<LoadedAssembly>, string)? FromDumps(LoadedNative native) => workspace.Read(() =>
    {
        var all = workspace.Assemblies.Where(a => aot.GetIndex(a).Count > 0).ToList();
        if (all.Count == 0) return ((List<LoadedAssembly>, string)?)null;
        var image = navigator.ImagesFor(all).FirstOrDefault(i => i.Dump?.Files.Describes(native) == true);
        return image == null ? null : (image.Assemblies.ToList(), $"the metadata in {image.Dump!.Files.Directory}");
    });

    private List<AotBuildMap.Method> Methods(List<LoadedAssembly> scope) => workspace.Read(() =>
        scope.SelectMany(a => aot.GetIndex(a)).Where(m => m.Rva is > 0 and <= uint.MaxValue)
            .Select(m => new AotBuildMap.Method(m.Assembly.AssemblyName + "|" + m.Method.FullName, (uint)m.Rva!.Value)).ToList());

    private MethodMappingSummary? AotMap((List<LoadedAssembly>? Scope, string Source) oldScope, (List<LoadedAssembly>? Scope, string Source) newScope, bool same,
        AddressMapper mapper, List<Item> items, Dictionary<string, (string Status, string Detail, int? Carried)> categories, CancellationToken ct)
    {
        if (oldScope.Scope == null || newScope.Scope == null || same)
        {
            categories[MethodMapping] = ("not_applicable", same ? "both builds resolve to the same metadata"
                : oldScope.Scope == null && newScope.Scope == null ? "no metadata for either build"
                : oldScope.Scope == null ? "no metadata for the old build" : "no metadata for the new build", null);
            return null;
        }
        var oldMethods = Methods(oldScope.Scope);
        var newMethods = Methods(newScope.Scope);
        var result = AotBuildMap.Map(oldMethods, newMethods, rva =>
        {
            var m = mapper.Map(rva, ct);
            return new AotBuildMap.NativeAnswer(m.NewRva, m.Pair?.Tier, m.Pair?.Basis, m.Confidence, m.Reason);
        }, ct);
        foreach (var e in result.Entries.Take(MaxAotItems))
        {
            string outcome = e.Status switch { "agree" or "disagree" or "metadata_only" => "carried", "removed" => "refused", _ => "ambiguous" };
            items.Add(new Item(MethodMapping, "method", e.OldRva, e.NewRva, e.Key, outcome, e.Status, e.Confidence, e.Tier, e.Detail));
        }
        categories[MethodMapping] = ("reported", $"old: {oldScope.Source}; new: {newScope.Source}" +
            (result.Entries.Count > MaxAotItems ? $"; items listed for the first {MaxAotItems}" : ""), null);
        return new MethodMappingSummary(oldScope.Source, newScope.Source, result.OldMethods, result.NewMethods, result.Count("agree"),
            result.Entries.Count(e => e.Status == "agree" && e.Basis != "name"), result.Count("disagree"), result.Count("metadata_only"),
            result.Count("removed"), result.Added, result.Count("ambiguous"));
    }

    /// <summary>Names the new build from its own metadata, else carries the old build's metadata names through the match.</summary>
    private void AotLayer(LoadedNative oldNative, LoadedNative newNative, (List<LoadedAssembly>? Scope, string Source) newScope, NativeCodeIndex newIndex,
        AddressMapper mapper, bool dryRun, List<Item> items, Dictionary<string, (string Status, string Detail, int? Carried)> categories, CancellationToken ct)
    {
        var layers = NativeNameLayers.Of(newNative);
        if (newScope.Scope is { } scope)
        {
            // A re-run: the layer applied from the same dummy assemblies is in place.
            if (layers.Get(NativeNameSource.Metadata) is { } applied && applied.Origin == $"AOT metadata ({string.Join(", ", scope.Select(a => a.Id))})")
            {
                items.Add(new Item(MetadataNames, "layer", null, null, newScope.Source, "already_present", "applied_from_metadata", 1, null,
                    $"the new build already has {applied.Names.Count} metadata names from {applied.Origin}"));
                categories[MetadataNames] = (Status(dryRun), $"the new build has its own metadata ({newScope.Source})", 0);
                return;
            }
            if (dryRun)
            {
                int functions = Methods(scope).Select(m => m.Rva).Distinct().Count();
                items.Add(new Item(MetadataNames, "layer", null, null, newScope.Source, "would_carry", "reapply_from_metadata", 1, null,
                    $"apply_metadata_names from {newScope.Source}: about {functions} function(s) with dummy methods, plus script.json instantiations and slots when present"));
                categories[MetadataNames] = ("previewed", $"the new build has its own metadata ({newScope.Source})", functions);
                return;
            }
            var index = code.Ready(newNative) ?? newIndex;
            var r = workspace.Read(() => aotNames.Apply(newNative, index, scope, ct));
            items.Add(new Item(MetadataNames, "layer", null, null, newScope.Source, "carried", "reapplied_from_metadata", 1, null,
                $"{r.Functions} functions, {r.Strings} strings, {r.MetadataSlots} metadata and {r.MethodInfoSlots} MethodInfo slots named; {r.UserNamesKept} user names kept"));
            categories[MetadataNames] = ("applied", $"re-applied from the new build's own metadata ({newScope.Source})", r.Functions);
            return;
        }
        var oldLayer = NativeNameLayers.OfOrNull(oldNative)?.Get(NativeNameSource.Metadata);
        if (oldLayer == null)
        {
            categories[MetadataNames] = ("not_applicable", "no metadata names on the old build and no metadata for the new build", null);
            return;
        }
        if (layers.Get(NativeNameSource.Metadata) is { } own && !own.Origin.StartsWith(CarriedOrigin, StringComparison.Ordinal))
        {
            items.Add(new Item(MetadataNames, "layer", null, null, own.Origin, "not_applicable", "new_has_own_metadata_names", 0, null,
                $"the new build already has metadata names ({own.Names.Count}, {own.Origin}); they are kept"));
            categories[MetadataNames] = (Status(dryRun), "the new build has its own metadata names", null);
            return;
        }

        var names = new Dictionary<uint, string>();
        var comments = new Dictionary<uint, string>();
        var firstAt = new Dictionary<uint, uint>();
        var current = layers.Get(NativeNameSource.Metadata);
        int n = 0;
        foreach (var (oldRva, name) in oldLayer.Names.OrderBy(kv => kv.Key))
        {
            if ((++n & 0xFFF) == 0) ct.ThrowIfCancellationRequested();
            var m = mapper.Map(oldRva, ct);
            if (m.NewRva is not { } at)
            {
                items.Add(new Item(MetadataNames, "name", oldRva, null, name, m.Reason == "ambiguous" ? "ambiguous" : "refused", m.Reason, m.Confidence, m.Pair?.Tier, m.Detail));
                continue;
            }
            if (firstAt.TryGetValue(at, out var earlier))
            {
                items.Add(new Item(MetadataNames, "name", oldRva, at, name, "refused", "duplicate_target", m.Confidence, m.Pair?.Tier, $"the name from rva 0x{earlier:X} already lands there"));
                continue;
            }
            firstAt[at] = oldRva;
            names[at] = name;
            var note = $"[metadata name carried by match from {oldNative.Id}, confidence {m.Confidence:0.##}]";
            comments[at] = oldLayer.Comments.TryGetValue(oldRva, out var c) ? $"{c} {note}" : note;
            bool present = current?.Names.TryGetValue(at, out var had) == true && had == name;
            items.Add(new Item(MetadataNames, "name", oldRva, at, name, present ? "already_present" : Carry(dryRun), m.Reason, m.Confidence, m.Pair?.Tier, "carried by match: " + m.Detail));
        }
        if (!dryRun && names.Count > 0)
        {
            var info = new ImportInfo(oldLayer.Info?.SourcePath, $"carried-by-match {oldNative.OriginalSha256}", DateTime.UtcNow);
            var index = code.Ready(newNative) ?? newIndex;
            layers.Set(new NativeNameLayers.Layer(NativeNameSource.Metadata, names, comments, $"{CarriedOrigin} {oldNative.Id} ({oldLayer.Origin})", info), index);
            if (code.SaveImported(newNative, NativeNameSource.Metadata) is { } problem)
                items.Add(new Item(MetadataNames, "layer", null, null, "save", "refused", "not_saved", 0, null, $"names not saved for the next load: {problem}"));
        }
        categories[MetadataNames] = (Status(dryRun), $"no metadata for the new build: the old build's {oldLayer.Names.Count} metadata names mapped through the function match", null);
        string Carry(bool dry) => dry ? "would_carry" : "carried";
    }

    private const string CarriedOrigin = "carried by match from";

    private async Task<List<(string Kind, uint OldRva, uint? NewRva, string Value)>> PatchStep(LoadedNative oldNative, LoadedNative newNative, NativeCodeIndex newIndex,
        MatchResult match, AddressMapper mapper, string? patchSet, StubPlacement placement, bool dryRun, List<Item> items,
        Dictionary<string, (string Status, string Detail, int? Carried)> categories, List<string> notes, List<EditId> editIds, CancellationToken ct)
    {
        List<MigratablePatch> patches;
        string source;
        // A JSON patch set is written for PE images; in-memory patches carry between builds of one format.
        if (string.IsNullOrWhiteSpace(patchSet) ? oldNative.Image.Format != newNative.Image.Format : newNative.Pe == null)
        {
            categories[Patches] = ("not_applicable", string.IsNullOrWhiteSpace(patchSet)
                ? $"{oldNative.Id} is {oldNative.Image.Format} and {newNative.Id} is {newNative.Image.Format}"
                : $"a patch set applies to PE images; {newNative.Id} is {newNative.Image.Format}", null);
            return [];
        }
        if (!string.IsNullOrWhiteSpace(patchSet))
        {
            var trimmed = patchSet.Trim();
            string json = trimmed.StartsWith('{') ? patchSet
                : Path.IsPathFullyQualified(trimmed) && File.Exists(trimmed) ? await File.ReadAllTextAsync(trimmed, ct)
                : throw new ToolError(ErrorCode.InvalidArgument, $"patchSet is neither JSON text nor an existing file path ({patchSet}).",
                    "pass a file written by export_native_patches with format=json, or its JSON text");
            patches = PatchMigration.FromJson(json);
            source = trimmed.StartsWith('{') ? "json" : Path.GetFullPath(trimmed);
        }
        else
        {
            patches = workspace.Read(() => oldNative.Patches.Patches.Select(PatchMigration.From).ToList());
            source = "in_memory";
        }
        var targets = new List<(string, uint, uint?, string)>();
        if (patches.Count == 0)
        {
            categories[Patches] = ("not_applicable", source == "in_memory" ? $"{oldNative.Id} has no in-memory patches" : "the patch set has no patches", null);
            return targets;
        }

        // A re-run: patches already on the new build at the mapped site are reported, not applied twice.
        var existing = workspace.Read(() => newNative.Patches.Patches.ToList());
        var pending = new List<MigratablePatch>();
        foreach (var p in patches)
        {
            ct.ThrowIfCancellationRequested();
            var m = mapper.Map(p.Rva, ct);
            if (m.NewRva is { } at && existing.FirstOrDefault(q => q.Rva == at && Same(q, p)) is { } done)
            {
                items.Add(new Item(Patches, "patch", p.Rva, at, p.Description, "already_present", MigrationReasons.SamePatch, m.Confidence, m.Pair?.Tier,
                    $"the new build already has this patch (#{existing.IndexOf(done) + 1})"));
                targets.Add(("patch", p.Rva, at, p.Description));
                continue;
            }
            pending.Add(p);
        }

        var currentNew = newIndex;
        var placements = new Dictionary<uint, string>();
        Func<string, ulong?> Resolver(NativeCodeIndex index) => name =>
        {
            try { return index.Image.ImageBase + NativeCodeTools.Address(index, name); }
            catch (ToolError) { return null; }
        };
        NativeEditService.PatchResult PreparePlain(uint rva, byte[] replacement, string? assembly) =>
            edits.PreparePatch(currentNew, rva, replacement, force: false, assembly != null ? "patch_asm (migrated)" : "patch_bytes (migrated)", RelocationMode.Auto, assembled: null, assembly: assembly);
        NativeEditService.PatchResult PrepareStub(uint rva, MigratablePatch p)
        {
            var r = edits.PrepareExtendedPatch(currentNew, rva, p.StubCode!, p.StubAssembly, PatchExtension.ParseMode(p.StubMode), $"{p.Description} (migrated)",
                Resolver(currentNew), placement);
            placements[rva] = r.Patch.Stub!.Placement;
            return r;
        }
        var steps = await Task.Run(() => PatchMigration.Plan(match, pending, (rva, repl, asm) => PreparePlain(rva, repl, asm), ct,
            (rva, p) => PrepareStub(rva, p).Patch.Replacement), ct);

        if (dryRun)
        {
            // Mark what applying would refuse for an existing patch of the new build.
            steps = steps.Select(s => s.Apply && s.NewRva is { } r && workspace.Read(() => newNative.Patches.Overlapping(r, s.NewReplacement!.Length)) is { } clash
                ? s with { Apply = false, Status = "refused", Reason = "conflicts_with_existing_patch", Detail = $"an existing patch of the new build covers {NativeAddress.Va(newIndex.Image, clash.Rva)}" }
                : s).ToList();
        }
        else
        {
            var updated = new List<PatchMigrationStep>(steps.Count);
            foreach (var step in steps)
            {
                ct.ThrowIfCancellationRequested();
                if (!step.Apply || step.NewRva is not { } rva || step.NewReplacement is not { } repl) { updated.Add(step); continue; }
                try
                {
                    var prepared = step.Patch.IsStub ? PrepareStub(rva, step.Patch) : PreparePlain(rva, repl, step.Patch.Assembly);
                    if (edits.Apply(newNative, currentNew, prepared, dryRun: false).EditId is { } patchId) editIds.Add(patchId);
                    currentNew = await code.Index(newNative, null, ct);
                    updated.Add(step with { Status = "applied" });
                }
                catch (ToolError ex)
                {
                    updated.Add(step with { Apply = false, Status = "refused", Reason = MigrationReasons.PatchRefusal(ex), Detail = ex.Message, NewReplacement = null });
                }
            }
            steps = updated;
        }

        foreach (var s in steps)
        {
            var p = s.Patch;
            string kind = p.IsStub ? (p.Grown ? "stub patch (grown file)" : "stub patch") : p.FromAsm ? "asm patch" : "byte patch";
            string detail = s.Detail;
            if (p.IsStub && s.Apply && s.NewRva is { } r && placements.TryGetValue(r, out var where)) detail += $"; stub placed: {where}";
            if (s.NewReplacement is { } bytes) detail += $"; site bytes {Convert.ToHexString(bytes)}";
            items.Add(new Item(Patches, "patch", p.Rva, s.NewRva, $"{p.Description} [{kind}]", s.Apply ? (dryRun ? "would_carry" : "carried") : s.Reason == "ambiguous" ? "ambiguous" : "refused",
                s.Reason, s.Confidence, s.Tier, detail));
            if (s.NewRva != null || !s.Apply) targets.Add(("patch", p.Rva, s.NewRva, p.Description));
        }
        if (dryRun && steps.Count(s => s.Apply && s.Patch.IsStub) > 1)
            notes.Add("dry run: each re-created stub is placed as if it were the only one; applying places them one after another");
        categories[Patches] = (Status(dryRun), $"{patches.Count} patch(es) from {source}", null);
        return targets;
    }

    private static bool Same(NativePatch existing, MigratablePatch p)
    {
        if (p.IsStub)
            return existing.Stub is { } s && s.NewCode != null && p.StubCode != null && s.NewCode.AsSpan().SequenceEqual(p.StubCode)
                   && s.NewAssembly == p.StubAssembly && string.Equals(s.Mode, p.StubMode, StringComparison.OrdinalIgnoreCase);
        if (existing.Stub != null) return false;
        return p.FromAsm ? existing.Assembly == p.Assembly : existing.Replacement.AsSpan().SequenceEqual(p.Replacement);
    }

    private static void PatternStep(MatchResult match, List<(string Kind, uint OldRva, uint? NewRva, string Value)> targets, int maxPatterns, List<Item> items,
        Dictionary<string, (string Status, string Detail, int? Carried)> categories, List<string> notes, CancellationToken ct)
    {
        var distinct = targets.DistinctBy(t => t.OldRva).ToList();
        if (distinct.Count == 0)
        {
            categories[Patterns] = ("not_applicable", "no carried names or patch sites to make patterns for", null);
            return;
        }
        var oldIndex = match.Old.Index;
        var newIndex = match.New.Index;
        var newSections = CodePatterns.CodeSections(newIndex.Image);
        foreach (var (kind, oldRva, mappedRva, value) in distinct.Take(maxPatterns))
        {
            ct.ThrowIfCancellationRequested();
            MadePattern old;
            try { old = CodePatterns.Make(oldIndex, oldRva, 64, allowReference: true, referenceOnly: false, ct); }
            catch (Exception ex) when (ex is ToolError or NotSupportedException or ArgumentException)
            {
                items.Add(new Item(Patterns, "pattern", oldRva, mappedRva, "", "refused", "no_pattern", 0, null, $"{kind} '{value}': {ex.Message}"));
                continue;
            }
            string drift;
            uint? found = null;
            string evidence;
            if (!old.Unique || old.Pattern.Length == 0)
            {
                drift = "not_unique_in_old";
                evidence = $"no unique pattern on the old build ({old.Note})";
            }
            else
            {
                var hits = CodePatterns.Find(newSections, old.Pattern, 8, out int total, ct);
                var targetsHit = hits.Select(h => Target(newIndex.Image, old, h)).ToList();
                if (total == 0) drift = "not_found";
                else if (total > 1) drift = "now_ambiguous";
                else
                {
                    found = targetsHit[0];
                    drift = mappedRva == null || found == mappedRva ? "still_unique" : "points_elsewhere";
                }
                evidence = $"old pattern {old.Pattern} ({old.Anchor}) has {total} hit(s) in the new build" +
                           (found is { } f ? $" at rva 0x{f:X}" : total > 1 ? $": {string.Join(", ", targetsHit.Take(4).Select(t => t is { } x ? $"0x{x:X}" : "?"))}" : "") +
                           (drift == "still_unique" && mappedRva == null ? " (the function match did not map it; the pattern did)" : "");
            }
            uint? newRva = mappedRva ?? (drift == "still_unique" ? found : null);
            if (newRva is not { } at)
            {
                items.Add(new Item(Patterns, "pattern", oldRva, null, "", "refused", drift, 0, null, $"{kind} '{value}': {evidence}; no new address to make a pattern for"));
                continue;
            }
            MadePattern made;
            try { made = CodePatterns.Make(newIndex, at, 64, allowReference: true, referenceOnly: false, ct); }
            catch (Exception ex) when (ex is ToolError or NotSupportedException or ArgumentException)
            {
                items.Add(new Item(Patterns, "pattern", oldRva, at, "", "refused", drift, 0, null, $"{kind} '{value}': {evidence}; new pattern failed: {ex.Message}"));
                continue;
            }
            items.Add(new Item(Patterns, "pattern", oldRva, at, made.Pattern.ToString(), made.Unique ? "carried" : "ambiguous", drift,
                drift == "still_unique" ? 1 : drift == "points_elsewhere" ? 0.3 : 0.6, null,
                $"{kind} '{value}': {evidence}; new pattern ({made.Anchor}) " + (made.Unique ? "unique" : $"not unique: {made.Note}")));
        }
        if (distinct.Count > maxPatterns) notes.Add($"code patterns made for the first {maxPatterns} of {distinct.Count} items (maxPatterns)");
        categories[Patterns] = ("reported", $"patterns for carried names and patch sites, on both builds' original bytes ({Math.Min(maxPatterns, distinct.Count)} of {distinct.Count})", null);
    }

    /// <summary>The address a pattern hit stands for: the hit itself, or for a reference anchor the operand's target.</summary>
    private static uint? Target(INativeImage image, MadePattern p, uint hit)
    {
        if (p.Anchor != "reference") return hit;
        if (p.OperandOffset is not { } off || p.OperandSize is not { } size || size is not (4 or 8)) return null;
        var buf = new byte[size];
        if (image.Read(hit + (uint)off, buf) < size) return null;
        long value = size == 4 ? BitConverter.ToInt32(buf) : BitConverter.ToInt64(buf);
        return p.OperandKind switch
        {
            "relative" or "rip_relative" when p.InstructionEnd is { } end => (uint)(hit + end + value),
            "absolute" => (uint)((ulong)(size == 4 ? (uint)value : (ulong)value) - image.ImageBase),
            _ => null,
        };
    }
}
