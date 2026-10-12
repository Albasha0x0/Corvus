using System.ComponentModel;
using System.Text;
using ModelContextProtocol;
using ModelContextProtocol.Protocol;
using ModelContextProtocol.Server;
using Corvus.Core;
using Corvus.Native;
using Corvus.Native.Code;
using Corvus.Native.Diff;
using Corvus.Native.Patching;
using Corvus.Native.Pdb;
using Corvus.Services;
using static Corvus.Tools.ToolSupport;

namespace Corvus.Tools;

/// <summary>
/// One call that carries the work done on an old build of a native image to its new build: user names and comments,
/// imported name layers (PDB, Il2Cpp), byte patches (stub extensions re-created), rebuild-stable code patterns, and the
/// Il2Cpp method -&gt; RVA mapping, all through one build match, with one consolidated report.
/// </summary>
[McpServerToolType]
public sealed class BuildUpdateTools(AssemblyWorkspace workspace, NativeCodeService code, NativeEditService edits, PdbService pdb,
    Il2CppService il2cpp, Il2CppNavigator navigator, Il2CppNativeNames il2cppNames, Il2CppRawLoader? il2cppRaw = null, NotesService? noteStore = null,
    AssemblyComparer? comparer = null)
{
    public const string Names = "names", Pdb = "pdb", Il2CppNames = "il2cpp_names", Patches = "patches", Patterns = "patterns",
        Il2CppMapping = "il2cpp_mapping", NoteCategory = "notes", DotNet = "dotnet";
    private static readonly string[] CategoryOrder = [Names, Pdb, Il2CppNames, Patches, Patterns, Il2CppMapping, NoteCategory, DotNet];
    private static readonly string[] Outcomes = ["carried", "would_carry", "already_present", "refused", "not_applicable", "ambiguous"];
    private const int MaxIl2CppItems = 200_000;

    public sealed record ReasonCount(string Reason, int Count);

    public sealed record UpdateCategory(
        [property: Description("names, pdb, il2cpp_names, patches, patterns, il2cpp_mapping, notes or dotnet.")] string Category,
        [property: Description("applied, previewed (dryRun), reported (patterns and the Il2Cpp mapping change nothing), not_applicable, not_included or out_of_scope.")] string Status,
        int Considered,
        [property: Description("Carried to the new build (or would be, in a dry run).")] int Carried,
        [property: Description("Already on the new build (a re-run).")] int AlreadyPresent,
        int Refused, int NotApplicable, int Ambiguous,
        [property: Description("Item counts by reason code.")] IReadOnlyList<ReasonCount> Reasons,
        [property: Description("Counts by reason code of the items not carried (refused, not_applicable, ambiguous).")] IReadOnlyList<ReasonCount> NotCarriedBy,
        string Detail);

    public sealed record UpdateItem(
        string Category,
        [property: Description("name, comment, layer, patch, pattern, method, note; user types: declarations, type, local, stack_var.")] string Kind,
        string? OldAddress,
        string? NewAddress,
        [property: Description("The name, comment, patch description, new pattern or method identity.")] string Value,
        [property: Description("carried, would_carry, already_present, refused, not_applicable or ambiguous.")] string Outcome,
        [property: Description("Reason code: how it was carried or why not. Patterns: still_unique, now_ambiguous, not_found, points_elsewhere, not_unique_in_old. " +
                               "Il2Cpp mapping: agree, disagree, metadata_only, removed.")] string Reason,
        [property: Description("0-1.")] double Confidence,
        [property: Description("Function-match tier (1 best .. 5 fuzzy), or null.")] int? Tier,
        string Detail);

    public sealed record Il2CppMappingSummary(
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
        [property: Description("One paragraph: what carried over, what did not, and the next step.")] string Summary,
        string OldImage, string NewImage, bool DryRun,
        [property: Description("Categories included in this run.")] IReadOnlyList<string> Included,
        int OldFunctions, int NewFunctions, int FunctionsMatched,
        IReadOnlyList<UpdateCategory> Categories,
        [property: Description("The Il2Cpp method mapping (null when not applicable).")] Il2CppMappingSummary? Il2CppMapping,
        [property: Description("Item filter: category.")] string? Category,
        [property: Description("Item filter: outcome.")] string? Outcome,
        int Offset, int Total, bool Truncated,
        IReadOnlyList<UpdateItem> Items,
        [property: Description("What was not covered (functions that did not decode, capped work, scope).")] IReadOnlyList<string> Notes);

    private sealed record Item(string Category, string Kind, uint? OldRva, uint? NewRva, string Value, string Outcome, string Reason, double Confidence, int? Tier, string Detail);

    [McpServerTool(Name = "update_to_new_build", Title = "Update work to a new build", UseStructuredContent = true)]
    [Description("Carry work on an old build of a native image (x86 / x64 / ARM64) to its new build through one function match " +
                 "(compare_native_images): user names, comments and engine types (migrate_native_names rules); the PDB layer (from the new build's " +
                 "PDB) and the Il2Cpp layer (from its metadata, else mapped); byte patches (migrate_native_patches rules, stubs re-created after " +
                 "verification); code patterns checked for drift; the Il2Cpp method -> RVA mapping; notes. dryRun=false applies names, layers, then " +
                 "patches; a re-run reports already_present. Returns per-category counts with reason codes and a paged item list. Two .NET " +
                 "assemblies: notes, mapped by find_counterpart; edits: export_edits + apply_edits.")]
    public Task<UpdateReport> UpdateToNewBuild(
        [Description("The old build: native image id or path (the source of names, layers and patches).")] string oldImage,
        [Description("The new build: native image id or path (load both; the second gets an id like name#2).")] string newImage,
        [Description("Report what would carry over without changing the new build.")] bool dryRun = true,
        [Description("Comma-separated: names, pdb, il2cpp (names layer and method mapping), patches, patterns, notes; default all.")] string? include = null,
        [Description("A JSON patch set (export_native_patches format=json; path or text) instead of the old build's in-memory patches.")] string? patchSet = null,
        [Description("Where re-created patch stubs go: auto (default: a cave, else a new section), cave or section.")] string? stubPlacement = null,
        [Description("The old build's Il2Cpp dummy assemblies (comma-separated ids); omit to find them (a dump of this binary, the metadata beside it, or what apply_il2cpp_names used).")] string? oldIl2Cpp = null,
        [Description("The new build's Il2Cpp dummy assemblies (comma-separated ids); omit to find them the same way.")] string? newIl2Cpp = null,
        [Description("Match functions by export, PDB, Il2Cpp and user names first; false: code only.")] bool useNames = true,
        [Description("Most sites (names and patches) to make code patterns for (0-1000).")] int maxPatterns = 100,
        [Description("Only items of this category.")] string? category = null,
        [Description("Only items with this outcome.")] string? outcome = null,
        [Description("Items to skip.")] int offset = 0,
        [Description("Items to return (max 2000).")] int limit = 100,
        RequestContext<CallToolRequestParams> context = null!,
        CancellationToken cancellationToken = default) => OrderedProgress.Run(context, async progress =>
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
        limit = ClampLimit(limit, 2000);
        const int phases = 7;
        void Phase(int done, string message) => progress.Report(new ProgressNotificationValue { Progress = done, Total = phases, Message = message });
        if (comparer != null && await Task.Run(() => ManagedPair(oldImage, newImage), ct) is { } managed)
            return await Task.Run(() => DotNetUpdate(managed.Old, managed.New, dryRun, included, categoryFilter, outcomeFilter, offset, limit, ct), ct);

        Phase(0, "indexing both builds");
        var oldNative = await Resolve(oldImage, ct);
        var newNative = await Resolve(newImage, ct);
        if (ReferenceEquals(oldNative, newNative))
            throw new ToolError(ErrorCode.InvalidArgument, $"Both arguments name {oldNative.Id}.", "load the other build too and pass its id (e.g. name#2)");
        var oldIndex = await code.Index(oldNative, null, ct);
        var newIndex = await code.Index(newNative, null, ct);
        if (oldIndex.Support != CodeSupport.Full || newIndex.Support != CodeSupport.Full)
            throw new ToolError(ErrorCode.Unsupported, $"{(oldIndex.Support != CodeSupport.Full ? oldNative.Id : newNative.Id)}: x86, x64 or ARM64 code is needed on both builds.");
        if (oldIndex.Image.Arch != newIndex.Image.Arch)
            throw new ToolError(ErrorCode.Unsupported, $"{oldNative.Id} is {oldIndex.Image.Arch} and {newNative.Id} is {newIndex.Image.Arch}; builds for different architectures are not matched.");
        var matchOld = await Task.Run(() => Original(oldNative, oldIndex, ct), ct);
        var matchNew = await Task.Run(() => Original(newNative, newIndex, ct), ct);
        Phase(1, "matching functions");
        var match = await Task.Run(() => MatchCache.Get(matchOld, matchNew, new MatchOptions { UseNames = useNames }, ct), ct);
        var mapper = new AddressMapper(match);
        var notes = match.Notes.Distinct().ToList();
        if (match.Old.Failed + match.New.Failed > 0)
            notes.Add($"{match.Old.Failed} old and {match.New.Failed} new function(s) could not be decoded and match only by name or import");
        notes.AddRange(match.Old.Index.Truncations.Select(t => "old: " + t));
        notes.AddRange(match.New.Index.Truncations.Select(t => "new: " + t));

        var items = new List<Item>();
        var categories = new Dictionary<string, (string Status, string Detail, int? Carried)>();
        var patternTargets = new List<(string Kind, uint OldRva, uint? NewRva, string Value)>();
        string Carry(bool set) => set ? dryRun ? "would_carry" : "carried" : "refused";
        string Status() => dryRun ? "previewed" : "applied";

        // ---- names (user layer) ----
        Phase(2, "names");
        if (included.Contains(Names))
        {
            var oldAnn = code.Annotations(oldNative);
            var sources = oldAnn.Names().Select(x => new MigrationSource("name", NativeNameSource.User, x.Rva, x.Name))
                .Concat(oldAnn.Comments().Select(x => new MigrationSource("comment", NativeNameSource.User, x.Rva, x.Comment)))
                .Concat(oldAnn.PseudoComments().Select(x => new MigrationSource(NameMigration.PseudoComment, NativeNameSource.User, x.Rva, x.Comment))).ToList();
            var newAnn = code.Annotations(newNative);
            var steps = await Task.Run(() => NameMigration.Plan(mapper, sources, match.New.Index, newAnn, new MigrationOptions(), ct), ct);
            foreach (var s in steps)
            {
                string result = s.Set ? Carry(true) : s.Reason is "same_name" or "same_comment" ? "already_present" : s.Reason == "ambiguous" ? "ambiguous" : "refused";
                items.Add(new Item(Names, s.Item.Kind, s.Item.OldRva, s.NewRva, s.Value, result, s.Reason, s.Confidence, s.Tier, s.Detail));
                if (s.Item.Kind == "name") patternTargets.Add(("name", s.Item.OldRva, s.NewRva, s.Value));
            }
            var setNames = steps.Where(s => s.Set && s.Item.Kind == "name").Select(s => (s.NewRva!.Value, s.Value)).ToList();
            var setComments = steps.Where(s => s.Set && s.Item.Kind == "comment").Select(s => (s.NewRva!.Value, s.Value)).ToList();
            var setPseudo = steps.Where(s => s.Set && s.Item.Kind == NameMigration.PseudoComment).Select(s => (s.NewRva!.Value, s.Value)).ToList();
            if (!dryRun && (setNames.Count > 0 || setComments.Count > 0 || setPseudo.Count > 0))
                workspace.Write(() =>
                {
                    newAnn.SetMany(setNames, setComments, setPseudo);
                    foreach (var index in new[] { match.New.Index, code.Ready(newNative) }.OfType<NativeCodeIndex>().Distinct())
                    {
                        foreach (var (rva, name) in setNames) index.SetUserName(rva, name);
                        foreach (var (rva, text) in setComments) index.SetUserComment(rva, text);
                    }
                    return 0;
                });
            var typeSteps = await Task.Run(() => UserTypeMigration.Plan(mapper, oldAnn.UserTypes, newAnn.UserTypes, new MigrationOptions(), ct), ct);
            foreach (var s in typeSteps)
                items.Add(new Item(Names, s.Kind, s.OldRva, s.NewRva, s.Value, s.Set ? Carry(true) : s.Reason.StartsWith("same_", StringComparison.Ordinal) ? "already_present"
                    : s.Reason == "ambiguous" ? "ambiguous" : "refused", s.Reason, s.Confidence, s.Tier, s.Detail));
            if (!dryRun && typeSteps.Any(s => s.Set)) newAnn.ChangeUserTypes(l => UserTypeMigration.Apply(l, typeSteps));
            categories[Names] = (sources.Count + typeSteps.Count == 0 ? "not_applicable" : Status(),
                sources.Count + typeSteps.Count == 0 ? $"{oldNative.Id} has no user names, comments or types"
                    : $"{sources.Count} user name(s) and comment(s) and {typeSteps.Count} user type(s) of {oldNative.Id}", null);
        }

        Phase(3, "imported names");
        if (included.Contains(Pdb)) await PdbLayer(oldNative, newNative, dryRun, items, categories, ct);

        // ---- Il2Cpp: method mapping (read-only) and the names layer ----
        Il2CppMappingSummary? mappingSummary = null;
        if (included.Contains(Il2CppNames))
        {
            var oldScope = await Task.Run(() => Il2CppScope(oldNative, oldIl2Cpp, notes, ct), ct);
            var newScope = await Task.Run(() => Il2CppScope(newNative, newIl2Cpp, notes, ct), ct);
            bool sameMetadata = oldScope.Scope != null && newScope.Scope != null && oldScope.Scope.ToHashSet().SetEquals(newScope.Scope);
            if (sameMetadata) notes.Add("both builds resolve to the same Il2Cpp dummy assemblies: pass oldIl2Cpp / newIl2Cpp to tell them apart");
            mappingSummary = await Task.Run(() => Il2CppMap(oldScope, newScope, sameMetadata, mapper, items, categories, ct), ct);
            await Task.Run(() => Il2CppLayer(oldNative, newNative, sameMetadata ? (null, "") : newScope, newIndex, mapper, dryRun, items, categories, ct), ct);
        }

        Phase(4, "patches");
        if (included.Contains(Patches))
        {
            var applied = await PatchStep(oldNative, newNative, newIndex, match, mapper, patchSet, placement, dryRun, items, categories, notes, ct);
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
        return new UpdateReport(Summary(oldNative.Id, newNative.Id, dryRun, match, categoryList, mappingSummary), oldNative.Id, newNative.Id, dryRun,
            CategoryOrder.Where(included.Contains).ToList(),
            match.Old.Functions.Length, match.New.Functions.Length, match.Pairs.Count, categoryList, mappingSummary,
            categoryFilter, outcomeFilter, offset, filtered.Count, offset + limit < filtered.Count, page, notes.Distinct().ToList());
    });

    private static HashSet<string> ParseInclude(string? include)
    {
        var set = new HashSet<string>(StringComparer.Ordinal);
        foreach (var part in (string.IsNullOrWhiteSpace(include) ? "all" : include).Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            switch (part.ToLowerInvariant())
            {
                case "all": set.UnionWith([Names, Pdb, Il2CppNames, Il2CppMapping, Patches, Patterns, NoteCategory]); break;
                case "notes": set.Add(NoteCategory); break;
                case "names": set.Add(Names); break;
                case "pdb": set.Add(Pdb); break;
                case "il2cpp" or "il2cpp_names" or "il2cpp_mapping": set.Add(Il2CppNames); set.Add(Il2CppMapping); break;
                case "patches": set.Add(Patches); break;
                case "patterns": set.Add(Patterns); break;
                default:
                    throw new ToolError(ErrorCode.InvalidArgument, $"Unknown category '{part}' in include.", "use names, pdb, il2cpp, patches, patterns, notes or all, comma-separated");
            }
        }
        return set;
    }

    /// <summary>
    /// Notes on the old build's addresses (and on the whole file) recorded again on the new build at the mapped address, with
    /// the old address as evidence; a note already there with the same text is already_present.
    /// </summary>
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
                items.Add(new Item(NoteCategory, "note", n.Anchor.Rva, newRva, text, "already_present", "same_note", confidence, tier, detail));
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
        foreach (var c in new[] { Names, Pdb, Il2CppNames, Il2CppMapping, Patches, Patterns })
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
        return new UpdateReport(sb.ToString(), oldAsm.Id, newAsm.Id, dryRun, CategoryOrder.Where(included.Contains).ToList(),
            Methods(oldAsm), Methods(newAsm), cmp.MemberMap.Keys.Count(k => k is dnlib.DotNet.MethodDef), categoryList, null,
            categoryFilter, outcomeFilter, offset, filtered.Count, offset + limit < filtered.Count, page,
            ["a .NET pair: notes are mapped by find_counterpart; addresses are metadata tokens"]);
    }

    /// <summary>
    /// Notes on the old build's members (and on the whole file) recorded again on the counterpart in the new build, with the
    /// old token as evidence; ambiguous and unmatched members are reported, not guessed.
    /// </summary>
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
                (reason, detail) = (found.Tier ?? "matched", $"{Format.MemberLabel(member)} -> {Format.MemberLabel(match)} ({found.How})");
                confidence = found.Confidence switch { "exact" => 1, "strong" => 0.9, _ => 0.7 };
                anchor = n.Anchor with { Sha256 = newAsm.OriginalSha256, Mvid = newMvid, Token = newToken, Label = $"{newAsm.Id}:{Format.MemberLabel(match)}" };
            }
            else anchor = n.Anchor with { Sha256 = newAsm.OriginalSha256, Label = newAsm.Id };
            if (existing.Any(e => e.Text == n.Text && e.Anchor.Kind == n.Anchor.Kind && e.Anchor.Token == newToken))
            {
                items.Add(new Item(NoteCategory, "note", n.Anchor.Token, newToken, text, "already_present", "same_note", confidence, null, detail));
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
            mine.Count(i => i.Outcome == "not_applicable"), mine.Count(i => i.Outcome == "ambiguous"), Count(mine),
            Count(mine.Where(i => i.Outcome is "refused" or "not_applicable" or "ambiguous")), c.Detail);
    }

    private static string Summary(string oldId, string newId, bool dryRun, MatchResult match, List<UpdateCategory> categories, Il2CppMappingSummary? map)
    {
        var sb = new StringBuilder();
        sb.Append(dryRun ? "Dry run (nothing changed): " : "Applied: ");
        sb.Append($"{oldId} -> {newId}, {match.Pairs.Count} of {match.Old.Functions.Length} old functions matched. ");
        AppendCategories(sb, categories, dryRun, map);
        sb.Append(dryRun ? "Run again with dryRun=false to apply." : "Run again to verify: carried items then report already_present.");
        return sb.ToString();
    }

    private static void AppendCategories(StringBuilder sb, List<UpdateCategory> categories, bool dryRun, Il2CppMappingSummary? map)
    {
        foreach (var c in categories.Where(c => c.Status is not ("not_included" or "out_of_scope")))
        {
            if (c.Category == Il2CppMapping && map != null)
            {
                sb.Append($"il2cpp mapping: {map.Agree} agree, {map.Disagree} disagree, {map.MetadataOnly} metadata only, {map.Removed} removed, {map.Added} added. ");
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

    /// <summary>
    /// The Il2Cpp dummy assemblies of <paramref name="native"/>: the given ones, else the loaded dump made from this binary,
    /// else the Il2Cpp metadata beside it (built-in reader), else what apply_il2cpp_names used for it; null when none.
    /// </summary>
    private (List<LoadedAssembly>? Scope, string Source) Il2CppScope(LoadedNative native, string? explicitScope, List<string> notes, CancellationToken ct)
    {
        if (!string.IsNullOrWhiteSpace(explicitScope))
        {
            var given = workspace.Read(() => explicitScope.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                .Select(workspace.Get).Distinct().Where(a => il2cpp.GetIndex(a).Count > 0).ToList());
            if (given.Count == 0)
                throw new ToolError(ErrorCode.InvalidArgument, $"'{explicitScope}' names no Il2Cpp dummy assembly (methods with [Address] attributes).",
                    "pass the ids of the build's DummyDll assemblies (list_assemblies), or omit it to find them");
            return (given, "assemblies " + string.Join(", ", given.Select(a => a.Id)));
        }
        if (FromDumps(native) is { } found) return found;
        Il2CppGameFiles? game = null;
        try { game = Il2CppGameFiles.Find(native.FilePath, native.SliceName); }
        catch (ToolError ex) { notes.Add($"{native.Id}: {ex.Message}"); }
        if (game != null && string.Equals(Path.GetFullPath(game.Binary), native.FilePath, StringComparison.OrdinalIgnoreCase))
        {
            try
            {
                (il2cppRaw ?? new Il2CppRawLoader(workspace)).Load(game, loadBinary: false, null, ct);
                if (FromDumps(native) is { } read) return read;
            }
            catch (ToolError ex) { notes.Add($"{native.Id}: Il2Cpp metadata {game.Metadata} not read: {ex.Message}"); }
        }
        if (Il2CppNativeNames.Of(native) is { } applied) return (applied.Image.Assemblies.ToList(), $"the dummy assemblies apply_il2cpp_names used ({applied.Assemblies})");
        return (null, "");
    }

    private (List<LoadedAssembly>, string)? FromDumps(LoadedNative native) => workspace.Read(() =>
    {
        var all = workspace.Assemblies.Where(a => il2cpp.GetIndex(a).Count > 0).ToList();
        if (all.Count == 0) return ((List<LoadedAssembly>, string)?)null;
        var image = navigator.ImagesFor(all).FirstOrDefault(i => i.Dump?.Files.Describes(native) == true);
        return image == null ? null : (image.Assemblies.ToList(), $"the Il2Cpp metadata in {image.Dump!.Files.Directory}");
    });

    private List<Il2CppBuildMap.Method> Methods(List<LoadedAssembly> scope) => workspace.Read(() =>
        scope.SelectMany(a => il2cpp.GetIndex(a)).Where(m => m.Rva is > 0 and <= uint.MaxValue)
            .Select(m => new Il2CppBuildMap.Method(m.Assembly.AssemblyName + "|" + m.Method.FullName, (uint)m.Rva!.Value)).ToList());

    private Il2CppMappingSummary? Il2CppMap((List<LoadedAssembly>? Scope, string Source) oldScope, (List<LoadedAssembly>? Scope, string Source) newScope, bool same,
        AddressMapper mapper, List<Item> items, Dictionary<string, (string Status, string Detail, int? Carried)> categories, CancellationToken ct)
    {
        if (oldScope.Scope == null || newScope.Scope == null || same)
        {
            categories[Il2CppMapping] = ("not_applicable", same ? "both builds resolve to the same Il2Cpp metadata"
                : oldScope.Scope == null && newScope.Scope == null ? "no Il2Cpp metadata for either build"
                : oldScope.Scope == null ? "no Il2Cpp metadata for the old build" : "no Il2Cpp metadata for the new build", null);
            return null;
        }
        var oldMethods = Methods(oldScope.Scope);
        var newMethods = Methods(newScope.Scope);
        var result = Il2CppBuildMap.Map(oldMethods, newMethods, rva =>
        {
            var m = mapper.Map(rva, ct);
            return new Il2CppBuildMap.NativeAnswer(m.NewRva, m.Pair?.Tier, m.Pair?.Basis, m.Confidence, m.Reason);
        }, ct);
        foreach (var e in result.Entries.Take(MaxIl2CppItems))
        {
            string outcome = e.Status switch { "agree" or "disagree" or "metadata_only" => "carried", "removed" => "refused", _ => "ambiguous" };
            items.Add(new Item(Il2CppMapping, "method", e.OldRva, e.NewRva, e.Key, outcome, e.Status, e.Confidence, e.Tier, e.Detail));
        }
        categories[Il2CppMapping] = ("reported", $"old: {oldScope.Source}; new: {newScope.Source}" +
            (result.Entries.Count > MaxIl2CppItems ? $"; items listed for the first {MaxIl2CppItems}" : ""), null);
        return new Il2CppMappingSummary(oldScope.Source, newScope.Source, result.OldMethods, result.NewMethods, result.Count("agree"),
            result.Entries.Count(e => e.Status == "agree" && e.Basis != "name"), result.Count("disagree"), result.Count("metadata_only"),
            result.Count("removed"), result.Added, result.Count("ambiguous"));
    }

    /// <summary>
    /// The new build's Il2Cpp names: re-applied from its own metadata when it has some, else the old build's layer mapped
    /// through the function match and saved as a layer whose origin says it was carried by match.
    /// </summary>
    private void Il2CppLayer(LoadedNative oldNative, LoadedNative newNative, (List<LoadedAssembly>? Scope, string Source) newScope, NativeCodeIndex newIndex,
        AddressMapper mapper, bool dryRun, List<Item> items, Dictionary<string, (string Status, string Detail, int? Carried)> categories, CancellationToken ct)
    {
        var layers = NativeNameLayers.Of(newNative);
        if (newScope.Scope is { } scope)
        {
            // a re-run: the layer applied from the same dummy assemblies is in place
            if (layers.Get(NativeNameSource.Il2Cpp) is { } applied && applied.Origin == $"Il2Cpp metadata ({string.Join(", ", scope.Select(a => a.Id))})")
            {
                items.Add(new Item(Il2CppNames, "layer", null, null, newScope.Source, "already_present", "applied_from_metadata", 1, null,
                    $"the new build already has {applied.Names.Count} Il2Cpp names from {applied.Origin}"));
                categories[Il2CppNames] = (Status(dryRun), $"the new build has its own metadata ({newScope.Source})", 0);
                return;
            }
            if (dryRun)
            {
                int functions = Methods(scope).Select(m => m.Rva).Distinct().Count();
                items.Add(new Item(Il2CppNames, "layer", null, null, newScope.Source, "would_carry", "reapply_from_metadata", 1, null,
                    $"apply_il2cpp_names from {newScope.Source}: about {functions} function(s) with dummy methods, plus script.json instantiations and slots when present"));
                categories[Il2CppNames] = ("previewed", $"the new build has its own metadata ({newScope.Source})", functions);
                return;
            }
            var index = code.Ready(newNative) ?? newIndex;
            var r = workspace.Read(() => il2cppNames.Apply(newNative, index, scope, ct));
            items.Add(new Item(Il2CppNames, "layer", null, null, newScope.Source, "carried", "reapplied_from_metadata", 1, null,
                $"{r.Functions} functions, {r.Strings} strings, {r.MetadataSlots} metadata and {r.MethodInfoSlots} MethodInfo slots named; {r.UserNamesKept} user names kept"));
            categories[Il2CppNames] = ("applied", $"re-applied from the new build's own metadata ({newScope.Source})", r.Functions);
            return;
        }
        var oldLayer = NativeNameLayers.OfOrNull(oldNative)?.Get(NativeNameSource.Il2Cpp);
        if (oldLayer == null)
        {
            categories[Il2CppNames] = ("not_applicable", "no Il2Cpp names on the old build and no metadata for the new build", null);
            return;
        }
        if (layers.Get(NativeNameSource.Il2Cpp) is { } own && !own.Origin.StartsWith(CarriedOrigin, StringComparison.Ordinal))
        {
            items.Add(new Item(Il2CppNames, "layer", null, null, own.Origin, "not_applicable", "new_has_own_il2cpp_names", 0, null,
                $"the new build already has Il2Cpp names ({own.Names.Count}, {own.Origin}); they are kept"));
            categories[Il2CppNames] = (Status(dryRun), "the new build has its own Il2Cpp names", null);
            return;
        }

        // carry by match
        var names = new Dictionary<uint, string>();
        var comments = new Dictionary<uint, string>();
        var firstAt = new Dictionary<uint, uint>();
        var current = layers.Get(NativeNameSource.Il2Cpp);
        int n = 0;
        foreach (var (oldRva, name) in oldLayer.Names.OrderBy(kv => kv.Key))
        {
            if ((++n & 0xFFF) == 0) ct.ThrowIfCancellationRequested();
            var m = mapper.Map(oldRva, ct);
            if (m.NewRva is not { } at)
            {
                items.Add(new Item(Il2CppNames, "name", oldRva, null, name, m.Reason == "ambiguous" ? "ambiguous" : "refused", m.Reason, m.Confidence, m.Pair?.Tier, m.Detail));
                continue;
            }
            if (firstAt.TryGetValue(at, out var earlier))
            {
                items.Add(new Item(Il2CppNames, "name", oldRva, at, name, "refused", "duplicate_target", m.Confidence, m.Pair?.Tier, $"the name from rva 0x{earlier:X} already lands there"));
                continue;
            }
            firstAt[at] = oldRva;
            names[at] = name;
            var note = $"[il2cpp name carried by match from {oldNative.Id}, confidence {m.Confidence:0.##}]";
            comments[at] = oldLayer.Comments.TryGetValue(oldRva, out var c) ? $"{c} {note}" : note;
            bool present = current?.Names.TryGetValue(at, out var had) == true && had == name;
            items.Add(new Item(Il2CppNames, "name", oldRva, at, name, present ? "already_present" : Carry(dryRun), m.Reason, m.Confidence, m.Pair?.Tier, "carried by match: " + m.Detail));
        }
        if (!dryRun && names.Count > 0)
        {
            var info = new ImportInfo(oldLayer.Info?.SourcePath, $"carried-by-match {oldNative.OriginalSha256}", DateTime.UtcNow);
            var index = code.Ready(newNative) ?? newIndex;
            layers.Set(new NativeNameLayers.Layer(NativeNameSource.Il2Cpp, names, comments, $"{CarriedOrigin} {oldNative.Id} ({oldLayer.Origin})", info), index);
            if (code.SaveImported(newNative, NativeNameSource.Il2Cpp) is { } problem)
                items.Add(new Item(Il2CppNames, "layer", null, null, "save", "refused", "not_saved", 0, null, $"names not saved for the next load: {problem}"));
        }
        categories[Il2CppNames] = (Status(dryRun), $"no metadata for the new build: the old build's {oldLayer.Names.Count} Il2Cpp names mapped through the function match", null);
        string Carry(bool dry) => dry ? "would_carry" : "carried";
    }

    private const string CarriedOrigin = "carried by match from";

    private async Task<List<(string Kind, uint OldRva, uint? NewRva, string Value)>> PatchStep(LoadedNative oldNative, LoadedNative newNative, NativeCodeIndex newIndex,
        MatchResult match, AddressMapper mapper, string? patchSet, StubPlacement placement, bool dryRun, List<Item> items,
        Dictionary<string, (string Status, string Detail, int? Carried)> categories, List<string> notes, CancellationToken ct)
    {
        List<MigratablePatch> patches;
        string source;
        // a json patch set is written for PE images; in-memory patches carry between builds of one format
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
                items.Add(new Item(Patches, "patch", p.Rva, at, p.Description, "already_present", "same_patch", m.Confidence, m.Pair?.Tier,
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
            // what applying would refuse for an existing patch of the new build
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
                    edits.ApplyPatch(newNative, currentNew, prepared, dryRun: false);
                    currentNew = await code.Index(newNative, null, ct);
                    updated.Add(step with { Status = "applied" });
                }
                catch (ToolError ex)
                {
                    var reason = System.Text.RegularExpressions.Regex.Match(ex.Message, "^([a-z0-9_]+): ") is { Success: true } m ? m.Groups[1].Value
                        : ex.Code == ErrorCode.Conflict ? "conflicts_with_existing_patch" : "cannot_prepare";
                    updated.Add(step with { Apply = false, Status = "refused", Reason = reason, Detail = ex.Message, NewReplacement = null });
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

    private static readonly System.Runtime.CompilerServices.ConditionalWeakTable<LoadedNative, Tuple<string, NativeCodeIndex>> Originals = new();

    /// <summary>
    /// The index the builds are matched on: the live one, or for a patched image one over its original bytes (patches
    /// would hide a patched function's identity), kept per image while its names stay the same so a dry run and the
    /// apply that follows match once.
    /// </summary>
    private NativeCodeIndex Original(LoadedNative native, NativeCodeIndex live, CancellationToken ct)
    {
        if (!native.HasPatches) return live;
        var ann = code.Annotations(native);
        var stamp = $"{ann.NameCount}|{ann.CommentCount}|" + string.Join(",", NativeNameLayers.Of(native).Layers.Select(l => $"{l.Source}:{l.Names.Count}:{l.Origin}"));
        if (Originals.TryGetValue(native, out var kept) && kept.Item1 == stamp) return kept.Item2;
        var index = code.IndexOfOriginal(native, ct);
        Originals.AddOrUpdate(native, Tuple.Create(stamp, index));
        return index;
    }

    private Task<LoadedNative> Resolve(string image, CancellationToken ct) => Task.Run(() =>
    {
        return Targets.Native(workspace, image);
    }, ct);
}
