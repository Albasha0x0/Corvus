using System.ComponentModel;
using System.Diagnostics;
using ModelContextProtocol;
using ModelContextProtocol.Protocol;
using ModelContextProtocol.Server;
using NetDecompilerMcp.Core;
using NetDecompilerMcp.Native;
using NetDecompilerMcp.Native.Code;
using NetDecompilerMcp.Native.Diff;
using NetDecompilerMcp.Services;
using static NetDecompilerMcp.Tools.ToolSupport;

namespace NetDecompilerMcp.Tools;

/// <summary>Two builds of one native image: function matching, carrying names and addresses forward, and rebuild-stable code patterns.</summary>
[McpServerToolType]
public sealed class NativeDiffTools(AssemblyWorkspace workspace, NativeCodeService code)
{
    private const string OldDescription = "The older build: native image id (e.g. game.dll) or path. Load both builds; the second gets an id like game.dll#2.";
    private const string NewDescription = "The newer build: native image id (e.g. game.dll#2) or path.";
    private const string UseNamesDescription =
        "Match functions by names from exports, PDB, Il2Cpp and user annotations (tier 1). false matches on code alone.";

    public sealed record TierCount(
        [property: Description("1 name_or_bytes, 2 structure, 3 signature, 4 call_graph, 5 fuzzy.")] int Tier, string Name, int Pairs);

    public sealed record FunctionPair(
        string OldAddress, string NewAddress, string OldName, string NewName,
        int Tier,
        [property: Description("What matched: name, import_thunk, identical_bytes, structure, signature, callee_position, callee, caller, context, table_slot, fuzzy.")] string Basis,
        [property: Description("Similarity 0-1 (1 for name and identical-byte matches).")] double Score,
        uint OldSize, uint NewSize, int OldBlocks, int NewBlocks, int OldCalls, int NewCalls,
        [property: Description("Same bytes after masking addresses.")] bool Identical,
        [property: Description("What differs: size, blocks, instructions, calls; 'identical' or 'moved' when nothing else.")] string Changes);

    public sealed record UnmatchedFunction(
        [property: Description("old or new.")] string Side, string Address, string Name, uint Size, int Blocks,
        [property: Description("ambiguous, below_min_score, too_small, not_decoded, not_in_new_build, new_in_this_build.")] string Reason,
        [property: Description("Best similarity seen to any candidate, when one was compared.")] double? BestScore);

    public sealed record MatchCandidate(string Address, string Name, double Score);

    public sealed record AmbiguousEntry(string Side, string Address, string Name,
        [property: Description("identical_code, same_structure, same_signature or close_scores.")] string Reason,
        IReadOnlyList<MatchCandidate> Candidates);

    public sealed record NativeComparison(
        string OldImage, string NewImage, int OldFunctions, int NewFunctions, int Matched,
        [property: Description("Matched pairs with identical masked bytes.")] int Identical,
        int Changed, int UnmatchedOld, int UnmatchedNew, int Ambiguous,
        IReadOnlyList<TierCount> Tiers,
        [property: Description("The list returned: pairs, changed, unmatched or ambiguous.")] string View,
        int Offset, int Total, bool Truncated,
        IReadOnlyList<FunctionPair> Pairs, IReadOnlyList<UnmatchedFunction> Unmatched, IReadOnlyList<AmbiguousEntry> AmbiguousFunctions,
        [property: Description("What was not covered (functions that did not decode, capped work).")] IReadOnlyList<string> Notes,
        double Seconds);

    public sealed record AddressMapping(
        string OldImage, string NewImage, string OldAddress,
        [property: Description("The address in the new build, or null when it could not be mapped.")] string? NewAddress,
        [property: Description("0-1: the function match's trust times how exactly the instruction aligned.")] double Confidence,
        [property: Description("function_start, aligned_instruction, replaced_instruction, same_string, followed_references; or why not: " +
                               "function_not_matched, ambiguous, instruction_removed, changed_region, conflicting_references, no_reference_to_follow, not_an_instruction.")]
        string Reason,
        string Detail, string? OldFunction, string? NewFunction, int? Tier,
        [property: Description("Candidate or nearby new addresses when not mapped.")] IReadOnlyList<string> Candidates);

    public sealed record MigrationEntry(
        [property: Description("name or comment.")] string Kind,
        [property: Description("Layer it came from in the old build: user, pdb or il2cpp.")] string Source,
        string OldAddress, string? NewAddress, string Value,
        [property: Description("set (or would_set in a dry run) or skipped.")] string Action,
        [property: Description("For set: how the address was mapped. For skipped: same_name, same_comment, user_name_exists, user_comment_exists, " +
                               "name_in_use, new_has_own_name, duplicate_target, invalid_name, below_min_tier, below_min_score, or the mapping's reason.")]
        string Reason,
        int? Tier, double Confidence, string Detail);

    public sealed record ReasonCount(string Reason, int Count);

    public sealed record MigrationReport(
        string OldImage, string NewImage, bool DryRun, int Considered, int Set, int Skipped,
        IReadOnlyList<ReasonCount> SkippedBy, int Offset, int Total, bool Truncated, IReadOnlyList<MigrationEntry> Entries, IReadOnlyList<string> Notes);

    public sealed record CodePatternResult(
        string Image, string Address,
        [property: Description("IDA-style pattern, ?? for bytes that change between builds; empty when none could be made.")] string Pattern,
        int Length, int FixedBytes, bool Unique,
        [property: Description("Occurrences in the image's executable sections.")] int Hits,
        [property: Description("address: the pattern starts at the address; reference: at (or shortly before) an instruction referencing it.")] string Anchor,
        [property: Description("Where the pattern starts.")] string PatternAddress,
        [property: Description("Reference anchor: offset of the referencing instruction from the pattern start.")] int? ReferenceOffset,
        [property: Description("Reference anchor: offset of the address operand from the pattern start.")] int? OperandOffset,
        int? OperandSize,
        [property: Description("relative, rip_relative or absolute.")] string? OperandKind,
        [property: Description("Reference anchor: offset of the end of the referencing instruction (relative operands count from it).")] int? InstructionEnd,
        string Note);

    public sealed record PatternHit(string Image, string Address, string Section, string? Function, string? FunctionAddress, uint? FunctionOffset);

    public sealed record PatternSearch(string Pattern, int Length, int Images, int Total, bool Truncated, IReadOnlyList<PatternHit> Hits, IReadOnlyList<string> Notes);

    [McpServerTool(Name = "compare_native_images", Title = "Compare native builds", UseStructuredContent = true)]
    [Description("Match the functions of two builds of one native image (x86 / x64), e.g. before and after an application update. Tiers, each accepting a pair " +
                 "only when unique on both sides: 1 same name (export, PDB, Il2Cpp, user), same import thunk, or identical bytes with addresses masked; " +
                 "2 same canonical control-flow graph and instruction shapes; 3 same imports, strings and constants; 4 call-graph propagation from matched " +
                 "pairs (callees in the same position, mutually best callers / callees, callers and callees in common, the same slot of matched " +
                 "function-pointer tables such as vtables) to a fixed point; 5 fuzzy similarity (instruction mix, graph, size, " +
                 "references, matched neighbors) above minScore with a margin over the runner-up. Returns per-tier counts and one paged list (view): pairs " +
                 "with tier, score and what changed; changed pairs; unmatched functions with the reason; ambiguous functions with their candidates. " +
                 "The first call waits for both code indexes; results are cached until names change.")]
    public async Task<NativeComparison> CompareNativeImages(
        [Description(OldDescription)] string oldImage,
        [Description(NewDescription)] string newImage,
        [Description("List to return: pairs (default), changed (pairs whose code differs), unmatched, ambiguous.")] string? view = null,
        [Description("Only pairs of this tier (1-5); 0 for all.")] int tier = 0,
        [Description(UseNamesDescription)] bool useNames = true,
        [Description("Least similarity for a fuzzy match (0-1, default 0.7).")] double minScore = 0.7,
        [Description("Items to skip.")] int offset = 0,
        [Description("Items to return (default 100, max 2000).")] int limit = 100,
        RequestContext<CallToolRequestParams> context = null!,
        CancellationToken cancellationToken = default)
    {
        var sw = Stopwatch.StartNew();
        var v = (view ?? "pairs").Trim().ToLowerInvariant();
        if (v is not ("pairs" or "changed" or "unmatched" or "ambiguous"))
            throw new ToolError(ErrorCode.InvalidArgument, $"Unknown view '{view}'.", "use pairs, changed, unmatched or ambiguous");
        if (tier is < 0 or > 5) throw new ToolError(ErrorCode.InvalidArgument, $"tier must be 0-5, not {tier}.");
        var (oldNative, newNative, match) = await Match(oldImage, newImage, useNames, minScore, context, cancellationToken);
        var o = match.Old.Index;
        var n = match.New.Index;
        offset = Math.Max(0, offset);
        limit = ClampLimit(limit, 2000);

        var pairs = new List<FunctionPair>();
        var unmatched = new List<UnmatchedFunction>();
        var ambiguous = new List<AmbiguousEntry>();
        int total;
        if (v is "pairs" or "changed")
        {
            var selected = match.Pairs.Where(p => tier == 0 || p.Tier == tier)
                .Where(p => v == "pairs" || !Identical(match, p)).OrderBy(p => match.Old.Functions[p.Old].Start).ToList();
            total = selected.Count;
            pairs.AddRange(selected.Skip(offset).Take(limit).Select(p => Pair(match, p)));
        }
        else if (v == "unmatched")
        {
            var all = Unmatched(match).ToList();
            total = all.Count;
            unmatched.AddRange(all.Skip(offset).Take(limit));
        }
        else
        {
            var all = match.Ambiguous.Values.OrderBy(a => !a.OldSide).ThenBy(a => Prints(match, a.OldSide)[a.Index].Start).ToList();
            total = all.Count;
            foreach (var a in all.Skip(offset).Take(limit))
            {
                var self = Prints(match, a.OldSide)[a.Index];
                var otherSide = Prints(match, !a.OldSide);
                var (selfIndex, otherIndex) = a.OldSide ? (o, n) : (n, o);
                ambiguous.Add(new AmbiguousEntry(a.OldSide ? "old" : "new", Va(selfIndex, self.Start), Name(selfIndex, self.Function), a.Reason,
                    a.Candidates.Take(8).Select(c => new MatchCandidate(Va(otherIndex, otherSide[c.Index].Start), Name(otherIndex, otherSide[c.Index].Function),
                        Math.Round(c.Score, 3))).ToList()));
            }
        }

        int identical = match.Pairs.Count(p => Identical(match, p));
        var tiers = Enumerable.Range(1, 5).Select(t => new TierCount(t, MatchResult.TierNames[t], match.Pairs.Count(p => p.Tier == t))).ToList();
        var notes = Notes(match);
        return new NativeComparison(oldNative.Id, newNative.Id, match.Old.Functions.Length, match.New.Functions.Length, match.Pairs.Count, identical,
            match.Pairs.Count - identical, match.ByOld.Count(m => m == null), match.ByNew.Count(m => m == null), match.Ambiguous.Count, tiers, v,
            offset, total, offset + limit < total, pairs, unmatched, ambiguous, notes, Math.Round(sw.Elapsed.TotalSeconds, 2));
    }

    [McpServerTool(Name = "map_address_between_builds", Title = "Map an address to a new build", UseStructuredContent = true)]
    [Description("Where an address of the old build is in the new build: a function start goes to the matched function (compare_native_images), " +
                 "an address inside a function to the corresponding instruction after aligning both instruction sequences, a string literal to the same " +
                 "string, other data by following the old build's references through matched instructions. Returns the new address with a confidence " +
                 "and the reason, or null with why (and nearby candidates).")]
    public async Task<AddressMapping> MapAddressBetweenBuilds(
        [Description(OldDescription)] string oldImage,
        [Description(NewDescription)] string newImage,
        [Description("Address in the old build: " + NativeTools.AddressDescription)] string address,
        [Description(UseNamesDescription)] bool useNames = true,
        RequestContext<CallToolRequestParams> context = null!,
        CancellationToken cancellationToken = default)
    {
        var (oldNative, newNative, match) = await Match(oldImage, newImage, useNames, 0.7, context, cancellationToken);
        var o = match.Old.Index;
        var n = match.New.Index;
        uint rva = NativeCodeTools.Address(o, address);
        var mapped = await Task.Run(() => new AddressMapper(match).Map(rva, cancellationToken), cancellationToken);
        var oldFn = o.FunctionAt(rva);
        var newFn = mapped.NewRva is { } nr ? n.FunctionAt(nr) : mapped.Pair is { } p ? match.New.Functions[p.New].Function : null;
        return new AddressMapping(oldNative.Id, newNative.Id, Va(o, rva), mapped.NewRva is { } at ? Va(n, at) : null, mapped.Confidence, mapped.Reason, mapped.Detail,
            oldFn != null ? Name(o, oldFn) : null, newFn != null ? Name(n, newFn) : null, mapped.Pair?.Tier, mapped.Candidates.Select(c => Va(n, c)).ToList());
    }

    [McpServerTool(Name = "migrate_native_names", Title = "Carry names to a new build", UseStructuredContent = true)]
    [Description("Copy names and comments from the old build to the new build's user annotations through the function matches of compare_native_images " +
                 "and map_address_between_builds: function names to the matched function, names and comments inside functions to the aligned instruction, " +
                 "data names to the same string or the data the matched instructions reference. Sources: the old build's user annotations (default), and " +
                 "optionally its pdb and il2cpp names (made identifiers). Never replaces a user name or comment of the new build; every skipped item has a " +
                 "reason code. dryRun shows exactly what would change.")]
    public async Task<MigrationReport> MigrateNativeNames(
        [Description(OldDescription)] string oldImage,
        [Description(NewDescription)] string newImage,
        [Description(DryRunDescription)] bool dryRun = false,
        [Description("Weakest match tier accepted for function addresses: 1 (names and identical bytes only) to 5 (all, default).")] int minTier = 5,
        [Description("Least mapping confidence accepted, 0-1 (default 0: any mapped address).")] double minScore = 0,
        [Description("Comma-separated layers of the old build to copy: user (default), pdb, il2cpp.")] string? sources = null,
        [Description("Copy comments too (default true).")] bool comments = true,
        [Description(UseNamesDescription)] bool useNames = true,
        [Description("Entries to skip in the report.")] int offset = 0,
        [Description("Entries to return (default 200, max 5000).")] int limit = 200,
        RequestContext<CallToolRequestParams> context = null!,
        CancellationToken cancellationToken = default)
    {
        if (minTier is < 1 or > 5) throw new ToolError(ErrorCode.InvalidArgument, $"minTier must be 1-5, not {minTier}.");
        if (double.IsNaN(minScore) || minScore is < 0 or > 1) throw new ToolError(ErrorCode.InvalidArgument, $"minScore must be 0-1, not {minScore}.");
        var layers = new HashSet<NativeNameSource>();
        foreach (var s in (sources ?? "user").Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            layers.Add(NativeNameSources.Parse(s) ?? throw new ToolError(ErrorCode.InvalidArgument, $"Unknown source '{s}'.", "use user, pdb or il2cpp, comma-separated"));
        var (oldNative, newNative, match) = await Match(oldImage, newImage, useNames, 0.7, context, cancellationToken);

        var items = new List<MigrationSource>();
        if (layers.Contains(NativeNameSource.User))
        {
            var ann = code.Annotations(oldNative);
            items.AddRange(ann.Names().Select(x => new MigrationSource("name", NativeNameSource.User, x.Rva, x.Name)));
            if (comments) items.AddRange(ann.Comments().Select(x => new MigrationSource("comment", NativeNameSource.User, x.Rva, x.Comment)));
        }
        foreach (var source in new[] { NativeNameSource.Pdb, NativeNameSource.Il2Cpp })
        {
            if (!layers.Contains(source) || NativeNameLayers.OfOrNull(oldNative)?.Get(source) is not { } layer) continue;
            items.AddRange(layer.Names.OrderBy(x => x.Key).Select(x => new MigrationSource("name", source, x.Key, x.Value)));
            if (comments) items.AddRange(layer.Comments.OrderBy(x => x.Key).Select(x => new MigrationSource("comment", source, x.Key, x.Value)));
        }
        var notes = Notes(match);
        if (items.Count == 0)
            notes.Add($"{oldNative.Id} has no {string.Join(" / ", layers.Select(l => l.Id()))} names or comments to carry over");

        var newAnn = code.Annotations(newNative);
        var steps = await Task.Run(() => NameMigration.Plan(new AddressMapper(match), items, match.New.Index, newAnn,
            new MigrationOptions { MinTier = minTier, MinScore = minScore }, cancellationToken), cancellationToken);

        var setNames = steps.Where(s => s.Set && s.Item.Kind == "name").Select(s => (s.NewRva!.Value, s.Value)).ToList();
        var setComments = steps.Where(s => s.Set && s.Item.Kind == "comment").Select(s => (s.NewRva!.Value, s.Value)).ToList();
        if (!dryRun && (setNames.Count > 0 || setComments.Count > 0))
        {
            var index = match.New.Index;
            workspace.Write(() =>
            {
                newAnn.SetMany(setNames, setComments);
                foreach (var (rva, name) in setNames) { index.SetUserName(rva, name); if (code.Ready(newNative) is { } ready && ready != index) ready.SetUserName(rva, name); }
                foreach (var (rva, text) in setComments) { index.SetUserComment(rva, text); if (code.Ready(newNative) is { } ready && ready != index) ready.SetUserComment(rva, text); }
                return 0;
            });
        }

        var o = match.Old.Index;
        var n = match.New.Index;
        offset = Math.Max(0, offset);
        limit = ClampLimit(limit, 5000);
        var entries = steps.OrderBy(s => s.Item.OldRva).ThenBy(s => s.Item.Kind).Skip(offset).Take(limit).Select(s => new MigrationEntry(
            s.Item.Kind, s.Item.Source.Id(), Va(o, s.Item.OldRva), s.NewRva is { } at ? Va(n, at) : null, s.Value,
            s.Set ? dryRun ? "would_set" : "set" : "skipped", s.Reason, s.Tier, s.Confidence, s.Detail)).ToList();
        var skippedBy = steps.Where(s => !s.Set).GroupBy(s => s.Reason).Select(g => new ReasonCount(g.Key, g.Count())).OrderByDescending(r => r.Count).ToList();
        int set = steps.Count(s => s.Set);
        return new MigrationReport(oldNative.Id, newNative.Id, dryRun, steps.Count, set, steps.Count - set, skippedBy, offset, steps.Count,
            offset + limit < steps.Count, entries, notes);
    }

    [McpServerTool(Name = "make_code_pattern", Title = "Make a code pattern", UseStructuredContent = true)]
    [Description("A byte pattern for an address that survives rebuilds: instruction bytes with branch displacements, RIP-relative displacements and " +
                 "relocated or in-image addresses as ?? (IDA style '48 8B 05 ?? ?? ?? ??'), extended an instruction at a time until it occurs once in the " +
                 "image's executable sections. When the code at the address is not unique (anchor auto) or anchor=reference, the pattern starts at or shortly " +
                 "before an instruction that references the address, with the operand's offset and how to recover the address from a hit. " +
                 "search_code_pattern finds it again in another build.")]
    public async Task<CodePatternResult> MakeCodePattern(
        [Description(NativeTools.ImageDescription)] string image,
        [Description(NativeTools.AddressDescription)] string address,
        [Description("auto (default): at the address, else at a reference to it; address; reference.")] string? anchor = null,
        [Description("Longest pattern in bytes (default 64, 8-512).")] int maxBytes = 64,
        RequestContext<CallToolRequestParams> context = null!,
        CancellationToken cancellationToken = default)
    {
        var a = (anchor ?? "auto").Trim().ToLowerInvariant();
        if (a is not ("auto" or "address" or "reference"))
            throw new ToolError(ErrorCode.InvalidArgument, $"Unknown anchor '{anchor}'.", "use auto, address or reference");
        var (native, index) = await Open(image, context, cancellationToken);
        uint rva = NativeCodeTools.Address(index, address);
        var made = await Task.Run(() => CodePatterns.Make(index, rva, maxBytes, allowReference: a != "address", referenceOnly: a == "reference", cancellationToken), cancellationToken);
        return new CodePatternResult(native.Id, Va(index, rva), made.Pattern.ToString(), made.Pattern.Length, made.Pattern.FixedBytes, made.Unique, made.Hits,
            made.Anchor, Va(index, made.Start), made.ReferenceOffset, made.OperandOffset, made.OperandSize, made.OperandKind, made.InstructionEnd, made.Note);
    }

    [McpServerTool(Name = "search_code_pattern", Title = "Search a code pattern", UseStructuredContent = true)]
    [Description("Find a byte pattern with ?? wildcards (as make_code_pattern or search_bytes write it) in the executable sections of every loaded native image, " +
                 "or of the given images, with the function containing each hit and the offset into it.")]
    public async Task<PatternSearch> SearchCodePattern(
        [Description("Hex bytes with ?? wildcards, e.g. '48 8B 05 ?? ?? ?? ?? E8'.")] string pattern,
        [Description("Comma-separated image ids or paths; omit for every loaded native image.")] string? images = null,
        [Description("Search every section, not only executable ones.")] bool allSections = false,
        [Description("Max hits (default 200, max 5000).")] int limit = 200,
        RequestContext<CallToolRequestParams> context = null!,
        CancellationToken cancellationToken = default)
    {
        var (bytes, mask, _) = NativeTools.ParseHexPattern(pattern ?? "");
        if (bytes.Length == 0)
            throw new ToolError(ErrorCode.InvalidArgument, "The pattern is empty.", "pass hex bytes such as '48 8B 05 ?? ?? ?? ??'");
        var p = new BytePattern(bytes, mask);
        limit = ClampLimit(limit, 5000);
        List<LoadedNative> targets;
        if (string.IsNullOrWhiteSpace(images))
        {
            targets = workspace.Read(() => workspace.Natives.ToList());
            if (targets.Count == 0)
                throw new ToolError(ErrorCode.NotLoaded, "No native images are loaded.", "load_assembly with the path of a native .exe or .dll");
        }
        else
        {
            targets = [];
            foreach (var id in images.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
                targets.Add(await Resolve(id, cancellationToken));
            targets = targets.DistinctBy(t => t.Id).ToList();
        }

        var hits = new List<PatternHit>();
        var notes = new List<string>();
        int total = 0;
        foreach (var native in targets)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var pe = native.Image;
            var sections = await Task.Run(() => CodePatterns.CodeSections(pe, allSections), cancellationToken);
            int count = 0;
            var found = await Task.Run(() => CodePatterns.Find(sections, p, limit, out count, cancellationToken), cancellationToken);
            total += count;
            if (found.Count == 0 || hits.Count >= limit) continue;
            NativeCodeIndex? index = null;
            if (pe.Arch is NativeArch.X86 or NativeArch.X64)
                index = await code.Index(native, null, cancellationToken);
            else notes.Add($"{native.Id}: {pe.Arch} code is not analyzed, so hits have no containing function");
            foreach (var rva in found)
            {
                if (hits.Count >= limit) break;
                var fn = index?.FunctionAt(rva);
                hits.Add(new PatternHit(native.Id, NativeAddress.Va(pe, rva), pe.SectionAt(rva)?.Name ?? "", fn != null ? Name(index!, fn) : null,
                    fn != null ? NativeAddress.Va(pe, fn.Start) : null, fn != null ? rva - fn.Start : null));
            }
        }
        return new PatternSearch(p.ToString(), p.Length, targets.Count, total, total > hits.Count, hits, notes);
    }

    private async Task<LoadedNative> Resolve(string image, CancellationToken ct) => await Task.Run(() =>
    {
        var id = workspace.Read(() => workspace.FindNative(image)?.Id);
        if (id == null && !string.IsNullOrWhiteSpace(image) && Path.IsPathFullyQualified(image.Trim()) && File.Exists(image.Trim()))
            id = workspace.LoadAny(image.Trim()).Native?.Id ?? throw new ToolError(ErrorCode.Unsupported, $"{image} is a .NET assembly, not a native image.",
                "use compare_assemblies for .NET builds");
        return workspace.Read(() => workspace.GetNative(id ?? image));
    }, ct);

    private async Task<(LoadedNative Native, NativeCodeIndex Index)> Open(string image, RequestContext<CallToolRequestParams>? context, CancellationToken ct)
    {
        var native = await Resolve(image, ct);
        IProgress<CodeIndexProgress>? progress = null;
        if (context?.Params?.ProgressToken != null)
        {
            var sink = new OrderedProgress(context);
            progress = new Progress<CodeIndexProgress>(p => sink.Report(new ProgressNotificationValue
                { Progress = p.Done, Total = p.Total > 0 ? p.Total : null, Message = $"indexing {native.Id}: {p.Phase}" }));
        }
        var index = await code.Index(native, progress, ct);
        if (index.Support != CodeSupport.Full)
            throw new ToolError(ErrorCode.Unsupported, $"{native.Id}: {index.SupportNote ?? "instructions are not decoded for this architecture"}.",
                "x86 and x64 images are supported");
        return (native, index);
    }

    private async Task<(LoadedNative Old, LoadedNative New, MatchResult Match)> Match(string oldImage, string newImage, bool useNames, double minScore,
        RequestContext<CallToolRequestParams>? context, CancellationToken ct)
    {
        if (double.IsNaN(minScore) || minScore is < 0 or > 1) throw new ToolError(ErrorCode.InvalidArgument, $"minScore must be 0-1, not {minScore}.");
        var (oldNative, oldIndex) = await Open(oldImage, context, ct);
        var (newNative, newIndex) = await Open(newImage, context, ct);
        if (ReferenceEquals(oldNative, newNative))
            throw new ToolError(ErrorCode.InvalidArgument, $"Both arguments name {oldNative.Id}.", "load the other build too and pass its id (e.g. name#2)");
        if (oldIndex.Image.Arch != newIndex.Image.Arch)
            throw new ToolError(ErrorCode.Unsupported, $"{oldNative.Id} is {oldIndex.Image.Arch} and {newNative.Id} is {newIndex.Image.Arch}; builds for different architectures are not matched.");
        var options = new MatchOptions { UseNames = useNames, MinScore = minScore };
        var match = await Task.Run(() => MatchCache.Get(oldIndex, newIndex, options, ct), ct);
        return (oldNative, newNative, match);
    }

    private static List<string> Notes(MatchResult match)
    {
        var notes = new List<string>(match.Notes);
        if (match.Old.Failed + match.New.Failed > 0)
            notes.Add($"{match.Old.Failed} old and {match.New.Failed} new function(s) could not be decoded and match only by name or import");
        foreach (var t in match.Old.Index.Truncations) notes.Add("old: " + t);
        foreach (var t in match.New.Index.Truncations) notes.Add("new: " + t);
        if (!match.Options.UseNames) notes.Add("names were not used (useNames=false)");
        return notes;
    }

    private static FunctionPrint[] Prints(MatchResult m, bool old) => old ? m.Old.Functions : m.New.Functions;

    private static bool Identical(MatchResult m, FunctionMatch p) =>
        !m.Old.Functions[p.Old].Failed && m.Old.Functions[p.Old].BytesHash == m.New.Functions[p.New].BytesHash;

    private static FunctionPair Pair(MatchResult m, FunctionMatch p)
    {
        var (a, b) = (m.Old.Functions[p.Old], m.New.Functions[p.New]);
        bool identical = Identical(m, p);
        var changes = new List<string>();
        if (a.Size != b.Size) changes.Add($"size {a.Size} -> {b.Size}");
        if (a.Blocks != b.Blocks) changes.Add($"blocks {a.Blocks} -> {b.Blocks}");
        if (a.Instructions != b.Instructions) changes.Add($"instructions {a.Instructions} -> {b.Instructions}");
        if (a.CallSites != b.CallSites) changes.Add($"calls {a.CallSites} -> {b.CallSites}");
        if (!identical && changes.Count == 0) changes.Add("code changed, same shape");
        if (changes.Count == 0) changes.Add(a.Start != b.Start ? "identical, moved" : "identical");
        return new FunctionPair(Va(m.Old.Index, a.Start), Va(m.New.Index, b.Start), Name(m.Old.Index, a.Function), Name(m.New.Index, b.Function),
            p.Tier, p.Basis, p.Score, a.Size, b.Size, a.Blocks, b.Blocks, a.CallSites, b.CallSites, identical, string.Join(", ", changes));
    }

    private static IEnumerable<UnmatchedFunction> Unmatched(MatchResult m)
    {
        foreach (var (prints, byX, old) in new[] { (m.Old.Functions, m.ByOld, true), (m.New.Functions, m.ByNew, false) })
        {
            var index = old ? m.Old.Index : m.New.Index;
            for (int i = 0; i < prints.Length; i++)
            {
                if (byX[i] != null) continue;
                var p = prints[i];
                double? best = m.BestSeen.TryGetValue((old, i), out var b) ? Math.Round(b, 3) : null;
                string reason = m.Ambiguous.ContainsKey((old, i)) ? "ambiguous"
                    : p.Failed ? "not_decoded"
                    : best >= 0.3 ? "below_min_score"
                    : p.Instructions < 3 ? "too_small"
                    : old ? "not_in_new_build" : "new_in_this_build";
                yield return new UnmatchedFunction(old ? "old" : "new", Va(index, p.Start), Name(index, p.Function), p.Size, p.Blocks, reason, best);
            }
        }
    }

    private static string Va(NativeCodeIndex index, uint rva) => NativeAddress.Va(index.Image, rva);

    private static string Name(NativeCodeIndex index, NativeFunction f) => index.NameAt(f.Start) ?? f.Name;
}
