using System.ComponentModel;
using System.Diagnostics;
using ModelContextProtocol;
using ModelContextProtocol.Protocol;
using ModelContextProtocol.Server;
using NetDecompilerMcp.Core;
using NetDecompilerMcp.Native;
using NetDecompilerMcp.Native.Code;
using NetDecompilerMcp.Native.Diff;
using NetDecompilerMcp.Native.Providers;
using NetDecompilerMcp.Services;
using static NetDecompilerMcp.Tools.ToolSupport;

namespace NetDecompilerMcp.Tools;

/// <summary>Two builds of one native image: function matching, carrying names and addresses forward, and rebuild-stable code patterns.</summary>
[McpServerToolType]
public sealed class NativeDiffTools(AssemblyWorkspace workspace, NativeCodeService code, NativeEngineService? engines = null)
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
        [property: Description("name, comment, or a user type: declarations, enum_member, analysis, operand, type, local, stack_var.")] string Kind,
        [property: Description("Layer it came from in the old build: user, pdb or il2cpp.")] string Source,
        [property: Description("Null for declarations.")] string? OldAddress, string? NewAddress, string Value,
        [property: Description("set (or would_set in a dry run) or skipped.")] string Action,
        [property: Description("For set: how the address was mapped. For skipped: same_name, same_comment, user_name_exists, user_comment_exists, " +
                               "name_in_use, new_has_own_name, duplicate_target, invalid_name, below_min_tier, below_min_score, same_declarations, same_type, " +
                               "user_type_exists, not_a_function_start, same_local, user_local_exists, same_stack_var, user_stack_var_exists, same_analysis, " +
                               "user_analysis_exists, same_operand, user_operand_exists, same_enum_member, user_enum_member_exists, or the mapping's reason.")]
        string Reason,
        int? Tier, double Confidence, string Detail);

    public sealed record ReasonCount(string Reason, int Count);

    public sealed record MigrationReport(
        string OldImage, string NewImage, bool DryRun, int Considered, int Set, int Skipped,
        IReadOnlyList<ReasonCount> SkippedBy, int Offset, int Total, bool Truncated, IReadOnlyList<MigrationEntry> Entries, IReadOnlyList<string> Notes);

    public sealed record CodePatternResult(
        string Image, string Address,
        [property: Description("The pattern in the format asked (default IDA style, ?? for bytes that change between builds); empty when none could be made.")] string Pattern,
        int Length, int FixedBytes, bool Unique,
        [property: Description("Occurrences in the image's executable sections.")] int Hits,
        [property: Description("address: the pattern starts at the address; reference: at (or shortly before) an instruction referencing it; xrefs; range.")] string Anchor,
        [property: Description("Where the pattern starts.")] string PatternAddress,
        [property: Description("Reference anchor: offset of the referencing instruction from the pattern start.")] int? ReferenceOffset,
        [property: Description("Reference anchor: offset of the address operand from the pattern start.")] int? OperandOffset,
        int? OperandSize,
        [property: Description("relative, rip_relative or absolute.")] string? OperandKind,
        [property: Description("Reference anchor: offset of the end of the referencing instruction (relative operands count from it).")] int? InstructionEnd,
        string Note,
        [property: Description("anchor=xrefs: a unique pattern at each referencing instruction, shortest first; null otherwise.")] IReadOnlyList<ReferencePattern>? References,
        [property: Description("anchor=xrefs: where the references came from.")] string? Engine);

    public sealed record ReferencePattern(
        string Pattern, int Length, int FixedBytes,
        [property: Description("Where the pattern starts.")] string PatternAddress,
        [property: Description("The instruction that references the address.")] string ReferenceAddress,
        string? Function,
        [property: Description("Offset of the address operand from the pattern start.")] int? OperandOffset,
        int? OperandSize,
        [property: Description("relative, rip_relative or absolute.")] string? OperandKind,
        int? InstructionEnd, string Note,
        [property: Description("ours (a reference the built-in index has), or ida or ghidra (one only that engine has).")] string Source);

    public sealed record FunctionDiffRow(
        [property: Description("= same, ~ same instruction shape with other operands, - only in the old build, + only in the new, … unchanged rows skipped.")] string Op,
        string? OldAddress, string? NewAddress, string? OldText, string? NewText);

    public sealed record FunctionDiffReport(
        string OldImage, string NewImage, string OldFunction, string NewFunction, string? OldAddress, string? NewAddress,
        [property: Description("Function-match tier (1 best .. 5 fuzzy); null when not matched.")] int? Tier,
        string? Basis, double? Score,
        [property: Description("asm or pseudocode.")] string View,
        [property: Description("What differs, or why there is no diff (function_not_matched, ambiguous, not_in_a_function).")] string Summary,
        int Same, int Changed, int Removed, int Added,
        [property: Description("asm: the aligned rows of the changed regions with context.")] IReadOnlyList<FunctionDiffRow> Rows,
        [property: Description("pseudocode: a unified diff of the normalized pseudocode.")] string? Unified,
        [property: Description("Candidate counterparts when ambiguous.")] IReadOnlyList<MatchCandidate> Candidates,
        bool Truncated, IReadOnlyList<string> Notes);

    public sealed record PatternHit(string Image, string Address, string Section, string? Function, string? FunctionAddress, uint? FunctionOffset);

    public sealed record PatternSearch(string Pattern, int Length, int Images, int Total, bool Truncated, IReadOnlyList<PatternHit> Hits, IReadOnlyList<string> Notes);

    [McpServerTool(Name = "compare_native_images", Title = "Compare native builds", UseStructuredContent = true)]
    [Description("Match the functions of two builds of one native image (x86 / x64 / ARM64), e.g. before and after an application update. Tiers, each accepting a pair " +
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

    [McpServerTool(Name = "diff_function", Title = "Diff a function between builds", UseStructuredContent = true)]
    [Description("What changed in one function between two builds. The function containing the address is paired through compare_native_images. " +
                 "view=asm (default): both instruction lists aligned, each row = (same), ~ (same shape, other operands), - or +; operands are " +
                 "build-independent: branch targets as labels of the aligned old instruction, calls to matched functions by the new build's name on " +
                 "both sides, strings by text, other data by the new address it maps to, so moved code and relocations do not show as changes. Only " +
                 "changed regions with context rows are returned. view=pseudocode: a unified diff of both functions' pseudocode (IDA) with addresses " +
                 "replaced the same way. An unmatched function returns the reason and candidates.")]
    public async Task<FunctionDiffReport> DiffFunction(
        [Description(OldDescription)] string oldImage,
        [Description(NewDescription)] string newImage,
        [Description("An address in the function: " + NativeTools.AddressDescription)] string address,
        [Description("Which build the address is in: old (default) or new.")] string? side = null,
        [Description("asm (default) or pseudocode (needs IDA).")] string? view = null,
        [Description("Unchanged rows (asm) or lines (pseudocode) shown around each change (default 4, 0-50).")] int context = 4,
        [Description("Most rows or diff lines returned (default 300, max 5000).")] int maxLines = 300,
        [Description(UseNamesDescription)] bool useNames = true,
        [Description("view=pseudocode: " + NativeCodeTools.EngineDescription)] string? engine = null,
        RequestContext<CallToolRequestParams> request = null!,
        CancellationToken cancellationToken = default)
    {
        var s = (side ?? "old").Trim().ToLowerInvariant();
        if (s is not ("old" or "new")) throw new ToolError(ErrorCode.InvalidArgument, $"side must be old or new, not '{side}'.");
        var v = (view ?? "asm").Trim().ToLowerInvariant();
        if (v is not ("asm" or "pseudocode")) throw new ToolError(ErrorCode.InvalidArgument, $"Unknown view '{view}'.", "use asm or pseudocode");
        if (context is < 0 or > 50) throw new ToolError(ErrorCode.InvalidArgument, $"context must be 0-50, not {context}.");
        maxLines = ClampLimit(maxLines, 5000);
        var (oldNative, newNative, match) = await Match(oldImage, newImage, useNames, 0.7, request, cancellationToken);
        var o = match.Old.Index;
        var n = match.New.Index;
        bool fromOld = s == "old";
        var index = fromOld ? o : n;
        uint rva = NativeCodeTools.Address(index, address);
        var notes = Notes(match);
        FunctionDiffReport Empty(string summary, string oldName, string newName, string? oldVa, string? newVa, IReadOnlyList<MatchCandidate> candidates) =>
            new(oldNative.Id, newNative.Id, oldName, newName, oldVa, newVa, null, null, null, v, summary, 0, 0, 0, 0, [], null, candidates, false, notes);
        if (index.FunctionAt(rva) is not { } fn || !(fromOld ? match.Old : match.New).ByStart.TryGetValue(fn.Start, out var fi))
            return Empty("not_in_a_function: the address is in no function the matcher compared", "", "", null, null, []);
        var pair = fromOld ? match.ByOld[fi] : match.ByNew[fi];
        if (pair == null)
        {
            var amb = match.Ambiguous.GetValueOrDefault((fromOld, fi));
            var other = fromOld ? n : o;
            var otherPrints = fromOld ? match.New.Functions : match.Old.Functions;
            var candidates = amb?.Candidates.Take(8).Select(c => new MatchCandidate(Va(other, otherPrints[c.Index].Start), Name(other, otherPrints[c.Index].Function),
                Math.Round(c.Score, 3))).ToList() ?? [];
            string label = Name(index, fn);
            return Empty(amb != null ? $"ambiguous: {amb.Reason}; candidates listed" : "function_not_matched: no counterpart in the other build",
                fromOld ? label : "", fromOld ? "" : label, fromOld ? Va(o, fn.Start) : null, fromOld ? null : Va(n, fn.Start), candidates);
        }
        var (a, b) = (match.Old.Functions[pair.Old], match.New.Functions[pair.New]);
        var differ = new FunctionDiff(match);
        string? unified = null;
        List<FunctionDiffRow> rows = [];
        int same = 0, changed = 0, removed = 0, added = 0;
        bool truncated = false;
        if (v == "asm")
        {
            var d = await Task.Run(() => differ.Diff(pair, context, maxLines, cancellationToken), cancellationToken);
            rows = d.Rows.Select(r => new FunctionDiffRow(r.Op, r.OldRva is { } x ? Va(o, x) : null, r.NewRva is { } y ? Va(n, y) : null, r.OldText, r.NewText)).ToList();
            (same, changed, removed, added, truncated) = (d.Same, d.Changed, d.Removed, d.Added, d.Truncated);
            notes.AddRange(d.Notes);
        }
        else
        {
            if (engines == null) throw new ToolError(ErrorCode.ProviderUnavailable, "No decompiler engine is configured.", "use view=asm");
            async Task<string> Pseudocode(LoadedNative native, uint start)
            {
                var session = await engines.Session(native, engine, null, cancellationToken);
                if (!session.DecompilerAvailable)
                    throw new ToolError(ErrorCode.ProviderUnavailable, $"The {session.ProviderId} decompiler is not available for {session.Arch} code here.", "use view=asm");
                return (await session.DecompileAsync(start, cancellationToken)).Text;
            }
            var before = differ.NormalizePseudocode(await Pseudocode(oldNative, a.Start), true, cancellationToken);
            var after = differ.NormalizePseudocode(await Pseudocode(newNative, b.Start), false, cancellationToken);
            var lines = TextDiff.Unified(before, after, $"{oldNative.Id} {Name(o, a.Function)}", $"{newNative.Id} {Name(n, b.Function)}", context)
                .ReplaceLineEndings("\n").TrimEnd('\n').Split('\n');
            truncated = lines.Length > maxLines;
            unified = string.Join("\n", lines.Take(maxLines)) + (truncated ? $"\n… cut at {maxLines} of {lines.Length} lines" : "");
            added = lines.Count(l => l.StartsWith('+') && !l.StartsWith("+++", StringComparison.Ordinal));
            removed = lines.Count(l => l.StartsWith('-') && !l.StartsWith("---", StringComparison.Ordinal));
        }
        var summary = v == "asm"
            ? changed + removed + added == 0 ? "identical after masking addresses" : $"{changed} changed, {removed} removed, {added} added of {a.Instructions} -> {b.Instructions} instructions"
            : removed + added == 0 ? "the same pseudocode after normalizing addresses" : $"{removed} line(s) removed, {added} added";
        return new FunctionDiffReport(oldNative.Id, newNative.Id, Name(o, a.Function), Name(n, b.Function), Va(o, a.Start), Va(n, b.Start), pair.Tier, pair.Basis,
            Math.Round(pair.Score, 3), v, summary, same, changed, removed, added, rows, unified, [], truncated, notes);
    }

    [McpServerTool(Name = "migrate_native_names", Title = "Carry names to a new build", UseStructuredContent = true)]
    [Description("Copy names and comments from the old build to the new build's user annotations through the function matches of compare_native_images " +
                 "and map_address_between_builds: function names to the matched function, names and comments inside functions to the aligned instruction, " +
                 "data names to the same string or the data the matched instructions reference. Sources: the old build's user annotations (default; with " +
                 "its engine types: declarations as they are, prototypes and global types by mapped address, locals and stack variables by matched function), " +
                 "and optionally its pdb and il2cpp names (made identifiers). Never replaces a user name, comment or type of the new build; every skipped " +
                 "item has a reason code. dryRun shows exactly what would change.")]
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
            if (comments) items.AddRange(ann.Comments().Select(x => new MigrationSource("comment", NativeNameSource.User, x.Rva, x.Comment))
                .Concat(ann.PseudoComments().Select(x => new MigrationSource(NameMigration.PseudoComment, NativeNameSource.User, x.Rva, x.Comment))));
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
        var options = new MigrationOptions { MinTier = minTier, MinScore = minScore };
        var steps = await Task.Run(() => NameMigration.Plan(new AddressMapper(match), items, match.New.Index, newAnn, options, cancellationToken), cancellationToken);
        var typeSteps = layers.Contains(NativeNameSource.User)
            ? await Task.Run(() => UserTypeMigration.Plan(new AddressMapper(match), code.Annotations(oldNative).UserTypes, newAnn.UserTypes, options, cancellationToken), cancellationToken)
            : [];
        if (!dryRun && typeSteps.Any(s => s.Set)) newAnn.ChangeUserTypes(l => UserTypeMigration.Apply(l, typeSteps));

        var setNames = steps.Where(s => s.Set && s.Item.Kind == "name").Select(s => (s.NewRva!.Value, s.Value)).ToList();
        var setComments = steps.Where(s => s.Set && s.Item.Kind == "comment").Select(s => (s.NewRva!.Value, s.Value)).ToList();
        var setPseudo = steps.Where(s => s.Set && s.Item.Kind == NameMigration.PseudoComment).Select(s => (s.NewRva!.Value, s.Value)).ToList();
        if (!dryRun && (setNames.Count > 0 || setComments.Count > 0 || setPseudo.Count > 0))
        {
            var index = match.New.Index;
            workspace.Write(() =>
            {
                newAnn.SetMany(setNames, setComments, setPseudo);
                foreach (var (rva, name) in setNames) { index.SetUserName(rva, name); if (code.Ready(newNative) is { } ready && ready != index) ready.SetUserName(rva, name); }
                foreach (var (rva, text) in setComments) { index.SetUserComment(rva, text); if (code.Ready(newNative) is { } ready && ready != index) ready.SetUserComment(rva, text); }
                return 0;
            });
        }

        var o = match.Old.Index;
        var n = match.New.Index;
        offset = Math.Max(0, offset);
        limit = ClampLimit(limit, 5000);
        string Action(bool isSet) => isSet ? dryRun ? "would_set" : "set" : "skipped";
        var all = steps.OrderBy(s => s.Item.OldRva).ThenBy(s => s.Item.Kind).Select(s => (s.Set, s.Reason, Entry: new MigrationEntry(
                s.Item.Kind, s.Item.Source.Id(), Va(o, s.Item.OldRva), s.NewRva is { } at ? Va(n, at) : null, s.Value, Action(s.Set), s.Reason, s.Tier, s.Confidence, s.Detail)))
            .Concat(typeSteps.Select(s => (s.Set, s.Reason, Entry: new MigrationEntry(s.Kind, NativeNameSource.User.Id(), s.OldRva is { } from ? Va(o, from) : null,
                s.NewRva is { } to ? Va(n, to) : null, s.Value, Action(s.Set), s.Reason, s.Tier, s.Confidence, s.Detail))))
            .ToList();
        var entries = all.Skip(offset).Take(limit).Select(e => e.Entry).ToList();
        var skippedBy = all.Where(s => !s.Set).GroupBy(s => s.Reason).Select(g => new ReasonCount(g.Key, g.Count())).OrderByDescending(r => r.Count).ToList();
        int set = all.Count(s => s.Set);
        return new MigrationReport(oldNative.Id, newNative.Id, dryRun, all.Count, set, all.Count - set, skippedBy, offset, all.Count,
            offset + limit < all.Count, entries, notes);
    }

    [McpServerTool(Name = "make_code_pattern", Title = "Make a code pattern", UseStructuredContent = true)]
    [Description("A byte pattern for an address that survives rebuilds: instruction bytes with branch displacements, RIP-relative displacements and " +
                 "relocated or in-image addresses as ?? (IDA style '48 8B 05 ?? ?? ?? ??'), extended an instruction at a time until it occurs once in the " +
                 "image's executable sections. When the code at the address is not unique (anchor auto) or anchor=reference, the pattern starts at or shortly " +
                 "before an instruction that references the address, with the operand's offset and how to recover the address from a hit. " +
                 "anchor=xrefs: a unique signature at each referencing instruction (shortest first; with engine IDA or Ghidra its references too), " +
                 "so a rebuild that changed one site keeps others. anchor=range: [address, end), unique or not. search_code_pattern finds it in another build.")]
    public async Task<CodePatternResult> MakeCodePattern(
        [Description(NativeTools.ImageDescription)] string image,
        [Description(NativeTools.AddressDescription)] string address,
        [Description("auto (default): the address, else a reference to it; address; reference; xrefs: one per reference; range.")] string? anchor = null,
        [Description("Longest pattern in bytes (default 64, 8-512).")] int maxBytes = 64,
        [Description("anchor=xrefs: most signatures (default 8, 1-32).")] int maxPatterns = 8,
        [Description("anchor=xrefs: " + NativeCodeTools.EngineDescription)] string? engine = null,
        [Description("Syntax: ida (default), x64dbg, mask (\\x48\\x00 x?) or bitmask (0x48, 0x00 0b01).")] string? format = null,
        [Description("anchor=range: exclusive end, an address or +length.")] string? end = null,
        RequestContext<CallToolRequestParams> context = null!,
        CancellationToken cancellationToken = default)
    {
        var a = (anchor ?? "auto").Trim().ToLowerInvariant();
        if (a is not ("auto" or "address" or "reference" or "xrefs" or "range"))
            throw new ToolError(ErrorCode.InvalidArgument, $"Unknown anchor '{anchor}'.", "use auto, address, reference, xrefs or range");
        if (maxPatterns is < 1 or > 32) throw new ToolError(ErrorCode.InvalidArgument, $"maxPatterns must be 1-32, not {maxPatterns}.");
        var fmt = PatternFormat(format);
        if ((a == "range") == string.IsNullOrWhiteSpace(end))
            throw new ToolError(ErrorCode.InvalidArgument, a == "range" ? "anchor=range needs end." : "end applies to anchor=range only.", "pass anchor=range end=<address or +length>");
        var mode = EngineModes.Resolve(engine, engines?.DefaultMode ?? EngineMode.Auto);
        var (native, index) = await Open(image, context, cancellationToken);
        uint rva = NativeCodeTools.Address(index, address);
        if (a == "range") return await RangePattern(native, index, rva, end!, fmt, cancellationToken);
        if (a == "xrefs") return await XrefPatterns(native, index, rva, maxBytes, maxPatterns, mode, !string.IsNullOrWhiteSpace(engine), fmt, cancellationToken);
        var made = await Task.Run(() => CodePatterns.Make(index, rva, maxBytes, allowReference: a != "address", referenceOnly: a == "reference", cancellationToken), cancellationToken);
        return new CodePatternResult(native.Id, Va(index, rva), FormatPattern(made.Pattern, fmt), made.Pattern.Length, made.Pattern.FixedBytes, made.Unique, made.Hits,
            made.Anchor, Va(index, made.Start), made.ReferenceOffset, made.OperandOffset, made.OperandSize, made.OperandKind, made.InstructionEnd, made.Note, null, null);
    }

    /// <summary>Longest anchor=range pattern; a function rarely needs more.</summary>
    private const int MaxRangeBytes = 4096;

    /// <summary>make_code_pattern anchor=range: every whole instruction in [rva, end) with the usual wildcards; not grown, so not necessarily unique.</summary>
    private static Task<CodePatternResult> RangePattern(LoadedNative native, NativeCodeIndex index, uint rva, string end, string fmt, CancellationToken ct)
    {
        var e = end.Trim();
        uint stop;
        if (e.StartsWith('+'))
        {
            var digits = e[1..];
            bool hex = digits.StartsWith("0x", StringComparison.OrdinalIgnoreCase);
            if (!uint.TryParse(hex ? digits[2..] : digits, hex ? System.Globalization.NumberStyles.AllowHexSpecifier : System.Globalization.NumberStyles.None, null, out var length) || length == 0)
                throw new ToolError(ErrorCode.InvalidArgument, $"'{end}' is not a length.", "pass end=+0x20 or an end address");
            stop = rva + Math.Min(length, MaxRangeBytes + 1u);
        }
        else stop = NativeCodeTools.Address(index, e);
        if (stop <= rva) throw new ToolError(ErrorCode.InvalidArgument, $"end {Va(index, stop)} is not after {Va(index, rva)}.");
        if (stop - rva > MaxRangeBytes) throw new ToolError(ErrorCode.LimitExceeded, $"The range is longer than {MaxRangeBytes} bytes.", "split the range");
        return Task.Run(() =>
        {
            var insns = new List<MaskedInsn>();
            new MaskedDecoder(index.Image).Decode(rva, stop, insns);
            var bytes = new List<byte>();
            var mask = new List<bool>();
            foreach (var insn in insns.TakeWhile(i => i.End <= stop))
                for (int i = 0; i < insn.Length; i++) { bytes.Add(insn.Bytes[i]); mask.Add(!insn.IsWild(i)); }
            uint covered = rva + (uint)bytes.Count;
            var pattern = new BytePattern([.. bytes], [.. mask]);
            int hits = 0;
            if (pattern.FixedBytes > 0) CodePatterns.Find(CodePatterns.CodeSections(index.Image), pattern, 0, out hits, ct);
            var note = (covered < stop ? $"stops at {Va(index, covered)}: the rest does not decode or an instruction crosses the end; " : "") +
                       $"{hits} hit(s) in executable sections";
            return new CodePatternResult(native.Id, Va(index, rva), FormatPattern(pattern, fmt), pattern.Length, pattern.FixedBytes, hits == 1, hits, "range",
                Va(index, rva), null, null, null, null, null, note, null, null);
        }, ct);
    }

    private static string PatternFormat(string? format) => (format ?? "").Trim().ToLowerInvariant() switch
    {
        "" or "ida" => "ida",
        "x64dbg" => "x64dbg",
        "mask" => "mask",
        "bitmask" => "bitmask",
        _ => throw new ToolError(ErrorCode.InvalidArgument, $"Unknown format '{format}'.", "use ida, x64dbg, mask or bitmask"),
    };

    /// <summary>A pattern in a signature tool's syntax; ida and x64dbg both read "??" as one wildcard byte.</summary>
    internal static string FormatPattern(BytePattern p, string format) => format switch
    {
        "mask" => string.Concat(Enumerable.Range(0, p.Length).Select(i => $"\\x{(p.Mask[i] ? p.Bytes[i] : 0):X2}")) + " " + string.Concat(p.Mask.Select(m => m ? 'x' : '?')),
        // bit i of the mask is byte i, so the string reads last byte first
        "bitmask" => string.Join(", ", Enumerable.Range(0, p.Length).Select(i => $"0x{(p.Mask[i] ? p.Bytes[i] : 0):X2}")) + " 0b" + string.Concat(p.Mask.Reverse().Select(m => m ? '1' : '0')),
        _ => p.ToString(),
    };

    /// <summary>make_code_pattern anchor=xrefs: a signature per referencing instruction, the engine's references added.</summary>
    private async Task<CodePatternResult> XrefPatterns(LoadedNative native, NativeCodeIndex index, uint rva, int maxBytes, int maxPatterns, EngineMode mode, bool named,
        string fmt, CancellationToken ct)
    {
        var choice = NativeEngineCode.Choose(mode, named, engines, native, index);
        var ours = index.RefsTo(rva, 256).Select(x => x.From).ToHashSet();
        var extra = new List<uint>();
        if (choice.External)
        {
            var session = await engines!.Session(native, choice.Engine, null, ct);
            // code that uses the address; data pointers to it are not signatures
            extra.AddRange((await session.GetXrefsToAsync(rva, ct)).Where(x => x.FromFunctionRva != null && x.Kind is not (NativeXrefKind.Jump or NativeXrefKind.Data))
                .Select(x => x.FromRva).Where(f => !ours.Contains(f)));
        }
        var made = await Task.Run(() => CodePatterns.MakeAtReferences(index, rva, maxBytes, maxPatterns, extra, ct), ct);
        var refs = made.Select(p => p.Start + (uint)(p.ReferenceOffset ?? 0)).ToList();
        var list = made.Zip(refs).Select(t => new ReferencePattern(FormatPattern(t.First.Pattern, fmt), t.First.Pattern.Length, t.First.Pattern.FixedBytes, Va(index, t.First.Start),
            Va(index, t.Second), index.FunctionAt(t.Second) is { } f ? Name(index, f) : null, t.First.OperandOffset, t.First.OperandSize, t.First.OperandKind,
            t.First.InstructionEnd, t.First.Note, ours.Contains(t.Second) ? "ours" : choice.Engine)).ToList();
        var note = $"{list.Count} unique signature(s) from {ours.Count + extra.Count} reference(s) ({ours.Count} built-in, {extra.Count} {choice.Engine}-only); {choice.Line}";
        if (made.FirstOrDefault() is not { } best)
            return new CodePatternResult(native.Id, Va(index, rva), "", 0, 0, false, 0, "xrefs", Va(index, rva), null, null, null, null, null,
                "no instruction that references the address yields a unique pattern; " + note, list, choice.Engine);
        return new CodePatternResult(native.Id, Va(index, rva), FormatPattern(best.Pattern, fmt), best.Pattern.Length, best.Pattern.FixedBytes, best.Unique, best.Hits,
            "xrefs", Va(index, best.Start), best.ReferenceOffset, best.OperandOffset, best.OperandSize, best.OperandKind, best.InstructionEnd,
            best.Note + "; " + note, list, choice.Engine);
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
                "x86, x64 and ARM64 images are supported");
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
