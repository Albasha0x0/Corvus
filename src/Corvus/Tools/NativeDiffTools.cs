using System.ComponentModel;
using ModelContextProtocol;
using ModelContextProtocol.Protocol;
using ModelContextProtocol.Server;
using Corvus.Core;
using Corvus.Mcp;
using Corvus.Native;
using Corvus.Native.Annotations;
using Corvus.Native.Code;
using Corvus.Native.Diff;
using Corvus.Native.Providers;
using Corvus.Services;
using static Corvus.Tools.ToolSupport;

namespace Corvus.Tools;

/// <summary>Two builds of one native image: function matching, carrying names and addresses forward, and rebuild-stable code patterns.</summary>
[McpServerToolType]
public sealed class NativeDiffTools(AssemblyWorkspace workspace, NativeCodeService code, NativeEngineService? engines = null, NativeEditService? edits = null)
{
    private readonly NativeEditJournal journal = edits?.Journal ?? new NativeEditJournal(workspace, code, engines);

    private const string OldDescription = "The older build: native image id or path (load both; the second gets an id like app.dll#2).";
    private const string NewDescription = "The newer build: native image id or path.";
    private const string UseNamesDescription =
        "Match functions by export, PDB, Il2Cpp and user names first (tier 1); false: code only.";
    internal const string CodeOnlyDescription = "Match functions by code only, not by export, PDB, Il2Cpp or user names.";

    /// <summary>
    /// One row of compare_native_images: a pair (both addresses, tier, basis, score, sizes; the new name and counts only where
    /// they differ), an unmatched function (one side, reason) or an ambiguous one (one side, reason, candidates).
    /// </summary>
    public sealed record FunctionRow(string? Old, string? New, string? OldName, string? NewName)
    {
        public int? Tier { get; init; }
        [Description("name, import_thunk, identical_bytes, structure, signature, callee_position, callee, caller, context, table_slot, fuzzy.")]
        public string? Basis { get; init; }
        public double? Score { get; init; }
        public uint? OldSize { get; init; }
        public uint? NewSize { get; init; }
        public int? OldBlocks { get; init; }
        public int? NewBlocks { get; init; }
        public int? OldCalls { get; init; }
        public int? NewCalls { get; init; }
        [Description("Same bytes after masking addresses.")] public bool? Identical { get; init; }
        [Description("Unmatched: ambiguous, below_min_score, too_small, not_decoded, not_in_new_build, new_in_this_build; ambiguous: identical_code, same_structure, same_signature, close_scores.")]
        public string? Reason { get; init; }
        public double? BestScore { get; init; }
        public IReadOnlyList<MatchCandidate>? Candidates { get; init; }
    }

    public sealed record MatchCandidate(string Address, string Name, double Score);

    public sealed record TierCount(int Tier, string Name, int Pairs);

    public sealed record NativeComparison(
        string OldImage, string NewImage, int OldFunctions, int NewFunctions, int Matched,
        [property: Description("Matched pairs with identical masked bytes.")] int Identical,
        int Changed, int UnmatchedOld, int UnmatchedNew, int Ambiguous,
        IReadOnlyList<TierCount> Tiers,
        [property: Description("pairs, changed, unmatched or ambiguous.")] string View,
        IReadOnlyList<FunctionRow> Items, int Offset, int Total,
        [property: Description("What was not covered (functions that did not decode, capped work).")] IReadOnlyList<string> Notes);

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
        [property: Description("name, comment, pseudo_comment, or a user type: declarations, type_edit, enum_member, field, analysis, operand, type, local, stack_var.")] string Kind,
        [property: Description("Layer it came from in the old build: user, pdb or il2cpp.")] string Source,
        string? OldAddress, string? NewAddress, string Value,
        [property: Description("set, would_set (dry run) or skipped.")] string Action,
        [property: Description("How it was carried or why not (docs/migration-reasons.md).")] string Reason,
        int? Tier, double Confidence, string Detail);

    public sealed record ReasonCount(string Reason, int Count);

    public sealed record MigrationReport(
        string OldImage, string NewImage, bool DryRun, bool Applied,
        [property: Description("The journaled edits (undo_native_edit): names and comments, user types.")] IReadOnlyList<EditId> EditIds,
        int Set, int Skipped, IReadOnlyList<ReasonCount> SkippedBy, IReadOnlyList<MigrationEntry> Items, int Offset, int Total, IReadOnlyList<string> Notes);

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

    [McpServerTool(Name = "compare_native_images", Title = "Compare native builds", UseStructuredContent = true, OutputSchemaType = typeof(NativeComparison))]
    [Description("Match the functions of two builds of one native image (x86 / x64 / ARM64) in tiers: 1 same name, import or identical bytes; 2 same " +
                 "control flow; 3 same imports, strings and constants; 4 call-graph neighbours; 5 fuzzy above minScore. A pair is taken only " +
                 "when unique on both sides. Returns per-tier counts and one view's rows by old address (unmatched: old, then new). The first " +
                 "call waits for both code indexes.")]
    public Task<string> CompareNativeImages(
        [Description(OldDescription)] string oldImage,
        [Description(NewDescription)] string newImage,
        [Description("pairs, changed (code differs), unmatched or ambiguous (with candidates).")] string view = "pairs",
        [Description("Only pairs of this tier (1-5); 0 for all.")] int tier = 0,
        [Description(CodeOnlyDescription)] bool codeOnly = false,
        [Description("Least similarity for a fuzzy match (0-1).")] double minScore = 0.7,
        [Description(RowOffsetDescription)] int offset = 0,
        [Description(LimitDescription)] int limit = 40,
        [Description(MaxTokensDescription)] int? maxTokens = null,
        RequestContext<CallToolRequestParams> context = null!,
        CancellationToken cancellationToken = default) => OrderedProgress.Run(context, async progress =>
    {
        var v = (string.IsNullOrWhiteSpace(view) ? "pairs" : view).Trim().ToLowerInvariant();
        if (v is not ("pairs" or "changed" or "unmatched" or "ambiguous"))
            throw new ToolError(ErrorCode.InvalidArgument, $"Unknown view '{view}'.", "use pairs, changed, unmatched or ambiguous");
        if (tier is < 0 or > 5) throw new ToolError(ErrorCode.InvalidArgument, $"tier must be 0-5, not {tier}.");
        if (double.IsNaN(minScore) || minScore is < 0 or > 1) throw new ToolError(ErrorCode.InvalidArgument, $"minScore must be 0-1, not {minScore}.");
        var pair = await pairs.Match(oldImage, newImage, new MatchOptions { UseNames = !codeOnly, MinScore = minScore }, new ProgressSpan(progress, 0, 1, 1), cancellationToken);
        var match = pair.Match;
        var o = match.Old.Index;
        var n = match.New.Index;
        offset = Math.Max(0, offset);

        IReadOnlyList<FunctionRow> rows;
        if (v is "pairs" or "changed")
            rows = match.Pairs.Where(p => tier == 0 || p.Tier == tier).Where(p => v == "pairs" || !Identical(match, p))
                .OrderBy(p => match.Old.Functions[p.Old].Start).Select(p => Pair(match, p)).ToList();
        else if (v == "unmatched") rows = Unmatched(match).ToList();
        else
            rows = match.Ambiguous.Values.OrderBy(a => !a.OldSide).ThenBy(a => Prints(match, a.OldSide)[a.Index].Start).Select(a =>
            {
                var self = Prints(match, a.OldSide)[a.Index];
                var other = Prints(match, !a.OldSide);
                var (selfIndex, otherIndex) = a.OldSide ? (o, n) : (n, o);
                var (at, name) = (Va(selfIndex, self.Start), Name(selfIndex, self.Function));
                return new FunctionRow(a.OldSide ? at : null, a.OldSide ? null : at, a.OldSide ? name : null, a.OldSide ? null : name)
                {
                    Reason = a.Reason,
                    Candidates = [.. a.Candidates.Take(8).Select(c => new MatchCandidate(Va(otherIndex, other[c.Index].Start), Name(otherIndex, other[c.Index].Function), Math.Round(c.Score, 3)))],
                };
            }).ToList();

        int identical = match.Pairs.Count(p => Identical(match, p));
        var tiers = Enumerable.Range(1, 5).Select(t => new TierCount(t, MatchResult.TierNames[t], match.Pairs.Count(p => p.Tier == t))).ToList();
        var record = new NativeComparison(pair.Old.Id, pair.New.Id, match.Old.Functions.Length, match.New.Functions.Length, match.Pairs.Count, identical,
            match.Pairs.Count - identical, match.ByOld.Count(m => m == null), match.ByNew.Count(m => m == null), match.Ambiguous.Count, tiers, v, [], offset, rows.Count, Notes(match));
        var head = new System.Text.StringBuilder($"{record.OldImage} -> {record.NewImage}: {record.Matched} of {record.OldFunctions} old functions matched " +
            $"({identical} identical, {record.Changed} changed); {record.UnmatchedOld} old and {record.UnmatchedNew} new unmatched, {record.Ambiguous} ambiguous. " +
            $"Tiers: {string.Join(", ", tiers.Select(t => $"{t.Tier} {t.Name} {t.Pairs}"))}.\n");
        foreach (var note in record.Notes) head.Append("Note: ").Append(note).Append('\n');
        head.Append($"View {v}{(tier > 0 && v is "pairs" or "changed" ? $", tier {tier}" : "")}:\n");
        return ToolOutput.List(rows.Skip(offset).ToList(), offset, limit, rows.Count, RowText, page => record with { Items = page },
            v is "pairs" or "changed" ? "pair" : "function", head.ToString());
    });

    private static string RowText(FunctionRow r)
    {
        if (r.Tier is { } t)
        {
            static string Delta<T>(string what, T a, T? b) where T : struct => b is { } x ? $" {what} {a}->{x}" : "";
            var changes = Delta("size", r.OldSize ?? 0, r.NewSize) + Delta("blocks", r.OldBlocks ?? 0, r.NewBlocks) + Delta("calls", r.OldCalls ?? 0, r.NewCalls);
            var what = r.Identical == true ? r.Old == r.New ? " identical" : " identical, moved" : changes.Length > 0 ? changes : " code changed, same shape";
            return $"{r.Old} -> {r.New} {r.OldName}{(r.NewName != null ? $" / {r.NewName}" : "")}  tier {t} {r.Basis} {r.Score:0.##}{what}";
        }
        var (side, at, name) = r.Old != null ? ("old", r.Old, r.OldName) : ("new", r.New, r.NewName);
        return $"{side} {at} {name}  {r.Reason}" + (r.BestScore is { } b ? $" (best {b:0.##})" : "") +
               (r.Candidates is { Count: > 0 } c ? ": " + string.Join(", ", c.Select(x => $"{x.Address} {x.Name} {x.Score:0.##}")) : "");
    }

    [McpServerTool(Name = "map_address_between_builds", Title = "Map an address to a new build", UseStructuredContent = true)]
    [Description("Where an address of the old build is in the new build: a function start to the matched function, an address inside one " +
                 "to the aligned instruction, a string to the same string, other data through the references of matched instructions. Returns the " +
                 "new address with confidence and reason, or null with why and nearby candidates.")]
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
    [Description("What changed in one function between two builds (paired through compare_native_images). view=asm: both instruction lists " +
                 "aligned, rows = (same), ~ (other operands), - or +, with build-independent operands (branch labels, matched callee names, string " +
                 "text, mapped data) so moved code and relocations do not show; only changed regions with context. view=pseudocode: a unified diff " +
                 "of both functions' pseudocode, addresses replaced the same way. An unmatched function returns the reason and candidates.")]
    public async Task<FunctionDiffReport> DiffFunction(
        [Description(OldDescription)] string oldImage,
        [Description(NewDescription)] string newImage,
        [Description("An address in the function: " + NativeTools.AddressDescription)] string address,
        [Description("Which build the address is in (default old).")] string? side = null,
        [Description("asm (default) or pseudocode (needs an engine).")] string? view = null,
        [Description("Unchanged rows or lines around each change (0-50).")] int context = 4,
        [Description("Most rows or lines returned (max 5000).")] int maxLines = 300,
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

    [McpServerTool(Name = "migrate_native_names", Title = "Carry names to a new build", UseStructuredContent = true, OutputSchemaType = typeof(MigrationReport))]
    [Description("Copy the old build's names, comments and engine types to the new build's user annotations through the function match " +
                 "(map_address_between_builds). Never replaces a user name, comment or type of the new build; each skipped item has a reason " +
                 "code. Applied as undoable edits (editIds).")]
    public Task<string> MigrateNativeNames(
        [Description(OldDescription)] string oldImage,
        [Description(NewDescription)] string newImage,
        [Description(DryRunDefaultTrueDescription)] bool dryRun = true,
        [Description("Weakest match tier accepted: 1 (names, identical bytes) to 5 (all).")] int minTier = 5,
        [Description("Least mapping confidence accepted (0-1).")] double minScore = 0,
        [Description("Layers to copy (default user).")] string[]? sources = null,
        [Description("Names only, no comments.")] bool namesOnly = false,
        [Description(CodeOnlyDescription)] bool codeOnly = false,
        [Description(RowOffsetDescription)] int offset = 0,
        [Description(LimitDescription)] int limit = 100,
        [Description(MaxTokensDescription)] int? maxTokens = null,
        RequestContext<CallToolRequestParams> context = null!,
        CancellationToken cancellationToken = default) => OrderedProgress.Run(context, async progress =>
    {
        var r = await CarryNames(oldImage, newImage, dryRun, minTier, minScore, sources, namesOnly, codeOnly, new ProgressSpan(progress, 0, 1, 1), cancellationToken);
        var head = new System.Text.StringBuilder();
        string skipped = r.Skipped == 0 ? "" : $"; {r.Skipped} skipped ({string.Join(", ", r.SkippedBy.Take(4).Select(x => $"{x.Reason} {x.Count}"))})";
        head.Append(dryRun ? $"Dry run: {r.Set} of {r.Total} item(s) would carry from {r.OldImage} to {r.NewImage}{skipped}. Nothing recorded; dryRun=false applies it.\n"
            : $"{r.Set} of {r.Total} item(s) carried from {r.OldImage} to {r.NewImage}{skipped}. " +
              (r.EditIds.Count > 0 ? $"Recorded as {string.Join(", ", r.EditIds)} (undo_native_edit editId={r.EditIds[0]}).\n" : "Nothing changed.\n"));
        foreach (var n in r.Notes) head.Append("Note: ").Append(n).Append('\n');
        return ToolOutput.List(r.Items, offset, limit, e =>
                $"{e.Kind} {e.OldAddress ?? "-"} -> {e.NewAddress ?? "-"} {Format.Literal(Clip(e.Value))}: " +
                (e.Action == "skipped" ? $"skipped, {e.Reason} ({e.Detail})" : $"{e.Action} ({e.Reason}{(e.Tier is { } t ? $", tier {t}" : "")})"),
            rows => r with { Items = rows, Offset = offset }, "item", head.ToString());
    });

    private static string Clip(string s) => s.Length <= 80 ? s : s[..77] + "...";

    /// <summary>
    /// migrate_native_names without paging (load_session uses it too): every planned item in old-address order, the user
    /// types after them; applied as journaled edits unless <paramref name="dryRun"/>.
    /// </summary>
    internal async Task<MigrationReport> CarryNames(string oldImage, string newImage, bool dryRun, int minTier, double minScore, string[]? sources,
        bool namesOnly, bool codeOnly, ProgressSpan progress, CancellationToken cancellationToken)
    {
        if (minTier is < 1 or > 5) throw new ToolError(ErrorCode.InvalidArgument, $"minTier must be 1-5, not {minTier}.");
        if (double.IsNaN(minScore) || minScore is < 0 or > 1) throw new ToolError(ErrorCode.InvalidArgument, $"minScore must be 0-1, not {minScore}.");
        var layers = new HashSet<NativeNameSource>();
        foreach (var s in sources is { Length: > 0 } ? sources : ["user"])
            layers.Add(NativeNameSources.Parse(s.Trim()) ?? throw new ToolError(ErrorCode.InvalidArgument, $"Unknown source '{s}'.", "use user, pdb or il2cpp"));
        var pair = await pairs.Match(oldImage, newImage, new MatchOptions { UseNames = !codeOnly }, progress.Part(0, 0.8), cancellationToken);
        var (oldNative, newNative, match) = (pair.Old, pair.New, pair.Match);
        bool comments = !namesOnly;

        var items = new List<MigrationSource>();
        if (layers.Contains(NativeNameSource.User)) items.AddRange(NameMigration.UserItems(code.Annotations(oldNative), comments));
        foreach (var source in new[] { NativeNameSource.Pdb, NativeNameSource.Il2Cpp })
        {
            if (!layers.Contains(source) || NativeNameLayers.OfOrNull(oldNative)?.Get(source) is not { } layer) continue;
            items.AddRange(layer.Names.OrderBy(x => x.Key).Select(x => new MigrationSource("name", source, x.Key, x.Value)));
            if (comments) items.AddRange(layer.Comments.OrderBy(x => x.Key).Select(x => new MigrationSource("comment", source, x.Key, x.Value)));
        }
        var notes = Notes(match);
        if (items.Count == 0)
            notes.Add($"{oldNative.Id} has no {string.Join(" / ", layers.Select(l => l.Id()))} names or comments to carry over");

        progress.Part(0.8, 1).Report(0, "planning");
        var newAnn = code.Annotations(newNative);
        var options = new MigrationOptions { MinTier = minTier, MinScore = minScore };
        var steps = await Task.Run(() => NameMigration.Plan(new AddressMapper(match), items, match.New.Index, newAnn, options, cancellationToken), cancellationToken);
        var typeSteps = layers.Contains(NativeNameSource.User)
            ? await Task.Run(() => UserTypeMigration.Plan(new AddressMapper(match), code.Annotations(oldNative).UserTypes, newAnn.UserTypes, options, cancellationToken), cancellationToken)
            : [];
        var ids = dryRun ? [] : ApplyMigration(journal, workspace, code, newNative, match.New.Index, steps, typeSteps, "migrate_native_names");

        var o = match.Old.Index;
        var n = match.New.Index;
        string Action(bool isSet) => isSet ? dryRun ? "would_set" : "set" : "skipped";
        var all = steps.OrderBy(s => s.Item.OldRva).ThenBy(s => s.Item.Kind).Select(s => (s.Set, s.Reason, Entry: new MigrationEntry(
                s.Item.Kind, s.Item.Source.Id(), Va(o, s.Item.OldRva), s.NewRva is { } at ? Va(n, at) : null, s.Value, Action(s.Set), s.Reason, s.Tier, s.Confidence, s.Detail)))
            .Concat(typeSteps.Select(s => (s.Set, s.Reason, Entry: new MigrationEntry(s.Kind, NativeNameSource.User.Id(), s.OldRva is { } from ? Va(o, from) : null,
                s.NewRva is { } to ? Va(n, to) : null, s.Value, Action(s.Set), s.Reason, s.Tier, s.Confidence, s.Detail))))
            .ToList();
        var skippedBy = all.Where(s => !s.Set).GroupBy(s => s.Reason).Select(g => new ReasonCount(g.Key, g.Count()))
            .OrderByDescending(r => r.Count).ThenBy(r => r.Reason, StringComparer.Ordinal).ToList();
        int set = all.Count(s => s.Set);
        return new MigrationReport(oldNative.Id, newNative.Id, dryRun, ids.Count > 0, ids, set, all.Count - set, skippedBy, [.. all.Select(e => e.Entry)], 0, all.Count, notes);
    }

    /// <summary>
    /// Writes the planned names and comments (with their kinds) to the new build's user layer and code indexes, and the
    /// planned user types, each as one journaled edit; returns their ids (none when nothing was set).
    /// </summary>
    internal static List<EditId> ApplyMigration(NativeEditJournal journal, AssemblyWorkspace workspace, NativeCodeService code, LoadedNative native,
        NativeCodeIndex matched, IReadOnlyList<MigrationStep> steps, IReadOnlyList<UserTypeStep> typeSteps, string tool)
    {
        var ids = new List<EditId>();
        var ann = code.Annotations(native);
        var set = steps.Where(s => s.Set && s.NewRva != null).ToList();
        if (set.Count > 0 && journal.RecordAnnotations(native, tool, set.Select(s => s.NewRva!.Value), () => workspace.Write(() =>
            {
                var (names, lines) = NameMigration.Apply(ann, set);
                foreach (var index in new[] { matched, code.Ready(native) }.OfType<NativeCodeIndex>().Distinct())
                {
                    foreach (var (rva, name) in names) index.SetUserName(rva, name);
                    foreach (var (rva, text) in lines) index.SetUserComment(rva, text);
                }
                return 0;
            }), $"{tool}: {set.Count} name(s) and comment(s)") is { } id)
            ids.Add(id);
        if (typeSteps.Any(s => s.Set))
        {
            UserTypeLayer? before = null, after = null;
            ann.ChangeUserTypes(l => { before = l; return after = UserTypeMigration.Apply(l, typeSteps); });
            if (before != null && journal.RecordUserTypes(native, tool, null, before, after!, $"{tool}: {typeSteps.Count(s => s.Set)} user type(s)") is { } typeId)
                ids.Add(typeId);
        }
        return ids;
    }

    [McpServerTool(Name = "make_code_pattern", Title = "Make a code pattern", UseStructuredContent = true)]
    [Description("A byte pattern for an address that survives rebuilds: instruction bytes with displacements and relocated addresses as ?? " +
                 "('48 8B 05 ?? ?? ?? ??'), extended until it is unique in the executable sections. anchor=reference (or auto when the code is not " +
                 "unique): the pattern starts at an instruction referencing the address, with the operand offset to recover it from a hit. " +
                 "anchor=xrefs: a signature at each referencing instruction, so a rebuild that changed one site keeps others. anchor=range: " +
                 "[address, end), unique or not. search_code_pattern finds it in another build.")]
    public async Task<CodePatternResult> MakeCodePattern(
        [Description(NativeTools.ImageDescription)] string image,
        [Description(NativeTools.AddressDescription)] string address,
        [Description("auto (default): the address, else a reference to it; xrefs: one per reference.")] string? anchor = null,
        [Description("Longest pattern in bytes (8-512).")] int maxBytes = 64,
        [Description("anchor=xrefs: most signatures (1-32).")] int maxPatterns = 8,
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
    [Description("Find a byte pattern with ?? wildcards (as make_code_pattern writes it) in the executable sections of the loaded native " +
                 "images, with the function and offset of each hit.")]
    public async Task<PatternSearch> SearchCodePattern(
        [Description("Hex bytes with ?? wildcards.")] string pattern,
        [Description("Comma-separated image ids or paths; omit for every loaded native image.")] string? images = null,
        [Description("Search every section, not only executable ones.")] bool allSections = false,
        [Description("Max hits (max 5000).")] int limit = 200,
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
            if (pe.Arch is NativeArch.X86 or NativeArch.X64 or NativeArch.Arm64)
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

    private readonly BuildPairs pairs = new(workspace, code);

    private Task<LoadedNative> Resolve(string image, CancellationToken ct) => pairs.Resolve(image, ct);

    private Task<(LoadedNative Native, NativeCodeIndex Index)> Open(string image, RequestContext<CallToolRequestParams>? context, CancellationToken ct) =>
        pairs.Open(image, Progress(context), ct);

    private async Task<(LoadedNative Old, LoadedNative New, MatchResult Match)> Match(string oldImage, string newImage, bool useNames, double minScore,
        RequestContext<CallToolRequestParams>? context, CancellationToken ct)
    {
        if (double.IsNaN(minScore) || minScore is < 0 or > 1) throw new ToolError(ErrorCode.InvalidArgument, $"minScore must be 0-1, not {minScore}.");
        var pair = await pairs.Match(oldImage, newImage, new MatchOptions { UseNames = useNames, MinScore = minScore }, Progress(context), ct);
        return (pair.Old, pair.New, pair.Match);
    }

    private static ProgressSpan Progress(RequestContext<CallToolRequestParams>? context) =>
        new(context?.Params?.ProgressToken != null ? new OrderedProgress(context) : null, 0, 1, 1);

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

    private static FunctionRow Pair(MatchResult m, FunctionMatch p)
    {
        var (a, b) = (m.Old.Functions[p.Old], m.New.Functions[p.New]);
        var (oldName, newName) = (Name(m.Old.Index, a.Function), Name(m.New.Index, b.Function));
        // the new side's name and counts only where they differ
        return new FunctionRow(Va(m.Old.Index, a.Start), Va(m.New.Index, b.Start), oldName, newName != oldName ? newName : null)
        {
            Tier = p.Tier, Basis = p.Basis, Score = Math.Round(p.Score, 3), OldSize = a.Size, NewSize = b.Size != a.Size ? b.Size : null, OldBlocks = a.Blocks,
            NewBlocks = b.Blocks != a.Blocks ? b.Blocks : null, OldCalls = a.CallSites, NewCalls = b.CallSites != a.CallSites ? b.CallSites : null, Identical = Identical(m, p),
        };
    }

    private static IEnumerable<FunctionRow> Unmatched(MatchResult m)
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
                var (at, name) = (Va(index, p.Start), Name(index, p.Function));
                yield return new FunctionRow(old ? at : null, old ? null : at, old ? name : null, old ? null : name)
                    { OldSize = old ? p.Size : null, NewSize = old ? null : p.Size, OldBlocks = old ? p.Blocks : null, NewBlocks = old ? null : p.Blocks, Reason = reason, BestScore = best };
            }
        }
    }

    private static string Va(NativeCodeIndex index, uint rva) => NativeAddress.Va(index.Image, rva);

    private static string Name(NativeCodeIndex index, NativeFunction f) => index.NameAt(f.Start) ?? f.Name;
}

/// <summary>A share of a call's progress: reports land in [From, To) of Total, so the steps of one call never go backwards.</summary>
internal readonly record struct ProgressSpan(IProgress<ProgressNotificationValue>? Sink, float From, float To, float Total)
{
    public void Report(double fraction, string message) =>
        Sink?.Report(new ProgressNotificationValue { Progress = From + (To - From) * (float)Math.Clamp(fraction, 0, 0.999), Total = Total, Message = message });

    /// <summary>The share [a, b) of this span.</summary>
    public ProgressSpan Part(double a, double b) => this with { From = From + (To - From) * (float)a, To = From + (To - From) * (float)b };
}

/// <summary>Two builds of one image, their live code indexes and their function match.</summary>
internal sealed record BuildPair(LoadedNative Old, LoadedNative New, NativeCodeIndex OldIndex, NativeCodeIndex NewIndex, MatchResult Match);

/// <summary>
/// Opens and matches two builds for every build tool: on each build's original bytes (patches would hide a patched
/// function's identity), through one cache, so the tools map an address the same way and report the same reason.
/// </summary>
internal sealed class BuildPairs(AssemblyWorkspace workspace, NativeCodeService code)
{
    public Task<LoadedNative> Resolve(string image, CancellationToken ct) => Task.Run(() => Targets.Native(workspace, image), ct);

    public async Task<(LoadedNative Native, NativeCodeIndex Index)> Open(string image, ProgressSpan progress, CancellationToken ct)
    {
        var native = await Resolve(image, ct);
        var index = await code.Index(native, progress.Sink == null ? null : new Progress<CodeIndexProgress>(p =>
            progress.Report(p.Total > 0 ? (double)p.Done / p.Total : 0, $"indexing {native.Id}: {p.Phase}")), ct);
        if (index.Support != CodeSupport.Full)
            throw new ToolError(ErrorCode.Unsupported, $"{native.Id}: {index.SupportNote ?? "instructions are not decoded for this architecture"}.",
                "x86, x64 and ARM64 images are supported");
        return (native, index);
    }

    /// <summary>Both builds indexed and matched; <paramref name="sameAllowed"/>: one image as both (a patch set replayed on its build).</summary>
    public async Task<BuildPair> Match(string oldImage, string newImage, MatchOptions options, ProgressSpan progress, CancellationToken ct, bool sameAllowed = false)
    {
        var (oldNative, oldIndex) = await Open(oldImage, progress.Part(0, 0.4), ct);
        var (newNative, newIndex) = await Open(newImage, progress.Part(0.4, 0.8), ct);
        if (ReferenceEquals(oldNative, newNative) && !sameAllowed)
            throw new ToolError(ErrorCode.InvalidArgument, $"Both arguments name {oldNative.Id}.", "load the other build too and pass its id (e.g. name#2)");
        if (oldIndex.Image.Arch != newIndex.Image.Arch)
            throw new ToolError(ErrorCode.Unsupported, $"{oldNative.Id} is {oldIndex.Image.Arch} and {newNative.Id} is {newIndex.Image.Arch}; builds for different architectures are not matched.");
        progress.Part(0.8, 1).Report(0, "matching functions");
        var matchOld = await Task.Run(() => Original(oldNative, oldIndex, ct), ct);
        var matchNew = await Task.Run(() => Original(newNative, newIndex, ct), ct);
        var match = await Task.Run(() => MatchCache.Get(matchOld, matchNew, options, ct), ct);
        return new BuildPair(oldNative, newNative, oldIndex, newIndex, match);
    }

    private static readonly System.Runtime.CompilerServices.ConditionalWeakTable<LoadedNative, Tuple<string, NativeCodeIndex>> Originals = new();

    /// <summary>The live index, or for a patched image one over its original bytes, kept while its names stay the same so a dry run and the apply that follows match once.</summary>
    private NativeCodeIndex Original(LoadedNative native, NativeCodeIndex live, CancellationToken ct)
    {
        if (!native.HasPatches) return live;
        var ann = code.Annotations(native);
        var stamp = $"{ann.NameCount}|{ann.CommentCount}|" + string.Join(",", NativeNameLayers.Of(native).Layers.Select(l => $"{l.Source}:{l.Names.Count}:{l.Origin}"))
                    + "|" + native.Patches.Patches.Count;
        if (Originals.TryGetValue(native, out var kept) && kept.Item1 == stamp) return kept.Item2;
        var index = code.IndexOfOriginal(native, ct);
        Originals.AddOrUpdate(native, Tuple.Create(stamp, index));
        return index;
    }
}
