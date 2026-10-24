using System.ComponentModel;
using System.Text;
using dnlib.DotNet;
using ModelContextProtocol.Protocol;
using ModelContextProtocol.Server;
using Corvus.Core;
using Corvus.Mcp;
using Corvus.Services;
using static Corvus.Tools.ToolSupport;
using Comparison = Corvus.Services.AssemblyComparer.Comparison;
using MemberChange = Corvus.Services.AssemblyComparer.MemberChange;
using TypeChange = Corvus.Services.AssemblyComparer.TypeChange;

namespace Corvus.Tools;

[McpServerToolType]
public sealed class CompareTools(AssemblyWorkspace workspace, AssemblyComparer comparer, DecompilerService decompiler, ResultStore? results = null,
    Services.Analysis.InspectionService? inspection = null)
{
    private static readonly string[] AllKinds = AssemblyComparer.ChangeKinds;

    private static readonly string[] Confidences = ["exact", "strong", "structural"];

    public sealed record BuildRef(string Assembly, string File, string Sha256, string Mvid)
    {
        public static BuildRef Of(LoadedAssembly asm) => new(asm.Id, asm.FilePath, asm.OriginalSha256, asm.Module.Mvid?.ToString() ?? "");
    }

    public sealed record KindCount(string Kind, int Count);

    public sealed record ChangeItem(
        [property: Description("type, method, field, property or event.")] string Kind,
        [property: Description("Types: renamed, changed, ambiguous, removed, added. Members: the first of Changes.")] string Change,
        string? Old, string? OldToken, string? New, string? NewToken,
        [property: Description("Every change of a matched member, with its detail.")] IReadOnlyList<AssemblyComparer.ChangeDimension> Changes,
        string? Tier, string? Confidence,
        [property: Description("Ambiguous: the tied candidates in the new build.")] IReadOnlyList<string>? Candidates);

    public sealed record AssemblyComparison(
        BuildRef Old, BuildRef New, int OldTypes, int MatchedTypes,
        IReadOnlyList<KindCount> TypeChanges,
        [property: Description("Member changes by kind; a member counts under each of its changes.")] IReadOnlyList<KindCount> MemberChanges,
        [property: Description("Member matches by confidence: exact, strong, structural.")] IReadOnlyList<KindCount> MemberMatches,
        int AmbiguousMembers, int OldSkippedBodies, int NewSkippedBodies,
        [property: Description("Compiler-generated type and member changes left out.")] int HiddenCompilerGenerated,
        [property: Description("The changes of this page, in the text's order.")] IReadOnlyList<ChangeItem> Items,
        int Offset, int Total,
        [property: Description("tokenMap=true: the kept token map; read_result id=<it> outputPath=<file>.json writes it.")] string? TokenMapResultId,
        int TokenMapEntries)
    {
        [Description("oldResult / newResult: inputs and counts.")] public EvidenceSummary? Evidence { get; init; }
        [Description("Results or capabilities that differ.")] public IReadOnlyList<EvidenceChange>? Changes { get; init; }
    }

    /// <summary>The token map file: both builds and every old type and member with its counterpart.</summary>
    public sealed record TokenMapFile(string Format, int Version, int IlHashVersion, BuildRef Old, BuildRef New, IReadOnlyList<AssemblyComparer.TokenMapEntry> Entries);

    private static readonly System.Text.Json.JsonSerializerOptions MapJson = new()
    {
        WriteIndented = true,
        PropertyNamingPolicy = System.Text.Json.JsonNamingPolicy.CamelCase,
        DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull,
    };

    [McpServerTool(Name = "compare_assemblies", Title = "Compare two builds", UseStructuredContent = true, OutputSchemaType = typeof(AssemblyComparison))]
    [Description("Two builds of an assembly: renamed, moved, added and removed types and members (matched by content in tiers, unique, else " +
                 "ambiguous), how matched members changed (signature, body by IL hash, metadata, Il2Cpp offset), capabilities added or removed. " +
                 "oldResult / newResult: kept results.")]
    public Task<string> CompareAssemblies(
        [Description("Old build: id, name or path.")] string? oldAssembly = null,
        [Description("New build: id, name or path.")] string? newAssembly = null,
        [Description("Only types whose old or new full name starts with this.")] string? @namespace = null,
        [Description("Kinds to list (unknown: unpaired for lack of evidence); default all but address.")] string[]? changes = null,
        [Description("Count added and removed types, not listed.")] bool typeCountsOnly = false,
        [Description("Also compiler-generated types and members (closures, state machines).")] bool includeCompilerGenerated = false,
        [Description("Keep the whole old-to-new token map as a result (tokenMapResultId).")] bool tokenMap = false,
        [Description(RowOffsetDescription)] int offset = 0,
        [Description("Changes per page.")] int limit = 100,
        [Description(MaxTokensDescription)] int? maxTokens = null,
        [Description(NativeDiffTools.OldResultDescription)] string? oldResult = null,
        [Description(NativeDiffTools.NewResultDescription)] string? newResult = null,
        RequestContext<CallToolRequestParams> context = null!,
        CancellationToken cancellationToken = default) => EditTools.WithProgress(context, () => Read(workspace, () =>
    {
        if (EvidenceInput.FromArguments(oldResult, newResult, oldAssembly != null || newAssembly != null, "oldAssembly and newAssembly", context?.Services) is var (ev, evidence))
            return NativeDiffTools.EvidenceList(evidence, offset, ClampLimit(limit), ev, page => new AssemblyComparison(new BuildRef(ev.Old.Ref, "", "", ""),
                new BuildRef(ev.New.Ref, "", "", ""), 0, 0, [], [], [], 0, 0, 0, 0, [], Math.Max(0, offset), evidence.Count, null, 0) { Evidence = ev, Changes = page });
        var oldAsm = workspace.Get(oldAssembly!);
        var newAsm = workspace.Get(newAssembly!);
        var kinds = (changes is { Length: > 0 } ? changes.Select(k => k.Trim()) : AllKinds.Where(k => k != "address")).Select(k => k.ToLowerInvariant()).ToHashSet();
        if (kinds.Remove("all")) kinds.UnionWith(AllKinds);
        foreach (var k in kinds.Where(k => !AllKinds.Contains(k)))
            throw new ToolError(ErrorCode.InvalidArgument, $"Unknown change kind '{k}'. Use: {string.Join(", ", AllKinds)}.");

        var cmp = comparer.Compare(oldAsm, newAsm, cancellationToken);
        bool InScope(TypeChange t) => @namespace == null
            || (t.Old?.FullName.StartsWith(@namespace, StringComparison.Ordinal) ?? false)
            || (t.New?.FullName.StartsWith(@namespace, StringComparison.Ordinal) ?? false);
        var types = cmp.Types.Where(InScope).ToList();
        int hiddenTypes = 0, hiddenMembers = 0;
        if (!includeCompilerGenerated)
        {
            hiddenTypes = types.Count(t => IsGenerated(t.Old ?? t.New));
            types = types.Where(t => !IsGenerated(t.Old ?? t.New)).ToList();
            hiddenMembers = types.Sum(t => t.Members.Count(m => IsGenerated(m.Old ?? m.New)));
            types = types.Select(t => t with { Members = t.Members.Where(m => !IsGenerated(m.Old ?? m.New)).ToList() }).ToList();
        }

        var sb = new StringBuilder($"Comparing {oldAsm.Id} ({oldAsm.FilePath}; {oldAsm.BuildIdentity})\n       -> {newAsm.Id} ({newAsm.FilePath}; {newAsm.BuildIdentity})\n");
        var memberCounts = types.SelectMany(t => t.Members).SelectMany(m => m.Dimensions).GroupBy(d => d.Kind).ToDictionary(g => g.Key, g => g.Count());
        sb.AppendLine($"Types: {Count(types, "renamed")} renamed, {Count(types, "changed")} with member changes, {Count(types, "removed")} removed, {Count(types, "added")} added" +
                      $"{(Count(types, "ambiguous") > 0 ? $", {Count(types, "ambiguous")} ambiguous" : "")} " +
                      $"({cmp.TypeMap.Count} matched of {MetadataUtil.CountedTypes(oldAsm.Module).Count} old).");
        sb.AppendLine("Members (each change of a member counted): " + string.Join(", ", AllKinds.Select(k => $"{memberCounts.GetValueOrDefault(k)} {k}")));
        sb.AppendLine(MatchSummary(cmp, @namespace));
        if (hiddenTypes + hiddenMembers > 0)
            sb.AppendLine($"Hidden: {hiddenTypes} compiler-generated type change(s) and {hiddenMembers} member change(s) " +
                          "(closures, state machines, backing fields, array data; includeCompilerGenerated=true shows them).");
        // Capabilities are surveyed over the whole assembly, whatever the namespace filter.
        IReadOnlyList<EvidenceChange>? capabilities = null;
        if (inspection != null)
        {
            (capabilities, var capabilityText) = Services.Analysis.CapabilityChanges.Between(inspection, oldAsm.Id, newAsm.Id, cancellationToken);
            sb.Append(capabilityText);
        }
        foreach (var (side, asm, skipped) in new[] { ("old", oldAsm, cmp.OldSkippedBodies), ("new", newAsm, cmp.NewSkippedBodies) })
            if (skipped > 0)
                sb.AppendLine($"Skipped: {skipped} method bodies of the {side} build ({asm.Id}) are not valid IL (encrypted?) and were not compared; " +
                              "their body changes are marked \"not comparable\", and members they leave without a counterpart \"unknown\".");

        string? mapId = null;
        int mapEntries = 0;
        if (tokenMap)
        {
            var map = AssemblyComparer.TokenMap(cmp);
            var json = System.Text.Json.JsonSerializer.Serialize(new TokenMapFile("token-map", 1, IlHash.Version, BuildRef.Of(oldAsm), BuildRef.Of(newAsm), map), MapJson);
            mapId = results?.Keep(json, new KeptOrigin("compare_assemblies", $"{oldAsm.Id} -> {newAsm.Id} token map", null,
                [new KeptInput(oldAsm.Id, oldAsm.OriginalSha256), new KeptInput(newAsm.Id, newAsm.OriginalSha256)]))
                ?? throw new ToolError(ErrorCode.Unsupported, "This server keeps no results, so the token map has nowhere to go.", "call compare_assemblies on the MCP server");
            mapEntries = map.Count;
            sb.AppendLine($"Token map: {map.Count} old types and members kept: read_result id={mapId} outputPath=<file>.json writes it.");
        }

        // One row per change; a row starting a new group (its type, or a section) prints the group's heading first.
        var rows = new List<(ChangeItem Item, string Group, string? Line)>();
        // Removed types are listed here only for the methods that moved out of them.
        foreach (var t in types.Where(t => t.Change is "renamed" or "changed" or "removed"))
        {
            var members = t.Members.Where(m => m.Dimensions.Any(d => kinds.Contains(d.Kind))).ToList();
            if (t.Change != "renamed" && members.Count == 0) continue;
            var heading = t.Change == "renamed"
                ? $"{t.Old!.FullName} -> {t.New!.FullName}  (renamed, match {Corvus.Core.Format.Percent(t.Score)}; {Tier(AssemblyComparer.TypeTier(t.Old, t.New))})"
                : t.Change == "removed" ? $"{t.Old!.FullName}  (removed)" : t.Old!.FullName;
            if (t.Change == "renamed") rows.Add((TypeItem(t), heading, null));
            foreach (var m in members) rows.Add((MemberItem(cmp, m), heading, $"{m.Change,-9} {Describe(cmp, m)}"));
        }
        var ambiguousTypes = types.Where(t => t.Change == "ambiguous").ToList();
        foreach (var t in ambiguousTypes)
            rows.Add((TypeItem(t), $"Ambiguous types ({ambiguousTypes.Count}; several new types match equally well):",
                $"{t.Old!.FullName} -> {string.Join(" | ", t.Candidates!.Select(c => c.FullName))}"));
        if (!typeCountsOnly)
            foreach (var change in new[] { "removed", "added" })
            {
                var list = types.Where(t => t.Change == change).ToList();
                foreach (var t in list) rows.Add((TypeItem(t), $"{(change == "removed" ? "Removed" : "Added")} types ({list.Count}):", (t.Old ?? t.New)!.FullName));
            }

        var matches = cmp.MemberMap.Where(m => @namespace == null || (m.Key.DeclaringType?.FullName.StartsWith(@namespace, StringComparison.Ordinal) ?? false))
            .GroupBy(m => m.Value.Confidence).ToDictionary(g => g.Key, g => g.Count());
        var result = new AssemblyComparison(BuildRef.Of(oldAsm), BuildRef.Of(newAsm), MetadataUtil.CountedTypes(oldAsm.Module).Count, cmp.TypeMap.Count,
            [.. new[] { "renamed", "changed", "ambiguous", "removed", "added" }.Select(k => new KindCount(k, Count(types, k)))],
            [.. AllKinds.Select(k => new KindCount(k, memberCounts.GetValueOrDefault(k)))],
            [.. Confidences.Select(c => new KindCount(c, matches.GetValueOrDefault(c)))],
            cmp.Ambiguous.Keys.Count(m => m is not TypeDef && (@namespace == null || (m.DeclaringType?.FullName.StartsWith(@namespace, StringComparison.Ordinal) ?? false))),
            cmp.OldSkippedBodies, cmp.NewSkippedBodies, hiddenTypes + hiddenMembers,
            [], Math.Max(0, offset), rows.Count, mapId, mapEntries) { Changes = capabilities };
        string? group = null;
        string Row((ChangeItem Item, string Group, string? Line) r)
        {
            // A row under a heading continues on an indented line: the same column as a row without one.
            var text = r.Group != group ? r.Group + (r.Line != null ? "\n  " + r.Line : "") : "    " + r.Line;
            group = r.Group;
            return text;
        }
        return ToolOutput.List(rows, offset, ClampLimit(limit), Row, page => result with { Items = page.Select(r => r.Item).ToList() }, "change",
            sb.Append('\n').ToString());
    }, cancellationToken));

    private static ChangeItem TypeItem(TypeChange t)
    {
        var (tier, confidence) = t is { Old: { } o, New: { } n } ? AssemblyComparer.TypeTier(o, n) : ((string?)null, (string?)null);
        return new ChangeItem("type", t.Change, t.Old?.FullName, t.Old is { } a ? Format.Token(a) : null, t.New?.FullName, t.New is { } b ? Format.Token(b) : null,
            [new(t.Change, t.Change == "renamed" ? $"match {Corvus.Core.Format.Percent(t.Score)}" : "")], tier, confidence, t.Candidates?.Select(c => $"{c.FullName} {Format.Token(c)}").ToList());
    }

    private static ChangeItem MemberItem(Comparison cmp, MemberChange m)
    {
        var match = m.Old != null && cmp.MemberMap.TryGetValue(m.Old, out var x) ? x : null;
        return new ChangeItem(SymbolRef.MemberKind(m.Old ?? m.New!), m.Change, m.Old is { } o ? Format.MemberLabel(o) : null, m.Old is { } a ? Format.Token(a) : null,
            m.New is { } n ? Format.MemberLabel(n) : null, m.New is { } b ? Format.Token(b) : null, m.Dimensions, match?.Tier, match?.Confidence,
            m.Candidates?.Select(c => $"{Format.MemberLabel(c)} {Format.Token(c)}").ToList());
    }

    /// <summary>One looked-up symbol: its counterpart in the new build (or the tied candidates), how it matched, and what changed.</summary>
    public sealed record CounterpartItem(
        string Kind, string Old, string OldToken, string? New, string? NewToken,
        [property: Description("How it matched, or why nothing did.")] string How,
        string? Tier, string? Confidence,
        [property: Description("Ambiguous: the tied candidates in the new build.")] IReadOnlyList<string>? Candidates,
        [property: Description("Change kinds of a matched member.")] IReadOnlyList<string>? Changes,
        [property: Description("Methods: whether the normalized IL hash differs; absent when not comparable.")] bool? BodyChanged);

    /// <summary>Old and New are the builds' ids (the text names their files and hashes).</summary>
    public sealed record CounterpartList(string Old, string New, IReadOnlyList<CounterpartItem> Items, int Offset, int Total);

    [McpServerTool(Name = "find_counterpart", Title = "Find symbol in another build", UseStructuredContent = true, OutputSchemaType = typeof(CounterpartList))]
    [Description("Where a type or member of the old build went in the new one (by name, then content, unique-only; else candidates): new name and " +
                 "token, tier, confidence, body change. diff=true and il=true add unified C# and normalized IL diffs of each pair, renames applied " +
                 "first.")]
    public Task<string> FindCounterpart(
        [Description("Old build: " + SymbolDescription)] string? symbol,
        [Description("Old build: id, name or path.")] string oldAssembly,
        [Description("New build: id, name or path.")] string newAssembly,
        [Description("C# diff of each pair (cut at " + DiffLinesText + " lines).")] bool diff = false,
        [Description("Normalized IL diff of each method pair.")] bool il = false,
        [Description("Instead of symbol: up to 100.")] string[]? symbols = null,
        [Description(RowOffsetDescription)] int offset = 0,
        [Description("Symbols per page.")] int limit = 25,
        [Description(MaxTokensDescription)] int? maxTokens = null,
        RequestContext<CallToolRequestParams> context = null!,
        CancellationToken cancellationToken = default) => EditTools.WithProgress(context, () => Read(workspace, () =>
    {
        var oldAsm = workspace.Get(oldAssembly);
        var newAsm = workspace.Get(newAssembly);
        if (symbols is { Length: > 100 })
            throw new ToolError(ErrorCode.LimitExceeded, $"{symbols.Length} symbols; at most 100 per call.", "split the list into calls of 100");
        var targets = symbols is { Length: > 0 } ? symbols : !string.IsNullOrWhiteSpace(symbol) ? [symbol]
            : throw new ToolError(ErrorCode.InvalidArgument, "Pass symbol, or symbols for several.", "pass symbol=<Ns.Type::Member> from the old build");
        var cmp = comparer.Compare(oldAsm, newAsm, cancellationToken);
        var head = new StringBuilder($"Old: {oldAsm.Id} ({oldAsm.BuildIdentity})\nNew: {newAsm.Id} ({newAsm.BuildIdentity})\n");
        if (cmp.OldSkippedBodies + cmp.NewSkippedBodies > 0)
            head.AppendLine($"Skipped: {cmp.OldSkippedBodies} old and {cmp.NewSkippedBodies} new method bodies are not valid IL and were not compared; " +
                            "matches by content involving them are less reliable.");
        var all = targets.SelectMany(t => SymbolResolver.Resolve(workspace, oldAsm.Id, t)).DistinctBy(s => s.Member).ToList();
        var page = all.Skip(Math.Max(0, offset)).Take(ClampLimit(limit, 100)).ToList();
        Renames? renames = null;
        var rows = page.Select(sym => Counterpart(sym)).ToList();
        return ToolOutput.List(rows, offset, ClampLimit(limit, 100), all.Count, r => r.Text,
            items => new CounterpartList(oldAsm.Id, newAsm.Id, items.Select(r => r.Item).ToList(), Math.Max(0, offset), all.Count),
            "symbol", head.ToString());

        (CounterpartItem Item, string Text) Counterpart(ResolvedSymbol sym)
        {
            var sb = new StringBuilder();
            var found = comparer.FindCounterpart(cmp, sym.Member);
            var kind = SymbolRef.MemberKind(sym.Member);
            var item = new CounterpartItem(kind, sym.Label, Format.Token(sym.Member), null, null, found.How, found.Tier, found.Confidence, null, null, null);
            sb.AppendLine($"{sym.Kind} {sym.Label}  [{oldAsm.Id}] {Format.Token(sym.Member)}");
            if (found.Candidates is { } candidates)
            {
                sb.AppendLine($"  -> ambiguous: {candidates.Count} candidates share the {found.Tier} key (no tier tells them apart):");
                foreach (var c in candidates)
                    sb.AppendLine($"     {Format.MemberLabel(c)}  [{newAsm.Id}] {Format.Token(c)}");
                return (item with { How = $"ambiguous: {candidates.Count} candidates share the {found.Tier} key", Candidates = candidates.Select(c => $"{Format.MemberLabel(c)} {Format.Token(c)}").ToList() },
                    sb.ToString().TrimEnd('\n'));
            }
            if (found.Match is not { } match)
            {
                sb.AppendLine($"  -> not found: {found.How}");
                return (item, sb.ToString().TrimEnd('\n'));
            }
            item = item with { New = Format.MemberLabel(match), NewToken = Format.Token(match) };
            sb.AppendLine($"  -> {Format.MemberLabel(match)}  [{newAsm.Id}] {Format.Token(match)}  ({found.How}; {Tier((found.Tier!, found.Confidence!))})");
            if (sym.Member is not TypeDef)
            {
                var change = cmp.Types.SelectMany(t => t.Members).FirstOrDefault(c => c.Old == sym.Member && c.New == match);
                item = item with { Changes = change?.Dimensions.Select(d => d.Kind).ToList() ?? [] };
                sb.AppendLine($"     changes: {(change == null ? "none" : string.Join(", ", change.Dimensions.Select(d => d.Kind)))}");
                if (change?.Dimensions.FirstOrDefault(d => d.Kind == "metadata") is { } metadata)
                    sb.AppendLine($"     metadata: {metadata.Detail}");
            }
            if (sym.Member is FieldDef of && match is FieldDef nf && Format.Type(of.FieldType) != Format.Type(nf.FieldType))
                sb.AppendLine($"     type: {Format.Type(of.FieldType)} -> {Format.Type(nf.FieldType)}");
            if (sym.Member is MethodDef om && match is MethodDef nm)
            {
                if (Format.ParameterTypes(om.MethodSig) != Format.ParameterTypes(nm.MethodSig))
                    sb.AppendLine($"     signature: ({Format.ParameterTypes(om.MethodSig)}) -> ({Format.ParameterTypes(nm.MethodSig)})");
                var (oldHash, newHash) = (IlHash.Of(oldAsm, om), IlHash.Of(newAsm, nm));
                if (oldHash != null && newHash != null) item = item with { BodyChanged = oldHash != newHash };
                sb.AppendLine(oldHash == null || newHash == null
                    ? $"     body: {(oldHash == null && newHash == null ? "none on either side" : "not comparable (no body or not valid IL on one side)")}"
                    : oldHash == newHash ? $"     body: unchanged (IL hash {IlHash.Short(oldHash)})"
                    : $"     body: changed (IL hash {IlHash.Short(oldHash)} -> {IlHash.Short(newHash)})");
            }
            var oldIl2Cpp = Il2CppService.CompactSummary(sym.Member);
            var newIl2Cpp = Il2CppService.CompactSummary(match);
            if (oldIl2Cpp != null || newIl2Cpp != null)
                sb.AppendLine($"     il2cpp: {oldIl2Cpp ?? "-"} -> {newIl2Cpp ?? "-"}");
            if (!diff && !il) return (item, sb.ToString().TrimEnd('\n'));
            renames ??= Renames.Of(cmp);
            int budget = DiffLines;
            if (diff && sym.Member is TypeDef oldType)
                TypeDiff(sb, cmp, oldType, renames, ref budget);
            else if (diff && sym.Member is MethodDef om2 && match is MethodDef nm2 && SameBody(oldAsm, om2, newAsm, nm2))
                sb.AppendLine("     C# diff: none needed (the same normalized IL)");
            else if (diff)
                AppendDiff(sb, "C#", () => renames.Apply(Source(oldAsm, sym.Member)), () => renames.Apply(Source(newAsm, match)),
                    $"{oldAsm.Id} {sym.Label}", $"{newAsm.Id} {Format.MemberLabel(match)}", ref budget, renames);
            if (il && sym.Member is MethodDef im && match is MethodDef jm)
                AppendDiff(sb, "normalized IL", () => renames.Apply(NormalizedIl(oldAsm, im)), () => renames.Apply(NormalizedIl(newAsm, jm)),
                    $"{oldAsm.Id} {sym.Label}", $"{newAsm.Id} {Format.MemberLabel(match)}", ref budget, renames);
            return (item, sb.ToString().TrimEnd('\n'));
        }

        string Source(LoadedAssembly asm, IMemberDef member) => member is TypeDef t
            ? decompiler.DecompileType(asm, t, cancellationToken)
            : decompiler.DecompileMembers(asm, [member], cancellationToken);

        // A type: each member that changed, was added or removed, under one line budget.
        void TypeDiff(StringBuilder sb, Comparison cmp, TypeDef oldType, Renames renames, ref int budget)
        {
            var change = cmp.Types.FirstOrDefault(t => t.Old == oldType);
            var members = change?.Members.Where(m => m.Change != "ambiguous" && !(m.Old is MethodDef a && m.New is MethodDef b && m.Change == "renamed"
                && m.Dimensions.Count == 1 && SameBody(oldAsm, a, newAsm, b))).ToList() ?? [];
            if (members.Count == 0)
            {
                sb.AppendLine("     C# diff: no member changed (renames aside)");
                return;
            }
            sb.AppendLine($"     C# diff of {members.Count} changed, added or removed member(s):");
            foreach (var m in members)
            {
                if (budget <= 0)
                {
                    sb.AppendLine($"       … the line budget is spent; find_counterpart on a member shows its diff.");
                    break;
                }
                var label = m.Old is { } o ? Format.MemberLabel(o) : Format.MemberLabel(m.New!);
                AppendDiff(sb, $"{m.Change} {label}", () => m.Old is { } o ? renames.Apply(Source(oldAsm, o)) : "",
                    () => m.New is { } n ? renames.Apply(Source(newAsm, n)) : "", m.Old != null ? $"{oldAsm.Id} {label}" : "(did not exist)",
                    m.New != null ? $"{newAsm.Id} {Format.MemberLabel(m.New)}" : "(removed)", ref budget, renames);
            }
        }
    }, cancellationToken));

    private static bool SameBody(LoadedAssembly oldAsm, MethodDef old, LoadedAssembly newAsm, MethodDef @new) =>
        IlHash.Of(oldAsm, old) is { } a && a == IlHash.Of(newAsm, @new) && Format.ParameterTypes(old.MethodSig) == Format.ParameterTypes(@new.MethodSig);

    /// <summary>
    /// The new build's names for what it renamed (types and members), applied to the old side's text before diffing, and the
    /// per-build "[token 0x...]" marks removed. A name renamed to several names, or also used unchanged elsewhere, is left alone.
    /// </summary>
    private sealed class Renames
    {
        private static readonly System.Text.RegularExpressions.Regex TokenMark = new(@"\s*\[token (?:0x[0-9A-Fa-f]{8}|\(new\))\]",
            System.Text.RegularExpressions.RegexOptions.CultureInvariant | System.Text.RegularExpressions.RegexOptions.NonBacktracking);
        private readonly Dictionary<string, string> _map;
        private readonly System.Text.RegularExpressions.Regex? _names;

        private Renames(Dictionary<string, string> map)
        {
            _map = map;
            // Literal names between one-character lookarounds: bounded work per
            // position, so no match timeout.
            if (map.Count > 0)
                _names = new(@"(?<![\w`])(" + string.Join("|", map.Keys.OrderByDescending(k => k.Length).Select(System.Text.RegularExpressions.Regex.Escape)) + @")(?![\w`])",
                    System.Text.RegularExpressions.RegexOptions.CultureInvariant);
        }

        public static Renames Of(Comparison cmp)
        {
            var pairs = cmp.TypeMap.Select(t => (Old: Simple(t.Key.Name), New: Simple(t.Value.Name)))
                .Concat(cmp.MemberMap.Where(m => m.Key is not MethodDef { IsConstructor: true }).Select(m => (Old: m.Key.Name.String, New: m.Value.New.Name.String)))
                .ToList();
            var kept = pairs.Where(p => p.Old == p.New).Select(p => p.Old).ToHashSet(StringComparer.Ordinal);
            var map = pairs.Where(p => p.Old != p.New && !kept.Contains(p.Old) && !p.Old.Contains('<') && p.Old.Length > 0)
                .GroupBy(p => p.Old, StringComparer.Ordinal).Where(g => g.Select(p => p.New).Distinct().Count() == 1)
                .ToDictionary(g => g.Key, g => g.First().New, StringComparer.Ordinal);
            return new Renames(map);
        }

        private static string Simple(string name) => name.IndexOf('`') is var tick and > 0 ? name[..tick] : name;

        public HashSet<string> Used { get; } = new(StringComparer.Ordinal);

        public string Apply(string text)
        {
            text = TokenMark.Replace(text, "");
            if (_names == null) return text;
            return _names.Replace(text, m =>
            {
                Used.Add(m.Value);
                return _map[m.Value];
            });
        }

        /// <summary>The renames applied so far, for the diff header.</summary>
        public string Describe(int max = 8)
        {
            var list = Used.Order(StringComparer.Ordinal).ToList();
            return string.Join(", ", list.Take(max).Select(n => $"{n} -> {_map[n]}")) + (list.Count > max ? $" (+{list.Count - max} more)" : "");
        }
    }

    private const int DiffLines = 300;
    private const string DiffLinesText = "300";

    private static string NormalizedIl(LoadedAssembly asm, MethodDef m) =>
        FastIlReader.Read(asm, m) is { } body ? IlHash.Canonical(body) : "(no body)\n";

    /// <summary>A unified diff of one pair, indented under it; cut when <paramref name="budget"/> lines are spent, with a note.</summary>
    private static void AppendDiff(StringBuilder sb, string what, Func<string> before, Func<string> after, string beforeLabel, string afterLabel, ref int budget,
        Renames renames)
    {
        string text;
        int used = renames.Used.Count;
        try { text = TextDiff.Unified(before(), after(), beforeLabel, afterLabel); }
        catch (ToolError ex)
        {
            sb.AppendLine($"     {what} diff: unavailable ({ex.Message})");
            return;
        }
        var lines = text.ReplaceLineEndings("\n").TrimEnd('\n').Split('\n');
        bool same = lines.All(l => l.Length == 0 || l.StartsWith("---", StringComparison.Ordinal) || l.StartsWith("+++", StringComparison.Ordinal)
            || !(l.StartsWith('+') || l.StartsWith('-')));
        sb.AppendLine($"     {what} diff:{(same ? " none" : "")}{(renames.Used.Count > used || (same && renames.Used.Count > 0) ? $" (old names read as renamed: {renames.Describe()})" : "")}");
        if (same) return;
        int shown = Math.Min(lines.Length, Math.Max(0, budget));
        foreach (var line in lines.Take(shown)) sb.Append("       ").AppendLine(line);
        budget -= shown;
        if (lines.Length > shown)
            sb.AppendLine($"       … diff cut at {shown} of {lines.Length} lines; decompile_member / get_il on each build show the rest.");
    }

    private static string Tier((string Tier, string Confidence) t) => $"tier: {t.Tier}, {t.Confidence}";

    /// <summary>Matched members by confidence and tier, and the ambiguous ones, for the types in scope.</summary>
    private static string MatchSummary(Comparison cmp, string? @namespace)
    {
        bool InScope(IMemberDef m) => @namespace == null || (m.DeclaringType?.FullName.StartsWith(@namespace, StringComparison.Ordinal) ?? false);
        var matches = cmp.MemberMap.Where(m => InScope(m.Key)).Select(m => m.Value).ToList();
        int ambiguous = cmp.Ambiguous.Keys.Count(m => m is not TypeDef && InScope(m));
        var confidence = matches.GroupBy(m => m.Confidence).ToDictionary(g => g.Key, g => g.Count());
        var tiers = matches.GroupBy(m => m.Tier).OrderByDescending(g => g.Count()).Select(g => $"{g.Key} {g.Count()}");
        return $"Member matches: {string.Join(", ", Confidences.Select(c => $"{confidence.GetValueOrDefault(c)} {c}"))}, {ambiguous} ambiguous " +
               $"(by tier: {string.Join(", ", tiers)}).";
    }

    private static int Count(List<TypeChange> types, string change) => types.Count(t => t.Change == change);

    /// <summary>True if the member or an enclosing type has '&lt;' in its name, which only compiler-generated names contain.</summary>
    private static bool IsGenerated(IMemberDef? member)
    {
        for (IMemberDef? m = member; m != null; m = m.DeclaringType)
            if (m.Name.String.Contains('<')) return true;
        return false;
    }

    private static string Describe(Comparison cmp, MemberChange m)
    {
        var member = m.Old ?? m.New!;
        string Name(IMemberDef d) => d switch
        {
            MethodDef md => $"{md.Name}({Format.ParameterTypes(md.MethodSig)})",
            _ => d.Name,
        };
        string kind = member switch { MethodDef => "method", FieldDef => "field", PropertyDef => "property", EventDef => "event", _ => "member" };
        string TierOf(IMemberDef old) => cmp.MemberMap.TryGetValue(old, out var match) ? "; " + Tier((match.Tier, match.Confidence)) : "";
        string more = string.Concat(m.Dimensions.Skip(1).Select(d => $"  +{d.Kind}: {d.Detail}"));
        return (m.Change switch
        {
            "renamed" => $"{kind} {Name(m.Old!)} -> {Name(m.New!)}  ({m.Detail}{TierOf(m.Old!)})",
            "moved" => $"{kind} {Name(m.Old!)} -> {m.New!.DeclaringType.FullName}::{Name(m.New!)}  ({cmp.MemberMap[m.Old!].How}{TierOf(m.Old!)})",
            "added" => $"{kind} {Name(m.New!)}  {m.Detail}",
            "removed" => $"{kind} {Name(m.Old!)}  {m.Detail}",
            // Candidates in another type (a move) are named with their type.
            "ambiguous" => $"{kind} {Name(m.Old!)}: {m.Detail}: {string.Join(" | ", m.Candidates!.Select(c =>
                c.DeclaringType?.Name == m.Old!.DeclaringType?.Name ? Name(c) : $"{c.DeclaringType?.FullName}::{Name(c)}"))}",
            _ => $"{kind} {Name(member)}: {m.Detail}",
        }) + more;
    }
}
