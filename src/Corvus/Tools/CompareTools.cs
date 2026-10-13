using System.ComponentModel;
using System.Text;
using dnlib.DotNet;
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
public sealed class CompareTools(AssemblyWorkspace workspace, AssemblyComparer comparer, DecompilerService decompiler)
{
    private static readonly string[] AllKinds = ["renamed", "moved", "signature", "body", "metadata", "type", "offset", "address", "added", "removed", "ambiguous", "unknown"];

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
        [property: Description("The file tokenMapPath wrote.")] string? TokenMapFile,
        int TokenMapEntries);

    /// <summary>The token map file: both builds and every old type and member with its counterpart.</summary>
    public sealed record TokenMapFile(string Format, int Version, int IlHashVersion, BuildRef Old, BuildRef New, IReadOnlyList<AssemblyComparer.TokenMapEntry> Entries);

    private static readonly System.Text.Json.JsonSerializerOptions MapJson = new()
    {
        WriteIndented = true,
        PropertyNamingPolicy = System.Text.Json.JsonNamingPolicy.CamelCase,
        DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull,
    };

    [McpServerTool(Name = "compare_assemblies", Title = "Compare two builds", UseStructuredContent = true, OutputSchemaType = typeof(AssemblyComparison))]
    [Description("Compare two builds of an assembly (load both; the second gets an id like Name#2): renamed / moved types and members (matched by content, " +
                 "in tiers, only when unique on both sides; else ambiguous with candidates), added and removed ones, and how each matched member changed: " +
                 "name, signature, body (normalized IL hash), metadata, field type, Il2Cpp field offset / address.")]
    public Task<string> CompareAssemblies(
        [Description("The old build (id, name or path).")] string oldAssembly,
        [Description("The new build (id, name or path).")] string newAssembly,
        [Description("Only types whose old or new full name starts with this.")] string? @namespace = null,
        [Description("Change kinds to list, comma-separated: renamed, moved, signature, body, metadata, type, offset, address, added, removed, ambiguous, " +
                     "unknown (unpaired for lack of evidence) or all; default all except address.")] string? changes = null,
        [Description("List added and removed type names (else counts).")] bool listAddedRemovedTypes = true,
        [Description("Also show compiler-generated types and members (closures, state machines, backing fields), which change with every recompile.")] bool includeCompilerGenerated = false,
        [Description("Write the whole assembly's token map (old -> new token, status, tier, confidence, body hash equality) to this JSON file.")] string? tokenMapPath = null,
        [Description("Replace an existing token map file.")] bool overwrite = false,
        [Description(RowOffsetDescription)] int offset = 0,
        [Description("Changes per page (default 200).")] int limit = 200,
        [Description(MaxTokensDescription)] int? maxTokens = null,
        CancellationToken cancellationToken = default) => Read(workspace, () =>
    {
        var oldAsm = workspace.Get(oldAssembly);
        var newAsm = workspace.Get(newAssembly);
        var kinds = (changes?.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries) ?? AllKinds.Where(k => k != "address").ToArray())
            .Select(k => k.ToLowerInvariant()).ToHashSet();
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
        foreach (var (side, asm, skipped) in new[] { ("old", oldAsm, cmp.OldSkippedBodies), ("new", newAsm, cmp.NewSkippedBodies) })
            if (skipped > 0)
                sb.AppendLine($"Skipped: {skipped} method bodies of the {side} build ({asm.Id}) are not valid IL (encrypted?) and were not compared; " +
                              "their body changes are marked \"not comparable\", and members they leave without a counterpart \"unknown\".");

        string? mapFile = null;
        int mapEntries = 0;
        if (tokenMapPath != null)
        {
            var map = AssemblyComparer.TokenMap(cmp);
            mapFile = SafeFile.WriteAllText(tokenMapPath, System.Text.Json.JsonSerializer.Serialize(
                new TokenMapFile("token-map", 1, IlHash.Version, BuildRef.Of(oldAsm), BuildRef.Of(newAsm), map), MapJson), overwrite);
            mapEntries = map.Count;
            sb.AppendLine($"Token map: {map.Count} old types and members written to {mapFile}.");
        }

        // One row per change; a row starting a new group (its type, or a section) prints the group's heading first.
        var rows = new List<(ChangeItem Item, string Group, string? Line)>();
        // Removed types are listed here only for the methods that moved out of them.
        foreach (var t in types.Where(t => t.Change is "renamed" or "changed" or "removed"))
        {
            var members = t.Members.Where(m => m.Dimensions.Any(d => kinds.Contains(d.Kind))).ToList();
            if (t.Change != "renamed" && members.Count == 0) continue;
            var heading = t.Change == "renamed"
                ? $"{t.Old!.FullName} -> {t.New!.FullName}  (renamed, match {t.Score:P0}; {Tier(AssemblyComparer.TypeTier(t.Old, t.New))})"
                : t.Change == "removed" ? $"{t.Old!.FullName}  (removed)" : t.Old!.FullName;
            if (t.Change == "renamed") rows.Add((TypeItem(t), heading, null));
            foreach (var m in members) rows.Add((MemberItem(cmp, m), heading, $"{m.Change,-9} {Describe(cmp, m)}"));
        }
        var ambiguousTypes = types.Where(t => t.Change == "ambiguous").ToList();
        foreach (var t in ambiguousTypes)
            rows.Add((TypeItem(t), $"Ambiguous types ({ambiguousTypes.Count}; several new types match equally well):",
                $"{t.Old!.FullName} -> {string.Join(" | ", t.Candidates!.Select(c => c.FullName))}"));
        if (listAddedRemovedTypes)
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
            [], Math.Max(0, offset), rows.Count, mapFile, mapEntries);
        string? group = null;
        string Row((ChangeItem Item, string Group, string? Line) r)
        {
            var text = (r.Group != group ? r.Group + (r.Line != null ? "\n" : "") : "") + (r.Line != null ? "  " + r.Line : "");
            group = r.Group;
            return text;
        }
        return ToolOutput.List(rows, offset, ClampLimit(limit), Row, page => result with { Items = page.Select(r => r.Item).ToList() }, "change",
            sb.Append('\n').ToString());
    }, cancellationToken);

    private static ChangeItem TypeItem(TypeChange t)
    {
        var (tier, confidence) = t is { Old: { } o, New: { } n } ? AssemblyComparer.TypeTier(o, n) : ((string?)null, (string?)null);
        return new ChangeItem("type", t.Change, t.Old?.FullName, t.Old is { } a ? Format.Token(a) : null, t.New?.FullName, t.New is { } b ? Format.Token(b) : null,
            [new(t.Change, t.Change == "renamed" ? $"match {t.Score:P0}" : "")], tier, confidence, t.Candidates?.Select(c => $"{c.FullName} {Format.Token(c)}").ToList());
    }

    private static ChangeItem MemberItem(Comparison cmp, MemberChange m)
    {
        var match = m.Old != null && cmp.MemberMap.TryGetValue(m.Old, out var x) ? x : null;
        return new ChangeItem(SymbolRef.MemberKind(m.Old ?? m.New!), m.Change, m.Old is { } o ? Format.MemberLabel(o) : null, m.Old is { } a ? Format.Token(a) : null,
            m.New is { } n ? Format.MemberLabel(n) : null, m.New is { } b ? Format.Token(b) : null, m.Dimensions, match?.Tier, match?.Confidence,
            m.Candidates?.Select(c => $"{Format.MemberLabel(c)} {Format.Token(c)}").ToList());
    }

    [McpServerTool(Name = "find_counterpart", Title = "Find symbol in another build")]
    [Description("Where a type or member of the old build went in the new build: matched by name, then by content (only when unique on both sides; else candidates). " +
                 "Shows the new name and token, tier and confidence, whether the body changed (normalized IL hash) and Il2Cpp offset / address changes. " +
                 "diff=true adds a unified diff of the pair's C# (a type: of each changed, added or removed member), il=true of their normalized IL; " +
                 "renames are rewritten first, so a pure rename is no change.")]
    public Task<string> FindCounterpart(
        [Description("In the old build. " + SymbolDescription)] string symbol,
        [Description("The old build (id, name or path).")] string oldAssembly,
        [Description("The new build (id, name or path).")] string newAssembly,
        [Description("Add a unified diff of the old and new decompiled C# of each matched pair (cut at " + DiffLinesText + " lines).")] bool diff = false,
        [Description("Add a unified diff of the matched methods' normalized IL (docs/il-hash.md).")] bool il = false,
        CancellationToken cancellationToken = default) => Read(workspace, () =>
    {
        var oldAsm = workspace.Get(oldAssembly);
        var newAsm = workspace.Get(newAssembly);
        var cmp = comparer.Compare(oldAsm, newAsm, cancellationToken);
        var sb = new StringBuilder($"Old: {oldAsm.Id} ({oldAsm.BuildIdentity})\nNew: {newAsm.Id} ({newAsm.BuildIdentity})\n");
        if (cmp.OldSkippedBodies + cmp.NewSkippedBodies > 0)
            sb.AppendLine($"Skipped: {cmp.OldSkippedBodies} old and {cmp.NewSkippedBodies} new method bodies are not valid IL and were not compared; " +
                          "matches by content involving them are less reliable.");
        Renames? renames = null;
        foreach (var sym in SymbolResolver.Resolve(workspace, oldAsm.Id, symbol).Take(25))
        {
            var found = comparer.FindCounterpart(cmp, sym.Member);
            sb.AppendLine($"{sym.Kind} {sym.Label}  [{oldAsm.Id}] {Format.Token(sym.Member)}");
            if (found.Candidates is { } candidates)
            {
                sb.AppendLine($"  -> ambiguous: {candidates.Count} candidates share the {found.Tier} key (no tier tells them apart):");
                foreach (var c in candidates)
                    sb.AppendLine($"     {Format.MemberLabel(c)}  [{newAsm.Id}] {Format.Token(c)}");
                continue;
            }
            if (found.Match is not { } match)
            {
                sb.AppendLine($"  -> not found: {found.How}");
                continue;
            }
            sb.AppendLine($"  -> {Format.MemberLabel(match)}  [{newAsm.Id}] {Format.Token(match)}  ({found.How}; {Tier((found.Tier!, found.Confidence!))})");
            if (sym.Member is not TypeDef)
            {
                var change = cmp.Types.SelectMany(t => t.Members).FirstOrDefault(c => c.Old == sym.Member && c.New == match);
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
                sb.AppendLine(oldHash == null || newHash == null
                    ? $"     body: {(oldHash == null && newHash == null ? "none on either side" : "not comparable (no body or not valid IL on one side)")}"
                    : oldHash == newHash ? $"     body: unchanged (IL hash {IlHash.Short(oldHash)})"
                    : $"     body: changed (IL hash {IlHash.Short(oldHash)} -> {IlHash.Short(newHash)})");
            }
            var oldIl2Cpp = Il2CppService.CompactSummary(sym.Member);
            var newIl2Cpp = Il2CppService.CompactSummary(match);
            if (oldIl2Cpp != null || newIl2Cpp != null)
                sb.AppendLine($"     il2cpp: {oldIl2Cpp ?? "-"} -> {newIl2Cpp ?? "-"}");
            if (!diff && !il) continue;
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
        }
        return sb.ToString();

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
    }, cancellationToken);

    private static bool SameBody(LoadedAssembly oldAsm, MethodDef old, LoadedAssembly newAsm, MethodDef @new) =>
        IlHash.Of(oldAsm, old) is { } a && a == IlHash.Of(newAsm, @new) && Format.ParameterTypes(old.MethodSig) == Format.ParameterTypes(@new.MethodSig);

    /// <summary>
    /// The new build's names for what it renamed (types and members), applied to the old side's text before diffing, and the
    /// per-build "[token 0x...]" marks removed. A name renamed to several names, or also used unchanged elsewhere, is left alone.
    /// </summary>
    private sealed class Renames
    {
        private static readonly System.Text.RegularExpressions.Regex TokenMark = new(@"\s*\[token (?:0x[0-9A-Fa-f]{8}|\(new\))\]",
            System.Text.RegularExpressions.RegexOptions.CultureInvariant, TimeSpan.FromSeconds(2));
        private readonly Dictionary<string, string> _map;
        private readonly System.Text.RegularExpressions.Regex? _names;

        private Renames(Dictionary<string, string> map)
        {
            _map = map;
            if (map.Count > 0)
                _names = new(@"(?<![\w`])(" + string.Join("|", map.Keys.OrderByDescending(k => k.Length).Select(System.Text.RegularExpressions.Regex.Escape)) + @")(?![\w`])",
                    System.Text.RegularExpressions.RegexOptions.CultureInvariant, TimeSpan.FromSeconds(5));
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
