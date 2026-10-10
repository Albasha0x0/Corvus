using System.ComponentModel;
using System.Text;
using dnlib.DotNet;
using ModelContextProtocol.Server;
using NetDecompilerMcp.Core;
using NetDecompilerMcp.Services;
using static NetDecompilerMcp.Tools.ToolSupport;
using Comparison = NetDecompilerMcp.Services.AssemblyComparer.Comparison;
using MemberChange = NetDecompilerMcp.Services.AssemblyComparer.MemberChange;
using TypeChange = NetDecompilerMcp.Services.AssemblyComparer.TypeChange;

namespace NetDecompilerMcp.Tools;

[McpServerToolType]
public sealed class CompareTools(AssemblyWorkspace workspace, AssemblyComparer comparer, OutputPager pager)
{
    private static readonly string[] AllKinds = ["renamed", "signature", "body", "metadata", "type", "offset", "address", "added", "removed", "ambiguous"];

    private static readonly string[] Confidences = ["exact", "strong", "structural"];

    [McpServerTool(Name = "compare_assemblies", Title = "Compare two builds")]
    [Description("Compare two builds of an assembly (e.g. before and after an update; load both — the second gets an id like Name#2). " +
                 "Reports renamed/moved types and members (matched by content, so transformed or refactored names carry forward), added and removed members, " +
                 "and for each matched member every way it changed: renamed, signature, body (normalized IL hash), metadata (flags, implementation flags, attributes), " +
                 "field type, and Il2Cpp field offset / address. Members are matched in tiers and only when the match is unique on both sides; " +
                 "otherwise they are listed as ambiguous with their candidates.")]
    public Task<string> CompareAssemblies(
        [Description("The old build (id, name or path).")] string oldAssembly,
        [Description("The new build (id, name or path).")] string newAssembly,
        [Description("Only types whose old or new full name starts with this.")] string? @namespace = null,
        [Description("Member change kinds to include, comma-separated: renamed, signature, body, metadata, type, offset, address, added, removed, ambiguous, or all; " +
                     "a member is listed when any of its changes is included. Default: all except address.")] string? changes = null,
        [Description("Also list the names of added and removed types (otherwise only counts).")] bool listAddedRemovedTypes = true,
        [Description("Also show compiler-generated types and members (closures, iterator / async state machines, backing fields, " +
                     "<PrivateImplementationDetails> data): they change with every recompile, so they are hidden and counted by default.")] bool includeCompilerGenerated = false,
        [Description(OffsetDescription)] int offset = 0,
        [Description(MaxCharsDescription)] int? maxChars = null,
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
                              "their body changes are marked \"not comparable\".");

        foreach (var t in types.Where(t => t.Change is "renamed" or "changed"))
        {
            var members = t.Members.Where(m => m.Dimensions.Any(d => kinds.Contains(d.Kind))).ToList();
            if (t.Change == "changed" && members.Count == 0) continue;
            sb.AppendLine();
            sb.AppendLine(t.Change == "renamed"
                ? $"{t.Old!.FullName} -> {t.New!.FullName}  (renamed, match {t.Score:P0}; {Tier(AssemblyComparer.TypeTier(t.Old, t.New))})"
                : t.Old!.FullName);
            foreach (var m in members)
                sb.AppendLine($"    {m.Change,-9} {Describe(cmp, m)}");
        }
        var ambiguousTypes = types.Where(t => t.Change == "ambiguous").ToList();
        if (ambiguousTypes.Count > 0)
        {
            sb.AppendLine($"\nAmbiguous types ({ambiguousTypes.Count}; several new types match equally well):");
            foreach (var t in ambiguousTypes.Take(300))
                sb.AppendLine($"  {t.Old!.FullName} -> {string.Join(" | ", t.Candidates!.Select(c => c.FullName))}");
        }
        if (listAddedRemovedTypes)
        {
            Section(sb, "Removed types", types.Where(t => t.Change == "removed").Select(t => t.Old!.FullName));
            Section(sb, "Added types", types.Where(t => t.Change == "added").Select(t => t.New!.FullName));
        }
        return pager.Page(sb.ToString(), offset, maxChars);
    }, cancellationToken);

    [McpServerTool(Name = "find_counterpart", Title = "Find symbol in another build")]
    [Description("Where did a type or member of the old build go in the new build? Matches by name, then by content (renamed/transformed members), " +
                 "taking a match only when it is unique on both sides. Shows the new name and token, the matching tier and its confidence (exact, strong, structural), " +
                 "whether a method body changed (normalized IL hash), and Il2Cpp offset/address changes; ambiguous matches list their candidates. " +
                 "Both builds are identified by file SHA-256 and MVID (tokens are only valid within their build). Use it to update FindClass names and offsets after an update.")]
    public Task<string> FindCounterpart(
        [Description("Symbol in the old build. " + SymbolDescription)] string symbol,
        [Description("The old build (id, name or path).")] string oldAssembly,
        [Description("The new build (id, name or path).")] string newAssembly,
        CancellationToken cancellationToken = default) => Read(workspace, () =>
    {
        var oldAsm = workspace.Get(oldAssembly);
        var newAsm = workspace.Get(newAssembly);
        var cmp = comparer.Compare(oldAsm, newAsm, cancellationToken);
        var sb = new StringBuilder($"Old: {oldAsm.Id} ({oldAsm.BuildIdentity})\nNew: {newAsm.Id} ({newAsm.BuildIdentity})\n");
        if (cmp.OldSkippedBodies + cmp.NewSkippedBodies > 0)
            sb.AppendLine($"Skipped: {cmp.OldSkippedBodies} old and {cmp.NewSkippedBodies} new method bodies are not valid IL and were not compared; " +
                          "matches by content involving them are less reliable.");
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
        }
        return sb.ToString();
    }, cancellationToken);

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
            "added" => $"{kind} {Name(m.New!)}  {m.Detail}",
            "removed" => $"{kind} {Name(m.Old!)}  {m.Detail}",
            "ambiguous" => $"{kind} {Name(m.Old!)}: {m.Detail}: {string.Join(" | ", m.Candidates!.Select(Name))}",
            _ => $"{kind} {Name(member)}: {m.Detail}",
        }) + more;
    }

    private static void Section(StringBuilder sb, string title, IEnumerable<string> names)
    {
        var list = names.ToList();
        if (list.Count == 0) return;
        sb.AppendLine($"\n{title} ({list.Count}):");
        foreach (var n in list.Take(300)) sb.AppendLine("  " + n);
        if (list.Count > 300) sb.AppendLine($"  … {list.Count - 300} more");
    }
}
