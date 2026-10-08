using System.ComponentModel;
using System.Text;
using dnlib.DotNet;
using ModelContextProtocol.Server;
using NetDecompilerMcp.Core;
using NetDecompilerMcp.Services;
using static NetDecompilerMcp.Tools.ToolSupport;
using MemberChange = NetDecompilerMcp.Services.AssemblyComparer.MemberChange;
using TypeChange = NetDecompilerMcp.Services.AssemblyComparer.TypeChange;

namespace NetDecompilerMcp.Tools;

[McpServerToolType]
public sealed class CompareTools(AssemblyWorkspace workspace, AssemblyComparer comparer, OutputPager pager)
{
    private static readonly string[] AllKinds = ["renamed", "signature", "body", "type", "offset", "address", "added", "removed"];

    [McpServerTool(Name = "compare_assemblies", Title = "Compare two builds", ReadOnly = true, OpenWorld = false)]
    [Description("Compare two builds of an assembly (e.g. before and after an update; load both — the second gets an id like Name#2). " +
                 "Reports renamed/moved types and members (matched by content, so obfuscated or refactored names carry forward), added and removed members, " +
                 "signature changes, changed method bodies, field type changes, and Il2Cpp field-offset / address changes.")]
    public Task<string> CompareAssemblies(
        [Description("The old build (id, name or path).")] string oldAssembly,
        [Description("The new build (id, name or path).")] string newAssembly,
        [Description("Only types whose old or new full name starts with this.")] string? @namespace = null,
        [Description("Member change kinds to include, comma-separated: renamed, signature, body, type, offset, address, added, removed, or all. Default: all except address.")] string? changes = null,
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
            throw new ToolError($"Unknown change kind '{k}'. Use: {string.Join(", ", AllKinds)}.");

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

        var sb = new StringBuilder($"Comparing {oldAsm.Id} ({oldAsm.FilePath})\n       -> {newAsm.Id} ({newAsm.FilePath})\n");
        var memberCounts = types.SelectMany(t => t.Members).GroupBy(m => m.Change).ToDictionary(g => g.Key, g => g.Count());
        sb.AppendLine($"Types: {Count(types, "renamed")} renamed, {Count(types, "changed")} with member changes, {Count(types, "removed")} removed, {Count(types, "added")} added " +
                      $"({cmp.TypeMap.Count} matched of {MetadataUtil.CountedTypes(oldAsm.Module).Count} old).");
        sb.AppendLine("Members: " + string.Join(", ", AllKinds.Select(k => $"{memberCounts.GetValueOrDefault(k)} {k}")));
        if (hiddenTypes + hiddenMembers > 0)
            sb.AppendLine($"Hidden: {hiddenTypes} compiler-generated type change(s) and {hiddenMembers} member change(s) " +
                          "(closures, state machines, backing fields, array data; includeCompilerGenerated=true shows them).");
        foreach (var (side, asm) in new[] { ("old", oldAsm), ("new", newAsm) })
            if (asm.BodyHealth.Invalid > 0)
                sb.AppendLine($"Warning ({side} build {asm.Id}): {asm.BodyHealth.Describe()} Those body changes are marked \"not comparable\"; name matches and signature/field-offset changes are still reliable, renames found by content less so.");

        foreach (var t in types.Where(t => t.Change is "renamed" or "changed"))
        {
            var members = t.Members.Where(m => kinds.Contains(m.Change)).ToList();
            if (t.Change == "changed" && members.Count == 0) continue;
            sb.AppendLine();
            sb.AppendLine(t.Change == "renamed"
                ? $"{t.Old!.FullName} -> {t.New!.FullName}  (renamed, match {t.Score:P0})"
                : t.Old!.FullName);
            foreach (var m in members)
                sb.AppendLine($"    {m.Change,-9} {Describe(m)}");
        }
        if (listAddedRemovedTypes)
        {
            Section(sb, "Removed types", types.Where(t => t.Change == "removed").Select(t => t.Old!.FullName));
            Section(sb, "Added types", types.Where(t => t.Change == "added").Select(t => t.New!.FullName));
        }
        return pager.Page(sb.ToString(), offset, maxChars);
    }, cancellationToken);

    [McpServerTool(Name = "find_counterpart", Title = "Find symbol in another build", ReadOnly = true, OpenWorld = false)]
    [Description("Where did a type or member of the old build go in the new build? Matches by name, then by content (renamed/obfuscated members). " +
                 "Shows the new name and token, how it was matched, and Il2Cpp offset/address changes — use it to update FindClass names and offsets after an update.")]
    public Task<string> FindCounterpart(
        [Description("Symbol in the old build. " + SymbolDescription)] string symbol,
        [Description("The old build (id, name or path).")] string oldAssembly,
        [Description("The new build (id, name or path).")] string newAssembly,
        CancellationToken cancellationToken = default) => Read(workspace, () =>
    {
        var oldAsm = workspace.Get(oldAssembly);
        var newAsm = workspace.Get(newAssembly);
        var cmp = comparer.Compare(oldAsm, newAsm, cancellationToken);
        var sb = new StringBuilder();
        foreach (var sym in SymbolResolver.Resolve(workspace, oldAsm.Id, symbol).Take(25))
        {
            var (match, how) = comparer.FindCounterpart(cmp, sym.Member);
            sb.AppendLine($"{sym.Kind} {sym.Label}  [{oldAsm.Id}] {Format.Token(sym.Member)}");
            if (match == null)
            {
                sb.AppendLine($"  -> not found: {how}");
                continue;
            }
            sb.AppendLine($"  -> {Format.MemberLabel(match)}  [{newAsm.Id}] {Format.Token(match)}  ({how})");
            if (sym.Member is FieldDef of && match is FieldDef nf && Format.Type(of.FieldType) != Format.Type(nf.FieldType))
                sb.AppendLine($"     type: {Format.Type(of.FieldType)} -> {Format.Type(nf.FieldType)}");
            if (sym.Member is MethodDef om && match is MethodDef nm && Format.ParameterTypes(om.MethodSig) != Format.ParameterTypes(nm.MethodSig))
                sb.AppendLine($"     signature: ({Format.ParameterTypes(om.MethodSig)}) -> ({Format.ParameterTypes(nm.MethodSig)})");
            var oldIl2Cpp = Il2CppService.CompactSummary(sym.Member);
            var newIl2Cpp = Il2CppService.CompactSummary(match);
            if (oldIl2Cpp != null || newIl2Cpp != null)
                sb.AppendLine($"     il2cpp: {oldIl2Cpp ?? "-"} -> {newIl2Cpp ?? "-"}");
        }
        return sb.ToString();
    }, cancellationToken);

    private static int Count(List<TypeChange> types, string change) => types.Count(t => t.Change == change);

    /// <summary>True if the member or an enclosing type has '&lt;' in its name, which only compiler-generated names contain.</summary>
    private static bool IsGenerated(IMemberDef? member)
    {
        for (IMemberDef? m = member; m != null; m = m.DeclaringType)
            if (m.Name.String.Contains('<')) return true;
        return false;
    }

    private static string Describe(MemberChange m)
    {
        var member = m.Old ?? m.New!;
        string Name(IMemberDef d) => d switch
        {
            MethodDef md => $"{md.Name}({Format.ParameterTypes(md.MethodSig)})",
            _ => d.Name,
        };
        string kind = member switch { MethodDef => "method", FieldDef => "field", PropertyDef => "property", EventDef => "event", _ => "member" };
        return m.Change switch
        {
            "renamed" => $"{kind} {Name(m.Old!)} -> {Name(m.New!)}  ({m.Detail})",
            "added" => $"{kind} {Name(m.New!)}  {m.Detail}",
            "removed" => $"{kind} {Name(m.Old!)}  {m.Detail}",
            _ => $"{kind} {Name(member)}: {m.Detail}",
        };
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
