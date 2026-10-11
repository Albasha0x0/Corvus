using System.ComponentModel;
using System.Text;
using dnlib.DotNet;
using ModelContextProtocol.Server;
using NetDecompilerMcp.Core;
using NetDecompilerMcp.Mcp;
using NetDecompilerMcp.Services;
using static NetDecompilerMcp.Tools.ToolSupport;

namespace NetDecompilerMcp.Tools;

[McpServerToolType]
public sealed class BrowseTools(AssemblyWorkspace workspace, ReferenceService references, OutputPager pager)
{
    private const string CompilerGenerated = "System.Runtime.CompilerServices.CompilerGeneratedAttribute";

    [McpServerTool(Name = "list_namespaces", Title = "List namespaces", UseStructuredContent = true, OutputSchemaType = typeof(NamespaceList))]
    [Description("List namespaces with their type counts (nested types under their outer type's namespace).")]
    public Task<string> ListNamespaces(
        [Description(AssemblyFilterDescription)] string? assembly = null,
        [Description("Substring (case-insensitive).")] string? filter = null,
        [Description("Index of the first namespace.")] int offset = 0,
        [Description("Max namespaces.")] int limit = 2000,
        CancellationToken cancellationToken = default) => Read(workspace, () =>
    {
        limit = ClampLimit(limit);
        offset = Math.Max(0, offset);
        var all = new List<NamespaceEntry>();
        var perAssembly = new List<(LoadedAssembly Asm, int Count)>();
        foreach (var asm in workspace.Scope(assembly))
        {
            var groups = MetadataUtil.CountedTypes(asm.Module)
                .GroupBy(t => MetadataUtil.TopLevel(t).Namespace.String)
                .Where(g => filter == null || g.Key.Contains(filter, StringComparison.OrdinalIgnoreCase))
                .OrderBy(g => g.Key, StringComparer.Ordinal)
                .ToList();
            if (groups.Count == 0 && assembly == null && filter != null)
                continue; // when filtering across all assemblies, omit those with no match
            perAssembly.Add((asm, groups.Count));
            all.AddRange(groups.Select(g => new NamespaceEntry(asm.Id, g.Key, g.Count())));
        }
        var page = all.Skip(offset).Take(limit).ToList();
        var result = new NamespaceList(page, offset, all.Count, offset + page.Count < all.Count);
        if (perAssembly.Count == 0) return StructuredOutput.With($"No namespaces match '{filter}'.", result);
        var sb = new StringBuilder();
        foreach (var (asm, count) in perAssembly)
        {
            var shown = page.Where(e => e.Assembly == asm.Id).ToList();
            if (shown.Count == 0 && count > 0) continue; // outside this page
            sb.AppendLine($"[{asm.Id}] {Plural(count, "namespace")}:");
            foreach (var e in shown)
                sb.AppendLine($"  {(e.Namespace.Length == 0 ? "<global>" : e.Namespace)}  ({e.Types})");
        }
        if (result.Truncated) sb.AppendLine($"[More: call again with offset={offset + page.Count}]");
        return StructuredOutput.With(pager.Page(sb.ToString()), result);
    }, cancellationToken);

    [McpServerTool(Name = "list_types", Title = "List types", UseStructuredContent = true, OutputSchemaType = typeof(TypeList))]
    [Description("List types, optionally by namespace, name filter and kind.")]
    public Task<string> ListTypes(
        [Description(AssemblyFilterDescription)] string? assembly = null,
        [Description("Exact namespace ('' or '<global>' for the global one).")] string? @namespace = null,
        [Description("Name substring or wildcard (*, ?), or a regex with regex=true.")] string? filter = null,
        [Description("Treat filter as a regular expression.")] bool regex = false,
        [Description("Only this kind.")] string? kind = null,
        [Description("Include nested types.")] bool includeNested = true,
        [Description("Index of the first result.")] int offset = 0,
        [Description("Max results.")] int limit = 300,
        CancellationToken cancellationToken = default) => Read(workspace, () =>
    {
        var timeouts = new RegexTimeouts();
        var matcher = filter == null ? null : SearchService.CreateMatcher(filter, regex, timeouts);
        var ns = @namespace == "<global>" ? "" : @namespace;
        bool showAssembly = workspace.Assemblies.Count > 1;
        var rows = new List<string>();
        var items = new List<TypeEntry>();
        foreach (var asm in workspace.Scope(assembly))
            foreach (var t in includeNested ? asm.Module.GetTypes() : asm.Module.Types)
            {
                if (t.FullName == "<Module>") continue;
                if (ns != null && MetadataUtil.TopLevel(t).Namespace != ns) continue;
                var k = Format.Kind(t);
                if (kind != null && !k.EndsWith(kind.Trim(), StringComparison.OrdinalIgnoreCase)) continue;
                if (matcher != null && !matcher(Format.StripArity(t.Name)) && !matcher(t.FullName)) continue;
                rows.Add($"{Format.Token(t)}  {k,-12} {t.FullName}{(showAssembly ? $"  [{asm.Id}]" : "")}");
                items.Add(new TypeEntry(asm.Id, Format.Token(t), k, t.FullName));
            }
        return StructuredOutput.With(timeouts.Note("name") + pager.PageRows(rows, offset, limit, "type"),
            Paged(items, offset, limit, (page, o, total, more) => new TypeList(page, o, total, more) { NotEvaluated = timeouts.Count }));
    }, cancellationToken);

    [McpServerTool(Name = "get_type_info", Title = "Type outline", UseStructuredContent = true, OutputSchemaType = typeof(TypeOutline))]
    [Description("Outline of a type without decompiling: declaration, attributes, nested types, fields (constants, enum values with hex, Il2Cpp offsets), properties, events and method signatures with tokens, IL sizes and Il2Cpp RVAs.")]
    public Task<string> GetTypeInfo(
        [Description(SymbolDescription)] string type,
        [Description(AssemblyFilterDescription)] string? assembly = null,
        [Description("Include compiler-generated members (backing fields, lambdas, state machines).")] bool includeCompilerGenerated = false,
        CancellationToken cancellationToken = default) => Read(workspace, () =>
    {
        var sym = SymbolResolver.ResolveOne(workspace, assembly, type, SymbolKind.Type);
        var t = (TypeDef)sym.Member;
        var sb = new StringBuilder();
        sb.AppendLine(Format.TypeHeader(t));
        sb.AppendLine($"  full name: {t.FullName}   token: {Format.Token(t)}   assembly: {sym.Assembly.Id}");
        if (t.DeclaringType != null) sb.AppendLine($"  declared in: {t.DeclaringType.FullName}");
        foreach (var gp in t.GenericParameters.Where(g => g.GenericParamConstraints.Count > 0))
            sb.AppendLine($"  where {gp.Name} : {string.Join(", ", gp.GenericParamConstraints.Select(c => Format.TypeName(c.Constraint)))}");
        if (t.HasClassLayout) sb.AppendLine($"  layout: pack {t.PackingSize}, size {t.ClassSize}");
        foreach (var ca in t.CustomAttributes) sb.AppendLine("  " + Format.Attribute(ca));

        bool Show(IHasCustomAttribute m, string name) =>
            includeCompilerGenerated || (!name.StartsWith('<') && !m.CustomAttributes.IsDefined(CompilerGenerated));
        static string Il2Cpp(IHasCustomAttribute m) => Il2CppService.CompactSummary(m) is { } s ? $"  [{s}]" : "";

        var nested = t.NestedTypes.Where(n => Show(n, n.Name)).ToList();
        Section(sb, "Nested types", nested, n => $"{Format.Token(n)}  {Format.Kind(n)} {Format.TypeName(n)}");

        var fields = t.Fields.Where(f => Show(f, f.Name)).ToList();
        Section(sb, "Fields", fields, f => $"{Format.Token(f)}  " +
            (t.IsEnum && f.IsLiteral ? $"{f.Name} = {Format.LiteralWithHex(f.Constant?.Value)}" : Format.Field(f)) + Il2Cpp(f));

        Section(sb, "Properties", t.Properties.ToList(), p => $"{Format.Token(p)}  {Format.Property(p)}");
        Section(sb, "Events", t.Events.ToList(), e => $"{Format.Token(e)}  {Format.Event(e)}");

        var methods = t.Methods.Where(m => Show(m, m.Name)).ToList();
        Section(sb, "Methods", methods, m =>
        {
            var accessor = MetadataUtil.IsAccessor(m) ? "  (accessor)" : "";
            var size = MetadataUtil.SafeBody(m) is { } body ? $"  IL {body.Instructions.Count} instr" : m.HasBody ? "" : "  no body";
            return $"{Format.Token(m)}  {Format.Method(m)}{accessor}{size}{Il2Cpp(m)}";
        });

        bool hidden = fields.Count != t.Fields.Count || methods.Count != t.Methods.Count || nested.Count != t.NestedTypes.Count;
        if (hidden)
            sb.AppendLine("\n(Compiler-generated members hidden; pass includeCompilerGenerated=true to show them.)");

        const int MaxMembers = 2000;
        bool cut = false;
        List<MemberEntry> Entries<T>(IReadOnlyList<T> items, Func<T, MemberEntry> entry)
        {
            cut |= items.Count > MaxMembers;
            return items.Take(MaxMembers).Select(entry).ToList();
        }
        var outline = new TypeOutline(SymbolRef.Of(sym), t.FullName, Format.TypeHeader(t), t.DeclaringType?.FullName,
            t.CustomAttributes.Select(Format.Attribute).ToList(),
            Entries(nested, n => new MemberEntry(Format.Token(n), n.Name, $"{Format.Kind(n)} {Format.TypeName(n)}", null, null)),
            Entries(fields, f => new MemberEntry(Format.Token(f), f.Name,
                t.IsEnum && f.IsLiteral ? $"{f.Name} = {Format.LiteralWithHex(f.Constant?.Value)}" : Format.Field(f), Il2CppService.CompactSummary(f), null)),
            Entries(t.Properties.ToList(), p => new MemberEntry(Format.Token(p), p.Name, Format.Property(p), null, null)),
            Entries(t.Events.ToList(), e => new MemberEntry(Format.Token(e), e.Name, Format.Event(e), null, null)),
            Entries(methods, m => new MemberEntry(Format.Token(m), m.Name, Format.Method(m), Il2CppService.CompactSummary(m),
                MetadataUtil.SafeBody(m)?.Instructions.Count)),
            hidden, cut);
        return StructuredOutput.With(pager.Page(sb.ToString()), outline);
    }, cancellationToken);

    private static void Section<T>(StringBuilder sb, string title, IReadOnlyList<T> items, Func<T, string> line)
    {
        if (items.Count == 0) return;
        sb.AppendLine($"\n{title} ({items.Count}):");
        foreach (var item in items) sb.AppendLine("  " + line(item));
    }

    [McpServerTool(Name = "get_type_hierarchy", Title = "Type hierarchy")]
    [Description("A type's base chain, all implemented interfaces, and the types deriving from (or implementing) it directly across loaded assemblies.")]
    public Task<string> GetTypeHierarchy(
        [Description(SymbolDescription)] string type,
        [Description(AssemblyFilterDescription)] string? assembly = null,
        [Description("Max derived types listed.")] int limit = 200,
        CancellationToken cancellationToken = default) => Read(workspace, () =>
    {
        var sym = SymbolResolver.ResolveOne(workspace, assembly, type, SymbolKind.Type, referenced: true);
        var t = (TypeDef)sym.Member;
        var h = references.GetHierarchy(t, ClampLimit(limit), cancellationToken);
        var sb = new StringBuilder($"{Format.TypeHeader(t)}   [{sym.Assembly.Id}]\n");
        sb.AppendLine("\nBase types (nearest first):");
        if (h.BaseChain.Count == 0) sb.AppendLine("  (none)");
        foreach (var b in h.BaseChain) sb.AppendLine("  " + b);
        sb.AppendLine($"\nInterfaces ({h.Interfaces.Count}):");
        foreach (var i in h.Interfaces) sb.AppendLine("  " + i);
        sb.AppendLine($"\n{(t.IsInterface ? "Implemented by" : "Directly derived types")} ({h.DerivedTotal}):");
        foreach (var d in h.Derived) sb.AppendLine($"  {d.Label}  [{d.Assembly.Id}] {Format.Token(d.Member)}");
        if (h.DerivedTotal > h.Derived.Count) sb.AppendLine($"  … {h.DerivedTotal - h.Derived.Count} more (raise limit)");
        return sb.ToString();
    }, cancellationToken);

    [McpServerTool(Name = "get_attributes", Title = "Custom attributes")]
    [Description("Custom attributes with arguments on a type, member (with parameter and return attributes), or the assembly / module when symbol is omitted. " +
                 "Everything carrying an attribute: find_references on the attribute type.")]
    public Task<string> GetAttributes(
        [Description(SymbolDescription + " Omit for assembly-level attributes.")] string? symbol = null,
        [Description(AssemblyFilterDescription + " Required when symbol is omitted.")] string? assembly = null,
        [Description("Only attributes whose type name contains this text.")] string? filter = null,
        CancellationToken cancellationToken = default) => Read(workspace, () =>
    {
        var sb = new StringBuilder();
        void Section(string title, IHasCustomAttribute owner)
        {
            var attrs = owner.CustomAttributes
                .Where(ca => filter == null || (ca.AttributeType?.FullName ?? "").Contains(filter, StringComparison.OrdinalIgnoreCase)).ToList();
            if (attrs.Count == 0) return;
            sb.AppendLine(title);
            foreach (var ca in attrs) sb.AppendLine("  " + Format.Attribute(ca));
        }

        if (string.IsNullOrWhiteSpace(symbol))
        {
            if (string.IsNullOrWhiteSpace(assembly))
                throw new ToolError(ErrorCode.InvalidArgument, "Pass symbol, or assembly for assembly-level attributes.");
            var asm = workspace.Get(assembly);
            if (asm.Module.Assembly != null) Section($"Assembly {asm.FullAssemblyName}:", asm.Module.Assembly);
            Section($"Module {asm.Module.Name}:", asm.Module);
        }
        else
        {
            foreach (var sym in SymbolResolver.Resolve(workspace, assembly, symbol).Take(25))
            {
                Section($"{sym.Kind} {sym.Label}  [{sym.Assembly.Id}]:", sym.Member);
                if (sym.Member is MethodDef m)
                    foreach (var p in m.ParamDefs)
                        Section(p.Sequence == 0 ? "  return value:" : $"  parameter {p.Name}:", p);
            }
        }
        return sb.Length == 0 ? "No custom attributes" + (filter != null ? $" matching '{filter}'." : ".") : pager.Page(sb.ToString());
    }, cancellationToken);

    [McpServerTool(Name = "resolve_symbol", Title = "Resolve symbol", UseStructuredContent = true, OutputSchemaType = typeof(SymbolList))]
    [Description("What a symbol string or token resolves to: every match with kind, assembly, token and signature, to disambiguate before other calls.")]
    public Task<string> ResolveSymbol(
        [Description(SymbolDescription)] string symbol,
        [Description(AssemblyFilterDescription)] string? assembly = null,
        [Description("Restrict to this kind.")] string? kind = null,
        CancellationToken cancellationToken = default) => Read(workspace, () =>
    {
        var all = SymbolResolver.Resolve(workspace, assembly, symbol, SymbolResolver.ParseKind(kind));
        var sb = new StringBuilder($"{Plural(all.Count, "match")}:\n");
        var items = new List<SymbolMatch>();
        foreach (var r in all)
        {
            var signature = r.Member switch
            {
                MethodDef m => Format.Method(m),
                FieldDef f => Format.Field(f),
                PropertyDef p => Format.Property(p),
                EventDef e => Format.Event(e),
                TypeDef t => Format.TypeHeader(t),
                _ => "",
            };
            sb.AppendLine($"  {r}\n      {signature}");
            if (items.Count < 1000) items.Add(Match(r, signature));
        }
        return StructuredOutput.With(sb.ToString(), Firsts(items, all.Count, (page, o, total, more) => new SymbolList(page, o, total, more)));
    }, cancellationToken);

    internal static SymbolMatch Match(ResolvedSymbol r, string? signature = null) =>
        new(SymbolRef.MemberKind(r.Member), r.Label, r.Assembly.Id, Format.Token(r.Member), signature);
}
