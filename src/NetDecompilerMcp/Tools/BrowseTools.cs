using System.ComponentModel;
using System.Text;
using dnlib.DotNet;
using ModelContextProtocol.Server;
using NetDecompilerMcp.Core;
using NetDecompilerMcp.Services;
using static NetDecompilerMcp.Tools.ToolSupport;

namespace NetDecompilerMcp.Tools;

[McpServerToolType]
public sealed class BrowseTools(AssemblyWorkspace workspace, ReferenceService references, OutputPager pager)
{
    private const string CompilerGenerated = "System.Runtime.CompilerServices.CompilerGeneratedAttribute";

    [McpServerTool(Name = "list_namespaces", Title = "List namespaces", ReadOnly = true, OpenWorld = false)]
    [Description("List namespaces with their type counts (nested types counted under their outer type's namespace, as list_types lists them; the counts add up to get_assembly_info's total).")]
    public Task<string> ListNamespaces(
        [Description(AssemblyFilterDescription)] string? assembly = null,
        [Description("Only namespaces containing this text (case-insensitive).")] string? filter = null,
        CancellationToken cancellationToken = default) => Read(workspace, () =>
    {
        var sb = new StringBuilder();
        foreach (var asm in workspace.Scope(assembly))
        {
            var groups = MetadataUtil.CountedTypes(asm.Module)
                .GroupBy(t => MetadataUtil.TopLevel(t).Namespace.String)
                .Where(g => filter == null || g.Key.Contains(filter, StringComparison.OrdinalIgnoreCase))
                .OrderBy(g => g.Key, StringComparer.Ordinal)
                .ToList();
            if (groups.Count == 0 && assembly == null && filter != null)
                continue; // searching across assemblies: only show the ones that match
            sb.AppendLine($"[{asm.Id}] {Plural(groups.Count, "namespace")}:");
            foreach (var g in groups)
                sb.AppendLine($"  {(g.Key.Length == 0 ? "<global>" : g.Key)}  ({g.Count()})");
        }
        return sb.Length == 0 ? $"No namespaces match '{filter}'." : pager.Page(sb.ToString());
    }, cancellationToken);

    [McpServerTool(Name = "list_types", Title = "List types", ReadOnly = true, OpenWorld = false)]
    [Description("List types, optionally restricted to a namespace, a name filter and a kind. Paged by offset/limit.")]
    public Task<string> ListTypes(
        [Description(AssemblyFilterDescription)] string? assembly = null,
        [Description("Exact namespace ('' or '<global>' for the global namespace). Omit for all.")] string? @namespace = null,
        [Description("Name filter: substring, wildcard (*, ?) or regex if regex=true.")] string? filter = null,
        [Description("Treat filter as a regular expression.")] bool regex = false,
        [Description("Only this kind: class, struct, interface, enum, delegate.")] string? kind = null,
        [Description("Include nested types.")] bool includeNested = true,
        [Description("Index of the first result to return.")] int offset = 0,
        [Description("Max results (default 300).")] int limit = 300,
        CancellationToken cancellationToken = default) => Read(workspace, () =>
    {
        var matcher = filter == null ? null : SearchService.CreateMatcher(filter, regex);
        var ns = @namespace == "<global>" ? "" : @namespace;
        bool showAssembly = workspace.Assemblies.Count > 1;
        var rows = new List<string>();
        foreach (var asm in workspace.Scope(assembly))
            foreach (var t in includeNested ? asm.Module.GetTypes() : asm.Module.Types)
            {
                if (t.FullName == "<Module>") continue;
                if (ns != null && MetadataUtil.TopLevel(t).Namespace != ns) continue;
                var k = Format.Kind(t);
                if (kind != null && !k.EndsWith(kind.Trim(), StringComparison.OrdinalIgnoreCase)) continue;
                if (matcher != null && !matcher(Format.StripArity(t.Name)) && !matcher(t.FullName)) continue;
                rows.Add($"{Format.Token(t)}  {k,-12} {t.FullName}{(showAssembly ? $"  [{asm.Id}]" : "")}");
            }
        return pager.PageRows(rows, offset, limit, "type");
    }, cancellationToken);

    [McpServerTool(Name = "get_type_info", Title = "Type outline", ReadOnly = true, OpenWorld = false)]
    [Description("Outline of a type without decompiling: declaration, attributes, nested types, fields (constants, enum values with hex, Il2Cpp offsets), properties, events and method signatures with tokens, IL sizes and Il2Cpp RVAs.")]
    public Task<string> GetTypeInfo(
        [Description("Type name or token. " + SymbolDescription)] string type,
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

        if (fields.Count != t.Fields.Count || methods.Count != t.Methods.Count || nested.Count != t.NestedTypes.Count)
            sb.AppendLine("\n(Compiler-generated members hidden; pass includeCompilerGenerated=true to show them.)");
        return pager.Page(sb.ToString());
    }, cancellationToken);

    private static void Section<T>(StringBuilder sb, string title, IReadOnlyList<T> items, Func<T, string> line)
    {
        if (items.Count == 0) return;
        sb.AppendLine($"\n{title} ({items.Count}):");
        foreach (var item in items) sb.AppendLine("  " + line(item));
    }

    [McpServerTool(Name = "get_type_hierarchy", Title = "Type hierarchy", ReadOnly = true, OpenWorld = false)]
    [Description("Base-type chain, all implemented interfaces (including inherited), and the types that directly derive from it (or implement it, for an interface) across all loaded assemblies.")]
    public Task<string> GetTypeHierarchy(
        [Description("Type name or token. " + SymbolDescription)] string type,
        [Description(AssemblyFilterDescription)] string? assembly = null,
        [Description("Max derived types to list (default 200).")] int limit = 200,
        CancellationToken cancellationToken = default) => Read(workspace, () =>
    {
        var sym = SymbolResolver.ResolveOne(workspace, assembly, type, SymbolKind.Type);
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

    [McpServerTool(Name = "get_attributes", Title = "Custom attributes", ReadOnly = true, OpenWorld = false)]
    [Description("Custom attributes with arguments on a type, method (including parameter and return attributes), field, property or event — or on the assembly/module when symbol is omitted. " +
                 "To find everything carrying an attribute, use find_references on the attribute type.")]
    public Task<string> GetAttributes(
        [Description("Symbol to inspect; omit for assembly-level attributes. " + SymbolDescription)] string? symbol = null,
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
                throw new ToolError("Pass symbol, or assembly for assembly-level attributes.");
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

    [McpServerTool(Name = "resolve_symbol", Title = "Resolve symbol", ReadOnly = true, OpenWorld = false)]
    [Description("Show what a symbol string or metadata token resolves to (every match, with kind, assembly, token and signature). Use it to disambiguate before other calls.")]
    public Task<string> ResolveSymbol(
        [Description(SymbolDescription)] string symbol,
        [Description(AssemblyFilterDescription)] string? assembly = null,
        [Description("Restrict to: any, type, method, field, property, event, member.")] string? kind = null,
        CancellationToken cancellationToken = default) => Read(workspace, () =>
    {
        var all = SymbolResolver.Resolve(workspace, assembly, symbol, SymbolResolver.ParseKind(kind));
        var sb = new StringBuilder($"{Plural(all.Count, "match")}:\n");
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
        }
        return sb.ToString();
    }, cancellationToken);
}
