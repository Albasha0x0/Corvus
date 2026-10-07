using System.ComponentModel;
using System.Text;
using dnlib.DotNet;
using ModelContextProtocol.Server;
using NetDecompilerMcp.Core;
using NetDecompilerMcp.Services;
using static NetDecompilerMcp.Tools.ToolSupport;

namespace NetDecompilerMcp.Tools;

[McpServerToolType]
public sealed class BrowseTools(AssemblyWorkspace workspace, AnalysisService analysis, OutputPager pager)
{
    [McpServerTool(Name = "list_namespaces", ReadOnly = true)]
    [Description("List namespaces with their type counts.")]
    public Task<string> ListNamespaces(
        [Description(AssemblyDescription)] string? assembly = null,
        [Description("Only namespaces containing this text (case-insensitive).")] string? filter = null,
        CancellationToken cancellationToken = default) => Read(workspace, () =>
    {
        var sb = new StringBuilder();
        foreach (var asm in workspace.Scope(assembly))
        {
            var groups = asm.Module.Types
                .GroupBy(t => t.Namespace.String)
                .Where(g => filter == null || g.Key.Contains(filter, StringComparison.OrdinalIgnoreCase))
                .OrderBy(g => g.Key, StringComparer.Ordinal)
                .ToList();
            sb.AppendLine($"[{asm.Id}] {Plural(groups.Count, "namespace")}:");
            foreach (var g in groups)
                sb.AppendLine($"  {(g.Key.Length == 0 ? "<global>" : g.Key)}  ({g.Count()})");
        }
        return pager.Page(sb.ToString());
    }, cancellationToken);

    [McpServerTool(Name = "list_types", ReadOnly = true)]
    [Description("List types, optionally restricted to a namespace, a name filter and a kind. Paged by offset/limit.")]
    public Task<string> ListTypes(
        [Description(AssemblyDescription)] string? assembly = null,
        [Description("Exact namespace ('' or '<global>' for the global namespace). Omit for all.")] string? @namespace = null,
        [Description("Name filter: substring, wildcard (*, ?) or regex if regex=true.")] string? filter = null,
        [Description("Treat filter as a regular expression.")] bool regex = false,
        [Description("Only this kind: class, struct, interface, enum, delegate.")] string? kind = null,
        [Description("Include nested types.")] bool includeNested = true,
        [Description("Index of the first result to return.")] int offset = 0,
        [Description("Max results (default 300).")] int limit = 300,
        CancellationToken cancellationToken = default) => Read(workspace, () =>
    {
        var matcher = filter == null ? null : AnalysisService.CreateMatcher(filter, regex);
        var ns = @namespace == "<global>" ? "" : @namespace;
        var rows = new List<string>();
        foreach (var asm in workspace.Scope(assembly))
            foreach (var t in includeNested ? asm.Module.GetTypes() : asm.Module.Types)
            {
                var top = t;
                while (top.DeclaringType != null) top = top.DeclaringType;
                if (ns != null && top.Namespace != ns) continue;
                if (t.FullName == "<Module>") continue;
                var k = Format.Kind(t);
                if (kind != null && !k.EndsWith(kind.Trim(), StringComparison.OrdinalIgnoreCase)) continue;
                if (matcher != null && !matcher(Format.StripArity(t.Name)) && !matcher(t.FullName)) continue;
                rows.Add($"{Format.Token(t)}  {k,-12} {t.FullName}{(workspace.Assemblies.Count > 1 ? $"  [{asm.Id}]" : "")}");
            }
        return Paged(rows, offset, limit, "type");
    }, cancellationToken);

    [McpServerTool(Name = "get_type_info", ReadOnly = true)]
    [Description("Structured outline of a type: declaration, attributes, nested types, fields (with constants / Il2Cpp offsets), properties, events and method signatures with tokens (and Il2Cpp RVAs when present). Cheaper than decompiling.")]
    public Task<string> GetTypeInfo(
        [Description("Type name or token. " + SymbolDescription)] string type,
        [Description(AssemblyDescription)] string? assembly = null,
        [Description("Include compiler-generated members (backing fields, lambdas, state machines).")] bool includeCompilerGenerated = false,
        CancellationToken cancellationToken = default) => Read(workspace, () =>
    {
        var sym = SymbolResolver.ResolveType(workspace, assembly, type);
        var t = (TypeDef)sym.Member;
        var sb = new StringBuilder();
        sb.AppendLine($"{Format.TypeHeader(t)}");
        sb.AppendLine($"  full name: {t.FullName}   token: {Format.Token(t)}   assembly: {sym.Assembly.Id}");
        if (t.DeclaringType != null) sb.AppendLine($"  declared in: {t.DeclaringType.FullName}");
        if (t.HasGenericParameters)
            foreach (var gp in t.GenericParameters.Where(g => g.GenericParamConstraints.Count > 0))
                sb.AppendLine($"  where {gp.Name} : {string.Join(", ", gp.GenericParamConstraints.Select(c => Format.TypeName(c.Constraint)))}");
        if (t.HasClassLayout) sb.AppendLine($"  layout: pack {t.PackingSize}, size {t.ClassSize}");
        AppendAttributes(sb, t, "  ");

        bool Show(IHasCustomAttribute m, string name) =>
            includeCompilerGenerated || (!name.StartsWith('<') && !m.CustomAttributes.IsDefined("System.Runtime.CompilerServices.CompilerGeneratedAttribute"));

        var nested = t.NestedTypes.Where(n => Show(n, n.Name)).ToList();
        if (nested.Count > 0)
        {
            sb.AppendLine($"\nNested types ({nested.Count}):");
            foreach (var n in nested) sb.AppendLine($"  {Format.Token(n)}  {Format.Kind(n)} {Format.TypeName(n)}");
        }

        var fields = t.Fields.Where(f => Show(f, f.Name)).ToList();
        if (fields.Count > 0)
        {
            sb.AppendLine($"\nFields ({fields.Count}):");
            foreach (var f in fields)
                sb.AppendLine($"  {Format.Token(f)}  {(t.IsEnum && f.IsLiteral ? $"{f.Name} = {Format.Literal(f.Constant?.Value)}{EnumHex(f.Constant?.Value)}" : Format.Field(f))}{Il2CppSuffix(f)}");
        }

        if (t.Properties.Count > 0)
        {
            sb.AppendLine($"\nProperties ({t.Properties.Count}):");
            foreach (var p in t.Properties) sb.AppendLine($"  {Format.Token(p)}  {Format.Property(p)}");
        }

        if (t.Events.Count > 0)
        {
            sb.AppendLine($"\nEvents ({t.Events.Count}):");
            foreach (var e in t.Events) sb.AppendLine($"  {Format.Token(e)}  {Format.Event(e)}");
        }

        var methods = t.Methods.Where(m => Show(m, m.Name)).ToList();
        if (methods.Count > 0)
        {
            sb.AppendLine($"\nMethods ({methods.Count}):");
            foreach (var m in methods)
            {
                var accessorOf = m.IsGetter || m.IsSetter || m.IsAddOn || m.IsRemoveOn ? "  (accessor)" : "";
                var size = AnalysisService.SafeBody(m) is { } body ? $"  IL {body.Instructions.Count} instr" : (m.HasBody ? "" : "  no body");
                sb.AppendLine($"  {Format.Token(m)}  {Format.Method(m)}{accessorOf}{size}{Il2CppSuffix(m)}");
            }
        }
        if (fields.Count != t.Fields.Count || methods.Count != t.Methods.Count || nested.Count != t.NestedTypes.Count)
            sb.AppendLine("\n(Compiler-generated members hidden; pass includeCompilerGenerated=true to show them.)");
        return pager.Page(sb.ToString());
    }, cancellationToken);

    [McpServerTool(Name = "get_type_hierarchy", ReadOnly = true)]
    [Description("Base-type chain, all implemented interfaces, and the types that directly derive from it (or implement it, for an interface) across all loaded assemblies.")]
    public Task<string> GetTypeHierarchy(
        [Description("Type name or token. " + SymbolDescription)] string type,
        [Description(AssemblyDescription)] string? assembly = null,
        [Description("Max derived types to list (default 200).")] int limit = 200,
        CancellationToken cancellationToken = default) => Read(workspace, () =>
    {
        var sym = SymbolResolver.ResolveType(workspace, assembly, type);
        var t = (TypeDef)sym.Member;
        var h = analysis.GetHierarchy(t, ClampLimit(limit), cancellationToken);
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

    [McpServerTool(Name = "resolve_symbol", ReadOnly = true)]
    [Description("Show what a symbol string or metadata token resolves to (every match, with kind, assembly and token). Useful to disambiguate before other calls.")]
    public Task<string> ResolveSymbol(
        [Description(SymbolDescription)] string symbol,
        [Description(AssemblyDescription)] string? assembly = null,
        [Description("Restrict to: any, type, method, field, property, event, member.")] string? kind = null,
        CancellationToken cancellationToken = default) => Read(workspace, () =>
    {
        var all = SymbolResolver.Resolve(workspace, assembly, symbol, SymbolResolver.ParseKind(kind));
        var sb = new StringBuilder($"{Plural(all.Count, "match")}:\n");
        foreach (var r in all)
        {
            var detail = r.Member switch
            {
                MethodDef m => Format.Method(m),
                FieldDef f => Format.Field(f),
                PropertyDef p => Format.Property(p),
                EventDef e => Format.Event(e),
                TypeDef t => Format.TypeHeader(t),
                _ => "",
            };
            sb.AppendLine($"  {r}\n      {detail}");
        }
        return sb.ToString();
    }, cancellationToken);

    [McpServerTool(Name = "get_attributes", ReadOnly = true)]
    [Description("Custom attributes with their arguments on a type, method (including parameter and return attributes), field, property or event — or on the assembly/module when symbol is omitted. " +
                 "To find everything that carries a given attribute, use find_references on the attribute type.")]
    public Task<string> GetAttributes(
        [Description("Symbol to inspect; omit for assembly-level attributes. " + SymbolDescription)] string? symbol = null,
        [Description(AssemblyDescription + " Required when symbol is omitted.")] string? assembly = null,
        [Description("Only attributes whose name contains this text.")] string? filter = null,
        CancellationToken cancellationToken = default) => Read(workspace, () =>
    {
        var sb = new StringBuilder();
        void Section(string title, IHasCustomAttribute owner)
        {
            var tmp = new StringBuilder();
            AppendAttributes(tmp, owner, "  ", filter);
            if (tmp.Length > 0) sb.AppendLine(title).Append(tmp);
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
                {
                    foreach (var p in m.ParamDefs)
                        Section(p.Sequence == 0 ? "  return:" : $"  parameter {p.Name}:", p);
                }
            }
        }
        return sb.Length == 0 ? "No custom attributes" + (filter != null ? $" matching '{filter}'." : ".") : pager.Page(sb.ToString());
    }, cancellationToken);

    internal static void AppendAttributes(StringBuilder sb, IHasCustomAttribute member, string indent, string? filter) =>
        AppendAttributes(sb, member.CustomAttributes.Where(ca => filter == null || (ca.AttributeType?.FullName ?? "").Contains(filter, StringComparison.OrdinalIgnoreCase)), indent);

    internal static void AppendAttributes(StringBuilder sb, IHasCustomAttribute member, string indent) =>
        AppendAttributes(sb, member.CustomAttributes, indent);

    private static void AppendAttributes(StringBuilder sb, IEnumerable<CustomAttribute> attributes, string indent)
    {
        foreach (var ca in attributes)
        {
            var name = Format.StripArity(ca.AttributeType?.Name ?? "?");
            if (name.EndsWith("Attribute", StringComparison.Ordinal)) name = name[..^"Attribute".Length];
            var args = ca.ConstructorArguments.Select(a => Format.Literal(a.Value))
                .Concat(ca.NamedArguments.Select(n => $"{n.Name} = {Format.Literal(n.Argument.Value)}"));
            sb.AppendLine($"{indent}[{name}{(ca.HasConstructorArguments || ca.HasNamedArguments ? "(" + string.Join(", ", args) + ")" : "")}]");
        }
    }

    private static string EnumHex(object? value) => value switch
    {
        int i => $" (0x{i:X})",
        uint u => $" (0x{u:X})",
        long l => $" (0x{l:X})",
        ulong ul => $" (0x{ul:X})",
        short s => $" (0x{s:X})",
        ushort us => $" (0x{us:X})",
        byte b => $" (0x{b:X})",
        sbyte sb => $" (0x{sb:X})",
        _ => "",
    };

    private static string Il2CppSuffix(IHasCustomAttribute member)
    {
        var attrs = Il2CppService.GetAttributes(member).Where(a => a.Name is "AddressAttribute" or "FieldOffsetAttribute").ToList();
        if (attrs.Count == 0) return "";
        var parts = attrs.SelectMany(a => a.Values.Where(kv => kv.Key is "RVA" or "Offset" or "VA" or "Slot" && kv.Value != "-1").Select(kv => $"{kv.Key}={kv.Value}"));
        return "  [" + string.Join(" ", parts) + "]";
    }

    internal string Paged(List<string> rows, int offset, int limit, string noun)
    {
        limit = ClampLimit(limit);
        offset = Math.Max(0, offset);
        var page = rows.Skip(offset).Take(limit).ToList();
        var sb = new StringBuilder($"{Plural(rows.Count, noun)} (showing {(page.Count == 0 ? 0 : offset + 1)}-{offset + page.Count}):\n");
        foreach (var r in page) sb.AppendLine("  " + r);
        if (offset + page.Count < rows.Count)
            sb.AppendLine($"[More: call again with offset={offset + page.Count}]");
        return pager.Page(sb.ToString());
    }
}
