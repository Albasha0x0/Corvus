using System.ComponentModel;
using System.Text;
using dnlib.DotNet;
using ModelContextProtocol.Server;
using Corvus.Core;
using Corvus.Mcp;
using Corvus.Services;
using static Corvus.Tools.ToolSupport;

namespace Corvus.Tools;

[McpServerToolType]
public sealed class BrowseTools(AssemblyWorkspace workspace, ReferenceService references, OutputPager pager, DecompilerService? decompiler = null)
{
    private const string CompilerGenerated = "System.Runtime.CompilerServices.CompilerGeneratedAttribute";

    [McpServerTool(Name = "list_namespaces", Title = "List namespaces", UseStructuredContent = true, OutputSchemaType = typeof(NamespaceList))]
    [Description("List namespaces with their type counts (nested types under the namespace of their outer type).")]
    public Task<string> ListNamespaces(
        [Description(AssemblyFilterDescription)] string? assembly = null,
        [Description("Substring (case-insensitive).")] string? filter = null,
        [Description(RowOffsetDescription)] int offset = 0,
        [Description(LimitDescription)] int limit = 200,
        [Description(MaxTokensDescription)] int? maxTokens = null,
        CancellationToken cancellationToken = default) => Read(workspace, () =>
    {
        var scope = workspace.Scope(assembly);
        bool several = scope.Count > 1;
        var all = new List<NamespaceEntry>();
        foreach (var asm in scope)
            all.AddRange(MetadataUtil.CountedTypes(asm.Module)
                .GroupBy(t => MetadataUtil.TopLevel(t).Namespace.String)
                .Where(g => filter == null || g.Key.Contains(filter, StringComparison.OrdinalIgnoreCase))
                .OrderBy(g => g.Key, StringComparer.Ordinal)
                .Select(g => new NamespaceEntry(g.Key, g.Count()) { Assembly = several ? asm.Id : null }));
        return ToolOutput.List(all, offset, limit,
            e => $"{(e.Namespace.Length == 0 ? "<global>" : e.Namespace)}  ({e.Types}){(e.Assembly != null ? $"  [{e.Assembly}]" : "")}",
            rows => new NamespaceList(rows, offset, all.Count), "namespace", all.Count == 0 && filter != null ? $"No namespaces match '{filter}'.\n" : null);
    }, cancellationToken);

    [McpServerTool(Name = "list_types", Title = "List types", UseStructuredContent = true, OutputSchemaType = typeof(TypeList))]
    [Description("List types, optionally by namespace, name filter and kind.")]
    public Task<string> ListTypes(
        [Description(AssemblyFilterDescription)] string? assembly = null,
        [Description("Exact namespace (\"\" or <global> for the global one).")] string? @namespace = null,
        [Description("Name substring or wildcard (*, ?), or regex with regex=true.")] string? filter = null,
        [Description("filter is a regex.")] bool regex = false,
        [Description("Only this kind.")] string? kind = null,
        [Description("Leave out nested types.")] bool topLevelOnly = false,
        [Description(RowOffsetDescription)] int offset = 0,
        [Description(LimitDescription)] int limit = 150,
        [Description(MaxTokensDescription)] int? maxTokens = null,
        CancellationToken cancellationToken = default) => Read(workspace, () =>
    {
        var timeouts = new RegexTimeouts();
        var matcher = filter == null ? null : SearchService.CreateMatcher(filter, regex, timeouts);
        var ns = @namespace == "<global>" ? "" : @namespace;
        var scope = workspace.Scope(assembly);
        bool several = scope.Count > 1;
        var items = new List<TypeEntry>();
        foreach (var asm in scope)
            foreach (var t in topLevelOnly ? asm.Module.Types : asm.Module.GetTypes())
            {
                if (t.FullName == "<Module>") continue;
                if (ns != null && MetadataUtil.TopLevel(t).Namespace != ns) continue;
                var k = Format.Kind(t);
                if (kind != null && !k.EndsWith(kind.Trim(), StringComparison.OrdinalIgnoreCase)) continue;
                if (matcher != null && !matcher(Format.StripArity(t.Name)) && !matcher(t.FullName)) continue;
                items.Add(new TypeEntry(Format.Token(t), t.FullName) { Kind = k == "class" ? null : k, Assembly = several ? asm.Id : null });
            }
        return ToolOutput.List(items.Skip(offset).Take(limit).ToList(), offset, limit, items.Count,
            e => $"{e.Token}  {e.Kind ?? "class",-12} {e.Name}{(e.Assembly != null ? $"  [{e.Assembly}]" : "")}",
            rows => new TypeList(rows, offset, items.Count) { NotEvaluated = timeouts.Count, TotalExact = timeouts.Count > 0 ? false : null },
            "type", Header(timeouts.Note("name")), totalExact: timeouts.Count == 0);
    }, cancellationToken);

    /// <summary>Header lines, null when empty; "Incomplete:" and "Skipped:" lines become the record's warnings too.</summary>
    internal static string? Header(params string?[] parts) => string.Concat(parts) is { Length: > 0 } text ? text : null;

    private static readonly string[] Sections = ["summary", "nested", "fields", "properties", "events", "methods", "all"];

    [McpServerTool(Name = "get_type_info", Title = "Type outline", UseStructuredContent = true, OutputSchemaType = typeof(TypeOutline))]
    [Description("Outline of a type without decompiling: declaration, attributes, member counts, the first members of each kind; section= pages one " +
                 "kind (constants, enum values, signatures, tokens, IL sizes, Il2Cpp RVAs). A field: its value or FieldRVA data (file offset, " +
                 "SHA-256, readers, typed elements, hex rows).")]
    public Task<string> GetTypeInfo(
        [Description(SymbolDescription)] string type,
        [Description(AssemblyFilterDescription)] string? assembly = null,
        [Description("A kind to page, or all.")] string section = "summary",
        [Description("Include compiler-generated members.")] bool includeCompilerGenerated = false,
        [Description(RowOffsetDescription)] int offset = 0,
        [Description(LimitDescription)] int limit = 100,
        [Description(MaxTokensDescription)] int? maxTokens = null,
        CancellationToken cancellationToken = default) => Read(workspace, () =>
    {
        section = (section ?? "summary").Trim().ToLowerInvariant();
        if (!Sections.Contains(section))
            throw new ToolError(ErrorCode.InvalidArgument, $"Unknown section '{section}'.", "pass section as one of " + string.Join(", ", Sections));
        ResolvedSymbol sym;
        try { sym = SymbolResolver.ResolveOne(workspace, assembly, type, SymbolKind.Type); }
        catch (ToolError e) when (e.Code == ErrorCode.NotFound
                                  && MetadataUtil.Try(() => SymbolResolver.Resolve(workspace, assembly, type, SymbolKind.Field)) is { Count: 1 } field)
        {
            return FieldOutline(field[0], offset, limit, cancellationToken);
        }
        var t = (TypeDef)sym.Member;
        bool Show(IHasCustomAttribute m, string name) =>
            includeCompilerGenerated || (!name.StartsWith('<') && !m.CustomAttributes.IsDefined(CompilerGenerated));
        static string? Il2Cpp(IHasCustomAttribute m) => Il2CppService.CompactSummary(m);

        var nested = t.NestedTypes.Where(n => Show(n, n.Name)).Select(n => new MemberEntry(Format.Token(n), $"{Format.Kind(n)} {Format.TypeName(n)}") { Kind = "nested" }).ToList();
        var fields = t.Fields.Where(f => Show(f, f.Name)).Select(f => new MemberEntry(Format.Token(f),
            t.IsEnum && f.IsLiteral ? $"{f.Name} = {Format.LiteralWithHex(f.Constant?.Value)}" : Format.Field(f)) { Kind = "field", Il2Cpp = Il2Cpp(f) }).ToList();
        var properties = t.Properties.Select(p => new MemberEntry(Format.Token(p), Format.Property(p)) { Kind = "property" }).ToList();
        var events = t.Events.Select(e => new MemberEntry(Format.Token(e), Format.Event(e)) { Kind = "event" }).ToList();
        var methods = t.Methods.Where(m => Show(m, m.Name)).Select(m => new MemberEntry(Format.Token(m),
            Format.Method(m) + (MetadataUtil.IsAccessor(m) ? "  (accessor)" : "") + (m.HasBody || MetadataUtil.SafeBody(m) != null ? "" : "  no body"))
            { Kind = "method", Il2Cpp = Il2Cpp(m), Il = MetadataUtil.SafeBody(m)?.Instructions.Count }).ToList();
        var kinds = new (string Name, List<MemberEntry> Rows)[] { ("nested", nested), ("fields", fields), ("properties", properties), ("events", events), ("methods", methods) };
        bool hidden = fields.Count != t.Fields.Count || methods.Count != t.Methods.Count || nested.Count != t.NestedTypes.Count;

        var header = new StringBuilder(Format.TypeHeader(t)).Append('\n');
        header.Append($"  full name: {t.FullName}   token: {Format.Token(t)}   assembly: {sym.Assembly.Id}\n");
        if (t.DeclaringType != null) header.Append($"  declared in: {t.DeclaringType.FullName}\n");
        foreach (var gp in t.GenericParameters.Where(g => g.GenericParamConstraints.Count > 0))
            header.Append($"  where {gp.Name} : {string.Join(", ", gp.GenericParamConstraints.Select(c => Format.TypeName(c.Constraint)))}\n");
        if (t.HasClassLayout) header.Append($"  layout: pack {t.PackingSize}, size {t.ClassSize}\n");
        var attributes = t.CustomAttributes.Select(Format.Attribute).ToList();
        foreach (var a in attributes) header.Append("  ").Append(a).Append('\n');
        header.Append("  members: ").Append(string.Join(", ", kinds.Select(k => $"{k.Rows.Count} {k.Name}"))).Append('\n');
        if (hidden) header.Append("  (compiler-generated members hidden; includeCompilerGenerated=true shows them)\n");

        const int PerKind = 8;
        List<MemberEntry> rows;
        if (section == "summary")
        {
            rows = kinds.SelectMany(k => k.Rows.Take(PerKind)).ToList();
            var more = kinds.Where(k => k.Rows.Count > PerKind).Select(k => $"section={k.Name} for all {k.Rows.Count}").ToList();
            if (more.Count > 0) header.Append("  first ").Append(PerKind).Append(" of each kind below; ").Append(string.Join(", ", more)).Append('\n');
            offset = 0;
            limit = Math.Max(1, rows.Count);
        }
        // One kind: the rows need not say it.
        else rows = section == "all" ? kinds.SelectMany(k => k.Rows).ToList() : kinds.First(k => k.Name == section).Rows.Select(r => r with { Kind = null }).ToList();
        var counts = kinds.ToDictionary(k => k.Name, k => k.Rows.Count);
        return ToolOutput.List(rows.Skip(offset).Take(limit).ToList(), offset, limit, rows.Count, MemberText,
            page => new TypeOutline(SymbolRef.Of(sym), Format.TypeHeader(t), counts, section, page, offset, rows.Count)
            {
                DeclaringType = t.DeclaringType?.FullName,
                Attributes = attributes.Count > 0 ? attributes : null,
                CompilerGeneratedHidden = hidden,
            }, section == "summary" ? "member" : section is "all" ? "member" : section.TrimEnd('s'), header.ToString());
    }, cancellationToken);

    private const int MaxElements = 64;

    /// <summary>A field's outline: declaration, attributes and, for a FieldRVA field, its data paged as 16-byte rows.</summary>
    private static string FieldOutline(ResolvedSymbol sym, int offset, int limit, CancellationToken ct)
    {
        var f = (FieldDef)sym.Member;
        var header = new StringBuilder(Format.Field(f)).Append('\n');
        header.Append($"  full name: {Format.MemberLabel(f)}   token: {Format.Token(f)}   assembly: {sym.Assembly.Id}\n");
        header.Append($"  declared in: {f.DeclaringType.FullName}\n");
        var attributes = f.CustomAttributes.Select(Format.Attribute).ToList();
        foreach (var a in attributes) header.Append("  ").Append(a).Append('\n');
        if (f.HasConstant) header.Append("  value: ").Append(Format.LiteralWithHex(f.Constant.Value)).Append('\n');
        if (f.FieldOffset is { } fieldOffset) header.Append($"  field offset: {fieldOffset}\n");
        var data = FieldInitialData.Of(sym.Assembly, f, ct);
        FieldDataInfo? info = null;
        var rows = new List<MemberEntry>();
        if (data == null) header.Append("  no initial data (not a FieldRVA field)\n");
        else
        {
            var bytes = data.Bytes;
            header.Append($"  initial data: {Plural(bytes.Length, "byte")} at RVA 0x{data.Rva:X}")
                  .Append(data.FileOffset is { } at ? $", file offset 0x{at:X}{(data.Verified ? " (bytes match)" : " (bytes differ from the declared data)")}" : ", in no section")
                  .Append($", SHA-256 {data.Sha256}\n");
            var element = data.Uses.Select(u => u.Element).FirstOrDefault(e => e != null);
            foreach (var u in data.Uses)
                header.Append($"  read by {Format.MemberLabel(u.Method)} @IL_{u.ILOffset:X4} {Format.Token(u.Method)}{(u.Element != null ? $" as {Format.Type(u.Element)}[]" : "")}\n");
            if (data.UsesTotal > data.Uses.Count) header.Append($"  ... {data.UsesTotal - data.Uses.Count} more reads (find_references lists them)\n");
            if (data.UsesTotal == 0) header.Append("  read by no method of this assembly\n");
            var elements = FieldInitialData.Elements(bytes, element, MaxElements, out int count);
            if (elements != null)
                header.Append($"  as {Format.Type(element!)}[{count}]: {string.Join(", ", elements)}{(count > elements.Count ? ", ..." : "")}\n");
            for (int i = 0; i < bytes.Length; i += 16) rows.Add(new MemberEntry($"0x{i:X4}", FieldInitialData.Row(bytes, i)));
            info = new FieldDataInfo($"0x{data.Rva:X}", data.FileOffset is { } o ? $"0x{o:X}" : null, data.Verified, bytes.Length, data.Sha256)
            {
                ElementType = element != null ? Format.Type(element) : null,
                Elements = elements,
                ReadBy = data.Uses.Count > 0 ? data.Uses.Select(u => $"{Format.MemberLabel(u.Method)} @IL_{u.ILOffset:X4}").ToList() : null,
            };
        }
        return ToolOutput.List(rows.Skip(offset).Take(limit).ToList(), offset, limit, rows.Count, r => $"{r.Token}  {r.Signature}",
            page => new TypeOutline(SymbolRef.Of(sym), Format.Field(f), new Dictionary<string, int>(), "data", page, offset, rows.Count)
            {
                DeclaringType = f.DeclaringType.FullName,
                Attributes = attributes.Count > 0 ? attributes : null,
                InitialData = info,
            }, "16-byte row", header.ToString());
    }

    private static string MemberText(MemberEntry m) =>
        $"{(m.Kind != null ? $"{m.Kind,-8} " : "")}{m.Token}  {m.Signature}{(m.Il is { } n ? $"  IL {n} instr" : "")}{(m.Il2Cpp is { } s ? $"  [{s}]" : "")}";

    [McpServerTool(Name = "get_type_hierarchy", Title = "Type hierarchy", UseStructuredContent = true, OutputSchemaType = typeof(TypeHierarchy))]
    [Description("Base chain, interfaces and directly derived or implementing loaded types of a type.")]
    public Task<string> GetTypeHierarchy(
        [Description(SymbolDescription)] string type,
        [Description(AssemblyFilterDescription)] string? assembly = null,
        [Description(RowOffsetDescription)] int offset = 0,
        [Description(LimitDescription)] int limit = 200,
        [Description(MaxTokensDescription)] int? maxTokens = null,
        CancellationToken cancellationToken = default) => Read(workspace, () =>
    {
        var sym = SymbolResolver.ResolveOne(workspace, assembly, type, SymbolKind.Type, referenced: true);
        var t = (TypeDef)sym.Member;
        var h = references.GetHierarchy(t, End(offset, limit), cancellationToken);
        var header = new StringBuilder($"{Format.TypeHeader(t)}   [{sym.Assembly.Id}]\n");
        header.Append("Base types (nearest first):\n");
        if (h.BaseChain.Count == 0) header.Append("  (none)\n");
        foreach (var b in h.BaseChain) header.Append("  ").Append(b).Append('\n');
        header.Append($"Interfaces ({h.Interfaces.Count}):\n");
        foreach (var i in h.Interfaces) header.Append("  ").Append(i).Append('\n');
        header.Append(t.IsInterface ? "Implemented by: " : "Directly derived types: ");
        var derived = h.Derived.Skip(offset).Select(d => new MemberRow(d.Label, Format.Token(d.Member)) { Assembly = d.Assembly.Id }).ToList();
        return ToolOutput.List(derived, offset, limit, h.DerivedTotal, d => $"{d.Label}  [{d.Assembly}] {d.Token}",
            page => new TypeHierarchy(SymbolRef.Of(sym), h.BaseChain, h.Interfaces, page, offset, h.DerivedTotal), "type", header.ToString());
    }, cancellationToken);

    [McpServerTool(Name = "get_attributes", Title = "Custom attributes", UseStructuredContent = true, OutputSchemaType = typeof(AttributeList))]
    [Description("Custom attributes with arguments on a type or member (parameters and return value included), or on the assembly and module " +
                 "(symbol omitted; format=csharp decompiles them).")]
    public Task<string> GetAttributes(
        [Description(SymbolDescription + " Omit for assembly-level attributes.")] string? symbol = null,
        [Description(AssemblyFilterDescription + " Required when symbol is omitted.")] string? assembly = null,
        [Description("Only attributes whose type name contains this.")] string? filter = null,
        [Description("rows, or csharp (symbol omitted).")] string format = "rows",
        [Description("Rows to skip (characters with format=csharp).")] int offset = 0,
        [Description(LimitDescription)] int limit = 200,
        [Description(MaxTokensDescription)] int? maxTokens = null,
        CancellationToken cancellationToken = default) => Read(workspace, () =>
    {
        bool csharp = (format ?? "rows").Trim().ToLowerInvariant() switch
        {
            "rows" => false,
            "csharp" or "c#" => true,
            _ => throw new ToolError(ErrorCode.InvalidArgument, $"Unknown format '{format}'.", "pass format=rows or format=csharp"),
        };
        if (string.IsNullOrWhiteSpace(symbol) && string.IsNullOrWhiteSpace(assembly))
            throw new ToolError(ErrorCode.InvalidArgument, "Pass symbol, or assembly for assembly-level attributes.", "pass symbol=<type or member>, or assembly=<id> for the assembly's own attributes");
        if (csharp)
        {
            if (!string.IsNullOrWhiteSpace(symbol))
                throw new ToolError(ErrorCode.InvalidArgument, "format=csharp decompiles assembly-level attributes: leave symbol out.",
                    "pass assembly only; decompile_member shows a member's attributes in its C#");
            if (decompiler == null) throw new ToolError(ErrorCode.Unsupported, "Decompilation is not available here.");
            var asm = workspace.Get(assembly!);
            var code = decompiler.DecompileAssemblyAttributes(asm, cancellationToken);
            return ToolOutput.Text(pager, code, offset, new AttributeList(null, offset, null), maxTokens);
        }
        var rows = new List<(AttributeEntry Entry, SymbolRef? Who)>();
        void Add(IHasCustomAttribute owner, string target, SymbolRef? who)
        {
            foreach (var ca in owner.CustomAttributes)
                if (filter == null || (ca.AttributeType?.FullName ?? "").Contains(filter, StringComparison.OrdinalIgnoreCase))
                    rows.Add((new AttributeEntry(target, Format.Attribute(ca)) { Arguments = Arguments(ca) }, who));
        }
        if (string.IsNullOrWhiteSpace(symbol))
        {
            var asm = workspace.Get(assembly!);
            if (asm.Module.Assembly != null) Add(asm.Module.Assembly, "assembly", null);
            Add(asm.Module, "module", null);
        }
        else
            foreach (var sym in SymbolResolver.Resolve(workspace, assembly, symbol))
            {
                var who = SymbolRef.Of(sym);
                Add(sym.Member, who.Kind, who);
                if (sym.Member is MethodDef m)
                    foreach (var p in m.ParamDefs)
                        Add(p, p.Sequence == 0 ? "return" : $"param:{p.Name}", who);
            }
        return ToolOutput.List(rows.Skip(offset).Take(limit).ToList(), offset, limit, rows.Count,
            r => $"{(r.Who is { } o ? $"{o.Label}  [{o.Assembly}]  " : "")}{(r.Entry.Target is "type" or "method" or "field" or "property" or "event" ? "" : r.Entry.Target + ": ")}{r.Entry.Attribute}",
            page => new AttributeList(Owners(page), offset, rows.Count), "attribute", rows.Count == 0 && filter != null ? $"No custom attributes match '{filter}'.\n" : null);
    }, cancellationToken);

    private static List<AttributeArgumentEntry>? Arguments(CustomAttribute ca)
    {
        if (!ca.HasConstructorArguments && !ca.HasNamedArguments) return null;
        return ca.ConstructorArguments.Select(a => new AttributeArgumentEntry(Format.Type(a.Type), Format.AttributeArgument(a)))
            .Concat(ca.NamedArguments.Select(n => new AttributeArgumentEntry(Format.Type(n.Type), Format.AttributeArgument(n.Argument)) { Name = n.Name }))
            .ToList();
    }

    /// <summary>The page's rows with the owner on the first row of each member only.</summary>
    private static List<AttributeEntry> Owners(IReadOnlyList<(AttributeEntry Entry, SymbolRef? Who)> page)
    {
        SymbolRef? last = null;
        var rows = new List<AttributeEntry>();
        foreach (var (entry, who) in page)
        {
            rows.Add(who != null && who != last ? entry with { Owner = who.Label, Token = who.Token, Assembly = who.Assembly } : entry);
            last = who;
        }
        return rows;
    }

    [McpServerTool(Name = "resolve_symbol", Title = "Resolve symbol", UseStructuredContent = true, OutputSchemaType = typeof(SymbolList))]
    [Description("Every match of a symbol string or token, with kind, assembly, token and signature: disambiguate before other calls.")]
    public Task<string> ResolveSymbol(
        [Description(SymbolDescription)] string symbol,
        [Description(AssemblyFilterDescription)] string? assembly = null,
        [Description("Restrict to this kind.")] string? kind = null,
        [Description(RowOffsetDescription)] int offset = 0,
        [Description(LimitDescription)] int limit = 50,
        [Description(MaxTokensDescription)] int? maxTokens = null,
        CancellationToken cancellationToken = default) => Read(workspace, () =>
    {
        var all = SymbolResolver.Resolve(workspace, assembly, symbol, SymbolResolver.ParseKind(kind));
        var page = all.Skip(offset).Take(limit).Select(r => Match(r, Signature(r.Member))).ToList();
        return ToolOutput.List(page, offset, limit, all.Count, m => $"{m.Kind,-8} {m.Label}  [{m.Assembly}] {m.Token}\n{m.Signature}",
            rows => new SymbolList(rows, offset, all.Count), "match");
    }, cancellationToken);

    internal static string Signature(IMemberDef member) => member switch
    {
        MethodDef m => Format.Method(m),
        FieldDef f => Format.Field(f),
        PropertyDef p => Format.Property(p),
        EventDef e => Format.Event(e),
        TypeDef t => Format.TypeHeader(t),
        _ => "",
    };

    internal static SymbolMatch Match(ResolvedSymbol r, string? signature = null) =>
        new(SymbolRef.MemberKind(r.Member), r.Label, r.Assembly.Id, Format.Token(r.Member)) { Signature = signature };
}
