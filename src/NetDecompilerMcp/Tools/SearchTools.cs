using System.ComponentModel;
using System.Text;
using dnlib.DotNet;
using ModelContextProtocol.Server;
using NetDecompilerMcp.Core;
using NetDecompilerMcp.Services;
using static NetDecompilerMcp.Tools.ToolSupport;

namespace NetDecompilerMcp.Tools;

[McpServerToolType]
public sealed class SearchTools(AssemblyWorkspace workspace, AnalysisService analysis, OutputPager pager)
{
    [McpServerTool(Name = "search_symbols", ReadOnly = true)]
    [Description("Find types and members by name across loaded assemblies. Query is a case-insensitive substring, a wildcard pattern (Get*Player?) or a regex (regex=true). " +
                 "Queries containing '.' or '::' also match against full names. Exact matches are listed first.")]
    public Task<string> SearchSymbols(
        [Description("Name, substring, wildcard or regex.")] string query,
        [Description("Restrict to: any, type, method, field, property, event, member.")] string? kind = null,
        [Description(AssemblyDescription)] string? assembly = null,
        [Description("Only types in namespaces starting with this.")] string? @namespace = null,
        [Description("Treat query as a regular expression.")] bool regex = false,
        [Description("Max results (default 100).")] int limit = 100,
        CancellationToken cancellationToken = default) => Read(workspace, () =>
    {
        var r = analysis.SearchSymbols(query, regex, SymbolResolver.ParseKind(kind), workspace.Scope(assembly), @namespace, ClampLimit(limit), cancellationToken);
        if (r.Total == 0) return $"No symbols match '{query}'.";
        var sb = new StringBuilder($"{Plural(r.Total, "match")}{(r.Total > r.Items.Count ? $" (showing {r.Items.Count}; raise limit or refine)" : "")}:\n");
        foreach (var s in r.Items)
            sb.AppendLine($"  {s.Kind,-8} {s.Label}  [{s.Assembly.Id}] {Format.Token(s.Member)}");
        return pager.Page(sb.ToString());
    }, cancellationToken);

    [McpServerTool(Name = "search_strings", ReadOnly = true)]
    [Description("Find string literals (ldstr in method bodies and string constants) matching a substring, wildcard or regex. Shows the method and IL offset using each one. Great for locating code from UI text, log messages, URLs, keys.")]
    public Task<string> SearchStrings(
        [Description("Substring, wildcard or regex.")] string query,
        [Description(AssemblyDescription)] string? assembly = null,
        [Description("Treat query as a regular expression.")] bool regex = false,
        [Description("Max results (default 200).")] int limit = 200,
        CancellationToken cancellationToken = default) => Read(workspace, () =>
    {
        var r = analysis.SearchStrings(query, regex, workspace.Scope(assembly), ClampLimit(limit), cancellationToken);
        if (r.Total == 0) return $"No string literals match '{query}'.";
        var sb = new StringBuilder($"{Plural(r.Total, "occurrence")}{(r.Total > r.Items.Count ? $" (showing {r.Items.Count})" : "")}:\n");
        foreach (var h in r.Items)
            sb.AppendLine($"  {Format.Literal(Format.Clip(h.Value, 200))}\n      in {Format.MemberLabel(h.Owner)}{(h.ILOffset is { } o ? $" @IL_{o:X4}" : " (constant)")}  [{h.Assembly.Id}] {Format.Token(h.Owner)}");
        return pager.Page(sb.ToString());
    }, cancellationToken);

    [McpServerTool(Name = "search_constants", ReadOnly = true)]
    [Description("Find a numeric constant (magic number, packet/opcode id, flag, hash seed, crypto constant) wherever it appears: IL literals (ldc.*), const and enum field values, and attribute arguments. Accepts decimal, 0x hex, negative and floating-point values.")]
    public Task<string> SearchConstants(
        [Description("Number, e.g. 1337, 0xDEADBEEF, -1, 3.14.")] string value,
        [Description(AssemblyDescription)] string? assembly = null,
        [Description("Max results (default 200).")] int limit = 200,
        CancellationToken cancellationToken = default) => Read(workspace, () =>
    {
        var r = analysis.SearchConstants(value, workspace.Scope(assembly), ClampLimit(limit), cancellationToken);
        if (r.Total == 0) return $"Constant {value} not found.";
        var sb = new StringBuilder($"{Plural(r.Total, "occurrence")} of {value}{(r.Total > r.Items.Count ? $" (showing {r.Items.Count})" : "")}:\n");
        foreach (var h in r.Items)
            sb.AppendLine($"  {Format.MemberLabel(h.Owner)}{(h.ILOffset is { } o ? $" @IL_{o:X4}" : "")}  {h.Kind} {h.Value}  [{h.Assembly.Id}] {Format.Token(h.Owner)}");
        return pager.Page(sb.ToString());
    }, cancellationToken);

    [McpServerTool(Name = "find_references", ReadOnly = true)]
    [Description("Find every usage of a symbol across all loaded assemblies (analyzer / 'Used By'). " +
                 "Method: call sites (call/callvirt/newobj/ldftn). Field: reads, writes, address-taken. Property/event: accessor calls. " +
                 "Type: base type, interface, field/parameter/return/local types, attributes, instantiations, casts, member accesses. " +
                 "Calls through a base/interface method are listed under that base method — use find_overrides to walk the other way.")]
    public Task<string> FindReferences(
        [Description(SymbolDescription)] string symbol,
        [Description("Assembly that defines the symbol (only needed to disambiguate). References are searched in all loaded assemblies.")] string? assembly = null,
        [Description("Restrict symbol resolution to: type, method, field, property, event.")] string? kind = null,
        [Description("Max results (default 300).")] int limit = 300,
        CancellationToken cancellationToken = default) => Read(workspace, () =>
    {
        var target = SymbolResolver.ResolveOne(workspace, assembly, symbol, SymbolResolver.ParseKind(kind));
        var r = analysis.FindReferences(target, ClampLimit(limit), cancellationToken);
        var sb = new StringBuilder($"References to {target.Kind} {target.Label} [{target.Assembly.Id}]: {r.Total}{(r.Total > r.Items.Count ? $" (showing {r.Items.Count})" : "")}\n");
        if (r.Total == 0)
            sb.AppendLine(workspace.Assemblies.Count == 1
                ? "  none found. Only loaded assemblies are searched — load the assemblies that might use it (e.g. load_assembly on the whole Managed folder)."
                : "  none found in loaded assemblies.");
        foreach (var g in r.Items.GroupBy(i => (i.Assembly, i.Where)))
        {
            sb.AppendLine($"  {Format.MemberLabel(g.Key.Where)}  [{g.Key.Assembly.Id}] {Format.Token(g.Key.Where)}");
            foreach (var i in g)
                sb.AppendLine($"      {(i.ILOffset is { } o ? $"IL_{o:X4} " : "")}{i.Kind}{(i.Detail.Length > 0 ? " " + i.Detail : "")}");
        }
        return pager.Page(sb.ToString());
    }, cancellationToken);

    [McpServerTool(Name = "find_callees", ReadOnly = true)]
    [Description("What a method uses: the methods it calls, fields it reads/writes, types it instantiates/casts, and string literals, in IL order with offsets ('Uses' analyzer).")]
    public Task<string> FindCallees(
        [Description("Method. " + SymbolDescription)] string method,
        [Description(AssemblyDescription)] string? assembly = null,
        [Description("Collapse repeated targets into one line with a count.")] bool distinct = false,
        CancellationToken cancellationToken = default) => Read(workspace, () =>
    {
        var sym = SymbolResolver.ResolveOne(workspace, assembly, method, SymbolKind.Method);
        var list = analysis.FindCallees((MethodDef)sym.Member);
        var sb = new StringBuilder($"{sym.Label} [{sym.Assembly.Id}] uses {Plural(list.Count, "item")}:\n");
        if (distinct)
        {
            foreach (var g in list.GroupBy(c => (c.Kind, c.Target)).OrderBy(g => g.Key.Kind).ThenBy(g => g.Key.Target))
                sb.AppendLine($"  {g.Key.Kind,-14} {g.Key.Target}{(g.Count() > 1 ? $"  x{g.Count()}" : "")}{Where(g.First())}");
        }
        else
        {
            foreach (var c in list)
                sb.AppendLine($"  IL_{c.ILOffset:X4} {c.OpCode,-10} {c.Kind,-14} {c.Target}{Where(c)}");
        }
        return pager.Page(sb.ToString());

        static string Where(AnalysisService.Callee c) => c.TargetAssembly != null ? $"  [{c.TargetAssembly.Id}]" : "";
    }, cancellationToken);

    [McpServerTool(Name = "find_overrides", ReadOnly = true)]
    [Description("Find methods that override a virtual/abstract method or implement an interface method, across all derived types in loaded assemblies.")]
    public Task<string> FindOverrides(
        [Description("Virtual, abstract or interface method. " + SymbolDescription)] string method,
        [Description(AssemblyDescription)] string? assembly = null,
        CancellationToken cancellationToken = default) => Read(workspace, () =>
    {
        var sym = SymbolResolver.ResolveOne(workspace, assembly, method, SymbolKind.Method);
        var list = analysis.FindOverrides((MethodDef)sym.Member, cancellationToken);
        var sb = new StringBuilder($"{Plural(list.Count, "override/implementation")} of {sym.Label}:\n");
        foreach (var o in list)
            sb.AppendLine($"  {o.Label}  [{o.Assembly.Id}] {Format.Token(o.Member)}");
        return sb.ToString();
    }, cancellationToken);
}
