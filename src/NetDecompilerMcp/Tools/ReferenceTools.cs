using System.ComponentModel;
using System.Text;
using dnlib.DotNet;
using ModelContextProtocol.Server;
using NetDecompilerMcp.Core;
using NetDecompilerMcp.Services;
using static NetDecompilerMcp.Tools.ToolSupport;

namespace NetDecompilerMcp.Tools;

[McpServerToolType]
public sealed class ReferenceTools(AssemblyWorkspace workspace, ReferenceService references, OutputPager pager)
{
    [McpServerTool(Name = "find_references", Title = "Find usages (xrefs to)", ReadOnly = true, OpenWorld = false)]
    [Description("Every usage of a symbol across all loaded assemblies ('Used By'). " +
                 "Method: call sites (call/callvirt/newobj/ldftn/ldtoken). Field: reads, writes, address-taken. Property/event: accessor calls. " +
                 "Type: base type, interface, generic constraint, field/parameter/return/local types, catch clauses, attributes, instantiations, casts, member accesses. " +
                 "With includeVirtualCalls (default true) a method's results also include calls made through the base/interface method it overrides or implements.")]
    public Task<string> FindReferences(
        [Description(SymbolDescription)] string symbol,
        [Description("Assembly that defines the symbol (only to disambiguate). References are searched in all loaded assemblies.")] string? assembly = null,
        [Description("Restrict symbol resolution to: type, method, field, property, event.")] string? kind = null,
        [Description("For methods: include calls through base/interface declarations that dispatch here.")] bool includeVirtualCalls = true,
        [Description("Max results (default 300).")] int limit = 300,
        CancellationToken cancellationToken = default) => Read(workspace, () =>
    {
        var target = SymbolResolver.ResolveOne(workspace, assembly, symbol, SymbolResolver.ParseKind(kind), referenced: true);
        var r = references.FindReferences(target, includeVirtualCalls, ClampLimit(limit), cancellationToken);
        var sb = new StringBuilder($"References to {target.Kind} {target.Label} [{target.Assembly.Id}]: {r.Total}{TruncationNote(r.Items.Count, r.Total)}\n");
        if (r.Total == 0)
            sb.AppendLine(workspace.Assemblies.Count == 1
                ? "  none found. Only loaded assemblies are searched — load the assemblies that might use it (e.g. the whole Managed folder)."
                : "  none found in loaded assemblies.");
        foreach (var g in r.Items.GroupBy(i => (i.Assembly, i.Where)))
        {
            sb.AppendLine($"  {Format.MemberLabel(g.Key.Where)}  [{g.Key.Assembly.Id}] {Format.Token(g.Key.Where)}");
            foreach (var i in g)
                sb.AppendLine($"      {(i.ILOffset is { } o ? $"IL_{o:X4} " : "")}{i.Kind}{(i.Detail.Length > 0 ? " " + i.Detail : "")}");
        }
        return pager.Page(sb.ToString());
    }, cancellationToken);

    [McpServerTool(Name = "find_callees", Title = "What a method uses (xrefs from)", ReadOnly = true, OpenWorld = false)]
    [Description("What a method uses: methods it calls, fields it reads/writes, types it instantiates/casts, and string literals, in IL order with offsets ('Uses').")]
    public Task<string> FindCallees(
        [Description("Method. " + SymbolDescription)] string method,
        [Description(AssemblyFilterDescription)] string? assembly = null,
        [Description("Collapse repeated targets into one line with a count.")] bool distinct = false,
        CancellationToken cancellationToken = default) => Read(workspace, () =>
    {
        var sym = SymbolResolver.ResolveOne(workspace, assembly, method, SymbolKind.Method);
        var list = references.FindCallees((MethodDef)sym.Member);
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

        static string Where(ReferenceService.Callee c) => c.TargetAssembly != null ? $"  [{c.TargetAssembly.Id}]" : "";
    }, cancellationToken);

    [McpServerTool(Name = "find_overrides", Title = "Find overrides / implementations", ReadOnly = true, OpenWorld = false)]
    [Description("Methods that override a virtual/abstract method or implement an interface method, across all derived types in loaded assemblies (explicit and implicit implementations).")]
    public Task<string> FindOverrides(
        [Description("Virtual, abstract or interface method. " + SymbolDescription)] string method,
        [Description(AssemblyFilterDescription)] string? assembly = null,
        [Description("Max results (default 200).")] int limit = 200,
        [Description("Index of the first result to return.")] int offset = 0,
        CancellationToken cancellationToken = default) => Read(workspace, () =>
    {
        var sym = SymbolResolver.ResolveOne(workspace, assembly, method, SymbolKind.Method, referenced: true);
        var list = references.FindOverrides((MethodDef)sym.Member, cancellationToken);
        var rows = list.Select(o => $"{o.Label}  [{o.Assembly.Id}] {Format.Token(o.Member)}").ToList();
        return $"Overrides / implementations of {sym.Label}  [{sym.Assembly.Id}]:\n" + pager.PageRows(rows, offset, ClampLimit(limit), "override/implementation");
    }, cancellationToken);
}
