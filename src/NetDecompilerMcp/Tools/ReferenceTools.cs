using System.ComponentModel;
using System.Text;
using dnlib.DotNet;
using ModelContextProtocol.Server;
using NetDecompilerMcp.Core;
using NetDecompilerMcp.Services;
using static NetDecompilerMcp.Tools.ToolSupport;

namespace NetDecompilerMcp.Tools;

[McpServerToolType]
public sealed class ReferenceTools(AssemblyWorkspace workspace, ReferenceService references, OutputPager pager, NativeLinkService? link = null)
{
    [McpServerTool(Name = "find_references", Title = "Find usages (xrefs to)", ReadOnly = true, OpenWorld = false)]
    [Description("Every usage of a symbol across all loaded assemblies ('Used By'). " +
                 "Method: call sites (call/callvirt/newobj/ldftn/ldtoken). Field: reads, writes, address-taken. Property/event: accessor calls. " +
                 "Type: base type, interface, generic constraint, field/parameter/return/local types, catch clauses, attributes, instantiations, casts, member accesses. " +
                 "With includeVirtualCalls (default true) a method's results also include calls made through the base/interface method it overrides or implements. " +
                 "A native export (kernel32.dll!CreateFileW) lists the P/Invoke declarations bound to it with their call sites, and native call sites in loaded images; " +
                 "a managed method called from native code (C++/CLI) also lists those native call sites.")]
    public async Task<string> FindReferences(
        [Description(SymbolOrNativeDescription)] string symbol,
        [Description("Assembly that defines the symbol (only to disambiguate). References are searched in all loaded assemblies.")] string? assembly = null,
        [Description("Restrict symbol resolution to: type, method, field, property, event.")] string? kind = null,
        [Description("For methods: include calls through base/interface declarations that dispatch here.")] bool includeVirtualCalls = true,
        [Description("Max results (default 300).")] int limit = 300,
        CancellationToken cancellationToken = default)
    {
        if (link != null) await link.WarmUp(null, cancellationToken);
        if (link != null && SymbolResolver.ParseNative(symbol) is { } native)
            return await Read(workspace, () => pager.Page(NativeReferences(link, native, includeVirtualCalls, ClampLimit(limit), cancellationToken)), cancellationToken);
        return await Read(workspace, () =>
        {
            var target = SymbolResolver.ResolveOne(workspace, assembly, symbol, SymbolResolver.ParseKind(kind), referenced: true);
            var r = references.FindReferences(target, includeVirtualCalls, ClampLimit(limit), cancellationToken);
            var nativeSites = link != null && target.Member is MethodDef md ? link.NativeCallSitesOf(md, cancellationToken) : [];
            var sb = new StringBuilder($"References to {target.Kind} {target.Label} [{target.Assembly.Id}]: {r.Total + nativeSites.Count}{TruncationNote(r.Items.Count, r.Total)}\n");
            if (r.Total == 0 && nativeSites.Count == 0)
                sb.AppendLine(workspace.Assemblies.Count == 1
                    ? "  none found. Only loaded assemblies are searched — load the assemblies that might use it (e.g. the whole Managed folder)."
                    : "  none found in loaded assemblies.");
            AppendReferences(sb, r.Items, "  ");
            if (nativeSites.Count > 0)
            {
                sb.AppendLine($"  native call sites ({nativeSites.Count}):");
                foreach (var row in nativeSites.Take(ClampLimit(limit))) sb.AppendLine("      " + row);
            }
            sb.Append(SkippedBodiesNote(workspace.Assemblies));
            return pager.Page(sb.ToString());
        }, cancellationToken);
    }

    private static void AppendReferences(StringBuilder sb, IEnumerable<ReferenceService.Reference> items, string indent)
    {
        foreach (var g in items.GroupBy(i => (i.Assembly, i.Where)))
        {
            sb.AppendLine($"{indent}{Format.MemberLabel(g.Key.Where)}  [{g.Key.Assembly.Id}] {Format.Token(g.Key.Where)}");
            foreach (var i in g)
                sb.AppendLine($"{indent}    {(i.ILOffset is { } o ? $"IL_{o:X4} " : "")}{i.Kind}{(i.Detail.Length > 0 ? " " + i.Detail : "")}");
        }
    }

    /// <summary>P/Invoke declarations bound to a native export with their callers, and native call sites in loaded images.</summary>
    private string NativeReferences(NativeLinkService link, NativeSymbol symbol, bool includeVirtualCalls, int limit, CancellationToken ct)
    {
        var target = link.Resolve(symbol);
        var managed = link.ManagedLinksTo(target, ct);
        var sites = link.NativeCallSites(target, ct);
        var sb = new StringBuilder($"References to native {symbol}: {target.Label}\n");
        sb.AppendLine($"Managed declarations bound to it: {managed.Count}");
        int shown = 0;
        foreach (var m in managed)
        {
            sb.AppendLine($"  {Format.MemberLabel(m.Method)}  [{m.Assembly.Id}] {Format.Token(m.Method)}  ({m.Kind}: {NativeLinkService.Describe(m.Binding)})");
            var r = references.FindReferences(new ResolvedSymbol(m.Assembly, m.Method), includeVirtualCalls, Math.Max(1, limit - shown), ct);
            shown += r.Items.Count;
            if (r.Total == 0) sb.AppendLine("      no callers in the loaded assemblies");
            AppendReferences(sb, r.Items, "      ");
            if (r.Items.Count < r.Total) sb.AppendLine($"      ... {r.Total - r.Items.Count} more (raise limit)");
        }
        if (managed.Count == 0)
            sb.AppendLine("  none (P/Invokes reaching it through a jump thunk are matched only when the thunk's image is loaded)");
        sb.AppendLine($"Native call sites in loaded images: {sites.Count}{TruncationNote(Math.Min(sites.Count, limit), sites.Count)}");
        foreach (var row in sites.Take(limit)) sb.AppendLine("  " + row);
        return sb.ToString();
    }

    [McpServerTool(Name = "find_callees", Title = "What a method uses (xrefs from)", ReadOnly = true, OpenWorld = false)]
    [Description("What a method uses: methods it calls, fields it reads/writes, types it instantiates/casts, and string literals, in IL order with offsets ('Uses'). " +
                 "Calls to P/Invoke declarations (and native method bodies of mixed-mode assemblies) also show the native code they bind to " +
                 "('native: module!export -> PROVIDER!export at VA [image]'; disassemble takes that image and VA). For a P/Invoke method itself, or a native " +
                 "export symbol, the native function's callees.")]
    public async Task<string> FindCallees(
        [Description("Method. " + SymbolOrNativeDescription)] string method,
        [Description(AssemblyFilterDescription)] string? assembly = null,
        [Description("Collapse repeated targets into one line with a count.")] bool distinct = false,
        CancellationToken cancellationToken = default)
    {
        if (link != null) await link.WarmUp(null, cancellationToken);
        if (link != null && SymbolResolver.ParseNative(method) is { } native)
            return await Read(workspace, () =>
            {
                var target = link.Resolve(native);
                var sb = new StringBuilder($"native {native}: {target.Label}\n");
                if (link.FunctionOf(target.Binding) is not { } fn)
                    sb.AppendLine(target.Binding.Status == NativeLinkService.Bound
                        ? "  (its image's code index is still being built or has no function there)"
                        : $"  (the code is in {target.Binding.FinalFile}, which is not loaded: load_assembly it to see what it calls)");
                else link.AppendTree(sb, fn.Image, fn.Function, false, 1, 2000, 1, withRoot: false, cancellationToken);
                return pager.Page(sb.ToString());
            }, cancellationToken);
        return await Read(workspace, () =>
        {
            var sym = SymbolResolver.ResolveOne(workspace, assembly, method, SymbolKind.Method);
            var md = (MethodDef)sym.Member;
            if (link?.NativeOf(md) is { } own && !md.HasBody)
                return pager.Page($"{sym.Label} [{sym.Assembly.Id}] is a {own.Kind} with no IL body; it runs:\n" +
                                  link.NativeCallees(md, 2, 1, 2000, cancellationToken));
            var list = references.FindCallees(md);
            var sb = new StringBuilder($"{sym.Label} [{sym.Assembly.Id}] uses {Plural(list.Count, "item")}:\n");
            if (distinct)
            {
                foreach (var g in list.GroupBy(c => (c.Kind, c.Target)).OrderBy(g => g.Key.Kind).ThenBy(g => g.Key.Target))
                    sb.AppendLine($"  {g.Key.Kind,-14} {g.Key.Target}{(g.Count() > 1 ? $"  x{g.Count()}" : "")}{Where(g.First())}{Native(g.First())}");
            }
            else
            {
                foreach (var c in list)
                    sb.AppendLine($"  IL_{c.ILOffset:X4} {c.OpCode,-10} {c.Kind,-14} {c.Target}{Where(c)}{Native(c)}");
            }
            return pager.Page(sb.ToString());
        }, cancellationToken);

        static string Where(ReferenceService.Callee c) => c.TargetAssembly != null ? $"  [{c.TargetAssembly.Id}]" : "";
        string Native(ReferenceService.Callee c) =>
            link != null && c.Method != null && link.NativeOf(c.Method) is { } n ? $"\n      -> native: {NativeLinkService.Describe(n.Binding)}" : "";
    }

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
