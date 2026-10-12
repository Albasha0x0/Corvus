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
public sealed class ReferenceTools(AssemblyWorkspace workspace, ReferenceService references, OutputPager pager, NativeLinkService? link = null)
{
    [McpServerTool(Name = "find_references", Title = "Find usages (xrefs to)", UseStructuredContent = true, OutputSchemaType = typeof(ReferenceList))]
    [Description("Every usage of a symbol across loaded assemblies ('Used By'): a method's call sites (also through the base / interface method it implements), " +
                 "a field's reads, writes and address-taken uses, accessor calls, a type's every use (bases, signatures, locals, casts, attributes, ...). " +
                 "A native export lists its P/Invoke declarations with their call sites and native call sites in loaded images; C++/CLI native callers are included.")]
    public async Task<string> FindReferences(
        [Description(SymbolOrNativeDescription)] string symbol,
        [Description("Assembly defining the symbol (only to disambiguate; all loaded ones are searched).")] string? assembly = null,
        [Description("Restrict symbol resolution to this kind.")] string? kind = null,
        [Description("Methods: include calls through base / interface declarations.")] bool includeVirtualCalls = true,
        [Description("Max results.")] int limit = 300,
        [Description("Index of the first reference.")] int offset = 0,
        CancellationToken cancellationToken = default)
    {
        limit = ClampLimit(limit);
        offset = Math.Clamp(offset, 0, int.MaxValue - limit);
        if (link != null) await link.WarmUp(null, cancellationToken);
        if (link != null && SymbolResolver.ParseNative(symbol) is { } native)
            return await Read(workspace, () => pager.Page(NativeReferences(link, native, includeVirtualCalls, limit, cancellationToken)), cancellationToken);
        return await Read(workspace, () =>
        {
            var target = SymbolResolver.ResolveOne(workspace, assembly, symbol, SymbolResolver.ParseKind(kind), referenced: true);
            var r = references.FindReferences(target, includeVirtualCalls, offset + limit, cancellationToken);
            var page = r.Items.Skip(offset).ToList();
            var nativeSites = link != null && target.Member is MethodDef md ? link.NativeCallSitesOf(md, cancellationToken) : [];
            var sb = new StringBuilder($"References to {target.Kind} {target.Label} [{target.Assembly.Id}]: {r.Total + nativeSites.Count}" +
                                       (offset >= r.Total && r.Total > 0 ? $" (none from offset {offset})" : offset > 0 ? $" (showing {offset + 1}-{offset + page.Count})" : TruncationNote(page.Count, r.Total)) + "\n");
            if (r.Total == 0 && nativeSites.Count == 0)
                sb.AppendLine(workspace.Assemblies.Count == 1
                    ? "  none found. Only loaded assemblies are searched — load the assemblies that might use it (e.g. the whole Managed folder)."
                    : "  none found in loaded assemblies.");
            AppendReferences(sb, page, "  ");
            if (nativeSites.Count > 0)
            {
                sb.AppendLine($"  native call sites ({nativeSites.Count}):");
                foreach (var row in nativeSites.Take(limit)) sb.AppendLine("      " + row);
            }
            if (offset > 0 && offset + page.Count < r.Total) sb.AppendLine($"[More: offset={offset + page.Count}]");
            sb.Append(SkippedBodiesNote(workspace.Assemblies));
            var result = new ReferenceList($"{target.Label} [{target.Assembly.Id}]", page.Select(i => Entry(i, null)).ToList(), nativeSites.Take(limit).ToList(),
                offset, r.Total, offset + page.Count < r.Total);
            return StructuredOutput.With(pager.Page(sb.ToString()), result);
        }, cancellationToken);
    }

    private static ReferenceEntry Entry(ReferenceService.Reference i, string? via) =>
        new(SymbolRef.Of(i.Assembly, i.Where), (int?)i.ILOffset, i.Kind, i.Detail.Length > 0 ? i.Detail : null, via);

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
        int shown = 0, total = 0;
        var items = new List<ReferenceEntry>();
        foreach (var m in managed)
        {
            sb.AppendLine($"  {Format.MemberLabel(m.Method)}  [{m.Assembly.Id}] {Format.Token(m.Method)}  ({m.Kind}: {NativeLinkService.Describe(m.Binding)})");
            var r = references.FindReferences(new ResolvedSymbol(m.Assembly, m.Method), includeVirtualCalls, Math.Max(1, limit - shown), ct);
            shown += r.Items.Count;
            total += r.Total;
            if (r.Total == 0) sb.AppendLine("      no callers in the loaded assemblies");
            AppendReferences(sb, r.Items, "      ");
            if (r.Items.Count < r.Total) sb.AppendLine($"      ... {r.Total - r.Items.Count} more (raise limit)");
            items.AddRange(r.Items.Select(i => Entry(i, $"{Format.MemberLabel(m.Method)} [{m.Assembly.Id}]")));
        }
        if (managed.Count == 0)
            sb.AppendLine("  none (P/Invokes reaching it through a jump thunk are matched only when the thunk's image is loaded)");
        sb.AppendLine($"Native call sites in loaded images: {sites.Count}{TruncationNote(Math.Min(sites.Count, limit), sites.Count)}");
        foreach (var row in sites.Take(limit)) sb.AppendLine("  " + row);
        return StructuredOutput.With(sb.ToString(),
            new ReferenceList($"native {symbol}: {target.Label}", items, sites.Take(limit).ToList(), 0, total, items.Count < total || sites.Count > limit));
    }

    [McpServerTool(Name = "find_callees", Title = "What a method uses (xrefs from)", UseStructuredContent = true, OutputSchemaType = typeof(CalleeList))]
    [Description("What a method uses ('Uses'): calls, field reads / writes, types instantiated or cast, and strings, in IL order with offsets. P/Invoke calls show " +
                 "the native code they bind to ('native: module!export -> PROVIDER!export at VA [image]'); for a P/Invoke or native export, its native callees.")]
    public async Task<string> FindCallees(
        [Description(SymbolOrNativeDescription)] string method,
        [Description(AssemblyFilterDescription)] string? assembly = null,
        [Description("Collapse repeated targets into one line with a count.")] bool distinct = false,
        [Description("Index of the first entry.")] int offset = 0,
        [Description("Max entries.")] int limit = 2000,
        CancellationToken cancellationToken = default)
    {
        limit = ClampLimit(limit);
        offset = Math.Max(0, offset);
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
                return StructuredOutput.With(pager.Page(sb.ToString()), new CalleeList($"native {native}: {target.Label}", [], Lines(sb.ToString()), 0, 0, false));
            }, cancellationToken);
        return await Read(workspace, () =>
        {
            var sym = SymbolResolver.ResolveOne(workspace, assembly, method, SymbolKind.Method);
            var md = (MethodDef)sym.Member;
            var label = $"{sym.Label} [{sym.Assembly.Id}]";
            if (link?.NativeOf(md) is { } own && !md.HasBody)
            {
                var runs = link.NativeCallees(md, 2, 1, 2000, cancellationToken);
                return StructuredOutput.With(pager.Page($"{label} is a {own.Kind} with no IL body; it runs:\n" + runs),
                    new CalleeList(label, [], Lines(runs), 0, 0, false));
            }
            var list = references.FindCallees(md);
            var entries = distinct
                ? list.GroupBy(c => (c.Kind, c.Target)).OrderBy(g => g.Key.Kind).ThenBy(g => g.Key.Target)
                    .Select(g => (Callee: g.First(), Count: g.Count(), Line: $"  {g.Key.Kind,-14} {g.Key.Target}{(g.Count() > 1 ? $"  x{g.Count()}" : "")}{Where(g.First())}{Native(g.First())}"))
                    .ToList()
                : list.Select(c => (Callee: c, Count: 1, Line: $"  IL_{c.ILOffset:X4} {c.OpCode,-10} {c.Kind,-14} {c.Target}{Where(c)}{Native(c)}")).ToList();
            var page = entries.Skip(offset).Take(limit).ToList();
            var sb = new StringBuilder($"{label} uses {Plural(list.Count, "item")}" +
                                       (offset > 0 || page.Count < entries.Count ? $" (showing {(page.Count == 0 ? 0 : offset + 1)}-{offset + page.Count} of {entries.Count})" : "") + ":\n");
            foreach (var e in page) sb.AppendLine(e.Line);
            if (offset + page.Count < entries.Count) sb.AppendLine($"[More: offset={offset + page.Count}]");
            var result = new CalleeList(label, page.Select(e => new CalleeEntry(distinct ? null : (int)e.Callee.ILOffset, distinct ? null : e.Callee.OpCode,
                    e.Callee.Kind, e.Callee.Target, e.Callee.TargetAssembly?.Id, NativeTarget(e.Callee), e.Count)).ToList(),
                [], offset, entries.Count, offset + page.Count < entries.Count);
            return StructuredOutput.With(pager.Page(sb.ToString()), result);
        }, cancellationToken);

        static string Where(ReferenceService.Callee c) => c.TargetAssembly != null ? $"  [{c.TargetAssembly.Id}]" : "";
        string? NativeTarget(ReferenceService.Callee c) =>
            link != null && c.Method != null && link.NativeOf(c.Method) is { } n ? NativeLinkService.Describe(n.Binding) : null;
        string Native(ReferenceService.Callee c) => NativeTarget(c) is { } n ? $"\n      -> native: {n}" : "";
    }

    /// <summary>Non-empty lines of a text block, for the structured form of native trees.</summary>
    internal static List<string> Lines(string text) =>
        text.Split('\n').Select(l => l.TrimEnd('\r')).Where(l => l.Trim().Length > 0).Take(5_000).ToList();

    [McpServerTool(Name = "find_overrides", Title = "Find overrides / implementations", UseStructuredContent = true, OutputSchemaType = typeof(OverrideList))]
    [Description("Methods overriding a virtual / abstract method or implementing an interface method (explicitly or implicitly), across loaded assemblies.")]
    public Task<string> FindOverrides(
        [Description(SymbolDescription)] string method,
        [Description(AssemblyFilterDescription)] string? assembly = null,
        [Description("Max results.")] int limit = 200,
        [Description("Index of the first result.")] int offset = 0,
        CancellationToken cancellationToken = default) => Read(workspace, () =>
    {
        var sym = SymbolResolver.ResolveOne(workspace, assembly, method, SymbolKind.Method, referenced: true);
        var list = references.FindOverrides((MethodDef)sym.Member, cancellationToken);
        var rows = list.Select(o => $"{o.Label}  [{o.Assembly.Id}] {Format.Token(o.Member)}").ToList();
        return StructuredOutput.With($"Overrides / implementations of {sym.Label}  [{sym.Assembly.Id}]:\n" + pager.PageRows(rows, offset, ClampLimit(limit), "override/implementation"),
            Paged(list.Select(o => BrowseTools.Match(o)).ToList(), offset, limit, (page, o, total, more) => new OverrideList(SymbolRef.Of(sym), page, o, total, more)));
    }, cancellationToken);
}
