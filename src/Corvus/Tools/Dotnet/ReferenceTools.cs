using System.ComponentModel;
using System.Text;
using dnlib.DotNet;
using ModelContextProtocol.Server;
using Corvus.Core;
using Corvus.Mcp;
using Corvus.Native;
using Corvus.Services;
using static Corvus.Tools.ToolSupport;

namespace Corvus.Tools;

[McpServerToolType]
public sealed class ReferenceTools(AssemblyWorkspace workspace, ReferenceService references, NativeLinkService? link = null)
{
    [McpServerTool(Name = "find_references", Title = "Find usages (xrefs to)", UseStructuredContent = true, OutputSchemaType = typeof(ReferenceList))]
    [Description("Every use of a symbol across loaded assemblies: method call sites (also via base or interface), field reads, writes " +
                 "and address uses, type uses. A native export gives P/Invoke callers and native call sites.")]
    public async Task<string> FindReferences(
        [Description(SymbolOrNativeDescription)] string symbol,
        [Description("Assembly defining the symbol, to disambiguate; all loaded are searched.")] string? assembly = null,
        [Description("Symbol kind; overrides: overrides and implementations of the method.")] string? kind = null,
        [Description("Methods: no calls through base / interface declarations.")] bool directOnly = false,
        [Description(LimitDescription)] int limit = 150,
        [Description(MaxTokensDescription)] int? maxTokens = null,
        [Description(RowOffsetDescription)] int offset = 0,
        CancellationToken cancellationToken = default)
    {
        bool overrides = string.Equals(kind?.Trim(), "overrides", StringComparison.OrdinalIgnoreCase);
        if (link != null && !overrides) await link.WarmUp(null, cancellationToken);
        if (link != null && !overrides && SymbolResolver.ParseNative(symbol) is { } native)
            return await Read(workspace, () => NativeReferences(link, native, !directOnly, offset, limit, cancellationToken), cancellationToken);
        return await Read(workspace, () =>
        {
            if (overrides) return Overrides(symbol, assembly, offset, limit, cancellationToken);
            var target = SymbolResolver.ResolveOne(workspace, assembly, symbol, SymbolResolver.ParseKind(kind), referenced: true);
            var r = references.FindReferences(target, !directOnly, End(offset, limit), cancellationToken);
            var nativeSites = link != null && target.Member is MethodDef md ? link.NativeCallSitesOf(md, cancellationToken) : [];
            int total = r.Total + nativeSites.Count;
            var page = new List<ReferenceEntry>();
            for (int i = offset; i < Math.Min(total, End(offset, limit)); i++)
                page.Add(i < r.Total ? Entry(r.Items[i], null) : NativeSite(nativeSites[i - r.Total]));
            var header = $"References to {target.Kind} {target.Label} [{target.Assembly.Id}]: ";
            if (total == 0)
                header += workspace.Assemblies.Count == 1
                    ? "none found. Only loaded assemblies are searched: load the assemblies that might use it.\n"
                    : "none found in loaded assemblies.\n";
            return ToolOutput.List(page, offset, limit, total, Row, rows => new ReferenceList($"{target.Label} [{target.Assembly.Id}]", Runs(rows), offset, total), "reference",
                SkippedBodiesNote(workspace.Assemblies) + header);
        }, cancellationToken);
    }

    private string Overrides(string symbol, string? assembly, int offset, int limit, CancellationToken ct)
    {
        var sym = SymbolResolver.ResolveOne(workspace, assembly, symbol, SymbolKind.Method, referenced: true);
        var method = (MethodDef)sym.Member;
        var list = references.FindOverrides(method, ct);
        string kind = method.DeclaringType.IsInterface ? "implementation" : "override";
        var page = list.Skip(offset).Take(limit).Select(o => new ReferenceEntry(kind, "observed") { Where = o.Label, Token = Format.Token(o.Member), Assembly = o.Assembly.Id }).ToList();
        return ToolOutput.List(page, offset, limit, list.Count, Row, rows => new ReferenceList($"{sym.Label} [{sym.Assembly.Id}]", rows, offset, list.Count),
            kind, $"Overrides / implementations of {sym.Label}  [{sym.Assembly.Id}]: ");
    }

    /// <summary>A reference row: derived when it reaches the symbol through a base or interface declaration or a delegate field.</summary>
    private static ReferenceEntry Entry(ReferenceService.Reference i, string? via) =>
        new(i.Kind, i.Detail.StartsWith("via ", StringComparison.Ordinal) ? "derived" : "observed")
        {
            Where = Format.MemberLabel(i.Where),
            Token = Format.Token(i.Where),
            Assembly = i.Assembly.Id,
            IlOffset = (int?)i.ILOffset,
            Detail = i.Detail.Length > 0 ? i.Detail : null,
            Via = via,
        };

    /// <summary>The record's rows: the containing member only where it changes from the row before.</summary>
    private static List<ReferenceEntry> Runs(IReadOnlyList<ReferenceEntry> rows)
    {
        var result = new List<ReferenceEntry>();
        ReferenceEntry? previous = null;
        foreach (var r in rows)
        {
            result.Add(previous != null && r.Where != null && r.Where == previous.Where && r.Token == previous.Token && r.Assembly == previous.Assembly
                ? r with { Where = null, Token = null, Assembly = null } : r);
            previous = r;
        }
        return result;
    }

    private static ReferenceEntry NativeSite(string row) => new("native call", "observed") { Detail = row };

    private static string Row(ReferenceEntry e) =>
        e.Where is { } w
            ? $"{w}  [{e.Assembly}] {e.Token}{(e.IlOffset is { } o ? $"  IL_{o:X4}" : "")}  {e.Kind}{(e.Detail != null ? " " + e.Detail : "")}{(e.Via != null ? $"  (through {e.Via})" : "")}"
            : $"{e.Kind}: {e.Detail}";

    /// <summary>P/Invoke declarations bound to a native export with their callers, then native call sites in loaded images, paged as one list.</summary>
    private string NativeReferences(NativeLinkService link, NativeSymbol symbol, bool includeVirtualCalls, int offset, int limit, CancellationToken ct)
    {
        var target = link.Resolve(symbol);
        var managed = link.ManagedLinksTo(target, ct);
        var sites = link.NativeCallSites(target, ct);
        var header = new StringBuilder($"References to native {symbol}: {target.Label}\n");
        header.Append($"Managed declarations bound to it: {managed.Count}\n");
        foreach (var m in managed)
            header.Append($"  {Format.MemberLabel(m.Method)}  [{m.Assembly.Id}] {Format.Token(m.Method)}  ({m.Kind}: {NativeLinkService.Describe(m.Binding)})\n");
        if (managed.Count == 0)
            header.Append("  none (P/Invokes reaching it through a jump thunk are matched only when the thunk's image is loaded)\n");
        // Each declaration's callers up to offset + limit: the rows before the page end are exact.
        var rows = new List<ReferenceEntry>();
        int total = 0;
        foreach (var m in managed)
        {
            var r = references.FindReferences(new ResolvedSymbol(m.Assembly, m.Method), includeVirtualCalls, End(offset, limit), ct);
            var via = $"{Format.MemberLabel(m.Method)} [{m.Assembly.Id}]";
            if (total < End(offset, limit)) rows.AddRange(r.Items.Take(End(offset, limit) - total).Select(i => Entry(i, via)));
            total += r.Total;
        }
        foreach (var s in sites)
        {
            if (total < End(offset, limit) && rows.Count == total) rows.Add(NativeSite(s));
            total++;
        }
        var page = rows.Skip(offset).Take(limit).ToList();
        return ToolOutput.List(page, offset, limit, total, Row, p => new ReferenceList($"native {symbol}: {target.Label}", Runs(p), offset, total), "reference", header.ToString());
    }

    [McpServerTool(Name = "find_callees", Title = "What a method uses (xrefs from)", UseStructuredContent = true, OutputSchemaType = typeof(CalleeList))]
    [Description("What a method uses, in IL order with offsets: calls, field reads and writes, types, strings. " +
                 "A P/Invoke or native export gives its native callees as call-tree rows.")]
    public async Task<string> FindCallees(
        [Description(SymbolOrNativeDescription)] string method,
        [Description(AssemblyFilterDescription)] string? assembly = null,
        [Description("One row per target, with a count.")] bool distinct = false,
        [Description(RowOffsetDescription)] int offset = 0,
        [Description(LimitDescription)] int limit = 200,
        [Description(MaxTokensDescription)] int? maxTokens = null,
        CancellationToken cancellationToken = default)
    {
        if (link != null) await link.WarmUp(null, cancellationToken);
        if (link != null && SymbolResolver.ParseNative(method) is { } native)
            return await Read(workspace, () =>
            {
                var target = link.Resolve(native);
                var header = $"native {native}: {target.Label}\n";
                var nodes = new List<NativeTreeNode>();
                if (link.FunctionOf(target.Binding) is not { } fn)
                    header += target.Binding.Status == NativeLinkService.Bound
                        ? "  (its image's code index is still being built or has no function there)\n"
                        : $"  (the code is in {target.Binding.FinalFile}, which is not loaded: load_assembly it to see what it calls)\n";
                else link.AppendTree(new StringBuilder(), fn.Image, fn.Function, false, 1, 5_000, 1, withRoot: false, cancellationToken, rows: nodes, home: fn.Image);
                return NativePage($"native {native}: {target.Label}", header, nodes, offset, limit);
            }, cancellationToken);
        return await Read(workspace, () =>
        {
            var sym = SymbolResolver.ResolveOne(workspace, assembly, method, SymbolKind.Method);
            var md = (MethodDef)sym.Member;
            var label = $"{sym.Label} [{sym.Assembly.Id}]";
            if (link?.NativeOf(md) is { } own && !md.HasBody)
            {
                var nodes = new List<NativeTreeNode>();
                link.NativeCallees(md, 2, 1, 5_000, cancellationToken, nodes);
                return NativePage(label, $"{label} is a {own.Kind} with no IL body; it runs:\n", nodes, offset, limit);
            }
            var list = references.FindCallees(md);
            var entries = distinct
                ? list.GroupBy(c => (c.Kind, c.Target)).OrderBy(g => g.Key.Kind).ThenBy(g => g.Key.Target)
                    .Select(g => new CalleeEntry(g.Key.Kind, g.Key.Target)
                    {
                        TargetAssembly = g.First().TargetAssembly?.Id,
                        Native = NativeTarget(g.First()),
                        Count = g.Count() > 1 ? g.Count() : null,
                    }).ToList()
                : list.Select(c => new CalleeEntry(c.Kind, c.Target)
                {
                    IlOffset = (int)c.ILOffset,
                    OpCode = c.OpCode,
                    TargetAssembly = c.TargetAssembly?.Id,
                    Native = NativeTarget(c),
                }).ToList();
            return ToolOutput.List(entries.Skip(offset).Take(limit).ToList(), offset, limit, entries.Count, CalleeRow,
                rows => new CalleeList(label, rows, offset, entries.Count), "callee", $"{label} uses:\n");
        }, cancellationToken);

        string? NativeTarget(ReferenceService.Callee c) =>
            link != null && c.Method != null && link.NativeOf(c.Method) is { } n ? NativeLinkService.Describe(n.Binding) : null;
    }

    private static string CalleeRow(CalleeEntry e) =>
        e.Node is { } n
            ? new string(' ', Math.Max(0, n.Depth - 1) * 2) + CallGraphTools.NativeLabel(n.Name, n.Address, n.Image, n.Edge, n.Flags, n.Note)
            : $"{(e.IlOffset is { } o ? $"IL_{o:X4} {e.OpCode,-10} " : "")}{e.Kind,-14} {e.Target}{(e.TargetAssembly != null ? $"  [{e.TargetAssembly}]" : "")}" +
              $"{(e.Count is { } c ? $"  x{c}" : "")}{(e.Native != null ? $"\n  -> native: {e.Native}" : "")}";

    private static string NativePage(string label, string header, List<NativeTreeNode> nodes, int offset, int limit)
    {
        var entries = nodes.Select(n => new CalleeEntry(n.Edge ?? "call", n.Name) { Node = n }).ToList();
        return ToolOutput.List(entries.Skip(offset).Take(limit).ToList(), offset, limit, entries.Count, CalleeRow,
            rows => new CalleeList(label, rows, offset, entries.Count), "callee", header);
    }
}
