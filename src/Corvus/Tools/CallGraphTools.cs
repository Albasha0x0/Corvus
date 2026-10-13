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
public sealed class CallGraphTools(AssemblyWorkspace workspace, CallGraphService graph, NativeLinkService? link = null,
    NativeCodeService? code = null, NativeEngineService? engines = null)
{
    /// <summary>Nodes a call tree walk visits at most; past it the tree is cut (totalExact=false).</summary>
    private const int MaxNodes = 20_000;

    [McpServerTool(Name = "get_call_tree", Title = "Call tree (callers / callees)", UseStructuredContent = true, OutputSchemaType = typeof(CallTree))]
    [Description("Multi-level callers or callees of a method across loaded assemblies, one row per node in tree order; calls through base / interface " +
                 "methods, repeats and recursion are marked. Continues through P/Invokes and C++/CLI into loaded native code; takes a native export too.")]
    public async Task<string> GetCallTree(
        [Description(SymbolOrNativeDescription)] string method,
        [Description("callers or callees.")] string direction = "callers",
        [Description("Levels to expand (1-8).")] int depth = 3,
        [Description("Callees: also calls into assemblies not loaded (framework).")] bool includeExternal = false,
        [Description(AssemblyFilterDescription)] string? assembly = null,
        [Description(RowOffsetDescription)] int offset = 0,
        [Description(LimitDescription)] int limit = 200,
        [Description(MaxTokensDescription)] int? maxTokens = null,
        CancellationToken cancellationToken = default)
    {
        string Page(string header, List<CallGraphService.TreeNode> nodes, string root, string direction, int levels, bool truncated) =>
            ToolOutput.List(nodes.Skip(offset).Take(limit).ToList(), offset, limit, nodes.Count, TreeRow,
                rows => new CallTree(root, direction, levels, rows, offset, nodes.Count) { TotalExact = truncated ? false : null }, "node", header, totalExact: !truncated);
        bool callers = (direction ?? "").Trim().ToLowerInvariant() switch
        {
            "callers" or "caller" or "up" or "in" => true,
            "callees" or "callee" or "down" or "out" => false,
            _ => throw new ToolError(ErrorCode.InvalidArgument, $"Unknown direction '{direction}'.", "pass direction=callers or direction=callees"),
        };
        int levels = Math.Clamp(depth, 1, 8);
        var directionName = callers ? "callers" : "callees";
        if (link != null) await link.WarmUp(null, cancellationToken);
        if (link != null && SymbolResolver.ParseNative(method) is { } native)
            return await Read(workspace, () =>
            {
                var nodes = new List<CallGraphService.TreeNode>();
                var header = NativeTree(link, native, callers, levels, nodes, cancellationToken);
                return Page(header, nodes, $"native {native}", directionName, levels, false);
            }, cancellationToken);
        return await Read(workspace, () =>
        {
            var sym = SymbolResolver.ResolveOne(workspace, assembly, method, SymbolKind.Method, referenced: true);
            CallGraphService.NativeLines? hook = link == null ? null
                : callers ? (m, left, indent, rows, parent) => link.NativeCallers(m, left, indent, MaxNodes, cancellationToken, rows, parent)
                : (m, left, indent, rows, parent) => link.NativeCallees(m, left, indent, MaxNodes, cancellationToken, rows, parent);
            var nodes = new List<CallGraphService.TreeNode>();
            var text = graph.Tree(sym.Assembly, (MethodDef)sym.Member, callers, levels, MaxNodes, includeExternal, cancellationToken, hook, nodes, out bool truncated);
            var lines = text.Split('\n');
            // The title, and the "none" line of an empty tree.
            var header = lines[0] + "\n" + (nodes.Count == 0 ? string.Concat(lines.Skip(1).Where(l => l.Trim().Length > 0).Select(l => l + "\n")) : "");
            return Page(header, nodes, $"{sym.Label} [{sym.Assembly.Id}]", directionName, levels, truncated);
        }, cancellationToken);
    }

    /// <summary>A tree node as its text line: two spaces per level below the first.</summary>
    private static string TreeRow(CallGraphService.TreeNode n)
    {
        var indent = new string(' ', Math.Max(0, n.Depth - 1) * 2);
        if (n.Token == null && n.Edge != "external") return indent + NativeLabel(n.Name, n.Address, n.Assembly, n.Edge, n.Flags, n.Note);
        var sb = new StringBuilder(indent).Append(n.Name);
        if (n.Assembly != null) sb.Append("  [").Append(n.Assembly).Append(']');
        if (n.Edge == "external") sb.Append("  (external)");
        else if (n.Note != null) sb.Append("  (").Append(n.Note).Append(')');
        return sb.ToString();
    }

    /// <summary>A native tree row as text: "native: binding" under a managed method, "import -> binding", else the function.</summary>
    internal static string NativeLabel(string name, string? address, string? image, string? edge, IReadOnlyList<string>? flags, string? note)
    {
        var sb = new StringBuilder();
        if (edge is "pinvoke" or "native") sb.Append("native: ").Append(note ?? name);
        else if (edge == "import" && note != null && !note.StartsWith("calls ", StringComparison.Ordinal)) sb.Append(name).Append(" -> ").Append(note);
        else
        {
            sb.Append(name);
            if (address != null && !name.Contains(address, StringComparison.Ordinal)) sb.Append(" at ").Append(address);
            if (image != null) sb.Append(" [").Append(image).Append(']');
            if (edge is "virtual" or "virtual?" or "dynamic" || note != null)
                sb.Append("  (").Append(edge is "virtual" or "virtual?" or "dynamic" ? edge + (note != null ? ": " : "") : "").Append(note).Append(')');
        }
        var shown = flags?.Where(f => f != "unresolved" || edge != "import").ToList();
        if (shown is { Count: > 0 }) sb.Append("  (").Append(string.Join(", ", shown.Select(f => f == "more" ? "more not shown" : f))).Append(')');
        return sb.ToString();
    }

    private static CallGraphService.TreeNode Node(NativeTreeNode n) =>
        new(n.Id, n.Parent, n.Depth, n.Name, n.Edge is "virtual?" or "dynamic" ? "derived" : "observed")
            { Assembly = n.Image, Address = n.Address, Edge = n.Edge, Flags = n.Flags, Note = n.Note };

    /// <summary>Call tree rooted at a native export: native code below or above it, and the managed methods bound to it; returns the header.</summary>
    private string NativeTree(NativeLinkService link, NativeSymbol symbol, bool callers, int depth, List<CallGraphService.TreeNode> nodes, CancellationToken ct)
    {
        var target = link.Resolve(symbol);
        var header = new StringBuilder($"{(callers ? "Callers" : "Callees")} of native {symbol}: {target.Label}  (depth {depth})\n");
        var fn = link.FunctionOf(target.Binding);
        if (fn == null)
            header.Append(target.Binding.Status == NativeLinkService.Bound
                ? "  (its image's code index is still being built or has no function there: native callers/callees are not shown)\n"
                : $"  (the code is in {target.Binding.FinalFile}, which is not loaded: load_assembly it to see native {(callers ? "callers" : "callees")})\n");
        else
        {
            var rows = new List<NativeTreeNode>();
            link.AppendTree(new StringBuilder(), fn.Value.Image, fn.Value.Function, callers, depth, MaxNodes, 1, withRoot: false, ct, rows: rows, home: fn.Value.Image);
            nodes.AddRange(rows.Select(Node));
        }
        if (!callers) return header.ToString();

        var managed = link.ManagedLinksTo(target, ct);
        foreach (var m in managed)
        {
            nodes.Add(new CallGraphService.TreeNode(nodes.Count, null, 1, Format.MemberLabel(m.Method), "observed")
                { Token = Format.Token(m.Method), Assembly = m.Assembly.Id, Edge = "pinvoke", Note = $"{m.Kind}: {NativeLinkService.Describe(m.Binding)}" });
            if (depth > 1) graph.WriteTree(new StringBuilder(), m.Assembly, m.Method, true, depth - 1, MaxNodes, false, 1, null, ct, nodes, nodes.Count - 1);
        }
        if (managed.Count == 0)
            header.Append("  (no P/Invoke declaration in the loaded assemblies binds to it; P/Invokes reaching it through a jump thunk are matched only when the thunk's image is loaded)\n");
        return header.ToString();
    }

    [McpServerTool(Name = "find_call_paths", Title = "Call paths to a method", UseStructuredContent = true, OutputSchemaType = typeof(CallPathList))]
    [Description("How execution reaches a method: call chains from 'from', or from entry points (methods nothing loaded calls), shortest first, direct " +
                 "calls preferred. A native 'to' follows native callers across loaded images and P/Invokes back to managed code (guide dotnet).")]
    public async Task<string> FindCallPaths(
        [Description("Target. " + SymbolOrNativeDescription)] string to,
        [Description("Start method, same forms as to (native only when to is native).")] string? from = null,
        [Description("Max chain length (max 30).")] int maxDepth = 8,
        [Description(LimitDescription)] int limit = 10,
        [Description(RowOffsetDescription)] int offset = 0,
        [Description("No hops through virtual dispatch (native: RTTI virtual calls, pointers).")] bool directOnly = false,
        [Description(AssemblyFilterDescription)] string? assembly = null,
        CancellationToken cancellationToken = default)
    {
        bool includeVirtual = !directOnly;
        var native = link != null ? SymbolResolver.ParseNative(to) : null;
        var nativeFrom = SymbolResolver.ParseNative(from);
        if (nativeFrom != null && native == null)
            throw new ToolError(ErrorCode.Unsupported, "A native 'from' needs a native 'to': chains are followed from native code into native code.",
                "pass to as native:<image>!<function>, or use native_call_tree with direction=callees from the native function");
        if (native != null) await link!.WarmUp(null, cancellationToken);
        // 'from' is looked up in the assembly first (another loaded build defines it too), then anywhere: it may call in from another assembly.
        ResolvedSymbol ResolveStart(string symbol)
        {
            if (assembly != null)
                try { return SymbolResolver.ResolveOne(workspace, assembly, symbol, SymbolKind.Method); }
                catch (ToolError e) when (e.Code == ErrorCode.NotFound) { }
            return SymbolResolver.ResolveOne(workspace, null, symbol, SymbolKind.Method);
        }
        return await Read(workspace, () =>
        {
            int wanted = End(offset, limit), deepest = Math.Clamp(maxDepth, 1, 30);
            if (native != null && code != null)
            {
                NativeLinkService.NativeTarget? resolved = null;
                ToolError? unresolved = null;
                try { resolved = link!.Resolve(native); }
                catch (ToolError e) when (e.Code == ErrorCode.NotFound) { unresolved = e; }
                if (resolved != null && link!.FunctionOf(resolved.Binding) is { } goal)
                    return NativePaths(native, new NativeNode(goal.Image, goal.Function.Start), null, nativeFrom, from, deepest, offset, limit, includeVirtual, cancellationToken);
                // the provider is not loaded (or not found, as an ELF or Mach-O library on Windows): the calls through its imports in loaded images
                // an import slot named by address in a loaded image: the calls through that import
                var symbol = native;
                if (resolved?.Binding is { Target: { } owner, Rva: { } slotRva } && owner.Image.Imports.FirstOrDefault(i => i.SlotRva == slotRva) is { Name: { } importName } slotImport)
                    symbol = new NativeSymbol(slotImport.Module, importName);
                var through = link!.ImportCallers(symbol, cancellationToken);
                if (through.Count > 0)
                {
                    var (image, import, _, _) = through[0];
                    var goalNode = new NativeNode(image, import.SlotRva);
                    var hops = through.Select(t => new NativeHop(new NativeNode(t.Image, t.Caller.Start), goalNode, "import", t.Site)).ToList();
                    // each importer's own slot, for the last step of its chains
                    var slots = through.GroupBy(t => t.Image).ToDictionary(g => g.Key, g => g.First().Import.SlotRva);
                    return NativePaths(symbol, goalNode, hops, nativeFrom, from, deepest, offset, limit, includeVirtual, cancellationToken, resolved, slots);
                }
                if (unresolved != null) throw unresolved;
            }
            if (nativeFrom != null)
                throw new ToolError(ErrorCode.NotFound, $"{native} has no function in an indexed image: native chains need its code loaded.", "load the image that holds its code with load_assembly");
            var start = from == null ? null : ResolveStart(from);
            var found = new List<(List<CallGraphService.PathStep> Path, NativeLinkService.ManagedLink? Native)>();
            string label;
            if (native != null)
            {
                var target = link!.Resolve(native);
                label = $"native {native} ({target.Label})";
                foreach (var m in link.ManagedLinksTo(target, cancellationToken))
                    found.AddRange(graph.PathSteps((MethodDef?)start?.Member, m.Method, Math.Max(1, deepest - 1), wanted, includeVirtual, cancellationToken)
                        .Select(p => (p, (NativeLinkService.ManagedLink?)m)));
                found = found.OrderBy(p => p.Path.Count).ThenBy(p => p.Path.Count(s => s.Via != null)).ToList();
            }
            else
            {
                var target = SymbolResolver.ResolveOne(workspace, assembly, to, SymbolKind.Method, referenced: true);
                label = target.Label;
                found.AddRange(graph.PathSteps((MethodDef?)start?.Member, (MethodDef)target.Member, deepest, wanted, includeVirtual, cancellationToken)
                    .Select(p => (p, (NativeLinkService.ManagedLink?)null)));
            }
            // The search stops at offset + limit paths: reaching that many means there may be more.
            bool cut = found.Count >= wanted;
            found = found.Take(wanted).ToList();
            var header = $"Paths to {label}{(start != null ? $" from {start.Label}" : " from entry points")}: ";
            if (found.Count == 0)
                header += (native != null
                    ? "none: no P/Invoke declaration in the loaded assemblies binds to it, or nothing reaches those declarations."
                    : start != null
                        ? $"none within {deepest} calls (raise maxDepth{(includeVirtual ? "" : ", drop directOnly")}, or the call happens through reflection/delegates/events)."
                        : "none: nothing in the loaded assemblies reaches it (it may be called by the runtime, reflection, or unloaded code).") + "\n";
            int n = 0;
            var items = found.Select(p =>
            {
                int virtualHops = p.Path.Count(s => s.Via != null);
                var text = new StringBuilder($"#{++n} ({Plural(p.Path.Count, "method")}{(virtualHops > 0 ? $", {Plural(virtualHops, "virtual hop")}" : "")})\n");
                AppendManaged(text, p.Path);
                var nativeHop = p.Native is { } hop ? NativeLinkService.Describe(hop.Binding) : null;
                if (nativeHop != null) text.Append($"  {new string(' ', p.Path.Count * 2)}-> native: {nativeHop}\n");
                return (new CallPathEntry(ManagedSteps(p.Path), virtualHops) { NativeHop = nativeHop }, text.ToString().ReplaceLineEndings("\n").TrimEnd('\n'));
            }).ToList();
            return PathList(label, start?.Label, items, offset, limit, cut, header, null);
        }, cancellationToken);
    }

    private static string PathList(string label, string? from, List<(CallPathEntry Entry, string Text)> all, int offset, int limit, bool cut, string header, string? engine)
    {
        if (engine != null) ToolOutput.Engine(engine, "references from the engine session open on the image join the built-in index (basis=derived on those steps)");
        return ToolOutput.List(all.Skip(offset).Take(limit).ToList(), offset, limit, all.Count, p => p.Text,
            rows => new CallPathList(label, rows.Select(r => r.Entry).ToList(), offset, all.Count) { From = from, TotalExact = cut ? false : null, Engine = engine },
            "path", header, totalExact: !cut);
    }

    private static void AppendManaged(StringBuilder sb, List<CallGraphService.PathStep> path)
    {
        for (int i = 0; i < path.Count; i++)
            sb.AppendLine($"  {new string(' ', i * 2)}{(i == 0 ? "" : "-> ")}{Format.MemberLabel(path[i].Method)}" +
                          (path[i].Via is { } via ? $"  (virtual dispatch: calls {Format.MemberLabel(via)})" : ""));
    }

    /// <summary>Path steps; the assembly only where it changes from the previous step.</summary>
    private List<PathStepEntry> ManagedSteps(List<CallGraphService.PathStep> path)
    {
        string? previous = null;
        var steps = new List<PathStepEntry>();
        foreach (var s in path)
        {
            var asm = workspace.FindByModule(s.Method.Module)?.Id;
            steps.Add(new PathStepEntry(Format.MemberLabel(s.Method))
            {
                Token = Format.Token(s.Method),
                Assembly = asm != previous ? asm : null,
                Via = s.Via is { } via ? Format.MemberLabel(via) : null,
                Basis = s.Via != null ? "derived" : "observed",
            });
            previous = asm;
        }
        return steps;
    }

    /// <summary>A chain to native code: managed steps (when it enters through P/Invoke), then native steps.</summary>
    private sealed record Chain(List<CallGraphService.PathStep> Managed, NativeLinkService.ManagedLink? Link, NativeChain Native)
    {
        public int Steps => Managed.Count + Native.Hops.Count + 1;
        public int Uncertain => Managed.Count(s => s.Via != null) + Native.Uncertain;
    }

    /// <summary>
    /// Native goal: chains through native callers (bounded backward search, then bounded enumeration), from 'from', or from
    /// native roots and from managed methods bound to the code on the way.
    /// </summary>
    /// <param name="goalCallers">For an import goal (the slot in one importer): the calls through the imports that name it, in every importer.</param>
    /// <param name="direct">For an import goal: the export it resolves to, whose P/Invoke declarations also reach it.</param>
    private string NativePaths(NativeSymbol symbol, NativeNode goalNode, IReadOnlyList<NativeHop>? goalCallers, NativeSymbol? nativeFrom, string? from, int deepest,
        int offset, int limit, bool includeVirtual, CancellationToken ct, NativeLinkService.NativeTarget? direct = null, IReadOnlyDictionary<LoadedNative, uint>? goalSlots = null)
    {
        int wanted = End(offset, limit);
        var paths = new NativeCallPaths(link!, code!) { EngineCallers = engines != null ? NativeCallPaths.FromEngines(engines, code!, ct) : null };
        var label = goalCallers != null
            ? $"native {symbol} (imported by {string.Join(", ", goalCallers.Select(h => h.From.Image.Id).Distinct())}; its library is not loaded)"
            : $"native {symbol} ([{goalNode.Image.Id}] {NativeName(goalNode)} at {NativeAddress.Va(goalNode.Image.Image, goalNode.Start)})";
        NativeNode? fromNode = null;
        if (nativeFrom != null)
            fromNode = link!.FunctionOf(link.Resolve(nativeFrom).Binding) is { } f ? new NativeNode(f.Image, f.Function.Start)
                : throw new ToolError(ErrorCode.NotFound, $"{nativeFrom} has no function in an indexed image.", "load the image that holds its code with load_assembly");
        var start = from != null && nativeFrom == null ? SymbolResolver.ResolveOne(workspace, null, from, SymbolKind.Method) : null;
        var explored = paths.Explore(goalNode, deepest, includeVirtual, ct, goalCallers);
        if (direct != null)
            foreach (var m in link!.ManagedLinksTo(direct, ct)) explored.Managed.Add(new ManagedEntry(m, goalNode, 0));
        var chains = new List<Chain>();
        bool truncated = explored.Cut;
        if (fromNode is { } fnode)
        {
            var (found, cut) = explored.Chains([(fnode, "from")], wanted, ct);
            chains.AddRange(found.Select(c => new Chain([], null, c)));
            truncated |= cut;
        }
        else
        {
            if (start == null)
            {
                var (found, cut) = explored.Chains(explored.Roots, wanted, ct);
                chains.AddRange(found.Select(c => new Chain([], null, c)));
                truncated |= cut;
            }
            foreach (var entry in explored.Managed.DistinctBy(e => e.Link.Method).OrderBy(e => e.Distance))
            {
                if (chains.Count >= 4 * wanted) { truncated = true; break; }
                var (suffix, _) = explored.Chains([(entry.Node, "P/Invoke")], 1, ct);
                if (suffix.Count == 0) continue;
                foreach (var prefix in graph.PathSteps((MethodDef?)start?.Member, entry.Link.Method, Math.Max(1, deepest - entry.Distance - 1), wanted, includeVirtual, ct))
                    chains.Add(new Chain(prefix, entry.Link, suffix[0]));
            }
        }
        var ranked = chains.OrderBy(c => c.Steps).ThenBy(c => c.Uncertain).ThenBy(c => c.Native.CrossImage)
            .ThenBy(c => NativeCallGraph.RootRank(c.Native.Root)).ThenBy(c => c.Native.First.Start).ToList();
        truncated |= ranked.Count > wanted;
        ranked = ranked.Take(wanted).ToList();

        var header = new StringBuilder($"Paths to {label}{(fromNode != null ? $" from {nativeFrom}" : start != null ? $" from {start.Label}" : " from entry points")}" +
                                       $" ({Plural(explored.Visited, "function")} explored backward): ");
        if (ranked.Count == 0)
            header.Append(explored.Frontier > 0
                ? $"none within {deepest} calls: {Plural(explored.Frontier, "function")} at the limit still have callers (raise maxDepth{(includeVirtual ? "" : ", or drop directOnly")}).\n"
                : fromNode != null || start != null
                    ? $"none: {(fromNode != null ? nativeFrom!.ToString() : start!.Label)} does not reach it through the calls the index knows{(includeVirtual ? "" : " (directOnly=true)")}.\n"
                    : "none: no root reaches it through the calls the index knows (it may be called through an unresolved pointer: resolve_call_targets scope=image).\n");
        else header.Append('\n');
        if (explored.Frontier > 0 && ranked.Count > 0) header.Append($"Partial: {Plural(explored.Frontier, "function")} at maxDepth={deepest} have callers not explored\n");
        foreach (var note in explored.Notes) header.Append("Note: ").Append(note).Append('\n');
        string? engine = null;
        int n = 0;
        var items = new List<(CallPathEntry, string)>();
        foreach (var c in ranked)
        {
            var sb = new StringBuilder($"#{++n} ({Plural(c.Native.Hops.Count, "native call")}{(c.Managed.Count > 0 ? $" after {Plural(c.Managed.Count, "managed method")} and P/Invoke" : "")}" +
                                       $"{(c.Uncertain > 0 ? $", {Plural(c.Uncertain, "uncertain hop")}" : "")}; root: {(c.Managed.Count > 0 ? "managed" : c.Native.Root)})\n");
            var steps = ManagedSteps(c.Managed);
            AppendManaged(sb, c.Managed);
            int indent = c.Managed.Count;
            if (c.Link != null) sb.Append($"  {new string(' ', indent * 2)}-> native: {NativeLinkService.Describe(c.Link.Binding)}\n");
            sb.Append($"  {new string(' ', indent * 2)}{(indent > 0 ? "-> " : "")}{NativeStep(c.Native.First)}{(c.Managed.Count == 0 ? $"  ({c.Native.Root})" : "")}\n");
            string? previous = steps.LastOrDefault(s => s.Assembly != null)?.Assembly;
            steps.Add(NativeEntry(c.Native.First, null, c.Link != null ? "pinvoke" : null, ref previous));
            foreach (var hop in c.Native.Hops)
            {
                indent++;
                var to = hop.To == goalNode && goalSlots != null && goalSlots.TryGetValue(hop.From.Image, out uint own) ? new NativeNode(hop.From.Image, own) : hop.To;
                sb.Append($"  {new string(' ', indent * 2)}-> {NativeStep(to)}  ({hop.Edge} at {NativeAddress.Va(hop.From.Image.Image, hop.Site)})\n");
                steps.Add(NativeEntry(to, NativeAddress.Va(hop.From.Image.Image, hop.Site), hop.Edge, ref previous));
                if (hop.Edge == "engine" && engines?.OpenSession(hop.From.Image) is { } session) engine ??= session.ProviderId;
            }
            items.Add((new CallPathEntry(steps, c.Managed.Count(s => s.Via != null) + c.Native.Hops.Count(h => h.Edge.StartsWith("virtual", StringComparison.Ordinal)))
                { NativeHop = c.Link != null ? NativeLinkService.Describe(c.Link.Binding) : null, Root = c.Managed.Count > 0 ? "managed" : c.Native.Root }, sb.ToString().ReplaceLineEndings("\n").TrimEnd('\n')));
        }
        return PathList(label, fromNode != null ? nativeFrom!.ToString() : start?.Label, items, offset, limit, truncated, header.ToString(), engine);
    }

    private string NativeName(NativeNode n) =>
        code!.Ready(n.Image) is { } index ? index.NameAt(n.Start) ?? index.FunctionByStart(n.Start)?.Name ?? $"sub_{n.Start:X}" : $"sub_{n.Start:X}";

    private string NativeStep(NativeNode n) => $"[{n.Image.Id}] {NativeName(n)} at {NativeAddress.Va(n.Image.Image, n.Start)}";

    /// <summary>A native step: derived when only an engine reference, a possible virtual target or a resolved pointer reaches it.</summary>
    private PathStepEntry NativeEntry(NativeNode n, string? site, string? edge, ref string? previous)
    {
        var image = n.Image.Id;
        var step = new PathStepEntry(NativeName(n))
        {
            Token = NativeAddress.Va(n.Image.Image, n.Start),
            Assembly = image != previous ? image : null,
            Site = site,
            Edge = edge,
            Basis = edge is "engine" or "virtual_possible" or "pointer" ? "derived" : "observed",
        };
        previous = image;
        return step;
    }
}
