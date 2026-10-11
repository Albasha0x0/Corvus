using System.ComponentModel;
using System.Text;
using dnlib.DotNet;
using ModelContextProtocol.Server;
using NetDecompilerMcp.Core;
using NetDecompilerMcp.Mcp;
using NetDecompilerMcp.Native;
using NetDecompilerMcp.Services;
using static NetDecompilerMcp.Tools.ToolSupport;

namespace NetDecompilerMcp.Tools;

[McpServerToolType]
public sealed class CallGraphTools(AssemblyWorkspace workspace, CallGraphService graph, OutputPager pager, NativeLinkService? link = null,
    NativeCodeService? code = null)
{
    [McpServerTool(Name = "get_call_tree", Title = "Call tree (callers / callees)", UseStructuredContent = true, OutputSchemaType = typeof(CallTree))]
    [Description("Multi-level call tree of a method across all loaded assemblies: direction=callers (who calls it, who calls those...) or callees (what it calls, recursively). " +
                 "Callers include calls through base/interface methods it overrides or implements. Repeated nodes and recursion are marked instead of expanded again. " +
                 "Callees continue into native code: a P/Invoke (or a native method body of a mixed-mode C++/CLI assembly) shows 'native: module!export -> " +
                 "PROVIDER!export at VA [image]' and, when that image is loaded, the native callees below it (disassemble works with the image and VA shown). " +
                 "Callers of a managed method called from native code (C++/CLI thunks) list those native callers. Given a native export, " +
                 "callers lists native call sites in loaded images and the P/Invoke declarations bound to it with their managed callers.")]
    public async Task<string> GetCallTree(
        [Description("Method. " + SymbolOrNativeDescription)] string method,
        [Description("callers or callees.")] string direction = "callers",
        [Description("Levels to expand (1-8, default 3).")] int depth = 3,
        [Description("Stop after this many nodes (default 300).")] int maxNodes = 300,
        [Description("For callees: also list calls into assemblies that are not loaded (framework).")] bool includeExternal = false,
        [Description(AssemblyFilterDescription)] string? assembly = null,
        [Description(OffsetDescription)] int offset = 0,
        [Description(MaxCharsDescription)] int? maxChars = null,
        CancellationToken cancellationToken = default)
    {
        bool callers = (direction ?? "").Trim().ToLowerInvariant() switch
        {
            "callers" or "caller" or "up" or "in" => true,
            "callees" or "callee" or "down" or "out" => false,
            _ => throw new ToolError(ErrorCode.InvalidArgument, $"Unknown direction '{direction}'. Use callers or callees."),
        };
        int levels = Math.Clamp(depth, 1, 8), max = ClampLimit(maxNodes, 20_000);
        var directionName = callers ? "callers" : "callees";
        if (link != null && SymbolResolver.ParseNative(method) is { } native)
        {
            await link.WarmUp(null, cancellationToken);
            return await Read(workspace, () =>
            {
                var text = NativeTree(link, native, callers, levels, max, cancellationToken);
                // Lines below the header, two spaces per level.
                var nodes = ReferenceTools.Lines(text).Skip(1)
                    .Select(l => new CallGraphService.TreeNode(Math.Max(1, (l.Length - l.TrimStart(' ').Length) / 2), l.Trim(), null, "native", null)).ToList();
                return StructuredOutput.With(pager.Page(text, offset, maxChars), new CallTree($"native {native}", directionName, levels, nodes, nodes.Count, false));
            }, cancellationToken);
        }
        if (link != null) await link.WarmUp(null, cancellationToken);
        return await Read(workspace, () =>
        {
            var sym = SymbolResolver.ResolveOne(workspace, assembly, method, SymbolKind.Method, referenced: true);
            Func<MethodDef, int, int, string>? hook = link == null ? null
                : callers ? (m, left, indent) => link.NativeCallers(m, left, indent, max, cancellationToken)
                : (m, left, indent) => link.NativeCallees(m, left, indent, max, cancellationToken);
            var nodes = new List<CallGraphService.TreeNode>();
            var text = graph.Tree(sym.Assembly, (MethodDef)sym.Member, callers, levels, max, includeExternal, cancellationToken, hook, nodes, out bool truncated);
            return StructuredOutput.With(pager.Page(text, offset, maxChars),
                new CallTree($"{sym.Label} [{sym.Assembly.Id}]", directionName, levels, nodes, nodes.Count, truncated));
        }, cancellationToken);
    }

    /// <summary>Call tree rooted at a native export: native code below or above it, and the managed methods bound to it.</summary>
    private string NativeTree(NativeLinkService link, NativeSymbol symbol, bool callers, int depth, int maxNodes, CancellationToken ct)
    {
        var target = link.Resolve(symbol);
        var sb = new StringBuilder($"{(callers ? "Callers" : "Callees")} of native {symbol}: {target.Label}  (depth {depth})\n");
        var fn = link.FunctionOf(target.Binding);
        if (fn == null)
            sb.AppendLine(target.Binding.Status == NativeLinkService.Bound
                ? "  (its image's code index is still being built or has no function there: native callers/callees are not shown)"
                : $"  (the code is in {target.Binding.FinalFile}, which is not loaded: load_assembly it to see native {(callers ? "callers" : "callees")})");
        else
            link.AppendTree(sb, fn.Value.Image, fn.Value.Function, callers, depth, maxNodes, 1, withRoot: false, ct);
        if (!callers) return sb.ToString();

        var managed = link.ManagedLinksTo(target, ct);
        foreach (var m in managed)
        {
            sb.AppendLine($"  {Format.MemberLabel(m.Method)}  [{m.Assembly.Id}]  ({m.Kind}: {NativeLinkService.Describe(m.Binding)})");
            if (depth > 1) graph.WriteTree(sb, m.Assembly, m.Method, true, depth - 1, maxNodes, false, 1, null, ct);
        }
        if (managed.Count == 0)
            sb.AppendLine("  (no P/Invoke declaration in the loaded assemblies binds to it; P/Invokes reaching it through a jump thunk are matched only when the thunk's image is loaded)");
        return sb.ToString();
    }

    [McpServerTool(Name = "find_call_paths", Title = "Call paths to a method", UseStructuredContent = true, OutputSchemaType = typeof(CallPathList))]
    [Description("How execution reaches a method: call chains from 'from' to 'to', or — when 'from' is omitted — from entry points (methods nothing in the workspace calls: Main, Unity callbacks, event handlers). " +
                 "Shortest first, direct calls preferred; a hop that only happens through virtual dispatch (a call to a base/interface method this one overrides) is marked. " +
                 "'to' may be native code (an export, or native:<image>!<address or function>): chains then run through native callers across loaded images " +
                 "(calls, tail calls, imports bound between images, RTTI virtual calls, function pointers resolve_call_targets resolved) back to native roots " +
                 "(entry point, exports, TLS callbacks, callbacks, uncalled functions) and to managed methods through P/Invoke; 'from' may then be native too. " +
                 "Each native step carries its call site and edge kind; chains are ranked by length, uncertain hops and image changes.")]
    public async Task<string> FindCallPaths(
        [Description("Target method. " + SymbolOrNativeDescription)] string to,
        [Description("Start method (optional): managed, or native (same forms as to) when to is native. " + SymbolDescription)] string? from = null,
        [Description("Maximum chain length (default 8, max 30).")] int maxDepth = 8,
        [Description("Maximum number of paths (default 10).")] int maxPaths = 10,
        [Description("Also follow virtual dispatch: calls to a base/interface method reaching an override (default true). False keeps only direct calls, " +
                     "which avoids chains through widely overridden methods (ToString, Dispose, interface callbacks). In native code: RTTI virtual calls and resolved function pointers.")] bool includeVirtual = true,
        [Description(AssemblyFilterDescription)] string? assembly = null,
        CancellationToken cancellationToken = default)
    {
        var native = link != null ? SymbolResolver.ParseNative(to) : null;
        var nativeFrom = SymbolResolver.ParseNative(from);
        if (nativeFrom != null && native == null)
            throw new ToolError(ErrorCode.Unsupported, "A native 'from' needs a native 'to': chains are followed from native code into native code.",
                "pass to as native:<image>!<function>, or use native_call_tree with direction=callees from the native function");
        if (native != null) await link!.WarmUp(null, cancellationToken);
        return await Read(workspace, () =>
        {
            int limit = ClampLimit(maxPaths, 200), deepest = Math.Clamp(maxDepth, 1, 30);
            if (native != null && code != null && link!.FunctionOf(link.Resolve(native).Binding) is { } goal)
                return NativePaths(native, goal, nativeFrom, from, deepest, limit, includeVirtual, cancellationToken);
            if (nativeFrom != null)
                throw new ToolError(ErrorCode.NotFound, $"{native} has no function in an indexed image: native chains need its code loaded.", "load the image that holds its code with load_assembly");
            var start = from == null ? null : SymbolResolver.ResolveOne(workspace, null, from, SymbolKind.Method);
            var found = new List<(List<CallGraphService.PathStep> Path, NativeLinkService.ManagedLink? Native)>();
            string label;
            if (native != null)
            {
                var target = link!.Resolve(native);
                label = $"native {native} ({target.Label})";
                foreach (var m in link.ManagedLinksTo(target, cancellationToken))
                    found.AddRange(graph.PathSteps((MethodDef?)start?.Member, m.Method, Math.Max(1, deepest - 1), limit, includeVirtual, cancellationToken)
                        .Select(p => (p, (NativeLinkService.ManagedLink?)m)));
                found = found.OrderBy(p => p.Path.Count).ThenBy(p => p.Path.Count(s => s.Via != null)).Take(limit).ToList();
            }
            else
            {
                var target = SymbolResolver.ResolveOne(workspace, assembly, to, SymbolKind.Method, referenced: true);
                label = target.Label;
                found.AddRange(graph.PathSteps((MethodDef?)start?.Member, (MethodDef)target.Member, deepest, limit, includeVirtual, cancellationToken)
                    .Select(p => (p, (NativeLinkService.ManagedLink?)null)));
            }
            var sb = new StringBuilder($"{Plural(found.Count, "path")} to {label}{(start != null ? $" from {start.Label}" : " from entry points")}:\n");
            if (found.Count == 0)
                sb.AppendLine(native != null
                    ? "  none: no P/Invoke declaration in the loaded assemblies binds to it, or nothing reaches those declarations."
                    : start != null
                        ? $"  none within {maxDepth} calls (raise maxDepth{(includeVirtual ? "" : ", allow includeVirtual")}, or the call happens through reflection/delegates/events)."
                        : "  none: nothing in the loaded assemblies reaches it (it may be called by the runtime, reflection, or unloaded code).");
            int n = 0;
            foreach (var (path, nativeHop) in found)
            {
                int virtualHops = path.Count(s => s.Via != null);
                sb.AppendLine($"\n#{++n} ({path.Count} methods{(virtualHops > 0 ? $", {Plural(virtualHops, "virtual hop")}" : "")})");
                AppendManaged(sb, path);
                if (nativeHop != null)
                    sb.AppendLine($"  {new string(' ', path.Count * 2)}-> native: {NativeLinkService.Describe(nativeHop.Binding)}");
            }
            var items = found.Select(p => new CallPathEntry(ManagedSteps(p.Path), p.Path.Count(s => s.Via != null),
                p.Native is { } hop ? NativeLinkService.Describe(hop.Binding) : null)).ToList();
            return StructuredOutput.With(pager.Page(sb.ToString()), new CallPathList(label, start?.Label, items, items.Count, false));
        }, cancellationToken);
    }

    private static void AppendManaged(StringBuilder sb, List<CallGraphService.PathStep> path)
    {
        for (int i = 0; i < path.Count; i++)
            sb.AppendLine($"  {new string(' ', i * 2)}{(i == 0 ? "" : "-> ")}{Format.MemberLabel(path[i].Method)}" +
                          (path[i].Via is { } via ? $"  (virtual dispatch: calls {Format.MemberLabel(via)})" : ""));
    }

    private List<PathStepEntry> ManagedSteps(List<CallGraphService.PathStep> path) =>
        path.Select(s => new PathStepEntry(new SymbolRef("method", Format.MemberLabel(s.Method), workspace.FindByModule(s.Method.Module)?.Id ?? "",
            Format.Token(s.Method)), s.Via is { } via ? Format.MemberLabel(via) : null)).ToList();

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
    private string NativePaths(NativeSymbol symbol, (LoadedNative Image, Native.Code.NativeFunction Function) goal, NativeSymbol? nativeFrom, string? from, int deepest,
        int limit, bool includeVirtual, CancellationToken ct)
    {
        var paths = new NativeCallPaths(link!, code!);
        var goalNode = new NativeNode(goal.Image, goal.Function.Start);
        var label = $"native {symbol} ([{goal.Image.Id}] {NativeName(goalNode)} at {NativeAddress.Va(goal.Image.Image, goalNode.Start)})";
        NativeNode? fromNode = null;
        if (nativeFrom != null)
            fromNode = link!.FunctionOf(link.Resolve(nativeFrom).Binding) is { } f ? new NativeNode(f.Image, f.Function.Start)
                : throw new ToolError(ErrorCode.NotFound, $"{nativeFrom} has no function in an indexed image.", "load the image that holds its code with load_assembly");
        var start = from != null && nativeFrom == null ? SymbolResolver.ResolveOne(workspace, null, from, SymbolKind.Method) : null;
        var explored = paths.Explore(goalNode, deepest, includeVirtual, ct);
        var chains = new List<Chain>();
        bool truncated = explored.Cut;
        if (fromNode is { } fnode)
        {
            var (found, cut) = explored.Chains([(fnode, "from")], limit, ct);
            chains.AddRange(found.Select(c => new Chain([], null, c)));
            truncated |= cut;
        }
        else
        {
            if (start == null)
            {
                var (found, cut) = explored.Chains(explored.Roots, limit, ct);
                chains.AddRange(found.Select(c => new Chain([], null, c)));
                truncated |= cut;
            }
            foreach (var entry in explored.Managed.DistinctBy(e => e.Link.Method).OrderBy(e => e.Distance))
            {
                if (chains.Count >= 4 * limit) { truncated = true; break; }
                var (suffix, _) = explored.Chains([(entry.Node, "P/Invoke")], 1, ct);
                if (suffix.Count == 0) continue;
                foreach (var prefix in graph.PathSteps((MethodDef?)start?.Member, entry.Link.Method, Math.Max(1, deepest - entry.Distance - 1), limit, includeVirtual, ct))
                    chains.Add(new Chain(prefix, entry.Link, suffix[0]));
            }
        }
        var ranked = chains.OrderBy(c => c.Steps).ThenBy(c => c.Uncertain).ThenBy(c => c.Native.CrossImage)
            .ThenBy(c => NativeCallGraph.RootRank(c.Native.Root)).ThenBy(c => c.Native.First.Start).ToList();
        truncated |= ranked.Count > limit;
        ranked = ranked.Take(limit).ToList();

        var sb = new StringBuilder($"{Plural(ranked.Count, "path")} to {label}{(fromNode != null ? $" from {nativeFrom}" : start != null ? $" from {start.Label}" : " from entry points")}" +
                                   $" ({Plural(explored.Visited, "function")} explored backward):\n");
        if (ranked.Count == 0)
            sb.AppendLine(explored.Frontier > 0
                ? $"  none within {deepest} calls: {Plural(explored.Frontier, "function")} at the limit still have callers (raise maxDepth{(includeVirtual ? "" : ", or allow includeVirtual")})."
                : fromNode != null || start != null
                    ? $"  none: {(fromNode != null ? nativeFrom!.ToString() : start!.Label)} does not reach it through the calls the index knows{(includeVirtual ? "" : " (includeVirtual=false)")}."
                    : "  none: no root reaches it through the calls the index knows (it may be called through an unresolved pointer: resolve_call_targets scope=image).");
        int n = 0;
        var items = new List<CallPathEntry>();
        foreach (var c in ranked)
        {
            var steps = ManagedSteps(c.Managed);
            sb.AppendLine($"\n#{++n} ({Plural(c.Native.Hops.Count, "native call")}{(c.Managed.Count > 0 ? $" after {Plural(c.Managed.Count, "managed method")} and P/Invoke" : "")}" +
                          $"{(c.Uncertain > 0 ? $", {Plural(c.Uncertain, "uncertain hop")}" : "")}; root: {(c.Managed.Count > 0 ? "managed" : c.Native.Root)})");
            AppendManaged(sb, c.Managed);
            int indent = c.Managed.Count;
            if (c.Link != null) sb.AppendLine($"  {new string(' ', indent * 2)}-> native: {NativeLinkService.Describe(c.Link.Binding)}");
            sb.AppendLine($"  {new string(' ', indent * 2)}{(indent > 0 ? "-> " : "")}{NativeStep(c.Native.First)}{(c.Managed.Count == 0 ? $"  ({c.Native.Root})" : "")}");
            steps.Add(NativeEntry(c.Native.First, null, c.Link != null ? "pinvoke" : null));
            foreach (var hop in c.Native.Hops)
            {
                indent++;
                sb.AppendLine($"  {new string(' ', indent * 2)}-> {NativeStep(hop.To)}  ({hop.Edge} at {NativeAddress.Va(hop.From.Image.Image, hop.Site)})");
                steps.Add(NativeEntry(hop.To, NativeAddress.Va(hop.From.Image.Image, hop.Site), hop.Edge));
            }
            items.Add(new CallPathEntry(steps, c.Managed.Count(s => s.Via != null) + c.Native.Hops.Count(h => h.Edge.StartsWith("virtual", StringComparison.Ordinal)),
                c.Link != null ? NativeLinkService.Describe(c.Link.Binding) : null, c.Managed.Count > 0 ? "managed" : c.Native.Root));
        }
        if (truncated) sb.AppendLine($"\n[More paths exist: raise maxPaths (now {limit}) or give from]");
        if (explored.Frontier > 0 && ranked.Count > 0) sb.AppendLine($"Note: {Plural(explored.Frontier, "function")} at maxDepth={deepest} have callers not explored");
        foreach (var note in explored.Notes) sb.AppendLine("Note: " + note);
        return StructuredOutput.With(pager.Page(sb.ToString()), new CallPathList(label, fromNode != null ? nativeFrom!.ToString() : start?.Label, items, items.Count, truncated));
    }

    private string NativeName(NativeNode n) =>
        code!.Ready(n.Image) is { } index ? index.NameAt(n.Start) ?? index.FunctionByStart(n.Start)?.Name ?? $"sub_{n.Start:X}" : $"sub_{n.Start:X}";

    private string NativeStep(NativeNode n) => $"[{n.Image.Id}] {NativeName(n)} at {NativeAddress.Va(n.Image.Image, n.Start)}";

    private PathStepEntry NativeEntry(NativeNode n, string? site, string? edge) =>
        new(new SymbolRef("native_function", NativeName(n), n.Image.Id, NativeAddress.Va(n.Image.Image, n.Start)), null, site, edge);
}
