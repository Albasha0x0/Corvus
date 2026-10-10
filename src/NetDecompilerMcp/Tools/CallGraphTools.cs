using System.ComponentModel;
using System.Text;
using dnlib.DotNet;
using ModelContextProtocol.Server;
using NetDecompilerMcp.Core;
using NetDecompilerMcp.Services;
using static NetDecompilerMcp.Tools.ToolSupport;

namespace NetDecompilerMcp.Tools;

[McpServerToolType]
public sealed class CallGraphTools(AssemblyWorkspace workspace, CallGraphService graph, OutputPager pager, NativeLinkService? link = null)
{
    [McpServerTool(Name = "get_call_tree", Title = "Call tree (callers / callees)")]
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
        if (link != null && SymbolResolver.ParseNative(method) is { } native)
        {
            await link.WarmUp(null, cancellationToken);
            return await Read(workspace, () => pager.Page(NativeTree(link, native, callers, levels, max, cancellationToken), offset, maxChars), cancellationToken);
        }
        if (link != null) await link.WarmUp(null, cancellationToken);
        return await Read(workspace, () =>
        {
            var sym = SymbolResolver.ResolveOne(workspace, assembly, method, SymbolKind.Method, referenced: true);
            Func<MethodDef, int, int, string>? hook = link == null ? null
                : callers ? (m, left, indent) => link.NativeCallers(m, left, indent, max, cancellationToken)
                : (m, left, indent) => link.NativeCallees(m, left, indent, max, cancellationToken);
            var text = graph.Tree(sym.Assembly, (MethodDef)sym.Member, callers, levels, max, includeExternal, cancellationToken, hook);
            return pager.Page(text, offset, maxChars);
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

    [McpServerTool(Name = "find_call_paths", Title = "Call paths to a method")]
    [Description("How execution reaches a method: call chains from 'from' to 'to', or — when 'from' is omitted — from entry points (methods nothing in the workspace calls: Main, Unity callbacks, event handlers). " +
                 "Shortest first, direct calls preferred; a hop that only happens through virtual dispatch (a call to a base/interface method this one overrides) is marked. " +
                 "'to' may be a native export: paths then end at the P/Invoke declarations bound to it, followed by the native hop.")]
    public async Task<string> FindCallPaths(
        [Description("Target method. " + SymbolOrNativeDescription)] string to,
        [Description("Start method (optional). " + SymbolDescription)] string? from = null,
        [Description("Maximum chain length (default 8).")] int maxDepth = 8,
        [Description("Maximum number of paths (default 10).")] int maxPaths = 10,
        [Description("Also follow virtual dispatch: calls to a base/interface method reaching an override (default true). False keeps only direct calls, " +
                     "which avoids chains through widely overridden methods (ToString, Dispose, interface callbacks).")] bool includeVirtual = true,
        [Description(AssemblyFilterDescription)] string? assembly = null,
        CancellationToken cancellationToken = default)
    {
        if (SymbolResolver.ParseNative(from) != null)
            throw new ToolError(ErrorCode.Unsupported, "find_call_paths starts at managed methods or entry points, not at native code.",
                "use native_call_tree with direction=callees from the native function");
        var native = link != null ? SymbolResolver.ParseNative(to) : null;
        if (native != null) await link!.WarmUp(null, cancellationToken);
        return await Read(workspace, () =>
        {
            int limit = ClampLimit(maxPaths, 200), deepest = Math.Clamp(maxDepth, 1, 30);
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
                for (int i = 0; i < path.Count; i++)
                    sb.AppendLine($"  {new string(' ', i * 2)}{(i == 0 ? "" : "-> ")}{Format.MemberLabel(path[i].Method)}" +
                                  (path[i].Via is { } via ? $"  (virtual dispatch: calls {Format.MemberLabel(via)})" : ""));
                if (nativeHop != null)
                    sb.AppendLine($"  {new string(' ', path.Count * 2)}-> native: {NativeLinkService.Describe(nativeHop.Binding)}");
            }
            return pager.Page(sb.ToString());
        }, cancellationToken);
    }
}
