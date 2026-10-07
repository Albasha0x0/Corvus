using System.ComponentModel;
using System.Text;
using dnlib.DotNet;
using ModelContextProtocol.Server;
using NetDecompilerMcp.Core;
using NetDecompilerMcp.Services;
using static NetDecompilerMcp.Tools.ToolSupport;

namespace NetDecompilerMcp.Tools;

[McpServerToolType]
public sealed class CallGraphTools(AssemblyWorkspace workspace, CallGraphService graph, OutputPager pager)
{
    [McpServerTool(Name = "get_call_tree", Title = "Call tree (callers / callees)", ReadOnly = true, OpenWorld = false)]
    [Description("Multi-level call tree of a method across all loaded assemblies: direction=callers (who calls it, who calls those...) or callees (what it calls, recursively). " +
                 "Callers include calls through base/interface methods it overrides or implements. Repeated nodes and recursion are marked instead of expanded again.")]
    public Task<string> GetCallTree(
        [Description("Method. " + SymbolDescription)] string method,
        [Description("callers or callees.")] string direction = "callers",
        [Description("Levels to expand (1-8, default 3).")] int depth = 3,
        [Description("Stop after this many nodes (default 300).")] int maxNodes = 300,
        [Description("For callees: also list calls into assemblies that are not loaded (framework).")] bool includeExternal = false,
        [Description(AssemblyFilterDescription)] string? assembly = null,
        [Description(OffsetDescription)] int offset = 0,
        [Description(MaxCharsDescription)] int? maxChars = null,
        CancellationToken cancellationToken = default) => Read(workspace, () =>
    {
        var sym = SymbolResolver.ResolveOne(workspace, assembly, method, SymbolKind.Method);
        bool callers = direction.Trim().ToLowerInvariant() switch
        {
            "callers" or "caller" or "up" or "in" => true,
            "callees" or "callee" or "down" or "out" => false,
            _ => throw new ToolError($"Unknown direction '{direction}'. Use callers or callees."),
        };
        var text = graph.Tree(sym.Assembly, (MethodDef)sym.Member, callers, Math.Clamp(depth, 1, 8), ClampLimit(maxNodes, 20_000), includeExternal, cancellationToken);
        return pager.Page(text, offset, maxChars);
    }, cancellationToken);

    [McpServerTool(Name = "find_call_paths", Title = "Call paths to a method", ReadOnly = true, OpenWorld = false)]
    [Description("How execution reaches a method: call chains from 'from' to 'to', or — when 'from' is omitted — from entry points (methods nothing in the workspace calls: Main, Unity callbacks, event handlers). Shortest first.")]
    public Task<string> FindCallPaths(
        [Description("Target method. " + SymbolDescription)] string to,
        [Description("Start method (optional). " + SymbolDescription)] string? from = null,
        [Description("Maximum chain length (default 8).")] int maxDepth = 8,
        [Description("Maximum number of paths (default 10).")] int maxPaths = 10,
        [Description(AssemblyFilterDescription)] string? assembly = null,
        CancellationToken cancellationToken = default) => Read(workspace, () =>
    {
        var target = SymbolResolver.ResolveOne(workspace, assembly, to, SymbolKind.Method);
        var start = from == null ? null : SymbolResolver.ResolveOne(workspace, null, from, SymbolKind.Method);
        var paths = graph.Paths((MethodDef?)start?.Member, (MethodDef)target.Member, Math.Clamp(maxDepth, 1, 30), ClampLimit(maxPaths, 200), cancellationToken);
        var sb = new StringBuilder($"{Plural(paths.Count, "path")} to {target.Label}{(start != null ? $" from {start.Label}" : " from entry points")}:\n");
        if (paths.Count == 0)
            sb.AppendLine(start != null
                ? $"  none within {maxDepth} calls (raise maxDepth, or the call happens through reflection/delegates/events)."
                : "  none: nothing in the loaded assemblies reaches it (it may be called by the runtime, reflection, or unloaded code).");
        int n = 0;
        foreach (var path in paths)
        {
            sb.AppendLine($"\n#{++n} ({path.Count} methods)");
            for (int i = 0; i < path.Count; i++)
                sb.AppendLine($"  {new string(' ', i * 2)}{(i == 0 ? "" : "-> ")}{Format.MemberLabel(path[i])}");
        }
        return pager.Page(sb.ToString());
    }, cancellationToken);
}
