using System.Collections.Concurrent;
using System.Text;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using NetDecompilerMcp.Core;
using static NetDecompilerMcp.Services.MetadataUtil;

namespace NetDecompilerMcp.Services;

/// <summary>
/// Whole-workspace call graph (callers and callees of every method), built once per workspace state with the fast IL
/// reader and cached. Drives call trees ("who calls the callers of X") and call paths ("how does execution get from A to B").
/// Callers include calls made through a base or interface method the target overrides/implements.
/// </summary>
public sealed class CallGraphService(AssemblyWorkspace workspace)
{
    public sealed record Edge(MethodDef Method, uint Offset, string OpCode);

    private sealed record Graph(long Key, Dictionary<MethodDef, List<Edge>> Callees, Dictionary<MethodDef, List<Edge>> Callers, Dictionary<MethodDef, List<string>> External)
    {
        /// <summary>Base/interface declarations per method (resolution across assemblies is costly; asked once per method).</summary>
        public ConcurrentDictionary<MethodDef, MethodDef[]> Bases { get; } = new();
    }

    private readonly object _sync = new();
    private Graph? _graph;

    /// <summary>True when the graph for the current workspace state is already built.</summary>
    public bool IsBuilt => _graph?.Key == StateKey();

    private long StateKey() => ((long)workspace.Generation << 32) | (uint)workspace.Assemblies.Sum(a => a.Version);

    /// <summary>Builds (or returns) the graph. Call under the workspace read lock.</summary>
    public void EnsureBuilt(CancellationToken ct) => GetGraph(ct);

    private Graph GetGraph(CancellationToken ct)
    {
        long key = StateKey();
        lock (_sync)
        {
            if (_graph?.Key == key) return _graph;
        }
        var resolved = new ConcurrentDictionary<IMethod, MethodDef?>();
        var loadedModules = workspace.Assemblies.Select(a => a.Module).ToHashSet();
        var edges = ParallelCollect<(MethodDef From, MethodDef? To, string? External, uint Offset, string Op)>(workspace.Assemblies, (asm, type, found) =>
        {
            foreach (var m in type.Methods)
                foreach (var instr in FastIlReader.Instructions(asm, m))
                {
                    if (!IsCall(instr.OpCode.Code) || AsMethod(instr.Operand) is not { } op) continue;
                    var target = resolved.GetOrAdd(op, o => Try(() => (o is MethodSpec spec ? spec.Method : o).ResolveMethodDef()));
                    if (target != null && loadedModules.Contains(target.Module))
                        found.Add((m, target, null, instr.Offset, instr.OpCode.Name));
                    else
                        found.Add((m, null, Format.MemberLabel(op), instr.Offset, instr.OpCode.Name));
                }
        }, ct);

        var callees = new Dictionary<MethodDef, List<Edge>>();
        var callers = new Dictionary<MethodDef, List<Edge>>();
        var external = new Dictionary<MethodDef, List<string>>();
        foreach (var (from, to, ext, offset, op) in edges)
        {
            if (to != null)
            {
                Add(callees, from, new Edge(to, offset, op));
                Add(callers, to, new Edge(from, offset, op));
            }
            else
            {
                if (!external.TryGetValue(from, out var list)) external[from] = list = new List<string>();
                if (!list.Contains(ext!)) list.Add(ext!);
            }
        }
        var graph = new Graph(key, callees, callers, external);
        lock (_sync) _graph = graph;
        return graph;
    }

    private static void Add(Dictionary<MethodDef, List<Edge>> map, MethodDef key, Edge edge)
    {
        if (!map.TryGetValue(key, out var list)) map[key] = list = new List<Edge>();
        list.Add(edge);
    }

    private static bool IsCall(Code c) => c is Code.Call or Code.Callvirt or Code.Newobj or Code.Ldftn or Code.Ldvirtftn or Code.Jmp;

    /// <summary>Direct callers, plus callers of the base/interface declarations (dispatching here at runtime).</summary>
    private static IEnumerable<(Edge Edge, MethodDef? Via)> CallersOf(Graph g, MethodDef m)
    {
        foreach (var e in g.Callers.GetValueOrDefault(m) ?? [])
            yield return (e, null);
        if (!m.IsVirtual) yield break;
        foreach (var b in g.Bases.GetOrAdd(m, x => ReferenceService.BaseDeclarations(x).ToArray()))
            foreach (var e in g.Callers.GetValueOrDefault(b) ?? [])
                yield return (e, b);
    }

    // ------------------------------------------------------------------ trees

    public string Tree(LoadedAssembly asm, MethodDef root, bool callers, int depth, int maxNodes, bool includeExternal, CancellationToken ct)
    {
        var g = GetGraph(ct);
        var sb = new StringBuilder($"{(callers ? "Callers" : "Callees")} of {Format.MemberLabel(root)}  [{asm.Id}]  (depth {depth})\n");
        var seen = new HashSet<MethodDef> { root };
        int nodes = 0;
        bool truncated = false;

        void Walk(MethodDef m, int level, HashSet<MethodDef> path)
        {
            if (level > depth) return;
            var children = callers
                ? CallersOf(g, m).GroupBy(x => x.Edge.Method).Select(x => (x.Key, Note: x.First().Via is { } via ? $"via {Format.MemberLabel(via)}" : null, Count: x.Count()))
                : (g.Callees.GetValueOrDefault(m) ?? []).GroupBy(e => e.Method).Select(x => (x.Key, Note: x.First().OpCode == "callvirt" && x.Key.IsVirtual ? "virtual" : null, Count: x.Count()));
            foreach (var (child, note, count) in children.OrderBy(c => Format.MemberLabel(c.Key), StringComparer.Ordinal))
            {
                ct.ThrowIfCancellationRequested();
                if (++nodes > maxNodes) { truncated = true; return; }
                var indent = new string(' ', level * 2);
                var tags = new List<string>();
                if (count > 1) tags.Add($"x{count}");
                if (note != null) tags.Add(note);
                if (path.Contains(child)) tags.Add("recursive");
                else if (!seen.Add(child)) tags.Add("expanded above");
                var owner = workspace.FindByModule(child.Module)?.Id;
                sb.AppendLine($"{indent}{Format.MemberLabel(child)}{(owner != null && owner != asm.Id ? $"  [{owner}]" : "")}{(tags.Count > 0 ? $"  ({string.Join(", ", tags)})" : "")}");
                if (tags.Contains("recursive") || tags.Contains("expanded above")) continue;
                path.Add(child);
                Walk(child, level + 1, path);
                path.Remove(child);
                if (truncated) return;
            }
            if (!callers && includeExternal && g.External.TryGetValue(m, out var ext))
                foreach (var e in ext)
                    sb.AppendLine($"{new string(' ', level * 2)}{e}  (external)");
        }

        Walk(root, 1, [root]);
        if (nodes == 0)
            sb.AppendLine(callers ? "  (no callers in the loaded assemblies — load the assemblies that might call it)" : "  (calls nothing in the loaded assemblies; includeExternal=true shows framework calls)");
        if (truncated) sb.AppendLine($"[Stopped after {maxNodes} nodes: raise maxNodes or lower depth.]");
        return sb.ToString();
    }

    // ------------------------------------------------------------------ paths

    /// <summary>
    /// Call chains ending at <paramref name="to"/>: from <paramref name="from"/> when given, otherwise from entry points
    /// (methods nothing in the workspace calls: Main, Unity callbacks, event handlers, reflection targets...).
    /// </summary>
    public List<List<MethodDef>> Paths(MethodDef? from, MethodDef to, int maxDepth, int maxPaths, CancellationToken ct)
    {
        var g = GetGraph(ct);

        // Backward BFS: distance of every method from 'to' (linear in the graph, unlike enumerating all simple paths,
        // which explodes on the cyclic call graphs of real games).
        var dist = new Dictionary<MethodDef, int> { [to] = 0 };
        var closer = new Dictionary<MethodDef, List<MethodDef>>(); // caller -> its callees one step closer to 'to'
        var targets = new List<MethodDef>();
        var queue = new Queue<MethodDef>();
        queue.Enqueue(to);
        while (queue.Count > 0)
        {
            ct.ThrowIfCancellationRequested();
            var m = queue.Dequeue();
            int d = dist[m];
            var callers = CallersOf(g, m).Select(x => x.Edge.Method).Distinct().ToList();
            if (from != null ? m == from : callers.Count == 0 && m != to)
            {
                targets.Add(m);
                if (from != null) break;
                continue;
            }
            if (d >= maxDepth) continue;
            foreach (var c in callers)
            {
                if (!dist.TryGetValue(c, out var dc))
                {
                    dist[c] = dc = d + 1;
                    queue.Enqueue(c);
                }
                if (dc == d + 1)
                {
                    if (!closer.TryGetValue(c, out var list)) closer[c] = list = new List<MethodDef>();
                    list.Add(m);
                }
            }
        }
        if (from == null && targets.Count == 0 && !CallersOf(g, to).Any())
            targets.Add(to); // 'to' is itself an entry point

        // Walk forward from each start along shortest-distance edges; one path per start first, for variety.
        var results = new List<List<MethodDef>>();
        var seen = new HashSet<string>();
        void Walk(List<MethodDef> path, int perStartLimit, ref int taken)
        {
            if (results.Count >= maxPaths || taken >= perStartLimit) return;
            var last = path[^1];
            if (last == to)
            {
                if (seen.Add(string.Join("|", path.Select(x => x.MDToken.Raw + x.Module.Name)))) { results.Add(new List<MethodDef>(path)); taken++; }
                return;
            }
            if (!closer.TryGetValue(last, out var next)) return;
            foreach (var n in next)
            {
                path.Add(n);
                Walk(path, perStartLimit, ref taken);
                path.RemoveAt(path.Count - 1);
                if (results.Count >= maxPaths || taken >= perStartLimit) return;
            }
        }
        foreach (int limit in new[] { 1, int.MaxValue })
            foreach (var start in targets)
            {
                int taken = 0;
                Walk(new List<MethodDef> { start }, limit, ref taken);
                if (results.Count >= maxPaths) break;
            }
        return results.OrderBy(p => p.Count).ToList();
    }
}
