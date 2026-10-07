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

        // Breadth-first: every level is complete before the next one starts, so maxNodes cuts the deepest level, and a
        // method reached several times is expanded once, at its shallowest occurrence (the others say where).
        var children = new Dictionary<MethodDef, List<(MethodDef Child, string? Note, int Count)>>();
        var expandedAt = new Dictionary<MethodDef, (MethodDef Parent, int Level)> { [root] = (root, 0) };
        var parentOf = new Dictionary<MethodDef, MethodDef>();
        int nodes = 0;
        bool truncated = false;
        var level = new List<MethodDef> { root };
        for (int l = 1; l <= depth && level.Count > 0 && !truncated; l++)
        {
            var next = new List<MethodDef>();
            foreach (var m in level)
            {
                ct.ThrowIfCancellationRequested();
                var list = (callers
                        ? CallersOf(g, m).GroupBy(x => x.Edge.Method).Select(x => (x.Key, Note: x.First().Via is { } via ? $"via {Format.MemberLabel(via)}" : null, Count: x.Count()))
                        : (g.Callees.GetValueOrDefault(m) ?? []).GroupBy(e => e.Method).Select(x => (x.Key, Note: x.First().OpCode == "callvirt" && x.Key.IsVirtual ? "virtual" : null, Count: x.Count())))
                    .OrderBy(c => Format.MemberLabel(c.Key), StringComparer.Ordinal).ToList();
                var kept = new List<(MethodDef, string?, int)>();
                foreach (var c in list)
                {
                    if (++nodes > maxNodes) { truncated = true; break; }
                    kept.Add(c);
                    if (expandedAt.TryAdd(c.Key, (m, l)))
                    {
                        parentOf[c.Key] = m;
                        next.Add(c.Key);
                    }
                }
                children[m] = kept;
                if (truncated) break;
            }
            level = next;
        }

        bool IsAncestor(MethodDef candidate, MethodDef of)
        {
            for (var x = of; ; x = parentOf[x])
            {
                if (x == candidate) return true;
                if (x == root) return false;
            }
        }

        void Print(MethodDef m, int l)
        {
            foreach (var (child, note, count) in children.GetValueOrDefault(m) ?? [])
            {
                var tags = new List<string>();
                if (count > 1) tags.Add($"x{count}");
                if (note != null) tags.Add(note);
                var home = expandedAt[child];
                bool expandHere = child != root && home.Parent == m && home.Level == l;
                if (!expandHere)
                    tags.Add(IsAncestor(child, m) ? "recursive" : $"expanded under {(home.Parent == root ? "the root" : Format.MemberLabel(home.Parent))}");
                var owner = workspace.FindByModule(child.Module)?.Id;
                sb.AppendLine($"{new string(' ', l * 2)}{Format.MemberLabel(child)}{(owner != null && owner != asm.Id ? $"  [{owner}]" : "")}{(tags.Count > 0 ? $"  ({string.Join(", ", tags)})" : "")}");
                if (expandHere) Print(child, l + 1);
            }
            if (!callers && includeExternal && children.ContainsKey(m) && g.External.TryGetValue(m, out var ext))
                foreach (var e in ext)
                    sb.AppendLine($"{new string(' ', l * 2)}{e}  (external)");
        }

        Print(root, 1);
        if (nodes == 0)
            sb.AppendLine(callers ? "  (no callers in the loaded assemblies — load the assemblies that might call it)" : "  (calls nothing in the loaded assemblies; includeExternal=true shows framework calls)");
        if (truncated) sb.AppendLine($"[Stopped after {maxNodes} nodes (the levels above the last one shown are complete): raise maxNodes or lower depth.]");
        return sb.ToString();
    }

    // ------------------------------------------------------------------ paths

    /// <summary>
    /// One step of a call path: the method, and — when the previous step reaches it by virtual dispatch — the
    /// base/interface declaration that step actually calls (null for a direct call).
    /// </summary>
    public sealed record PathStep(MethodDef Method, MethodDef? Via);

    /// <summary>Call chains as methods only (see <see cref="PathSteps"/>).</summary>
    public List<List<MethodDef>> Paths(MethodDef? from, MethodDef to, int maxDepth, int maxPaths, CancellationToken ct, bool includeVirtual = true) =>
        PathSteps(from, to, maxDepth, maxPaths, includeVirtual, ct).Select(p => p.Select(s => s.Method).ToList()).ToList();

    /// <summary>
    /// Call chains ending at <paramref name="to"/>: from <paramref name="from"/> when given, otherwise from entry points
    /// (methods nothing in the workspace calls: Main, Unity callbacks, event handlers, reflection targets...).
    /// Paths made of direct calls come first (shortest first); then, with <paramref name="includeVirtual"/>, paths that
    /// need a virtual-dispatch hop (shortest first, fewer such hops first). Without it only direct calls are followed.
    /// Entry points are judged by the same edges: a method only called through virtual dispatch is an entry point of the
    /// direct-call paths, so a short direct chain is not hidden behind a longer chain through a broad base method.
    /// </summary>
    public List<List<PathStep>> PathSteps(MethodDef? from, MethodDef to, int maxDepth, int maxPaths, bool includeVirtual, CancellationToken ct)
    {
        var direct = Search(from, to, maxDepth, maxPaths, includeVirtual: false, ct);
        if (!includeVirtual || direct.Count >= maxPaths) return direct;
        string Key(List<PathStep> p) => string.Join("|", p.Select(x => x.Method.MDToken.Raw + x.Method.Module.Name));
        var known = direct.Select(Key).ToHashSet();
        return direct.Concat(Search(from, to, maxDepth, maxPaths, includeVirtual: true, ct).Where(p => p.Any(s => s.Via != null) && known.Add(Key(p))))
            .Take(maxPaths).ToList();
    }

    private List<List<PathStep>> Search(MethodDef? from, MethodDef to, int maxDepth, int maxPaths, bool includeVirtual, CancellationToken ct)
    {
        var g = GetGraph(ct);

        // a caller of m, and the base declaration it calls when it reaches m only through virtual dispatch
        List<(MethodDef Caller, MethodDef? Via)> Callers(MethodDef m) =>
            CallersOf(g, m).Where(x => includeVirtual || x.Via == null)
                .GroupBy(x => x.Edge.Method)
                .Select(x => (x.Key, x.Any(e => e.Via == null) ? null : x.First().Via)).ToList();

        // Backward BFS: distance of every method from 'to' (linear in the graph, unlike enumerating all simple paths,
        // which explodes on the cyclic call graphs of real games).
        var dist = new Dictionary<MethodDef, int> { [to] = 0 };
        var closer = new Dictionary<MethodDef, List<PathStep>>(); // caller -> its callees one step closer to 'to'
        var targets = new List<MethodDef>();
        var queue = new Queue<MethodDef>();
        queue.Enqueue(to);
        while (queue.Count > 0)
        {
            ct.ThrowIfCancellationRequested();
            var m = queue.Dequeue();
            int d = dist[m];
            var callers = Callers(m);
            if (from != null ? m == from : callers.Count == 0 && m != to)
            {
                targets.Add(m);
                if (from != null) break;
                continue;
            }
            if (d >= maxDepth) continue;
            foreach (var (c, via) in callers)
            {
                if (!dist.TryGetValue(c, out var dc))
                {
                    dist[c] = dc = d + 1;
                    queue.Enqueue(c);
                }
                if (dc == d + 1)
                {
                    if (!closer.TryGetValue(c, out var list)) closer[c] = list = new List<PathStep>();
                    list.Add(new PathStep(m, via));
                }
            }
        }
        if (from == null && targets.Count == 0 && Callers(to).Count == 0)
            targets.Add(to); // 'to' is itself an entry point
        foreach (var list in closer.Values) // direct calls are explored first
            list.Sort((a, b) => (a.Via != null).CompareTo(b.Via != null));

        // Walk forward from each start along shortest-distance edges; one path per start first, for variety.
        var results = new List<List<PathStep>>();
        var seen = new HashSet<string>();
        void Walk(List<PathStep> path, int perStartLimit, ref int taken)
        {
            if (results.Count >= maxPaths || taken >= perStartLimit) return;
            var last = path[^1].Method;
            if (last == to)
            {
                if (seen.Add(string.Join("|", path.Select(x => x.Method.MDToken.Raw + x.Method.Module.Name)))) { results.Add(new List<PathStep>(path)); taken++; }
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
                Walk(new List<PathStep> { new(start, null) }, limit, ref taken);
                if (results.Count >= maxPaths) break;
            }
        return results.OrderBy(p => p.Count).ThenBy(p => p.Count(s => s.Via != null)).ToList();
    }
}
