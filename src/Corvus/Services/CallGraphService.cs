using System.Collections.Concurrent;
using System.Text;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using Corvus.Core;
using static Corvus.Core.MetadataUtil;

namespace Corvus.Services;

/// <summary>
/// Workspace-wide call graph, cached per workspace state, for call trees and call paths. Callers include calls made
/// through a base or interface method the target overrides or implements.
/// </summary>
public sealed class CallGraphService(AssemblyWorkspace workspace)
{
    public sealed record Edge(MethodDef Method, uint Offset, string OpCode);

    private sealed record Graph(long Key, Dictionary<MethodDef, List<Edge>> Callees, Dictionary<MethodDef, List<Edge>> Callers, Dictionary<MethodDef, List<string>> External,
        Dictionary<string, List<Edge>> ExternalCallers)
    {
        /// <summary>Base/interface declarations per method, memoized because cross-assembly resolution is costly.</summary>
        public ConcurrentDictionary<MethodDef, MethodDef[]> Bases { get; } = new();
    }

    private readonly object _sync = new();
    private Graph? _graph;

    public bool IsBuilt => _graph?.Key == StateKey();

    private long StateKey() => ((long)workspace.Generation << 32) | (uint)workspace.Assemblies.Sum(a => a.Version);

    /// <summary>Call under the workspace read lock.</summary>
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
        var edges = ParallelCollect<(MethodDef From, MethodDef? To, string? External, MethodDef? ExternalDef, uint Offset, string Op)>(workspace.Assemblies, (asm, type, found) =>
        {
            foreach (var m in type.Methods)
                foreach (var instr in FastIlReader.Instructions(asm, m))
                {
                    if (!IsCall(instr.OpCode.Code) || AsMethod(instr.Operand) is not { } op) continue;
                    var target = resolved.GetOrAdd(op, o => Try(() => (o is MethodSpec spec ? spec.Method : o).ResolveMethodDef()));
                    if (target != null && loadedModules.Contains(target.Module))
                        found.Add((m, target, null, null, instr.Offset, instr.OpCode.Name));
                    else
                        found.Add((m, null, Format.MemberLabel(op), target, instr.Offset, instr.OpCode.Name));
                }
        }, ct).ToList();

        // Calls through static delegate fields, to the method each field's delegate calls.
        foreach (var asm in workspace.Assemblies)
        {
            foreach (var site in Simplify.DelegateCalls.Of(asm, ct))
            {
                var target = resolved.GetOrAdd(site.Target, o => Try(() => (o is MethodSpec spec ? spec.Method : o).ResolveMethodDef()));
                var via = "via " + Format.MemberLabel(site.Field);
                if (target != null && loadedModules.Contains(target.Module))
                    edges.Add((site.Caller, target, null, null, site.Offset, via));
                else
                    edges.Add((site.Caller, null, Format.MemberLabel(site.Target), target, site.Offset, via));
            }
        }

        var callees = new Dictionary<MethodDef, List<Edge>>();
        var callers = new Dictionary<MethodDef, List<Edge>>();
        var external = new Dictionary<MethodDef, List<string>>();
        var externalCallers = new Dictionary<string, List<Edge>>(StringComparer.Ordinal);
        foreach (var (from, to, ext, extDef, offset, op) in edges)
        {
            if (extDef != null)
            {
                var k = ExternalKey(extDef);
                if (!externalCallers.TryGetValue(k, out var callersOfExternal)) externalCallers[k] = callersOfExternal = new List<Edge>();
                callersOfExternal.Add(new Edge(from, offset, op));
            }
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
        var graph = new Graph(key, callees, callers, external, externalCallers);
        lock (_sync) _graph = graph;
        return graph;
    }

    private static void Add(Dictionary<MethodDef, List<Edge>> map, MethodDef key, Edge edge)
    {
        if (!map.TryGetValue(key, out var list)) map[key] = list = new List<Edge>();
        list.Add(edge);
    }

    /// <summary>"via Type::field" for a call through a delegate field (see <see cref="Simplify.DelegateCalls"/>).</summary>
    private static string? DelegateNote(Edge e) => e.OpCode.StartsWith("via ", StringComparison.Ordinal) ? e.OpCode : null;

    private static bool IsCall(Code c) => c is Code.Call or Code.Callvirt or Code.Newobj or Code.Ldftn or Code.Ldvirtftn or Code.Jmp;

    /// <summary>Direct callers plus callers of the base/interface declarations that dispatch here.</summary>
    private static IEnumerable<(Edge Edge, MethodDef? Via)> CallersOf(Graph g, MethodDef m)
    {
        foreach (var e in Direct(m))
            yield return (e, null);
        if (!m.IsVirtual) yield break;
        foreach (var b in g.Bases.GetOrAdd(m, x => ReferenceService.BaseDeclarations(x).ToArray()))
            foreach (var e in Direct(b))
                yield return (e, b);

        // External methods match by name and signature, since callers may reference different facades.
        List<Edge> Direct(MethodDef x) => g.Callers.GetValueOrDefault(x)
            ?? (MetadataUtil.IsReferenceOnly(x) ? g.ExternalCallers.GetValueOrDefault(ExternalKey(x)) : null) ?? [];
    }

    private static string ExternalKey(MethodDef m) =>
        $"{m.DeclaringType?.FullName}::{m.Name}({Format.ParameterTypes(m.MethodSig)}){m.GenericParameters.Count}";

    /// <param name="native">
    /// Optional lines written under each expanded method (and the root): given the method, the levels left and the
    /// indent level; used for native code a method binds to (callees) or native code calling it (callers).
    /// </param>
    public string Tree(LoadedAssembly asm, MethodDef root, bool callers, int depth, int maxNodes, bool includeExternal, CancellationToken ct,
        Func<MethodDef, int, int, string>? native = null, List<TreeNode>? nodes = null) =>
        Tree(asm, root, callers, depth, maxNodes, includeExternal, ct, native, nodes, out _);

    /// <summary>As above; <paramref name="truncated"/>: maxNodes stopped the walk.</summary>
    public string Tree(LoadedAssembly asm, MethodDef root, bool callers, int depth, int maxNodes, bool includeExternal, CancellationToken ct,
        Func<MethodDef, int, int, string>? native, List<TreeNode>? nodes, out bool truncated)
    {
        var sb = new StringBuilder($"{(callers ? "Callers" : "Callees")} of {Format.MemberLabel(root)}  [{asm.Id}]  (depth {depth})\n");
        int length = sb.Length;
        truncated = WriteTree(sb, asm, root, callers, depth, maxNodes, includeExternal, 0, native, ct, nodes);
        if (sb.Length == length)
            sb.AppendLine(callers ? "  (no callers in the loaded assemblies — load the assemblies that might call it)" : "  (calls nothing in the loaded assemblies; includeExternal=true shows framework calls)");
        if (truncated) sb.AppendLine($"[Stopped after {maxNodes} nodes (the levels above the last one shown are complete): raise maxNodes or lower depth.]");
        return sb.ToString();
    }

    /// <summary>The tree below <paramref name="root"/> (not the root line), indented by <paramref name="baseIndent"/> levels; true when maxNodes cut it.</summary>
    /// <param name="sink">When given, receives the lines written as nodes (level relative to the root, without <paramref name="baseIndent"/>).</param>
    public bool WriteTree(StringBuilder sb, LoadedAssembly asm, MethodDef root, bool callers, int depth, int maxNodes, bool includeExternal, int baseIndent,
        Func<MethodDef, int, int, string>? native, CancellationToken ct, List<TreeNode>? sink = null)
    {
        var g = GetGraph(ct);

        // Breadth-first so maxNodes truncates only the deepest level; each method is expanded once, at its shallowest occurrence.
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
                        ? CallersOf(g, m).GroupBy(x => x.Edge.Method).Select(x => (x.Key, Note: x.First().Via is { } via ? $"via {Format.MemberLabel(via)}" : DelegateNote(x.First().Edge), Count: x.Count()))
                        : (g.Callees.GetValueOrDefault(m) ?? []).GroupBy(e => e.Method).Select(x => (x.Key, Note: x.First().OpCode == "callvirt" && x.Key.IsVirtual ? "virtual" : DelegateNote(x.First()), Count: x.Count())))
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
                sb.AppendLine($"{new string(' ', (l + baseIndent) * 2)}{Format.MemberLabel(child)}{(owner != null && owner != asm.Id ? $"  [{owner}]" : "")}{(tags.Count > 0 ? $"  ({string.Join(", ", tags)})" : "")}");
                sink?.Add(new TreeNode(l, Format.MemberLabel(child), owner, "method", tags.Count > 0 ? string.Join(", ", tags) : null));
                if (expandHere) Print(child, l + 1);
            }
            if (!callers && includeExternal && children.ContainsKey(m) && g.External.TryGetValue(m, out var ext))
                foreach (var e in ext)
                {
                    sb.AppendLine($"{new string(' ', (l + baseIndent) * 2)}{e}  (external)");
                    sink?.Add(new TreeNode(l, e, null, "external", null));
                }
            if (native != null && depth - l + 1 > 0)
            {
                var lines = native(m, depth - l + 1, l + baseIndent);
                sb.Append(lines);
                // Native lines are indented two spaces per level, like the managed ones.
                if (sink != null)
                    foreach (var line in lines.Split('\n').Where(x => x.Trim().Length > 0))
                        sink.Add(new TreeNode(Math.Max(l, (line.Length - line.TrimStart(' ').Length) / 2 - baseIndent), line.Trim(), null, "native", null));
            }
        }

        Print(root, 1);
        return truncated;
    }

    /// <summary>A line of a call tree: a method, an external call, or a line of native code below a method.</summary>
    public sealed record TreeNode(
        [property: System.ComponentModel.Description("Depth below the root (1: direct callers/callees).")] int Level,
        string Label,
        [property: System.ComponentModel.Description("Assembly id when it differs from the root's.")] string? Assembly,
        [property: System.ComponentModel.Description("method, external or native.")] string Kind,
        [property: System.ComponentModel.Description("xN, virtual, via ..., recursive, expanded under ...")] string? Note);

    /// <summary>A call path step; <c>Via</c> is the base/interface method called when reached by virtual dispatch.</summary>
    public sealed record PathStep(MethodDef Method, MethodDef? Via);

    /// <summary><see cref="PathSteps"/> as plain method lists.</summary>
    public List<List<MethodDef>> Paths(MethodDef? from, MethodDef to, int maxDepth, int maxPaths, CancellationToken ct, bool includeVirtual = true) =>
        PathSteps(from, to, maxDepth, maxPaths, includeVirtual, ct).Select(p => p.Select(s => s.Method).ToList()).ToList();

    /// <summary>
    /// Call chains ending at <paramref name="to"/>, starting at <paramref name="from"/> or, if null, at entry points
    /// (methods with no callers in the workspace). Direct-call paths come first, shortest first; with
    /// <paramref name="includeVirtual"/>, paths needing virtual-dispatch hops follow. Entry points are determined per
    /// edge set, so short direct chains are not hidden behind longer chains through a broad base method.
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

        // Via is set only when the caller reaches m solely through virtual dispatch.
        List<(MethodDef Caller, MethodDef? Via)> Callers(MethodDef m) =>
            CallersOf(g, m).Where(x => includeVirtual || x.Via == null)
                .GroupBy(x => x.Edge.Method)
                .Select(x => (x.Key, x.Any(e => e.Via == null) ? null : x.First().Via)).ToList();

        // Backward BFS from 'to': linear, unlike enumerating all simple paths in a cyclic graph.
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
        // 'to' is itself an entry point, unless it is an external method.
        if (from == null && targets.Count == 0 && Callers(to).Count == 0 && !MetadataUtil.IsReferenceOnly(to))
            targets.Add(to);
        foreach (var list in closer.Values) // direct calls first
            list.Sort((a, b) => (a.Via != null).CompareTo(b.Via != null));

        // Walk forward along shortest-distance edges; one path per start first, for variety.
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
