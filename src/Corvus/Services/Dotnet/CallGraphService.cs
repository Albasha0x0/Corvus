using System.Collections.Concurrent;
using System.Text;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using Corvus.Core;
using Corvus.Native;
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
    private long _searchVisits;

    /// <summary>Methods taken off the queue by path searches so far; a search visits each method at most once.</summary>
    internal long SearchVisits => Interlocked.Read(ref _searchVisits);

    public bool IsBuilt => _graph?.Key == StateKey();

    private long StateKey() => ((long)workspace.Generation << 32) | (uint)workspace.Assemblies.Sum(a => a.Version);

    /// <summary>Types per shared-lock section when the graph is built without the caller holding the lock.</summary>
    private const int SectionTypes = 500;

    /// <summary>
    /// Builds the graph unless it is current. Called without the workspace lock, it reads the assemblies in sections so a
    /// queued writer gets in between; an edit meanwhile leaves the graph to be built on first use.
    /// </summary>
    public void EnsureBuilt(CancellationToken ct)
    {
        if (workspace.LockHeld) GetGraph(ct);
        else BuildInSections(ct);
    }

    private Graph GetGraph(CancellationToken ct)
    {
        long key = StateKey();
        lock (_sync)
        {
            if (_graph?.Key == key) return _graph;
        }
        var resolved = new ConcurrentDictionary<IMethod, MethodDef?>();
        var loadedModules = workspace.Assemblies.Select(a => (ModuleDef)a.Module).ToHashSet();
        var edges = Collect(Types(workspace.Assemblies), resolved, loadedModules, ct);
        foreach (var asm in workspace.Assemblies)
            DelegateEdges(asm, edges, resolved, loadedModules, ct);
        return Publish(key, edges);
    }

    private void BuildInSections(CancellationToken ct)
    {
        var (key, assemblies, work, loadedModules) = workspace.Read(() =>
            (StateKey(), workspace.Assemblies, Types(workspace.Assemblies), workspace.Assemblies.Select(a => (ModuleDef)a.Module).ToHashSet()), ct);
        lock (_sync)
        {
            if (_graph?.Key == key) return;
        }
        var resolved = new ConcurrentDictionary<IMethod, MethodDef?>();
        var edges = new List<Call>();
        bool Section(Action read) => workspace.Read(() =>
        {
            if (StateKey() != key) return false;
            read();
            return true;
        }, ct);
        for (int start = 0; start < work.Length; start += SectionTypes)
        {
            var part = work[start..Math.Min(work.Length, start + SectionTypes)];
            if (!Section(() => edges.AddRange(Collect(part, resolved, loadedModules, ct)))) return;
        }
        foreach (var asm in assemblies)
            if (!Section(() => DelegateEdges(asm, edges, resolved, loadedModules, ct))) return;
        Publish(key, edges);
    }

    private record struct Call(MethodDef From, MethodDef? To, string? External, MethodDef? ExternalDef, uint Offset, string Op);

    private static (LoadedAssembly Assembly, TypeDef Type)[] Types(IEnumerable<LoadedAssembly> assemblies) =>
        assemblies.SelectMany(a => a.Module.GetTypes().Select(t => (a, t))).ToArray();

    private static List<Call> Collect((LoadedAssembly Assembly, TypeDef Type)[] work, ConcurrentDictionary<IMethod, MethodDef?> resolved,
        HashSet<ModuleDef> loadedModules, CancellationToken ct)
    {
        var buckets = new List<Call>?[work.Length];
        Parallel.For(0, work.Length, new ParallelOptions { CancellationToken = ct }, i =>
        {
            var (asm, type) = work[i];
            List<Call>? found = null;
            foreach (var m in type.Methods)
                foreach (var instr in FastIlReader.Instructions(asm, m))
                {
                    if (!IsCall(instr.OpCode.Code) || AsMethod(instr.Operand) is not { } op) continue;
                    var target = resolved.GetOrAdd(op, o => Try(() => (o is MethodSpec spec ? spec.Method : o).ResolveMethodDef()));
                    found ??= new();
                    found.Add(target != null && loadedModules.Contains(target.Module)
                        ? new Call(m, target, null, null, instr.Offset, instr.OpCode.Name)
                        : new Call(m, null, Format.MemberLabel(op), target, instr.Offset, instr.OpCode.Name));
                }
            buckets[i] = found;
        });
        var edges = new List<Call>();
        foreach (var bucket in buckets)
            if (bucket != null) edges.AddRange(bucket);
        return edges;
    }

    /// <summary>Calls through static delegate fields, to the method each field's delegate calls.</summary>
    private static void DelegateEdges(LoadedAssembly asm, List<Call> edges, ConcurrentDictionary<IMethod, MethodDef?> resolved, HashSet<ModuleDef> loadedModules,
        CancellationToken ct)
    {
        foreach (var site in Simplify.DelegateCalls.Of(asm, ct))
        {
            var target = resolved.GetOrAdd(site.Target, o => Try(() => (o is MethodSpec spec ? spec.Method : o).ResolveMethodDef()));
            var via = "via " + Format.MemberLabel(site.Field);
            edges.Add(target != null && loadedModules.Contains(target.Module)
                ? new Call(site.Caller, target, null, null, site.Offset, via)
                : new Call(site.Caller, null, Format.MemberLabel(site.Target), target, site.Offset, via));
        }
    }

    private Graph Publish(long key, List<Call> edges)
    {
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

    /// <summary>Returns the native lines under a call tree method and adds their rows to <c>rows</c>, ids continuing from its count.</summary>
    public delegate string NativeLines(MethodDef method, int levels, int indent, List<NativeTreeNode> rows, int? parent);

    /// <summary>
    /// The call tree of <paramref name="root"/> as text, nodes in <paramref name="nodes"/>; <paramref name="truncated"/> when maxNodes stopped it.
    /// </summary>
    /// <param name="native">Optional native lines under each expanded method and the root.</param>
    public string Tree(LoadedAssembly asm, MethodDef root, bool callers, int depth, int maxNodes, bool includeExternal, CancellationToken ct,
        NativeLines? native, List<TreeNode>? nodes, out bool truncated)
    {
        var sb = new StringBuilder($"{(callers ? "Callers" : "Callees")} of {Format.MemberLabel(root)}  [{asm.Id}]  (depth {depth})\n");
        int length = sb.Length;
        truncated = WriteTree(sb, asm, root, callers, depth, maxNodes, includeExternal, 0, native, ct, nodes);
        if (sb.Length == length)
            sb.AppendLine(callers ? "  (no callers in the loaded assemblies; load the assemblies that might call it)" : "  (calls nothing in the loaded assemblies; includeExternal=true shows framework calls)");
        if (truncated) sb.AppendLine($"[Stopped after {maxNodes} nodes; levels above the last are complete; lower depth for a complete tree.]");
        return sb.ToString();
    }

    /// <summary>The call tree as text, without native lines.</summary>
    public string Tree(LoadedAssembly asm, MethodDef root, bool callers, int depth, int maxNodes, bool includeExternal, CancellationToken ct) =>
        Tree(asm, root, callers, depth, maxNodes, includeExternal, ct, null, null, out _);

    /// <summary>The tree below <paramref name="root"/> (not the root line), indented by <paramref name="baseIndent"/> levels; true when maxNodes cut it.</summary>
    /// <param name="sink">When given, receives the lines written as nodes (depth: levels below the root plus <paramref name="baseIndent"/>); ids continue from its count.</param>
    /// <param name="parent">The sink row the top nodes hang under.</param>
    public bool WriteTree(StringBuilder sb, LoadedAssembly asm, MethodDef root, bool callers, int depth, int maxNodes, bool includeExternal, int baseIndent,
        NativeLines? native, CancellationToken ct, List<TreeNode>? sink = null, int? parent = null)
    {
        var g = GetGraph(ct);

        // Breadth-first so maxNodes truncates only the deepest level; each method is expanded once, at its shallowest occurrence.
        var children = new Dictionary<MethodDef, List<(MethodDef Child, string? Note, int Count, string Edge)>>();
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
                        ? CallersOf(g, m).GroupBy(x => x.Edge.Method).Select(x => (x.Key, Note: x.First().Via is { } via ? $"via {Format.MemberLabel(via)}" : DelegateNote(x.First().Edge), Count: x.Count(),
                            Edge: x.First().Via != null ? "virtual" : DelegateNote(x.First().Edge) != null ? "delegate" : "call"))
                        : (g.Callees.GetValueOrDefault(m) ?? []).GroupBy(e => e.Method).Select(x => (x.Key, Note: x.First().OpCode == "callvirt" && x.Key.IsVirtual ? "virtual" : DelegateNote(x.First()), Count: x.Count(),
                            Edge: DelegateNote(x.First()) != null ? "delegate" : x.First().OpCode == "callvirt" && x.Key.IsVirtual ? "virtual" : "call")))
                    .OrderBy(c => Format.MemberLabel(c.Key), StringComparer.Ordinal).ToList();
                var kept = new List<(MethodDef, string?, int, string)>();
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

        int? Add(TreeNode node)
        {
            if (sink == null) return null;
            sink.Add(node with { Id = sink.Count });
            return sink.Count - 1;
        }

        void Print(MethodDef m, int l, int? up)
        {
            foreach (var (child, note, count, edge) in children.GetValueOrDefault(m) ?? [])
            {
                var tags = new List<string>();
                if (count > 1) tags.Add($"x{count}");
                if (note != null) tags.Add(note);
                var home = expandedAt[child];
                bool expandHere = child != root && home.Parent == m && home.Level == l;
                string? flag = null;
                if (!expandHere)
                {
                    flag = IsAncestor(child, m) ? "recursive" : "repeated";
                    tags.Add(flag == "recursive" ? "recursive" : $"expanded under {(home.Parent == root ? "the root" : Format.MemberLabel(home.Parent))}");
                }
                var owner = workspace.FindByModule(child.Module)?.Id;
                sb.AppendLine($"{new string(' ', (l + baseIndent) * 2)}{Format.MemberLabel(child)}{(owner != null && owner != asm.Id ? $"  [{owner}]" : "")}{(tags.Count > 0 ? $"  ({string.Join(", ", tags)})" : "")}");
                var id = Add(new TreeNode(0, up, l + baseIndent, Format.MemberLabel(child), edge is "virtual" && callers || edge == "delegate" ? "derived" : null)
                {
                    Token = Format.Token(child),
                    Assembly = owner != null && owner != asm.Id ? owner : null,
                    Edge = edge == "call" ? null : edge,
                    Flags = flag != null ? [flag] : null,
                    // The edge already says virtual.
                    Note = tags.Where(t => t != "virtual").ToList() is { Count: > 0 } kept ? string.Join(", ", kept) : null,
                });
                if (expandHere) Print(child, l + 1, id);
            }
            if (!callers && includeExternal && children.ContainsKey(m) && g.External.TryGetValue(m, out var ext))
                foreach (var e in ext)
                {
                    sb.AppendLine($"{new string(' ', (l + baseIndent) * 2)}{e}  (external)");
                    Add(new TreeNode(0, up, l + baseIndent, e, null) { Edge = "external" });
                }
            if (native != null && depth - l + 1 > 0)
            {
                // Native rows get ids from the list's count: it stands in for the sink up to here.
                var rows = new List<NativeTreeNode>();
                System.Runtime.InteropServices.CollectionsMarshal.SetCount(rows, sink?.Count ?? 0);
                int first = rows.Count;
                sb.Append(native(m, depth - l + 1, l + baseIndent, rows, up));
                if (sink != null)
                    foreach (var n in rows.Skip(first))
                        sink.Add(new TreeNode(n.Id, n.Parent, n.Depth, n.Name, n.Edge is "virtual?" or "dynamic" ? "derived" : null)
                            { Assembly = n.Image, Address = n.Address, Edge = n.Edge == "call" ? null : n.Edge, Flags = n.Flags, Note = n.Note });
            }
        }

        Print(root, 1, parent);
        return truncated;
    }

    /// <summary>A node of a call tree: a method, an external call, or native code below a method, in text order.</summary>
    public sealed record TreeNode(
        [property: System.ComponentModel.Description("Node id: its position in tree order.")] int Id,
        [property: System.ComponentModel.Description("Parent node id; absent at the top level.")] int? Parent,
        [property: System.ComponentModel.Description("Levels below the root (1: direct callers or callees).")] int Depth,
        [property: System.ComponentModel.Description("Method label, external call, or native function or import.")] string Name,
        [property: System.ComponentModel.Description("derived: through a base or interface method, a delegate field or a possible virtual target; absent: observed.")] string? Basis)
    {
        [System.ComponentModel.Description("Managed: metadata token.")] public string? Token { get; init; }
        [System.ComponentModel.Description("Assembly or image id when it differs from the root's.")] public string? Assembly { get; init; }
        [System.ComponentModel.Description("Native: VA.")] public string? Address { get; init; }
        [System.ComponentModel.Description("virtual, delegate, external, pinvoke, native, import, ...; absent: a direct call.")] public string? Edge { get; init; }
        [System.ComponentModel.Description("repeated, recursive, more, unresolved, not-loaded.")] public IReadOnlyList<string>? Flags { get; init; }
        [System.ComponentModel.Description("xN, via Base::Method, expanded under ..., binding details.")] public string? Note { get; init; }
    }

    /// <summary>A call path step; <c>Via</c> is the base/interface method called when reached by virtual dispatch.</summary>
    public sealed record PathStep(MethodDef Method, MethodDef? Via);

    /// <summary><see cref="PathSteps"/> as plain method lists.</summary>
    public List<List<MethodDef>> Paths(MethodDef? from, MethodDef to, int maxDepth, int maxPaths, CancellationToken ct, bool includeVirtual = true) =>
        PathSteps(from, to, maxDepth, maxPaths, includeVirtual, ct).Select(p => p.Select(s => s.Method).ToList()).ToList();

    /// <summary>
    /// Call chains to <paramref name="to"/> from <paramref name="from"/> or, if null, from methods with no callers;
    /// direct paths first, shortest first, then paths with virtual-dispatch hops. Entry points are found per edge set, so
    /// a broad base method does not hide short direct chains.
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
        // Caller to its callees one step closer to 'to'.
        var closer = new Dictionary<MethodDef, List<PathStep>>();
        var targets = new List<MethodDef>();
        var queue = new Queue<MethodDef>();
        queue.Enqueue(to);
        while (queue.Count > 0)
        {
            ct.ThrowIfCancellationRequested();
            var m = queue.Dequeue();
            Interlocked.Increment(ref _searchVisits);
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
        // Direct calls first.
        foreach (var list in closer.Values)
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
