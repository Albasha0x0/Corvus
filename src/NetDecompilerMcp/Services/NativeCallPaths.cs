using System.Runtime.CompilerServices;
using NetDecompilerMcp.Core;
using NetDecompilerMcp.Native;
using NetDecompilerMcp.Native.Calls;
using NetDecompilerMcp.Native.Code;

namespace NetDecompilerMcp.Services;

/// <summary>A function of a loaded native image.</summary>
public readonly record struct NativeNode(LoadedNative Image, uint Start);

/// <summary>
/// A call from <see cref="From"/> to <see cref="To"/> at <see cref="Site"/> (in From's image). Edge: call, tail, import
/// (through an import bound to the other image), virtual_exact, virtual_possible or pointer (a function pointer
/// resolve_call_targets resolved).
/// </summary>
public sealed record NativeHop(NativeNode From, NativeNode To, string Edge, uint Site);

/// <summary>A chain of calls from a start to the goal; <see cref="Root"/> says why the first function is a start.</summary>
public sealed record NativeChain(string Root, NativeNode First, IReadOnlyList<NativeHop> Hops)
{
    public int Uncertain => Hops.Count(h => h.Edge is "virtual_possible" or "pointer");
    public int CrossImage => Hops.Count(h => h.From.Image != h.To.Image);
}

/// <summary>A managed method bound to native code on the way to the goal (P/Invoke, C++/CLI native body), <see cref="Distance"/> calls from it.</summary>
public sealed record ManagedEntry(NativeLinkService.ManagedLink Link, NativeNode Node, int Distance);

/// <summary>
/// The callers of a goal explored backward: each function's distance in calls, its hops one call closer, the roots met
/// and the managed methods bound to the code on the way. <see cref="Chains"/> enumerates the shortest chains from starts.
/// </summary>
public sealed class NativeCallGraph
{
    private const int MaxFanOut = 16;
    internal readonly Dictionary<NativeNode, int> Distance = [];
    internal readonly Dictionary<NativeNode, List<NativeHop>> Toward = [];
    internal readonly Dictionary<NativeNode, string> RootKinds = [];

    public NativeNode Goal { get; init; }
    public List<ManagedEntry> Managed { get; } = [];
    public List<string> Notes { get; } = [];
    /// <summary>Functions whose callers were not explored (depth or node budget).</summary>
    public int Frontier { get; internal set; }
    /// <summary>The node budget stopped the search.</summary>
    public bool Cut { get; internal set; }
    public int Visited => Distance.Count;
    public int? DistanceOf(NativeNode n) => Distance.TryGetValue(n, out var d) ? d : null;

    /// <summary>The roots met: entry point, exports, TLS callbacks, address-taken or data-referenced functions, uncalled functions.</summary>
    public IEnumerable<(NativeNode Node, string Root)> Roots => RootKinds.Where(r => r.Key != Goal).Select(r => (r.Key, r.Value));

    /// <summary>
    /// Up to <paramref name="max"/> shortest chains from the starts to the goal: nearer starts first, cheapest edges first, a
    /// bounded fan-out per function; ranked by calls, uncertain hops (virtual_possible, pointer), image changes, root.
    /// </summary>
    public (List<NativeChain> Chains, bool Truncated) Chains(IEnumerable<(NativeNode Node, string Root)> starts, int max, CancellationToken ct)
    {
        var ordered = starts.Where(s => Distance.ContainsKey(s.Node)).OrderBy(s => Distance[s.Node]).ThenBy(s => RootRank(s.Root))
            .ThenBy(s => s.Node.Image.Id, StringComparer.Ordinal).ThenBy(s => s.Node.Start).ToList();
        var chains = new List<NativeChain>();
        bool truncated = false;
        foreach (var (node, root) in ordered)
        {
            if (chains.Count >= max) { truncated = true; break; }
            truncated |= Enumerate(node, root, chains, max, ct);
        }
        return (chains.OrderBy(c => c.Hops.Count).ThenBy(c => c.Uncertain).ThenBy(c => c.CrossImage).ThenBy(c => RootRank(c.Root)).ThenBy(c => c.First.Start).ToList(),
            truncated);
    }

    private bool Enumerate(NativeNode start, string root, List<NativeChain> into, int max, CancellationToken ct)
    {
        var path = new List<NativeHop>();
        bool cut = false;
        void Walk(NativeNode n)
        {
            ct.ThrowIfCancellationRequested();
            if (into.Count >= max) { cut = true; return; }
            if (n == Goal)
            {
                into.Add(new NativeChain(root, start, path.ToList()));
                return;
            }
            if (!Toward.TryGetValue(n, out var next)) return;
            int taken = 0;
            foreach (var hop in next.OrderBy(h => EdgeRank(h.Edge)).ThenBy(h => h.From.Image != h.To.Image).ThenBy(h => h.To.Start))
            {
                if (++taken > MaxFanOut) { cut = true; break; }
                path.Add(hop);
                Walk(hop.To);
                path.RemoveAt(path.Count - 1);
                if (into.Count >= max) { cut = true; return; }
            }
        }
        Walk(start);
        return cut;
    }

    private static int EdgeRank(string edge) => edge switch { "call" or "tail" => 0, "import" => 1, "virtual_exact" => 2, "pointer" => 3, _ => 4 };

    internal static int RootRank(string root) => root switch
    {
        "from" => 0, "entry point" => 1, "export" => 2, "TLS callback" => 3, "no callers" => 4, _ => 5,
    };
}

/// <summary>
/// Shortest call chains to a native function across loaded images: a backward search over the in-memory call graph
/// (direct and tail calls, imports bound between images, RTTI virtual calls and resolved function pointers when asked),
/// then a bounded enumeration over distance-decreasing edges (<see cref="NativeCallGraph.Chains"/>).
/// </summary>
public sealed class NativeCallPaths(NativeLinkService link, NativeCodeService code)
{
    public const int MaxVisited = 50_000;
    private static readonly ConditionalWeakTable<CallAnalysis, Tuple<int, Dictionary<uint, List<(uint Site, uint Caller)>>>> PointerCallers = new();

    /// <summary>Explores the callers of <paramref name="goal"/> backward up to <paramref name="maxDepth"/> calls and <see cref="MaxVisited"/> functions.</summary>
    public NativeCallGraph Explore(NativeNode goal, int maxDepth, bool indirect, CancellationToken ct)
    {
        var g = new NativeCallGraph { Goal = goal };
        g.Distance[goal] = 0;
        var queue = new Queue<NativeNode>();
        var unscanned = new HashSet<string>(StringComparer.Ordinal);
        queue.Enqueue(goal);
        while (queue.Count > 0)
        {
            ct.ThrowIfCancellationRequested();
            var n = queue.Dequeue();
            int d = g.Distance[n];
            var preds = Predecessors(n, indirect, g.Notes, unscanned, ct);
            foreach (var m in link.ManagedLinksAt(n.Image, n.Start, ct)) g.Managed.Add(new ManagedEntry(m, n, d));
            if (Root(n, preds.Count) is { } why) g.RootKinds[n] = why;
            if (d >= maxDepth)
            {
                if (preds.Count > 0) g.Frontier++;
                continue;
            }
            foreach (var hop in preds)
            {
                if (!g.Distance.TryGetValue(hop.From, out int known))
                {
                    if (g.Distance.Count >= MaxVisited) { g.Cut = true; g.Frontier++; continue; }
                    g.Distance[hop.From] = known = d + 1;
                    queue.Enqueue(hop.From);
                }
                if (known != d + 1) continue;
                if (!g.Toward.TryGetValue(hop.From, out var list)) g.Toward[hop.From] = list = [];
                if (!list.Any(h => h.To == hop.To && h.Edge == hop.Edge)) list.Add(hop);
            }
        }
        if (g.Cut) g.Notes.Add($"the search stopped at {MaxVisited:N0} functions");
        if (unscanned.Count > 0)
            g.Notes.Add($"calls through function pointers are not followed in {string.Join(", ", unscanned.Order(StringComparer.Ordinal))}: " +
                        "resolve_call_targets scope=image resolves them once per image, and later searches use them");
        return g;
    }

    /// <summary>Why a function starts control flow, or null.</summary>
    private string? Root(NativeNode n, int callers)
    {
        var image = n.Image.Image;
        if (n.Start == image.EntryPointRva) return "entry point";
        if (image.Exports.Any(e => e.Rva == n.Start && e.ForwardedTo == null)) return "export";
        if (image.TlsCallbackRvas.Contains(n.Start)) return "TLS callback";
        if (callers > 0 || code.Ready(n.Image) is not { } index) return null;
        var refs = index.RefsTo(n.Start);
        if (refs.Any(x => x.Kind == XrefKind.Address)) return "address taken (callback)";
        if (refs.Any(x => x.Kind == XrefKind.Pointer)) return "pointer in data (vftable or table)";
        return "no callers";
    }

    private List<NativeHop> Predecessors(NativeNode n, bool indirect, List<string> notes, HashSet<string> unscanned, CancellationToken ct)
    {
        var result = new List<NativeHop>();
        if (code.Ready(n.Image) is not { } index)
        {
            if (notes.Count < 10) notes.Add($"{n.Image.Id}: the code index is not built yet; its callers are not known");
            return result;
        }
        if (index.FunctionByStart(n.Start) is not { } fn) return result;
        foreach (var c in index.Callers(fn, indirect ? CallEdgeFilter.All : CallEdgeFilter.Direct))
            if (c.Caller is { } caller)
                result.Add(new NativeHop(new NativeNode(n.Image, caller.Start), n, c.Kind switch
                {
                    XrefKind.TailCall => "tail",
                    XrefKind.VirtualExact => "virtual_exact",
                    XrefKind.VirtualPossible => "virtual_possible",
                    _ => "call",
                }, c.From));
        if (indirect && CallAnalysis.Supports(index))
        {
            if (Pointers(CallAnalysis.For(index)) is { } pointers)
                foreach (var (site, caller) in pointers.GetValueOrDefault(n.Start) ?? [])
                    result.Add(new NativeHop(new NativeNode(n.Image, caller), n, "pointer", site));
            else unscanned.Add(n.Image.Id);
        }
        foreach (var (importer, import) in link.ImportersOf(n.Image, n.Start, ct))
            if (code.Ready(importer) is { } other)
                foreach (var c in other.Callers(import))
                    if (c.Caller is { } caller)
                        result.Add(new NativeHop(new NativeNode(importer, caller.Start), n, "import", c.From));
        return result;
    }

    /// <summary>
    /// Callers through function pointers that resolve_call_targets resolved (writers of globals, tables, constants), by target;
    /// null until its image-wide scan has run, which can take long on a large image.
    /// </summary>
    private static Dictionary<uint, List<(uint Site, uint Caller)>>? Pointers(CallAnalysis a)
    {
        int version = a.Index.Sourced.Version;
        if (PointerCallers.TryGetValue(a, out var hit) && hit.Item1 == version) return hit.Item2;
        if (CallTargets.ImageIfComputed(a, deep: false) is not { } sites) return null;
        var map = new Dictionary<uint, List<(uint, uint)>>();
        foreach (var s in sites)
        {
            if (s.Status is "virtual_exact" or "virtual_possible" or "import" or "unresolved") continue;
            foreach (var t in s.Targets)
                if (a.Index.FunctionByStart(t.Address) != null && t.Basis is not ("import_slot" or "thunk_import"))
                {
                    if (!map.TryGetValue(t.Address, out var list)) map[t.Address] = list = [];
                    list.Add((s.Rva, s.Function.Start));
                }
        }
        PointerCallers.AddOrUpdate(a, Tuple.Create(version, map));
        return map;
    }
}
