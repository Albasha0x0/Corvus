using System.Runtime.CompilerServices;
using Corvus.Core;
using Corvus.Native;
using Corvus.Native.Calls;
using Corvus.Native.Code;
using Corvus.Native.Providers;

namespace Corvus.Services;

/// <summary>A function of a loaded native image.</summary>
public readonly record struct NativeNode(LoadedNative Image, uint Start);

/// <summary>
/// A call from <see cref="From"/> to <see cref="To"/> at <see cref="Site"/> (in From's image). Edge: call, tail, import
/// (through an import bound to the other image), virtual_exact, virtual_possible, pointer (a call through a function
/// pointer held in data, a global or a register) or engine (a call reference only the open IDA / Ghidra session has).
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

    private static int EdgeRank(string edge) => edge switch { "call" or "tail" => 0, "import" or "engine" => 1, "virtual_exact" => 2, "pointer" => 3, _ => 4 };

    internal static int RootRank(string root) => root switch
    {
        "from" => 0, "entry point" => 1, "export" => 2, "TLS callback" => 3, "no callers" => 4, _ => 5,
    };
}

/// <summary>
/// Shortest call chains to a native function across loaded images: a backward search over the in-memory call graph
/// (direct and tail calls, imports bound between images, the open engine session's call references, RTTI virtual calls
/// and calls through function pointers when asked), then a bounded enumeration over distance-decreasing edges
/// (<see cref="NativeCallGraph.Chains"/>).
/// </summary>
public sealed class NativeCallPaths(NativeLinkService link, NativeCodeService code)
{
    public const int MaxVisited = 50_000;
    /// <summary>Functions searched for calls through the pointers to one function.</summary>
    private const int MaxPointerUsers = 64;
    private static readonly ConditionalWeakTable<CallAnalysis, Tuple<int, Dictionary<uint, List<(uint Site, uint Caller)>>>> PointerCallers = new();
    private static readonly ConditionalWeakTable<NativeCodeIndex, Dictionary<(int, uint), List<(uint Site, uint Caller)>>> TargetedPointers = new();

    /// <summary>Call references of an engine session open on an image: (site, caller start) of the calls to a function start.</summary>
    public Func<LoadedNative, uint, IReadOnlyList<(uint Site, uint Caller)>>? EngineCallers { get; init; }

    /// <summary>The call and jump references to a function in the IDA or Ghidra session already open on its image (none is started).</summary>
    public static Func<LoadedNative, uint, IReadOnlyList<(uint Site, uint Caller)>> FromEngines(NativeEngineService engines, NativeCodeService code, CancellationToken ct) =>
        (native, start) =>
        {
            if (engines.OpenSession(native) is not { } session) return [];
            var index = code.Ready(native);
            var result = new List<(uint, uint)>();
            foreach (var x in session.GetXrefsToAsync(start, ct).GetAwaiter().GetResult())
            {
                if (x.Kind is not (NativeXrefKind.Call or NativeXrefKind.Jump)) continue;
                uint caller = index?.FunctionAt(x.FromRva)?.Start ?? x.FromFunctionRva ?? x.FromRva;
                if (x.Kind == NativeXrefKind.Jump && caller == start) continue;
                result.Add((x.FromRva, caller));
            }
            return result;
        };

    /// <summary>
    /// Explores the callers of <paramref name="goal"/> backward up to <paramref name="maxDepth"/> calls and <see cref="MaxVisited"/> functions;
    /// <paramref name="goalCallers"/> replaces the goal's own callers (an import of a library that is not loaded: the calls through it).
    /// </summary>
    public NativeCallGraph Explore(NativeNode goal, int maxDepth, bool indirect, CancellationToken ct, IReadOnlyList<NativeHop>? goalCallers = null)
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
            var preds = goalCallers != null && n == goal ? goalCallers.ToList() : Predecessors(n, indirect, g.Notes, unscanned, ct);
            if (goalCallers == null || n != goal)
                foreach (var m in link.ManagedLinksAt(n.Image, n.Start, ct)) g.Managed.Add(new ManagedEntry(m, n, d));
            if (n != goal && Root(n, preds.Count) is { } why) g.RootKinds[n] = why;
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
            g.Notes.Add($"calls through function pointers were searched in part in {string.Join(", ", unscanned.Order(StringComparer.Ordinal))}: " +
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
        var index = code.Ready(n.Image);
        if (EngineCallers != null)
        {
            try
            {
                var known = index?.FunctionByStart(n.Start) is { } own ? index.Callers(own).Select(c => c.From).ToHashSet() : [];
                foreach (var (site, caller) in EngineCallers(n.Image, n.Start))
                    if (!known.Contains(site)) result.Add(new NativeHop(new NativeNode(n.Image, caller), n, "engine", site));
            }
            catch (ToolError e) { if (notes.Count < 10) notes.Add($"{n.Image.Id}: the engine's references were not read: {e.Message}"); }
        }
        if (index == null)
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
        if (indirect)
        {
            var pointers = CallAnalysis.Supports(index) && Pointers(CallAnalysis.For(index)) is { } scanned ? scanned.GetValueOrDefault(n.Start) ?? [] : Targeted(index, fn, unscanned, n.Image.Id, ct);
            foreach (var (site, caller) in pointers)
                result.Add(new NativeHop(new NativeNode(n.Image, caller), n, "pointer", site));
        }
        foreach (var (importer, import) in link.ImportersOf(n.Image, n.Start, ct))
            if (code.Ready(importer) is { } other)
                foreach (var c in other.Callers(import))
                    if (c.Caller is { } caller)
                        result.Add(new NativeHop(new NativeNode(importer, caller.Start), n, "import", c.From));
        return result;
    }

    /// <summary>
    /// Calls through pointers to <paramref name="fn"/>, found from its references: the data holding its address (a global, a table
    /// entry and the table's start) and the code taking it; the functions reading those places have their call sites resolved
    /// and the ones reaching <paramref name="fn"/> are kept. Bounded by <see cref="MaxPointerUsers"/> functions.
    /// </summary>
    private static List<(uint Site, uint Caller)> Targeted(NativeCodeIndex index, NativeFunction fn, HashSet<string> cut, string image, CancellationToken ct)
    {
        var cache = TargetedPointers.GetValue(index, _ => []);
        var key = (index.Sourced.Version, fn.Start);
        lock (cache) if (cache.TryGetValue(key, out var hit)) return hit;
        Func<NativeFunction, IEnumerable<CallTargetSite>>? sitesIn = CallAnalysis.Supports(index) ? f => CallTargets.In(CallAnalysis.For(index), f, false, ct)
            : Arm64Trace.Supports(index) ? f => Arm64CallTargets.In(Arm64Trace.For(index), f, false, ct) : null;
        var result = new List<(uint, uint)>();
        if (sitesIn == null) return result;
        int ptr = index.Image.Is64Bit ? 8 : 4;
        var places = new HashSet<uint>();
        var users = new List<NativeFunction>();
        void Use(NativeFunction f)
        {
            if (!users.Contains(f)) users.Add(f);
        }
        foreach (var x in index.RefsTo(fn.Start))
        {
            if (x.Kind is XrefKind.Call or XrefKind.TailCall or XrefKind.Jump or XrefKind.ConditionalJump) continue;
            if (index.FunctionAt(x.From) is { } taker)
            {
                // the address taken in code: called there, or stored to a global that is read elsewhere
                Use(taker);
                foreach (var (s, e) in index.Ranges(taker))
                    foreach (var w in index.RefsFrom(s, e).Where(r => r.Kind == XrefKind.Write && index.FunctionAt(r.To) == null)) places.Add(w.To);
                continue;
            }
            // a pointer in data, and the start of the table it is in
            places.Add(x.From);
            for (uint at = x.From, k = 0; k < 64 && at >= (uint)ptr && index.RefsFrom(at - (uint)ptr, at).Any(r => r.Kind == XrefKind.Pointer); k++)
            {
                at -= (uint)ptr;
                places.Add(at);
            }
        }
        foreach (var place in places)
            foreach (var r in index.RefsTo(place))
                if (index.FunctionAt(r.From) is { } reader) Use(reader);
        if (users.Count > MaxPointerUsers) cut.Add($"{image} (more than {MaxPointerUsers} functions use pointers to {fn.Name})");
        foreach (var f in users.Take(MaxPointerUsers))
        {
            ct.ThrowIfCancellationRequested();
            foreach (var s in sitesIn(f))
                if (s.IsIndirect && s.Status is not ("import" or "unresolved") && s.Targets.Any(t => t.Address == fn.Start)) result.Add((s.Rva, f.Start));
        }
        lock (cache)
        {
            if (cache.Count > 4096) cache.Clear();
            cache[key] = result;
        }
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
