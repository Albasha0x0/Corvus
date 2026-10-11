using System.Buffers.Binary;
using NetDecompilerMcp.Native.Code;

namespace NetDecompilerMcp.Native.Calls;

public enum TraceDirection : byte { Backward, Forward, Both }

/// <param name="MaxDepth">Function boundaries crossed (into callers, callees, writers and readers of globals).</param>
/// <param name="MaxFunctions">Distinct functions sliced.</param>
/// <param name="MaxCallers">Call sites bound per parameter or return.</param>
/// <param name="MaxWriters">Writers (backward) or readers (forward) followed per global.</param>
/// <param name="MaxSteps">Instruction steps over all slices.</param>
public sealed record ValueTraceOptions(TraceDirection Direction = TraceDirection.Backward, int MaxDepth = 3, int MaxFunctions = 32, int MaxNodes = 500,
    int MaxCallers = 16, int MaxWriters = 16, bool FollowGlobals = true, int MaxSteps = 200_000);

public enum TraceSeedKind : byte
{
    /// <summary>A register or stack / frame slot at an instruction.</summary>
    Location,
    /// <summary>An argument of the call at the address.</summary>
    Argument,
    /// <summary>An incoming parameter of the function starting at the address.</summary>
    Parameter,
    /// <summary>The value the call at the address returns.</summary>
    Result,
    /// <summary>A writable global at the address: its writers (backward) or readers (forward).</summary>
    Global,
}

/// <param name="Location">Location: the register or slot at the instruction; Argument / Parameter: the callee-entry location.</param>
/// <param name="Param">The API parameter the value meets (decodes constants), when known.</param>
/// <param name="Returns">What the API whose result is traced returns (decodes compares), when known.</param>
public sealed record TraceSeed(TraceSeedKind Kind, uint Address, NativeFunction? Function, string? Location, string Description,
    ApiParam? Param = null, ApiReturn? Returns = null);

/// <summary>Node kinds of a value trace.</summary>
public enum TraceNodeKind : byte
{
    Seed, Const, Address, String, Function, Import, ApiResult, CallResult, Parameter, Global, Field, StackLocal, Merge, Loop, Unknown,
    Argument, Sink, Store, FieldStore, Return, Compare, Switch, Dereference, CallTarget,
}

/// <param name="Address">The instruction that defines (backward) or uses (forward) the value; the global or the function for those nodes.</param>
/// <param name="ValueRva">The address the value is (strings, functions, globals).</param>
/// <param name="Decoded">The value named through the API parameter or return it meets (GENERIC_READ|GENERIC_WRITE, WAIT_TIMEOUT).</param>
/// <param name="Depth">Function boundaries crossed from the seed.</param>
/// <param name="Parent">The node it was reached from (-1 for the seed).</param>
public sealed record TraceNode(int Id, TraceNodeKind Kind, uint Address, NativeFunction? Function, string? Location, string Text, ulong? Value,
    uint? ValueRva, string? Decoded, int Depth, string Derivation, int Parent, bool Backward);

/// <summary>Data flows <see cref="From"/> to <see cref="To"/>.</summary>
public sealed record TraceEdge(int From, int To, string Kind, uint Site);

/// <summary>Something a budget left unexplored at <see cref="Node"/>, with the exact call that continues there.</summary>
public sealed record TraceFrontier(int Node, string Reason, string Detail, string Next);

/// <summary>A distinct terminal value (backward) or API the value reaches (forward).</summary>
public sealed record TraceValue(string Text, TraceNodeKind Kind, uint? Rva, int Node);

public sealed record ValueTraceGraph(TraceSeed Seed, ValueTraceOptions Options, string Engine, IReadOnlyList<TraceNode> Nodes, IReadOnlyList<TraceEdge> Edges,
    IReadOnlyList<TraceFrontier> Frontier, IReadOnlyList<TraceValue> Values, int Functions, int Steps, IReadOnlyList<string> Notes);

/// <summary>What the trace driver needs from an instruction set's analysis besides its per-function slices.</summary>
internal interface ITraceHost
{
    NativeCodeIndex Index { get; }
    bool Is64 { get; }
    ValueTraceCache Traces { get; }
    IFunctionSliceProvider Slices { get; }
    /// <summary>Where functions return their integer result ("rax", "x0").</summary>
    string ReturnLocation { get; }
    string Va(uint rva);
    bool IsRelocated(uint rva);
    (ArgKind Kind, ulong? Value, uint? Rva, string Text) FormatAddress(uint rva, ApiParam? p);
    /// <summary>Where the callee-entry location <paramref name="entry"/> is at the call or tail jump <paramref name="site"/>.</summary>
    string AtCall(NativeFunction f, uint site, string entry, CancellationToken ct);
    /// <summary>The constant <paramref name="location"/> holds just after the instruction at <paramref name="address"/>, or null.</summary>
    ulong? ConstantAfter(NativeFunction f, uint address, string location, CancellationToken ct);
}

/// <summary>
/// Interprocedural value tracing composed from per-function slices (<see cref="IFunctionSliceProvider"/>): backward from a
/// use to the values that reach it (merges, loops, parameters bound to every caller's argument, callee return values,
/// writers of globals), forward from a definition to its uses (call arguments into callees, returns into callers' uses,
/// stores to globals into their readers). Constants are named through the API parameter or return they meet. Budgets on
/// depth, functions, nodes, callers, writers and steps; whatever a budget stops is a frontier entry with the follow-up call.
/// </summary>
public sealed class ValueTrace
{
    private readonly ITraceHost _a;
    private readonly IFunctionSliceProvider _p;
    private readonly TraceSeed _seed;
    private readonly ValueTraceOptions _o;
    private readonly CancellationToken _ct;
    private readonly List<TraceNode> _nodes = [];
    private readonly List<TraceEdge> _edges = [];
    private readonly List<TraceFrontier> _frontier = [];
    private readonly List<string> _notes = [];
    private readonly HashSet<uint> _functions = [];
    private readonly Dictionary<string, int> _expanded = [];
    private readonly Queue<Expansion> _queue = new();
    private int _steps;
    private bool _nodesFull;

    private enum Step : byte { Callers, Returns, Writers, IntoCallee, ResultUses, Readers }

    /// <summary>A boundary node to continue from: <see cref="Key"/> identifies it across the graph (recursion, repeats).</summary>
    private sealed record Expansion(Step Step, int Node, NativeFunction? Function, int Depth, bool Backward, string Key, string? Location, int Index,
        uint Rva, ApiParam? Param, ApiReturn? Returns);

    private ValueTrace(ITraceHost a, IFunctionSliceProvider p, TraceSeed seed, ValueTraceOptions o, CancellationToken ct)
    {
        _a = a;
        _p = p;
        _seed = seed;
        _o = o;
        _ct = ct;
    }

    private NativeCodeIndex Index => _a.Index;
    private string Va(uint rva) => _a.Va(rva);

    /// <summary>Builds the graph (cached per index: the same seed and options return the same graph until names change).</summary>
    internal static ValueTraceGraph Build(ITraceHost analysis, TraceSeed seed, ValueTraceOptions options, IFunctionSliceProvider? provider = null,
        CancellationToken ct = default)
    {
        provider ??= analysis.Slices;
        var key = $"{provider.Engine}|{seed.Kind}|{seed.Address}|{seed.Location}|{seed.Param?.Name}|{options}|{analysis.Index.Sourced.Version}";
        return analysis.Traces.GetOrAdd(key, () => new ValueTrace(analysis, provider, seed, options, ct).Run());
    }

    private ValueTraceGraph Run()
    {
        var seedNode = AddNode(TraceNodeKind.Seed, _seed.Address, _seed.Function, _seed.Location, _seed.Description, null, null, null, 0, "", -1, true);
        if (_seed.Function != null) _functions.Add(_seed.Function.Start);
        if (_o.Direction != TraceDirection.Forward) StartBackward(seedNode);
        if (_o.Direction != TraceDirection.Backward) StartForward(seedNode);
        while (_queue.Count > 0)
        {
            _ct.ThrowIfCancellationRequested();
            var e = _queue.Dequeue();
            if (_nodesFull) { Frontier(e, "nodes", $"the node budget ({_o.MaxNodes}) is used"); continue; }
            if (_steps > _o.MaxSteps) { Frontier(e, "steps", $"the step budget ({_o.MaxSteps}) is used"); continue; }
            Expand(e);
        }
        return new ValueTraceGraph(_seed, _o, _p.Engine, _nodes, _edges, _frontier, Values(), _functions.Count, _steps, _notes);
    }

    private void StartBackward(int seedNode)
    {
        var f = _seed.Function;
        switch (_seed.Kind)
        {
            case TraceSeedKind.Global:
                Enqueue(new Expansion(Step.Writers, seedNode, null, 0, true, $"writers:{_seed.Address}", null, -1, _seed.Address, _seed.Param, null));
                return;
            case TraceSeedKind.Location or TraceSeedKind.Argument or TraceSeedKind.Parameter or TraceSeedKind.Result when f != null:
            {
                var kind = _seed.Kind switch
                {
                    TraceSeedKind.Argument => SliceSeedKind.Argument,
                    TraceSeedKind.Parameter => SliceSeedKind.Parameter,
                    TraceSeedKind.Result => SliceSeedKind.Result,
                    _ => SliceSeedKind.Location,
                };
                var slice = Slice(f, new SliceSeed(kind, _seed.Address, _seed.Location), forward: false);
                Materialize(slice, 0, seedNode, true, _seed.Kind == TraceSeedKind.Argument ? "argument" : "copy", _seed.Address, _seed.Param, null);
                return;
            }
        }
    }

    private void StartForward(int seedNode)
    {
        var f = _seed.Function;
        switch (_seed.Kind)
        {
            case TraceSeedKind.Global:
                Enqueue(new Expansion(Step.Readers, seedNode, null, 0, false, $"readers:{_seed.Address}", null, -1, _seed.Address, null, null));
                return;
            case TraceSeedKind.Argument when f != null && _seed.Location != null:
            {
                // the value in the argument's location at the call: its uses start with the call
                var atCall = _a.AtCall(f, _seed.Address, _seed.Location, _ct);
                Materialize(Slice(f, new SliceSeed(SliceSeedKind.Location, _seed.Address, atCall), forward: true), 0, seedNode, false, "copy", _seed.Address, _seed.Param, _seed.Returns);
                return;
            }
            case TraceSeedKind.Location or TraceSeedKind.Parameter or TraceSeedKind.Result when f != null:
            {
                var kind = _seed.Kind switch
                {
                    TraceSeedKind.Parameter => SliceSeedKind.Parameter,
                    TraceSeedKind.Result => SliceSeedKind.Result,
                    _ => SliceSeedKind.Location,
                };
                Materialize(Slice(f, new SliceSeed(kind, _seed.Address, _seed.Location), forward: true), 0, seedNode, false, "copy", _seed.Address, _seed.Param, _seed.Returns);
                return;
            }
        }
    }

    private FunctionSlice Slice(NativeFunction f, SliceSeed seed, bool forward)
    {
        _functions.Add(f.Start);
        var s = forward ? _p.Forward(f, seed, _ct) : _p.Backward(f, seed, _ct);
        _steps += s.Steps;
        if (s.Note != null && _notes.Count < 20) _notes.Add($"{f.Name}: {s.Note}");
        if (s.Truncated && s.Note == null && _notes.Count < 20) _notes.Add($"{f.Name}: slice cut at {OursSliceProvider.MaxSliceNodes} nodes");
        return s;
    }

    private int AddNode(TraceNodeKind kind, uint address, NativeFunction? f, string? location, string text, ulong? value, uint? valueRva, string? decoded,
        int depth, string derivation, int parent, bool backward)
    {
        int id = _nodes.Count;
        _nodes.Add(new TraceNode(id, kind, address, f, location, text, value, valueRva, decoded, depth, derivation, parent, backward));
        if (_nodes.Count >= _o.MaxNodes) _nodesFull = true;
        return id;
    }

    /// <summary>
    /// Adds a slice's nodes and edges. Backward: the slice's root feeds <paramref name="attach"/> through an edge of
    /// <paramref name="link"/>. Forward: the slice's origin is <paramref name="attach"/>. Boundary nodes are queued.
    /// </summary>
    private void Materialize(FunctionSlice s, int depth, int attach, bool backward, string link, uint site, ApiParam? param, ApiReturn? returns)
    {
        var map = new int[s.Nodes.Count];
        Array.Fill(map, -1);
        var parent = new int[s.Nodes.Count];
        Array.Fill(parent, -1);
        foreach (var e in s.Edges)
            if (backward) { if (parent[e.From] < 0) parent[e.From] = e.To; }
            else if (parent[e.To] < 0) parent[e.To] = e.From;
        if (!backward) map[s.Root] = attach;
        for (int i = 0; i < s.Nodes.Count; i++)
        {
            if (map[i] >= 0) continue;
            if (_nodesFull)
            {
                _frontier.Add(new TraceFrontier(attach, "nodes", $"{s.Nodes.Count - i} more nodes of the slice of {s.Function.Name}", Next(attach, backward)));
                break;
            }
            int from = i == s.Root ? attach : parent[i] >= 0 ? map[parent[i]] : attach;
            map[i] = Convert(s.Nodes[i], s.Function, depth, from < 0 ? attach : from, backward, param, returns);
        }
        if (backward && map[s.Root] >= 0) _edges.Add(new TraceEdge(map[s.Root], attach, link, site));
        foreach (var e in s.Edges)
            if (map[e.From] >= 0 && map[e.To] >= 0)
                _edges.Add(new TraceEdge(map[e.From], map[e.To], e.Kind.ToString().ToLowerInvariant(), 0));
        for (int i = 0; i < s.Nodes.Count; i++)
            if (map[i] >= 0 && (i != s.Root || backward)) Boundary(s.Nodes[i], map[i], s.Function, depth, backward, param, returns);
    }

    private TraceNode Get(int id) => _nodes[id];

    /// <summary>A slice node as a graph node: constants and addresses named in the context of the API parameter they meet.</summary>
    private int Convert(SliceNode n, NativeFunction f, int depth, int parent, bool backward, ApiParam? param, ApiReturn? returns)
    {
        int Add(TraceNodeKind kind, string text, ulong? value = null, uint? rva = null, string? decoded = null, string? location = null) =>
            AddNode(kind, n.Address, f, location ?? n.Location, text, value, rva, decoded, depth, n.Derivation, parent, backward);
        switch (n.Kind)
        {
            case SliceNodeKind.Constant:
            {
                var text = CallAnalysis.FormatNumber(n.Value, param);
                var hex = n.Value < 10 ? n.Value.ToString() : $"0x{n.Value:X}";
                return Add(TraceNodeKind.Const, text == hex || param == null ? hex : $"{hex} = {text}", n.Value, decoded: param?.Type is ApiParamType.Enum or ApiParamType.Bool ? text : null);
            }
            case SliceNodeKind.Address:
            {
                var (kind, _, rva, text) = _a.FormatAddress(n.Rva, param);
                var nodeKind = kind switch
                {
                    ArgKind.String => TraceNodeKind.String,
                    ArgKind.Name when Index.FunctionByStart(n.Rva) != null => TraceNodeKind.Function,
                    _ => TraceNodeKind.Address,
                };
                return Add(nodeKind, text, rva: rva ?? n.Rva);
            }
            case SliceNodeKind.Import: return Add(TraceNodeKind.Import, n.Text, rva: n.Rva);
            case SliceNodeKind.Global: return Add(TraceNodeKind.Global, n.Text, rva: n.Rva);
            case SliceNodeKind.Field: return Add(TraceNodeKind.Field, n.Text, n.Value);
            case SliceNodeKind.StackAddress or SliceNodeKind.TakenLocal: return Add(TraceNodeKind.StackLocal, n.Text);
            case SliceNodeKind.Merge: return Add(TraceNodeKind.Merge, n.Text + (n.Truncated ? $" (more than {ValueResolver.MaxSlicePaths} paths: the first {ValueResolver.MaxSlicePaths})" : ""));
            case SliceNodeKind.Loop: return Add(TraceNodeKind.Loop, n.Text);
            case SliceNodeKind.Parameter: return Add(TraceNodeKind.Parameter, $"{n.Text} of {f.Name}");
            case SliceNodeKind.CallResult:
            {
                if (n.CallKind is CalleeKind.Import or CalleeKind.Dynamic)
                {
                    var r = ApiSignatures.FindReturn(n.Callee);
                    return Add(TraceNodeKind.ApiResult, n.Text, decoded: r == null ? null : r.Enum != null ? $"{r.Meaning}: {string.Join(" | ", r.Enum.Entries.Take(6).Select(e => e.Name))}{(r.Enum.Entries.Count > 6 ? " | ..." : "")}" : r.Meaning);
                }
                return Add(TraceNodeKind.CallResult, n.Text);
            }
            case SliceNodeKind.Origin: return Add(TraceNodeKind.Unknown, n.Text);
            case SliceNodeKind.Argument:
            {
                var sig = n.Target == null ? ApiSignatures.Find(n.Callee) : null;
                var p = sig != null && n.Index >= 0 && n.Index < sig.Params.Count ? sig.Params[n.Index] : null;
                string? decoded = SeedConstant is { } v && !n.Derived && p != null ? CallAnalysis.FormatNumber(v, p) : null;
                return Add(n.Target != null ? TraceNodeKind.Argument : TraceNodeKind.Sink, n.Text + (p != null ? $" ({p.TypeName})" : ""), decoded: decoded);
            }
            case SliceNodeKind.Store: return Add(TraceNodeKind.Store, n.Text, rva: n.Rva);
            case SliceNodeKind.FieldStore: return Add(TraceNodeKind.FieldStore, n.Text);
            case SliceNodeKind.Return: return Add(TraceNodeKind.Return, n.Text);
            case SliceNodeKind.Compare:
            {
                string? decoded = !n.Truncated && returns?.Enum?.Describe(n.Value) is { } name ? $"compared with {name}" : null;
                return Add(TraceNodeKind.Compare, n.Text, n.Truncated ? null : n.Value, decoded: decoded);
            }
            case SliceNodeKind.Switch: return Add(TraceNodeKind.Switch, n.Text);
            case SliceNodeKind.Dereference: return Add(TraceNodeKind.Dereference, n.Text);
            case SliceNodeKind.CallTarget: return Add(TraceNodeKind.CallTarget, n.Text);
            default: return Add(TraceNodeKind.Unknown, n.Text == "?" ? "unknown" : n.Text);
        }
    }

    private ulong? _seedConstant;
    private bool _seedConstantDone;

    /// <summary>The seed's value when it is a constant (forward: decodes the API parameters it reaches).</summary>
    private ulong? SeedConstant
    {
        get
        {
            if (_seedConstantDone) return _seedConstant;
            _seedConstantDone = true;
            if (_seed.Function == null || _seed.Kind != TraceSeedKind.Location || _seed.Location == null) return null;
            _seedConstant = _a.ConstantAfter(_seed.Function, _seed.Address, _seed.Location, _ct);
            return _seedConstant;
        }
    }

    private void Boundary(SliceNode n, int node, NativeFunction f, int depth, bool backward, ApiParam? param, ApiReturn? returns)
    {
        switch (n.Kind)
        {
            case SliceNodeKind.Parameter when backward:
                Enqueue(new Expansion(Step.Callers, node, f, depth, true, $"callers:{f.Start}:{n.Location}", n.Location, n.Index, 0, param, null));
                break;
            case SliceNodeKind.CallResult when backward && n.Target is { } t && Index.FunctionByStart(t) is { } callee:
                Enqueue(new Expansion(Step.Returns, node, callee, depth, true, $"returns:{callee.Start}", null, -1, n.Site, param, null));
                break;
            case SliceNodeKind.CallResult when backward && n.CallKind is CalleeKind.Indirect or CalleeKind.VirtualPossible:
                _nodes[node] = Get(node) with { Derivation = Get(node).Derivation + " (callee not resolved: resolve_call_targets address=" + Va(n.Site) + ")" };
                break;
            case SliceNodeKind.Global when backward && _o.FollowGlobals:
                Enqueue(new Expansion(Step.Writers, node, null, depth, true, $"writers:{n.Rva}", null, -1, n.Rva, param, null));
                break;
            case SliceNodeKind.Argument when !backward && n.Target is { } t && Index.FunctionByStart(t) is { } callee:
                Enqueue(new Expansion(Step.IntoCallee, node, callee, depth, false, $"callee:{callee.Start}:{n.Location}", n.Location, n.Index, n.Site, null, null));
                break;
            case SliceNodeKind.Return when !backward:
                Enqueue(new Expansion(Step.ResultUses, node, f, depth, false, $"results:{f.Start}", n.Location, -1, 0, null, returns));
                break;
            case SliceNodeKind.Store when !backward && _o.FollowGlobals:
                Enqueue(new Expansion(Step.Readers, node, null, depth, false, $"readers:{n.Rva}", null, -1, n.Rva, null, returns));
                break;
        }
    }

    private void Enqueue(Expansion e)
    {
        if (_expanded.TryGetValue(e.Key, out int earlier))
        {
            // reached again (recursion, or a second path to the same boundary): link instead of expanding twice
            if (earlier != e.Node) _edges.Add(new TraceEdge(earlier, e.Node, "loop", 0));
            return;
        }
        _expanded[e.Key] = e.Node;
        if (e.Depth >= _o.MaxDepth && e.Step is not (Step.Writers or Step.Readers) || e.Depth > _o.MaxDepth)
        {
            Frontier(e, "depth", $"maxDepth={_o.MaxDepth} reached");
            return;
        }
        _queue.Enqueue(e);
    }

    private void Frontier(Expansion e, string reason, string detail) => _frontier.Add(new TraceFrontier(e.Node, reason, detail, Next(e)));

    private string Direction(bool backward) => backward ? "" : " direction=forward";

    /// <summary>The call that continues from an expansion.</summary>
    private string Next(Expansion e)
    {
        const string T = "trace_native_values";
        switch (e.Step)
        {
            case Step.Callers:
                return $"{T} address={Va(e.Function!.Start)} {(e.Index >= 0 ? $"argument={e.Index + 1}" : $"location={e.Location}")}";
            case Step.Returns:
                return $"{T} address={Va(e.Rva)} location=result";
            case Step.Writers or Step.Readers:
                return $"{T} address={Va(e.Rva)}{Direction(e.Backward)}";
            case Step.IntoCallee:
                return $"{T} address={Va(e.Function!.Start)} {(e.Index >= 0 ? $"argument={e.Index + 1}" : $"location={e.Location}")} direction=forward";
            default:
            {
                var callers = Index.Callers(e.Function!);
                return callers.Count == 1
                    ? $"{T} address={Va(callers[0].From)} location=result direction=forward"
                    : $"find_xrefs address={Va(e.Function!.Start)} lists the {callers.Count} call sites; then {T} address=<call> location=result direction=forward";
            }
        }
    }

    /// <summary>The follow-up for a node whose slice the node budget cut.</summary>
    private string Next(int node, bool backward)
    {
        var n = Get(node);
        return n.Kind == TraceNodeKind.Seed
            ? $"trace_native_values with a larger maxNodes (now {_o.MaxNodes})"
            : $"trace_native_values address={Va(n.Address)}{(n.Location != null ? $" location={n.Location}" : "")}{Direction(backward)}";
    }

    private bool CanEnter(NativeFunction f) => _functions.Contains(f.Start) || _functions.Count < _o.MaxFunctions;

    private void Expand(Expansion e)
    {
        switch (e.Step)
        {
            case Step.Callers: Callers(e); break;
            case Step.Returns:
                if (!CanEnter(e.Function!)) { Frontier(e, "functions", $"maxFunctions={_o.MaxFunctions} reached"); break; }
                Materialize(Slice(e.Function!, new SliceSeed(SliceSeedKind.Returns, e.Function!.Start, _a.ReturnLocation), false), e.Depth + 1, e.Node, true, "return", e.Rva, e.Param, null);
                break;
            case Step.Writers: Writers(e); break;
            case Step.IntoCallee:
            {
                if (!CanEnter(e.Function!)) { Frontier(e, "functions", $"maxFunctions={_o.MaxFunctions} reached"); break; }
                var slice = Slice(e.Function!, new SliceSeed(SliceSeedKind.Parameter, e.Function!.Start, e.Location), true);
                int origin = AddNode(TraceNodeKind.Parameter, e.Function!.Start, e.Function, e.Location,
                    $"{(e.Index >= 0 ? $"parameter {e.Index + 1}" : e.Location)} of {e.Function!.Name}", null, null, null, e.Depth + 1, "", e.Node, false);
                _edges.Add(new TraceEdge(e.Node, origin, "parameter", e.Rva));
                Materialize(slice, e.Depth + 1, origin, false, "parameter", e.Rva, null, null);
                break;
            }
            case Step.ResultUses: ResultUses(e); break;
            case Step.Readers: Readers(e); break;
        }
    }

    private void Callers(Expansion e)
    {
        var f = e.Function!;
        var sites = Index.Callers(f).DistinctBy(c => c.From).Where(c => c.Caller != null).ToList();
        if (sites.Count == 0)
        {
            _nodes[e.Node] = Get(e.Node) with { Derivation = AppendNote(Get(e.Node).Derivation, "no known callers (an export, a callback or a pointer call)") };
            return;
        }
        int taken = 0;
        foreach (var c in sites)
        {
            if (taken >= _o.MaxCallers)
            {
                _frontier.Add(new TraceFrontier(e.Node, "callers", $"{sites.Count - taken} more of {sites.Count} call sites",
                    $"trace_native_values address={Va(f.Start)} {(e.Index >= 0 ? $"argument={e.Index + 1}" : $"location={e.Location}")} maxCallers={Math.Min(256, sites.Count)}"));
                break;
            }
            if (_nodesFull) { _frontier.Add(new TraceFrontier(e.Node, "nodes", $"{sites.Count - taken} call sites not bound", Next(e))); break; }
            taken++;
            var caller = c.Caller!;
            var argNext = $"trace_native_values address={Va(c.From)} {(e.Index >= 0 ? $"argument={e.Index + 1}" : $"location={e.Location}")}";
            if (!CanEnter(caller)) { _frontier.Add(new TraceFrontier(e.Node, "functions", $"call site {Where(c.From)}: maxFunctions={_o.MaxFunctions} reached", argNext)); continue; }
            Materialize(Slice(caller, new SliceSeed(SliceSeedKind.Argument, c.From, e.Location), false), e.Depth + 1, e.Node, true, "argument", c.From, e.Param, null);
        }
    }

    private void ResultUses(Expansion e)
    {
        var f = e.Function!;
        var sites = Index.Callers(f).DistinctBy(c => c.From).Where(c => c.Caller != null && c.Kind != XrefKind.TailCall).ToList();
        int taken = 0;
        foreach (var c in sites)
        {
            if (taken >= _o.MaxCallers)
            {
                _frontier.Add(new TraceFrontier(e.Node, "callers", $"{sites.Count - taken} more of {sites.Count} call sites", Next(e)));
                break;
            }
            if (_nodesFull) { _frontier.Add(new TraceFrontier(e.Node, "nodes", $"{sites.Count - taken} call sites not followed", Next(e))); break; }
            taken++;
            if (!CanEnter(c.Caller!))
            {
                _frontier.Add(new TraceFrontier(e.Node, "functions", $"call site {Where(c.From)}: maxFunctions={_o.MaxFunctions} reached",
                    $"trace_native_values address={Va(c.From)} location=result direction=forward"));
                continue;
            }
            var slice = Slice(c.Caller!, new SliceSeed(SliceSeedKind.Result, c.From, e.Location), true);
            int origin = AddNode(TraceNodeKind.CallResult, c.From, c.Caller, e.Location, $"result of {f.Name} at {Where(c.From)}", null, null, null, e.Depth + 1, "", e.Node, false);
            _edges.Add(new TraceEdge(e.Node, origin, "return", c.From));
            Materialize(slice, e.Depth + 1, origin, false, "return", c.From, null, e.Returns);
        }
    }

    private void Writers(Expansion e)
    {
        uint g = e.Rva;
        var writers = Index.RefsTo(g).Where(x => x.Kind == XrefKind.Write).DistinctBy(x => x.From).ToList();
        if (Initial(g, writers.Count == 0) is { } init)
        {
            int id = AddNode(init.Kind, g, null, null, init.Text, init.Value, init.Rva, null, e.Depth, $"initial contents of {Va(g)} in the image", e.Node, true);
            _edges.Add(new TraceEdge(id, e.Node, "store", g));
        }
        if (writers.Count == 0)
        {
            _nodes[e.Node] = Get(e.Node) with { Derivation = AppendNote(Get(e.Node).Derivation, "no instruction writes it directly (written through a pointer, by another module, or never)") };
            return;
        }
        int taken = 0;
        foreach (var w in writers)
        {
            if (taken >= _o.MaxWriters)
            {
                _frontier.Add(new TraceFrontier(e.Node, "writers", $"{writers.Count - taken} more of {writers.Count} writers",
                    $"trace_native_values address={Va(g)} maxWriters={Math.Min(256, writers.Count)}"));
                break;
            }
            if (_nodesFull) { _frontier.Add(new TraceFrontier(e.Node, "nodes", $"{writers.Count - taken} writers not followed", Next(e))); break; }
            taken++;
            if (Index.FunctionAt(w.From) is not { } fn)
            {
                int id = AddNode(TraceNodeKind.Unknown, w.From, null, null, $"written at {Va(w.From)} outside any known function", null, null, null, e.Depth + 1, "", e.Node, true);
                _edges.Add(new TraceEdge(id, e.Node, "store", w.From));
                continue;
            }
            if (!CanEnter(fn)) { _frontier.Add(new TraceFrontier(e.Node, "functions", $"writer {Where(w.From)}: maxFunctions={_o.MaxFunctions} reached", Next(e))); continue; }
            Materialize(Slice(fn, new SliceSeed(SliceSeedKind.Stored, w.From), false), e.Depth + 1, e.Node, true, "store", w.From, e.Param, null);
        }
    }

    private void Readers(Expansion e)
    {
        uint g = e.Rva;
        var readers = Index.RefsTo(g).Where(x => x.Kind == XrefKind.Read).DistinctBy(x => x.From).ToList();
        int taken = 0;
        foreach (var r in readers)
        {
            if (taken >= _o.MaxWriters)
            {
                _frontier.Add(new TraceFrontier(e.Node, "readers", $"{readers.Count - taken} more of {readers.Count} readers",
                    $"trace_native_values address={Va(g)} direction=forward maxWriters={Math.Min(256, readers.Count)}"));
                break;
            }
            if (_nodesFull) { _frontier.Add(new TraceFrontier(e.Node, "nodes", $"{readers.Count - taken} readers not followed", Next(e))); break; }
            taken++;
            if (Index.FunctionAt(r.From) is not { } fn) continue;
            if (!CanEnter(fn)) { _frontier.Add(new TraceFrontier(e.Node, "functions", $"reader {Where(r.From)}: maxFunctions={_o.MaxFunctions} reached", Next(e))); continue; }
            var slice = Slice(fn, new SliceSeed(SliceSeedKind.Loaded, r.From), true);
            int origin = AddNode(TraceNodeKind.Global, r.From, fn, null, $"read of [{Index.NameAt(g) ?? Va(g)}] at {Where(r.From)}", null, g, null, e.Depth + 1, "", e.Node, false);
            _edges.Add(new TraceEdge(e.Node, origin, "load", r.From));
            Materialize(slice, e.Depth + 1, origin, false, "load", r.From, null, e.Returns);
        }
    }

    /// <summary>A global's initial contents: a relocated pointer, or a number when nonzero (or when nothing writes it).</summary>
    private (TraceNodeKind Kind, string Text, ulong? Value, uint? Rva)? Initial(uint g, bool always)
    {
        int size = _a.Is64 ? 8 : 4;
        Span<byte> b = stackalloc byte[8];
        b.Clear();
        if (Index.Image.Read(g, b[..size]) != size) return null;
        ulong v = BinaryPrimitives.ReadUInt64LittleEndian(b);
        if (_a.IsRelocated(g) && FunctionCode.TryRva(Index.Image, _a.Is64, v, out uint target))
        {
            var (kind, _, _, text) = _a.FormatAddress(target, null);
            return (Index.FunctionByStart(target) != null ? TraceNodeKind.Function : kind == ArgKind.String ? TraceNodeKind.String : TraceNodeKind.Address, $"{text} (initial contents)", null, target);
        }
        if (v == 0 && !always) return null;
        return (TraceNodeKind.Const, $"{(v < 10 ? v.ToString() : $"0x{v:X}")} (initial contents)", v, null);
    }

    private string Where(uint rva) => Index.FunctionAt(rva) is { } f ? $"{f.Name}+0x{rva - f.Start:X}" : Va(rva);

    private static string AppendNote(string derivation, string note) => derivation.Length == 0 ? note : derivation + "; " + note;

    private static readonly HashSet<TraceNodeKind> Terminal =
        [TraceNodeKind.Const, TraceNodeKind.String, TraceNodeKind.Function, TraceNodeKind.Address, TraceNodeKind.Import, TraceNodeKind.ApiResult];

    private List<TraceValue> Values()
    {
        var result = new List<TraceValue>();
        var seen = new HashSet<string>();
        foreach (var n in _nodes)
        {
            bool backwardValue = n.Backward && Terminal.Contains(n.Kind);
            bool forwardSink = !n.Backward && n.Kind == TraceNodeKind.Sink;
            if (!backwardValue && !forwardSink) continue;
            var text = n.Decoded != null && n.Kind == TraceNodeKind.Sink ? $"{n.Text} = {n.Decoded}" : n.Text;
            if (seen.Add(n.Kind + text)) result.Add(new TraceValue(text, n.Kind, n.ValueRva, n.Id));
        }
        return result;
    }
}

/// <summary>Built value-trace graphs of one image, most recent first; pages of a trace are served from here.</summary>
public sealed class ValueTraceCache
{
    private const int Capacity = 32;
    private readonly LinkedList<(string Key, ValueTraceGraph Graph)> _graphs = new();
    private int _builds;

    /// <summary>Graphs built (not served from the cache).</summary>
    public int Builds => Volatile.Read(ref _builds);

    public ValueTraceGraph GetOrAdd(string key, Func<ValueTraceGraph> build)
    {
        lock (_graphs)
            for (var node = _graphs.First; node != null; node = node.Next)
                if (node.Value.Key == key)
                {
                    _graphs.Remove(node);
                    _graphs.AddFirst(node);
                    return node.Value.Graph;
                }
        var graph = build();
        Interlocked.Increment(ref _builds);
        lock (_graphs)
        {
            _graphs.AddFirst((key, graph));
            while (_graphs.Count > Capacity) _graphs.RemoveLast();
        }
        return graph;
    }
}
