using System.Buffers.Binary;
using Corvus.Native.Code;

namespace Corvus.Native.Calls;

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
    uint? ValueRva, string? Decoded, int Depth, string Derivation, int Parent, bool Backward)
{
    /// <summary>Index into <see cref="ValueTraceGraph.Images"/> of the image the addresses are in (0: the seed's).</summary>
    public int Image { get; init; }
}

/// <summary>Data flows <see cref="From"/> to <see cref="To"/>; <see cref="Image"/> is the image of <see cref="Site"/>.</summary>
public sealed record TraceEdge(int From, int To, string Kind, uint Site, int Image = 0);

/// <summary>Something a budget left unexplored at <see cref="Node"/>, with the exact call that continues there.</summary>
public sealed record TraceFrontier(int Node, string Reason, string Detail, string Next);

/// <summary>A distinct terminal value (backward) or API the value reaches (forward).</summary>
public sealed record TraceValue(string Text, TraceNodeKind Kind, uint? Rva, int Node, int Image = 0);

/// <param name="Images">The images the graph spans: the seed's first, then loaded images it crossed into through imports and exports.</param>
public sealed record ValueTraceGraph(TraceSeed Seed, ValueTraceOptions Options, string Engine, IReadOnlyList<TraceNode> Nodes, IReadOnlyList<TraceEdge> Edges,
    IReadOnlyList<TraceFrontier> Frontier, IReadOnlyList<TraceValue> Values, int Functions, int Steps, IReadOnlyList<string> Notes,
    IReadOnlyList<(INativeImage Image, string Id)> Images);

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
    /// <summary>The entry location of the 0-based integer parameter <paramref name="index"/> ("rcx", "[esp+4h]", "x2").</summary>
    string ParameterLocation(int index);
}

/// <summary>Pointer types of function parameters (PDB prototypes, RTTI classes, the user's types): a value stored into a field is read back where the same type is.</summary>
internal interface ITraceTypes
{
    /// <summary>Identifies the type sources (part of the graph cache key).</summary>
    string Key { get; }
    /// <summary>The struct or class the parameter at entry location <paramref name="location"/> of <paramref name="f"/> points to, or null.</summary>
    string? ParameterType(ITraceHost host, NativeFunction f, string location);
    /// <summary>Functions with a parameter pointing to <paramref name="type"/>, with that parameter's entry location.</summary>
    IReadOnlyList<(NativeFunction Function, string Location)> Holders(ITraceHost host, string type);
    /// <summary>The member of <paramref name="type"/> at <paramref name="offset"/>, or null.</summary>
    string? Member(ITraceHost host, string type, long offset);
    /// <summary>The primary vftables of class <paramref name="type"/>: code that stores one at +0 constructs that class (an inlined constructor).</summary>
    IReadOnlyList<uint> Vftables(ITraceHost host, string type) => [];
}

/// <summary>Other loaded images a trace continues into: the code an import binds to, and the call sites that reach a function through imports.</summary>
internal interface ITraceLinks
{
    /// <summary>Identifies the set of loaded images (part of the graph cache key).</summary>
    string Key { get; }
    /// <summary>The image id of <paramref name="host"/> ("provlib.dll").</summary>
    string ImageOf(ITraceHost host);
    /// <summary>The function the import whose slot is <paramref name="slot"/> binds to in a loaded image of the same instruction set, or null.</summary>
    (ITraceHost Host, NativeFunction Function)? Provider(ITraceHost host, uint slot);
    /// <summary>Calls in other loaded images that reach <paramref name="f"/> through an import.</summary>
    IReadOnlyList<(ITraceHost Host, uint Site, NativeFunction Caller)> Importers(ITraceHost host, NativeFunction f);
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
    private readonly List<(ITraceHost Host, IFunctionSliceProvider Slices)> _hosts = [];
    private readonly ITraceLinks? _links;
    private readonly ITraceTypes? _types;
    private readonly TraceSeed _seed;
    private readonly ValueTraceOptions _o;
    private readonly CancellationToken _ct;
    private readonly List<TraceNode> _nodes = [];
    private readonly List<TraceEdge> _edges = [];
    private readonly List<TraceFrontier> _frontier = [];
    private readonly List<string> _notes = [];
    private readonly HashSet<(int, uint)> _functions = [];
    private readonly Dictionary<string, int> _expanded = [];
    /// <summary>Forward: the constant a node's value is (the seed's, passed on through plain additions).</summary>
    private readonly Dictionary<int, ulong> _consts = [];
    private readonly Queue<Expansion> _queue = new();
    private int _steps;
    private bool _nodesFull;
    /// <summary>The image being expanded (index into <see cref="_hosts"/>).</summary>
    private int _cur;

    private enum Step : byte { Callers, Returns, Writers, IntoCallee, ResultUses, Readers, FieldWriters, FieldReaders }

    /// <summary>A boundary node to continue from: <see cref="Key"/> identifies it across the graph (recursion, repeats).</summary>
    private sealed record Expansion(Step Step, int Node, NativeFunction? Function, int Depth, bool Backward, string Key, string? Location, int Index,
        uint Rva, ApiParam? Param, ApiReturn? Returns)
    {
        /// <summary>The image <see cref="Function"/> is in; -1: the image being expanded when queued.</summary>
        public int Host { get; init; } = -1;
        /// <summary>The image <see cref="Rva"/> is in when it is a call site in another image than <see cref="Host"/>, else -1.</summary>
        public int SiteHost { get; init; } = -1;
        /// <summary>Field steps: the field's offset in the type named by <see cref="Location"/>.</summary>
        public long Offset { get; init; }
    }

    private ValueTrace(ITraceHost a, IFunctionSliceProvider p, TraceSeed seed, ValueTraceOptions o, ITraceLinks? links, ITraceTypes? types, CancellationToken ct)
    {
        _hosts.Add((a, p));
        _links = links;
        _types = types;
        _seed = seed;
        _o = o;
        _ct = ct;
    }

    private ITraceHost Host => _hosts[_cur].Host;
    private IFunctionSliceProvider Slices => _hosts[_cur].Slices;
    private NativeCodeIndex Index => Host.Index;
    private string Va(uint rva) => Host.Va(rva);

    /// <summary>The index of another image's host, added on first use (its own built-in slices).</summary>
    private int HostIndex(ITraceHost h)
    {
        int i = _hosts.FindIndex(x => ReferenceEquals(x.Host, h));
        if (i >= 0) return i;
        _hosts.Add((h, h.Slices));
        return _hosts.Count - 1;
    }

    /// <summary>The trace call for an image ("trace_native_values image=x.dll" outside the seed's image).</summary>
    private string ToolAt(int host) => host == 0 ? "trace_native_values" : $"trace_native_values image={_links!.ImageOf(_hosts[host].Host)}";

    private string Tool => ToolAt(_cur);

    /// <summary>The function in another loaded image that the import call or argument <paramref name="n"/> reaches, or null.</summary>
    private (int Host, NativeFunction Function)? Provider(SliceNode n) =>
        n.CallKind == CalleeKind.Import && n.Rva != 0 && _links?.Provider(Host, n.Rva) is { } p ? (HostIndex(p.Host), p.Function) : null;

    /// <summary>Builds the graph (cached per index: the same seed and options return the same graph until names change).</summary>
    /// <param name="links">Loaded images the trace may continue into through imports and exports.</param>
    /// <param name="types">Parameter types: a value stored into a field is followed to where that field of the type is read, and back.</param>
    internal static ValueTraceGraph Build(ITraceHost analysis, TraceSeed seed, ValueTraceOptions options, IFunctionSliceProvider? provider = null,
        CancellationToken ct = default, ITraceLinks? links = null, ITraceTypes? types = null)
    {
        provider ??= analysis.Slices;
        var key = $"{provider.Engine}|{seed.Kind}|{seed.Address}|{seed.Location}|{seed.Param?.Name}|{options}|{analysis.Index.Sourced.Version}|{links?.Key}|{types?.Key}";
        return analysis.Traces.GetOrAdd(key, () => new ValueTrace(analysis, provider, seed, options, links, types, ct).Run());
    }

    private ValueTraceGraph Run()
    {
        var seedNode = AddNode(TraceNodeKind.Seed, _seed.Address, _seed.Function, _seed.Location, _seed.Description, null, null, null, 0, "", -1, true);
        if (_seed.Function != null) _functions.Add((0, _seed.Function.Start));
        if (_o.Direction != TraceDirection.Forward) StartBackward(seedNode);
        if (_o.Direction != TraceDirection.Backward) StartForward(seedNode);
        while (_queue.Count > 0)
        {
            _ct.ThrowIfCancellationRequested();
            var e = _queue.Dequeue();
            _cur = e.Host;
            if (_nodesFull) { Frontier(e, "nodes", $"the node budget ({_o.MaxNodes}) is used"); continue; }
            if (_steps > _o.MaxSteps) { Frontier(e, "steps", $"the step budget ({_o.MaxSteps}) is used"); continue; }
            Expand(e);
        }
        _cur = 0;
        return new ValueTraceGraph(_seed, _o, Slices.Engine, _nodes, _edges, _frontier, Values(), _functions.Count, _steps, _notes,
            _hosts.Select((h, i) => (h.Host.Index.Image, i == 0 ? "" : _links!.ImageOf(h.Host))).ToList());
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
        if (SeedConstant is { } c) _consts[seedNode] = c;
        switch (_seed.Kind)
        {
            case TraceSeedKind.Global:
                Enqueue(new Expansion(Step.Readers, seedNode, null, 0, false, $"readers:{_seed.Address}", null, -1, _seed.Address, null, null));
                return;
            case TraceSeedKind.Argument when f != null && _seed.Location != null:
            {
                // the value in the argument's location at the call: its uses start with the call
                var atCall = Host.AtCall(f, _seed.Address, _seed.Location, _ct);
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
        _functions.Add((_cur, f.Start));
        var s = forward ? Slices.Forward(f, seed, _ct) : Slices.Backward(f, seed, _ct);
        _steps += s.Steps;
        if (s.Note != null && _notes.Count < 20) _notes.Add($"{f.Name}: {s.Note}");
        if (s.Truncated && s.Note == null && _notes.Count < 20) _notes.Add($"{f.Name}: slice cut at {OursSliceProvider.MaxSliceNodes} nodes");
        return s;
    }

    private int AddNode(TraceNodeKind kind, uint address, NativeFunction? f, string? location, string text, ulong? value, uint? valueRva, string? decoded,
        int depth, string derivation, int parent, bool backward)
    {
        int id = _nodes.Count;
        _nodes.Add(new TraceNode(id, kind, address, f, location, text, value, valueRva, decoded, depth, derivation, parent, backward) { Image = _cur });
        if (_nodes.Count >= _o.MaxNodes) _nodesFull = true;
        return id;
    }

    /// <summary>
    /// Adds a slice's nodes and edges. Backward: the slice's root feeds <paramref name="attach"/> through an edge of
    /// <paramref name="link"/>. Forward: the slice's origin is <paramref name="attach"/>. Boundary nodes are queued.
    /// </summary>
    private void Materialize(FunctionSlice s, int depth, int attach, bool backward, string link, uint site, ApiParam? param, ApiReturn? returns, int siteHost = -1)
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
        if (backward && map[s.Root] >= 0) _edges.Add(new TraceEdge(map[s.Root], attach, link, site, siteHost >= 0 ? siteHost : _cur));
        foreach (var e in s.Edges)
            if (map[e.From] >= 0 && map[e.To] >= 0)
                _edges.Add(new TraceEdge(map[e.From], map[e.To], e.Kind.ToString().ToLowerInvariant(), 0, _cur));
        for (int i = 0; i < s.Nodes.Count; i++)
            if (map[i] >= 0 && (i != s.Root || backward)) Boundary(s.Nodes[i], map[i], s.Function, depth, backward, param, returns);
        if (_types != null)
            for (int i = 0; i < s.Nodes.Count; i++)
                if (map[i] >= 0) TypedField(s, i, map[i], depth, backward, param, returns);
        if (!backward && _consts.TryGetValue(attach, out ulong entering))
            for (int i = 0; i < s.Nodes.Count; i++)
            {
                if (map[i] < 0 || i == s.Root || s.Nodes[i].Offset is not { } delta) continue;
                if (s.Nodes[i].Kind == SliceNodeKind.Argument) _consts[map[i]] = entering + (ulong)delta;
                else if (s.Nodes[i].Kind == SliceNodeKind.Switch && s.Nodes[i].Site != 0) SwitchCase(map[i], s.Function, s.Nodes[i].Site, (long)(entering + (ulong)delta));
            }
    }

    /// <summary>The case a constant switch index selects: index plus the table's bias is the switched value.</summary>
    private void SwitchCase(int node, NativeFunction f, uint jump, long index)
    {
        if (Index.GetGraph(f, _ct).Switches.FirstOrDefault(t => t.JumpRva == jump) is not { } table) return;
        long value = index + table.Bias;
        string what;
        if (table.Cases.FirstOrDefault(c => c.Values.Contains(value)) is { } hit) what = $"selects case {value} -> {Va(hit.Target)}";
        else if (table.Default is { } d) what = $"selects the default -> {Va(d)} (value {value})";
        else return;
        _nodes[node] = Get(node) with { Decoded = what, Value = (ulong)value };
    }

    /// <summary>
    /// A load from or a store to a field of a parameter whose type is known: the other functions holding that type are
    /// searched for the field's writers (backward) or readers (forward).
    /// </summary>
    private void TypedField(FunctionSlice s, int i, int node, int depth, bool backward, ApiParam? param, ApiReturn? returns)
    {
        var n = s.Nodes[i];
        string? location = null;
        long offset;
        if (backward && n.Kind == SliceNodeKind.Field)
        {
            foreach (var e in s.Edges)
                if (e.To == i && e.Kind == SliceEdgeKind.Field && s.Nodes[e.From] is { Kind: SliceNodeKind.Parameter } b) location = b.Location;
            offset = (long)n.Value;
        }
        else if (!backward && n.Kind == SliceNodeKind.FieldStore && n.Base != null && n.Offset is { } stored)
        {
            var root = Slices.Backward(s.Function, new SliceSeed(SliceSeedKind.Location, n.Address, n.Base), _ct);
            _steps += root.Steps;
            if (root.Nodes.Count > root.Root && root.Nodes[root.Root] is { Kind: SliceNodeKind.Parameter } b) location = b.Location;
            offset = stored;
        }
        else return;
        if (location == null || _types!.ParameterType(Host, s.Function, location) is not { } type) return;
        var member = _types.Member(Host, type, offset);
        _nodes[node] = Get(node) with { Text = $"{Get(node).Text}: {type}+0x{offset:X}{(member != null ? $" ({member})" : "")}" };
        Enqueue(new Expansion(backward ? Step.FieldWriters : Step.FieldReaders, node, s.Function, depth, backward,
            $"{(backward ? "fieldwriters" : "fieldreaders")}:{type}:{offset}", type, -1, 0, param, returns) { Offset = offset });
    }

    private TraceNode Get(int id) => _nodes[id];

    /// <summary>A slice node as a graph node: constants and addresses named in the context of the API parameter they meet.</summary>
    private int Convert(SliceNode n, NativeFunction f, int depth, int parent, bool backward, ApiParam? param, ApiReturn? returns)
    {
        int Add(TraceNodeKind kind, string text, ulong? value = null, uint? rva = null, string? decoded = null, string? location = null) =>
            AddNode(kind, n.Address, f, location ?? n.Location, text, value, rva, decoded, depth, n.Derivation, parent, backward);
        switch (n.Kind)
        {
            case SliceNodeKind.Constant when n.Float:
                return Add(TraceNodeKind.Const, n.Text, n.Value);
            case SliceNodeKind.Constant:
            {
                var text = CallAnalysis.FormatNumber(n.Value, param);
                var hex = n.Value < 10 ? n.Value.ToString() : $"0x{n.Value:X}";
                return Add(TraceNodeKind.Const, text == hex || param == null ? hex : $"{hex} = {text}", n.Value, decoded: param?.Type is ApiParamType.Enum or ApiParamType.Bool ? text : null);
            }
            case SliceNodeKind.Address:
            {
                var (kind, _, rva, text) = Host.FormatAddress(n.Rva, param);
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
                if (n.CallKind is CalleeKind.Import or CalleeKind.Dynamic && Provider(n) == null)
                {
                    var r = ApiSignatures.FindReturn(n.Callee);
                    return Add(TraceNodeKind.ApiResult, n.Text, decoded: r == null ? null : r.Enum != null ? $"{r.Meaning}: {string.Join(" | ", r.Enum.Entries.Take(6).Select(e => e.Name))}{(r.Enum.Entries.Count > 6 ? " | ..." : "")}" : r.Meaning);
                }
                return Add(TraceNodeKind.CallResult, n.Text);
            }
            case SliceNodeKind.Origin: return Add(TraceNodeKind.Unknown, n.Text);
            case SliceNodeKind.Argument:
            {
                var sig = n.Target == null ? ApiSignatures.Find(n.Callee, Index.Image) : null;
                var p = sig != null && n.Index >= 0 && n.Index < sig.Params.Count ? sig.Params[n.Index] : null;
                string? decoded = SeedConstant is { } v && !n.Derived && p != null ? CallAnalysis.FormatNumber(v, p) : null;
                return Add(n.Target != null || Provider(n) != null ? TraceNodeKind.Argument : TraceNodeKind.Sink, n.Text + (p != null ? $" ({p.TypeName})" : ""), decoded: decoded);
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
            _seedConstant = _hosts[0].Host.ConstantAfter(_seed.Function, _seed.Address, _seed.Location, _ct);
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
            case SliceNodeKind.CallResult when backward && Provider(n) is { } provider:
                Enqueue(new Expansion(Step.Returns, node, provider.Function, depth, true, $"returns:{provider.Function.Start}", null, -1, n.Site, param, null)
                    { Host = provider.Host, SiteHost = _cur });
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
            case SliceNodeKind.Argument when !backward && n.Target == null && Provider(n) is { } provider:
                Enqueue(new Expansion(Step.IntoCallee, node, provider.Function, depth, false, $"callee:{provider.Function.Start}:{n.Location}", n.Location, n.Index,
                    n.Site, null, null) { Host = provider.Host, SiteHost = _cur });
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
        if (e.Host < 0) e = e with { Host = _cur };
        var key = $"{e.Host}:{e.Key}";
        if (_expanded.TryGetValue(key, out int earlier))
        {
            // reached again (recursion, or a second path to the same boundary): link instead of expanding twice
            if (earlier != e.Node) _edges.Add(new TraceEdge(earlier, e.Node, "loop", 0, _cur));
            return;
        }
        _expanded[key] = e.Node;
        if (e.Depth >= _o.MaxDepth && e.Step is not (Step.Writers or Step.Readers or Step.FieldWriters or Step.FieldReaders) || e.Depth > _o.MaxDepth)
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
        int home = _cur;
        _cur = e.Host < 0 ? _cur : e.Host;
        try { return NextHere(e); }
        finally { _cur = home; }
    }

    private string NextHere(Expansion e)
    {
        var T = Tool;
        switch (e.Step)
        {
            case Step.Callers:
                return $"{T} address={Va(e.Function!.Start)} {(e.Index >= 0 ? $"argument={e.Index + 1}" : $"location={e.Location}")}";
            case Step.Returns when e.SiteHost >= 0:
                return $"{ToolAt(e.SiteHost)} address={_hosts[e.SiteHost].Host.Va(e.Rva)} location=result";
            case Step.Returns:
                return $"{T} address={Va(e.Rva)} location=result";
            case Step.Writers or Step.Readers:
                return $"{T} address={Va(e.Rva)}{Direction(e.Backward)}";
            case Step.FieldWriters or Step.FieldReaders:
                return $"this trace with maxDepth={Math.Min(8, _o.MaxDepth + 1)} and maxWriters={Math.Min(256, 2 * _o.MaxWriters)} " +
                       $"({e.Location}+0x{e.Offset:X} {(e.Backward ? "writers" : "readers")})";
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
            : $"{ToolAt(n.Image)} address={_hosts[n.Image].Host.Va(n.Address)}{(n.Location != null ? $" location={n.Location}" : "")}{Direction(backward)}";
    }

    private bool CanEnter(NativeFunction f) => _functions.Contains((_cur, f.Start)) || _functions.Count < _o.MaxFunctions;

    private void Expand(Expansion e)
    {
        switch (e.Step)
        {
            case Step.Callers: Callers(e); break;
            case Step.Returns:
                if (!CanEnter(e.Function!)) { Frontier(e, "functions", $"maxFunctions={_o.MaxFunctions} reached"); break; }
                Materialize(Slice(e.Function!, new SliceSeed(SliceSeedKind.Returns, e.Function!.Start, Host.ReturnLocation), false), e.Depth + 1, e.Node, true, "return",
                    e.Rva, e.Param, null, e.SiteHost);
                break;
            case Step.Writers: Writers(e); break;
            case Step.IntoCallee:
            {
                if (!CanEnter(e.Function!)) { Frontier(e, "functions", $"maxFunctions={_o.MaxFunctions} reached"); break; }
                var slice = Slice(e.Function!, new SliceSeed(SliceSeedKind.Parameter, e.Function!.Start, e.Location), true);
                int origin = AddNode(TraceNodeKind.Parameter, e.Function!.Start, e.Function, e.Location,
                    $"{(e.Index >= 0 ? $"parameter {e.Index + 1}" : e.Location)} of {e.Function!.Name}", null, null, null, e.Depth + 1, "", e.Node, false);
                _edges.Add(new TraceEdge(e.Node, origin, "parameter", e.Rva, e.SiteHost >= 0 ? e.SiteHost : _cur));
                if (_consts.TryGetValue(e.Node, out ulong passed)) _consts[origin] = passed;
                Materialize(slice, e.Depth + 1, origin, false, "parameter", e.Rva, null, null);
                break;
            }
            case Step.ResultUses: ResultUses(e); break;
            case Step.Readers: Readers(e); break;
            case Step.FieldWriters or Step.FieldReaders: Fields(e); break;
        }
    }

    /// <summary>The writers (backward) or readers (forward) of a field: stores through and loads from the parameters of that type.</summary>
    private void Fields(Expansion e)
    {
        var holders = _types!.Holders(Host, e.Location!);
        var what = e.Backward ? "writers" : "readers";
        int taken = 0, found = 0;
        var seen = new HashSet<uint>();
        void Uses(NativeFunction g, FunctionSlice uses)
        {
            var kind = e.Backward ? SliceNodeKind.FieldStore : SliceNodeKind.Dereference;
            foreach (var u in uses.Nodes.Where(u => u.Kind == kind && u.Base == null && u.Offset == e.Offset && !u.Derived).ToList())
            {
                if (!seen.Add(u.Address)) continue;
                found++;
                if (e.Backward)
                {
                    Materialize(Slice(g, new SliceSeed(SliceSeedKind.Stored, u.Address), false), e.Depth + 1, e.Node, true, "store", u.Address, e.Param, null);
                    continue;
                }
                var slice = Slice(g, new SliceSeed(SliceSeedKind.Loaded, u.Address), true);
                int origin = AddNode(TraceNodeKind.Field, u.Address, g, null, $"read of {e.Location}+0x{e.Offset:X} at {Where(u.Address)}", (ulong)e.Offset, null, null,
                    e.Depth + 1, "", e.Node, false);
                _edges.Add(new TraceEdge(e.Node, origin, "load", u.Address, _cur));
                Materialize(slice, e.Depth + 1, origin, false, "load", u.Address, null, e.Returns);
            }
        }
        foreach (var (g, location) in holders)
        {
            if (taken >= _o.MaxWriters)
            {
                _frontier.Add(new TraceFrontier(e.Node, what, $"{holders.Count - taken} more of {holders.Count} functions holding {e.Location}", Next(e)));
                break;
            }
            if (_nodesFull) { _frontier.Add(new TraceFrontier(e.Node, "nodes", $"{holders.Count - taken} functions holding {e.Location} not searched", Next(e))); break; }
            taken++;
            if (!CanEnter(g)) { _frontier.Add(new TraceFrontier(e.Node, "functions", $"{Where(g.Start)}: maxFunctions={_o.MaxFunctions} reached", Next(e))); continue; }
            Uses(g, Slice(g, new SliceSeed(SliceSeedKind.Parameter, g.Start, location), true));
        }
        // objects typed by a vftable store at +0 (an inlined constructor): the object register from that store on
        int constructions = 0;
        foreach (uint vftable in _types.Vftables(Host, e.Location!))
            foreach (var r in Index.RefsTo(vftable).Where(r => r.Kind == XrefKind.Address))
            {
                if (constructions >= _o.MaxWriters || _nodesFull) { _frontier.Add(new TraceFrontier(e.Node, what, $"more code constructing {e.Location}", Next(e))); goto done; }
                if (Index.FunctionAt(r.From) is not { } g || !CanEnter(g)) continue;
                if (ImmediateStoreBase(r.From, vftable) is { } stored)
                {
                    constructions++;
                    Uses(g, Slice(g, new SliceSeed(SliceSeedKind.Location, r.From, stored), true));
                    continue;
                }
                foreach (var store in Slice(g, new SliceSeed(SliceSeedKind.Loaded, r.From), true).Nodes
                             .Where(n => n.Kind == SliceNodeKind.FieldStore && n.Base != null && n.Offset == 0 && !n.Derived).ToList())
                {
                    constructions++;
                    Uses(g, Slice(g, new SliceSeed(SliceSeedKind.Location, store.Address, store.Base), true));
                }
            }
        done:
        if (found == 0)
            _nodes[e.Node] = Get(e.Node) with
            {
                Derivation = AppendNote(Get(e.Node).Derivation, $"no {(e.Backward ? "store to" : "load from")} {e.Location}+0x{e.Offset:X} through a parameter " +
                                                              $"of that type in the {taken} functions holding it" +
                                                              (constructions > 0 ? $" or the {constructions} objects its vftable constructs" : "")),
            };
    }

    /// <summary>
    /// The base register of "mov [reg], imm" storing <paramref name="target"/> at <paramref name="rva"/> (x86 "mov dword [ecx], offset vftable",
    /// x64 "mov qword [rcx], imm32" below 2 GB), or null: no register carries the address, so the object register is followed from the store.
    /// </summary>
    private string? ImmediateStoreBase(uint rva, uint target)
    {
        if (Index.Image.Arch is not (NativeArch.X86 or NativeArch.X64)) return null;
        var bytes = new byte[15];
        int n = Index.Image.Read(rva, bytes);
        var decoder = Iced.Intel.Decoder.Create(Host.Is64 ? 64 : 32, new Iced.Intel.ByteArrayCodeReader(bytes, 0, n));
        decoder.IP = Index.Image.ImageBase + rva;
        decoder.Decode(out var i);
        return i.Mnemonic == Iced.Intel.Mnemonic.Mov && i.Op0Kind == Iced.Intel.OpKind.Memory && i.Op1Kind is Iced.Intel.OpKind.Immediate32 or Iced.Intel.OpKind.Immediate32to64
            && i.MemoryIndex == Iced.Intel.Register.None && i.MemoryDisplacement64 == 0 && Iced.Intel.RegisterExtensions.IsGPR(i.MemoryBase)
            && i.GetImmediate(1) - Index.Image.ImageBase == target
            ? i.MemoryBase.ToString().ToLowerInvariant() : null;
    }

    /// <summary>The call sites of <paramref name="f"/>: in its image, then in other loaded images through their imports.</summary>
    private List<(int Host, uint Site, NativeFunction Caller)> CallSites(NativeFunction f, bool resultUses)
    {
        var sites = Index.Callers(f).DistinctBy(c => c.From).Where(c => c.Caller != null && (!resultUses || c.Kind != XrefKind.TailCall))
            .Select(c => (_cur, c.From, c.Caller!)).ToList();
        if (_links != null)
            foreach (var (h, site, caller) in _links.Importers(Host, f)) sites.Add((HostIndex(h), site, caller));
        return sites;
    }

    private void Callers(Expansion e)
    {
        var f = e.Function!;
        var sites = CallSites(f, false);
        if (sites.Count == 0)
        {
            _nodes[e.Node] = Get(e.Node) with { Derivation = AppendNote(Get(e.Node).Derivation, "no known callers (an export, a callback or a pointer call)") };
            return;
        }
        int taken = 0, home = _cur;
        var position = e.Index >= 0 ? $"argument={e.Index + 1}" : $"location={e.Location}";
        foreach (var (h, site, caller) in sites)
        {
            if (taken >= _o.MaxCallers)
            {
                _frontier.Add(new TraceFrontier(e.Node, "callers", $"{sites.Count - taken} more of {sites.Count} call sites",
                    $"{Tool} address={Va(f.Start)} {position} maxCallers={Math.Min(256, sites.Count)}"));
                break;
            }
            if (_nodesFull) { _frontier.Add(new TraceFrontier(e.Node, "nodes", $"{sites.Count - taken} call sites not bound", Next(e))); break; }
            taken++;
            _cur = h;
            if (!CanEnter(caller))
                _frontier.Add(new TraceFrontier(e.Node, "functions", $"call site {Where(site)}: maxFunctions={_o.MaxFunctions} reached", $"{Tool} address={Va(site)} {position}"));
            // a jump thunk (incremental-link entry, one jump to the function) passes the arguments on: it costs no depth
            else Materialize(Slice(caller, new SliceSeed(SliceSeedKind.Argument, site, e.Location), false),
                caller.InstructionCount == 1 && site == caller.Start ? e.Depth : e.Depth + 1, e.Node, true, "argument", site, e.Param, null);
            _cur = home;
        }
    }

    private void ResultUses(Expansion e)
    {
        var f = e.Function!;
        var sites = CallSites(f, true);
        int taken = 0, home = _cur;
        foreach (var (h, site, caller) in sites)
        {
            if (taken >= _o.MaxCallers)
            {
                _frontier.Add(new TraceFrontier(e.Node, "callers", $"{sites.Count - taken} more of {sites.Count} call sites", Next(e)));
                break;
            }
            if (_nodesFull) { _frontier.Add(new TraceFrontier(e.Node, "nodes", $"{sites.Count - taken} call sites not followed", Next(e))); break; }
            taken++;
            _cur = h;
            if (!CanEnter(caller))
                _frontier.Add(new TraceFrontier(e.Node, "functions", $"call site {Where(site)}: maxFunctions={_o.MaxFunctions} reached",
                    $"{Tool} address={Va(site)} location=result direction=forward"));
            else
            {
                var slice = Slice(caller, new SliceSeed(SliceSeedKind.Result, site, e.Location), true);
                int origin = AddNode(TraceNodeKind.CallResult, site, caller, e.Location, $"result of {f.Name} at {Where(site)}", null, null, null, e.Depth + 1, "", e.Node, false);
                _edges.Add(new TraceEdge(e.Node, origin, "return", site, _cur));
                Materialize(slice, e.Depth + 1, origin, false, "return", site, null, e.Returns);
            }
            _cur = home;
        }
    }

    private void Writers(Expansion e)
    {
        uint g = e.Rva;
        var writers = Index.RefsTo(g).Where(x => x.Kind == XrefKind.Write).DistinctBy(x => x.From).ToList();
        if (Initial(g, writers.Count == 0) is { } init)
        {
            int id = AddNode(init.Kind, g, null, null, init.Text, init.Value, init.Rva, null, e.Depth, $"initial contents of {Va(g)} in the image", e.Node, true);
            _edges.Add(new TraceEdge(id, e.Node, "store", g, _cur));
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
                    $"{Tool} address={Va(g)} maxWriters={Math.Min(256, writers.Count)}"));
                break;
            }
            if (_nodesFull) { _frontier.Add(new TraceFrontier(e.Node, "nodes", $"{writers.Count - taken} writers not followed", Next(e))); break; }
            taken++;
            if (Index.FunctionAt(w.From) is not { } fn)
            {
                int id = AddNode(TraceNodeKind.Unknown, w.From, null, null, $"written at {Va(w.From)} outside any known function", null, null, null, e.Depth + 1, "", e.Node, true);
                _edges.Add(new TraceEdge(id, e.Node, "store", w.From, _cur));
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
                    $"{Tool} address={Va(g)} direction=forward maxWriters={Math.Min(256, readers.Count)}"));
                break;
            }
            if (_nodesFull) { _frontier.Add(new TraceFrontier(e.Node, "nodes", $"{readers.Count - taken} readers not followed", Next(e))); break; }
            taken++;
            if (Index.FunctionAt(r.From) is not { } fn) continue;
            if (!CanEnter(fn)) { _frontier.Add(new TraceFrontier(e.Node, "functions", $"reader {Where(r.From)}: maxFunctions={_o.MaxFunctions} reached", Next(e))); continue; }
            var slice = Slice(fn, new SliceSeed(SliceSeedKind.Loaded, r.From), true);
            int origin = AddNode(TraceNodeKind.Global, r.From, fn, null, $"read of [{Index.NameAt(g) ?? Va(g)}] at {Where(r.From)}", null, g, null, e.Depth + 1, "", e.Node, false);
            _edges.Add(new TraceEdge(e.Node, origin, "load", r.From, _cur));
            Materialize(slice, e.Depth + 1, origin, false, "load", r.From, null, e.Returns);
        }
    }

    /// <summary>A global's initial contents: a relocated pointer, or a number when nonzero (or when nothing writes it).</summary>
    private (TraceNodeKind Kind, string Text, ulong? Value, uint? Rva)? Initial(uint g, bool always)
    {
        int size = Host.Is64 ? 8 : 4;
        Span<byte> b = stackalloc byte[8];
        b.Clear();
        if (Index.Image.Read(g, b[..size]) != size) return null;
        ulong v = BinaryPrimitives.ReadUInt64LittleEndian(b);
        if (Host.IsRelocated(g) && FunctionCode.TryRva(Index.Image, Host.Is64, v, out uint target))
        {
            var (kind, _, _, text) = Host.FormatAddress(target, null);
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
            bool forwardSink = !n.Backward && (n.Kind == TraceNodeKind.Sink || n.Kind == TraceNodeKind.Switch && n.Decoded != null);
            if (!backwardValue && !forwardSink) continue;
            var text = n.Decoded != null && n.Kind is TraceNodeKind.Sink or TraceNodeKind.Switch ? $"{n.Text} = {n.Decoded}" : n.Text;
            if (seen.Add(n.Kind + text)) result.Add(new TraceValue(text, n.Kind, n.ValueRva, n.Id, n.Image));
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
