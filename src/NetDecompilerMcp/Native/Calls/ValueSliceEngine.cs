using System.Collections.Concurrent;
using NetDecompilerMcp.Native.Code;
using NetDecompilerMcp.Native.Providers;

namespace NetDecompilerMcp.Native.Calls;

/// <summary>
/// Per-function slices from an engine's decompiler IR (IDA microcode, Ghidra p-code). Seeds the engine cannot place (stack
/// slots, a register the IR does not name at that address) and functions it fails on fall back to the built-in slice of
/// that function, counted in <see cref="Fallbacks"/> and said in the slice's note. Engine nodes are completed from the
/// built-in analysis where it knows more: callees of call sites, import slots, parameter locations (x86 / x64 and ARM64).
/// </summary>
internal sealed class EngineSliceProvider(ITraceHost host, INativeDecompilerSession session) : IFunctionSliceProvider
{
    private readonly CallAnalysis? _x86 = host as CallAnalysis;
    private readonly Arm64Trace? _arm = host as Arm64Trace;
    private readonly IFunctionSliceProvider _fallback = host.Slices;
    private readonly ConcurrentDictionary<(uint, SliceSeed, bool), FunctionSlice> _cache = new();
    private int _engine, _fallbacks;

    public string Engine => session.ProviderId;
    /// <summary>Slices the engine answered.</summary>
    public int EngineSlices => _engine;
    /// <summary>Slices answered by the built-in analysis because the engine could not.</summary>
    public int Fallbacks => _fallbacks;

    public FunctionSlice Backward(NativeFunction function, SliceSeed seed, CancellationToken ct) => Slice(function, seed, false, ct);

    public FunctionSlice Forward(NativeFunction function, SliceSeed seed, CancellationToken ct) => Slice(function, seed, true, ct);

    private FunctionSlice Slice(NativeFunction f, SliceSeed seed, bool forward, CancellationToken ct) =>
        _cache.GetOrAdd((f.Start, seed, forward), _ =>
        {
            string why;
            if (Request(f, seed, forward, ct) is { } request)
            {
                try
                {
                    var slice = session.ValueSliceAsync(request, ct).GetAwaiter().GetResult();
                    if (slice.Nodes.Count > 0)
                    {
                        Interlocked.Increment(ref _engine);
                        return Convert(f, slice, ct);
                    }
                    why = slice.Note ?? "the engine returned nothing";
                }
                catch (Core.ToolError e) when (e.Code != Core.ErrorCode.Cancelled)
                {
                    why = e.Message;
                }
            }
            else why = $"the seed {seed.Location} is not a register or argument the engine names";
            Interlocked.Increment(ref _fallbacks);
            var ours = forward ? _fallback.Forward(f, seed, ct) : _fallback.Backward(f, seed, ct);
            return ours with { Note = $"{Engine}: {why}; built-in slice{(ours.Note != null ? "; " + ours.Note : "")}" };
        });

    /// <summary>A location as a register name and its parameter position (-1 for none), or null when it is not a register.</summary>
    private (string? Register, int Index)? Location(string? text)
    {
        if (_x86 != null)
            return OursSliceProvider.ParseLocation(text, _x86.Is64) is { } l
                ? (l.Kind == LocKind.Register ? _x86.Slices.LocationName(l) : null, _x86.Slices.ParameterIndex(l)) : null;
        return A64Function.Parse(text, null) is { } a ? (a.IsSlot ? null : A64Function.Name(a, null), A64Function.ParameterIndex(a)) : null;
    }

    private bool IsCall(uint site, CancellationToken ct) => _x86 != null ? _x86.CallAt(site, ct) != null : _arm?.CallAt(site, ct) != null;

    /// <summary>The engine request for a seed, or null when the engine cannot place it.</summary>
    private EngineSliceRequest? Request(NativeFunction f, SliceSeed seed, bool forward, CancellationToken ct)
    {
        var loc = Location(seed.Location);
        switch (seed.Kind)
        {
            case SliceSeedKind.Argument or SliceSeedKind.Parameter:
                return loc is not { Index: >= 0 } p ? null
                    : new EngineSliceRequest(f.Start, seed.Kind == SliceSeedKind.Argument ? "argument" : "parameter", seed.Address, forward, Index: p.Index);
            case SliceSeedKind.Location:
            {
                if (loc is not { Register: { } register } r) return null;
                // a register passing an argument at a call: the engine knows the argument, not the register
                int index = _x86 != null && OursSliceProvider.ParseLocation(seed.Location, _x86.Is64) is { } l && _x86.Slices.CallToEntry(l, tail: false) is { } entry
                    ? _x86.Slices.ParameterIndex(entry) : _x86 == null ? r.Index : -1;
                if (index >= 0 && IsCall(seed.Address, ct)) return new EngineSliceRequest(f.Start, "argument", seed.Address, forward, Index: index);
                return new EngineSliceRequest(f.Start, "location", seed.Address, forward, register);
            }
            case SliceSeedKind.Result: return new EngineSliceRequest(f.Start, "result", seed.Address, forward);
            case SliceSeedKind.Returns: return new EngineSliceRequest(f.Start, "returns", f.Start, forward);
            case SliceSeedKind.Stored: return new EngineSliceRequest(f.Start, "stored", seed.Address, forward);
            case SliceSeedKind.Loaded: return new EngineSliceRequest(f.Start, "loaded", seed.Address, forward);
            default: return null;
        }
    }

    private FunctionSlice Convert(NativeFunction f, EngineSlice s, CancellationToken ct)
    {
        var code = _x86?.Code(f, ct);
        var nodes = new List<SliceNode>(s.Nodes.Count);
        foreach (var n in s.Nodes)
        {
            var why = n.Why;
            nodes.Add(n.Kind switch
            {
                "constant" => new SliceNode(SliceNodeKind.Constant, n.Rva, n.Text, why) { Value = n.Value ?? 0 },
                "address" when n.Target is { } t => new SliceNode(SliceNodeKind.Address, n.Rva, host.FormatAddress(t, null).Text, why) { Rva = t },
                "global" when n.Target is { } g => Global(n.Rva, g, why),
                "stack_address" => new SliceNode(SliceNodeKind.StackAddress, n.Rva, n.Text, why) { Value = n.Value ?? 0 },
                "merge" => new SliceNode(SliceNodeKind.Merge, n.Rva, n.Text, why) { Truncated = n.Derived },
                "loop" => new SliceNode(SliceNodeKind.Loop, n.Rva, n.Text, why),
                "field" => new SliceNode(SliceNodeKind.Field, n.Rva, n.Text, why) { Value = n.Value ?? 0 },
                "parameter" when n.Index >= 0 => Parameter(f, n.Index, why),
                "call_result" when n.Site is { } site => code != null ? _x86!.Slices.CallResult(code, site, why) : CallResult(site, n, why),
                "origin" => new SliceNode(SliceNodeKind.Origin, n.Rva, n.Text, why),
                "argument" when n.Site is { } site => Argument(code, site, n, why),
                "store" when n.Target is { } g => new SliceNode(SliceNodeKind.Store, n.Rva, $"stored to [{host.Index.NameAt(g) ?? host.Va(g)}]", why) { Rva = g, Derived = n.Derived },
                "field_store" => new SliceNode(SliceNodeKind.FieldStore, n.Rva, n.Text, why) { Derived = n.Derived },
                "return" => new SliceNode(SliceNodeKind.Return, n.Rva, n.Text, why) { Location = host.ReturnLocation, Derived = n.Derived },
                "compare" => new SliceNode(SliceNodeKind.Compare, n.Rva, n.Text, why) { Value = n.Value ?? 0, Truncated = n.Value == null, Derived = n.Derived },
                "switch" => new SliceNode(SliceNodeKind.Switch, n.Rva, n.Text, why) { Derived = n.Derived },
                "dereference" => new SliceNode(SliceNodeKind.Dereference, n.Rva, n.Text, why) { Derived = n.Derived },
                "call_target" => new SliceNode(SliceNodeKind.CallTarget, n.Rva, n.Text, why) { Site = n.Site ?? n.Rva, Derived = n.Derived },
                _ => new SliceNode(SliceNodeKind.Unknown, n.Rva, n.Text.Length > 0 ? n.Text : "?", why),
            });
        }
        var edges = s.Edges.Where(e => e.From >= 0 && e.From < nodes.Count && e.To >= 0 && e.To < nodes.Count)
            .Select(e => new SliceEdge(e.From, e.To, e.Kind switch
            {
                "merge" => SliceEdgeKind.Merge,
                "loop" => SliceEdgeKind.Loop,
                "field" => SliceEdgeKind.Field,
                "use" => SliceEdgeKind.Use,
                _ => SliceEdgeKind.Copy,
            })).ToList();
        var note = s.Variable != null ? $"{Engine} variable {s.Variable}" + (s.Note != null ? "; " + s.Note : "") : s.Note;
        return new FunctionSlice(f, Engine, 0, nodes, edges, 0, s.Truncated, note);
    }

    private NativeImport? ImportAt(uint slot) => _x86 != null ? _x86.ImportAtSlot(slot) : _arm?.ImportAt(slot);

    /// <summary>A load of a fixed address: an import slot or a late-bound pointer names the function it holds; anything else is a global.</summary>
    private SliceNode Global(uint at, uint g, string why)
    {
        if (ImportAt(g) is { } imp)
            return new SliceNode(SliceNodeKind.Import, at, NativeCodeIndex.ImportName(imp), why) { Rva = g, Callee = NativeCodeIndex.ImportName(imp), CallKind = CalleeKind.Import };
        if (_x86?.LateBoundPointer(g, default) is { } dyn)
            return new SliceNode(SliceNodeKind.Import, at, dyn.FullName, why) { Rva = g, Callee = dyn.FullName, CallKind = CalleeKind.Dynamic };
        return new SliceNode(SliceNodeKind.Global, at, $"[{host.Index.NameAt(g) ?? host.Va(g)}]", why) { Rva = g };
    }

    private string EntryName(int index) => _x86 != null ? _x86.Slices.LocationName(_x86.Slices.ParameterEntry(index)) : A64Function.Name(A64Function.ParameterEntry(index), null);

    private SliceNode Parameter(NativeFunction f, int index, string why)
    {
        var name = EntryName(index);
        return new SliceNode(SliceNodeKind.Parameter, f.Start, $"parameter {index + 1} ({name})", why) { Location = name, Index = index };
    }

    /// <summary>A call result where only the engine knows the callee (ARM64): the built-in call site when it decodes, else the engine's target.</summary>
    private SliceNode CallResult(uint site, EngineSliceNode n, string why)
    {
        if (_arm?.CallAt(site, default) is { } call)
        {
            uint? target = call.Kind is CalleeKind.Function or CalleeKind.VirtualExact ? call.Target : null;
            return new SliceNode(SliceNodeKind.CallResult, site, $"result of {call.Callee}", why) { Site = site, Callee = call.Callee, CallKind = call.Kind, Target = target, Rva = call.Import?.SlotRva ?? 0 };
        }
        uint? t = n.Target is { } x && host.Index.FunctionByStart(x) != null ? x : null;
        return new SliceNode(SliceNodeKind.CallResult, site, n.Callee != null ? $"result of {n.Callee}" : $"result of the call at {host.Va(site)}", why)
            { Site = site, Callee = n.Callee, CallKind = t != null ? CalleeKind.Function : CalleeKind.Indirect, Target = t };
    }

    private SliceNode Argument(FunctionCode? code, uint site, EngineSliceNode n, string why)
    {
        var entry = EntryName(Math.Max(0, n.Index));
        CallAnalysis.Callee? c = null;
        if (code != null && code.Position(site) is var (block, i) && block >= 0) c = _x86!.CalleeAt(code, block, i);
        else if (_arm?.CallAt(site, default) is { } call) c = new CallAnalysis.Callee(call.Callee, call.Kind, call.Import, call.Target, call.Dynamic, null);
        if (c is not { } callee)
            return new SliceNode(SliceNodeKind.Argument, site, n.Text, why) { Site = site, Location = entry, Index = n.Index, Callee = n.Callee, Target = n.Target, Derived = n.Derived };
        uint? target = callee.Kind is CalleeKind.Function or CalleeKind.VirtualExact ? callee.Target : null;
        var sig = CallAnalysis.SignatureOf(callee);
        var name = sig != null && n.Index >= 0 && n.Index < sig.Params.Count ? $" {sig.Params[n.Index].Name}" : "";
        return new SliceNode(SliceNodeKind.Argument, site, $"argument {n.Index + 1}{name} of {callee.Name}", why)
            { Site = site, Location = entry, Index = n.Index, Callee = callee.Name, CallKind = callee.Kind, Target = target, Derived = n.Derived, Rva = callee.Import?.SlotRva ?? 0 };
    }
}
