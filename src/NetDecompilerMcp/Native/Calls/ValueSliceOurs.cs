using System.Collections.Concurrent;
using System.Globalization;
using Iced.Intel;
using NetDecompilerMcp.Native.Code;

namespace NetDecompilerMcp.Native.Calls;

/// <summary>
/// The built-in engine's per-function slices (x86 / x64): backward through <see cref="ValueResolver"/> in slice mode,
/// forward through <see cref="ForwardSlicer"/>. Slices are memoized per function and seed, so repeated traces reuse them.
/// </summary>
internal sealed class OursSliceProvider(CallAnalysis analysis) : IFunctionSliceProvider
{
    public const string EngineName = "ours";
    /// <summary>Nodes per slice; merges of merges grow fast.</summary>
    public const int MaxSliceNodes = 256;
    private const int MaxReturns = 16;
    private const int ResolverBudget = 6000;
    private const int MaxCachedSlices = 4096;
    private readonly ConcurrentDictionary<(uint, SliceSeed, bool, int), FunctionSlice> _cache = new();

    public string Engine => EngineName;
    public CallAnalysis Analysis => analysis;
    private bool Is64 => analysis.Is64;
    private int Ptr => Is64 ? 8 : 4;

    public FunctionSlice Backward(NativeFunction function, SliceSeed seed, CancellationToken ct) => Cached(function, seed, false, ct);

    /// <summary>Drops the memoized slices (the late-bound imports they name callees by became known).</summary>
    public void Clear() => _cache.Clear();

    public FunctionSlice Forward(NativeFunction function, SliceSeed seed, CancellationToken ct) => Cached(function, seed, true, ct);

    private FunctionSlice Cached(NativeFunction f, SliceSeed seed, bool forward, CancellationToken ct)
    {
        var key = (f.Start, seed, forward, analysis.Index.Sourced.Version);
        if (_cache.TryGetValue(key, out var hit)) return hit;
        var code = analysis.Code(f, ct);
        var slice = forward ? new ForwardSlicer(this, code).Run(seed, ct) : BackwardSlice(code, seed);
        if (_cache.Count >= MaxCachedSlices) _cache.Clear();
        _cache[key] = slice;
        return slice;
    }

    private ValueResolver Resolver(FunctionCode code) => new(analysis, code) { Slice = true, Budget = ResolverBudget };

    private FunctionSlice BackwardSlice(FunctionCode code, SliceSeed seed)
    {
        var b = new Builder(this, code);
        int steps = 0;
        string? note = null;
        switch (seed.Kind)
        {
            case SliceSeedKind.Location or SliceSeedKind.Argument:
            {
                var (block, index) = code.Position(seed.Address);
                var loc = ParseLocation(seed.Location, Is64);
                if (block < 0 || loc == null) { b.Add(Val.Unknown(block < 0 ? "not an instruction of the function" : $"unknown location '{seed.Location}'")); break; }
                if (seed.Kind == SliceSeedKind.Argument)
                    loc = EntryToCall(loc.Value, analysis.SiteKindOf(code, in code.Blocks[block][index]) == 2);
                var r = Resolver(code);
                b.Add(r.ValueBefore(loc.Value, block, index));
                steps = r.Steps;
                break;
            }
            case SliceSeedKind.Stored:
            {
                var (block, index) = code.Position(seed.Address);
                if (block < 0) { b.Add(Val.Unknown("not an instruction of the function")); break; }
                var r = Resolver(code);
                b.Add(r.ValueStoredBy(block, index));
                steps = r.Steps;
                break;
            }
            case SliceSeedKind.Result:
                b.Add(new Val(VKind.Result, 0, 0, seed.Address, ""));
                break;
            case SliceSeedKind.Parameter:
            {
                var loc = ParseLocation(seed.Location, Is64);
                b.Add(loc is { } l ? Incoming(l) : Val.Unknown($"unknown location '{seed.Location}'"));
                break;
            }
            case SliceSeedKind.Returns:
                steps = Returns(code, seed, b, out note);
                break;
        }
        return new FunctionSlice(code.Function, EngineName, 0, b.Nodes, b.Edges, steps, b.Truncated, note);
    }

    /// <summary>The returned values: the return register before each ret, and the results of tail calls; one merge node over them.</summary>
    private int Returns(FunctionCode code, SliceSeed seed, Builder b, out string? note)
    {
        note = null;
        var reg = ParseLocation(seed.Location ?? "rax", Is64) is { Kind: LocKind.Register } l ? l : Loc.Of(Register.RAX);
        var values = new List<Val>();
        int steps = 0, sites = 0;
        for (int block = 0; block < code.Blocks.Length; block++)
        {
            var insns = code.Blocks[block];
            if (insns.Length == 0) continue;
            int last = insns.Length - 1;
            ref readonly var d = ref insns[last];
            Val v;
            if (d.I.FlowControl == FlowControl.Return)
            {
                var r = Resolver(code);
                v = r.ValueBefore(reg, block, last);
                steps += r.Steps;
            }
            else if (analysis.SiteKindOf(code, in d) == 2) v = new Val(VKind.Result, 0, 0, d.Rva, $"tail call at {analysis.Va(d.Rva)}") { At = d.Rva };
            else continue;
            if (++sites > MaxReturns) { note = $"more than {MaxReturns} returns: the first {MaxReturns}"; break; }
            if (!values.Any(o => o.SameAs(in v) && (v.Kind != VKind.Unknown || o.Why == v.Why))) values.Add(v);
        }
        if (values.Count == 0) b.Add(Val.Unknown("the function has no return"));
        else if (values.Count == 1) b.Add(values[0]);
        else b.Add(new Val(VKind.Merge, (ulong)sites, note != null ? 1u : 0, 0, $"returned at {sites} sites", [.. values]));
        return steps;
    }

    private Val Incoming(Loc l) => l.Kind == LocKind.Register
        ? new Val(VKind.Incoming, 0, 0, (uint)l.Reg, "")
        : new Val(VKind.Incoming, (ulong)(long)l.Slot, 0, 0, "");

    /// <summary>Turns a resolver value tree into slice nodes.</summary>
    private sealed class Builder(OursSliceProvider p, FunctionCode code)
    {
        public readonly List<SliceNode> Nodes = [];
        public readonly List<SliceEdge> Edges = [];
        public bool Truncated;
        private CallAnalysis A => p.Analysis;

        private int Node(SliceNode n)
        {
            Nodes.Add(n);
            return Nodes.Count - 1;
        }

        public int Add(in Val v)
        {
            if (Nodes.Count >= MaxSliceNodes) { Truncated = true; return -1; }
            var why = v.Why ?? "";
            switch (v.Kind)
            {
                case VKind.Const:
                    return Node(new SliceNode(SliceNodeKind.Constant, v.At, $"0x{v.Num:X}", why) { Value = v.Num });
                case VKind.Addr:
                    return Node(new SliceNode(SliceNodeKind.Address, v.At, A.FormatAddress(v.Rva, null).Text, why) { Rva = v.Rva });
                case VKind.Load:
                {
                    if (A.ImportAtSlot(v.Rva) is { } imp)
                        return Node(new SliceNode(SliceNodeKind.Import, v.At, NativeCodeIndex.ImportName(imp), why) { Rva = v.Rva, Callee = NativeCodeIndex.ImportName(imp), CallKind = CalleeKind.Import });
                    if (A.LateBoundPointer(v.Rva, default) is { } dyn)
                        return Node(new SliceNode(SliceNodeKind.Import, v.At, dyn.FullName, why) { Rva = v.Rva, Callee = dyn.FullName, CallKind = CalleeKind.Dynamic });
                    return Node(new SliceNode(SliceNodeKind.Global, v.At, $"[{A.Index.NameAt(v.Rva) ?? A.Va(v.Rva)}]", why) { Rva = v.Rva });
                }
                case VKind.Result:
                    return Node(p.CallResult(code, v.Site, why));
                case VKind.StackAddr:
                    return Node(new SliceNode(SliceNodeKind.StackAddress, v.At, $"&local [{(v.Site == 0 ? p.Sp : p.Fp)}{(long)v.Num:+0;-0}]", why) { Value = v.Num });
                case VKind.TakenLocal:
                    return Node(new SliceNode(SliceNodeKind.TakenLocal, v.At, $"local [{(v.Site == 0 ? p.Sp : p.Fp)}{(long)v.Num:+0;-0}] (address taken)", why) { Value = v.Num });
                case VKind.Incoming:
                {
                    var loc = v.Site != 0 ? Loc.Of((Register)v.Site) : Loc.Stack((int)(long)v.Num);
                    int index = p.ParameterIndex(loc);
                    var name = p.LocationName(loc);
                    return Node(new SliceNode(SliceNodeKind.Parameter, code.Function.Start, index >= 0 ? $"parameter {index + 1} ({name})" : $"incoming {name}", why)
                        { Location = name, Index = index });
                }
                case VKind.Merge:
                {
                    int id = Node(new SliceNode(SliceNodeKind.Merge, v.At, $"{v.Alternatives!.Length} values", why) { Value = v.Num, Truncated = v.Rva == 1 });
                    Truncated |= v.Rva == 1;
                    foreach (var alt in v.Alternatives!)
                    {
                        int c = Add(alt);
                        if (c >= 0) Edges.Add(new SliceEdge(c, id, alt.Kind == VKind.Cycle ? SliceEdgeKind.Loop : SliceEdgeKind.Merge));
                    }
                    return id;
                }
                case VKind.Field:
                {
                    long off = (long)v.Num;
                    int id = Node(new SliceNode(SliceNodeKind.Field, v.Site, $"field {(off < 0 ? "-" : "+")}0x{Math.Abs(off):X}", why) { Value = v.Num });
                    int c = Add(v.Alternatives![0]);
                    if (c >= 0) Edges.Add(new SliceEdge(c, id, SliceEdgeKind.Field));
                    return id;
                }
                case VKind.Cycle:
                    return Node(new SliceNode(SliceNodeKind.Loop, v.At, "loop-carried value", why));
                default:
                    return Node(new SliceNode(SliceNodeKind.Unknown, v.At, "?", why));
            }
        }
    }

    /// <summary>A call-result node for the call at <paramref name="site"/>, with its resolved callee.</summary>
    internal SliceNode CallResult(FunctionCode code, uint site, string why)
    {
        var (block, index) = code.Position(site);
        if (block < 0) return new SliceNode(SliceNodeKind.CallResult, site, $"result of the call at {analysis.Va(site)}", why) { Site = site };
        var c = analysis.CalleeAt(code, block, index);
        uint? target = c.Kind is CalleeKind.Function or CalleeKind.VirtualExact ? c.Target : null;
        var text = c.Kind is CalleeKind.Indirect or CalleeKind.VirtualPossible ? $"result of the call at {analysis.Va(site)}" : $"result of {c.Name}";
        return new SliceNode(SliceNodeKind.CallResult, site, text, string.IsNullOrEmpty(why) ? c.Why ?? "" : why)
            { Site = site, Callee = c.Name, CallKind = c.Kind, Target = target, Rva = c.Import?.SlotRva ?? 0 };
    }

    // Locations as text, and the calling convention.

    internal string Sp => Is64 ? "rsp" : "esp";
    internal string Fp => Is64 ? "rbp" : "ebp";

    internal string LocationName(Loc loc) => loc.Kind switch
    {
        LocKind.Register => RegisterName(loc.Reg),
        LocKind.Stack => $"[{Sp}{(loc.Slot < 0 ? "-" : "+")}{Math.Abs(loc.Slot):X}h]",
        _ => $"[{Fp}{(loc.Slot < 0 ? "-" : "+")}{Math.Abs(loc.Slot):X}h]",
    };

    private string RegisterName(Register full)
    {
        if (full >= Register.ZMM0 && full <= Register.ZMM31) return $"xmm{full - Register.ZMM0}";
        if (!Is64 && full >= Register.RAX && full <= Register.RDI) return (Register.EAX + (full - Register.RAX)).ToString().ToLowerInvariant();
        return full.ToString().ToLowerInvariant();
    }

    /// <summary>A register ("rdx", "edx", "xmm1"), stack slot ("[rsp+28h]", "[esp+0x4]") or frame slot ("[rbp-8]"); null when not one.</summary>
    internal static Loc? ParseLocation(string? text, bool is64)
    {
        if (string.IsNullOrWhiteSpace(text)) return null;
        var t = text.Trim().ToLowerInvariant().Replace(" ", "");
        if (t.StartsWith('[') && t.EndsWith(']'))
        {
            t = t[1..^1];
            int sign = t.IndexOfAny(['+', '-']);
            var reg = sign < 0 ? t : t[..sign];
            long off = 0;
            if (sign >= 0 && !TryNumber(t[(sign + 1)..], out off)) return null;
            if (sign >= 0 && t[sign] == '-') off = -off;
            if (reg is "rsp" or "esp" or "sp") return Loc.Stack((int)off);
            if (reg is "rbp" or "ebp" or "fp") return Loc.Frame((int)off);
            return null;
        }
        if (!Enum.TryParse<Register>(t, true, out var r) || r == Register.None || int.TryParse(t, out _)) return null;
        var full = r.GetFullRegister();
        if (FunctionCode.Bit(full) < 0 || full is Register.RSP or Register.RIP) return null;
        if (!is64 && (full > Register.RDI && full < Register.ZMM0 || full > Register.ZMM7)) return null;
        return Loc.Of(full);
    }

    private static bool TryNumber(string s, out long value)
    {
        value = 0;
        if (s.EndsWith('h')) return long.TryParse(s[..^1], NumberStyles.AllowHexSpecifier, CultureInfo.InvariantCulture, out value);
        if (s.StartsWith("0x", StringComparison.Ordinal)) return long.TryParse(s[2..], NumberStyles.AllowHexSpecifier, CultureInfo.InvariantCulture, out value);
        return long.TryParse(s, NumberStyles.Integer, CultureInfo.InvariantCulture, out value);
    }

    /// <summary>The 0-based parameter position of an entry location (x64 per <see cref="X64Abi.ParameterIndex"/>; x86 [esp+4+4i]); -1 for none.</summary>
    internal int ParameterIndex(Loc entry)
    {
        if (Is64) return analysis.Abi.ParameterIndex(entry);
        if (entry.Kind != LocKind.Stack || entry.Slot < 4 || entry.Slot % 4 != 0) return -1;
        return (entry.Slot - 4) / 4;
    }

    /// <summary>The entry location of the 0-based parameter <paramref name="index"/>.</summary>
    internal Loc ParameterEntry(int index, bool isFloat = false) => Is64 ? analysis.Abi.ParameterEntry(index, isFloat) : Loc.Stack(4 + 4 * index);

    /// <summary>Where an entry location is at a call (the return address not pushed yet) or a tail jump (already there).</summary>
    internal Loc EntryToCall(Loc entry, bool tail) => entry.Kind == LocKind.Stack && !tail ? Loc.Stack(entry.Slot - Ptr) : entry;

    /// <summary>The callee-entry location of a location live at a call when it passes an argument there, else null.</summary>
    internal Loc? CallToEntry(Loc atCall, bool tail)
    {
        int shift = tail ? 0 : Ptr;
        switch (atCall.Kind)
        {
            case LocKind.Stack:
            {
                var entry = Loc.Stack(atCall.Slot + shift);
                return ParameterIndex(entry) is >= 0 and < 20 ? entry : null;
            }
            case LocKind.Register:
                if (Is64) return ParameterIndex(atCall) >= 0 ? atCall : null;
                return atCall.Reg is Register.RCX or Register.RDX ? atCall : null;
            default:
                return null;
        }
    }

    internal bool IsVolatile(Register full) => Is64
        ? analysis.Abi.IsVolatile(full)
        : full is Register.RAX or Register.RCX or Register.RDX || (full >= Register.ZMM0 && full <= Register.ZMM7);
}
