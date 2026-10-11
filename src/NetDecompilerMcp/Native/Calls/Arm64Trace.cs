using System.Collections.Concurrent;
using System.Runtime.CompilerServices;
using System.Text;
using AsmArm64;
using NetDecompilerMcp.Native.Code;

namespace NetDecompilerMcp.Native.Calls;

/// <summary>
/// Value tracing and call-target facts for ARM64 code under the AAPCS64 (x0-x7 and 8-byte stack slots for arguments, x0
/// for results, x0-x18 and x30 caller-saved): decoded functions, the backward resolver and the per-function slices the
/// <see cref="ValueTrace"/> driver composes. One instance per code index, thread-safe.
/// </summary>
internal sealed class Arm64Trace : ITraceHost
{
    private const int MaxCachedFunctions = 512;
    private static readonly ConditionalWeakTable<NativeCodeIndex, Arm64Trace> Table = new();
    private readonly uint[] _relocs;
    private readonly Dictionary<uint, NativeImport> _slots = [];
    private readonly HashSet<uint> _guardSlots = [];
    private readonly ConcurrentDictionary<uint, A64Function> _code = new();
    private Arm64SliceProvider? _slices;
    private ValueTraceCache? _traces;

    private Arm64Trace(NativeCodeIndex index)
    {
        Index = index;
        _relocs = index.Image.RelocationRvas.ToArray();
        Array.Sort(_relocs);
        foreach (var i in index.Image.Imports) _slots.TryAdd(i.SlotRva, i);
        if (index.Image is Pe.PeFile { LoadConfig: { } lc })
            foreach (var va in new[] { lc.GuardCfCheckFunctionPointer, lc.GuardXfgCheckFunctionPointer })
                if (va > index.Image.ImageBase && va - index.Image.ImageBase < index.Image.SizeOfImage) _guardSlots.Add((uint)(va - index.Image.ImageBase));
    }

    /// <summary>
    /// A blr through the CFG check function pointer (Windows ARM64): it validates x15 and preserves every register but
    /// x16, x17 and x30, so values and arguments flow past it.
    /// </summary>
    public bool IsGuardCheck(A64Function code, int block, int k)
    {
        if (_guardSlots.Count == 0) return false;
        var steps = code.Blocks[block];
        if (steps[k].Facts.Flow != FlowKind.IndirectCall || A64Function.Gpr(steps[k].I, 0) is not (var r and >= 0)) return false;
        for (int j = k - 1; j >= 0; j--)
            if (A64Function.Dest(steps[j].I) is { Kind: Arm64RegisterKind.X } d && d.Index == r)
                return steps[j].Facts.HasMem && _guardSlots.Contains(steps[j].Facts.MemTarget);
        return false;
    }

    public static bool Supports(NativeCodeIndex index) => Arm64CallSites.Supports(index);

    public static Arm64Trace For(NativeCodeIndex index)
    {
        if (!Supports(index)) throw new NotSupportedException($"ARM64 value analysis needs an ARM64 code index, not {index.Image.Arch}");
        return Table.GetValue(index, i => new Arm64Trace(i));
    }

    public NativeCodeIndex Index { get; }
    public bool Is64 => true;
    public string ReturnLocation => "x0";
    public string ParameterLocation(int index) => A64Function.Name(A64Function.ParameterEntry(index), null);
    public ValueTraceCache Traces => LazyInitializer.EnsureInitialized(ref _traces, () => new ValueTraceCache());
    public IFunctionSliceProvider Slices => LazyInitializer.EnsureInitialized(ref _slices, () => new Arm64SliceProvider(this));
    public Arm64CallSites Calls => Arm64CallSites.For(Index);

    public string Va(uint rva) => NativeAddress.Va(Index.Image, rva);
    public bool IsRelocated(uint rva) => Array.BinarySearch(_relocs, rva) >= 0;
    public NativeImport? ImportAt(uint slot) => _slots.GetValueOrDefault(slot);

    public A64Function Code(NativeFunction f, CancellationToken ct)
    {
        if (_code.TryGetValue(f.Start, out var hit)) return hit;
        var code = new A64Function(Index, f, ct);
        if (_code.Count >= MaxCachedFunctions) _code.Clear();
        _code[f.Start] = code;
        return code;
    }

    public (ArgKind Kind, ulong? Value, uint? Rva, string Text) FormatAddress(uint rva, ApiParam? p)
    {
        bool wide = p?.Type is ApiParamType.WideString or ApiParamType.WideFormat;
        if (Index.StringAt(rva) is { } s && (s.Encoding == StringEncoding.Utf16) == wide) return (ArgKind.String, null, rva, Quote(Index.ReadString(s, 200), wide));
        if (Index.CfStringAt(rva) is { } cf) return (ArgKind.String, null, rva, "@" + Quote(Index.ReadString(cf, 200), false));
        if (Index.NameAt(rva) is { } name) return (ArgKind.Name, null, rva, name);
        return (ArgKind.Address, null, rva, Va(rva));
    }

    private static string Quote(string text, bool wide)
    {
        var sb = new StringBuilder(wide ? "L\"" : "\"");
        foreach (char c in text.Length > 120 ? text[..120] : text)
            sb.Append(c switch { '\\' => "\\\\", '"' => "\\\"", '\n' => "\\n", '\r' => "\\r", '\t' => "\\t", _ => c < ' ' ? $"\\x{(int)c:X2}" : c.ToString() });
        if (text.Length > 120) sb.Append("...");
        return sb.Append('"').ToString();
    }

    /// <summary>Arguments travel in registers and caller-frame slots that a bl or b leaves where they are.</summary>
    public string AtCall(NativeFunction f, uint site, string entry, CancellationToken ct)
    {
        var code = Code(f, ct);
        var (b, i) = code.Position(site);
        if (b < 0 || A64Function.Parse(entry, null) is not { } loc) return entry;
        return loc.IsSlot ? A64Function.Name(loc, null) : entry;
    }

    public ulong? ConstantAfter(NativeFunction f, uint address, string location, CancellationToken ct)
    {
        var code = Code(f, ct);
        var (b, i) = code.Position(address);
        if (b < 0 || A64Function.Parse(location, code.Blocks[b][i]) is not { } loc) return null;
        var v = new Arm64Resolver(this, code) { Budget = 2000 }.Before(loc, b, i + 1);
        return v.Kind == A64Kind.Const ? v.Num : null;
    }

    /// <summary>The callee of the call or tail jump at <paramref name="site"/>.</summary>
    public CallSiteInfo? CallAt(uint site, CancellationToken ct) => Calls.CallAt(site, ct);
}

/// <summary>The built-in engine's ARM64 slices: backward through <see cref="Arm64Resolver"/>, forward through <see cref="Arm64Forward"/>; memoized per function and seed.</summary>
internal sealed class Arm64SliceProvider(Arm64Trace host) : IFunctionSliceProvider
{
    private const int MaxReturns = 16;
    private const int MaxCachedSlices = 4096;
    private readonly ConcurrentDictionary<(uint, SliceSeed, bool, int), FunctionSlice> _cache = new();

    public string Engine => OursSliceProvider.EngineName;

    public FunctionSlice Backward(NativeFunction function, SliceSeed seed, CancellationToken ct) => Cached(function, seed, false, ct);

    public FunctionSlice Forward(NativeFunction function, SliceSeed seed, CancellationToken ct) => Cached(function, seed, true, ct);

    private FunctionSlice Cached(NativeFunction f, SliceSeed seed, bool forward, CancellationToken ct)
    {
        var key = (f.Start, seed, forward, host.Index.Sourced.Version);
        if (_cache.TryGetValue(key, out var hit)) return hit;
        var code = host.Code(f, ct);
        var slice = forward ? new Arm64Forward(host, code).Run(seed, ct) : BackwardSlice(code, seed, ct);
        if (_cache.Count >= MaxCachedSlices) _cache.Clear();
        _cache[key] = slice;
        return slice;
    }

    private FunctionSlice BackwardSlice(A64Function code, SliceSeed seed, CancellationToken ct)
    {
        var b = new Builder(host, code, ct);
        var r = new Arm64Resolver(host, code);
        string? note = null;
        switch (seed.Kind)
        {
            case SliceSeedKind.Location or SliceSeedKind.Argument:
            {
                var (block, index) = code.Position(seed.Address);
                var loc = block >= 0 ? A64Function.Parse(seed.Location, seed.Kind == SliceSeedKind.Argument ? null : code.Blocks[block][index]) : null;
                // an argument's entry slot is the slot at the call, where sp is the caller's sp there
                if (seed.Kind == SliceSeedKind.Argument && loc is { IsSlot: true } entry && block >= 0)
                    loc = code.Blocks[block][index].Sp is { } sp ? A64Loc.Slot(sp + entry.Value) : null;
                b.Add(block < 0 || loc == null ? A64Val.Unknown(block < 0 ? "not an instruction of the function" : $"unknown location '{seed.Location}'") : r.Before(loc.Value, block, index));
                break;
            }
            case SliceSeedKind.Stored:
            {
                var (block, index) = code.Position(seed.Address);
                b.Add(block < 0 ? A64Val.Unknown("not an instruction of the function") : r.Stored(block, index));
                break;
            }
            case SliceSeedKind.Result:
                b.Add(new A64Val(A64Kind.Result, seed.Address, "") { Rva = seed.Address });
                break;
            case SliceSeedKind.Parameter:
                b.Add(A64Function.Parse(seed.Location, null) is { } p ? new A64Val(A64Kind.Incoming, code.Function.Start, "") { Loc = p } : A64Val.Unknown($"unknown location '{seed.Location}'"));
                break;
            case SliceSeedKind.Returns:
                note = Returns(code, r, b);
                break;
        }
        return new FunctionSlice(code.Function, Engine, 0, b.Nodes, b.Edges, r.Steps, b.Truncated, note);
    }

    /// <summary>x0 before each ret and the results of tail calls, merged.</summary>
    private string? Returns(A64Function code, Arm64Resolver r, Builder b)
    {
        string? note = null;
        var values = new List<A64Val>();
        int sites = 0;
        var tails = code.Graph.TailCalls.ToHashSet();
        for (int block = 0; block < code.Blocks.Length; block++)
        {
            var steps = code.Blocks[block];
            if (steps.Length == 0) continue;
            var last = steps[^1];
            A64Val v;
            if (last.Facts.Flow == FlowKind.Return) v = r.Before(A64Loc.Reg(0), block, steps.Length - 1);
            else if (last.Facts.Flow == FlowKind.Jump && last.Facts.HasTarget && tails.Contains(last.Facts.Target)
                     || last.Facts.Flow == FlowKind.IndirectJump && !code.Graph.Switches.Any(s => s.JumpRva == last.Rva))
                v = new A64Val(A64Kind.Result, last.Rva, $"tail call at {host.Va(last.Rva)}") { Rva = last.Rva };
            else continue;
            if (++sites > MaxReturns) { note = $"more than {MaxReturns} returns: the first {MaxReturns}"; break; }
            if (!values.Any(o => o.SameAs(v))) values.Add(v);
        }
        if (values.Count == 0) b.Add(A64Val.Unknown("the function has no return"));
        else if (values.Count == 1) b.Add(values[0]);
        else b.Add(new A64Val(A64Kind.Merge, 0, $"returned at {sites} sites") { Inputs = [.. values], Truncated = note != null });
        return note;
    }

    /// <summary>Turns a resolver value tree into slice nodes.</summary>
    private sealed class Builder(Arm64Trace host, A64Function code, CancellationToken ct)
    {
        public readonly List<SliceNode> Nodes = [];
        public readonly List<SliceEdge> Edges = [];
        public bool Truncated;

        private int Node(SliceNode n)
        {
            Nodes.Add(n);
            return Nodes.Count - 1;
        }

        public int Add(A64Val v)
        {
            if (Nodes.Count >= OursSliceProvider.MaxSliceNodes) { Truncated = true; return -1; }
            var why = v.Why;
            switch (v.Kind)
            {
                case A64Kind.Const:
                    return Node(new SliceNode(SliceNodeKind.Constant, v.At, $"0x{v.Num:X}", why) { Value = v.Num });
                case A64Kind.Addr:
                    return Node(new SliceNode(SliceNodeKind.Address, v.At, host.FormatAddress(v.Rva, null).Text, why) { Rva = v.Rva });
                case A64Kind.StackAddr:
                    return Node(new SliceNode(SliceNodeKind.StackAddress, v.At, $"&local {A64Function.Name(A64Loc.Slot((int)(long)v.Num), null)} (from entry sp)", why) { Value = v.Num });
                case A64Kind.Import:
                {
                    var name = NativeCodeIndex.ImportName(host.ImportAt(v.Rva)!);
                    return Node(new SliceNode(SliceNodeKind.Import, v.At, name, why) { Rva = v.Rva, Callee = name, CallKind = CalleeKind.Import });
                }
                case A64Kind.Global:
                    return Node(new SliceNode(SliceNodeKind.Global, v.At, $"[{host.Index.NameAt(v.Rva) ?? host.Va(v.Rva)}]", why) { Rva = v.Rva });
                case A64Kind.Result:
                    return Node(CallResult(v.Rva, why));
                case A64Kind.Incoming:
                {
                    int index = A64Function.ParameterIndex(v.Loc);
                    var name = A64Function.Name(v.Loc, null);
                    return Node(new SliceNode(SliceNodeKind.Parameter, code.Function.Start, index >= 0 ? $"parameter {index + 1} ({name})" : $"incoming {name}", why)
                        { Location = name, Index = index });
                }
                case A64Kind.Merge:
                {
                    int id = Node(new SliceNode(SliceNodeKind.Merge, v.At, $"{v.Inputs!.Length} values", why) { Value = (ulong)v.Inputs.Length, Truncated = v.Truncated });
                    Truncated |= v.Truncated;
                    foreach (var input in v.Inputs)
                    {
                        int c = Add(input);
                        if (c >= 0) Edges.Add(new SliceEdge(c, id, input.Kind == A64Kind.Cycle ? SliceEdgeKind.Loop : SliceEdgeKind.Merge));
                    }
                    return id;
                }
                case A64Kind.Field:
                {
                    long off = (long)v.Num;
                    int id = Node(new SliceNode(SliceNodeKind.Field, v.At, $"field {(off < 0 ? "-" : "+")}0x{Math.Abs(off):X}", why) { Value = v.Num });
                    int c = Add(v.Inputs![0]);
                    if (c >= 0) Edges.Add(new SliceEdge(c, id, SliceEdgeKind.Field));
                    return id;
                }
                case A64Kind.Cycle:
                    return Node(new SliceNode(SliceNodeKind.Loop, v.At, "loop-carried value", why));
                default:
                    return Node(new SliceNode(SliceNodeKind.Unknown, v.At, "?", why));
            }
        }

        private SliceNode CallResult(uint site, string why)
        {
            if (host.CallAt(site, ct) is not { } c)
                return new SliceNode(SliceNodeKind.CallResult, site, $"result of the call at {host.Va(site)}", why) { Site = site };
            var text = c.Kind == CalleeKind.Indirect ? $"result of the call at {host.Va(site)}" : $"result of {c.Callee}";
            uint? target = c.Kind == CalleeKind.Function ? c.Target : null;
            return new SliceNode(SliceNodeKind.CallResult, site, text, why) { Site = site, Callee = c.Callee, CallKind = c.Kind, Target = target, Rva = c.Import?.SlotRva ?? 0 };
        }
    }
}

/// <summary>
/// Forward slice in an ARM64 function: the registers and stack slots holding the value are followed over the blocks
/// through copies and arithmetic until overwritten; each use is a node: call argument (x0-x7, stack slots at the call),
/// call target, store to a global or through a pointer, compare (cmp, cbz, tbz), switch index, dereference, return in x0.
/// </summary>
internal sealed class Arm64Forward(Arm64Trace host, A64Function code)
{
    private const int MaxSteps = 20_000;
    private const int MaxPathEntries = 6;
    private readonly List<SliceNode> _nodes = [];
    private readonly List<SliceEdge> _edges = [];
    private readonly Dictionary<(SliceNodeKind, uint, string?), int> _seen = [];
    private int _steps;
    private bool _truncated;
    private string? _note;

    /// <param name="Delta">What plain additions added to the traced value on the way here (null after other arithmetic).</param>
    private readonly record struct Live(bool Derived, string Path, long? Delta = 0);

    public FunctionSlice Run(SliceSeed seed, CancellationToken ct)
    {
        var live = new Dictionary<A64Loc, Live>();
        int block = -1, index = 0;
        string origin = "";
        switch (seed.Kind)
        {
            case SliceSeedKind.Parameter:
                block = code.BlockIndexOf(code.Function.Start);
                if (A64Function.Parse(seed.Location, null) is { } p) { live[p] = new Live(false, ""); origin = $"{A64Function.Name(p, null)} at entry"; }
                break;
            case SliceSeedKind.Result:
                (block, index) = code.Position(seed.Address);
                if (block >= 0) { live[A64Function.Parse(seed.Location, null) ?? A64Loc.Reg(0)] = new Live(false, ""); index++; }
                origin = $"result of the call at {host.Va(seed.Address)}";
                break;
            case SliceSeedKind.Loaded:
                (block, index) = code.Position(seed.Address);
                if (block >= 0 && A64Function.Gpr(code.Blocks[block][index].I, 0) is var d and >= 0 and < 31)
                {
                    live[A64Loc.Reg(d)] = new Live(false, "");
                    origin = $"{code.Blocks[block][index].Text} @{host.Va(seed.Address)}";
                    index++;
                }
                break;
            default:
                (block, index) = code.Position(seed.Address);
                if (block >= 0 && A64Function.Parse(seed.Location, code.Blocks[block][index]) is { } loc)
                {
                    live[loc] = new Live(false, "");
                    origin = $"{seed.Location} at {host.Va(seed.Address)}";
                    if (Defines(code.Blocks[block][index], loc)) index++;
                }
                break;
        }
        _nodes.Add(new SliceNode(SliceNodeKind.Origin, seed.Address, origin.Length > 0 ? origin : "?", ""));
        if (block < 0 || live.Count == 0) _note = "the seed is not an instruction or location of the function";
        else Walk(block, index, live, ct);
        return new FunctionSlice(code.Function, OursSliceProvider.EngineName, 0, _nodes, _edges, _steps, _truncated, _note);
    }

    private static bool Defines(A64Step s, A64Loc loc)
    {
        if (loc.IsSlot) return Arm64Resolver.IsStore(s.I) && A64Function.Memory(s)?.Slot == loc.Value;
        return A64Function.Dest(s.I) is { Kind: Arm64RegisterKind.X or Arm64RegisterKind.W } d && d.Index == loc.Value;
    }

    private void Walk(int startBlock, int startIndex, Dictionary<A64Loc, Live> start, CancellationToken ct)
    {
        var work = new Queue<(int Block, int Index, Dictionary<A64Loc, Live> Live)>();
        var visited = new HashSet<string>();
        work.Enqueue((startBlock, startIndex, start));
        while (work.Count > 0)
        {
            ct.ThrowIfCancellationRequested();
            var (block, index, live) = work.Dequeue();
            if (!Block(block, index, live)) continue;
            foreach (int next in code.Successors(block))
            {
                var key = next + ":" + string.Join(",", live.OrderBy(l => l.Key.IsSlot).ThenBy(l => l.Key.Value)
                    .Select(l => $"{(l.Key.IsSlot ? 's' : 'r')}{l.Key.Value}.{(l.Value.Derived ? 1 : 0)}.{l.Value.Delta}"));
                if (visited.Add(key)) work.Enqueue((next, 0, new Dictionary<A64Loc, Live>(live)));
            }
        }
    }

    private bool Block(int block, int index, Dictionary<A64Loc, Live> live)
    {
        var steps = code.Blocks[block];
        var tails = code.Graph.TailCalls;
        for (int k = index; k < steps.Length; k++)
        {
            if (live.Count == 0) return false;
            if (++_steps > MaxSteps)
            {
                _truncated = true;
                _note = $"stopped after {MaxSteps} instruction steps";
                return false;
            }
            var s = steps[k];
            var i = s.I;
            var flow = s.Facts.Flow;
            bool switchJump = flow == FlowKind.IndirectJump && code.Graph.Switches.Any(t => t.JumpRva == s.Rva);
            if (flow == FlowKind.IndirectCall && host.IsGuardCheck(code, block, k))
            {
                live.Remove(A64Loc.Reg(16));
                live.Remove(A64Loc.Reg(17));
                live.Remove(A64Loc.Reg(30));
                continue;
            }
            if (flow is FlowKind.Call or FlowKind.IndirectCall)
            {
                Target(s, live);
                Arguments(s, live);
                foreach (var loc in live.Keys.Where(l => !l.IsSlot && A64Function.IsVolatile(l.Value)).ToList()) live.Remove(loc);
                continue;
            }
            if (flow == FlowKind.Jump && s.Facts.HasTarget && tails.Contains(s.Facts.Target) || flow == FlowKind.IndirectJump && !switchJump)
            {
                Target(s, live);
                Arguments(s, live);
                return false;
            }
            if (flow == FlowKind.Return)
            {
                if (live.TryGetValue(A64Loc.Reg(0), out var r0))
                    Use(new SliceNode(SliceNodeKind.Return, s.Rva, "returned in x0", r0.Path) { Location = "x0", Derived = r0.Derived });
                return false;
            }
            if (i.Mnemonic is Arm64Mnemonic.CBZ or Arm64Mnemonic.CBNZ or Arm64Mnemonic.TBZ or Arm64Mnemonic.TBNZ)
            {
                if (A64Function.Gpr(i, 0) is var t and >= 0 && live.TryGetValue(A64Loc.Reg(t), out var l))
                {
                    ulong value = i.Mnemonic is Arm64Mnemonic.TBZ or Arm64Mnemonic.TBNZ && A64Function.Imm(in i, 1) is { } bit ? 1UL << (int)bit : 0;
                    Use(new SliceNode(SliceNodeKind.Compare, s.Rva, Disasm(s), Step(l.Path, s)) { Value = value, Derived = l.Derived });
                }
                continue;
            }
            if (Arm64Extensions.IsBranch(i.Id)) continue;
            Instruction(s, block, live, steps);
        }
        return true;
    }

    private string Disasm(A64Step s) => host.Index.Disassemble(s.Rva, 1) is [var line] ? line.Text.Replace("  ", " ").Trim() : s.Text;

    private string Step(string path, A64Step s)
    {
        var entry = $"{s.Text} @{host.Va(s.Rva)}";
        if (path.Length == 0) return entry;
        var parts = path.Split(" -> ");
        return parts.Length >= MaxPathEntries ? "... -> " + string.Join(" -> ", parts.Skip(parts.Length - MaxPathEntries + 2)) + " -> " + entry : path + " -> " + entry;
    }

    private void Instruction(A64Step s, int block, Dictionary<A64Loc, Live> live, A64Step[] steps)
    {
        var i = s.I;
        var mem = A64Function.Memory(s);
        Live? source = null;
        bool store = Arm64Resolver.IsStore(i), load = Arm64Resolver.IsLoad(i);
        // register operands read
        int firstRead = store ? 0 : 1;
        for (int k = firstRead; k < i.OperandCount; k++)
        {
            if (i.GetOperand(k) is not { Kind: Arm64OperandKind.Register } op || (op.Flags & Arm64OperandFlags.Read) == 0 && !store) continue;
            var r = ((Arm64RegisterOperand)op).Value;
            if (r.Kind is Arm64RegisterKind.X or Arm64RegisterKind.W && r.Index < 31 && live.TryGetValue(A64Loc.Reg(r.Index), out var l)) { source ??= l; if (store) break; }
        }
        // a live base or index register: the value is a pointer used here
        if (mem is { } m && m.Slot == null)
        {
            var a = m.Accessor;
            Live? pointer = null;
            bool field = false;
            if (a.BaseRegister.Kind == Arm64RegisterKind.X && live.TryGetValue(A64Loc.Reg(a.BaseRegister.Index), out var bl)) (pointer, field) = (bl, !a.HasIndexRegister);
            bool indexed = a.HasIndexRegister && live.TryGetValue(A64Loc.Reg(a.IndexRegister.Index), out var il) && (pointer = il) != null;
            if (pointer is { } p && !s.Facts.HasMem)
            {
                var text = MemoryText(s);
                var table = indexed && steps[^1].Facts.Flow == FlowKind.IndirectJump ? code.Graph.Switches.FirstOrDefault(t => t.JumpRva == steps[^1].Rva) : null;
                if (table != null)
                {
                    Use(new SliceNode(SliceNodeKind.Switch, s.Rva, $"indexes the switch at {host.Va(table.JumpRva)} ({table.Targets.Count} targets)", Step(p.Path, s))
                        { Derived = p.Derived, Value = (ulong)table.Targets.Count, Site = table.JumpRva, Offset = p.Delta });
                }
                else Use(new SliceNode(store ? SliceNodeKind.FieldStore : SliceNodeKind.Dereference, s.Rva,
                    $"{(store ? "points to the store" : "points to the load")} {text}", Step(p.Path, s))
                    { Derived = p.Derived, Offset = field ? Displacement(m) : null });
            }
        }
        // loads from a live stack slot carry it into the destination
        if (load && mem is { Slot: { } slot } && live.TryGetValue(A64Loc.Slot(slot), out var sl)) source = sl;

        if (i.Mnemonic is Arm64Mnemonic.CMP or Arm64Mnemonic.CMN or Arm64Mnemonic.TST or Arm64Mnemonic.CCMP or Arm64Mnemonic.CCMN)
        {
            if (A64Function.Gpr(i, 0) is var c and >= 0 and < 31 && live.TryGetValue(A64Loc.Reg(c), out var cl))
            {
                long? imm = A64Function.Imm(in i, 1);
                Use(new SliceNode(SliceNodeKind.Compare, s.Rva, Disasm(s), Step(cl.Path, s)) { Value = (ulong)(imm ?? 0), Derived = cl.Derived, Truncated = imm == null });
            }
            return;
        }

        if (store && mem is { } st && source is { } stored)
        {
            var next = new Live(stored.Derived, Step(stored.Path, s), stored.Delta);
            if (st.Slot is { } to) live[A64Loc.Slot(to)] = next;
            else if (s.Facts.HasMem && host.ImportAt(s.Facts.MemTarget) == null && IsWritable(s.Facts.MemTarget))
                Use(new SliceNode(SliceNodeKind.Store, s.Rva, $"stored to [{host.Index.NameAt(s.Facts.MemTarget) ?? host.Va(s.Facts.MemTarget)}]", next.Path)
                    { Rva = s.Facts.MemTarget, Derived = next.Derived });
            else if (!s.Facts.HasMem)
            {
                bool plain = !st.Accessor.HasIndexRegister && st.Accessor.BaseRegister.Kind == Arm64RegisterKind.X;
                Use(new SliceNode(SliceNodeKind.FieldStore, s.Rva, $"stored to {MemoryText(s)}", next.Path)
                    { Derived = next.Derived, Offset = plain ? Displacement(st) : null, Base = plain ? $"x{st.Accessor.BaseRegister.Index}" : null });
            }
        }
        else if (store && mem is { Slot: { } over }) live.Remove(A64Loc.Slot(over));

        // destinations: written registers get the value (derived unless a copy) or lose it
        bool copy = i.Mnemonic is Arm64Mnemonic.MOV or Arm64Mnemonic.SXTW or Arm64Mnemonic.SXTH or Arm64Mnemonic.SXTB
            or Arm64Mnemonic.UXTB or Arm64Mnemonic.UXTH || load && mem is { Slot: not null };
        for (int k = 0; k < i.OperandCount && !store; k++)
        {
            if (i.GetOperand(k) is not { Kind: Arm64OperandKind.Register } op || (op.Flags & Arm64OperandFlags.Write) == 0) continue;
            var r = ((Arm64RegisterOperand)op).Value;
            if (r.Kind is not (Arm64RegisterKind.X or Arm64RegisterKind.W) || r.Index >= 31) continue;
            var dest = A64Loc.Reg(r.Index);
            if (source is { } src && (k == 0 || load && mem is { Slot: not null }))
            {
                long? delta = copy ? src.Delta
                    : i.Mnemonic is Arm64Mnemonic.ADD or Arm64Mnemonic.SUB && A64Function.Imm(in i, 2) is { } imm && i.GetOperand(1).Kind == Arm64OperandKind.Register
                        ? src.Delta + (i.Mnemonic == Arm64Mnemonic.SUB ? -imm : imm) : null;
                live[dest] = new Live(src.Derived || !copy, Step(src.Path, s), delta);
            }
            else live.Remove(dest);
        }
        if (mem is { } wb && (wb.Accessor.IsPreIncrement || wb.Post) && wb.Accessor.BaseRegister.Kind == Arm64RegisterKind.X)
            live.Remove(A64Loc.Reg(wb.Accessor.BaseRegister.Index));
    }

    private bool IsWritable(uint rva) => host.Index.Image.SectionAt(rva) is { } s && (s.Access & SectionAccess.Write) != 0;

    private static long Displacement((int Operand, Arm64MemoryAccessorAny Accessor, bool Post, int? Slot) m) =>
        m.Post || !m.Accessor.HasImmediate ? 0 : m.Accessor.Immediate;

    private static string MemoryText(A64Step s)
    {
        var t = s.Text;
        int open = t.IndexOf('['), close = t.IndexOf(']');
        return open >= 0 && close > open ? t[open..(close + 1)] : "memory";
    }

    private void Target(A64Step s, Dictionary<A64Loc, Live> live)
    {
        if (s.Facts.Flow is not (FlowKind.IndirectCall or FlowKind.IndirectJump)) return;
        if (A64Function.Gpr(s.I, 0) is var t and >= 0 && live.TryGetValue(A64Loc.Reg(t), out var l))
            Use(new SliceNode(SliceNodeKind.CallTarget, s.Rva, "called", Step(l.Path, s)) { Site = s.Rva, Derived = l.Derived });
    }

    private void Arguments(A64Step s, Dictionary<A64Loc, Live> live)
    {
        CallSiteInfo? call = null;
        bool looked = false;
        foreach (var (loc, l) in live.OrderBy(l => l.Key.IsSlot).ThenBy(l => l.Key.Value).ToList())
        {
            A64Loc entry;
            if (!loc.IsSlot) { if (loc.Value >= 8) continue; entry = loc; }
            else if (s.Sp is { } sp && loc.Value - sp is var off and >= 0 && off < 8 * 16 && off % 8 == 0) entry = A64Loc.Slot(off);
            else continue;
            if (!looked) { call = host.CallAt(s.Rva, default); looked = true; }
            int index = A64Function.ParameterIndex(entry);
            var sig = call?.Signature;
            if (sig != null && !sig.Variadic && index >= sig.Params.Count) continue;
            var calleeName = call?.Callee ?? s.Text;
            var name = sig != null && index >= 0 && index < sig.Params.Count ? $" {sig.Params[index].Name}" : "";
            uint? target = call is { Kind: CalleeKind.Function } ? call.Target : null;
            Use(new SliceNode(SliceNodeKind.Argument, s.Rva, $"argument {index + 1}{name} of {calleeName}", Step(l.Path, s))
            {
                Offset = l.Delta,
                Site = s.Rva, Location = A64Function.Name(entry, null), Index = index, Callee = calleeName, CallKind = call?.Kind ?? CalleeKind.Indirect,
                Target = target, Derived = l.Derived, Rva = call?.Import?.SlotRva ?? 0,
            });
        }
    }

    private void Use(SliceNode node)
    {
        var key = (node.Kind, node.Address, node.Location);
        if (_seen.ContainsKey(key)) return;
        if (_nodes.Count >= OursSliceProvider.MaxSliceNodes) { _truncated = true; return; }
        _nodes.Add(node);
        _seen[key] = _nodes.Count - 1;
        _edges.Add(new SliceEdge(0, _nodes.Count - 1, SliceEdgeKind.Use));
    }
}
