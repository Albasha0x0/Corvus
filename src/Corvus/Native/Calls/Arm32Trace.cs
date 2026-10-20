using System.Collections.Concurrent;
using System.Runtime.CompilerServices;
using System.Text;
using Corvus.Core;
using Corvus.Native.Code;

namespace Corvus.Native.Calls;

/// <summary>
/// Value tracing and call-target facts for 32-bit ARM code under the AAPCS (r0-r3 and 4-byte stack slots for arguments,
/// r0 for results, r0-r3, r12 and lr caller-saved): decoded functions, the backward resolver and the per-function slices
/// the <see cref="ValueTrace"/> driver composes. One instance per code index, thread-safe.
/// </summary>
internal sealed class Arm32Trace : ITraceHost
{
    private const int MaxCachedFunctions = 512;
    private static readonly ConditionalWeakTable<NativeCodeIndex, Arm32Trace> Table = new();
    private readonly uint[] _relocs;
    private readonly Dictionary<uint, NativeImport> _slots = [];
    private readonly ConcurrentDictionary<uint, A32Function> _code = new();
    private Arm32SliceProvider? _slices;
    private ValueTraceCache? _traces;

    private Arm32Trace(NativeCodeIndex index)
    {
        Index = index;
        _relocs = index.Image.RelocationRvas.ToArray();
        Array.Sort(_relocs);
        foreach (var i in index.Image.Imports) _slots.TryAdd(i.SlotRva, i);
    }

    public static bool Supports(NativeCodeIndex index) => index.Support == CodeSupport.Full && index.Image.Arch == NativeArch.Arm;

    public static Arm32Trace For(NativeCodeIndex index)
    {
        if (!Supports(index)) throw new NotSupportedException($"ARM32 value analysis needs a 32-bit ARM code index, not {index.Image.Arch}");
        return Table.GetValue(index, i => new Arm32Trace(i));
    }

    public NativeCodeIndex Index { get; }
    public bool Is64 => false;
    public string ReturnLocation => "r0";
    public string ParameterLocation(int index) => A32Function.Name(A32Function.ParameterEntry(index), null);
    public ValueTraceCache Traces => LazyInitializer.EnsureInitialized(ref _traces, () => new ValueTraceCache());
    public IFunctionSliceProvider Slices => LazyInitializer.EnsureInitialized(ref _slices, () => new Arm32SliceProvider(this));
    public Arm32CallSites Calls => Arm32CallSites.For(Index);

    public string Va(uint rva) => NativeAddress.Va(Index.Image, rva);
    public bool IsRelocated(uint rva) => Array.BinarySearch(_relocs, rva) >= 0;
    public NativeImport? ImportAt(uint slot) => _slots.GetValueOrDefault(slot);

    /// <summary>The function a GOT slot of an exported function of this image reaches, or null.</summary>
    public uint? LocalSlot(uint slot) => Index.ArmModes?.LocalSlots.TryGetValue(slot, out uint fn) == true ? fn & ~1u : null;

    public A32Function Code(NativeFunction f, CancellationToken ct)
    {
        if (_code.TryGetValue(f.Start, out var hit)) return hit;
        var code = new A32Function(Index, f, ct);
        if (_code.Count >= MaxCachedFunctions) _code.Clear();
        _code[f.Start] = code;
        return code;
    }

    public (ArgKind Kind, ulong? Value, uint? Rva, string Text) FormatAddress(uint rva, ApiParam? p)
    {
        bool wide = p?.Type is ApiParamType.WideString or ApiParamType.WideFormat;
        if (Index.StringAt(rva) is { } s && (s.Encoding == StringEncoding.Utf16) == wide) return (ArgKind.String, null, rva, Quote(Index.ReadString(s, 200), wide));
        if (Index.NameAt(rva) is { } name) return (ArgKind.Name, null, rva, name);
        return (ArgKind.Address, null, rva, Va(rva));
    }

    internal static string Quote(string text, bool wide)
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
        if (code.Position(site).Block < 0 || code.Parse(entry, null) is not { } loc) return entry;
        return loc.IsSlot ? A32Function.Name(loc, null) : entry;
    }

    public ulong? ConstantAfter(NativeFunction f, uint address, string location, CancellationToken ct)
    {
        var code = Code(f, ct);
        var (b, i) = code.Position(address);
        if (b < 0 || code.Parse(location, code.Blocks[b][i]) is not { } loc) return null;
        var v = new Arm32Resolver(this, code) { Budget = 2000 }.Before(loc, b, i + 1);
        return v.Kind == A64Kind.Const ? v.Num : null;
    }

    public CallSiteInfo? CallAt(uint site, CancellationToken ct) => Calls.CallAt(site, ct);

    /// <summary>The seed: registers r0-r14, stack slots relative to sp or the frame pointer at the instruction, AAPCS argument positions.</summary>
    internal static TraceSeed Seed(Arm32Trace a, string address, uint rva, string? location, string? argument, CancellationToken ct)
    {
        var index = a.Index;
        string Va(uint r) => NativeAddress.Va(index.Image, r);
        string Where(uint r) => index.FunctionAt(r) is { } f ? Format.Within(f.Name, f.Start, r) : Va(r);
        var fn = index.FunctionAt(rva);
        if (!string.IsNullOrWhiteSpace(argument))
        {
            if (fn == null) throw new ToolError(ErrorCode.NotFound, $"No function contains {Va(rva)}.", "argument needs a call instruction or a function start");
            if (a.CallAt(rva, ct) is { } call)
            {
                var sig = call.Signature;
                int k = ArgumentIndex(argument, sig, call.Callee);
                var entry = A32Function.Name(A32Function.ParameterEntry(k), null);
                var p = sig != null && k < sig.Params.Count ? sig.Params[k] : null;
                return new TraceSeed(TraceSeedKind.Argument, rva, fn, entry, $"argument {k + 1}{(p != null ? " " + p.Name : "")} ({entry}) of {call.Callee} at {Va(rva)} ({Where(rva)})", p);
            }
            if (fn.Start == rva)
            {
                int k = ArgumentIndex(argument, null, fn.Name);
                var entry = A32Function.Name(A32Function.ParameterEntry(k), null);
                return new TraceSeed(TraceSeedKind.Parameter, rva, fn, entry, $"parameter {k + 1} ({entry}) of {fn.Name}");
            }
            throw new ToolError(ErrorCode.InvalidArgument, $"{Va(rva)} ({Where(rva)}) is neither a call nor a function start.",
                "pass a call instruction or a function start with argument, or use location at other instructions");
        }
        if (string.IsNullOrWhiteSpace(location))
        {
            if (fn == null && index.Image.SectionAt(rva) is { } section && (section.Access & SectionAccess.Write) != 0)
                return new TraceSeed(TraceSeedKind.Global, rva, null, null, $"global [{index.NameAt(rva) ?? Va(rva)}]");
            throw new ToolError(ErrorCode.InvalidArgument, "Pass location (a register r0-r12 / lr / s0-s31 / d0-d31, a stack slot [sp+10h] or [r7-8], op1 / op2 or result) or argument; " +
                "address alone is for a writable global.", "for example location=r0, or argument=1 at a call");
        }
        if (fn == null) throw new ToolError(ErrorCode.NotFound, $"No function contains {Va(rva)}.", "list_functions shows the functions; a writable global needs no location");
        var code = a.Code(fn, ct);
        var (block, at) = code.Position(rva);
        if (block < 0)
            throw new ToolError(ErrorCode.InvalidArgument, $"{Va(rva)} is not the start of an instruction of {fn.Name}.", "disassemble shows the instruction addresses");
        var step = code.Blocks[block][at];
        var loc = location.Trim();
        if (loc.Equals("result", StringComparison.OrdinalIgnoreCase))
        {
            var call = a.CallAt(rva, ct) ?? throw new ToolError(ErrorCode.InvalidArgument, $"{Va(rva)} is not a call: location=result needs one.");
            return new TraceSeed(TraceSeedKind.Result, rva, fn, null, $"result of {call.Callee} at {Va(rva)} ({Where(rva)})", Returns: ApiSignatures.FindReturn(call.Callee));
        }
        if (loc.Length == 3 && loc.StartsWith("op", StringComparison.OrdinalIgnoreCase) && char.IsAsciiDigit(loc[2]))
        {
            int k = loc[2] - '1';
            var x = step.I;
            if (k < 0 || k >= x.OperandCount) throw new ToolError(ErrorCode.InvalidArgument, $"{step.Text} has {x.OperandCount} operands.", "op1 is the first operand");
            var op = x.Op(k);
            if (op.Kind is ArmOperandKind.Register or ArmOperandKind.ShiftedRegister && op.Reg is < A32Function.Sp or A32Function.Lr) loc = ArmInstruction.RegisterNames[op.Reg];
            else if (A32Function.Vfp(op) is { } vfp) loc = A32Function.Name(vfp, null);
            else if (op.Kind == ArmOperandKind.Memory && step.Facts.HasMem && index.Image.SectionAt(step.Facts.MemTarget) is { } s && (s.Access & SectionAccess.Write) != 0)
                return new TraceSeed(TraceSeedKind.Global, step.Facts.MemTarget, null, null, $"global [{index.NameAt(step.Facts.MemTarget) ?? Va(step.Facts.MemTarget)}] ({step.Text} at {Where(rva)})");
            else if (op.Kind == ArmOperandKind.Memory && code.Slot(step) is { } slot) loc = A32Function.Name(A32Loc.Slot(slot), step);
            else
                throw new ToolError(ErrorCode.InvalidArgument, $"Operand {k + 1} of {step.Text} is not a register, stack slot or writable global.",
                    "trace the base register of a memory operand instead (location=<register>)");
        }
        var parsed = code.Parse(loc, step) ?? throw new ToolError(ErrorCode.InvalidArgument, $"Unknown location '{location}'.", "use r0-r12, lr, s0-s31, d0-d31, [sp+10h] or [r7-8]");
        var name = A32Function.Name(parsed, step);
        return new TraceSeed(TraceSeedKind.Location, rva, fn, name, $"{name} at {Va(rva)} ({Where(rva)}: {step.Text})");
    }

    private static int ArgumentIndex(string argument, ApiSignature? sig, string callee)
    {
        var text = argument.Trim();
        if (int.TryParse(text, out int n))
        {
            if (n is < 1 or > 32) throw new ToolError(ErrorCode.InvalidArgument, $"argument {n}: positions run from 1 to 32.", "pass argument=1 for the first");
            if (sig is { Variadic: false } && n > sig.Params.Count)
                throw new ToolError(ErrorCode.InvalidArgument, $"{callee} takes {sig.Params.Count} arguments.", $"pass 1 to {sig.Params.Count}");
            return n - 1;
        }
        if (sig == null) throw new ToolError(ErrorCode.InvalidArgument, $"No signature is known for {callee}: pass the argument's position.");
        for (int k = 0; k < sig.Params.Count; k++)
            if (sig.Params[k].Name.Equals(text, StringComparison.OrdinalIgnoreCase)) return k;
        throw new ToolError(ErrorCode.InvalidArgument, $"{callee} has no parameter '{text}'.", "its parameters: " + string.Join(", ", sig.Params.Select(p => p.Name)));
    }
}

/// <summary>The built-in engine's ARM32 slices: backward through <see cref="Arm32Resolver"/>, forward through <see cref="Arm32Forward"/>; memoized per function and seed.</summary>
internal sealed class Arm32SliceProvider(Arm32Trace host) : IFunctionSliceProvider
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
        var slice = forward ? new Arm32Forward(host, code).Run(seed, ct) : BackwardSlice(code, seed, ct);
        if (_cache.Count >= MaxCachedSlices) _cache.Clear();
        _cache[key] = slice;
        return slice;
    }

    private FunctionSlice BackwardSlice(A32Function code, SliceSeed seed, CancellationToken ct)
    {
        var b = new Builder(host, code, ct);
        var r = new Arm32Resolver(host, code);
        string? note = null;
        switch (seed.Kind)
        {
            case SliceSeedKind.Location or SliceSeedKind.Argument:
            {
                var (block, index) = code.Position(seed.Address);
                var loc = block >= 0 ? code.Parse(seed.Location, seed.Kind == SliceSeedKind.Argument ? null : code.Blocks[block][index]) : null;
                // an argument's entry slot is the slot at the call, where sp is the caller's sp there
                if (seed.Kind == SliceSeedKind.Argument && loc is { IsSlot: true } entry && block >= 0)
                    loc = code.Blocks[block][index].Sp is { } sp ? A32Loc.Slot(sp + entry.Value) : null;
                b.Add(block < 0 || loc == null ? A32Val.Unknown(block < 0 ? "not an instruction of the function" : $"unknown location '{seed.Location}'") : r.Before(loc.Value, block, index));
                break;
            }
            case SliceSeedKind.Stored:
            {
                var (block, index) = code.Position(seed.Address);
                b.Add(block < 0 ? A32Val.Unknown("not an instruction of the function") : r.Stored(block, index));
                break;
            }
            case SliceSeedKind.Result:
                b.Add(new A32Val(A64Kind.Result, seed.Address, "") { Rva = seed.Address });
                break;
            case SliceSeedKind.Parameter:
                b.Add(code.Parse(seed.Location, null) is { } p ? new A32Val(A64Kind.Incoming, code.Function.Start, "") { Loc = p } : A32Val.Unknown($"unknown location '{seed.Location}'"));
                break;
            case SliceSeedKind.Returns:
                note = Returns(code, r, b);
                break;
        }
        return new FunctionSlice(code.Function, Engine, 0, b.Nodes, b.Edges, r.Steps, b.Truncated, note);
    }

    /// <summary>r0 before each return and the results of tail calls, merged.</summary>
    private string? Returns(A32Function code, Arm32Resolver r, Builder b)
    {
        string? note = null;
        var values = new List<A32Val>();
        int sites = 0;
        var tails = code.Graph.TailCalls.ToHashSet();
        for (int block = 0; block < code.Blocks.Length; block++)
        {
            var steps = code.Blocks[block];
            for (int k = 0; k < steps.Length; k++)
            {
                var s = steps[k];
                bool last = k == steps.Length - 1;
                A32Val v;
                if (s.Facts.Flow == FlowKind.Return) v = r.Before(A32Loc.Reg(0), block, k);
                else if (last && (s.Facts.Flow is FlowKind.Jump && s.Facts.HasTarget && tails.Contains(s.Facts.Target)
                         || s.Facts.Flow == FlowKind.IndirectJump && !code.Graph.Switches.Any(t => t.JumpRva == s.Rva)))
                    v = new A32Val(A64Kind.Result, s.Rva, $"tail call at {host.Va(s.Rva)}") { Rva = s.Rva };
                else continue;
                if (++sites > MaxReturns) { note = $"more than {MaxReturns} returns: the first {MaxReturns}"; goto done; }
                if (!values.Any(o => o.SameAs(v))) values.Add(v);
            }
        }
        done:
        if (values.Count == 0) b.Add(A32Val.Unknown("the function has no return"));
        else if (values.Count == 1) b.Add(values[0]);
        else b.Add(new A32Val(A64Kind.Merge, 0, $"returned at {sites} sites") { Inputs = [.. values], Truncated = note != null });
        return note;
    }

    /// <summary>Turns a resolver value tree into slice nodes.</summary>
    private sealed class Builder(Arm32Trace host, A32Function code, CancellationToken ct)
    {
        public readonly List<SliceNode> Nodes = [];
        public readonly List<SliceEdge> Edges = [];
        public bool Truncated;

        private int Node(SliceNode n)
        {
            Nodes.Add(n);
            return Nodes.Count - 1;
        }

        public int Add(A32Val v)
        {
            if (Nodes.Count >= OursSliceProvider.MaxSliceNodes) { Truncated = true; return -1; }
            var why = v.Why;
            switch (v.Kind)
            {
                case A64Kind.Const:
                    return Node(new SliceNode(SliceNodeKind.Constant, v.At, v.Text ?? $"0x{v.Num:X}", why) { Value = v.Num, Float = v.Text != null });
                case A64Kind.Addr:
                    return Node(new SliceNode(SliceNodeKind.Address, v.At, host.FormatAddress(v.Rva, null).Text, why) { Rva = v.Rva });
                case A64Kind.StackAddr:
                    return Node(new SliceNode(SliceNodeKind.StackAddress, v.At, $"&local {A32Function.Name(A32Loc.Slot((int)(long)v.Num), null)} (from entry sp)", why) { Value = v.Num });
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
                    int index = A32Function.ParameterIndex(v.Loc);
                    var name = A32Function.Name(v.Loc, null);
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
            return new SliceNode(SliceNodeKind.CallResult, site, text, why) { Site = site, Callee = c.Callee, CallKind = c.Kind, Target = target };
        }
    }
}

/// <summary>
/// Forward slice in a 32-bit ARM function: the registers and stack slots holding the value are followed over the blocks
/// through copies and arithmetic until overwritten; each use is a node: call argument (r0-r3, stack slots at the call),
/// call target, store to a global or through a pointer, compare (cmp, tst, cbz, vcmp), switch index, dereference, return in
/// r0 (s0 / d0 for a float). VFP registers follow vmov, vldr / vstr of locals and arithmetic.
/// </summary>
internal sealed class Arm32Forward(Arm32Trace host, A32Function code)
{
    private const int MaxSteps = 20_000;
    private const int MaxPathEntries = 6;
    private readonly List<SliceNode> _nodes = [];
    private readonly List<SliceEdge> _edges = [];
    private readonly Dictionary<(SliceNodeKind, uint, string?), int> _seen = [];
    private int _steps;
    private bool _truncated;
    private string? _note;

    private readonly record struct Live(bool Derived, string Path);

    public FunctionSlice Run(SliceSeed seed, CancellationToken ct)
    {
        var live = new Dictionary<A32Loc, Live>();
        int block = -1, index = 0;
        string origin = "";
        switch (seed.Kind)
        {
            case SliceSeedKind.Parameter:
                block = code.BlockIndexOf(code.Function.Start);
                if (code.Parse(seed.Location, null) is { } p) { live[p] = new Live(false, ""); origin = $"{A32Function.Name(p, null)} at entry"; }
                break;
            case SliceSeedKind.Result:
                (block, index) = code.Position(seed.Address);
                if (block >= 0) { live[code.Parse(seed.Location, null) ?? A32Loc.Reg(0)] = new Live(false, ""); index++; }
                origin = $"result of the call at {host.Va(seed.Address)}";
                break;
            case SliceSeedKind.Loaded:
                (block, index) = code.Position(seed.Address);
                if (block >= 0 && A32Function.Dest(code.Blocks[block][index].I) is var d and >= 0 and < A32Function.Sp)
                {
                    live[A32Loc.Reg(d)] = new Live(false, "");
                    origin = $"{code.Blocks[block][index].Text} @{host.Va(seed.Address)}";
                    index++;
                }
                break;
            default:
                (block, index) = code.Position(seed.Address);
                if (block >= 0 && code.Parse(seed.Location, code.Blocks[block][index]) is { } loc)
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

    private bool Defines(A32Step s, A32Loc loc) =>
        loc.IsSlot ? s.I.Stores && code.Slot(s) == loc.Value : loc.IsVfp ? A32Function.VfpDest(s.I) == loc : (s.I.Writes & (1 << loc.Value)) != 0;

    private void Walk(int startBlock, int startIndex, Dictionary<A32Loc, Live> start, CancellationToken ct)
    {
        var work = new Queue<(int Block, int Index, Dictionary<A32Loc, Live> Live)>();
        var visited = new HashSet<string>();
        work.Enqueue((startBlock, startIndex, start));
        while (work.Count > 0)
        {
            ct.ThrowIfCancellationRequested();
            var (block, index, live) = work.Dequeue();
            if (!Block(block, index, live)) continue;
            foreach (int next in code.Successors(block))
            {
                var key = next + ":" + string.Join(",", live.OrderBy(l => l.Key.IsSlot).ThenBy(l => l.Key.Value).Select(l => $"{(l.Key.IsSlot ? 's' : 'r')}{l.Key.Value}.{(l.Value.Derived ? 1 : 0)}"));
                if (visited.Add(key)) work.Enqueue((next, 0, new Dictionary<A32Loc, Live>(live)));
            }
        }
    }

    private bool Block(int block, int index, Dictionary<A32Loc, Live> live)
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
            if (switchJump)
            {
                if (A32Function.Memory(i) is { Index: var ix } && ix != ArmOperand.NoReg && live.TryGetValue(A32Loc.Reg(ix), out var sw))
                {
                    var table = code.Graph.Switches.First(t => t.JumpRva == s.Rva);
                    Use(new SliceNode(SliceNodeKind.Switch, s.Rva, $"indexes the switch at {host.Va(s.Rva)} ({table.Targets.Count} targets)", Step(sw.Path, s))
                        { Derived = sw.Derived, Value = (ulong)table.Targets.Count });
                }
                continue;
            }
            if (flow is FlowKind.Call or FlowKind.IndirectCall)
            {
                Target(s, live);
                Arguments(s, live);
                foreach (var loc in live.Keys.Where(l => !l.IsSlot && A32Function.IsVolatile(l.Value)).ToList()) live.Remove(loc);
                continue;
            }
            if ((flow == FlowKind.Jump && s.Facts.HasTarget && tails.Contains(s.Facts.Target) || flow == FlowKind.IndirectJump) && !i.IsConditional)
            {
                Target(s, live);
                Arguments(s, live);
                return false;
            }
            if (flow == FlowKind.Return)
            {
                foreach (var ret in new[] { A32Loc.Reg(0), A32Loc.Reg(A32Function.VfpS), A32Loc.Reg(A32Function.VfpD) })
                    if (live.TryGetValue(ret, out var r0))
                    {
                        var name = A32Function.Name(ret, null);
                        Use(new SliceNode(SliceNodeKind.Return, s.Rva, $"returned in {name}", r0.Path) { Location = name, Derived = r0.Derived });
                    }
                if (!s.Facts.Conditional) return false;
                continue;
            }
            if (i.Mnemonic is "vcmp" or "vcmpe")
            {
                if (A32Function.Vfp(i.Op(0)) is { } v && live.TryGetValue(v, out var l))
                    Use(new SliceNode(SliceNodeKind.Compare, s.Rva, s.Text, Step(l.Path, s)) { Derived = l.Derived, Truncated = i.OperandCount < 2 || i.Op(1).Kind != ArmOperandKind.Text });
                continue;
            }
            if (i.Mnemonic is "cbz" or "cbnz" or "cmp" or "cmn" or "tst" or "teq")
            {
                if (i.Op(0).Kind == ArmOperandKind.Register && live.TryGetValue(A32Loc.Reg(i.Op(0).Reg), out var l))
                {
                    long? imm = i.Mnemonic is "cbz" or "cbnz" ? 0 : i.OperandCount > 1 && i.Op(1).Kind == ArmOperandKind.Immediate ? i.Op(1).Value : null;
                    Use(new SliceNode(SliceNodeKind.Compare, s.Rva, s.Text, Step(l.Path, s)) { Value = (ulong)(imm ?? 0), Derived = l.Derived, Truncated = imm == null });
                }
                continue;
            }
            if (flow != FlowKind.Next) continue;
            Instruction(s, live);
        }
        return true;
    }

    private string Step(string path, A32Step s)
    {
        var entry = $"{s.Text} @{host.Va(s.Rva)}";
        if (path.Length == 0) return entry;
        var parts = path.Split(" -> ");
        return parts.Length >= MaxPathEntries ? "... -> " + string.Join(" -> ", parts.Skip(parts.Length - MaxPathEntries + 2)) + " -> " + entry : path + " -> " + entry;
    }

    private void Instruction(A32Step s, Dictionary<A32Loc, Live> live)
    {
        var i = s.I;
        var mem = A32Function.Memory(i);
        int? slot = code.Slot(s);
        Live? source = null;
        // core registers read (a store's first operand is its value)
        for (int k = i.Stores ? 0 : 1; k < i.OperandCount; k++)
        {
            var op = i.Op(k);
            if ((op.Kind is ArmOperandKind.Register or ArmOperandKind.ShiftedRegister && op.Reg < A32Function.Sp && live.TryGetValue(A32Loc.Reg(op.Reg), out var l))
                || A32Function.Vfp(op) is { } v && live.TryGetValue(v, out l))
            {
                source ??= l;
                if (i.Stores) break;
            }
        }
        if (i.OperandCount == 2 && !i.Stores && i.Op(0).Kind == ArmOperandKind.Register && live.TryGetValue(A32Loc.Reg(i.Op(0).Reg), out var self) && i.Mnemonic is not ("mov" or "mvn"))
            source ??= self;
        // a live base or index register: the value is a pointer used here
        if (mem is { } m && slot == null && m.Reg != A32Function.Pc && !s.Facts.HasMem)
        {
            Live? pointer = live.TryGetValue(A32Loc.Reg(m.Reg), out var bl) ? bl : m.Index != ArmOperand.NoReg && live.TryGetValue(A32Loc.Reg(m.Index), out var il) ? il : null;
            if (pointer is { } p)
                Use(new SliceNode(i.Stores ? SliceNodeKind.FieldStore : SliceNodeKind.Dereference, s.Rva,
                    $"{(i.Stores ? "points to the store" : "points to the load")} {MemoryText(s)}", Step(p.Path, s)) { Derived = p.Derived });
        }
        if (i.Loads && slot is { } from && live.TryGetValue(A32Loc.Slot(from), out var sl)) source = sl;

        if (i.Stores && mem != null && source is { } stored)
        {
            var next = new Live(stored.Derived, Step(stored.Path, s));
            if (slot is { } to) live[A32Loc.Slot(to)] = next;
            else if (s.Facts.HasMem && host.ImportAt(s.Facts.MemTarget) == null && IsWritable(s.Facts.MemTarget))
                Use(new SliceNode(SliceNodeKind.Store, s.Rva, $"stored to [{host.Index.NameAt(s.Facts.MemTarget) ?? host.Va(s.Facts.MemTarget)}]", next.Path)
                    { Rva = s.Facts.MemTarget, Derived = next.Derived });
            else if (!s.Facts.HasMem) Use(new SliceNode(SliceNodeKind.FieldStore, s.Rva, $"stored to {MemoryText(s)}", next.Path) { Derived = next.Derived });
        }
        else if (i.Stores && slot is { } over) live.Remove(A32Loc.Slot(over));
        if (i.Mnemonic == "push" && s.Sp is { } sp)
        {
            // pushed registers land in the slots below sp
            long mask = i.Op(0).Value;
            int n = System.Numerics.BitOperations.PopCount((ulong)mask), rank = 0;
            for (int r = 0; r < 16; r++)
                if ((mask & (1 << r)) != 0)
                {
                    if (live.TryGetValue(A32Loc.Reg(r), out var pushed)) live[A32Loc.Slot(sp - 4 * n + 4 * rank)] = pushed with { Path = Step(pushed.Path, s) };
                    rank++;
                }
        }

        // destinations: written registers get the value (derived unless a copy) or lose it
        bool copy = i.Mnemonic is "mov" or "uxtb" or "uxth" or "sxtb" or "sxth" or "vmov" || i.Loads && slot != null;
        foreach (var gone in live.Keys.Where(l => l.IsVfp && (A32Function.ListCovers(i, l) || A32Function.VfpDest(i) is { } d && d != l && A32Function.Overlaps(d, l))).ToList())
            live.Remove(gone);
        if (A32Function.VfpDest(i) is { } vd)
        {
            if (source is { } src) live[vd] = new Live(src.Derived || !copy, Step(src.Path, s));
            else if (!i.IsConditional) live.Remove(vd);
        }
        for (int r = 0; r < A32Function.Sp; r++)
        {
            if ((i.Writes & (1 << r)) == 0) continue;
            var dest = A32Loc.Reg(r);
            if (source is { } src && !i.Stores && (A32Function.Dest(i) == r || i.Loads && slot != null)) live[dest] = new Live(src.Derived || !copy, Step(src.Path, s));
            else if (!i.IsConditional) live.Remove(dest);
        }
    }

    private bool IsWritable(uint rva) => host.Index.Image.SectionAt(rva) is { } s && (s.Access & SectionAccess.Write) != 0;

    private static string MemoryText(A32Step s)
    {
        var t = s.Text;
        int open = t.IndexOf('['), close = t.IndexOf(']');
        return open >= 0 && close > open ? t[open..(close + 1)] : "memory";
    }

    private void Target(A32Step s, Dictionary<A32Loc, Live> live)
    {
        if (s.Facts.Flow is not (FlowKind.IndirectCall or FlowKind.IndirectJump)) return;
        if (s.I.Mnemonic is "bx" or "blx" && s.I.Op(0).Kind == ArmOperandKind.Register && live.TryGetValue(A32Loc.Reg(s.I.Op(0).Reg), out var l))
            Use(new SliceNode(SliceNodeKind.CallTarget, s.Rva, "called", Step(l.Path, s)) { Site = s.Rva, Derived = l.Derived });
    }

    private void Arguments(A32Step s, Dictionary<A32Loc, Live> live)
    {
        CallSiteInfo? call = null;
        bool looked = false;
        foreach (var (loc, l) in live.OrderBy(l => l.Key.IsSlot).ThenBy(l => l.Key.Value).ToList())
        {
            A32Loc entry;
            if (!loc.IsSlot) { if (!(loc.Value < 4 || loc.IsVfp && A32Function.IsVolatile(loc.Value) && loc.Value < A32Function.VfpD + 8)) continue; entry = loc; }
            else if (s.Sp is { } sp && loc.Value - sp is var off and >= 0 && off < 4 * 16 && off % 4 == 0) entry = A32Loc.Slot(off);
            else continue;
            if (!looked) { call = host.CallAt(s.Rva, default); looked = true; }
            int index = A32Function.ParameterIndex(entry);
            var sig = call?.Signature;
            if (sig != null && !sig.Variadic && index >= sig.Params.Count) continue;
            var calleeName = call?.Callee ?? s.Text;
            var name = sig != null && index >= 0 && index < sig.Params.Count ? $" {sig.Params[index].Name}" : "";
            uint? target = call is { Kind: CalleeKind.Function } ? call.Target : null;
            Use(new SliceNode(SliceNodeKind.Argument, s.Rva, $"argument {(index >= 0 ? (index + 1).ToString(System.Globalization.CultureInfo.InvariantCulture) : A32Function.Name(entry, null))}{name} of {calleeName}", Step(l.Path, s))
            {
                Site = s.Rva, Location = A32Function.Name(entry, null), Index = index, Callee = calleeName, CallKind = call?.Kind ?? CalleeKind.Indirect,
                Target = target, Derived = l.Derived,
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
