using Iced.Intel;
using NetDecompilerMcp.Native.Code;

namespace NetDecompilerMcp.Native.Calls;

/// <summary>
/// Forward slice inside one function: from a defining point, the locations holding the value (registers, stack and frame
/// slots) are followed over the control-flow graph through copies and arithmetic until overwritten; each use is a node:
/// call argument, call target, store to a global or through a pointer, compare, switch index, dereference, return.
/// A fixed point over (block, live locations).
/// </summary>
internal sealed class ForwardSlicer(OursSliceProvider provider, FunctionCode code)
{
    private const int MaxSteps = 20_000;
    private const int MaxPathEntries = 6;
    private readonly CallAnalysis _a = provider.Analysis;
    private readonly InstructionInfoFactory _info = new();
    private readonly List<SliceNode> _nodes = [];
    private readonly List<SliceEdge> _edges = [];
    private readonly Dictionary<(SliceNodeKind, uint, string?), int> _seen = [];
    private int _steps;
    private bool _truncated;
    private string? _note;

    private readonly record struct Live(bool Derived, string Path);

    public FunctionSlice Run(SliceSeed seed, CancellationToken ct)
    {
        var live = new Dictionary<Loc, Live>();
        int block = -1, index = 0;
        string origin = "";
        switch (seed.Kind)
        {
            case SliceSeedKind.Parameter:
            {
                block = code.BlockIndexOf(code.Function.Start);
                if (OursSliceProvider.ParseLocation(seed.Location, _a.Is64) is { } loc)
                {
                    live[loc] = new Live(false, "");
                    origin = $"{provider.LocationName(loc)} at entry";
                }
                break;
            }
            case SliceSeedKind.Result:
            {
                (block, index) = code.Position(seed.Address);
                var loc = OursSliceProvider.ParseLocation(seed.Location ?? "rax", _a.Is64) ?? Loc.Of(Register.RAX);
                if (block >= 0) index++;
                live[loc] = new Live(false, "");
                origin = $"result of the call at {_a.Va(seed.Address)}";
                break;
            }
            case SliceSeedKind.Loaded:
            {
                (block, index) = code.Position(seed.Address);
                if (block >= 0 && code.Blocks[block][index].I is { Op0Kind: OpKind.Register } x)
                {
                    live[Loc.Of(x.Op0Register)] = new Live(false, "");
                    origin = $"{x} @{_a.Va(seed.Address)}";
                    index++;
                }
                break;
            }
            default:
            {
                (block, index) = code.Position(seed.Address);
                if (block >= 0 && OursSliceProvider.ParseLocation(seed.Location, _a.Is64) is { } loc)
                {
                    live[loc] = new Live(false, "");
                    origin = $"{provider.LocationName(loc)} at {_a.Va(seed.Address)}";
                    // a definition of the location: its uses start after it
                    ref readonly var d = ref code.Blocks[block][index];
                    if (Defines(in d, loc)) index++;
                }
                break;
            }
        }
        _nodes.Add(new SliceNode(SliceNodeKind.Origin, seed.Address, origin.Length > 0 ? origin : "?", ""));
        if (block < 0 || live.Count == 0) _note = "the seed is not an instruction or location of the function";
        else Walk(block, index, live, ct);
        return new FunctionSlice(code.Function, OursSliceProvider.EngineName, 0, _nodes, _edges, _steps, _truncated, _note);
    }

    private bool Defines(in Decoded d, Loc loc)
    {
        if (loc.Kind == LocKind.Register) return FunctionCode.Bit(loc.Reg) is var bit and >= 0 && (d.Writes & (1UL << bit)) != 0;
        return SlotOf(in d.I) == loc && _info.GetInfo(in d.I).GetOpAccess(0) is OpAccess.Write or OpAccess.ReadWrite;
    }

    private void Walk(int startBlock, int startIndex, Dictionary<Loc, Live> start, CancellationToken ct)
    {
        var work = new Queue<(int Block, int Index, Dictionary<Loc, Live> Live)>();
        var visited = new HashSet<string>();
        work.Enqueue((startBlock, startIndex, start));
        while (work.Count > 0)
        {
            ct.ThrowIfCancellationRequested();
            var (block, index, live) = work.Dequeue();
            if (!Block(block, index, live)) continue;
            foreach (var e in code.Graph.Blocks[block].Successors)
            {
                if (e.Kind == EdgeKind.TailCall) continue;
                int next = code.BlockIndexOf(e.To);
                if (next < 0) continue;
                var key = next + ":" + string.Join(",", live.OrderBy(l => l.Key.Kind).ThenBy(l => l.Key.Reg).ThenBy(l => l.Key.Slot)
                    .Select(l => $"{(int)l.Key.Kind}.{(int)l.Key.Reg}.{l.Key.Slot}.{(l.Value.Derived ? 1 : 0)}"));
                if (visited.Add(key)) work.Enqueue((next, 0, new Dictionary<Loc, Live>(live)));
            }
        }
    }

    /// <summary>Runs one block from <paramref name="index"/>; false when the path ends (return, tail call, nothing live, budget).</summary>
    private bool Block(int block, int index, Dictionary<Loc, Live> live)
    {
        var insns = code.Blocks[block];
        for (int i = index; i < insns.Length; i++)
        {
            if (live.Count == 0) return false;
            if (++_steps > MaxSteps)
            {
                _truncated = true;
                _note = $"stopped after {MaxSteps} instruction steps";
                return false;
            }
            ref readonly var d = ref insns[i];
            ref readonly var x = ref d.I;
            int site = _a.SiteKindOf(code, in d);
            if (site == 1) { Call(block, i, live); continue; }
            if (site == 2) { Arguments(block, i, live, tail: true); return false; }
            if (x.FlowControl == FlowControl.Return)
            {
                foreach (var (loc, l) in live)
                    if (loc.Kind == LocKind.Register && loc.Reg is Register.RAX or Register.ZMM0)
                        Use(new SliceNode(SliceNodeKind.Return, d.Rva, $"returned in {provider.LocationName(loc)}", l.Path) { Location = provider.LocationName(loc), Derived = l.Derived });
                return false;
            }
            if (x.FlowControl == FlowControl.IndirectBranch) { Branch(in d, live); continue; }
            if (x.FlowControl is FlowControl.Call or FlowControl.IndirectCall) continue; // guard checks
            Instruction(in d, insns, i, live);
        }
        return true;
    }

    private Loc? SlotOf(in Instruction x)
    {
        if (x.Op0Kind != OpKind.Memory && x.Op1Kind != OpKind.Memory && (x.OpCount < 3 || x.Op2Kind != OpKind.Memory)) return null;
        if (x.MemoryIndex != Register.None) return null;
        var b = x.MemoryBase.GetFullRegister();
        int disp = (int)(long)x.MemoryDisplacement64;
        if (b == Register.RSP) return Loc.Stack(disp);
        if (b == Register.RBP && code.HasFramePointer) return Loc.Frame(disp);
        return null;
    }

    private static bool Reads(OpAccess a) => a is OpAccess.Read or OpAccess.ReadWrite or OpAccess.CondRead or OpAccess.ReadCondWrite;
    private static bool Writes(OpAccess a) => a is OpAccess.Write or OpAccess.ReadWrite or OpAccess.CondWrite or OpAccess.ReadCondWrite;

    private static bool IsCopy(Mnemonic m) => m is Mnemonic.Mov or Mnemonic.Movzx or Mnemonic.Movsx or Mnemonic.Movsxd or Mnemonic.Movd or Mnemonic.Movq
        or Mnemonic.Movss or Mnemonic.Movsd or Mnemonic.Movaps or Mnemonic.Movups or Mnemonic.Movapd or Mnemonic.Movupd or Mnemonic.Movdqa
        or Mnemonic.Movdqu or Mnemonic.Vmovss or Mnemonic.Vmovsd or Mnemonic.Xchg or Mnemonic.Push or Mnemonic.Pop;

    private string Step(string path, in Decoded d)
    {
        var entry = $"{d.I} @{_a.Va(d.Rva)}";
        if (path.Length == 0) return entry;
        var parts = path.Split(" -> ");
        return parts.Length >= MaxPathEntries ? "... -> " + string.Join(" -> ", parts.Skip(parts.Length - MaxPathEntries + 2)) + " -> " + entry : path + " -> " + entry;
    }

    private void Instruction(in Decoded d, Decoded[] insns, int i, Dictionary<Loc, Live> live)
    {
        ref readonly var x = ref d.I;
        var info = _info.GetInfo(in x);
        Live? source = null;
        bool zeroing = x.Mnemonic is Mnemonic.Xor or Mnemonic.Sub or Mnemonic.Pxor or Mnemonic.Xorps or Mnemonic.Xorpd
            && x.OpCount == 2 && x.Op0Kind == OpKind.Register && x.Op1Kind == OpKind.Register && x.Op0Register == x.Op1Register;
        // reads of live locations, and pointers formed from them
        for (int k = 0; k < x.OpCount && !zeroing; k++)
        {
            var kind = x.GetOpKind(k);
            var access = info.GetOpAccess(k);
            if (kind == OpKind.Register && Reads(access) && live.TryGetValue(Loc.Of(x.GetOpRegister(k)), out var l)) source ??= l;
            else if (kind == OpKind.Memory)
            {
                if (SlotOf(in x) is { } slot)
                {
                    if (Reads(access) && live.TryGetValue(slot, out var s)) source ??= s;
                }
                else if (x.Mnemonic == Mnemonic.Lea)
                {
                    if (live.TryGetValue(Loc.Of(x.MemoryBase), out var b) || live.TryGetValue(Loc.Of(x.MemoryIndex), out b)) source ??= b with { Derived = true };
                }
                else if (x.MemoryBase != Register.None && live.TryGetValue(Loc.Of(x.MemoryBase), out var b) || x.MemoryIndex != Register.None && live.TryGetValue(Loc.Of(x.MemoryIndex), out b))
                {
                    var text = MemoryText(in x);
                    Use(new SliceNode(Writes(access) ? SliceNodeKind.FieldStore : SliceNodeKind.Dereference, d.Rva,
                        $"{(Writes(access) ? "points to the store" : "points to the load")} {text}", Step(b.Path, in d)) { Derived = b.Derived });
                }
            }
        }
        if (x.Mnemonic == Mnemonic.Push)
        {
            Shift(live, x.StackPointerIncrement);
            if (source is { } p) live[Loc.Stack(0)] = new Live(p.Derived, Step(p.Path, in d));
            return;
        }
        if (x.Mnemonic == Mnemonic.Pop)
        {
            if (x.Op0Kind == OpKind.Register)
            {
                var dest = Loc.Of(x.Op0Register);
                if (live.TryGetValue(Loc.Stack(0), out var top)) live[dest] = new Live(top.Derived, Step(top.Path, in d));
                else live.Remove(dest);
            }
            Shift(live, x.StackPointerIncrement);
            return;
        }
        if (source is { } src && x.Mnemonic is Mnemonic.Cmp or Mnemonic.Test or Mnemonic.Bt or Mnemonic.Ucomiss or Mnemonic.Ucomisd or Mnemonic.Comiss or Mnemonic.Comisd)
        {
            ulong? imm = x.OpCount > 1 && IsImmediate(x.GetOpKind(1)) ? x.GetImmediate(1) : null;
            var branch = i + 1 < insns.Length && insns[i + 1].I.FlowControl == FlowControl.ConditionalBranch ? $"; {insns[i + 1].I.Mnemonic.ToString().ToLowerInvariant()}" : "";
            Use(new SliceNode(SliceNodeKind.Compare, d.Rva, $"{x}{branch}", Step(src.Path, in d)) { Value = imm ?? 0, Derived = src.Derived, Truncated = imm == null });
            return;
        }
        var written = new HashSet<Loc>();
        for (int k = 0; k < x.OpCount; k++)
        {
            var access = info.GetOpAccess(k);
            if (!Writes(access)) continue;
            var kind = x.GetOpKind(k);
            Loc? dest = kind == OpKind.Register ? Loc.Of(x.GetOpRegister(k)) : kind == OpKind.Memory ? SlotOf(in x) : null;
            if (source is { } s && !zeroing)
            {
                var next = new Live(s.Derived || !IsCopy(x.Mnemonic), Step(s.Path, in d));
                if (dest is { } dl) { live[dl] = next; written.Add(dl); }
                else if (kind == OpKind.Memory && d.HasMem && _a.ImportAtSlot(d.MemRva) == null && IsWritable(d.MemRva))
                    Use(new SliceNode(SliceNodeKind.Store, d.Rva, $"stored to [{_a.Index.NameAt(d.MemRva) ?? _a.Va(d.MemRva)}]", next.Path) { Rva = d.MemRva, Derived = next.Derived });
                else if (kind == OpKind.Memory && !d.HasMem && x.MemoryBase.GetFullRegister() is not (Register.RSP or Register.RBP))
                    Use(new SliceNode(SliceNodeKind.FieldStore, d.Rva, $"stored to {MemoryText(in x)}", next.Path) { Derived = next.Derived });
            }
            else if (dest is { } dl) live.Remove(dl);
        }
        // implicit register writes (cdq, mul, rep movs) end the value there
        foreach (var loc in live.Keys.Where(l => l.Kind == LocKind.Register && !written.Contains(l)).ToList())
            if (FunctionCode.Bit(loc.Reg) is var bit and >= 0 && (d.Writes & (1UL << bit)) != 0) live.Remove(loc);
        if ((d.Writes & (1UL << FunctionCode.Bit(Register.RSP))) != 0)
        {
            if (x.Mnemonic is Mnemonic.Sub or Mnemonic.Add && x.Op0Kind == OpKind.Register && x.Op0Register.GetFullRegister() == Register.RSP && IsImmediate(x.Op1Kind))
            {
                long imm = (long)x.GetImmediate(1);
                Shift(live, (int)(x.Mnemonic == Mnemonic.Sub ? -imm : imm));
            }
            else if (x.StackPointerIncrement != 0) Shift(live, x.StackPointerIncrement);
            else foreach (var loc in live.Keys.Where(l => l.Kind == LocKind.Stack).ToList()) live.Remove(loc);
        }
        if ((d.Writes & (1UL << FunctionCode.Bit(Register.RBP))) != 0 && !written.Contains(Loc.Of(Register.RBP)))
            foreach (var loc in live.Keys.Where(l => l.Kind == LocKind.Frame).ToList()) live.Remove(loc);
    }

    private bool IsWritable(uint rva) => _a.Image.SectionAt(rva) is { } s && (s.Access & SectionAccess.Write) != 0;

    private static bool IsImmediate(OpKind k) => k is OpKind.Immediate8 or OpKind.Immediate8to16 or OpKind.Immediate8to32 or OpKind.Immediate8to64
        or OpKind.Immediate16 or OpKind.Immediate32 or OpKind.Immediate32to64 or OpKind.Immediate64;

    private static string MemoryText(in Instruction x)
    {
        var s = x.ToString();
        int open = s.IndexOf('['), close = s.IndexOf(']');
        return open >= 0 && close > open ? s[open..(close + 1)] : "memory";
    }

    /// <summary>The stack pointer moved by <paramref name="delta"/> (negative: pushed): stack slots are relative to it.</summary>
    private static void Shift(Dictionary<Loc, Live> live, int delta)
    {
        var moved = live.Where(l => l.Key.Kind == LocKind.Stack).ToList();
        foreach (var (loc, _) in moved) live.Remove(loc);
        foreach (var (loc, l) in moved)
            if (loc.Slot - delta >= 0) live[Loc.Stack(loc.Slot - delta)] = l;
    }

    private void Branch(in Decoded d, Dictionary<Loc, Live> live)
    {
        ref readonly var x = ref d.I;
        Live? used = null;
        if (x.Op0Kind == OpKind.Register && live.TryGetValue(Loc.Of(x.Op0Register), out var r)) used = r;
        else if (x.Op0Kind == OpKind.Memory && (live.TryGetValue(Loc.Of(x.MemoryIndex), out var m) || live.TryGetValue(Loc.Of(x.MemoryBase), out m))) used = m;
        if (used is not { } u) return;
        uint rva = d.Rva;
        var table = code.Graph.Switches.FirstOrDefault(s => s.JumpRva == rva);
        Use(new SliceNode(SliceNodeKind.Switch, d.Rva, table != null ? $"indexes the switch at {_a.Va(d.Rva)} ({table.Targets.Count} targets)" : $"selects the target of {x}",
            Step(u.Path, in d)) { Derived = u.Derived, Value = (ulong)(table?.Targets.Count ?? 0) });
    }

    private void Call(int block, int i, Dictionary<Loc, Live> live)
    {
        ref readonly var d = ref code.Blocks[block][i];
        ref readonly var x = ref d.I;
        if (x.Op0Kind == OpKind.Register && live.TryGetValue(Loc.Of(x.Op0Register), out var t)
            || x.Op0Kind == OpKind.Memory && !d.HasMem && (live.TryGetValue(Loc.Of(x.MemoryBase), out t) || live.TryGetValue(Loc.Of(x.MemoryIndex), out t)))
            Use(new SliceNode(SliceNodeKind.CallTarget, d.Rva, x.Op0Kind == OpKind.Register ? "called" : $"called through {MemoryText(in x)}", Step(t.Path, in d))
                { Site = d.Rva, Derived = t.Derived });
        Arguments(block, i, live, tail: false);
        foreach (var loc in live.Keys.Where(l => l.Kind == LocKind.Register && provider.IsVolatile(l.Reg)).ToList()) live.Remove(loc);
        if (!_a.Is64 && live.Keys.Any(l => l.Kind == LocKind.Stack))
        {
            if (_a.CalleePops(code, block, i) is { } pops) Shift(live, pops);
            else foreach (var loc in live.Keys.Where(l => l.Kind == LocKind.Stack).ToList()) live.Remove(loc);
        }
    }

    private void Arguments(int block, int i, Dictionary<Loc, Live> live, bool tail)
    {
        CallAnalysis.Callee? callee = null;
        ApiSignature? sig = null;
        ref readonly var d = ref code.Blocks[block][i];
        foreach (var (loc, l) in live.OrderBy(l => l.Key.Kind).ThenBy(l => l.Key.Reg).ThenBy(l => l.Key.Slot).ToList())
        {
            if (provider.CallToEntry(loc, tail) is not { } entry) continue;
            if (callee == null)
            {
                callee = _a.CalleeAt(code, block, i);
                sig = CallAnalysis.SignatureOf(callee.Value);
            }
            var c = callee.Value;
            int index = provider.ParameterIndex(entry);
            if (sig != null && !sig.Variadic && index >= sig.Params.Count) continue;
            uint? target = c.Kind is CalleeKind.Function or CalleeKind.VirtualExact ? c.Target : null;
            var name = sig != null && index >= 0 && index < sig.Params.Count ? $" {sig.Params[index].Name}" : "";
            Use(new SliceNode(SliceNodeKind.Argument, d.Rva, $"argument {(index >= 0 ? (index + 1).ToString() : provider.LocationName(entry))}{name} of {c.Name}",
                Step(l.Path, in d)) { Site = d.Rva, Location = provider.LocationName(entry), Index = index, Callee = c.Name, CallKind = c.Kind, Target = target, Derived = l.Derived,
                    Rva = c.Import?.SlotRva ?? 0 });
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
