using System.Runtime.CompilerServices;
using Iced.Intel;
using NetDecompilerMcp.Native.Code;

namespace NetDecompilerMcp.Native.Calls;

/// <param name="Basis">direct_branch, import_slot, thunk_import, constant_pointer, getprocaddress, rtti_vftable_exact, rtti_vftable_possible,
/// global_writers, initial_contents, pointer_table, caller_argument, ida_xref, hexrays_direct, interface_dispatch_cell (NativeAOT).</param>
/// <param name="Confidence">exact, possible or candidate (from an incomplete set, or another engine's view only).</param>
public sealed record CallTarget(uint Address, string Name, string Basis, string Confidence, string Evidence);

/// <param name="Mechanism">direct, import_slot, thunk, register, memory_pointer, vftable_slot, cfg_dispatch, tail_jump, pointer_table, interface_dispatch.</param>
/// <param name="Status">direct, import, resolved (the complete target set), possible (several, or not proven complete), virtual_exact,
/// virtual_possible, ambiguous (engines disagree) or unresolved.</param>
/// <param name="Hint">For unresolved sites: the call that traces the target's value.</param>
public sealed record CallTargetSite(uint Rva, NativeFunction Function, string Text, string Mechanism, string Status, IReadOnlyList<CallTarget> Targets,
    int TargetCount, string? Reason, string? Hint)
{
    public bool IsIndirect => Mechanism is not ("direct" or "tail_jump" or "thunk");
}

/// <summary>
/// Targets of call and tail-jump sites in layers: the direct branch, import slots and thunks, constant pointers through the
/// CFG dispatch, GetProcAddress pointers, RTTI virtual calls; then the writers of a global function pointer (and its initial
/// contents), relocated pointer tables (complete when an index bound is found), and with deep the values callers pass for
/// a pointer that arrives as a parameter (<see cref="ValueTrace"/>). Several targets are listed, never collapsed into one.
/// </summary>
public static class CallTargets
{
    public const int MaxTargets = 64;
    private const int MaxWriters = 32;
    private static readonly ConditionalWeakTable<CallAnalysis, Dictionary<(bool, int), List<CallTargetSite>>> ImageCache = new();

    /// <summary>The call or tail jump at <paramref name="rva"/>, or null when it is not one.</summary>
    public static CallTargetSite? At(CallAnalysis a, uint rva, bool deep, CancellationToken ct = default)
    {
        if (a.Index.FunctionAt(rva) is not { } f) return null;
        var code = a.Code(f, ct);
        var (b, i) = code.Position(rva);
        if (b < 0 || a.SiteKindOf(code, in code.Blocks[b][i]) == 0) return null;
        return Resolve(a, code, b, i, deep, ct);
    }

    /// <summary>Every call and tail-jump site of <paramref name="f"/>, in address order.</summary>
    public static List<CallTargetSite> In(CallAnalysis a, NativeFunction f, bool deep, CancellationToken ct = default)
    {
        var code = a.Code(f, ct);
        var result = new Dictionary<uint, CallTargetSite>();
        for (int b = 0; b < code.Blocks.Length; b++)
            for (int i = 0; i < code.Blocks[b].Length; i++)
            {
                ref readonly var d = ref code.Blocks[b][i];
                if (result.ContainsKey(d.Rva) || a.SiteKindOf(code, in d) == 0) continue;
                ct.ThrowIfCancellationRequested();
                result[d.Rva] = Resolve(a, code, b, i, deep, ct);
            }
        return result.Values.OrderBy(s => s.Rva).ToList();
    }

    /// <summary>The image's indirect sites when <see cref="Image"/> has computed them for the current names, else null (never computes).</summary>
    public static List<CallTargetSite>? ImageIfComputed(CallAnalysis a, bool deep)
    {
        if (!ImageCache.TryGetValue(a, out var cache)) return null;
        lock (cache) return cache.GetValueOrDefault((deep, a.Index.Sourced.Version));
    }

    /// <summary>The indirect sites of the whole image (computed once per image, deep and names version).</summary>
    public static List<CallTargetSite> Image(CallAnalysis a, bool deep, CancellationToken ct = default)
    {
        var cache = ImageCache.GetValue(a, _ => []);
        var key = (deep, a.Index.Sourced.Version);
        lock (cache) if (cache.TryGetValue(key, out var hit)) return hit;
        var list = new List<CallTargetSite>();
        foreach (var f in a.Index.Functions)
        {
            ct.ThrowIfCancellationRequested();
            if ((f.Flags & FunctionFlags.Thunk) != 0) continue;
            list.AddRange(In(a, f, deep, ct).Where(s => s.IsIndirect));
        }
        lock (cache)
        {
            cache.Clear();
            cache[key] = list;
        }
        return list;
    }

    private static CallTargetSite Resolve(CallAnalysis a, FunctionCode code, int b, int i, bool deep, CancellationToken ct)
    {
        var index = a.Index;
        ref readonly var d = ref code.Blocks[b][i];
        var x = d.I;
        uint rva = d.Rva;
        bool tail = a.SiteKindOf(code, in d) == 2;
        var c = a.CalleeAt(code, b, i);
        string Name(uint t) => index.NameAt(t) ?? $"sub_{t:X}";
        CallTargetSite Site(string mechanism, string status, List<CallTarget> targets, string? reason = null, string? hint = null)
        {
            var distinct = targets.DistinctBy(t => (t.Address, t.Name)).ToList();
            return new CallTargetSite(rva, code.Function, x.ToString(), mechanism, status, distinct.Take(MaxTargets).ToList(), distinct.Count, reason, hint);
        }

        string mechanism;
        bool isBranch = x.Op0Kind is OpKind.NearBranch16 or OpKind.NearBranch32 or OpKind.NearBranch64;
        if (index.VirtualCalls.SiteAt(rva) is not null) mechanism = "vftable_slot";
        else if (isBranch && FunctionCode.TryRva(a.Image, a.Is64, x.NearBranchTarget, out uint bt) && a.IsDispatchThunk(bt)) mechanism = "cfg_dispatch";
        else if (isBranch) mechanism = c.Kind == CalleeKind.Import ? "thunk" : tail ? "tail_jump" : "direct";
        else if (x.Op0Kind == OpKind.Memory && d.HasMem) mechanism = a.ImportAtSlot(d.MemRva) != null ? "import_slot" : c.Why == "through the CFG dispatch" ? "cfg_dispatch" : "memory_pointer";
        else if (x.Op0Kind == OpKind.Memory) mechanism = x.MemoryIndex != Register.None ? "pointer_table" : "memory_pointer";
        else mechanism = "register";

        switch (c.Kind)
        {
            case CalleeKind.Import:
                return Site(mechanism, "import", [new CallTarget(c.Import!.SlotRva, c.Name, mechanism == "thunk" ? "thunk_import" : "import_slot", "exact",
                    mechanism == "register" ? "register loaded from the import slot" : $"import slot {a.Va(c.Import.SlotRva)}")]);
            case CalleeKind.Function:
                return isBranch && mechanism != "cfg_dispatch"
                    ? Site(mechanism, "direct", [new CallTarget(c.Target!.Value, c.Name, "direct_branch", "exact", "branch target")])
                    : Site(mechanism, "resolved", [new CallTarget(c.Target!.Value, c.Name, "constant_pointer", "exact", "constant pointer")]);
            case CalleeKind.Dynamic:
                return Site(mechanism, "resolved", [new CallTarget(c.Dynamic!.PointerGlobal ?? c.Dynamic.CallSite, c.Name, "getprocaddress", "exact",
                    $"GetProcAddress at {a.Va(c.Dynamic.CallSite)}; {c.Dynamic.How}")]);
            case CalleeKind.VirtualExact or CalleeKind.VirtualPossible:
            {
                bool exact = c.Kind == CalleeKind.VirtualExact;
                var targets = index.VirtualTargets(rva).Select(t => new CallTarget(t, Name(t), exact ? "rtti_vftable_exact" : "rtti_vftable_possible",
                    exact ? "exact" : "possible", c.Why ?? "RTTI")).ToList();
                return Site(mechanism, exact ? "virtual_exact" : "virtual_possible", targets);
            }
        }

        if (InterfaceDispatch(a, code, b, i) is { } dispatch) return Site("interface_dispatch", "virtual_possible", dispatch);

        // indirect: a global function pointer, a pointer table, a parameter
        uint? global = c.Target ?? (x.Op0Kind == OpKind.Memory && d.HasMem ? d.MemRva : null);
        if (global is { } g && a.ImportAtSlot(g) == null && a.Image.SectionAt(g) is { } sec && (sec.Access & SectionAccess.Write) != 0)
            return GlobalWriters(a, g, mechanism, Site);
        if (mechanism == "pointer_table" && PointerTable(a, code, b, i) is { } table)
            return Site(mechanism, table.Bounded ? "resolved" : "possible", table.Targets);
        var hintLocation = x.Op0Kind == OpKind.Register ? a.Slices.LocationName(Loc.Of(x.Op0Register))
            : x.Op0Kind == OpKind.Memory && x.MemoryBase != Register.None && x.MemoryBase != Register.RIP ? a.Slices.LocationName(Loc.Of(x.MemoryBase)) : null;
        var hint = hintLocation != null ? $"trace_native_values address={a.Va(rva)} location={hintLocation}" : null;
        if (deep && hintLocation != null && x.Op0Kind == OpKind.Register)
        {
            var graph = ValueTrace.Build(a, new TraceSeed(TraceSeedKind.Location, rva, code.Function, hintLocation, $"call target {hintLocation} at {a.Va(rva)}"),
                new ValueTraceOptions(MaxDepth: 2, MaxCallers: 16, MaxNodes: 400), ct: ct);
            var found = graph.Values.Where(v => v.Kind is TraceNodeKind.Function or TraceNodeKind.Import && v.Rva is not null)
                .Select(v => new CallTarget(v.Rva!.Value, v.Text, "caller_argument", "possible", $"value trace node #{v.Node}")).ToList();
            bool complete = graph.Frontier.Count == 0 && graph.Values.Count == found.Count && !graph.Nodes.Any(n => n.Backward && n.Kind == TraceNodeKind.Unknown);
            if (found.Count > 0)
                return Site(mechanism, complete && found.Count == 1 ? "resolved" : "possible",
                    complete && found.Count == 1 ? [found[0] with { Confidence = "exact" }] : found,
                    complete ? null : "other values may reach it (unknown paths or budgets)", complete ? null : hint);
        }
        return Site(mechanism, "unresolved", [], c.Why ?? "target not known", hint);
    }

    /// <summary>
    /// A NativeAOT interface call through its dispatch cell ("call [cell]", or "lea r11, [cell]; call [r11]"): the types
    /// whose dispatch maps implement the cell's interface slot; null for other calls.
    /// </summary>
    private static List<CallTarget>? InterfaceDispatch(CallAnalysis a, FunctionCode code, int b, int i)
    {
        ref readonly var d = ref code.Blocks[b][i];
        var x = d.I;
        if (x.Op0Kind != OpKind.Memory || NativeAot.NativeAotImage.For(a.Image) is not { } aot) return null;
        uint? at = d.HasMem ? d.MemRva
            : x.MemoryBase != Register.None && x.MemoryIndex == Register.None && x.MemoryDisplacement64 == 0
              && new ValueResolver(a, code) { Budget = 200 }.ValueBefore(Loc.Of(x.MemoryBase), b, i) is { Kind: VKind.Addr } v ? v.Rva : null;
        if (at is not { } rva || aot.Dispatch.CellAt(rva) is not { } cell) return null;
        string evidence = $"{cell.Target} through the interface dispatch cell at {a.Va(rva)}";
        return [.. aot.Dispatch.Implementers(cell.Interface, cell.Slot).Select(m =>
            new CallTarget(m.Code, a.Index.NameAt(m.Code) ?? $"sub_{m.Code:X}", "interface_dispatch_cell", "possible", $"{m.TypeName}: {evidence}"))];
    }

    private static CallTargetSite GlobalWriters(CallAnalysis a, uint g, string mechanism,
        Func<string, string, List<CallTarget>, string?, string?, CallTargetSite> site)
    {
        var index = a.Index;
        var targets = new List<CallTarget>();
        var unknown = new List<string>();
        string Where(uint r) => index.FunctionAt(r) is { } f ? $"{f.Name}+0x{r - f.Start:X}" : a.Va(r);
        var writers = index.RefsTo(g).Where(x => x.Kind == XrefKind.Write).DistinctBy(x => x.From).ToList();
        int ptr = a.Is64 ? 8 : 4;
        Span<byte> buffer = stackalloc byte[8];
        buffer.Clear();
        if (a.IsRelocated(g) && a.Image.Read(g, buffer[..ptr]) == ptr
            && FunctionCode.TryRva(a.Image, a.Is64, BitConverter.ToUInt64(buffer), out uint init) && index.FunctionByStart(init) != null)
            targets.Add(new CallTarget(init, index.NameAt(init) ?? $"sub_{init:X}", "initial_contents", "exact", $"relocated pointer at {a.Va(g)} in the image"));
        foreach (var w in writers.Take(MaxWriters))
        {
            if (index.FunctionAt(w.From) is not { } f) { unknown.Add(a.Va(w.From)); continue; }
            var code = a.Code(f, default);
            var (b, i) = code.Position(w.From);
            if (b < 0) { unknown.Add(Where(w.From)); continue; }
            var v = new ValueResolver(a, code) { Budget = 3000 }.ValueStoredBy(b, i);
            if (v.Kind == VKind.Addr && index.FunctionByStart(v.Rva) != null)
                targets.Add(new CallTarget(v.Rva, index.NameAt(v.Rva) ?? $"sub_{v.Rva:X}", "global_writers", "exact", $"stored at {Where(w.From)}"));
            else if (v.Kind == VKind.Load && a.ImportAtSlot(v.Rva) is { } imp)
                targets.Add(new CallTarget(v.Rva, NativeCodeIndex.ImportName(imp), "global_writers", "exact", $"stored at {Where(w.From)}"));
            else if (!(v.Kind == VKind.Const && v.Num == 0)) unknown.Add(Where(w.From));
        }
        var name = $"global {index.NameAt(g) ?? a.Va(g)}";
        var hint = $"trace_native_values address={a.Va(g)}";
        if (writers.Count > MaxWriters) unknown.Add($"{writers.Count - MaxWriters} writers not examined");
        if (unknown.Count > 0)
            return site(mechanism, "unresolved", targets.Select(t => t with { Confidence = "candidate" }).ToList(),
                $"{name} written by {writers.Count} stores, {unknown.Count} unknown at {string.Join(", ", unknown.Take(4))}", hint);
        if (targets.Count == 0)
            return site(mechanism, "unresolved", targets, $"{name} holds no function address written by code or in the image", hint);
        int distinct = targets.Select(t => t.Address).Distinct().Count();
        return site(mechanism, distinct == 1 ? "resolved" : "possible", distinct == 1 ? targets : targets.Select(t => t with { Confidence = "possible" }).ToList(), null, null);
    }

    /// <summary>call [table + index*ptr]: consecutive relocated entries that are function starts; bounded by a cmp / ja on the index.</summary>
    private static (List<CallTarget> Targets, bool Bounded)? PointerTable(CallAnalysis a, FunctionCode code, int b, int i)
    {
        var x = code.Blocks[b][i].I;
        int ptr = a.Is64 ? 8 : 4;
        if (x.MemoryIndexScale != ptr) return null;
        uint table;
        if (x.MemoryBase == Register.None)
        {
            if (!FunctionCode.TryRva(a.Image, a.Is64, x.MemoryDisplacement64, out table)) return null;
        }
        else
        {
            var v = new ValueResolver(a, code) { Budget = 2000 }.ValueBefore(Loc.Of(x.MemoryBase), b, i);
            if (v.Kind != VKind.Addr) return null;
            table = (uint)(v.Rva + (long)x.MemoryDisplacement64);
        }
        var index = a.Index;
        var targets = new List<CallTarget>();
        Span<byte> buffer = stackalloc byte[8];
        for (int k = 0; k < MaxTargets; k++)
        {
            uint at = (uint)(table + k * ptr);
            buffer.Clear();
            if (!a.IsRelocated(at) || a.Image.Read(at, buffer[..ptr]) != ptr || !FunctionCode.TryRva(a.Image, a.Is64, BitConverter.ToUInt64(buffer), out uint t)
                || index.FunctionByStart(t) == null) break;
            targets.Add(new CallTarget(t, index.NameAt(t) ?? $"sub_{t:X}", "pointer_table", "possible", $"entry {k} of the table at {a.Va(table)}"));
        }
        if (targets.Count == 0) return null;
        // a bound: cmp idx, n; ja/jae earlier in the block
        var idx = x.MemoryIndex.GetFullRegister();
        var insns = code.Blocks[b];
        for (int j = i - 1; j >= 0; j--)
        {
            var y = insns[j].I;
            if (y.Mnemonic == Mnemonic.Cmp && y.Op0Kind == OpKind.Register && y.Op0Register.GetFullRegister() == idx && y.Op1Kind is not (OpKind.Register or OpKind.Memory))
            {
                int n = (int)Math.Min(y.GetImmediate(1) + 1, MaxTargets);
                if (n <= targets.Count) return (targets.Take(n).Select(t => t with { Confidence = "exact" }).ToList(), true);
                break;
            }
            if (FunctionCode.Bit(idx) is var bit and >= 0 && (insns[j].Writes & (1UL << bit)) != 0) break;
        }
        // the bound check usually ends the previous block: cmp idx, n; ja default
        var block = code.Graph.Blocks[b];
        if (block.Predecessors.Count == 1 && code.BlockIndexOf(block.Predecessors[0].From) is var p and >= 0 && code.Blocks[p] is { Length: >= 2 } prev
            && prev[^1].I.Mnemonic is Mnemonic.Ja or Mnemonic.Jae && prev[^2].I is { Mnemonic: Mnemonic.Cmp, Op0Kind: OpKind.Register } cmp
            && cmp.Op0Register.GetFullRegister() == idx && cmp.Op1Kind is not (OpKind.Register or OpKind.Memory))
        {
            int n = (int)Math.Min(cmp.GetImmediate(1) + (prev[^1].I.Mnemonic == Mnemonic.Ja ? 1UL : 0UL), MaxTargets);
            if (n <= targets.Count) return (targets.Take(n).Select(t => t with { Confidence = "exact" }).ToList(), true);
        }
        return (targets, false);
    }
}
