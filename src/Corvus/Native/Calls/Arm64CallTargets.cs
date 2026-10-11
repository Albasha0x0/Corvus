using System.Runtime.CompilerServices;
using AsmArm64;
using Corvus.Native.Code;

namespace Corvus.Native.Calls;

/// <summary>
/// Targets of ARM64 call and tail-jump sites: bl / b to functions and PLT or stub thunks, blr / br through registers loaded
/// from GOT and import slots, constant function addresses (adr, adrp + add, literal pools, relocated pointers in read-only
/// data), writable function pointer globals (their writers and initial contents), relocated pointer tables indexed by a
/// bounded register, and with deep the function pointers callers pass in. Loads from an object's field (vtable-style
/// dispatch) stay unresolved with the trace to follow.
/// </summary>
internal static class Arm64CallTargets
{
    private const int MaxWriters = 32;
    private static readonly ConditionalWeakTable<Arm64Trace, Dictionary<(bool, int), List<CallTargetSite>>> ImageCache = new();

    public static CallTargetSite? At(Arm64Trace a, uint rva, bool deep, CancellationToken ct = default)
    {
        if (a.Index.FunctionAt(rva) is not { } f) return null;
        var code = a.Code(f, ct);
        var (b, i) = code.Position(rva);
        if (b < 0 || !IsSite(code, code.Blocks[b][i]) || a.IsGuardCheck(code, b, i)) return null;
        return Resolve(a, code, b, i, deep, ct);
    }

    public static List<CallTargetSite> In(Arm64Trace a, NativeFunction f, bool deep, CancellationToken ct = default)
    {
        var code = a.Code(f, ct);
        var result = new List<CallTargetSite>();
        for (int b = 0; b < code.Blocks.Length; b++)
            for (int i = 0; i < code.Blocks[b].Length; i++)
            {
                if (!IsSite(code, code.Blocks[b][i]) || a.IsGuardCheck(code, b, i)) continue;
                ct.ThrowIfCancellationRequested();
                result.Add(Resolve(a, code, b, i, deep, ct));
            }
        return result.DistinctBy(s => s.Rva).OrderBy(s => s.Rva).ToList();
    }

    public static List<CallTargetSite> Image(Arm64Trace a, bool deep, CancellationToken ct = default)
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

    /// <summary>Calls, tail calls to function starts, and indirect jumps that are no switch dispatch.</summary>
    private static bool IsSite(A64Function code, A64Step s) => s.Facts.Flow switch
    {
        FlowKind.Call or FlowKind.IndirectCall => true,
        FlowKind.Jump => s.Facts.HasTarget && code.Graph.TailCalls.Contains(s.Facts.Target),
        FlowKind.IndirectJump => !code.Graph.Switches.Any(t => t.JumpRva == s.Rva),
        _ => false,
    };

    private static CallTargetSite Resolve(Arm64Trace a, A64Function code, int b, int i, bool deep, CancellationToken ct)
    {
        var index = a.Index;
        var s = code.Blocks[b][i];
        string text = index.Disassemble(s.Rva, 1) is [var line] ? line.Text : s.Text;
        string Name(uint t) => index.NameAt(t) ?? $"sub_{t:X}";
        CallTargetSite Site(string mechanism, string status, List<CallTarget> targets, string? reason = null, string? hint = null)
        {
            var distinct = targets.DistinctBy(t => (t.Address, t.Name)).ToList();
            return new CallTargetSite(s.Rva, code.Function, text, mechanism, status, distinct.Take(CallTargets.MaxTargets).ToList(), distinct.Count, reason, hint);
        }
        bool tail = s.Facts.Flow is FlowKind.Jump or FlowKind.IndirectJump;

        if (s.Facts.HasTarget)
        {
            uint t = s.Facts.Target;
            if (index.FunctionByStart(t) is { ThunkImport: { } imp })
                return Site("thunk", "import", [new CallTarget(imp.SlotRva, NativeCodeIndex.ImportName(imp), "thunk_import", "exact", $"stub at {a.Va(t)} through slot {a.Va(imp.SlotRva)}")]);
            return Site(tail ? "tail_jump" : "direct", "direct", [new CallTarget(t, Name(t), "direct_branch", "exact", "branch target")]);
        }
        if (s.Facts.HasMem && a.ImportAt(s.Facts.MemTarget) is { } slot)
            return Site("import_slot", "import", [new CallTarget(slot.SlotRva, NativeCodeIndex.ImportName(slot), "import_slot", "exact", "register loaded from the import slot")]);

        int reg = A64Function.Gpr(s.I, 0);
        if (reg is < 0 or >= 31) return Site("register", "unresolved", [], "the target register is not a general-purpose register");
        var resolver = new Arm64Resolver(a, code) { Budget = 3000 };
        var v = resolver.Before(A64Loc.Reg(reg), b, i);
        string hint = $"trace_native_values address={a.Va(s.Rva)} location=x{reg}";
        var dynamic = v.Kind switch
        {
            A64Kind.Result => a.Calls.DynamicImports(ct).BySite.GetValueOrDefault(v.Rva),
            A64Kind.Global => a.Calls.DynamicImports(ct).ByGlobal.GetValueOrDefault(v.Rva),
            _ => null,
        };
        if (dynamic != null)
            return Site("register", "resolved", [new CallTarget(dynamic.PointerGlobal ?? dynamic.CallSite, dynamic.FullName, "getprocaddress", "exact",
                $"resolved by name at {a.Va(dynamic.CallSite)}; {dynamic.How}")]);
        switch (v.Kind)
        {
            case A64Kind.Addr when index.FunctionByStart(v.Rva) != null:
                return Site("register", "resolved", [new CallTarget(v.Rva, Name(v.Rva), "constant_pointer", "exact", v.Why)]);
            case A64Kind.Import:
            {
                var imp = a.ImportAt(v.Rva)!;
                return Site("import_slot", "import", [new CallTarget(imp.SlotRva, NativeCodeIndex.ImportName(imp), "import_slot", "exact", v.Why)]);
            }
            case A64Kind.Global:
                return GlobalWriters(a, v.Rva, Site);
            case A64Kind.Unknown when v.Why.StartsWith("loaded through an indexed address", StringComparison.Ordinal) && PointerTable(a, code, resolver, b, i, reg) is { } table:
                return Site("pointer_table", table.Bounded ? "resolved" : "possible", table.Targets);
            case A64Kind.Field:
                return Site("memory_pointer", "unresolved", [],
                    $"loaded from field +0x{v.Num:X} of {Describe(v.Inputs![0])} (a virtual call, callback or function-pointer member)", hint);
        }
        if (deep && v.Kind is A64Kind.Incoming or A64Kind.Merge or A64Kind.Result)
        {
            var graph = ValueTrace.Build(a, new TraceSeed(TraceSeedKind.Location, s.Rva, code.Function, $"x{reg}", $"call target x{reg} at {a.Va(s.Rva)}"),
                new ValueTraceOptions(MaxDepth: 2, MaxCallers: 16, MaxNodes: 400), ct: ct);
            var found = graph.Values.Where(x => x.Kind is TraceNodeKind.Function or TraceNodeKind.Import && x.Rva is not null)
                .Select(x => new CallTarget(x.Rva!.Value, x.Text, "caller_argument", "possible", $"value trace node #{x.Node}")).ToList();
            bool complete = graph.Frontier.Count == 0 && graph.Values.Count == found.Count && !graph.Nodes.Any(n => n.Backward && n.Kind == TraceNodeKind.Unknown);
            if (found.Count > 0)
                return Site("register", complete && found.Count == 1 ? "resolved" : "possible",
                    complete && found.Count == 1 ? [found[0] with { Confidence = "exact" }] : found,
                    complete ? null : "other values may reach it (unknown paths or budgets)", complete ? null : hint);
        }
        return Site("register", "unresolved", [], v.Kind switch
        {
            A64Kind.Incoming => $"the target arrives in {A64Function.Name(v.Loc, null)}" + (A64Function.ParameterIndex(v.Loc) is var p and >= 0 ? $" (parameter {p + 1})" : ""),
            A64Kind.Result => "the target is a call result",
            A64Kind.Merge => "several values reach it",
            A64Kind.Const => $"the target is the constant 0x{v.Num:X}",
            A64Kind.Addr => $"the target {a.Va(v.Rva)} is no function start",
            _ => v.Why.Length > 0 ? v.Why : "target not known",
        }, hint);
    }

    private static string Describe(A64Val v) => v.Kind switch
    {
        A64Kind.Incoming => $"incoming {A64Function.Name(v.Loc, null)}",
        A64Kind.Result => "a call result",
        A64Kind.Field => $"a field +0x{v.Num:X}",
        A64Kind.Global => "a global",
        _ => "an unknown object",
    };

    private static CallTargetSite GlobalWriters(Arm64Trace a, uint g, Func<string, string, List<CallTarget>, string?, string?, CallTargetSite> site)
    {
        var index = a.Index;
        var targets = new List<CallTarget>();
        var unknown = new List<string>();
        string Where(uint r) => index.FunctionAt(r) is { } f ? $"{f.Name}+0x{r - f.Start:X}" : a.Va(r);
        var writers = index.RefsTo(g).Where(x => x.Kind == XrefKind.Write).DistinctBy(x => x.From).ToList();
        Span<byte> buffer = stackalloc byte[8];
        if (a.IsRelocated(g) && index.Image.Read(g, buffer) == 8 && BitConverter.ToUInt64(buffer) is var p
            && p >= index.Image.ImageBase && p - index.Image.ImageBase < index.Image.SizeOfImage && index.FunctionByStart((uint)(p - index.Image.ImageBase)) is { } init)
            targets.Add(new CallTarget(init.Start, init.Name, "initial_contents", "exact", $"relocated pointer at {a.Va(g)} in the image"));
        foreach (var w in writers.Take(MaxWriters))
        {
            if (index.FunctionAt(w.From) is not { } f) { unknown.Add(a.Va(w.From)); continue; }
            var code = a.Code(f, default);
            var (b, i) = code.Position(w.From);
            if (b < 0) { unknown.Add(Where(w.From)); continue; }
            var v = new Arm64Resolver(a, code) { Budget = 3000 }.Stored(b, i, g);
            if (v.Kind == A64Kind.Addr && index.FunctionByStart(v.Rva) != null)
                targets.Add(new CallTarget(v.Rva, index.NameAt(v.Rva) ?? $"sub_{v.Rva:X}", "global_writers", "exact", $"stored at {Where(w.From)}"));
            else if (v.Kind == A64Kind.Import && a.ImportAt(v.Rva) is { } imp)
                targets.Add(new CallTarget(v.Rva, NativeCodeIndex.ImportName(imp), "global_writers", "exact", $"stored at {Where(w.From)}"));
            else if (!(v.Kind == A64Kind.Const && v.Num == 0)) unknown.Add(Where(w.From));
        }
        var name = $"global {index.NameAt(g) ?? a.Va(g)}";
        var hint = $"trace_native_values address={a.Va(g)}";
        if (writers.Count > MaxWriters) unknown.Add($"{writers.Count - MaxWriters} writers not examined");
        if (unknown.Count > 0)
            return site("memory_pointer", "unresolved", targets.Select(t => t with { Confidence = "candidate" }).ToList(),
                $"{name} written by {writers.Count} stores, {unknown.Count} unknown at {string.Join(", ", unknown.Take(4))}", hint);
        if (targets.Count == 0)
            return site("memory_pointer", "unresolved", targets, $"{name} holds no function address written by code or in the image", hint);
        int distinct = targets.Select(t => t.Address).Distinct().Count();
        return site("memory_pointer", distinct == 1 ? "resolved" : "possible", distinct == 1 ? targets : targets.Select(t => t with { Confidence = "possible" }).ToList(), null, null);
    }

    /// <summary>
    /// ldr xT, [xTab, xIdx, lsl #3] then blr xT with xTab a known address: consecutive relocated entries that are function
    /// starts, bounded by a cmp of the index and a b.hi / b.hs before it.
    /// </summary>
    private static (List<CallTarget> Targets, bool Bounded)? PointerTable(Arm64Trace a, A64Function code, Arm64Resolver resolver, int b, int i, int reg)
    {
        var steps = code.Blocks[b];
        int k = i - 1;
        for (; k >= 0; k--)
            if (A64Function.Dest(steps[k].I) is { Kind: Arm64RegisterKind.X or Arm64RegisterKind.W } d && d.Index == reg) break;
        if (k < 0 || A64Function.Memory(steps[k]) is not { } m || !m.Accessor.HasIndexRegister || Arm64Inspector.AccessSize(steps[k].I) != 8) return null;
        if (m.Accessor.HasExtend && m.Accessor.Extend.Amount is not (0 or 3)) return null;
        var tab = resolver.Before(A64Loc.Reg(m.Accessor.BaseRegister.Index), b, k);
        if (tab.Kind != A64Kind.Addr) return null;
        var index = a.Index;
        var targets = new List<CallTarget>();
        Span<byte> buffer = stackalloc byte[8];
        for (int n = 0; n < CallTargets.MaxTargets; n++)
        {
            uint at = tab.Rva + (uint)(n * 8);
            if (!a.IsRelocated(at) || index.Image.Read(at, buffer) != 8) break;
            ulong p = BitConverter.ToUInt64(buffer);
            if (p < index.Image.ImageBase || p - index.Image.ImageBase >= index.Image.SizeOfImage || index.FunctionByStart((uint)(p - index.Image.ImageBase)) is not { } f) break;
            targets.Add(new CallTarget(f.Start, f.Name, "pointer_table", "possible", $"entry {n} of the table at {a.Va(tab.Rva)}"));
        }
        if (targets.Count == 0) return null;
        int idx = m.Accessor.IndexRegister.Index;
        // cmp idx, #n; b.hi / b.hs in this block, or ending the single predecessor
        foreach (var (block, upTo) in new[] { (b, k) }.Concat(code.Predecessors(b).Take(1).Select(p => (p, code.Blocks[p].Length))))
        {
            var bs = code.Blocks[block];
            for (int j = upTo - 1; j >= 1; j--)
            {
                var cmp = bs[j - 1].I;
                if (cmp.Mnemonic != Arm64Mnemonic.CMP || A64Function.Gpr(cmp, 0) != idx || A64Function.Imm(in cmp, 1) is not { } bound) continue;
                var br = bs[j].I;
                ulong add = br.Mnemonic == Arm64Mnemonic.B && br.ToString().StartsWith("b.hi", StringComparison.Ordinal) ? 1UL : 0UL;
                int count = (int)Math.Min((ulong)bound + add, (ulong)CallTargets.MaxTargets);
                if (count <= targets.Count) return (targets.Take(count).Select(t => t with { Confidence = "exact" }).ToList(), true);
                break;
            }
        }
        return (targets, false);
    }
}
