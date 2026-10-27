using System.Runtime.CompilerServices;
using Corvus.Core;
using Corvus.Native.Code;

namespace Corvus.Native.Calls;

/// <summary>Targets of 32-bit ARM call and tail-jump sites: direct, import and GOT slots, constant addresses, pointer globals; field loads stay unresolved.</summary>
internal static class Arm32CallTargets
{
    private const int MaxWriters = 32;
    private static readonly ConditionalWeakTable<Arm32Trace, Dictionary<(bool, int), List<CallTargetSite>>> ImageCache = new();

    public static CallTargetSite? At(Arm32Trace a, uint rva, bool deep, CancellationToken ct = default)
    {
        if (a.Index.FunctionAt(rva) is not { } f) return null;
        var code = a.Code(f, ct);
        var (b, i) = code.Position(rva);
        if (b < 0 || !IsSite(code, code.Blocks[b][i])) return null;
        return Resolve(a, code, b, i, deep, ct);
    }

    public static List<CallTargetSite> In(Arm32Trace a, NativeFunction f, bool deep, CancellationToken ct = default)
    {
        var code = a.Code(f, ct);
        var result = new List<CallTargetSite>();
        for (int b = 0; b < code.Blocks.Length; b++)
            for (int i = 0; i < code.Blocks[b].Length; i++)
            {
                if (!IsSite(code, code.Blocks[b][i])) continue;
                ct.ThrowIfCancellationRequested();
                result.Add(Resolve(a, code, b, i, deep, ct));
            }
        return result.DistinctBy(s => s.Rva).OrderBy(s => s.Rva).ToList();
    }

    public static List<CallTargetSite> Image(Arm32Trace a, bool deep, CancellationToken ct = default)
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

    /// <summary>Calls, tail calls to function starts, and indirect jumps that are neither switch dispatches nor returns.</summary>
    private static bool IsSite(A32Function code, A32Step s) => s.Facts.Flow switch
    {
        FlowKind.Call or FlowKind.IndirectCall => true,
        FlowKind.Jump => s.Facts.HasTarget && code.Graph.TailCalls.Contains(s.Facts.Target),
        FlowKind.IndirectJump => !code.Graph.Switches.Any(t => t.JumpRva == s.Rva),
        _ => false,
    };

    private static CallTargetSite Resolve(Arm32Trace a, A32Function code, int b, int i, bool deep, CancellationToken ct)
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
            return Site("import_slot", "import", [new CallTarget(slot.SlotRva, NativeCodeIndex.ImportName(slot), "import_slot", "exact", "loaded from the import slot")]);

        var resolver = new Arm32Resolver(a, code) { Budget = 3000 };
        A32Val v;
        string location;
        if (s.I.Loads && s.I.WritesPc)
        {
            v = resolver.LoadedBy(b, i);
            location = "pc";
        }
        else if (s.I.OperandCount > 0 && s.I.Op(s.I.OperandCount - 1) is { Kind: ArmOperandKind.Register } op && op.Reg < A32Function.Sp)
        {
            v = resolver.Before(A32Loc.Reg(op.Reg), b, i);
            location = ArmInstruction.RegisterNames[op.Reg];
        }
        else return Site("register", "unresolved", [], "the target is not in a general-purpose register");
        string hint = $"trace_native_values address={a.Va(s.Rva)} location={(location == "pc" ? "op2" : location)}";
        switch (v.Kind)
        {
            case A64Kind.Addr when index.FunctionByStart(v.Rva) != null:
                return Site(location == "pc" ? "memory_pointer" : "register", "resolved", [new CallTarget(v.Rva, Name(v.Rva), "constant_pointer", "exact", v.Why)]);
            case A64Kind.Import:
            {
                var imp = a.ImportAt(v.Rva)!;
                return Site("import_slot", "import", [new CallTarget(imp.SlotRva, NativeCodeIndex.ImportName(imp), "import_slot", "exact", v.Why)]);
            }
            case A64Kind.Global:
                return GlobalWriters(a, v.Rva, Site);
            case A64Kind.Field:
                return Site("memory_pointer", "unresolved", [],
                    $"loaded from field +0x{v.Num:X} of {Describe(v.Inputs![0])} (a virtual call, callback or function-pointer member)", hint);
        }
        if (deep && location != "pc" && v.Kind is A64Kind.Incoming or A64Kind.Merge or A64Kind.Result)
        {
            var graph = ValueTrace.Build(a, new TraceSeed(TraceSeedKind.Location, s.Rva, code.Function, location, $"call target {location} at {a.Va(s.Rva)}"),
                new ValueTraceOptions(MaxDepth: 2, MaxCallers: 16, MaxNodes: 400), ct: ct);
            var found = graph.Values.Where(x => x.Kind is TraceNodeKind.Function or TraceNodeKind.Import && x.Rva is not null)
                .Select(x => new CallTarget(x.Rva!.Value, x.Text, "caller_argument", "possible", $"value trace node #{x.Node}")).ToList();
            bool complete = graph.Frontier.Count == 0 && graph.Values.Count == found.Count && !graph.Nodes.Any(n => n.Backward && n.Kind == TraceNodeKind.Unknown);
            if (found.Count > 0)
                return Site("register", complete && found.Count == 1 ? "resolved" : "possible",
                    complete && found.Count == 1 ? [found[0] with { Confidence = "exact" }] : found,
                    complete ? null : "other values may reach it (unknown paths or budgets)", complete ? null : hint);
        }
        return Site(location == "pc" ? "memory_pointer" : "register", "unresolved", [], v.Kind switch
        {
            A64Kind.Incoming => $"the target arrives in {A32Function.Name(v.Loc, null)}" + (A32Function.ParameterIndex(v.Loc) is var p and >= 0 ? $" (parameter {p + 1})" : ""),
            A64Kind.Result => "the target is a call result",
            A64Kind.Merge => "several values reach it",
            A64Kind.Const => $"the target is the constant 0x{v.Num:X}",
            A64Kind.Addr => $"the target {a.Va(v.Rva)} is no function start",
            _ => v.Why.Length > 0 ? v.Why : "target not known",
        }, hint);
    }

    private static string Describe(A32Val v) => v.Kind switch
    {
        A64Kind.Incoming => $"incoming {A32Function.Name(v.Loc, null)}",
        A64Kind.Result => "a call result",
        A64Kind.Field => $"a field +0x{v.Num:X}",
        A64Kind.Global => "a global",
        _ => "an unknown object",
    };

    private static CallTargetSite GlobalWriters(Arm32Trace a, uint g, Func<string, string, List<CallTarget>, string?, string?, CallTargetSite> site)
    {
        var index = a.Index;
        var targets = new List<CallTarget>();
        var unknown = new List<string>();
        string Where(uint r) => index.FunctionAt(r) is { } f ? Format.Within(f.Name, f.Start, r) : a.Va(r);
        var writers = index.RefsTo(g).Where(x => x.Kind == XrefKind.Write).DistinctBy(x => x.From).ToList();
        Span<byte> buffer = stackalloc byte[4];
        if (index.Image.Read(g, buffer) == 4 && BitConverter.ToUInt32(buffer) is var p && p >= index.Image.ImageBase && p - index.Image.ImageBase < index.Image.SizeOfImage
            && index.FunctionByStart((uint)(p - index.Image.ImageBase) & ~1u) is { } init && a.IsRelocated(g))
            targets.Add(new CallTarget(init.Start, init.Name, "initial_contents", "exact", $"relocated pointer at {a.Va(g)} in the image"));
        foreach (var w in writers.Take(MaxWriters))
        {
            if (index.FunctionAt(w.From) is not { } f) { unknown.Add(a.Va(w.From)); continue; }
            var code = a.Code(f, default);
            var (b, i) = code.Position(w.From);
            if (b < 0) { unknown.Add(Where(w.From)); continue; }
            var v = new Arm32Resolver(a, code) { Budget = 3000 }.Stored(b, i, g);
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
}
