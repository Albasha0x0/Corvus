using System.Diagnostics;
using Corvus.Core.WebAssembly;

namespace Corvus.Native.Code;

public sealed partial class NativeCodeIndex
{
    private const int MaxIndirectTargets = 256, MaxIndirectEdges = 4_000_000;

    /// <summary>The index of a WebAssembly module: one function per body, calls, call_indirect edges, globals, references and strings.</summary>
    private static NativeCodeIndex FromWasm(WasmImage image, ProgressGate report, CancellationToken ct)
    {
        var sw = Stopwatch.StartNew();
        var m = image.Module;
        var memory = new WasmMemoryMap(m);
        int imported = m.ImportedFunctions;
        uint FunctionAddress(uint f) => m.BodyOf(f) is { } b ? (uint)b.Start : f < imported ? (uint)(m.ImportAt(WasmExternal.Func, f)?.Offset ?? 0) : 0;

        // Call_indirect candidates: functions each funcref table's element segments place, by structural type.
        var byType = new Dictionary<(uint Table, string Type), List<uint>>();
        foreach (var e in m.Elements)
        {
            if (e.Mode == WasmSegmentMode.Declarative || e.Type != WasmType.FuncRef) continue;
            foreach (var f in e.Functions ?? [])
                if (m.FunctionType(f) is { } ft)
                {
                    // A passive segment is usually table.init into table 0.
                    var key = (e.Mode == WasmSegmentMode.Active ? e.Table : 0, Signature(ft));
                    if (!byType.TryGetValue(key, out var list)) byType[key] = list = [];
                    list.Add(f);
                }
        }
        foreach (var list in byType.Values) { list.Sort(); var distinct = list.Distinct().ToList(); list.Clear(); list.AddRange(distinct); }

        var bodies = m.Bodies;
        var perFunction = new CodeXref[bodies.Count][];
        var indirect = new CodeXref[bodies.Count][];
        var counts = new int[bodies.Count];
        var stringTargets = new System.Collections.Concurrent.ConcurrentDictionary<uint, byte>();
        long done = 0;
        Parallel.For(0, bodies.Count, new ParallelOptions { CancellationToken = ct }, i =>
        {
            var xrefs = new List<CodeXref>();
            var virtuals = new List<CodeXref>();
            var b = bodies[i];
            var code = new WasmCode(m.Bytes, b.CodeStart, b.End);
            int n = 0;
            long lastConst = long.MinValue;
            bool constBefore = false;
            while (code.Next(out var ins))
            {
                n++;
                uint at = (uint)ins.Offset;
                switch (ins.Op)
                {
                    case 0x10 or 0x12:
                        {
                            bool tail = ins.Op == 0x12;
                            if (ins.A < imported) xrefs.Add(new CodeXref(at, FunctionAddress(ins.A), tail ? XrefKind.ImportJump : XrefKind.ImportCall));
                            else if (m.BodyOf(ins.A) is { } t) xrefs.Add(new CodeXref(at, (uint)t.Start, tail ? XrefKind.TailCall : XrefKind.Call));
                            break;
                        }
                    case 0x11 or 0x13:
                        if (ins.A < m.Types.Count && byType.TryGetValue((ins.B, Signature(m.Types[(int)ins.A])), out var candidates) && candidates.Count <= MaxIndirectTargets)
                            foreach (var f in candidates) virtuals.Add(new CodeXref(at, FunctionAddress(f), XrefKind.VirtualPossible));
                        break;
                    case 0x23 or 0x24:
                        if (image.GlobalAddress(ins.A) is { } g) xrefs.Add(new CodeXref(at, g, ins.Op == 0x23 ? XrefKind.Read : XrefKind.Write));
                        break;
                    case 0xD2:
                        if (ins.A < m.FunctionCount) xrefs.Add(new CodeXref(at, FunctionAddress(ins.A), XrefKind.Address));
                        break;
                    case 0x41 or 0x42:
                        {
                            ulong address = ins.Op == 0x41 ? (uint)(int)ins.Value : (ulong)ins.Value;
                            if (memory.FileOffset(address) is { } file)
                            {
                                xrefs.Add(new CodeXref(at, (uint)file, XrefKind.Address));
                                stringTargets.TryAdd((uint)file, 0);
                            }
                            lastConst = ins.Value;
                            constBefore = true;
                            continue;
                        }
                    default:
                        if (constBefore && ins.Info.IsMemoryAccess && ins.Memory == 0)
                        {
                            ulong address = (ulong)(uint)(int)lastConst + ins.MemOffset;
                            if (ins.MemOffset != 0 && memory.FileOffset(address) is { } file)
                                xrefs.Add(new CodeXref(at, (uint)file, ins.Info.Signature.EndsWith(':') ? XrefKind.Write : XrefKind.Read));
                        }
                        break;
                }
                constBefore = false;
            }
            xrefs.Sort((a, c) => a.From != c.From ? a.From.CompareTo(c.From) : a.To != c.To ? a.To.CompareTo(c.To) : a.Kind.CompareTo(c.Kind));
            perFunction[i] = [.. xrefs];
            indirect[i] = [.. virtuals];
            counts[i] = n;
            long d = Interlocked.Increment(ref done);
            if ((d & 0x3FF) == 0) report.Report("decoding functions", d, bodies.Count);
        });

        // Element segment entries point at their functions.
        var pointers = new List<CodeXref>();
        foreach (var e in m.Elements)
            foreach (var f in e.Functions ?? [])
                if (f < m.FunctionCount) pointers.Add(new CodeXref((uint)e.Position, FunctionAddress(f), XrefKind.Pointer));
        pointers.Sort((a, c) => a.From != c.From ? a.From.CompareTo(c.From) : a.To.CompareTo(c.To));

        long total = pointers.Count + perFunction.Sum(x => (long)x.Length);
        var all = new CodeXref[total];
        int k = 0;
        foreach (var x in pointers) all[k++] = x;
        foreach (var list in perFunction) { list.CopyTo(all, k); k += list.Length; }
        if (pointers.Count > 0 && bodies.Count > 0 && pointers[^1].From > bodies[0].Start) Array.Sort(all, (a, c) => a.From != c.From ? a.From.CompareTo(c.From) : a.To.CompareTo(c.To));

        var exported = m.Exports.Where(e => e.Kind == WasmExternal.Func).Select(e => e.Index).ToHashSet();
        var functions = new NativeFunction[bodies.Count];
        var starts = new uint[bodies.Count];
        var ends = new uint[bodies.Count];
        for (int i = 0; i < bodies.Count; i++)
        {
            uint index = (uint)(imported + i);
            functions[i] = new NativeFunction
            {
                Start = (uint)bodies[i].Start, End = (uint)bodies[i].End, Size = (uint)(bodies[i].End - bodies[i].Start), Index = i,
                Sources = FunctionSource.Symbol | (exported.Contains(index) ? FunctionSource.Export : 0) | (m.Start == index ? FunctionSource.EntryPoint : 0),
                KnownName = image.FunctionNames[(int)index], InstructionCount = counts[i], BlockCount = 1, FirstRange = i, RangeCount = 1,
            };
            starts[i] = (uint)bodies[i].Start;
            ends[i] = (uint)bodies[i].End;
        }

        var strings = new List<StringLiteral>();
        foreach (var target in stringTargets.Keys.Order())
            if (WasmMemoryMap.CString(m.Bytes, (int)target) is { } s) strings.Add(new StringLiteral(target, System.Text.Encoding.UTF8.GetByteCount(s), StringEncoding.Ascii));

        var edges = indirect.SelectMany(x => x).Take(MaxIndirectEdges + 1).ToArray();
        var truncations = new List<string>();
        if (edges.Length > MaxIndirectEdges)
        {
            truncations.Add($"call_indirect edges stopped at {MaxIndirectEdges:N0}");
            edges = edges[..MaxIndirectEdges];
        }
        long skipped = byType.Values.Count(l => l.Count > MaxIndirectTargets);
        if (skipped > 0) truncations.Add($"{skipped:N0} function types have more than {MaxIndirectTargets} table entries: their call_indirect sites get no edges");
        report.Done();
        var stats = new CodeIndexStats(functions.Length, 0, 0, counts.Sum(c => (long)c), functions.Length, all.Length, strings.Count, 0, 0, 0, 1, 0, sw.Elapsed);
        var built = new NativeCodeIndex(image, CodeSupport.Bytecode,
            "WebAssembly: functions, calls and references from the module's own reader; disassemble gives WAT, decompile_native a lifted view",
            null, functions, starts, ends, all, [.. strings], truncations, stats);
        if (edges.Length > 0) built.SetVirtualCalls(VirtualCallSet.Empty, edges);
        return built;
    }

    /// <summary>A WebAssembly function's basic blocks and edges from its structured control flow.</summary>
    private FunctionGraph WasmGraph(NativeFunction f, CancellationToken ct)
    {
        var w = (WasmImage)Image;
        var m = w.Module;
        var body = m.Bodies[f.Index];
        var list = new List<WasmInstr>();
        var code = new WasmCode(m.Bytes, body.CodeStart, body.End);
        while (code.Next(out var ins)) { list.Add(ins); if ((list.Count & 0xFFFF) == 0) ct.ThrowIfCancellationRequested(); }
        int n = list.Count;
        uint After(int i) => i + 1 < n ? (uint)list[i + 1].Offset : (uint)body.End;
        // The end and else of each block, loop, if and try.
        var endOf = new int[n];
        var elseOf = new int[n];
        Array.Fill(endOf, -1);
        Array.Fill(elseOf, -1);
        var open = new List<int>();
        for (int i = 0; i < n; i++)
        {
            var ins = list[i];
            if (ins.Op is 0x02 or 0x03 or 0x04 or 0x06 or 0x1F) open.Add(i);
            else if (ins.Op == 0x05 && open.Count > 0) elseOf[open[^1]] = i;
            else if (ins.Op == 0x0B && open.Count > 0) { endOf[open[^1]] = i; open.RemoveAt(open.Count - 1); }
        }
        // Branch targets: a loop's first instruction or the one after a block's end; null leaves the function.
        open.Clear();
        var targets = new Dictionary<int, uint?[]>();
        for (int i = 0; i < n; i++)
        {
            var ins = list[i];
            uint? Target(uint depth)
            {
                if (depth >= open.Count) return null;
                int c = open[open.Count - 1 - (int)depth];
                return list[c].Op == 0x03 ? After(c) : endOf[c] >= 0 ? After(endOf[c]) : null;
            }
            switch (ins.Op)
            {
                case 0x0C or 0x0D or 0xD5 or 0xD6 or 0xFB0018 or 0xFB0019: targets[i] = [Target(ins.A)]; break;
                case 0x0E: targets[i] = [.. WasmCode.Targets(m.Bytes, ins).Select(Target)]; break;
            }
            if (ins.Op is 0x02 or 0x03 or 0x04 or 0x06 or 0x1F) open.Add(i);
            else if (ins.Op == 0x0B && open.Count > 0) open.RemoveAt(open.Count - 1);
        }
        var leaders = new SortedSet<uint> { (uint)body.CodeStart };
        for (int i = 0; i < n; i++)
        {
            var ins = list[i];
            if (ins.Op is 0x0C or 0x0D or 0x0E or 0x0F or 0x00 or 0x04 or 0x05 or 0x0B or 0x08 or 0x09 or 0x0A or 0x12 or 0x13 or 0x03 or 0xD5 or 0xD6 or 0xFB0018 or 0xFB0019)
                if (i + 1 < n) leaders.Add(After(i));
            if (ins.Op == 0x04 && elseOf[i] >= 0) leaders.Add(After(elseOf[i]));
            foreach (var t in targets.GetValueOrDefault(i) ?? []) if (t is { } at && at < body.End) leaders.Add(at);
        }
        var starts = leaders.ToArray();
        var blocks = new List<BasicBlock>();
        var byStart = new Dictionary<uint, BasicBlock>();
        int at0 = 0;
        var pending = new List<(BasicBlock Block, uint To, EdgeKind Kind)>();
        var tails = new List<uint>();
        for (int b = 0; b < starts.Length; b++)
        {
            uint start = starts[b], end = b + 1 < starts.Length ? starts[b + 1] : (uint)body.End;
            while (at0 < n && list[at0].Offset < start) at0++;
            int first = at0, last = at0;
            while (last + 1 < n && list[last + 1].Offset < end) last++;
            if (first >= n) break;
            var term = list[last];
            var kind = term.Op switch
            {
                0x0C => BlockEnd.Jump, 0x0D or 0xD5 or 0xD6 or 0xFB0018 or 0xFB0019 or 0x04 => BlockEnd.ConditionalJump, 0x0E => BlockEnd.Switch, 0x0F => BlockEnd.Return,
                0x00 or 0x08 or 0x09 or 0x0A => BlockEnd.Trap, 0x12 or 0x13 => BlockEnd.TailCall, 0x05 => BlockEnd.Jump,
                0x0B when last == n - 1 => BlockEnd.Return, _ => BlockEnd.FallThrough,
            };
            if (kind == BlockEnd.Jump && term.Op == 0x0C && targets[last][0] == null) kind = BlockEnd.Return;
            var block = new BasicBlock { Start = start, End = end, InstructionCount = last - first + 1, LastInstruction = (uint)term.Offset, EndKind = kind };
            blocks.Add(block);
            byStart[start] = block;
            uint next = end;
            switch (term.Op)
            {
                case 0x0C: if (targets[last][0] is { } t) pending.Add((block, t, EdgeKind.Jump)); break;
                case 0x0D or 0xD5 or 0xD6 or 0xFB0018 or 0xFB0019:
                    if (targets[last][0] is { } c) pending.Add((block, c, EdgeKind.ConditionalTaken));
                    pending.Add((block, next, EdgeKind.ConditionalFallThrough));
                    break;
                case 0x0E: foreach (var s in targets[last].OfType<uint>().Distinct()) pending.Add((block, s, EdgeKind.Switch)); break;
                case 0x04:
                    pending.Add((block, next, EdgeKind.ConditionalFallThrough));
                    int ifAt = last;
                    pending.Add((block, elseOf[ifAt] >= 0 ? After(elseOf[ifAt]) : endOf[ifAt] >= 0 ? After(endOf[ifAt]) : next, EdgeKind.ConditionalTaken));
                    break;
                case 0x05:
                    {
                        int owner = Array.FindLastIndex(elseOf, x => x == last);
                        if (owner >= 0 && endOf[owner] >= 0) pending.Add((block, After(endOf[owner]), EdgeKind.Jump));
                        break;
                    }
                case 0x12: if (m.BodyOf(term.A) is { } callee) tails.Add((uint)callee.Start); break;
                case 0x0F or 0x00 or 0x08 or 0x09 or 0x0A or 0x13: break;
                default: if (kind == BlockEnd.FallThrough) pending.Add((block, next, EdgeKind.FallThrough)); break;
            }
        }
        foreach (var (block, to, edge) in pending)
            if (byStart.TryGetValue(to, out var target))
            {
                var e = new CfgEdge(block.Start, to, edge);
                block.Successors.Add(e);
                target.Predecessors.Add(e);
            }
        return new FunctionGraph { Function = f, Blocks = blocks, Switches = [], UnresolvedJumps = [], TailCalls = tails };
    }

    /// <summary>The error for a request that needs a machine-code walker this index lacks.</summary>
    private Exception NoWalker() => Support == CodeSupport.Bytecode
        ? new Core.ToolError(Core.ErrorCode.Unsupported, $"{Path.GetFileName(Image.Path)} is WebAssembly: there are no machine-code basic blocks or instruction facts.",
            "disassemble gives its WAT, decompile_native a lifted view; find_xrefs, native_call_tree and list_functions read its calls and references")
        : new NotSupportedException(SupportNote);

    /// <summary>A function type as text, so structurally equal types match as call_indirect requires.</summary>
    private static string Signature(WasmFuncType t) =>
        string.Concat(t.Params.Select(p => (char)p)) + ":" + string.Concat(t.Results.Select(r => (char)r));
}
