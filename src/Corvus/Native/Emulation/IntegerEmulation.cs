using System.Diagnostics;
using System.Globalization;
using System.Text.Json.Nodes;
using Corvus.Native.Calls;
using Corvus.Native.Code;

namespace Corvus.Native.Emulation;

/// <summary>The built-in emulator, taking and returning the Ghidra worker's emulate fields; each import slot holds a distinct address outside the image.</summary>
public static partial class IntegerEmulation
{
    // Stack in the low half of the region, scratch buffers in the high half; the return sentinel just above it.
    private const ulong Region = 0x200000, StackSize = 0x100000, ImportArea = 0x10000;
    private const ulong HeapSize = 0x1000000;
    private const int MaxCalls = 100, MaxRanges = 64, MaxRangeBytes = 4096, MaxRead = 65536;

    /// <summary>The instruction sets the built-in emulator models: x86, x64 and ARM64.</summary>
    public static bool Supports(INativeImage image) => image.Arch is NativeArch.X86 or NativeArch.X64 or NativeArch.Arm64;

    /// <summary>The processor for <paramref name="image"/>; Unsupported for other instruction sets.</summary>
    public static IEmulatorCpu Cpu(INativeImage image) => image.Arch switch
    {
        NativeArch.X64 => new X86Cpu(true, image.Format == ImageFormat.Pe),
        NativeArch.X86 => new X86Cpu(false, image.Format == ImageFormat.Pe),
        NativeArch.Arm64 => new Arm64Cpu(),
        _ => throw new Core.ToolError(Core.ErrorCode.Unsupported, $"The built-in emulator runs x86, x64 and ARM64 code, not {image.Arch}.",
            "omit engine to use Ghidra's p-code emulator"),
    };

    /// <summary>Runs one request and returns the worker's result fields with "engine": "ours"; bad input throws InvalidArgument or LimitExceeded.</summary>
    public static JsonObject Run(INativeImage image, ulong imageBase, NativeCodeIndex? index, JsonObject request, CancellationToken ct) =>
        Start(image, imageBase, index, request, ct).Result;

    /// <summary>Lays out a run's memory: the region, the import addresses with their slots written, and the heap.</summary>
    private static (EmulatorMemory Mem, EmulatorHeap Heap, Dictionary<ulong, NativeImport> ByAddress, ulong Sentinel, ulong RegionBase) Layout(
        INativeImage image, ulong imageBase, IEmulatorCpu cpu)
    {
        int ptr = cpu.PointerSize;
        var imports = image.Imports.Where(i => i.SlotRva != 0 && i.SlotRva + (uint)ptr <= image.SizeOfImage).GroupBy(i => i.SlotRva).Select(g => g.First()).ToList();
        // The region reserves the heap after the import addresses.
        ulong regionBase = PickRegion(imageBase, image.SizeOfImage, ptr, (ulong)imports.Count * 16 + HeapSize);
        var mem = new EmulatorMemory(image, imageBase, regionBase, Region);
        ulong sentinel = regionBase + Region, importBase = regionBase + Region + ImportArea;
        ulong heapBase = (importBase + (ulong)imports.Count * 16 + 0xFFF) & ~0xFFFUL;
        var heap = new EmulatorHeap(mem, heapBase, HeapSize);
        var byAddress = new Dictionary<ulong, NativeImport>();
        for (int k = 0; k < imports.Count; k++)
        {
            ulong at = importBase + (ulong)k * 16;
            byAddress[at] = imports[k];
            mem.WriteUInt(imageBase + imports[k].SlotRva, at, ptr);
        }
        return (mem, heap, byAddress, sentinel, regionBase);
    }

    /// <summary>Runs one request like Run and returns the run beside its result.</summary>
    internal static (JsonObject Result, EmulationRun Run) Start(INativeImage image, ulong imageBase, NativeCodeIndex? index, JsonObject request, CancellationToken ct)
    {
        var cpu = Cpu(image);
        int ptr = cpu.PointerSize;
        var (mem, heap, byAddress, sentinel, regionBase) = Layout(image, imageBase, cpu);

        ulong start = Va(Text(request, "start")!);
        int traceMax = (int)(Number(request["trace"]) ?? 0);

        ulong stackTop = regionBase + StackSize;
        cpu.Sp = (stackTop - 0x1000) & ~0xFUL;
        cpu.Pc = start;
        cpu.SetReturnAddress(mem, sentinel);
        ulong spAtEntry = cpu.Sp;
        ulong scratch = stackTop + 0x1000;
        var scratchOut = new JsonArray();

        ulong Value(JsonNode? v, string label)
        {
            if (v?["value"] is { } number) return Va(number.GetValue<string>());
            var bytes = Convert.FromHexString(v?["bytes"]?.GetValue<string>() ?? "");
            ulong at = scratch, next = (at + (ulong)bytes.Length + 16 + 15) & ~0xFUL;
            if (next > regionBase + Region) throw new Core.ToolError(Core.ErrorCode.LimitExceeded, $"scratch buffers exceed {Region - StackSize - 0x1000} bytes");
            mem.Write(at, bytes);
            scratch = next;
            scratchOut.Add(new JsonObject { ["label"] = label, ["va"] = Hex(at), ["length"] = bytes.Length });
            return at;
        }

        if (request["memory"] is JsonArray writes)
            foreach (var w in writes)
                mem.Write(Va(Text(w, "va")!), Convert.FromHexString(Text(w, "bytes") ?? ""));
        if (request["args"] is JsonArray args)
        {
            var slots = cpu.Arguments(args.Count);
            for (int k = 0; k < args.Count; k++)
            {
                ulong v = Value(args[k], "arg" + (k + 1));
                if (slots[k].Register is { } reg) cpu.TrySet(reg, v);
                else mem.WriteUInt(spAtEntry + (ulong)slots[k].StackOffset, v, ptr);
            }
        }
        if (request["registers"] is JsonArray regs)
            foreach (var pair in regs.OfType<JsonArray>())
            {
                string name = pair[0]!.GetValue<string>();
                ulong v = Value(pair[1], name);
                if (!cpu.TrySet(name, v)) throw new Core.ToolError(Core.ErrorCode.InvalidArgument, $"no register '{name}' in {cpu.Language}");
            }
        var stops = new HashSet<ulong>((request["stops"] as JsonArray)?.Select(s => Va(s!.GetValue<string>())) ?? []);
        var stubs = (request["stubs"] as JsonArray)?.OfType<JsonArray>().Select(p => (Key: p[0]!.GetValue<string>().Trim(), Value: p[1]!.GetValue<string>())).ToList() ?? [];
        string? anyStub = stubs.FirstOrDefault(s => s.Key == "*").Value;

        var shown = cpu.MainRegisters;
        var before = shown.Select(n => cpu.TryGet(n, out var v) ? v : 0).ToList();

        var run = new EmulationRun(image, imageBase, index, cpu, mem, heap, byAddress, sentinel, regionBase, stackTop, shown, before, scratchOut, stops, stubs,
            anyStub, traceMax, start, request["reads"] as JsonArray);
        long maxIns = (long)(Number(request["max_instructions"]) ?? 1_000_000);
        double seconds = Number(request["seconds"]) ?? 10;
        return (Execute(run, maxIns, seconds, ct), run);
    }

    /// <summary>Continues a run with fresh budgets; returns the whole run's result.</summary>
    internal static JsonObject Resume(EmulationRun run, long maxInstructions, double seconds, CancellationToken ct) =>
        Execute(run, maxInstructions, seconds, ct);

    private const ulong NullPageSpan = 0x1000;

    private const string NullPageHint = "args can pass a pointer to a buffer (buf:N)";

    /// <summary>
    /// Names a fault below the first page as a null page access: the register
    /// holding the base, the argument it came from and the offset; null for
    /// any other fault.
    /// </summary>
    private static string? NullPageDetail(EmulatorFaultException f, IEmulatorCpu cpu)
    {
        if (f.Address >= (ulong)EmulatorMemory.PageSize) return null;
        var args = cpu.Arguments(6);
        if (cpu.LastMemoryOperand is { } op)
        {
            // The base is the register that is small; else the index.
            foreach (var (reg, source) in new[] { (op.Base, op.BaseSource), (op.Index, op.IndexSource) })
            {
                if (reg == null || !cpu.TryGet(reg, out var held) || held >= NullPageSpan) continue;
                int k = source == null ? -1 : args.ToList().FindIndex(a => string.Equals(a.Register, source, StringComparison.OrdinalIgnoreCase));
                string where = k < 0 ? reg.ToUpperInvariant()
                    : string.Equals(reg, source, StringComparison.OrdinalIgnoreCase) ? $"argument {k + 1} ({source})"
                    : $"argument {k + 1} ({source}, copied to {reg.ToUpperInvariant()})";
                return $"{f.Message}: null page, {where} plus 0x{f.Address - held:x}; {NullPageHint}";
            }
        }
        // No operand is known (x86-32, ARM64, short history): a zero argument is the
        // base, else the nearest value below the address.
        int pick = -1;
        ulong pickValue = 0;
        for (int k = 0; k < args.Count; k++)
        {
            if (args[k].Register is not { } r || !cpu.TryGet(r, out var v)) continue;
            if (v > f.Address || f.Address - v >= NullPageSpan) continue;
            if (pick < 0 || v == 0 && pickValue != 0) { pick = k; pickValue = v; }
        }
        if (pick < 0) return $"{f.Message}: null page";
        string name = args[pick].Register!;
        return $"{f.Message}: null page, argument {pick + 1} ({name}) plus " +
            $"0x{f.Address - pickValue:x}; {NullPageHint}";
    }

    private static JsonObject Execute(EmulationRun run, long maxIns, double seconds, CancellationToken ct)
    {
        var (image, imageBase, index, cpu, mem, heap, byAddress, sentinel) = (run.Image, run.ImageBase, run.Index, run.Cpu, run.Mem, run.Heap, run.ByAddress, run.Sentinel);
        var (regionBase, stackTop, shown, before, scratchOut) = (run.RegionBase, run.StackTop, run.Shown, run.Before, run.ScratchOut);
        var (stops, stubs, anyStub, traceMax, start) = (run.Stops, run.Stubs, run.AnyStub, run.TraceMax, run.Start);
        int ptr = cpu.PointerSize;
        var trace = run.Trace;
        var calls = run.Calls;
        long executed = run.Executed, limit = executed + maxIns;
        int callCount = run.CallCount;
        ulong lastSite = run.LastSite;
        bool afterCall = run.AfterCall;
        string? stop = null, detail = null;
        ulong? stoppedAt = null;
        mem.Tracking = true;
        var clock = Stopwatch.StartNew();

        var rows = run.CallRows;
        void Record(ulong site, ulong target, string? name, string action, ulong? value)
        {
            callCount++;
            // Identical rows are one row with a count, so a loop does not fill the list.
            var key = (site, target, name, action, value);
            if (rows.TryGetValue(key, out var row))
            {
                row["count"] = (int)row["count"]! + 1;
                return;
            }
            if (calls.Count >= MaxCalls) return;
            rows[key] = new JsonObject
            {
                ["site"] = Hex(site), ["target"] = Hex(target), ["name"] = name, ["action"] = action, ["value"] = value is { } v ? Hex(v) : null, ["count"] = 1,
            };
            calls.Add(rows[key]);
        }

        // Answers a callee without a stub from the heap model; null when the callee has none.
        ulong? Model(string? name, out string? fault)
        {
            fault = null;
            var label = name == null ? null : name.Contains('!') ? name[(name.IndexOf('!') + 1)..] : name;
            if (!EmulatorHeap.Models(label)) return null;
            return heap.Call(label!, k =>
            {
                var slot = cpu.Arguments(k + 1)[k];
                return slot.Register is { } r ? cpu.TryGet(r, out var v) ? v : 0 : mem.ReadUInt(cpu.Sp + (ulong)slot.StackOffset, ptr);
            }, out fault);
        }

        int Purge(NativeImport? import) => ptr == 4 && image.Format == ImageFormat.Pe && import != null ? X86ImportArity.Pops(import, image.Path) ?? 0 : 0;

        // Order: named stub, then heap model, then library model, then the
        // any-call stub.
        // A fault or limit in a model sets stop.
        bool TryModel(string? name, ulong site, ulong target, NativeImport? import)
        {
            if (LibraryModels.Find(name) is not { } model) return false;
            try
            {
                ulong v = LibraryModels.Run(model, cpu, mem);
                Record(site, target, name, "model", v);
                cpu.ReturnFromCall(mem, v, Purge(import));
            }
            catch (EmulatorFaultException f)
            {
                stop = "memory_fault";
                stoppedAt = site;
                detail = $"{model}: {f.Message}";
            }
            catch (EmulatorUnsupportedException u)
            {
                stop = "error";
                stoppedAt = site;
                detail = u.Message;
            }
            return true;
        }

        while (true)
        {
            ulong pc = cpu.Pc;
            if (pc == sentinel) { stop = "returned"; break; }
            if (byAddress.TryGetValue(pc, out var reached))
            {
                // Execution reached an import through a slot (a jump stub, a register call): its stub answers it.
                afterCall = true;
                string name = NativeCodeIndex.ImportName(reached);
                string? named = Stub(stubs, name, pc), value = named;
                if (named == null && ThrowHelpers.Find(name) is { } thrown)
                {
                    stop = "managed_exception";
                    stoppedAt = lastSite;
                    detail = $"call at 0x{lastSite:x} to {name} raises {thrown}";
                    break;
                }
                if (named == null && Model(name, out var heapFault) is { } modelled)
                {
                    if (heapFault != null)
                    {
                        stop = "heap_error";
                        stoppedAt = lastSite;
                        detail = $"call at 0x{lastSite:x}: {heapFault}";
                        break;
                    }
                    Record(lastSite, pc, name, "model", modelled);
                    cpu.ReturnFromCall(mem, modelled, Purge(reached));
                    continue;
                }
                if (named == null && TryModel(name, lastSite, pc, reached)) { if (stop != null) break; continue; }
                value ??= anyStub;
                if (value == null)
                {
                    stop = "unmodelled_call";
                    stoppedAt = lastSite;
                    detail = $"call at 0x{lastSite:x} to {name} (outside the image): stub it (stubs=NAME=VALUE, or *=VALUE for every call outside the image)";
                    break;
                }
                ulong v = Va(value);
                Record(lastSite, pc, name, named != null ? "stub" : "skip", v);
                cpu.ReturnFromCall(mem, v, Purge(reached));
                continue;
            }
            if (executed > 0 && stops.Contains(pc)) { stop = "stop_address"; break; }
            if (executed >= limit) { stop = "instruction_budget"; break; }
            if ((executed & 1023) == 0)
            {
                if (ct.IsCancellationRequested) { stop = "cancelled"; break; }
                if (clock.Elapsed.TotalSeconds >= seconds) { stop = "time_budget"; break; }
            }
            if (!mem.Mapped(pc))
            {
                stop = "unmapped_execute";
                detail = $"execution reached unmapped address 0x{pc:x}";
                break;
            }
            EmulatorStep step;
            try
            {
                step = cpu.Step(mem);
            }
            catch (EmulatorFaultException f)
            {
                // Step advanced the program counter; report the faulting instruction.
                cpu.Pc = pc;
                stop = "memory_fault";
                stoppedAt = pc;
                detail = NullPageDetail(f, cpu) ?? f.Message;
                if (traceMax > 0) Trace(trace, traceMax, pc, cpu.LastText);
                break;
            }
            catch (EmulatorTrapException t)
            {
                stop = "trap";
                stoppedAt = pc;
                detail = afterCall
                    ? "reached a trap after a call that does not return"
                    : $"reached a trap instruction ({t.Message})";
                break;
            }
            catch (EmulatorUnsupportedException u)
            {
                stop = "error";
                stoppedAt = pc;
                detail = u.Message;
                break;
            }
            if (traceMax > 0) Trace(trace, traceMax, pc, cpu.LastText);
            executed++;
            lastSite = pc;
            // Only a call answered without entering the callee returns to the next instruction.
            afterCall = step.IsCall && cpu.Pc == step.FallThrough;
            if (!step.IsCall) continue;
            ulong target = cpu.Pc;
            if (byAddress.ContainsKey(target)) continue;
            var (calleeName, thunk) = Callee(image, imageBase, index, target);
            string? stubValue = Stub(stubs, calleeName, target);
            if (stubValue == null && ThrowHelpers.Find(calleeName) is { } raised)
            {
                stop = "managed_exception";
                stoppedAt = step.Site;
                detail = $"call at 0x{step.Site:x} to {calleeName} raises {raised}";
                break;
            }
            if (stubValue == null && thunk != null && Model(calleeName, out var thunkFault) is { } thunkValue)
            {
                if (thunkFault != null)
                {
                    stop = "heap_error";
                    stoppedAt = step.Site;
                    detail = $"call at 0x{step.Site:x}: {thunkFault}";
                    break;
                }
                Record(step.Site, target, calleeName, "model", thunkValue);
                cpu.ReturnFromCall(mem, thunkValue, Purge(thunk));
                continue;
            }
            if (stubValue == null && TryModel(calleeName, step.Site, target, thunk)) { if (stop != null) break; continue; }
            // The any-call stub answers calls outside the image only, so image
            // routines run. A call to the next instruction is never skipped.
            bool external = thunk != null || target < imageBase || target - imageBase >= image.SizeOfImage;
            string? anyValue = stubValue == null && external && target != step.FallThrough ? anyStub : null;
            if (stubValue != null || anyValue != null)
            {
                ulong v = Va(stubValue ?? anyValue!);
                Record(step.Site, target, calleeName, stubValue != null ? "stub" : "skip", v);
                cpu.ReturnFromCall(mem, v, Purge(thunk));
                continue;
            }
            if (thunk != null)
            {
                stop = "unmodelled_call";
                stoppedAt = step.Site;
                detail = $"call at 0x{step.Site:x} to {calleeName} (outside the image): stub it (stubs=NAME=VALUE, or *=VALUE for every call outside the image)";
                break;
            }
            if (!mem.Mapped(target))
            {
                stop = "unmodelled_call";
                stoppedAt = step.Site;
                detail = $"call at 0x{step.Site:x} to 0x{target:x} (unmapped): stub it (stubs=NAME=VALUE, or *=VALUE for every call outside the image)";
                break;
            }
            Record(step.Site, target, calleeName, "into", null);
        }
        mem.Tracking = false;
        run.Executed = executed;
        run.CallCount = callCount;
        run.LastSite = lastSite;
        run.AfterCall = afterCall;
        run.Elapsed += clock.Elapsed;
        run.Resumable = stop is "instruction_budget" or "time_budget" or "cancelled";

        ulong stopPc = stoppedAt ?? cpu.Pc;
        var o = new JsonObject
        {
            ["engine"] = "ours",
            ["language"] = cpu.Language,
            ["stop"] = stop,
            ["detail"] = detail,
            ["pc"] = Hex(stopPc),
            ["where"] = Where(imageBase, index, stopPc),
            ["instructions"] = executed,
            ["seconds"] = Math.Round(run.Elapsed.TotalSeconds, 3),
            ["return_register"] = cpu.ReturnRegister,
            ["return_value"] = Hex(cpu.TryGet(cpu.ReturnRegister, out var ret) ? ret : 0),
        };
        var regRows = new JsonArray();
        for (int k = 0; k < shown.Count; k++)
        {
            cpu.TryGet(shown[k], out var now);
            regRows.Add(new JsonArray(shown[k], Hex(now), now != before[k]));
        }
        o["registers"] = regRows;
        o["calls"] = calls.DeepClone();
        o["call_count"] = callCount;
        o["scratch"] = scratchOut.DeepClone();
        o["stack"] = Hex(regionBase) + "-" + Hex(stackTop);

        // Written memory outside the stack.
        var ranges = mem.WrittenRanges();
        long stackBytes = 0;
        var data = new List<(ulong Start, ulong Length)>();
        foreach (var (s, len) in ranges)
        {
            ulong e = s + len;
            ulong lo = Math.Max(s, regionBase), hi = Math.Min(e, stackTop);
            if (lo < hi) stackBytes += (long)(hi - lo);
            if (s < regionBase) data.Add((s, Math.Min(e, regionBase) - s));
            if (e > stackTop) data.Add((Math.Max(s, stackTop), e - Math.Max(s, stackTop)));
        }
        o["stack_bytes_written"] = stackBytes;
        var written = new JsonArray();
        foreach (var (s, len) in data.Take(MaxRanges))
        {
            var bytes = new byte[(int)Math.Min(len, MaxRangeBytes)];
            mem.Read(s, bytes);
            written.Add(new JsonObject { ["va"] = Hex(s), ["length"] = (long)len, ["bytes"] = Convert.ToHexString(bytes).ToLowerInvariant(), ["where"] = Where(imageBase, index, s) });
        }
        o["written"] = written;
        o["written_ranges"] = data.Count;
        // Writes below the first page come from a null or small receiver.
        var low = ranges.Where(r => r.Start < (ulong)EmulatorMemory.PageSize).ToList();
        o["null_page_writes"] = low.Count == 0 ? null : new JsonObject
        {
            ["first"] = Hex(low.Min(r => r.Start)),
            ["bytes"] = low.Sum(r => (long)Math.Min(r.Length, (ulong)EmulatorMemory.PageSize - r.Start)),
        };

        var reads = new JsonArray();
        if (run.Reads is { } asked)
            foreach (var q in asked)
            {
                var row = new JsonObject();
                int len = (int)Math.Clamp(Number(q?["length"]) ?? 64, 1, MaxRead);
                ulong from;
                if (Text(q, "register") is { } reg)
                {
                    if (!cpu.TryGet(reg, out from)) throw new Core.ToolError(Core.ErrorCode.InvalidArgument, $"no register '{reg}' in {cpu.Language}");
                    row["label"] = reg;
                }
                else from = Va(Text(q, "va")!);
                row["va"] = Hex(from);
                var bytes = new byte[len];
                try
                {
                    mem.Read(from, bytes);
                    row["bytes"] = Convert.ToHexString(bytes).ToLowerInvariant();
                }
                catch (EmulatorFaultException)
                {
                    row["error"] = "unmapped";
                }
                reads.Add(row);
            }
        o["reads"] = reads;
        o["trace"] = new JsonArray([.. trace.Select(t => (JsonNode)new JsonArray(Hex(t.Item1), t.Item2))]);
        return o;
    }

    private static void Trace(Queue<(ulong, string)> trace, int max, ulong pc, string text)
    {
        if (trace.Count == max) trace.Dequeue();
        trace.Enqueue((pc, text));
    }

    /// <summary>The name of a call target in the image (a function, an export, a symbol) and the import a jump thunk there reaches.</summary>
    private static (string? Name, NativeImport? Thunk) Callee(INativeImage image, ulong imageBase, NativeCodeIndex? index, ulong target)
    {
        if (target < imageBase || target - imageBase >= image.SizeOfImage) return (null, null);
        uint rva = (uint)(target - imageBase);
        if (index?.FunctionByStart(rva) is { } f)
            return f.ThunkImport is { } imp ? (NativeCodeIndex.ImportName(imp), imp) : (index.NameAt(rva) ?? f.KnownName, null);
        return (index?.NameAt(rva) ?? image.Exports.FirstOrDefault(e => e.Rva == rva && e.ForwardedTo == null)?.Name
            ?? image.Symbols.FirstOrDefault(s => s.Rva == rva && s.Kind == ImageSymbolKind.Function)?.Name, null);
    }

    /// <summary>The stub value for a callee: by 0x address, by name, or by library!name (".dll" optional, case ignored).</summary>
    private static string? Stub(List<(string Key, string Value)> stubs, string? name, ulong target)
    {
        foreach (var (key, value) in stubs)
        {
            if (key == "*") continue;
            if (key.StartsWith("0x", StringComparison.OrdinalIgnoreCase)
                && ulong.TryParse(key[2..], NumberStyles.HexNumber, CultureInfo.InvariantCulture, out var a) && a == target) return value;
            if (name == null) continue;
            string label = name.Contains('!') ? name[(name.IndexOf('!') + 1)..] : name;
            if (key.Contains('!'))
            {
                if (name.Contains('!') && Module(key) == Module(name) && key[(key.IndexOf('!') + 1)..].Equals(label, StringComparison.OrdinalIgnoreCase)) return value;
            }
            else if (key.Equals(label, StringComparison.OrdinalIgnoreCase)) return value;
        }
        return null;
    }

    private static string Module(string qualified)
    {
        var m = qualified[..qualified.IndexOf('!')].ToLowerInvariant();
        return m.EndsWith(".dll", StringComparison.Ordinal) ? m[..^4] : m;
    }

    private static string? Where(ulong imageBase, NativeCodeIndex? index, ulong va)
    {
        if (index == null || va < imageBase || va - imageBase > uint.MaxValue) return null;
        if (index.FunctionAt((uint)(va - imageBase)) is not { } f) return null;
        ulong off = va - imageBase - f.Start;
        return off == 0 ? f.Name : $"{f.Name}+0x{off:x}";
    }

    /// <summary>A free range for the stack, scratch, the return sentinel and the import addresses, outside the image.</summary>
    private static ulong PickRegion(ulong imageBase, uint imageSize, int ptr, ulong importBytes)
    {
        ulong[] candidates = ptr >= 8 ? [0x7ffe00000000, 0x100000000000, 0x10000000] : [0x7f000000, 0x10000000, 0x30000000, 0x50000000, 0xa0000000];
        ulong need = Region + ImportArea + importBytes + 0x1000;
        foreach (var c in candidates)
            if (c + need <= imageBase || c >= imageBase + imageSize) return c;
        throw new Core.ToolError(Core.ErrorCode.Failed, "no free address range for the emulator's stack");
    }

    // A JSON number whatever CLR type built the node.
    private static double? Number(JsonNode? node) =>
        node is JsonValue ? double.Parse(node.ToJsonString(), CultureInfo.InvariantCulture) : null;

    private static string? Text(JsonNode? node, string name) => node?[name] is JsonValue v && v.TryGetValue<string>(out var s) ? s : null;

    /// <summary>Decimal or 0x hex, a leading minus as two's complement.</summary>
    private static ulong Va(string s)
    {
        var t = s.Trim().ToLowerInvariant();
        bool negative = t.StartsWith('-');
        if (negative) t = t[1..];
        ulong v = t.StartsWith("0x", StringComparison.Ordinal) ? ulong.Parse(t[2..], NumberStyles.HexNumber, CultureInfo.InvariantCulture) : ulong.Parse(t, CultureInfo.InvariantCulture);
        return negative ? (ulong)-(long)v : v;
    }

    private static string Hex(ulong v) => "0x" + v.ToString("x", CultureInfo.InvariantCulture);
}
