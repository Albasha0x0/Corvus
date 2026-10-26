using System.Diagnostics;
using System.Globalization;
using System.Text.Json.Nodes;
using Corvus.Native.Calls;
using Corvus.Native.Code;

namespace Corvus.Native.Emulation;

/// <summary>
/// The built-in emulator's run: the request and result fields of the Ghidra worker's emulate command, so both render
/// through one report. Memory is the image (copy on write), a private stack and scratch region, and the caller's
/// writes; each import slot holds a distinct address outside the image, so a call through it is named by its import.
/// </summary>
public static class IntegerEmulation
{
    // Stack in the low half of the region, scratch buffers in the high half; the return sentinel just above it.
    private const ulong Region = 0x200000, StackSize = 0x100000, ImportArea = 0x10000;
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

    /// <summary>
    /// Runs one request (start, args, registers, memory, stops, stubs, reads, max_instructions, seconds, trace) and
    /// returns the worker's result fields with "engine": "ours". Bad input is an InvalidArgument or LimitExceeded error.
    /// </summary>
    public static JsonObject Run(INativeImage image, ulong imageBase, NativeCodeIndex? index, JsonObject request, CancellationToken ct)
    {
        var cpu = Cpu(image);
        int ptr = cpu.PointerSize;
        var imports = image.Imports.Where(i => i.SlotRva != 0 && i.SlotRva + (uint)ptr <= image.SizeOfImage).GroupBy(i => i.SlotRva).Select(g => g.First()).ToList();
        ulong regionBase = PickRegion(imageBase, image.SizeOfImage, ptr, (ulong)imports.Count * 16);
        var mem = new EmulatorMemory(image, imageBase, regionBase, Region);
        ulong sentinel = regionBase + Region, importBase = regionBase + Region + ImportArea;
        var byAddress = new Dictionary<ulong, NativeImport>();
        for (int k = 0; k < imports.Count; k++)
        {
            ulong at = importBase + (ulong)k * 16;
            byAddress[at] = imports[k];
            mem.WriteUInt(imageBase + imports[k].SlotRva, at, ptr);
        }

        ulong start = Va(Text(request, "start")!);
        long maxIns = (long)(Number(request["max_instructions"]) ?? 1_000_000);
        double seconds = Number(request["seconds"]) ?? 10;
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

        mem.Tracking = true;
        var clock = Stopwatch.StartNew();
        long executed = 0;
        string? stop = null, detail = null;
        ulong? stoppedAt = null;
        var trace = new Queue<(ulong, string)>();
        var calls = new JsonArray();
        int callCount = 0;
        ulong lastSite = start;

        void Record(ulong site, ulong target, string? name, string action, ulong? value)
        {
            if (callCount++ >= MaxCalls) return;
            calls.Add(new JsonObject
            {
                ["site"] = Hex(site), ["target"] = Hex(target), ["name"] = name, ["action"] = action, ["value"] = value is { } v ? Hex(v) : null,
            });
        }

        int Purge(NativeImport? import) => ptr == 4 && image.Format == ImageFormat.Pe && import != null ? X86ImportArity.Pops(import, image.Path) ?? 0 : 0;

        while (true)
        {
            ulong pc = cpu.Pc;
            if (pc == sentinel) { stop = "returned"; break; }
            if (byAddress.TryGetValue(pc, out var reached))
            {
                // Execution reached an import through a slot (a jump stub, a register call): its stub answers it.
                string name = NativeCodeIndex.ImportName(reached);
                string? named = Stub(stubs, name, pc), value = named ?? anyStub;
                if (value == null)
                {
                    stop = "unmodelled_call";
                    stoppedAt = lastSite;
                    detail = $"call at 0x{lastSite:x} to {name} (outside the image): stub it (stubs=NAME=VALUE, or *=VALUE for every call)";
                    break;
                }
                ulong v = Va(value);
                Record(lastSite, pc, name, named != null ? "stub" : "skip", v);
                cpu.ReturnFromCall(mem, v, Purge(reached));
                continue;
            }
            if (executed > 0 && stops.Contains(pc)) { stop = "stop_address"; break; }
            if (executed >= maxIns) { stop = "instruction_budget"; break; }
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
                stop = "memory_fault";
                stoppedAt = pc;
                detail = f.Message;
                if (traceMax > 0) Trace(trace, traceMax, pc, cpu.LastText);
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
            if (!step.IsCall) continue;
            ulong target = cpu.Pc;
            if (byAddress.ContainsKey(target)) continue;
            var (calleeName, thunk) = Callee(image, imageBase, index, target);
            string? stubValue = Stub(stubs, calleeName, target);
            // A call to the next instruction reads its own address and is never skipped.
            string? anyValue = stubValue == null && target != step.FallThrough ? anyStub : null;
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
                detail = $"call at 0x{step.Site:x} to {calleeName} (outside the image): stub it (stubs=NAME=VALUE, or *=VALUE for every call)";
                break;
            }
            if (!mem.Mapped(target))
            {
                stop = "unmodelled_call";
                stoppedAt = step.Site;
                detail = $"call at 0x{step.Site:x} to 0x{target:x} (unmapped): stub it (stubs=NAME=VALUE, or *=VALUE for every call)";
                break;
            }
            Record(step.Site, target, calleeName, "into", null);
        }
        mem.Tracking = false;

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
            ["seconds"] = Math.Round(clock.Elapsed.TotalSeconds, 3),
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
        o["calls"] = calls;
        o["call_count"] = callCount;
        o["scratch"] = scratchOut;
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

        var reads = new JsonArray();
        if (request["reads"] is JsonArray asked)
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
