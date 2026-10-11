using System.Collections.Concurrent;
using System.Runtime.CompilerServices;
using System.Text;
using AsmArm64;
using NetDecompilerMcp.Native.Code;

namespace NetDecompilerMcp.Native.Calls;

/// <summary>Call sites with their targets and argument values, whatever the instruction set.</summary>
internal interface ICallSites
{
    CallSiteInfo? CallAt(uint rva, CancellationToken ct = default);
    IReadOnlyList<CallSiteInfo> CallsIn(NativeFunction f, CancellationToken ct = default);
    IEnumerable<CallSiteInfo> CallsTo(NativeImport import, int max, CancellationToken ct = default);
}

/// <summary>
/// ARM64 call sites under the AAPCS64: integer and pointer arguments in x0-x7 (then the stack), floating-point ones in
/// v0-v7 (s / d registers, counted apart), recovered by walking back in the call's block to the instruction that sets each
/// register (mov / movz / movk / movn constants, adr / adrp + add addresses and the strings there, loads from known
/// addresses, register copies, earlier call results, stack buffers; fmov, literal loads and conversions for floating
/// point), then through the predecessor blocks (<see cref="Arm64Resolver"/>). Known APIs (<see cref="ApiSignatures"/>)
/// give names, counts and constant decoding; other callees get the registers set before the call. A register call whose
/// target is the result of GetProcAddress / dlsym with a constant name (directly or through a global written once) is a
/// call to that late-bound import. One instance per code index, thread-safe.
/// </summary>
internal sealed partial class Arm64CallSites : ICallSites
{
    private static readonly ConditionalWeakTable<NativeCodeIndex, Arm64CallSites> Table = new();
    private const int Arguments = 8;
    private const int MaxGuessed = 8;

    private sealed record Step(uint Rva, Arm64Instruction Instruction, Insn Facts);

    private readonly NativeCodeIndex _index;
    private readonly Dictionary<uint, NativeImport> _slots = [];
    private readonly ConcurrentDictionary<uint, IReadOnlyList<CallSiteInfo>> _sites = new();

    private Arm64CallSites(NativeCodeIndex index)
    {
        _index = index;
        foreach (var i in index.Image.Imports) _slots.TryAdd(i.SlotRva, i);
    }

    public static bool Supports(NativeCodeIndex index) => index.Support == CodeSupport.Full && index.Image.Arch == NativeArch.Arm64;

    public static Arm64CallSites For(NativeCodeIndex index)
    {
        if (!Supports(index)) throw new NotSupportedException($"ARM64 call sites need an ARM64 code index, not {index.Image.Arch}");
        return Table.GetValue(index, i => new Arm64CallSites(i));
    }

    public CallSiteInfo? CallAt(uint rva, CancellationToken ct = default) =>
        _index.FunctionAt(rva) is { } f ? CallsIn(f, ct).FirstOrDefault(s => s.Rva == rva) : null;

    public IEnumerable<CallSiteInfo> CallsTo(NativeImport import, int max, CancellationToken ct = default)
    {
        int n = 0;
        foreach (var c in _index.Callers(import))
        {
            if (n >= max) yield break;
            ct.ThrowIfCancellationRequested();
            if (CallAt(c.From, ct) is { } s) { n++; yield return s; }
        }
    }

    public IReadOnlyList<CallSiteInfo> CallsIn(NativeFunction f, CancellationToken ct = default)
    {
        EnsureDynamic(ct);
        // while the late-bound imports are being found, sites are computed without them and not kept
        return _dynamic == null ? Analyze(f, ct) : _sites.GetOrAdd(f.Start, _ => Analyze(f, ct));
    }

    private List<CallSiteInfo> Analyze(NativeFunction f, CancellationToken ct)
    {
        var result = new List<CallSiteInfo>();
        var graph = _index.GetGraph(f, ct);
        var dec = new Arm64Decoder(_index.Image, null, Sorted(_index.Image.RelocationRvas), _slots.Keys.ToHashSet());
        foreach (var block in graph.Blocks)
        {
            ct.ThrowIfCancellationRequested();
            var steps = new List<Step>();
            dec.BeginRun(IndexBound.None);
            for (uint a = block.Start; a < block.End; a += 4)
            {
                if (!dec.DecodeMapped(a, out var insn) || insn.Flow == FlowKind.Invalid) break;
                steps.Add(new Step(a, dec.Last, insn));
            }
            for (int k = 0; k < steps.Count; k++)
                if (steps[k].Facts.Flow is FlowKind.Call or FlowKind.IndirectCall || IsTailCall(steps[k], graph))
                    result.Add(Site(f, steps, k, ct));
        }
        result.Sort((a, b) => a.Rva.CompareTo(b.Rva));
        return result;
    }

    private static bool IsTailCall(Step s, FunctionGraph graph) =>
        s.Facts.Flow == FlowKind.Jump && s.Facts.HasTarget && graph.TailCalls.Contains(s.Facts.Target);

    private static uint[] Sorted(IReadOnlyList<uint> values)
    {
        var a = values.ToArray();
        Array.Sort(a);
        return a;
    }

    private CallSiteInfo Site(NativeFunction caller, List<Step> steps, int k, CancellationToken ct)
    {
        var s = steps[k];
        string callee;
        CalleeKind kind;
        NativeImport? import = null;
        DynamicImport? dynamic = null;
        uint? target = null;
        if (s.Facts.HasTarget)
        {
            target = s.Facts.Target;
            var fn = _index.FunctionByStart(s.Facts.Target);
            import = fn?.ThunkImport;
            callee = import != null ? NativeCodeIndex.ImportName(import) : _index.NameAt(s.Facts.Target) ?? $"sub_{s.Facts.Target:X}";
            kind = import != null ? CalleeKind.Import : CalleeKind.Function;
        }
        else if (s.Facts.HasMem && _slots.TryGetValue(s.Facts.MemTarget, out var slot))
        {
            import = slot;
            callee = NativeCodeIndex.ImportName(slot);
            kind = CalleeKind.Import;
        }
        else if (Register(caller, s, ct) is { } resolved)
        {
            (callee, kind, import, target, dynamic) = resolved;
        }
        else
        {
            callee = s.Instruction.ToString();
            kind = CalleeKind.Indirect;
        }
        var signature = ApiSignatures.Find(import?.Name ?? dynamic?.Name ?? callee);
        var args = new List<CallArgument>();
        int ints = 0, floats = 0;
        if (signature != null)
            for (int i = 0; i < Math.Min(signature.Params.Count, 2 * Arguments); i++)
            {
                var p = signature.Params[i];
                if (p.IsFloat)
                {
                    int v = floats++;
                    var width = p.Type == ApiParamType.Float ? "s" : "d";
                    args.Add(v >= Arguments ? new CallArgument(i, p.Name, p.TypeName, "stack", ArgKind.Unknown, null, null, "?", "passed on the stack")
                        : Float(caller, steps, k, i, v, width, p, ct));
                    continue;
                }
                int r = ints++;
                args.Add(r >= Arguments ? new CallArgument(i, p.Name, p.TypeName, "stack", ArgKind.Unknown, null, null, "?", "passed on the stack")
                    : Integer(caller, steps, k, i, r, p, ct));
            }
        else
        {
            for (int r = GuessedCount(steps, k); ints < r; ints++) args.Add(Integer(caller, steps, k, ints, ints, null, ct));
            foreach (var (v, width) in GuessedFloats(steps, k)) args.Add(Float(caller, steps, k, args.Count, v, width, null, ct));
        }
        return new CallSiteInfo(s.Rva, caller, callee, kind, import, target, dynamic, signature, signature == null, args, s.Facts.Flow == FlowKind.Jump);
    }

    /// <summary>An integer argument in x<paramref name="reg"/>: from the call's block, else through the predecessors.</summary>
    private CallArgument Integer(NativeFunction caller, List<Step> steps, int k, int index, int reg, ApiParam? p, CancellationToken ct)
    {
        var resolved = Resolve(steps, k, reg, p);
        if (resolved.Item1 == ArgKind.Unknown && Across(caller, steps[k].Rva, reg, p, ct) is { } across) resolved = across;
        var (argKind, value, rva, text, derivation) = resolved;
        return new CallArgument(index, p?.Name, p?.TypeName, "x" + reg, argKind, value, rva, text, derivation);
    }

    /// <summary>The value of x<paramref name="reg"/> before the call, through the function's blocks; null when it is not known either.</summary>
    private (ArgKind, ulong?, uint?, string, string)? Across(NativeFunction caller, uint site, int reg, ApiParam? p, CancellationToken ct)
    {
        var trace = Arm64Trace.For(_index);
        var code = trace.Code(caller, ct);
        var (b, i) = code.Position(site);
        if (b < 0) return null;
        var v = new Arm64Resolver(trace, code) { Budget = 1500 }.Before(A64Loc.Reg(reg), b, i);
        return Value(v, p, code);
    }

    private (ArgKind, ulong?, uint?, string, string)? Value(A64Val v, ApiParam? p, A64Function code)
    {
        switch (v.Kind)
        {
            case A64Kind.Const: return Number(v.Num, p, v.Why);
            case A64Kind.Addr: return Address(v.Rva, p, v.Why);
            case A64Kind.StackAddr: return (ArgKind.Address, null, null, "&local", v.Why);
            case A64Kind.Import when _slots.TryGetValue(v.Rva, out var imp): return (ArgKind.Name, null, v.Rva, NativeCodeIndex.ImportName(imp), v.Why);
            case A64Kind.Global when _dynamic?.ByGlobal.GetValueOrDefault(v.Rva) is { } dyn: return (ArgKind.Name, null, v.Rva, dyn.FullName, v.Why);
            case A64Kind.Global: return (ArgKind.Global, null, v.Rva, $"[{_index.NameAt(v.Rva) ?? Va(v.Rva)}]", v.Why);
            case A64Kind.Result:
            {
                var (b, i) = code.Position(v.Rva);
                var name = b >= 0 && code.Blocks[b][i] is var at ? CalleeOf(new Step(at.Rva, at.I, at.Facts)) : Va(v.Rva);
                return (ArgKind.Result, null, null, $"<result of {name}>", v.Why);
            }
            case A64Kind.Merge when v.Inputs is { } inputs:
                return (ArgKind.Unknown, null, null, "?", $"differs between paths: {string.Join(" / ", inputs.Take(4).Select(Short))}{(inputs.Length > 4 ? " / ..." : "")}");
            case A64Kind.Incoming:
                return (ArgKind.Unknown, null, null, "?", $"incoming {A64Function.Name(v.Loc, null)}" + (A64Function.ParameterIndex(v.Loc) is var n and >= 0 ? $" (parameter {n + 1})" : ""));
            default: return null;
        }
    }

    private string Short(A64Val v) => v.Kind switch
    {
        A64Kind.Const => v.Num < 10 ? v.Num.ToString(System.Globalization.CultureInfo.InvariantCulture) : $"0x{v.Num:X}",
        A64Kind.Addr => _index.NameAt(v.Rva) ?? Va(v.Rva),
        A64Kind.Incoming => A64Function.Name(v.Loc, null),
        _ => v.Kind.ToString().ToLowerInvariant(),
    };

    /// <summary>The target of blr / br through a register: an import slot, a function address, or a late-bound import (directly or through its global).</summary>
    private (string Callee, CalleeKind Kind, NativeImport? Import, uint? Target, DynamicImport? Dynamic)? Register(NativeFunction caller, Step s, CancellationToken ct)
    {
        if (s.Facts.Flow is not (FlowKind.IndirectCall or FlowKind.IndirectJump) || A64Function.Gpr(s.Instruction, 0) is not (var reg and >= 0 and < 31)) return null;
        var trace = Arm64Trace.For(_index);
        var code = trace.Code(caller, ct);
        var (b, i) = code.Position(s.Rva);
        if (b < 0) return null;
        var v = new Arm64Resolver(trace, code) { Budget = 1500 }.Before(A64Loc.Reg(reg), b, i);
        switch (v.Kind)
        {
            case A64Kind.Import when _slots.TryGetValue(v.Rva, out var imp):
                return (NativeCodeIndex.ImportName(imp), CalleeKind.Import, imp, imp.SlotRva, null);
            case A64Kind.Addr when _index.FunctionByStart(v.Rva) is { } f:
                return f.ThunkImport is { } thunk ? (NativeCodeIndex.ImportName(thunk), CalleeKind.Import, thunk, v.Rva, null)
                    : (_index.NameAt(v.Rva) ?? $"sub_{v.Rva:X}", CalleeKind.Function, null, v.Rva, null);
            case A64Kind.Result when _dynamic?.BySite.GetValueOrDefault(v.Rva) is { } dyn:
                return (dyn.FullName, CalleeKind.Dynamic, null, dyn.PointerGlobal, dyn);
            case A64Kind.Global when _dynamic?.ByGlobal.GetValueOrDefault(v.Rva) is { } dyn:
                return (dyn.FullName, CalleeKind.Dynamic, null, dyn.PointerGlobal, dyn);
            default:
                return null;
        }
    }

    /// <summary>Without a signature: the argument registers set in the block before the call, up to the highest one.</summary>
    private static int GuessedCount(List<Step> steps, int k)
    {
        int highest = -1;
        for (int j = k - 1; j >= 0; j--)
        {
            if (steps[j].Facts.Flow is FlowKind.Call or FlowKind.IndirectCall) break;
            int r = Written(steps[j].Instruction);
            if (r is >= 0 and < MaxGuessed && r > highest) highest = r;
        }
        return highest + 1;
    }

    private static int Written(in Arm64Instruction i)
    {
        if (Arm64Extensions.IsBranch(i.Id) || i.OperandCount == 0 || i.GetOperand(0).Kind != Arm64OperandKind.Register) return -1;
        var op = i.GetOperand(0);
        if ((op.Flags & Arm64OperandFlags.Write) == 0) return -1;
        return Register((Arm64RegisterOperand)op);
    }

    private static int Register(Arm64RegisterOperand op) =>
        op.Value.Kind is Arm64RegisterKind.X or Arm64RegisterKind.W && !op.IsZeroRegister && op.Value.Index < 31 ? op.Value.Index : -1;

    private string Va(uint rva) => NativeAddress.Va(_index.Image, rva);

    /// <summary>The value register <paramref name="reg"/> holds before step <paramref name="k"/>.</summary>
    private (ArgKind, ulong?, uint?, string, string) Resolve(List<Step> steps, int k, int reg, ApiParam? p, int depth = 0)
    {
        ulong movk = 0, movkMask = 0;
        for (int j = k - 1; j >= 0 && depth < 8; j--)
        {
            var s = steps[j];
            var i = s.Instruction;
            string at = $"{Text(i)} @{Va(s.Rva)}";
            if (s.Facts.Flow is FlowKind.Call or FlowKind.IndirectCall)
            {
                if (reg != 0) return (ArgKind.Unknown, null, null, "?", $"clobbered by the call {at}");
                return (ArgKind.Result, null, null, $"<result of {CalleeOf(steps[j])}>", at);
            }
            if (Written(i) != reg && !(i.Mnemonic is Arm64Mnemonic.LDP && i.OperandCount > 1 && i.GetOperand(1).Kind == Arm64OperandKind.Register
                                        && Register((Arm64RegisterOperand)i.GetOperand(1)) == reg)) continue;
            switch (i.Mnemonic)
            {
                case Arm64Mnemonic.MOV when i.OperandCount >= 2 && i.GetOperand(1).Kind == Arm64OperandKind.Immediate:
                {
                    ulong v = (ulong)((Arm64ImmediateOperand)i.GetOperand(1)).Value;
                    if (IsW(i)) v &= 0xFFFFFFFF;
                    v = v & ~movkMask | movk;
                    return Number(v, p, at);
                }
                case Arm64Mnemonic.MOVK when i.OperandCount >= 2 && i.GetOperand(1).Kind == Arm64OperandKind.Immediate:
                {
                    int shift = i.OperandCount > 2 && i.GetOperand(2).Kind == Arm64OperandKind.Shift ? ((Arm64ShiftOperand)i.GetOperand(2)).Amount : 0;
                    ulong bits = 0xFFFFUL << shift;
                    if ((movkMask & bits) == 0)
                    {
                        movk |= ((ulong)((Arm64ImmediateOperand)i.GetOperand(1)).Value << shift) & bits;
                        movkMask |= bits;
                    }
                    continue;
                }
                case Arm64Mnemonic.MOV when i.OperandCount >= 2 && i.GetOperand(1).Kind == Arm64OperandKind.Register:
                {
                    var src = (Arm64RegisterOperand)i.GetOperand(1);
                    if (src.IsZeroRegister) return Number(0, p, at);
                    if (src.Value.Kind == Arm64RegisterKind.SP) return (ArgKind.Address, null, null, "&local", at);
                    if (movkMask != 0) break;
                    var (kind, value, rva, text, derivation) = Resolve(steps, j, Register(src), p, depth + 1);
                    return (kind, value, rva, text, $"{at}; {derivation}");
                }
                case Arm64Mnemonic.ADD or Arm64Mnemonic.SUB when i.OperandCount > 1 && i.GetOperand(1).Kind == Arm64OperandKind.Register
                                                               && ((Arm64RegisterOperand)i.GetOperand(1)).Value.Kind == Arm64RegisterKind.SP:
                    return (ArgKind.Address, null, null, "&local", at);
            }
            if (movkMask != 0) break;
            if (s.Facts.HasImm && !s.Facts.HasMem) return Address(s.Facts.ImmTarget, p, at);
            if (s.Facts.HasMem && i.Mnemonic is Arm64Mnemonic.LDR or Arm64Mnemonic.LDUR)
            {
                if (_slots.TryGetValue(s.Facts.MemTarget, out var imp)) return (ArgKind.Name, null, s.Facts.MemTarget, NativeCodeIndex.ImportName(imp), at);
                var name = _index.NameAt(s.Facts.MemTarget);
                return (ArgKind.Global, null, s.Facts.MemTarget, $"[{name ?? Va(s.Facts.MemTarget)}]", at);
            }
            return (ArgKind.Unknown, null, null, "?", $"set by {at}");
        }
        if (movkMask != 0) return Number(movk, p, "movk");
        return (ArgKind.Unknown, null, null, "?", "set before the block");
    }

    private string CalleeOf(Step s)
    {
        if (s.Facts.HasTarget)
            return _index.FunctionByStart(s.Facts.Target) is { ThunkImport: { } imp } ? imp.Name ?? NativeCodeIndex.ImportName(imp) : _index.NameAt(s.Facts.Target) ?? Va(s.Facts.Target);
        if (s.Facts.HasMem && _slots.TryGetValue(s.Facts.MemTarget, out var slot)) return slot.Name ?? NativeCodeIndex.ImportName(slot);
        return s.Instruction.ToString();
    }

    private static bool IsW(in Arm64Instruction i) =>
        i.GetOperand(0).Kind == Arm64OperandKind.Register && ((Arm64RegisterOperand)i.GetOperand(0)).Value.Kind == Arm64RegisterKind.W;

    private static string Text(in Arm64Instruction i) => i.ToString();

    private static (ArgKind, ulong?, uint?, string, string) Number(ulong v, ApiParam? p, string at)
    {
        string text = p?.Type switch
        {
            ApiParamType.Enum => p.Enum!.Describe(v) ?? Hex(v),
            ApiParamType.Bool => v switch { 0 => "false", 1 => "true", _ => Hex(v) },
            ApiParamType.Pointer or ApiParamType.AnsiString or ApiParamType.WideString or ApiParamType.AnsiFormat or ApiParamType.WideFormat
                or ApiParamType.Handle or ApiParamType.Module or ApiParamType.Guid => v == 0 ? "NULL" : Hex(v),
            ApiParamType.Int => ((long)v is var l and < 0 ? l : (int)(uint)v).ToString(System.Globalization.CultureInfo.InvariantCulture),
            ApiParamType.Hex => Hex(v),
            _ => v < 0x10000 ? v.ToString(System.Globalization.CultureInfo.InvariantCulture) : Hex(v),
        };
        return (ArgKind.Immediate, v, null, text, at);
    }

    private static string Hex(ulong n) => n < 10 ? n.ToString(System.Globalization.CultureInfo.InvariantCulture) : $"0x{n:X}";

    private (ArgKind, ulong?, uint?, string, string) Address(uint rva, ApiParam? p, string at)
    {
        bool wide = p?.Type is ApiParamType.WideString or ApiParamType.WideFormat;
        if (_index.StringAt(rva) is { } s && (s.Encoding == StringEncoding.Utf16) == wide)
            return (ArgKind.String, null, rva, Quote(_index.ReadString(s, 200), wide), at);
        if (_index.CfStringAt(rva) is { } cf) return (ArgKind.String, null, rva, "@" + Quote(_index.ReadString(cf, 200), false), at);
        if ((p?.IsString == true || p?.Type == ApiParamType.ProcName) && ReadText(rva, wide) is { } text) return (ArgKind.String, null, rva, Quote(text, wide), at);
        if (_index.NameAt(rva) is { } name) return (ArgKind.Name, null, rva, name, at);
        return (ArgKind.Address, null, rva, Va(rva), at);
    }

    /// <summary>A NUL-terminated string of printable characters at <paramref name="rva"/> (short ones too: the parameter says it is a string), or null.</summary>
    private string? ReadText(uint rva, bool wide, int max = 1024)
    {
        var buffer = new byte[(max + 1) * (wide ? 2 : 1)];
        int n = _index.Image.Read(rva, buffer);
        var sb = new StringBuilder();
        for (int i = 0; wide ? i + 1 < n : i < n; i += wide ? 2 : 1)
        {
            char c = wide ? (char)(buffer[i] | buffer[i + 1] << 8) : (char)buffer[i];
            if (c == 0) return sb.ToString();
            if (c < ' ' && c is not ('\t' or '\r' or '\n')) return null;
            if (!wide && c > 0x7E) return null;
            sb.Append(c);
        }
        return null;
    }

    private static string Quote(string text, bool wide)
    {
        var sb = new StringBuilder(wide ? "L\"" : "\"");
        foreach (char c in text.Length > 120 ? text[..120] : text)
            sb.Append(c switch { '\\' => "\\\\", '"' => "\\\"", '\n' => "\\n", '\r' => "\\r", '\t' => "\\t", _ => c < ' ' ? $"\\x{(int)c:X2}" : c.ToString() });
        if (text.Length > 120) sb.Append("...");
        return sb.Append('"').ToString();
    }
}
