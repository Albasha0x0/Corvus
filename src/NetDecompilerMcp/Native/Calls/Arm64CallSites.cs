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
/// ARM64 call sites under the AAPCS64: integer and pointer arguments in x0-x7, recovered by walking back in the call's
/// block to the instruction that sets each register (mov / movz / movk / movn constants, adr / adrp + add addresses and
/// the strings there, loads from known addresses, register copies, earlier call results, stack buffers). Known APIs
/// (<see cref="ApiSignatures"/>) give names, counts and constant decoding; other callees get the registers set before
/// the call. Floating-point arguments (v0-v7) are not recovered. One instance per code index, thread-safe.
/// </summary>
internal sealed class Arm64CallSites : ICallSites
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

    public IReadOnlyList<CallSiteInfo> CallsIn(NativeFunction f, CancellationToken ct = default) => _sites.GetOrAdd(f.Start, _ => Analyze(f, ct));

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
                    result.Add(Site(f, steps, k));
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

    private CallSiteInfo Site(NativeFunction caller, List<Step> steps, int k)
    {
        var s = steps[k];
        string callee;
        CalleeKind kind;
        NativeImport? import = null;
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
        else
        {
            callee = s.Instruction.ToString();
            kind = CalleeKind.Indirect;
        }
        var signature = ApiSignatures.Find(import?.Name ?? callee);
        var args = new List<CallArgument>();
        int count = signature != null ? Math.Min(signature.Params.Count, Arguments) : GuessedCount(steps, k);
        for (int i = 0; i < count; i++)
        {
            var p = signature != null && i < signature.Params.Count ? signature.Params[i] : null;
            if (p is { IsFloat: true })
            {
                args.Add(new CallArgument(i, p.Name, p.TypeName, "v" + i, ArgKind.Unknown, null, null, "?", "floating-point arguments are not recovered"));
                continue;
            }
            var (argKind, value, rva, text, derivation) = Resolve(steps, k, i, p);
            args.Add(new CallArgument(i, p?.Name, p?.TypeName, "x" + i, argKind, value, rva, text, derivation));
        }
        return new CallSiteInfo(s.Rva, caller, callee, kind, import, target, null, signature, signature == null, args, s.Facts.Flow == FlowKind.Jump);
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
        if (p?.IsString == true && ReadText(rva, wide) is { } text) return (ArgKind.String, null, rva, Quote(text, wide), at);
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
