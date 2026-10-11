using System.Collections.Concurrent;
using System.Globalization;
using System.Runtime.CompilerServices;
using System.Text;
using NetDecompilerMcp.Native.Code;

namespace NetDecompilerMcp.Native.Calls;

/// <summary>
/// 32-bit ARM call sites under the AAPCS: arguments in r0-r3, then 4-byte stack slots at the call's sp, each recovered by
/// the backward resolver (constants, MOVW / MOVT, literal pools, PC-relative addresses and the strings there, loads from
/// known addresses, stack buffers, earlier call results). Known APIs (<see cref="ApiSignatures"/>) give names, counts and
/// constant decoding; other callees get the registers set before the call. Floating-point arguments are not recovered.
/// One instance per code index, thread-safe.
/// </summary>
internal sealed class Arm32CallSites : ICallSites
{
    private static readonly ConditionalWeakTable<NativeCodeIndex, Arm32CallSites> Table = new();
    private const int MaxArguments = 8;

    private readonly NativeCodeIndex _index;
    private readonly ConcurrentDictionary<uint, IReadOnlyList<CallSiteInfo>> _sites = new();

    private Arm32CallSites(NativeCodeIndex index) => _index = index;

    public static bool Supports(NativeCodeIndex index) => Arm32Trace.Supports(index);

    public static Arm32CallSites For(NativeCodeIndex index)
    {
        if (!Supports(index)) throw new NotSupportedException($"ARM32 call sites need a 32-bit ARM code index, not {index.Image.Arch}");
        return Table.GetValue(index, i => new Arm32CallSites(i));
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
        var trace = Arm32Trace.For(_index);
        var code = trace.Code(f, ct);
        var result = new List<CallSiteInfo>();
        for (int b = 0; b < code.Blocks.Length; b++)
        {
            ct.ThrowIfCancellationRequested();
            var steps = code.Blocks[b];
            for (int k = 0; k < steps.Length; k++)
                if (steps[k].Facts.Flow is FlowKind.Call or FlowKind.IndirectCall || IsTailCall(steps[k], code.Graph))
                    result.Add(Site(trace, code, b, k));
        }
        result.Sort((a, b) => a.Rva.CompareTo(b.Rva));
        return result;
    }

    private static bool IsTailCall(A32Step s, FunctionGraph graph) =>
        s.Facts.Flow == FlowKind.Jump && s.Facts.HasTarget && graph.TailCalls.Contains(s.Facts.Target);

    private CallSiteInfo Site(Arm32Trace trace, A32Function code, int b, int k)
    {
        var s = code.Blocks[b][k];
        string callee;
        CalleeKind kind;
        NativeImport? import = null;
        uint? target = null;
        if (s.Facts.HasTarget)
        {
            target = s.Facts.Target;
            import = _index.FunctionByStart(s.Facts.Target)?.ThunkImport;
            callee = import != null ? NativeCodeIndex.ImportName(import) : _index.NameAt(s.Facts.Target) ?? $"sub_{s.Facts.Target:X}";
            kind = import != null ? CalleeKind.Import : CalleeKind.Function;
        }
        else if (s.Facts.HasMem && trace.ImportAt(s.Facts.MemTarget) is { } slot)
        {
            import = slot;
            callee = NativeCodeIndex.ImportName(slot);
            kind = CalleeKind.Import;
        }
        else
        {
            callee = s.Text;
            kind = CalleeKind.Indirect;
        }
        var signature = ApiSignatures.Find(import?.Name ?? callee);
        var resolver = new Arm32Resolver(trace, code) { Budget = 3000 };
        var args = new List<CallArgument>();
        int count = signature != null ? Math.Min(signature.Params.Count, MaxArguments) : GuessedCount(code.Blocks[b], k);
        for (int i = 0; i < count; i++)
        {
            var p = signature != null && i < signature.Params.Count ? signature.Params[i] : null;
            var entry = A32Function.ParameterEntry(i);
            string location = A32Function.Name(entry, null);
            if (p is { IsFloat: true })
            {
                args.Add(new CallArgument(i, p.Name, p.TypeName, location, ArgKind.Unknown, null, null, "?", "floating-point arguments are not recovered"));
                continue;
            }
            A32Val v = entry.IsSlot
                ? s.Sp is { } sp ? resolver.Before(A32Loc.Slot(sp + entry.Value), b, k) : A32Val.Unknown("sp is not known at the call")
                : resolver.Before(entry, b, k);
            var (argKind, value, rva, text) = Format(trace, code, v, p);
            args.Add(new CallArgument(i, p?.Name, p?.TypeName, location, argKind, value, rva, text, v.Why.Length > 0 ? v.Why : Describe(v)));
        }
        return new CallSiteInfo(s.Rva, code.Function, callee, kind, import, target, null, signature, signature == null, args, s.Facts.Flow == FlowKind.Jump);
    }

    /// <summary>Without a signature: the argument registers set in the block before the call, up to the highest one.</summary>
    private static int GuessedCount(A32Step[] steps, int k)
    {
        int highest = -1;
        for (int j = k - 1; j >= 0; j--)
        {
            if (A32Function.IsCall(steps[j].I)) break;
            for (int r = 3; r > highest; r--)
                if ((steps[j].I.Writes & (1 << r)) != 0) { highest = r; break; }
        }
        return highest + 1;
    }

    private static string Describe(A32Val v) => v.Kind switch
    {
        A64Kind.Incoming => $"incoming {A32Function.Name(v.Loc, null)}",
        A64Kind.Merge => $"{v.Inputs?.Length} values meet",
        _ => v.Kind.ToString().ToLowerInvariant(),
    };

    private (ArgKind, ulong?, uint?, string) Format(Arm32Trace trace, A32Function code, A32Val v, ApiParam? p) => v.Kind switch
    {
        A64Kind.Const => (ArgKind.Immediate, v.Num, null, Number(v.Num, p)),
        A64Kind.Addr => Address(v.Rva, p),
        A64Kind.StackAddr => (ArgKind.Address, null, null, "&local"),
        A64Kind.Import => (ArgKind.Name, null, v.Rva, NativeCodeIndex.ImportName(trace.ImportAt(v.Rva)!)),
        A64Kind.Global => (ArgKind.Global, null, v.Rva, $"[{_index.NameAt(v.Rva) ?? trace.Va(v.Rva)}]"),
        A64Kind.Result => (ArgKind.Result, null, null, $"<result of {CalleeOf(trace, code, v.Rva)}>"),
        _ => (ArgKind.Unknown, null, null, "?"),
    };

    /// <summary>The callee of the call at <paramref name="site"/> by its instruction alone (no argument analysis: that would recurse).</summary>
    private string CalleeOf(Arm32Trace trace, A32Function code, uint site)
    {
        var (b, k) = code.Position(site);
        if (b < 0) return trace.Va(site);
        var f = code.Blocks[b][k].Facts;
        if (f.HasTarget)
            return _index.FunctionByStart(f.Target) is { ThunkImport: { } imp } ? NativeCodeIndex.ImportName(imp) : _index.NameAt(f.Target) ?? $"sub_{f.Target:X}";
        if (f.HasMem && trace.ImportAt(f.MemTarget) is { } slot) return NativeCodeIndex.ImportName(slot);
        return code.Blocks[b][k].Text;
    }

    private static string Number(ulong v, ApiParam? p) => p?.Type switch
    {
        ApiParamType.Enum => p.Enum!.Describe(v) ?? Hex(v),
        ApiParamType.Bool => v switch { 0 => "false", 1 => "true", _ => Hex(v) },
        ApiParamType.Pointer or ApiParamType.AnsiString or ApiParamType.WideString or ApiParamType.AnsiFormat or ApiParamType.WideFormat
            or ApiParamType.Handle or ApiParamType.Module or ApiParamType.Guid => v == 0 ? "NULL" : Hex(v),
        ApiParamType.Int => ((int)(uint)v).ToString(CultureInfo.InvariantCulture),
        ApiParamType.Hex => Hex(v),
        _ => v < 0x10000 ? v.ToString(CultureInfo.InvariantCulture) : Hex(v),
    };

    private static string Hex(ulong n) => n < 10 ? n.ToString(CultureInfo.InvariantCulture) : $"0x{n:X}";

    private (ArgKind, ulong?, uint?, string) Address(uint rva, ApiParam? p)
    {
        bool wide = p?.Type is ApiParamType.WideString or ApiParamType.WideFormat;
        if (_index.StringAt(rva) is { } s && (s.Encoding == StringEncoding.Utf16) == wide)
            return (ArgKind.String, null, rva, Arm32Trace.Quote(_index.ReadString(s, 200), wide));
        if (p?.IsString == true && ReadText(rva, wide) is { } text) return (ArgKind.String, null, rva, Arm32Trace.Quote(text, wide));
        if (_index.NameAt(rva) is { } name) return (ArgKind.Name, null, rva, name);
        return (ArgKind.Address, null, rva, NativeAddress.Va(_index.Image, rva));
    }

    /// <summary>A NUL-terminated string of printable characters at <paramref name="rva"/>, or null.</summary>
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
}
