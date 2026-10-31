using System.Text.RegularExpressions;
using Corvus.Native;
using Corvus.Native.Code;

namespace Corvus.Tools;

/// <summary>Finds runtime-support shapes in an x86 listing and names each as one comment line; off unless collapse=runtime.</summary>
internal static partial class RuntimeCollapse
{
    internal const string Runtime = "runtime";

    // Instructions searched after a shift by 12 for the card-table update.
    private const int BarrierWindow = 8;

    // Setup instructions allowed between a guard branch and its initializer call.
    private const int LazyWindow = 4;

    /// <summary>The collapse mode, ignoring case: null, empty or "none" is off, "runtime" is on; anything else is rejected.</summary>
    internal static bool Parse(string? mode) => mode?.Trim().ToLowerInvariant() switch
    {
        null or "" or "none" => false,
        Runtime => true,
        _ => throw new ArgumentException($"disassemble collapse '{mode}' is not supported; use 'none' or '{Runtime}'."),
    };

    /// <summary>Throws when collapse=runtime cannot apply: an external engine, a WebAssembly image or a non-x86 architecture.</summary>
    internal static void RequireEngine(bool external, bool wasm, NativeArch arch)
    {
        if (external || wasm || arch is not (NativeArch.X86 or NativeArch.X64))
            throw new ArgumentException("disassemble collapse=runtime applies to x86 and x64 images on the built-in engine only.");
    }

    /// <summary>Throws when the listing is a linear range, which collapse=runtime does not cover.</summary>
    internal static void RequireFunction(bool inFunction)
    {
        if (!inFunction) throw new ArgumentException("disassemble collapse=runtime applies to a function listing, not to a range from an address.");
    }

    /// <summary>One collapsed run: the first instruction, the end of the run, the instruction count and the comment line.</summary>
    internal sealed record Run(uint Start, uint End, int Count, string Note);

    /// <summary>The non-overlapping runs found in <paramref name="lines"/>, keyed by start address; empty when none match. <paramref name="calls"/> names call targets that the decoder text does not.</summary>
    internal static Dictionary<uint, Run> Find(IReadOnlyList<DisasmLine> lines, Func<uint, string> va, IReadOnlyDictionary<uint, string>? calls = null)
    {
        var runs = new Dictionary<uint, Run>();
        for (int i = 0; i < lines.Count;)
        {
            var run = Barrier(lines, i, va) ?? Lazy(lines, i, va) ?? Init(lines, i, va, calls);
            if (run == null || !Contiguous(lines, i, run.Count)) { i++; continue; }
            runs[lines[i].Rva] = run;
            i += run.Count;
        }
        return runs;
    }

    // A gap between blocks inside a run would be swallowed with no gap line.
    private static bool Contiguous(IReadOnlyList<DisasmLine> lines, int from, int count)
    {
        for (int k = from + 1; k < from + count; k++)
            if (lines[k].Rva != lines[k - 1].Rva + (uint)lines[k - 1].Facts.Length) return false;
        return true;
    }

    private static string Mnemonic(DisasmLine l)
    {
        var t = l.Text.AsSpan().TrimStart();
        if (t.StartsWith("lock ")) t = t[5..].TrimStart();
        int s = t.IndexOf(' ');
        return (s < 0 ? t : t[..s]).ToString().ToLowerInvariant();
    }

    private static bool IsLockCmpxchg(DisasmLine l) => l.Text.TrimStart().StartsWith("lock cmpxchg", StringComparison.OrdinalIgnoreCase);

    // Lower case, no blanks around commas, so checks ignore engine spacing.
    private static string Normal(DisasmLine l) => Spaces().Replace(l.Text.Trim().ToLowerInvariant(), m => m.Value.Contains(',') ? "," : " ");

    private static Run Make(IReadOnlyList<DisasmLine> lines, int from, int count, string what, Func<uint, string> va)
    {
        var last = lines[from + count - 1];
        uint end = last.Rva + (uint)last.Facts.Length;
        return new Run(lines[from].Rva, end, count, $"collapsed: {what} ({ToolSupport.Plural(count, "instruction")}, {va(lines[from].Rva)}-{va(end)})");
    }

    // Shift by 12, a bit-set or locked exchange, and a closing backward branch.
    private static Run? Barrier(IReadOnlyList<DisasmLine> lines, int i, Func<uint, string> va)
    {
        if (!ShiftBy12().IsMatch(Normal(lines[i]))) return null;
        int last = -1;
        for (int k = i + 1; k < lines.Count && k <= i + BarrierWindow; k++)
        {
            var flow = lines[k].Facts.Flow;
            if (flow is FlowKind.Call or FlowKind.IndirectCall or FlowKind.Return) break;
            if (Mnemonic(lines[k]) == "bts" || IsLockCmpxchg(lines[k])) last = k;
        }
        if (last < 0 || last + 1 >= lines.Count) return null;
        var close = lines[last + 1];
        uint start = lines[i].Rva, tail = lines[last].Rva;
        if (close.Facts.Flow != FlowKind.ConditionalJump || close.Facts.BranchTarget is not { } head || head < start || head > tail) return null;
        // A jump out of the run means the shift is ordinary index math.
        for (int k = i + 1; k <= last; k++)
        {
            if (lines[k].Facts.Flow is not (FlowKind.ConditionalJump or FlowKind.Jump)) continue;
            if (lines[k].Facts.BranchTarget is not { } to || to < start || to > close.Rva) return null;
        }
        return Make(lines, i, last + 1 - i + 1, "write barrier", va);
    }

    // Skips exactly one initializer call after a zero check of a static.
    private static Run? Lazy(IReadOnlyList<DisasmLine> lines, int i, Func<uint, string> va)
    {
        var cmp = lines[i];
        if (Mnemonic(cmp) != "cmp" || !cmp.Facts.MemoryIsRipRelative || !ZeroOperand().IsMatch(Normal(cmp))) return null;
        if (i + 2 >= lines.Count) return null;
        var jump = lines[i + 1];
        if (jump.Facts.Flow != FlowKind.ConditionalJump || Mnemonic(jump) is not ("jne" or "jnz") || jump.Facts.BranchTarget is not { } skip) return null;
        for (int k = i + 2; k < lines.Count && k <= i + 2 + LazyWindow; k++)
        {
            var l = lines[k];
            if (l.Facts.Flow == FlowKind.Call)
            {
                if (l.Rva + (uint)l.Facts.Length != skip) return null;
                return Make(lines, i, k - i + 1, $"lazy initialization of {va(cmp.Facts.MemoryTarget ?? 0)}", va);
            }
            if (Mnemonic(l) is not ("mov" or "lea" or "xor" or "sub" or "add")) return null;
        }
        return null;
    }

    // Matches calls that name a static-base helper; unnamed targets stay listed.
    private static Run? Init(IReadOnlyList<DisasmLine> lines, int i, Func<uint, string> va, IReadOnlyDictionary<uint, string>? calls)
    {
        var l = lines[i];
        var m = StaticBase().Match(l.Text);
        if (m.Success) return Make(lines, i, 1, "metadata initialization " + m.Groups[1].Value, va);
        if (l.Facts.Flow != FlowKind.Call) return null;
        string? named = calls != null && calls.TryGetValue(l.Rva, out var c) ? c : null;
        var t = StaticBaseName().Match(named ?? "");
        if (!t.Success) t = StaticBaseName().Match(l.Comment ?? "");
        return t.Success ? Make(lines, i, 1, "metadata initialization " + t.Value, va) : null;
    }

    [GeneratedRegex(@"\s*,\s*|\s+")]
    private static partial Regex Spaces();

    [GeneratedRegex(@"^cmp [^,]+,(0|0x0+|0+h)$")]
    private static partial Regex ZeroOperand();

    [GeneratedRegex(@"^shr \w+,(12|0xc|0*ch)$")]
    private static partial Regex ShiftBy12();

    [GeneratedRegex(@"\S*(?:GetGCStaticBase|GetNonGCStaticBase|GetThreadStaticBase)\S*")]
    private static partial Regex StaticBaseName();

    [GeneratedRegex(@"^\s*call\s+(\S*(?:GetGCStaticBase|GetNonGCStaticBase|GetThreadStaticBase)\S*)\s*$")]
    private static partial Regex StaticBase();
}
