using System.Text.RegularExpressions;
using Corvus.Core;
using Corvus.Native;
using Corvus.Native.Code;

namespace Corvus.Tools;

/// <summary>Finds runtime-support shapes in an x86 listing and names each as one comment line; off unless collapse=runtime.</summary>
internal static partial class RuntimeCollapse
{
    internal const string Runtime = "runtime";

    // Instructions searched after a shift by 12 for the card-table update,
    // which may retry its exchange in a loop.
    private const int BarrierWindow = 32;

    // Instructions between the last exchange and the branch that closes the loop.
    private const int BarrierClose = 8;

    // Setup instructions allowed between a guard branch and its initializer call.
    private const int LazyWindow = 4;

    // Calls scanned after a guard branch before the block is given up.
    private const int LazyCalls = 8;

    /// <summary>The collapse mode, ignoring case: null, empty or "none" is off, "runtime" is on; anything else is rejected.</summary>
    internal static bool Parse(string? mode) => mode?.Trim().ToLowerInvariant() switch
    {
        null or "" or "none" => false,
        Runtime => true,
        _ => throw new ToolError(ErrorCode.InvalidArgument, $"disassemble collapse '{mode}' is not supported; use 'none' or '{Runtime}'.", "pass collapse=none or collapse=runtime"),
    };

    /// <summary>Throws an unsupported error when collapse=runtime cannot apply: an external engine, a WebAssembly image or a non-x86 architecture.</summary>
    internal static void RequireEngine(bool external, bool wasm, NativeArch arch)
    {
        if (external || wasm || arch is not (NativeArch.X86 or NativeArch.X64))
            throw new ToolError(ErrorCode.Unsupported, "disassemble collapse=runtime applies to x86 and x64 images on the built-in engine only.", "pass collapse=none");
    }

    /// <summary>Throws when the listing is a linear range, which collapse=runtime does not cover.</summary>
    internal static void RequireFunction(bool inFunction)
    {
        if (!inFunction) throw new ToolError(ErrorCode.InvalidArgument, "disassemble collapse=runtime applies to a function listing, not to a range from an address.", "pass the function's name or start address");
    }

    /// <summary>One collapsed run: the first instruction, the end of the run, the instruction count and the comment line.</summary>
    internal sealed record Run(uint Start, uint End, int Count, string Note);

    /// <summary>The non-overlapping runs found in <paramref name="lines"/>, keyed by start address; empty when none match. <paramref name="calls"/> names call targets that the decoder text does not.</summary>
    internal static Dictionary<uint, Run> Find(IReadOnlyList<DisasmLine> lines, Func<uint, string> va, IReadOnlyDictionary<uint, string>? calls = null)
    {
        var runs = new Dictionary<uint, Run>();
        for (int i = 0; i < lines.Count;)
        {
            int lead = 0;
            var run = Barrier(lines, i, va) ?? Lazy(lines, i, va, calls, out lead) ?? ClassInit(lines, i, va, calls) ?? Init(lines, i, va, calls);
            if (run == null || !Contiguous(lines, i + lead, run.Count)) { i++; continue; }
            runs[run.Start] = run;
            i += lead + run.Count;
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
    // A first exchange may skip the retry loop by a forward branch.
    private static Run? Barrier(IReadOnlyList<DisasmLine> lines, int i, Func<uint, string> va)
    {
        if (!ShiftBy12().IsMatch(Normal(lines[i]))) return null;
        int last = -1;
        for (int k = i + 1; k < lines.Count && k <= i + BarrierWindow; k++)
        {
            var flow = lines[k].Facts.Flow;
            if (flow is FlowKind.Call or FlowKind.IndirectCall or FlowKind.Return) break;
            // The card table is updated in memory; a register bit-set is index math.
            if ((Mnemonic(lines[k]) == "bts" || IsLockCmpxchg(lines[k])) && lines[k].Text.Contains('[')) last = k;
        }
        if (last < 0) return null;
        uint start = lines[i].Rva, tail = lines[last].Rva;
        // The closing branch returns to the loop head, a few instructions
        // after the exchange.
        int closeAt = -1;
        for (int k = last + 1; k < lines.Count && k <= last + BarrierClose; k++)
        {
            var flow = lines[k].Facts.Flow;
            if (flow is FlowKind.Call or FlowKind.IndirectCall or FlowKind.Return) return null;
            if (flow is FlowKind.ConditionalJump or FlowKind.Jump && lines[k].Facts.BranchTarget is { } head && head >= start && head <= tail) { closeAt = k; break; }
        }
        if (closeAt < 0) return null;
        var close = lines[closeAt];
        uint closeEnd = close.Rva + (uint)close.Facts.Length;
        // A jump out of the run, other than past the closing branch, means
        // the shift is ordinary index math.
        for (int k = i + 1; k < closeAt; k++)
        {
            if (lines[k].Facts.Flow is not (FlowKind.ConditionalJump or FlowKind.Jump)) continue;
            if (lines[k].Facts.BranchTarget is not { } to || to < start || to > closeEnd) return null;
        }
        return Make(lines, i, closeAt - i + 1, "write barrier", va);
    }

    // Skips initializer calls after a zero check of a static: a compare with
    // zero, or a load of the flag and a test of the loaded register. The run
    // starts at the branch or the test, so register moves scheduled after the
    // check stay listed. One call may have any target; several must all be
    // metadata initializers.
    private static Run? Lazy(IReadOnlyList<DisasmLine> lines, int i, Func<uint, string> va, IReadOnlyDictionary<uint, string>? calls, out int lead)
    {
        lead = 0;
        var cmp = lines[i];
        int j = i + 1;
        bool compare = Mnemonic(cmp) == "cmp" && cmp.Facts.MemoryIsRipRelative && ZeroOperand().IsMatch(Normal(cmp));
        if (!compare && !LoadsFlag(cmp)) return null;
        while (j < lines.Count && j < i + 1 + LazyWindow && IsRegisterMove(lines[j])) j++;
        if (!compare)
        {
            if (j + 1 >= lines.Count || !TestsRegister(lines[j], cmp)) return null;
            lead = j - i;
            j++;
        }
        if (j + 1 >= lines.Count) return null;
        var jump = lines[j];
        if (jump.Facts.Flow != FlowKind.ConditionalJump || Mnemonic(jump) is not ("jne" or "jnz") || jump.Facts.BranchTarget is not { } skip) return null;
        int callCount = 0, setup = 0;
        bool allInit = true;
        for (int k = j + 1; k < lines.Count; k++)
        {
            var l = lines[k];
            if (l.Rva >= skip) return null;
            if (l.Facts.Flow == FlowKind.Call)
            {
                if (++callCount > LazyCalls) return null;
                allInit &= Names(InitMetadata(), l, calls);
                setup = 0;
                int last = k;
                uint end = l.Rva + (uint)l.Facts.Length;
                // A fence and flag store may precede the skip target.
                if (end != skip && last + 1 < lines.Count && IsFence(lines[last + 1])) { last++; end = lines[last].Rva + (uint)lines[last].Facts.Length; }
                if (end != skip && last + 1 < lines.Count && IsFlagStore(lines[last + 1], cmp)) { last++; end = lines[last].Rva + (uint)lines[last].Facts.Length; }
                // A fence between two calls is part of the run, not setup.
                if (end != skip) { k = last; continue; }
                if (callCount > 1 && !allInit) return null;
                // A tested load of a wider static is a null check, not a flag.
                if (!compare && !allInit && !ByteLoad(cmp)) { lead = 0; return null; }
                if (compare) lead = j == i + 1 ? 0 : j - i;
                return Make(lines, i + lead, last - i - lead + 1, $"lazy initialization of {va(cmp.Facts.MemoryTarget ?? 0)}", va);
            }
            if (Mnemonic(l) is not ("mov" or "lea" or "xor" or "sub" or "add") || ++setup > LazyWindow) return null;
        }
        return null;
    }

    // Folds a zero check of a class flag, a skip and the class-init call. The
    // check is a compare with zero, or a load of the flag and a test of the
    // loaded register.
    private static Run? ClassInit(IReadOnlyList<DisasmLine> lines, int i, Func<uint, string> va, IReadOnlyDictionary<uint, string>? calls)
    {
        var first = lines[i];
        int j = i + 1;
        bool compare = Mnemonic(first) == "cmp" && !first.Facts.MemoryIsRipRelative && first.Text.Contains('[') && ZeroOperand().IsMatch(Normal(first));
        if (!compare)
        {
            if (Mnemonic(first) is not ("mov" or "movzx") || first.Facts.MemoryIsRipRelative || Destination(first).Contains('[') || !first.Text.Contains('[')) return null;
            if (j >= lines.Count || !TestsRegister(lines[j], first)) return null;
            j++;
        }
        if (j >= lines.Count) return null;
        var jump = lines[j];
        if (jump.Facts.Flow != FlowKind.ConditionalJump || Mnemonic(jump) is not ("jne" or "jnz") || jump.Facts.BranchTarget is not { } skip) return null;
        // The argument is set up between the branch and the call.
        int k = j + 1;
        while (k < lines.Count && k < j + 1 + LazyWindow && IsRegisterLoad(lines[k])) k++;
        if (k >= lines.Count) return null;
        var call = lines[k];
        if (call.Facts.Flow != FlowKind.Call || !Names(ClassInitName(), call, calls)) return null;
        // A padding instruction may follow the call.
        if (call.Rva + (uint)call.Facts.Length != skip)
        {
            if (k + 1 >= lines.Count || Mnemonic(lines[k + 1]) != "nop" || lines[k + 1].Rva + (uint)lines[k + 1].Facts.Length != skip) return null;
            k++;
        }
        return Make(lines, i, k - i + 1, "class initialization", va);
    }

    // A call matches when its call-map name, its operand text or its decoder comment does.
    private static bool Names(Regex name, DisasmLine l, IReadOnlyDictionary<uint, string>? calls) =>
        name.IsMatch(calls != null && calls.TryGetValue(l.Rva, out var c) ? c : "") || name.IsMatch(l.Text) || name.IsMatch(l.Comment ?? "");

    // A move between registers has no memory operand, so it cannot write memory.
    private static bool IsRegisterMove(DisasmLine l) => Mnemonic(l) is "mov" or "movzx" or "movsx" or "movsxd" && l.Facts.Flow == FlowKind.Next && !l.Text.Contains('[') && !l.Facts.MemoryIsRipRelative && l.Facts.MemoryTarget == null;

    // A load or address into a register: the destination is not memory.
    private static bool IsRegisterLoad(DisasmLine l) =>
        Mnemonic(l) is "mov" or "movzx" or "lea" && l.Facts.Flow == FlowKind.Next && !Destination(l).Contains('[');

    private static string Destination(DisasmLine l)
    {
        var text = Normal(l);
        int space = text.IndexOf(' ');
        int comma = text.IndexOf(',');
        return space < 0 || comma < space ? "" : text[(space + 1)..comma];
    }

    // A load of a static into a register.
    private static bool LoadsFlag(DisasmLine l) =>
        Mnemonic(l) is "mov" or "movzx" && l.Facts.MemoryIsRipRelative && l.Facts.Flow == FlowKind.Next && !Destination(l).Contains('[');

    // A load of one byte: a byte operand or an 8-bit destination register.
    private static bool ByteLoad(DisasmLine l) =>
        Normal(l).Contains("byte ptr", StringComparison.Ordinal) || ByteRegister().IsMatch(Destination(l));

    // test reg,reg on the register family that the load wrote.
    private static bool TestsRegister(DisasmLine test, DisasmLine load)
    {
        var m = TestSelf().Match(Normal(test));
        return m.Success && m.Groups[1].Value == m.Groups[2].Value && Family(m.Groups[1].Value) == Family(Destination(load));
    }

    // The 64-bit register that a name addresses: al, ax, eax and rax are one.
    private static string Family(string register)
    {
        var r = NumberedRegister().Match(register);
        if (r.Success) return "r" + r.Groups[1].Value;
        var legacy = LegacyRegister().Match(register);
        return legacy.Success ? (legacy.Groups[1].Success ? legacy.Groups[1].Value : legacy.Groups[2].Value) : register;
    }

    [GeneratedRegex(@"^(?:[abcd]l|[abcd]h|(?:si|di|sp|bp)l|r\d+b)$")]
    private static partial Regex ByteRegister();

    [GeneratedRegex(@"^test (\w+),(\w+)$")]
    private static partial Regex TestSelf();

    [GeneratedRegex(@"^r(\d+)[dwb]?$")]
    private static partial Regex NumberedRegister();

    [GeneratedRegex(@"^(?:e|r)?([abcd])(?:x|l|h)$|^(?:e|r)?(si|di|sp|bp)l?$")]
    private static partial Regex LegacyRegister();

    private static bool IsFence(DisasmLine l) => FenceText().IsMatch(Normal(l));

    // A store of 1 to the flag the guard compared.
    private static bool IsFlagStore(DisasmLine l, DisasmLine cmp) =>
        Mnemonic(l) == "mov" && l.Facts.MemoryIsRipRelative && l.Facts.MemoryTarget == cmp.Facts.MemoryTarget && FlagOne().IsMatch(Normal(l));

    // Matches calls that name a static-base helper; unnamed targets stay listed.
    private static Run? Init(IReadOnlyList<DisasmLine> lines, int i, Func<uint, string> va, IReadOnlyDictionary<uint, string>? calls)
    {
        var l = lines[i];
        var m = StaticBase().Match(l.Text);
        if (m.Success) return Make(lines, i, 1, "metadata initialization " + m.Groups[1].Value, va);
        if (l.Facts.Flow != FlowKind.Call) return null;
        var t = StaticBaseName().Match(calls != null && calls.TryGetValue(l.Rva, out var c) ? c : "");
        if (!t.Success) t = StaticBaseName().Match(l.Comment ?? "");
        return t.Success ? Make(lines, i, 1, "metadata initialization " + t.Value, va) : null;
    }

    [GeneratedRegex(@"(?<![A-Za-z0-9])InitMetadata(?![A-Za-z0-9])")]
    private static partial Regex InitMetadata();

    [GeneratedRegex(@"(?<![A-Za-z0-9])Runtime_ClassInit(?![A-Za-z0-9])")]
    private static partial Regex ClassInitName();

    [GeneratedRegex(@"\s*,\s*|\s+")]
    private static partial Regex Spaces();

    [GeneratedRegex(@"^cmp [^,]+,(0|0x0+|0+h)$")]
    private static partial Regex ZeroOperand();

    [GeneratedRegex(@"^lock or (?:dword ptr )?\[rsp\],0(?:x0+|0*h)?$")]
    private static partial Regex FenceText();

    [GeneratedRegex(@"^mov (?:byte ptr )?\[[^\]]+\],(1|0x0*1|0*1h)$")]
    private static partial Regex FlagOne();

    [GeneratedRegex(@"^shr \w+,(12|0xc|0*ch)$")]
    private static partial Regex ShiftBy12();

    [GeneratedRegex(@"\S*(?:GetGCStaticBase|GetNonGCStaticBase|GetThreadStaticBase)\S*")]
    private static partial Regex StaticBaseName();

    [GeneratedRegex(@"^\s*call\s+(\S*(?:GetGCStaticBase|GetNonGCStaticBase|GetThreadStaticBase)\S*)\s*$")]
    private static partial Regex StaticBase();
}
