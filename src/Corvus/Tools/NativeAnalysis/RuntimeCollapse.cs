using System.Text.RegularExpressions;
using Iced.Intel;
using Corvus.Core;
using Corvus.Native;
using Corvus.Native.Code;

namespace Corvus.Tools;

/// <summary>Folds runtime-support shapes of a listing into comment lines.</summary>
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

    /// <summary>Throws unsupported when collapse=runtime cannot apply.</summary>
    internal static void RequireEngine(bool external, bool wasm, NativeArch arch)
    {
        if (external || wasm || arch != NativeArch.X64)
            throw new ToolError(ErrorCode.Unsupported, "disassemble collapse=runtime applies to x64 images on the built-in engine only.", "pass collapse=none");
    }

    /// <summary>Throws when the listing is a linear range, which collapse=runtime does not cover.</summary>
    internal static void RequireFunction(bool inFunction)
    {
        if (!inFunction) throw new ToolError(ErrorCode.InvalidArgument, "disassemble collapse=runtime applies to a function listing, not to a range from an address.", "pass the function's name or start address");
    }

    /// <summary>One collapsed run: the first instruction, the end of the run, the instruction count and the comment line.</summary>
    internal sealed record Run(uint Start, uint End, int Count, string Note);

    // Shapes are queries on the value-provenance facts of the decoded
    // instructions. Call names, which only the listing text, its comment and
    // the call map carry, are the one text input.
    private sealed class Scan(IReadOnlyList<Instruction> code, RuntimeFacts facts, ulong imageBase, Func<uint, string> va,
        IReadOnlyDictionary<uint, DisasmLine> lines, IReadOnlyDictionary<uint, string>? calls)
    {
        public readonly IReadOnlyList<Instruction> Code = code;
        public readonly RuntimeFacts Facts = facts;
        public readonly ulong ImageBase = imageBase;
        public readonly Func<uint, string> Va = va;
        public readonly Dictionary<ulong, int> At = code.Select((ins, k) => (ins.IP, k)).ToDictionary(p => p.IP, p => p.k);
        public readonly Dictionary<ulong, CallFact> CallAt = facts.Calls.ToDictionary(c => c.Ip);

        public uint Rva(in Instruction ins) => (uint)(ins.IP - ImageBase);

        // The match in the call-map name, operand text or decoder comment.
        public string? Name(Regex name, in Instruction call)
        {
            uint rva = Rva(call);
            lines.TryGetValue(rva, out var line);
            foreach (var text in new[] { calls != null && calls.TryGetValue(rva, out var mapped) ? mapped : "", line?.Text ?? "", line?.Comment ?? "" })
                if (name.Match(text) is { Success: true } m) return m.Value;
            return null;
        }

        public bool Names(Regex name, in Instruction call) => Name(name, call) != null;
    }

    /// <summary>
    /// The non-overlapping runs found in <paramref name="listing"/> of
    /// <paramref name="fn"/>, keyed by start address; empty when none match or
    /// the function is not x64 code. <paramref name="calls"/> names call
    /// targets that the decoder text does not.
    /// </summary>
    internal static Dictionary<uint, Run> Find(NativeCodeIndex index, NativeFunction fn, IReadOnlyList<DisasmLine> listing, Func<uint, string> va,
        IReadOnlyDictionary<uint, string>? calls = null, CancellationToken ct = default)
    {
        var runs = new Dictionary<uint, Run>();
        if (index.FactsOf(fn, ct) is not { } facts) return runs;
        var lines = listing.ToDictionary(l => l.Rva);
        ulong imageBase = index.Image.ImageBase;
        var code = FunctionInstructions.Decode(index.Image, index.Ranges(fn), ct).Where(ins => lines.ContainsKey((uint)(ins.IP - imageBase))).ToList();
        var scan = new Scan(code, facts, imageBase, va, lines, calls);
        var guards = Guards(scan);
        for (int i = 0; i < code.Count;)
        {
            var run = Barrier(scan, i);
            if (run == null && guards.TryGetValue(i, out var guard)) run = Lazy(scan, i, guard) ?? ClassInit(scan, i, guard);
            run ??= Init(scan, i);
            if (run == null || !Contiguous(code, i, run.Count)) { i++; continue; }
            runs[run.Start] = run;
            i += run.Count;
        }
        return runs;
    }

    // A gap between blocks inside a run would be swallowed with no gap line.
    private static bool Contiguous(IReadOnlyList<Instruction> code, int from, int count)
    {
        if (from + count > code.Count) return false;
        for (int k = from + 1; k < from + count; k++)
            if (code[k].IP != code[k - 1].NextIP) return false;
        return true;
    }

    private static Run Make(Scan scan, int from, int count, string what)
    {
        var last = scan.Code[from + count - 1];
        uint start = scan.Rva(scan.Code[from]), end = scan.Rva(last) + (uint)last.Length;
        return new Run(start, end, count, $"collapsed: {what} ({ToolSupport.Plural(count, "instruction")}, {scan.Va(start)}-{scan.Va(end)})");
    }

    // Where a run on a zero test starts, by position: at the test when the
    // jump follows it, else at the jump so moves scheduled between stay
    // listed. Only register moves may sit between the test and the jump.
    private static Dictionary<int, GuardFact> Guards(Scan scan)
    {
        var result = new Dictionary<int, GuardFact>();
        foreach (var guard in scan.Facts.Guards)
        {
            if (!scan.At.TryGetValue(guard.Branch, out int jump) || !scan.At.TryGetValue(guard.Test.Check, out int check) || check >= jump) continue;
            if (jump - check - 1 > LazyWindow || Enumerable.Range(check + 1, jump - check - 1).Any(k => !IsRegisterMove(scan.Code[k]))) continue;
            result[jump - check == 1 ? check : jump] = guard;
        }
        return result;
    }

    // Shift by 12, then a locked exchange or bit-set of memory with a value
    // computed from the shifted one, and a closing backward branch. A first
    // exchange may skip the retry loop by a forward branch.
    private static Run? Barrier(Scan scan, int i)
    {
        var code = scan.Code;
        var updates = scan.Facts.Updates.Where(u => u.Shift == code[i].IP).Select(u => u.Update).ToHashSet();
        if (updates.Count == 0) return null;
        int last = -1;
        for (int k = i + 1; k < code.Count && k <= i + BarrierWindow; k++)
        {
            if (code[k].FlowControl is FlowControl.Call or FlowControl.IndirectCall or FlowControl.Return) break;
            if (updates.Contains(code[k].IP)) last = k;
        }
        if (last < 0) return null;
        uint start = scan.Rva(code[i]), tail = scan.Rva(code[last]);
        // The closing branch returns to the loop head, a few instructions
        // after the exchange.
        int closeAt = -1;
        for (int k = last + 1; k < code.Count && k <= last + BarrierClose; k++)
        {
            if (code[k].FlowControl is FlowControl.Call or FlowControl.IndirectCall or FlowControl.Return) return null;
            if (Branch(scan, code[k]) is { } head && head >= start && head <= tail) { closeAt = k; break; }
        }
        if (closeAt < 0) return null;
        uint closeEnd = scan.Rva(code[closeAt]) + (uint)code[closeAt].Length;
        // A jump out of the run, other than past the closing branch, means
        // the shift is ordinary index math.
        for (int k = i + 1; k < closeAt; k++)
            if (Branch(scan, code[k]) is { } to && (to < start || to > closeEnd)) return null;
        return Make(scan, i, closeAt - i + 1, "write barrier");
    }

    // The target of a direct jump, null for other instructions.
    private static uint? Branch(Scan scan, in Instruction ins) =>
        ins.FlowControl is FlowControl.ConditionalBranch or FlowControl.UnconditionalBranch && ins.Op0Kind == OpKind.NearBranch64
            ? (uint)(ins.NearBranchTarget - scan.ImageBase) : null;

    // Skips initializer calls after a zero test of a static flag. One call may
    // have any target; several must all be metadata initializers.
    private static Run? Lazy(Scan scan, int start, GuardFact guard)
    {
        if (guard.Test.Value is not LoadOrigin { Base: AddressOrigin flag, Disp: 0 } tested) return null;
        var code = scan.Code;
        int callCount = 0, setup = 0;
        bool allInit = true;
        for (int k = scan.At[guard.Branch] + 1; k < code.Count; k++)
        {
            var l = code[k];
            if (scan.Rva(l) >= guard.Target) return null;
            if (l.FlowControl == FlowControl.Call)
            {
                if (++callCount > LazyCalls) return null;
                allInit &= scan.Names(InitMetadata(), l);
                setup = 0;
                int last = k;
                uint end = scan.Rva(l) + (uint)l.Length;
                // A fence and flag store may precede the skip target.
                if (end != guard.Target && last + 1 < code.Count && IsFence(code[last + 1])) { last++; end = scan.Rva(code[last]) + (uint)code[last].Length; }
                if (end != guard.Target && last + 1 < code.Count && IsFlagStore(code[last + 1], flag.Address)) { last++; end = scan.Rva(code[last]) + (uint)code[last].Length; }
                // A fence between two calls is part of the run, not setup.
                if (end != guard.Target) { k = last; continue; }
                if (callCount > 1 && !allInit) return null;
                // A tested load of a wider static is a null check, not a flag.
                if (!guard.Test.Direct && !allInit && tested.Size != 1) return null;
                return Make(scan, start, last - start + 1, $"lazy initialization of {scan.Va((uint)(flag.Address - scan.ImageBase))}");
            }
            if (l.Mnemonic is not (Mnemonic.Mov or Mnemonic.Lea or Mnemonic.Xor or Mnemonic.Sub or Mnemonic.Add) || ++setup > LazyWindow) return null;
        }
        return null;
    }

    // Folds a zero test of a class field, a skip and the class-init call made
    // with the class pointer the field was read from.
    private static Run? ClassInit(Scan scan, int start, GuardFact guard)
    {
        if (guard.Test.Value is not LoadOrigin { Base: var klass } || klass is AddressOrigin) return null;
        var code = scan.Code;
        // The argument is set up between the branch and the call.
        int k = scan.At[guard.Branch] + 1;
        int limit = k + LazyWindow;
        while (k < code.Count && k < limit && IsRegisterLoad(code[k])) k++;
        if (k >= code.Count) return null;
        var call = code[k];
        if (call.FlowControl != FlowControl.Call || !scan.Names(ClassInitName(), call)) return null;
        if (!scan.CallAt.TryGetValue(call.IP, out var fact) || !klass.Equals(fact.Arguments[0])) return null;
        // Padding or a register restored from the setup may follow the call.
        for (int after = 0; scan.Rva(code[k]) + (uint)code[k].Length != guard.Target; after++)
        {
            if (after >= LazyWindow || k + 1 >= code.Count || code[k + 1].Mnemonic != Mnemonic.Nop && !IsRegisterLoad(code[k + 1])) return null;
            k++;
        }
        return Make(scan, start, k - start + 1, "class initialization");
    }

    // A move between registers cannot write memory.
    private static bool IsRegisterMove(in Instruction ins) =>
        ins.Mnemonic is Mnemonic.Mov or Mnemonic.Movzx or Mnemonic.Movsx or Mnemonic.Movsxd
        && ins.Op0Kind == OpKind.Register && ins.Op1Kind == OpKind.Register;

    // A load or address into a register.
    private static bool IsRegisterLoad(in Instruction ins) =>
        ins.Mnemonic is Mnemonic.Mov or Mnemonic.Movzx or Mnemonic.Lea && ins.FlowControl == FlowControl.Next && ins.Op0Kind == OpKind.Register;

    // lock or [rsp + d], 0.
    private static bool IsFence(in Instruction ins) =>
        ins.Mnemonic == Mnemonic.Or && ins.HasLockPrefix && ins.Op0Kind == OpKind.Memory && ins.MemoryBase == Register.RSP
        && ins.MemoryIndex == Register.None && ins.Op1Kind != OpKind.Register && ins.GetImmediate(1) == 0;

    // A store of 1 to the flag the guard tested.
    private static bool IsFlagStore(in Instruction ins, ulong flag) =>
        ins.Mnemonic == Mnemonic.Mov && ins.Op0Kind == OpKind.Memory && ins.MemoryBase == Register.RIP
        && ins.IPRelativeMemoryAddress == flag && ins.Op1Kind != OpKind.Register && ins.GetImmediate(1) == 1;

    // Matches calls that name a static-base helper; unnamed targets stay listed.
    private static Run? Init(Scan scan, int i)
    {
        var ins = scan.Code[i];
        if (ins.FlowControl != FlowControl.Call) return null;
        return scan.Name(StaticBaseName(), ins) is { } name ? Make(scan, i, 1, "metadata initialization " + name) : null;
    }

    [GeneratedRegex(@"(?<![A-Za-z0-9])InitMetadata(?![A-Za-z0-9])")]
    private static partial Regex InitMetadata();

    [GeneratedRegex(@"(?<![A-Za-z0-9])Runtime_ClassInit(?![A-Za-z0-9])")]
    private static partial Regex ClassInitName();

    [GeneratedRegex(@"\S*(?:GetGCStaticBase|GetNonGCStaticBase|GetThreadStaticBase)\S*")]
    private static partial Regex StaticBaseName();
}
