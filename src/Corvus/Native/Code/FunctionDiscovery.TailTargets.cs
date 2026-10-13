using Iced.Intel;

namespace Corvus.Native.Code;

internal sealed partial class FunctionDiscovery
{
    /// <summary>x86 / x64: unconditional jumps of functions without unwind ranges that may leave the function (site, target, function).</summary>
    private readonly List<(uint Site, uint Target, uint Root)> _jumps = [];

    private const int TailTargetLimit = 512;

    /// <summary>
    /// x86 / x64: a jump target outside its function's contiguous code (before its entry, or past another function's start)
    /// that decodes as a function of its own (stack balanced from its first instruction, ends in a return) is a tail-called
    /// function, not a block of the jumping one. Cold blocks a compiler moves out of line use their parent's frame or never
    /// return, so they stay blocks. Evaluated once discovery settles, in the order the jumps were found.
    /// </summary>
    private bool AddTailTargets()
    {
        if (_x86Peek == null || _jumps.Count == 0) return false;
        var starts = _functions.Keys.ToArray();
        Array.Sort(starts);
        var tried = new HashSet<uint>();
        bool added = false;
        foreach (var (site, target, root) in _jumps)
        {
            if (_functions.ContainsKey(target) || !tried.Add(target)) continue;
            int next = Array.BinarySearch(starts, site + 1);
            if (next < 0) next = ~next;
            bool outside = target < root || (next < starts.Length && starts[next] < target);
            // inside unwind ranges: a part of that function (x64 cold code has chained .pdata entries); with .pdata, separately
            // compiled functions are padded apart while cold blocks are packed together
            if (!outside || _ctx.PdataOwner(target) != null || (_ctx.PdataSorted.Length > 0 && !AfterPadding(target))
                || FallsInto(target) || !DecodesAsOwnFunction(target, starts)) continue;
            Add(target, FunctionSource.TailJump, strong: true);
            added = true;
        }
        _jumps.Clear();
        return added;
    }

    private bool AfterPadding(uint rva) => _ctx.Code.RegionAt(rva) is { } region && rva > region.Rva && region.Bytes[rva - region.Rva - 1] is 0xCC or 0x90;

    /// <summary>A decoded instruction ends at <paramref name="rva"/> and runs on into it: the target is a block of that code (a shared return), not a function.</summary>
    private bool FallsInto(uint rva)
    {
        for (uint k = 1; k <= 15 && k <= rva; k++)
        {
            long bit = _ctx.Code.BitIndex(rva - k);
            if (bit < 0 || !_starts[bit]) continue;
            if (!_peek.Decode(rva - k, out var insn) || insn.Length != k) continue;
            return insn.Flow is FlowKind.Next or FlowKind.ConditionalJump || (insn.Flow is FlowKind.Call or FlowKind.IndirectCall && !(insn.HasTarget && IsNoReturnTarget(insn.Target)));
        }
        return false;
    }

    /// <summary>
    /// The code at <paramref name="start"/>, up to the next known function start, runs on a frame of its own: every path
    /// pops only what it pushed and returns with the stack it was entered with, tail-calls a known function, or ends in a
    /// trap or a call that does not return; at least one path returns.
    /// </summary>
    private bool DecodesAsOwnFunction(uint start, uint[] starts)
    {
        var peek = _x86Peek!;
        int at = Array.BinarySearch(starts, start + 1);
        if (at < 0) at = ~at;
        uint end = at < starts.Length ? starts[at] : uint.MaxValue;
        int pointer = peek.Is64 ? 8 : 4;
        var work = new Stack<(uint Rva, int Depth, int Frame)>();
        var seen = new HashSet<uint>();
        work.Push((start, 0, -1));
        bool returns = false;
        int count = 0;
        peek.BeginFunction();
        while (work.Count > 0)
        {
            var (a, depth, frame) = work.Pop();
            peek.BeginRun(IndexBound.None);
            while (seen.Add(a))
            {
                if (a < start || a >= end || ++count > TailTargetLimit || !peek.Decode(a, out var insn) || insn.Flow == FlowKind.Invalid) return false;
                ref readonly var x = ref peek.Last;
                if (!StackStep(in x, insn.Flow, pointer, ref depth, ref frame)) return false;
                bool tail = insn.HasTarget && (_functions.ContainsKey(insn.Target) || ThunkSlot(insn.Target) != null);
                switch (insn.Flow)
                {
                    case FlowKind.Return:
                        if (depth != 0) return false;
                        returns = true;
                        goto next;
                    case FlowKind.Trap:
                        goto next;
                    case FlowKind.Call:
                        if (insn.HasTarget && insn.Target != insn.Next && IsNoReturnTarget(insn.Target)) goto next;
                        break;
                    case FlowKind.IndirectCall:
                        if (insn.HasMem && _ctx.NoReturn.Contains(insn.MemTarget)) goto next;
                        break;
                    case FlowKind.Jump:
                        if (!insn.HasTarget) return false;
                        if (tail) { if (depth != 0) return false; goto next; }
                        work.Push((insn.Target, depth, frame));
                        goto next;
                    case FlowKind.ConditionalJump:
                        if (!insn.HasTarget) return false;
                        if (tail) { if (depth != 0) return false; }
                        else work.Push((insn.Target, depth, frame));
                        break;
                    case FlowKind.IndirectJump:
                        // through an import slot or a register: a tail call, on the entry stack
                        if (depth != 0) return false;
                        goto next;
                }
                a = insn.Next;
            }
            next:;
        }
        return returns;
    }

    /// <summary>
    /// Bytes pushed since the entry after <paramref name="x"/>; false when it pops below the entry (the parent's frame) or
    /// moves the stack pointer in a way not followed. <paramref name="frame"/>: the depth "mov rbp, rsp" saved, or -1.
    /// </summary>
    private static bool StackStep(in Instruction x, FlowKind flow, int pointer, ref int depth, ref int frame)
    {
        if (flow is FlowKind.Call or FlowKind.IndirectCall or FlowKind.Return) return true;
        bool sp = x.Op0Kind == Iced.Intel.OpKind.Register && x.Op0Register.GetFullRegister() == Register.RSP;
        if (sp && x.Mnemonic is Mnemonic.Sub or Mnemonic.Add && x.Op1Kind is Iced.Intel.OpKind.Immediate8to32 or Iced.Intel.OpKind.Immediate32 or Iced.Intel.OpKind.Immediate8to64 or Iced.Intel.OpKind.Immediate32to64)
        {
            depth += x.Mnemonic == Mnemonic.Sub ? (int)x.GetImmediate(1) : -(int)x.GetImmediate(1);
            return depth >= 0;
        }
        if (sp && x.Mnemonic == Mnemonic.Mov && x.Op1Kind == Iced.Intel.OpKind.Register && x.Op1Register.GetFullRegister() == Register.RBP)
        {
            depth = frame;
            return frame >= 0;
        }
        if (x.Mnemonic == Mnemonic.Mov && x.Op0Kind == Iced.Intel.OpKind.Register && x.Op0Register.GetFullRegister() == Register.RBP
            && x.Op1Kind == Iced.Intel.OpKind.Register && x.Op1Register.GetFullRegister() == Register.RSP)
        {
            frame = depth;
            return true;
        }
        if (x.Mnemonic == Mnemonic.Leave)
        {
            if (frame < pointer) return false;
            depth = frame - pointer;
            return true;
        }
        if (sp || x.Mnemonic == Mnemonic.Enter) return false;
        depth -= x.StackPointerIncrement;
        return depth >= 0;
    }
}
