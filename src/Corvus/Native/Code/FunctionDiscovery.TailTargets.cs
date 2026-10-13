using Iced.Intel;

namespace Corvus.Native.Code;

internal sealed partial class FunctionDiscovery
{
    /// <summary>Unconditional jumps of functions without unwind ranges that may leave the function (site, target, function).</summary>
    private readonly List<(uint Site, uint Target, uint Root)> _jumps = [];

    private const int TailTargetLimit = 512;

    /// <summary>
    /// A jump target outside its function's contiguous code (before its entry, or past another function's start)
    /// that decodes as a function of its own (stack balanced from its first instruction, ends in a return) is a tail-called
    /// function, not a block of the jumping one. Cold blocks a compiler moves out of line use their parent's frame or never
    /// return, so they stay blocks. Evaluated once discovery settles, in the order the jumps were found.
    /// </summary>
    private bool AddTailTargets()
    {
        if (_jumps.Count == 0) return false;
        var starts = _functions.Keys.ToArray();
        Array.Sort(starts);
        var tried = new HashSet<uint>();
        bool added = false;
        foreach (var (site, target, root) in _jumps)
        {
            if (_functions.ContainsKey(target) || !tried.Add(target)) continue;
            int next = Array.BinarySearch(starts, site + 1);
            if (next < 0) next = ~next;
            bool outside = target < root || (next < starts.Length && starts[next] < target) || JumpOverBarrier(site, target);
            if (!outside) continue;
            // ARM32: a branch keeps the state, so the target decodes in its function's
            if (_ctx.ArmModes != null) _peek.BeginFunction(target);
            // inside unwind ranges: a part of that function (x64 cold code has chained .pdata entries); with .pdata, separately
            // compiled functions are padded apart while cold blocks are packed together
            if (_ctx.PdataOwner(target) != null || (_ctx.PdataSorted.Length > 0 && !AfterPadding(target))
                || FallsInto(target) || !DecodesAsOwnFunction(target, starts)) continue;
            Add(target, FunctionSource.TailJump, strong: true);
            added = true;
        }
        _jumps.Clear();
        return added;
    }

    private bool IsArm64 => HybridDecoder.PrimaryOf(_peek) is Arm64Decoder;

    /// <summary>x86: int3 / nop fill before <paramref name="rva"/>; ARM64: a zero, nop or ret word; Thumb: a zero, nop, bx lr or pop {.., pc} halfword.</summary>
    private bool AfterPadding(uint rva)
    {
        bool arm64 = IsArm64, arm32 = _ctx.ArmModes != null;
        if (_ctx.Code.RegionAt(rva) is not { } region || rva - region.Rva < (arm64 ? 4u : arm32 ? 2u : 1u)) return false;
        int at = (int)(rva - region.Rva);
        if (arm32) return BitConverter.ToUInt16(region.Bytes, at - 2) is 0 or 0xBF00 or 0x4770 or (>= 0xBD00 and <= 0xBDFF);
        return arm64 ? BitConverter.ToUInt32(region.Bytes, at - 4) is 0 or 0xD503201F or 0xD65F03C0 : region.Bytes[at - 1] is 0xCC or 0x90;
    }

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
        var peek = _peek;
        bool arm64 = IsArm64;
        var arm32 = HybridDecoder.PrimaryOf(peek) as Arm32Decoder;
        int at = Array.BinarySearch(starts, start + 1);
        if (at < 0) at = ~at;
        uint end = at < starts.Length ? starts[at] : uint.MaxValue;
        int pointer = peek.Is64 ? 8 : 4;
        Span<byte> word = stackalloc byte[4];
        var work = new Stack<(uint Rva, int Depth, int Frame)>();
        var seen = new HashSet<uint>();
        work.Push((start, 0, -1));
        bool returns = false;
        int count = 0;
        peek.BeginFunction(start);
        while (work.Count > 0)
        {
            var (a, depth, frame) = work.Pop();
            peek.BeginRun(IndexBound.None);
            while (seen.Add(a))
            {
                // ARM32: a literal pool known code loads ends the path (after a call that does not return), as in exploring
                if (arm32 != null && IsLiteral(a, 2)) goto next;
                if (a < start || a >= end || ++count > TailTargetLimit || !peek.Decode(a, out var insn) || insn.Flow == FlowKind.Invalid) return false;
                if (arm32 != null)
                {
                    // a conditional instruction moves the stack on its taken path only: a conditional return (popeq {.., pc})
                    var x = arm32.Last;
                    int taken = depth, takenFrame = frame;
                    if (!Arm32StackStep(in x, ref taken, ref takenFrame)) return false;
                    if (!x.IsConditional) (depth, frame) = (taken, takenFrame);
                    else if (taken != depth && insn.Flow != FlowKind.Return) return false;
                    else if (insn.Flow == FlowKind.Return)
                    {
                        if (taken != 0) return false;
                        returns = true;
                        a = insn.Next;
                        continue;
                    }
                }
                else if (!(arm64
                    ? _ctx.Read(a, word) == 4 && Arm64StackStep(BitConverter.ToUInt32(word), ref depth, ref frame)
                    : StackStep(in _x86Peek!.Last, insn.Flow, pointer, ref depth, ref frame))) return false;
                bool tail = insn.HasTarget && (_functions.ContainsKey(insn.Target) || ThunkSlot(insn.Target) != null
                    || arm32 != null && (arm32.LastSwitchesState || arm32.LastIsComputed || arm32.IsStateSwitchStub(insn.Target)));
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
                        // a switch: its cases run on the same stack
                        if (peek.MatchSwitch(out _) is { } m && _ctx.ReadSwitch(insn.Rva, m, null, out _) is { } table)
                        {
                            foreach (uint t in table.Targets) work.Push((t, depth, frame));
                            if (insn.Conditional) break;
                            goto next;
                        }
                        // through an import slot or a register: a tail call, on the entry stack
                        if (depth != 0) return false;
                        if (insn.Conditional) break;
                        goto next;
                }
                a = insn.Next;
            }
            next:;
        }
        return returns;
    }

    /// <summary>
    /// A64: bytes allocated since the entry after instruction <paramref name="w"/> (stp / str pre-index and sub on sp
    /// allocate, ldp / ldr post-index and add free, mov x29, sp and back); false when it frees below the entry or writes sp
    /// otherwise.
    /// </summary>
    private static bool Arm64StackStep(uint w, ref int depth, ref int frame)
    {
        static int Imm7(uint w, int scale) => ((int)(w << 10) >> 25) * scale;
        static int Imm9(uint w) => (int)(w << 11) >> 23;
        int delta;
        if ((w & 0x3E0) != 0x3E0 && (w & 0x1F) != 31) return true; // neither base nor destination is sp
        switch (w & 0xFFC003E0)
        {
            case 0xA98003E0: case 0x6D8003E0: delta = -Imm7(w, 8); break;  // stp x / d, [sp, #-n]!
            case 0xAD8003E0: delta = -Imm7(w, 16); break;                  // stp q
            case 0xA8C003E0: case 0x6CC003E0: delta = -Imm7(w, 8); break;  // ldp x / d, [sp], #n
            case 0xACC003E0: delta = -Imm7(w, 16); break;                  // ldp q
            default:
                if ((w & 0xFFE00FE0) is 0xF8000FE0 or 0xFC000FE0) delta = -Imm9(w);       // str x / d, [sp, #-n]!
                else if ((w & 0xFFE00FE0) is 0xF84007E0 or 0xFC4007E0) delta = -Imm9(w);  // ldr x / d, [sp], #n
                else if ((w & 0x7F8003FF) is 0x510003FF or 0x110003FF)                    // sub / add sp, sp, #n
                {
                    int imm = (int)((w >> 10) & 0xFFF) << ((w & 0x400000) != 0 ? 12 : 0);
                    delta = (w & 0x40000000) != 0 ? imm : -imm;
                }
                else if ((w & 0xFF8003FF) == 0x910003FD) { frame = depth - (int)((w >> 10) & 0xFFF); return true; } // add x29, sp, #n
                else if (w == 0x910003BF) { depth = frame; return frame >= 0; }                                      // mov sp, x29
                // other writes to sp: add / sub (immediate, extended) and logical immediate without flags (with flags register 31 is zr)
                else if ((w & 0x1F) == 31 && (w & 0x20000000) == 0
                    && ((w & 0x1F000000) == 0x11000000 || (w & 0x1FE00000) == 0x0B200000 || (w & 0x1F800000) == 0x12000000)) return false;
                else return true;
                break;
        }
        depth += delta;
        return depth >= 0;
    }

    /// <summary>
    /// A32 / T32: bytes allocated since the entry after <paramref name="i"/> (push / vpush, sub sp, writeback stores and
    /// loads on sp, the r7 / r11 frame pointer set from sp and moved back); false when it frees below the entry or writes
    /// sp otherwise.
    /// </summary>
    private static bool Arm32StackStep(in ArmInstruction i, ref int depth, ref int frame)
    {
        const int Sp = 13;
        int delta = 0;
        bool writesSp = (i.Writes & (1 << Sp)) != 0;
        if (i.OperandCount > 0 && i.Op(0).Kind == ArmOperandKind.Register && i.Op(0).Reg is 7 or 11 && i.Mnemonic is "add" or "mov")
        {
            // add r7, sp, #n / mov r7, sp: the frame pointer; any other write to it ends what it says
            if (i.Mnemonic == "mov" && i.OperandCount == 2 && i.Op(1) is { Kind: ArmOperandKind.Register, Reg: Sp }) frame = depth;
            else if (i.OperandCount == 3 && i.Op(1) is { Kind: ArmOperandKind.Register, Reg: Sp } && i.Op(2).Kind == ArmOperandKind.Immediate) frame = depth - (int)i.Op(2).Value;
            else frame = -1;
            return true;
        }
        if (!writesSp)
        {
            if ((i.Writes & (1 << 7 | 1 << 11)) != 0) frame = -1;
            return true;
        }
        switch (i.Mnemonic)
        {
            case "push" or "pop":
                for (int k = 0; k < i.OperandCount; k++)
                    if (i.Op(k).Kind == ArmOperandKind.RegisterList) delta = 4 * System.Numerics.BitOperations.PopCount((uint)i.Op(k).Value);
                if (i.Mnemonic == "pop") delta = -delta;
                break;
            case "vpush" or "vpop":
                for (int k = 0; k < i.OperandCount; k++)
                    if (i.Op(k).Kind == ArmOperandKind.VectorList) delta = i.Op(k).Count * (i.Op(k).Vector == ArmVector.S ? 4 : 8);
                if (i.Mnemonic == "vpop") delta = -delta;
                break;
            case "add" or "sub" or "addw" or "subw" when i.Op(0) is { Kind: ArmOperandKind.Register, Reg: Sp }:
            {
                var last = i.Op(i.OperandCount - 1);
                if (i.OperandCount == 3 && i.Op(1) is { Kind: ArmOperandKind.Register, Reg: 7 or 11 } && last.Kind == ArmOperandKind.Immediate && i.Mnemonic is "sub" or "subw")
                {
                    // sub sp, r7, #n: back to the frame
                    if (frame < 0) return false;
                    depth = frame + (int)last.Value;
                    return depth >= 0;
                }
                if (last.Kind != ArmOperandKind.Immediate || i.OperandCount == 3 && i.Op(1) is not { Kind: ArmOperandKind.Register, Reg: Sp }) return false;
                delta = i.Mnemonic.StartsWith("sub", StringComparison.Ordinal) ? (int)last.Value : -(int)last.Value;
                break;
            }
            case "mov" when i.OperandCount == 2 && i.Op(0) is { Kind: ArmOperandKind.Register, Reg: Sp } && i.Op(1) is { Kind: ArmOperandKind.Register, Reg: 7 or 11 }:
                if (frame < 0) return false;
                depth = frame;
                return true;
            default:
                // a load or store that writes its sp base back: str lr, [sp, #-4]! / ldr pc, [sp], #4
                int m = -1;
                for (int k = 0; k < i.OperandCount; k++)
                    if (i.Op(k).Kind == ArmOperandKind.Memory) m = k;
                if (m < 0 || i.Op(m) is not { Reg: Sp, Index: ArmOperand.NoReg } op || op.Indexing == ArmIndexing.Offset
                    || i.Op(0) is { Kind: ArmOperandKind.Register, Reg: Sp }) return false;
                delta = op.Subtract ? (int)op.Value : -(int)op.Value;
                break;
        }
        depth += delta;
        return depth >= 0;
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
